// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package unreceipteddoaction implements the "unreceipted-do-action"
// llmcheat.Pattern: it flags a function whose name contains "deploy",
// "publish", "release", or "push" (case-insensitive) that performs a real
// mutating/network action (a subprocess/exec call, an HTTP POST/PUT-looking
// call, or a "git push"/"docker push" invocation) but contains no call to
// anything named or shaped like a receipt/ledger writer ("receipt",
// "ledger", "ocel", "audit_log") anywhere in the same function body. This is
// the DO-authority-without-EVIDENCE shape: an irreversible external action
// performed with no adjacent evidence-writing step, so there is nothing a
// later reader can replay or verify the action actually happened as
// claimed.
//
// Detect is a text-level heuristic, not a full parser, for the same reason
// every other pattern package in this tree is: 50 of these are authored
// independently and in parallel, and a shared full-language-parser
// dependency would be exactly the kind of centralized bottleneck this
// design avoids. It recognizes function bodies in two shapes:
//
//   - Brace-delimited (Go, Rust, JavaScript/TypeScript, and bare
//     POSIX-shell-style `name() { ... }` functions): the body is the text
//     between the function signature's first `{` and its balanced matching
//     `}`, found by counting brace depth across lines. This does not
//     understand string/comment literals, so a brace character embedded in
//     a string literal within a flagged function's body could in principle
//     desynchronize the count — an accepted, documented heuristic
//     limitation shared with this tree's other brace-scanning detectors
//     (see gopanictodostub).
//   - Indentation-delimited (Python `def name(...):`): the body is every
//     following line indented further than the `def` line, ending at the
//     first line (blank lines excluded) whose indentation returns to or
//     below the `def` line's own indentation, or at end of file.
//
// Go methods with a receiver (`func (d *Deployer) Push(...) {`) are
// recognized explicitly, since that is the idiomatic Go method shape and
// the assigned dirty/clean examples for this pattern are Go. Out of scope,
// documented rather than silently mishandled: arrow-function assignments
// (`const deploy = () => {}`) and typed-return C-style signatures
// (`void deploy() {}`) are not recognized as function definitions by this
// detector.
package unreceipteddoaction

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID       = "unreceipted-do-action"
	patternCategory = "determinism-and-provenance-violation"
)

// funcNameKeywordRe matches the action-word substrings named by this
// pattern's description, case-insensitively, anywhere in a function name
// (not anchored to a whole word: "pushImage" and "ReleaseArtifact" both
// qualify, same as the description's own "contains" wording).
var funcNameKeywordRe = regexp.MustCompile(`(?i)(deploy|publish|release|push)`)

// goMethodSigRe matches a Go method with a receiver:
// `func (d *Deployer) Push(image string) error {`. Checked before
// braceFuncSigRe because braceFuncSigRe's `func\s+NAME\s*\(` shape cannot
// match past a receiver clause.
var goMethodSigRe = regexp.MustCompile(`^\s*func\s*\([^)]*\)\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(`)

// braceFuncSigRe matches a bare Go/Rust/JavaScript/TypeScript function
// definition keyword followed directly by a name and an opening paren:
// `func Deploy(`, `fn deploy(`, `function deploy(`, `async function deploy(`
// (the "async" prefix does not need its own alternative since "function"
// still appears as its own word right before the name).
var braceFuncSigRe = regexp.MustCompile(`(?i)\b(?:func|fn|function)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(`)

// methodShorthandSigRe matches a JS/TS class-method or object-method
// shorthand definition with an explicit same-line opening brace:
// `push(image) {`. The same-line `{` requirement (rather than allowing a
// bare `name(...)` line) is deliberate: without it this shape is
// indistinguishable from an ordinary function *call* statement sitting
// alone on its own line, which would misfire body-extraction on unrelated
// following code.
var methodShorthandSigRe = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{\s*$`)

// shellFuncSigRe matches a POSIX-shell-style function definition with empty
// parens, with or without a same-line opening brace (the brace is commonly
// placed on the following line in shell scripts): `deploy() {` or `deploy()`.
var shellFuncSigRe = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*\{?\s*$`)

// pyFuncSigRe matches a Python function definition, capturing its leading
// indentation (to bound the indentation-delimited body) and its name.
var pyFuncSigRe = regexp.MustCompile(`^(\s*)def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(`)

// mutatingCallRe matches the mutating/network call shapes named by this
// pattern's description: a subprocess/exec invocation, an HTTP POST/PUT
// call, or a git/docker push. Matched against the whole (possibly
// multi-line) function-body text, case-insensitively, since Go's regexp
// \s already spans newlines without needing a dotall flag.
var mutatingCallRe = regexp.MustCompile(`(?i)` +
	`exec\.Command\s*\(` + // Go os/exec
	`|subprocess\.(?:run|call|Popen|check_call|check_output)\s*\(` + // Python subprocess
	`|os\.system\s*\(` + // Python/generic shell-out
	`|Command::new\s*\(` + // Rust std::process::Command
	`|child_process\.\w+\s*\(` + // Node child_process.*
	`|execSync\s*\(` + // Node execSync
	`|\bspawn(?:Sync)?\s*\(` + // Node spawn/spawnSync
	`|http\.(?:Post|Put)\s*\(` + // Go net/http Post/Put
	`|requests\.(?:post|put)\s*\(` + // Python requests
	`|axios\.(?:post|put)\s*\(` + // JS axios
	`|method\s*[:=]\s*["'](?:POST|PUT)["']` + // fetch/http-client { method: "POST" }
	`|\bgit\b\W{0,10}\bpush\b` + // git push, incl. exec.Command("git","push",...)
	`|\bdocker\b\W{0,10}\bpush\b`) // docker push, incl. exec.Command("docker","push",...)

// receiptRe matches any of the receipt/ledger/audit-evidence shapes named
// by this pattern's description, as a substring so identifiers like
// writeReceipt, receipts.Write, auditLog(...), or ledger_append(...) all
// count as the adjacent evidence-writing step this pattern requires.
var receiptRe = regexp.MustCompile(`(?i)(receipt|ledger|ocel|audit_log|auditlog)`)

// detector is the real, stateless implementation of llmcheat.Pattern for
// this pattern. It holds no fields because Detect is a pure function of its
// arguments: the type exists only to give the interface methods a receiver.
type detector struct{}

func (detector) ID() string { return patternID }

func (detector) Category() string { return patternCategory }

// Detect scans path's content for function definitions whose name contains
// a deploy/publish/release/push keyword, extracts each such function's
// body (brace-delimited or Python-indentation-delimited, per the package
// doc comment), and reports one Match per qualifying function whose body
// contains a mutating/network call but no receipt/ledger/evidence call.
// This pattern names no file-type restriction, so it runs on any text
// content it is given.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	lines := splitLines(content)

	var matches []llmcheat.Match

	i := 0
	n := len(lines)
	for i < n {
		line := lines[i]
		lineNum := uint(i + 1)

		if pm := pyFuncSigRe.FindStringSubmatch(line); pm != nil {
			indent, name := pm[1], pm[2]
			if funcNameKeywordRe.MatchString(name) {
				bodyLines, next := extractIndentedBody(lines, i, indent)
				if m := matchForFunction(path, name, lineNum, bodyLines); m != nil {
					matches = append(matches, *m)
				}
				i = next
				continue
			}
			i++
			continue
		}

		var name string
		switch {
		case goMethodSigRe.MatchString(line):
			name = goMethodSigRe.FindStringSubmatch(line)[1]
		case braceFuncSigRe.MatchString(line):
			name = braceFuncSigRe.FindStringSubmatch(line)[1]
		case methodShorthandSigRe.MatchString(line):
			name = methodShorthandSigRe.FindStringSubmatch(line)[1]
		case shellFuncSigRe.MatchString(line):
			name = shellFuncSigRe.FindStringSubmatch(line)[1]
		}

		if name != "" && funcNameKeywordRe.MatchString(name) {
			bodyLines, next := extractBraceBody(lines, i)
			if m := matchForFunction(path, name, lineNum, bodyLines); m != nil {
				matches = append(matches, *m)
			}
			i = next
			continue
		}

		i++
	}

	return matches
}

// matchForFunction applies the pattern's core rule to one already-extracted
// function body: a Match is produced only when the body contains a real
// mutating/network call AND contains no receipt/ledger/evidence call.
// Returns nil when either condition fails to hold.
func matchForFunction(path, name string, lineNum uint, bodyLines []string) *llmcheat.Match {
	body := strings.Join(bodyLines, "\n")

	if !mutatingCallRe.MatchString(body) {
		return nil
	}
	if receiptRe.MatchString(body) {
		return nil
	}

	return &llmcheat.Match{
		PatternID: patternID,
		Category:  patternCategory,
		Path:      path,
		Line:      lineNum,
		Message: fmt.Sprintf(
			"function %q performs an irreversible mutating/network action (deploy/publish/release/push) with no receipt/ledger/audit-log call anywhere in its body",
			name,
		),
		Severity: llmcheat.SeverityHigh,
	}
}

// extractBraceBody collects the lines making up a brace-delimited function
// body starting at start (the function's signature line, which may or may
// not itself contain the opening brace). It scans forward counting `{` and
// `}` characters until brace depth returns to zero after having seen at
// least one opening brace, returning every scanned line (inclusive of both
// the signature line and the line containing the matching closing brace)
// plus the index of the line following the closing brace. If no balanced
// close is found before end of file, it returns everything scanned through
// EOF and n as the next index.
//
// This does not understand string or comment literals, so a `{`/`}`
// embedded in a string literal within the scanned lines could in principle
// desynchronize the count; this is an accepted heuristic limitation (see
// the package doc comment).
func extractBraceBody(lines []string, start int) ([]string, int) {
	n := len(lines)
	depth := 0
	foundOpen := false

	i := start
	var body []string
	for i < n {
		line := lines[i]
		body = append(body, line)

		for _, r := range line {
			switch r {
			case '{':
				depth++
				foundOpen = true
			case '}':
				if foundOpen {
					depth--
				}
			}
		}

		i++
		if foundOpen && depth <= 0 {
			return body, i
		}
	}

	return body, i
}

// extractIndentedBody collects the lines making up a Python-style
// indentation-delimited function body starting at start (the `def` line
// itself, whose leading indentation is indent). It includes every following
// line that is either blank or indented further than indent, stopping at
// (and not including) the first non-blank line whose indentation is less
// than or equal to indent, or at end of file. Returns the collected lines
// plus the index of the first line not included.
func extractIndentedBody(lines []string, start int, indent string) ([]string, int) {
	n := len(lines)
	baseIndent := len(indent)

	body := []string{lines[start]}
	i := start + 1
	for i < n {
		line := lines[i]
		if strings.TrimSpace(line) == "" {
			body = append(body, line)
			i++
			continue
		}

		curIndent := len(line) - len(strings.TrimLeft(line, " \t"))
		if curIndent <= baseIndent {
			break
		}

		body = append(body, line)
		i++
	}

	return body, i
}

// splitLines splits content into its raw lines with no trailing newline
// characters, using bufio.Scanner (with an expanded buffer, since source
// lines can occasionally exceed the 64KiB default) rather than
// bytes.Split so that both "\n" and "\r\n" line endings are handled
// uniformly.
func splitLines(content []byte) []string {
	var lines []string

	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines
}

func init() {
	llmcheat.Register(detector{})
}
