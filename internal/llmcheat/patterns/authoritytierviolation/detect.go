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

// Package authoritytierviolation implements the "authority-tier-violation"
// llmcheat Pattern.
//
// This repo's own operating doctrine (see ggen-ecosystem's CLAUDE.md/AGENTS.md
// authority boundary: SELECT / CONSTRUCT / DO) is one real-world instance of a
// broader pattern that shows up across many codebases under many names: a
// function, file, or module whose doc comment or containing directory
// declares a read-only / non-mutating tier ("SELECT-only", "CONSTRUCT-only",
// "read-only", "no mutation authority"), while its actual body performs a
// real mutating side effect anyway (a `git push`, a filesystem delete, a SQL
// DROP/DELETE, a `docker push`, ...). An LLM asked to "add a read-only
// helper" or "keep this in the SELECT tier" will sometimes paste in the
// doc-comment boundary claim as decoration while still wiring up the
// mutating call it was asked to avoid — the comment and the code disagree,
// and the comment is the one that's lying.
//
// Detect is intentionally language-agnostic: it works over line-based text
// using comment-prefix and function/body heuristics common to Go, Python,
// JS/TS, Rust, and SQL-embedded-in-any-of-the-above, rather than parsing any
// one language's AST. It does not attempt full parsing (brace/indent
// tracking is heuristic, not string/comment-aware within a line), which is a
// deliberate, stated trade-off consistent with this package family's other
// detectors: cheap, dependency-free, no false negatives on the stated
// fixture shapes, occasional false positives accepted as the cost of staying
// a pure function with no language-specific parser dependency.
package authoritytierviolation

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID       = "authority-tier-violation"
	patternCategory = "determinism-and-provenance-violation"
)

// boundaryPhraseRe matches any of the four stated read-only/non-mutating
// tier declarations, case-insensitively.
var boundaryPhraseRe = regexp.MustCompile(`(?i)select-only|construct-only|read-only|no mutation authority`)

// commentPrefixRe recognizes a line that looks like a comment (or a
// docstring delimiter) across the common languages this detector runs over:
// Go/Rust/JS/TS/C-like "//", Python/shell/YAML "#", a continuation line
// inside a "/* ... */" block ("*"), a block-comment opener ("/*"), SQL "--",
// Python triple-quoted docstring delimiters, and HTML/XML "<!--".
var commentPrefixRe = regexp.MustCompile(`^\s*(//|#|\*|/\*|--|"""|'''|<!--)`)

// mutatingPattern is one named, real-mutation call shape this detector
// treats as a genuine violation of a declared read-only/non-mutating tier.
type mutatingPattern struct {
	label string
	re    *regexp.Regexp
}

// mutatingPatterns is exactly the set named in this pattern's specification.
// "git push" and "docker push" are matched against both a plain-string shape
// (`git push`, e.g. inside a shell string or f-string) and an
// argv-list/exec.Command shape (`"git", "push"`, `["git", "push"]`) by
// tolerating a short run of quote/comma/whitespace characters between the
// two words rather than requiring a literal space.
var mutatingPatterns = []mutatingPattern{
	{"git push", regexp.MustCompile(`(?i)\bgit\b["'\s,]{0,8}\bpush\b`)},
	{".Push(", regexp.MustCompile(`\.Push\(`)},
	{"os.Remove(", regexp.MustCompile(`os\.Remove\(`)},
	{"shutil.rmtree(", regexp.MustCompile(`shutil\.rmtree\(`)},
	{"DROP TABLE", regexp.MustCompile(`(?i)\bDROP\s+TABLE\b`)},
	{"DELETE FROM", regexp.MustCompile(`(?i)\bDELETE\s+FROM\b`)},
	{"docker push", regexp.MustCompile(`(?i)\bdocker\b["'\s,]{0,8}\bpush\b`)},
	{"subprocess...push", regexp.MustCompile(`(?i)subprocess.*push`)},
	{"fs.unlink(", regexp.MustCompile(`fs\.unlink\(`)},
}

// pathBoundaryPhraseRe matches a directory/file-name-implied read-only tier
// signal: a path segment or filename containing one of these words, with or
// without a hyphen (e.g. "readonly/", "read-only-gate.go",
// "select_only.py"). This lets the file/directory name itself stand in for
// a per-function doc comment, per the pattern's stated scope ("or containing
// file/directory-implied name").
var pathBoundaryPhraseRe = regexp.MustCompile(`(?i)read[-_]?only|select[-_]?only|construct[-_]?only|no[-_]?mutation`)

// detector is the real, stateless implementation of llmcheat.Pattern for
// this pattern. It holds no fields because Detect is a pure function of its
// arguments: the type exists only to give the interface methods a receiver.
type detector struct{}

func (detector) ID() string { return patternID }

func (detector) Category() string { return patternCategory }

// Detect scans path's content for functions whose declared read-only/
// non-mutating tier (via a doc comment immediately above them, or via the
// file's own path implying that tier) is contradicted by a real mutating
// call somewhere in their body.
//
// Two independent trigger mechanisms are combined, and their results may
// legitimately overlap for the same file (a function with both a local
// boundary comment and a path-implied boundary produces one match from
// each pass) — this is accepted redundancy, not a bug, since the contract
// only promises "at least one Match" per real violation, not exactly one:
//
//  1. Per-function: a comment-shaped line containing one of the boundary
//     phrases, immediately followed (skipping further comment/blank lines)
//     by what looks like a function signature. That function's body is then
//     scanned — brace-depth-tracked for C-like languages, indentation-
//     tracked for Python-shaped "def ...:" bodies, or a fixed lookahead
//     window as a last-resort fallback — for a mutating call.
//  2. Whole-file: if the file's own path implies a read-only tier (e.g. it
//     lives under a "readonly/" or "select-only/" directory, or is itself
//     named that way), every non-comment line in the file is scanned for a
//     mutating call, since the declared boundary applies to the whole file
//     rather than one function.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	lines := splitLines(content)
	var matches []llmcheat.Match

	// Mechanism 1: per-function doc-comment boundary vs. body mutation.
	for i := 0; i < len(lines); i++ {
		if !commentPrefixRe.MatchString(lines[i]) {
			continue
		}
		phrase := boundaryPhraseRe.FindString(lines[i])
		if phrase == "" {
			continue
		}

		bodyStart, bodyEnd, ok := findFunctionBody(lines, i)
		if !ok {
			continue
		}

		for ln := bodyStart; ln <= bodyEnd; ln++ {
			label, snippet := findMutatingCall(lines[ln])
			if label == "" {
				continue
			}
			matches = append(matches, llmcheat.Match{
				PatternID: patternID,
				Category:  patternCategory,
				Path:      path,
				Line:      uint(ln + 1),
				Message: fmt.Sprintf(
					"function declared %q but its body contains a mutating call (%s): %s",
					strings.TrimSpace(phrase), label, snippet,
				),
				Severity: llmcheat.SeverityHigh,
			})
		}

		// Advance past this function's body so a multi-line doc-comment
		// block containing the boundary phrase more than once (or a second,
		// separate boundary phrase in the same block) doesn't re-locate and
		// re-scan the exact same body, duplicating every match within it.
		i = bodyEnd
	}

	// Mechanism 2: whole-file, path-implied boundary vs. any body mutation.
	if pathBoundaryPhraseRe.MatchString(path) {
		for ln, line := range lines {
			if commentPrefixRe.MatchString(line) {
				continue
			}
			label, snippet := findMutatingCall(line)
			if label == "" {
				continue
			}
			matches = append(matches, llmcheat.Match{
				PatternID: patternID,
				Category:  patternCategory,
				Path:      path,
				Line:      uint(ln + 1),
				Message: fmt.Sprintf(
					"file path %q implies a read-only/no-mutation tier but contains a mutating call (%s): %s",
					path, label, snippet,
				),
				Severity: llmcheat.SeverityHigh,
			})
		}
	}

	return matches
}

// splitLines splits content on "\n" and strips a trailing "\r" from each
// line, so CRLF-terminated fixtures/files scan identically to LF-terminated
// ones.
func splitLines(content []byte) []string {
	raw := strings.Split(string(content), "\n")
	out := make([]string, len(raw))
	for i, l := range raw {
		out[i] = strings.TrimSuffix(l, "\r")
	}
	return out
}

// findMutatingCall returns the label of the first mutatingPatterns entry
// that matches line, and a trimmed snippet of that line for the Match
// message. It returns ("", "") when no mutating pattern matches.
func findMutatingCall(line string) (label, snippet string) {
	for _, mp := range mutatingPatterns {
		if mp.re.MatchString(line) {
			return mp.label, strings.TrimSpace(line)
		}
	}
	return "", ""
}

// findFunctionBody locates the function whose signature begins after
// commentIdx (skipping any further comment/blank lines that are part of the
// same doc-comment block) and returns the 0-based, inclusive
// [bodyStart, bodyEnd] line range covering that function's signature and
// body. ok is false when no function-like signature could be located
// (e.g. the boundary comment was the last real content in the file).
func findFunctionBody(lines []string, commentIdx int) (bodyStart, bodyEnd int, ok bool) {
	i := commentIdx + 1
	for i < len(lines) {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || commentPrefixRe.MatchString(lines[i]) {
			i++
			continue
		}
		break
	}
	if i >= len(lines) {
		return 0, 0, false
	}
	sigIdx := i

	// Look ahead a few lines from the signature for either a brace-based
	// body opener ('{') or a Python-style ":"-terminated header line — a
	// signature can legitimately wrap across a handful of lines (long
	// parameter lists).
	lookaheadEnd := sigIdx + 10
	if lookaheadEnd > len(lines) {
		lookaheadEnd = len(lines)
	}
	for j := sigIdx; j < lookaheadEnd; j++ {
		if idx := strings.IndexByte(lines[j], '{'); idx >= 0 {
			return scanBraceBody(lines, sigIdx, j, idx)
		}
		if strings.HasSuffix(strings.TrimSpace(lines[j]), ":") {
			return sigIdx, scanIndentBody(lines, sigIdx, j), true
		}
	}

	// Unknown style (no brace, no Python-style colon header found nearby):
	// fall back to a fixed lookahead window so the detector still has some
	// coverage instead of giving up entirely.
	fallbackEnd := sigIdx + 20
	if fallbackEnd >= len(lines) {
		fallbackEnd = len(lines) - 1
	}
	return sigIdx, fallbackEnd, true
}

// scanBraceBody tracks brace depth starting at line braceLine, column
// braceCol (the first '{' found at or after the signature) until it returns
// to zero, and returns [sigIdx, closingLine] inclusive. If the braces never
// balance before EOF, it returns up to the last line as a safe fallback.
//
// This is a plain character scan, not comment/string-literal aware: a '{'
// or '}' inside a string literal or a line comment would perturb the
// depth count. That is a deliberate, stated heuristic trade-off (see the
// package doc comment) shared with this detector family's other members.
func scanBraceBody(lines []string, sigIdx, braceLine, braceCol int) (int, int, bool) {
	depth := 0
	for j := braceLine; j < len(lines); j++ {
		l := lines[j]
		start := 0
		if j == braceLine {
			start = braceCol
		}
		for k := start; k < len(l); k++ {
			switch l[k] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					return sigIdx, j, true
				}
			}
		}
	}
	// Unterminated (shouldn't happen in real, compiling source): take the
	// rest of the file as the body rather than reporting no body at all.
	return sigIdx, len(lines) - 1, true
}

// scanIndentBody returns the last 0-based line index of a Python-style
// indented body that starts after colonLineIdx (a line ending in ":"),
// using sigIdx's own leading indentation as the "outside the body" baseline.
// Blank lines are treated as part of the body (common inside real function
// bodies) and do not end it; the first non-blank line at or below the
// baseline indentation does.
func scanIndentBody(lines []string, sigIdx, colonLineIdx int) int {
	baseIndent := leadingWhitespace(lines[sigIdx])
	end := colonLineIdx
	for j := colonLineIdx + 1; j < len(lines); j++ {
		if strings.TrimSpace(lines[j]) == "" {
			end = j
			continue
		}
		if leadingWhitespace(lines[j]) <= baseIndent {
			break
		}
		end = j
	}
	return end
}

// leadingWhitespace returns the count of leading space/tab characters on s.
func leadingWhitespace(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			n++
		} else {
			break
		}
	}
	return n
}

func init() {
	llmcheat.Register(detector{})
}
