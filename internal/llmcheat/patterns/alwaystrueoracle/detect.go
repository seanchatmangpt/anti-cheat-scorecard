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

// Package alwaystrueoracle implements the "always-true-oracle" llmcheat
// Pattern: it flags a function whose *name* looks like a verifier/validator
// (starts with verify/validate/check/is_valid, in any casing) but whose
// *body* structurally cannot fail — no if/elif/match/switch and no
// comparison operator anywhere in it, and its only return statement (an
// explicit `return true` / `return True` / `return nil` / `return Ok(())`,
// or — for languages with implicit tail-expression returns, e.g. Rust — a
// bare trailing `true` / `Ok(())` statement) is a hardcoded success literal.
//
// This is a very common shape for an LLM to leave behind when it is asked to
// "add signature verification" or "add input validation" under time
// pressure: the function signature and call sites all look right, tests
// that only check the happy path pass, but the oracle itself never actually
// inspects its arguments and therefore can never report failure.
//
// The detector is a heuristic line/brace/indent scanner, not a full
// per-language parser (this package has no per-language AST dependency by
// design — see llmcheat.Pattern's doc comment on staying pure and
// dependency-light). It recognizes function definitions across Go, Rust,
// Python, and JS/TS-style source, extracts each candidate function's body
// text, and re-derives the same structural signal from that text that a
// human reviewer would eyeball: "does this body branch or compare anything,
// and does it do anything other than hand back a canned success value?"
package alwaystrueoracle

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID       = "always-true-oracle"
	patternCategory = "test-integrity-violation"
)

// bodyStyle records how a candidate function's body is delimited in source,
// which determines how extractBody locates it.
type bodyStyle int

const (
	// styleBrace: body runs from the first '{' after the definition line to
	// its matching '}' (Go, Rust, JS/TS).
	styleBrace bodyStyle = iota
	// styleIndent: body is every line after the definition line indented
	// strictly more than the definition line, until indentation drops back
	// to (or below) it (Python).
	styleIndent
)

// Function-definition line matchers. Each captures the function/method
// name; the Python one also captures the definition line's own leading
// whitespace, needed to find where its indented body ends.
var (
	pyDefRe    = regexp.MustCompile(`^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(`)
	goFuncRe   = regexp.MustCompile(`^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(`)
	rustFnRe   = regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_]\w*)\s*[(<]`)
	jsFuncRe   = regexp.MustCompile(`^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s+([A-Za-z_]\w*)\s*\(`)
	jsArrowRe  = regexp.MustCompile(`^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_]\w*)\s*(?::[^=]+)?=\s*(?:async\s*)?\([^)]*\)\s*(?::[^=]+)?=>\s*\{`)
	verifierRe = regexp.MustCompile(`^(verify|validate|check|isvalid)`)
	// controlFlowRe matches any conditional/branching keyword. "elif" is
	// included alongside the spec's literal if/match/switch because it is
	// Python's spelling of an else-if chain — the same construct as "if"
	// under a different token, not a different construct to leave open.
	controlFlowRe = regexp.MustCompile(`\b(if|elif|match|switch)\b`)
	returnWordRe  = regexp.MustCompile(`\breturn\b`)
	// literalReturnRe matches a full statement of the form
	// "return <success-literal>" with nothing else on the statement.
	literalReturnRe = regexp.MustCompile(`^return\s+(?:true|True|nil|Ok\(\(\)\))$`)
	// literalBareRe matches a bare success literal with no `return` keyword
	// at all — Rust's implicit tail-expression return shape.
	literalBareRe = regexp.MustCompile(`^(?:true|True|nil|Ok\(\(\)\))$`)
)

// detector is the real, stateless implementation of llmcheat.Pattern for
// this pattern. It holds no fields because Detect is a pure function of its
// arguments: the type exists only to give the interface methods a receiver.
type detector struct{}

func (detector) ID() string { return patternID }

func (detector) Category() string { return patternCategory }

// Detect scans every line of content looking for a function/method
// definition whose name reads as a verifier, then inspects that function's
// extracted body for the always-true-oracle shape described in the package
// doc comment. There is no file-extension restriction: the pattern is
// defined in terms of a general cross-language shape, not one specific
// source language, so it runs on any text content it is given.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	lines := strings.Split(string(content), "\n")
	var matches []llmcheat.Match

	for i, line := range lines {
		name, style, indent, ok := matchFuncDef(line)
		if !ok || !isVerifierName(name) {
			continue
		}

		var bodyText string
		switch style {
		case styleIndent:
			bodyText = extractIndentBody(lines, i, indent)
			if strings.TrimSpace(bodyText) == "" {
				continue
			}
		default: // styleBrace
			body, found := extractBraceBody(lines, i)
			if !found {
				continue
			}
			bodyText = body
		}

		if controlFlowRe.MatchString(bodyText) || hasComparison(bodyText) {
			continue
		}

		stmts := statementsOf(bodyText)
		if len(stmts) == 0 {
			continue
		}

		var returnStmts []string
		for _, s := range stmts {
			if returnWordRe.MatchString(s) {
				returnStmts = append(returnStmts, s)
			}
		}

		var alwaysSucceeds bool
		var literal string
		switch len(returnStmts) {
		case 1:
			literal = returnStmts[0]
			alwaysSucceeds = literalReturnRe.MatchString(literal)
		case 0:
			// No explicit `return` at all: only a bare trailing literal
			// (Rust-style implicit tail-expression return) counts.
			literal = stmts[len(stmts)-1]
			alwaysSucceeds = literalBareRe.MatchString(literal)
		default:
			// More than one return statement without any if/match/switch
			// in between is not the single-oracle shape this pattern
			// targets; leave it unflagged rather than guess.
			alwaysSucceeds = false
		}

		if !alwaysSucceeds {
			continue
		}

		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  patternCategory,
			Path:      path,
			Line:      uint(i + 1),
			Message: fmt.Sprintf(
				"verifier-shaped function %q has no if/match/switch or comparison in its body and unconditionally %q — it structurally cannot fail",
				name, literal,
			),
			Severity: llmcheat.SeverityHigh,
		})
	}

	return matches
}

// matchFuncDef tries each known function-definition shape against line and
// returns the declared name, how its body is delimited, and (for
// styleIndent only) the definition line's own leading-whitespace width.
func matchFuncDef(line string) (name string, style bodyStyle, indent int, ok bool) {
	if m := pyDefRe.FindStringSubmatch(line); m != nil {
		return m[2], styleIndent, len(m[1]), true
	}
	if m := goFuncRe.FindStringSubmatch(line); m != nil {
		return m[1], styleBrace, 0, true
	}
	if m := rustFnRe.FindStringSubmatch(line); m != nil {
		return m[1], styleBrace, 0, true
	}
	if m := jsFuncRe.FindStringSubmatch(line); m != nil {
		return m[1], styleBrace, 0, true
	}
	if m := jsArrowRe.FindStringSubmatch(line); m != nil {
		return m[1], styleBrace, 0, true
	}
	return "", 0, 0, false
}

// isVerifierName reports whether name reads as a verifier/validator/checker
// per the pattern's spec: starts with verify/validate/check/is_valid in any
// casing, underscores ignored (so Verify, verify_foo, IsValidQux, and
// is_valid_email all match).
func isVerifierName(name string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(name, "_", ""))
	return verifierRe.MatchString(normalized)
}

// extractBraceBody finds the first '{' at or after lines[defLineIdx] and
// returns the text strictly between it and its matching '}' (simple depth
// counting over the raw text; this is a heuristic scanner, not a
// string/comment-aware lexer, consistent with the rest of this package).
// found is false if no balanced '{'...'}' pair exists before EOF.
func extractBraceBody(lines []string, defLineIdx int) (body string, found bool) {
	joined := strings.Join(lines[defLineIdx:], "\n")
	depth := 0
	start := -1
	for i := 0; i < len(joined); i++ {
		switch joined[i] {
		case '{':
			depth++
			if start == -1 {
				start = i + 1
			}
		case '}':
			depth--
			if start != -1 && depth == 0 {
				return joined[start:i], true
			}
		}
	}
	return "", false
}

// extractIndentBody returns every line after lines[defLineIdx] that is
// indented strictly more than defIndent (blank lines are included and do
// not themselves end the body), stopping at the first non-blank line whose
// indentation is <= defIndent.
func extractIndentBody(lines []string, defLineIdx int, defIndent int) string {
	var sb strings.Builder
	for i := defLineIdx + 1; i < len(lines); i++ {
		line := lines[i]
		if strings.TrimSpace(line) == "" {
			sb.WriteString(line)
			sb.WriteString("\n")
			continue
		}
		if leadingWhitespaceLen(line) <= defIndent {
			break
		}
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	return sb.String()
}

func leadingWhitespaceLen(s string) int {
	n := 0
	for _, r := range s {
		if r == ' ' || r == '\t' {
			n++
		} else {
			break
		}
	}
	return n
}

// hasComparison reports whether body contains a comparison operator
// (==, !=, <=, >=, or a bare < / >). Arrow (->, <-) and shift (<<, >>)
// sequences are stripped first so Rust return-type arrows, Go channel
// direction arrows, and bit-shift expressions are not misread as
// comparisons.
func hasComparison(body string) bool {
	if strings.Contains(body, "==") || strings.Contains(body, "!=") ||
		strings.Contains(body, "<=") || strings.Contains(body, ">=") {
		return true
	}
	cleaned := body
	for _, seq := range []string{"->", "<-", "<<", ">>"} {
		cleaned = strings.ReplaceAll(cleaned, seq, "")
	}
	return strings.ContainsAny(cleaned, "<>")
}

// statementsOf splits bodyText into trimmed, non-empty candidate
// statements: one per non-blank source line, further split on ';' to catch
// multiple statements sharing a line, with stray brace-only lines (leaked
// in at the edges of extractBraceBody's slice) and whole-line comments
// dropped.
func statementsOf(bodyText string) []string {
	var stmts []string
	for _, raw := range strings.Split(bodyText, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || line == "{" || line == "}" {
			continue
		}
		if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
			continue
		}
		for _, part := range strings.Split(line, ";") {
			part = strings.TrimSpace(part)
			if part != "" {
				stmts = append(stmts, part)
			}
		}
	}
	return stmts
}

func init() {
	llmcheat.Register(detector{})
}
