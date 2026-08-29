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

// Package deadalternativebranch detects a permanently-dead conditional
// branch left sitting beside the "real" code path — the shape an LLM leaves
// behind when it writes a genuine implementation, then loses confidence (or
// is told to ship a stub instead) and disables the real branch rather than
// deleting it: `if false { <real logic> }`, Python's `if False:`, the
// parenthesized `if (false)` spelling, or Rust's `#[cfg(any())]` (an empty
// `any()` predicate list is unsatisfiable by definition, so whatever it
// guards can never be compiled in).
//
// A bare `if false { ... }`/`if False:`/`if (false)` guarding something
// trivial (a comment, a bare `pass`/no-op) is not flagged — that is
// ordinary temporarily-disabled scaffolding, not a discarded real
// implementation. What makes this pattern's target distinctive is that the
// dead branch still *looks like real work*: it contains a function call or
// an assignment. That heuristic (regex-based, not a real parser for any of
// the languages involved) is a deliberate trade-off for a pure,
// dependency-free, independently-testable detector; see Detect's doc
// comment for its precise scope and known blind spots.
package deadalternativebranch

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "dead-alternative-branch"
	category  = "hollow-implementation"
)

// pyIfFalseRe matches a Python `if False:` guard line (optionally followed
// by a trailing `# comment`), capturing the guard's own leading whitespace
// so the caller can compare it against the indentation of the lines that
// follow to find the block Python-style (indentation-delimited, no braces).
var pyIfFalseRe = regexp.MustCompile(`^(\s*)if\b\s+False\b\s*:\s*(#.*)?$`)

// braceIfFalseRe matches a brace-language (Go/Rust/C/Java/JS/...) `if
// false` guard, in either its bare form (`if false`), its
// C-family-parenthesized form (`if (false)`), or with an opening brace on
// the same line (`if false {`). The optional capture group records whether
// a `{` was present so the caller knows whether to scan for a matching `}`
// or, for a brace-free guard, treat the immediately following statement (or
// an Allman-style `{` on its own next line) as the guarded block.
var braceIfFalseRe = regexp.MustCompile(`^\s*if\b\s*\(?\s*false\b\s*\)?\s*(\{)?\s*$`)

// cfgAnyRe matches a Rust `#[cfg(any())]` (or inner `#![cfg(any())]`)
// attribute with a literally empty `any()` predicate list. `any()` over
// zero predicates is false by definition (there is nothing for "any" to be
// true of), so whatever item the attribute is attached to can never be
// compiled in — unlike `#[cfg(any(feature = "x", feature = "y"))]`, which
// is ordinary, legitimate conditional compilation and is deliberately not
// matched here (the empty-parens requirement is what separates a
// permanently-dead marker from a real feature gate).
var cfgAnyRe = regexp.MustCompile(`^\s*#!?\[\s*cfg\s*\(\s*any\s*\(\s*\)\s*\)\s*\]\s*$`)

// callRe matches an identifier immediately followed by `(`, i.e. something
// that reads as a function/method call: `computeReal(`, `self.save(`,
// `obj.Method(`.
var callRe = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_.]*\s*\(`)

// assignRe matches a single `=` that is not part of a `==`, `!=`, `<=`, or
// `>=` comparison operator, i.e. an assignment: `result = 5`, `x.y = f()`.
// Requiring a non-`=`/`!`/`<`/`>` character immediately before the `=` and
// a non-`=` character immediately after is enough to reject the comparison
// operators without a real parser (RE2, which Go's regexp package uses,
// supports neither lookahead nor lookbehind, so this 3-character-window
// approach is the pragmatic substitute).
var assignRe = regexp.MustCompile(`[^=!<>]=[^=]`)

// detector is the Pattern implementation for this package. It is
// unexported: callers outside this package only ever interact with it
// through the llmcheat.Pattern interface (or, in tests, by constructing it
// directly).
type detector struct{}

func (detector) ID() string       { return patternID }
func (detector) Category() string { return category }

// Detect scans one file's content line by line for a dead-but-real-looking
// alternative branch. It runs on any text content (the description names no
// specific file-type restriction for the `if false`/`if False:`/`if
// (false)` forms — they occur across Go, Rust, C, Java, JS, and Python
// alike), except the Rust-specific `#[cfg(any())]` check, which is scoped
// to `.rs` files to avoid a stray look-alike attribute-shaped comment in an
// unrelated file being misread as Rust syntax.
//
// This is a heuristic line scanner, not a real parser for any of the
// languages involved: it does not understand string literals or block
// comments that might themselves contain a `{`/`}` or `if false`-shaped
// text, and its brace/indentation block extraction is line-oriented (a
// same-line `if (false) { stmt(); }` fully closed on one line is not
// matched — only a guard whose block starts on its own line or on a
// following line is). Both are accepted trade-offs for a pure,
// dependency-free, independently-testable detector, and neither affects the
// documented dirty/clean fixtures this package is tested against.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	lines := splitLines(content)
	var matches []llmcheat.Match

	if strings.EqualFold(filepath.Ext(path), ".rs") {
		for i, line := range lines {
			if cfgAnyRe.MatchString(line) {
				matches = append(matches, llmcheat.Match{
					PatternID: patternID,
					Category:  category,
					Path:      path,
					Line:      uint(i + 1), //nolint:gosec // line count, never negative
					Message:   "#[cfg(any())] guards this item with an unsatisfiable (empty) predicate list — the item can never be compiled in; this is the Rust idiom for a permanently-dead branch kept beside a stub rather than deleted",
					Severity:  llmcheat.SeverityHigh,
				})
			}
		}
	}

	for i := 0; i < len(lines); {
		line := lines[i]

		if m := pyIfFalseRe.FindStringSubmatch(line); m != nil {
			indent := leadingWhitespaceLen(m[1])
			block, next := pythonBlock(lines, i+1, indent)
			if looksLikeRealLogic(block) {
				matches = append(matches, newMatch(path, uint(i+1), //nolint:gosec // line count, never negative
					"if False: guards a block containing a function call or assignment — a discarded real implementation kept beside a stub rather than deleted"))
			}
			i = next
			continue
		}

		if m := braceIfFalseRe.FindStringSubmatch(line); m != nil {
			hasBrace := m[1] == "{"
			var block []string
			var next int
			if hasBrace {
				block, next = braceBlock(lines, i+1, 1)
			} else {
				block, next = braceFreeBlock(lines, i+1)
			}
			if looksLikeRealLogic(block) {
				matches = append(matches, newMatch(path, uint(i+1), //nolint:gosec // line count, never negative
					"if false guards a block containing a function call or assignment — a discarded real implementation kept beside a stub rather than deleted"))
			}
			i = next
			continue
		}

		i++
	}

	return matches
}

// newMatch builds a Match with this pattern's fixed PatternID, Category,
// and Severity, varying only by path, line, and message.
func newMatch(path string, line uint, msg string) llmcheat.Match {
	return llmcheat.Match{
		PatternID: patternID,
		Category:  category,
		Path:      path,
		Line:      line,
		Message:   msg,
		Severity:  llmcheat.SeverityHigh,
	}
}

// splitLines splits content into lines on "\n", trimming a trailing "\r"
// from each so CRLF-terminated files are handled the same as LF-terminated
// ones.
func splitLines(content []byte) []string {
	raw := strings.Split(string(content), "\n")
	lines := make([]string, len(raw))
	for i, l := range raw {
		lines[i] = strings.TrimSuffix(l, "\r")
	}
	return lines
}

// leadingWhitespaceLen returns the number of leading space/tab characters
// in s.
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

// braceBlock returns the lines strictly between an already-consumed opening
// `{` (at nesting depth 1) and its matching closing `}`, starting the scan
// at lines[start], plus the index of the first line after that closing
// brace. It tracks nesting depth by counting `{`/`}` per line — a
// line-oriented heuristic, not a real parser (see Detect's doc comment).
func braceBlock(lines []string, start, depth int) (block []string, next int) {
	i := start
	for i < len(lines) {
		line := lines[i]
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if depth <= 0 {
			return block, i + 1
		}
		block = append(block, line)
		i++
	}
	return block, i
}

// braceFreeBlock handles a brace-language `if false`/`if (false)` guard
// that had no `{` on its own line. It looks past any blank lines for
// either: an Allman-style `{` sitting alone on its own line (in which case
// the block is whatever braceBlock finds after it), or otherwise treats the
// single next non-blank line as the entire guarded statement (the
// brace-free `if (false) stmt();` C-family form).
func braceFreeBlock(lines []string, start int) (block []string, next int) {
	j := start
	for j < len(lines) && strings.TrimSpace(lines[j]) == "" {
		j++
	}
	if j >= len(lines) {
		return nil, j
	}
	if strings.TrimSpace(lines[j]) == "{" {
		return braceBlock(lines, j+1, 1)
	}
	return []string{lines[j]}, j + 1
}

// pythonBlock returns the lines of a Python indentation-delimited block
// that starts at lines[start], where membership is "more indented than
// guardIndent" (blank lines are skipped over without ending the block, the
// same way a real Python block treats them).
func pythonBlock(lines []string, start, guardIndent int) (block []string, next int) {
	i := start
	for i < len(lines) {
		line := lines[i]
		if strings.TrimSpace(line) == "" {
			i++
			continue
		}
		if leadingWhitespaceLen(line) <= guardIndent {
			break
		}
		block = append(block, line)
		i++
	}
	return block, i
}

// looksLikeRealLogic reports whether any line in block contains a function
// call or an assignment — the coarse signal that separates a discarded real
// implementation (worth flagging) from trivial disabled scaffolding like a
// bare comment or a `pass`/no-op (not worth flagging).
func looksLikeRealLogic(block []string) bool {
	for _, line := range block {
		if callRe.MatchString(line) || assignRe.MatchString(line) {
			return true
		}
	}
	return false
}

func init() {
	llmcheat.Register(detector{})
}
