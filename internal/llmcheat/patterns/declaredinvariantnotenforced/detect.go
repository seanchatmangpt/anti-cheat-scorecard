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

// Package declaredinvariantnotenforced implements the
// "declared-invariant-not-enforced" llmcheat.Pattern: it flags a doc
// comment or standalone comment block that describes a behavioral
// invariant ("Invariant:", "must never", "must always", "guaranteed to")
// for the function/block immediately following it, where that
// function/block's real body contains no enforcement mechanism at all —
// no assert, no panic, no raise, no throw, and no return-of-an-error
// statement. A comment that promises a guarantee the code makes no attempt
// to uphold is a classic LLM-cheat tell: the prose reads like a contract,
// but nothing in the implementation would ever catch a violation of it.
package declaredinvariantnotenforced

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID       = "declared-invariant-not-enforced"
	patternCategory = "determinism-and-provenance-violation"
)

// triggerPhraseRe matches the four invariant-declaring phrases named in the
// pattern description, case-insensitively, tolerant of internal whitespace
// variation (e.g. "must  never" across a wrapped comment) and anchored on a
// word boundary so "invariant:" doesn't also fire inside an unrelated
// identifier like "coinvariant:".
var triggerPhraseRe = regexp.MustCompile(`(?i)\b(invariant\s*:|must\s+never|must\s+always|guaranteed\s+to)`)

// enforcementKeywordRe matches the four bare enforcement keywords named in
// the pattern description — assert (assert(), self.assertEqual, assert_eq!,
// ASSERT_EQ, ...), panic (Go panic(), Rust panic!()), raise (Python), and
// throw (JS/TS/Java/C#) — anywhere in a function/block's body text.
var enforcementKeywordRe = regexp.MustCompile(`(?i)\b(assert|panic|raise|throw)\b`)

// returnErrRe matches a "return"-shaped statement that also mentions
// err/error/Errorf/errors on the same line — the fifth enforcement
// mechanism the description names ("return-error statement"), i.e. Go's
// idiomatic "return err" / "return nil, err" / "return errors.New(...)"
// shape. \berr (no trailing \b) deliberately matches "err", "error",
// "errors", and "Errorf" alike, since all four are real enforcement.
var returnErrRe = regexp.MustCompile(`(?i)\breturn\b.*\berr`)

// commentPrefixes are the line-start markers that identify a "comment/doc
// line" across the common languages this multi-language, dependency-free
// tool is expected to scan (Go/C/Java/Rust-style //, block-comment
// continuation *, Python/shell/Ruby #, SQL/Lua --, Lisp ;, HTML/XML
// <!-- -->, and Python triple-quoted docstrings). This is a deliberate
// heuristic, not a real per-language parser — good enough to identify
// "this line is prose commentary, not executable code" for this pattern.
var commentPrefixes = []string{
	"///", "//", "/*", "*/", "*", "#", "--", ";;", ";", "%", "<!--", "-->", `"""`, "'''",
}

// detector is the real, stateless implementation of llmcheat.Pattern for
// this pattern. It holds no fields because Detect is a pure function of its
// arguments: the type exists only to give the interface methods a receiver.
type detector struct{}

func (detector) ID() string { return patternID }

func (detector) Category() string { return patternCategory }

// Detect scans content line-by-line, groups contiguous comment lines into
// blocks, and — for every block that contains at least one invariant-
// declaring trigger phrase — locates the immediately-following non-blank,
// non-comment line (the declared function/block), extracts that
// function/block's real body text, and reports a Match only when that body
// contains none of the five enforcement mechanisms named in the pattern
// description. Line numbers are 1-based and computed from a real running
// index over the actual scanned lines, not fabricated or left at zero.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	lines := strings.Split(string(content), "\n")

	isComment := make([]bool, len(lines))
	for i, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		isComment[i] = trimmed != "" && hasCommentPrefix(trimmed)
	}

	var matches []llmcheat.Match

	i := 0
	for i < len(lines) {
		if !isComment[i] {
			i++
			continue
		}

		// Accumulate the contiguous run of comment lines starting at i.
		start := i
		end := i
		for end+1 < len(lines) && isComment[end+1] {
			end++
		}

		triggerLine := -1
		for j := start; j <= end; j++ {
			if triggerPhraseRe.MatchString(lines[j]) {
				triggerLine = j
				break
			}
		}

		if triggerLine == -1 {
			// No invariant-declaring phrase in this comment block — it's
			// an ordinary doc comment, out of scope for this pattern
			// regardless of what the following code does.
			i = end + 1
			continue
		}

		declIdx := nextCodeLine(lines, isComment, end+1)
		if declIdx == -1 {
			// The comment block is the last content in the file — there
			// is no following function/block to check.
			i = end + 1
			continue
		}

		bodyLines := extractBody(lines, declIdx)
		bodyText := strings.Join(bodyLines, "\n")

		if !hasEnforcement(bodyText) {
			matches = append(matches, llmcheat.Match{
				PatternID: patternID,
				Category:  patternCategory,
				Path:      path,
				Line:      uint(triggerLine + 1), //nolint:gosec // line index from a real split, never overflows uint
				Message: fmt.Sprintf(
					"comment %q declares an invariant for the function/block at line %d, but its body contains no assert/panic/raise/throw/return-error enforcement",
					strings.TrimSpace(lines[triggerLine]), declIdx+1,
				),
				Severity: llmcheat.SeverityMedium,
			})
		}

		i = end + 1
	}

	return matches
}

// nextCodeLine returns the index of the first non-blank, non-comment line
// at or after from, or -1 if no such line exists before EOF.
func nextCodeLine(lines []string, isComment []bool, from int) int {
	for j := from; j < len(lines); j++ {
		if strings.TrimSpace(lines[j]) == "" || isComment[j] {
			continue
		}
		return j
	}
	return -1
}

// braceLookahead bounds how many lines past a declaration line this
// detector will scan looking for an opening '{' before concluding the
// declaration uses a different body shape (indentation-based or
// single-line). Real function declarations open their body brace within a
// handful of lines even when the signature wraps across several lines.
const braceLookahead = 5

// extractBody returns the real source lines that make up the body of the
// function/block starting at lines[declIdx], using one of three shapes:
//
//  1. Brace-delimited (Go/Rust/JS/TS/Java/C/...): find the first '{' within
//     braceLookahead lines of declIdx, then track brace depth character by
//     character until it returns to zero — the real matching close brace,
//     not a fixed line-count guess.
//  2. Indentation-delimited (Python/YAML-style, declaration line ends in
//     ':'): every subsequent line indented further than the declaration
//     line belongs to the body; the first equally-or-less-indented
//     non-blank line ends it.
//  3. Single-line: no brace and no trailing colon — the declaration line
//     itself is the whole body (e.g. a one-line arrow function).
func extractBody(lines []string, declIdx int) []string {
	braceLine, braceCol := -1, -1
	for j := declIdx; j < len(lines) && j < declIdx+braceLookahead; j++ {
		if col := strings.IndexByte(lines[j], '{'); col != -1 {
			braceLine, braceCol = j, col
			break
		}
	}

	if braceLine != -1 {
		depth := 0
		endLine := -1
		for j := braceLine; j < len(lines); j++ {
			line := lines[j]
			start := 0
			if j == braceLine {
				start = braceCol
			}
			for k := start; k < len(line); k++ {
				switch line[k] {
				case '{':
					depth++
				case '}':
					depth--
					if depth == 0 {
						endLine = j
					}
				}
			}
			if endLine != -1 {
				break
			}
		}
		if endLine == -1 {
			// Unbalanced braces (e.g. a truncated fixture) — fall back to
			// the rest of the file rather than silently reporting an empty
			// body.
			endLine = len(lines) - 1
		}
		return lines[declIdx : endLine+1]
	}

	if strings.HasSuffix(strings.TrimSpace(lines[declIdx]), ":") {
		declIndent := indentWidth(lines[declIdx])
		end := declIdx
		for j := declIdx + 1; j < len(lines); j++ {
			trimmed := strings.TrimSpace(lines[j])
			if trimmed == "" {
				end = j
				continue
			}
			if indentWidth(lines[j]) > declIndent {
				end = j
				continue
			}
			break
		}
		return lines[declIdx : end+1]
	}

	return lines[declIdx : declIdx+1]
}

// indentWidth returns the number of leading space/tab characters on line.
func indentWidth(line string) int {
	n := 0
	for _, r := range line {
		if r != ' ' && r != '\t' {
			break
		}
		n++
	}
	return n
}

// hasEnforcement reports whether bodyText contains any of the five
// enforcement mechanisms the pattern description names.
func hasEnforcement(bodyText string) bool {
	if enforcementKeywordRe.MatchString(bodyText) {
		return true
	}
	for _, line := range strings.Split(bodyText, "\n") {
		if returnErrRe.MatchString(line) {
			return true
		}
	}
	return false
}

// hasCommentPrefix reports whether a trimmed line starts with one of the
// recognized comment markers.
func hasCommentPrefix(trimmed string) bool {
	for _, prefix := range commentPrefixes {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	return false
}

func init() {
	llmcheat.Register(detector{})
}
