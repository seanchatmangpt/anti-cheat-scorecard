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

// Package silentdefaultfallbackmasksfailure implements the
// "silent-default-fallback-masks-failure" llmcheat Pattern: it flags a
// fallible operation whose failure is silently converted into a
// successful-looking empty/default result instead of being surfaced to the
// caller. This is a shape an LLM commonly leaves behind when it wants a
// function to "always return something" and reaches for a default-value
// fallback instead of real error propagation:
//
//   - Rust: `.unwrap_or_default()` or `.unwrap_or(Default::default())`
//     called on a `Result`/`Option` — either form discards the `Err`/`None`
//     and substitutes the type's zero value, silently.
//   - Python: an `except Exception:` clause whose entire body is a single
//     `return None`, `return {}`, or `return []` statement — the exception
//     is caught and converted into an empty-but-successful-looking return
//     value instead of being logged, re-raised, or otherwise surfaced.
//   - Go: an `if err != nil { ... }` guard whose `return` statement's last
//     returned value is the literal `nil` — i.e. the function reports a nil
//     error (success) even though `err` was non-nil, discarding the real
//     failure. `if err != nil { return nil, err }` (or any form that
//     returns something other than a literal `nil` in the error position,
//     e.g. `fmt.Errorf("...: %w", err)`) is real error propagation and is
//     not flagged.
package silentdefaultfallbackmasksfailure

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID       = "silent-default-fallback-masks-failure"
	patternCategory = "complexity-and-surface-obfuscation"
)

// rustUnwrapOrDefaultRe matches the Rust `.unwrap_or_default()` method call.
var rustUnwrapOrDefaultRe = regexp.MustCompile(`\.unwrap_or_default\(\s*\)`)

// rustUnwrapOrDefaultCallRe matches the Rust `.unwrap_or(Default::default())`
// method call — the longer-hand spelling of the same fallback.
var rustUnwrapOrDefaultCallRe = regexp.MustCompile(`\.unwrap_or\(\s*Default::default\(\s*\)\s*\)`)

// pyExceptExceptionRe matches a Python `except Exception:` line (a bare
// `except:` or a more specific exception type is intentionally out of scope
// for this pattern, matching the description's exact shape). Group 1
// captures the line's leading whitespace so the caller can determine the
// except clause's indentation level and, from that, the
// indentation-delimited extent of its body.
var pyExceptExceptionRe = regexp.MustCompile(`^(\s*)except\s+Exception\s*:\s*(#.*)?$`)

// pyDefaultReturnRe matches a Python statement (already stripped of any
// trailing inline comment and surrounding whitespace) that returns one of
// the three "empty-but-successful-looking" default values named in the
// pattern description.
var pyDefaultReturnRe = regexp.MustCompile(`^return\s+(None|\{\}|\[\])$`)

// goIfErrRe matches a Go `if err != nil {` guard. The match's end index is
// the position right after the opening brace, which is exactly what the
// brace-matching scan below needs to find the guard's body.
var goIfErrRe = regexp.MustCompile(`\bif\s+err\s*!=\s*nil\s*\{`)

// goReturnKeywordRe finds every standalone `return` token inside a matched
// `if err != nil { ... }` block body.
var goReturnKeywordRe = regexp.MustCompile(`\breturn\b`)

// detector is the real, stateless implementation of llmcheat.Pattern for
// this pattern. It holds no fields because Detect is a pure function of its
// arguments: the type exists only to give the interface methods a receiver.
type detector struct{}

func (detector) ID() string { return patternID }

func (detector) Category() string { return patternCategory }

// Detect scans path's content for a silent default-value fallback that
// masks a real failure, dispatching on file extension since each of the
// three shapes this pattern covers is language-specific syntax.
func (d detector) Detect(path string, content []byte) []llmcheat.Match {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".rs":
		return detectRust(path, content)
	case ".py":
		return detectPython(path, content)
	case ".go":
		return detectGo(path, content)
	default:
		return nil
	}
}

// detectRust flags every `.unwrap_or_default()` and every
// `.unwrap_or(Default::default())` call, either of which silently discards
// a `Result`/`Option`'s failure and substitutes the type's zero value.
func detectRust(path string, content []byte) []llmcheat.Match {
	var matches []llmcheat.Match

	for _, loc := range rustUnwrapOrDefaultRe.FindAllIndex(content, -1) {
		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  patternCategory,
			Path:      path,
			Line:      uint(lineOf(content, loc[0])),
			Message:   "`.unwrap_or_default()` silently discards a Result/Option failure and substitutes a default value instead of surfacing it",
			Severity:  llmcheat.SeverityMedium,
		})
	}
	for _, loc := range rustUnwrapOrDefaultCallRe.FindAllIndex(content, -1) {
		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  patternCategory,
			Path:      path,
			Line:      uint(lineOf(content, loc[0])),
			Message:   "`.unwrap_or(Default::default())` silently discards a Result/Option failure and substitutes a default value instead of surfacing it",
			Severity:  llmcheat.SeverityMedium,
		})
	}
	return matches
}

// detectPython flags every `except Exception:` clause whose body — once
// blank lines and comment-only lines are discounted — consists solely of a
// `return None` / `return {}` / `return []` statement. A body that also
// contains other real statements (e.g. logging the exception before
// returning a default) is not flagged: something is at least surfacing the
// failure somewhere, even if the return value itself is still a default.
func detectPython(path string, content []byte) []llmcheat.Match {
	lines := splitLines(content)

	var matches []llmcheat.Match
	for i, line := range lines {
		m := pyExceptExceptionRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		exceptIndent := len(leadingWhitespace(line))

		sawStatement := false
		onlyDefaultReturn := true
		for j := i + 1; j < len(lines); j++ {
			bodyLine := lines[j]
			if strings.TrimSpace(bodyLine) == "" {
				continue
			}
			indent := len(leadingWhitespace(bodyLine))
			if indent <= exceptIndent {
				// Indentation has returned to (or below) the except
				// clause's own level: the body has ended.
				break
			}
			code := strings.TrimSpace(stripPyLineComment(bodyLine))
			if code == "" {
				// Comment-only body line: doesn't count as real handling,
				// but doesn't disqualify an otherwise-empty-of-substance
				// body either.
				continue
			}
			sawStatement = true
			if !pyDefaultReturnRe.MatchString(code) {
				onlyDefaultReturn = false
			}
		}

		if sawStatement && onlyDefaultReturn {
			matches = append(matches, llmcheat.Match{
				PatternID: patternID,
				Category:  patternCategory,
				Path:      path,
				Line:      uint(i + 1),
				Message:   "except Exception block silently swallows the failure, returning a default/empty value instead of surfacing it",
				Severity:  llmcheat.SeverityHigh,
			})
		}
	}
	return matches
}

// detectGo flags every `if err != nil { ... }` guard whose return
// statement's last returned value is the literal `nil` — i.e. the function
// reports success (a nil error) even though a real error occurred.
func detectGo(path string, content []byte) []llmcheat.Match {
	var matches []llmcheat.Match

	for _, loc := range goIfErrRe.FindAllIndex(content, -1) {
		bracePos := loc[1] - 1 // goIfErrRe's match ends exactly on '{'.
		braceClose := findMatchingBrace(content, bracePos)
		if braceClose < 0 {
			continue
		}
		body := content[bracePos+1 : braceClose]
		if blockHasReturnAllNilLast(body) {
			matches = append(matches, llmcheat.Match{
				PatternID: patternID,
				Category:  patternCategory,
				Path:      path,
				Line:      uint(lineOf(content, loc[0])),
				Message:   "if err != nil block returns a literal nil in the error position, silently masking the real failure instead of surfacing it",
				Severity:  llmcheat.SeverityHigh,
			})
		}
	}
	return matches
}

// blockHasReturnAllNilLast reports whether body — the content strictly
// between a matched pair of `{` `}` following an `if err != nil` guard —
// contains a `return` statement whose last comma-separated returned value
// is the literal identifier `nil`. A statement like `return nil, err` or
// `return nil, fmt.Errorf("...: %w", err)` does not match: its last value
// is not the literal `nil`, so the real error is being propagated.
func blockHasReturnAllNilLast(body []byte) bool {
	for _, loc := range goReturnKeywordRe.FindAllIndex(body, -1) {
		after := body[loc[1]:]

		end := len(after)
		if idx := bytes.IndexByte(after, '\n'); idx >= 0 && idx < end {
			end = idx
		}
		if idx := bytes.IndexByte(after, ';'); idx >= 0 && idx < end {
			end = idx
		}

		stmt := strings.TrimSpace(string(after[:end]))
		if stmt == "" {
			// Bare `return` with no values (e.g. named return values
			// already set) — out of scope for this simple heuristic.
			continue
		}

		parts := splitTopLevelCommas(stmt)
		if len(parts) == 0 {
			continue
		}
		last := strings.TrimSpace(parts[len(parts)-1])
		if last == "nil" {
			return true
		}
	}
	return false
}

// splitTopLevelCommas splits s on commas that are not nested inside
// parentheses, brackets, braces, or a double-quoted string literal. This is
// a pragmatic heuristic (it does not understand rune/backtick literals)
// rather than a full Go tokenizer, which is an acceptable trade-off for a
// best-effort static pattern detector operating on arbitrary source text.
func splitTopLevelCommas(s string) []string {
	var parts []string
	var b strings.Builder
	depth := 0
	inString := false
	escaped := false

	for _, r := range s {
		switch {
		case inString:
			b.WriteRune(r)
			switch {
			case escaped:
				escaped = false
			case r == '\\':
				escaped = true
			case r == '"':
				inString = false
			}
		case r == '"':
			inString = true
			b.WriteRune(r)
		case r == '(' || r == '[' || r == '{':
			depth++
			b.WriteRune(r)
		case r == ')' || r == ']' || r == '}':
			depth--
			b.WriteRune(r)
		case r == ',' && depth == 0:
			parts = append(parts, b.String())
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	parts = append(parts, b.String())
	return parts
}

// findMatchingBrace returns the index in content of the `}` that closes the
// `{` at openIdx, using simple depth counting over the raw bytes. This is a
// pragmatic heuristic (it does not understand string/rune literals
// containing brace characters) rather than a full tokenizer, which is an
// acceptable trade-off for a best-effort static pattern detector operating
// on arbitrary source text. Returns -1 if openIdx is not a '{' or no
// matching close is found.
func findMatchingBrace(content []byte, openIdx int) int {
	if openIdx < 0 || openIdx >= len(content) || content[openIdx] != '{' {
		return -1
	}
	depth := 0
	for i := openIdx; i < len(content); i++ {
		switch content[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// lineOf returns the 1-based line number of byte offset idx within content.
func lineOf(content []byte, idx int) int {
	if idx > len(content) {
		idx = len(content)
	}
	if idx < 0 {
		idx = 0
	}
	return bytes.Count(content[:idx], []byte("\n")) + 1
}

// splitLines splits content into lines on "\n", first normalizing "\r\n" so
// callers never see a trailing "\r" on a line.
func splitLines(content []byte) []string {
	s := strings.ReplaceAll(string(content), "\r\n", "\n")
	return strings.Split(s, "\n")
}

// leadingWhitespace returns the leading run of spaces/tabs on line.
func leadingWhitespace(line string) string {
	i := 0
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	return line[:i]
}

// stripPyLineComment returns line with everything from the first '#' onward
// removed. This is a pragmatic heuristic (it does not account for a '#'
// appearing inside a string literal) rather than a full Python tokenizer,
// which is an acceptable trade-off for a best-effort static pattern
// detector operating on arbitrary source text.
func stripPyLineComment(line string) string {
	if idx := strings.IndexByte(line, '#'); idx >= 0 {
		return line[:idx]
	}
	return line
}

func init() {
	llmcheat.Register(detector{})
}
