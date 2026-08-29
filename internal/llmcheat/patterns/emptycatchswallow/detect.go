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

// Package emptycatchswallow implements the "empty-catch-swallow" llmcheat
// Pattern: it flags an error/exception handler whose body does nothing to
// actually handle the error — no logging, no re-raise, no recovery, just a
// block that silently discards the failure. This is a very common shape an
// LLM leaves behind when it wraps risky code in a try/catch (or an `if err
// != nil` guard) to make a linter or type-checker happy, without doing any
// real error handling:
//
//   - Python: a bare `except:` or `except Exception:` whose body is only
//     `pass` (a more specific exception type, or a body that does anything
//     beyond `pass`, is out of scope for this pattern).
//   - JavaScript/TypeScript: an empty `catch {}` / `catch (e) {}` block, or
//     a Promise `.catch(() => {})` (or `.catch(err => {})`) whose arrow body
//     is empty.
//   - Go: an `if err != nil { }` block with an empty body.
//
// A body that consists only of comments is treated as equivalent to an
// empty body — a comment is not error handling, and this is exactly the
// shape an LLM produces when it leaves a "// ignore for now" placeholder
// instead of real logic.
package emptycatchswallow

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID       = "empty-catch-swallow"
	patternCategory = "hollow-implementation"
)

// pyExceptRe matches a Python `except:` or `except Exception:` line (and
// nothing more specific — `except ValueError:` etc. is intentionally out of
// scope, per the pattern definition). Group 1 captures the line's leading
// whitespace so the caller can determine the except clause's indentation
// level and, from that, the indentation-delimited extent of its body.
var pyExceptRe = regexp.MustCompile(`^(\s*)except(\s+Exception)?\s*:\s*(#.*)?$`)

// jsCatchKeywordRe finds every standalone `catch` token (word-bounded, so it
// does not match an identifier like `catchAll`) in JS/TS source. Each hit is
// then classified as either a `try { } catch (...) { }` clause or a Promise
// `.catch(...)` call by looking at the character immediately before it.
var jsCatchKeywordRe = regexp.MustCompile(`\bcatch\b`)

// goIfErrRe matches a Go `if err != nil {` guard. The match's end index is
// the position right after the opening brace, which is exactly what the
// brace-matching scan below needs to find the guard's body.
var goIfErrRe = regexp.MustCompile(`\bif\s+err\s*!=\s*nil\s*\{`)

// blockCommentRe and lineCommentRe strip C-style comments (shared by both
// JS/TS and Go) when deciding whether a brace-delimited body is effectively
// empty.
var (
	blockCommentRe = regexp.MustCompile(`(?s)/\*.*?\*/`)
	lineCommentRe  = regexp.MustCompile(`//[^\n]*`)
)

// detector is the real, stateless implementation of llmcheat.Pattern for
// this pattern. It holds no fields because Detect is a pure function of its
// arguments: the type exists only to give the interface methods a receiver.
type detector struct{}

func (detector) ID() string { return patternID }

func (detector) Category() string { return patternCategory }

// Detect scans path's content for a silently-swallowed error/exception,
// dispatching on file extension since each of the three shapes this pattern
// covers is language-specific syntax.
func (d detector) Detect(path string, content []byte) []llmcheat.Match {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".py":
		return detectPython(path, content)
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx":
		return detectJS(path, content)
	case ".go":
		return detectGo(path, content)
	default:
		return nil
	}
}

// detectPython flags every `except:` / `except Exception:` clause whose
// body — once blank lines and comment-only lines are discounted — consists
// solely of a `pass` statement (a trailing inline comment on the `pass`
// line itself, e.g. "pass  # TODO", does not rescue it; it is still just a
// pass).
func detectPython(path string, content []byte) []llmcheat.Match {
	lines := splitLines(content)

	var matches []llmcheat.Match
	for i, line := range lines {
		m := pyExceptRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		exceptIndent := len(leadingWhitespace(line))

		sawStatement := false
		onlyPass := true
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
				// but doesn't disqualify an otherwise-empty body either.
				continue
			}
			sawStatement = true
			if code != "pass" {
				onlyPass = false
			}
		}

		if sawStatement && onlyPass {
			matches = append(matches, llmcheat.Match{
				PatternID: patternID,
				Category:  patternCategory,
				Path:      path,
				Line:      uint(i + 1),
				Message:   "except block silently swallows the exception with only a `pass` statement",
				Severity:  llmcheat.SeverityHigh,
			})
		}
	}
	return matches
}

// detectJS flags every empty `catch { }` / `catch (e) { }` block and every
// empty-bodied Promise `.catch(() => { })` handler.
func detectJS(path string, content []byte) []llmcheat.Match {
	var matches []llmcheat.Match

	for _, loc := range jsCatchKeywordRe.FindAllIndex(content, -1) {
		start, end := loc[0], loc[1]
		isPromiseForm := start > 0 && content[start-1] == '.'

		if isPromiseForm {
			m, ok := detectEmptyPromiseCatch(content, end)
			if ok {
				m.Path = path
				m.Line = uint(lineOf(content, start))
				matches = append(matches, m)
			}
			continue
		}

		m, ok := detectEmptyTryCatch(content, end)
		if ok {
			m.Path = path
			m.Line = uint(lineOf(content, start))
			matches = append(matches, m)
		}
	}
	return matches
}

// detectEmptyTryCatch handles the `catch { }` / `catch (e) { }` shapes.
// afterKeyword is the byte offset in content immediately after the `catch`
// token.
func detectEmptyTryCatch(content []byte, afterKeyword int) (llmcheat.Match, bool) {
	rest := content[afterKeyword:]
	pos := afterKeyword + skipWhitespace(rest)
	if pos >= len(content) {
		return llmcheat.Match{}, false
	}

	if content[pos] == '(' {
		parenClose := findMatchingParen(content, pos)
		if parenClose < 0 {
			return llmcheat.Match{}, false
		}
		after := content[parenClose+1:]
		pos = parenClose + 1 + skipWhitespace(after)
	}

	if pos >= len(content) || content[pos] != '{' {
		return llmcheat.Match{}, false
	}
	braceClose := findMatchingBrace(content, pos)
	if braceClose < 0 {
		return llmcheat.Match{}, false
	}

	if !isEffectivelyEmptyCStyleBody(content[pos+1 : braceClose]) {
		return llmcheat.Match{}, false
	}
	return llmcheat.Match{
		PatternID: patternID,
		Category:  patternCategory,
		Message:   "catch block has an empty body and silently swallows the error",
		Severity:  llmcheat.SeverityHigh,
	}, true
}

// detectEmptyPromiseCatch handles the `.catch(() => { })` / `.catch(err =>
// { })` shape. afterKeyword is the byte offset in content immediately after
// the `catch` token (i.e. pointing at the call's opening parenthesis, once
// whitespace is skipped).
func detectEmptyPromiseCatch(content []byte, afterKeyword int) (llmcheat.Match, bool) {
	rest := content[afterKeyword:]
	parenOpen := afterKeyword + skipWhitespace(rest)
	if parenOpen >= len(content) || content[parenOpen] != '(' {
		return llmcheat.Match{}, false
	}
	parenClose := findMatchingParen(content, parenOpen)
	if parenClose < 0 {
		return llmcheat.Match{}, false
	}

	args := content[parenOpen+1 : parenClose]
	arrowIdx := bytes.Index(args, []byte("=>"))
	if arrowIdx < 0 {
		// Not an arrow-function handler (e.g. a named function reference or
		// a `function (e) { }` expression) — out of scope for this pattern.
		return llmcheat.Match{}, false
	}
	afterArrow := args[arrowIdx+2:]
	wsSkip := skipWhitespace(afterArrow)
	if wsSkip >= len(afterArrow) || afterArrow[wsSkip] != '{' {
		// An arrow with an expression body (no braces), e.g.
		// `.catch(() => doSomething())` — not this pattern's empty-body
		// shape, and not trivially "empty" either way.
		return llmcheat.Match{}, false
	}
	braceOpenAbs := parenOpen + 1 + arrowIdx + 2 + wsSkip
	braceClose := findMatchingBrace(content, braceOpenAbs)
	if braceClose < 0 {
		return llmcheat.Match{}, false
	}

	if !isEffectivelyEmptyCStyleBody(content[braceOpenAbs+1 : braceClose]) {
		return llmcheat.Match{}, false
	}
	return llmcheat.Match{
		PatternID: patternID,
		Category:  patternCategory,
		Message:   "promise .catch() handler has an empty body and silently swallows the rejection",
		Severity:  llmcheat.SeverityHigh,
	}, true
}

// detectGo flags every `if err != nil { }` guard whose body is empty.
func detectGo(path string, content []byte) []llmcheat.Match {
	var matches []llmcheat.Match

	for _, loc := range goIfErrRe.FindAllIndex(content, -1) {
		bracePos := loc[1] - 1 // goIfErrRe's match ends exactly on '{'.
		braceClose := findMatchingBrace(content, bracePos)
		if braceClose < 0 {
			continue
		}
		if !isEffectivelyEmptyCStyleBody(content[bracePos+1 : braceClose]) {
			continue
		}
		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  patternCategory,
			Path:      path,
			Line:      uint(lineOf(content, loc[0])),
			Message:   "if err != nil block is empty and silently swallows the error",
			Severity:  llmcheat.SeverityHigh,
		})
	}
	return matches
}

// isEffectivelyEmptyCStyleBody reports whether body — the content strictly
// between a matched pair of `{` `}` in JS/TS/Go source — contains nothing
// but whitespace and/or C-style comments (`//...` and `/* ... */`). A
// comment-only body counts as empty: a comment is not error handling.
func isEffectivelyEmptyCStyleBody(body []byte) bool {
	s := blockCommentRe.ReplaceAll(body, nil)
	s = lineCommentRe.ReplaceAll(s, nil)
	return len(bytes.TrimSpace(s)) == 0
}

// findMatchingBrace returns the index in content of the `}` that closes the
// `{` at openIdx, using simple depth counting over the raw bytes. This is a
// pragmatic heuristic (it does not understand string/template literals or
// rune/char literals containing brace characters) rather than a full
// tokenizer, which is an acceptable trade-off for a best-effort static
// pattern detector operating on arbitrary source text. Returns -1 if
// openIdx is not a '{' or no matching close is found.
func findMatchingBrace(content []byte, openIdx int) int {
	return findMatching(content, openIdx, '{', '}')
}

// findMatchingParen is findMatchingBrace's sibling for `(` / `)`.
func findMatchingParen(content []byte, openIdx int) int {
	return findMatching(content, openIdx, '(', ')')
}

func findMatching(content []byte, openIdx int, openByte, closeByte byte) int {
	if openIdx < 0 || openIdx >= len(content) || content[openIdx] != openByte {
		return -1
	}
	depth := 0
	for i := openIdx; i < len(content); i++ {
		switch content[i] {
		case openByte:
			depth++
		case closeByte:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// skipWhitespace returns the index of the first non-whitespace byte in b
// (space, tab, newline, or carriage return), or len(b) if b is all
// whitespace.
func skipWhitespace(b []byte) int {
	i := 0
	for i < len(b) {
		switch b[i] {
		case ' ', '\t', '\n', '\r':
			i++
		default:
			return i
		}
	}
	return i
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
