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

// Package pythonhollowfunction implements the "python-hollow-function"
// llmcheat.Pattern: it flags a Python `def name(...):` whose entire body is
// nothing but `pass`, nothing but `...`, or a docstring immediately followed
// by `pass`/`...` and no other statement. That shape is the signature of an
// LLM (or a human under deadline pressure) declaring a function "done" while
// leaving it unimplemented.
//
// Legitimate abstract-method stubs (methods of a class whose declared bases
// look like typing.Protocol, abc.ABC, or a hand-rolled *Interface base) are
// deliberately excluded: an ellipsis body on a Protocol method is the
// idiomatic, correct way to declare an interface method in Python, not a
// cheat signal.
//
// This is a line-oriented heuristic scanner, not a full Python parser (no
// tokenizer, no AST). It tracks class/def nesting purely via indentation,
// which is exactly the signal Python's own grammar uses to delimit blocks,
// so it is accurate for realistic, PEP8-formatted source while remaining a
// small, dependency-free, pure function as required by the llmcheat
// contract.
package pythonhollowfunction

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "python-hollow-function"
	category  = "hollow-implementation"
)

// detector is the unexported Pattern implementation. It carries no state:
// Detect is a pure function of (path, content).
type detector struct{}

func (detector) ID() string       { return patternID }
func (detector) Category() string { return category }

func init() {
	llmcheat.Register(detector{})
}

var (
	classHeaderRe = regexp.MustCompile(`^class\s+[A-Za-z_]\w*`)
	defHeaderRe   = regexp.MustCompile(`^(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(`)
)

// scopeKind distinguishes a class body from a def body on the indentation
// stack used while scanning.
type scopeKind int

const (
	scopeClass scopeKind = iota
	scopeDef
)

// scope is one open (class or def) block on the indentation stack.
type scope struct {
	kind         scopeKind
	indent       int
	abstractLike bool // only meaningful when kind == scopeClass
}

// Detect scans one Python file's content and reports each hollow function
// definition found, skipping methods that are legitimate Protocol/ABC/
// Interface stubs.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	if !strings.EqualFold(filepath.Ext(path), ".py") {
		return nil
	}

	lines := splitLines(string(content))
	var matches []llmcheat.Match
	var stack []scope

	for i := 0; i < len(lines); i++ {
		raw := lines[i]
		stripped := strings.TrimSpace(raw)
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}
		indent := indentWidth(raw)

		// Pop every scope we've dedented out of (or level with — a sibling
		// statement at the same indent closes the previous block).
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}

		if classHeaderRe.MatchString(stripped) {
			bases := extractBases(stripped)
			stack = append(stack, scope{
				kind:         scopeClass,
				indent:       indent,
				abstractLike: looksAbstract(bases),
			})
			continue
		}

		m := defHeaderRe.FindStringSubmatch(stripped)
		if m == nil {
			continue
		}
		funcName := m[1]

		// A method is exempt only when it is a *direct* member of a class
		// body whose bases look abstract — decide this from the stack
		// BEFORE pushing the new def scope, i.e. from the immediate parent.
		inAbstractClass := len(stack) > 0 &&
			stack[len(stack)-1].kind == scopeClass &&
			stack[len(stack)-1].abstractLike

		stack = append(stack, scope{kind: scopeDef, indent: indent})

		parenCol := strings.IndexByte(raw, '(')
		if parenCol == -1 {
			// defHeaderRe requires a '(' in stripped, so this should be
			// unreachable, but fail closed rather than index out of range.
			continue
		}
		headerEndLine, headerEndCol, ok := findHeaderColonEnd(lines, i, parenCol)
		if !ok {
			// Truncated/unterminated signature (e.g. a syntax error, or a
			// file cut off mid-function) — nothing sensible to analyze.
			continue
		}

		inline := ""
		if headerEndCol+1 <= len(lines[headerEndLine]) {
			inline = stripTrailingComment(strings.TrimSpace(lines[headerEndLine][headerEndCol+1:]))
		}

		var statements []string
		if inline != "" {
			statements = []string{inline}
		} else {
			statements = collectBodyStatements(lines, headerEndLine+1, indent)
		}

		if inAbstractClass || !isHollow(statements) {
			continue
		}

		severity := llmcheat.SeverityMedium
		if len(statements) == 2 {
			// A docstring paired with pass/... is the clearest case: the
			// author wrote a description of behavior that was never
			// implemented.
			severity = llmcheat.SeverityHigh
		}

		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      uint(i + 1),
			Message:   "function \"" + funcName + "\" has no real implementation (body is only pass/.../a stub docstring)",
			Severity:  severity,
		})
	}

	return matches
}

// splitLines normalizes CRLF/CR line endings and splits on "\n".
func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.Split(s, "\n")
}

// indentWidth returns the number of leading space/tab characters on a line.
func indentWidth(line string) int {
	n := 0
	for n < len(line) && (line[n] == ' ' || line[n] == '\t') {
		n++
	}
	return n
}

// extractBases returns the raw text inside a class header's base-class
// parentheses, e.g. "Protocol" from "class Foo(Protocol):", or "" if the
// class declares no bases at all.
func extractBases(stripped string) string {
	start := strings.IndexByte(stripped, '(')
	if start == -1 {
		return ""
	}
	depth := 0
	for i := start; i < len(stripped); i++ {
		switch stripped[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return stripped[start+1 : i]
			}
		}
	}
	return stripped[start+1:]
}

// looksAbstract reports whether a base-class list looks like it declares an
// interface-style class: typing.Protocol, abc.ABC / abc.ABCMeta (including
// as a metaclass=... kwarg), or a hand-rolled *Interface base.
func looksAbstract(bases string) bool {
	if bases == "" {
		return false
	}
	lower := strings.ToLower(bases)
	for _, marker := range []string{"protocol", "abc", "interface"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// findHeaderColonEnd walks forward from (startLine, startCol) — which must
// point at the '(' opening a def's parameter list — tracking paren depth
// across possibly multiple physical lines, and returns the position of the
// ':' that actually terminates the function header (the first ':' seen once
// paren depth has returned to 0).
func findHeaderColonEnd(lines []string, startLine, startCol int) (endLine, endCol int, ok bool) {
	depth := 0
	started := false
	for li := startLine; li < len(lines); li++ {
		line := lines[li]
		col := 0
		if li == startLine {
			col = startCol
		}
		for ; col < len(line); col++ {
			switch line[col] {
			case '(':
				depth++
				started = true
			case ')':
				if depth > 0 {
					depth--
				}
			case ':':
				if started && depth == 0 {
					return li, col, true
				}
			}
		}
	}
	return 0, 0, false
}

// stripTrailingComment removes a trailing "# ..." comment from a single
// line of code, respecting simple single/double-quoted strings so a '#'
// inside a string literal isn't mistaken for a comment marker.
func stripTrailingComment(s string) string {
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return strings.TrimSpace(s[:i])
			}
		}
	}
	return strings.TrimSpace(s)
}

// collectBodyStatements walks the indented block starting at line index
// `start` (0-based) whose members all have indent strictly greater than
// headerIndent, and returns one entry per logical statement found. Blank
// lines and full-line comments are skipped entirely (they are never
// statements and never end the block). A multi-line triple-quoted docstring
// collapses to a single "DOCSTRING" entry regardless of how many physical
// lines it spans, so a docstring-then-pass body is correctly seen as
// exactly two statements.
func collectBodyStatements(lines []string, start, headerIndent int) []string {
	var statements []string
	i := start
	for i < len(lines) {
		raw := lines[i]
		stripped := strings.TrimSpace(raw)
		if stripped == "" {
			i++
			continue
		}
		if strings.HasPrefix(stripped, "#") {
			i++
			continue
		}
		if indentWidth(raw) <= headerIndent {
			break
		}

		if quote, rest, isDocStart := docstringOpen(stripped); isDocStart {
			if strings.Contains(rest, quote) {
				// Opens and closes on the same physical line.
				statements = append(statements, "DOCSTRING")
				i++
				continue
			}
			j := i + 1
			for j < len(lines) && !strings.Contains(lines[j], quote) {
				j++
			}
			statements = append(statements, "DOCSTRING")
			if j < len(lines) {
				i = j + 1
			} else {
				i = j
			}
			continue
		}

		statements = append(statements, stripTrailingComment(stripped))
		i++
	}
	return statements
}

// docstringOpen reports whether `stripped` opens a triple-quoted string
// (optionally prefixed with r/u/b/f in any case, e.g. r"""raw docstring"""),
// returning the quote delimiter used and the text following the opening
// delimiter on this same line.
func docstringOpen(stripped string) (quote, rest string, ok bool) {
	prefixLen := 0
	for prefixLen < len(stripped) && prefixLen < 2 && isStringPrefixByte(stripped[prefixLen]) {
		prefixLen++
	}
	rem := stripped[prefixLen:]
	switch {
	case strings.HasPrefix(rem, `"""`):
		return `"""`, rem[3:], true
	case strings.HasPrefix(rem, `'''`):
		return `'''`, rem[3:], true
	default:
		return "", "", false
	}
}

func isStringPrefixByte(b byte) bool {
	switch b {
	case 'r', 'R', 'u', 'U', 'b', 'B', 'f', 'F':
		return true
	default:
		return false
	}
}

// isHollow reports whether a function body's statement list matches one of
// the three hollow shapes: bare "pass", bare "...", or a single docstring
// followed by "pass"/"...".
func isHollow(statements []string) bool {
	switch len(statements) {
	case 1:
		return statements[0] == "pass" || statements[0] == "..."
	case 2:
		return statements[0] == "DOCSTRING" && (statements[1] == "pass" || statements[1] == "...")
	default:
		return false
	}
}
