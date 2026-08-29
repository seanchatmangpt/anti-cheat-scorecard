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

// Package contractsignaturedrift implements the "contract-signature-drift"
// llmcheat.Pattern: it flags a Python function whose docstring documents a
// parameter — via a Sphinx-style `:param name:` directive or a Google-style
// `Args:`/`Arguments:`/`Parameters:` block — that does not actually appear
// in the function's own `def name(...):` parameter list. That mismatch is
// exactly the shape an LLM (or a human editing in a hurry) leaves behind
// when it rewrites a function's signature but never goes back to update the
// docstring's claimed contract, or vice versa: the documented contract and
// the real, callable signature disagree, and any caller or reader trusting
// the docstring is trusting a lie about what the function actually accepts.
//
// A function whose signature declares a `**kwargs`-shaped catch-all
// parameter is deliberately exempted: documenting individual accepted
// keyword names inside a `**kwargs` docstring block (a common, legitimate
// Google-style convention) can never literally match the bare `**kwargs`
// token in the signature, so flagging it would be a guaranteed false
// positive rather than a real contract drift.
//
// This is a line-oriented heuristic scanner, not a full Python parser (no
// tokenizer, no AST) — it locates `def`/`async def` headers with a regexp,
// walks bracket depth to recover the raw parameter-list text (which may
// span multiple physical lines), and walks the docstring immediately
// following the header line by line. That is enough to be accurate on
// realistic, PEP8-formatted source while remaining a small, dependency-free,
// pure function as required by the llmcheat contract.
package contractsignaturedrift

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "contract-signature-drift"
	category  = "determinism-and-provenance-violation"
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
	defHeaderRe = regexp.MustCompile(`^(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(`)

	// argsHeaderRe matches a Google/NumPy-style docstring section header
	// that introduces a parameter list, alone on its own logical line.
	argsHeaderRe = regexp.MustCompile(`(?i)^(?:args|arguments|parameters)\s*:$`)

	// sectionHeaderRe matches any other well-known docstring section
	// header, used to know when a preceding Args:-style block has ended.
	sectionHeaderRe = regexp.MustCompile(`(?i)^(?:returns?|raises?|yields?|notes?|examples?|attributes?|todo|warnings?|see also|references)\s*:$`)

	// paramLineRe matches one Google/NumPy-style documented-parameter
	// entry, e.g. "data: input" or "data (int): input", capturing the name.
	paramLineRe = regexp.MustCompile(`^([A-Za-z_]\w*)\s*(?:\([^)]*\))?\s*:`)

	// sphinxParamRe matches a Sphinx-style ":param [type] name:" directive,
	// capturing everything between "param" and the terminating ":" — the
	// parameter name is the last whitespace-separated token of that group,
	// since an optional type may precede it (":param str name:").
	sphinxParamRe = regexp.MustCompile(`^:param\s+(.+?)\s*:`)
)

// docLine is one physical (or delimiter-trimmed) line of docstring content,
// paired with the real 1-based source line number it came from so matches
// can be anchored at the exact line the drifted name was documented on.
type docLine struct {
	lineNo uint
	text   string
}

// documentedParam is one parameter name found documented in a docstring,
// paired with the source line it was documented on.
type documentedParam struct {
	name   string
	lineNo uint
}

// Detect scans one Python file's content and reports each function whose
// docstring documents a parameter name absent from its real signature.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	if !strings.EqualFold(filepath.Ext(path), ".py") {
		return nil
	}

	lines := splitLines(string(content))
	var matches []llmcheat.Match

	for i := 0; i < len(lines); i++ {
		raw := lines[i]
		stripped := strings.TrimSpace(raw)
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}

		m := defHeaderRe.FindStringSubmatch(stripped)
		if m == nil {
			continue
		}
		funcName := m[1]

		parenCol := strings.IndexByte(raw, '(')
		if parenCol == -1 {
			// defHeaderRe requires a '(' in stripped, so this should be
			// unreachable, but fail closed rather than index out of range.
			continue
		}

		paramsText, headerEndLine, headerEndCol, ok := extractSignature(lines, i, parenCol)
		if !ok {
			// Truncated/unterminated signature — nothing sensible to
			// analyze.
			continue
		}
		actualParams, hasKwargsCatchAll := parseParamNames(paramsText)
		if hasKwargsCatchAll {
			// A **kwargs catch-all legitimately absorbs documented names
			// that can never literally appear in the signature — see the
			// package doc comment. Nothing to flag for this function.
			continue
		}

		docLines, ok := findDocstring(lines, headerEndLine, headerEndCol)
		if !ok {
			// No docstring immediately follows this def — nothing to
			// compare the signature against.
			continue
		}

		for _, dp := range extractDocumentedParams(docLines) {
			if actualParams[dp.name] {
				continue
			}
			matches = append(matches, llmcheat.Match{
				PatternID: patternID,
				Category:  category,
				Path:      path,
				Line:      dp.lineNo,
				Message: fmt.Sprintf(
					"function %q docstring documents parameter %q, which does not appear in its actual def %s(...) signature",
					funcName, dp.name, funcName,
				),
				Severity: llmcheat.SeverityMedium,
			})
		}
	}

	return matches
}

// splitLines normalizes CRLF/CR line endings and splits on "\n".
func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.Split(s, "\n")
}

// extractSignature walks forward from (defLine, openParenCol) — which must
// point at the '(' opening a def's parameter list — tracking bracket depth
// (across '(', '[', '{' and their closers) across possibly multiple
// physical lines, and returns the raw text between the outer parens plus
// the position of the ':' that terminates the function header (the first
// ':' seen once the outer paren has closed).
func extractSignature(lines []string, defLine, openParenCol int) (paramsText string, headerEndLine, headerEndCol int, ok bool) {
	var sb strings.Builder
	depth := 1
	li := defLine
	col := openParenCol + 1
	for li < len(lines) {
		line := lines[li]
		for ; col < len(line); col++ {
			ch := line[col]
			switch ch {
			case '(', '[', '{':
				depth++
				sb.WriteByte(ch)
			case ')', ']', '}':
				depth--
				if depth == 0 {
					cLine, cCol, found := findColonFrom(lines, li, col+1)
					if !found {
						return "", 0, 0, false
					}
					return sb.String(), cLine, cCol, true
				}
				sb.WriteByte(ch)
			default:
				sb.WriteByte(ch)
			}
		}
		sb.WriteByte('\n')
		li++
		col = 0
	}
	return "", 0, 0, false
}

// findColonFrom scans forward from (li, col) for the next ':' character,
// used to find a function header's terminating colon once its parameter
// list has closed (anything between the closing ')' and the ':' is just a
// "-> ReturnType" annotation and/or whitespace).
func findColonFrom(lines []string, li, col int) (int, int, bool) {
	for ; li < len(lines); li++ {
		line := lines[li]
		for ; col < len(line); col++ {
			if line[col] == ':' {
				return li, col, true
			}
		}
		col = 0
	}
	return 0, 0, false
}

// parseParamNames splits a raw parameter-list text (as returned by
// extractSignature) into the set of real parameter names it declares, and
// separately reports whether any parameter is a "**kwargs"-shaped
// catch-all.
func parseParamNames(paramsText string) (names map[string]bool, hasKwargsCatchAll bool) {
	names = map[string]bool{}
	for _, part := range splitTopLevelCommas(paramsText) {
		token := strings.TrimSpace(part)
		if token == "" || token == "*" || token == "/" {
			continue
		}
		if strings.HasPrefix(token, "**") {
			hasKwargsCatchAll = true
		}
		name := leadingIdentifier(strings.TrimLeft(token, "*"))
		if name != "" {
			names[name] = true
		}
	}
	return names, hasKwargsCatchAll
}

// splitTopLevelCommas splits s on commas that are not nested inside
// parens/brackets/braces (for default values or type annotations like
// "Dict[str, int]") and not inside a quoted string literal (for a default
// value like "sep=', '").
func splitTopLevelCommas(s string) []string {
	var parts []string
	depth := 0
	start := 0
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case inSingle || inDouble:
			// inside a string literal: structural characters below don't
			// count.
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		case c == ',' && depth == 0:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// leadingIdentifier returns the leading Python identifier at the start of
// s, or "" if s does not begin with one.
func leadingIdentifier(s string) string {
	i := 0
	for i < len(s) {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || (i > 0 && c >= '0' && c <= '9') {
			i++
			continue
		}
		break
	}
	return s[:i]
}

// findDocstring looks for a triple-quoted docstring that is the first
// statement of the function body starting right after the header's
// terminating colon (either inline on the same physical line, or as the
// first non-blank, non-comment line that follows), and returns its content
// as a sequence of logical lines each paired with its real source line
// number.
func findDocstring(lines []string, headerEndLine, headerEndCol int) ([]docLine, bool) {
	bodyLine := headerEndLine
	var candidate string

	if headerEndCol+1 <= len(lines[headerEndLine]) {
		inline := strings.TrimSpace(lines[headerEndLine][headerEndCol+1:])
		if inline != "" && !strings.HasPrefix(inline, "#") {
			candidate = inline
		}
	}
	if candidate == "" {
		found := false
		for li := headerEndLine + 1; li < len(lines); li++ {
			stripped := strings.TrimSpace(lines[li])
			if stripped == "" || strings.HasPrefix(stripped, "#") {
				continue
			}
			bodyLine = li
			candidate = stripped
			found = true
			break
		}
		if !found {
			return nil, false
		}
	}

	quote, rest, isDocStart := docstringOpen(candidate)
	if !isDocStart {
		return nil, false
	}

	if idx := strings.Index(rest, quote); idx != -1 {
		// Opens and closes on the same logical line.
		return []docLine{{lineNo: uint(bodyLine + 1), text: rest[:idx]}}, true
	}

	out := []docLine{{lineNo: uint(bodyLine + 1), text: rest}}
	for li := bodyLine + 1; li < len(lines); li++ {
		if idx := strings.Index(lines[li], quote); idx != -1 {
			out = append(out, docLine{lineNo: uint(li + 1), text: lines[li][:idx]})
			return out, true
		}
		out = append(out, docLine{lineNo: uint(li + 1), text: lines[li]})
	}
	// Unterminated docstring (truncated file); use what was collected.
	return out, true
}

// docstringOpen reports whether s opens a triple-quoted string (optionally
// prefixed with r/u/b/f in any case, e.g. r"""raw docstring"""), returning
// the quote delimiter used and the text following the opening delimiter.
func docstringOpen(s string) (quote, rest string, ok bool) {
	prefixLen := 0
	for prefixLen < len(s) && prefixLen < 2 && isStringPrefixByte(s[prefixLen]) {
		prefixLen++
	}
	rem := s[prefixLen:]
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

// leadingSpaceCount counts the leading space/tab characters of s (each
// counted as one column of indentation), used to find the baseline
// indentation of a Google-style Args: block's parameter entries.
func leadingSpaceCount(s string) int {
	n := 0
	for n < len(s) && (s[n] == ' ' || s[n] == '\t') {
		n++
	}
	return n
}

// extractDocumentedParams scans a docstring's logical lines for every
// documented parameter name, from both a Sphinx-style ":param name:"
// directive (which may appear anywhere) and a Google/NumPy-style
// "Args:"/"Arguments:"/"Parameters:" block (whose entries are recognized by
// matching the block's own first-entry indentation, ending at a blank line,
// a dedent, or another recognized section header).
func extractDocumentedParams(lines []docLine) []documentedParam {
	var out []documentedParam
	i := 0
	for i < len(lines) {
		trimmed := strings.TrimSpace(lines[i].text)

		if argsHeaderRe.MatchString(trimmed) {
			i++
			baseIndent := -1
			for i < len(lines) {
				text := lines[i].text
				inner := strings.TrimSpace(text)
				if inner == "" {
					i++
					break
				}
				indent := leadingSpaceCount(text)
				if baseIndent == -1 {
					baseIndent = indent
				}
				if indent < baseIndent || sectionHeaderRe.MatchString(inner) {
					break
				}
				if indent == baseIndent {
					if m := paramLineRe.FindStringSubmatch(inner); m != nil {
						out = append(out, documentedParam{name: m[1], lineNo: lines[i].lineNo})
					}
				}
				i++
			}
			continue
		}

		if m := sphinxParamRe.FindStringSubmatch(trimmed); m != nil {
			out = append(out, documentedParam{name: lastToken(m[1]), lineNo: lines[i].lineNo})
		}
		i++
	}
	return out
}

// lastToken returns the last whitespace-separated token of s, used to pull
// the parameter name out of a Sphinx ":param [type] name:" capture group
// where an optional type may precede the name.
func lastToken(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}
