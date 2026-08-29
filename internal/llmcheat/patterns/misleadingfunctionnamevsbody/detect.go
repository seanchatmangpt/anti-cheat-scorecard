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

// Package misleadingfunctionnamevsbody implements the
// "misleading-function-name-vs-body" llmcheat.Pattern: it flags a function
// named verify*/validate*/check*/ensure* (any casing, any of the four
// prefixes) whose real body contains no conditional keyword (if/match/
// switch/case), no ternary (`cond ? a : b`), and no comparison operator
// (==, !=, <, >, <=, >=) anywhere. That combination — a name that promises a
// decision the body structurally never makes — is the signature of a
// function an LLM (or a human under deadline pressure) wrote to look like
// real validation logic while actually just logging, calling out, or
// unconditionally returning a fixed value.
//
// This is a line/character-oriented heuristic scanner, not a compiler
// front end for any single language. It deliberately supports the two
// function-body delimiting conventions that cover the large majority of
// mainstream languages:
//
//   - brace-delimited bodies (Go, Rust, Java, C#, C/C++, JavaScript/
//     TypeScript, Kotlin, Swift, PHP, ...) — the body is the balanced
//     {...} block following the parameter list (and any return-type
//     annotation) on the header.
//   - Python-style colon+indentation bodies — the header line ends with
//     ':' and the body is the block of more-indented lines that follows.
//
// Function *headers* are recognized via a small ordered set of per-language
// signature shapes (Python/Ruby `def`, Rust `fn`, Go/Swift `func`, Kotlin
// `fun`, JS/TS `function` declarations and `const x = (...) => {`-style
// arrow assignments, PHP `function`, and a generic
// "<modifiers> <ReturnType> name(...)" shape for Java/C#/Kotlin/C++-style
// methods that use no defining keyword at all). Two things keep this both
// honest and safe against false positives despite that breadth:
//
//  1. Only identifiers matching the target name prefixes are ever
//     considered a candidate in the first place — a plain call site or
//     control-flow keyword captured by the broad structural regexes is
//     discarded here before anything else happens.
//  2. A candidate is only ever reported if a REAL body was actually found
//     (a balanced brace block, or a genuinely more-indented Python block).
//     A bare declaration/prototype ending in ';' with no block, or a call
//     statement that never opens a body at all, has nothing to judge and is
//     silently skipped rather than flagged — this is the deliberate
//     "allowlisted exception" for interface/abstract-method declarations.
//
// Once a body is isolated, the conditional/comparison check is intentionally
// a plain textual scan of that body text (matching the pattern description's
// own wording: "anywhere" in the body) — not a semantic evaluation. A call
// like `re.match(...)` inside the body counts as a "conditional" textually
// present, same as an actual `match` statement would; this is a known,
// accepted source of under-flagging (fewer false accusations) rather than
// over-flagging, consistent with a heuristic anti-cheat scanner.
//
// Known, deliberate scope limits (documented rather than silently wrong):
// Ruby's `def ... end` block delimiter is not specifically supported (a
// Ruby `def` header is recognized, but since it has neither a trailing
// colon nor a brace, no body is found and the candidate is safely skipped
// — missed coverage, not a false positive). C++ scoped method definitions
// (`Type Class::method(...)`) and multi-word primitive return types
// (`unsigned long foo(...)`) are not matched by the generic OOP header
// shape, which only supports a single-token return type before the name.
package misleadingfunctionnamevsbody

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "misleading-function-name-vs-body"
	category  = "complexity-and-surface-obfuscation"

	// maxTerminatorScan bounds how far past a parameter list's closing ')'
	// we look for the body's opening '{' or a Python-style trailing ':'
	// before giving up. Generous enough for any realistic signature
	// (including multi-line return-type/generic clauses) while keeping a
	// malformed or truncated file from causing an unbounded scan.
	maxTerminatorScan = 4000
)

// detector is the unexported Pattern implementation. It carries no state:
// Detect is a pure function of (path, content).
type detector struct{}

func (detector) ID() string       { return patternID }
func (detector) Category() string { return category }

func init() {
	llmcheat.Register(detector{})
}

// headerPatterns recognizes a function/method definition header across
// several mainstream language shapes, each anchored to the start of a
// (possibly indented) line so a nested call or condition expression is
// never mistaken for a definition. Tried in order; the first pattern that
// matches at a given line position wins over any broader pattern later in
// the list that might also match the same position (see findHeaders).
var headerPatterns = []*regexp.Regexp{
	// Python / Ruby: def name(...):
	regexp.MustCompile(`(?m)^[ \t]*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(`),
	// Rust: fn name(...) -> T {
	regexp.MustCompile(`(?m)^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:default\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+"[^"]*"\s+)?fn\s+([A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*\(`),
	// Go / Swift: func name(...) or func (recv Type) name(...)
	regexp.MustCompile(`(?m)^[ \t]*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*\(`),
	// Kotlin: [modifiers] fun name(...)
	regexp.MustCompile(`(?m)^[ \t]*(?:(?:public|private|protected|internal|open|override|suspend|inline)\s+)*fun\s+([A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*\(`),
	// JS/TS function declarations: [export] [default] [async] function name(...)
	regexp.MustCompile(`(?m)^[ \t]*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s+([A-Za-z_$][\w$]*)\s*\(`),
	// JS/TS arrow/function assigned to const/let/var: const name = (...) => {
	regexp.MustCompile(`(?m)^[ \t]*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]*?)?=\s*(?:async\s*)?\(`),
	// PHP: [modifiers] function name(...)
	regexp.MustCompile(`(?m)^[ \t]*(?:(?:public|private|protected|static|final|abstract)\s+)*function\s+(?:&\s*)?([A-Za-z_]\w*)\s*\(`),
	// Generic OOP method with a single-token return type and no defining
	// keyword (Java, C#, Kotlin-alt, simple C/C++): [modifiers] Type name(...)
	regexp.MustCompile(`(?m)^[ \t]*(?:(?:public|private|protected|internal|static|final|virtual|override|abstract|synchronized|inline|constexpr|async|extern)\s+)*[A-Za-z_]\w*(?:<[^>()]*>)?(?:\[\])?\s+([A-Za-z_]\w*)\s*\(`),
}

// namePrefixRe matches an identifier that "reads" as a decision-maker:
// verify*, validate*, check*, or ensure*, case-insensitively, anywhere the
// name starts with one of those words.
var namePrefixRe = regexp.MustCompile(`(?i)^(?:verify|validate|check|ensure)`)

// Body-content scan: intentionally a plain textual match over the isolated
// body text (see the package doc's "textual scan" note), not a semantic
// parse.
var (
	conditionalRe = regexp.MustCompile(`\b(?:if|match|switch|case)\b`)
	ternaryRe     = regexp.MustCompile(`\?[^:?]*:`)
	comparisonRe  = regexp.MustCompile(`==|!=|<=|>=`)
	// bareRelRe catches a lone < or > used as a comparison (e.g. "x > 0"),
	// while excluding it when immediately adjacent to characters that make
	// it part of ->, <-, <<, >>, <=, >=, ==, or != instead.
	bareRelRe = regexp.MustCompile(`[^<>=!\-](?:<|>)[^<>=\-]`)
)

// Detect scans one file's content for functions named like decision-makers
// whose real body never actually branches or compares anything.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	src := normalizeNewlines(string(content))
	if strings.TrimSpace(src) == "" {
		return nil
	}

	lines := strings.Split(src, "\n")
	lineStarts := make([]int, len(lines))
	offset := 0
	for i, l := range lines {
		lineStarts[i] = offset
		offset += len(l) + 1
	}

	var matches []llmcheat.Match

	for _, h := range findHeaders(src) {
		if !namePrefixRe.MatchString(h.name) {
			continue
		}
		if h.parenOpen < 0 || h.parenOpen >= len(src) || src[h.parenOpen] != '(' {
			continue
		}

		parenClose, ok := matchParen(src, h.parenOpen)
		if !ok {
			continue
		}
		afterParen := parenClose + 1

		isBrace, bodyMarker, ok := findBodyStart(src, afterParen)
		if !ok {
			// No balanced '{' and no Python-style trailing ':' found — a
			// bare declaration/prototype (or a call statement) with no
			// body to judge. Nothing to flag.
			continue
		}

		var bodyText string
		headerLineIdx := lineIndexForOffset(lineStarts, h.start)

		if isBrace {
			bodyClose, ok := findMatchingBrace(src, bodyMarker)
			if !ok {
				continue
			}
			bodyText = src[bodyMarker+1 : bodyClose]
		} else {
			colonLineIdx := lineIndexForOffset(lineStarts, bodyMarker)
			headerIndent := indentWidth(lines[headerLineIdx])
			bodyText = collectPythonBody(lines, colonLineIdx+1, headerIndent)
		}

		if strings.TrimSpace(bodyText) == "" {
			// An empty body (nothing at all) has no decision logic to
			// speak of but also nothing to meaningfully report against —
			// treat like a declaration-only case.
			continue
		}

		if conditionalRe.MatchString(bodyText) || ternaryRe.MatchString(bodyText) {
			continue
		}
		if comparisonRe.MatchString(bodyText) || bareRelRe.MatchString(bodyText) {
			continue
		}

		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      uint(headerLineIdx + 1),
			Message: fmt.Sprintf(
				"function %q is named like a decision-maker (verify/validate/check/ensure) "+
					"but its body contains no conditional and no comparison operator anywhere",
				h.name,
			),
			Severity: severityFor(bodyText),
		})
	}

	return matches
}

// headerMatch is one recognized function-definition header.
type headerMatch struct {
	start     int // byte offset where the header match begins (start of line)
	name      string
	parenOpen int // byte offset of the parameter list's opening '('
}

// findHeaders runs every headerPatterns regex over the whole file and
// returns one headerMatch per distinct start offset, preferring whichever
// pattern is earliest in headerPatterns when more than one matches the same
// position (e.g. the generic OOP fallback also structurally matching a
// `def name(...)` line that the dedicated Python pattern already claimed).
func findHeaders(src string) []headerMatch {
	type candidate struct {
		start, parenOpen, priority int
		name                       string
	}
	var all []candidate
	for pi, re := range headerPatterns {
		for _, m := range re.FindAllStringSubmatchIndex(src, -1) {
			if len(m) < 4 || m[2] < 0 {
				continue
			}
			all = append(all, candidate{
				start:     m[0],
				parenOpen: m[1] - 1,
				name:      src[m[2]:m[3]],
				priority:  pi,
			})
		}
	}

	sort.Slice(all, func(i, j int) bool {
		if all[i].start != all[j].start {
			return all[i].start < all[j].start
		}
		return all[i].priority < all[j].priority
	})

	var out []headerMatch
	lastStart := -1
	for _, c := range all {
		if c.start == lastStart {
			continue
		}
		out = append(out, headerMatch{start: c.start, name: c.name, parenOpen: c.parenOpen})
		lastStart = c.start
	}
	return out
}

// matchParen returns the offset of the ')' that balances the '(' at
// src[openIdx], skipping over any characters inside string/char/backtick
// literals so a paren-like character inside a default-value string doesn't
// throw off the depth count.
func matchParen(src string, openIdx int) (closeIdx int, ok bool) {
	depth := 0
	i := openIdx
	for i < len(src) {
		c := src[i]
		switch c {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i, true
			}
		case '"', '\'', '`':
			i = skipStringLiteral(src, i)
			continue
		}
		i++
	}
	return 0, false
}

// skipStringLiteral returns the offset just past the string/char literal
// that starts at src[start] (src[start] must be a quote character),
// honoring backslash escapes.
func skipStringLiteral(src string, start int) int {
	quote := src[start]
	i := start + 1
	for i < len(src) {
		if src[i] == '\\' && i+1 < len(src) {
			i += 2
			continue
		}
		if src[i] == quote {
			return i + 1
		}
		i++
	}
	return i
}

// findBodyStart scans forward from just after a parameter list's closing
// ')' for the first sign of a real function body: a '{' (brace-delimited
// body — isBrace=true, marker = offset of that '{'), or a physical line
// that — once a trailing '#'/'//' comment is stripped — ends with ':' with
// no '{' found first (Python-style body — isBrace=false, marker = offset
// of the newline ending that header line). A ';' encountered before either
// means a bare declaration/prototype with no body at all: ok=false.
func findBodyStart(src string, afterParen int) (isBrace bool, marker int, ok bool) {
	limit := afterParen + maxTerminatorScan
	if limit > len(src) {
		limit = len(src)
	}

	lastNewline := afterParen - 1
	i := afterParen
	for i < limit {
		c := src[i]
		switch {
		case c == '{':
			return true, i, true
		case c == ';':
			return false, 0, false
		case c == '"' || c == '\'' || c == '`':
			i = skipStringLiteral(src, i)
			continue
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			i += 2
			for i+1 < len(src) && !(src[i] == '*' && src[i+1] == '/') {
				i++
			}
			i += 2
			continue
		case c == '\n':
			line := strings.TrimSpace(stripLineComment(src[lastNewline+1 : i]))
			if strings.HasSuffix(line, ":") {
				return false, i, true
			}
			lastNewline = i
		}
		i++
	}
	return false, 0, false
}

// stripLineComment trims a trailing "#..." or "//..." comment from a
// single-line text segment. String literals within the header's return-type
// clause were already skipped during the character scan in findBodyStart,
// so a '#' or "//" reaching here is a real comment marker in the
// overwhelming common case.
func stripLineComment(s string) string {
	if idx := strings.Index(s, "#"); idx >= 0 {
		s = s[:idx]
	}
	if idx := strings.Index(s, "//"); idx >= 0 {
		s = s[:idx]
	}
	return s
}

// findMatchingBrace returns the offset of the '}' that balances the '{' at
// src[openIdx], skipping string/char/backtick literals and // and /* */
// comments so a brace-like character inside either doesn't throw off depth.
func findMatchingBrace(src string, openIdx int) (closeIdx int, ok bool) {
	depth := 0
	i := openIdx
	for i < len(src) {
		c := src[i]
		switch {
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				return i, true
			}
		case c == '"' || c == '\'' || c == '`':
			i = skipStringLiteral(src, i)
			continue
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			i += 2
			for i+1 < len(src) && !(src[i] == '*' && src[i+1] == '/') {
				i++
			}
			i += 2
			continue
		}
		i++
	}
	return 0, false
}

// collectPythonBody concatenates the raw text of every line, starting at
// line index `start`, whose indentation is strictly greater than
// headerIndent — the same "more indented than the header" rule Python's own
// grammar uses to delimit a block. Blank lines don't end the block; the
// first non-blank line at or below headerIndent does.
func collectPythonBody(lines []string, start, headerIndent int) string {
	var sb strings.Builder
	for i := start; i < len(lines); i++ {
		raw := lines[i]
		if strings.TrimSpace(raw) == "" {
			sb.WriteByte('\n')
			continue
		}
		if indentWidth(raw) <= headerIndent {
			break
		}
		sb.WriteString(raw)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// indentWidth returns the number of leading space/tab characters on a line.
func indentWidth(line string) int {
	n := 0
	for n < len(line) && (line[n] == ' ' || line[n] == '\t') {
		n++
	}
	return n
}

// lineIndexForOffset returns the 0-based index of the line containing byte
// offset in src, given starts[i] = the byte offset where lines[i] begins.
func lineIndexForOffset(starts []int, offset int) int {
	lo, hi := 0, len(starts)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if starts[mid] <= offset {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	if lo < 0 {
		return 0
	}
	return lo
}

// normalizeNewlines collapses CRLF/CR line endings to plain "\n" so every
// downstream offset/line computation only has to deal with one convention.
func normalizeNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return s
}

// severityFor grades how obviously hollow a flagged body is: a body with at
// most two non-blank lines (e.g. a single log call plus a fixed return) is
// the clearest case of a decision-shaped name over a decision-free body.
func severityFor(bodyText string) llmcheat.Severity {
	n := 0
	for _, l := range strings.Split(bodyText, "\n") {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	if n <= 2 {
		return llmcheat.SeverityHigh
	}
	return llmcheat.SeverityMedium
}
