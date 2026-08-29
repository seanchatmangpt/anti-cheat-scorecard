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

// Package godfunctionhidesstub implements the "god-function-hides-stub"
// llmcheat.Pattern.
//
// It looks for a Go/Python/Rust/TypeScript top-level function whose line
// count towers over its file's other top-level functions — more than 4x
// the file's median top-level function line count — while its real (non-
// blank, non-comment) line count is under 20% of its own total line count.
// That combination is the shape an LLM (or a human papering over unfinished
// work) leaves behind when a function is padded out with narrated-but-not-
// implemented steps, removed-feature commentary, or other comment/blank
// filler: it *looks* enormous and important next to its siblings, but most
// of that size is not real logic. The 5-function-minimum gate exists
// specifically so a tiny file with one naturally long function (and nothing
// to compare it against) never trips this heuristic — "disproportionate"
// requires real siblings to be disproportionate relative to.
//
// This is a line- and bracket-oriented heuristic scanner, not a full parser
// for any of the four languages: it locates each language's top-level
// (column-0) function-declaration keyword, then walks forward skipping over
// string/char/backtick literals and // and /* */ comments to find the
// parameter list and the function body's matching brace pair (Go/Rust/
// TypeScript) or its indented block (Python). "Top-level" is deliberately
// literal — column 0 — so Go methods (written at column 0 in Go) are
// included, while Rust/TypeScript impl-block and class methods and any
// language's nested/closure functions are not: those live at deeper
// indentation and are a different comparison population than a file's
// free-standing functions.
package godfunctionhidesstub

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "god-function-hides-stub"
	category  = "complexity-and-surface-obfuscation"

	// minFunctionsForSignal is the smallest number of top-level functions a
	// file must have before "disproportionate relative to the median" means
	// anything at all.
	minFunctionsForSignal = 5
	// lineCountMultiplier is how many times the file's median top-level
	// function line count a function's own line count must exceed.
	lineCountMultiplier = 4.0
	// realContentRatioMax is the non-comment/non-blank share of a flagged
	// function's lines that must stay strictly below this fraction.
	realContentRatioMax = 0.20
)

// detector is the unexported Pattern implementation. It carries no state:
// Detect is a pure function of (path, content).
type detector struct{}

func (detector) ID() string       { return patternID }
func (detector) Category() string { return category }

func init() {
	llmcheat.Register(detector{})
}

// language is one of the four source languages this pattern understands.
type language int

const (
	langUnknown language = iota
	langGo
	langPython
	langRust
	langTypeScript
)

func languageFor(path string) language {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go":
		return langGo
	case ".py":
		return langPython
	case ".rs":
		return langRust
	case ".ts", ".tsx":
		return langTypeScript
	default:
		return langUnknown
	}
}

// funcSpan is one top-level function's full line extent within a file,
// header line through its last body line, inclusive.
type funcSpan struct {
	name  string
	start uint
	end   uint
}

func (f funcSpan) lineCount() int { return int(f.end-f.start) + 1 }

var (
	goHeaderRe   = regexp.MustCompile(`(?m)^func\s+(?:\([^()]*\)\s+)?([A-Za-z_]\w*)`)
	rustHeaderRe = regexp.MustCompile(
		`(?m)^(?:pub(?:\([^()]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+"[^"]*"\s+)?fn\s+([A-Za-z_]\w*)`,
	)
	tsHeaderRe = regexp.MustCompile(`(?m)^(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s+([A-Za-z_$][\w$]*)`)
	pyHeaderRe = regexp.MustCompile(`^(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(`)
)

// Detect scans one file's content and reports each top-level function that
// is both far longer than its file's other top-level functions and mostly
// non-real (comment/blank) lines.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	lang := languageFor(path)
	if lang == langUnknown {
		return nil
	}

	normalized := normalizeNewlines(string(content))
	lines := strings.Split(normalized, "\n")

	var spans []funcSpan
	switch lang {
	case langGo:
		spans = extractBraceFuncs(normalized, lines, goHeaderRe)
	case langRust:
		spans = extractBraceFuncs(normalized, lines, rustHeaderRe)
	case langTypeScript:
		spans = extractBraceFuncs(normalized, lines, tsHeaderRe)
	case langPython:
		spans = extractPythonFuncs(lines, pyHeaderRe)
	}

	if len(spans) < minFunctionsForSignal {
		return nil
	}

	median := medianLineCount(spans)
	if median <= 0 {
		return nil
	}

	var matches []llmcheat.Match
	for _, fn := range spans {
		lc := fn.lineCount()
		if float64(lc) <= lineCountMultiplier*median {
			continue
		}

		real, total := realContentRatio(lines, fn.start, fn.end, lang)
		if total == 0 {
			continue
		}
		ratio := float64(real) / float64(total)
		if ratio >= realContentRatioMax {
			continue
		}

		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      fn.start,
			Message: fmt.Sprintf(
				"function %q is %d lines (>%.0fx the file's %d top-level functions' median of %.1f) "+
					"but only %.0f%% of its lines are real code, not comments/blank padding — "+
					"looks like a stub hidden behind a god function's silhouette",
				fn.name, lc, lineCountMultiplier, len(spans), median, ratio*100,
			),
			Severity: llmcheat.SeverityMedium,
		})
	}

	return matches
}

// normalizeNewlines collapses CRLF/CR line endings to a single "\n" so line
// splitting and byte-offset math are consistent regardless of source
// checkout line-ending settings.
func normalizeNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return s
}

// indentWidth returns the number of leading space/tab characters on a line.
func indentWidth(line string) int {
	n := 0
	for n < len(line) && (line[n] == ' ' || line[n] == '\t') {
		n++
	}
	return n
}

// lineStartOffsets returns, for each line in lines (as produced by
// strings.Split(content, "\n")), the byte offset in the reconstructed
// "\n"-joined content string at which that line begins.
func lineStartOffsets(lines []string) []int {
	offs := make([]int, len(lines))
	cur := 0
	for i, l := range lines {
		offs[i] = cur
		cur += len(l) + 1
	}
	return offs
}

// offsetToLine returns the 1-based line number containing byte offset
// `offset`, given the line-start-offset table produced by lineStartOffsets.
func offsetToLine(offs []int, offset int) uint {
	i := sort.Search(len(offs), func(i int) bool { return offs[i] > offset }) - 1
	if i < 0 {
		i = 0
	}
	return uint(i + 1)
}

// skipNoise, given content and an offset pointing at content[i], returns
// the offset immediately after a string/char/backtick literal or a // or
// /* */ comment starting at i, or i itself if none of those start there.
// Every bracket-matching walk in this file runs through skipNoise first so
// a brace or paren living inside a string literal or inside one of the very
// comments this pattern is built to notice never corrupts depth counting.
func skipNoise(content string, i int) int {
	n := len(content)
	if i >= n {
		return i
	}
	switch content[i] {
	case '"':
		return skipDelimited(content, i, '"', false)
	case '\'':
		return skipDelimited(content, i, '\'', false)
	case '`':
		return skipDelimited(content, i, '`', true)
	}
	if content[i] == '/' && i+1 < n {
		switch content[i+1] {
		case '/':
			if j := strings.IndexByte(content[i:], '\n'); j != -1 {
				return i + j // stop at the newline itself; leave it for the caller
			}
			return n
		case '*':
			if j := strings.Index(content[i+2:], "*/"); j != -1 {
				return i + 2 + j + 2
			}
			return n
		}
	}
	return i
}

// skipDelimited returns the offset immediately after the literal delimited
// by `quote` that opens at content[i], honoring backslash escapes and
// (for a backtick-delimited literal) allowing embedded newlines.
func skipDelimited(content string, i int, quote byte, allowNewline bool) int {
	n := len(content)
	j := i + 1
	for j < n {
		c := content[j]
		if c == '\\' && j+1 < n {
			j += 2
			continue
		}
		if c == quote {
			return j + 1
		}
		if c == '\n' && !allowNewline {
			return j // unterminated on this physical line; stop before the newline
		}
		j++
	}
	return n
}

// findParamsOpen scans forward from `from` for the offset of the '(' that
// opens a function's parameter list, skipping over noise and over any
// generic type-parameter list first (Go's [T any], Rust/TypeScript's
// <T>) so it isn't mistaken for the parameter list itself. Returns false if
// a body/statement boundary is reached before any '(' is found at all.
func findParamsOpen(content string, from int) (int, bool) {
	n := len(content)
	angleDepth := 0
	bracketDepth := 0
	i := from
	for i < n {
		if j := skipNoise(content, i); j != i {
			i = j
			continue
		}
		switch content[i] {
		case '(':
			if angleDepth == 0 && bracketDepth == 0 {
				return i, true
			}
		case '<':
			angleDepth++
		case '>':
			if angleDepth > 0 {
				angleDepth--
			}
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		case '{', ';':
			return 0, false
		}
		i++
	}
	return 0, false
}

// matchDelim returns the offset of the closing delimiter that balances the
// opening delimiter `openCh` found at content[openOffset], tracking nested
// pairs and skipping noise along the way.
func matchDelim(content string, openOffset int, openCh, closeCh byte) (int, bool) {
	n := len(content)
	depth := 0
	i := openOffset
	for i < n {
		if j := skipNoise(content, i); j != i {
			i = j
			continue
		}
		switch content[i] {
		case openCh:
			depth++
		case closeCh:
			depth--
			if depth == 0 {
				return i, true
			}
		}
		i++
	}
	return 0, false
}

// findBodyOpenBrace scans forward from `from` (immediately after a
// parameter list's closing ')') for the '{' that opens the function body,
// skipping over noise and over any return-type parens/brackets (Go's
// `(int, error)` multi-return, `[]int`/`map[string]T` types, and similar)
// so those don't get mistaken for the body brace. Returns false if a ';'
// (a body-less declaration, e.g. a Rust trait method signature) is reached
// first.
func findBodyOpenBrace(content string, from int) (int, bool) {
	n := len(content)
	parenDepth := 0
	bracketDepth := 0
	i := from
	for i < n {
		if j := skipNoise(content, i); j != i {
			i = j
			continue
		}
		switch content[i] {
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		case '{':
			if parenDepth == 0 && bracketDepth == 0 {
				return i, true
			}
		case ';':
			if parenDepth == 0 && bracketDepth == 0 {
				return 0, false
			}
		}
		i++
	}
	return 0, false
}

// extractBraceFuncs finds every top-level (column-0) function declaration
// matched by headerRe in content and returns its full header-to-closing-
// brace line span. Used for the three brace-delimited languages this
// pattern supports: Go, Rust, TypeScript.
func extractBraceFuncs(content string, lines []string, headerRe *regexp.Regexp) []funcSpan {
	offs := lineStartOffsets(lines)
	var spans []funcSpan

	for _, m := range headerRe.FindAllStringSubmatchIndex(content, -1) {
		headerStart := m[0]
		name := content[m[2]:m[3]]
		cursor := m[1]

		openParen, ok := findParamsOpen(content, cursor)
		if !ok {
			continue
		}
		parenClose, ok := matchDelim(content, openParen, '(', ')')
		if !ok {
			continue
		}
		bodyOpen, ok := findBodyOpenBrace(content, parenClose+1)
		if !ok {
			continue
		}
		bodyClose, ok := matchDelim(content, bodyOpen, '{', '}')
		if !ok {
			continue
		}

		spans = append(spans, funcSpan{
			name:  name,
			start: offsetToLine(offs, headerStart),
			end:   offsetToLine(offs, bodyClose),
		})
	}

	return spans
}

// extractPythonFuncs finds every top-level (column-0) `def`/`async def`
// matched by headerRe and returns its header-to-last-body-line span, using
// Python's own indentation to delimit the body rather than brace matching.
func extractPythonFuncs(lines []string, headerRe *regexp.Regexp) []funcSpan {
	var spans []funcSpan

	for i := 0; i < len(lines); i++ {
		raw := lines[i]
		if indentWidth(raw) != 0 {
			continue
		}
		stripped := strings.TrimSpace(raw)
		m := headerRe.FindStringSubmatch(stripped)
		if m == nil {
			continue
		}
		name := m[1]

		headerEndLine, ok := findPyHeaderColonLine(lines, i)
		if !ok {
			continue
		}

		end := headerEndLine
		for j := headerEndLine + 1; j < len(lines); j++ {
			l := lines[j]
			if strings.TrimSpace(l) == "" {
				continue // a blank line doesn't decide the boundary by itself
			}
			if indentWidth(l) == 0 {
				break // dedented back to column 0: the function body has ended
			}
			end = j
		}

		spans = append(spans, funcSpan{
			name:  name,
			start: uint(i + 1),
			end:   uint(end + 1),
		})
	}

	return spans
}

// findPyHeaderColonLine walks forward from a `def` header's own line,
// tracking parenthesis depth (so a colon inside a type hint or default
// value doesn't end the search early) across however many physical lines
// the parameter list wraps, and returns the 0-based line index of the ':'
// that actually terminates the function header.
func findPyHeaderColonLine(lines []string, startLine int) (int, bool) {
	depth := 0
	started := false
	for li := startLine; li < len(lines); li++ {
		line := lines[li]
		for ci := 0; ci < len(line); ci++ {
			switch line[ci] {
			case '(':
				depth++
				started = true
			case ')':
				if depth > 0 {
					depth--
				}
			case ':':
				if started && depth == 0 {
					return li, true
				}
			}
		}
	}
	return 0, false
}

// medianLineCount returns the median line count across spans (the ordinary
// average-of-the-two-middle-values definition when len(spans) is even).
func medianLineCount(spans []funcSpan) float64 {
	counts := make([]int, len(spans))
	for i, s := range spans {
		counts[i] = s.lineCount()
	}
	sort.Ints(counts)

	n := len(counts)
	if n%2 == 1 {
		return float64(counts[n/2])
	}
	return float64(counts[n/2-1]+counts[n/2]) / 2.0
}

// realContentRatio counts how many of the lines in [start, end] (1-based,
// inclusive) are neither blank nor comment-only ("real"), against the total
// number of lines in that span.
func realContentRatio(lines []string, start, end uint, lang language) (real, total int) {
	lineComment := "//"
	if lang == langPython {
		lineComment = "#"
	}

	for i := start; i <= end; i++ {
		idx := int(i) - 1
		if idx < 0 || idx >= len(lines) {
			continue
		}
		total++

		t := strings.TrimSpace(lines[idx])
		switch {
		case t == "":
			continue
		case strings.HasPrefix(t, lineComment):
			continue
		case lang != langPython && strings.HasPrefix(t, "/*"):
			continue
		}
		real++
	}

	return real, total
}
