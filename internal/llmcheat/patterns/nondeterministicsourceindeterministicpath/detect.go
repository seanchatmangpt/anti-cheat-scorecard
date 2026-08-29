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

// Package nondeterministicsourceindeterministicpath implements the
// "nondeterministic-source-in-deterministic-path" llmcheat.Pattern.
//
// It flags a real-time-or-random call — Go's time.Now(), JavaScript's
// Date.now() or a no-argument new Date(), Math.random(), Python's
// random.random(, Rust's rand::random( or an unseeded rand::thread_rng() —
// appearing inside the body of a function whose name OR whose immediately
// preceding doc comment contains "deterministic", "reproducible", "hash",
// or "digest". A function that promises determinism/reproducibility by name
// or by doc comment, yet reads the wall clock or a random source in its own
// body, cannot actually keep that promise: two runs of the same function
// over the same input will disagree, which is exactly the kind of silent,
// hard-to-notice provenance defect this category exists to catch.
//
// This is a content-only heuristic scanner, not a real parser for any of
// the four languages it covers, and it deliberately runs on any text
// content it is given rather than gating on filepath.Ext: the pattern's own
// contract lists call shapes from four different languages with no stated
// file-type restriction, so scoping by extension would silently drop real
// coverage for no benefit — a file with none of the recognized function
// shapes simply produces zero candidate regions and therefore zero matches,
// which is the right answer for an irrelevant file too.
//
// Function bodies are located by two simple, well-tested heuristics rather
// than a real AST:
//   - brace-delimited bodies (Go func, Rust fn, JS/TS function declarations
//     and same-line-brace arrow functions): find the function's first
//     opening brace, then track nesting depth until it returns to zero.
//   - indentation-delimited bodies (Python def): the body is every
//     subsequent line indented further than the def line, until a
//     non-blank line at or below that indentation ends it.
//
// A "declaration-only" signature (a Rust trait method or TS interface
// method ending in ';' with no '{' at all) is recognized and treated as
// having no body, rather than misreading the rest of the file as its body.
package nondeterministicsourceindeterministicpath

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID       = "nondeterministic-source-in-deterministic-path"
	patternCategory = "determinism-and-provenance-violation"
)

// keywordRe matches any of the four determinism-promising keywords named in
// the pattern's contract, case-insensitively, as a substring of a function
// name (e.g. "ComputeDeterministicHash") or anywhere in a preceding doc
// comment.
var keywordRe = regexp.MustCompile(`(?i:deterministic|reproducible|hash|digest)`)

// nondeterministicSourceRe matches any of the real-time-or-random call
// shapes named in the pattern's contract. `rand::thread_rng()` is matched
// unconditionally for "unseeded": thread_rng() is, by its own Rust API
// contract, always drawn from OS/thread entropy at call time — a genuinely
// seeded alternative uses a different call shape entirely (e.g.
// StdRng::seed_from_u64(...)), which this regex does not match.
var nondeterministicSourceRe = regexp.MustCompile(
	`time\.Now\(\)` +
		`|Date\.now\(\)` +
		`|new\s+Date\(\s*\)` +
		`|Math\.random\(\)` +
		`|random\.random\(` +
		`|rand::random\(` +
		`|rand::thread_rng\(\)`,
)

// commentLineRe matches a whole source line that is only a comment, in any
// of the four languages' single-line-comment styles: Go/Rust/JS "//" (and
// Rust's "///" doc-comment form, a superset of "//"), Python "#", or a
// continuation/opening line of a "/* ... */" block comment.
var commentLineRe = regexp.MustCompile(`^\s*(?://.*|#.*|/\*.*|\*.*)$`)

// funcHeader describes one recognized function-definition line shape across
// the four languages this pattern's contract names.
type funcHeader struct {
	re        *regexp.Regexp
	nameGroup int  // capture group index (in re's match) holding the function/method name
	indented  bool // true for Python's indentation-delimited body; false for a brace-delimited one
}

var funcHeaders = []funcHeader{
	// Go: func Name(...) ... { / func (recv Type) Name(...) ... {
	{
		re:        regexp.MustCompile(`^\s*func\s+(?:\([^)]*\)\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(`),
		nameGroup: 1,
	},
	// Rust: [pub[(...)]] [async] [unsafe] fn name(...) ... { or fn name<T>(...) -> T {
	{
		re:        regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[(<]`),
		nameGroup: 1,
	},
	// JS/TS function declaration: [export] [default] [async] function[*] name(...) {
	{
		re:        regexp.MustCompile(`^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\(`),
		nameGroup: 1,
	},
	// JS/TS arrow function bound to a name, with its body opened on the same line:
	// [export] const|let|var name[: Type] = [async] (...) [: Type] => {
	{
		re:        regexp.MustCompile(`^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*(?::[^=]+)?=\s*(?:async\s*)?\([^)]*\)\s*(?::[^=]+)?=>\s*\{`),
		nameGroup: 1,
	},
	// Python: [async] def name(...):
	{
		re:        regexp.MustCompile(`^(\s*)(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(`),
		nameGroup: 2,
		indented:  true,
	},
}

// region is one located function body, in 1-based inclusive source lines.
type region struct {
	start, end int
}

// detector is the real, stateless implementation of llmcheat.Pattern for
// this pattern. It holds no fields because Detect is a pure function of its
// arguments: the type exists only to give the interface methods a receiver.
type detector struct{}

func (detector) ID() string { return patternID }

func (detector) Category() string { return patternCategory }

// Detect scans path's content for functions whose name or immediately
// preceding doc comment promises determinism/reproducibility, then scans
// each such function's own body for a nondeterministic-source call. Line
// numbers are 1-based and computed from the actual scanned lines.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	lines := splitLines(content)
	n := len(lines)

	var promising []region
	for i := 0; i < n; i++ {
		line := lines[i]
		for _, fh := range funcHeaders {
			m := fh.re.FindStringSubmatch(line)
			if m == nil {
				continue
			}

			name := m[fh.nameGroup]
			doc := precedingDocComment(lines, i)
			if !keywordRe.MatchString(name) && !keywordRe.MatchString(doc) {
				// A recognized function header, but one that makes no
				// determinism/reproducibility promise: not in scope.
				break
			}

			var end int
			if fh.indented {
				end = indentedBodyEnd(lines, i, m[1])
			} else {
				end = braceBodyEnd(lines, i)
			}
			promising = append(promising, region{start: i + 1, end: end})
			break
		}
	}

	if len(promising) == 0 {
		return nil
	}

	var matches []llmcheat.Match
	seen := make(map[int]bool, len(promising))
	for _, r := range promising {
		for ln := r.start; ln <= r.end && ln <= n; ln++ {
			if seen[ln] {
				continue
			}
			line := lines[ln-1]
			loc := nondeterministicSourceRe.FindString(line)
			if loc == "" {
				continue
			}
			seen[ln] = true
			matches = append(matches, llmcheat.Match{
				PatternID: patternID,
				Category:  patternCategory,
				Path:      path,
				Line:      uint(ln),
				Message: fmt.Sprintf(
					"nondeterministic source %q found inside a function that promises determinism/reproducibility by name or doc comment: %s",
					loc, strings.TrimSpace(line),
				),
				Severity: llmcheat.SeverityHigh,
			})
		}
	}

	return matches
}

// splitLines splits content into its individual lines with line-ending
// characters stripped, the same way bufio.Scanner's default line-splitter
// does, with a raised buffer so one unusually long source line can't cause
// a silent bufio.ErrTooLong scan failure that would make this detector
// miss real matches.
func splitLines(content []byte) []string {
	var lines []string
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

// precedingDocComment walks backward from the line immediately above
// lines[headerIdx], collecting contiguous whole-comment-line text (per
// commentLineRe) until it hits the first line that is not a comment (a
// blank line included) — i.e. the doc comment immediately, contiguously
// preceding the function header, exactly the shape the pattern's own dirty
// example uses. Lines are returned in original top-to-bottom order.
func precedingDocComment(lines []string, headerIdx int) string {
	var parts []string
	for i := headerIdx - 1; i >= 0; i-- {
		if !commentLineRe.MatchString(lines[i]) {
			break
		}
		parts = append([]string{lines[i]}, parts...)
	}
	return strings.Join(parts, "\n")
}

// leadingWhitespaceLen returns the number of leading space/tab characters
// on line. Each tab counts as one column, a heuristic simplification that
// is exact for space-indented sources and still correct as a same-or-more
// / less comparison for consistently tab-indented ones.
func leadingWhitespaceLen(line string) int {
	i := 0
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	return i
}

// indentedBodyEnd returns the 1-based last line of a Python-style function
// whose def line is lines[headerIdx] with leading indentation indent: every
// following line indented further than indent is body; the first
// non-blank line at or below indent's depth (or end of file) closes it.
func indentedBodyEnd(lines []string, headerIdx int, indent string) int {
	baseIndent := len(indent)
	n := len(lines)
	end := headerIdx + 1 // 1-based; covers a def with no following body lines at all
	for i := headerIdx + 1; i < n; i++ {
		line := lines[i]
		if strings.TrimSpace(line) == "" {
			end = i + 1
			continue
		}
		if leadingWhitespaceLen(line) > baseIndent {
			end = i + 1
			continue
		}
		break
	}
	return end
}

// braceBodyEnd returns the 1-based last line of a brace-delimited function
// whose header line is lines[headerIdx]: the line containing the brace that
// closes the header's own first opening brace, tracking nesting depth
// across lines. If the header is a declaration-only signature (no '{'
// before a terminating ';', e.g. a Rust trait method or TS interface
// method) or no opening brace is found within a small lookahead window, the
// region is conservatively just the header line itself — never the rest of
// the file.
func braceBodyEnd(lines []string, headerIdx int) int {
	n := len(lines)
	const maxHeaderLookahead = 20

	braceLine, braceCol := -1, -1
scanHeader:
	for i := headerIdx; i < n && i < headerIdx+maxHeaderLookahead; i++ {
		line := lines[i]
		for j := 0; j < len(line); j++ {
			switch line[j] {
			case '{':
				braceLine, braceCol = i, j
				break scanHeader
			case ';':
				return headerIdx + 1
			}
		}
	}
	if braceLine == -1 {
		return headerIdx + 1
	}

	depth := 0
	started := false
	for i := braceLine; i < n; i++ {
		line := lines[i]
		start := 0
		if i == braceLine {
			start = braceCol
		}
		for j := start; j < len(line); j++ {
			switch line[j] {
			case '{':
				depth++
				started = true
			case '}':
				depth--
				if started && depth == 0 {
					return i + 1
				}
			}
		}
	}
	return n
}

func init() {
	llmcheat.Register(detector{})
}
