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

// Package interactiononlyassertion implements the
// "interaction-only-assertion" llmcheat.Pattern: it flags a test function
// (Python/Rust "test_..." def/fn, Go "Test..." func, or a JS/TS "it("/"test("
// block) whose ONLY assertion-shaped lines are call-verification style
// (".assert_called...()", ".toHaveBeenCalled...()", "verify(...)", or a bare
// ".called" attribute check) with no state/value assertion
// ("assert x == y", "assertEqual(...)", "expect(x).toBe/toEqual(...)",
// "assert_eq!(...)", or a testify-style ".Equal(...)") anywhere in the same
// function body.
//
// A test built entirely out of "did I call the mock" checks proves the
// production code invoked a collaborator; it proves nothing about what that
// collaborator actually did or what the caller ended up with — exactly the
// gap a hollow or reward-hacked implementation can hide behind while every
// test in the suite stays green.
//
// Deliberately out of scope: a function this heuristic cannot recognize as a
// test at all (no "test_"/"Test" name, no "it("/"test(" call, no "#[test]"
// attribute), and a test that has no assertion-shaped line whatsoever (an
// empty/smoke test is a different, weaker problem than an interaction-only
// one and is not this pattern's concern).
package interactiononlyassertion

import (
	"fmt"
	"strings"

	"regexp"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "interaction-only-assertion"
	category  = "test-integrity-violation"
)

// quote characters assembled without a raw-string literal containing a
// backtick (Go raw strings are themselves backtick-delimited, so the
// backtick has to be spliced in from a separate interpreted string).
const (
	singleQuoteChar = `'`
	doubleQuoteChar = `"`
	backtickChar    = "`"
)

var quoteClass = singleQuoteChar + doubleQuoteChar + backtickChar

// interactionAssertRe matches a call-verification-style assertion: it checks
// that a mock/spy *was called*, never what any value in the test actually
// equals.
var interactionAssertRe = regexp.MustCompile(
	`\.\s*assert_called(?:_once)?(?:_with)?\s*\(` + // Python unittest.mock: .assert_called(), .assert_called_once(), .assert_called_with(), .assert_called_once_with()
		`|\.\s*toHaveBeenCalled(?:Times|With)?\s*\(` + // Jest/Vitest: .toHaveBeenCalled(), .toHaveBeenCalledTimes(), .toHaveBeenCalledWith()
		`|\bverify\s*\(` + // Mockito/mockall-style: verify(mock).method(...)
		`|\.\s*called\b`, // Python unittest.mock: bare "mock.called" attribute check
)

// stateAssertRe matches a real state/value assertion: it checks what a
// value actually is, not merely that a call happened.
var stateAssertRe = regexp.MustCompile(
	`\bassert\b\s+\S.*==` + // Python bare "assert x == y"
		`|\bassertEqual\s*\(` + // Python unittest.TestCase.assertEqual(...)
		`|\bexpect\s*\([^)]*\)\s*\.\s*toBe\s*\(` + // Jest/Vitest expect(x).toBe(y)
		`|\bexpect\s*\([^)]*\)\s*\.\s*toEqual\s*\(` + // Jest/Vitest expect(x).toEqual(y)
		`|\bassert_eq!\s*\(` + // Rust assert_eq!(...)
		`|\.\s*Equal\s*\(`, // Go testify assert.Equal(...) / require.Equal(...)
)

// Test-function start markers, one per supported language shape.
var (
	pyTestDefRe    = regexp.MustCompile(`^\s*def\s+(test_\w*)\s*\(`)
	goTestFuncRe   = regexp.MustCompile(`^\s*func\s+(Test\w*)\s*\(`)
	rustTestAttrRe = regexp.MustCompile(`^\s*#\[[^\]]*\btest\b[^\]]*\]`)
	rustFnLineRe   = regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)`)
	jsTestStartRe  = regexp.MustCompile(`\b(?:it|test)\s*\(\s*[` + quoteClass + `]`)
)

// fnNameRe pulls the identifier out of a def/func/fn signature line.
var fnNameRe = regexp.MustCompile(`\b(?:def|func|fn)\s+([A-Za-z_][A-Za-z0-9_]*)`)

// jsNameRe pulls the quoted description string out of an it(...)/test(...)
// call, e.g. it("saves the record", ...).
var jsNameRe = regexp.MustCompile(`\b(?:it|test)\s*\(\s*[` + quoteClass + `]([^` + quoteClass + `]*)`)

// detector is the unexported implementation of llmcheat.Pattern for this
// pattern. It holds no state: Detect is a pure function of its arguments.
type detector struct{}

func (detector) ID() string { return patternID }

func (detector) Category() string { return category }

func init() {
	llmcheat.Register(detector{})
}

// Detect scans content line by line, looking for a test-function start
// (Python/Rust "test_..." def/fn, Go "Test..." func, or a JS/TS
// "it("/"test(" block). For each one it recovers, it locates that function's
// body (indentation-based for Python, brace-balance-based for Go/JS/Rust)
// and checks whether the body contains at least one call-verification-style
// assertion and zero state/value assertions. If so, every call-verification
// line is reported as a match.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	if len(content) == 0 {
		return nil
	}

	lines := splitLines(content)
	var matches []llmcheat.Match

	for i := 0; i < len(lines); i++ {
		line := lines[i]

		switch {
		case pyTestDefRe.MatchString(line):
			end := indentBodyEnd(lines, i)
			checkBody(lines, i, end, path, &matches)

		case goTestFuncRe.MatchString(line):
			if start, end, ok := braceBodyRange(lines, i); ok {
				checkBody(lines, start, end, path, &matches)
			}

		case rustTestAttrRe.MatchString(line):
			if fnIdx := findNextFnLine(lines, i+1); fnIdx >= 0 {
				if start, end, ok := braceBodyRange(lines, fnIdx); ok {
					checkBody(lines, start, end, path, &matches)
				}
			}

		case jsTestStartRe.MatchString(line):
			if start, end, ok := braceBodyRange(lines, i); ok {
				checkBody(lines, start, end, path, &matches)
			}
		}
	}

	return matches
}

// checkBody scans lines[start..end] (inclusive, both indices valid into
// lines) for call-verification and state/value assertions. If at least one
// call-verification line is found and no state/value assertion appears
// anywhere in the range, it appends one Match per call-verification line.
func checkBody(lines []string, start, end int, path string, matches *[]llmcheat.Match) {
	if start < 0 || end >= len(lines) || start > end {
		return
	}

	hasState := false
	var interactionLines []int
	for i := start; i <= end; i++ {
		if stateAssertRe.MatchString(lines[i]) {
			hasState = true
		}
		if interactionAssertRe.MatchString(lines[i]) {
			interactionLines = append(interactionLines, i)
		}
	}
	if hasState || len(interactionLines) == 0 {
		return
	}

	fnName := functionNameFrom(lines[start])
	for _, li := range interactionLines {
		lineNo := uint(li + 1) // 1-based
		*matches = append(*matches, llmcheat.Match{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      lineNo,
			Message: fmt.Sprintf(
				"test function %q verifies a call (%s) but asserts no resulting state or value anywhere in its body",
				fnName, strings.TrimSpace(lines[li]),
			),
			Severity: llmcheat.SeverityMedium,
		})
	}
}

// functionNameFrom extracts a human-readable name for the test function
// whose signature (or it("...")/test("...") call) is on line, for use in a
// Match's Message. Falls back to the trimmed line itself if no recognized
// shape matches.
func functionNameFrom(line string) string {
	if m := fnNameRe.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	if m := jsNameRe.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	return strings.TrimSpace(line)
}

// indentBodyEnd returns the last line index (inclusive) of the
// indentation-delimited body starting after startIdx (a Python "def ...:"
// line): every immediately-following line indented strictly more than
// startIdx's line, blank lines bridged over, until a non-blank line at or
// below startIdx's indentation is hit (or EOF).
func indentBodyEnd(lines []string, startIdx int) int {
	baseIndent := leadingWhitespaceLen(lines[startIdx])
	end := startIdx
	for i := startIdx + 1; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" {
			continue // blank line: don't end the body on it, but don't extend end either unless a later real line does
		}
		if leadingWhitespaceLen(lines[i]) <= baseIndent {
			break
		}
		end = i
	}
	return end
}

// leadingWhitespaceLen returns the number of leading space/tab characters
// on line.
func leadingWhitespaceLen(line string) int {
	return len(line) - len(strings.TrimLeft(line, " \t"))
}

// braceBodyRange locates a brace-delimited function body starting at or
// shortly after startIdx: it looks for the first "{" within a short
// lookahead window (the signature line itself, or a couple of lines after
// it for a multi-line signature), then balances braces from there to find
// the matching close. Returns (startIdx, closeIdx, true) on success, an
// unspecified range and false if no opening brace is found nearby.
func braceBodyRange(lines []string, startIdx int) (int, int, bool) {
	const lookahead = 5
	openIdx := -1
	for i := startIdx; i < len(lines) && i < startIdx+lookahead; i++ {
		if strings.Contains(lines[i], "{") {
			openIdx = i
			break
		}
	}
	if openIdx == -1 {
		return 0, 0, false
	}

	depth := 0
	for i := openIdx; i < len(lines); i++ {
		depth += strings.Count(lines[i], "{")
		depth -= strings.Count(lines[i], "}")
		if depth <= 0 {
			return startIdx, i, true
		}
	}
	// Unterminated (truncated fixture/file): body runs to EOF.
	return startIdx, len(lines) - 1, true
}

// findNextFnLine searches forward from index from (inclusive) for the next
// "fn ..." line, skipping blank lines and further attribute lines
// ("#[...]") — the sequence a Rust "#[test]\nfn test_foo() {" (optionally
// with more attributes, e.g. "#[test]\n#[should_panic]\nfn test_foo() {")
// takes. Returns -1 if no such line is found within a short lookahead, or
// if a non-attribute, non-blank, non-fn line is hit first (the "#[test]"
// wasn't actually attached to a function).
func findNextFnLine(lines []string, from int) int {
	const lookahead = 6
	for i := from; i < len(lines) && i < from+lookahead; i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "#[") {
			continue
		}
		if rustFnLineRe.MatchString(lines[i]) {
			return i
		}
		return -1
	}
	return -1
}

// splitLines splits content into lines, dropping a trailing '\r' from each
// (so CRLF files behave the same as LF files) and never returning a
// trailing empty line caused solely by a final '\n'.
func splitLines(content []byte) []string {
	raw := strings.Split(string(content), "\n")
	if len(raw) > 0 && raw[len(raw)-1] == "" {
		raw = raw[:len(raw)-1]
	}
	out := make([]string, len(raw))
	for i, l := range raw {
		out[i] = strings.TrimSuffix(l, "\r")
	}
	return out
}
