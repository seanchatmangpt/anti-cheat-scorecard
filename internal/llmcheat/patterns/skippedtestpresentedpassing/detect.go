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

// Package skippedtestpresentedpassing implements the
// "skipped-test-presented-passing" llmcheat.Pattern: it flags a test skipped
// via @pytest.mark.skip (Python), #[ignore] (Rust), or it.skip(/xit(/
// test.skip( (JS/TS) with no explanation given for why the test is being
// skipped. An unexplained skip is a classic way to make a failing or
// inconvenient test disappear from a "tests pass" summary without actually
// fixing anything, and it becomes especially suspicious when it sits next to
// a comment claiming the suite fully passes -- that combination is flagged
// at a higher severity.
//
// Python and Rust both have a formal "reason" mechanism at the language
// level (pytest.mark.skip(reason="...") / #[ignore = "..."]), so "no reason"
// there means the call/attribute carries no argument at all. The JS/TS
// skip-family functions (it.skip, xit, test.skip) have no such mechanism in
// their API -- their only argument is the test's own name -- so "no reason"
// there is judged by whether a nearby comment (trailing on the same line, or
// a whole-line comment immediately above) explains the skip.
package skippedtestpresentedpassing

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// patternID and category are the two identifiers this detector self-registers
// under; they must stay in sync with what ID()/Category() return.
const (
	patternID = "skipped-test-presented-passing"
	category  = "test-integrity-violation"
)

func init() {
	llmcheat.Register(&detector{})
}

// detector is the unexported llmcheat.Pattern implementation. It holds no
// state of its own (state lives entirely on the stack built fresh inside
// each Detect call), so a single shared instance is safe to register once.
type detector struct{}

func (d *detector) ID() string       { return patternID }
func (d *detector) Category() string { return category }

var (
	// pyPytestSkipMarkerRe matches the "@pytest.mark.skip" decorator marker
	// itself, not "@pytest.mark.skipif" -- the trailing \b fails to match
	// between "skip" and "if" since both are word characters, so skipif
	// (a conditional skip, out of this pattern's stated scope) never matches.
	pyPytestSkipMarkerRe = regexp.MustCompile(`@pytest\.mark\.skip\b`)

	// rustIgnoreRe matches Rust's "#[ignore]" test attribute, optionally
	// with its reason form "#[ignore = \"...\"]". Group 1 is the reason
	// text when present.
	rustIgnoreRe = regexp.MustCompile(`#\[\s*ignore\s*(?:=\s*"([^"]*)")?\s*\]`)

	// jsItSkipRe, jsXitRe, and jsTestSkipRe match the three common JS/TS
	// test-runner skip call shapes. Each \b prevents matching inside a
	// longer identifier (e.g. "exit(" never matches jsXitRe, "sometest.skip("
	// never matches jsTestSkipRe).
	jsItSkipRe   = regexp.MustCompile(`\bit\.skip\s*\(`)
	jsXitRe      = regexp.MustCompile(`\bxit\s*\(`)
	jsTestSkipRe = regexp.MustCompile(`\btest\.skip\s*\(`)

	// allTestsPassRe matches a nearby comment/text claiming the full test
	// suite passes, e.g. "all tests pass", "all tests are passing", "all
	// test cases passing".
	allTestsPassRe = regexp.MustCompile(`(?i)all\s+tests?\s+(?:are\s+|is\s+)?pass(?:ing)?`)
)

// fileKind identifies which language-specific skip syntax applies to a file,
// based on its extension.
type fileKind int

const (
	fileKindUnsupported fileKind = iota
	fileKindPython
	fileKindRust
	fileKindJS
)

func kindForPath(path string) fileKind {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".py":
		return fileKindPython
	case ".rs":
		return fileKindRust
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts":
		return fileKindJS
	default:
		return fileKindUnsupported
	}
}

// skipFinding is what a per-language line matcher returns when it recognizes
// a skip call/attribute on a line: whether it already carries an explanation
// (hasReason), and a short human-readable label for the syntax found (used
// in the reported Match's Message).
type skipFinding struct {
	hasReason bool
	label     string
}

// Detect is a pure function: it scans the file line by line for a
// language-appropriate "skip this test" marker with no accompanying
// explanation, and reports one Match per unexplained occurrence. A match
// found near a comment claiming the whole suite passes is reported at
// SeverityHigh instead of SeverityMedium, since that combination is actively
// misleading rather than merely undocumented.
func (d *detector) Detect(path string, content []byte) []llmcheat.Match {
	kind := kindForPath(path)
	if kind == fileKindUnsupported {
		return nil
	}

	lines := strings.Split(string(content), "\n")
	var matches []llmcheat.Match

	for i := range lines {
		var found *skipFinding
		switch kind {
		case fileKindPython:
			found = detectPythonSkip(lines, i)
		case fileKindRust:
			found = detectRustIgnore(lines[i])
		case fileKindJS:
			found = detectJSSkip(lines, i)
		case fileKindUnsupported:
			// unreachable: kindForPath already filtered this out above.
		}
		if found == nil || found.hasReason {
			continue
		}

		lineNo := uint(i + 1) //nolint:gosec // i is bounded by len(lines), never near uint overflow
		var (
			severity llmcheat.Severity
			message  string
		)
		if nearbyClaimsAllTestsPass(lines, i) {
			severity = llmcheat.SeverityHigh
			message = fmt.Sprintf(
				"%s used with no reason/explanation given, near a comment claiming the tests pass -- "+
					"the suite is not actually fully passing while this test is silently skipped",
				found.label)
		} else {
			severity = llmcheat.SeverityMedium
			message = fmt.Sprintf(
				"%s used with no reason/explanation given: an unexplained test skip can hide a real "+
					"gap in coverage behind an apparently-green test run",
				found.label)
		}

		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      lineNo,
			Message:   message,
			Severity:  severity,
		})
	}

	return matches
}

// detectPythonSkip looks for "@pytest.mark.skip" on lines[idx] (after
// stripping any "# ..." comment) and determines whether it carries a
// non-empty argument list. It handles both the single-line form
// ("@pytest.mark.skip(reason=\"...\")") and the common multi-line form
// where the call is opened on this line and closed a few lines later
// ("@pytest.mark.skip(\n    reason=\"...\",\n)"), by joining forward lines
// until a closing paren is found (bounded lookahead, not a full parser).
func detectPythonSkip(lines []string, idx int) *skipFinding {
	const label = "@pytest.mark.skip"

	code := stripPythonComment(lines[idx])
	loc := pyPytestSkipMarkerRe.FindStringIndex(code)
	if loc == nil {
		return nil
	}

	rest := strings.TrimSpace(code[loc[1]:])
	if rest == "" {
		// Bare "@pytest.mark.skip" with nothing else on this line: no
		// argument list at all, so no reason.
		return &skipFinding{hasReason: false, label: label}
	}
	if rest[0] != '(' {
		// The marker is immediately followed by something that isn't a
		// call -- not the shape this pattern targets (defensive; the
		// word-boundary regex above should already exclude most of these).
		return nil
	}

	joined := rest
	for steps := 0; !strings.Contains(joined, ")") && idx+steps+1 < len(lines) && steps < 10; steps++ {
		joined += " " + stripPythonComment(lines[idx+steps+1])
	}

	var args string
	if closeIdx := strings.Index(joined, ")"); closeIdx > 0 {
		args = joined[1:closeIdx]
	}
	return &skipFinding{hasReason: strings.TrimSpace(args) != "", label: label}
}

// detectRustIgnore looks for "#[ignore]" or "#[ignore = \"...\"]" on rawLine
// (after stripping any trailing "// ..." comment).
func detectRustIgnore(rawLine string) *skipFinding {
	const label = "#[ignore]"

	code, _ := splitSlashComment(rawLine)
	m := rustIgnoreRe.FindStringSubmatch(code)
	if m == nil {
		return nil
	}
	return &skipFinding{hasReason: strings.TrimSpace(m[1]) != "", label: label}
}

// detectJSSkip looks for it.skip(/xit(/test.skip( on lines[idx] (after
// stripping any trailing "// ..." comment). Since none of these APIs carry a
// formal "reason" argument, a skip is treated as explained when either a
// meaningful trailing comment follows the call on the same line, or the
// immediately preceding line is itself a whole-line comment with real
// content.
func detectJSSkip(lines []string, idx int) *skipFinding {
	code, trailingComment := splitSlashComment(lines[idx])

	var label string
	switch {
	case jsItSkipRe.MatchString(code):
		label = "it.skip("
	case jsXitRe.MatchString(code):
		label = "xit("
	case jsTestSkipRe.MatchString(code):
		label = "test.skip("
	default:
		return nil
	}

	if hasMeaningfulComment(trailingComment) {
		return &skipFinding{hasReason: true, label: label}
	}
	if idx > 0 {
		prevCode, prevComment := splitSlashComment(lines[idx-1])
		if strings.TrimSpace(prevCode) == "" && hasMeaningfulComment(prevComment) {
			return &skipFinding{hasReason: true, label: label}
		}
	}
	return &skipFinding{hasReason: false, label: label}
}

// nearbyClaimsAllTestsPass reports whether any line within 3 lines before or
// after lines[idx] (inclusive of idx itself) matches allTestsPassRe.
func nearbyClaimsAllTestsPass(lines []string, idx int) bool {
	const window = 3

	start := idx - window
	if start < 0 {
		start = 0
	}
	end := idx + window
	if end >= len(lines) {
		end = len(lines) - 1
	}
	for i := start; i <= end; i++ {
		if allTestsPassRe.MatchString(lines[i]) {
			return true
		}
	}
	return false
}

// hasMeaningfulComment reports whether s (a comment's text, with the leading
// "//" already removed) contains anything beyond whitespace.
func hasMeaningfulComment(s string) bool {
	return strings.TrimSpace(s) != ""
}

// stripPythonComment returns the code portion of a Python source line, with
// any trailing "# ..." comment removed, honoring single- and double-quoted
// string literals so a '#' inside a string (e.g. a URL fragment or issue
// reference like "see issue #42") is not mistaken for the start of a
// comment. Triple-quoted strings and line continuations are not modeled --
// a deliberate simplification for a heuristic line scanner, consistent with
// this package's sibling pattern detectors.
func stripPythonComment(line string) string {
	inSingle, inDouble := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '\\' && (inSingle || inDouble) && i+1 < len(line):
			i++ // skip the escaped character
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case c == '#' && !inSingle && !inDouble:
			return line[:i]
		}
	}
	return line
}

// splitSlashComment splits a Rust/JS-family source line into its code
// portion and its trailing "// ..." comment portion (with the leading "//"
// removed), honoring single-, double-, and backtick-quoted string literals
// so a "//" inside a string (e.g. a URL) is not mistaken for a comment
// start. Block comments ("/* ... */") are not modeled -- a deliberate
// simplification for a heuristic line scanner. When the line has no "//"
// outside a string, comment is "".
func splitSlashComment(line string) (code, comment string) {
	inSingle, inDouble, inBacktick := false, false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '\\' && (inSingle || inDouble || inBacktick) && i+1 < len(line):
			i++ // skip the escaped character
		case c == '\'' && !inDouble && !inBacktick:
			inSingle = !inSingle
		case c == '"' && !inSingle && !inBacktick:
			inDouble = !inDouble
		case c == '`' && !inSingle && !inDouble:
			inBacktick = !inBacktick
		case c == '/' && !inSingle && !inDouble && !inBacktick && i+1 < len(line) && line[i+1] == '/':
			return line[:i], line[i+2:]
		}
	}
	return line, ""
}
