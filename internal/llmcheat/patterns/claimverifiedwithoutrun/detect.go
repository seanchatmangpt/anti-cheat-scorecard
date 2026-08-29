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

// Package claimverifiedwithoutrun implements the "claim-verified-without-run"
// internal/llmcheat.Pattern: a comment, doc line, or commit-message-shaped
// line that asserts something was "verified"/"confirmed"/"validated" with no
// nearby evidence (a backticked command, a test-looking token such as
// `pytest`/`cargo test`/`go test`/a `*_test.go`-style filename, or a
// CLI-flag-looking token such as `-v`/`--verbose`) that the claim was
// actually checked by running something.
package claimverifiedwithoutrun

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// patternID is the stable, kebab-case identifier for this detector. It must
// match the ID() method below and is unique across the shared registry.
const patternID = "claim-verified-without-run"

// category is one of the seven Anti-Cheat categories llmcheat.Match.Category
// documents; an unsubstantiated "verified"/"confirmed"/"validated" claim is a
// fabricated claim about work that was never actually checked.
const category = "fabricated-claims"

// claimWordRe matches a standalone occurrence of "verified", "confirmed", or
// "validated" (case-insensitive, whole word only — so it does not fire on
// identifiers like isVerified, verified_output, or unverified, none of which
// have a \b transition immediately around the word).
var claimWordRe = regexp.MustCompile(`(?i)\b(verified|confirmed|validated)\b`)

// backtickCommandRe matches any backticked span, e.g. “ `pytest -v` “.
// A backticked span is treated as command/tool-invocation evidence
// regardless of its exact contents — that is the conventional way both
// Markdown and code comments quote a literal command.
var backtickCommandRe = regexp.MustCompile("`[^`\n]+`")

// testToolRe matches common test-runner invocations and testing frameworks
// by name, with or without backticks: pytest, `cargo test`, `go test`, `npm
// test`, jest, rspec, etc.
var testToolRe = regexp.MustCompile(`(?i)\b(pytest|cargo\s+test|go\s+test|npm\s+test|yarn\s+test|jest|rspec|unittest|mvn\s+test|gradle\s+test|make\s+test|tox|nose2|phpunit|rake\s+test|dotnet\s+test|ctest)\b`)

// testFileRe matches test-name-looking tokens such as test_x.py,
// x_test.go, x.test.ts, x.spec.ts, XTest.java.
var testFileRe = regexp.MustCompile(`(?i)\b[\w./-]*(?:_test|test_|\.test|\.spec)[\w./-]*\.[a-z]+\b`)

// cliFlagRe matches a CLI-flag-looking token: a "-" or "--" immediately
// preceded by whitespace or the start of the line and immediately followed
// by a letter, e.g. "-v", "--verbose". It deliberately requires no space
// between the dash(es) and the following letter so it does not match a
// Markdown bullet ("- Verified ...") or a mid-word hyphen ("well-tested").
var cliFlagRe = regexp.MustCompile(`(?:^|\s)--?[A-Za-z][\w-]*`)

// commentPrefixes are line-start markers that unambiguously introduce a
// comment or doc line across the languages/doc formats this pattern needs to
// cover (shell/Python/Ruby/YAML #, C-family/Go/Rust/JS //, C block /* and
// continuation *, HTML/Markdown <!--, SQL/Lua/Turtle --, Lisp/ini ;, and a
// Markdown bullet/list "-").
var commentPrefixes = []string{"#", "//", "/*", "*", "<!--", "--", ";", "-"}

// codeMarkers are substrings that, when present on a line with no
// recognized comment prefix, indicate the line is an actual source
// statement (an assignment, a block, a function call terminator, ...)
// rather than prose — so it is not "comment/doc/commit-message-shaped" and
// is skipped even if it happens to contain one of the claim words as a
// standalone identifier (e.g. `verified := check()`).
var codeMarkers = []string{"{", "}", "(", ")", ";", "=", "->", "=>"}

// codeKeywordRe matches a line that opens with a common statement keyword,
// another signal the line is code rather than prose.
var codeKeywordRe = regexp.MustCompile(`^(func|def|class|import|package|return|if|for|while|let|const|var|type)\b`)

// detector is the unexported real implementation of llmcheat.Pattern.
type detector struct{}

func newDetector() *detector { return &detector{} }

func (d *detector) ID() string       { return patternID }
func (d *detector) Category() string { return category }

// Detect scans content line by line. For every line whose text is
// comment/doc/commit-message-shaped and contains a standalone
// "verified"/"confirmed"/"validated" claim word, it looks for adjacent
// run-evidence (a backticked command, a test-tool/test-file token, or a
// CLI-flag token) on that same line or either of the next two lines. If no
// evidence is found in that 3-line window, the claim is reported as a
// Match.
func (d *detector) Detect(path string, content []byte) []llmcheat.Match {
	if len(content) == 0 {
		return nil
	}

	lines := strings.Split(string(content), "\n")
	var matches []llmcheat.Match

	for i, line := range lines {
		if !isProseShapedLine(line) {
			continue
		}

		loc := claimWordRe.FindStringSubmatchIndex(line)
		if loc == nil {
			continue
		}
		word := line[loc[2]:loc[3]]

		if hasRunEvidence(lines, i) {
			continue
		}

		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      uint(i + 1), //nolint:gosec // i is a small, bounded slice index
			Message: fmt.Sprintf(
				"line claims work was %q with no adjacent command, test name, or tool invocation as evidence (checked this line and the next 2)",
				strings.ToLower(word),
			),
			Severity: llmcheat.SeverityMedium,
		})
	}

	return matches
}

// isProseShapedLine reports whether line looks like a comment, doc line, or
// commit-message-shaped line (as opposed to an actual source-code
// statement that merely happens to contain a claim word as an identifier).
func isProseShapedLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}

	for _, prefix := range commentPrefixes {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}

	// No recognized comment marker: still treat it as prose (e.g. a commit
	// message subject/body line, which carries no marker at all) unless it
	// looks like an actual code statement.
	if codeKeywordRe.MatchString(trimmed) {
		return false
	}
	for _, marker := range codeMarkers {
		if strings.Contains(trimmed, marker) {
			return false
		}
	}
	return true
}

// hasRunEvidence reports whether lines[i] or either of the following two
// lines (a 3-line window: the claim line plus its next 2) contains a
// backticked command, a recognizable test-tool/test-file token, or a
// CLI-flag-looking token.
func hasRunEvidence(lines []string, i int) bool {
	end := i + 2
	if end > len(lines)-1 {
		end = len(lines) - 1
	}
	for j := i; j <= end; j++ {
		l := lines[j]
		if backtickCommandRe.MatchString(l) {
			return true
		}
		if testToolRe.MatchString(l) {
			return true
		}
		if testFileRe.MatchString(l) {
			return true
		}
		if cliFlagRe.MatchString(l) {
			return true
		}
	}
	return false
}

func init() {
	llmcheat.Register(newDetector())
}
