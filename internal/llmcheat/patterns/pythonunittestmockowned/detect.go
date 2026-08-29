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

// Package pythonunittestmockowned implements the
// "python-unittest-mock-owned" llmcheat.Pattern: it flags Python test files
// that reach for unittest.mock (or the pytest-mock/monkeypatch equivalents)
// to fake an owned, in-process collaborator instead of exercising a real
// one. This mirrors this project's own global Chicago-testing-discipline
// stance — interaction-based mocking of a collaborator the codebase owns or
// could realistically run in-process is banned by default, not merely
// discouraged, because a test built that way verifies the test's own model
// of the collaborator rather than the real integration.
package pythonunittestmockowned

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// patternID and category are the two identifiers this detector self-registers
// under; they must stay in sync with what ID()/Category() return.
const (
	patternID = "python-unittest-mock-owned"
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

// mockRule pairs one regex identifying a specific mocking idiom with the
// human-readable explanation attached to any Match it produces.
type mockRule struct {
	re      *regexp.Regexp
	message string
}

// mockRules is the fixed set of mocking idioms this pattern flags, taken
// directly from the pattern's stated scope. Each regex is anchored with a
// leading \b (or is itself preceded by a "." that already forces a boundary)
// so that, e.g., "Mock(" does not spuriously match inside "MagicMock(" —
// the character immediately before "Mock" in "MagicMock(" is "c", a word
// character, so \b correctly refuses to match there.
var mockRules = []mockRule{
	{
		re:      regexp.MustCompile(`\bunittest\.mock\b`),
		message: `references "unittest.mock" directly instead of exercising a real, owned collaborator`,
	},
	{
		re:      regexp.MustCompile(`\bMock\(`),
		message: `constructs a bare Mock(), replacing a real collaborator with an interaction-only stand-in`,
	},
	{
		re:      regexp.MustCompile(`\bMagicMock\(`),
		message: `constructs a MagicMock(), replacing a real collaborator with an interaction-only stand-in`,
	},
	{
		// Qualified forms ("@mock.patch(", "@unittest.mock.patch(") are
		// included alongside the bare "@patch(" spelling: which spelling a
		// test uses depends only on how the import at the top of the file
		// was written ("from unittest.mock import patch" vs.
		// "from unittest import mock" / "import unittest.mock"), not on
		// whether it is mocking an owned collaborator — the same violation
		// either way.
		re:      regexp.MustCompile(`@(?:[\w.]+\.)?patch\(`),
		message: `applies @patch(...) to substitute a mock for a real, owned collaborator at test time`,
	},
	{
		re:      regexp.MustCompile(`\bmonkeypatch\.setattr\(`),
		message: `uses monkeypatch.setattr(...) to substitute a mock for a real, owned collaborator`,
	},
	{
		re:      regexp.MustCompile(`\bmocker\.patch\(`),
		message: `uses mocker.patch(...) (pytest-mock) to substitute a mock for a real, owned collaborator`,
	},
}

// Detect is a pure function: it first gates on whether path names a Python
// test file at all (per the pattern's stated scope), then scans .py content
// line by line, matching each line against every rule in mockRules and
// recording a real 1-based line number for every hit.
func (d *detector) Detect(path string, content []byte) []llmcheat.Match {
	if !isPythonTestFile(path) {
		return nil
	}

	var matches []llmcheat.Match
	lines := strings.Split(string(content), "\n")
	for i, rawLine := range lines {
		lineNo := uint(i + 1) //nolint:gosec // i is bounded by len(lines), never near uint overflow

		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			// Blank and whole-line-comment lines can never contain a real,
			// executed mock usage: skip them outright.
			continue
		}

		codeLine := stripLineComment(rawLine)
		if strings.TrimSpace(codeLine) == "" {
			continue
		}

		for _, rule := range mockRules {
			if !rule.re.MatchString(codeLine) {
				continue
			}
			matches = append(matches, llmcheat.Match{
				PatternID: patternID,
				Category:  category,
				Path:      path,
				Line:      lineNo,
				Message:   rule.message,
				Severity:  llmcheat.SeverityHigh,
			})
		}
	}

	return matches
}

// isPythonTestFile reports whether path names a Python test file under this
// pattern's stated scope: a .py file whose path contains "/test", or whose
// filename starts with "test_", or whose filename ends with "_test.py".
// The .py extension gate additionally applies to the "/test"-directory
// case (not just the filename-prefix/suffix cases) since the pattern is
// scoped to *Python* test files specifically, not every file that happens
// to live under a directory with "test" in its name.
func isPythonTestFile(path string) bool {
	if !strings.EqualFold(filepath.Ext(path), ".py") {
		return false
	}
	base := filepath.Base(path)
	if strings.HasPrefix(base, "test_") {
		return true
	}
	if strings.HasSuffix(base, "_test.py") {
		return true
	}
	return strings.Contains(path, "/test")
}

// stripLineComment returns line with a trailing "# ..." comment removed,
// honoring single- and double-quoted string literals so that a '#' inside a
// string (e.g. a URL fragment or format string) is not mistaken for the
// start of a comment. It does not attempt to understand triple-quoted
// strings or line-continuations — a deliberate, documented simplification
// for a heuristic line-scanner, not a full Python tokenizer.
func stripLineComment(line string) string {
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
