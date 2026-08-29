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

// Package fixturesmuggledintoprod implements the "fixture-smuggled-into-prod"
// llmcheat Pattern: it flags an obviously test-fixture-shaped literal
// ("test-token", "test_password", "fake-api-key", "dummy-secret", or the
// bare numeric "123456") assigned directly to a token/secret/credential-
// shaped variable, in a file whose path is NOT itself under a test,
// fixture, or mock directory. This is the shape left behind when a
// placeholder value that started life in a test fixture gets copy-pasted
// (by an LLM or a human under deadline pressure) straight into real
// application code instead of being wired to a real secret source (env var,
// secret manager, config file) — the code "works" in the sense that it
// compiles and runs, but it is silently running on a fake credential.
//
// This pattern deliberately has no file-extension restriction: the same
// smuggled-fixture shape shows up identically in Go, Python, JS/TS, and
// JSON/YAML-ish config, so Detect runs on any text content it is given and
// relies on the assignment-shape regex plus the path check to scope itself.
package fixturesmuggledintoprod

import (
	"bufio"
	"bytes"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID       = "fixture-smuggled-into-prod"
	patternCategory = "test-integrity-violation"
)

// assignRe matches a simple "identifier <assignment-op> quoted-string"
// shape across the languages a real polyglot codebase mixes: Go's
// `apiKey := "..."` / `apiKey = "..."`, Python's `api_key = "..."`, JS/TS's
// `const apiKey = "...";`, and a JSON/YAML-ish `"apiKey": "..."`. The
// identifier itself may optionally be quoted (JSON object keys) or
// backtick-quoted; the assignment operator is one of `:=`, a bare `=`, or a
// bare `:` (JSON/YAML key-value separator). The value is only matched up to
// 200 bytes so one unterminated quote on a pathological line can't make the
// regex engine scan the rest of the line as a single literal.
var assignRe = regexp.MustCompile(
	"[\"'`]?([A-Za-z_][A-Za-z0-9_]*)[\"'`]?\\s*(:=|[:=])\\s*[\"']([^\"']{1,200})[\"']",
)

// secretShapedNameRe matches a variable/key name that reads as a
// token/secret/credential holder specifically — this is what distinguishes
// "a test-shaped literal happens to be assigned to some unrelated string
// variable" (not this pattern's business) from "a test-shaped literal is
// smuggled into what is clearly meant to hold a real secret".
var secretShapedNameRe = regexp.MustCompile(`(?i)(apikey|api_key|key|token|secret|password|passwd|pwd|credential)`)

// dirtyLiteralRe matches one of the specific, obviously-test-fixture-shaped
// literal values named in this pattern's spec: "test-token", "test_password",
// "fake-api-key", "dummy-secret" (hyphen/underscore treated as
// interchangeable, since both spellings show up across languages), and the
// bare numeric "123456". The numeric case is anchored to the *whole* value
// (^123456$) rather than matched as a substring — unlike the word-shaped
// fixtures, "123456" is common enough as a six-digit substring of a real
// token (e.g. part of a real API key) that a substring match would
// false-positive constantly; requiring the entire literal to be exactly
// "123456" keeps it scoped to the actual placeholder-PIN shape.
var dirtyLiteralRe = regexp.MustCompile(`(?i)test[-_]token|test[-_]password|fake[-_]api[-_]key|dummy[-_]secret|^123456$`)

// detector is the real, stateless implementation of llmcheat.Pattern for
// this pattern. It holds no fields because Detect is a pure function of its
// arguments: the type exists only to give the interface methods a receiver.
type detector struct{}

func (detector) ID() string { return patternID }

func (detector) Category() string { return patternCategory }

// isTestishPath reports whether path is itself under a test, fixture, or
// mock directory (or is such a top-level directory with no leading
// separator, e.g. "test/auth.go" at a repo root) — the allowlisted location
// where a hardcoded fixture value legitimately belongs and this pattern
// must never fire.
func isTestishPath(path string) bool {
	p := strings.ToLower(filepath.ToSlash(path))

	for _, marker := range []string{"/test", "/fixture", "/mock"} {
		if strings.Contains(p, marker) {
			return true
		}
	}
	for _, prefix := range []string{"test/", "fixture/", "mock/"} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// Detect scans path's content line-by-line (skipping entirely any path
// that already lives under a test/fixture/mock directory, per the pattern's
// allowlist) and returns one Match per line where a token/secret-shaped
// variable is assigned one of the known test-fixture-shaped literals. Line
// numbers are 1-based and computed from a real running counter over the
// actual scanned lines, not fabricated or left at zero.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	if isTestishPath(path) {
		return nil
	}

	var matches []llmcheat.Match

	scanner := bufio.NewScanner(bytes.NewReader(content))
	// Source lines can be long; raise the scanner's buffer well above
	// bufio's 64KiB default so a single unusually long line doesn't cause a
	// silent bufio.ErrTooLong scan failure that would make this detector
	// miss real matches.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNum := uint(0)
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, m := range assignRe.FindAllStringSubmatch(line, -1) {
			name := m[1]
			value := m[3]

			if !secretShapedNameRe.MatchString(name) {
				continue
			}
			if !dirtyLiteralRe.MatchString(value) {
				continue
			}

			matches = append(matches, llmcheat.Match{
				PatternID: patternID,
				Category:  patternCategory,
				Path:      path,
				Line:      lineNum,
				Message: fmt.Sprintf(
					"variable %q is assigned the test-fixture-shaped literal %q outside any test/fixture/mock path — looks like a hardcoded test credential smuggled into production code",
					name, value,
				),
				Severity: llmcheat.SeverityHigh,
			})
		}
	}

	return matches
}

func init() {
	llmcheat.Register(detector{})
}
