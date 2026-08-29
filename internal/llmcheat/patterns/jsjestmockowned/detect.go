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

// Package jsjestmockowned implements the "js-jest-mock-owned"
// internal/llmcheat.Pattern: it flags JavaScript/TypeScript test files that
// reach for jest.mock(...) or jest.fn(...) instead of exercising a real,
// codebase-owned collaborator.
//
// This is the JS/TS-specific instance of the Chicago-school (classicist)
// testing discipline this whole tool is built to enforce: interaction-based
// mocking of a collaborator the project owns (or that is realistically
// runnable in-process/locally) hides whether the real integration actually
// works, and an LLM asked to "make the tests pass" will reach for
// jest.mock/jest.fn far more readily than it will wire up a real
// dependency. jest.mock(...) replaces an entire owned module wholesale;
// jest.fn() fabricates an interaction-only stand-in — both let a test
// verify the test's own model of a collaborator rather than the real one.
package jsjestmockowned

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
	patternID = "js-jest-mock-owned"
	category  = "test-integrity-violation"
)

// jestMockRe matches a `jest.mock(` call (optional whitespace around the
// dot and before the opening paren) — jest's whole-module-replacement API.
var jestMockRe = regexp.MustCompile(`\bjest\s*\.\s*mock\s*\(`)

// jestFnRe matches a `jest.fn(` call, with or without an implementation
// argument — jest's ad hoc mock-function factory.
var jestFnRe = regexp.MustCompile(`\bjest\s*\.\s*fn\s*\(`)

// relevantExts is the set of file extensions this pattern inspects.
var relevantExts = map[string]bool{
	".ts":  true,
	".tsx": true,
	".js":  true,
	".jsx": true,
}

// testFileSuffixes lists the "<ext-family>.<ts|js variant>" filename
// suffixes that mark a file as a test file on their own, regardless of
// directory.
var testFileSuffixes = []string{
	".test.ts", ".spec.ts",
	".test.tsx", ".spec.tsx",
	".test.js", ".spec.js",
	".test.jsx", ".spec.jsx",
}

// detector implements llmcheat.Pattern for jest.mock(...)/jest.fn(...)
// usage inside JS/TS test files.
type detector struct{}

// newDetector constructs a fresh detector. It has no state, so every call
// returns an equivalent, independently usable instance — tests use this
// directly rather than reaching into the package-level registry.
func newDetector() *detector {
	return &detector{}
}

func (d *detector) ID() string { return patternID }

func (d *detector) Category() string { return category }

// Detect scans content line-by-line looking for jest.mock(...) or
// jest.fn(...) calls, but only inside files this pattern considers a JS/TS
// test file (see isTestFile). Non-test source files are never flagged: a
// production module reaching for something named "jest" would be unusual
// enough to be a different problem, and is out of scope for this pattern.
func (d *detector) Detect(path string, content []byte) []llmcheat.Match {
	if !isTestFile(path) {
		return nil
	}

	var matches []llmcheat.Match

	scanner := bufio.NewScanner(bytes.NewReader(content))
	// Widen the default 64KiB scanner limit so a single very long
	// (e.g. minified or generated) source line doesn't abort the scan.
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var lineNo uint
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()

		for _, loc := range jestMockRe.FindAllString(line, -1) {
			matches = append(matches, llmcheat.Match{
				PatternID: patternID,
				Category:  category,
				Path:      path,
				Line:      lineNo,
				Message: fmt.Sprintf(
					"test-integrity violation: %q replaces an owned module wholesale instead of exercising the real collaborator — prefer a real object/subprocess/local service per the Chicago-school (classicist) testing discipline",
					strings.TrimSpace(loc),
				),
				Severity: llmcheat.SeverityHigh,
			})
		}

		for _, loc := range jestFnRe.FindAllString(line, -1) {
			matches = append(matches, llmcheat.Match{
				PatternID: patternID,
				Category:  category,
				Path:      path,
				Line:      lineNo,
				Message: fmt.Sprintf(
					"test-integrity violation: %q fabricates an interaction-only mock function instead of asserting on real returned/persisted state — prefer a real collaborator and a state-based assertion",
					strings.TrimSpace(loc),
				),
				Severity: llmcheat.SeverityMedium,
			})
		}
	}

	return matches
}

// isTestFile reports whether path is a JS/TS test file this pattern should
// inspect: it must have a relevant JS/TS extension, and it must either sit
// under a "/test.../" or "/__tests__/" directory, or be named
// "*.test.<ext>"/"*.spec.<ext>" for one of the relevant extensions.
func isTestFile(path string) bool {
	if !relevantExts[strings.ToLower(filepath.Ext(path))] {
		return false
	}

	slashPath := filepath.ToSlash(path)
	// Prepend a leading "/" before lower-casing so a path with no
	// directory prefix at all (e.g. "test/service.test.ts", relative to
	// some repo root) still matches the "/test" substring check the same
	// way "src/test/service.test.ts" would.
	lowerPath := "/" + strings.ToLower(strings.TrimPrefix(slashPath, "/"))

	if strings.Contains(lowerPath, "/test") {
		return true
	}
	if strings.Contains(lowerPath, "/__tests__/") {
		return true
	}

	base := strings.ToLower(filepath.Base(slashPath))
	for _, suffix := range testFileSuffixes {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	return false
}

func init() {
	llmcheat.Register(newDetector())
}
