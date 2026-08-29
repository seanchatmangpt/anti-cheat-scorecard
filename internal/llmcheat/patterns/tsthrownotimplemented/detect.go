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

// Package tsthrownotimplemented implements the
// "typescript-throw-not-implemented" internal/llmcheat.Pattern: it flags
// TypeScript/JavaScript functions whose body is nothing more than
//
//	throw new Error("not implemented");
//
// (or the "TODO" spelling, either quote style, any case) — a classic
// hollowed-out stub an LLM leaves behind when it accepts a function
// signature/contract but never actually writes the implementation.
package tsthrownotimplemented

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
	patternID = "typescript-throw-not-implemented"
	category  = "hollow-implementation"
)

// throwErrorRe matches `throw new Error(...)` where the first argument is a
// single- or double-quoted string literal, capturing that literal's body in
// whichever of the two groups actually matched (RE2 has no backreferences,
// so we can't require the same quote character on both ends with a single
// group — two alternative groups do the same job).
var throwErrorRe = regexp.MustCompile(`(?i)throw\s+new\s+Error\s*\(\s*(?:"([^"]*)"|'([^']*)')`)

// relevantExts is the set of file extensions this pattern inspects.
var relevantExts = map[string]bool{
	".ts":  true,
	".tsx": true,
	".js":  true,
	".jsx": true,
}

// testFileSuffixes lists the "<ext-family>.<ts|js variant>" suffixes that
// mark a file as a test file, regardless of which of the four relevant
// extensions it uses.
var testFileSuffixes = []string{
	".test.ts", ".spec.ts",
	".test.tsx", ".spec.tsx",
	".test.js", ".spec.js",
	".test.jsx", ".spec.jsx",
}

// detector implements llmcheat.Pattern for stubbed-out
// `throw new Error("not implemented")` / `throw new Error("TODO...")`
// TypeScript/JavaScript bodies.
type detector struct{}

// newDetector constructs a fresh detector. It has no state, so every call
// returns an equivalent, independently usable instance — tests use this
// directly rather than reaching into the package-level registry.
func newDetector() *detector {
	return &detector{}
}

func (d *detector) ID() string { return patternID }

func (d *detector) Category() string { return category }

// Detect scans content line-by-line looking for `throw new Error(...)`
// calls whose message argument mentions "not implemented" or "todo"
// (case-insensitive), skipping non TS/JS files and test files entirely.
func (d *detector) Detect(path string, content []byte) []llmcheat.Match {
	if !isRelevantFile(path) {
		return nil
	}
	if isTestPath(path) {
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

		for _, sub := range throwErrorRe.FindAllStringSubmatch(line, -1) {
			message := sub[1]
			if message == "" {
				message = sub[2]
			}
			lower := strings.ToLower(message)

			notImplemented := strings.Contains(lower, "not implemented")
			todo := strings.Contains(lower, "todo")
			if !notImplemented && !todo {
				continue
			}

			severity := llmcheat.SeverityMedium
			reason := "references TODO"
			if notImplemented {
				severity = llmcheat.SeverityHigh
				reason = `contains "not implemented"`
			}

			matches = append(matches, llmcheat.Match{
				PatternID: patternID,
				Category:  category,
				Path:      path,
				Line:      lineNo,
				Message: fmt.Sprintf(
					"hollow implementation: throw new Error(%q) %s — function body looks stubbed rather than implemented",
					message, reason,
				),
				Severity: severity,
			})
		}
	}

	return matches
}

// isRelevantFile reports whether path is a TypeScript/JavaScript source
// file this pattern should inspect at all.
func isRelevantFile(path string) bool {
	return relevantExts[strings.ToLower(filepath.Ext(path))]
}

// isTestPath reports whether path looks like a test file — anywhere under a
// "/test.../" or "/__tests__/" directory, or named "*.test.<ext>"/
// "*.spec.<ext>" for one of the relevant extensions — which this pattern
// deliberately does not flag: a stub thrown from a test double/fixture is
// not the same hollow-implementation smell as one left in production code.
func isTestPath(path string) bool {
	slashPath := filepath.ToSlash(path)
	lowerPath := strings.ToLower(slashPath)

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
