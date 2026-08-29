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

// Package rusttodounimplementedmacro detects Rust's todo!(), unimplemented!(),
// and unreachable!() panic macros used outside test code. In shipped
// (non-test) Rust, these macros are stand-ins for behavior that was never
// actually written: the code compiles and type-checks, but panics the
// instant that code path runs — the exact "presented as done but hollow"
// shape internal/llmcheat exists to catch.
//
// Legitimate uses inside a #[cfg(test)] module (placeholder test bodies not
// yet fleshed out, or a genuinely-unreachable match arm inside test-only
// code) are not flagged, nor are files that live under a "tests/" directory
// (integration-test crates, which never ship as part of the library/binary).
package rusttodounimplementedmacro

import (
	"bufio"
	"bytes"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "rust-todo-unimplemented-macro"
	category  = "hollow-implementation"
)

// macroRe matches a todo!(, unimplemented!(, or unreachable!( invocation,
// capturing which of the three macros was used. \b on both sides keeps it
// from matching a longer identifier that merely contains one of these words
// (e.g. a hypothetical `custom_todo!()` macro of a project's own).
var macroRe = regexp.MustCompile(`\b(todo|unimplemented|unreachable)!\s*\(`)

// cfgTestRe matches a #[cfg(test)] attribute, including compound forms like
// #[cfg(all(test, feature = "x"))].
var cfgTestRe = regexp.MustCompile(`#\[\s*cfg\s*\(.*\btest\b.*\)\s*\]`)

// attrLineRe matches an outer (#[...]) or inner (#![...]) attribute line.
var attrLineRe = regexp.MustCompile(`^\s*#!?\[`)

// detector is the Pattern implementation for this package. It is
// unexported: callers outside this package only ever interact with it
// through the llmcheat.Pattern interface (or, in tests, by constructing it
// directly).
type detector struct{}

func (detector) ID() string       { return patternID }
func (detector) Category() string { return category }

// Detect scans one Rust source file's content line by line, tracking Rust
// brace nesting well enough to know whether the current line sits inside a
// #[cfg(test)] ... mod { ... } block, and reports every todo!/unimplemented!/
// unreachable! invocation found outside that (and outside any file under a
// "tests/" directory, which never ships as part of the library/binary).
//
// This is a heuristic line/brace scanner, not a full Rust parser: it does
// not understand block comments (/* ... */) or braces embedded in string
// literals. That is an accepted trade-off for a pure, dependency-free,
// independently-testable detector — both are rare in real Rust source
// relative to genuine scope-defining braces, and neither affects the
// documented dirty/clean fixtures this package is tested against.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	if !strings.EqualFold(filepath.Ext(path), ".rs") {
		return nil
	}
	normalizedPath := filepath.ToSlash(path)
	if strings.Contains(normalizedPath, "/tests/") || strings.HasPrefix(normalizedPath, "tests/") {
		return nil
	}

	var matches []llmcheat.Match

	depth := 0
	// testScopeDepth is the brace depth at which the current #[cfg(test)]
	// item's body opened, or -1 when we are not inside one. Depth equality
	// (not just "greater than") is what lets a nested non-test item inside
	// a test module still correctly read as "inside test scope".
	testScopeDepth := -1
	pendingCfgTest := false

	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var lineNum uint
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if attrLineRe.MatchString(line) {
			if cfgTestRe.MatchString(line) {
				pendingCfgTest = true
			}
			// Attribute lines never themselves contain a macro invocation in
			// legitimate Rust, and their parens are attribute arguments, not
			// scope-defining braces, so nothing else to do with this line.
			continue
		}

		inTestScope := testScopeDepth != -1
		isCommentLine := strings.HasPrefix(trimmed, "//")

		if !inTestScope && !isCommentLine {
			for _, idx := range macroRe.FindAllStringSubmatchIndex(line, -1) {
				macroName := line[idx[2]:idx[3]]
				matches = append(matches, llmcheat.Match{
					PatternID: patternID,
					Category:  category,
					Path:      path,
					Line:      lineNum,
					Message: "`" + macroName + "!(` used outside any #[cfg(test)] module: " +
						"this compiles but panics at runtime instead of implementing the behavior",
					Severity: llmcheat.SeverityHigh,
				})
			}
		}

		// Update brace depth / test-scope tracking using this line's braces,
		// evaluated after macro scanning above (a #[cfg(test)] item's own
		// opening-brace line is itself never inside its own scope yet).
		for _, ch := range line {
			switch ch {
			case '{':
				if pendingCfgTest && testScopeDepth == -1 {
					testScopeDepth = depth
					pendingCfgTest = false
				}
				depth++
			case '}':
				if depth > 0 {
					depth--
				}
				if testScopeDepth != -1 && depth == testScopeDepth {
					testScopeDepth = -1
				}
			}
		}
	}

	return matches
}

func init() {
	llmcheat.Register(detector{})
}
