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

// Package tautologicalassertion implements the "tautological-assertion"
// llmcheat.Pattern: it flags an assertion statement that can never fail
// regardless of code behavior — a bare boolean-literal assertion (Python's
// `assert True`, C/JS/Node's `assert(true)`, Jest's
// `expect(true).toBe(true)`) or an equality assertion where the same
// expression appears on both sides (`assert 1 == 1`, Rust's
// `assert_eq!(1, 1)`, or the generalized `assert x == x`). This is a common
// LLM-cheat tell in test scaffolding: the assertion is syntactically
// present, the test file "has coverage", and the test passes every single
// run — but it verifies nothing about the code under test, because its
// truth value does not depend on that code at all.
//
// This pattern has no stated file-type restriction (the shapes it looks for
// span Python, Rust, and JS/TS test files, plus any other language with a
// similarly-spelled assert construct), so Detect runs on any text content
// it is given, line by line.
package tautologicalassertion

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID       = "tautological-assertion"
	patternCategory = "test-integrity-violation"
)

var (
	// pyAssertTrueRe matches Python's bare `assert True` — optionally
	// parenthesized (`assert(True)`), optionally followed by a
	// `, "message"` clause or a trailing comment — the canonical shape of
	// an assertion whose truth value is a hardcoded literal rather than a
	// real check of any computed condition.
	pyAssertTrueRe = regexp.MustCompile(`\bassert\s*\(?\s*True\s*\)?(\s*,|\s*#|\s*$)`)

	// cAssertTrueRe matches the C/JS/TS/Node function-call form
	// `assert(true)` (node:assert, chai's assert, C's assert.h) — a
	// lowercase `true` literal passed directly as the sole condition.
	cAssertTrueRe = regexp.MustCompile(`\bassert\s*\(\s*true\s*\)`)

	// jestExpectTrueRe matches Jest/Jasmine's `expect(true).toBe(true)` —
	// asserting that the literal `true` equals the literal `true`.
	jestExpectTrueRe = regexp.MustCompile(`\bexpect\s*\(\s*true\s*\)\s*\.\s*toBe\s*\(\s*true\s*\)`)

	// genericSelfEqRe matches a generic `assert <expr> == <expr>`
	// statement (Python, or any C-family `assert` expression statement),
	// capturing both sides of the `==` so the caller can check whether
	// they are the same expression — e.g. `assert 1 == 1` or
	// `assert x == x`, which are true independent of any real computation.
	genericSelfEqRe = regexp.MustCompile(`\bassert\s+(\S+?)\s*==\s*(\S+?)\s*(,|#|;|$)`)

	// rustAssertEqMacroRe matches Rust's `assert_eq!(<expr>, <expr>)`
	// macro, capturing both arguments so the caller can check whether they
	// are the same expression — e.g. `assert_eq!(1, 1)`.
	rustAssertEqMacroRe = regexp.MustCompile(`\bassert_eq!\s*\(\s*([^,()]+?)\s*,\s*([^,()]+?)\s*\)`)
)

// detector is the real, stateless implementation of llmcheat.Pattern for
// this pattern. It holds no fields because Detect is a pure function of its
// arguments: the type exists only to give the interface methods a receiver.
type detector struct{}

func (detector) ID() string { return patternID }

func (detector) Category() string { return patternCategory }

// Detect scans path's content line-by-line and returns one Match for every
// line that contains an assertion that can never fail regardless of code
// behavior. Line numbers are 1-based and computed from a real running
// counter over the actual scanned lines, not fabricated or left at zero.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	var matches []llmcheat.Match

	scanner := bufio.NewScanner(bytes.NewReader(content))
	// Source lines can be long (e.g. a wrapped assertion message); raise
	// the scanner's buffer well above bufio's 64KiB default so a single
	// unusually long line doesn't cause a silent bufio.ErrTooLong scan
	// failure that would make this detector miss real matches.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNum := uint(0)
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		msg, ok := tautologyMessage(line)
		if !ok {
			continue
		}

		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  patternCategory,
			Path:      path,
			Line:      lineNum,
			Message:   msg,
			Severity:  llmcheat.SeverityHigh,
		})
	}

	return matches
}

// tautologyMessage inspects a single source line and, if it contains an
// assertion that can never fail regardless of code behavior, returns a
// human-readable explanation and true. Checks run in a fixed order, and
// return on the first hit, so a line that happens to satisfy more than one
// shape at once (e.g. `assert True == True`, which the bare-literal check
// fails to anchor on but the self-equality check does catch) produces
// exactly one Match rather than being double-reported.
func tautologyMessage(line string) (string, bool) {
	switch {
	case pyAssertTrueRe.MatchString(line):
		return fmt.Sprintf(
			"bare `assert True` can never fail regardless of code behavior: %s",
			strings.TrimSpace(line),
		), true
	case jestExpectTrueRe.MatchString(line):
		return fmt.Sprintf(
			"`expect(true).toBe(true)` can never fail regardless of code behavior: %s",
			strings.TrimSpace(line),
		), true
	case cAssertTrueRe.MatchString(line):
		return fmt.Sprintf(
			"`assert(true)` can never fail regardless of code behavior: %s",
			strings.TrimSpace(line),
		), true
	}

	if m := rustAssertEqMacroRe.FindStringSubmatch(line); m != nil {
		if lhs, rhs := normalizeExpr(m[1]), normalizeExpr(m[2]); lhs != "" && lhs == rhs {
			return fmt.Sprintf(
				"assert_eq!() compares %q to itself and can never fail: %s",
				lhs, strings.TrimSpace(line),
			), true
		}
	}

	if m := genericSelfEqRe.FindStringSubmatch(line); m != nil {
		if lhs, rhs := normalizeExpr(m[1]), normalizeExpr(m[2]); lhs != "" && lhs == rhs {
			return fmt.Sprintf(
				"assertion compares %q to itself and can never fail: %s",
				lhs, strings.TrimSpace(line),
			), true
		}
	}

	return "", false
}

// normalizeExpr trims surrounding whitespace and a trailing statement
// separator (Python's optional `, "message"` clause boundary, a C-family
// `;` terminator) so `1` and `1,` — or `x` and `x;` — compare equal as the
// same expression when checking the two sides of an equality/macro-argument
// pair for self-comparison.
func normalizeExpr(expr string) string {
	return strings.TrimSpace(strings.TrimRight(strings.TrimSpace(expr), ",;"))
}

func init() {
	llmcheat.Register(detector{})
}
