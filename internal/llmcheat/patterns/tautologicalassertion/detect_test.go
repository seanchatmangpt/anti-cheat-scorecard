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

package tautologicalassertion

import (
	"strings"
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// pyDirtySource is a realistic multi-line Python test module: a real
// assertion-driven test alongside one whose body is a placeholder
// `assert True` rather than a real check of any computed condition.
const pyDirtySource = `import unittest


class SanityTest(unittest.TestCase):
    def test_placeholder(self):
        assert True  # sanity check

    def test_real_thing(self):
        result = compute()
        assert result.status == "ALIVE"
`

// pyCleanSource is a realistic multi-line Python test module where every
// assertion checks a real, computed condition and none of them can pass
// independent of the code under test.
const pyCleanSource = `import unittest


class PipelineTest(unittest.TestCase):
    def test_pipeline_completes(self):
        result = run_pipeline(config)
        assert result.status == "ALIVE"
        assert result.error is None
        assert len(result.records) == 42
`

// rustDirtySource is a realistic multi-line Rust test module: one real
// arithmetic test alongside one whose body is a placeholder
// assert_eq!(1, 1) that compares a literal to itself.
const rustDirtySource = `#[test]
fn test_placeholder() {
    assert_eq!(1, 1);
}

#[test]
fn test_real_addition() {
    let sum = add(2, 3);
    assert_eq!(sum, 5);
}
`

// jsDirtySource is a realistic multi-line TypeScript/Jest+chai test module
// mixing a real assertion against computed output with two tautological
// shapes: Jest's expect(true).toBe(true) and node:assert's assert(true).
const jsDirtySource = `import { expect } from "chai";
import assert from "node:assert";

describe("sanity", () => {
  it("passes trivially", () => {
    expect(true).toBe(true);
  });

  it("checks the real assertion library too", () => {
    assert(true);
  });

  it("validates real output", () => {
    const result = computeTotal(items);
    assert(result.total === 42);
  });
});
`

// findLine returns the 1-based line number of the first line in source
// containing substr, deriving it directly from the fixture text itself
// (rather than a hand-counted literal, which is easy to get off-by-one on a
// multi-line raw string) so assertions stay correct even if a fixture is
// edited later. It fails the test if substr is not found at all.
func findLine(t *testing.T, source, substr string) uint {
	t.Helper()
	for i, line := range strings.Split(source, "\n") {
		if strings.Contains(line, substr) {
			return uint(i + 1) //nolint:gosec // line count from a real split, never overflows uint
		}
	}
	t.Fatalf("test fixture bug: source does not contain %q", substr)
	return 0
}

func TestDetect_PythonBareAssertTrue_ProducesMatch(t *testing.T) {
	d := detector{}

	matches := d.Detect("tests/test_sanity.py", []byte(pyDirtySource))

	if len(matches) != 1 {
		t.Fatalf("Detect() on Python dirty fixture = %d matches, want 1; matches=%+v", len(matches), matches)
	}

	got := matches[0]
	if got.PatternID != patternID {
		t.Errorf("Match.PatternID = %q, want %q", got.PatternID, patternID)
	}
	if got.Category != patternCategory {
		t.Errorf("Match.Category = %q, want %q", got.Category, patternCategory)
	}
	if got.Path != "tests/test_sanity.py" {
		t.Errorf("Match.Path = %q, want %q", got.Path, "tests/test_sanity.py")
	}
	wantLine := findLine(t, pyDirtySource, "assert True")
	if got.Line != wantLine {
		t.Errorf("Match.Line = %d, want %d", got.Line, wantLine)
	}
	if got.Severity != llmcheat.SeverityHigh {
		t.Errorf("Match.Severity = %q, want %q", got.Severity, llmcheat.SeverityHigh)
	}
	if got.Message == "" {
		t.Error("Match.Message is empty, want a real explanation")
	}
}

func TestDetect_PythonCleanRealAssertions_ProducesNoMatches(t *testing.T) {
	d := detector{}

	matches := d.Detect("tests/test_pipeline.py", []byte(pyCleanSource))

	if len(matches) != 0 {
		t.Fatalf("Detect() on Python clean fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

func TestDetect_RustAssertEqSelfComparison_ProducesMatchOnlyForTautology(t *testing.T) {
	d := detector{}

	matches := d.Detect("tests/placeholder.rs", []byte(rustDirtySource))

	if len(matches) != 1 {
		t.Fatalf("Detect() on Rust dirty fixture = %d matches, want 1; matches=%+v", len(matches), matches)
	}

	got := matches[0]
	if got.PatternID != patternID {
		t.Errorf("Match.PatternID = %q, want %q", got.PatternID, patternID)
	}
	if got.Category != patternCategory {
		t.Errorf("Match.Category = %q, want %q", got.Category, patternCategory)
	}
	wantLine := findLine(t, rustDirtySource, "assert_eq!(1, 1)")
	if got.Line != wantLine {
		t.Errorf("Match.Line = %d, want %d", got.Line, wantLine)
	}
	// The second assert_eq!(sum, 5) in the same fixture compares a real
	// computed value to an expected literal — it must NOT be the line that
	// was flagged.
	if strings.Contains(got.Message, "sum") {
		t.Errorf("Match.Message unexpectedly references the real assert_eq!(sum, 5) call: %q", got.Message)
	}
}

func TestDetect_JsExpectTrueAndAssertTrue_ProducesMatchesOnlyForTautologies(t *testing.T) {
	d := detector{}

	matches := d.Detect("tests/sanity.test.ts", []byte(jsDirtySource))

	if len(matches) != 2 {
		t.Fatalf("Detect() on JS/TS dirty fixture = %d matches, want 2; matches=%+v", len(matches), matches)
	}

	wantExpectLine := findLine(t, jsDirtySource, "expect(true).toBe(true)")
	wantAssertLine := findLine(t, jsDirtySource, "assert(true)")

	gotLines := map[uint]llmcheat.Match{}
	for _, m := range matches {
		gotLines[m.Line] = m
		if m.PatternID != patternID {
			t.Errorf("Match.PatternID = %q, want %q", m.PatternID, patternID)
		}
		if m.Category != patternCategory {
			t.Errorf("Match.Category = %q, want %q", m.Category, patternCategory)
		}
	}
	if _, ok := gotLines[wantExpectLine]; !ok {
		t.Errorf("no match reported for expect(true).toBe(true) at line %d; matches=%+v", wantExpectLine, matches)
	}
	if _, ok := gotLines[wantAssertLine]; !ok {
		t.Errorf("no match reported for assert(true) at line %d; matches=%+v", wantAssertLine, matches)
	}
	// The real assertion against computed output (assert(result.total ===
	// 42)) must not have been flagged.
	for line := range gotLines {
		if line != wantExpectLine && line != wantAssertLine {
			t.Errorf("unexpected match at line %d; matches=%+v", line, matches)
		}
	}
}

// TestDetect_SelfEqualityGeneralization_IdentifierTautologyVsRealInequality
// covers the generalized "compares an expression to itself" boundary the
// pattern description implies ("an assertion that can never fail regardless
// of code behavior") beyond the literal `1 == 1` example: `assert x == x`
// is tautological for any value of x, while `assert 1 == 2` is a real
// (always-failing, not tautological) comparison of two distinct literals
// and must not be flagged by this pattern.
func TestDetect_SelfEqualityGeneralization_IdentifierTautologyVsRealInequality(t *testing.T) {
	const src = `def test_self_equality_edge_cases():
    assert x == x  # always true regardless of x's value
    assert 1 == 2  # always false, but not a self-comparison tautology
`
	d := detector{}

	matches := d.Detect("tests/test_edge_cases.py", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() on self-equality edge-case fixture = %d matches, want 1; matches=%+v", len(matches), matches)
	}

	got := matches[0]
	wantLine := findLine(t, src, "assert x == x")
	if got.Line != wantLine {
		t.Errorf("Match.Line = %d, want %d", got.Line, wantLine)
	}
	if got.PatternID != patternID {
		t.Errorf("Match.PatternID = %q, want %q", got.PatternID, patternID)
	}
	if got.Category != patternCategory {
		t.Errorf("Match.Category = %q, want %q", got.Category, patternCategory)
	}
}

func TestPattern_IDAndCategory(t *testing.T) {
	d := detector{}

	if got := d.ID(); got != patternID {
		t.Errorf("ID() = %q, want %q", got, patternID)
	}
	if got := d.Category(); got != patternCategory {
		t.Errorf("Category() = %q, want %q", got, patternCategory)
	}
}
