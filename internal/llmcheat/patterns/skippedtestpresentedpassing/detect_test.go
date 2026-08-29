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

package skippedtestpresentedpassing

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

func TestIDAndCategory(t *testing.T) {
	d := &detector{}
	if got, want := d.ID(), "skipped-test-presented-passing"; got != want {
		t.Errorf("ID() = %q, want %q", got, want)
	}
	if got, want := d.Category(), "test-integrity-violation"; got != want {
		t.Errorf("Category() = %q, want %q", got, want)
	}
}

func assertAllMatches(t *testing.T, matches []llmcheat.Match, wantPath string) {
	t.Helper()
	for _, m := range matches {
		if m.PatternID != "skipped-test-presented-passing" {
			t.Errorf("match PatternID = %q, want %q", m.PatternID, "skipped-test-presented-passing")
		}
		if m.Category != "test-integrity-violation" {
			t.Errorf("match Category = %q, want %q", m.Category, "test-integrity-violation")
		}
		if m.Path != wantPath {
			t.Errorf("match Path = %q, want %q", m.Path, wantPath)
		}
	}
}

// --- Python: @pytest.mark.skip -------------------------------------------

// TestDirty_PytestSkipBareNoReason is the pattern spec's dirty shape
// ("@pytest.mark.skip\ndef test_edge_case(): ...") expanded into a realistic
// module. It must produce at least one match.
func TestDirty_PytestSkipBareNoReason(t *testing.T) {
	src := `"""Edge case tests for the parser."""


class TestParser:
    """Tests for the config parser."""

    @pytest.mark.skip
    def test_edge_case(self):
        assert parse_config(EDGE_CASE_INPUT) == EXPECTED
`
	d := &detector{}
	matches := d.Detect("test_parser.py", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1\nsource:\n%s\nmatches: %+v", len(matches), src, matches)
	}
	assertAllMatches(t, matches, "test_parser.py")
	if matches[0].Line != 7 {
		t.Errorf("Line = %d, want 7 (the @pytest.mark.skip line)", matches[0].Line)
	}
	if matches[0].Severity != llmcheat.SeverityMedium {
		t.Errorf("Severity = %q, want %q (no nearby \"all tests pass\" claim)", matches[0].Severity, llmcheat.SeverityMedium)
	}
}

// TestClean_PytestSkipWithReason is the pattern spec's clean shape
// ("@pytest.mark.skip(reason=\"requires live network, see issue #42\")")
// expanded into a realistic module. It must produce zero matches -- notably
// including verifying that the '#' inside the reason string (a URL/issue
// fragment) is not mistaken for a Python comment start.
func TestClean_PytestSkipWithReason(t *testing.T) {
	src := `"""Edge case tests for the parser."""


class TestParser:
    @pytest.mark.skip(reason="requires live network, see issue #42")
    def test_edge_case(self):
        assert parse_config(EDGE_CASE_INPUT) == EXPECTED
`
	d := &detector{}
	matches := d.Detect("test_parser.py", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0\nsource:\n%s\nmatches: %+v", len(matches), src, matches)
	}
}

// TestClean_PytestSkipWithPositionalReasonString covers pytest's positional
// reason form (skip(reason="") accepts the reason positionally too).
func TestClean_PytestSkipWithPositionalReasonString(t *testing.T) {
	src := "@pytest.mark.skip(\"not yet supported on Windows CI\")\ndef test_windows_only(self):\n    pass\n"

	d := &detector{}
	matches := d.Detect("test_platform.py", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0\nsource:\n%s\nmatches: %+v", len(matches), src, matches)
	}
}

// TestDirty_PytestSkipEmptyParens covers the "@pytest.mark.skip()" shape:
// an argument list is present syntactically but carries no content, which
// is just as unexplained as the fully bare decorator.
func TestDirty_PytestSkipEmptyParens(t *testing.T) {
	src := "@pytest.mark.skip()\ndef test_edge_case(self):\n    pass\n"

	d := &detector{}
	matches := d.Detect("test_empty.py", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1\nsource:\n%s\nmatches: %+v", len(matches), src, matches)
	}
	if matches[0].Line != 1 {
		t.Errorf("Line = %d, want 1", matches[0].Line)
	}
}

// TestClean_PytestSkipMultilineWithReason covers a common real-world
// formatting where the decorator call spans multiple lines with the reason
// on its own line; the detector must join forward lines to find it.
func TestClean_PytestSkipMultilineWithReason(t *testing.T) {
	src := `class TestFlaky:
    @pytest.mark.skip(
        reason="flaky in CI, see issue #77",
    )
    def test_flaky(self):
        pass
`
	d := &detector{}
	matches := d.Detect("test_flaky.py", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 (multi-line reason)\nsource:\n%s\nmatches: %+v", len(matches), src, matches)
	}
}

// TestDirty_PytestSkipMultilineEmptyParens is the multi-line counterpart of
// TestDirty_PytestSkipEmptyParens: the call spans lines but never actually
// supplies any argument content before the closing paren.
func TestDirty_PytestSkipMultilineEmptyParens(t *testing.T) {
	src := `class TestFlaky:
    @pytest.mark.skip(
    )
    def test_flaky(self):
        pass
`
	d := &detector{}
	matches := d.Detect("test_flaky_bare.py", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1\nsource:\n%s\nmatches: %+v", len(matches), src, matches)
	}
	if matches[0].Line != 2 {
		t.Errorf("Line = %d, want 2 (the line the call opens on)", matches[0].Line)
	}
}

// TestClean_PytestSkipifNotFlagged ensures the conditional-skip decorator
// skipif (out of this pattern's stated scope: it always documents its own
// condition) is never matched by the bare-skip marker regex.
func TestClean_PytestSkipifNotFlagged(t *testing.T) {
	src := "@pytest.mark.skipif(sys.platform == \"win32\", reason=\"posix only\")\ndef test_posix_only(self):\n    pass\n"

	d := &detector{}
	matches := d.Detect("test_skipif.py", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 (skipif is out of scope)\nsource:\n%s\nmatches: %+v", len(matches), src, matches)
	}
}

// TestClean_CommentedOutPytestSkipIgnored ensures a "@pytest.mark.skip" that
// appears only inside a '#' comment (never actually applied) is not flagged.
func TestClean_CommentedOutPytestSkipIgnored(t *testing.T) {
	src := "class TestParser:\n    # @pytest.mark.skip  # old, now fixed and re-enabled\n    def test_edge_case(self):\n        pass\n"

	d := &detector{}
	matches := d.Detect("test_commented.py", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 (decorator was commented out)\nsource:\n%s\nmatches: %+v", len(matches), src, matches)
	}
}

// TestDirty_PytestSkipNearAllTestsPassClaim covers the aggravated case named
// explicitly in the pattern description: an unexplained skip sitting next to
// a comment claiming the whole suite passes. It must still match, and at
// SeverityHigh rather than the baseline SeverityMedium.
func TestDirty_PytestSkipNearAllTestsPassClaim(t *testing.T) {
	src := `class TestParser:
    # NOTE: all tests pass in CI now.
    @pytest.mark.skip
    def test_edge_case(self):
        assert parse_config(EDGE_CASE_INPUT) == EXPECTED
`
	d := &detector{}
	matches := d.Detect("test_claims_passing.py", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1\nsource:\n%s\nmatches: %+v", len(matches), src, matches)
	}
	if matches[0].Line != 3 {
		t.Errorf("Line = %d, want 3", matches[0].Line)
	}
	if matches[0].Severity != llmcheat.SeverityHigh {
		t.Errorf("Severity = %q, want %q (nearby \"all tests pass\" claim must aggravate)", matches[0].Severity, llmcheat.SeverityHigh)
	}
}

// --- Rust: #[ignore] -------------------------------------------------------

func TestDirty_RustIgnoreBareNoReason(t *testing.T) {
	src := `#[test]
#[ignore]
fn test_race_condition_detection() {
    let result = detect_race(&INPUT);
    assert_eq!(result, EXPECTED);
}
`
	d := &detector{}
	matches := d.Detect("race_test.rs", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1\nsource:\n%s\nmatches: %+v", len(matches), src, matches)
	}
	assertAllMatches(t, matches, "race_test.rs")
	if matches[0].Line != 2 {
		t.Errorf("Line = %d, want 2 (the #[ignore] line)", matches[0].Line)
	}
}

func TestClean_RustIgnoreWithReason(t *testing.T) {
	src := `#[test]
#[ignore = "requires live network, see issue #42"]
fn test_race_condition_detection() {
    let result = detect_race(&INPUT);
    assert_eq!(result, EXPECTED);
}
`
	d := &detector{}
	matches := d.Detect("race_test.rs", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0\nsource:\n%s\nmatches: %+v", len(matches), src, matches)
	}
}

func TestClean_RustIgnoreCommentedOutIgnored(t *testing.T) {
	src := "// #[ignore] // old, now fixed\n#[test]\nfn test_race_condition_detection() {}\n"

	d := &detector{}
	matches := d.Detect("race_test_commented.rs", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 (attribute was commented out)\nsource:\n%s\nmatches: %+v", len(matches), src, matches)
	}
}

// --- JS/TS: it.skip(/xit(/test.skip( ---------------------------------------

func TestDirty_JSItSkipNoComment(t *testing.T) {
	src := `describe('parser', () => {
  it.skip('handles the edge case input', () => {
    expect(parse(EDGE_CASE_INPUT)).toEqual(EXPECTED);
  });
});
`
	d := &detector{}
	matches := d.Detect("parser.test.js", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1\nsource:\n%s\nmatches: %+v", len(matches), src, matches)
	}
	assertAllMatches(t, matches, "parser.test.js")
	if matches[0].Line != 2 {
		t.Errorf("Line = %d, want 2 (the it.skip( line)", matches[0].Line)
	}
	if matches[0].Severity != llmcheat.SeverityMedium {
		t.Errorf("Severity = %q, want %q", matches[0].Severity, llmcheat.SeverityMedium)
	}
}

func TestClean_JSItSkipWithTrailingComment(t *testing.T) {
	src := `describe('parser', () => {
  it.skip('handles the edge case input', () => { // requires live network, see issue #42
    expect(parse(EDGE_CASE_INPUT)).toEqual(EXPECTED);
  });
});
`
	d := &detector{}
	matches := d.Detect("parser.test.js", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 (trailing reason comment)\nsource:\n%s\nmatches: %+v", len(matches), src, matches)
	}
}

func TestClean_JSItSkipWithPrecedingCommentLine(t *testing.T) {
	src := `describe('parser', () => {
  // requires live network, see issue #42
  it.skip('handles the edge case input', () => {
    expect(parse(EDGE_CASE_INPUT)).toEqual(EXPECTED);
  });
});
`
	d := &detector{}
	matches := d.Detect("parser.test.ts", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 (preceding whole-line reason comment)\nsource:\n%s\nmatches: %+v", len(matches), src, matches)
	}
}

func TestDirty_JSXitNoComment(t *testing.T) {
	src := `describe('parser', () => {
  xit('handles the edge case input', () => {
    expect(parse(EDGE_CASE_INPUT)).toEqual(EXPECTED);
  });
});
`
	d := &detector{}
	matches := d.Detect("parser.test.jsx", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1\nsource:\n%s\nmatches: %+v", len(matches), src, matches)
	}
	if matches[0].Line != 2 {
		t.Errorf("Line = %d, want 2", matches[0].Line)
	}
}

func TestDirty_JSTestSkipNearAllTestsPassClaim(t *testing.T) {
	// The "all tests passing" claim sits two lines above the skip (outside
	// the immediately-preceding-line "reason comment" check, but still
	// inside the nearby-claim aggravation window), so this must still match
	// as unexplained -- just at the higher, aggravated severity.
	src := `// CI dashboard: all tests passing as of this commit.

test.skip('parses the edge case input', () => {
  expect(parse(EDGE_CASE_INPUT)).toEqual(EXPECTED);
});
`
	d := &detector{}
	matches := d.Detect("parser.test.tsx", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1\nsource:\n%s\nmatches: %+v", len(matches), src, matches)
	}
	if matches[0].Severity != llmcheat.SeverityHigh {
		t.Errorf("Severity = %q, want %q (nearby \"all tests passing\" claim must aggravate)", matches[0].Severity, llmcheat.SeverityHigh)
	}
}

func TestClean_JSNoFalsePositiveOnSimilarIdentifiers(t *testing.T) {
	src := `function exit(code) {
  process.exitCode = code;
}

function sometest_skip_helper() {
  return true;
}
`
	d := &detector{}
	matches := d.Detect("helpers.test.js", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 (exit()/sometest_skip_helper() are not xit(/test.skip()\nsource:\n%s\nmatches: %+v", len(matches), src, matches)
	}
}

// --- File-extension gating --------------------------------------------------

func TestClean_UnsupportedExtensionIgnored(t *testing.T) {
	src := "@pytest.mark.skip\ndef test_edge_case(): pass\n"

	d := &detector{}
	matches := d.Detect("NOTES.md", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() on a .md path returned %d matches, want 0\nmatches: %+v", len(matches), matches)
	}
}

// --- Registry integration ---------------------------------------------------

// TestDirty_RegisteredInGlobalRegistry is a real, non-mocked integration
// check: verify this package's init() actually registered a Pattern into
// the shared llmcheat registry (not just that the local *detector value
// behaves correctly in isolation), then reset the registry afterward so
// this test doesn't leak state into other packages' test binaries.
func TestDirty_RegisteredInGlobalRegistry(t *testing.T) {
	found := false
	for _, p := range llmcheat.All() {
		if p.ID() == "skipped-test-presented-passing" {
			found = true
			if p.Category() != "test-integrity-violation" {
				t.Errorf("registered pattern Category() = %q, want %q", p.Category(), "test-integrity-violation")
			}
		}
	}
	if !found {
		t.Fatal("skipped-test-presented-passing was not found in llmcheat.All() after package init()")
	}
}
