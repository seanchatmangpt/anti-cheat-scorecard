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

package overclaimingsuperlative

import (
	"strings"
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// fixture builds realistic file content from explicit lines so every test's
// expected match Line number is correct by construction (index+1) rather
// than by manually counting characters in a raw string literal.
func fixture(lines ...string) []byte {
	return []byte(strings.Join(lines, "\n") + "\n")
}

func assertPatternFields(t *testing.T, matches []llmcheat.Match) {
	t.Helper()
	for _, m := range matches {
		if m.PatternID != patternID {
			t.Errorf("Match.PatternID = %q, want %q", m.PatternID, patternID)
		}
		if m.Category != patternCategory {
			t.Errorf("Match.Category = %q, want %q", m.Category, patternCategory)
		}
	}
}

// TestDetect_DirtyOverclaimingProducesMatch expands the required dirty
// example ("This guarantees correctness 100% of the time.") into a
// realistic multi-line Go comment block and asserts at least one real
// match is produced, with the correct pattern identity and line number.
func TestDetect_DirtyOverclaimingProducesMatch(t *testing.T) {
	content := fixture(
		"package fuzzcheck",
		"",
		"// validate reports whether the fuzz corpus round-trips cleanly.",
		"//",
		"// This guarantees correctness 100% of the time.",
		"func validate() bool {",
		"\treturn true",
		"}",
	)

	d := detector{}
	matches := d.Detect("fuzzcheck/validate.go", content)

	if len(matches) < 1 {
		t.Fatalf("expected at least 1 match for the unqualified overclaiming comment, got %d: %+v", len(matches), matches)
	}
	assertPatternFields(t, matches)
	for _, m := range matches {
		if m.Line != 5 {
			t.Errorf("Match.Line = %d, want 5 (the overclaiming comment line)", m.Line)
		}
	}
}

// TestDetect_CleanQualifiedClaimProducesNoMatch expands the required clean
// example (a percentage derived from a real fuzz-run count, with a file
// citation) into a realistic multi-line block and asserts zero matches.
func TestDetect_CleanQualifiedClaimProducesNoMatch(t *testing.T) {
	content := fixture(
		"package fuzzcheck",
		"",
		"// reportFuzzResults summarizes the latest fuzz corpus run.",
		"//",
		"// 98.7% of 10,000 fuzz runs passed; see receipts/fuzz-20260101.json for the 3 known failures.",
		"func reportFuzzResults() {}",
	)

	d := detector{}
	matches := d.Detect("fuzzcheck/report.go", content)

	if len(matches) != 0 {
		t.Fatalf("expected 0 matches for a percentage derived from a real measured count with a citation, got %d: %+v", len(matches), matches)
	}
}

// TestDetect_HundredPercentWithRealCountIsNotFlagged is the boundary case
// the description calls out explicitly: a literal "100%" is not flagged
// when it is adjacent to a real number+unit count on the same line, even
// without a "see" citation.
func TestDetect_HundredPercentWithRealCountIsNotFlagged(t *testing.T) {
	content := fixture(
		"package fuzzcheck",
		"",
		"// The regression suite passed 100% across 5,000 CI runs today.",
		"func run() {}",
	)

	d := detector{}
	matches := d.Detect("fuzzcheck/run.go", content)

	if len(matches) != 0 {
		t.Fatalf("expected 0 matches: a literal 100%% qualified by a real run count must not be flagged, got %d: %+v", len(matches), matches)
	}
}

// TestDetect_AlwaysNeverAbsoluteClaims covers the two literal phrase
// examples named in the spec ("always works", "never fails") together on
// one unqualified line, and expects one match per phrase.
func TestDetect_AlwaysNeverAbsoluteClaims(t *testing.T) {
	content := fixture(
		"package fuzzcheck",
		"",
		"// This retry loop always works and never fails, no matter the input.",
		"func retry() {}",
	)

	d := detector{}
	matches := d.Detect("fuzzcheck/retry.go", content)

	if len(matches) != 2 {
		t.Fatalf(`expected exactly 2 matches ("always works" and "never fails"), got %d: %+v`, len(matches), matches)
	}
	assertPatternFields(t, matches)
	for _, m := range matches {
		if m.Line != 3 {
			t.Errorf("Match.Line = %d, want 3", m.Line)
		}
	}
}

// TestDetect_NonCommentCodeLineIgnored verifies the pattern scans
// comment/doc lines only: the same overclaiming phrase inside an ordinary
// Go string literal (not a comment) must not be flagged.
func TestDetect_NonCommentCodeLineIgnored(t *testing.T) {
	content := fixture(
		"package fuzzcheck",
		"",
		`const msg = "This guarantees correctness 100% of the time."`,
		"func x() {}",
	)

	d := detector{}
	matches := d.Detect("fuzzcheck/x.go", content)

	if len(matches) != 0 {
		t.Fatalf("expected 0 matches: pattern scans comment/doc lines only, not arbitrary code/string literals, got %d: %+v", len(matches), matches)
	}
}

// TestDetect_MarkdownDocFileScansAllLines verifies the doc-file-extension
// path: in a .md file, prose lines with no comment prefix are still
// scanned, since the whole file is doc content.
func TestDetect_MarkdownDocFileScansAllLines(t *testing.T) {
	content := fixture(
		"# Fuzzing Report",
		"",
		"This tool is fully guaranteed to catch every bug, always.",
	)

	d := detector{}
	matches := d.Detect("docs/fuzzing.md", content)

	if len(matches) < 1 {
		t.Fatalf("expected at least 1 match scanning a .md doc file, got %d: %+v", len(matches), matches)
	}
	assertPatternFields(t, matches)
	for _, m := range matches {
		if m.Line != 3 {
			t.Errorf("Match.Line = %d, want 3", m.Line)
		}
	}
}

// TestID_Category is a trivial state check that the detector reports the
// exact identity the shared registry and the Anti-Cheat check rely on.
func TestID_Category(t *testing.T) {
	d := detector{}
	if got := d.ID(); got != "overclaiming-superlative" {
		t.Errorf("ID() = %q, want %q", got, "overclaiming-superlative")
	}
	if got := d.Category(); got != "fabricated-claims" {
		t.Errorf("Category() = %q, want %q", got, "fabricated-claims")
	}
}
