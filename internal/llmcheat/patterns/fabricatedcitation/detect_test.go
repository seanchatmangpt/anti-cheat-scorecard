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

package fabricatedcitation

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// TestDetect_DirtyPlaceholderCitation_ProducesMatch is a real, expanded
// version of the assignment's dirty one-liner ("As documented elsewhere in
// the codebase, this is safe.") embedded in a realistic multi-line Go
// comment block, run through the real detector against real bytes.
func TestDetect_DirtyPlaceholderCitation_ProducesMatch(t *testing.T) {
	content := []byte(`// Package cheatcomments contains a deliberately dirty fixture.
//
// As documented elsewhere in the codebase, this is safe.
//
// The receipt verifier trusts this claim without re-checking it, which is
// exactly the kind of hand-wave this detector exists to catch.
func doSomethingRisky() {
}
`)

	d := detector{}
	matches := d.Detect("internal/example/risky.go", content)

	if len(matches) == 0 {
		t.Fatalf("Detect() returned 0 matches for a fixture containing a generic-placeholder citation; want >= 1")
	}

	foundOnTriggerLine := false
	for _, m := range matches {
		if m.PatternID != patternID {
			t.Errorf("match PatternID = %q, want %q", m.PatternID, patternID)
		}
		if m.Category != patternCategory {
			t.Errorf("match Category = %q, want %q", m.Category, patternCategory)
		}
		if m.Path != "internal/example/risky.go" {
			t.Errorf("match Path = %q, want %q", m.Path, "internal/example/risky.go")
		}
		if m.Line == 0 {
			t.Errorf("match Line = 0, want a real 1-based line number")
		}
		if m.Message == "" {
			t.Errorf("match Message is empty, want a real explanation")
		}
		if m.Line == 3 {
			foundOnTriggerLine = true
		}
	}
	if !foundOnTriggerLine {
		t.Errorf("expected a match anchored at line 3 (the %q line); got matches at lines %v",
			"// As documented elsewhere in the codebase, this is safe.", lineNumbers(matches))
	}
}

// TestDetect_CleanRealPathCitation_ProducesZeroMatches is a real, expanded
// version of the assignment's clean one-liner ("As documented in
// docs/AUTHORITY.md#do-tier, this requires a receipted broker.") plus a
// second real-path citation via "see", embedded in a realistic multi-line
// Go comment block.
func TestDetect_CleanRealPathCitation_ProducesZeroMatches(t *testing.T) {
	content := []byte(`// Package cheatcomments contains a deliberately clean fixture.
//
// As documented in docs/AUTHORITY.md#do-tier, this requires a receipted
// broker; see internal/broker/broker.go for the enforcement path.
func doSomethingSafe() {
}
`)

	d := detector{}
	matches := d.Detect("internal/example/safe.go", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches for a fixture whose citations are all real paths; want 0, got %+v", len(matches), matches)
	}
}

// TestDetect_BareFilenameWithExtension_NoSlash_IsTreatedAsRealPath covers
// the boundary case named in this pattern's assignment: a target with a
// recognizable extension but no "/" (a bare filename) still counts as a
// real locator and must not be flagged.
func TestDetect_BareFilenameWithExtension_NoSlash_IsTreatedAsRealPath(t *testing.T) {
	content := []byte(`See README.md for the full setup instructions.
`)

	d := detector{}
	matches := d.Detect("docs/onboarding.md", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches for a bare filename-with-extension target; want 0 (README.md is a real locator even without a slash), got %+v", len(matches), matches)
	}
}

// TestDetect_OrdinaryProseWithTriggerWords_ProducesZeroMatches covers the
// other boundary: sentences that merely contain the trigger words "see" or
// "per" without citing anything, generic-placeholder or otherwise, must not
// be flagged — only a target that both lacks a real locator AND matches a
// known placeholder phrase is a match.
func TestDetect_OrdinaryProseWithTriggerWords_ProducesZeroMatches(t *testing.T) {
	content := []byte(`We will see how this performs over time.
Latency is reported per request processed.
`)

	d := detector{}
	matches := d.Detect("internal/example/prose.go", content)

	if len(matches) != 0 {
		t.Fatalf(`Detect() returned %d matches for ordinary prose that merely contains the words "see"/"per"; want 0, got %+v`, len(matches), matches)
	}
}

// TestDetect_MultiplePlaceholderCitationsInOneFile_ProducesOneMatchPerLine
// exercises all three trigger phrasings named in the assignment ("See X",
// "per X", and the "documented ... in X" family) in one file, and asserts
// on the real, exact resulting match count and line numbers.
func TestDetect_MultiplePlaceholderCitationsInOneFile_ProducesOneMatchPerLine(t *testing.T) {
	content := []byte(`// See the relevant file for the full rationale.
// Per the docs, this flag defaults to false.
// This is documented somewhere in the codebase.
`)

	d := detector{}
	matches := d.Detect("internal/example/multi.go", content)

	if len(matches) != 3 {
		t.Fatalf("Detect() returned %d matches, want 3 (one per placeholder-citation line); got %+v", len(matches), matches)
	}

	wantLines := map[uint]bool{1: true, 2: true, 3: true}
	for _, m := range matches {
		if !wantLines[m.Line] {
			t.Errorf("unexpected match line %d; want one of {1,2,3}", m.Line)
		}
		delete(wantLines, m.Line)
	}
	if len(wantLines) != 0 {
		t.Errorf("missing matches on lines %v", wantLines)
	}
}

func lineNumbers(matches []llmcheat.Match) []uint {
	out := make([]uint, len(matches))
	for i, m := range matches {
		out[i] = m.Line
	}
	return out
}
