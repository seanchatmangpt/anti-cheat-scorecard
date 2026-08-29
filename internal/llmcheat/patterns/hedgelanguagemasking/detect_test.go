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

package hedgelanguagemasking

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// dirtySameLineGo expands the required dirty example into a realistic,
// multi-line Go source file: a hedge phrase and a definite-outcome word
// share the exact same comment line, directly above the function it
// (falsely) claims confidence about.
const dirtySameLineGo = `package retry

// This should work in all cases and the tests probably pass.
// It handles the retry logic for the flaky network client.
func Retry() error {
	return nil
}
`

// cleanHonestGo expands the required clean example: an honestly-hedged TODO
// that names a real, unresolved gap instead of asserting a definite outcome.
const cleanHonestGo = `package retry

// TODO: unverified — need to confirm edge case behavior with a real test.
// The retry count is currently hardcoded to 3; revisit before v2.
func Retry() error {
	return nil
}
`

func TestDetect_DirtySameLineFlagged(t *testing.T) {
	d := detector{}
	matches := d.Detect("retry.go", []byte(dirtySameLineGo))

	if len(matches) < 1 {
		t.Fatalf("Detect() on dirty same-line fixture returned %d matches, want >= 1", len(matches))
	}
	for _, m := range matches {
		if m.PatternID != "hedge-language-masking-uncertainty" {
			t.Errorf("Match.PatternID = %q, want %q", m.PatternID, "hedge-language-masking-uncertainty")
		}
		if m.Category != "fabricated-claims" {
			t.Errorf("Match.Category = %q, want %q", m.Category, "fabricated-claims")
		}
		if m.Path != "retry.go" {
			t.Errorf("Match.Path = %q, want %q", m.Path, "retry.go")
		}
	}
	// The hedge+outcome combination lives on line 3 of dirtySameLineGo.
	if matches[0].Line != 3 {
		t.Errorf("Match.Line = %d, want 3", matches[0].Line)
	}
}

func TestDetect_CleanHedgeWithoutOutcomeNotFlagged(t *testing.T) {
	d := detector{}
	matches := d.Detect("retry.go", []byte(cleanHonestGo))

	if len(matches) != 0 {
		t.Fatalf("Detect() on clean fixture returned %d matches, want 0: %+v", len(matches), matches)
	}
}

// dirtyNearbyBlockGo puts the hedge phrase and the definite-outcome word on
// different, but contiguous, comment lines above the same declaration —
// exercising the "nearby" part of the pattern description rather than the
// same-line case already covered above.
const dirtyNearbyBlockGo = `package writer

// I believe this approach handles concurrent writers safely.
// The mutex around the shared buffer was added last week.
// The refactor should be complete once review wraps up.
func Write() {}
`

func TestDetect_NearbyBlockAcrossLinesFlagged(t *testing.T) {
	d := detector{}
	matches := d.Detect("writer.go", []byte(dirtyNearbyBlockGo))

	if len(matches) < 1 {
		t.Fatalf("Detect() on nearby-block fixture returned %d matches, want >= 1", len(matches))
	}
	// "I believe" is the hedge phrase; it sits on line 3, while the
	// definite-outcome word ("complete") is two lines later on line 5 —
	// same contiguous comment block, so it must still be flagged, anchored
	// at the hedge phrase's own line.
	found := false
	for _, m := range matches {
		if m.Line == 3 {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a match anchored at line 3 (the hedge phrase's line), got matches: %+v", matches)
	}
}

// dirtyWordsInCodeNotComment puts the exact same hedge+outcome vocabulary
// inside a string literal in real, executable code rather than in a
// comment — this must NOT be flagged, because the pattern is specifically
// about comment/doc lines masking real uncertainty, not arbitrary string
// content.
const dirtyWordsInCodeNotComment = `package logger

func Log() {
	fmt.Println("I believe this works and all tests probably pass")
}
`

func TestDetect_HedgeWordsInCodeNotCommentNotFlagged(t *testing.T) {
	d := detector{}
	matches := d.Detect("logger.go", []byte(dirtyWordsInCodeNotComment))

	if len(matches) != 0 {
		t.Fatalf("Detect() on non-comment code fixture returned %d matches, want 0: %+v", len(matches), matches)
	}
}

// dirtyMarkdownDoc exercises the no-comment-syntax doc case: a markdown
// file has no "//" prefix at all, but its prose lines are still doc content
// the pattern must scan.
const dirtyMarkdownDoc = `# Release Notes

This module should work correctly for all supported inputs.
`

func TestDetect_MarkdownDocLineFlagged(t *testing.T) {
	d := detector{}
	matches := d.Detect("NOTES.md", []byte(dirtyMarkdownDoc))

	if len(matches) < 1 {
		t.Fatalf("Detect() on markdown fixture returned %d matches, want >= 1", len(matches))
	}
	if matches[0].PatternID != "hedge-language-masking-uncertainty" {
		t.Errorf("Match.PatternID = %q, want %q", matches[0].PatternID, "hedge-language-masking-uncertainty")
	}
	if matches[0].Category != "fabricated-claims" {
		t.Errorf("Match.Category = %q, want %q", matches[0].Category, "fabricated-claims")
	}
}

func TestDetector_IdentityMatchesPatternContract(t *testing.T) {
	d := detector{}
	if got := d.ID(); got != "hedge-language-masking-uncertainty" {
		t.Errorf("ID() = %q, want %q", got, "hedge-language-masking-uncertainty")
	}
	if got := d.Category(); got != "fabricated-claims" {
		t.Errorf("Category() = %q, want %q", got, "fabricated-claims")
	}
	var _ llmcheat.Pattern = d // compile-time check: detector satisfies the shared contract.
}
