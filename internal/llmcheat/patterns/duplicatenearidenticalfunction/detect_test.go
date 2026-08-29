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

package duplicatenearidenticalfunction

import (
	"strings"
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// dirtySource is a realistic multi-line Go file: two DIFFERENT top-level
// functions (different names, different parameter names even) whose bodies
// are byte-identical once whitespace is stripped — the copy-paste-without-
// adaptation shape this pattern targets. This directly expands the
// assignment's one-line dirty example into a full, realistic file with
// package/import/doc-comment context.
const dirtySource = `package pricing

// ComputeDiscountedPrice applies a flat markup then doubles it.
func ComputeDiscountedPrice(x int) int {
	y := x + 1
	return y * 2
}

// ComputeAdjustedTotal applies a flat markup then doubles it.
//
// NOTE: this looks suspiciously like ComputeDiscountedPrice above — same
// body, different name — exactly the shape this test exists to catch.
func ComputeAdjustedTotal(x int) int {
	y := x + 1
	return y * 2
}
`

// cleanSource is a realistic multi-line Go file where two similarly-shaped
// functions have genuinely different bodies (different operations, not
// just different surface tokens standing in for the same logic).
const cleanSource = `package pricing

// Increment returns x plus one.
func Increment(x int) int { return x + 1 }

// Double returns x times two.
func Double(x int) int { return x * 2 }
`

func TestDetect_DirtyDuplicateFunction_ProducesMatch(t *testing.T) {
	d := detector{}

	matches := d.Detect("pricing/pricing.go", []byte(dirtySource))

	if len(matches) < 1 {
		t.Fatalf("Detect() on dirty fixture = %d matches, want >= 1", len(matches))
	}

	got := matches[0]
	if got.PatternID != patternID {
		t.Errorf("Match.PatternID = %q, want %q", got.PatternID, patternID)
	}
	if got.Category != patternCategory {
		t.Errorf("Match.Category = %q, want %q", got.Category, patternCategory)
	}
	if got.Path != "pricing/pricing.go" {
		t.Errorf("Match.Path = %q, want %q", got.Path, "pricing/pricing.go")
	}
	// ComputeAdjustedTotal (the second, duplicate function) starts on line
	// 13 of dirtySource; the match should be anchored there, not at 0 or
	// at the first (original) function's line.
	const wantLine = uint(13)
	if got.Line != wantLine {
		t.Errorf("Match.Line = %d, want %d", got.Line, wantLine)
	}
	if got.Severity != llmcheat.SeverityMedium {
		t.Errorf("Match.Severity = %q, want %q", got.Severity, llmcheat.SeverityMedium)
	}
	if got.Message == "" {
		t.Error("Match.Message is empty, want a real explanation")
	}
}

func TestDetect_CleanDifferentFunctions_ProducesNoMatches(t *testing.T) {
	d := detector{}

	matches := d.Detect("pricing/pricing.go", []byte(cleanSource))

	if len(matches) != 0 {
		t.Fatalf("Detect() on clean fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

// TestDetect_TrivialSingleLineBodiesNotFlagged proves the minimum-size
// floor: two different functions that both happen to have the exact same
// single-line body (a very common, legitimate shape — e.g. two unrelated
// no-op-error methods) must NOT be flagged, since a 1-line coincidence is
// not meaningful evidence of copy-paste-without-adaptation.
func TestDetect_TrivialSingleLineBodiesNotFlagged(t *testing.T) {
	const src = `package store

func (s *Reader) Close() error {
	return nil
}

func (s *Writer) Close() error {
	return nil
}
`
	d := detector{}

	matches := d.Detect("store/store.go", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() on trivial single-line-body fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

// TestDetect_MethodsWithReceiversAlsoDetected proves the detector covers
// methods (FuncDecl with a receiver), not just free functions, and that the
// duplicate's Match.Message names both methods including their receiver
// types for a human reviewer to act on.
func TestDetect_MethodsWithReceiversAlsoDetected(t *testing.T) {
	const src = `package store

type Reader struct{ path string }
type Writer struct{ path string }

func (s *Reader) Validate() error {
	if s.path == "" {
		return errPathRequired
	}
	return nil
}

func (s *Writer) Validate() error {
	if s.path == "" {
		return errPathRequired
	}
	return nil
}
`
	d := detector{}

	matches := d.Detect("store/store.go", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() = %d matches, want 1; matches=%+v", len(matches), matches)
	}
	got := matches[0]
	if got.PatternID != patternID {
		t.Errorf("Match.PatternID = %q, want %q", got.PatternID, patternID)
	}
	if got.Category != patternCategory {
		t.Errorf("Match.Category = %q, want %q", got.Category, patternCategory)
	}
	if !strings.Contains(got.Message, "(*Reader).Validate") || !strings.Contains(got.Message, "(*Writer).Validate") {
		t.Errorf("Match.Message = %q, want it to name both (*Reader).Validate and (*Writer).Validate", got.Message)
	}
}

// TestDetect_NonGoFileExcluded proves the file-extension gate: identical
// dirty content in a non-.go file must not be flagged, since this pattern's
// body extraction is Go-syntax-specific (built on go/parser).
func TestDetect_NonGoFileExcluded(t *testing.T) {
	d := detector{}

	matches := d.Detect("pricing/pricing.py", []byte(dirtySource))

	if len(matches) != 0 {
		t.Fatalf("Detect() on non-.go fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

// TestDetect_UnparseableGoContent_ReturnsNilNotPanic proves the detector
// degrades gracefully (no matches, no panic) on content that does not parse
// as valid Go, rather than crashing the whole scan over one malformed file.
func TestDetect_UnparseableGoContent_ReturnsNilNotPanic(t *testing.T) {
	d := detector{}

	matches := d.Detect("broken/broken.go", []byte("this is not valid { go source at all"))

	if len(matches) != 0 {
		t.Fatalf("Detect() on unparseable fixture = %d matches, want 0; matches=%+v", len(matches), matches)
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
