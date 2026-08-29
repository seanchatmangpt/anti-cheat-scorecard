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

package declaredinvariantnotenforced

import (
	"strings"
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// dirtySource is a realistic multi-function Go file: one well-formed helper
// followed by a function whose doc comment declares an invariant ("must
// never be nil") but whose body does nothing to enforce it — it dereferences
// the pointer unconditionally instead.
const dirtySource = `package data

// Data holds a single field used across the store.
type Data struct {
	Value int
}

// Validate checks basic structural well-formedness.
func Validate(d *Data) bool {
	return d != nil
}

// Invariant: input must never be nil.
func process(x *Data) int {
	return x.Value
}
`

// cleanSource is the same shape as dirtySource, except process now actually
// enforces the declared invariant with a real panic guard before touching
// the pointer.
const cleanSource = `package data

// Data holds a single field used across the store.
type Data struct {
	Value int
}

// Invariant: input must never be nil.
func process(x *Data) int {
	if x == nil {
		panic("process: nil input")
	}
	return x.Value
}
`

func TestDetect_DirtyUnenforcedInvariant_ProducesMatch(t *testing.T) {
	d := detector{}

	matches := d.Detect("data/process.go", []byte(dirtySource))

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
	if got.Path != "data/process.go" {
		t.Errorf("Match.Path = %q, want %q", got.Path, "data/process.go")
	}

	// Derive the expected 1-based line number directly from the fixture
	// text itself, so the assertion stays correct even if the fixture is
	// edited later.
	wantLine := uint(0)
	for i, line := range strings.Split(dirtySource, "\n") {
		if strings.Contains(line, "Invariant:") {
			wantLine = uint(i + 1)
			break
		}
	}
	if wantLine == 0 {
		t.Fatal("test fixture bug: dirtySource does not contain the expected 'Invariant:' comment")
	}
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

func TestDetect_CleanEnforcedInvariant_ProducesNoMatches(t *testing.T) {
	d := detector{}

	matches := d.Detect("data/process.go", []byte(cleanSource))

	if len(matches) != 0 {
		t.Fatalf("Detect() on clean fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

// TestDetect_OrdinaryCommentNoTriggerPhrase proves the trigger-phrase gate:
// a completely hollow function preceded by an ordinary doc comment that
// contains none of the four invariant-declaring phrases must not be
// flagged — this detector only judges functions whose comment actually
// makes a guarantee, not every under-implemented function in the codebase
// (that is a different pattern's job).
func TestDetect_OrdinaryCommentNoTriggerPhrase(t *testing.T) {
	const src = `package data

// Process performs a basic transformation and returns the result.
func Process(x *Data) int {
	return x.Value
}
`
	d := detector{}

	matches := d.Detect("data/process.go", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() on no-trigger-phrase fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

// TestDetect_ReturnErrorCountsAsEnforcement proves the fifth named
// enforcement mechanism — a real "return err"-shaped statement, with no
// assert/panic/raise/throw anywhere in the body — is correctly recognized
// as enforcing the declared invariant, not just the four keyword forms.
func TestDetect_ReturnErrorCountsAsEnforcement(t *testing.T) {
	const src = `package data

import "errors"

// Invariant: the returned slice must always be non-nil.
func Load(id string) ([]byte, error) {
	if id == "" {
		return nil, errors.New("id must not be empty")
	}
	return []byte(id), nil
}
`
	d := detector{}

	matches := d.Detect("data/load.go", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() on return-error-enforced fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

// TestDetect_IndentationDelimitedBody proves the detector's second body
// shape (Python-style: declaration line ends in ':', body is whatever is
// indented further) on a language with no braces at all, and that the
// other three trigger phrases ("must always", "guaranteed to") are
// recognized in addition to "invariant:".
func TestDetect_IndentationDelimitedBody(t *testing.T) {
	const src = `class Cache:
    # This getter is guaranteed to return a non-negative count.
    def size(self):
        return self._count

    # A sibling method with real enforcement, for contrast.
    def get(self, key):
        if key not in self._store:
            raise KeyError(key)
        return self._store[key]
`
	d := detector{}

	matches := d.Detect("data/cache.py", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() on indentation-delimited fixture = %d matches, want 1; matches=%+v", len(matches), matches)
	}

	got := matches[0]
	if got.PatternID != patternID {
		t.Errorf("Match.PatternID = %q, want %q", got.PatternID, patternID)
	}
	if got.Category != patternCategory {
		t.Errorf("Match.Category = %q, want %q", got.Category, patternCategory)
	}
	wantLine := uint(0)
	for i, line := range strings.Split(src, "\n") {
		if strings.Contains(line, "guaranteed to") {
			wantLine = uint(i + 1)
			break
		}
	}
	if got.Line != wantLine {
		t.Errorf("Match.Line = %d, want %d", got.Line, wantLine)
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
