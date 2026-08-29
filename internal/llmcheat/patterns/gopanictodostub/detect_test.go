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

package gopanictodostub

import (
	"strings"
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// dirtySource is a realistic multi-line Go file: a package with a real
// helper alongside one stubbed-out method whose body is just a placeholder
// panic() rather than real logic.
const dirtySource = `package store

import "errors"

// Record is a persisted domain object.
type Record struct {
	ID   string
	Data []byte
}

// Validate checks that a Record is well-formed before it is written.
func Validate(r Record) error {
	if r.ID == "" {
		return errors.New("record ID must not be empty")
	}
	return nil
}

// Save persists r to the backing store.
func Save(r Record) {
	panic("TODO: implement")
}
`

// cleanSource is a realistic multi-line Go file where every function has a
// real, working body and no placeholder panics of any kind.
const cleanSource = `package store

import "fmt"

// Record is a persisted domain object.
type Record struct {
	ID   string
	Data []byte
}

// db is the package-level backing store handle.
var db = newMemoryStore()

// Save persists record to the backing store, returning any write error.
func Save(record Record) error {
	if record.ID == "" {
		return fmt.Errorf("record ID must not be empty")
	}
	return db.Write(record)
}

// Delete panics on a genuinely invalid, programmer-error precondition — this
// is a real runtime invariant guard, not a placeholder for missing logic.
func Delete(id string) {
	if id == "" {
		panic("store: Delete called with empty id")
	}
	db.Remove(id)
}
`

func TestDetect_DirtyStubPanic_ProducesMatch(t *testing.T) {
	d := detector{}

	matches := d.Detect("store/save.go", []byte(dirtySource))

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
	if got.Path != "store/save.go" {
		t.Errorf("Match.Path = %q, want %q", got.Path, "store/save.go")
	}
	// Derive the expected 1-based line number directly from the fixture
	// text itself (rather than a hand-counted literal, which is easy to
	// get off-by-one on a multi-line raw string) so the assertion stays
	// correct even if the fixture is edited later.
	wantLine := uint(0)
	for i, line := range strings.Split(dirtySource, "\n") {
		if strings.Contains(line, `panic("TODO`) {
			wantLine = uint(i + 1)
			break
		}
	}
	if wantLine == 0 {
		t.Fatal("test fixture bug: dirtySource does not contain the expected panic(\"TODO literal")
	}
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

func TestDetect_CleanImplementation_ProducesNoMatches(t *testing.T) {
	d := detector{}

	matches := d.Detect("store/save.go", []byte(cleanSource))

	if len(matches) != 0 {
		t.Fatalf("Detect() on clean fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

// TestDetect_TestFileExcluded proves the stated _test.go allowlist
// exception: the exact dirty pattern, in a file literally named
// "*_test.go", must not be flagged (test helpers legitimately panic on
// "TODO" markers to fail loudly on unfinished test setup, and this
// detector's job is production hollow-implementation, not test scaffolding).
func TestDetect_TestFileExcluded(t *testing.T) {
	d := detector{}

	matches := d.Detect("store/save_test.go", []byte(dirtySource))

	if len(matches) != 0 {
		t.Fatalf("Detect() on _test.go fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

// TestDetect_NonGoFileExcluded proves the file-extension gate: identical
// dirty content in a non-.go file must not be flagged, since this pattern
// is scoped to Go source specifically.
func TestDetect_NonGoFileExcluded(t *testing.T) {
	d := detector{}

	matches := d.Detect("store/save.py", []byte(`def save():
    raise NotImplementedError("TODO: implement")
`))

	if len(matches) != 0 {
		t.Fatalf("Detect() on non-.go fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

// TestDetect_CaseInsensitiveAndOtherPhrases proves the detector matches all
// three stated placeholder phrases, case-insensitively, each on its own
// realistic line, with correct per-line line numbers.
func TestDetect_CaseInsensitiveAndOtherPhrases(t *testing.T) {
	const src = `package worker

// Start begins processing.
func Start() {
	panic("unimplemented")
}

// Stop halts processing.
func Stop() {
	panic("Not Implemented: graceful shutdown")
}
`
	d := detector{}

	matches := d.Detect("worker/worker.go", []byte(src))

	if len(matches) != 2 {
		t.Fatalf("Detect() = %d matches, want 2; matches=%+v", len(matches), matches)
	}
	if matches[0].Line != 5 {
		t.Errorf("matches[0].Line = %d, want 5", matches[0].Line)
	}
	if matches[1].Line != 10 {
		t.Errorf("matches[1].Line = %d, want 10", matches[1].Line)
	}
	for _, m := range matches {
		if m.PatternID != patternID {
			t.Errorf("Match.PatternID = %q, want %q", m.PatternID, patternID)
		}
		if m.Category != patternCategory {
			t.Errorf("Match.Category = %q, want %q", m.Category, patternCategory)
		}
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
