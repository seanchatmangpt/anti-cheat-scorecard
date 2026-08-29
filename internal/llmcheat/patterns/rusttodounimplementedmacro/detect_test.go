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

package rusttodounimplementedmacro

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// TestDetect_DirtyShippedCode proves that todo!() and unimplemented!() calls
// living in ordinary (non-test) impl code are both flagged, with correct
// PatternID, Category, and 1-based line numbers.
func TestDetect_DirtyShippedCode(t *testing.T) {
	const src = `use std::fmt;

pub struct Widget {
    name: String,
}

impl Widget {
    pub fn save(&self) {
        todo!()
    }

    pub fn load(path: &str) -> Self {
        unimplemented!("loading from {} is not supported yet")
    }
}
`
	d := detector{}
	got := d.Detect("src/widget.rs", []byte(src))

	if len(got) < 1 {
		t.Fatalf("Detect() returned %d matches, want at least 1 for dirty shipped code", len(got))
	}

	for _, m := range got {
		if m.PatternID != "rust-todo-unimplemented-macro" {
			t.Errorf("match PatternID = %q, want %q", m.PatternID, "rust-todo-unimplemented-macro")
		}
		if m.Category != "hollow-implementation" {
			t.Errorf("match Category = %q, want %q", m.Category, "hollow-implementation")
		}
		if m.Path != "src/widget.rs" {
			t.Errorf("match Path = %q, want %q", m.Path, "src/widget.rs")
		}
		if m.Severity != llmcheat.SeverityHigh {
			t.Errorf("match Severity = %q, want %q", m.Severity, llmcheat.SeverityHigh)
		}
	}

	if len(got) != 2 {
		t.Fatalf("Detect() returned %d matches, want exactly 2 (one todo!, one unimplemented!); got %+v", len(got), got)
	}

	// Line 9 is `todo!()` inside save(); line 13 is `unimplemented!(...)`
	// inside load() (both 1-based, counting the leading blank-free source
	// starting at "use std::fmt;" as line 1).
	if got[0].Line != 9 {
		t.Errorf("first match Line = %d, want 9", got[0].Line)
	}
	if got[1].Line != 13 {
		t.Errorf("second match Line = %d, want 13", got[1].Line)
	}
}

// TestDetect_CleanTestOnlyUsage proves that the same macros used inside a
// #[cfg(test)] mod block produce zero matches, even though the module also
// contains ordinary (non-test-attributed) code above it that is genuinely
// clean.
func TestDetect_CleanTestOnlyUsage(t *testing.T) {
	const src = `pub struct Widget;

impl Widget {
    pub fn save(&self) {
        // Fully implemented: no placeholder macros here.
        self.persist();
    }

    fn persist(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_todo_placeholder() {
        // Intentionally left unfinished until fixture data is ready.
        todo!("write assertions once the fixture is finalized")
    }

    #[test]
    fn test_unreachable_guard() {
        let x: Option<i32> = Some(1);
        match x {
            Some(_) => {}
            None => unreachable!(),
        }
    }
}
`
	d := detector{}
	got := d.Detect("src/widget.rs", []byte(src))

	if len(got) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 for macros confined to a #[cfg(test)] module; got %+v", len(got), got)
	}
}

// TestDetect_IntegrationTestsDirectoryExcluded proves that a file whose path
// runs through a "tests/" directory is excluded entirely, even for a
// top-level (non-cfg(test)) todo!() call, matching real Cargo integration
// test crates (tests/*.rs) that never ship as part of the library/binary.
func TestDetect_IntegrationTestsDirectoryExcluded(t *testing.T) {
	const src = `#[test]
fn it_checks_something() {
    todo!("integration test not written yet")
}
`
	d := detector{}
	got := d.Detect("tests/integration_test.rs", []byte(src))

	if len(got) != 0 {
		t.Fatalf("Detect() returned %d matches for a tests/ directory file, want 0; got %+v", len(got), got)
	}

	// Sanity check: the same content at a non-tests/ path IS flagged, so the
	// zero-match result above is really the path exclusion at work and not
	// some other bug silently swallowing the match.
	got2 := d.Detect("src/integration_check.rs", []byte(src))
	if len(got2) != 1 {
		t.Fatalf("Detect() returned %d matches for the equivalent src/ path, want 1; got %+v", len(got2), got2)
	}
}

// TestDetect_NonRustFileIgnored proves the detector only ever inspects .rs
// files, even when the content contains the exact dirty pattern.
func TestDetect_NonRustFileIgnored(t *testing.T) {
	const src = `def save(self):
    raise NotImplementedError("todo!(this is not actually rust)")
`
	d := detector{}
	got := d.Detect("src/widget.py", []byte(src))

	if len(got) != 0 {
		t.Fatalf("Detect() returned %d matches for a non-.rs file, want 0; got %+v", len(got), got)
	}
}

// TestDetect_UnreachableOutsideTestFlagged proves the third macro named in
// the pattern description, unreachable!(), is also flagged when it appears
// in shipped (non-test) code.
func TestDetect_UnreachableOutsideTestFlagged(t *testing.T) {
	const src = `pub fn classify(n: i32) -> &'static str {
    match n.signum() {
        -1 => "negative",
        0 => "zero",
        1 => "positive",
        _ => unreachable!(),
    }
}
`
	d := detector{}
	got := d.Detect("src/classify.rs", []byte(src))

	if len(got) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1 for unreachable!() outside tests; got %+v", len(got), got)
	}
	if got[0].Line != 6 {
		t.Errorf("match Line = %d, want 6", got[0].Line)
	}
	if got[0].PatternID != "rust-todo-unimplemented-macro" {
		t.Errorf("match PatternID = %q, want %q", got[0].PatternID, "rust-todo-unimplemented-macro")
	}
}

// TestID_Category proves the detector reports the exact ID/Category
// contract this pattern was assigned.
func TestID_Category(t *testing.T) {
	d := detector{}
	if got := d.ID(); got != "rust-todo-unimplemented-macro" {
		t.Errorf("ID() = %q, want %q", got, "rust-todo-unimplemented-macro")
	}
	if got := d.Category(); got != "hollow-implementation" {
		t.Errorf("Category() = %q, want %q", got, "hollow-implementation")
	}
}
