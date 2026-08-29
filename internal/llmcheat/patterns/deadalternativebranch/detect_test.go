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

package deadalternativebranch

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// assertMatch checks the fields every match from this detector must share:
// PatternID, Category, Severity, and Path.
func assertMatch(t *testing.T, m llmcheat.Match, wantPath string) {
	t.Helper()
	if m.PatternID != "dead-alternative-branch" {
		t.Errorf("match PatternID = %q, want %q", m.PatternID, "dead-alternative-branch")
	}
	if m.Category != "hollow-implementation" {
		t.Errorf("match Category = %q, want %q", m.Category, "hollow-implementation")
	}
	if m.Severity != llmcheat.SeverityHigh {
		t.Errorf("match Severity = %q, want %q", m.Severity, llmcheat.SeverityHigh)
	}
	if m.Path != wantPath {
		t.Errorf("match Path = %q, want %q", m.Path, wantPath)
	}
}

// TestDetect_DirtyGoStyleIfFalse proves the exact dirty shape named in the
// spec ("if false { result = computeReal(x) } result = 0"), expanded to a
// realistic Go function, produces exactly one match at the `if false {`
// line.
func TestDetect_DirtyGoStyleIfFalse(t *testing.T) {
	const src = `package widget

func Compute(x int) int {
	var result int
	if false {
		result = computeReal(x)
	}
	result = 0
	return result
}
`
	d := detector{}
	got := d.Detect("widget.go", []byte(src))

	if len(got) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1; got %+v", len(got), got)
	}
	assertMatch(t, got[0], "widget.go")
	if got[0].Line != 5 {
		t.Errorf("match Line = %d, want 5 (the `if false {` line)", got[0].Line)
	}
}

// TestDetect_CleanRealConditional proves the exact clean shape named in the
// spec ("if debugMode { logVerbose(x) }") produces zero matches: the guard
// condition is a real variable, not a literal false, so this is an ordinary
// conditional, not a dead branch.
func TestDetect_CleanRealConditional(t *testing.T) {
	const src = `package widget

func Debug(x int) {
	if debugMode {
		logVerbose(x)
	}
}
`
	d := detector{}
	got := d.Detect("widget.go", []byte(src))

	if len(got) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0; got %+v", len(got), got)
	}
}

// TestDetect_CleanIfFalseTrivialBlock proves the boundary the spec draws:
// `if false { ... }` guarding only a comment (no function call, no
// assignment) is ordinary disabled scaffolding, not a discarded real
// implementation, and must not be flagged.
func TestDetect_CleanIfFalseTrivialBlock(t *testing.T) {
	const src = `package widget

func Compute(x int) int {
	if false {
		// TODO: not needed anymore
	}
	return realResult()
}
`
	d := detector{}
	got := d.Detect("widget.go", []byte(src))

	if len(got) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 (trivial if-false block); got %+v", len(got), got)
	}
}

// TestDetect_DirtyPythonIfFalse proves the Python `if False:` spelling is
// detected when it guards real logic (an assignment and a function call),
// with the correct 1-based line number.
func TestDetect_DirtyPythonIfFalse(t *testing.T) {
	const src = `def compute(x):
    if False:
        result = compute_real(x)
        return result
    return 0
`
	d := detector{}
	got := d.Detect("widget.py", []byte(src))

	if len(got) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1; got %+v", len(got), got)
	}
	assertMatch(t, got[0], "widget.py")
	if got[0].Line != 2 {
		t.Errorf("match Line = %d, want 2 (the `if False:` line)", got[0].Line)
	}
}

// TestDetect_CleanPythonIfFalsePass proves `if False: pass` — the ordinary
// idiom for temporarily disabled scaffolding with no discarded logic
// beneath it — produces zero matches.
func TestDetect_CleanPythonIfFalsePass(t *testing.T) {
	const src = `def compute(x):
    if False:
        pass
    return 0
`
	d := detector{}
	got := d.Detect("widget.py", []byte(src))

	if len(got) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 (if False: pass); got %+v", len(got), got)
	}
}

// TestDetect_DirtyRustCfgAnyEmpty proves Rust's `#[cfg(any())]` — an
// unsatisfiable, always-false predicate list — is flagged unconditionally
// on a .rs file, regardless of what real logic it guards.
func TestDetect_DirtyRustCfgAnyEmpty(t *testing.T) {
	const src = `#[cfg(any())]
fn compute_real(x: i32) -> i32 {
    x * 2 + 1
}

fn compute_stub(x: i32) -> i32 {
    0
}
`
	d := detector{}
	got := d.Detect("src/lib.rs", []byte(src))

	if len(got) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1; got %+v", len(got), got)
	}
	assertMatch(t, got[0], "src/lib.rs")
	if got[0].Line != 1 {
		t.Errorf("match Line = %d, want 1 (the #[cfg(any())] line)", got[0].Line)
	}
}

// TestDetect_CleanRustCfgAnyWithPredicates proves the boundary the spec
// draws for the Rust form: `#[cfg(any(feature = "a", feature = "b"))]` is
// ordinary, legitimate conditional compilation (a real, satisfiable
// predicate list), not a permanently-dead marker, and must not be flagged.
func TestDetect_CleanRustCfgAnyWithPredicates(t *testing.T) {
	const src = `#[cfg(any(feature = "a", feature = "b"))]
fn compute(x: i32) -> i32 {
    x * 2
}
`
	d := detector{}
	got := d.Detect("src/lib.rs", []byte(src))

	if len(got) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 (cfg(any(...)) with real predicates); got %+v", len(got), got)
	}
}

// TestDetect_RustCfgAnyIgnoredOutsideRustFiles proves the Rust-specific
// check is scoped to .rs files: the same #[cfg(any())]-shaped line in a
// non-Rust file is not flagged by this rule (it isn't Rust syntax there).
func TestDetect_RustCfgAnyIgnoredOutsideRustFiles(t *testing.T) {
	const src = `#[cfg(any())]
some unrelated text
`
	d := detector{}
	got := d.Detect("notes.txt", []byte(src))

	if len(got) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 (cfg(any()) outside a .rs file); got %+v", len(got), got)
	}
}

// TestDetect_DirtyBraceFreeIfFalse proves the brace-free C-family form,
// `if (false)` guarding a single statement with no braces at all, is still
// detected when that statement is real logic.
func TestDetect_DirtyBraceFreeIfFalse(t *testing.T) {
	const src = `int compute(int x) {
    if (false)
        result = computeReal(x);
    return 0;
}
`
	d := detector{}
	got := d.Detect("widget.c", []byte(src))

	if len(got) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1; got %+v", len(got), got)
	}
	assertMatch(t, got[0], "widget.c")
	if got[0].Line != 2 {
		t.Errorf("match Line = %d, want 2 (the `if (false)` line)", got[0].Line)
	}
}

// TestDetect_DirtyAllmanStyleIfFalse proves the Allman brace style (the `{`
// on its own line after the guard) is also handled.
func TestDetect_DirtyAllmanStyleIfFalse(t *testing.T) {
	const src = `int Compute(int x)
{
    if (false)
    {
        result = computeReal(x);
    }
    return 0;
}
`
	d := detector{}
	got := d.Detect("widget.c", []byte(src))

	if len(got) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1; got %+v", len(got), got)
	}
	assertMatch(t, got[0], "widget.c")
	if got[0].Line != 3 {
		t.Errorf("match Line = %d, want 3 (the `if (false)` line)", got[0].Line)
	}
}
