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

package authoritytierviolation

import (
	"strings"
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// dirtyGoSource is a realistic, multi-function Go file: one legitimate
// read-only helper alongside a "SELECT-only" gate whose body actually
// shells out to `git push` via exec.Command's argv-list form — the exact
// shape the pattern spec names as the dirty fixture, expanded with real
// surrounding context.
const dirtyGoSource = `package sync

import (
	"os/exec"
)

// queryGraph reads current graph state without mutating it.
func queryGraph() string {
	return "graph-state"
}

// SELECT-only: must never mutate state.
func syncGate() {
	exec.Command("git", "push").Run()
}
`

// cleanGoSource mirrors dirtyGoSource exactly except syncGate's body is a
// real, non-mutating read — the pattern spec's stated clean fixture,
// expanded with the same surrounding context as dirtyGoSource so the two
// fixtures are directly comparable.
const cleanGoSource = `package sync

// queryGraph reads current graph state without mutating it.
func queryGraph() string {
	return "graph-state"
}

// SELECT-only: must never mutate state.
func syncGate() {
	return queryGraph()
}
`

func TestDetect_Dirty_GitPushInDeclaredSelectOnlyGate_ProducesMatch(t *testing.T) {
	d := detector{}

	matches := d.Detect("sync/gate.go", []byte(dirtyGoSource))

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
	if got.Path != "sync/gate.go" {
		t.Errorf("Match.Path = %q, want %q", got.Path, "sync/gate.go")
	}
	if got.Severity != llmcheat.SeverityHigh {
		t.Errorf("Match.Severity = %q, want %q", got.Severity, llmcheat.SeverityHigh)
	}
	if got.Message == "" {
		t.Error("Match.Message is empty, want a real explanation")
	}

	// Derive the expected 1-based line number from the fixture text itself
	// (rather than a hand-counted literal) so the assertion stays correct
	// even if the fixture is edited later.
	wantLine := uint(0)
	for i, line := range strings.Split(dirtyGoSource, "\n") {
		if strings.Contains(line, `exec.Command("git", "push")`) {
			wantLine = uint(i + 1)
			break
		}
	}
	if wantLine == 0 {
		t.Fatal("test fixture bug: dirtyGoSource does not contain the expected exec.Command line")
	}
	if got.Line != wantLine {
		t.Errorf("Match.Line = %d, want %d", got.Line, wantLine)
	}
}

func TestDetect_Clean_DeclaredSelectOnlyGateReallyIsReadOnly_ProducesNoMatches(t *testing.T) {
	d := detector{}

	matches := d.Detect("sync/gate.go", []byte(cleanGoSource))

	if len(matches) != 0 {
		t.Fatalf("Detect() on clean fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

// TestDetect_Dirty_PythonShutilRmtreeUnderReadOnlyDocstring proves the
// detector is not Go-specific: a Python function whose comment declares
// "read-only" but whose body calls shutil.rmtree(...) must be flagged, with
// the correct 1-based line number for the actual mutating call.
func TestDetect_Dirty_PythonShutilRmtreeUnderReadOnlyDocstring(t *testing.T) {
	const src = `import shutil

# read-only: inspects the workspace, never modifies it.
def inspect_workspace(path):
    entries = list_entries(path)
    if not entries:
        shutil.rmtree(path)
    return entries
`
	d := detector{}

	matches := d.Detect("tools/inspect.py", []byte(src))

	if len(matches) < 1 {
		t.Fatalf("Detect() on dirty Python fixture = %d matches, want >= 1", len(matches))
	}
	for _, m := range matches {
		if m.PatternID != patternID {
			t.Errorf("Match.PatternID = %q, want %q", m.PatternID, patternID)
		}
		if m.Category != patternCategory {
			t.Errorf("Match.Category = %q, want %q", m.Category, patternCategory)
		}
	}

	wantLine := uint(0)
	for i, line := range strings.Split(src, "\n") {
		if strings.Contains(line, "shutil.rmtree(path)") {
			wantLine = uint(i + 1)
			break
		}
	}
	if wantLine == 0 {
		t.Fatal("test fixture bug: src does not contain the expected shutil.rmtree( line")
	}
	found := false
	for _, m := range matches {
		if m.Line == wantLine {
			found = true
		}
	}
	if !found {
		t.Errorf("no match at expected line %d; matches=%+v", wantLine, matches)
	}
}

// TestDetect_Dirty_DeleteFromUnderNoMutationAuthority proves the "no
// mutation authority" phrasing and the DELETE FROM SQL trigger both work,
// and that the doc-comment block may span more than one line before the
// signature without breaking function-body location.
func TestDetect_Dirty_DeleteFromUnderNoMutationAuthority(t *testing.T) {
	const src = `package audit

// purgeStale reports rows that look stale.
//
// This helper has no mutation authority: it is called from the read path
// only and must never write to the database.
func purgeStale(db *sql.DB) error {
	_, err := db.Exec("DELETE FROM sessions WHERE expired = 1")
	return err
}
`
	d := detector{}

	matches := d.Detect("audit/purge.go", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() = %d matches, want 1; matches=%+v", len(matches), matches)
	}
	if matches[0].PatternID != patternID {
		t.Errorf("Match.PatternID = %q, want %q", matches[0].PatternID, patternID)
	}
	if !strings.Contains(matches[0].Message, "DELETE FROM") {
		t.Errorf("Match.Message = %q, want it to name the DELETE FROM trigger", matches[0].Message)
	}
}

// TestDetect_PathImpliesBoundary_NoLocalComment_ProducesMatch proves the
// second, whole-file trigger mechanism: a file living in a path that itself
// implies a read-only tier is flagged for a mutating call even when the
// offending function carries no local boundary doc comment at all.
func TestDetect_PathImpliesBoundary_NoLocalComment_ProducesMatch(t *testing.T) {
	const src = `package gate

// cleanup removes a stale checkout directory.
func cleanup(path string) error {
	return os.Remove(path)
}
`
	d := detector{}

	matches := d.Detect("internal/readonly/gate.go", []byte(src))

	if len(matches) < 1 {
		t.Fatalf("Detect() on path-implied-boundary fixture = %d matches, want >= 1", len(matches))
	}
	for _, m := range matches {
		if m.PatternID != patternID || m.Category != patternCategory {
			t.Errorf("Match = %+v, want PatternID=%q Category=%q", m, patternID, patternCategory)
		}
	}
}

// TestDetect_MutatingFunctionWithoutBoundaryClaim_NoMatch proves the
// detector flags the *contradiction* between a declared tier and real
// behavior, not merely the presence of a mutating call: a function that
// legitimately mutates, with an ordinary comment and an ordinary path,
// must not be flagged at all.
func TestDetect_MutatingFunctionWithoutBoundaryClaim_NoMatch(t *testing.T) {
	const src = `package workspace

// Cleanup removes the temporary checkout directory after a build.
func Cleanup(path string) error {
	return os.Remove(path)
}
`
	d := detector{}

	matches := d.Detect("workspace/cleanup.go", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() on legitimately-mutating fixture = %d matches, want 0; matches=%+v", len(matches), matches)
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
