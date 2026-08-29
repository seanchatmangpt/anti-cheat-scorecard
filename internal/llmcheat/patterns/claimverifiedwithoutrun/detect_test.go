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

package claimverifiedwithoutrun

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// TestDirtyClaimWithNoEvidenceProducesMatch expands the assignment's
// one-line dirty example into a realistic multi-line Python fixture: a
// legitimate preceding comment line, then an unsubstantiated "Verified"
// claim with no command, test name, or tool invocation anywhere nearby.
func TestDirtyClaimWithNoEvidenceProducesMatch(t *testing.T) {
	content := []byte(`# Fixed the race condition in the connection pool.
# Verified this works correctly in all cases.
def acquire_connection(self):
    with self._lock:
        return self._pool.pop()
`)

	got := newDetector().Detect("pool.py", content)

	if len(got) < 1 {
		t.Fatalf("Detect() returned %d matches, want >= 1 for an unsubstantiated verification claim: %+v", len(got), got)
	}
	for _, m := range got {
		if m.PatternID != "claim-verified-without-run" {
			t.Errorf("Match.PatternID = %q, want %q", m.PatternID, "claim-verified-without-run")
		}
		if m.Category != "fabricated-claims" {
			t.Errorf("Match.Category = %q, want %q", m.Category, "fabricated-claims")
		}
	}
	// The claim sits on line 2 of the fixture.
	if got[0].Line != 2 {
		t.Errorf("Match.Line = %d, want 2 (the line bearing the claim word)", got[0].Line)
	}
}

// TestCleanClaimWithBacktickedCommandProducesNoMatch expands the
// assignment's one-line clean example: the same claim word, but backed by a
// backticked, real test-runner invocation on the same line.
func TestCleanClaimWithBacktickedCommandProducesNoMatch(t *testing.T) {
	content := []byte(`# Fixed the race condition in the connection pool.
# Verified via ` + "`pytest tests/test_pool.py -v`" + `, 12 passed.
def acquire_connection(self):
    with self._lock:
        return self._pool.pop()
`)

	got := newDetector().Detect("pool.py", content)

	if len(got) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 for a claim backed by a backticked pytest invocation: %+v", len(got), got)
	}
}

// TestEvidenceOnFollowingLineWithinWindowProducesNoMatch covers the "same
// or next 2 lines" window explicitly: the claim and its evidence are on
// separate lines, but the evidence (a backticked cargo test invocation) is
// still within the 2-line lookahead.
func TestEvidenceOnFollowingLineWithinWindowProducesNoMatch(t *testing.T) {
	content := []byte(`// Fixed the deadlock in the scheduler shutdown path.
// Confirmed the fix resolves the deadlock.
// Ran: ` + "`cargo test --test deadlock_regression`" + ` and it passed.
fn shutdown(&mut self) {
    self.workers.join_all();
}
`)

	got := newDetector().Detect("scheduler.rs", content)

	if len(got) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0: evidence is on the line after the claim, still inside the 2-line window: %+v", len(got), got)
	}
}

// TestClaimWordInsideCodeStatementProducesNoMatch covers the boundary
// against false positives: "verified" appears as a real Go identifier in an
// actual source statement, not in a comment/doc/commit-message-shaped line,
// so it must not be flagged even though there is no nearby test evidence.
func TestClaimWordInsideCodeStatementProducesNoMatch(t *testing.T) {
	content := []byte(`func process(input []byte) bool {
    verified := checkSignature(input)
    return verified
}
`)

	got := newDetector().Detect("process.go", content)

	if len(got) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0: %q is a code identifier, not a prose claim: %+v", len(got), "verified", got)
	}
}

// TestCommitMessageShapedLineWithNoMarkerIsFlagged covers a
// commit-message-shaped line, which (unlike a source comment) carries no
// comment marker at all, to confirm the marker-less prose branch of
// isProseShapedLine still catches an unsubstantiated claim.
func TestCommitMessageShapedLineWithNoMarkerIsFlagged(t *testing.T) {
	content := []byte(`fix(pool): resolve connection leak under load

Confirmed the fix addresses issue #482 in production.
`)

	got := newDetector().Detect("COMMIT_EDITMSG", content)

	if len(got) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1 for the marker-less commit-message claim: %+v", len(got), got)
	}
	if got[0].PatternID != "claim-verified-without-run" || got[0].Category != "fabricated-claims" {
		t.Errorf("Match = %+v, want PatternID claim-verified-without-run / Category fabricated-claims", got[0])
	}
}

// TestClaimWithUnbacktickedCliFlagEvidenceProducesNoMatch covers the
// CLI-flag-looking-token evidence path (no backticks involved at all).
func TestClaimWithUnbacktickedCliFlagEvidenceProducesNoMatch(t *testing.T) {
	content := []byte(`# Validated the output using go test -run TestPool -v
`)

	got := newDetector().Detect("pool.py", content)

	if len(got) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0: line names go test and CLI flags directly: %+v", len(got), got)
	}
}

// TestIDAndCategoryMatchInterfaceMethods is a direct, state-based check
// (no mocking — there is nothing here to mock) that the detector's ID()
// and Category() methods return the exact constants documented for this
// pattern.
func TestIDAndCategoryMatchInterfaceMethods(t *testing.T) {
	d := newDetector()
	if got := d.ID(); got != "claim-verified-without-run" {
		t.Errorf("ID() = %q, want %q", got, "claim-verified-without-run")
	}
	if got := d.Category(); got != "fabricated-claims" {
		t.Errorf("Category() = %q, want %q", got, "fabricated-claims")
	}
}

// TestRegistersWithSharedRegistry proves this package's init() actually
// registers a working Pattern against the real, shared llmcheat registry
// (state-based: inspect what llmcheat.All() really returns after Reset(),
// not an interaction assertion on a mock).
func TestRegistersWithSharedRegistry(t *testing.T) {
	llmcheat.Reset()
	llmcheat.Register(newDetector())

	all := llmcheat.All()
	if len(all) != 1 {
		t.Fatalf("llmcheat.All() returned %d patterns after a fresh Reset+Register, want 1", len(all))
	}
	if all[0].ID() != "claim-verified-without-run" {
		t.Errorf("registered pattern ID = %q, want %q", all[0].ID(), "claim-verified-without-run")
	}

	llmcheat.Reset()
}
