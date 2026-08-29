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

package selfcontradictingstatus

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// TestDetect_Dirty_AdjacentContradiction expands the task's one-line dirty
// example into a realistic multi-line Go comment block: a completion claim
// immediately followed by a TODO that admits the same feature is not
// actually finished.
func TestDetect_Dirty_AdjacentContradiction(t *testing.T) {
	content := []byte(
		"// parseConfig loads and validates the deployment config.\n" +
			"//\n" +
			"// Feature complete.\n" +
			"// TODO: still need to handle the error case above.\n" +
			"func parseConfig(path string) (*Config, error) {\n" +
			"\treturn loadYAML(path)\n" +
			"}\n",
	)

	d := detector{}
	matches := d.Detect("internal/config/parse.go", content)

	if len(matches) < 1 {
		t.Fatalf("Detect() returned %d matches, want >= 1 for dirty fixture", len(matches))
	}

	for i, m := range matches {
		if m.PatternID != "self-contradicting-status" {
			t.Errorf("matches[%d].PatternID = %q, want %q", i, m.PatternID, "self-contradicting-status")
		}
		if m.Category != "fabricated-claims" {
			t.Errorf("matches[%d].Category = %q, want %q", i, m.Category, "fabricated-claims")
		}
		if m.Path != "internal/config/parse.go" {
			t.Errorf("matches[%d].Path = %q, want %q", i, m.Path, "internal/config/parse.go")
		}
		if m.Line == 0 {
			t.Errorf("matches[%d].Line = 0, want a real 1-based line number", i)
		}
	}

	// The TODO is on line 4 (1-based); that is the line the contradiction
	// is anchored to.
	found := false
	for _, m := range matches {
		if m.Line == 4 {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a match anchored at line 4 (the TODO line), got lines: %+v", matches)
	}
}

// TestDetect_Clean_CompleteWithNoNearbyMarker expands the task's one-line
// clean example: a completion claim that is actually substantiated (it
// names what was covered and where the evidence lives) and has no
// TODO/FIXME/BLOCKED marker anywhere nearby.
func TestDetect_Clean_CompleteWithNoNearbyMarker(t *testing.T) {
	content := []byte(
		"# process_payment handles the full checkout flow.\n" +
			"#\n" +
			"# Feature complete: happy path + error handling both covered,\n" +
			"# see tests/test_feature.py.\n" +
			"def process_payment(order):\n" +
			"    return charge(order)\n",
	)

	d := detector{}
	matches := d.Detect("payments/process.py", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 for clean fixture; matches=%+v", len(matches), matches)
	}
}

// TestDetect_MarkerFarFromClaim_NoMatch is the boundary case for the ~5-line
// proximity window: a real TODO does exist in the file, and a real
// completion claim does exist in the file, but they are far enough apart
// that they plausibly refer to different subjects and must NOT be reported
// as a same-scope contradiction.
func TestDetect_MarkerFarFromClaim_NoMatch(t *testing.T) {
	content := []byte(
		"// Auth module: feature complete, fully implemented and reviewed.\n" +
			"//\n" +
			"// (many unrelated lines follow)\n" +
			"// line 4\n" +
			"// line 5\n" +
			"// line 6\n" +
			"// line 7\n" +
			"// line 8\n" +
			"// line 9\n" +
			"// line 10\n" +
			"//\n" +
			"// Unrelated: TODO clean up the logging module later.\n",
	)

	d := detector{}
	matches := d.Detect("internal/auth/auth.go", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 when claim and marker are >5 lines apart; matches=%+v",
			len(matches), matches)
	}
}

// TestDetect_MarkerJustInsideWindow_Matches checks the other side of that
// same boundary: exactly proximityWindowLines apart still counts as nearby.
func TestDetect_MarkerJustInsideWindow_Matches(t *testing.T) {
	content := []byte(
		"// Status: ALIVE.\n" + // line 1: done-claim
			"// line 2\n" +
			"// line 3\n" +
			"// line 4\n" +
			"// line 5\n" +
			"// FIXME: this is not actually working end to end yet.\n", // line 6: marker, distance 5
	)

	d := detector{}
	matches := d.Detect("STATUS.md", content)

	if len(matches) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1 at the edge of the proximity window; matches=%+v",
			len(matches), matches)
	}
	if matches[0].Line != 6 {
		t.Errorf("matches[0].Line = %d, want 6", matches[0].Line)
	}
}

// TestDetect_LowercaseAliveWord_NotTreatedAsStatusClaim guards against a
// false positive: "alive" used as an ordinary English word (not the
// upper-cased ALIVE status keyword) sitting near a TODO must not be
// reported, since it isn't actually a completion claim.
func TestDetect_LowercaseAliveWord_NotTreatedAsStatusClaim(t *testing.T) {
	content := []byte(
		"// keepAlive pings the server to keep the connection alive.\n" +
			"// TODO: make the keepalive interval configurable.\n",
	)

	d := detector{}
	matches := d.Detect("internal/net/keepalive.go", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 for lowercase 'alive' (not a status claim); matches=%+v",
			len(matches), matches)
	}
}

// TestDetector_IDAndCategory checks the two Pattern identity methods
// directly, since checks/raw/anti_cheat.go and internal/llmcheat.Register
// both key off these exact strings.
func TestDetector_IDAndCategory(t *testing.T) {
	d := detector{}
	if got := d.ID(); got != "self-contradicting-status" {
		t.Errorf("ID() = %q, want %q", got, "self-contradicting-status")
	}
	if got := d.Category(); got != "fabricated-claims" {
		t.Errorf("Category() = %q, want %q", got, "fabricated-claims")
	}
}

// TestDetector_ImplementsPattern is a compile-time-flavored, still
// state-based check that detector genuinely satisfies llmcheat.Pattern (the
// real interface, not a hand-rolled substitute) and that init() registered
// it under its own real ID via the real llmcheat.Register/llmcheat.All path.
func TestDetector_ImplementsPattern(t *testing.T) {
	var _ llmcheat.Pattern = detector{}

	found := false
	for _, p := range llmcheat.All() {
		if p.ID() == "self-contradicting-status" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("llmcheat.All() does not contain a registered %q pattern; init() may not have run Register",
			"self-contradicting-status")
	}
}
