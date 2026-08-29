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

package standingvocabularymisuse

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// dirtyStatusFile is a realistic expansion of the spec's one-line dirty
// example: a status file that has clearly adopted the closed, ALL-CAPS
// vocabulary (ALIVE / BLOCKED elsewhere in the history) but then narrates
// the actual status change informally instead of citing real evidence.
const dirtyStatusFile = `# gate-9 standing status
#
# History:
#   2026-01-01  status = "UNKNOWN"
#   2026-01-05  status = "BLOCKED"  # ci: build_broken on nightly toolchain
#   2026-01-08  status = "ALIVE" # was BLOCKED yesterday, should be good now
#
# Verified by: nobody yet, just looks finished to me and the receipts are
# probably fine, the pipeline seems stable enough to ship.
status = "ALIVE"
`

// cleanStatusFile is a realistic expansion of the spec's one-line clean
// example: it also uses the closed vocabulary, but every status change is
// backed by a cited artifact rather than an informal adjective.
const cleanStatusFile = `# gate-9 standing status
#
# History:
#   2026-01-01  status = "UNKNOWN"  # see receipts/gate-9-20260101-init.json
#   2026-01-05  status = "BLOCKED"  # see receipts/gate-9-20260105-ci.json
#   2026-01-08  status = "ALIVE"    # see receipts/gate-9-20260108-verify.json
#
status = "ALIVE"  # see receipts/gate-9-20260101.json
`

func TestDetect_DirtyFixture_ProducesMatchesWithCorrectIdentity(t *testing.T) {
	d := &detector{}

	got := d.Detect("STANDING.md", []byte(dirtyStatusFile))

	if len(got) == 0 {
		t.Fatalf("Detect() on dirty fixture returned 0 matches, want >= 1")
	}

	for _, m := range got {
		if m.PatternID != "standing-vocabulary-misuse" {
			t.Errorf("match PatternID = %q, want %q", m.PatternID, "standing-vocabulary-misuse")
		}
		if m.Category != "fabricated-claims" {
			t.Errorf("match Category = %q, want %q", m.Category, "fabricated-claims")
		}
		if m.Path != "STANDING.md" {
			t.Errorf("match Path = %q, want %q", m.Path, "STANDING.md")
		}
		if m.Line == 0 {
			t.Errorf("match Line = 0, want a real 1-based line number")
		}
	}

	// The offending line ("...should be good now") carries at least
	// "good" and "finished" ("...just looks finished to me...") and
	// "stable" ("...seems stable enough...") as informal synonyms; make
	// sure the specific words this pattern targets are actually found,
	// not just some unrelated match.
	wantWords := map[string]bool{"good": false, "finished": false, "stable": false}
	for _, m := range got {
		for w := range wantWords {
			if containsFold(m.Message, w) {
				wantWords[w] = true
			}
		}
	}
	for w, found := range wantWords {
		if !found {
			t.Errorf("expected a match mentioning informal word %q, none found in: %+v", w, got)
		}
	}
}

func TestDetect_CleanFixture_ProducesZeroMatches(t *testing.T) {
	d := &detector{}

	got := d.Detect("STANDING.md", []byte(cleanStatusFile))

	if len(got) != 0 {
		t.Fatalf("Detect() on clean fixture returned %d matches, want 0: %+v", len(got), got)
	}
}

func TestDetect_NoClosedVocabularyEvidence_InformalWordsIgnored(t *testing.T) {
	// A file that never uses the closed ALL-CAPS vocabulary anywhere has
	// nothing for an informal word to be a substitute for — "good",
	// "ready" etc. here are just ordinary prose, not a standing-vocabulary
	// violation, so this must produce zero matches even though every
	// informal target word is present.
	const noEvidence = `# release notes
The build is done, tests are passing, everything looks good and ready.
This release is stable and the migration is finished.
`
	d := &detector{}

	got := d.Detect("NOTES.md", []byte(noEvidence))

	if len(got) != 0 {
		t.Fatalf("Detect() with no closed-vocabulary evidence returned %d matches, want 0: %+v", len(got), got)
	}
}

func TestDetect_WordBoundaries_SubstringsAndAllCapsTokensDoNotMatch(t *testing.T) {
	// Evidence is present (ALIVE, READY), but every candidate word below
	// is either a substring of a larger identifier (not a whole-word
	// match) or a literal all-caps use of the vocabulary itself (READY),
	// so none of them should be flagged. Deliberately avoids repeating any
	// target word as a bare, standalone token anywhere in the fixture
	// (including in comments), so a pass here is only possible if the
	// word-boundary logic itself is correct.
	const boundaryFile = `status = "ALIVE"
workingDir = "/tmp/build"
readying_the_next_release = true
goodness_knows_what_happened = 1
next_status = "READY"
`
	d := &detector{}

	got := d.Detect("boundary.toml", []byte(boundaryFile))

	if len(got) != 0 {
		t.Fatalf("Detect() on boundary fixture returned %d matches, want 0: %+v", len(got), got)
	}
}

func TestDetect_LineNumbersAreAccurate(t *testing.T) {
	const multiLine = "status = \"BLOCKED\"\n" + // line 1: evidence only
		"\n" + // line 2: blank
		"# should be ready soon\n" // line 3: informal "ready"

	d := &detector{}

	got := d.Detect("f.toml", []byte(multiLine))

	if len(got) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1: %+v", len(got), got)
	}
	if got[0].Line != 3 {
		t.Errorf("match Line = %d, want 3", got[0].Line)
	}
}

func TestDetector_IdentityMethods(t *testing.T) {
	d := &detector{}

	if got := d.ID(); got != "standing-vocabulary-misuse" {
		t.Errorf("ID() = %q, want %q", got, "standing-vocabulary-misuse")
	}
	if got := d.Category(); got != "fabricated-claims" {
		t.Errorf("Category() = %q, want %q", got, "fabricated-claims")
	}
}

// TestPattern_SatisfiesLLMCheatInterface is a compile-time-flavored check
// (run at test time) that the real registered instance satisfies
// llmcheat.Pattern, and that it registered itself under the expected ID via
// this package's init().
func TestPattern_SatisfiesLLMCheatInterface(t *testing.T) {
	var _ llmcheat.Pattern = instance

	if instance.ID() != patternID {
		t.Errorf("registered instance ID() = %q, want %q", instance.ID(), patternID)
	}
}

// containsFold reports whether s contains substr, ASCII-case-insensitively.
// Small local helper kept dependency-free rather than pulling in strings
// twice for one case-fold check.
func containsFold(s, substr string) bool {
	sl := []byte(s)
	bl := []byte(substr)
	for i := 0; i+len(bl) <= len(sl); i++ {
		match := true
		for j := 0; j < len(bl); j++ {
			a, b := sl[i+j], bl[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
