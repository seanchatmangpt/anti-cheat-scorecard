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

package rustmockalltraitmock

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// TestDetect_DirtyAutomockTraitFlagged proves the assigned dirty example
// (#[automock] on a trait) produces at least one match with the correct
// PatternID and Category, and a correct 1-based line number.
func TestDetect_DirtyAutomockTraitFlagged(t *testing.T) {
	const src = `use mockall::automock;

#[automock]
trait Storage {
    fn save(&self);
    fn load(&self, key: &str) -> Vec<u8>;
}
`
	d := detector{}
	got := d.Detect("src/storage.rs", []byte(src))

	if len(got) < 1 {
		t.Fatalf("Detect() returned %d matches, want at least 1 for #[automock] trait", len(got))
	}

	for _, m := range got {
		if m.PatternID != "rust-mockall-trait-mock" {
			t.Errorf("match PatternID = %q, want %q", m.PatternID, "rust-mockall-trait-mock")
		}
		if m.Category != "test-integrity-violation" {
			t.Errorf("match Category = %q, want %q", m.Category, "test-integrity-violation")
		}
		if m.Path != "src/storage.rs" {
			t.Errorf("match Path = %q, want %q", m.Path, "src/storage.rs")
		}
	}

	// Both the `use mockall::automock;` import (line 1) and the
	// `#[automock]` attribute (line 3) are independently detectable, so
	// this fixture must yield exactly two matches at those two lines.
	if len(got) != 2 {
		t.Fatalf("Detect() returned %d matches, want exactly 2 (import + attribute); got %+v", len(got), got)
	}
	if got[0].Line != 1 {
		t.Errorf("first match Line = %d, want 1 (the `use mockall::automock;` import)", got[0].Line)
	}
	if got[0].Severity != llmcheat.SeverityMedium {
		t.Errorf("first match Severity = %q, want %q", got[0].Severity, llmcheat.SeverityMedium)
	}
	if got[1].Line != 3 {
		t.Errorf("second match Line = %d, want 3 (the #[automock] attribute)", got[1].Line)
	}
	if got[1].Severity != llmcheat.SeverityHigh {
		t.Errorf("second match Severity = %q, want %q", got[1].Severity, llmcheat.SeverityHigh)
	}
}

// TestDetect_CleanRealStructNoMatches proves the assigned clean example (a
// plain real struct, no mockall involvement at all) produces zero matches.
func TestDetect_CleanRealStructNoMatches(t *testing.T) {
	const src = `use std::path::PathBuf;

struct RealStorage {
    path: PathBuf,
}

impl RealStorage {
    fn save(&self, data: &[u8]) -> std::io::Result<()> {
        std::fs::write(&self.path, data)
    }

    fn load(&self) -> std::io::Result<Vec<u8>> {
        std::fs::read(&self.path)
    }
}
`
	d := detector{}
	got := d.Detect("src/storage.rs", []byte(src))

	if len(got) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 for a real, non-mocked implementation; got %+v", len(got), got)
	}
}

// TestDetect_CfgAttrAutomockVariantFlagged proves the conditional
// #[cfg_attr(test, automock)] spelling — the idiomatic real-world way to
// generate a mock only under `cfg(test)` while still shipping the trait
// unmocked in production builds — is also flagged, since the mock code
// generation (and the London-style test discipline it enables) is present
// in the source either way.
func TestDetect_CfgAttrAutomockVariantFlagged(t *testing.T) {
	const src = `#[cfg_attr(test, mockall::automock)]
pub trait Notifier {
    fn notify(&self, msg: &str);
}
`
	d := detector{}
	got := d.Detect("src/notifier.rs", []byte(src))

	if len(got) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1 for #[cfg_attr(test, mockall::automock)]; got %+v", len(got), got)
	}
	if got[0].Line != 1 {
		t.Errorf("match Line = %d, want 1", got[0].Line)
	}
	if got[0].Severity != llmcheat.SeverityHigh {
		t.Errorf("match Severity = %q, want %q", got[0].Severity, llmcheat.SeverityHigh)
	}
}

// TestDetect_BareMockallImportWithoutAutomockFlagged proves a bare
// `use mockall::` import is flagged on its own even when #[automock] never
// appears in the same file (e.g. a shared test-support module that imports
// mockall::predicate helpers for use against mocks defined elsewhere).
func TestDetect_BareMockallImportWithoutAutomockFlagged(t *testing.T) {
	const src = `use mockall::predicate::*;

fn assert_called_with_prefix() {
    // uses predicate helpers against a mock defined in another module
}
`
	d := detector{}
	got := d.Detect("tests/support.rs", []byte(src))

	if len(got) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1 for bare mockall import; got %+v", len(got), got)
	}
	if got[0].PatternID != "rust-mockall-trait-mock" {
		t.Errorf("match PatternID = %q, want %q", got[0].PatternID, "rust-mockall-trait-mock")
	}
	if got[0].Severity != llmcheat.SeverityMedium {
		t.Errorf("match Severity = %q, want %q", got[0].Severity, llmcheat.SeverityMedium)
	}
}

// TestDetect_CommentMentionIgnored proves a full-line `//` comment that
// merely mentions mockall in prose (e.g. explaining why it is deliberately
// NOT used) is not itself flagged as an import or attribute.
func TestDetect_CommentMentionIgnored(t *testing.T) {
	const src = `// Deliberately not using mockall::automock here — see
// use mockall::automock in the old version we moved away from.
struct RealStorage;
`
	d := detector{}
	got := d.Detect("src/storage.rs", []byte(src))

	if len(got) != 0 {
		t.Fatalf("Detect() returned %d matches for comment-only mentions, want 0; got %+v", len(got), got)
	}
}

// TestDetect_NonRustFileIgnored proves the detector only ever inspects .rs
// files, even when the content contains the exact dirty pattern.
func TestDetect_NonRustFileIgnored(t *testing.T) {
	const src = `# not rust: this is a fixture pretending to have Rust-shaped text
# #[automock]
# use mockall::automock;
`
	d := detector{}
	got := d.Detect("notes/storage.py", []byte(src))

	if len(got) != 0 {
		t.Fatalf("Detect() returned %d matches for a non-.rs file, want 0; got %+v", len(got), got)
	}
}

// TestID_Category proves the detector reports the exact ID/Category
// contract this pattern was assigned.
func TestID_Category(t *testing.T) {
	d := detector{}
	if got := d.ID(); got != "rust-mockall-trait-mock" {
		t.Errorf("ID() = %q, want %q", got, "rust-mockall-trait-mock")
	}
	if got := d.Category(); got != "test-integrity-violation" {
		t.Errorf("Category() = %q, want %q", got, "test-integrity-violation")
	}
}
