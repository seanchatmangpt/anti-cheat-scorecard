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

package nondeterministicsourceindeterministicpath

import (
	"strings"
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// dirtyGoSource is a realistic multi-line Go file: a function that
// documents itself as computing a deterministic hash, yet salts its
// output with the wall clock — the exact shape named in the pattern's own
// contract example.
const dirtyGoSource = `package content

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Computes a deterministic content hash.
func hash(data []byte) string {
	salt := time.Now().String()
	sum := sha256.Sum256(append(data, salt...))
	return hex.EncodeToString(sum[:])
}
`

// cleanGoSource is the same function shape with the wall-clock read
// removed: it genuinely is a pure function of its input, so it must
// produce zero matches.
const cleanGoSource = `package content

import (
	"crypto/sha256"
	"encoding/hex"
)

// Computes a deterministic content hash.
func hash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
`

func TestDetect_DirtyGoFixture_ProducesMatch(t *testing.T) {
	d := detector{}

	matches := d.Detect("content/hash.go", []byte(dirtyGoSource))

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
	if got.Path != "content/hash.go" {
		t.Errorf("Match.Path = %q, want %q", got.Path, "content/hash.go")
	}

	// Derive the expected 1-based line number directly from the fixture
	// text itself (rather than a hand-counted literal) so the assertion
	// stays correct even if the fixture is edited later.
	wantLine := uint(0)
	for i, line := range strings.Split(dirtyGoSource, "\n") {
		if strings.Contains(line, "time.Now()") {
			wantLine = uint(i + 1)
			break
		}
	}
	if wantLine == 0 {
		t.Fatal("test fixture bug: dirtyGoSource does not contain the expected time.Now() literal")
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

func TestDetect_CleanGoFixture_ProducesNoMatches(t *testing.T) {
	d := detector{}

	matches := d.Detect("content/hash.go", []byte(cleanGoSource))

	if len(matches) != 0 {
		t.Fatalf("Detect() on clean fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

// TestDetect_NonPromisingFunction_TimeNowNotFlagged proves the pattern's
// scope boundary: time.Now() used inside a function that neither by name
// nor by doc comment claims determinism/reproducibility (a plain
// observability timestamp helper) is legitimate and must not be flagged —
// this pattern targets a broken *promise*, not every real-time read.
func TestDetect_NonPromisingFunction_TimeNowNotFlagged(t *testing.T) {
	const src = `package clock

import "time"

// Logs the current server timestamp for observability.
func logTimestamp() string {
	return time.Now().String()
}
`
	d := detector{}

	matches := d.Detect("clock/clock.go", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() on non-promising fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

// TestDetect_DocCommentOnlyKeyword_StillFlagged proves the doc-comment half
// of the "name OR doc comment" rule: a function name with no keyword
// substring, but a preceding multi-line doc comment that does, must still
// be flagged.
func TestDetect_DocCommentOnlyKeyword_StillFlagged(t *testing.T) {
	const src = `package ordering

import "time"

// Returns a reproducible ordering key for two records so re-runs
// always sort the same way.
func orderKey(a, b string) string {
	salt := time.Now().String()
	return a + salt + b
}
`
	d := detector{}

	matches := d.Detect("ordering/order.go", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() on doc-comment-only fixture = %d matches, want 1; matches=%+v", len(matches), matches)
	}
	if matches[0].PatternID != patternID {
		t.Errorf("Match.PatternID = %q, want %q", matches[0].PatternID, patternID)
	}
}

// TestDetect_RustUnseededThreadRng_ProducesMatch proves the Rust shape:
// rand::thread_rng() called inside a fn whose doc comment claims a
// reproducible digest.
func TestDetect_RustUnseededThreadRng_ProducesMatch(t *testing.T) {
	const src = `/// Computes a reproducible digest for the given payload.
fn build_digest(payload: &[u8]) -> String {
    let mut rng = rand::thread_rng();
    let salt: u64 = rng.gen();
    format!("{:x}-{}", crc32(payload), salt)
}
`
	d := detector{}

	matches := d.Detect("src/digest.rs", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() on Rust fixture = %d matches, want 1; matches=%+v", len(matches), matches)
	}
	if matches[0].Line != 3 {
		t.Errorf("Match.Line = %d, want 3", matches[0].Line)
	}
	if matches[0].Category != patternCategory {
		t.Errorf("Match.Category = %q, want %q", matches[0].Category, patternCategory)
	}
}

// TestDetect_JavaScriptMathRandom_ProducesMatch proves the JS/TS shape: a
// function declaration whose own name claims a deterministic digest, yet
// calls Math.random() in its body.
func TestDetect_JavaScriptMathRandom_ProducesMatch(t *testing.T) {
	const src = `// Builds a deterministic identifier for caching.
function generateDeterministicDigest(input) {
  const nonce = Math.random();
  return input + ':' + nonce;
}
`
	d := detector{}

	matches := d.Detect("src/digest.js", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() on JS fixture = %d matches, want 1; matches=%+v", len(matches), matches)
	}
	if matches[0].Line != 3 {
		t.Errorf("Match.Line = %d, want 3", matches[0].Line)
	}
}

// TestDetect_PythonRandomRandom_ProducesMatch proves the Python
// indentation-delimited-body shape, including the doc-comment-only match
// path (the function name "cache_key" carries no keyword itself).
func TestDetect_PythonRandomRandom_ProducesMatch(t *testing.T) {
	const src = `import random

# Returns a reproducible hash key for cache lookups.
def cache_key(payload):
    salt = random.random()
    return f"{payload}-{salt}"
`
	d := detector{}

	matches := d.Detect("src/cache.py", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() on Python fixture = %d matches, want 1; matches=%+v", len(matches), matches)
	}
	if matches[0].Line != 5 {
		t.Errorf("Match.Line = %d, want 5", matches[0].Line)
	}
}

// TestDetect_RustTraitMethodDeclaration_NoOpeningBrace proves the
// declaration-only-signature guard: a Rust trait method signature ending in
// ';' with no body at all must not cause the rest of the file to be
// misread as that method's body.
func TestDetect_RustTraitMethodDeclaration_NoOpeningBrace(t *testing.T) {
	const src = `trait Hasher {
    /// Returns a deterministic digest of the given bytes.
    fn digest(&self, data: &[u8]) -> String;
}

/// Computes a deterministic digest using a real implementation.
fn real_digest(data: &[u8]) -> String {
    sha256_hex(data)
}
`
	d := detector{}

	matches := d.Detect("src/hasher.rs", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() on trait-declaration fixture = %d matches, want 0; matches=%+v", len(matches), matches)
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
