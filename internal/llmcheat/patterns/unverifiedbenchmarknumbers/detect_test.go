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

package unverifiedbenchmarknumbers

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

func assertIDAndCategory(t *testing.T, matches []llmcheat.Match) {
	t.Helper()
	for _, m := range matches {
		if m.PatternID != "unverified-benchmark-numbers" {
			t.Errorf("Match.PatternID = %q, want %q", m.PatternID, "unverified-benchmark-numbers")
		}
		if m.Category != "fabricated-claims" {
			t.Errorf("Match.Category = %q, want %q", m.Category, "fabricated-claims")
		}
	}
}

// TestDetect_DirtySpeedupClaim expands on the assignment's one-line dirty
// example into a realistic multi-line Go comment block: an unbacked "10x
// faster" claim with no benchmark/receipt/output reference anywhere nearby.
func TestDetect_DirtySpeedupClaim(t *testing.T) {
	src := []byte(`// Package sync implements the new incremental sync engine.
//
// This is 10x faster than the old implementation. We rewrote the diffing
// algorithm from scratch and it just flies now.
package sync
`)

	d := detector{}
	matches := d.Detect("internal/sync/engine.go", src)

	if len(matches) < 1 {
		t.Fatalf("Detect() returned %d matches for an unbacked speedup claim, want >= 1", len(matches))
	}
	assertIDAndCategory(t, matches)

	// The claim is on line 3 (1-based): "// This is 10x faster..."
	found := false
	for _, m := range matches {
		if m.Line == 3 {
			found = true
		}
	}
	if !found {
		t.Errorf("Detect() matches = %+v, want a match anchored at line 3", matches)
	}
}

// TestDetect_CleanWithReceiptCitation expands the assignment's one-line
// clean example: the same kind of specific numbers, but immediately citing
// a receipt file and the benchmark script that produced it.
func TestDetect_CleanWithReceiptCitation(t *testing.T) {
	src := []byte(`// Sync latency, measured locally:
// p50=96ms p95=203ms, see receipts/benchmark-sync-dryrun-20260101.json (scripts/benchmark.sh)
// Re-run scripts/benchmark.sh to reproduce.
func Sync() error {
	return nil
}
`)

	d := detector{}
	matches := d.Detect("internal/sync/engine.go", src)

	if len(matches) != 0 {
		t.Fatalf("Detect() = %+v, want 0 matches for a receipt-backed performance claim", matches)
	}
}

// TestDetect_ReferenceWithinThreeLinesStillClean proves the 3-line window
// is actually honored: the number and its reference are two lines apart,
// not on the same line.
func TestDetect_ReferenceWithinThreeLinesStillClean(t *testing.T) {
	src := []byte(`// Benchmark results below.
//
// Sync now completes in 3.2s on the reference corpus.
//
// Raw command output: scripts/benchmark.sh > receipts/sync-bench.log
`)

	d := detector{}
	matches := d.Detect("internal/sync/README.md", src)

	if len(matches) != 0 {
		t.Fatalf("Detect() = %+v, want 0 matches when a benchmark reference is within 3 lines", matches)
	}
}

// TestDetect_ReferenceOutsideThreeLinesIsDirty is the negative control for
// the previous test: the same reference exists in the file, but far enough
// away (more than 3 lines) that it should no longer suppress the match.
func TestDetect_ReferenceOutsideThreeLinesIsDirty(t *testing.T) {
	src := []byte(`// Benchmark results below.
//
//
//
//
// Sync now completes in 3.2s on the reference corpus.
//
//
//
//
// Raw command output: scripts/benchmark.sh > receipts/sync-bench.log
`)

	d := detector{}
	matches := d.Detect("internal/sync/README.md", src)

	if len(matches) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1 when the only reference is >3 lines away", len(matches))
	}
	assertIDAndCategory(t, matches)
	if matches[0].Line != 6 {
		t.Errorf("Detect() match line = %d, want 6 (\"Sync now completes in 3.2s...\")", matches[0].Line)
	}
}

// TestDetect_NonCommentCodeLineIgnored proves a bare performance-shaped
// number inside real, non-comment source code (not a claim, just a
// constant) is not flagged: the pattern is about unverified prose claims,
// not about the presence of a duration literal in code.
func TestDetect_NonCommentCodeLineIgnored(t *testing.T) {
	src := []byte(`package sync

import "time"

func defaultTimeout() time.Duration {
	return 96 * time.Millisecond // 96ms default, tuned for local networks
}
`)

	d := detector{}
	matches := d.Detect("internal/sync/config.go", src)

	// Line 6 is code (not comment-prefixed) even though it ends in a
	// trailing comment; commentPrefixRe only matches when the comment
	// marker starts the line, so this line is out of scope entirely.
	if len(matches) != 0 {
		t.Fatalf("Detect() = %+v, want 0 matches for a non-comment-prefixed code line", matches)
	}
}

// TestDetect_DecadeIsNotADuration proves the bare "s" unit does not
// misfire on a plain decade reference like "1990s" or "2020s".
func TestDetect_DecadeIsNotADuration(t *testing.T) {
	src := []byte(`// This retry-loop style was common in the 1990s and still works fine
// today; no need to modernize it.
`)

	d := detector{}
	matches := d.Detect("internal/sync/retry.go", src)

	if len(matches) != 0 {
		t.Fatalf("Detect() = %+v, want 0 matches; \"1990s\" is a decade, not a duration claim", matches)
	}
}

// TestDetect_MarkdownWholeFileInScope proves that for a .md file every
// line is in scope (no "//" comment-prefix requirement), matching the
// assignment's markdown-file case.
func TestDetect_MarkdownWholeFileInScope(t *testing.T) {
	src := []byte(`# Sync Performance

Our new sync engine is 4x faster than the previous release and completes
typical repos in well under a second.
`)

	d := detector{}
	matches := d.Detect("docs/PERFORMANCE.md", src)

	if len(matches) < 1 {
		t.Fatalf("Detect() returned %d matches for an unbacked markdown speedup claim, want >= 1", len(matches))
	}
	assertIDAndCategory(t, matches)
}

// TestDetect_IDAndCategory locks down the two Pattern interface accessors
// independently of any Detect() call.
func TestDetect_IDAndCategory(t *testing.T) {
	d := detector{}
	if got, want := d.ID(), "unverified-benchmark-numbers"; got != want {
		t.Errorf("ID() = %q, want %q", got, want)
	}
	if got, want := d.Category(), "fabricated-claims"; got != want {
		t.Errorf("Category() = %q, want %q", got, want)
	}
}
