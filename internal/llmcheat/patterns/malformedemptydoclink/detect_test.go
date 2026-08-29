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

package malformedemptydoclink

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// TestDetect_DirtyPlaceholderLink_ProducesMatch is a real, expanded version
// of the assignment's dirty one-liner ("See [the design doc](TODO) for
// details.") embedded in a realistic multi-line Markdown README section, run
// through the real detector against real bytes.
func TestDetect_DirtyPlaceholderLink_ProducesMatch(t *testing.T) {
	content := []byte(`# Architecture Overview

This module implements the receipt-verification pipeline.

See [the design doc](TODO) for details.

The verifier checks the chain hash before admitting a receipt.
`)

	d := detector{}
	matches := d.Detect("docs/ARCHITECTURE.md", content)

	if len(matches) == 0 {
		t.Fatalf("Detect() returned 0 matches for a fixture containing a TODO-placeholder link; want >= 1")
	}

	foundOnTriggerLine := false
	for _, m := range matches {
		if m.PatternID != patternID {
			t.Errorf("match PatternID = %q, want %q", m.PatternID, patternID)
		}
		if m.Category != patternCategory {
			t.Errorf("match Category = %q, want %q", m.Category, patternCategory)
		}
		if m.Path != "docs/ARCHITECTURE.md" {
			t.Errorf("match Path = %q, want %q", m.Path, "docs/ARCHITECTURE.md")
		}
		if m.Line == 0 {
			t.Errorf("match Line = 0, want a real 1-based line number")
		}
		if m.Message == "" {
			t.Errorf("match Message is empty, want a real explanation")
		}
		if m.Line == 5 {
			foundOnTriggerLine = true
		}
	}
	if !foundOnTriggerLine {
		t.Errorf("expected a match anchored at line 5 (the %q line); got matches at lines %v",
			"See [the design doc](TODO) for details.", lineNumbers(matches))
	}
}

// TestDetect_CleanRealPathLink_ProducesZeroMatches is a real, expanded
// version of the assignment's clean one-liner ("See [the design doc]
// (docs/DESIGN.md) for details.") embedded in a realistic multi-line
// Markdown README section, alongside a second real link to prove more than
// one legitimate link in the same file stays clean.
func TestDetect_CleanRealPathLink_ProducesZeroMatches(t *testing.T) {
	content := []byte(`# Architecture Overview

This module implements the receipt-verification pipeline.

See [the design doc](docs/DESIGN.md) for details, and the
[admission shapes](../admission/shapes.ttl) for the SHACL contract.

The verifier checks the chain hash before admitting a receipt.
`)

	d := detector{}
	matches := d.Detect("docs/ARCHITECTURE.md", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches for a fixture whose links all target real paths; want 0, got %+v", len(matches), matches)
	}
}

// TestDetect_EmptyLinkTarget_ProducesMatch covers the bare `()` shape named
// explicitly in the assignment, distinct from a placeholder token.
func TestDetect_EmptyLinkTarget_ProducesMatch(t *testing.T) {
	content := []byte(`## Follow-up

We still need to write up [the migration guide]() once the schema settles.
`)

	d := detector{}
	matches := d.Detect("docs/NOTES.md", content)

	if len(matches) != 1 {
		t.Fatalf("Detect() returned %d matches for an empty-target link; want 1, got %+v", len(matches), matches)
	}
	if matches[0].Line != 3 {
		t.Errorf("match Line = %d, want 3", matches[0].Line)
	}
}

// TestDetect_BareHashFragment_ProducesMatch covers the bare `#` shape named
// explicitly in the assignment (an in-page anchor link with no real anchor
// name), while TestDetect_NamedHashFragment_ProducesZeroMatches below proves
// a real, non-empty in-page anchor is left alone.
func TestDetect_BareHashFragment_ProducesMatch(t *testing.T) {
	content := []byte(`See [back to top](#) to return to the beginning.
`)

	d := detector{}
	matches := d.Detect("docs/GUIDE.md", content)

	if len(matches) != 1 {
		t.Fatalf("Detect() returned %d matches for a bare '#' fragment link; want 1, got %+v", len(matches), matches)
	}
}

// TestDetect_NamedHashFragment_ProducesZeroMatches is the boundary case for
// TestDetect_BareHashFragment_ProducesMatch: a real, named in-page anchor
// (not a bare "#") is a legitimate link and must not be flagged.
func TestDetect_NamedHashFragment_ProducesZeroMatches(t *testing.T) {
	content := []byte(`See [the admission section](#admission-and-closure) below.
`)

	d := detector{}
	matches := d.Detect("docs/GUIDE.md", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches for a real, named in-page anchor; want 0, got %+v", len(matches), matches)
	}
}

// TestDetect_AllPlaceholderTokens_EachProducesMatch exercises every
// placeholder token named in the assignment ("TODO", "TBD", "link", "FIXME",
// "xxx"), including mixed case and a trailing punctuation mark, to prove the
// case-insensitive, punctuation-trimmed matching actually works for all of
// them rather than just the one dirty example.
func TestDetect_AllPlaceholderTokens_EachProducesMatch(t *testing.T) {
	content := []byte(`- [runbook](TODO)
- [design notes](TBD)
- [source](link)
- [tracking issue](FIXME)
- [scratch](xxx)
- [trailing punctuation](TODO.)
`)

	d := detector{}
	matches := d.Detect("docs/BACKLOG.md", content)

	if len(matches) != 6 {
		t.Fatalf("Detect() returned %d matches, want 6 (one per placeholder-token link); got %+v", len(matches), matches)
	}
	wantLines := map[uint]bool{1: true, 2: true, 3: true, 4: true, 5: true, 6: true}
	for _, m := range matches {
		if !wantLines[m.Line] {
			t.Errorf("unexpected match line %d; want one of {1..6}", m.Line)
		}
		delete(wantLines, m.Line)
	}
	if len(wantLines) != 0 {
		t.Errorf("missing matches on lines %v", wantLines)
	}
}

// TestDetect_PlaceholderLikeSubstringInRealFilename_ProducesZeroMatches
// covers a boundary the assignment implies but doesn't spell out: a real
// filename that merely starts with a placeholder token as a substring (e.g.
// "TODO.md", a real if oddly-named doc file) is a real locator, not a bare
// placeholder token, and must not be flagged.
func TestDetect_PlaceholderLikeSubstringInRealFilename_ProducesZeroMatches(t *testing.T) {
	content := []byte(`See [the TODO tracker](TODO.md) for the current backlog.
`)

	d := detector{}
	matches := d.Detect("docs/GUIDE.md", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches for a real filename that merely starts with 'TODO'; want 0, got %+v", len(matches), matches)
	}
}

// TestDetect_LinkWithTitle_NotMisclassifiedAsMalformed covers the Markdown
// link-title syntax (`[text](url "title")`): the title must be stripped
// before classification so a real, titled link isn't misread as malformed,
// while a placeholder token that happens to carry a title is still caught.
func TestDetect_LinkWithTitle_NotMisclassifiedAsMalformed(t *testing.T) {
	content := []byte(`Real, titled link: [the design doc](docs/DESIGN.md "Design Doc").
Placeholder with a title: [the design doc](TODO "fill this in later").
`)

	d := detector{}
	matches := d.Detect("docs/GUIDE.md", content)

	if len(matches) != 1 {
		t.Fatalf("Detect() returned %d matches; want exactly 1 (only the TODO-with-title link), got %+v", len(matches), matches)
	}
	if matches[0].Line != 2 {
		t.Errorf("match Line = %d, want 2 (the placeholder-with-title line)", matches[0].Line)
	}
}

// TestDetect_NonMarkdownFile_ProducesZeroMatches proves the file-extension
// restriction is real: the same dirty content, in a .go file instead of a
// .md file, must be left entirely alone.
func TestDetect_NonMarkdownFile_ProducesZeroMatches(t *testing.T) {
	content := []byte(`// See [the design doc](TODO) for details.
// See [another one](#) too.
package example
`)

	d := detector{}
	matches := d.Detect("internal/example/example.go", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches for a non-.md file; want 0 (this pattern only scans Markdown), got %+v", len(matches), matches)
	}
}

func lineNumbers(matches []llmcheat.Match) []uint {
	out := make([]uint, len(matches))
	for i, m := range matches {
		out[i] = m.Line
	}
	return out
}
