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

package claimalivewithoutreceipt

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// Chicago-style throughout: every test constructs the real detector{} type
// directly and calls the real Detect on real, realistic multi-line byte
// content, then asserts on the real returned []llmcheat.Match slice. There
// is no collaborator here to fake — Detect is a pure function of its two
// arguments — so there is nothing legitimate to mock.

func assertMatch(t *testing.T, m llmcheat.Match, wantLine uint) {
	t.Helper()
	if m.PatternID != patternID {
		t.Errorf("PatternID = %q, want %q", m.PatternID, patternID)
	}
	if m.Category != category {
		t.Errorf("Category = %q, want %q", m.Category, category)
	}
	if m.Line != wantLine {
		t.Errorf("Line = %d, want %d", m.Line, wantLine)
	}
	if m.Message == "" {
		t.Error("Message is empty, want a real explanation")
	}
	switch m.Severity {
	case llmcheat.SeverityLow, llmcheat.SeverityMedium, llmcheat.SeverityHigh:
		// ok
	default:
		t.Errorf("Severity = %q, want one of low/medium/high", m.Severity)
	}
}

func TestDetect_DirtyGoComment_ProducesMatch(t *testing.T) {
	content := []byte(
		"package sample\n" +
			"\n" +
			"// Package sample implements the authentication flow.\n" +
			"\n" +
			"func Login() error {\n" +
			"\t// Auth flow is done and fully working.\n" +
			"\treturn nil\n" +
			"}\n",
	)

	d := detector{}
	matches := d.Detect("sample/auth.go", content)

	if len(matches) < 1 {
		t.Fatalf("Detect() returned %d matches, want >= 1 for a bare completion claim with no evidence", len(matches))
	}
	// Line 6 is "\t// Auth flow is done and fully working."
	assertMatch(t, matches[0], 6)
}

func TestDetect_CleanGoComment_ProducesNoMatch(t *testing.T) {
	content := []byte(
		"package sample\n" +
			"\n" +
			"func Login() error {\n" +
			"\t// Auth flow is done; see receipts/auth-verify-20260101.json and tests/test_auth.py::test_login_flow.\n" +
			"\treturn nil\n" +
			"}\n",
	)

	d := detector{}
	matches := d.Detect("sample/auth.go", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0: a receipt path, a file path, and a test name are all present on the same line: %+v", len(matches), matches)
	}
}

// TestDetect_StatusWordInsideEndUserStringLiteral_IsOutOfScope proves the
// pattern's stated scope boundary: a strong status word inside an ordinary
// string literal meant for end users (not a comment or doc-string) must not
// be flagged, even with zero nearby evidence.
func TestDetect_StatusWordInsideEndUserStringLiteral_IsOutOfScope(t *testing.T) {
	content := []byte(
		"package sample\n" +
			"\n" +
			"import \"fmt\"\n" +
			"\n" +
			"func StartupBanner() {\n" +
			"\tfmt.Println(\"Startup complete and fully working, no test needed\")\n" +
			"}\n",
	)

	d := detector{}
	matches := d.Detect("sample/banner.go", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0: the claim is inside an end-user string literal, not a comment: %+v", len(matches), matches)
	}
}

// TestDetect_EvidenceWithinWindow_SuppressesMatch and its sibling below pin
// down the exact "same or adjacent 3 lines" boundary: evidence 3 lines away
// suppresses the match, evidence 4 lines away does not.
func TestDetect_EvidenceWithinWindow_SuppressesMatch(t *testing.T) {
	content := []byte(
		"// Auth flow is done and fully working.\n" +
			"\n" +
			"\n" +
			"// see tests/test_auth.py for coverage\n",
	)

	d := detector{}
	matches := d.Detect("notes.go", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0: evidence is exactly 3 lines away, inside the window: %+v", len(matches), matches)
	}
}

func TestDetect_EvidenceOutsideWindow_StillProducesMatch(t *testing.T) {
	content := []byte(
		"// Auth flow is done and fully working.\n" +
			"\n" +
			"\n" +
			"\n" +
			"// see tests/test_auth.py for coverage\n",
	)

	d := detector{}
	matches := d.Detect("notes.go", content)

	if len(matches) < 1 {
		t.Fatalf("Detect() returned %d matches, want >= 1: evidence is 4 lines away, outside the window", len(matches))
	}
	assertMatch(t, matches[0], 1)
}

func TestDetect_DirtyMarkdownProse_ProducesMatch(t *testing.T) {
	content := []byte(
		"# Status\n" +
			"\n" +
			"The ingestion pipeline is complete and finished, no more work needed.\n",
	)

	d := detector{}
	matches := d.Detect("STATUS.md", content)

	if len(matches) < 1 {
		t.Fatalf("Detect() returned %d matches, want >= 1 for bare markdown status prose with no evidence", len(matches))
	}
	assertMatch(t, matches[0], 3)
}

// TestDetect_MarkdownFencedCode_IsExcludedFromProse proves fenced code
// blocks inside a markdown file are not treated as prose: a status word
// inside a fence, with no evidence anywhere in the file, must not match.
func TestDetect_MarkdownFencedCode_IsExcludedFromProse(t *testing.T) {
	content := []byte("Some intro text.\n" +
		"\n" +
		"```\n" +
		"done and complete\n" +
		"```\n" +
		"\n" +
		"More text without evidence.\n")

	d := detector{}
	matches := d.Detect("README.md", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0: the claim is inside a fenced code block, not prose: %+v", len(matches), matches)
	}
}

func TestID_And_Category(t *testing.T) {
	d := detector{}
	if got := d.ID(); got != "claim-alive-without-receipt" {
		t.Errorf("ID() = %q, want %q", got, "claim-alive-without-receipt")
	}
	if got := d.Category(); got != "fabricated-claims" {
		t.Errorf("Category() = %q, want %q", got, "fabricated-claims")
	}
}

func TestDetect_EmptyContent_ProducesNoMatch(t *testing.T) {
	d := detector{}
	if matches := d.Detect("empty.go", nil); len(matches) != 0 {
		t.Fatalf("Detect(nil) returned %d matches, want 0", len(matches))
	}
	if matches := d.Detect("empty.go", []byte{}); len(matches) != 0 {
		t.Fatalf("Detect([]byte{}) returned %d matches, want 0", len(matches))
	}
}
