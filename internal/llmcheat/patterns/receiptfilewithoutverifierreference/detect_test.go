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

package receiptfilewithoutverifierreference

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// Chicago-style throughout: every test constructs the real detector{} type
// directly and calls the real Detect on real, realistic multi-line byte
// content, then asserts on the real returned []llmcheat.Match slice. There
// is no collaborator here to fake — Detect is a pure function of its two
// arguments — so there is nothing legitimate to mock.

func assertReceiptMatch(t *testing.T, m llmcheat.Match, wantPath string) {
	t.Helper()
	if m.PatternID != patternID {
		t.Errorf("PatternID = %q, want %q", m.PatternID, patternID)
	}
	if m.Category != category {
		t.Errorf("Category = %q, want %q", m.Category, category)
	}
	if m.Path != wantPath {
		t.Errorf("Path = %q, want %q", m.Path, wantPath)
	}
	if m.Line == 0 {
		t.Error("Line = 0, want a real 1-based line number")
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

func TestDetect_ReceiptWithoutVerifierKey_ProducesMatch(t *testing.T) {
	// Expanded, realistic multi-line version of the "dirty" example from
	// the pattern spec: a status/commit claim with no declared verifier.
	content := []byte(
		"{\n" +
			"  \"status\": \"ALIVE\",\n" +
			"  \"commit\": \"abc123def4567890abc123def4567890abc123d\",\n" +
			"  \"timestamp\": \"2026-08-28T12:00:00Z\",\n" +
			"  \"notes\": \"bootstrap manufacturing receipt\"\n" +
			"}\n",
	)

	d := detector{}
	matches := d.Detect("receipts/bootstrap.json", content)

	if len(matches) < 1 {
		t.Fatalf("Detect() returned %d matches, want >= 1 for a receipt with no verifier-reference key", len(matches))
	}
	assertReceiptMatch(t, matches[0], "receipts/bootstrap.json")
	if matches[0].Line != 1 {
		t.Errorf("Line = %d, want 1 (the opening brace)", matches[0].Line)
	}
	if matches[0].Severity != llmcheat.SeverityMedium {
		t.Errorf("Severity = %q, want %q", matches[0].Severity, llmcheat.SeverityMedium)
	}
}

func TestDetect_ReceiptWithVerifierKey_ProducesNoMatch(t *testing.T) {
	// Expanded, realistic multi-line version of the "clean" example from
	// the pattern spec: the same claim, but with schema + verifier keys
	// declared, so the claim is mechanically checkable.
	content := []byte(
		"{\n" +
			"  \"status\": \"ALIVE\",\n" +
			"  \"commit\": \"abc123def4567890abc123def4567890abc123d\",\n" +
			"  \"timestamp\": \"2026-08-28T12:00:00Z\",\n" +
			"  \"schema\": \"receipt-v1\",\n" +
			"  \"verifier\": \"scripts/verify_receipt.py\"\n" +
			"}\n",
	)

	d := detector{}
	matches := d.Detect("receipts/bootstrap.json", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 for a receipt that declares a verifier key; matches: %+v", len(matches), matches)
	}
}

func TestDetect_EachRecognizedVerifierKeyAloneClears(t *testing.T) {
	// Boundary case: every one of the six recognized keys, on its own,
	// must be sufficient — not just "schema" and "verifier" together.
	for _, key := range []string{"schema", "verifier", "verified_by", "verification", "receipt_schema", "$schema"} {
		content := []byte(
			"{\n" +
				"  \"status\": \"ALIVE\",\n" +
				"  \"" + key + "\": \"present\"\n" +
				"}\n",
		)

		d := detector{}
		matches := d.Detect("receipts/single-key.json", content)

		if len(matches) != 0 {
			t.Errorf("key %q: Detect() returned %d matches, want 0; matches: %+v", key, len(matches), matches)
		}
	}
}

func TestDetect_MalformedJSONInReceiptsDir_ProducesMatch(t *testing.T) {
	// Realistic truncated/corrupted receipt: an unterminated top-level
	// object. A receipt that cannot be re-parsed cannot be re-verified
	// either, so this must flag too, at high severity.
	content := []byte(
		"{\n" +
			"  \"status\": \"ALIVE\",\n" +
			"  \"commit\": \"abc123d\",\n" +
			"  \"schema\": \"receipt-v1\"\n",
		// deliberately missing the closing brace
	)

	d := detector{}
	matches := d.Detect("receipts/corrupt.json", content)

	if len(matches) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1 for malformed JSON; matches: %+v", len(matches), matches)
	}
	assertReceiptMatch(t, matches[0], "receipts/corrupt.json")
	if matches[0].Severity != llmcheat.SeverityHigh {
		t.Errorf("Severity = %q, want %q (malformed/unverifiable receipt)", matches[0].Severity, llmcheat.SeverityHigh)
	}
}

func TestDetect_TopLevelJSONArrayInReceiptsDir_ProducesMatch(t *testing.T) {
	// Syntactically valid JSON, but the top level isn't an object, so there
	// are no top-level keys to check — treated the same as malformed.
	content := []byte(
		"[\n" +
			"  {\"status\": \"ALIVE\"},\n" +
			"  {\"status\": \"BLOCKED\"}\n" +
			"]\n",
	)

	d := detector{}
	matches := d.Detect("receipts/array-shaped.json", content)

	if len(matches) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1 for a non-object top-level JSON value; matches: %+v", len(matches), matches)
	}
	assertReceiptMatch(t, matches[0], "receipts/array-shaped.json")
}

func TestDetect_NestedReceiptsDirectory_StillMatches(t *testing.T) {
	// The pattern spec says "path contains /receipts/", which must also
	// catch a nested directory, not only a top-level receipts/ prefix.
	content := []byte("{\n  \"status\": \"ALIVE\"\n}\n")

	d := detector{}
	matches := d.Detect("docs/receipts/2026/census-closure.json", content)

	if len(matches) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1 for a nested receipts/ directory; matches: %+v", len(matches), matches)
	}
	assertReceiptMatch(t, matches[0], "docs/receipts/2026/census-closure.json")
}

func TestDetect_NonReceiptsJSONFile_ProducesNoMatch(t *testing.T) {
	// Boundary case: same "dirty"-shaped content (no verifier key at all),
	// but the path is not under a receipts/ directory — must be left alone.
	content := []byte(
		"{\n" +
			"  \"status\": \"ALIVE\",\n" +
			"  \"commit\": \"abc123\"\n" +
			"}\n",
	)

	d := detector{}
	matches := d.Detect("config/settings.json", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 for a non-receipts/ JSON path; matches: %+v", len(matches), matches)
	}
}

func TestDetect_ReceiptsDirectoryNonJSONFile_ProducesNoMatch(t *testing.T) {
	// Boundary case: right directory, wrong extension — the pattern is
	// scoped to .json files under receipts/, not every file in that dir.
	content := []byte("status: ALIVE\ncommit: abc123\n")

	d := detector{}
	matches := d.Detect("receipts/bootstrap.yaml", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 for a non-.json file under receipts/; matches: %+v", len(matches), matches)
	}
}
