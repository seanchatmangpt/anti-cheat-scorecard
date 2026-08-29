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

package ttlclaimtriplewithoutreceipt

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

// TestDetect_DirtyGateStanding_ProducesMatch expands the one-line dirty
// example from the pattern spec into a realistic gate-status graph fragment
// with no evidence/receipt predicate anywhere in the file.
func TestDetect_DirtyGateStanding_ProducesMatch(t *testing.T) {
	content := []byte(
		"@prefix ex: <https://example.org/ecosystem#> .\n" +
			"@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\n" +
			"\n" +
			"ex:gate9 a ex:Gate ;\n" +
			"    rdfs:label \"Release readiness gate\" .\n" +
			"\n" +
			"ex:gate9 ex:standing \"ALIVE\" .\n",
	)

	d := detector{}
	matches := d.Detect("ontology/standing.ttl", content)

	if len(matches) < 1 {
		t.Fatalf("Detect() returned %d matches, want >= 1 for a bare ALIVE standing claim with zero evidence in the file", len(matches))
	}
	// Line 7 is `ex:gate9 ex:standing "ALIVE" .`
	assertMatch(t, matches[0], 7)
	if matches[0].Severity != llmcheat.SeverityHigh {
		t.Errorf("Severity = %q, want %q for an exact ALIVE claim", matches[0].Severity, llmcheat.SeverityHigh)
	}
}

// TestDetect_CleanGateStandingWithEvidence_ProducesNoMatch expands the
// one-line clean example: the same strong claim triple, but the file also
// carries an ex:evidence predicate pointing at a receipt path, which gates
// out every match in the file.
func TestDetect_CleanGateStandingWithEvidence_ProducesNoMatch(t *testing.T) {
	content := []byte(
		"@prefix ex: <https://example.org/ecosystem#> .\n" +
			"\n" +
			"ex:gate9 ex:standing \"ALIVE\" ;\n" +
			"  ex:evidence <receipts/gate9-20260101.json> .\n",
	)

	d := detector{}
	matches := d.Detect("ontology/standing.ttl", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0: the file carries an ex:evidence/receipt reference: %+v", len(matches), matches)
	}
}

// TestDetect_ReceiptMentionedElsewhereInFile_GatesTheWholeFile proves the
// evidence gate is file-wide, not line-local: a "receipt" mention on a
// completely unrelated line still suppresses a standing claim match
// elsewhere in the same file.
func TestDetect_ReceiptMentionedElsewhereInFile_GatesTheWholeFile(t *testing.T) {
	content := []byte(
		"@prefix ex: <https://example.org/ecosystem#> .\n" +
			"\n" +
			"# See the receipts/ directory for the full audit trail.\n" +
			"\n" +
			"ex:gate9 ex:standing \"ALIVE\" .\n",
	)

	d := detector{}
	matches := d.Detect("ontology/standing.ttl", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0: \"receipts\" appears elsewhere in the file: %+v", len(matches), matches)
	}
}

// TestDetect_NonTTLFile_IsOutOfScope proves the pattern only ever runs on
// .ttl files: identical dirty triple content in a .md file must not match.
func TestDetect_NonTTLFile_IsOutOfScope(t *testing.T) {
	content := []byte("ex:gate9 ex:standing \"ALIVE\" .\n")

	d := detector{}
	matches := d.Detect("notes/standing.md", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0: path is not a .ttl file: %+v", len(matches), matches)
	}
}

// TestDetect_UnrelatedPredicateWithClaimShapedValue_IsOutOfScope proves the
// value alone is not enough: a predicate that does not itself look like a
// standing/status assertion (no "standing"/"status"/":alive"/":verified"/
// ":done" substring) must not be flagged even though its object literal is
// spelled exactly like a strong claim value.
func TestDetect_UnrelatedPredicateWithClaimShapedValue_IsOutOfScope(t *testing.T) {
	content := []byte(
		"@prefix ex: <https://example.org/ecosystem#> .\n" +
			"\n" +
			"ex:gate9 ex:codename \"ALIVE\" .\n",
	)

	d := detector{}
	matches := d.Detect("ontology/standing.ttl", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0: predicate ex:codename does not look like a standing assertion: %+v", len(matches), matches)
	}
}

// TestDetect_StandingPredicateWithNonStrongValue_IsOutOfScope proves the
// predicate alone is not enough either: a standing-shaped predicate whose
// object is not one of the five strong-claim values must not be flagged.
func TestDetect_StandingPredicateWithNonStrongValue_IsOutOfScope(t *testing.T) {
	content := []byte(
		"@prefix ex: <https://example.org/ecosystem#> .\n" +
			"\n" +
			"ex:gate9 ex:status \"in-progress\" .\n",
	)

	d := detector{}
	matches := d.Detect("ontology/standing.ttl", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0: object \"in-progress\" is not a strong-claim value: %+v", len(matches), matches)
	}
}

// TestDetect_BareBooleanVerified_ProducesMatch proves the pattern also
// catches Turtle's bare (unquoted) xsd:boolean literal shorthand, not just
// quoted string literals.
func TestDetect_BareBooleanVerified_ProducesMatch(t *testing.T) {
	content := []byte(
		"@prefix ex: <https://example.org/ecosystem#> .\n" +
			"\n" +
			"ex:gate9 ex:verified true .\n",
	)

	d := detector{}
	matches := d.Detect("ontology/standing.ttl", content)

	if len(matches) < 1 {
		t.Fatalf("Detect() returned %d matches, want >= 1 for a bare `ex:verified true` claim with zero evidence in the file", len(matches))
	}
	assertMatch(t, matches[0], 3)
	if matches[0].Severity != llmcheat.SeverityMedium {
		t.Errorf("Severity = %q, want %q for a non-ALIVE strong claim", matches[0].Severity, llmcheat.SeverityMedium)
	}
}

// TestDetect_MultipleDirtyTriples_ProducesOneMatchPerTriple proves multiple
// independent standing claims in one evidence-free file each produce their
// own match at their own line.
func TestDetect_MultipleDirtyTriples_ProducesOneMatchPerTriple(t *testing.T) {
	content := []byte(
		"@prefix ex: <https://example.org/ecosystem#> .\n" +
			"\n" +
			"ex:gate9 ex:standing \"ALIVE\" .\n" +
			"ex:gate10 ex:standing \"done\" .\n",
	)

	d := detector{}
	matches := d.Detect("ontology/standing.ttl", content)

	if len(matches) != 2 {
		t.Fatalf("Detect() returned %d matches, want 2: %+v", len(matches), matches)
	}
	assertMatch(t, matches[0], 3)
	assertMatch(t, matches[1], 4)
}

func TestID_And_Category(t *testing.T) {
	d := detector{}
	if got := d.ID(); got != "ttl-claim-triple-without-receipt" {
		t.Errorf("ID() = %q, want %q", got, "ttl-claim-triple-without-receipt")
	}
	if got := d.Category(); got != "semantic-web-integrity" {
		t.Errorf("Category() = %q, want %q", got, "semantic-web-integrity")
	}
}

func TestDetect_EmptyContent_ProducesNoMatch(t *testing.T) {
	d := detector{}
	if matches := d.Detect("empty.ttl", nil); len(matches) != 0 {
		t.Fatalf("Detect(nil) returned %d matches, want 0", len(matches))
	}
	if matches := d.Detect("empty.ttl", []byte{}); len(matches) != 0 {
		t.Fatalf("Detect([]byte{}) returned %d matches, want 0", len(matches))
	}
}
