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

package rdfblanknodestatusclaim

import (
	"strings"
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

// TestDetect_AnonymousBlankNode_ProducesMatch expands the task's dirty
// one-liner ("[ ex:standing \"ALIVE\" ] .") into a realistic multi-triple
// .ttl fixture and confirms it is caught.
func TestDetect_AnonymousBlankNode_ProducesMatch(t *testing.T) {
	content := []byte(
		"@prefix ex: <https://example.org/ecosystem#> .\n" + // line 1
			"\n" + // line 2
			"ex:gate9 ex:label \"gate nine\" .\n" + // line 3
			"\n" + // line 4
			"[ ex:standing \"ALIVE\" ] .\n" + // line 5 - dirty: bare anon blank node
			"\n" + // line 6
			"ex:gate10 ex:label \"gate ten\" .\n", // line 7
	)

	d := detector{}
	matches := d.Detect("ontology/standing.ttl", content)

	if len(matches) != 1 {
		t.Fatalf("len(matches) = %d, want 1; matches = %+v", len(matches), matches)
	}
	assertMatch(t, matches[0], 5)
	if !strings.Contains(matches[0].Message, "anonymous") {
		t.Errorf("Message = %q, want it to mention the anonymous blank node", matches[0].Message)
	}
}

// TestDetect_NamedSubjectStatusClaim_ProducesZeroMatches is the task's clean
// one-liner ("ex:gate9 ex:standing \"ALIVE\" .") expanded into a realistic
// multi-triple fixture: a real, referenceable IRI subject making the exact
// same status claim must never be flagged — only the blank-node subject
// shape is the defect.
func TestDetect_NamedSubjectStatusClaim_ProducesZeroMatches(t *testing.T) {
	content := []byte(
		"@prefix ex: <https://example.org/ecosystem#> .\n" +
			"\n" +
			"ex:gate9 ex:standing \"ALIVE\" ;\n" +
			"    ex:verifiedBy \"receipt-2026-08-27\" ;\n" +
			"    ex:label \"gate nine\" .\n",
	)

	d := detector{}
	matches := d.Detect("ontology/standing.ttl", content)

	if len(matches) != 0 {
		t.Fatalf("len(matches) = %d, want 0; matches = %+v", len(matches), matches)
	}
}

// TestDetect_NamedBlankNodeSubject_ProducesMatch covers the other blank-node
// shape the pattern description names: a labelled blank node ("_:label")
// used directly as a statement's subject, not just an anonymous "[ ... ]".
func TestDetect_NamedBlankNodeSubject_ProducesMatch(t *testing.T) {
	content := []byte(
		"@prefix ex: <https://example.org/ecosystem#> .\n" + // line 1
			"\n" + // line 2
			"_:b1 ex:standing \"ALIVE\" ;\n" + // line 3
			"    ex:date \"2026-08-27\" .\n", // line 4
	)

	d := detector{}
	matches := d.Detect("ontology/standing.ttl", content)

	if len(matches) != 1 {
		t.Fatalf("len(matches) = %d, want 1; matches = %+v", len(matches), matches)
	}
	assertMatch(t, matches[0], 3)
	if !strings.Contains(matches[0].Message, "_:b1") {
		t.Errorf("Message = %q, want it to name the blank node label _:b1", matches[0].Message)
	}
}

// TestDetect_NestedBlankNodeObject_ProducesMatch covers the case the
// package doc calls out explicitly: a "[ ... ]" property list nested as the
// OBJECT of a perfectly good, real-IRI subject. The outer statement's
// subject (ex:gate9) is fine, but the nested anonymous blank node is itself
// the real RDF subject of the two triples written inside the brackets, so
// both of its status-shaped predicates must be flagged.
func TestDetect_NestedBlankNodeObject_ProducesMatch(t *testing.T) {
	content := []byte(
		"@prefix ex: <https://example.org/ecosystem#> .\n" + // line 1
			"\n" + // line 2
			"ex:gate9 ex:hasReport [\n" + // line 3
			"    ex:standing \"ALIVE\" ;\n" + // line 4
			"    ex:verifiedBy \"human\"\n" + // line 5
			"] .\n", // line 6
	)

	d := detector{}
	matches := d.Detect("ontology/standing.ttl", content)

	if len(matches) != 2 {
		t.Fatalf("len(matches) = %d, want 2; matches = %+v", len(matches), matches)
	}
	assertMatch(t, matches[0], 4)
	assertMatch(t, matches[1], 5)
}

// TestDetect_BlankNodeWithoutStatusPredicate_ProducesZeroMatches is the
// boundary the pattern description implies: a blank node subject is not
// itself a defect — plenty of legitimate Turtle uses them for ordinary
// structural data. Only a STATUS-shaped predicate on that blank node is the
// defect, so an unrelated predicate must not be flagged.
func TestDetect_BlankNodeWithoutStatusPredicate_ProducesZeroMatches(t *testing.T) {
	content := []byte(
		"@prefix ex: <https://example.org/ecosystem#> .\n" +
			"\n" +
			"_:b2 ex:name \"Anonymous Contributor\" ;\n" +
			"    ex:role \"reviewer\" .\n" +
			"\n" +
			"ex:gate11 ex:hasNote [ ex:text \"nothing to see here\" ] .\n",
	)

	d := detector{}
	matches := d.Detect("ontology/standing.ttl", content)

	if len(matches) != 0 {
		t.Fatalf("len(matches) = %d, want 0; matches = %+v", len(matches), matches)
	}
}

// TestDetect_StatusWordOnlyInsideCommentOrLiteral_ProducesZeroMatches
// guards against two easy false-positive traps: the status keyword
// appearing in a "#" comment (not real triple structure at all) and the
// status keyword appearing inside an OBJECT's quoted string value (not the
// predicate) on an otherwise ordinary, real-IRI-subject triple.
func TestDetect_StatusWordOnlyInsideCommentOrLiteral_ProducesZeroMatches(t *testing.T) {
	content := []byte(
		"@prefix ex: <https://example.org/ecosystem#> .\n" +
			"\n" +
			"# ex:standing claims should never live in comments: _:b3 ex:alive \"x\" .\n" +
			"ex:gate12 ex:hasNote \"manually verified status, see receipt\" .\n",
	)

	d := detector{}
	matches := d.Detect("ontology/standing.ttl", content)

	if len(matches) != 0 {
		t.Fatalf("len(matches) = %d, want 0; matches = %+v", len(matches), matches)
	}
}

// TestDetect_NonTurtleFile_ProducesZeroMatches confirms the .ttl-only file
// gate: the exact dirty fixture in a .md file must not be scanned at all.
func TestDetect_NonTurtleFile_ProducesZeroMatches(t *testing.T) {
	content := []byte("[ ex:standing \"ALIVE\" ] .\n")

	d := detector{}
	matches := d.Detect("docs/notes.md", content)

	if len(matches) != 0 {
		t.Fatalf("len(matches) = %d, want 0 for a non-.ttl path; matches = %+v", len(matches), matches)
	}
}

// TestDetect_EmptyContent_ProducesZeroMatches confirms empty input degrades
// gracefully rather than panicking or misbehaving on out-of-range indices.
func TestDetect_EmptyContent_ProducesZeroMatches(t *testing.T) {
	d := detector{}
	if matches := d.Detect("ontology/empty.ttl", []byte{}); len(matches) != 0 {
		t.Fatalf("len(matches) = %d, want 0 for empty content; matches = %+v", len(matches), matches)
	}
}

func TestDetector_IDAndCategory(t *testing.T) {
	d := detector{}
	if got := d.ID(); got != "rdf-blank-node-status-claim" {
		t.Errorf("ID() = %q, want %q", got, "rdf-blank-node-status-claim")
	}
	if got := d.Category(); got != "semantic-web-integrity" {
		t.Errorf("Category() = %q, want %q", got, "semantic-web-integrity")
	}
}
