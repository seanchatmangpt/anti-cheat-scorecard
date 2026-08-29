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

package ttlprefixdeclaredunused

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

func TestIDAndCategory(t *testing.T) {
	d := &detector{}
	if got, want := d.ID(), "ttl-prefix-declared-unused"; got != want {
		t.Errorf("ID() = %q, want %q", got, want)
	}
	if got, want := d.Category(), "semantic-web-integrity"; got != want {
		t.Errorf("Category() = %q, want %q", got, want)
	}
}

// TestDirty_UnusedPrefixesInCopyPastedHeader expands the spec's one-line
// dirty example into a realistic ontology header of the kind that gets
// copy-pasted wholesale between .ttl files (rdf/rdfs/owl/xsd/dc/skos), where
// only some of the declared prefixes are actually referenced by the real
// triples below. rdfs, owl, xsd and ex are all genuinely used (including
// rdfs:label, which must NOT be mistaken for a use of the shorter "rdf"
// prefix — proving the match is anchored, not a substring probe); rdf, dc
// and skos are declared and never touched again.
func TestDirty_UnusedPrefixesInCopyPastedHeader(t *testing.T) {
	src := `@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix dc: <http://purl.org/dc/elements/1.1/> .
@prefix skos: <http://www.w3.org/2004/02/skos/core#> .
@prefix ex: <http://example.org/ontology#> .

ex:Widget a owl:Class ;
    rdfs:label "Widget"^^xsd:string ;
    rdfs:comment "A manufactured widget." .

ex:hasColor a owl:DatatypeProperty ;
    rdfs:domain ex:Widget ;
    rdfs:range xsd:string .
`
	d := &detector{}
	matches := d.Detect("ontology/widget.ttl", []byte(src))

	wantLines := map[uint]bool{1: true, 5: true, 6: true}
	if len(matches) != len(wantLines) {
		gotLines := make([]uint, len(matches))
		for i, m := range matches {
			gotLines[i] = m.Line
		}
		t.Fatalf("Detect() returned %d matches, want %d\ngot lines: %v\nwant lines: %v",
			len(matches), len(wantLines), gotLines, wantLines)
	}
	for _, m := range matches {
		if m.PatternID != "ttl-prefix-declared-unused" {
			t.Errorf("match at line %d: PatternID = %q, want %q", m.Line, m.PatternID, "ttl-prefix-declared-unused")
		}
		if m.Category != "semantic-web-integrity" {
			t.Errorf("match at line %d: Category = %q, want %q", m.Line, m.Category, "semantic-web-integrity")
		}
		if m.Path != "ontology/widget.ttl" {
			t.Errorf("match at line %d: Path = %q, want %q", m.Line, m.Path, "ontology/widget.ttl")
		}
		if m.Severity != llmcheat.SeverityLow {
			t.Errorf("match at line %d: Severity = %q, want %q", m.Line, m.Severity, llmcheat.SeverityLow)
		}
		if !wantLines[m.Line] {
			t.Errorf("unexpected match at line %d: %+v", m.Line, m)
		}
		if m.Message == "" {
			t.Errorf("match at line %d has empty Message", m.Line)
		}
	}
}

// TestClean_EveryDeclaredPrefixIsUsed is the same header shape but trimmed
// to exactly the prefixes the triples below actually reference — the
// expanded, realistic form of the spec's one-line clean example. It must
// produce zero matches.
func TestClean_EveryDeclaredPrefixIsUsed(t *testing.T) {
	src := `@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix owl: <http://www.w3.org/2002/07/owl#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix ex: <http://example.org/ontology#> .

ex:Widget a owl:Class ;
    rdf:type rdfs:Class ;
    rdfs:label "Widget"^^xsd:string ;
    rdfs:comment "A manufactured widget." .
`
	d := &detector{}
	matches := d.Detect("ontology/widget.ttl", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0\nsource:\n%s\nmatches: %+v", len(matches), src, matches)
	}
}

// TestDirty_SubstringPrefixIsNotFalselyUsed proves a declared short prefix
// "ex" is not considered used merely because the unrelated, longer word
// "example" appears in the file's prose (inside a string literal comment,
// no less) — the "example" substring must not satisfy "ex:"'s usage check.
func TestDirty_SubstringPrefixIsNotFalselyUsed(t *testing.T) {
	src := `@prefix ex: <http://example.org/> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .

rdfs:label "See the example documentation for more info." .
`
	d := &detector{}
	matches := d.Detect("notes.ttl", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() returned %d matches, want 1\nmatches: %+v", len(matches), matches)
	}
	if matches[0].Line != 1 {
		t.Errorf("Line = %d, want 1 (the \"ex\" declaration)", matches[0].Line)
	}
}

// TestDirty_MentionInsideCommentDoesNotCountAsUse proves a prefix name that
// appears only inside a "#" comment (never as a real triple) is still
// flagged as unused — comment text must not count as a use.
func TestDirty_MentionInsideCommentDoesNotCountAsUse(t *testing.T) {
	src := `@prefix ex: <http://example.org/> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .

# NOTE: legacy triples referenced ex:OldClass here before the rewrite.
rdf:Property a rdfs:Class .
`
	d := &detector{}
	matches := d.Detect("legacy.ttl", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() returned %d matches, want 1\nmatches: %+v", len(matches), matches)
	}
	if matches[0].Line != 1 {
		t.Errorf("Line = %d, want 1 (the \"ex\" declaration)", matches[0].Line)
	}
}

// TestClean_NonTtlExtensionIgnored ensures the .ttl extension gate applies
// even when the content is byte-for-byte the dirty fixture.
func TestClean_NonTtlExtensionIgnored(t *testing.T) {
	src := "@prefix unused: <http://example.org/unused#> .\nex:x a ex:Y .\n"

	d := &detector{}
	matches := d.Detect("notes.md", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() on a non-.ttl path returned %d matches, want 0\nmatches: %+v", len(matches), matches)
	}
}

// TestDirty_DefaultPrefixUnused covers the boundary case of the default
// (unnamed) prefix, "@prefix : <iri> .": its short name is the empty
// string, and this must still be tracked and flagged like any named prefix
// when no bare ":localname" reference ever follows it.
func TestDirty_DefaultPrefixUnused(t *testing.T) {
	src := `@prefix : <http://example.org/base#> .
@prefix ex: <http://example.org/> .

ex:Thing a ex:Class .
`
	d := &detector{}
	matches := d.Detect("base.ttl", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() returned %d matches, want 1\nmatches: %+v", len(matches), matches)
	}
	if matches[0].Line != 1 {
		t.Errorf("Line = %d, want 1 (the default \":\" declaration)", matches[0].Line)
	}
	if matches[0].Message == "" {
		t.Errorf("match has empty Message")
	}
}

// TestClean_DefaultPrefixUsedViaBareLocalName is the companion clean case:
// the default prefix is referenced via a bare ":Thing" local name, so it
// must not be flagged.
func TestClean_DefaultPrefixUsedViaBareLocalName(t *testing.T) {
	src := `@prefix : <http://example.org/base#> .
@prefix ex: <http://example.org/> .

:Thing a ex:Class .
`
	d := &detector{}
	matches := d.Detect("base.ttl", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0\nsource:\n%s\nmatches: %+v", len(matches), src, matches)
	}
}

// TestDirty_RegisteredInGlobalRegistry is a real, non-mocked integration
// check: verify this package's init() actually registered a Pattern into
// the shared llmcheat registry (not just that the local *detector value
// behaves correctly in isolation).
func TestDirty_RegisteredInGlobalRegistry(t *testing.T) {
	found := false
	for _, p := range llmcheat.All() {
		if p.ID() == "ttl-prefix-declared-unused" {
			found = true
			if p.Category() != "semantic-web-integrity" {
				t.Errorf("registered pattern Category() = %q, want %q", p.Category(), "semantic-web-integrity")
			}
		}
	}
	if !found {
		t.Fatal("ttl-prefix-declared-unused was not found in llmcheat.All() after package init()")
	}
}
