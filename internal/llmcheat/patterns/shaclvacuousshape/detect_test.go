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

package shaclvacuousshape

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// dirtyShapesFile is a realistic expansion of the spec's one-line dirty
// example: an admission shapes file (modeled on ggen-ecosystem's own
// admission/shapes.ttl) with two shapes, both declaring a target and
// neither declaring any real constraint predicate — they read like
// governance but validate every node in their target unconditionally.
const dirtyShapesFile = `@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix ex: <http://example.org/ecosystem#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

ex:GateShape a sh:NodeShape ;
  sh:targetClass ex:Gate .

ex:RepositoryShape a sh:NodeShape ;
  sh:targetClass ex:Repository ;
  sh:closed false .
`

// cleanShapesFile is a realistic expansion of the spec's one-line clean
// example: both shapes target a class *and* declare real constraints, so
// neither should be flagged.
const cleanShapesFile = `@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix ex: <http://example.org/ecosystem#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .

ex:GateShape a sh:NodeShape ;
  sh:targetClass ex:Gate ;
  sh:property [
    sh:path ex:standing ;
    sh:minCount 1 ;
    sh:in ("ALIVE" "BLOCKED" "UNKNOWN")
  ] .

ex:RepositoryShape a sh:NodeShape ;
  sh:targetClass ex:Repository ;
  sh:property [
    sh:path ex:name ;
    sh:datatype xsd:string ;
    sh:minLength 1 ;
    sh:maxLength 200
  ] .
`

func TestDetect_DirtyFixture_ProducesMatchesWithCorrectIdentity(t *testing.T) {
	d := &detector{}

	got := d.Detect("admission/shapes.ttl", []byte(dirtyShapesFile))

	if len(got) < 2 {
		t.Fatalf("Detect() on dirty fixture returned %d matches, want >= 2 (one per vacuous shape); got=%#v", len(got), got)
	}

	for _, m := range got {
		if m.PatternID != patternID {
			t.Errorf("Match.PatternID = %q, want %q", m.PatternID, patternID)
		}
		if m.Category != category {
			t.Errorf("Match.Category = %q, want %q", m.Category, category)
		}
		if m.Path != "admission/shapes.ttl" {
			t.Errorf("Match.Path = %q, want %q", m.Path, "admission/shapes.ttl")
		}
		if m.Line == 0 {
			t.Errorf("Match.Line = 0, want a real 1-based line number")
		}
	}

	// GateShape's "a sh:NodeShape" declaration starts on line 5.
	if got[0].Line != 5 {
		t.Errorf("first match Line = %d, want 5 (GateShape's shape declaration)", got[0].Line)
	}
	// RepositoryShape's "a sh:NodeShape" declaration starts on line 8.
	if got[1].Line != 8 {
		t.Errorf("second match Line = %d, want 8 (RepositoryShape's shape declaration)", got[1].Line)
	}
}

func TestDetect_CleanFixture_ProducesZeroMatches(t *testing.T) {
	d := &detector{}

	got := d.Detect("admission/shapes.ttl", []byte(cleanShapesFile))

	if len(got) != 0 {
		t.Fatalf("Detect() on clean fixture returned %d matches, want 0; got=%#v", len(got), got)
	}
}

func TestDetect_ShapeWithoutTarget_IsNotVacuous(t *testing.T) {
	// A shape with no sh:targetClass/sh:targetNode at all is out of this
	// pattern's scope (it may be an abstract shape referenced only via
	// sh:node from elsewhere) — it must never be flagged just because it
	// also lacks constraint predicates.
	const noTargetShape = `@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix ex: <http://example.org/ecosystem#> .

ex:AbstractFragment a sh:NodeShape ;
  sh:description "reused only via sh:node from other shapes" .
`
	d := &detector{}

	got := d.Detect("admission/shapes.ttl", []byte(noTargetShape))

	if len(got) != 0 {
		t.Fatalf("Detect() on target-less shape returned %d matches, want 0; got=%#v", len(got), got)
	}
}

func TestDetect_PropertyShape_TargetNodeWithHasValue_IsClean(t *testing.T) {
	// Exercises sh:PropertyShape (not just sh:NodeShape), sh:targetNode
	// (not just sh:targetClass), and sh:hasValue as the real constraint —
	// all three named in the spec but not covered by the two headline
	// fixtures above.
	const shape = `@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix ex: <http://example.org/ecosystem#> .

ex:RootStandingShape a sh:PropertyShape ;
  sh:targetNode ex:Root ;
  sh:path ex:standing ;
  sh:hasValue "ALIVE" .
`
	d := &detector{}

	got := d.Detect("ontology/standing.ttl", []byte(shape))

	if len(got) != 0 {
		t.Fatalf("Detect() on sh:hasValue-constrained PropertyShape returned %d matches, want 0; got=%#v", len(got), got)
	}
}

func TestDetect_NonTurtleFile_IsOutOfScope(t *testing.T) {
	// The same vacuous-shape text in a file extension this pattern does
	// not claim (e.g. a .md doc quoting the shape as an example) must never
	// be flagged — the pattern is explicitly scoped to .ttl/.shacl files.
	d := &detector{}

	got := d.Detect("docs/ADMISSION.md", []byte(dirtyShapesFile))

	if len(got) != 0 {
		t.Fatalf("Detect() on non-Turtle file returned %d matches, want 0; got=%#v", len(got), got)
	}
}

func TestDetect_ShaclExtension_IsAlsoInScope(t *testing.T) {
	d := &detector{}

	got := d.Detect("admission/shapes.shacl", []byte(dirtyShapesFile))

	if len(got) < 2 {
		t.Fatalf("Detect() on .shacl file returned %d matches, want >= 2", len(got))
	}
}

func TestDetect_FileWithNoShapes_ProducesZeroMatches(t *testing.T) {
	const noShapesFile = `@prefix ex: <http://example.org/ecosystem#> .

ex:Gate ex:standing "ALIVE" .
`
	d := &detector{}

	got := d.Detect("ontology/standing.ttl", []byte(noShapesFile))

	if len(got) != 0 {
		t.Fatalf("Detect() on shape-free file returned %d matches, want 0; got=%#v", len(got), got)
	}
}

func TestPattern_IdentityMethods(t *testing.T) {
	d := &detector{}

	if got := d.ID(); got != "shacl-vacuous-shape" {
		t.Errorf("ID() = %q, want %q", got, "shacl-vacuous-shape")
	}
	if got := d.Category(); got != "semantic-web-integrity" {
		t.Errorf("Category() = %q, want %q", got, "semantic-web-integrity")
	}

	// Compile-time + runtime check that detector really implements
	// llmcheat.Pattern (the interface this whole package exists to satisfy).
	var _ llmcheat.Pattern = d
}
