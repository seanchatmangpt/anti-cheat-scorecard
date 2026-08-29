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

package sparqlselectstarindecisionquery

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// TestDetect_SelectStar_ProducesMatch expands the task's dirty one-liner
// into a realistic multi-line decision query — the ecosystem's own
// falsifiers.rq shape, but written with a careless wildcard projection
// instead of naming the fields the downstream verifier actually reads.
func TestDetect_SelectStar_ProducesMatch(t *testing.T) {
	content := []byte(`# falsifiers.rq (careless variant)
PREFIX ex: <https://ggen-ecosystem.example/ontology#>

SELECT * WHERE {
  ?s ?p ?o .
}
`)

	d := detector{}
	matches := d.Detect("queries/falsifiers.rq", content)

	if len(matches) < 1 {
		t.Fatalf("Detect() returned %d matches, want at least 1 for a wildcard SELECT *", len(matches))
	}
	for _, m := range matches {
		if m.PatternID != "sparql-select-star-in-decision-query" {
			t.Errorf("Match.PatternID = %q, want %q", m.PatternID, "sparql-select-star-in-decision-query")
		}
		if m.Category != "semantic-web-integrity" {
			t.Errorf("Match.Category = %q, want %q", m.Category, "semantic-web-integrity")
		}
	}

	// The "SELECT * WHERE {" line is line 4 (1-based) in the fixture above.
	found := false
	for _, m := range matches {
		if m.Line == 4 {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a match anchored at line 4 (the SELECT * clause), got matches: %+v", matches)
	}
}

// TestDetect_ExplicitProjection_ProducesNoMatches proves the clean-shaped
// fixture — a real decision query that names exactly the variables a
// downstream consumer depends on — produces zero matches.
func TestDetect_ExplicitProjection_ProducesNoMatches(t *testing.T) {
	content := []byte(`# profile-closure.rq
PREFIX ex: <https://ggen-ecosystem.example/ontology#>

SELECT ?gate ?standing WHERE {
  ?gate ex:standing ?standing .
}
`)

	d := detector{}
	matches := d.Detect("queries/profile-closure.rq", content)

	if len(matches) != 0 {
		t.Errorf("Detect() returned %d matches for an explicit projection, want 0; matches: %+v", len(matches), matches)
	}
}

// TestDetect_SelectDistinctStarSplitAcrossLines_ProducesMatch covers two
// real boundaries at once: the DISTINCT solution modifier between SELECT
// and the star, and a formatter that has split SELECT and * onto separate
// lines — both must still be recognized as a wildcard projection.
func TestDetect_SelectDistinctStarSplitAcrossLines_ProducesMatch(t *testing.T) {
	content := []byte(`PREFIX ex: <https://ggen-ecosystem.example/ontology#>

SELECT
  DISTINCT
  *
WHERE {
  ?repo ex:catalogStatus ?status .
}
`)

	d := detector{}
	matches := d.Detect("queries/github-catalog-scope.rq", content)

	if len(matches) < 1 {
		t.Fatalf("Detect() returned %d matches, want at least 1 for a multi-line SELECT DISTINCT *", len(matches))
	}
	if matches[0].PatternID != "sparql-select-star-in-decision-query" {
		t.Errorf("Match.PatternID = %q, want %q", matches[0].PatternID, "sparql-select-star-in-decision-query")
	}
}

// TestDetect_CountStarAggregate_ProducesNoMatches proves the pattern does
// not misfire on a legitimate aggregate function whose argument happens to
// be the "*" token — "SELECT (COUNT(*) AS ?n)" is not a wildcard
// projection, it selects exactly one named binding, ?n.
func TestDetect_CountStarAggregate_ProducesNoMatches(t *testing.T) {
	content := []byte(`PREFIX ex: <https://ggen-ecosystem.example/ontology#>

SELECT (COUNT(*) AS ?repoCount) WHERE {
  ?repo a ex:Repository .
}
`)

	d := detector{}
	matches := d.Detect("queries/repository-matrix.rq", content)

	if len(matches) != 0 {
		t.Errorf("Detect() returned %d matches for a COUNT(*) aggregate, want 0; matches: %+v", len(matches), matches)
	}
}

// TestDetect_SelectStarInsideComment_ProducesNoMatches proves a "SELECT *"
// that appears only inside a "#" line comment — e.g. documentation warning
// against the anti-pattern — is not itself flagged as the anti-pattern: the
// pattern must reason about the real query text, not raw substring search.
func TestDetect_SelectStarInsideComment_ProducesNoMatches(t *testing.T) {
	content := []byte(`# Anti-pattern example, don't do this: SELECT * WHERE { ?s ?p ?o }
PREFIX ex: <https://ggen-ecosystem.example/ontology#>

SELECT ?gate ?standing WHERE {
  ?gate ex:standing ?standing .
}
`)

	d := detector{}
	matches := d.Detect("queries/premature-admission.rq", content)

	if len(matches) != 0 {
		t.Errorf("Detect() returned %d matches for a SELECT * appearing only in a comment, want 0; matches: %+v", len(matches), matches)
	}
}

// TestDetect_NonRqFile_IsIgnored proves the .rq file-type restriction is
// real: the exact same dirty SPARQL text embedded in a non-.rq file (e.g.
// a Markdown doc quoting the query) must never be scanned by this pattern.
func TestDetect_NonRqFile_IsIgnored(t *testing.T) {
	content := []byte("```sparql\nSELECT * WHERE { ?s ?p ?o }\n```\n")

	d := detector{}
	matches := d.Detect("docs/QUERIES.md", content)

	if len(matches) != 0 {
		t.Errorf("Detect() returned %d matches for a non-.rq file, want 0; matches: %+v", len(matches), matches)
	}
}

// TestDetector_IDAndCategory pins the two identity strings this pattern
// package must expose, independent of any Detect fixture.
func TestDetector_IDAndCategory(t *testing.T) {
	d := detector{}
	if got := d.ID(); got != "sparql-select-star-in-decision-query" {
		t.Errorf("ID() = %q, want %q", got, "sparql-select-star-in-decision-query")
	}
	if got := d.Category(); got != "semantic-web-integrity" {
		t.Errorf("Category() = %q, want %q", got, "semantic-web-integrity")
	}
}

// TestDetector_IsRegistered proves init() actually registered this pattern
// against the shared llmcheat registry under its declared ID.
func TestDetector_IsRegistered(t *testing.T) {
	found := false
	for _, p := range llmcheat.All() {
		if p.ID() == "sparql-select-star-in-decision-query" {
			found = true
			break
		}
	}
	if !found {
		t.Error("pattern \"sparql-select-star-in-decision-query\" was not found in llmcheat.All() — init() registration missing or broken")
	}
}
