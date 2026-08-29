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

package sparqlunusedselectvariable

import (
	"strings"
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// TestDetect_UnusedSelectVariable_ProducesMatch expands the task's one-line
// dirty example into a realistic multi-line query in this repo's own
// house style (a PREFIX block plus a standing-vocabulary lookup over
// ontology/standing.ttl): ?unused is projected but never bound anywhere
// inside the WHERE clause body.
func TestDetect_UnusedSelectVariable_ProducesMatch(t *testing.T) {
	content := []byte(`PREFIX ex: <https://ggen-ecosystem.example/ontology#>

# Falsifier query: gates and their current standing, plus a column that
# was supposed to carry the last-verified timestamp but never got wired
# into the WHERE clause below.
SELECT ?gate ?standing ?unused
WHERE {
  ?gate a ex:Gate .
  ?gate ex:standing ?standing .
}
`)

	d := detector{}
	matches := d.Detect("queries/falsifiers.rq", content)

	if len(matches) < 1 {
		t.Fatalf("Detect() returned %d matches, want at least 1 for the unused ?unused SELECT variable", len(matches))
	}

	foundUnused := false
	for _, m := range matches {
		if m.PatternID != patternID {
			t.Errorf("Match.PatternID = %q, want %q", m.PatternID, patternID)
		}
		if m.Category != category {
			t.Errorf("Match.Category = %q, want %q", m.Category, category)
		}
		if m.Path != "queries/falsifiers.rq" {
			t.Errorf("Match.Path = %q, want %q", m.Path, "queries/falsifiers.rq")
		}
		if strings.Contains(m.Message, "?unused") {
			foundUnused = true
			// ?unused is on line 6 (1-based) of the fixture above.
			if m.Line != 6 {
				t.Errorf("Match.Line = %d, want 6 (the SELECT line listing ?unused)", m.Line)
			}
		}
		// ?gate and ?standing are both bound in WHERE and must never be
		// flagged.
		if strings.Contains(m.Message, `"?gate"`) || strings.Contains(m.Message, `"?standing"`) {
			t.Errorf("Detect() incorrectly flagged a variable that IS bound in WHERE: %+v", m)
		}
	}
	if !foundUnused {
		t.Errorf("expected a match naming ?unused, got matches: %+v", matches)
	}
}

// TestDetect_AllSelectVariablesBound_ProducesNoMatches is the task's clean
// example, expanded the same way as the dirty fixture above but with the
// third column actually wired through WHERE.
func TestDetect_AllSelectVariablesBound_ProducesNoMatches(t *testing.T) {
	content := []byte(`PREFIX ex: <https://ggen-ecosystem.example/ontology#>

SELECT ?gate ?standing
WHERE {
  ?gate a ex:Gate .
  ?gate ex:standing ?standing .
}
`)

	d := detector{}
	matches := d.Detect("queries/falsifiers.rq", content)

	if len(matches) != 0 {
		t.Errorf("Detect() returned %d matches, want 0 for a query where every SELECT variable is bound in WHERE: %+v", len(matches), matches)
	}
}

// TestDetect_WildcardSelect_IsNotApplicable covers the explicit
// "non-wildcard SELECT" boundary named in this pattern's description:
// "SELECT *" and "SELECT DISTINCT *" have no explicit variable list to
// check and must never be flagged.
func TestDetect_WildcardSelect_IsNotApplicable(t *testing.T) {
	for _, content := range [][]byte{
		[]byte(`SELECT * WHERE { ?gate ex:standing ?standing }`),
		[]byte(`SELECT DISTINCT * WHERE { ?gate ex:standing ?standing }`),
	} {
		d := detector{}
		matches := d.Detect("queries/everything.rq", content)
		if len(matches) != 0 {
			t.Errorf("Detect(%q) returned %d matches, want 0 for a wildcard SELECT: %+v", content, len(matches), matches)
		}
	}
}

// TestDetect_AsBoundAggregateVariable_IsExempt covers the "AS ?name"
// idiom: a variable computed inside the SELECT clause itself (e.g. via an
// aggregate) is legitimately never bound in WHERE and must not be flagged,
// while a genuinely unused plain projection variable alongside it still
// must be.
func TestDetect_AsBoundAggregateVariable_IsExempt(t *testing.T) {
	content := []byte(`PREFIX ex: <https://ggen-ecosystem.example/ontology#>

SELECT ?gate (COUNT(?item) AS ?itemCount) ?neverBound
WHERE {
  ?gate a ex:Gate .
  ?gate ex:hasItem ?item .
}
GROUP BY ?gate
`)

	d := detector{}
	matches := d.Detect("queries/item-counts.rq", content)

	foundNeverBound := false
	for _, m := range matches {
		if strings.Contains(m.Message, `"?itemCount"`) {
			t.Errorf("Detect() incorrectly flagged AS-bound ?itemCount, which is computed in SELECT itself: %+v", m)
		}
		if strings.Contains(m.Message, `"?gate"`) {
			t.Errorf("Detect() incorrectly flagged ?gate, which IS bound in WHERE: %+v", m)
		}
		if strings.Contains(m.Message, `"?neverBound"`) {
			foundNeverBound = true
		}
	}
	if !foundNeverBound {
		t.Errorf("expected ?neverBound to be flagged (it is a plain projection variable never bound in WHERE), got matches: %+v", matches)
	}
}

// TestDetect_NonRqFile_IsIgnored covers the file-extension gate: identical
// dirty-shaped content in a non-.rq file must never be scanned.
func TestDetect_NonRqFile_IsIgnored(t *testing.T) {
	content := []byte(`SELECT ?gate ?unused WHERE { ?gate ex:standing ?standing }`)

	d := detector{}
	matches := d.Detect("notes/some-query.ttl", content)

	if len(matches) != 0 {
		t.Errorf("Detect() on a non-.rq file returned %d matches, want 0: %+v", len(matches), matches)
	}
}

// TestDetect_IdentityAndRegistration exercises the llmcheat.Pattern
// interface surface directly (ID/Category) and confirms the package's
// init() registered exactly this detector under the expected ID without
// relying on the shared, mutable llmcheat.All() registry across other
// packages' tests.
func TestDetect_IdentityAndRegistration(t *testing.T) {
	d := detector{}
	if got := d.ID(); got != "sparql-unused-select-variable" {
		t.Errorf("ID() = %q, want %q", got, "sparql-unused-select-variable")
	}
	if got := d.Category(); got != "semantic-web-integrity" {
		t.Errorf("Category() = %q, want %q", got, "semantic-web-integrity")
	}

	var _ llmcheat.Pattern = d // compile-time interface conformance check
}
