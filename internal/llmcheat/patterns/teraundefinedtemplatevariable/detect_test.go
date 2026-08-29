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

package teraundefinedtemplatevariable

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// TestDetect_UndefinedVariables_ProduceMatches expands the task's one-line
// dirty example ("Hello {{ mystery_var }}") into a realistic multi-line
// report template: it defines "title" via {% set %} and uses several
// allowlisted builtins/context variables correctly, but references two
// variables ("repo_name" and "mystery_var") that nothing in the file ever
// defines.
func TestDetect_UndefinedVariables_ProduceMatches(t *testing.T) {
	content := []byte(`{% set title = "Repository Manufacturing Report" %}
<h1>{{ title }}</h1>
<p>Generated for {{ repo_name }} on {{ now() }}.</p>
<ul>
{% for row in sparql_results.rows %}
  <li>{{ row.subject }} -&gt; {{ row.predicate }}</li>
{% endfor %}
</ul>
<footer>Rendered by {{ mystery_var }}</footer>
`)

	d := detector{}
	matches := d.Detect("templates/repository-report.tera", content)

	if len(matches) < 1 {
		t.Fatalf("Detect() returned %d matches, want at least 1 for undefined template variables", len(matches))
	}
	for _, m := range matches {
		if m.PatternID != "tera-undefined-template-variable" {
			t.Errorf("Match.PatternID = %q, want %q", m.PatternID, "tera-undefined-template-variable")
		}
		if m.Category != "generated-artifact-tampering" {
			t.Errorf("Match.Category = %q, want %q", m.Category, "generated-artifact-tampering")
		}
	}

	// Both undefined variables must be individually named in some match's
	// Message, and neither "title" (set-defined) nor any allowlisted
	// builtin/context variable (now, row, sparql_results) may appear as a
	// flagged name.
	wantFlagged := map[string]bool{"repo_name": true, "mystery_var": true}
	gotFlagged := map[string]bool{}
	for _, m := range matches {
		for name := range wantFlagged {
			if containsSubstring(m.Message, `"`+name+`"`) {
				gotFlagged[name] = true
			}
		}
		for _, mustNotFlag := range []string{`"title"`, `"now"`, `"row"`, `"sparql_results"`} {
			if containsSubstring(m.Message, mustNotFlag) {
				t.Errorf("Detect() flagged %s, which should never be reported (set-defined or allowlisted): %+v", mustNotFlag, m)
			}
		}
	}
	for name, want := range wantFlagged {
		if want && !gotFlagged[name] {
			t.Errorf("expected some match to flag undefined variable %q, got matches: %+v", name, matches)
		}
	}

	// "mystery_var" is on the last line of the fixture (line 9, 1-based).
	foundOnLine9 := false
	for _, m := range matches {
		if m.Line == 9 {
			foundOnLine9 = true
		}
	}
	if !foundOnLine9 {
		t.Errorf("expected a match anchored at line 9 (the mystery_var reference), got matches: %+v", matches)
	}
}

// TestDetect_AllVariablesSetOrAllowlisted_ProducesNoMatches expands the
// task's clean example ("{% set name = \"world\" %}\nHello {{ name }}")
// into the same realistic report template as the dirty test above, but with
// every referenced variable either {% set %}-defined or a known
// builtin/context variable — proving this pattern does not fire on a
// template that was actually exercised against its real context.
func TestDetect_AllVariablesSetOrAllowlisted_ProducesNoMatches(t *testing.T) {
	content := []byte(`{% set title = "Repository Manufacturing Report" %}
{% set repo_name = "ggen-ecosystem" %}
<h1>{{ title }}</h1>
<p>Generated for {{ repo_name }} on {{ now() }}.</p>
<ul>
{% for row in sparql_results.rows %}
  <li>{{ row.subject }} -&gt; {{ row.predicate }}</li>
{% endfor %}
</ul>
<footer>Rendered after {{ loop.index }} passes by {{ self }}</footer>
`)

	d := detector{}
	matches := d.Detect("templates/repository-report.tera", content)

	if len(matches) != 0 {
		t.Errorf("Detect() = %d matches, want 0 for a fully set-defined/allowlisted template; matches: %+v", len(matches), matches)
	}
}

// TestDetect_AllowlistedBuiltins_ProducesNoMatches is a focused edge case
// for every name in the allowlist named in the task description
// (loop, self, super, config, now, range, throw, true, false) plus the
// minimal literal fixture from the task ("Hello {{ mystery_var }}" analog)
// to prove the allowlist itself, not incidental set-definitions, is what
// suppresses these.
func TestDetect_AllowlistedBuiltins_ProducesNoMatches(t *testing.T) {
	content := []byte(`{% for item in range(end=3) %}
  {{ loop.index }}: {{ super() }}
{% endfor %}
{{ config.title }}
{{ throw(message="boom") }}
{{ true }} {{ false }}
`)

	d := detector{}
	matches := d.Detect("templates/builtins-only.tera", content)

	if len(matches) != 0 {
		t.Errorf("Detect() = %d matches, want 0 when every referenced {{ }} name is on the allowlist; matches: %+v", len(matches), matches)
	}
}

// TestDetect_NonTeraFile_Ignored proves the .tera-only file-type gate: the
// exact dirty shape from the task description, but under a non-.tera path,
// must never be scanned.
func TestDetect_NonTeraFile_Ignored(t *testing.T) {
	content := []byte("Hello {{ mystery_var }}")

	d := detector{}
	matches := d.Detect("notes/example.txt", content)

	if len(matches) != 0 {
		t.Errorf("Detect() = %d matches for a non-.tera file, want 0 (pattern must only scan .tera files); matches: %+v", len(matches), matches)
	}
}

// TestID_And_Category verifies the Pattern interface's static identity
// methods directly, independent of any Detect() call.
func TestID_And_Category(t *testing.T) {
	d := detector{}
	if got := d.ID(); got != "tera-undefined-template-variable" {
		t.Errorf("ID() = %q, want %q", got, "tera-undefined-template-variable")
	}
	if got := d.Category(); got != "generated-artifact-tampering" {
		t.Errorf("Category() = %q, want %q", got, "generated-artifact-tampering")
	}
}

// containsSubstring is a tiny local helper so this test file has zero
// non-stdlib, non-llmcheat imports beyond "testing" itself.
func containsSubstring(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// compile-time check that detector really implements llmcheat.Pattern.
var _ llmcheat.Pattern = detector{}
