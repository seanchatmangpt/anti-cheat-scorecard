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

package placeholderloremipsum

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// TestDetect_LoremIpsumInStringLiteral_ProducesMatch exercises the exact
// dirty shape from the task description, expanded into a realistic
// multi-line Python module: a "description" field whose value is Lorem
// Ipsum boilerplate rather than a real description.
func TestDetect_LoremIpsumInStringLiteral_ProducesMatch(t *testing.T) {
	content := []byte(`"""Metadata module for the widget plugin."""


def get_plugin_metadata():
    name = "widget"
    description = "lorem ipsum dolor sit amet, consectetur adipiscing elit"
    version = "1.0.0"
    return {"name": name, "description": description, "version": version}
`)

	d := detector{}
	matches := d.Detect("pkg/widget/metadata.py", content)

	if len(matches) < 1 {
		t.Fatalf("Detect() returned %d matches, want at least 1 for lorem-ipsum string literal", len(matches))
	}
	for _, m := range matches {
		if m.PatternID != "placeholder-lorem-ipsum-in-code" {
			t.Errorf("Match.PatternID = %q, want %q", m.PatternID, "placeholder-lorem-ipsum-in-code")
		}
		if m.Category != "hollow-implementation" {
			t.Errorf("Match.Category = %q, want %q", m.Category, "hollow-implementation")
		}
	}

	// The lorem-ipsum line is line 6 in the fixture above (1-based).
	found := false
	for _, m := range matches {
		if m.Line == 6 {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a match anchored at line 6 (the lorem-ipsum string literal), got matches: %+v", matches)
	}
}

// TestDetect_RealDescription_ProducesNoMatches proves the clean-shaped
// fixture — a real, specific description of what the code does — produces
// zero matches, i.e. this pattern does not fire on ordinary well-written
// code.
func TestDetect_RealDescription_ProducesNoMatches(t *testing.T) {
	content := []byte(`"""Metadata module for the moving-average plugin."""


def get_plugin_metadata():
    name = "moving-average"
    description = "Computes the moving average over the given window."
    version = "1.0.0"
    return {"name": name, "description": description, "version": version}
`)

	d := detector{}
	matches := d.Detect("pkg/movingavg/metadata.py", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 for a real description: %+v", len(matches), matches)
	}
}

// TestDetect_FixturePathAllowlisted proves the exact same lorem-ipsum
// content that fires in TestDetect_LoremIpsumInStringLiteral_ProducesMatch
// is allowlisted (zero matches) once the path names a fixture/test/mock
// directory, per the description's explicit exception.
func TestDetect_FixturePathAllowlisted(t *testing.T) {
	content := []byte(`description = "lorem ipsum dolor sit amet"
`)

	d := detector{}

	paths := []string{
		"internal/checker/testdata/fixtures/metadata.py",
		"pkg/widget/test/metadata.py",
		"pkg/widget/mocks/metadata.py",
	}
	for _, p := range paths {
		matches := d.Detect(p, content)
		if len(matches) != 0 {
			t.Errorf("Detect(%q, ...) returned %d matches, want 0 (allowlisted path): %+v", p, len(matches), matches)
		}
	}
}

// TestDetect_PlaceholderInComment proves the pattern also fires on
// placeholder text living in a comment, not only in a string literal — a Go
// source file with a lorem-ipsum doc comment and a "foo bar baz" TODO.
func TestDetect_PlaceholderInComment(t *testing.T) {
	content := []byte(`package widget

// Lorem ipsum dolor sit amet — this is a placeholder doc comment.
func Compute() int {
	return 42
}

// TODO: foo bar baz, replace with the real validation logic.
func Validate() error {
	return nil
}
`)

	d := detector{}
	matches := d.Detect("pkg/widget/widget.go", content)

	if len(matches) < 2 {
		t.Fatalf("Detect() returned %d matches, want at least 2 (one per placeholder comment): %+v", len(matches), matches)
	}

	gotLines := map[uint]bool{}
	for _, m := range matches {
		gotLines[m.Line] = true
		if m.PatternID != "placeholder-lorem-ipsum-in-code" {
			t.Errorf("Match.PatternID = %q, want %q", m.PatternID, "placeholder-lorem-ipsum-in-code")
		}
	}
	if !gotLines[3] {
		t.Errorf("expected a match anchored at line 3 (lorem-ipsum comment), got matches: %+v", matches)
	}
	if !gotLines[8] {
		t.Errorf("expected a match anchored at line 8 (foo-bar-baz comment), got matches: %+v", matches)
	}
}

// TestDetect_RepeatedAsdfPlaceholder proves the "asdf" repeated shape fires
// both when adjacent with no separator and when space-separated, and that a
// generic repeated placeholder token ("xxx xxx xxx") also fires via the
// broader repeated-token generalization.
func TestDetect_RepeatedAsdfPlaceholder(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"adjacent", `token := "asdfasdfasdf"` + "\n"},
		{"space-separated", `token := "asdf asdf asdf"` + "\n"},
		{"generic-triple-repeat", `token := "xxx xxx xxx"` + "\n"},
	}

	d := detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := d.Detect("pkg/auth/token.go", []byte(tt.content))
			if len(matches) < 1 {
				t.Fatalf("Detect() returned %d matches for %q, want at least 1", len(matches), tt.content)
			}
			if matches[0].PatternID != "placeholder-lorem-ipsum-in-code" {
				t.Errorf("Match.PatternID = %q, want %q", matches[0].PatternID, "placeholder-lorem-ipsum-in-code")
			}
		})
	}
}

// TestDetect_CodeIdentifierNotFlagged proves a bare code identifier that
// happens to spell out placeholder-looking words (not inside a string
// literal or comment, and not space-separated the way the placeholder
// phrases are) is never flagged — only text living inside string literals
// or comments is in scope.
func TestDetect_CodeIdentifierNotFlagged(t *testing.T) {
	content := []byte(`package widget

func FooBarBaz(xxxYyyZzz int) int {
	return xxxYyyZzz * 2
}
`)

	d := detector{}
	matches := d.Detect("pkg/widget/widget.go", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches for code identifiers, want 0: %+v", len(matches), matches)
	}
}

// TestDetect_ImplementsPatternInterface is a compile-time-flavored check
// that detector really satisfies llmcheat.Pattern and reports the expected
// ID/Category via the real interface methods (not just the concrete type).
func TestDetect_ImplementsPatternInterface(t *testing.T) {
	var p llmcheat.Pattern = detector{}
	if p.ID() != "placeholder-lorem-ipsum-in-code" {
		t.Errorf("ID() = %q, want %q", p.ID(), "placeholder-lorem-ipsum-in-code")
	}
	if p.Category() != "hollow-implementation" {
		t.Errorf("Category() = %q, want %q", p.Category(), "hollow-implementation")
	}
}
