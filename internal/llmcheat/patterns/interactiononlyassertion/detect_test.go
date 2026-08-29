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

package interactiononlyassertion

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// TestDetect_Dirty_Python expands the task's one-line Python dirty example
// into a realistic multi-line fixture: a test whose only assertion-shaped
// line checks that a mock was called, never what actually got saved.
func TestDetect_Dirty_Python(t *testing.T) {
	content := []byte(
		"def test_save():\n" +
			"    svc = SaveService(mock_save)\n" +
			"    svc.save(data)\n" +
			"    mock_save.assert_called_once()\n",
	)

	d := detector{}
	matches := d.Detect("services/test_save.py", content)

	if len(matches) < 1 {
		t.Fatalf("Detect() returned %d matches, want >= 1 for dirty fixture", len(matches))
	}
	for i, m := range matches {
		if m.PatternID != patternID {
			t.Errorf("matches[%d].PatternID = %q, want %q", i, m.PatternID, patternID)
		}
		if m.Category != category {
			t.Errorf("matches[%d].Category = %q, want %q", i, m.Category, category)
		}
		if m.Path != "services/test_save.py" {
			t.Errorf("matches[%d].Path = %q, want %q", i, m.Path, "services/test_save.py")
		}
		if m.Line != 4 {
			t.Errorf("matches[%d].Line = %d, want 4 (the assert_called_once line)", i, m.Line)
		}
	}
}

// TestDetect_Clean_Python expands the task's one-line Python clean example:
// the test asserts on the actual resulting state (what got loaded back from
// the repo), not merely that a mock was called.
func TestDetect_Clean_Python(t *testing.T) {
	content := []byte(
		"def test_save():\n" +
			"    svc = SaveService(repo)\n" +
			"    svc.save(data)\n" +
			"    assert repo.load() == data\n",
	)

	d := detector{}
	matches := d.Detect("services/test_save.py", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 for clean fixture; matches=%+v", len(matches), matches)
	}
}

// TestDetect_MixedAssertions_NoMatch is the boundary case that matters most:
// a test that checks BOTH the call AND the resulting state must NOT be
// flagged — the presence of an interaction check is not itself the problem,
// only its being the *only* assertion in the function is.
func TestDetect_MixedAssertions_NoMatch(t *testing.T) {
	content := []byte(
		"def test_save():\n" +
			"    svc = SaveService(mock_save, repo)\n" +
			"    svc.save(data)\n" +
			"    mock_save.assert_called_once()\n" +
			"    assert repo.load() == data\n",
	)

	d := detector{}
	matches := d.Detect("services/test_save.py", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 when a real state assertion is also present; matches=%+v",
			len(matches), matches)
	}
}

// TestDetect_NoAssertionsAtAll_NoMatch guards the other boundary: a test
// with no assertion-shaped line at all (a smoke test) is a different,
// weaker problem than an interaction-only test and must not be flagged by
// this pattern.
func TestDetect_NoAssertionsAtAll_NoMatch(t *testing.T) {
	content := []byte(
		"def test_warms_cache():\n" +
			"    svc = CacheService()\n" +
			"    svc.warm_cache()\n",
	)

	d := detector{}
	matches := d.Detect("services/test_cache.py", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 for a test with no assertions at all; matches=%+v",
			len(matches), matches)
	}
}

// TestDetect_Dirty_JavaScript covers the "it("/"test(" shape with a Jest
// call-verification matcher and no toBe/toEqual anywhere in the body.
func TestDetect_Dirty_JavaScript(t *testing.T) {
	content := []byte(
		"test('saves the record', () => {\n" +
			"  const svc = new SaveService(saveMock);\n" +
			"  svc.save(data);\n" +
			"  expect(saveMock).toHaveBeenCalledWith(data);\n" +
			"});\n",
	)

	d := detector{}
	matches := d.Detect("services/save.test.js", content)

	if len(matches) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1 for the JS dirty fixture; matches=%+v",
			len(matches), matches)
	}
	if matches[0].PatternID != patternID {
		t.Errorf("matches[0].PatternID = %q, want %q", matches[0].PatternID, patternID)
	}
	if matches[0].Category != category {
		t.Errorf("matches[0].Category = %q, want %q", matches[0].Category, category)
	}
	if matches[0].Line != 4 {
		t.Errorf("matches[0].Line = %d, want 4 (the toHaveBeenCalledWith line)", matches[0].Line)
	}
}

// TestDetect_Dirty_Rust covers the "#[test]\nfn test_...() {" shape with a
// verify(...) call-verification style and no assert_eq!/state assertion.
func TestDetect_Dirty_Rust(t *testing.T) {
	content := []byte(
		"#[test]\n" +
			"fn test_save() {\n" +
			"    let mock_saver = MockSaver::new();\n" +
			"    do_save(&mock_saver, &data);\n" +
			"    verify(&mock_saver).save(&data);\n" +
			"}\n",
	)

	d := detector{}
	matches := d.Detect("src/save_test.rs", content)

	if len(matches) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1 for the Rust dirty fixture; matches=%+v",
			len(matches), matches)
	}
	if matches[0].Line != 5 {
		t.Errorf("matches[0].Line = %d, want 5 (the verify(...) line)", matches[0].Line)
	}
}

// TestDetect_Clean_Go covers the Go "func Test...(t *testing.T) {" shape
// with a real testify .Equal(...) state assertion and no interaction check
// at all — must produce zero matches, and exercises the brace-balance body
// extraction path with no assertion at all being interaction-only.
func TestDetect_Clean_Go(t *testing.T) {
	content := []byte(
		"func TestSave(t *testing.T) {\n" +
			"\tsvc := NewSaveService(repo)\n" +
			"\tsvc.Save(data)\n" +
			"\tassert.Equal(t, data, repo.Load())\n" +
			"}\n",
	)

	d := detector{}
	matches := d.Detect("save_test.go", content)

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 for the Go clean fixture; matches=%+v", len(matches), matches)
	}
}

// TestDetector_IDAndCategory checks the two Pattern identity methods
// directly, since checks/raw/anti_cheat.go and internal/llmcheat.Register
// both key off these exact strings.
func TestDetector_IDAndCategory(t *testing.T) {
	d := detector{}
	if got := d.ID(); got != patternID {
		t.Errorf("ID() = %q, want %q", got, patternID)
	}
	if got := d.Category(); got != category {
		t.Errorf("Category() = %q, want %q", got, category)
	}
}

// TestDetector_ImplementsPattern is a compile-time-flavored, still
// state-based check that detector genuinely satisfies llmcheat.Pattern (the
// real interface, not a hand-rolled substitute) and that init() registered
// it under its own real ID via the real llmcheat.Register/llmcheat.All path.
func TestDetector_ImplementsPattern(t *testing.T) {
	var _ llmcheat.Pattern = detector{}

	found := false
	for _, p := range llmcheat.All() {
		if p.ID() == patternID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("llmcheat.All() does not contain a registered %q pattern; init() may not have run Register", patternID)
	}
}
