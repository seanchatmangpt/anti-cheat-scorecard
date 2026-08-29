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

package misleadingfunctionnamevsbody

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// d is the same real detector Register() wires up in init(); constructing it
// directly here lets the test call Detect() with no global registry
// involvement, per the Chicago-style "real collaborator, no mocking" rule —
// detector has no collaborators to mock in the first place.
var d = detector{}

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
}

func TestDetect_DirtyPythonBody_IsFlagged(t *testing.T) {
	// The exact dirty example from the pattern spec, expanded to a
	// realistic multi-line function.
	src := []byte("def validate(x):\n    log.info(\"validating\")\n    return True\n")

	matches := d.Detect("app/checks.py", src)

	if len(matches) != 1 {
		t.Fatalf("expected exactly 1 match, got %d: %+v", len(matches), matches)
	}
	assertMatch(t, matches[0], 1)
	if matches[0].Path != "app/checks.py" {
		t.Errorf("Path = %q, want %q", matches[0].Path, "app/checks.py")
	}
	if matches[0].Severity != llmcheat.SeverityHigh {
		t.Errorf("Severity = %q, want %q (2-line hollow body)", matches[0].Severity, llmcheat.SeverityHigh)
	}
}

func TestDetect_CleanPythonBody_IsClean(t *testing.T) {
	// The exact clean example from the pattern spec: a real comparison in
	// the body.
	src := []byte("def validate(x):\n    return x is not None and x > 0\n")

	matches := d.Detect("app/checks.py", src)

	if len(matches) != 0 {
		t.Fatalf("expected 0 matches for a real comparison body, got %d: %+v", len(matches), matches)
	}
}

func TestDetect_MixedPythonFixture_OnlyHollowNamedFunctionFlagged(t *testing.T) {
	// A realistic multi-method class exercising three cases in one file:
	//   - compute: hollow body, but name doesn't match the target prefixes
	//     -> never even considered.
	//   - verify: target-prefixed name, hollow body (no conditional, no
	//     comparison) -> flagged.
	//   - check_ready: target-prefixed name (check*), but the body DOES
	//     branch and DOES compare -> clean.
	src := []byte(`class Foo:
    def compute(self, x):
        return x * 2

    def verify(self, token):
        log.debug("checking token")
        send_metric("verify_called")

    def check_ready(self):
        if self.state == "ready":
            return True
        return False
`)

	matches := d.Detect("app/foo.py", src)

	if len(matches) != 1 {
		t.Fatalf("expected exactly 1 match (only verify), got %d: %+v", len(matches), matches)
	}
	assertMatch(t, matches[0], 5)
}

func TestDetect_NameDoesNotMatchPrefix_IsClean(t *testing.T) {
	// A hollow body under a name that does NOT start with
	// verify/validate/check/ensure must never be flagged by this pattern.
	src := []byte("def process(x):\n    log.info(x)\n    return True\n")

	matches := d.Detect("app/checks.py", src)

	if len(matches) != 0 {
		t.Fatalf("expected 0 matches for a non-decision-shaped name, got %d: %+v", len(matches), matches)
	}
}

func TestDetect_DeclarationWithoutBody_IsSkipped(t *testing.T) {
	// A genuine interface/abstract-method declaration has no body at all
	// to judge — nothing to flag, distinct from a hollow *implementation*.
	src := []byte("interface Foo {\n    boolean verifyToken(String t);\n}\n")

	matches := d.Detect("app/Foo.java", src)

	if len(matches) != 0 {
		t.Fatalf("expected 0 matches for a bodyless declaration, got %d: %+v", len(matches), matches)
	}
}

func TestDetect_GoDirtyFunction_IsFlagged(t *testing.T) {
	src := []byte("package foo\n\nfunc VerifyToken(t string) bool {\n\tlog.Println(\"checking token\")\n\treturn true\n}\n")

	matches := d.Detect("pkg/foo.go", src)

	if len(matches) != 1 {
		t.Fatalf("expected exactly 1 match, got %d: %+v", len(matches), matches)
	}
	assertMatch(t, matches[0], 3)
}

func TestDetect_RustFunctions_ComparisonOnlyIsClean_NoConditionOrComparisonIsFlagged(t *testing.T) {
	clean := []byte("fn verify(x: i32) -> bool {\n    x > 0\n}\n")
	if matches := d.Detect("src/lib.rs", clean); len(matches) != 0 {
		t.Fatalf("expected 0 matches for a comparison-only rust body, got %d: %+v", len(matches), matches)
	}

	dirty := []byte("fn verify(t: &str) -> bool {\n    println!(\"checking token\");\n    log_event(\"verify_called\");\n    true\n}\n")
	matches := d.Detect("src/lib.rs", dirty)
	if len(matches) != 1 {
		t.Fatalf("expected exactly 1 match for the hollow rust body, got %d: %+v", len(matches), matches)
	}
	assertMatch(t, matches[0], 1)
}

func TestDetect_JSArrowDirtyFunction_IsFlagged(t *testing.T) {
	src := []byte("const validateInput = (x) => {\n    console.log(\"validating\");\n    return true;\n};\n")

	matches := d.Detect("web/input.js", src)

	if len(matches) != 1 {
		t.Fatalf("expected exactly 1 match, got %d: %+v", len(matches), matches)
	}
	assertMatch(t, matches[0], 1)
}

func TestDetect_JavaDirtyMethod_IsFlagged(t *testing.T) {
	src := []byte("class Foo {\n    public boolean verifyToken(String t) {\n        System.out.println(\"checking\");\n        return true;\n    }\n}\n")

	matches := d.Detect("src/Foo.java", src)

	if len(matches) != 1 {
		t.Fatalf("expected exactly 1 match, got %d: %+v", len(matches), matches)
	}
	assertMatch(t, matches[0], 2)
}

func TestDetect_NonMatchingFile_IsIgnored(t *testing.T) {
	matches := d.Detect("README.md", []byte("# just some prose, no functions here\n"))
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches for content with no function headers, got %d: %+v", len(matches), matches)
	}
}

func TestDetect_EmptyContent_IsClean(t *testing.T) {
	if matches := d.Detect("empty.py", []byte("")); len(matches) != 0 {
		t.Fatalf("expected 0 matches for empty content, got %d: %+v", len(matches), matches)
	}
	if matches := d.Detect("blank.py", []byte("   \n\n\t\n")); len(matches) != 0 {
		t.Fatalf("expected 0 matches for whitespace-only content, got %d: %+v", len(matches), matches)
	}
}

func TestDetect_IDAndCategory(t *testing.T) {
	if got := d.ID(); got != "misleading-function-name-vs-body" {
		t.Errorf("ID() = %q, want %q", got, "misleading-function-name-vs-body")
	}
	if got := d.Category(); got != "complexity-and-surface-obfuscation" {
		t.Errorf("Category() = %q, want %q", got, "complexity-and-surface-obfuscation")
	}
}

// Compile-time assertion that detector really implements llmcheat.Pattern —
// mirrors the interface contract without needing the global registry.
var _ llmcheat.Pattern = detector{}
