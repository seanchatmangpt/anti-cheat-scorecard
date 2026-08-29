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

package floatingdependencyversionunpinned

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// Chicago-style throughout: every test constructs the real detector{} type
// directly and calls the real Detect on real, realistic multi-line byte
// content, then asserts on the real returned []llmcheat.Match slice. Detect
// is a pure function of (path, content) with no collaborators, so there is
// nothing legitimate here to mock.

// assertCommonFields checks the fields every match from this detector must
// share, regardless of which of the five file shapes produced it.
func assertCommonFields(t *testing.T, m llmcheat.Match, wantPath string) {
	t.Helper()
	if m.PatternID != patternID {
		t.Errorf("PatternID = %q, want %q", m.PatternID, patternID)
	}
	if m.Category != category {
		t.Errorf("Category = %q, want %q", m.Category, category)
	}
	if m.Path != wantPath {
		t.Errorf("Path = %q, want %q", m.Path, wantPath)
	}
	if m.Message == "" {
		t.Error("Message is empty, want a real explanation")
	}
	if m.Line == 0 {
		t.Error("Line = 0, want a real 1-based line number")
	}
}

// matchLines extracts the Line field of every match, for order-sensitive
// "did we flag exactly these lines" assertions.
func matchLines(matches []llmcheat.Match) []uint {
	out := make([]uint, len(matches))
	for i, m := range matches {
		out[i] = m.Line
	}
	return out
}

func assertLines(t *testing.T, got []llmcheat.Match, want []uint) {
	t.Helper()
	gotLines := matchLines(got)
	if len(gotLines) != len(want) {
		t.Fatalf("got %d matches at lines %v, want %d matches at lines %v", len(gotLines), gotLines, len(want), want)
	}
	for i := range want {
		if gotLines[i] != want[i] {
			t.Errorf("match[%d].Line = %d, want %d (all matched lines: %v)", i, gotLines[i], want[i], gotLines)
		}
	}
}

// ---- the task's own one-line dirty/clean examples, exercised directly ----

func TestDetect_TaskDirtyExample_ProducesMatch(t *testing.T) {
	content := []byte("{\n  \"dependencies\": {\n    \"lodash\": \"^4.17.21\"\n  }\n}\n")
	got := detector{}.Detect("package.json", content)
	if len(got) < 1 {
		t.Fatalf("Detect() = %d matches, want >= 1 for dirty fixture %q", len(got), string(content))
	}
	for _, m := range got {
		assertCommonFields(t, m, "package.json")
	}
}

func TestDetect_TaskCleanExample_ProducesZeroMatches(t *testing.T) {
	content := []byte("{\n  \"dependencies\": {\n    \"lodash\": \"4.17.21\"\n  }\n}\n")
	got := detector{}.Detect("package.json", content)
	if len(got) != 0 {
		t.Fatalf("Detect() = %d matches, want 0 for clean fixture %q; matches: %+v", len(got), string(content), got)
	}
}

// ---- package.json, expanded realistic fixture ----------------------------

const packageJSONDirty = `{
  "name": "example",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "^4.17.21",
    "chalk": "~4.1.0",
    "leftpad": "*",
    "express": "latest",
    "react": "1.2.x",
    "exact-pkg": "4.17.21"
  },
  "devDependencies": {
    "jest": ">=29.0.0"
  }
}
`

func TestDetect_PackageJSON_Dirty_FlagsEachFloatingForm(t *testing.T) {
	got := detector{}.Detect("package.json", []byte(packageJSONDirty))
	// lines: 5 (^), 6 (~), 7 (*), 8 (latest), 9 (1.2.x), 13 (unbounded >=).
	// exact-pkg on line 10 and the top-level "version" field on line 3 must
	// NOT be flagged.
	assertLines(t, got, []uint{5, 6, 7, 8, 9, 13})
	for _, m := range got {
		assertCommonFields(t, m, "package.json")
	}
}

const packageJSONClean = `{
  "name": "example",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.21",
    "chalk": "4.1.0"
  }
}
`

func TestDetect_PackageJSON_Clean_ProducesZeroMatches(t *testing.T) {
	got := detector{}.Detect("package.json", []byte(packageJSONClean))
	if len(got) != 0 {
		t.Fatalf("Detect() = %d matches, want 0; matches: %+v", len(got), got)
	}
}

// ---- Cargo.toml ------------------------------------------------------

const cargoTomlDirty = `[package]
name = "example"
version = "0.1.0"

[dependencies]
serde = "1.2"
tokio = { version = "1.28", features = ["full"] }
regex = "^1.10"
once_cell = "=1.19.0"
local-crate = { path = "../local-crate" }

[dev-dependencies]
proptest = "1.0"
`

func TestDetect_CargoToml_Dirty_FlagsUnpinnedRequirements(t *testing.T) {
	got := detector{}.Detect("Cargo.toml", []byte(cargoTomlDirty))
	// line 6 serde bare "1.2", line 7 tokio inline-table bare "1.28",
	// line 8 regex explicit "^1.10", line 13 proptest bare "1.0". Line 9
	// (once_cell "=1.19.0", exact pin) and line 10 (local-crate has no
	// version field at all -- a path dependency) must NOT be flagged.
	assertLines(t, got, []uint{6, 7, 8, 13})
	for _, m := range got {
		assertCommonFields(t, m, "Cargo.toml")
	}
}

const cargoTomlClean = `[package]
name = "example"
version = "0.1.0"

[dependencies]
serde = "=1.0.204"
tokio = { version = "=1.28.0", features = ["full"] }
local-crate = { path = "../local-crate" }
`

func TestDetect_CargoToml_Clean_ProducesZeroMatches(t *testing.T) {
	got := detector{}.Detect("Cargo.toml", []byte(cargoTomlClean))
	if len(got) != 0 {
		t.Fatalf("Detect() = %d matches, want 0; matches: %+v", len(got), got)
	}
}

// ---- requirements.txt --------------------------------------------------

const requirementsTxtDirty = `# core dependencies
flask>=2.0.0
requests==2.31.0
numpy~=1.21
django>=4.0,<5.0
-e git+https://example.com/foo.git#egg=foo
click>=8.0.0  # cli parsing, no upper bound
`

func TestDetect_RequirementsTxt_Dirty_FlagsUnboundedAndCompatible(t *testing.T) {
	got := detector{}.Detect("requirements.txt", []byte(requirementsTxtDirty))
	// line 2 flask>=2.0.0 (unbounded), line 4 numpy~=1.21 (compatible
	// release), line 7 click>=8.0.0 (unbounded, despite a trailing inline
	// comment). requests==2.31.0 (exact) and django>=4.0,<5.0 (has an
	// upper bound) must NOT be flagged; the "-e git+..." line is not a
	// version-specifier line at all.
	assertLines(t, got, []uint{2, 4, 7})
	for _, m := range got {
		assertCommonFields(t, m, "requirements.txt")
	}
}

const requirementsTxtClean = `# pinned versions only
flask==2.0.0
requests==2.31.0
django>=4.0,<5.0
numpy==1.21.0
`

func TestDetect_RequirementsTxt_Clean_ProducesZeroMatches(t *testing.T) {
	got := detector{}.Detect("requirements.txt", []byte(requirementsTxtClean))
	if len(got) != 0 {
		t.Fatalf("Detect() = %d matches, want 0; matches: %+v", len(got), got)
	}
}

func TestDetect_RequirementsVariantFilename_IsScanned(t *testing.T) {
	got := detector{}.Detect("requirements-dev.txt", []byte("pytest>=7.0.0\n"))
	assertLines(t, got, []uint{1})
}

// ---- pyproject.toml ----------------------------------------------------

const pyprojectTomlDirty = `[project]
name = "example"
version = "0.1.0"
dependencies = [
    "requests>=2.0.0",
    "flask==2.1.3",
    "numpy~=1.21",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "black==23.1.0",
]

[tool.other]
dependencies = ["should-not-be-scanned>=1.0.0"]
`

func TestDetect_PyprojectToml_Dirty_ScansProjectAndOptionalDependenciesOnly(t *testing.T) {
	got := detector{}.Detect("pyproject.toml", []byte(pyprojectTomlDirty))
	// line 5 requests>=2.0.0, line 7 numpy~=1.21, line 12 pytest>=7.0.0.
	// flask==2.1.3 and black==23.1.0 are exact pins. The dependencies
	// array under the unrelated [tool.other] table (line 17) must NOT be
	// scanned at all -- this is the section-gating behavior under test.
	assertLines(t, got, []uint{5, 7, 12})
	for _, m := range got {
		assertCommonFields(t, m, "pyproject.toml")
	}
}

const pyprojectTomlClean = `[project]
name = "example"
version = "0.1.0"
dependencies = [
    "requests==2.31.0",
    "flask==2.1.3",
]

[project.optional-dependencies]
dev = [
    "pytest==7.4.0",
]
`

func TestDetect_PyprojectToml_Clean_ProducesZeroMatches(t *testing.T) {
	got := detector{}.Detect("pyproject.toml", []byte(pyprojectTomlClean))
	if len(got) != 0 {
		t.Fatalf("Detect() = %d matches, want 0; matches: %+v", len(got), got)
	}
}

// ---- go.mod --------------------------------------------------------------

const goModDirty = `module example.com/foo

go 1.23

require (
	github.com/pkg/errors v0.9.1
	github.com/some/pkg latest
	github.com/other/pkg v1.2.3 // indirect
)

require golang.org/x/tools latest
`

func TestDetect_GoMod_Dirty_FlagsLatestPseudoVersion(t *testing.T) {
	got := detector{}.Detect("go.mod", []byte(goModDirty))
	// line 7 (inside the require block) and line 11 (single-line require
	// form) both use the floating "latest" pseudo-version. The two
	// properly pinned require entries (lines 6 and 8) must NOT be
	// flagged.
	assertLines(t, got, []uint{7, 11})
	for _, m := range got {
		assertCommonFields(t, m, "go.mod")
	}
}

const goModClean = `module example.com/foo

go 1.23

require (
	github.com/pkg/errors v0.9.1
	github.com/some/pkg v1.4.0
)
`

func TestDetect_GoMod_Clean_ProducesZeroMatches(t *testing.T) {
	got := detector{}.Detect("go.mod", []byte(goModClean))
	if len(got) != 0 {
		t.Fatalf("Detect() = %d matches, want 0; matches: %+v", len(got), got)
	}
}

// ---- dispatch gating: irrelevant filenames are never scanned -----------

func TestDetect_IrrelevantFilename_ProducesZeroMatchesEvenWithFloatingShapedContent(t *testing.T) {
	// Same floating-shaped body as the dirty package.json fixture, but
	// under a filename this pattern has no business scanning.
	got := detector{}.Detect("README.md", []byte(packageJSONDirty))
	if len(got) != 0 {
		t.Fatalf("Detect() = %d matches for README.md, want 0 (filename dispatch must gate scanning); matches: %+v", len(got), got)
	}
}

// ---- registration and interface identity --------------------------------

func TestDetector_IDAndCategory(t *testing.T) {
	d := detector{}
	if got := d.ID(); got != "floating-dependency-version-unpinned" {
		t.Errorf("ID() = %q, want %q", got, "floating-dependency-version-unpinned")
	}
	if got := d.Category(); got != "determinism-and-provenance-violation" {
		t.Errorf("Category() = %q, want %q", got, "determinism-and-provenance-violation")
	}
}

func TestDetector_ImplementsPatternInterface(t *testing.T) {
	var _ llmcheat.Pattern = detector{}
}
