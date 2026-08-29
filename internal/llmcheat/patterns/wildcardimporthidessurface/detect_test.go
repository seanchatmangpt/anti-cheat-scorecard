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

package wildcardimporthidessurface

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

func assertBaseFields(t *testing.T, got []llmcheat.Match, wantPath string) {
	t.Helper()
	for _, m := range got {
		if m.PatternID != patternID {
			t.Errorf("match PatternID = %q, want %q", m.PatternID, patternID)
		}
		if m.Category != category {
			t.Errorf("match Category = %q, want %q", m.Category, category)
		}
		if m.Path != wantPath {
			t.Errorf("match Path = %q, want %q", m.Path, wantPath)
		}
	}
}

// TestDetect_PythonDirtyWildcardImportFlagged proves the assigned dirty
// example ("from utils import *"), expanded to a realistic multi-line
// module, produces at least one match with the correct PatternID/Category
// and a correct 1-based line number.
func TestDetect_PythonDirtyWildcardImportFlagged(t *testing.T) {
	const src = `"""Loads app configuration."""
import os
from utils import *


def load():
    return parse_config(os.environ)
`
	d := detector{}
	got := d.Detect("app/loader.py", []byte(src))

	if len(got) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1; got %+v", len(got), got)
	}
	assertBaseFields(t, got, "app/loader.py")
	if got[0].Line != 3 {
		t.Errorf("match Line = %d, want 3 (the `from utils import *` line)", got[0].Line)
	}
	if got[0].Severity != llmcheat.SeverityMedium {
		t.Errorf("match Severity = %q, want %q", got[0].Severity, llmcheat.SeverityMedium)
	}
}

// TestDetect_PythonCleanExplicitImportsNoMatches proves the assigned clean
// example ("from utils import parse_config, load_data"), expanded to a
// realistic multi-line module, produces zero matches.
func TestDetect_PythonCleanExplicitImportsNoMatches(t *testing.T) {
	const src = `"""Loads app configuration."""
import os
from utils import parse_config, load_data


def load():
    return parse_config(os.environ), load_data()
`
	d := detector{}
	got := d.Detect("app/loader.py", []byte(src))

	if len(got) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 for explicit named imports; got %+v", len(got), got)
	}
}

// TestDetect_PythonRelativeWildcardImportFlagged proves a relative-module
// wildcard import (`from . import *` / `from .sub import *`) is also
// caught, not just an absolute module path.
func TestDetect_PythonRelativeWildcardImportFlagged(t *testing.T) {
	const src = `from . import *
from .helpers import *
`
	d := detector{}
	got := d.Detect("pkg/__init__.py", []byte(src))

	if len(got) != 2 {
		t.Fatalf("Detect() returned %d matches, want exactly 2; got %+v", len(got), got)
	}
	if got[0].Line != 1 || got[1].Line != 2 {
		t.Errorf("match Lines = %d, %d, want 1, 2", got[0].Line, got[1].Line)
	}
}

// TestDetect_PythonCommentMentionIgnored proves a full-line `#` comment
// that merely mentions the wildcard-import shape in prose is not itself
// flagged.
func TestDetect_PythonCommentMentionIgnored(t *testing.T) {
	const src = `# Deliberately not doing: from utils import *
from utils import parse_config
`
	d := detector{}
	got := d.Detect("app/loader.py", []byte(src))

	if len(got) != 0 {
		t.Fatalf("Detect() returned %d matches for comment-only mention, want 0; got %+v", len(got), got)
	}
}

// TestDetect_RustDirtyWildcardUseFlagged proves a Rust `use module::*;`
// glob import, expanded to a realistic multi-line module, produces at
// least one match with the correct PatternID/Category and a correct
// 1-based line number.
func TestDetect_RustDirtyWildcardUseFlagged(t *testing.T) {
	const src = `use std::fmt;
use utils::*;

pub fn run() {
    fmt::println!("running");
}
`
	d := detector{}
	got := d.Detect("src/runner.rs", []byte(src))

	if len(got) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1; got %+v", len(got), got)
	}
	assertBaseFields(t, got, "src/runner.rs")
	if got[0].Line != 2 {
		t.Errorf("match Line = %d, want 2 (the `use utils::*;` line)", got[0].Line)
	}
	if got[0].Severity != llmcheat.SeverityMedium {
		t.Errorf("match Severity = %q, want %q", got[0].Severity, llmcheat.SeverityMedium)
	}
}

// TestDetect_RustCleanNamedUseNoMatches proves explicit named Rust `use`
// imports produce zero matches.
func TestDetect_RustCleanNamedUseNoMatches(t *testing.T) {
	const src = `use std::fmt;
use utils::{parse_config, load_data};

pub fn run() {
    fmt::println!("running");
}
`
	d := detector{}
	got := d.Detect("src/runner.rs", []byte(src))

	if len(got) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 for named imports; got %+v", len(got), got)
	}
}

// TestDetect_RustSuperAndPreludeGlobsExcluded proves the two named
// idiomatic exceptions — `use super::*;` and any `...::prelude::*;` — are
// NOT flagged, even though both are syntactically the same
// `use <path>::*;` glob shape as the flagged cases.
func TestDetect_RustSuperAndPreludeGlobsExcluded(t *testing.T) {
	const src = `use super::*;
use std::prelude::*;
use crate::prelude::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
`
	d := detector{}
	got := d.Detect("src/lib.rs", []byte(src))

	if len(got) != 0 {
		t.Fatalf("Detect() returned %d matches for idiomatic super/prelude globs, want 0; got %+v", len(got), got)
	}
}

// TestDetect_RustPubUseWildcardFlagged proves a `pub use module::*;`
// re-export glob is also caught, not just a bare `use`.
func TestDetect_RustPubUseWildcardFlagged(t *testing.T) {
	const src = `pub use internal::*;
`
	d := detector{}
	got := d.Detect("src/lib.rs", []byte(src))

	if len(got) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1 for `pub use internal::*;`; got %+v", len(got), got)
	}
	if got[0].Line != 1 {
		t.Errorf("match Line = %d, want 1", got[0].Line)
	}
}

// TestDetect_RustCommentMentionIgnored proves a full-line `//` comment that
// merely mentions the wildcard shape in prose is not itself flagged.
func TestDetect_RustCommentMentionIgnored(t *testing.T) {
	const src = `// Deliberately not doing: use utils::*;
use utils::parse_config;
`
	d := detector{}
	got := d.Detect("src/lib.rs", []byte(src))

	if len(got) != 0 {
		t.Fatalf("Detect() returned %d matches for comment-only mention, want 0; got %+v", len(got), got)
	}
}

// TestDetect_GoDirtySingleDotImportFlagged proves a single-statement Go
// dot-import (`import . "pkg"`) is flagged with a correct line number.
func TestDetect_GoDirtySingleDotImportFlagged(t *testing.T) {
	const src = `package runner

import . "fmt"

func Run() {
	Println("running")
}
`
	d := detector{}
	got := d.Detect("runner/runner.go", []byte(src))

	if len(got) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1; got %+v", len(got), got)
	}
	assertBaseFields(t, got, "runner/runner.go")
	if got[0].Line != 3 {
		t.Errorf("match Line = %d, want 3 (the `import . \"fmt\"` line)", got[0].Line)
	}
	if got[0].Severity != llmcheat.SeverityMedium {
		t.Errorf("match Severity = %q, want %q", got[0].Severity, llmcheat.SeverityMedium)
	}
}

// TestDetect_GoDirtyBlockDotImportFlagged proves a block-form Go
// dot-import (`. "pkg"` inside a parenthesized import block) is flagged,
// while sibling non-dot imports in the same block are not.
func TestDetect_GoDirtyBlockDotImportFlagged(t *testing.T) {
	const src = `package runner

import (
	"os"
	. "fmt"
)

func Run() {
	Println(os.Getenv("HOME"))
}
`
	d := detector{}
	got := d.Detect("runner/runner.go", []byte(src))

	if len(got) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1; got %+v", len(got), got)
	}
	if got[0].Line != 5 {
		t.Errorf("match Line = %d, want 5 (the `. \"fmt\"` line)", got[0].Line)
	}
}

// TestDetect_GoCleanNamedImportsNoMatches proves ordinary named and
// aliased Go imports (no dot-import) produce zero matches.
func TestDetect_GoCleanNamedImportsNoMatches(t *testing.T) {
	const src = `package runner

import (
	"fmt"
	"os"

	myfmt "fmt"
)

func Run() {
	fmt.Println(os.Getenv("HOME"))
	myfmt.Println("aliased")
}
`
	d := detector{}
	got := d.Detect("runner/runner.go", []byte(src))

	if len(got) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 for named/aliased imports; got %+v", len(got), got)
	}
}

// TestDetect_GoCommentMentionIgnored proves a full-line `//` comment that
// merely mentions the dot-import shape in prose is not itself flagged.
func TestDetect_GoCommentMentionIgnored(t *testing.T) {
	const src = `package runner

// Deliberately not doing: import . "fmt"
import "fmt"

func Run() {
	fmt.Println("running")
}
`
	d := detector{}
	got := d.Detect("runner/runner.go", []byte(src))

	if len(got) != 0 {
		t.Fatalf("Detect() returned %d matches for comment-only mention, want 0; got %+v", len(got), got)
	}
}

// TestDetect_IrrelevantFileExtensionIgnored proves the detector only ever
// inspects .py/.rs/.go files, even when the content contains an exact
// dirty pattern for one of the three languages.
func TestDetect_IrrelevantFileExtensionIgnored(t *testing.T) {
	const src = `from utils import *
use utils::*;
import . "fmt"
`
	d := detector{}
	got := d.Detect("notes/scratch.md", []byte(src))

	if len(got) != 0 {
		t.Fatalf("Detect() returned %d matches for a non-.py/.rs/.go file, want 0; got %+v", len(got), got)
	}
}

// TestID_Category proves the detector reports the exact ID/Category
// contract this pattern was assigned.
func TestID_Category(t *testing.T) {
	d := detector{}
	if got := d.ID(); got != "wildcard-import-hides-surface" {
		t.Errorf("ID() = %q, want %q", got, "wildcard-import-hides-surface")
	}
	if got := d.Category(); got != "complexity-and-surface-obfuscation" {
		t.Errorf("Category() = %q, want %q", got, "complexity-and-surface-obfuscation")
	}
}
