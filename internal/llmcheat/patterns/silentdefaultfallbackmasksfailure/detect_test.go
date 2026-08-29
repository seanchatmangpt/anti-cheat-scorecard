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

package silentdefaultfallbackmasksfailure

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// --- Go: the pattern description's own dirty/clean example, expanded into
// realistic function bodies. ---

const dirtyGoSource = `package worker

func fetchUser(id string) (*User, error) {
	result, err := risky()
	if err != nil {
		return nil, nil
	}
	return result, nil
}
`

const cleanGoSource = `package worker

import "fmt"

func fetchUser(id string) (*User, error) {
	result, err := risky()
	if err != nil {
		return nil, fmt.Errorf("risky: %w", err)
	}
	return result, nil
}
`

func TestDetect_GoReturnNilNil_ProducesMatch(t *testing.T) {
	d := detector{}

	matches := d.Detect("worker/fetch_user.go", []byte(dirtyGoSource))

	if len(matches) != 1 {
		t.Fatalf("Detect() on dirty Go fixture = %d matches, want 1; matches=%+v", len(matches), matches)
	}
	got := matches[0]
	if got.PatternID != patternID {
		t.Errorf("Match.PatternID = %q, want %q", got.PatternID, patternID)
	}
	if got.Category != patternCategory {
		t.Errorf("Match.Category = %q, want %q", got.Category, patternCategory)
	}
	if got.Path != "worker/fetch_user.go" {
		t.Errorf("Match.Path = %q, want %q", got.Path, "worker/fetch_user.go")
	}
	if got.Line != 5 {
		t.Errorf("Match.Line = %d, want 5 (the `if err != nil {` line)", got.Line)
	}
	if got.Severity != llmcheat.SeverityHigh {
		t.Errorf("Match.Severity = %q, want %q", got.Severity, llmcheat.SeverityHigh)
	}
	if got.Message == "" {
		t.Error("Match.Message is empty, want a real explanation")
	}
}

func TestDetect_GoReturnErrWrapped_ProducesNoMatches(t *testing.T) {
	d := detector{}

	matches := d.Detect("worker/fetch_user.go", []byte(cleanGoSource))

	if len(matches) != 0 {
		t.Fatalf("Detect() on clean Go fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

func TestDetect_GoTable(t *testing.T) {
	tests := []struct {
		name      string
		src       string
		wantCount int
	}{
		{
			name: "return nil, nil discards both the result and the error",
			src: `package worker

func do() (*Thing, error) {
	result, err := risky()
	if err != nil {
		return nil, nil
	}
	return result, nil
}
`,
			wantCount: 1,
		},
		{
			name: "return nil for a single error-only return value",
			src: `package worker

func do() error {
	err := risky()
	if err != nil {
		return nil
	}
	return nil
}
`,
			wantCount: 1,
		},
		{
			name: "return count, nil substitutes a default result but still reports success",
			src: `package worker

func do() (*Thing, error) {
	result, err := risky()
	if err != nil {
		return defaultThing, nil
	}
	return result, nil
}
`,
			wantCount: 1,
		},
		{
			name: "return nil, err propagates the real error",
			src: `package worker

func do() (*Thing, error) {
	result, err := risky()
	if err != nil {
		return nil, err
	}
	return result, nil
}
`,
			wantCount: 0,
		},
		{
			name: "return nil, fmt.Errorf wraps and propagates the real error",
			src: `package worker

import "fmt"

func do() (*Thing, error) {
	result, err := risky()
	if err != nil {
		return nil, fmt.Errorf("risky: %w", err)
	}
	return result, nil
}
`,
			wantCount: 0,
		},
		{
			name: "bare return with named return values already set is out of this heuristic's scope",
			src: `package worker

func do() (user *User, err error) {
	_, err = risky()
	if err != nil {
		return
	}
	return
}
`,
			wantCount: 0,
		},
		{
			name: "log then propagate is not a silent default fallback",
			src: `package worker

func do() (*Thing, error) {
	result, err := risky()
	if err != nil {
		log.Printf("risky failed: %v", err)
		return nil, err
	}
	return result, nil
}
`,
			wantCount: 0,
		},
	}

	d := detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := d.Detect("worker/do.go", []byte(tt.src))
			if len(matches) != tt.wantCount {
				t.Fatalf("Detect() = %d matches, want %d; matches=%+v", len(matches), tt.wantCount, matches)
			}
			for _, m := range matches {
				if m.PatternID != patternID {
					t.Errorf("Match.PatternID = %q, want %q", m.PatternID, patternID)
				}
				if m.Category != patternCategory {
					t.Errorf("Match.Category = %q, want %q", m.Category, patternCategory)
				}
				if m.Line == 0 {
					t.Error("Match.Line = 0, want a real 1-based line number")
				}
			}
		})
	}
}

// --- Python: except Exception clauses whose whole body is a default return. ---

const dirtyPythonSource = `import logging

logger = logging.getLogger(__name__)


def load_config(path):
    try:
        return parse(path)
    except Exception:
        return None
`

const cleanPythonSource = `import logging

logger = logging.getLogger(__name__)


def load_config(path):
    try:
        return parse(path)
    except Exception as e:
        logger.error("failed to load config: %s", e)
        raise
`

func TestDetect_PythonExceptExceptionReturnNone_ProducesMatch(t *testing.T) {
	d := detector{}

	matches := d.Detect("worker/load_config.py", []byte(dirtyPythonSource))

	if len(matches) != 1 {
		t.Fatalf("Detect() on dirty Python fixture = %d matches, want 1; matches=%+v", len(matches), matches)
	}
	got := matches[0]
	if got.PatternID != patternID {
		t.Errorf("Match.PatternID = %q, want %q", got.PatternID, patternID)
	}
	if got.Category != patternCategory {
		t.Errorf("Match.Category = %q, want %q", got.Category, patternCategory)
	}
	if got.Path != "worker/load_config.py" {
		t.Errorf("Match.Path = %q, want %q", got.Path, "worker/load_config.py")
	}
	if got.Line != 9 {
		t.Errorf("Match.Line = %d, want 9 (the `except Exception:` line)", got.Line)
	}
	if got.Severity != llmcheat.SeverityHigh {
		t.Errorf("Match.Severity = %q, want %q", got.Severity, llmcheat.SeverityHigh)
	}
	if got.Message == "" {
		t.Error("Match.Message is empty, want a real explanation")
	}
}

func TestDetect_PythonLoggedAndReraised_ProducesNoMatches(t *testing.T) {
	d := detector{}

	matches := d.Detect("worker/load_config.py", []byte(cleanPythonSource))

	if len(matches) != 0 {
		t.Fatalf("Detect() on clean Python fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

func TestDetect_PythonTable(t *testing.T) {
	tests := []struct {
		name      string
		src       string
		wantCount int
	}{
		{
			name: "except Exception: return None",
			src: `def load(path):
    try:
        return parse(path)
    except Exception:
        return None
`,
			wantCount: 1,
		},
		{
			name: "except Exception: return {}",
			src: `def load_settings(path):
    try:
        return parse_settings(path)
    except Exception:
        return {}
`,
			wantCount: 1,
		},
		{
			name: "except Exception: return []",
			src: `def load_items(path):
    try:
        return parse_items(path)
    except Exception:
        return []
`,
			wantCount: 1,
		},
		{
			name: "except Exception with a comment-only line before the default return still swallows",
			src: `def load(path):
    try:
        return parse(path)
    except Exception:
        # fall back silently
        return None
`,
			wantCount: 1,
		},
		{
			name: "except with a specific exception type is out of this pattern's scope",
			src: `def load(path):
    try:
        return parse(path)
    except ValueError:
        return None
`,
			wantCount: 0,
		},
		{
			name: "bare except is out of this pattern's scope",
			src: `def load(path):
    try:
        return parse(path)
    except:
        return None
`,
			wantCount: 0,
		},
		{
			name: "except Exception that logs before returning a default is not a silent swallow",
			src: `def load(path):
    try:
        return parse(path)
    except Exception as e:
        logger.warning("using default config: %s", e)
        return None
`,
			wantCount: 0,
		},
		{
			name: "except Exception that returns a non-default sentinel is not this pattern's shape",
			src: `def load(path):
    try:
        return parse(path)
    except Exception:
        return -1
`,
			wantCount: 0,
		},
		{
			name: "except Exception that re-raises is not a swallow",
			src: `def load(path):
    try:
        return parse(path)
    except Exception:
        raise
`,
			wantCount: 0,
		},
	}

	d := detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := d.Detect("case.py", []byte(tt.src))
			if len(matches) != tt.wantCount {
				t.Fatalf("Detect() = %d matches, want %d; matches=%+v", len(matches), tt.wantCount, matches)
			}
			for _, m := range matches {
				if m.PatternID != patternID {
					t.Errorf("Match.PatternID = %q, want %q", m.PatternID, patternID)
				}
				if m.Category != patternCategory {
					t.Errorf("Match.Category = %q, want %q", m.Category, patternCategory)
				}
			}
		})
	}
}

// --- Rust: .unwrap_or_default() / .unwrap_or(Default::default()). ---

const dirtyRustSource = `use std::collections::HashMap;

fn load_config(raw: &str) -> HashMap<String, String> {
    parse_config(raw).unwrap_or_default()
}
`

const cleanRustSource = `use std::collections::HashMap;

fn load_config(raw: &str) -> Result<HashMap<String, String>, ConfigError> {
    parse_config(raw).map_err(ConfigError::Parse)
}
`

func TestDetect_RustUnwrapOrDefault_ProducesMatch(t *testing.T) {
	d := detector{}

	matches := d.Detect("src/config.rs", []byte(dirtyRustSource))

	if len(matches) != 1 {
		t.Fatalf("Detect() on dirty Rust fixture = %d matches, want 1; matches=%+v", len(matches), matches)
	}
	got := matches[0]
	if got.PatternID != patternID {
		t.Errorf("Match.PatternID = %q, want %q", got.PatternID, patternID)
	}
	if got.Category != patternCategory {
		t.Errorf("Match.Category = %q, want %q", got.Category, patternCategory)
	}
	if got.Path != "src/config.rs" {
		t.Errorf("Match.Path = %q, want %q", got.Path, "src/config.rs")
	}
	if got.Line != 4 {
		t.Errorf("Match.Line = %d, want 4 (the `.unwrap_or_default()` line)", got.Line)
	}
	if got.Message == "" {
		t.Error("Match.Message is empty, want a real explanation")
	}
}

func TestDetect_RustPropagatesResult_ProducesNoMatches(t *testing.T) {
	d := detector{}

	matches := d.Detect("src/config.rs", []byte(cleanRustSource))

	if len(matches) != 0 {
		t.Fatalf("Detect() on clean Rust fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

func TestDetect_RustTable(t *testing.T) {
	tests := []struct {
		name      string
		src       string
		wantCount int
	}{
		{
			name:      "unwrap_or_default",
			src:       "fn load(raw: &str) -> Settings {\n    parse(raw).unwrap_or_default()\n}\n",
			wantCount: 1,
		},
		{
			name:      "unwrap_or(Default::default())",
			src:       "fn load(raw: &str) -> Settings {\n    parse(raw).unwrap_or(Default::default())\n}\n",
			wantCount: 1,
		},
		{
			name:      "both forms in the same file are each flagged",
			src:       "fn load_a(raw: &str) -> Settings {\n    parse(raw).unwrap_or_default()\n}\n\nfn load_b(raw: &str) -> Options {\n    parse_opts(raw).unwrap_or(Default::default())\n}\n",
			wantCount: 2,
		},
		{
			name:      "unwrap_or with an explicit non-default fallback is not this pattern's shape",
			src:       "fn load(raw: &str) -> Settings {\n    parse(raw).unwrap_or(Settings::safe_mode())\n}\n",
			wantCount: 0,
		},
		{
			name:      "expect with a message is real error surfacing, not a silent default",
			src:       "fn load(raw: &str) -> Settings {\n    parse(raw).expect(\"config must parse\")\n}\n",
			wantCount: 0,
		},
	}

	d := detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := d.Detect("src/lib.rs", []byte(tt.src))
			if len(matches) != tt.wantCount {
				t.Fatalf("Detect() = %d matches, want %d; matches=%+v", len(matches), tt.wantCount, matches)
			}
			for _, m := range matches {
				if m.PatternID != patternID {
					t.Errorf("Match.PatternID = %q, want %q", m.PatternID, patternID)
				}
				if m.Category != patternCategory {
					t.Errorf("Match.Category = %q, want %q", m.Category, patternCategory)
				}
				if m.Severity != llmcheat.SeverityMedium {
					t.Errorf("Match.Severity = %q, want %q", m.Severity, llmcheat.SeverityMedium)
				}
			}
		})
	}
}

// TestDetect_NonTargetFileExtension proves the extension gate: identical
// dirty-shaped text in a file whose extension this pattern doesn't cover
// must not be flagged, for all three covered languages.
func TestDetect_NonTargetFileExtension(t *testing.T) {
	d := detector{}

	tests := []struct {
		name string
		src  string
	}{
		{name: "go-shaped", src: dirtyGoSource},
		{name: "python-shaped", src: dirtyPythonSource},
		{name: "rust-shaped", src: dirtyRustSource},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := d.Detect("notes.txt", []byte(tt.src))
			if len(matches) != 0 {
				t.Fatalf("Detect() on non-target extension = %d matches, want 0; matches=%+v", len(matches), matches)
			}
		})
	}
}

func TestPattern_IDAndCategory(t *testing.T) {
	d := detector{}

	if got := d.ID(); got != patternID {
		t.Errorf("ID() = %q, want %q", got, patternID)
	}
	if got := d.Category(); got != patternCategory {
		t.Errorf("Category() = %q, want %q", got, patternCategory)
	}
	if patternID != "silent-default-fallback-masks-failure" {
		t.Errorf("patternID const = %q, want %q", patternID, "silent-default-fallback-masks-failure")
	}
	if patternCategory != "complexity-and-surface-obfuscation" {
		t.Errorf("patternCategory const = %q, want %q", patternCategory, "complexity-and-surface-obfuscation")
	}
}
