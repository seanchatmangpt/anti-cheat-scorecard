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

package emptycatchswallow

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// dirtyPythonSource is a realistic multi-line Python module: a real helper
// alongside one function whose error handling is a bare `except Exception:
// pass` that discards the failure entirely.
const dirtyPythonSource = `import logging

logger = logging.getLogger(__name__)


def load_config(path):
    with open(path) as f:
        return f.read()


def do_work():
    try:
        risky()
    except Exception:
        pass
`

// cleanPythonSource is the same shape, but the exception handler actually
// logs the failure and re-raises it — real error handling, not a swallow.
const cleanPythonSource = `import logging

logger = logging.getLogger(__name__)


def do_work():
    try:
        risky()
    except Exception as e:
        logger.error("risky failed: %s", e)
        raise
`

func TestDetect_PythonBareExceptPass_ProducesMatch(t *testing.T) {
	d := detector{}

	matches := d.Detect("worker/do_work.py", []byte(dirtyPythonSource))

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
	if got.Path != "worker/do_work.py" {
		t.Errorf("Match.Path = %q, want %q", got.Path, "worker/do_work.py")
	}
	if got.Line != 14 {
		t.Errorf("Match.Line = %d, want 14 (the `except Exception:` line)", got.Line)
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

	matches := d.Detect("worker/do_work.py", []byte(cleanPythonSource))

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
			name: "bare except with pass",
			src: `try:
    risky()
except:
    pass
`,
			wantCount: 1,
		},
		{
			name: "except Exception with pass and a trailing inline comment still swallows",
			src: `try:
    risky()
except Exception:
    pass  # TODO: handle this properly
`,
			wantCount: 1,
		},
		{
			name: "except Exception with only a comment body still swallows",
			src: `try:
    risky()
except Exception:
    # ignore for now
    pass
`,
			wantCount: 1,
		},
		{
			name: "except with a specific exception type is out of this pattern's scope",
			src: `try:
    risky()
except ValueError:
    pass
`,
			wantCount: 0,
		},
		{
			name: "except Exception that re-raises is not a swallow",
			src: `try:
    risky()
except Exception:
    raise
`,
			wantCount: 0,
		},
		{
			name: "except Exception that logs before passing is not a swallow",
			src: `try:
    risky()
except Exception:
    logger.warning("ignoring known-flaky risky()")
    pass
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
		})
	}
}

func TestDetect_JS(t *testing.T) {
	tests := []struct {
		name      string
		src       string
		wantCount int
	}{
		{
			name: "empty catch with a bound param",
			src: `function doWork() {
  try {
    risky();
  } catch (e) {}
}
`,
			wantCount: 1,
		},
		{
			name: "empty catch with no param, body on its own line",
			src: `function doWork() {
  try {
    risky();
  } catch {
  }
}
`,
			wantCount: 1,
		},
		{
			name: "catch body containing only a comment still swallows",
			src: `function doWork() {
  try {
    risky();
  } catch (e) {
    // ignore for now
  }
}
`,
			wantCount: 1,
		},
		{
			name: "catch that logs and rethrows is not a swallow",
			src: `function doWork() {
  try {
    risky();
  } catch (e) {
    console.error('risky failed', e);
    throw e;
  }
}
`,
			wantCount: 0,
		},
		{
			name: "promise .catch with an empty arrow body",
			src: `fetchThing().catch(() => {});
`,
			wantCount: 1,
		},
		{
			name: "promise .catch with a single-param empty arrow body",
			src: `fetchThing().catch(err => {});
`,
			wantCount: 1,
		},
		{
			name: "promise .catch that actually logs the error is not a swallow",
			src: `fetchThing().catch((err) => { logError(err); });
`,
			wantCount: 0,
		},
		{
			name: "an identifier merely containing catch is not matched",
			src: `const catchAllHandler = buildHandler();
`,
			wantCount: 0,
		},
	}

	d := detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := d.Detect("case.js", []byte(tt.src))
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

// TestDetect_TypeScriptExtensionAlsoScanned proves the JS-shaped detection
// also runs on a .ts file, since the pattern is defined over JS/TS syntax
// generically.
func TestDetect_TypeScriptExtensionAlsoScanned(t *testing.T) {
	d := detector{}
	const src = `async function load(): Promise<void> {
  try {
    await risky();
  } catch (e: unknown) {}
}
`
	matches := d.Detect("worker.ts", []byte(src))
	if len(matches) != 1 {
		t.Fatalf("Detect() on .ts fixture = %d matches, want 1; matches=%+v", len(matches), matches)
	}
}

func TestDetect_Go(t *testing.T) {
	tests := []struct {
		name      string
		src       string
		wantCount int
	}{
		{
			name: "empty if err block",
			src: `package worker

func do() error {
	err := risky()
	if err != nil {
	}
	return nil
}
`,
			wantCount: 1,
		},
		{
			name: "if err block containing only a comment still swallows",
			src: `package worker

func do() error {
	err := risky()
	if err != nil {
		// ignore for now
	}
	return nil
}
`,
			wantCount: 1,
		},
		{
			name: "if err block that returns the error is not a swallow",
			src: `package worker

func do() error {
	err := risky()
	if err != nil {
		return err
	}
	return nil
}
`,
			wantCount: 0,
		},
		{
			name: "if err block that logs before continuing is not a swallow",
			src: `package worker

func do() error {
	err := risky()
	if err != nil {
		log.Printf("risky failed: %v", err)
	}
	return nil
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
			}
		})
	}
}

// TestDetect_NonTargetFileExtension proves the extension gate: identical
// dirty-shaped text in a file whose extension this pattern doesn't cover
// must not be flagged.
func TestDetect_NonTargetFileExtension(t *testing.T) {
	d := detector{}

	matches := d.Detect("notes.txt", []byte("except Exception:\n    pass\n"))

	if len(matches) != 0 {
		t.Fatalf("Detect() on non-target extension = %d matches, want 0; matches=%+v", len(matches), matches)
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
	if patternID != "empty-catch-swallow" {
		t.Errorf("patternID const = %q, want %q", patternID, "empty-catch-swallow")
	}
	if patternCategory != "hollow-implementation" {
		t.Errorf("patternCategory const = %q, want %q", patternCategory, "hollow-implementation")
	}
}
