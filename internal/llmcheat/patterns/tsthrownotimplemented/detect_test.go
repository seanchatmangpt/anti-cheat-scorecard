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

package tsthrownotimplemented

import (
	"strings"
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// dirtyDoubleQuoted expands the assignment's one-line dirty example into a
// realistic multi-line TypeScript module: a real export, a real signature,
// and a hollowed-out body.
const dirtyDoubleQuoted = `import { Record } from "./types";

export class RecordStore {
  save(record: Record): void {
    throw new Error("not implemented");
  }
}
`

// cleanImplementation expands the assignment's one-line clean example the
// same way: a real function that actually does the work its signature
// promises.
const cleanImplementation = `import { db } from "./db";
import { Record } from "./types";

export class RecordStore {
  save(record: Record): void {
    return db.write(record);
  }
}
`

func TestDetect_DirtyThrowNotImplemented_ProducesMatch(t *testing.T) {
	d := newDetector()

	matches := d.Detect("src/store.ts", []byte(dirtyDoubleQuoted))

	if len(matches) < 1 {
		t.Fatalf("Detect() = %d matches, want >= 1 for a stubbed throw new Error(\"not implemented\") body", len(matches))
	}
	for _, m := range matches {
		if m.PatternID != "typescript-throw-not-implemented" {
			t.Errorf("match.PatternID = %q, want %q", m.PatternID, "typescript-throw-not-implemented")
		}
		if m.Category != "hollow-implementation" {
			t.Errorf("match.Category = %q, want %q", m.Category, "hollow-implementation")
		}
	}

	// The dirty fixture's throw is on line 5 (1-based): blank, import,
	// blank, class, save signature, throw.
	if got, want := matches[0].Line, uint(5); got != want {
		t.Errorf("match.Line = %d, want %d", got, want)
	}
	if matches[0].Severity != llmcheat.SeverityHigh {
		t.Errorf("match.Severity = %q, want %q for an explicit \"not implemented\" message", matches[0].Severity, llmcheat.SeverityHigh)
	}
	if matches[0].Path != "src/store.ts" {
		t.Errorf("match.Path = %q, want %q", matches[0].Path, "src/store.ts")
	}
}

func TestDetect_CleanImplementation_ProducesZeroMatches(t *testing.T) {
	d := newDetector()

	matches := d.Detect("src/store.ts", []byte(cleanImplementation))

	if len(matches) != 0 {
		t.Fatalf("Detect() = %d matches, want 0 for a real implementation; got %+v", len(matches), matches)
	}
}

func TestDetect_SingleQuotedAndCaseInsensitive(t *testing.T) {
	d := newDetector()

	src := `function load(id: string) {
  throw new Error('NOT Implemented');
}
`
	matches := d.Detect("src/loader.tsx", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() = %d matches, want 1 for a single-quoted, mixed-case match; got %+v", len(matches), matches)
	}
	if matches[0].Line != 2 {
		t.Errorf("match.Line = %d, want 2", matches[0].Line)
	}
}

func TestDetect_TodoVariant_ProducesMediumSeverityMatch(t *testing.T) {
	d := newDetector()

	src := `export function render(props: Props): JSX.Element {
  throw new Error("TODO: wire up the real renderer");
}
`
	matches := d.Detect("src/render.jsx", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() = %d matches, want 1 for the TODO variant; got %+v", len(matches), matches)
	}
	if matches[0].Severity != llmcheat.SeverityMedium {
		t.Errorf("match.Severity = %q, want %q for a TODO-only message", matches[0].Severity, llmcheat.SeverityMedium)
	}
	if !strings.Contains(matches[0].Message, "TODO") {
		t.Errorf("match.Message = %q, want it to quote the TODO message text", matches[0].Message)
	}
}

func TestDetect_TestFilePaths_AreExempt(t *testing.T) {
	d := newDetector()

	testPaths := []string{
		"src/store.test.ts",
		"src/store.spec.ts",
		"test/store.ts",
		"src/__tests__/store.ts",
	}

	for _, path := range testPaths {
		t.Run(path, func(t *testing.T) {
			matches := d.Detect(path, []byte(dirtyDoubleQuoted))
			if len(matches) != 0 {
				t.Errorf("Detect(%q, dirty) = %d matches, want 0 — test-shaped paths are exempt", path, len(matches))
			}
		})
	}
}

func TestDetect_NonTypeScriptFile_IsIgnored(t *testing.T) {
	d := newDetector()

	matches := d.Detect("src/store.py", []byte(`raise NotImplementedError("not implemented")`))

	if len(matches) != 0 {
		t.Fatalf("Detect() on a .py file = %d matches, want 0 — pattern is TS/JS-only", len(matches))
	}
}

func TestDetect_PatternIdentity(t *testing.T) {
	d := newDetector()

	if got, want := d.ID(), "typescript-throw-not-implemented"; got != want {
		t.Errorf("ID() = %q, want %q", got, want)
	}
	if got, want := d.Category(), "hollow-implementation"; got != want {
		t.Errorf("Category() = %q, want %q", got, want)
	}
}
