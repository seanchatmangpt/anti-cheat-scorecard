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

package jsjestmockowned

import (
	"strings"
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// dirtyMockedService expands the assignment's one-line dirty example
// (`jest.mock("./service");`) into a realistic multi-line Jest test: the
// whole ./service module is replaced wholesale, and the assertion is
// entirely interaction-based ("was save called with X"), never touching
// real returned/persisted state.
const dirtyMockedService = `import { save } from "./service";

jest.mock("./service");

describe("save", () => {
  it("calls the service", () => {
    save({ id: 1 });
    expect(save).toHaveBeenCalledWith({ id: 1 });
  });
});
`

// dirtyJestFn is a second dirty shape: no whole-module jest.mock(...), but
// an ad hoc jest.fn() mock function standing in for a real collaborator.
const dirtyJestFn = `import { RecordStore } from "./store";

describe("RecordStore", () => {
  it("writes a record", () => {
    const write = jest.fn();
    const store = new RecordStore(write);

    store.save({ id: 1 });

    expect(write).toHaveBeenCalled();
  });
});
`

// cleanRealCollaborator expands the assignment's one-line clean example
// (`const svc = new RealService(tmpDir);`) into a realistic multi-line
// Jest test that exercises a real, codebase-owned collaborator and asserts
// on its real returned/persisted state instead of an interaction.
const cleanRealCollaborator = `import { mkdtempSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { RealService } from "./service";

describe("RealService", () => {
  it("persists a record for real", () => {
    const tmpDir = mkdtempSync(join(tmpdir(), "svc-"));
    const svc = new RealService(tmpDir);

    svc.save({ id: 1 });

    expect(svc.load(1)).toEqual({ id: 1 });
  });
});
`

func TestDetect_DirtyJestMock_ProducesMatch(t *testing.T) {
	d := newDetector()

	matches := d.Detect("src/service.test.ts", []byte(dirtyMockedService))

	if len(matches) < 1 {
		t.Fatalf("Detect() = %d matches, want >= 1 for a jest.mock(...) call", len(matches))
	}
	for _, m := range matches {
		if m.PatternID != "js-jest-mock-owned" {
			t.Errorf("match.PatternID = %q, want %q", m.PatternID, "js-jest-mock-owned")
		}
		if m.Category != "test-integrity-violation" {
			t.Errorf("match.Category = %q, want %q", m.Category, "test-integrity-violation")
		}
	}

	// jest.mock("./service"); is on line 3 (1-based): blank import line,
	// blank, then the mock call.
	if got, want := matches[0].Line, uint(3); got != want {
		t.Errorf("match.Line = %d, want %d", got, want)
	}
	if matches[0].Severity != llmcheat.SeverityHigh {
		t.Errorf("match.Severity = %q, want %q for jest.mock(...)", matches[0].Severity, llmcheat.SeverityHigh)
	}
	if matches[0].Path != "src/service.test.ts" {
		t.Errorf("match.Path = %q, want %q", matches[0].Path, "src/service.test.ts")
	}
	if !strings.Contains(matches[0].Message, "jest.mock") {
		t.Errorf("match.Message = %q, want it to mention jest.mock", matches[0].Message)
	}
}

func TestDetect_DirtyJestFn_ProducesMediumSeverityMatch(t *testing.T) {
	d := newDetector()

	matches := d.Detect("src/store.test.ts", []byte(dirtyJestFn))

	if len(matches) != 1 {
		t.Fatalf("Detect() = %d matches, want 1 for a single jest.fn() call; got %+v", len(matches), matches)
	}
	if matches[0].PatternID != "js-jest-mock-owned" {
		t.Errorf("match.PatternID = %q, want %q", matches[0].PatternID, "js-jest-mock-owned")
	}
	if matches[0].Category != "test-integrity-violation" {
		t.Errorf("match.Category = %q, want %q", matches[0].Category, "test-integrity-violation")
	}
	if matches[0].Severity != llmcheat.SeverityMedium {
		t.Errorf("match.Severity = %q, want %q for jest.fn()", matches[0].Severity, llmcheat.SeverityMedium)
	}
	// const write = jest.fn(); is line 5 (1-based).
	if got, want := matches[0].Line, uint(5); got != want {
		t.Errorf("match.Line = %d, want %d", got, want)
	}
}

func TestDetect_CleanRealCollaborator_ProducesZeroMatches(t *testing.T) {
	d := newDetector()

	matches := d.Detect("src/service.test.ts", []byte(cleanRealCollaborator))

	if len(matches) != 0 {
		t.Fatalf("Detect() = %d matches, want 0 for a real collaborator with state-based assertions; got %+v", len(matches), matches)
	}
}

func TestDetect_MultipleCallsOnOneLine_ProducesOneMatchEach(t *testing.T) {
	d := newDetector()

	src := `jest.mock("./a"); jest.mock("./b");
`
	matches := d.Detect("src/multi.test.js", []byte(src))

	if len(matches) != 2 {
		t.Fatalf("Detect() = %d matches, want 2 for two jest.mock(...) calls on one line; got %+v", len(matches), matches)
	}
	for _, m := range matches {
		if m.Line != 1 {
			t.Errorf("match.Line = %d, want 1", m.Line)
		}
	}
}

func TestDetect_TestFilePathVariants_AreDetected(t *testing.T) {
	d := newDetector()

	testPaths := []string{
		"src/service.test.ts",
		"src/service.spec.ts",
		"src/service.test.js",
		"src/service.spec.js",
		"test/service.ts",
		"src/__tests__/service.js",
	}

	for _, path := range testPaths {
		t.Run(path, func(t *testing.T) {
			matches := d.Detect(path, []byte(`jest.mock("./service");`))
			if len(matches) != 1 {
				t.Errorf("Detect(%q, dirty) = %d matches, want 1", path, len(matches))
			}
		})
	}
}

func TestDetect_NonTestFile_IsIgnored(t *testing.T) {
	d := newDetector()

	// jest.mock(...) sitting in a plain, non-test-shaped source file is
	// out of this pattern's scope — it only inspects JS/TS test files.
	matches := d.Detect("src/service.ts", []byte(`jest.mock("./service");`))

	if len(matches) != 0 {
		t.Fatalf("Detect() on a non-test file = %d matches, want 0; got %+v", len(matches), matches)
	}
}

func TestDetect_NonJSExtension_IsIgnored(t *testing.T) {
	d := newDetector()

	// Same dirty-shaped content, but in a file extension this pattern
	// doesn't inspect at all (jest is JS/TS-specific tooling).
	matches := d.Detect("test/service.py", []byte(`jest.mock("./service")`))

	if len(matches) != 0 {
		t.Fatalf("Detect() on a .py file = %d matches, want 0 — pattern is JS/TS-only", len(matches))
	}
}

func TestDetect_PatternIdentity(t *testing.T) {
	d := newDetector()

	if got, want := d.ID(), "js-jest-mock-owned"; got != want {
		t.Errorf("ID() = %q, want %q", got, want)
	}
	if got, want := d.Category(), "test-integrity-violation"; got != want {
		t.Errorf("Category() = %q, want %q", got, want)
	}
}
