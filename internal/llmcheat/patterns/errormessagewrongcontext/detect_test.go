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

package errormessagewrongcontext

import (
	"strings"
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// goDirtySource is a realistic Go file: computeTotal's own error message
// mentions "parseInput" — a different function's name, never defined here —
// exactly the copy-pasted-from-elsewhere shape this pattern targets.
const goDirtySource = `package billing

import "errors"

// computeTotal sums the line items and validates the result.
func computeTotal(items []int) (int, error) {
	total := 0
	for _, v := range items {
		total += v
	}
	if total < 0 {
		return 0, errors.New("parseInput failed")
	}
	return total, nil
}
`

// goCleanSource is the same function with its error message correctly
// naming itself instead of a different function.
const goCleanSource = `package billing

import "errors"

// computeTotal sums the line items and validates the result.
func computeTotal(items []int) (int, error) {
	total := 0
	for _, v := range items {
		total += v
	}
	if total < 0 {
		return 0, errors.New("computeTotal: invalid input")
	}
	return total, nil
}
`

func TestDetect_GoDirty_ProducesMatch(t *testing.T) {
	d := detector{}

	matches := d.Detect("billing/total.go", []byte(goDirtySource))

	if len(matches) < 1 {
		t.Fatalf("Detect() on Go dirty fixture = %d matches, want >= 1", len(matches))
	}

	got := matches[0]
	if got.PatternID != patternID {
		t.Errorf("Match.PatternID = %q, want %q", got.PatternID, patternID)
	}
	if got.Category != patternCategory {
		t.Errorf("Match.Category = %q, want %q", got.Category, patternCategory)
	}
	if got.Path != "billing/total.go" {
		t.Errorf("Match.Path = %q, want %q", got.Path, "billing/total.go")
	}

	wantLine := uint(0)
	for i, line := range strings.Split(goDirtySource, "\n") {
		if strings.Contains(line, `errors.New("parseInput`) {
			wantLine = uint(i + 1)
			break
		}
	}
	if wantLine == 0 {
		t.Fatal("test fixture bug: goDirtySource does not contain the expected errors.New(\"parseInput literal")
	}
	if got.Line != wantLine {
		t.Errorf("Match.Line = %d, want %d", got.Line, wantLine)
	}
	if got.Message == "" {
		t.Error("Match.Message is empty, want a real explanation")
	}
	if !strings.Contains(got.Message, "parseInput") {
		t.Errorf("Match.Message = %q, want it to name the mismatched token %q", got.Message, "parseInput")
	}
	if !strings.Contains(got.Message, "computeTotal") {
		t.Errorf("Match.Message = %q, want it to name the enclosing function %q", got.Message, "computeTotal")
	}
}

func TestDetect_GoClean_ProducesNoMatches(t *testing.T) {
	d := detector{}

	matches := d.Detect("billing/total.go", []byte(goCleanSource))

	if len(matches) != 0 {
		t.Fatalf("Detect() on Go clean fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

// pyDirtySource is a realistic Python file where compute_total's raise
// mentions "parse_input" — a different function's name.
const pyDirtySource = `def compute_total(items):
    total = 0
    for item in items:
        total += item
    if total < 0:
        raise ValueError("parse_input failed: negative total")
    return total
`

// pyCleanSource is the same function with a self-referencing message.
const pyCleanSource = `def compute_total(items):
    total = 0
    for item in items:
        total += item
    if total < 0:
        raise ValueError("compute_total: total must not be negative")
    return total
`

func TestDetect_PythonDirty_ProducesMatch(t *testing.T) {
	d := detector{}

	matches := d.Detect("billing/total.py", []byte(pyDirtySource))

	if len(matches) != 1 {
		t.Fatalf("Detect() on Python dirty fixture = %d matches, want 1; matches=%+v", len(matches), matches)
	}
	if matches[0].PatternID != patternID {
		t.Errorf("Match.PatternID = %q, want %q", matches[0].PatternID, patternID)
	}
	if !strings.Contains(matches[0].Message, "parse_input") {
		t.Errorf("Match.Message = %q, want it to name the mismatched token %q", matches[0].Message, "parse_input")
	}
}

func TestDetect_PythonClean_ProducesNoMatches(t *testing.T) {
	d := detector{}

	matches := d.Detect("billing/total.py", []byte(pyCleanSource))

	if len(matches) != 0 {
		t.Fatalf("Detect() on Python clean fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

// tsDirtySource is a realistic TypeScript arrow-function file whose thrown
// Error mentions "parseInput" — a different function's name.
const tsDirtySource = `const computeTotal = (items: number[]): number => {
  let total = 0;
  for (const item of items) {
    total += item;
  }
  if (total < 0) {
    throw new Error("parseInput failed");
  }
  return total;
};
`

// tsCleanSource is the same function with a self-referencing message.
const tsCleanSource = `const computeTotal = (items: number[]): number => {
  let total = 0;
  for (const item of items) {
    total += item;
  }
  if (total < 0) {
    throw new Error("computeTotal: total must not be negative");
  }
  return total;
};
`

func TestDetect_TypeScriptDirty_ProducesMatch(t *testing.T) {
	d := detector{}

	matches := d.Detect("billing/total.ts", []byte(tsDirtySource))

	if len(matches) != 1 {
		t.Fatalf("Detect() on TypeScript dirty fixture = %d matches, want 1; matches=%+v", len(matches), matches)
	}
	if matches[0].Category != patternCategory {
		t.Errorf("Match.Category = %q, want %q", matches[0].Category, patternCategory)
	}
	if !strings.Contains(matches[0].Message, "parseInput") {
		t.Errorf("Match.Message = %q, want it to name the mismatched token %q", matches[0].Message, "parseInput")
	}
}

func TestDetect_TypeScriptClean_ProducesNoMatches(t *testing.T) {
	d := detector{}

	matches := d.Detect("billing/total.ts", []byte(tsCleanSource))

	if len(matches) != 0 {
		t.Fatalf("Detect() on TypeScript clean fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

// goPanicDirtySource exercises the fourth named call shape (panic(...))
// with the mismatched identifier appearing before a "(" in the message
// text, mirroring the "doThing(" example from the pattern spec.
const goPanicDirtySource = `package server

// startServer boots the listener or panics on a fatal misconfiguration.
func startServer() {
	if cfg == nil {
		panic("loadConfig() must be called before startServer")
	}
}
`

func TestDetect_GoPanicDirty_ProducesMatch(t *testing.T) {
	d := detector{}

	matches := d.Detect("server/main.go", []byte(goPanicDirtySource))

	if len(matches) != 1 {
		t.Fatalf("Detect() on Go panic dirty fixture = %d matches, want 1; matches=%+v", len(matches), matches)
	}
	if !strings.Contains(matches[0].Message, "loadConfig") {
		t.Errorf("Match.Message = %q, want it to name the mismatched token %q", matches[0].Message, "loadConfig")
	}
}

// goPlainEnglishSource is the boundary case this pattern must NOT flag:
// the enclosing function's name differs from nothing in particular because
// the message is ordinary English prose with no camelCase/snake_case token
// at all. A detector that flagged every mismatched function name regardless
// of message content would be far too noisy to be useful.
const goPlainEnglishSource = `package server

func startServer() {
	if cfg == nil {
		panic("configuration must not be nil")
	}
}
`

func TestDetect_PlainEnglishMessage_ProducesNoMatches(t *testing.T) {
	d := detector{}

	matches := d.Detect("server/main.go", []byte(goPlainEnglishSource))

	if len(matches) != 0 {
		t.Fatalf("Detect() on plain-English fixture = %d matches, want 0; matches=%+v", len(matches), matches)
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
	if got := d.ID(); got != "error-message-wrong-context" {
		t.Errorf("ID() = %q, want %q", got, "error-message-wrong-context")
	}
	if got := d.Category(); got != "complexity-and-surface-obfuscation" {
		t.Errorf("Category() = %q, want %q", got, "complexity-and-surface-obfuscation")
	}
}

// TestDetect_TypeAssertsPattern proves detector genuinely satisfies the
// llmcheat.Pattern interface (compile-time-checkable, but asserted here too
// so a future refactor that breaks the interface fails loudly in `go test`
// output, not just in some other package's build).
func TestDetect_TypeAssertsPattern(t *testing.T) {
	var _ llmcheat.Pattern = detector{}
}
