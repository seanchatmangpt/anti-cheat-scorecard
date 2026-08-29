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

package contractsignaturedrift

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// d is the same real detector Register() wires up in init(); constructing it
// directly here lets the test call Detect() with no global registry
// involvement, per the Chicago-style "real collaborator, no mocking" rule —
// detector has no collaborators to mock in the first place.
var d = detector{}

func TestDetect_GoogleArgsDrift_ProducesMatch(t *testing.T) {
	src := []byte(`def process(data):
    """Args:
        data: input
        options: config dict
    """
    return data
`)

	matches := d.Detect("pkg/process.py", src)

	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
	got := matches[0]
	if got.PatternID != "contract-signature-drift" {
		t.Errorf("PatternID = %q, want %q", got.PatternID, "contract-signature-drift")
	}
	if got.Category != "determinism-and-provenance-violation" {
		t.Errorf("Category = %q, want %q", got.Category, "determinism-and-provenance-violation")
	}
	if got.Path != "pkg/process.py" {
		t.Errorf("Path = %q, want %q", got.Path, "pkg/process.py")
	}
	if got.Line != 4 {
		t.Errorf("Line = %d, want 4 (the \"options: config dict\" docstring line)", got.Line)
	}
}

func TestDetect_GoogleArgsMatchingSignature_NoMatches(t *testing.T) {
	src := []byte(`def process(data, options):
    """Args:
        data: input
        options: config dict
    """
    return data
`)

	matches := d.Detect("pkg/process.py", src)

	if len(matches) != 0 {
		t.Fatalf("expected 0 matches for a signature that matches its docstring, got %d: %+v", len(matches), matches)
	}
}

func TestDetect_SphinxParamDrift_ProducesMatch(t *testing.T) {
	src := []byte(`def compute(total, rate):
    """Compute a total.

    :param total: base amount
    :param rate: interest rate
    :param currency: ISO currency code
    """
    return total * rate
`)

	matches := d.Detect("pkg/billing.py", src)

	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d: %+v", len(matches), matches)
	}
	got := matches[0]
	if got.PatternID != "contract-signature-drift" {
		t.Errorf("PatternID = %q, want %q", got.PatternID, "contract-signature-drift")
	}
	if got.Category != "determinism-and-provenance-violation" {
		t.Errorf("Category = %q, want %q", got.Category, "determinism-and-provenance-violation")
	}
	if got.Line != 6 {
		t.Errorf("Line = %d, want 6 (the \":param currency:\" docstring line)", got.Line)
	}
}

func TestDetect_SphinxParamMatchingSignature_NoMatches(t *testing.T) {
	src := []byte(`def compute(total, rate, currency):
    """Compute a total.

    :param total: base amount
    :param rate: interest rate
    :param currency: ISO currency code
    """
    return total * rate
`)

	matches := d.Detect("pkg/billing.py", src)

	if len(matches) != 0 {
		t.Fatalf("expected 0 matches for a signature that matches its :param: directives, got %d: %+v", len(matches), matches)
	}
}

// TestDetect_KwargsCatchAll_NoFalsePositive covers the one deliberate
// allowlisted exception named in the package doc comment: a "**kwargs"
// catch-all parameter legitimately absorbs individually documented keyword
// names that can never literally match a fixed positional/keyword parameter
// name in the signature, so this must never be flagged as drift.
func TestDetect_KwargsCatchAll_NoFalsePositive(t *testing.T) {
	src := []byte(`def configure(name, **kwargs):
    """Configure a resource.

    Args:
        name: resource name
        timeout: optional timeout override
        retries: optional retry count
    """
    return name
`)

	matches := d.Detect("pkg/configure.py", src)

	if len(matches) != 0 {
		t.Fatalf("expected 0 matches for a **kwargs catch-all function, got %d: %+v", len(matches), matches)
	}
}

// TestDetect_NonPythonFile_Ignored covers the file-type gate: the exact
// dirty fixture shape must produce zero matches when the path is not a
// .py file, since this pattern's contract keys specifically off Python
// def/docstring grammar.
func TestDetect_NonPythonFile_Ignored(t *testing.T) {
	src := []byte(`def process(data):
    """Args:
        data: input
        options: config dict
    """
    return data
`)

	matches := d.Detect("notes/process.py.txt", src)

	if len(matches) != 0 {
		t.Fatalf("expected 0 matches for a non-.py path, got %d: %+v", len(matches), matches)
	}
}

// TestDetect_MultipleFunctions_OnlyDriftedOneFlagged proves the scanner
// correctly evaluates each function in a file independently: a clean
// function ahead of a drifted one must not suppress or corrupt the
// drifted one's match, and the clean function must contribute no matches
// of its own.
func TestDetect_MultipleFunctions_OnlyDriftedOneFlagged(t *testing.T) {
	src := []byte(`def clean(a, b):
    """Args:
        a: left operand
        b: right operand
    """
    return a + b


def dirty(a):
    """Args:
        a: left operand
        b: right operand
    """
    return a
`)

	matches := d.Detect("pkg/mixed.py", src)

	if len(matches) != 1 {
		t.Fatalf("expected exactly 1 match (from dirty only), got %d: %+v", len(matches), matches)
	}
	if matches[0].Message == "" {
		t.Error("expected a non-empty Message explaining the drift")
	}
	if want := uint(12); matches[0].Line != want {
		t.Errorf("Line = %d, want %d (the \"b: right operand\" line inside dirty's docstring)", matches[0].Line, want)
	}

	var llmSeverity llmcheat.Severity = matches[0].Severity
	if llmSeverity == "" {
		t.Error("expected a non-empty Severity")
	}
}
