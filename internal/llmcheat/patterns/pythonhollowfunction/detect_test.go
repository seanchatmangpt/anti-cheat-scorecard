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

package pythonhollowfunction

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// d is the same real detector Register() wires up in init(); constructing it
// directly here lets the test call Detect() with no global registry
// involvement, per the Chicago-style "real collaborator, no mocking" rule —
// detector has no collaborators to mock in the first place.
var d = detector{}

func TestDetect_HollowFunctions_AreFlagged(t *testing.T) {
	src := []byte(`"""Billing helpers module."""


def compute(x):
    pass


def apply_discount(total, pct):
    ...


def refund(order_id: str, amount: float) -> None:
    """Issue a refund for the given order.

    Args:
        order_id: the order to refund.
        amount: the amount to refund, in cents.
    """
    pass


def one_liner_stub(x):
    ...
`)

	matches := d.Detect("billing/helpers.py", src)

	if len(matches) != 4 {
		t.Fatalf("expected 4 matches, got %d: %+v", len(matches), matches)
	}

	wantLines := map[uint]bool{4: false, 8: false, 12: false, 22: false}
	for _, m := range matches {
		if m.PatternID != "python-hollow-function" {
			t.Errorf("match at line %d: PatternID = %q, want %q", m.Line, m.PatternID, "python-hollow-function")
		}
		if m.Category != "hollow-implementation" {
			t.Errorf("match at line %d: Category = %q, want %q", m.Line, m.Category, "hollow-implementation")
		}
		if m.Path != "billing/helpers.py" {
			t.Errorf("match at line %d: Path = %q, want %q", m.Line, m.Path, "billing/helpers.py")
		}
		if _, known := wantLines[m.Line]; !known {
			t.Errorf("unexpected match line %d (matches: %+v)", m.Line, matches)
			continue
		}
		wantLines[m.Line] = true
	}
	for line, seen := range wantLines {
		if !seen {
			t.Errorf("expected a match anchored at line %d, none found (matches: %+v)", line, matches)
		}
	}
}

func TestDetect_RealImplementations_AreClean(t *testing.T) {
	src := []byte(`"""Billing helpers module."""


def compute(x):
    return x * 2


def apply_discount(total, pct):
    if pct < 0 or pct > 100:
        raise ValueError("pct out of range")
    return total * (1 - pct / 100)


def refund(order_id: str, amount: float) -> None:
    """Issue a refund for the given order."""
    ledger.record(order_id, -amount)
    notify_customer(order_id, amount)
`)

	matches := d.Detect("billing/helpers.py", src)

	if len(matches) != 0 {
		t.Fatalf("expected 0 matches for real implementations, got %d: %+v", len(matches), matches)
	}
}

func TestDetect_ProtocolAndABCMethodStubs_AreExempt(t *testing.T) {
	src := []byte(`from typing import Protocol
import abc


class Greeter(Protocol):
    def greet(self, name: str) -> str:
        ...

    def farewell(self, name: str) -> str:
        """Say goodbye to name."""
        ...


class Repository(abc.ABC):
    @abc.abstractmethod
    def save(self, record):
        pass


class ConcreteRepository(Repository):
    def save(self, record):
        pass
`)

	matches := d.Detect("interfaces.py", src)

	if len(matches) != 1 {
		t.Fatalf("expected exactly 1 match (only the ConcreteRepository.save stub is real code), got %d: %+v", len(matches), matches)
	}
	if matches[0].PatternID != "python-hollow-function" || matches[0].Category != "hollow-implementation" {
		t.Errorf("unexpected match shape: %+v", matches[0])
	}
	// ConcreteRepository does NOT declare Protocol/ABC bases, so its "save"
	// override — even though it shadows an abstract method — is a real,
	// checkable function body and correctly still gets flagged when hollow.
	const wantLine = 21
	if matches[0].Line != wantLine {
		t.Errorf("match line = %d, want %d (ConcreteRepository.save)", matches[0].Line, wantLine)
	}
}

func TestDetect_DocstringOnlyBody_IsNotFlagged(t *testing.T) {
	// A docstring with no trailing pass/... is NOT one of the three hollow
	// shapes the pattern targets (bare pass, bare ..., or docstring+pass/...)
	// — it is syntactically valid on its own and deliberately out of scope
	// per the pattern description's exact three shapes.
	src := []byte(`def compute(x):
    """TODO: implement this."""
`)

	matches := d.Detect("todo.py", src)

	if len(matches) != 0 {
		t.Fatalf("expected 0 matches for a docstring-only body, got %d: %+v", len(matches), matches)
	}
}

func TestDetect_NonPythonFile_IsIgnored(t *testing.T) {
	src := []byte("def compute(x):\n    pass\n")

	matches := d.Detect("billing/helpers.rs", src)

	if len(matches) != 0 {
		t.Fatalf("expected 0 matches for a non-.py path, got %d: %+v", len(matches), matches)
	}
}

func TestDetect_IDAndCategory(t *testing.T) {
	if got := d.ID(); got != "python-hollow-function" {
		t.Errorf("ID() = %q, want %q", got, "python-hollow-function")
	}
	if got := d.Category(); got != "hollow-implementation" {
		t.Errorf("Category() = %q, want %q", got, "hollow-implementation")
	}
}

// Compile-time assertion that detector really implements llmcheat.Pattern —
// mirrors the interface contract without needing the global registry.
var _ llmcheat.Pattern = detector{}
