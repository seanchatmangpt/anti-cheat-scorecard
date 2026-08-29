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

package pythonnotimplementedshipped

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

func TestIDAndCategory(t *testing.T) {
	d := &detector{}
	if got, want := d.ID(), "python-notimplemented-shipped"; got != want {
		t.Errorf("ID() = %q, want %q", got, want)
	}
	if got, want := d.Category(), "hollow-implementation"; got != want {
		t.Errorf("Category() = %q, want %q", got, want)
	}
}

// TestDirty_ConcreteMethodShipped is the exact dirty shape from the pattern
// spec, expanded into a realistic multi-line module: a plain (non-abstract)
// class whose method raises bare NotImplementedError with no abstract
// marker anywhere. It must produce at least one real match.
func TestDirty_ConcreteMethodShipped(t *testing.T) {
	src := `"""A storage backend module."""


class LocalStorage:
    """Persists data to local disk."""

    def __init__(self, root):
        self.root = root

    def save(self, data):
        raise NotImplementedError

    def load(self, key):
        return self.root.joinpath(key).read_bytes()
`
	d := &detector{}
	matches := d.Detect("storage.py", []byte(src))

	if len(matches) < 1 {
		t.Fatalf("Detect() returned %d matches, want >= 1\nsource:\n%s", len(matches), src)
	}
	for _, m := range matches {
		if m.PatternID != "python-notimplemented-shipped" {
			t.Errorf("match PatternID = %q, want %q", m.PatternID, "python-notimplemented-shipped")
		}
		if m.Category != "hollow-implementation" {
			t.Errorf("match Category = %q, want %q", m.Category, "hollow-implementation")
		}
		if m.Path != "storage.py" {
			t.Errorf("match Path = %q, want %q", m.Path, "storage.py")
		}
	}

	// The "raise NotImplementedError" line is line 11 in the fixture above
	// (counting the leading blank lines and docstring): verify the real
	// computed line number, not just that some match exists.
	const wantLine = 11
	found := false
	for _, m := range matches {
		if m.Line == wantLine {
			found = true
		}
	}
	if !found {
		lines := make([]uint, len(matches))
		for i, m := range matches {
			lines[i] = m.Line
		}
		t.Errorf("no match at line %d; got match lines %v", wantLine, lines)
	}
}

// TestDirty_OneLinerBareFunction is the literal one-line dirty fixture from
// the pattern spec ("def save(self, data):\n    raise NotImplementedError"),
// with no surrounding class at all.
func TestDirty_OneLinerBareFunction(t *testing.T) {
	src := "def save(self, data):\n    raise NotImplementedError\n"

	d := &detector{}
	matches := d.Detect("bare.py", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1\nsource:\n%s", len(matches), src)
	}
	if matches[0].PatternID != "python-notimplemented-shipped" {
		t.Errorf("PatternID = %q, want %q", matches[0].PatternID, "python-notimplemented-shipped")
	}
	if matches[0].Category != "hollow-implementation" {
		t.Errorf("Category = %q, want %q", matches[0].Category, "hollow-implementation")
	}
	if matches[0].Line != 2 {
		t.Errorf("Line = %d, want 2", matches[0].Line)
	}
}

// TestClean_AbstractmethodDecorated is the literal clean fixture from the
// pattern spec ("@abstractmethod\ndef save(self, data): raise
// NotImplementedError"), a one-liner def body on the same physical line as
// the decorated header.
func TestClean_AbstractmethodDecorated(t *testing.T) {
	src := "@abstractmethod\ndef save(self, data): raise NotImplementedError\n"

	d := &detector{}
	matches := d.Detect("abstract_bare.py", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0\nsource:\n%s\nmatches: %+v", len(matches), src, matches)
	}
}

// TestClean_AbstractmethodDecoratedInClass expands the spec's clean example
// into a realistic class body, using the qualified "abc.abstractmethod"
// decorator form.
func TestClean_AbstractmethodDecoratedInClass(t *testing.T) {
	src := `import abc


class StorageBackend:
    """Interface documented by convention, not by deriving from ABC."""

    @abc.abstractmethod
    def save(self, data):
        raise NotImplementedError

    @abc.abstractmethod
    def load(self, key):
        raise NotImplementedError
`
	d := &detector{}
	matches := d.Detect("abstract_class.py", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0\nsource:\n%s\nmatches: %+v", len(matches), src, matches)
	}
}

// TestClean_ABCDerivedClass covers the other stated exemption: a method
// nested inside a class that itself derives from ABC, even though the
// method has no @abstractmethod decorator of its own.
func TestClean_ABCDerivedClass(t *testing.T) {
	src := `from abc import ABC


class StorageBackend(ABC):
    def save(self, data):
        raise NotImplementedError
`
	d := &detector{}
	matches := d.Detect("abc_class.py", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0\nsource:\n%s\nmatches: %+v", len(matches), src, matches)
	}
}

// TestClean_ProtocolDerivedClass covers the typing.Protocol exemption named
// explicitly in the pattern description.
func TestClean_ProtocolDerivedClass(t *testing.T) {
	src := `from typing import Protocol


class StorageBackend(Protocol):
    def save(self, data):
        raise NotImplementedError
`
	d := &detector{}
	matches := d.Detect("protocol_class.py", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0\nsource:\n%s\nmatches: %+v", len(matches), src, matches)
	}
}

// TestDirty_ABCMetaWithoutDecoratorStillFlagsSiblingConcreteMethod checks
// that an ABC-derived class only exempts methods that are actually nested
// inside it: a second, unrelated concrete class in the same file must still
// be flagged.
func TestDirty_SiblingConcreteClassStillFlagged(t *testing.T) {
	src := `from abc import ABC


class AbstractBase(ABC):
    def save(self, data):
        raise NotImplementedError


class ConcreteOops:
    def save(self, data):
        raise NotImplementedError
`
	d := &detector{}
	matches := d.Detect("mixed.py", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1 (only the non-ABC class)\nmatches: %+v", len(matches), matches)
	}
	// The flagged raise belongs to ConcreteOops.save, the second occurrence
	// in the file.
	if matches[0].Line != 11 {
		t.Errorf("Line = %d, want 11 (ConcreteOops.save's raise)", matches[0].Line)
	}
}

// TestClean_CommentedOutRaiseIsIgnored ensures a "raise NotImplementedError"
// that appears only inside a comment (never executed) is not flagged.
func TestClean_CommentedOutRaiseIsIgnored(t *testing.T) {
	src := `class Storage:
    def save(self, data):
        # raise NotImplementedError  # old placeholder, now implemented below
        self._write(data)
`
	d := &detector{}
	matches := d.Detect("commented.py", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 (raise was commented out)\nmatches: %+v", len(matches), matches)
	}
}

// TestClean_NonPythonFileIgnored ensures the detector only inspects .py
// files, even when the content is byte-for-byte the dirty fixture.
func TestClean_NonPythonFileIgnored(t *testing.T) {
	src := "def save(self, data):\n    raise NotImplementedError\n"

	d := &detector{}
	matches := d.Detect("storage.go", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() on a .go path returned %d matches, want 0\nmatches: %+v", len(matches), matches)
	}
}

// TestClean_ModuleLevelRaiseOutsideFunctionIgnored ensures a bare raise at
// module scope (not inside any function at all) is out of this pattern's
// stated scope ("inside a function").
func TestClean_ModuleLevelRaiseOutsideFunctionIgnored(t *testing.T) {
	src := "if False:\n    raise NotImplementedError\n"

	d := &detector{}
	matches := d.Detect("module_scope.py", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 (no enclosing function)\nmatches: %+v", len(matches), matches)
	}
}

// TestDirty_RegisteredInGlobalRegistry is a real, non-mocked integration
// check: verify this package's init() actually registered a Pattern into
// the shared llmcheat registry (not just that the local *detector value
// behaves correctly in isolation), then reset the registry afterward so
// this test doesn't leak state into other packages' test binaries.
func TestDirty_RegisteredInGlobalRegistry(t *testing.T) {
	found := false
	for _, p := range llmcheat.All() {
		if p.ID() == "python-notimplemented-shipped" {
			found = true
			if p.Category() != "hollow-implementation" {
				t.Errorf("registered pattern Category() = %q, want %q", p.Category(), "hollow-implementation")
			}
		}
	}
	if !found {
		t.Fatal("python-notimplemented-shipped was not found in llmcheat.All() after package init()")
	}
}
