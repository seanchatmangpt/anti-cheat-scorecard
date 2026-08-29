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

package pythonunittestmockowned

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

func TestIDAndCategory(t *testing.T) {
	d := &detector{}
	if got, want := d.ID(), "python-unittest-mock-owned"; got != want {
		t.Errorf("ID() = %q, want %q", got, want)
	}
	if got, want := d.Category(), "test-integrity-violation"; got != want {
		t.Errorf("Category() = %q, want %q", got, want)
	}
}

// TestDirty_FullMockingSuite expands the spec's one-line dirty example
// ("from unittest.mock import Mock\ndef test_x():\n    svc = Mock()") into a
// realistic pytest module that exercises every idiom this pattern is
// scoped to flag: the unittest.mock import, a bare Mock(), a MagicMock(),
// an @patch(...) decorator, monkeypatch.setattr(...), and mocker.patch(...).
// It asserts on the real, exact set of match lines and fields — not just a
// nonzero count.
func TestDirty_FullMockingSuite(t *testing.T) {
	src := `"""Tests for the payment service."""

from unittest.mock import MagicMock, Mock, patch


class TestPaymentService:
    """Exercises PaymentService against a mocked gateway."""

    def test_charge_calls_gateway(self):
        svc = Mock()
        gateway = MagicMock()
        svc.gateway = gateway
        svc.charge(100)
        gateway.charge.assert_called_once_with(100)

    @patch("payments.gateway.Client")
    def test_client_created(self, mock_client):
        svc = PaymentService()
        svc.connect()
        mock_client.assert_called_once()

    def test_monkeypatched_env(self, monkeypatch):
        monkeypatch.setattr("os.environ", {"ENV": "test"})
        assert True

    def test_mocker_patch(self, mocker):
        mocker.patch("payments.gateway.send")
        assert True
`
	d := &detector{}
	matches := d.Detect("test_payment_service.py", []byte(src))

	wantLines := map[uint]bool{3: true, 10: true, 11: true, 16: true, 23: true, 27: true}
	if len(matches) != len(wantLines) {
		gotLines := make([]uint, len(matches))
		for i, m := range matches {
			gotLines[i] = m.Line
		}
		t.Fatalf("Detect() returned %d matches, want %d\ngot lines: %v\nwant lines: %v",
			len(matches), len(wantLines), gotLines, wantLines)
	}
	for _, m := range matches {
		if m.PatternID != "python-unittest-mock-owned" {
			t.Errorf("match at line %d: PatternID = %q, want %q", m.Line, m.PatternID, "python-unittest-mock-owned")
		}
		if m.Category != "test-integrity-violation" {
			t.Errorf("match at line %d: Category = %q, want %q", m.Line, m.Category, "test-integrity-violation")
		}
		if m.Path != "test_payment_service.py" {
			t.Errorf("match at line %d: Path = %q, want %q", m.Line, m.Path, "test_payment_service.py")
		}
		if m.Severity != llmcheat.SeverityHigh {
			t.Errorf("match at line %d: Severity = %q, want %q", m.Line, m.Severity, llmcheat.SeverityHigh)
		}
		if !wantLines[m.Line] {
			t.Errorf("unexpected match at line %d: %+v", m.Line, m)
		}
		if m.Message == "" {
			t.Errorf("match at line %d has empty Message", m.Line)
		}
	}
}

// TestClean_RealCollaborator is the exact clean shape from the pattern
// spec ("def test_x():\n    svc = RealService(tmp_path)"), expanded into a
// realistic module that constructs and exercises a real, owned collaborator
// instead of mocking it. It must produce zero matches.
func TestClean_RealCollaborator(t *testing.T) {
	src := `"""Tests for the payment service using a real, owned collaborator."""


class TestPaymentService:
    """Exercises PaymentService against a real in-memory gateway."""

    def test_charge_calls_gateway(self, tmp_path):
        gateway = RealGateway(tmp_path)
        svc = PaymentService(gateway)
        svc.charge(100)
        assert gateway.total_charged() == 100
`
	d := &detector{}
	matches := d.Detect("test_payment_service.py", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0\nsource:\n%s\nmatches: %+v", len(matches), src, matches)
	}
}

// TestClean_NonTestFileIgnored ensures a plain (non-test) Python source file
// is out of scope even when it is byte-for-byte the dirty mocking content:
// this pattern only fires inside Python *test* files.
func TestClean_NonTestFileIgnored(t *testing.T) {
	src := "from unittest.mock import Mock\ndef make_gateway():\n    return Mock()\n"

	d := &detector{}
	matches := d.Detect("app/gateway.py", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() on a non-test .py path returned %d matches, want 0\nmatches: %+v", len(matches), matches)
	}
}

// TestClean_NonPyExtensionIgnored ensures the .py extension gate applies
// even when the filename otherwise looks exactly like a Python test file
// name (test_ prefix) and the content is the dirty fixture.
func TestClean_NonPyExtensionIgnored(t *testing.T) {
	src := "from unittest.mock import Mock\nsvc = Mock()\n"

	d := &detector{}
	matches := d.Detect("test_config.json", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() on a non-.py path returned %d matches, want 0\nmatches: %+v", len(matches), matches)
	}
}

// TestClean_DirectoryNameContainingTestSubstringIsNotAMatch proves the
// "/test" directory rule is anchored to an actual "/test" path segment
// boundary, not to the bare substring "test" appearing anywhere in the
// path (e.g. a "latest" directory must not be mistaken for a "test" one).
func TestClean_DirectoryNameContainingTestSubstringIsNotAMatch(t *testing.T) {
	src := "from unittest.mock import Mock\ndef helper():\n    return Mock()\n"

	d := &detector{}
	matches := d.Detect("src/latest/helpers.py", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() on src/latest/helpers.py returned %d matches, want 0 (not a test path)\nmatches: %+v",
			len(matches), matches)
	}
}

// TestDirty_TestsDirectoryPathMatchesEvenWithoutTestFilenamePrefix covers
// the "/test" path-substring branch of the naming rule directly: a file
// under a tests/ directory whose own filename is neither "test_"-prefixed
// nor "_test.py"-suffixed (e.g. conftest.py) must still be treated as a
// Python test file.
func TestDirty_TestsDirectoryPathMatchesEvenWithoutTestFilenamePrefix(t *testing.T) {
	src := `import pytest

from unittest.mock import Mock


@pytest.fixture
def fake_gateway():
    return Mock()
`
	d := &detector{}
	matches := d.Detect("src/tests/conftest.py", []byte(src))

	wantLines := map[uint]bool{3: true, 8: true}
	if len(matches) != len(wantLines) {
		gotLines := make([]uint, len(matches))
		for i, m := range matches {
			gotLines[i] = m.Line
		}
		t.Fatalf("Detect() returned %d matches, want %d\ngot lines: %v\nwant lines: %v",
			len(matches), len(wantLines), gotLines, wantLines)
	}
	for _, m := range matches {
		if !wantLines[m.Line] {
			t.Errorf("unexpected match at line %d: %+v", m.Line, m)
		}
	}
}

// TestClean_CommentedOutMockUsageIsIgnored ensures a Mock() reference that
// appears only inside a comment (never executed) is not flagged.
func TestClean_CommentedOutMockUsageIsIgnored(t *testing.T) {
	src := `def test_real_service():
    # svc = Mock()  # old placeholder, now using RealService
    svc = RealService()
    assert svc.status() == "ok"
`
	d := &detector{}
	matches := d.Detect("test_real_service.py", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() returned %d matches, want 0 (Mock() was only in a comment)\nmatches: %+v", len(matches), matches)
	}
}

// TestDirty_MagicMockDoesNotDoubleCountAsBareMock proves the two
// substring-overlapping rules ("Mock(" and "MagicMock(") do not both fire
// on the same MagicMock() call — exactly one match, from the MagicMock
// rule, not two.
func TestDirty_MagicMockDoesNotDoubleCountAsBareMock(t *testing.T) {
	src := "def test_x():\n    gateway = MagicMock()\n"

	d := &detector{}
	matches := d.Detect("test_gateway.py", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() returned %d matches, want exactly 1 (no double count)\nmatches: %+v", len(matches), matches)
	}
	if matches[0].Line != 2 {
		t.Errorf("Line = %d, want 2", matches[0].Line)
	}
}

// TestDirty_TestSuffixFilenameMatches covers the "_test.py" filename-suffix
// branch of the naming rule (as opposed to the "test_" prefix branch
// already exercised by the other fixtures above).
func TestDirty_TestSuffixFilenameMatches(t *testing.T) {
	src := "from unittest.mock import Mock\n\n\ndef test_gateway():\n    svc = Mock()\n"

	d := &detector{}
	matches := d.Detect("gateway_test.py", []byte(src))

	if len(matches) != 2 {
		t.Fatalf("Detect() returned %d matches, want 2\nmatches: %+v", len(matches), matches)
	}
}

// TestDirty_RegisteredInGlobalRegistry is a real, non-mocked integration
// check: verify this package's init() actually registered a Pattern into
// the shared llmcheat registry (not just that the local *detector value
// behaves correctly in isolation).
func TestDirty_RegisteredInGlobalRegistry(t *testing.T) {
	found := false
	for _, p := range llmcheat.All() {
		if p.ID() == "python-unittest-mock-owned" {
			found = true
			if p.Category() != "test-integrity-violation" {
				t.Errorf("registered pattern Category() = %q, want %q", p.Category(), "test-integrity-violation")
			}
		}
	}
	if !found {
		t.Fatal("python-unittest-mock-owned was not found in llmcheat.All() after package init()")
	}
}
