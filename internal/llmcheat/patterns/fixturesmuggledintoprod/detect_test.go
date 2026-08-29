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

package fixturesmuggledintoprod

import (
	"strings"
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// dirtySource is a realistic multi-line Go file: a real production auth
// client whose constructor hardcodes an obviously test-shaped token literal
// into a secret-shaped field instead of sourcing it from a real credential
// provider.
const dirtySource = `package auth

import "net/http"

// Client authenticates outbound requests against the upstream identity
// provider.
type Client struct {
	httpClient *http.Client
	apiKey     string
}

// NewClient constructs a Client for production use.
func NewClient() *Client {
	apiKey := "test-token-123" // in production auth.go
	return &Client{httpClient: &http.Client{}, apiKey: apiKey}
}
`

// cleanSource is the same file shape, but the credential is sourced from
// the environment instead of being hardcoded — this must never be flagged.
const cleanSource = `package auth

import (
	"net/http"
	"os"
)

// Client authenticates outbound requests against the upstream identity
// provider.
type Client struct {
	httpClient *http.Client
	apiKey     string
}

// NewClient constructs a Client for production use, reading its credential
// from the environment rather than hardcoding it.
func NewClient() *Client {
	apiKey := os.Getenv("API_KEY")
	return &Client{httpClient: &http.Client{}, apiKey: apiKey}
}
`

func TestDetect_DirtyHardcodedTestToken_ProducesMatch(t *testing.T) {
	d := detector{}

	matches := d.Detect("auth/client.go", []byte(dirtySource))

	if len(matches) < 1 {
		t.Fatalf("Detect() on dirty fixture = %d matches, want >= 1", len(matches))
	}

	got := matches[0]
	if got.PatternID != patternID {
		t.Errorf("Match.PatternID = %q, want %q", got.PatternID, patternID)
	}
	if got.Category != patternCategory {
		t.Errorf("Match.Category = %q, want %q", got.Category, patternCategory)
	}
	if got.Path != "auth/client.go" {
		t.Errorf("Match.Path = %q, want %q", got.Path, "auth/client.go")
	}
	// Derive the expected 1-based line number directly from the fixture
	// text itself (rather than a hand-counted literal, which is easy to get
	// off-by-one on a multi-line raw string) so the assertion stays correct
	// even if the fixture is edited later.
	wantLine := uint(0)
	for i, line := range strings.Split(dirtySource, "\n") {
		if strings.Contains(line, `"test-token-123"`) {
			wantLine = uint(i + 1)
			break
		}
	}
	if wantLine == 0 {
		t.Fatal("test fixture bug: dirtySource does not contain the expected \"test-token-123\" literal")
	}
	if got.Line != wantLine {
		t.Errorf("Match.Line = %d, want %d", got.Line, wantLine)
	}
	if got.Severity != llmcheat.SeverityHigh {
		t.Errorf("Match.Severity = %q, want %q", got.Severity, llmcheat.SeverityHigh)
	}
	if got.Message == "" {
		t.Error("Match.Message is empty, want a real explanation")
	}
}

func TestDetect_CleanEnvVarLookup_ProducesNoMatches(t *testing.T) {
	d := detector{}

	matches := d.Detect("auth/client.go", []byte(cleanSource))

	if len(matches) != 0 {
		t.Fatalf("Detect() on clean fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

// TestDetect_TestFixtureMockPathsExcluded proves the stated allowlist: the
// exact dirty content, located under a test, fixture, or mock directory (in
// either a "/marker" mid-path shape or a "marker/" leading-path shape),
// must never be flagged — that is exactly where a hardcoded fixture
// literal legitimately belongs.
func TestDetect_TestFixtureMockPathsExcluded(t *testing.T) {
	d := detector{}

	paths := []string{
		"internal/test/client.go",
		"test/client.go",
		"pkg/fixtures/client.go",
		"fixture/client.go",
		"internal/mocks/client.go",
		"mock/client.go",
	}

	for _, path := range paths {
		matches := d.Detect(path, []byte(dirtySource))
		if len(matches) != 0 {
			t.Errorf("Detect(%q) = %d matches, want 0; matches=%+v", path, len(matches), matches)
		}
	}
}

// TestDetect_NonSecretShapedVariable_ProducesNoMatches proves the second
// half of the pattern's scope: an obviously test-fixture-shaped literal
// assigned to a variable that does NOT read as a secret/token/credential
// holder is out of scope — this pattern is about smuggled credentials
// specifically, not every string that happens to look test-ish.
func TestDetect_NonSecretShapedVariable_ProducesNoMatches(t *testing.T) {
	d := detector{}

	const src = `package config

// greeting is shown in the CLI's welcome banner and happens to reuse a
// string that looks fixture-shaped, but it is not a credential of any kind.
var greeting = "test-token-123"
`

	matches := d.Detect("config/banner.go", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() on non-secret-shaped-variable fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

// TestDetect_BareNumericPin proves the "123456" boundary named in the
// pattern spec: it must fire when assigned whole to a secret-shaped
// variable, but must NOT fire merely because "123456" appears as a
// substring of some longer, real-looking token value.
func TestDetect_BareNumericPin(t *testing.T) {
	d := detector{}

	t.Run("exact literal on a token-shaped variable matches", func(t *testing.T) {
		const src = `package auth

// NewSession issues a session token for a newly authenticated request.
func NewSession() string {
	token := "123456"
	return token
}
`
		matches := d.Detect("auth/session.go", []byte(src))
		if len(matches) != 1 {
			t.Fatalf("Detect() = %d matches, want 1; matches=%+v", len(matches), matches)
		}
		if matches[0].PatternID != patternID || matches[0].Category != patternCategory {
			t.Errorf("Match = %+v, want PatternID=%q Category=%q", matches[0], patternID, patternCategory)
		}
	})

	t.Run("123456 as a substring of a longer real-looking token does not match", func(t *testing.T) {
		const src = `package auth

// NewSession issues a session token for a newly authenticated request.
func NewSession() string {
	token := "sk_live_51234567890abcdef"
	return token
}
`
		matches := d.Detect("auth/session.go", []byte(src))
		if len(matches) != 0 {
			t.Fatalf("Detect() = %d matches, want 0; matches=%+v", len(matches), matches)
		}
	})
}

// TestDetect_OtherLanguageShapes proves the pattern is not Go-specific: the
// same smuggled-fixture shape in Python and JSON-config syntax, in a
// non-test/fixture/mock path, must also be caught.
func TestDetect_OtherLanguageShapes(t *testing.T) {
	d := detector{}

	t.Run("python", func(t *testing.T) {
		const src = `import requests

class UpstreamClient:
    """Talks to the upstream billing provider in production."""

    def __init__(self):
        self.api_key = "fake-api-key-000"

    def charge(self, amount):
        return requests.post(
            "https://billing.example.com/charge",
            headers={"Authorization": self.api_key},
            json={"amount": amount},
        )
`
		matches := d.Detect("billing/upstream_client.py", []byte(src))
		if len(matches) < 1 {
			t.Fatalf("Detect() on python fixture = %d matches, want >= 1", len(matches))
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

	t.Run("json config", func(t *testing.T) {
		const src = `{
  "service": "billing",
  "apiKey": "dummy-secret-xyz",
  "timeoutSeconds": 30
}
`
		matches := d.Detect("config/billing.prod.json", []byte(src))
		if len(matches) != 1 {
			t.Fatalf("Detect() on json fixture = %d matches, want 1; matches=%+v", len(matches), matches)
		}
		if matches[0].Line != 3 {
			t.Errorf("matches[0].Line = %d, want 3", matches[0].Line)
		}
	})
}

func TestPattern_IDAndCategory(t *testing.T) {
	d := detector{}

	if got := d.ID(); got != patternID {
		t.Errorf("ID() = %q, want %q", got, patternID)
	}
	if got := d.Category(); got != patternCategory {
		t.Errorf("Category() = %q, want %q", got, patternCategory)
	}
}
