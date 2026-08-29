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

package alwaystrueoracle

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// --- Go fixtures -----------------------------------------------------------

// dirtyGoBoolLiteral is the canonical dirty shape from the pattern spec,
// expanded into a realistic surrounding file: a real helper alongside a
// verifier whose body is nothing but `return true`.
const dirtyGoBoolLiteral = `package auth

import "crypto/ed25519"

// pubKey is the server's signing public key.
var pubKey ed25519.PublicKey

// VerifySignature is supposed to check sig against msg using pubKey, but
// its body never actually does — it always reports success.
func VerifySignature(sig []byte) bool {
	return true
}

func helperUnrelated(x int) int {
	return x + 1
}
`

// cleanGoRealCheck is the canonical clean shape from the pattern spec: the
// same signature, but the body performs a real cryptographic check.
const cleanGoRealCheck = `package auth

import "crypto/ed25519"

var pubKey ed25519.PublicKey
var msg []byte

// VerifySignature really verifies sig against msg using pubKey.
func VerifySignature(sig []byte) bool {
	return ed25519.Verify(pubKey, msg, sig)
}
`

// dirtyGoAlwaysNilValidator is a very common real-world instance of this
// pattern in Go: a Validate function whose contract is "return non-nil
// error on failure," but whose body always returns nil, i.e. always
// reports success regardless of input.
const dirtyGoAlwaysNilValidator = `package config

// Validate is supposed to check cfg for required fields, but always
// reports success.
func Validate(cfg *Config) error {
	return nil
}
`

// cleanGoRealBranching is a real validator: it branches and compares, so
// it must NOT be flagged even though every one of its individual return
// statements is itself a literal.
const cleanGoRealBranching = `package auth

// CheckAge really checks whether age meets the minimum.
func CheckAge(age int) bool {
	if age >= 18 {
		return true
	}
	return false
}
`

// dirtyGoWithLogging shows that a non-branching, non-comparing statement
// (a log line) ahead of the literal return does not save the function from
// being flagged — it still structurally cannot fail.
const dirtyGoWithLogging = `package auth

import "log"

func VerifyToken(tok string) bool {
	log.Println("verifying token")
	return true
}
`

// cleanGoNameMismatch has the exact dirty body shape (bare "return true")
// but a name that does not read as a verifier at all, so it must not be
// flagged — this is the name-gate boundary.
const cleanGoNameMismatch = `package auth

func AlwaysTrue() bool {
	return true
}
`

// --- Python fixtures --------------------------------------------------------

const dirtyPythonBoolLiteral = `import re


def is_valid_email(email):
    return True


def unrelated_helper(x):
    return x + 1
`

const cleanPythonRealCheck = `import re

EMAIL_RE = re.compile(r"^[^@]+@[^@]+\.[^@]+$")


def is_valid_email(email):
    return bool(EMAIL_RE.match(email))
`

// --- Rust fixtures -----------------------------------------------------------

const dirtyRustTailExpr = `pub struct Error;

// verify_signature is supposed to check sig, but its tail expression
// always reports success regardless of input.
fn verify_signature(sig: &[u8]) -> Result<(), Error> {
    Ok(())
}
`

const cleanRustRealCheck = `pub struct Error;

fn verify_signature(sig: &[u8]) -> Result<(), Error> {
    if sig.len() != 64 {
        return Err(Error);
    }
    Ok(())
}
`

func hasPatternMatch(matches []llmcheat.Match) bool {
	for _, m := range matches {
		if m.PatternID == patternID && m.Category == patternCategory {
			return true
		}
	}
	return false
}

func TestDetect_DirtyGoBoolLiteral_Matches(t *testing.T) {
	d := detector{}
	matches := d.Detect("auth/verify.go", []byte(dirtyGoBoolLiteral))

	if len(matches) < 1 {
		t.Fatalf("expected >=1 match for dirty Go bool-literal oracle, got %d: %+v", len(matches), matches)
	}
	if !hasPatternMatch(matches) {
		t.Fatalf("expected a match with PatternID=%q Category=%q, got %+v", patternID, patternCategory, matches)
	}
	m := matches[0]
	if m.Line != 10 {
		t.Errorf("expected match on line 10 (the func line), got line %d", m.Line)
	}
	if m.Severity != llmcheat.SeverityHigh {
		t.Errorf("expected SeverityHigh, got %q", m.Severity)
	}
}

func TestDetect_CleanGoRealCheck_NoMatches(t *testing.T) {
	d := detector{}
	matches := d.Detect("auth/verify.go", []byte(cleanGoRealCheck))

	if len(matches) != 0 {
		t.Fatalf("expected 0 matches for a real ed25519.Verify call, got %d: %+v", len(matches), matches)
	}
}

func TestDetect_DirtyGoAlwaysNilValidator_Matches(t *testing.T) {
	d := detector{}
	matches := d.Detect("config/validate.go", []byte(dirtyGoAlwaysNilValidator))

	if len(matches) < 1 {
		t.Fatalf("expected >=1 match for a Validate() that always returns nil, got %d: %+v", len(matches), matches)
	}
	for _, m := range matches {
		if m.PatternID != patternID || m.Category != patternCategory {
			t.Errorf("unexpected PatternID/Category on match: %+v", m)
		}
	}
}

func TestDetect_CleanGoRealBranching_NoMatches(t *testing.T) {
	d := detector{}
	matches := d.Detect("auth/check_age.go", []byte(cleanGoRealBranching))

	if len(matches) != 0 {
		t.Fatalf("expected 0 matches for a real branching/comparing check, got %d: %+v", len(matches), matches)
	}
}

func TestDetect_DirtyGoWithLogging_StillMatches(t *testing.T) {
	d := detector{}
	matches := d.Detect("auth/verify_token.go", []byte(dirtyGoWithLogging))

	if len(matches) < 1 {
		t.Fatalf("expected a log statement ahead of `return true` to still be flagged, got %d matches", len(matches))
	}
}

func TestDetect_NameDoesNotReadAsVerifier_NoMatches(t *testing.T) {
	d := detector{}
	matches := d.Detect("auth/always_true.go", []byte(cleanGoNameMismatch))

	if len(matches) != 0 {
		t.Fatalf("expected 0 matches: function name %q does not start with verify/validate/check/is_valid, got %+v", "AlwaysTrue", matches)
	}
}

func TestDetect_DirtyPythonBoolLiteral_Matches(t *testing.T) {
	d := detector{}
	matches := d.Detect("validators.py", []byte(dirtyPythonBoolLiteral))

	if len(matches) < 1 {
		t.Fatalf("expected >=1 match for dirty Python bool-literal oracle, got %d: %+v", len(matches), matches)
	}
	if !hasPatternMatch(matches) {
		t.Fatalf("expected a match with PatternID=%q Category=%q, got %+v", patternID, patternCategory, matches)
	}
}

func TestDetect_CleanPythonRealCheck_NoMatches(t *testing.T) {
	d := detector{}
	matches := d.Detect("validators.py", []byte(cleanPythonRealCheck))

	if len(matches) != 0 {
		t.Fatalf("expected 0 matches for a real regex-backed email check, got %d: %+v", len(matches), matches)
	}
}

func TestDetect_DirtyRustTailExpr_Matches(t *testing.T) {
	d := detector{}
	matches := d.Detect("src/sig.rs", []byte(dirtyRustTailExpr))

	if len(matches) < 1 {
		t.Fatalf("expected >=1 match for a Rust verifier whose only tail expression is Ok(()), got %d: %+v", len(matches), matches)
	}
	if !hasPatternMatch(matches) {
		t.Fatalf("expected a match with PatternID=%q Category=%q, got %+v", patternID, patternCategory, matches)
	}
}

func TestDetect_CleanRustRealCheck_NoMatches(t *testing.T) {
	d := detector{}
	matches := d.Detect("src/sig.rs", []byte(cleanRustRealCheck))

	if len(matches) != 0 {
		t.Fatalf("expected 0 matches: real length check with if/!= present, got %d: %+v", len(matches), matches)
	}
}

func TestID_And_Category(t *testing.T) {
	d := detector{}
	if got := d.ID(); got != "always-true-oracle" {
		t.Errorf("ID() = %q, want %q", got, "always-true-oracle")
	}
	if got := d.Category(); got != "test-integrity-violation" {
		t.Errorf("Category() = %q, want %q", got, "test-integrity-violation")
	}
}
