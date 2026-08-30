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

// Package llmcheat is the shared, dependency-free contract every LLM-cheat
// pattern detector under internal/llmcheat/patterns/* implements and
// self-registers against. It intentionally has ZERO dependency on the
// checker/checks packages so that pattern detectors stay pure functions of
// (path, file content) -> matches, independently unit-testable with real
// fixture strings and state-based assertions (no mocking) and independently
// writable in parallel with no shared-file or import-cycle risk.
//
// checks/raw/anti_cheat.go is the one place this package's output is wired
// into Scorecard's real checker.RawResults/RepoClient machinery.
package llmcheat

import (
	"fmt"
	"sort"
)

// Severity is a coarse triage signal for a Match; it does not gate whether a
// match is reported, only how the Anti-Cheat check's evaluation weighs it.
type Severity string

const (
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

// Match is one occurrence of a detected pattern in one file.
type Match struct {
	// PatternID must equal the owning Pattern's ID().
	PatternID string
	// Category groups related patterns for the Anti-Cheat check's probes — one
	// of: fabricated-claims, hollow-implementation, test-integrity-violation,
	// generated-artifact-tampering, semantic-web-integrity,
	// determinism-and-provenance-violation, complexity-and-surface-obfuscation,
	// option-space-collapse, governed-execution-integrity.
	Category string
	// Path is the file-relative path the match was found in.
	Path string
	// Line is the 1-based line number the match starts at (0 if not
	// line-addressable, e.g. a whole-file-shaped finding).
	Line uint
	// Message is a short, human-readable explanation of what was found and
	// why it looks like an LLM-cheat pattern rather than legitimate code.
	Message string
	Severity Severity
}

// Pattern is one independent, orthogonal cheat-pattern detector. Each
// implementation lives in its own internal/llmcheat/patterns/<id>/ package
// so independently-authored detectors avoid symbol collisions while the
// production aggregator remains the explicit registration boundary.
type Pattern interface {
	// ID is a stable, kebab-case identifier, e.g. "claim-alive-without-receipt".
	// It must be unique across every registered pattern (Register panics on
	// a duplicate) and must match the const ID the pattern package defines.
	ID() string
	// Category is one of the nine Anti-Cheat categories listed on Match.Category.
	Category() string
	// Detect scans one file's full content and returns zero or more matches.
	// Implementations must be pure and side-effect-free: no filesystem, no
	// network, no shared mutable state beyond registration at init() time.
	Detect(path string, content []byte) []Match
}

var registered = map[string]Pattern{}

// Register adds a Pattern to the shared registry. Call this from a pattern
// package's init() — never call it with the same ID twice; a second call
// with a colliding ID panics loudly at program start.
func Register(p Pattern) {
	if p == nil {
		panic("llmcheat: Register called with a nil Pattern")
	}
	if p.ID() == "" {
		panic("llmcheat: Register called with an empty Pattern ID")
	}
	if existing, ok := registered[p.ID()]; ok {
		panic(fmt.Sprintf("llmcheat: duplicate pattern ID %q (already registered by %T, now also by %T)",
			p.ID(), existing, p))
	}
	registered[p.ID()] = p
}

// All returns every registered pattern, sorted by ID for deterministic
// iteration order.
func All() []Pattern {
	out := make([]Pattern, 0, len(registered))
	for _, p := range registered {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// Reset clears the registry. Test-only: lets pattern-package tests that
// construct a Pattern directly avoid depending on global registry state.
func Reset() {
	registered = map[string]Pattern{}
}
