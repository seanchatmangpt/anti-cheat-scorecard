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

// Package rustmockalltraitmock detects use of the mockall crate's
// #[automock] attribute (in any of its common spellings, including
// #[mockall::automock] and the conditional #[cfg_attr(test, automock)]
// form) and any `use mockall::...;` import in Rust (.rs) source.
//
// Both are the Rust-ecosystem instance of London-school/mockist
// interaction-based mocking of a trait this codebase owns: #[automock]
// mechanically generates a MockFoo type that records "was this method
// called, with these arguments" instead of exercising real collaborator
// behavior, and a bare `use mockall::` import is the precondition for doing
// so anywhere else in the same crate. Chicago-school discipline (real
// collaborators, state-based assertions — see this repo's own
// testing-chicago-style convention) treats both as a default-banned pattern
// for any trait genuinely owned by, or realistically runnable in-process
// within, the project under test — the exact shape a from-scratch LLM
// author reaches for to make a test pass without exercising real behavior.
//
// This detector does not attempt to distinguish a legitimate "one genuinely
// infeasible external collaborator" exception (per testing-chicago-style.md
// §"The one legitimate use of a test double") from a mocked in-process
// collaborator — mockall usage is flagged unconditionally, in both test and
// non-test code, because #[automock] itself carries no such justification
// in the source text for Detect to inspect; that judgment call is left to
// the human/reviewer consuming the Match, not manufactured here.
package rustmockalltraitmock

import (
	"bufio"
	"bytes"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "rust-mockall-trait-mock"
	category  = "test-integrity-violation"
)

// automockRe matches any attribute line whose body contains the word
// "automock" as a whole word — covering #[automock], #[mockall::automock],
// and #[cfg_attr(test, automock)] / #[cfg_attr(test, mockall::automock)]
// alike, without requiring the attribute to be spelled a single fixed way.
var automockRe = regexp.MustCompile(`^\s*#!?\[.*\bautomock\b.*\]\s*$`)

// useMockallRe matches a `use mockall::...;` (or `use ::mockall::...;`)
// import statement, including brace-grouped imports such as
// `use mockall::{automock, predicate::*};`. The literal `mockall::` (crate
// name immediately followed by `::`) keeps this from matching an unrelated
// crate whose name merely starts with "mockall" (e.g. a hypothetical
// `mockallish` crate would read as "mockallish::", not "mockall::").
var useMockallRe = regexp.MustCompile(`^\s*use\s+(::)?mockall::`)

// detector is the Pattern implementation for this package. It is
// unexported: callers outside this package only ever interact with it
// through the llmcheat.Pattern interface (or, in tests, by constructing it
// directly).
type detector struct{}

func (detector) ID() string       { return patternID }
func (detector) Category() string { return category }

// Detect scans one Rust source file's content line by line and reports
// every #[automock]-shaped attribute and every `use mockall::...;` import
// found, each with its real 1-based line number. Full-line `//` comments
// are skipped so that a mention of mockall in prose (e.g. a doc comment
// explaining why it is NOT used) is not itself flagged.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	if !strings.EqualFold(filepath.Ext(path), ".rs") {
		return nil
	}

	var matches []llmcheat.Match

	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var lineNum uint
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "//") {
			continue
		}

		switch {
		case automockRe.MatchString(line):
			matches = append(matches, llmcheat.Match{
				PatternID: patternID,
				Category:  category,
				Path:      path,
				Line:      lineNum,
				Message: "mockall's #[automock] generates a trait mock that verifies interactions " +
					"instead of exercising a real collaborator's behavior",
				Severity: llmcheat.SeverityHigh,
			})
		case useMockallRe.MatchString(line):
			matches = append(matches, llmcheat.Match{
				PatternID: patternID,
				Category:  category,
				Path:      path,
				Line:      lineNum,
				Message: "`use mockall::` imports the interaction-based trait-mocking crate, " +
					"the precondition for mocking an owned/realistically-runnable collaborator",
				Severity: llmcheat.SeverityMedium,
			})
		}
	}

	return matches
}

func init() {
	llmcheat.Register(detector{})
}
