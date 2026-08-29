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

// Package standingvocabularymisuse implements the "standing-vocabulary-misuse"
// llmcheat.Pattern: it flags a file that has already committed to a closed,
// ALL-CAPS status vocabulary (e.g. ALIVE / BLOCKED / UNKNOWN / PARTIAL_ALIVE /
// READY / DRAFT / BUILD_BROKEN / UNSUPPORTED / REFUSED, the exact style used
// by this repository's own sibling ggen-ecosystem STANDING vocabulary) but
// then, somewhere else in the same file, describes status informally instead
// ("should be good now", "looks ready", "finished it up"). Reaching for an
// informal synonym instead of the file's own declared enum value is itself a
// smell that the claim behind it was never actually run through the closed
// vocabulary's admission discipline — an unaudited assertion slipping in
// under looser words than the ones the file otherwise holds itself to.
//
// A file that never uses the closed vocabulary at all is out of scope: this
// pattern only fires where the file's own text supplies the evidence that a
// closed vocabulary was the declared standard to begin with.
package standingvocabularymisuse

import (
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// patternID is this pattern's stable, registry-unique identifier.
const patternID = "standing-vocabulary-misuse"

// category is one of the seven Anti-Cheat categories llmcheat.Match.Category
// documents; an informal status word standing in for an audited enum value
// is a fabricated-claims smell (an unverified status slipping past the
// file's own declared closed vocabulary), not a hollow-implementation or
// determinism issue.
const category = "fabricated-claims"

// evidenceTokenRe matches the ALL-CAPS, enum-like status tokens whose mere
// presence in a file is evidence that the file has adopted a closed status
// vocabulary. Matching is case-sensitive by construction (no (?i) flag) so a
// lowercase or mixed-case occurrence of the same word never counts as
// evidence — only the literal, all-caps enum spelling does.
var evidenceTokenRe = regexp.MustCompile(
	`\b(?:ALIVE|BLOCKED|UNKNOWN|PARTIAL_ALIVE|READY|DRAFT|BUILD_BROKEN|UNSUPPORTED|REFUSED)\b`,
)

// informalWordRe matches the informal synonyms called out in this pattern's
// spec. It is case-insensitive at the regexp level; detector.Detect then
// discards any match whose captured text is itself entirely upper-case,
// since an all-caps occurrence (e.g. literal "READY") is a use of the
// closed vocabulary itself, not an informal stand-in for it.
var informalWordRe = regexp.MustCompile(`(?i)\b(done|working|finished|good|ready|stable)\b`)

// detector is the unexported Pattern implementation for this package. It
// carries no state: Detect is a pure function of its two arguments, as
// required by the llmcheat.Pattern contract.
type detector struct{}

// instance is the single registered Pattern value for this package.
var instance = &detector{}

func init() {
	llmcheat.Register(instance)
}

func (d *detector) ID() string { return patternID }

func (d *detector) Category() string { return category }

// Detect implements llmcheat.Pattern. It runs in two passes over content:
//
//  1. Evidence pass — does this file use the closed, ALL-CAPS status
//     vocabulary anywhere at all? If not, there is nothing to be inconsistent
//     with, and Detect returns no matches even if informal status words are
//     present (they're just ordinary prose in that case).
//  2. Violation pass — line by line, find informal status-word occurrences
//     that are not themselves all-caps (i.e. not a literal use of the closed
//     vocabulary) and report each as a Match with a real, computed 1-based
//     line number.
//
// No file-type restriction applies: the pattern's spec names no specific
// extensions, so Detect runs uniformly on any text content it is given.
func (d *detector) Detect(path string, content []byte) []llmcheat.Match {
	if !evidenceTokenRe.Match(content) {
		// This file never commits to the closed vocabulary in the first
		// place, so an informal word here is not a substitution for
		// anything — it's just prose. Nothing to flag.
		return nil
	}

	var matches []llmcheat.Match

	text := strings.ReplaceAll(string(content), "\r\n", "\n")
	lines := strings.Split(text, "\n")

	for i, line := range lines {
		lineNo := uint(i + 1) //nolint:gosec // line count bounded by file size, no overflow risk

		for _, loc := range informalWordRe.FindAllStringIndex(line, -1) {
			word := line[loc[0]:loc[1]]
			if isAllUpper(word) {
				// A literal all-caps occurrence (e.g. "READY") is a real
				// use of the closed vocabulary itself, not an informal
				// stand-in for it — not a violation.
				continue
			}

			matches = append(matches, llmcheat.Match{
				PatternID: patternID,
				Category:  category,
				Path:      path,
				Line:      lineNo,
				Message: "informal status word \"" + word + "\" used in a file that elsewhere " +
					"declares a closed ALL-CAPS status vocabulary (e.g. ALIVE/BLOCKED/UNKNOWN/" +
					"PARTIAL_ALIVE/READY/DRAFT) — use the declared enum value instead of an " +
					"informal synonym, or cite the evidence (receipt/log/link) backing the claim",
				Severity: llmcheat.SeverityMedium,
			})
		}
	}

	return matches
}

// isAllUpper reports whether s contains at least one letter and no
// lowercase letters — i.e. it is a literal all-caps token occurrence rather
// than an informal, lower/mixed-case synonym.
func isAllUpper(s string) bool {
	hasLetter := false
	for _, r := range s {
		if r >= 'a' && r <= 'z' {
			return false
		}
		if r >= 'A' && r <= 'Z' {
			hasLetter = true
		}
	}
	return hasLetter
}
