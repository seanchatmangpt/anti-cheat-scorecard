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

// Package fabricatedcitation implements the "fabricated-citation"
// llmcheat.Pattern: it flags citation-shaped sentences ("See X", "as
// documented in X", "per X", and close synonyms such as "as described in
// X"/"as noted in X") whose target X is a vague, generic placeholder (e.g.
// "the docs", "the relevant file", "somewhere in the codebase") rather than
// a real, checkable locator (a path containing a "/", or a filename with a
// recognizable extension such as .md/.go/.rs/.py/.ttl).
//
// A companion check that actually resolves the cited path against the repo
// tree is out of scope here: Detect only ever sees one file's content, with
// no filesystem access (per the llmcheat.Pattern contract — pure function,
// no I/O). So instead of "does X exist", this package answers the narrower,
// still-real question: "was X ever a real locator in the first place, or is
// it hand-wavy filler standing in for one". A sentence that names an actual
// path is left alone even if that path turns out not to exist — that's the
// companion check's job, not this one's.
package fabricatedcitation

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID       = "fabricated-citation"
	patternCategory = "fabricated-claims"
)

// citationTarget is the shared, non-greedy capture used by every trigger
// regex below: everything from right after the trigger phrase up to (but
// not including) a sentence-ending ". " or ".$", a clause-ending
// [,;:!?], or end of line.
//
// It deliberately does NOT stop at a bare "." wherever it appears mid-target
// (only at one immediately followed by whitespace or end-of-string) so a
// real file path/extension like "docs/AUTHORITY.md" or "internal/foo.go" is
// captured whole rather than being truncated at its own extension dot.
const citationTarget = `([^,;:!?\n]+?)(?:\.\s|\.$|[,;:!?]|$)`

var (
	// seeRe matches "See X" / "see X" — the classic doc/comment
	// cross-reference form named directly in this pattern's assignment.
	seeRe = regexp.MustCompile(`(?i)\bsee\s+` + citationTarget)

	// documentedRe matches "as documented in X" / "documented in X", plus
	// close synonyms real comments use for the same move ("as described
	// in", "as noted in", "as explained in", "as detailed in", "as
	// outlined in", "as specified in"), each with an optional
	// "elsewhere"/"somewhere" filler word before "in" — exactly the shape
	// of the assignment's dirty fixture: "documented elsewhere in the
	// codebase".
	documentedRe = regexp.MustCompile(`(?i)\b(?:documented|described|noted|explained|detailed|outlined|specified)\s+(?:elsewhere\s+|somewhere\s+)?in\s+` + citationTarget)

	// perRe matches "per X" (e.g. "per the docs"). It is deliberately NOT
	// gated on "the" being present after "per" — placeholderRe below is
	// what keeps this from flagging ordinary, non-citation uses like "per
	// item" or "per second": their targets never match any known
	// placeholder phrase, so they never reach the point of being flagged.
	perRe = regexp.MustCompile(`(?i)\bper\s+` + citationTarget)

	// extRe recognizes a target that carries a real, checkable file
	// extension even when it has no "/" (e.g. a bare "README.md").
	extRe = regexp.MustCompile(`(?i)\.(?:md|markdown|go|rs|py|ts|tsx|js|jsx|json|yaml|yml|toml|ttl|rq|txt|rst|adoc|sh|proto|lock)\b`)

	// placeholderRe recognizes a target that reads as a generic stand-in
	// for a real locator rather than an actual one — the specific,
	// checkable-without-repo-access case this package detects.
	placeholderRe = regexp.MustCompile(`(?i)\b(?:` +
		`docs?\b` +
		`|documentation\b` +
		`|(?:relevant|appropriate|right|correct|corresponding|associated|referenced|linked)\s+(?:file|files|doc|document|place|location|spot)\b` +
		`|codebase\b` +
		`|repo(?:sitory)?\b` +
		`|source(?:\s+code)?\b` +
		`|code\b` +
		`|somewhere\b` +
		`|elsewhere\b` +
		`|(?:another|other|a\s+different|a\s+separate)\s+file\b` +
		`|the\s+(?:usual|standard)\s+place\b` +
		`)`)
)

// trigger pairs a citation-shaped regex with the human-readable label used
// in a produced Match's Message.
type trigger struct {
	re    *regexp.Regexp
	label string
}

// triggers lists every citation-shaped phrasing this pattern looks for.
var triggers = []trigger{
	{seeRe, "see"},
	{documentedRe, "documented/described/noted/explained in"},
	{perRe, "per"},
}

// detector is the real, stateless fabricated-citation Pattern
// implementation. It holds no fields because Detect is a pure function of
// its (path, content) arguments — a zero value is the whole of it, which is
// exactly what init() registers below.
type detector struct{}

func (detector) ID() string { return patternID }

func (detector) Category() string { return patternCategory }

// Detect scans content line by line for a citation-shaped trigger phrase
// ("See X", "as documented in X", "per X", or a close synonym) whose target
// X both:
//
//  1. does not look like a real, checkable file locator (no "/" and no
//     recognizable extension), and
//  2. does look like one of a curated set of generic placeholder phrases
//     ("the docs", "the relevant file", "somewhere in the codebase", ...).
//
// Both conditions must hold. Condition 1 alone would also flag ordinary
// prose that happens to contain "see" or "per" ("we'll see how it
// performs", "billed per item") — condition 2 is what actually
// distinguishes a fabricated/placeholder citation from real prose that
// merely lacks a path.
func (d detector) Detect(path string, content []byte) []llmcheat.Match {
	var matches []llmcheat.Match

	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var lineNum uint
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, trig := range triggers {
			for _, sub := range trig.re.FindAllStringSubmatch(line, -1) {
				target := strings.TrimSpace(sub[1])
				if target == "" {
					continue
				}
				if looksLikeRealPath(target) {
					continue
				}
				if !placeholderRe.MatchString(target) {
					continue
				}

				matches = append(matches, llmcheat.Match{
					PatternID: patternID,
					Category:  patternCategory,
					Path:      path,
					Line:      lineNum,
					Message: fmt.Sprintf(
						"citation-shaped reference (%q trigger) points at %q, a generic placeholder with no real file locator (no %q separator, no recognizable extension) — looks like a fabricated citation",
						trig.label, target, "/",
					),
					Severity: llmcheat.SeverityMedium,
				})
			}
		}
	}

	return matches
}

// looksLikeRealPath reports whether target already looks like an actual,
// checkable file locator: it has a path separator, or it carries a
// recognizable source/doc-file extension (e.g. "docs/AUTHORITY.md",
// "README.md", "internal/foo.go").
func looksLikeRealPath(target string) bool {
	if strings.Contains(target, "/") {
		return true
	}
	return extRe.MatchString(target)
}

func init() {
	llmcheat.Register(detector{})
}
