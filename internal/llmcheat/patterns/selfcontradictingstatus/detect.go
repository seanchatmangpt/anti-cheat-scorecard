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

// Package selfcontradictingstatus implements the "self-contradicting-status"
// llmcheat.Pattern: it flags a file that claims a piece of work is
// done/complete/ALIVE in one place while, within a handful of lines, also
// marking that same nearby subject as TODO/FIXME/BLOCKED/incomplete — a
// direct, same-scope contradiction that is a classic LLM-generated status
// fabrication ("Feature complete." immediately followed by "TODO: still
// need to handle the error case above.").
//
// Line proximity (see proximityWindowLines) is used as a cheap, language- and
// file-type-agnostic proxy for "refers to the same subject": this package
// has no AST/semantic-parsing collaborator to establish true subject
// identity, and the task this pattern targets (a status comment directly
// contradicted by an adjacent outstanding-work marker) is overwhelmingly a
// local, few-lines-apart phenomenon in real LLM-authored code and docs.
package selfcontradictingstatus

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "self-contradicting-status"
	category  = "fabricated-claims"

	// proximityWindowLines is how many lines apart a "done" claim and an
	// "incomplete" marker may be and still be treated as referring to the
	// same nearby subject (a same-scope contradiction) rather than two
	// unrelated statements elsewhere in the file.
	proximityWindowLines = 5

	// maxMessageSnippet bounds how much of a matched line is echoed back in
	// a Match's Message, so a very long line doesn't blow up report output.
	maxMessageSnippet = 80
)

// doneClaimPattern matches phrasing that asserts a piece of work is
// finished/complete/ALIVE. The case-insensitive alternation covers common
// prose phrasing ("feature complete", "fully implemented", "done"); ALIVE is
// matched case-sensitively and separately, since it is a specific status
// keyword (see this repo's own STANDING vocabulary convention of always
// upper-casing status words) and lower-casing it would make "alive" match
// ordinary unrelated prose (e.g. "keep the connection alive").
var doneClaimPattern = regexp.MustCompile(
	`(?i:\b(feature\s+complete|fully\s+implemented|fully\s+working|fully\s+functional|` +
		`all\s+done|completed|complete|finished|done)\b)|\bALIVE\b`,
)

// incompleteMarkerPattern matches phrasing that flags outstanding,
// unfinished, or blocked work.
var incompleteMarkerPattern = regexp.MustCompile(
	`(?i)\b(TODO|FIXME|XXX|HACK|BLOCKED|incomplete|unimplemented|not\s+implemented|` +
		`not\s+yet\s+(?:implemented|done|finished|complete)|still\s+need(?:s)?\s+to|` +
		`still\s+needs|pending|work\s+in\s+progress|WIP)\b`,
)

// lineHit is one line that matched either the done-claim or the
// incomplete-marker pattern.
type lineHit struct {
	line uint
	text string
}

// detector is the unexported implementation of llmcheat.Pattern for this
// package. It holds no state: Detect is a pure function of its arguments.
type detector struct{}

func (detector) ID() string { return patternID }

func (detector) Category() string { return category }

// Detect scans content line-by-line, collecting every line that reads as a
// "done"-shaped claim and every line that reads as an "incomplete"-shaped
// marker, then reports one Match per marker line that has a done-claim line
// within proximityWindowLines of it (same-scope contradiction). No file-type
// restriction applies: a self-contradicting status claim is equally real in
// a .py docstring, a .go comment, a .md status doc, or a .ttl/.rq comment,
// so this pattern runs on any text content it is given.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	if bytes.IndexByte(content, 0) != -1 {
		// Binary content (a null byte present) — nothing meaningful to scan
		// as line-oriented status prose.
		return nil
	}

	var doneHits, markerHits []lineHit

	scanner := bufio.NewScanner(bytes.NewReader(content))
	// Allow long lines (e.g. minified/generated content) without the
	// scanner erroring out, while still bounding memory use per line.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var lineNo uint
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if doneClaimPattern.MatchString(line) {
			doneHits = append(doneHits, lineHit{line: lineNo, text: line})
		}
		if incompleteMarkerPattern.MatchString(line) {
			markerHits = append(markerHits, lineHit{line: lineNo, text: line})
		}
	}

	if len(doneHits) == 0 || len(markerHits) == 0 {
		// Need both a claim and a marker present at all before proximity
		// even matters.
		return nil
	}

	var matches []llmcheat.Match
	for _, marker := range markerHits {
		claim, _, found := closestWithin(doneHits, marker.line, proximityWindowLines)
		if !found {
			continue
		}

		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      marker.line,
			Message: fmt.Sprintf(
				"line %d claims completion (%q) but nearby line %d flags outstanding work (%q) — self-contradicting status",
				claim.line, snippet(claim.text), marker.line, snippet(marker.text),
			),
			Severity: llmcheat.SeverityMedium,
		})
	}

	return matches
}

// closestWithin returns the doneHit closest (by absolute line distance) to
// targetLine among hits, provided that distance is <= window. The second
// return value reports whether any hit fell within the window.
func closestWithin(hits []lineHit, targetLine uint, window uint) (lineHit, uint, bool) {
	var best lineHit
	var bestDist uint
	found := false

	for _, h := range hits {
		dist := lineDistance(h.line, targetLine)
		if dist > window {
			continue
		}
		if !found || dist < bestDist {
			best = h
			bestDist = dist
			found = true
		}
	}

	return best, bestDist, found
}

// lineDistance returns the absolute difference between two 1-based line
// numbers.
func lineDistance(a, b uint) uint {
	if a > b {
		return a - b
	}
	return b - a
}

// snippet trims and bounds a matched line for inclusion in a Match message.
func snippet(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxMessageSnippet {
		return s[:maxMessageSnippet] + "..."
	}
	return s
}

func init() {
	llmcheat.Register(detector{})
}
