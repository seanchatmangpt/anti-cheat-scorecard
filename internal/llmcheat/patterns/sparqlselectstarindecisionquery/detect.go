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

// Package sparqlselectstarindecisionquery implements the
// "sparql-select-star-in-decision-query" llmcheat.Pattern: it flags a
// wildcard "SELECT *" (optionally "SELECT DISTINCT *" / "SELECT REDUCED *")
// projection in a .rq SPARQL query file.
//
// A decision query — one whose result is consumed by a downstream template,
// script, or gate/standing computation — exists precisely to name the exact
// fields that downstream logic depends on. "SELECT *" erases that contract:
// a reviewer can no longer tell, from the query text alone, which bindings
// the consumer actually reads versus which happen to ride along in the
// result set. That is exactly the kind of audit-defeating vagueness this
// tool exists to catch, applied to the semantic-web layer instead of to
// source code.
package sparqlselectstarindecisionquery

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "sparql-select-star-in-decision-query"
	category  = "semantic-web-integrity"
)

// selectStarRe matches a SPARQL SELECT clause whose projection is the bare
// wildcard "*", with an optional DISTINCT/REDUCED solution modifier between
// SELECT and the star, case-insensitively, and tolerant of arbitrary
// whitespace (including newlines, since Go's RE2 \s already matches \n) —
// e.g. "SELECT *", "select   *", "SELECT DISTINCT *", or SELECT and * split
// across lines by a formatter. It intentionally requires the literal
// "SELECT" keyword immediately (module whitespace/DISTINCT/REDUCED) before
// the "*", so it does not fire on an aggregate like "SELECT (COUNT(*) AS
// ?c)" — there the character after SELECT's whitespace is "(", not "*".
var selectStarRe = regexp.MustCompile(`(?i)\bSELECT\b\s*(?:(?:DISTINCT|REDUCED)\s+)?\*`)

// detector is the real, stateless implementation of llmcheat.Pattern for
// this pattern. It has no fields because Detect is a pure function of its
// arguments; it exists as a named type only so it can implement the
// interface and be registered.
type detector struct{}

func init() {
	llmcheat.Register(detector{})
}

func (detector) ID() string       { return patternID }
func (detector) Category() string { return category }

// Detect scans .rq files only (any other extension is skipped outright,
// including files with no extension). It first masks out SPARQL line
// comments ("#" to end of line, honoring simple '...'/"..." string-literal
// quoting so a "#" inside a bound string value is never mistaken for a
// comment marker) so that a "SELECT *" appearing only in a comment — e.g.
// documentation explaining why NOT to use it — is never flagged. It then
// finds every wildcard-select occurrence in the remaining (real query)
// text and reports it with a real 1-based line number, computed by
// counting newlines in the original content up to the match's byte offset.
func (d detector) Detect(path string, content []byte) []llmcheat.Match {
	if !strings.EqualFold(filepath.Ext(path), ".rq") {
		return nil
	}
	if len(content) == 0 {
		return nil
	}

	masked := maskLineComments(content)

	locs := selectStarRe.FindAllIndex(masked, -1)
	if len(locs) == 0 {
		return nil
	}

	matches := make([]llmcheat.Match, 0, len(locs))
	for _, loc := range locs {
		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      lineAt(content, loc[0]),
			Message: `"SELECT *" wildcard projection hides which fields this decision query actually depends on; ` +
				`enumerate the exact variables selected (e.g. "SELECT ?gate ?standing") so a downstream ` +
				`template or script's real dependency on the graph is auditable from the query text alone`,
			Severity: llmcheat.SeverityMedium,
		})
	}
	return matches
}

// maskLineComments returns a same-length copy of content with every SPARQL
// line comment ("#" through end of line) overwritten with spaces, while
// leaving every newline byte untouched — so byte offsets and line numbers
// computed against the result stay valid against the original content. A
// "#" is only treated as starting a comment when it appears outside a
// simple '...' or "..." string literal (backslash-escaped quotes inside a
// literal are honored); SPARQL's triple-quoted long-string form is not
// modeled, since decision queries in this repository's convention bind
// short scalar/IRI values, not multi-line literals.
func maskLineComments(content []byte) []byte {
	out := make([]byte, len(content))
	copy(out, content)

	var inQuote byte
	for i := 0; i < len(out); i++ {
		c := out[i]
		switch {
		case inQuote != 0:
			switch {
			case c == '\\' && i+1 < len(out):
				i++ // skip the escaped character
			case c == inQuote:
				inQuote = 0
			case c == '\n':
				inQuote = 0 // defensive: an unterminated literal never masks past its own line
			}
		case c == '\'' || c == '"':
			inQuote = c
		case c == '#':
			for i < len(out) && out[i] != '\n' {
				out[i] = ' '
				i++
			}
		}
	}
	return out
}

// lineAt returns the 1-based line number of the byte at offset in content.
func lineAt(content []byte, offset int) uint {
	line := uint(1)
	if offset > len(content) {
		offset = len(content)
	}
	for i := 0; i < offset; i++ {
		if content[i] == '\n' {
			line++
		}
	}
	return line
}
