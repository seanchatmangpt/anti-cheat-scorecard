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

// Package rdfblanknodestatusclaim implements the "rdf-blank-node-status-claim"
// llmcheat.Pattern: it flags a Turtle (.ttl) triple whose SUBJECT is a blank
// node — either a labelled blank node ("_:label ...") or an anonymous
// "[ ... ]" property list — and whose predicate looks like a status/standing
// assertion (matches /standing|status|alive|verified/i). A status claim
// attached to a node with no stable, referenceable identity (an IRI) can
// never be looked up or audited later: the very next graph load can mint a
// different, unrelated blank node label, so "who is ALIVE" becomes
// unanswerable.
//
// Turtle allows a "[ ... ]" property list at either the subject or the
// object position of an enclosing statement, and at any nesting depth
// (e.g. ":s :hasReport [ :standing \"ALIVE\" ] .") — in every one of those
// positions the predicates written directly inside the brackets have that
// anonymous blank node as their real RDF subject, regardless of where the
// brackets themselves sit syntactically. This detector treats every
// "[ ... ]" span the same way for that reason.
//
// This is a heuristic, line/byte-oriented scanner over Turtle's surface
// syntax, not a real RDF parser: it masks quoted string literals, IRIREFs
// ("<...>"), and "#"-comments (so punctuation inside any of them — most
// commonly a "#" inside a namespace IRI on an "@prefix" line — can't be
// mistaken for real triple structure) and then tracks bracket nesting and
// statement-terminator periods textually. It does not resolve prefixes and
// does not validate IRIs. One consequence of masking IRIREF content: a
// predicate written as a bare full IRI ("<https://ex.org/standing>") rather
// than a prefixed name ("ex:standing") will not be matched against the
// status/standing keyword regex — an accepted, narrow heuristic limitation,
// since prefixed names are overwhelmingly the standard style and masking
// IRIREF content is what keeps ordinary "@prefix ex: <https://ex.org/ns#> ."
// declarations (near-universal in real Turtle) from being misread as an
// unterminated comment.
package rdfblanknodestatusclaim

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "rdf-blank-node-status-claim"
	category  = "semantic-web-integrity"
)

// statusPredicateRe matches the status/standing vocabulary named in the
// pattern description, case-insensitively, as a substring of the predicate
// token (predicates are commonly prefixed local names like "ex:standing" or
// "ex:isVerified", not always a bare word).
var statusPredicateRe = regexp.MustCompile(`(?i)(standing|status|alive|verified)`)

// detector is the unexported implementation of llmcheat.Pattern for this
// pattern. It holds no state: Detect is a pure function of its arguments.
type detector struct{}

func (detector) ID() string { return patternID }

func (detector) Category() string { return category }

func init() {
	llmcheat.Register(detector{})
}

// Detect scans a .ttl file's content for status/standing predicates whose
// subject is a blank node. Non-.ttl files and empty content are ignored.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	if !isTurtlePath(path) || len(content) == 0 {
		return nil
	}

	structural := maskStringsAndComments(content)
	spans := bracketSpans(structural)

	// work is mutated as spans are consumed (innermost first) so that a
	// span's "own" predicate list never includes predicates that actually
	// belong to a nested blank node.
	work := append([]byte(nil), structural...)

	var matches []llmcheat.Match

	ordered := append([]span(nil), spans...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].depth > ordered[j].depth })

	for _, sp := range ordered {
		own := append([]byte(nil), work[sp.start+1:sp.end]...)
		for _, pm := range findPredicateTokens(own, sp.start+1) {
			if kw := statusPredicateRe.FindString(pm.text); kw != "" {
				matches = append(matches, buildMatch(path, content, pm.offset, pm.text, kw,
					"an anonymous blank node `[ ... ]`"))
			}
		}
		blankRange(work, sp.start, sp.end+1)
	}

	// By this point every "[ ... ]" span at every depth has been blanked out
	// of work entirely (brackets included), so what remains is exactly the
	// top-level subject/predicate/object text and statement-terminating
	// periods — no bracket nesting to track any more.
	for _, st := range topLevelStatements(work) {
		raw := work[st.start:st.end]
		lead := len(raw) - len(bytesTrimLeftSpace(raw))
		subjStart := st.start + lead
		tokLen := tokenLength(work, subjStart)
		if tokLen == 0 {
			continue
		}
		subject := string(work[subjStart : subjStart+tokLen])
		if !strings.HasPrefix(subject, "_:") {
			continue // subject is not a blank node
		}

		predAreaStart := subjStart + tokLen
		predArea := append([]byte(nil), work[predAreaStart:st.end]...)
		for _, pm := range findPredicateTokens(predArea, predAreaStart) {
			if kw := statusPredicateRe.FindString(pm.text); kw != "" {
				matches = append(matches, buildMatch(path, content, pm.offset, pm.text, kw,
					fmt.Sprintf("the named blank node `%s`", subject)))
			}
		}
	}

	return matches
}

// isTurtlePath reports whether path names a Turtle file by extension.
func isTurtlePath(path string) bool {
	return strings.EqualFold(filepath.Ext(path), ".ttl")
}

// severityFor triages by how strong/official the matched status keyword is.
// "alive" and "verified" mirror this ecosystem's own standing-vocabulary
// crown claims and get the highest severity; "standing"/"status" are the
// generic predicate-name shape and get medium.
func severityFor(keyword string) llmcheat.Severity {
	switch strings.ToLower(keyword) {
	case "alive", "verified":
		return llmcheat.SeverityHigh
	default: // "standing", "status"
		return llmcheat.SeverityMedium
	}
}

// buildMatch constructs the llmcheat.Match for one status-predicate hit,
// computing a real 1-based line number from offset's position in content.
func buildMatch(path string, content []byte, offset int, predText, keyword, scopeDesc string) llmcheat.Match {
	return llmcheat.Match{
		PatternID: patternID,
		Category:  category,
		Path:      path,
		Line:      lineForOffset(content, offset),
		Message: fmt.Sprintf(
			"predicate %q on %s looks like a status/standing claim (matched %q) but a blank "+
				"node has no stable, referenceable identity — the claim can never be looked up "+
				"or audited again once the graph is reloaded",
			predText, scopeDesc, keyword,
		),
		Severity: severityFor(keyword),
	}
}

// lineForOffset returns the 1-based line number of byte index offset within
// content, by counting newlines that precede it.
func lineForOffset(content []byte, offset int) uint {
	if offset < 0 {
		offset = 0
	}
	if offset > len(content) {
		offset = len(content)
	}
	line := uint(1)
	for _, c := range content[:offset] {
		if c == '\n' {
			line++
		}
	}
	return line
}

// span is one matched "[" ... "]" bracket pair in a masked buffer. depth is
// its nesting depth (1 = not nested inside any other bracket).
type span struct {
	start, end, depth int
}

// bracketSpans finds every matched "[...]" pair in m (which must already
// have quoted literals and comments masked out, so stray "[" / "]" bytes
// inside a string value are never mistaken for real Turtle syntax) and
// returns them along with their nesting depth. An unmatched "]" is ignored;
// an unmatched "[" never becomes a span.
func bracketSpans(m []byte) []span {
	var stack []int
	var out []span
	for i, c := range m {
		switch c {
		case '[':
			stack = append(stack, i)
		case ']':
			if len(stack) == 0 {
				continue
			}
			start := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			out = append(out, span{start: start, end: i, depth: len(stack) + 1})
		}
	}
	return out
}

// stmt is one top-level, period-terminated statement's byte range in a
// buffer, [start, end) — end is the index of the terminating '.', not
// included.
type stmt struct {
	start, end int
}

// topLevelStatements splits work (which must already have every bracket
// span blanked out, so no ';' or '.' from inside a "[...]" property list
// can leak through) into period-terminated statements. A '.' counts as a
// statement terminator when it is not part of a decimal number (digit on
// both sides) and is followed by whitespace or end-of-buffer.
func topLevelStatements(work []byte) []stmt {
	var out []stmt
	prev := 0
	for i := 0; i < len(work); i++ {
		if work[i] != '.' {
			continue
		}
		if i > 0 && isDigitByte(work[i-1]) && i+1 < len(work) && isDigitByte(work[i+1]) {
			continue // decimal point, e.g. "3.14"
		}
		if i+1 < len(work) && !isSpaceByte(work[i+1]) {
			continue // not followed by whitespace/EOF: not a real terminator
		}
		out = append(out, stmt{start: prev, end: i})
		prev = i + 1
	}
	return out
}

// predicateMatch is one candidate predicate token found by
// findPredicateTokens, with its absolute byte offset in the original file.
type predicateMatch struct {
	offset int
	text   string
}

// findPredicateTokens splits scope on top-level ';' (a Turtle
// predicateObjectList separator) and returns the leading whitespace-
// delimited token of each ';'-separated group — i.e. each group's
// predicate — together with its absolute offset (scope's own bytes start at
// baseOffset in the original file). A group that is empty or
// whitespace-only (e.g. because a nested "[...]" consumed all of it) yields
// no token.
func findPredicateTokens(scope []byte, baseOffset int) []predicateMatch {
	var out []predicateMatch
	segStart := 0
	for i := 0; i <= len(scope); i++ {
		if i == len(scope) || scope[i] == ';' {
			seg := scope[segStart:i]
			if pm, ok := leadingToken(seg, baseOffset+segStart); ok {
				out = append(out, pm)
			}
			segStart = i + 1
		}
	}
	return out
}

// leadingToken returns the first whitespace-delimited token in seg (skipping
// leading whitespace) and its absolute offset, or ok=false if seg has no
// non-whitespace content.
func leadingToken(seg []byte, baseOffset int) (predicateMatch, bool) {
	i := 0
	for i < len(seg) && isSpaceByte(seg[i]) {
		i++
	}
	j := i
	for j < len(seg) && !isSpaceByte(seg[j]) {
		j++
	}
	if j == i {
		return predicateMatch{}, false
	}
	return predicateMatch{offset: baseOffset + i, text: string(seg[i:j])}, true
}

// blankRange overwrites buf[start:end] with spaces, leaving any '\n' bytes
// in that range untouched so line-number accounting stays correct for
// everything scanned afterward.
func blankRange(buf []byte, start, end int) {
	if start < 0 {
		start = 0
	}
	if end > len(buf) {
		end = len(buf)
	}
	for i := start; i < end; i++ {
		if buf[i] != '\n' {
			buf[i] = ' '
		}
	}
}

// bytesTrimLeftSpace returns b with any leading whitespace bytes removed.
func bytesTrimLeftSpace(b []byte) []byte {
	i := 0
	for i < len(b) && isSpaceByte(b[i]) {
		i++
	}
	return b[i:]
}

// tokenLength returns the length of the run of non-whitespace bytes in b
// starting at start (0 if start is itself whitespace or out of range).
func tokenLength(b []byte, start int) int {
	i := start
	for i < len(b) && !isSpaceByte(b[i]) {
		i++
	}
	return i - start
}

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

func isDigitByte(c byte) bool {
	return c >= '0' && c <= '9'
}

// maskStringsAndComments returns a same-length copy of content with every
// byte inside a Turtle quoted string literal ('"…"', "'…'", '"""…"""',
// "”'…”'"), an IRIREF ("<...>"), or a '#'-to-end-of-line comment replaced
// with a space — newlines are always preserved so line-number accounting
// stays correct. Masking IRIREF content specifically prevents a "#" inside
// an ordinary namespace IRI (e.g. "@prefix ex: <https://ex.org/ns#> .") from
// being misread as the start of a comment.
func maskStringsAndComments(content []byte) []byte {
	out := append([]byte(nil), content...)
	n := len(out)
	i := 0
	for i < n {
		switch {
		case out[i] == '#':
			for i < n && out[i] != '\n' {
				out[i] = ' '
				i++
			}
		case hasPrefixAt(out, i, `"""`):
			i = maskDelimited(out, i, `"""`)
		case hasPrefixAt(out, i, `'''`):
			i = maskDelimited(out, i, `'''`)
		case out[i] == '"':
			i = maskDelimited(out, i, `"`)
		case out[i] == '\'':
			i = maskDelimited(out, i, `'`)
		case out[i] == '<':
			i = maskAngleIRI(out, i)
		default:
			i++
		}
	}
	return out
}

// maskAngleIRI masks a Turtle IRIREF starting at start (out[start] == '<')
// through its matching '>', honoring a single backslash-escape before any
// character so an escaped '>' inside the IRI doesn't end it early. It
// returns the index just past the masked region (or len(out) if the '<' was
// never closed).
func maskAngleIRI(out []byte, start int) int {
	n := len(out)
	i := start
	maskByte(out, i)
	i++
	for i < n {
		if out[i] == '\\' && i+1 < n {
			maskByte(out, i)
			maskByte(out, i+1)
			i += 2
			continue
		}
		if out[i] == '>' {
			maskByte(out, i)
			i++
			return i
		}
		maskByte(out, i)
		i++
	}
	return i
}

// hasPrefixAt reports whether b[i:] starts with prefix.
func hasPrefixAt(b []byte, i int, prefix string) bool {
	end := i + len(prefix)
	if end > len(b) {
		return false
	}
	return string(b[i:end]) == prefix
}

// maskDelimited masks the delimited literal starting at start (start must
// be the index of delim's opening occurrence) — including both delimiters —
// up to and including its closing occurrence of delim, honoring a single
// backslash-escape before any character (so an escaped delimiter inside the
// literal doesn't end it early). It returns the index just past the masked
// region (or len(out) if the literal was never closed).
func maskDelimited(out []byte, start int, delim string) int {
	n := len(out)
	dl := len(delim)
	i := start
	for k := 0; k < dl && i < n; k++ {
		maskByte(out, i)
		i++
	}
	for i < n {
		if out[i] == '\\' && i+1 < n {
			maskByte(out, i)
			maskByte(out, i+1)
			i += 2
			continue
		}
		if hasPrefixAt(out, i, delim) {
			for k := 0; k < dl; k++ {
				maskByte(out, i)
				i++
			}
			return i
		}
		maskByte(out, i)
		i++
	}
	return i
}

// maskByte replaces out[i] with a space unless it is a newline.
func maskByte(out []byte, i int) {
	if out[i] != '\n' {
		out[i] = ' '
	}
}
