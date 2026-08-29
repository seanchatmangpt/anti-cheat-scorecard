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

// Package ttlclaimtriplewithoutreceipt implements the
// "ttl-claim-triple-without-receipt" llmcheat.Pattern: it flags an RDF/Turtle
// (.ttl) triple whose predicate or object term looks like a status/standing
// assertion (contains "standing", "status", ":alive", ":verified", or
// ":done", case-insensitive) and whose object literal is one of a small set
// of strong, unqualified claim values ("ALIVE", "true", "verified", "done",
// "complete", case-insensitive, exact match) — but ONLY when the whole graph
// file contains zero mention of "receipt" or "evidence" (case-insensitive)
// anywhere. A graph that asserts a strong standing claim while carrying not
// a single evidence-shaped predicate anywhere in the same file is treated as
// the whole-graph equivalent of an unbacked claim: this mirrors
// ggen-ecosystem's own STANDING.md rule that a crown claim like ALIVE
// requires a receipt chain, projected onto raw Turtle triples rather than
// prose.
//
// This is a coarse, line-oriented Turtle heuristic, not a real RDF parser:
// it recognizes the common `predicate "object"` / `predicate 'object'` /
// `predicate true` adjacency (prefixed-name or <IRI> predicate immediately
// followed by a literal object on the same line), which covers the
// overwhelming majority of hand- or LLM-authored status/standing triples in
// this ecosystem's own ontology files. It deliberately does not attempt to
// track subjects across `;`/`,` predicate-object-list continuations or
// multi-line literals — the evidence gate is file-wide, so a continuation
// line carrying `ex:evidence <...>` still suppresses the match regardless of
// which line the standing triple itself is on.
package ttlclaimtriplewithoutreceipt

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "ttl-claim-triple-without-receipt"
	category  = "semantic-web-integrity"
)

// standingKeywords are the substrings (case-insensitive) whose presence in
// either the predicate term or the object term marks a triple as a
// status/standing assertion, per the pattern description.
var standingKeywords = []string{"standing", "status", ":alive", ":verified", ":done"}

// strongClaimValues are the exact (case-insensitive, whitespace-trimmed)
// object literal values that count as an unqualified strong claim.
var strongClaimValues = map[string]bool{
	"alive":    true,
	"true":     true,
	"verified": true,
	"done":     true,
	"complete": true,
}

// termPattern matches a Turtle term usable as a predicate: a prefixed name
// (prefix:localname, e.g. "ex:standing") or a full IRI ("<...>").
const termPattern = `(?:[A-Za-z_][\w-]*:[A-Za-z_][\w.-]*|<[^>]+>)`

// quotedObjectRe matches "<predicate-term> <ws> <quoted-literal>" — the
// common shape of a Turtle triple's tail written on a single line, e.g.
// `ex:standing "ALIVE"` inside `ex:gate9 ex:standing "ALIVE" .`. Group 1 is
// the predicate term; group 2 is a double-quoted literal's content, group 3
// a single-quoted literal's content (exactly one of the two is non-empty
// for any real match — the other is left as "" by Go's regexp package for
// the alternative that did not participate).
var quotedObjectRe = regexp.MustCompile(`(` + termPattern + `)\s+(?:"([^"]*)"|'([^']*)')`)

// boolObjectRe matches "<predicate-term> <ws> true|false" — Turtle's bare
// (unquoted) xsd:boolean literal shorthand, e.g. `ex:verified true .`.
var boolObjectRe = regexp.MustCompile(`(?i)(` + termPattern + `)\s+\b(true|false)\b`)

// detector is the unexported implementation of llmcheat.Pattern for this
// pattern. It holds no state: Detect is a pure function of its arguments.
type detector struct{}

func (detector) ID() string { return patternID }

func (detector) Category() string { return category }

func init() {
	llmcheat.Register(detector{})
}

// Detect scans path's content only when path is a .ttl file. It first
// applies the file-wide evidence gate (if "receipt" or "evidence" appears
// anywhere in the file, case-insensitive, the whole file is exempt and
// Detect returns no matches at all), then scans line by line for a
// standing-shaped predicate paired with a strong-claim object literal.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	if len(content) == 0 {
		return nil
	}
	if !isTTLPath(path) {
		return nil
	}

	lowerText := strings.ToLower(string(content))
	if strings.Contains(lowerText, "receipt") || strings.Contains(lowerText, "evidence") {
		return nil
	}

	var matches []llmcheat.Match
	for i, line := range splitLines(content) {
		for _, part := range extractTripleParts(line) {
			if !looksLikeStandingAssertion(part.predicate, part.object) {
				continue
			}
			if !isStrongClaimValue(part.object) {
				continue
			}
			lineNo := uint(i + 1) // 1-based
			matches = append(matches, llmcheat.Match{
				PatternID: patternID,
				Category:  category,
				Path:      path,
				Line:      lineNo,
				Message: fmt.Sprintf(
					"triple on line %d asserts a strong standing/status claim (predicate %s, object %q) but no line in the file mentions \"receipt\" or \"evidence\"",
					lineNo, part.predicate, part.object,
				),
				Severity: severityFor(part.object),
			})
		}
	}
	return matches
}

// triplePart is one (predicate, object-literal-text) pair extracted from a
// single line of Turtle.
type triplePart struct {
	predicate string
	object    string
}

// extractTripleParts finds every predicate-then-literal-object adjacency on
// line, covering both quoted-string and bare-boolean object shapes.
func extractTripleParts(line string) []triplePart {
	var out []triplePart

	for _, m := range quotedObjectRe.FindAllStringSubmatch(line, -1) {
		obj := m[2]
		if obj == "" {
			obj = m[3]
		}
		out = append(out, triplePart{predicate: m[1], object: obj})
	}

	for _, m := range boolObjectRe.FindAllStringSubmatch(line, -1) {
		out = append(out, triplePart{predicate: m[1], object: m[2]})
	}

	return out
}

// looksLikeStandingAssertion reports whether predicate or object contains
// (case-insensitive) any of standingKeywords.
func looksLikeStandingAssertion(predicate, object string) bool {
	p := strings.ToLower(predicate)
	o := strings.ToLower(object)
	for _, kw := range standingKeywords {
		if strings.Contains(p, kw) || strings.Contains(o, kw) {
			return true
		}
	}
	return false
}

// isStrongClaimValue reports whether object, trimmed and lower-cased,
// exactly matches one of strongClaimValues.
func isStrongClaimValue(object string) bool {
	return strongClaimValues[strings.ToLower(strings.TrimSpace(object))]
}

// severityFor triages by how close the claimed value is to this
// ecosystem's own crown-claim spelling: an exact "ALIVE" gets the highest
// severity, everything else in the strong-claim set is still a bare,
// unqualified claim but a step down.
func severityFor(object string) llmcheat.Severity {
	if strings.EqualFold(strings.TrimSpace(object), "alive") {
		return llmcheat.SeverityHigh
	}
	return llmcheat.SeverityMedium
}

// isTTLPath reports whether path names a Turtle file by extension.
func isTTLPath(path string) bool {
	return strings.EqualFold(filepath.Ext(path), ".ttl")
}

// splitLines splits content into lines, dropping a trailing '\r' from each
// (so CRLF files behave the same as LF files) and never returning a
// trailing empty line caused solely by a final '\n'.
func splitLines(content []byte) []string {
	raw := strings.Split(string(content), "\n")
	if len(raw) > 0 && raw[len(raw)-1] == "" {
		raw = raw[:len(raw)-1]
	}
	out := make([]string, len(raw))
	for i, l := range raw {
		out[i] = strings.TrimSuffix(l, "\r")
	}
	return out
}
