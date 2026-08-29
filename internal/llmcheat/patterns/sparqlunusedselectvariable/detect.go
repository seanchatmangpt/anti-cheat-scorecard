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

// Package sparqlunusedselectvariable implements the
// "sparql-unused-select-variable" llmcheat.Pattern: it scans .rq SPARQL
// query files for a non-wildcard SELECT clause that lists a `?var`/`$var`
// projection variable the query's own WHERE clause body never binds. A
// SPARQL SELECT variable that never appears inside WHERE { ... } is a real
// correctness defect — that result column is guaranteed to be unbound
// (empty) for every solution — and is a common artifact of a query that
// was authored by pattern-matching against a shape rather than actually
// run against the graph it claims to describe: the classic
// "looks-plausible, never-executed" shape this tool exists to catch.
package sparqlunusedselectvariable

import (
	"bytes"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "sparql-unused-select-variable"
	category  = "semantic-web-integrity"
)

var (
	// selectRe locates the (first, outermost) SELECT keyword. SPARQL
	// keywords are case-insensitive per the grammar, so this matches
	// "SELECT", "Select", "select", etc.
	selectRe = regexp.MustCompile(`(?i)\bSELECT\b`)

	// whereRe locates the WHERE keyword that closes the SELECT clause's
	// variable list. SPARQL also permits an implicit-WHERE form
	// (`SELECT ?x { ... }`, no WHERE keyword) — that form is handled
	// separately by falling back to the first `{` when whereRe finds
	// nothing after SELECT.
	whereRe = regexp.MustCompile(`(?i)\bWHERE\b`)

	// modifierRe strips a single leading DISTINCT or REDUCED solution
	// modifier from the trimmed SELECT-clause text so the wildcard check
	// below isn't fooled by "SELECT DISTINCT * WHERE { ... }".
	modifierRe = regexp.MustCompile(`(?i)^(DISTINCT|REDUCED)\s+`)

	// selectVarRe finds every `?name` / `$name` token inside the SELECT
	// clause text (i.e. between the SELECT keyword and the WHERE clause
	// boundary), capturing the bare name (sigil stripped).
	selectVarRe = regexp.MustCompile(`[?$]([A-Za-z_][A-Za-z0-9_]*)`)

	// asTargetRe finds `AS ?name` / `AS $name` bindings inside the SELECT
	// clause text. A variable introduced this way (e.g.
	// `(COUNT(?item) AS ?itemCount)`) is computed by the SELECT clause
	// itself, not read out of WHERE, so it is legitimately exempt from
	// the "must also appear in WHERE" requirement — flagging it would be
	// a false positive on an extremely common, correct SPARQL idiom.
	asTargetRe = regexp.MustCompile(`(?i)\bAS\s+[?$]([A-Za-z_][A-Za-z0-9_]*)`)
)

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

// Detect scans .rq files only. It locates the (first) SELECT clause and its
// WHERE clause body via brace matching, skips wildcard SELECT queries
// ("SELECT *", including with a DISTINCT/REDUCED modifier) as not
// applicable to this pattern, then flags every distinct projection
// variable named in the SELECT clause that never occurs — as `?name` or
// `$name` — anywhere inside the WHERE clause body, except for variables
// bound in the SELECT clause itself via an `AS ?name` expression.
//
// Known scope limits (deliberate, to keep this a real but bounded
// heuristic rather than a full SPARQL parser): only the first top-level
// SELECT ... WHERE { ... } in the file is examined (sufficient for the
// single-query .rq files this project's queries/ directory contains);
// `#`-comments are not stripped, since a naive strip would also truncate
// IRIs containing '#' (e.g. `<http://example.org/onto#Type>`); and GROUP
// BY / ORDER BY / HAVING clauses following WHERE are out of scope — this
// pattern is specifically about the SELECT-vs-WHERE binding relationship.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	if !strings.EqualFold(filepath.Ext(path), ".rq") {
		return nil
	}

	src := string(content)

	selLoc := selectRe.FindStringIndex(src)
	if selLoc == nil {
		return nil
	}
	selectClauseStart := selLoc[1]

	// Locate the WHERE keyword after SELECT, if present, and from there
	// (or from the SELECT clause directly, for the implicit-WHERE form)
	// find the opening '{' of the WHERE body.
	var selectClauseEnd, braceOpen int
	if whereLoc := whereRe.FindStringIndex(src[selectClauseStart:]); whereLoc != nil {
		selectClauseEnd = selectClauseStart + whereLoc[0]
		whereKeywordEnd := selectClauseStart + whereLoc[1]
		rel := strings.IndexByte(src[whereKeywordEnd:], '{')
		if rel == -1 {
			return nil // malformed / unparseable — no false claim
		}
		braceOpen = whereKeywordEnd + rel
	} else {
		rel := strings.IndexByte(src[selectClauseStart:], '{')
		if rel == -1 {
			return nil
		}
		braceOpen = selectClauseStart + rel
		selectClauseEnd = braceOpen
	}

	braceClose := findMatchingBrace(src, braceOpen)
	if braceClose == -1 {
		return nil // unbalanced braces — unparseable, no false claim
	}
	whereBody := src[braceOpen : braceClose+1]

	selectClause := src[selectClauseStart:selectClauseEnd]

	// Wildcard SELECT ("SELECT *" / "SELECT DISTINCT *") is out of scope
	// for this pattern — there is no explicit variable list to check.
	trimmed := modifierRe.ReplaceAllString(strings.TrimSpace(selectClause), "")
	if strings.HasPrefix(strings.TrimSpace(trimmed), "*") {
		return nil
	}

	// Variables bound via "AS ?name" inside the SELECT clause are
	// computed there, not projected from WHERE — exempt by name.
	exempt := map[string]bool{}
	for _, sm := range asTargetRe.FindAllStringSubmatch(selectClause, -1) {
		exempt[sm[1]] = true
	}

	// Collect every distinct variable named in the SELECT clause, in
	// first-appearance order, with the absolute offset (into the full
	// file content) of its first occurrence for line-number reporting.
	var order []string
	firstOffset := map[string]int{}
	for _, m := range selectVarRe.FindAllStringSubmatchIndex(selectClause, -1) {
		name := selectClause[m[2]:m[3]]
		if _, seen := firstOffset[name]; seen {
			continue
		}
		firstOffset[name] = selectClauseStart + m[0]
		order = append(order, name)
	}

	var matches []llmcheat.Match
	for _, name := range order {
		if exempt[name] {
			continue
		}
		whereRefRe := regexp.MustCompile(`[?$]` + regexp.QuoteMeta(name) + `\b`)
		if whereRefRe.MatchString(whereBody) {
			continue
		}
		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      lineAt(content, firstOffset[name]),
			Message: fmt.Sprintf(
				"SELECT clause projects variable %q but the WHERE clause body never binds it — this result column will always be unbound",
				"?"+name,
			),
			Severity: llmcheat.SeverityMedium,
		})
	}

	return matches
}

// findMatchingBrace returns the index of the '}' that closes the '{' at
// openIdx (which must itself be a '{'), accounting for nested braces
// (OPTIONAL/UNION/FILTER NOT EXISTS/etc. blocks inside WHERE all nest
// braces). Returns -1 if the braces are unbalanced.
func findMatchingBrace(s string, openIdx int) int {
	depth := 0
	for i := openIdx; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// lineAt returns the 1-based line number of the byte offset in content.
func lineAt(content []byte, offset int) uint {
	if offset < 0 {
		offset = 0
	}
	if offset > len(content) {
		offset = len(content)
	}
	return uint(bytes.Count(content[:offset], []byte("\n")) + 1)
}
