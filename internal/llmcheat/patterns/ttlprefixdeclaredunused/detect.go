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

// Package ttlprefixdeclaredunused implements the "ttl-prefix-declared-unused"
// llmcheat.Pattern: it flags Turtle (.ttl) files that declare an @prefix
// whose short name is never used elsewhere in the file as "name:something".
// A prefix block copy-pasted wholesale from another ontology (rdf, rdfs,
// owl, xsd, dc, skos, ...) commonly carries entries nobody in this file
// actually authored a triple against — declared-but-unused boilerplate is a
// concrete, checkable signal of that, distinct from a legitimate but
// currently-empty-of-use prefix a human deliberately reserved.
package ttlprefixdeclaredunused

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// patternID and category are the two identifiers this detector self-registers
// under; they must stay in sync with what ID()/Category() return.
const (
	patternID = "ttl-prefix-declared-unused"
	category  = "semantic-web-integrity"
)

func init() {
	llmcheat.Register(&detector{})
}

// detector is the unexported llmcheat.Pattern implementation. It holds no
// state of its own (state lives entirely on the stack built fresh inside
// each Detect call), so a single shared instance is safe to register once.
type detector struct{}

func (d *detector) ID() string       { return patternID }
func (d *detector) Category() string { return category }

// prefixDeclRe matches a Turtle "@prefix name: <iri> ." directive and
// captures the short prefix name (the part before the colon). The name
// group is optional so the default/unnamed prefix form "@prefix : <iri> ."
// (a bare colon) is also recognized, capturing an empty string — that
// default prefix is checked for use exactly like any named one, via bare
// ":localname" references elsewhere in the file.
var prefixDeclRe = regexp.MustCompile(`^\s*@prefix\s+([A-Za-z_][\w.-]*)?:\s*<[^>]*>\s*\.`)

// prefixDecl is one @prefix directive found in the file: its short name and
// the 1-based line it was declared on.
type prefixDecl struct {
	name string
	line uint
}

// Detect is a pure function: it gates on the .ttl extension, then makes two
// passes over the file's lines. The first pass extracts every @prefix
// declaration and builds a "body" of the remaining, comment-stripped
// content (declaration lines contribute nothing to the body, since a
// directive's own "name:" is not a use of that prefix). The second pass
// checks, per declared name, whether "name:" followed by a non-whitespace
// character ever appears in that body — if it never does, the prefix is
// flagged as declared-but-unused at its declaration line.
func (d *detector) Detect(path string, content []byte) []llmcheat.Match {
	if !strings.EqualFold(filepath.Ext(path), ".ttl") {
		return nil
	}

	lines := strings.Split(string(content), "\n")

	var decls []prefixDecl
	var body strings.Builder
	body.Grow(len(content))

	for i, rawLine := range lines {
		lineNo := uint(i + 1) //nolint:gosec // i is bounded by len(lines), never near uint overflow

		// Strip trailing "#" comments before matching or accumulating into
		// the usage-scan body, so neither a commented-out @prefix directive
		// nor a prefix name merely mentioned in prose inside a comment is
		// mistaken for a real declaration or a real use.
		codeLine := stripLineComment(rawLine)

		if m := prefixDeclRe.FindStringSubmatch(codeLine); m != nil {
			decls = append(decls, prefixDecl{name: m[1], line: lineNo})
			body.WriteByte('\n')
			continue
		}

		body.WriteString(codeLine)
		body.WriteByte('\n')
	}

	if len(decls) == 0 {
		return nil
	}

	bodyStr := body.String()

	var matches []llmcheat.Match
	handled := map[string]bool{}
	for _, dcl := range decls {
		if handled[dcl.name] {
			// A prefix redeclared under the same short name later in the
			// file: only ever report (or clear) it once, at its first
			// declaration, rather than once per repeated directive.
			continue
		}
		handled[dcl.name] = true

		if isPrefixUsed(dcl.name, bodyStr) {
			continue
		}

		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      dcl.line,
			Message:   "prefix \"" + dcl.name + ":\" is declared but never used elsewhere in this file — likely copy-pasted ontology scaffolding",
			Severity:  llmcheat.SeverityLow,
		})
	}

	return matches
}

// isPrefixUsed reports whether short prefix name appears as "name:x" (x
// being any non-whitespace character, i.e. the start of a local name)
// somewhere in body, with the occurrence anchored so it cannot be a
// spurious tail-match inside a longer identifier — e.g. declared prefix
// "ex" must not be considered used merely because the unrelated, longer
// prefix "example" appears as "example:Thing" elsewhere in the file. The
// empty name (the default/unnamed prefix, "@prefix : <iri> .") is checked
// the same way: a bare ":x" reference counts as its use.
func isPrefixUsed(name, body string) bool {
	usageRe := regexp.MustCompile(`(?:^|[^A-Za-z0-9_])` + regexp.QuoteMeta(name) + `:[^\s]`)
	return usageRe.MatchString(body)
}

// stripLineComment returns line with a trailing "#" comment removed,
// honoring Turtle IRIREFs ("<...>", which may legitimately contain a "#"
// fragment separator) and single/double-quoted string literals, so that a
// "#" inside either is not mistaken for the start of a comment. It does not
// attempt to understand triple-quoted (long) string literals or
// line-continuations — a deliberate, documented simplification for a
// heuristic line-scanner, not a full Turtle parser.
func stripLineComment(line string) string {
	inAngle := false
	inSingle, inDouble := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '\\' && (inSingle || inDouble) && i+1 < len(line):
			i++ // skip the escaped character
		case c == '<' && !inSingle && !inDouble:
			inAngle = true
		case c == '>' && !inSingle && !inDouble:
			inAngle = false
		case c == '\'' && !inDouble && !inAngle:
			inSingle = !inSingle
		case c == '"' && !inSingle && !inAngle:
			inDouble = !inDouble
		case c == '#' && !inSingle && !inDouble && !inAngle:
			return line[:i]
		}
	}
	return line
}
