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

// Package shaclvacuousshape implements the "shacl-vacuous-shape"
// llmcheat.Pattern: it scans .ttl/.shacl files for a SHACL shape (a
// "sh:NodeShape" or "sh:PropertyShape" statement) that declares a target
// (sh:targetClass or sh:targetNode — "this shape applies to these nodes")
// but no real constraint predicate at all (sh:minCount, sh:maxCount,
// sh:pattern, sh:datatype, sh:class, sh:in, sh:minLength, sh:maxLength,
// sh:hasValue, sh:node — "and here is what must be true of them").
//
// A shape that targets something but constrains nothing is not a defect a
// SHACL validator will ever surface: it simply always validates, for every
// node in its target, forever. That is exactly the shape of a generated
// admission/policy graph that was authored to look like real governance
// (it names a target class, it reads like a rule) without ever actually
// gating anything — the "looks like enforcement, enforces nothing" pattern
// this tool exists to catch, transplanted from code into RDF/SHACL.
//
// Turtle has no single-token statement terminator this package can just
// regex for in isolation, so shape-block extraction is deliberately
// best-effort rather than a full Turtle parser: starting from each "a
// sh:NodeShape" / "a sh:PropertyShape" occurrence, the block is read
// forward, tracking "[...]" / "(...)" nesting depth, until whichever of the
// following comes first: a top-level (nesting depth zero) "." that closes
// the statement, a blank line, or the next top-level shape declaration.
// That is sufficient to correctly delimit the realistic, blank-node-nested
// shape blocks SHACL files actually use (see the fixtures in
// detect_test.go), without requiring a real Turtle grammar.
package shaclvacuousshape

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "shacl-vacuous-shape"
	category  = "semantic-web-integrity"
)

// shapeStartRe matches the idiomatic Turtle "a" (rdf:type) shorthand
// declaring a resource to be a SHACL node or property shape. It anchors
// both the start of a shape block and, on any later line, a top-level
// boundary marking the start of the *next* shape block.
var shapeStartRe = regexp.MustCompile(`\ba\s+sh:(?:NodeShape|PropertyShape)\b`)

// targetRe matches either shape-target predicate: the thing that gives a
// shape something to actually apply to.
var targetRe = regexp.MustCompile(`\bsh:target(?:Class|Node)\b`)

// realConstraintPredicates are the SHACL predicates that actually constrain
// a targeted value node. If a shape block has a target (targetRe) but none
// of these appear anywhere in the block, the shape validates every node in
// its target unconditionally.
var realConstraintPredicates = []*regexp.Regexp{
	regexp.MustCompile(`\bsh:minCount\b`),
	regexp.MustCompile(`\bsh:maxCount\b`),
	regexp.MustCompile(`\bsh:pattern\b`),
	regexp.MustCompile(`\bsh:datatype\b`),
	regexp.MustCompile(`\bsh:class\b`),
	regexp.MustCompile(`\bsh:in\b`),
	regexp.MustCompile(`\bsh:minLength\b`),
	regexp.MustCompile(`\bsh:maxLength\b`),
	regexp.MustCompile(`\bsh:hasValue\b`),
	regexp.MustCompile(`\bsh:node\b`),
}

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

// Detect implements llmcheat.Pattern. It runs only on .ttl/.shacl files
// (case-insensitive extension match); every other path is out of scope and
// returns no matches. Within an in-scope file it walks line by line,
// grouping lines into best-effort shape blocks (see the package doc
// comment for the exact boundary rule) and flags each block that has a
// target predicate but no real constraint predicate, reporting the match at
// the 1-based line number where that block's "a sh:...Shape" declaration
// starts.
func (d *detector) Detect(path string, content []byte) []llmcheat.Match {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".ttl" && ext != ".shacl" {
		return nil
	}
	if !shapeStartRe.Match(content) {
		// No shape declarations in this file at all — nothing to group
		// into blocks, so there is nothing to evaluate.
		return nil
	}

	// Splitting on "\n" and trimming a trailing "\r" per line (rather than
	// a CRLF-aware scanner) keeps line numbering trivial: line index i
	// (0-based) is always reported as line i+1, matching the source file
	// exactly regardless of line-ending style.
	lines := strings.Split(string(content), "\n")

	var matches []llmcheat.Match

	for i := 0; i < len(lines); i++ {
		startLine := strings.TrimRight(lines[i], "\r")
		if !shapeStartRe.MatchString(startLine) {
			continue
		}

		blockStart := i
		depth := 0
		blockLines := make([]string, 0, 4)
		// nextIndex is where the outer loop resumes after this block; it
		// defaults to "ran off the end of the file" and is narrowed by
		// whichever boundary condition actually fires below.
		nextIndex := len(lines)

		for j := blockStart; j < len(lines); j++ {
			cur := strings.TrimRight(lines[j], "\r")

			if j != blockStart && depth == 0 {
				if strings.TrimSpace(cur) == "" {
					// Blank-line boundary: the block ends before this
					// line: resume scanning from the blank line itself so
					// the outer loop's i++ advances past it naturally.
					nextIndex = j
					break
				}
				if shapeStartRe.MatchString(cur) {
					// Next shape's declaration starts here: the block ends
					// before this line, and this line is the next block's
					// start line — resume scanning here, not past it.
					nextIndex = j
					break
				}
			}

			blockLines = append(blockLines, cur)

			foundTopLevelPeriod := false
			for _, r := range cur {
				switch r {
				case '[', '(':
					depth++
				case ']', ')':
					if depth > 0 {
						depth--
					}
				case '.':
					if depth == 0 {
						foundTopLevelPeriod = true
					}
				}
			}
			if foundTopLevelPeriod {
				// The statement's closing period, at top-level nesting:
				// the block ends with this line, resume right after it.
				nextIndex = j + 1
				break
			}
		}

		block := strings.Join(blockLines, "\n")
		if targetRe.MatchString(block) && !hasRealConstraint(block) {
			matches = append(matches, llmcheat.Match{
				PatternID: patternID,
				Category:  category,
				Path:      path,
				Line:      uint(blockStart + 1),
				Message: "SHACL shape declares sh:targetClass/sh:targetNode but no real " +
					"constraint predicate (sh:minCount/maxCount/pattern/datatype/class/in/" +
					"minLength/maxLength/hasValue/node) — it targets nodes but constrains " +
					"nothing, so it always validates",
				Severity: llmcheat.SeverityHigh,
			})
		}

		// -1 because the outer for loop's own i++ will advance past
		// nextIndex-1 to nextIndex on the next iteration.
		i = nextIndex - 1
	}

	return matches
}

// hasRealConstraint reports whether block contains at least one of the
// SHACL predicates that actually constrains a targeted value node.
func hasRealConstraint(block string) bool {
	for _, re := range realConstraintPredicates {
		if re.MatchString(block) {
			return true
		}
	}
	return false
}
