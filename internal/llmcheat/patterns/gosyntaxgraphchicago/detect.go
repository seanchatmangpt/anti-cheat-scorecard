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

// Package gosyntaxgraphchicago detects non-Chicago acceptance structure by
// querying a parsed Go syntax graph rather than matching unparsed text.
package gosyntaxgraphchicago

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
	"github.com/ossf/scorecard/v5/internal/llmcheat/syntaxgraph"
)

const (
	patternID = "go-syntax-graph-chicago"
	category  = "test-integrity-violation"
)

type detector struct{}

func newDetector() *detector         { return &detector{} }
func (d *detector) ID() string       { return patternID }
func (d *detector) Category() string { return category }

func (d *detector) Detect(path string, content []byte) []llmcheat.Match {
	if strings.ToLower(filepath.Ext(path)) != ".go" || !isAcceptancePath(path) {
		return nil
	}
	g, err := syntaxgraph.ParseGo(path, content)
	if err != nil {
		// Syntax-invalid Go is compiler/test territory. A failed parse is not
		// laundered into an anti-cheat finding because there is no admitted
		// syntax graph to query.
		return nil
	}

	digest := g.Digest()
	seen := map[string]bool{}
	matches := make([]llmcheat.Match, 0)
	add := func(rule string, n syntaxgraph.Node, message string) {
		if seen[rule] {
			return
		}
		seen[rule] = true
		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      n.Line,
			Message: fmt.Sprintf(
				"Go syntax graph [%s] %s (graph sha256=%s)",
				rule, message, digest[:16],
			),
			Severity: llmcheat.SeverityHigh,
		})
	}

	for _, n := range g.Nodes {
		switch n.Role {
		case "call":
			callee := strings.ToLower(n.Value)
			switch {
			case strings.HasSuffix(callee, ".skip"), strings.HasSuffix(callee, ".skipf"), strings.HasSuffix(callee, ".skipnow"):
				add("skipped-acceptance", n, "contains an executable test-skip call; a skipped acceptance path cannot establish Chicago standing")
			case callee == "httptest.newserver" || callee == "httptest.newtlsserver":
				add("synthetic-http-server", n, "uses httptest server substitution in an acceptance surface instead of the admitted production dependency")
			case callee == "panic" && hasPlaceholderLiteral(g.Descendants(n.ID)):
				add("placeholder-panic", n, "contains an executable placeholder panic in an acceptance path")
			case (strings.HasSuffix(callee, ".true") || strings.HasSuffix(callee, ".truef")) && hasBooleanIdentifier(g.Descendants(n.ID), "true"):
				add("tautological-assertion", n, "asserts the literal true rather than an observed system consequence")
			}
		case "if-condition":
			condition := strings.TrimSpace(strings.ToLower(n.Value))
			if condition == "true" || condition == "false" {
				add("constant-control-branch", n, "uses a constant Boolean branch in acceptance control flow, predeclaring a path rather than observing it")
			}
		case "composite":
			desc := g.Descendants(n.ID)
			if booleanCount(desc) >= 3 && hasStandingLiteral(desc) {
				add("boolean-standing-court", n, "encodes standing alongside three or more Boolean facts inside one composite literal; declarative model state is not execution evidence")
			}
		}
	}
	return matches
}

func isAcceptancePath(path string) bool {
	p := strings.ToLower(filepath.ToSlash(path))
	for _, marker := range []string{"chicago", "acceptance", "qualification", "consumer", "journey", "e2e", "end_to_end", "end-to-end", "court"} {
		if strings.Contains(p, marker) {
			return true
		}
	}
	return false
}

func hasPlaceholderLiteral(nodes []syntaxgraph.Node) bool {
	for _, n := range nodes {
		if n.Role != "literal" {
			continue
		}
		v, err := strconv.Unquote(n.Value)
		if err != nil {
			v = n.Value
		}
		v = strings.ToLower(v)
		if strings.Contains(v, "todo") || strings.Contains(v, "not implemented") || strings.Contains(v, "unimplemented") {
			return true
		}
	}
	return false
}

func hasBooleanIdentifier(nodes []syntaxgraph.Node, want string) bool {
	for _, n := range nodes {
		if n.Role == "identifier" && strings.EqualFold(n.Value, want) {
			return true
		}
	}
	return false
}

func booleanCount(nodes []syntaxgraph.Node) int {
	count := 0
	for _, n := range nodes {
		if n.Role == "identifier" && (n.Value == "true" || n.Value == "false") {
			count++
		}
	}
	return count
}

func hasStandingLiteral(nodes []syntaxgraph.Node) bool {
	for _, n := range nodes {
		if n.Role != "literal" {
			continue
		}
		v, err := strconv.Unquote(n.Value)
		if err != nil {
			v = n.Value
		}
		upper := strings.ToUpper(v)
		for _, standing := range []string{"ALIVE", "PARTIAL_ALIVE", "BLOCKED", "BUILD_BROKEN", "UNSUPPORTED", "REFUSED"} {
			if strings.Contains(upper, standing) {
				return true
			}
		}
	}
	return false
}

func init() { llmcheat.Register(newDetector()) }
