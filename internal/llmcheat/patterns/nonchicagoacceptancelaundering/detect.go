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

// Package nonchicagoacceptancelaundering detects strong Chicago/production
// standing claims that are backed only by non-Chicago evidence, or that omit
// the minimum execution/exit/consequence bundle needed to make such a claim
// falsifiable. It is intentionally evidence-oriented: ordinary unit-test
// claims are out of scope, while ALIVE/Chicago/production/release/merge-ready
// claims receive a higher evidence bar.
package nonchicagoacceptancelaundering

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const patternID = "non-chicago-acceptance-laundering"
const category = "fabricated-claims"

var strongClaimRe = regexp.MustCompile(`(?i)\b(chicago(?:[- ]style)?\s+(?:pass(?:ed)?|green|alive)|alive(?:\[[^\]]+\])?|production(?:[- ]ready|\s+ready|\s+verified|\s+validated|\s+passed)|release(?:[- ]ready|\s+ready)|merge(?:[- ]ready|\s+ready)|end[- ]to[- ]end\s+(?:pass(?:ed)?|verified|validated)|e2e\s+(?:pass(?:ed)?|verified|validated)|real[- ]path\s+(?:pass(?:ed)?|verified|validated))\b`)

var nonChicagoEvidenceRe = regexp.MustCompile(`(?i)\b(dry[- ]run|mock(?:ed|s)?|stub(?:bed|s)?|fake(?:d|s)?|synthetic|fixture[- ]only|schema[- ]only|syntax[- ]only|parse(?:d|[- ]only)?|inspection[- ]only|inspected[- ]only|workflow\s+(?:exists|created|defined)|ci\s+(?:started|queued|pending)|pr\s+(?:opened|created)|pull request\s+(?:opened|created)|push(?:ed)?\s+(?:only|successfully)?|exact[- ]sha\s+(?:only|resolved)|unit[- ]tests?\s+(?:only|pass(?:ed)?)|classifier[- ]only|hard[- ]coded\s+status|predeclared\s+status|recorded\s+response|fixture\s+response|test[- ]double)\b`)

var executionRe = regexp.MustCompile(`(?i)\b(ran|run|executed|execute|invoked|invocation|docker\s+run|go\s+run|cargo\s+run|curl|http\s+(?:get|post|put|patch|delete)|workflow\s+run\s+\d+|actions\s+run\s+\d+)\b`)
var exitRe = regexp.MustCompile(`(?i)\b(exit(?:\s+code)?\s*[:=]?\s*0|status\s*[:=]?\s*0|conclusion\s*[:=]?\s*success|completed\s+successfully)\b`)
var consequenceRe = regexp.MustCompile(`(?i)\b(wrote|created|returned|responded|observed|output|artifact|digest|receipt|replay|containment|ancestor|default[- ]branch|merged\s+into\s+(?:main|master)|generated\s+file|http\s+[12][0-9]{2})\b`)
var normativeRe = regexp.MustCompile(`(?i)\b(requires?|requirement|means|defined\s+as|definition|must|should|cannot|can't|do\s+not|don't|only\s+when|example|e\.g\.|counterexample|anti[- ]pattern|detects?|detector|rule|policy|vocabulary)\b`)
var negativeClaimRe = regexp.MustCompile(`(?i)\b(not|isn't|is\s+not|wasn't|was\s+not|never)\s+(?:chicago|alive|production[- ]ready|release[- ]ready|merge[- ]ready|e2e|end[- ]to[- ]end)\b`)

var evidenceExtensions = map[string]bool{
	".md": true, ".txt": true, ".log": true, ".json": true, ".sarif": true,
	".yml": true, ".yaml": true, ".toml": true,
}

type detector struct{}

func newDetector() *detector         { return &detector{} }
func (d *detector) ID() string       { return patternID }
func (d *detector) Category() string { return category }

func (d *detector) Detect(path string, content []byte) []llmcheat.Match {
	if len(content) == 0 || !isEvidenceBearingPath(path) {
		return nil
	}
	lines := strings.Split(string(content), "\n")
	var matches []llmcheat.Match
	for i, line := range lines {
		if !strongClaimRe.MatchString(line) {
			continue
		}
		if negativeClaimRe.MatchString(line) || normativeRe.MatchString(line) {
			continue
		}
		window := joinWindow(lines, i, 4)
		severity := llmcheat.SeverityMedium
		reason := "strong Chicago/production standing claim lacks an observed execution + exit + consequence evidence bundle"
		if nonChicagoEvidenceRe.MatchString(window) {
			severity = llmcheat.SeverityHigh
			reason = "strong Chicago/production standing claim is supported by non-Chicago evidence (mock/dry-run/inspection/workflow/PR/push/static-only evidence)"
		} else if executionRe.MatchString(window) && exitRe.MatchString(window) && consequenceRe.MatchString(window) {
			continue
		}
		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      uint(i + 1), //nolint:gosec // bounded slice index from repository text
			Message: fmt.Sprintf(
				"%s; Chicago requires real production-path execution and an observed consequence",
				reason,
			),
			Severity: severity,
		})
	}
	return matches
}

func isEvidenceBearingPath(path string) bool {
	base := strings.ToUpper(filepath.Base(path))
	if base == "COMMIT_EDITMSG" || base == "PULL_REQUEST_TEMPLATE" {
		return true
	}
	return evidenceExtensions[strings.ToLower(filepath.Ext(path))]
}

func joinWindow(lines []string, start, lookahead int) string {
	end := start + lookahead
	if end >= len(lines) {
		end = len(lines) - 1
	}
	return strings.Join(lines[start:end+1], "\n")
}

func init() { llmcheat.Register(newDetector()) }
