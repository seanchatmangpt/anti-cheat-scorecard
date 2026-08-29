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

// Package nonchicagoevidence detects acceptance artifacts that claim real
// execution while substituting models, mocks, mutable identities, masked
// failures, dry-runs, or incomplete receipts for observed production behavior.
package nonchicagoevidence

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const patternID = "non-chicago-evidence"
const category = "test-integrity-violation"

var (
	acceptanceMarkerRe  = regexp.MustCompile(`(?i)\b(chicago|acceptance|qualification|consumer[ _-]?court|journey[ _-]?court|end[ _-]?to[ _-]?end|e2e)\b`)
	statusRe            = regexp.MustCompile(`(?i)\b(ALIVE|PARTIAL_ALIVE|BLOCKED|BUILD_BROKEN|UNSUPPORTED|REFUSED(?:\[[^\]]+\])?)\b`)
	boolAssignmentRe    = regexp.MustCompile(`(?i)["']?[A-Za-z0-9_.-]+["']?\s*[:=]\s*(?:true|false)\b`)
	syntheticStateRe    = regexp.MustCompile(`(?i)\b(canonical|capabilities|scenario|invalid|control|expected)\b`)
	mockRe              = regexp.MustCompile(`(?i)\b(mock(?:ed|ing)?|stub(?:bed|bing)?|fake(?:d|s|ing)?|monkeypatch|wiremock|mockall|httptest\.newserver|jest\.mock|unittest\.mock)\b`)
	skipRe              = regexp.MustCompile(`(?i)(?:\bt\.skip(?:f|now)?\s*\(|pytest\.skip\s*\(|\b(?:it|test|describe)\.skip\s*\(|#\s*\[\s*ignore\s*\]|@\s*(?:disabled|ignore)\b)`)
	failureMaskRe       = regexp.MustCompile(`(?im)^\s*(?:continue-on-error\s*:\s*true|allow_failure\s*:\s*true)\s*$|(?m)\|\|\s*true(?:\s*(?:#.*)?)$`)
	mutableUseRe        = regexp.MustCompile(`(?im)^\s*uses\s*:\s*[^@\s]+@(main|master|latest|v\d+(?:\.\d+){0,2})\s*(?:#.*)?$`)
	mutableRefRe        = regexp.MustCompile(`(?im)^\s*ref\s*:\s*(?:main|master|head|latest)\s*(?:#.*)?$`)
	dryRunRe            = regexp.MustCompile(`(?i)(?:--dry-run\b|\bdry[_ -]?run\b)`)
	aliveRe             = regexp.MustCompile(`(?i)(?:\bstanding\b[^\n]{0,24}\bALIVE\b|\bALIVE(?:\[[^\]]+\])?\b)`)
	mergedRe            = regexp.MustCompile(`(?i)\bmerged?\b|\bmerge[_ -]?commit\b`)
	unsettledWorkflowRe = regexp.MustCompile(`(?i)\b(queued|pending|in[_ -]?progress|skipped|cancelled)\b`)
	exactHeadClaimRe    = regexp.MustCompile(`(?i)\bexact[_ -]?head\b`)
	fullSHARe           = regexp.MustCompile(`\b[0-9a-f]{40}\b`)
)

type detector struct{}

func newDetector() *detector { return &detector{} }

func (d *detector) ID() string       { return patternID }
func (d *detector) Category() string { return category }

func (d *detector) Detect(path string, content []byte) []llmcheat.Match {
	if len(content) == 0 {
		return nil
	}

	lowerPath := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	// Detector-unit-test fixtures intentionally contain anti-pattern text.
	// Excluding the detector implementation subtree prevents the scorecard
	// from scoring its own test vectors as subject-repository cheating.
	if strings.Contains(lowerPath, "internal/llmcheat/patterns/") {
		return nil
	}

	text := string(content)
	lower := strings.ToLower(text)
	acceptance := isAcceptanceContext(lowerPath, text)
	receiptish := isReceiptContext(lowerPath, lower)
	workflow := strings.Contains(lowerPath, ".github/workflows/") && (strings.HasSuffix(lowerPath, ".yml") || strings.HasSuffix(lowerPath, ".yaml"))

	seen := map[string]bool{}
	var matches []llmcheat.Match
	add := func(rule, message string, severity llmcheat.Severity, idx int) {
		if seen[rule] {
			return
		}
		seen[rule] = true
		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      lineAt(text, idx),
			Message:   fmt.Sprintf("non-Chicago evidence [%s]: %s", rule, message),
			Severity:  severity,
		})
	}

	bools := boolAssignmentRe.FindAllStringIndex(text, -1)
	if (strings.Contains(lowerPath, "fixture") || strings.Contains(lowerPath, "test")) && len(bools) > 0 && statusRe.MatchString(text) && syntheticStateRe.MatchString(text) {
		idx := 0
		if loc := statusRe.FindStringIndex(text); loc != nil {
			idx = loc[0]
		}
		add("synthetic-status-fixture", "a declarative fixture maps synthetic state to a standing instead of driving the real production entrypoint", llmcheat.SeverityHigh, idx)
	}

	if acceptance && len(bools) >= 3 && statusRe.MatchString(text) && syntheticStateRe.MatchString(text) {
		idx := bools[0][0]
		add("boolean-court", "acceptance is represented by a Boolean/state model with predeclared standings; model truth is not observed execution", llmcheat.SeverityHigh, idx)
	}

	if acceptance {
		if loc := mockRe.FindStringIndex(text); loc != nil {
			add("mock-substitution", "an acceptance/Chicago surface substitutes a mock, fake, stub, or simulated server for the production dependency", llmcheat.SeverityHigh, loc[0])
		}
		if loc := skipRe.FindStringIndex(text); loc != nil {
			add("skipped-acceptance", "an acceptance/Chicago surface contains a skipped or ignored test", llmcheat.SeverityHigh, loc[0])
		}
		if loc := failureMaskRe.FindStringIndex(text); loc != nil {
			add("failure-masking", "an acceptance/Chicago surface can convert a real command failure into success", llmcheat.SeverityHigh, loc[0])
		}
		if loc := mutableUseRe.FindStringIndex(text); loc != nil {
			add("mutable-action-identity", "an acceptance workflow uses a mutable action ref instead of an immutable commit SHA", llmcheat.SeverityHigh, loc[0])
		}
		if loc := mutableRefRe.FindStringIndex(text); loc != nil {
			add("mutable-subject-identity", "an acceptance surface selects main/master/HEAD/latest instead of binding the admitted immutable subject", llmcheat.SeverityHigh, loc[0])
		}
	}

	if workflow && acceptance && strings.Contains(lower, "pull_request:") && strings.Contains(lower, "actions/checkout@") && !strings.Contains(lower, "github.event.pull_request.head.sha") {
		idx := strings.Index(lower, "actions/checkout@")
		add("missing-pr-head-binding", "pull-request acceptance checks out code without explicitly binding to github.event.pull_request.head.sha", llmcheat.SeverityHigh, idx)
	}

	if acceptance && dryRunRe.MatchString(text) && aliveRe.MatchString(text) && !hasNonDryProductionCommand(text) {
		idx := 0
		if loc := dryRunRe.FindStringIndex(text); loc != nil {
			idx = loc[0]
		}
		add("dry-run-crowned-alive", "ALIVE/qualification is claimed while the only detectable production command is a dry-run", llmcheat.SeverityHigh, idx)
	}

	if receiptish && aliveRe.MatchString(text) {
		missing := missingReceiptEvidence(lower)
		if len(missing) >= 2 {
			idx := 0
			if loc := aliveRe.FindStringIndex(text); loc != nil {
				idx = loc[0]
			}
			add("alive-without-execution-receipt", fmt.Sprintf("ALIVE evidence is missing execution fields: %s", strings.Join(missing, ", ")), llmcheat.SeverityHigh, idx)
		}

		if mergedRe.MatchString(text) && !strings.Contains(lower, "contain") && !strings.Contains(lower, "default branch") && !strings.Contains(lower, "default_branch") {
			idx := 0
			if loc := mergedRe.FindStringIndex(text); loc != nil {
				idx = loc[0]
			}
			add("merged-without-containment", "merged/ALIVE is claimed without proving the merged head is contained in the live default branch", llmcheat.SeverityHigh, idx)
		}

		if unsettledWorkflowRe.MatchString(text) {
			idx := 0
			if loc := unsettledWorkflowRe.FindStringIndex(text); loc != nil {
				idx = loc[0]
			}
			add("workflow-status-overclaim", "ALIVE is claimed while workflow evidence still says queued/pending/in-progress/skipped/cancelled", llmcheat.SeverityHigh, idx)
		}

		if exactHeadClaimRe.MatchString(text) && !fullSHARe.MatchString(text) {
			idx := 0
			if loc := exactHeadClaimRe.FindStringIndex(text); loc != nil {
				idx = loc[0]
			}
			add("exact-head-without-sha", "exact-head evidence is claimed without a full immutable 40-hex commit identity", llmcheat.SeverityMedium, idx)
		}
	}

	return matches
}

func isAcceptanceContext(path, text string) bool {
	for _, marker := range []string{"chicago", "acceptance", "qualification", "e2e", "end-to-end", "journey", "consumer", "court"} {
		if strings.Contains(path, marker) {
			return true
		}
	}
	return acceptanceMarkerRe.MatchString(text)
}

func isReceiptContext(path, lower string) bool {
	for _, marker := range []string{"receipt", "evidence", "report", "verification", "qualification"} {
		if strings.Contains(path, marker) {
			return true
		}
	}
	return strings.Contains(lower, `"standing"`) || strings.Contains(lower, "standing:") || strings.Contains(lower, "final standing")
}

func missingReceiptEvidence(lower string) []string {
	var missing []string
	if !strings.Contains(lower, "sha") && !strings.Contains(lower, "commit") {
		missing = append(missing, "immutable subject SHA")
	}
	if !strings.Contains(lower, "command") && !strings.Contains(lower, "run:") {
		missing = append(missing, "executed command")
	}
	if !strings.Contains(lower, "exit") && !strings.Contains(lower, "conclusion") {
		missing = append(missing, "exit/conclusion")
	}
	if !strings.Contains(lower, "observed") && !strings.Contains(lower, "digest") && !strings.Contains(lower, "hash") && !strings.Contains(lower, "result") {
		missing = append(missing, "observed consequence")
	}
	return missing
}

func hasNonDryProductionCommand(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "--dry-run") || strings.Contains(lower, "dry_run") || strings.Contains(lower, "dry-run") {
			continue
		}
		if strings.Contains(lower, "sync run") || strings.Contains(lower, "cargo test") || strings.Contains(lower, "go test") || strings.Contains(lower, "pytest") || strings.Contains(lower, "mix test") || strings.Contains(lower, "npm test") || strings.Contains(lower, "execute") || strings.Contains(lower, "verify") {
			return true
		}
	}
	return false
}

func lineAt(text string, idx int) uint {
	if idx < 0 {
		return 0
	}
	return uint(strings.Count(text[:min(idx, len(text))], "\n") + 1) //nolint:gosec
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func init() {
	llmcheat.Register(newDetector())
}
