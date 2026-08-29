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

// Package llmCheatOptionSpaceCollapse projects DfCM option-space-collapse
// detector matches from the shared Anti-Cheat raw result into Scorecard
// findings. It is deliberately a distinct probe so irreversible commitment
// and failure-to-preserve alternatives cannot be diluted into a generic
// complexity score.
package llmCheatOptionSpaceCollapse

import (
	"fmt"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/finding"
	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const Probe = "llmCheatOptionSpaceCollapse"
const category = "option-space-collapse"

func Run(raw *checker.RawResults) ([]finding.Finding, string) {
	findings := make([]finding.Finding, 0)
	for _, match := range raw.AntiCheat.Matches {
		if match.Category != category {
			continue
		}
		outcome := finding.OutcomeFalse
		if match.Severity == string(llmcheat.SeverityLow) {
			outcome = finding.OutcomeTrue
		}
		findings = append(findings, finding.Finding{
			Probe:   Probe,
			Outcome: outcome,
			Message: fmt.Sprintf("%s: %s — %s", match.Category, match.PatternID, match.Message),
			Location: &finding.Location{
				Path: match.Path,
				Line: &finding.Line{Start: match.Line, End: match.Line},
			},
		})
	}
	if len(findings) == 0 {
		findings = append(findings, finding.Finding{Probe: Probe, Outcome: finding.OutcomeTrue})
	}
	return findings, ""
}
