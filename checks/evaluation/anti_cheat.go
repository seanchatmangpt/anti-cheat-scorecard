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

package evaluation

import (
	"github.com/ossf/scorecard/v5/checker"
	sce "github.com/ossf/scorecard/v5/errors"
	"github.com/ossf/scorecard/v5/finding"
	"github.com/ossf/scorecard/v5/probes/llmCheatComplexityObfuscation"
	"github.com/ossf/scorecard/v5/probes/llmCheatDeterminismViolation"
	"github.com/ossf/scorecard/v5/probes/llmCheatFabricatedClaims"
	"github.com/ossf/scorecard/v5/probes/llmCheatGeneratedArtifactTampering"
	"github.com/ossf/scorecard/v5/probes/llmCheatGovernedExecutionIntegrity"
	"github.com/ossf/scorecard/v5/probes/llmCheatHollowImplementation"
	"github.com/ossf/scorecard/v5/probes/llmCheatOptionSpaceCollapse"
	"github.com/ossf/scorecard/v5/probes/llmCheatSemanticWebIntegrity"
	"github.com/ossf/scorecard/v5/probes/llmCheatTestIntegrityViolation"
)

// AntiCheat applies the score policy for the Anti-Cheat check.
//
// Each probe wraps one category of the shared internal/llmcheat pattern
// registry. A probe is clean when it produced zero OutcomeFalse findings;
// the score is the proportion of the nine admitted categories that are clean.
func AntiCheat(name string,
	findings []finding.Finding,
	dl checker.DetailLogger,
) checker.CheckResult {
	expectedProbes := []string{
		llmCheatFabricatedClaims.Probe,
		llmCheatHollowImplementation.Probe,
		llmCheatTestIntegrityViolation.Probe,
		llmCheatGeneratedArtifactTampering.Probe,
		llmCheatSemanticWebIntegrity.Probe,
		llmCheatDeterminismViolation.Probe,
		llmCheatComplexityObfuscation.Probe,
		llmCheatOptionSpaceCollapse.Probe,
		llmCheatGovernedExecutionIntegrity.Probe,
	}

	if !finding.UniqueProbesEqual(findings, expectedProbes) {
		e := sce.WithMessage(sce.ErrScorecardInternal, "invalid probe results")
		return checker.CreateRuntimeErrorResult(name, e)
	}

	dirtyByProbe := make(map[string]bool, len(expectedProbes))
	for i := range findings {
		f := &findings[i]
		var logLevel checker.DetailType
		switch f.Outcome {
		case finding.OutcomeFalse:
			dirtyByProbe[f.Probe] = true
			logLevel = checker.DetailWarn
		case finding.OutcomeTrue:
			logLevel = checker.DetailInfo
		default:
			logLevel = checker.DetailDebug
		}
		checker.LogFinding(dl, f, logLevel)
	}

	clean := 0
	for _, probeName := range expectedProbes {
		if !dirtyByProbe[probeName] {
			clean++
		}
	}

	score := checker.CreateProportionalScore(clean, len(expectedProbes))
	if score == checker.MaxResultScore {
		return checker.CreateMaxScoreResult(name, "no LLM-cheat patterns detected across any category")
	}
	return checker.CreateResultWithScore(name,
		"one or more LLM-cheat patterns detected — see findings for pattern IDs and locations", score)
}
