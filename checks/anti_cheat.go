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

package checks

import (
	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/checks/evaluation"
	"github.com/ossf/scorecard/v5/checks/raw"
	sce "github.com/ossf/scorecard/v5/errors"
	"github.com/ossf/scorecard/v5/probes"
	"github.com/ossf/scorecard/v5/probes/zrunner"
)

// CheckAntiCheat is the registered name for Anti-Cheat.
//
// This check is the fork's whole reason for existing: repurposing
// Scorecard's proven probe architecture (composable def.yml + Run() units,
// per-check raw-data collection, generated docs, SARIF/OIDC publish) as a
// scaffold for a different question than upstream Scorecard asks. Upstream
// asks "is this repo's supply chain secured"; this check asks "does this
// repo's own code and history contain a fabricated, hollow, or
// unfalsifiable claim of correctness" — consolidating what was previously
// scattered across ~177 files in ~31 sibling repositories (ad hoc
// scripts/*.py variants) and a separate, narrower Rust LSP tool
// (anti-llm-cheat-lsp, which had zero RDF/Turtle/SPARQL coverage and two
// dead rule stubs) into one tool with one real architecture.
const CheckAntiCheat = "Anti-Cheat"

//nolint:gochecknoinits
func init() {
	supportedRequestTypes := []checker.RequestType{
		checker.CommitBased,
		checker.FileBased,
	}
	if err := registerCheck(CheckAntiCheat, AntiCheat, supportedRequestTypes); err != nil {
		// this should never happen
		panic(err)
	}
}

// AntiCheat runs the Anti-Cheat check.
func AntiCheat(c *checker.CheckRequest) checker.CheckResult {
	rawData, err := raw.AntiCheat(c)
	if err != nil {
		e := sce.WithMessage(sce.ErrScorecardInternal, err.Error())
		return checker.CreateRuntimeErrorResult(CheckAntiCheat, e)
	}

	// Set the raw results.
	pRawResults := getRawResults(c)
	pRawResults.AntiCheatResults = rawData

	// Evaluate the probes.
	findings, err := zrunner.Run(pRawResults, probes.AntiCheat)
	if err != nil {
		e := sce.WithMessage(sce.ErrScorecardInternal, err.Error())
		return checker.CreateRuntimeErrorResult(CheckAntiCheat, e)
	}

	ret := evaluation.AntiCheat(CheckAntiCheat, findings, c.Dlogger)
	ret.Findings = findings
	return ret
}
