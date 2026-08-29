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

// Package llmCheatGeneratedArtifactTampering is one of the 7 Anti-Cheat category probes. It is a thin
// Scorecard-shaped wrapper: all real detection logic lives in the 50
// independent internal/llmcheat/patterns/* detectors, aggregated once by
// checks/raw/anti_cheat.go into checker.RawResults.AntiCheatResults. This
// probe only filters that shared result set down to its own category and
// projects each match into a real Scorecard finding/location.
package llmCheatGeneratedArtifactTampering

import (
	"embed"
	"fmt"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/finding"
	"github.com/ossf/scorecard/v5/internal/checknames"
	"github.com/ossf/scorecard/v5/internal/probes"
	"github.com/ossf/scorecard/v5/probes/internal/utils/uerror"
)

func init() {
	probes.MustRegister(Probe, Run, []checknames.CheckName{checknames.AntiCheat})
}

//go:embed *.yml
var fs embed.FS

// Probe is this probe's registered name.
const Probe = "llmCheatGeneratedArtifactTampering"

// category must match the llmcheat.Match.Category string every pattern in
// internal/llmcheat/patterns/ under this category self-reports.
const category = "generated-artifact-tampering"

// Run filters the shared Anti-Cheat raw results down to this probe's
// category: one OutcomeFalse finding per match found, or a single
// OutcomeTrue finding if the category came back clean.
func Run(raw *checker.RawResults) ([]finding.Finding, string, error) {
	if raw == nil {
		return nil, "", fmt.Errorf("%w: raw", uerror.ErrNil)
	}

	var findings []finding.Finding
	for _, m := range raw.AntiCheatResults.Matches {
		if m.Category != category {
			continue
		}
		loc := &finding.Location{Path: m.Path, Type: finding.FileTypeSource}
		if m.Line > 0 {
			line := m.Line
			loc.LineStart = &line
			loc.LineEnd = &line
		}
		text := fmt.Sprintf("[%s] %s", m.PatternID, m.Message)
		f, err := finding.NewFalse(fs, Probe, text, loc)
		if err != nil {
			return nil, Probe, fmt.Errorf("create finding: %w", err)
		}
		findings = append(findings, *f)
	}

	if len(findings) == 0 {
		f, err := finding.NewTrue(fs, Probe, "no generated-artifact-tampering patterns detected", nil)
		if err != nil {
			return nil, Probe, fmt.Errorf("create finding: %w", err)
		}
		findings = append(findings, *f)
	}

	return findings, Probe, nil
}
