// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

// Package llmCheatGovernedExecutionIntegrity projects governed-execution
// integrity matches from the shared Anti-Cheat raw result into Scorecard findings.
package llmCheatGovernedExecutionIntegrity

import (
	"embed"
	"fmt"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/finding"
	"github.com/ossf/scorecard/v5/internal/checknames"
	"github.com/ossf/scorecard/v5/internal/probes"
	"github.com/ossf/scorecard/v5/probes/internal/utils/uerror"
)

func init() { probes.MustRegister(Probe, Run, []checknames.CheckName{checknames.AntiCheat}) }

//go:embed *.yml
var fs embed.FS

// Probe is this probe's registered name.
const Probe = "llmCheatGovernedExecutionIntegrity"
const category = "governed-execution-integrity"

// Run filters the shared Anti-Cheat raw results to governed-execution integrity.
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
		f, err := finding.NewFalse(fs, Probe, fmt.Sprintf("[%s] %s", m.PatternID, m.Message), loc)
		if err != nil {
			return nil, Probe, fmt.Errorf("create finding: %w", err)
		}
		findings = append(findings, *f)
	}
	if len(findings) == 0 {
		f, err := finding.NewTrue(fs, Probe, "no governed-execution-integrity patterns detected", nil)
		if err != nil {
			return nil, Probe, fmt.Errorf("create finding: %w", err)
		}
		findings = append(findings, *f)
	}
	return findings, Probe, nil
}
