// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package llmCheatGovernedExecutionIntegrity

import (
	"testing"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/finding"
)

func TestRunClean(t *testing.T) {
	t.Parallel()
	findings, probeName, err := Run(&checker.RawResults{})
	if err != nil {
		t.Fatal(err)
	}
	if probeName != Probe {
		t.Fatalf("probe name = %q, want %q", probeName, Probe)
	}
	if len(findings) != 1 || findings[0].Outcome != finding.OutcomeTrue {
		t.Fatalf("findings = %+v, want one clean OutcomeTrue", findings)
	}
}
func TestRunProjectsCategory(t *testing.T) {
	t.Parallel()
	raw := &checker.RawResults{AntiCheatResults: checker.AntiCheatData{Matches: []checker.AntiCheatMatch{
		{PatternID: "untyped-refused-status", Category: category, Path: "receipt.yml", Line: 2, Message: "untyped"},
		{PatternID: "other", Category: "fabricated-claims", Path: "README.md", Line: 1, Message: "other"},
	}}}
	findings, _, err := Run(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Outcome != finding.OutcomeFalse {
		t.Fatalf("findings = %+v, want one OutcomeFalse", findings)
	}
}
func TestRunRejectsNil(t *testing.T) {
	t.Parallel()
	if _, _, err := Run(nil); err == nil {
		t.Fatal("Run(nil) returned nil error")
	}
}
