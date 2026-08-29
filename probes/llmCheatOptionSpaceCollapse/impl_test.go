// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package llmCheatOptionSpaceCollapse

import (
	"testing"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/finding"
)

func Test_Run_cleanWhenNoOptionSpaceMatches(t *testing.T) {
	t.Parallel()
	findings, probeName, err := Run(&checker.RawResults{})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if probeName != Probe {
		t.Fatalf("probe name = %q, want %q", probeName, Probe)
	}
	if len(findings) != 1 || findings[0].Outcome != finding.OutcomeTrue {
		t.Fatalf("findings = %+v, want one clean OutcomeTrue", findings)
	}
}

func Test_Run_projectsOnlyOptionSpaceCollapseMatches(t *testing.T) {
	t.Parallel()
	raw := &checker.RawResults{AntiCheatResults: checker.AntiCheatData{Matches: []checker.AntiCheatMatch{
		{PatternID: "premature-option-collapse", Category: category, Path: "PLAN.md", Line: 4, Message: "collapsed too early"},
		{PatternID: "irreversible-action-without-rollback", Category: category, Path: "deploy.sh", Line: 9, Message: "no rollback"},
		{PatternID: "other", Category: "fabricated-claims", Path: "README.md", Line: 1, Message: "unrelated"},
	}}}
	findings, probeName, err := Run(raw)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if probeName != Probe {
		t.Fatalf("probe name = %q, want %q", probeName, Probe)
	}
	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Outcome != finding.OutcomeFalse {
			t.Fatalf("outcome = %v, want OutcomeFalse", f.Outcome)
		}
	}
}

func Test_Run_rejectsNilRawResults(t *testing.T) {
	t.Parallel()
	if _, _, err := Run(nil); err == nil {
		t.Fatal("Run(nil) returned nil error, want typed nil-input refusal")
	}
}
