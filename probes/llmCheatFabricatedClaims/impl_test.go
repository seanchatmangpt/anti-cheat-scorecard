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

package llmCheatFabricatedClaims

import (
	"testing"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/finding"
)

// Chicago-style: real checker.RawResults input, real Run() call, real
// state-based assertions on the returned findings — no mocking of Run's
// own collaborators (there are none to mock; it is a pure function of its
// raw-results argument).

func Test_Run_cleanWhenNoMatchesInCategory(t *testing.T) {
	t.Parallel()
	raw := &checker.RawResults{}
	findings, probeName, err := Run(raw)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if probeName != Probe {
		t.Fatalf("probe name = %q, want %q", probeName, Probe)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1 (single clean OutcomeTrue)", len(findings))
	}
	if findings[0].Outcome != finding.OutcomeTrue {
		t.Fatalf("findings[0].Outcome = %v, want OutcomeTrue", findings[0].Outcome)
	}
}

func Test_Run_reportsOneFindingPerMatchInCategory(t *testing.T) {
	t.Parallel()
	raw := &checker.RawResults{
		AntiCheatResults: checker.AntiCheatData{
			Matches: []checker.AntiCheatMatch{
				{PatternID: "example-pattern-a", Category: category, Path: "a.go", Line: 3, Message: "example a"},
				{PatternID: "example-pattern-b", Category: category, Path: "b.go", Line: 7, Message: "example b"},
				{PatternID: "unrelated-pattern", Category: "not-" + category, Path: "c.go", Line: 1, Message: "should be filtered out"},
			},
		},
	}
	findings, _, err := Run(raw)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2 (only this category's matches, unrelated-category match filtered out)", len(findings))
	}
	for _, f := range findings {
		if f.Outcome != finding.OutcomeFalse {
			t.Errorf("finding outcome = %v, want OutcomeFalse for a real match", f.Outcome)
		}
	}
}
