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

package patterns_test

import (
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns"
)

func TestProductionAggregatorRegistersChicagoAndLandedFleet(t *testing.T) {
	all := llmcheat.All()
	if len(all) != 65 {
		t.Fatalf("production aggregator registered %d patterns, want exactly 65 admitted detectors", len(all))
	}

	want := map[string]bool{
		"ci-success-claims-authority":              false,
		"claim-verified-without-run":               false,
		"dfcm-plan-without-reserve":                false,
		"exact-head-claim-with-floating-ref":       false,
		"generated-projection-claims-authority":    false,
		"go-syntax-graph-chicago":                  false,
		"hand-edited-generated-file-marker":        false,
		"historical-receipt-promotes-current-head": false,
		"interaction-only-assertion":               false,
		"irreversible-action-without-rollback":     false,
		"non-chicago-acceptance-laundering":        false,
		"non-chicago-evidence":                     false,
		"premature-option-collapse":                false,
		"receipt-subject-head-mismatch":            false,
		"replay-claim-without-evidence":            false,
		"select-construct-do-collapsed":            false,
		"terminal-failure-without-reserve":         false,
		"untyped-refused-status":                   false,
		"unverified-benchmark-numbers":             false,
	}
	for _, p := range all {
		if _, ok := want[p.ID()]; ok {
			want[p.ID()] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("production aggregator did not register %q", id)
		}
	}
}
