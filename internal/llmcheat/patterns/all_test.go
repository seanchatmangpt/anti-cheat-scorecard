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
	"slices"
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns"
)

func TestProductionRegistryContainsEveryLandedDetector(t *testing.T) {
	t.Parallel()
	required := []string{
		"claim-verified-without-run",
		"go-panic-todo-stub",
		"hedge-language-masking-uncertainty",
		"non-chicago-evidence",
		"overclaiming-superlative",
		"placeholder-lorem-ipsum-in-code",
		"python-notimplemented-shipped",
		"rust-todo-unimplemented-macro",
		"self-contradicting-status",
		"standing-vocabulary-misuse",
		"typescript-throw-not-implemented",
		"unverified-benchmark-numbers",
	}
	all := llmcheat.All()
	got := make([]string, 0, len(all))
	for _, p := range all {
		got = append(got, p.ID())
	}
	if !slices.IsSorted(got) {
		t.Fatalf("registry order must be deterministic, got %v", got)
	}
	for _, id := range required {
		if !slices.Contains(got, id) {
			t.Errorf("production registry missing detector %q; registered=%v", id, got)
		}
	}
	if len(got) < len(required) {
		t.Fatalf("production registry has %d detectors, need at least %d", len(got), len(required))
	}
}
