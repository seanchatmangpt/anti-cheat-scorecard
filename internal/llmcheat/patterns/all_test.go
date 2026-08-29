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
	"os"
	"slices"
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns"
)

func TestProductionRegistryContainsEveryDetectorDirectory(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	expected := 0
	for _, entry := range entries {
		if entry.IsDir() {
			expected++
		}
	}

	all := llmcheat.All()
	if len(all) != expected {
		t.Fatalf("production registry has %d detectors but source tree has %d detector directories", len(all), expected)
	}

	ids := make([]string, 0, len(all))
	seen := map[string]bool{}
	for _, p := range all {
		if p.ID() == "" {
			t.Fatal("production registry contains empty detector ID")
		}
		if seen[p.ID()] {
			t.Fatalf("production registry contains duplicate detector ID %q", p.ID())
		}
		seen[p.ID()] = true
		ids = append(ids, p.ID())
	}
	if !slices.IsSorted(ids) {
		t.Fatalf("production registry order is nondeterministic: %v", ids)
	}
	if !seen["non-chicago-evidence"] {
		t.Fatalf("production registry does not contain non-chicago-evidence: %v", ids)
	}
}
