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

package raw

import "testing"

func TestShouldScanAntiCheatEvidenceFormats(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"receipts/chicago.json", true},
		{"receipts/chicago.jsonl", true},
		{"evidence/run.log", true},
		{"evidence/summary.txt", true},
		{"results/findings.sarif", true},
		{"docs/status.md", true},
		{"vendor/evidence/run.log", false},
		{"node_modules/report.json", false},
		{"artifacts/image.png", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, err := shouldScanForAntiCheat(tt.path)
			if err != nil {
				t.Fatalf("shouldScanForAntiCheat(%q) error: %v", tt.path, err)
			}
			if got != tt.want {
				t.Fatalf("shouldScanForAntiCheat(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
