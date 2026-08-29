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

func TestAntiCheatScansChicagoEvidenceFormats(t *testing.T) {
	for _, path := range []string{
		"tests/fixtures/chicago.json",
		"receipts/chicago.jsonl",
		"verification/chicago.txt",
		".github/workflows/chicago.yml",
		"scripts/chicago.py",
	} {
		got, err := shouldScanForAntiCheat(path)
		if err != nil {
			t.Fatalf("shouldScanForAntiCheat(%q): %v", path, err)
		}
		if !got {
			t.Errorf("Chicago evidence format was not admitted for scanning: %s", path)
		}
	}
}

func TestAntiCheatStillRejectsBuildAndVendorNoise(t *testing.T) {
	for _, path := range []string{"vendor/fake.json", "target/receipt.jsonl", "node_modules/fake.js"} {
		got, err := shouldScanForAntiCheat(path)
		if err != nil {
			t.Fatalf("shouldScanForAntiCheat(%q): %v", path, err)
		}
		if got {
			t.Errorf("non-subject build/vendor path unexpectedly admitted: %s", path)
		}
	}
}
