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

package nonchicagoevidence

import (
	"strings"
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

func TestDetectNonChicagoEvidence(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		path     string
		content  string
		wantRule string
	}{
		{name: "synthetic status fixture", path: "tests/fixtures/starter-journey/p001.json", content: `{"invalid":{"anonymous_clone":false},"expected":"REFUSED[AUTHENTICATED_CLONE_REQUIRED]","control":{}}`, wantRule: "synthetic-status-fixture"},
		{name: "boolean court", path: "scripts/chicago_court.py", content: "CANONICAL = {\n  'clone': True,\n  'runner': True,\n  'receipt': True,\n}\nexpected = 'ALIVE'\n", wantRule: "boolean-court"},
		{name: "mock substitution", path: "tests/e2e/checkout_test.go", content: "func TestE2E(t *testing.T) { server := httptest.NewServer(handler) }", wantRule: "mock-substitution"},
		{name: "skipped acceptance", path: "tests/chicago/test_runtime.py", content: "def test_runtime():\n    pytest.skip('later')\n", wantRule: "skipped-acceptance"},
		{name: "failure masking", path: ".github/workflows/chicago.yml", content: "name: Chicago\njobs:\n  chicago:\n    steps:\n      - run: ggen sync run || true\n", wantRule: "failure-masking"},
		{name: "mutable action identity", path: ".github/workflows/acceptance.yml", content: "name: Acceptance\non:\n  push:\njobs:\n  acceptance:\n    steps:\n      - uses: actions/checkout@v4\n", wantRule: "mutable-action-identity"},
		{name: "mutable subject identity", path: ".github/workflows/consumer-court.yml", content: "name: Consumer Court\njobs:\n  qualify:\n    steps:\n      - run: echo ok\n        env:\n          ref: main\n", wantRule: "mutable-subject-identity"},
		{name: "missing pr head binding", path: ".github/workflows/chicago.yml", content: "name: Chicago\non:\n  pull_request:\njobs:\n  chicago:\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n      - run: go test ./...\n", wantRule: "missing-pr-head-binding"},
		{name: "dry run crowned alive", path: "verification/chicago-receipt.md", content: "Standing: ALIVE\nCommand: `ggen sync run --dry-run`\nExit: 0\nSHA: 0123456789012345678901234567890123456789\nResult: no diff\n", wantRule: "dry-run-crowned-alive"},
		{name: "alive without execution receipt", path: "receipts/run.json", content: `{"standing":"ALIVE","sha":"0123456789012345678901234567890123456789"}`, wantRule: "alive-without-execution-receipt"},
		{name: "merged without containment", path: "verification/report.md", content: "Standing: ALIVE\nMerged: yes\nSHA: 0123456789012345678901234567890123456789\nCommand: go test ./...\nExit: 0\nObserved result: pass\n", wantRule: "merged-without-containment"},
		{name: "workflow status overclaim", path: "verification/report.md", content: "Standing: ALIVE\nWorkflow: in_progress\nSHA: 0123456789012345678901234567890123456789\nCommand: go test ./...\nExit: 0\nObserved result: pending\n", wantRule: "workflow-status-overclaim"},
		{name: "exact head without sha", path: "verification/report.md", content: "Standing: ALIVE\nExact-head CI: success\nCommand: go test ./...\nExit: 0\nObserved result: pass\n", wantRule: "exact-head-without-sha"},
	}

	d := newDetector()
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			matches := d.Detect(tc.path, []byte(tc.content))
			if !containsRule(matches, tc.wantRule) {
				t.Fatalf("expected rule %q, got %#v", tc.wantRule, matches)
			}
		})
	}
}

func TestRealChicagoWorkflowIsNotFlagged(t *testing.T) {
	t.Parallel()
	content := `name: Chicago
on:
  pull_request:
jobs:
  chicago:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: false
      - run: |
          set -euo pipefail
          test "$(git rev-parse HEAD)" = "${{ github.event.pull_request.head.sha }}"
          ggen sync run
          go test ./...
`
	if matches := newDetector().Detect(".github/workflows/chicago.yml", []byte(content)); len(matches) != 0 {
		t.Fatalf("real exact-head workflow should not be flagged: %#v", matches)
	}
}

func TestCompleteMergedReceiptIsNotFlagged(t *testing.T) {
	t.Parallel()
	content := `Standing: ALIVE
Subject SHA: 0123456789012345678901234567890123456789
Command: go test ./...
Exit: 0
Observed result: pass
Merged: yes
Default branch containment: merge commit is ancestor of main
`
	if matches := newDetector().Detect("verification/final-receipt.md", []byte(content)); len(matches) != 0 {
		t.Fatalf("complete receipt should not be flagged: %#v", matches)
	}
}

func containsRule(matches []llmcheat.Match, rule string) bool {
	needle := "[" + rule + "]"
	for _, m := range matches {
		if strings.Contains(m.Message, needle) {
			return true
		}
	}
	return false
}
