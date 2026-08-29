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

package gosyntaxgraphchicago

import (
	"strings"
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

func TestDetectSyntaxLevelNonChicagoEvidence(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		src  string
		rule string
	}{
		{
			name: "skip call",
			src:  `package p; func TestChicago(t *testing.T) { t.Skip("later") }`,
			rule: "skipped-acceptance",
		},
		{
			name: "synthetic HTTP server",
			src:  `package p; import "net/http/httptest"; func TestAcceptance(t *testing.T) { _ = httptest.NewServer(nil) }`,
			rule: "synthetic-http-server",
		},
		{
			name: "placeholder panic",
			src:  `package p; func TestE2E(t *testing.T) { panic("TODO production call") }`,
			rule: "placeholder-panic",
		},
		{
			name: "tautological assertion",
			src:  `package p; func TestQualification(t *testing.T) { require.True(t, true) }`,
			rule: "tautological-assertion",
		},
		{
			name: "constant branch",
			src:  `package p; func TestJourney(t *testing.T) { if true { doRealThing() } }`,
			rule: "constant-control-branch",
		},
		{
			name: "boolean standing court",
			src: `package p
func TestConsumerCourt(t *testing.T) {
	_ = map[string]any{"clone": true, "runner": true, "receipt": false, "standing": "ALIVE"}
}`,
			rule: "boolean-standing-court",
		},
	}

	d := newDetector()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			matches := d.Detect("tests/chicago/acceptance_test.go", []byte(tc.src))
			if !hasRule(matches, tc.rule) {
				t.Fatalf("want rule %q, got %#v", tc.rule, matches)
			}
		})
	}
}

func TestCommentsAndNonAcceptanceFilesAreNotSyntaxEvidence(t *testing.T) {
	t.Parallel()
	d := newDetector()
	commentOnly := []byte(`package p
// t.Skip("not real")
// httptest.NewServer(nil)
func TestChicago(t *testing.T) { observeProduction() }
`)
	if matches := d.Detect("tests/chicago/runtime_test.go", commentOnly); len(matches) != 0 {
		t.Fatalf("comment text became executable evidence: %#v", matches)
	}
	if matches := d.Detect("pkg/runtime.go", []byte(`package p; func f(){ if true {} }`)); len(matches) != 0 {
		t.Fatalf("non-acceptance file should be out of scope: %#v", matches)
	}
}

func TestMalformedSyntaxIsNotAdmittedAsFinding(t *testing.T) {
	t.Parallel()
	if matches := newDetector().Detect("tests/chicago/broken_test.go", []byte(`package p; func {`)); len(matches) != 0 {
		t.Fatalf("malformed syntax should not manufacture semantic findings: %#v", matches)
	}
}

func hasRule(matches []llmcheat.Match, rule string) bool {
	needle := "[" + rule + "]"
	for _, m := range matches {
		if strings.Contains(m.Message, needle) {
			return true
		}
	}
	return false
}
