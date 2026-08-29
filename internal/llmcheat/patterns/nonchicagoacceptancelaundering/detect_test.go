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

package nonchicagoacceptancelaundering

import (
	"strings"
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

func TestFlagsDryRunPromotedToChicago(t *testing.T) {
	got := newDetector().Detect("receipt.md", []byte("Chicago passed. Verified with ggen sync run --dry-run; exit 0."))
	if len(got) != 1 || got[0].Severity != llmcheat.SeverityHigh {
		t.Fatalf("got=%+v", got)
	}
}

func TestFlagsMocksPromotedToAlive(t *testing.T) {
	got := newDetector().Detect("report.md", []byte("ALIVE[consumer_path].\nEvidence: all mocked integration tests passed."))
	if len(got) != 1 || got[0].Severity != llmcheat.SeverityHigh {
		t.Fatalf("got=%+v", got)
	}
}

func TestFlagsWorkflowExistenceAsProductionProof(t *testing.T) {
	got := newDetector().Detect("status.md", []byte("Production ready.\nWorkflow exists and CI started successfully."))
	if len(got) != 1 || got[0].Severity != llmcheat.SeverityHigh {
		t.Fatalf("got=%+v", got)
	}
}

func TestFlagsPushOnlyAsMergeReadyProof(t *testing.T) {
	got := newDetector().Detect("PR_BODY.md", []byte("Merge-ready.\nPR opened and branch pushed successfully."))
	if len(got) != 1 || got[0].Severity != llmcheat.SeverityHigh {
		t.Fatalf("got=%+v", got)
	}
}

func TestFlagsExactSHAWithoutExecution(t *testing.T) {
	got := newDetector().Detect("receipt.json", []byte(`{"standing":"ALIVE","subject":"abc123"}`))
	if len(got) != 1 || got[0].Severity != llmcheat.SeverityMedium {
		t.Fatalf("got=%+v", got)
	}
}

func TestAcceptsRealChicagoEvidenceBundle(t *testing.T) {
	content := []byte("Chicago passed.\nRan `docker run app:sha` against the admitted subject.\nExit code: 0.\nObserved HTTP 200 and wrote receipt.json.\nMerged into main; containment checked with merge-base --is-ancestor.")
	if got := newDetector().Detect("receipt.md", content); len(got) != 0 {
		t.Fatalf("got=%+v", got)
	}
}

func TestNormativeDefinitionDoesNotSelfFlag(t *testing.T) {
	content := []byte("ALIVE requires observed execution against the exact admitted subject and a replay-verifiable receipt.")
	if got := newDetector().Detect("CHICAGO.md", content); len(got) != 0 {
		t.Fatalf("got=%+v", got)
	}
}

func TestNegativeStandingDoesNotSelfFlag(t *testing.T) {
	content := []byte("This is not ALIVE because only a dry-run was observed.")
	if got := newDetector().Detect("status.md", content); len(got) != 0 {
		t.Fatalf("got=%+v", got)
	}
}

func TestOrdinaryUnitTestClaimIsOutOfScope(t *testing.T) {
	content := []byte("Verified parser behavior with `go test ./parser -run TestMalformed`.")
	if got := newDetector().Detect("notes.md", content); len(got) != 0 {
		t.Fatalf("got=%+v", got)
	}
}

func TestCodeFileIsOutOfScope(t *testing.T) {
	content := []byte("const status = \"ALIVE\"")
	if got := newDetector().Detect("status.go", content); len(got) != 0 {
		t.Fatalf("got=%+v", got)
	}
}

func TestMessageNamesChicagoBoundary(t *testing.T) {
	got := newDetector().Detect("status.md", []byte("Release-ready after schema-only validation."))
	if len(got) != 1 || !strings.Contains(got[0].Message, "Chicago requires real production-path execution") {
		t.Fatalf("got=%+v", got)
	}
}

func TestIDCategoryAndRegistration(t *testing.T) {
	d := newDetector()
	if d.ID() != patternID || d.Category() != category {
		t.Fatalf("id=%q category=%q", d.ID(), d.Category())
	}
	llmcheat.Reset()
	llmcheat.Register(d)
	defer llmcheat.Reset()
	all := llmcheat.All()
	if len(all) != 1 || all[0].ID() != patternID {
		t.Fatalf("all=%+v", all)
	}
}
