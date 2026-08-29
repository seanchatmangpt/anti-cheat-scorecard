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

package unreceipteddoaction

import (
	"strings"
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// dirtyGoSource is a realistic multi-line Go file: a real deploy pipeline
// helper alongside one Deploy function that shells out to `docker push`
// with no adjacent receipt/ledger call anywhere in its body.
const dirtyGoSource = `package deployer

import (
	"fmt"
	"os/exec"
)

// buildTag renders the image tag used for this deploy.
func buildTag(version string) string {
	return fmt.Sprintf("registry.example.com/app:%s", version)
}

// Deploy pushes the built image to the container registry.
func Deploy(image string) error {
	return exec.Command("docker", "push", image).Run()
}
`

// cleanGoSource is the same shape, except Deploy also calls writeReceipt
// after the mutating push — the adjacent evidence-writing step this
// pattern requires.
const cleanGoSource = `package deployer

import (
	"fmt"
	"os/exec"
)

// buildTag renders the image tag used for this deploy.
func buildTag(version string) string {
	return fmt.Sprintf("registry.example.com/app:%s", version)
}

// Deploy pushes the built image to the container registry and records a
// receipt of the action.
func Deploy(image string) error {
	if err := exec.Command("docker", "push", image).Run(); err != nil {
		return err
	}
	return writeReceipt("deploy", image)
}

// writeReceipt appends a durable record of a completed DO action.
func writeReceipt(action, subject string) error {
	return nil
}
`

func TestDetect_DirtyGoDeploy_ProducesMatch(t *testing.T) {
	d := detector{}

	matches := d.Detect("deployer/deploy.go", []byte(dirtyGoSource))

	if len(matches) < 1 {
		t.Fatalf("Detect() on dirty Go fixture = %d matches, want >= 1", len(matches))
	}

	got := matches[0]
	if got.PatternID != patternID {
		t.Errorf("Match.PatternID = %q, want %q", got.PatternID, patternID)
	}
	if got.Category != patternCategory {
		t.Errorf("Match.Category = %q, want %q", got.Category, patternCategory)
	}
	if got.Path != "deployer/deploy.go" {
		t.Errorf("Match.Path = %q, want %q", got.Path, "deployer/deploy.go")
	}

	// Derive the expected 1-based line number from the fixture text itself
	// (rather than a hand-counted literal) so the assertion stays correct
	// even if the fixture is edited later.
	wantLine := uint(0)
	for i, line := range strings.Split(dirtyGoSource, "\n") {
		if strings.Contains(line, "func Deploy(image string) error {") {
			wantLine = uint(i + 1)
			break
		}
	}
	if wantLine == 0 {
		t.Fatal("test fixture bug: dirtyGoSource does not contain the expected Deploy signature line")
	}
	if got.Line != wantLine {
		t.Errorf("Match.Line = %d, want %d", got.Line, wantLine)
	}
	if got.Severity != llmcheat.SeverityHigh {
		t.Errorf("Match.Severity = %q, want %q", got.Severity, llmcheat.SeverityHigh)
	}
	if got.Message == "" {
		t.Error("Match.Message is empty, want a real explanation")
	}
}

func TestDetect_CleanGoDeployWithReceipt_ProducesNoMatches(t *testing.T) {
	d := detector{}

	matches := d.Detect("deployer/deploy.go", []byte(cleanGoSource))

	if len(matches) != 0 {
		t.Fatalf("Detect() on clean Go fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

// TestDetect_GoMethodWithReceiver proves the Go receiver-method shape
// (`func (d *Deployer) Push(...) {`) is recognized, not just bare `func
// Name(...)`, since that is the idiomatic Go form for this kind of type.
func TestDetect_GoMethodWithReceiver(t *testing.T) {
	const src = `package deployer

// Deployer pushes images on behalf of a configured registry.
type Deployer struct {
	Registry string
}

// Push ships image to d's configured registry with no recorded evidence.
func (d *Deployer) Push(image string) error {
	return exec.Command("docker", "push", image).Run()
}
`
	d := detector{}

	matches := d.Detect("deployer/deployer.go", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() on receiver-method fixture = %d matches, want 1; matches=%+v", len(matches), matches)
	}
	if matches[0].PatternID != patternID {
		t.Errorf("Match.PatternID = %q, want %q", matches[0].PatternID, patternID)
	}
}

// TestDetect_KeywordNameButNoMutatingCall_NoMatch proves the mutating-call
// gate is real and independent of the name gate: a function named with a
// qualifying keyword that never actually performs a mutating/network
// action must not be flagged, even though it has no receipt call either.
func TestDetect_KeywordNameButNoMutatingCall_NoMatch(t *testing.T) {
	const src = `package notes

import "log"

// PublishNotes only logs locally; it never calls out to any external
// system, so there is nothing here that needs a receipt.
func PublishNotes(notes string) {
	log.Println("publishing notes:", notes)
}
`
	d := detector{}

	matches := d.Detect("notes/notes.go", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() on no-mutating-call fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

// TestDetect_MutatingCallButNoKeywordName_NoMatch proves the name gate is
// real and independent of the mutating-call gate: a function that performs
// the exact same unreceipted docker-push action as the dirty fixture, but
// whose name contains none of deploy/publish/release/push, must not be
// flagged — this pattern is scoped to DO-shaped function names specifically.
func TestDetect_MutatingCallButNoKeywordName_NoMatch(t *testing.T) {
	const src = `package shipper

import "os/exec"

// ship performs the same unreceipted docker push as Deploy above, but its
// name does not contain any of this pattern's qualifying keywords.
func ship(image string) error {
	return exec.Command("docker", "push", image).Run()
}
`
	d := detector{}

	matches := d.Detect("shipper/ship.go", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() on non-keyword-name fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

// dirtyPythonSource and cleanPythonSource prove this pattern is not
// Go-specific: it recognizes Python's indentation-delimited function body
// shape too.
const dirtyPythonSource = `import subprocess


def deploy(image):
    """Push image to the registry with no recorded evidence."""
    subprocess.run(["docker", "push", image], check=True)
`

const cleanPythonSource = `import subprocess


def deploy(image):
    """Push image to the registry and record a receipt of the action."""
    subprocess.run(["docker", "push", image], check=True)
    write_receipt("deploy", image)
`

func TestDetect_DirtyPythonDeploy_ProducesMatch(t *testing.T) {
	d := detector{}

	matches := d.Detect("deployer/deploy.py", []byte(dirtyPythonSource))

	if len(matches) != 1 {
		t.Fatalf("Detect() on dirty Python fixture = %d matches, want 1; matches=%+v", len(matches), matches)
	}
	if matches[0].PatternID != patternID {
		t.Errorf("Match.PatternID = %q, want %q", matches[0].PatternID, patternID)
	}
	if matches[0].Category != patternCategory {
		t.Errorf("Match.Category = %q, want %q", matches[0].Category, patternCategory)
	}

	wantLine := uint(0)
	for i, line := range strings.Split(dirtyPythonSource, "\n") {
		if strings.HasPrefix(line, "def deploy(image):") {
			wantLine = uint(i + 1)
			break
		}
	}
	if wantLine == 0 {
		t.Fatal("test fixture bug: dirtyPythonSource does not contain the expected def line")
	}
	if matches[0].Line != wantLine {
		t.Errorf("Match.Line = %d, want %d", matches[0].Line, wantLine)
	}
}

func TestDetect_CleanPythonDeployWithReceipt_ProducesNoMatches(t *testing.T) {
	d := detector{}

	matches := d.Detect("deployer/deploy.py", []byte(cleanPythonSource))

	if len(matches) != 0 {
		t.Fatalf("Detect() on clean Python fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

// TestDetect_GitPushViaShellFunction proves the POSIX-shell-style
// `name() { ... }` body shape and the "git push" literal-text match (as
// opposed to the exec.Command(...) call form) are both recognized.
func TestDetect_GitPushViaShellFunction(t *testing.T) {
	const src = `#!/usr/bin/env bash
set -euo pipefail

release() {
	git add -A
	git commit -m "release"
	git push origin main
}
`
	d := detector{}

	matches := d.Detect("scripts/release.sh", []byte(src))

	if len(matches) != 1 {
		t.Fatalf("Detect() on shell git-push fixture = %d matches, want 1; matches=%+v", len(matches), matches)
	}
	if matches[0].PatternID != patternID {
		t.Errorf("Match.PatternID = %q, want %q", matches[0].PatternID, patternID)
	}
}

func TestPattern_IDAndCategory(t *testing.T) {
	d := detector{}

	if got := d.ID(); got != patternID {
		t.Errorf("ID() = %q, want %q", got, patternID)
	}
	if got := d.Category(); got != patternCategory {
		t.Errorf("Category() = %q, want %q", got, patternCategory)
	}
}
