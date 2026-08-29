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

package godfunctionhidesstub

import (
	"strings"
	"testing"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// dirtyGoSource is a realistic 5-function Go file: four small, real helper
// functions and one (Process) whose body is almost entirely narrated-but-
// removed-feature comment filler around a single real statement. Process's
// own line count is far more than 4x the file's median top-level function
// line count (3), and under 20% of its lines are real code.
const dirtyGoSource = `package worker

import "errors"

// Job represents a unit of work.
type Job struct {
	ID string
}

// Validate checks that a Job is well-formed.
func Validate(j Job) error {
	if j.ID == "" {
		return errors.New("job ID required")
	}
	return nil
}

// Enqueue adds a job to the queue.
func Enqueue(j Job) error {
	return queue.Push(j)
}

// Dequeue removes the next job from the queue.
func Dequeue() (Job, error) {
	return queue.Pop()
}

// Cancel marks a job as cancelled.
func Cancel(id string) error {
	return store.MarkCancelled(id)
}

// Process runs a job end to end.
func Process(j Job) error {
	// step 1: validate preconditions before doing anything else
	// step 2: acquire a lease on the job so no other worker races us
	// step 3: record a started-at timestamp for observability
	// step 4: check the job hasn't already been cancelled out from under us
	// step 5: resolve the handler registered for this job's type
	// step 6: build the execution context the handler expects
	// step 7: snapshot current metrics before running, for a before/after diff
	// step 8: log that execution is starting, at debug level
	// step 9: this used to also warm a cache, but that path was removed
	// step 10: this used to also emit a legacy event, but that path was removed
	// step 11: this used to also update a counter, but that path was removed
	// step 12: this used to also refresh a token, but that path was removed
	// step 13: this used to also ping a healthcheck, but that path was removed
	// step 14: this used to also flush a buffer, but that path was removed
	// step 15: this used to also rotate a log file, but that path was removed
	// step 16: this used to also sync a clock, but that path was removed
	// step 17: this used to also reload config, but that path was removed
	// step 18: this used to also re-check permissions, but that path was removed
	// step 19: this used to also re-validate the payload, but that path was removed
	// step 20: this used to also re-acquire the lease, but that path was removed
	// step 21: this used to also re-log the start event, but that path was removed
	// step 22: this used to also re-snapshot metrics, but that path was removed
	// step 23: this used to also re-resolve the handler, but that path was removed
	// step 24: this used to also re-build the context, but that path was removed
	// step 25: none of the above matter; only the next line actually runs
	return run(j)
}
`

// cleanGoSource is the same 5-function shape, but Process is genuinely long
// because it does real work at every line — no comment/blank padding.
const cleanGoSource = `package worker

import "errors"

// Job represents a unit of work.
type Job struct {
	ID string
}

// Validate checks that a Job is well-formed.
func Validate(j Job) error {
	if j.ID == "" {
		return errors.New("job ID required")
	}
	return nil
}

// Enqueue adds a job to the queue.
func Enqueue(j Job) error {
	return queue.Push(j)
}

// Dequeue removes the next job from the queue.
func Dequeue() (Job, error) {
	return queue.Pop()
}

// Cancel marks a job as cancelled.
func Cancel(id string) error {
	return store.MarkCancelled(id)
}

// Process runs a job through every real stage.
func Process(j Job) error {
	if err := Validate(j); err != nil {
		return err
	}
	lease, err := acquireLease(j.ID)
	if err != nil {
		return err
	}
	defer lease.Release()
	result, err := run(j)
	if err != nil {
		return err
	}
	return record(j.ID, result)
}
`

func TestDetect_DirtyGoFixture_ProducesMatch(t *testing.T) {
	d := detector{}

	matches := d.Detect("worker/job.go", []byte(dirtyGoSource))

	if len(matches) != 1 {
		t.Fatalf("Detect() on dirty fixture = %d matches, want 1; matches=%+v", len(matches), matches)
	}

	got := matches[0]
	if got.PatternID != patternID {
		t.Errorf("Match.PatternID = %q, want %q", got.PatternID, patternID)
	}
	if got.Category != category {
		t.Errorf("Match.Category = %q, want %q", got.Category, category)
	}
	if got.Path != "worker/job.go" {
		t.Errorf("Match.Path = %q, want %q", got.Path, "worker/job.go")
	}

	// Derive the expected header line straight from the fixture text so the
	// assertion survives future edits to the fixture.
	wantLine := uint(0)
	for i, line := range strings.Split(dirtyGoSource, "\n") {
		if strings.HasPrefix(line, "func Process(") {
			wantLine = uint(i + 1)
			break
		}
	}
	if wantLine == 0 {
		t.Fatal("test fixture bug: dirtyGoSource does not contain the expected \"func Process(\" header")
	}
	if got.Line != wantLine {
		t.Errorf("Match.Line = %d, want %d", got.Line, wantLine)
	}
	if got.Severity != llmcheat.SeverityMedium {
		t.Errorf("Match.Severity = %q, want %q", got.Severity, llmcheat.SeverityMedium)
	}
	if !strings.Contains(got.Message, "Process") {
		t.Errorf("Match.Message = %q, want it to name the flagged function", got.Message)
	}
}

func TestDetect_CleanGoFixture_ProducesNoMatches(t *testing.T) {
	d := detector{}

	matches := d.Detect("worker/job.go", []byte(cleanGoSource))

	if len(matches) != 0 {
		t.Fatalf("Detect() on clean fixture = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

// TestDetect_FewerThanFiveFunctions_NoMatches proves the stated noise-
// avoidance gate: the exact same disproportionate-and-padded Process shape
// from the dirty fixture, but in a file with only 3 top-level functions,
// must not be flagged — "disproportionate" requires enough siblings to be
// disproportionate relative to.
func TestDetect_FewerThanFiveFunctions_NoMatches(t *testing.T) {
	const src = `package worker

func Validate(j Job) error {
	return nil
}

func Enqueue(j Job) error {
	return queue.Push(j)
}

func Process(j Job) error {
	// step 1: validate preconditions before doing anything else
	// step 2: acquire a lease on the job so no other worker races us
	// step 3: record a started-at timestamp for observability
	// step 4: check the job hasn't already been cancelled out from under us
	// step 5: resolve the handler registered for this job's type
	// step 6: build the execution context the handler expects
	// step 7: snapshot current metrics before running, for a before/after diff
	// step 8: log that execution is starting, at debug level
	// step 9: this used to also warm a cache, but that path was removed
	// step 10: this used to also emit a legacy event, but that path was removed
	// step 11: this used to also update a counter, but that path was removed
	// step 12: this used to also refresh a token, but that path was removed
	// step 13: this used to also ping a healthcheck, but that path was removed
	// step 14: this used to also flush a buffer, but that path was removed
	// step 15: this used to also rotate a log file, but that path was removed
	// step 16: this used to also sync a clock, but that path was removed
	// step 17: this used to also reload config, but that path was removed
	// step 18: this used to also re-check permissions, but that path was removed
	// step 19: this used to also re-validate the payload, but that path was removed
	// step 20: this used to also re-acquire the lease, but that path was removed
	// step 21: this used to also re-log the start event, but that path was removed
	// step 22: this used to also re-snapshot metrics, but that path was removed
	// step 23: this used to also re-resolve the handler, but that path was removed
	// step 24: this used to also re-build the context, but that path was removed
	// step 25: none of the above matter; only the next line actually runs
	return run(j)
}
`
	d := detector{}

	matches := d.Detect("worker/job.go", []byte(src))

	if len(matches) != 0 {
		t.Fatalf("Detect() on a 3-function file = %d matches, want 0 (below the 5-function gate); matches=%+v", len(matches), matches)
	}
}

// TestDetect_UniformlyPaddedFunctions_NoMatches proves the "relative to the
// median" semantics specifically: five top-level functions that are all
// comment-padded to roughly the same degree (each individually under the
// 20% real-content threshold) must not be flagged, because none of them is
// disproportionate relative to its siblings — this pattern targets a
// function that stands out, not a file where every function is padded.
func TestDetect_UniformlyPaddedFunctions_NoMatches(t *testing.T) {
	padded := func(name string) string {
		var b strings.Builder
		b.WriteString("func " + name + "() error {\n")
		for i := 1; i <= 14; i++ {
			b.WriteString("\t// filler line explaining a removed step\n")
		}
		b.WriteString("\treturn nil\n}\n")
		return b.String()
	}

	var src strings.Builder
	src.WriteString("package worker\n\n")
	for _, name := range []string{"StepOne", "StepTwo", "StepThree", "StepFour", "StepFive"} {
		src.WriteString(padded(name))
		src.WriteString("\n")
	}

	d := detector{}
	matches := d.Detect("worker/steps.go", []byte(src.String()))

	if len(matches) != 0 {
		t.Fatalf("Detect() on uniformly padded functions = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

func TestDetect_NonRelevantFileType_NoMatches(t *testing.T) {
	d := detector{}

	matches := d.Detect("worker/notes.md", []byte(dirtyGoSource))

	if len(matches) != 0 {
		t.Fatalf("Detect() on a .md file = %d matches, want 0; matches=%+v", len(matches), matches)
	}
}

// dirtyPythonSource mirrors dirtyGoSource's shape in Python: 4 small real
// top-level functions and one (process) padded with comment filler around a
// single real statement.
const dirtyPythonSource = `def validate(job):
    if not job.id:
        raise ValueError("job id required")
    return True


def enqueue(job):
    return queue.push(job)


def dequeue():
    return queue.pop()


def cancel(job_id):
    return store.mark_cancelled(job_id)


def process(job):
    # step 1: validate preconditions before doing anything else
    # step 2: acquire a lease on the job so no other worker races us
    # step 3: record a started-at timestamp for observability
    # step 4: check the job hasn't already been cancelled out from under us
    # step 5: resolve the handler registered for this job's type
    # step 6: build the execution context the handler expects
    # step 7: snapshot current metrics before running, for a before/after diff
    # step 8: log that execution is starting, at debug level
    # step 9: this used to also warm a cache, but that path was removed
    # step 10: this used to also emit a legacy event, but that path was removed
    # step 11: this used to also update a counter, but that path was removed
    # step 12: this used to also refresh a token, but that path was removed
    # step 13: this used to also ping a healthcheck, but that path was removed
    # step 14: this used to also flush a buffer, but that path was removed
    # step 15: this used to also rotate a log file, but that path was removed
    # step 16: this used to also sync a clock, but that path was removed
    # step 17: this used to also reload config, but that path was removed
    # step 18: this used to also re-check permissions, but that path was removed
    # step 19: this used to also re-validate the payload, but that path was removed
    # step 20: this used to also re-acquire the lease, but that path was removed
    # step 21: this used to also re-log the start event, but that path was removed
    # step 22: this used to also re-snapshot metrics, but that path was removed
    # step 23: this used to also re-resolve the handler, but that path was removed
    # step 24: this used to also re-build the context, but that path was removed
    # step 25: none of the above matter; only the next line actually runs
    return run(job)
`

func TestDetect_DirtyPythonFixture_ProducesMatch(t *testing.T) {
	d := detector{}

	matches := d.Detect("worker/job.py", []byte(dirtyPythonSource))

	if len(matches) != 1 {
		t.Fatalf("Detect() on dirty Python fixture = %d matches, want 1; matches=%+v", len(matches), matches)
	}
	if matches[0].PatternID != patternID {
		t.Errorf("Match.PatternID = %q, want %q", matches[0].PatternID, patternID)
	}
	if matches[0].Category != category {
		t.Errorf("Match.Category = %q, want %q", matches[0].Category, category)
	}
	if !strings.Contains(matches[0].Message, "process") {
		t.Errorf("Match.Message = %q, want it to name the flagged function", matches[0].Message)
	}
}

// dirtyRustSource mirrors the same shape in Rust.
const dirtyRustSource = `fn validate(job: &Job) -> Result<(), String> {
    if job.id.is_empty() {
        return Err("job id required".to_string());
    }
    Ok(())
}

fn enqueue(job: Job) -> Result<(), String> {
    queue::push(job)
}

fn dequeue() -> Option<Job> {
    queue::pop()
}

fn cancel(job_id: &str) -> Result<(), String> {
    store::mark_cancelled(job_id)
}

fn process(job: Job) -> Result<(), String> {
    // step 1: validate preconditions before doing anything else
    // step 2: acquire a lease on the job so no other worker races us
    // step 3: record a started-at timestamp for observability
    // step 4: check the job hasn't already been cancelled out from under us
    // step 5: resolve the handler registered for this job's type
    // step 6: build the execution context the handler expects
    // step 7: snapshot current metrics before running, for a before/after diff
    // step 8: log that execution is starting, at debug level
    // step 9: this used to also warm a cache, but that path was removed
    // step 10: this used to also emit a legacy event, but that path was removed
    // step 11: this used to also update a counter, but that path was removed
    // step 12: this used to also refresh a token, but that path was removed
    // step 13: this used to also ping a healthcheck, but that path was removed
    // step 14: this used to also flush a buffer, but that path was removed
    // step 15: this used to also rotate a log file, but that path was removed
    // step 16: this used to also sync a clock, but that path was removed
    // step 17: this used to also reload config, but that path was removed
    // step 18: this used to also re-check permissions, but that path was removed
    // step 19: this used to also re-validate the payload, but that path was removed
    // step 20: this used to also re-acquire the lease, but that path was removed
    // step 21: this used to also re-log the start event, but that path was removed
    // step 22: this used to also re-snapshot metrics, but that path was removed
    // step 23: this used to also re-resolve the handler, but that path was removed
    // step 24: this used to also re-build the context, but that path was removed
    // step 25: none of the above matter; only the next line actually runs
    run(job)
}
`

func TestDetect_DirtyRustFixture_ProducesMatch(t *testing.T) {
	d := detector{}

	matches := d.Detect("worker/job.rs", []byte(dirtyRustSource))

	if len(matches) != 1 {
		t.Fatalf("Detect() on dirty Rust fixture = %d matches, want 1; matches=%+v", len(matches), matches)
	}
	if matches[0].PatternID != patternID {
		t.Errorf("Match.PatternID = %q, want %q", matches[0].PatternID, patternID)
	}
	if matches[0].Category != category {
		t.Errorf("Match.Category = %q, want %q", matches[0].Category, category)
	}
}

// dirtyTSSource mirrors the same shape in TypeScript.
const dirtyTSSource = `function validate(job: Job): boolean {
  if (!job.id) {
    throw new Error("job id required");
  }
  return true;
}

function enqueue(job: Job): void {
  queue.push(job);
}

function dequeue(): Job | undefined {
  return queue.pop();
}

function cancel(jobId: string): void {
  store.markCancelled(jobId);
}

function process(job: Job): void {
  // step 1: validate preconditions before doing anything else
  // step 2: acquire a lease on the job so no other worker races us
  // step 3: record a started-at timestamp for observability
  // step 4: check the job hasn't already been cancelled out from under us
  // step 5: resolve the handler registered for this job's type
  // step 6: build the execution context the handler expects
  // step 7: snapshot current metrics before running, for a before/after diff
  // step 8: log that execution is starting, at debug level
  // step 9: this used to also warm a cache, but that path was removed
  // step 10: this used to also emit a legacy event, but that path was removed
  // step 11: this used to also update a counter, but that path was removed
  // step 12: this used to also refresh a token, but that path was removed
  // step 13: this used to also ping a healthcheck, but that path was removed
  // step 14: this used to also flush a buffer, but that path was removed
  // step 15: this used to also rotate a log file, but that path was removed
  // step 16: this used to also sync a clock, but that path was removed
  // step 17: this used to also reload config, but that path was removed
  // step 18: this used to also re-check permissions, but that path was removed
  // step 19: this used to also re-validate the payload, but that path was removed
  // step 20: this used to also re-acquire the lease, but that path was removed
  // step 21: this used to also re-log the start event, but that path was removed
  // step 22: this used to also re-snapshot metrics, but that path was removed
  // step 23: this used to also re-resolve the handler, but that path was removed
  // step 24: this used to also re-build the context, but that path was removed
  // step 25: none of the above matter; only the next line actually runs
  run(job);
}
`

func TestDetect_DirtyTypeScriptFixture_ProducesMatch(t *testing.T) {
	d := detector{}

	matches := d.Detect("worker/job.ts", []byte(dirtyTSSource))

	if len(matches) != 1 {
		t.Fatalf("Detect() on dirty TypeScript fixture = %d matches, want 1; matches=%+v", len(matches), matches)
	}
	if matches[0].PatternID != patternID {
		t.Errorf("Match.PatternID = %q, want %q", matches[0].PatternID, patternID)
	}
	if matches[0].Category != category {
		t.Errorf("Match.Category = %q, want %q", matches[0].Category, category)
	}
}

func TestPattern_IDAndCategory(t *testing.T) {
	d := detector{}

	if got := d.ID(); got != patternID {
		t.Errorf("ID() = %q, want %q", got, patternID)
	}
	if got := d.Category(); got != category {
		t.Errorf("Category() = %q, want %q", got, category)
	}
}
