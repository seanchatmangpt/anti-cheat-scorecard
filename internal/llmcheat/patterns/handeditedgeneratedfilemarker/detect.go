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

// Package handeditedgeneratedfilemarker implements the
// "hand-edited-generated-file-marker" llmcheat Pattern: it flags a file that
// declares itself machine-generated — a "DO NOT EDIT" / "Code generated ...
// DO NOT EDIT" / "@generated" marker in its first few lines, the universal
// convention across protoc-gen-go, `go generate`, GraphQL/OpenAPI codegen,
// Buck/Bazel, and Facebook's @generated tooling — and ALSO contains a
// human-editorial comment marker somewhere in its body ("// HACK",
// "# manual fix", "// FIXME by", "<!-- manually adjusted -->", or
// "// hand-edited"). Neither half is suspicious alone: plenty of generated
// files are pristine, and plenty of hand-written files legitimately contain
// a "// HACK" comment. The combination is the signal — a file whose header
// says "never touch me, this gets clobbered on the next regen" that someone
// touched anyway, meaning the real, regeneratable source of truth has now
// silently drifted from the checked-in artifact.
//
// This pattern is deliberately not scoped to any one file extension: the
// "DO NOT EDIT" convention shows up verbatim across .go, .py, .ts, .rs,
// .md, .html/.xml (as an HTML comment), and generated config/lock files
// alike, so Detect runs on any text content it is given.
package handeditedgeneratedfilemarker

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID       = "hand-edited-generated-file-marker"
	patternCategory = "generated-artifact-tampering"
)

// maxHeaderLines bounds how many lines from the top of the file are
// inspected for a generated-file marker. Every real generator this pattern
// targets (protoc-gen-go, `go generate`, GraphQL/OpenAPI codegen, ggen
// itself) emits the marker on line 1 or 2; 5 lines gives slack for a
// preceding license/copyright header or a blank line without drifting into
// treating an arbitrary marker anywhere in a large file as a generated-file
// declaration.
const maxHeaderLines = 5

// generatedMarkers are the literal substrings that identify a file as
// machine-generated. Matched case-insensitively against each header line,
// since real-world generators vary casing ("DO NOT EDIT." vs a lowercase
// "@generated" convention) but the phrases themselves are fixed.
var generatedMarkers = []string{
	"do not edit",
	"@generated",
}

// editorialMarkers are the literal, case-sensitive substrings that signal a
// human went back into a file and edited it by hand despite its generated
// marker. These are exactly the markers named in this pattern's
// specification, matched as-is (not case-folded): they are deliberately
// distinctive spellings unlikely to appear by coincidence in a generator's
// own boilerplate output.
var editorialMarkers = []string{
	"// HACK",
	"# manual fix",
	"// FIXME by",
	"<!-- manually adjusted -->",
	"// hand-edited",
}

// detector is the real, stateless implementation of llmcheat.Pattern for
// this pattern. It holds no fields because Detect is a pure function of its
// arguments: the type exists only to give the interface methods a receiver.
type detector struct{}

func (detector) ID() string { return patternID }

func (detector) Category() string { return patternCategory }

// Detect scans content for the generated-marker + hand-edited-marker
// combination described in the package doc. It first checks whether any of
// the file's first maxHeaderLines lines declare the file generated; if not,
// it returns immediately with no matches (an editorial comment in an
// ordinary, non-generated file is not this pattern's concern). Only once
// that header check passes does it scan the full file for editorial
// markers, producing one Match per line that contains one, with a real
// 1-based line number computed from an actual running counter over the
// scanned lines.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	lines := splitLines(content)
	if len(lines) == 0 {
		return nil
	}

	if !hasGeneratedMarker(lines) {
		return nil
	}

	var matches []llmcheat.Match
	for i, line := range lines {
		marker, found := findEditorialMarker(line)
		if !found {
			continue
		}
		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  patternCategory,
			Path:      path,
			Line:      uint(i + 1),
			Message: fmt.Sprintf(
				"file declares itself machine-generated (a %q-style marker in its first %d lines) but also contains the human-editorial marker %q, meaning someone hand-edited a file that says it will be overwritten on regen: %s",
				"DO NOT EDIT", maxHeaderLines, marker, strings.TrimSpace(line),
			),
			Severity: llmcheat.SeverityHigh,
		})
	}

	return matches
}

// splitLines splits content into its constituent lines using a real
// line-oriented scan (not a naive strings.Split on "\n", which mishandles a
// trailing-newline-less final line inconsistently across callers). The
// scanner's buffer is raised well above bufio's 64KiB default so one
// unusually long generated line (a minified table, a long import list)
// doesn't cause a silent bufio.ErrTooLong scan failure that would make this
// detector miss real matches.
func splitLines(content []byte) []string {
	if len(content) == 0 {
		return nil
	}
	var lines []string
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

// hasGeneratedMarker reports whether any of lines' first maxHeaderLines
// entries contains one of generatedMarkers, case-insensitively.
func hasGeneratedMarker(lines []string) bool {
	limit := maxHeaderLines
	if len(lines) < limit {
		limit = len(lines)
	}
	for i := 0; i < limit; i++ {
		lower := strings.ToLower(lines[i])
		for _, marker := range generatedMarkers {
			if strings.Contains(lower, marker) {
				return true
			}
		}
	}
	return false
}

// findEditorialMarker reports the first editorialMarkers entry contained in
// line, if any.
func findEditorialMarker(line string) (marker string, found bool) {
	for _, marker := range editorialMarkers {
		if strings.Contains(line, marker) {
			return marker, true
		}
	}
	return "", false
}

func init() {
	llmcheat.Register(detector{})
}
