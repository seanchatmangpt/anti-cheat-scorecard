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

// Package prematureoptioncollapse detects decisions that collapse to one
// implementation before the surrounding evidence records any option census,
// comparison, falsifier, reserve, or reversible route. This is the core DfCM
// failure mode: selection is allowed, but selection without preserving and
// evaluating lawful alternatives destroys information before it is needed.
package prematureoptioncollapse

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const patternID = "premature-option-collapse"
const category = "option-space-collapse"

var commitmentRe = regexp.MustCompile(`(?i)\b(only (?:viable |reasonable |safe )?option|no (?:other )?alternative|must use|must choose|chosen approach|selected approach|we chose|we selected|the solution is)\b`)
var explorationRe = regexp.MustCompile(`(?i)\b(alternatives?|options?|candidates?|census|inventory|compare|comparison|trade[- ]?offs?|reserve|fallback|rollback|reversible|contingency|falsifier|next lawful route)\b`)
var normativeRe = regexp.MustCompile(`(?i)\b(detects?|detector|rule|anti[- ]pattern|counterexample|example|must not|should flag|rejects?|forbids?)\b`)

var evidenceExtensions = map[string]bool{
	".md": true, ".txt": true, ".log": true, ".json": true,
	".yml": true, ".yaml": true, ".toml": true,
}

type detector struct{}

func newDetector() *detector         { return &detector{} }
func (d *detector) ID() string       { return patternID }
func (d *detector) Category() string { return category }

func (d *detector) Detect(path string, content []byte) []llmcheat.Match {
	if len(content) == 0 || !evidenceExtensions[strings.ToLower(filepath.Ext(path))] {
		return nil
	}
	lines := strings.Split(string(content), "\n")
	var matches []llmcheat.Match
	for i, line := range lines {
		if !commitmentRe.MatchString(line) || normativeRe.MatchString(line) {
			continue
		}
		window := joinWindow(lines, i, 4)
		if explorationRe.MatchString(window) {
			continue
		}
		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      uint(i + 1), //nolint:gosec // bounded repository-text index
			Message: fmt.Sprintf(
				"%q collapses the option space without a nearby census/comparison/falsifier/reserve or reversible route",
				strings.TrimSpace(line),
			),
			Severity: llmcheat.SeverityHigh,
		})
	}
	return matches
}

func joinWindow(lines []string, center, radius int) string {
	start := center - radius
	if start < 0 {
		start = 0
	}
	end := center + radius
	if end >= len(lines) {
		end = len(lines) - 1
	}
	return strings.Join(lines[start:end+1], "\n")
}

func init() { llmcheat.Register(newDetector()) }
