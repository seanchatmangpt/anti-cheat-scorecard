// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

// Package terminalfailurewithoutreserve detects automation/status language
// that turns one failed transition into terminal work stoppage without
// naming either a typed authority/transport/capability boundary or another
// lawful route. DfCM treats failure as information until the admitted option
// set is exhausted.
package terminalfailurewithoutreserve

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const patternID = "terminal-failure-without-reserve"
const category = "option-space-collapse"

var terminalRe = regexp.MustCompile(`(?i)\b(stop on first failure|if [^\n.]*fails?[,;:]?\s*(?:stop|abort|exit)|on failure[: ]+(?:stop|abort|exit)|stopping because|cannot continue|no further work|failure_action\s*[:=]\s*(?:stop|abort|exit))\b`)
var reserveRe = regexp.MustCompile(`(?i)\b(reserve|fallback|alternative|continue with|next route|next lawful route|retry|repair|root cause|\bRCA\b|requeue|promote [^\n]*reserve|other work|parallel lane|remaining queue)\b`)
var typedBoundaryRe = regexp.MustCompile(`(?i)\b(?:BLOCKED|REFUSED|UNSUPPORTED)\[[A-Z0-9_:\-]+\]|\b(authority|transport|capability) boundary\b`)
var normativeRe = regexp.MustCompile(`(?i)\b(detects?|detector|anti[- ]pattern|example|must not|do not|don't|forbid|reject)\b`)

var evidenceExtensions = map[string]bool{
	".md": true, ".txt": true, ".log": true, ".json": true,
	".yml": true, ".yaml": true, ".toml": true, ".sh": true, ".bash": true,
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
		if !terminalRe.MatchString(line) || normativeRe.MatchString(line) {
			continue
		}
		window := joinWindow(lines, i, 5)
		if reserveRe.MatchString(window) || typedBoundaryRe.MatchString(window) {
			continue
		}
		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      uint(i + 1), //nolint:gosec // bounded repository-text index
			Message: fmt.Sprintf("terminal failure statement %q names neither a reserve route nor a typed authority/transport/capability boundary", strings.TrimSpace(line)),
			Severity:  llmcheat.SeverityHigh,
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
