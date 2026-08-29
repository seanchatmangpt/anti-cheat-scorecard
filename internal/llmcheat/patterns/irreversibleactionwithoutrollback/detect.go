// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

// Package irreversibleactionwithoutrollback detects destructive operational
// actions that collapse future options without recording a compensating,
// recovery, or rollback route nearby.
package irreversibleactionwithoutrollback

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "irreversible-action-without-rollback"
	category  = "option-space-collapse"
)

var (
	destructiveRe = regexp.MustCompile(
		`(?i)(` +
			`git\s+push[^\n]*--force(?:-with-lease)?|terraform\s+destroy\b|kubectl\s+delete\b|` +
			`helm\s+uninstall\b|gh\s+release\s+delete\b|\bDROP\s+(?:TABLE|DATABASE)\b|` +
			`\bTRUNCATE\s+TABLE\b|\bDELETE\s+FROM\b` +
			`)`,
	)
	recoveryRe = regexp.MustCompile(
		`(?i)\b(` +
			`rollback|revert|restore|backup|snapshot|undo|compensat(?:e|ion)|canary|` +
			`blue[- ]?green|savepoint|recovery|recover|recreate|restore point` +
			`)\b`,
	)
	negativeRe = regexp.MustCompile(
		`(?i)\b(do not|don't|never|forbid|forbidden|reject|detect|anti[- ]pattern|example of|must not)\b`,
	)
)

var operationalExtensions = map[string]bool{
	".sh": true, ".bash": true, ".yml": true, ".yaml": true,
	".md": true, ".txt": true, ".toml": true, ".sql": true,
}

type detector struct{}

func newDetector() *detector         { return &detector{} }
func (d *detector) ID() string       { return patternID }
func (d *detector) Category() string { return category }

func (d *detector) Detect(path string, content []byte) []llmcheat.Match {
	if len(content) == 0 || !operationalExtensions[strings.ToLower(filepath.Ext(path))] {
		return nil
	}
	lines := strings.Split(string(content), "\n")
	var matches []llmcheat.Match
	for i, line := range lines {
		if !destructiveRe.MatchString(line) || negativeRe.MatchString(line) {
			continue
		}
		window := joinWindow(lines, i, 6)
		if recoveryRe.MatchString(window) {
			continue
		}
		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      uint(i + 1),
			Message: fmt.Sprintf(
				"destructive action %q has no nearby rollback/backup/restore/compensation route",
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

//nolint:gochecknoinits // package registration is the production plugin contract.
func init() { llmcheat.Register(newDetector()) }
