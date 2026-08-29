// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

// Package dfcmplanwithoutreserve detects planning artifacts that explicitly
// claim DfCM/combinatorial-maximalism discipline while omitting both reserve
// routes and a reversible/rollback path. A DfCM label without preserved
// alternatives is itself evidence of option-space laundering.
package dfcmplanwithoutreserve

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "dfcm-plan-without-reserve"
	category  = "option-space-collapse"
)

var (
	dfcmRe = regexp.MustCompile(
		`(?i)\b(` +
			`dfcm|design for combinatorial maximalism|combinatorial maximalism|` +
			`maximi[sz]e reversible options` +
			`)\b`,
	)
	planRe = regexp.MustCompile(
		`(?i)\b(plan|strategy|roadmap|execution|implementation|workflow|work queue|primary|takt|iteration)\b`,
	)
	breadthRe = regexp.MustCompile(
		`(?i)\b(` +
			`reserves?|fallbacks?|alternatives?|options?|candidates?|contingenc(?:y|ies)|` +
			`secondary route|next lawful route` +
			`)\b`,
	)
	reversibilityRe = regexp.MustCompile(
		`(?i)\b(rollback|reversible|revert|undo|restore|compensat(?:e|ion)|replay)\b`,
	)
)

var planExtensions = map[string]bool{
	".md": true, ".txt": true, ".json": true, ".yml": true, ".yaml": true, ".toml": true,
}

type detector struct{}

func newDetector() *detector         { return &detector{} }
func (d *detector) ID() string       { return patternID }
func (d *detector) Category() string { return category }

func (d *detector) Detect(path string, content []byte) []llmcheat.Match {
	if len(content) == 0 || !planExtensions[strings.ToLower(filepath.Ext(path))] {
		return nil
	}
	text := string(content)
	loc := dfcmRe.FindStringIndex(text)
	if loc == nil || !planRe.MatchString(text) {
		return nil
	}
	missing := make([]string, 0, 2)
	if !breadthRe.MatchString(text) {
		missing = append(missing, "reserve/alternative route")
	}
	if !reversibilityRe.MatchString(text) {
		missing = append(missing, "rollback/reversible route")
	}
	if len(missing) == 0 {
		return nil
	}
	line := uint(1 + strings.Count(text[:loc[0]], "\n"))
	return []llmcheat.Match{{
		PatternID: patternID,
		Category:  category,
		Path:      path,
		Line:      line,
		Message: fmt.Sprintf(
			"DfCM execution plan is missing %s; the plan claims combinatorial maximalism while collapsing future routes",
			strings.Join(missing, " and "),
		),
		Severity: llmcheat.SeverityHigh,
	}}
}

//nolint:gochecknoinits // package registration is the production plugin contract.
func init() { llmcheat.Register(newDetector()) }
