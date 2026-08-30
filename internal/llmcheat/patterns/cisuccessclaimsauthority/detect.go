// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

// Package cisuccessclaimsauthority detects prose that upgrades CI success from
// evidence transport into standing/certification authority.
package cisuccessclaimsauthority

import (
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "ci-success-claims-authority"
	category  = "governed-execution-integrity"
)

var (
	ciRe        = regexp.MustCompile(`(?i)\b(ci|continuous integration|github actions|workflow)\b`)
	passRe      = regexp.MustCompile(`(?i)\b(pass(?:ed|es|ing)?|green|success(?:ful|fully)?)\b`)
	inferenceRe = regexp.MustCompile(`(?i)\b(therefore|thus|proves?|means?|certif(?:y|ies|ied)|declares?)\b`)
	standingRe  = regexp.MustCompile(`(?i)\b(ALIVE|standing|authoritative|authority|certified)\b`)
)

type detector struct{}

func (d *detector) ID() string       { return patternID }
func (d *detector) Category() string { return category }
func (d *detector) Detect(path string, content []byte) []llmcheat.Match {
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	for i, line := range lines {
		if ciRe.MatchString(line) && passRe.MatchString(line) &&
			inferenceRe.MatchString(line) && standingRe.MatchString(line) {
			return []llmcheat.Match{{PatternID: patternID, Category: category, Path: path, Line: uint(i + 1),
				Message: "CI success is used as standing/certification authority; CI may transport evidence " +
					"but cannot manufacture authority or ALIVE standing by itself",
				Severity: llmcheat.SeverityHigh}}
		}
	}
	return nil
}

//nolint:gochecknoinits // package registration is the production plugin contract.
func init() { llmcheat.Register(&detector{}) }
