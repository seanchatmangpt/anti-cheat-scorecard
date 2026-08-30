// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

// Package selectconstructdocollapsed detects explicit collapse of SELECT,
// CONSTRUCT, and DO into one authority surface.
package selectconstructdocollapsed

import (
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "select-construct-do-collapsed"
	category  = "governed-execution-integrity"
)

var collapseRe = regexp.MustCompile(`(?i)\b(same|single|combined|unified|one|collapse[ds]?|together)\b`)

type detector struct{}

func (d *detector) ID() string       { return patternID }
func (d *detector) Category() string { return category }
func (d *detector) Detect(path string, content []byte) []llmcheat.Match {
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	for i, line := range lines {
		upper := strings.ToUpper(line)
		if strings.Contains(upper, "SELECT") &&
			strings.Contains(upper, "CONSTRUCT") &&
			strings.Contains(upper, "DO") && collapseRe.MatchString(line) {
			return []llmcheat.Match{{PatternID: patternID, Category: category, Path: path, Line: uint(i + 1),
				Message: "SELECT, CONSTRUCT, and DO are explicitly collapsed into one authority surface; " +
					"preserve selection, construction, and receipted actuation as distinct stages",
				Severity: llmcheat.SeverityHigh}}
		}
	}
	return nil
}

//nolint:gochecknoinits // package registration is the production plugin contract.
func init() { llmcheat.Register(&detector{}) }
