// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

// Package untypedrefusedstatus detects REFUSED standing emitted without a
// machine-auditable refusal type.
package untypedrefusedstatus

import (
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "untyped-refused-status"
	category  = "governed-execution-integrity"
)

var statusRe = regexp.MustCompile(`(?im)\b(?:status|standing)\s*[:=]\s*["']?REFUSED`)

type detector struct{}

func (d *detector) ID() string       { return patternID }
func (d *detector) Category() string { return category }
func (d *detector) Detect(path string, content []byte) []llmcheat.Match {
	text := string(content)
	loc := statusRe.FindStringIndex(text)
	if loc == nil {
		return nil
	}
	tail := text[loc[1]:]
	if strings.HasPrefix(tail, "[") {
		return nil
	}
	line := uint(1 + strings.Count(text[:loc[0]], "\n"))
	return []llmcheat.Match{{PatternID: patternID, Category: category, Path: path, Line: line,
		Message:  "REFUSED standing is untyped; preserve the refusal boundary as REFUSED[REASON_CODE] so the failed edge remains machine-auditable topology",
		Severity: llmcheat.SeverityMedium}}
}

//nolint:gochecknoinits // package registration is the production plugin contract.
func init() { llmcheat.Register(&detector{}) }
