// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

// Package replayclaimwithoutevidence detects replay-verification claims that
// provide no command, receipt, digest, or immutable subject evidence.
package replayclaimwithoutevidence

import (
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "replay-claim-without-evidence"
	category  = "governed-execution-integrity"
)

var (
	replayClaimRe = regexp.MustCompile(`(?i)\breplay\b.{0,30}\b(verified|passed|successful|complete|reproducible)\b`)
	evidenceRe    = regexp.MustCompile(`(?i)\b(command|receipt|digest|sha256|blake3|commit sha|subject sha|artifact|log|run id)\b|[0-9a-f]{40}`)
)

type detector struct{}

func (d *detector) ID() string       { return patternID }
func (d *detector) Category() string { return category }
func (d *detector) Detect(path string, content []byte) []llmcheat.Match {
	text := string(content)
	loc := replayClaimRe.FindStringIndex(text)
	if loc == nil || evidenceRe.MatchString(text) {
		return nil
	}
	line := uint(1 + strings.Count(text[:loc[0]], "\n"))
	return []llmcheat.Match{{PatternID: patternID, Category: category, Path: path, Line: line,
		Message:  "replay is claimed verified without a command, receipt, digest, immutable subject SHA, artifact, log, or run identity; a named replay is not verified replay evidence",
		Severity: llmcheat.SeverityMedium}}
}

//nolint:gochecknoinits // package registration is the production plugin contract.
func init() { llmcheat.Register(&detector{}) }
