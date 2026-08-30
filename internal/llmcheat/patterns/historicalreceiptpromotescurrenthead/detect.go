// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

// Package historicalreceiptpromotescurrenthead detects attempts to promote a
// newer/current subject using only historical receipt evidence.
package historicalreceiptpromotescurrenthead

import (
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "historical-receipt-promotes-current-head"
	category  = "governed-execution-integrity"
)

var (
	historicalRe = regexp.MustCompile(
		`(?i)\b(previous|prior|historical|old)\b.{0,40}\breceipt\b|` +
			`\breceipt\b.{0,40}\b(previous|prior|historical|old)\b`,
	)
	promotionRe = regexp.MustCompile(`(?i)\b(current|latest|new)\b.{0,30}\b(head|commit|sha|subject)\b|\bALIVE\b`)
	freshRe = regexp.MustCompile(
		`(?i)\b(fresh|new)\b.{0,20}\breceipt\b|` +
			`\b(re-?run|re-?execute|fresh evidence|recertif)\w*\b`,
	)
)

type detector struct{}

func (d *detector) ID() string       { return patternID }
func (d *detector) Category() string { return category }
func (d *detector) Detect(path string, content []byte) []llmcheat.Match {
	text := string(content)
	loc := historicalRe.FindStringIndex(text)
	if loc == nil || !promotionRe.MatchString(text) || freshRe.MatchString(text) {
		return nil
	}
	line := uint(1 + strings.Count(text[:loc[0]], "\n"))
	return []llmcheat.Match{{PatternID: patternID, Category: category, Path: path, Line: line,
		Message: "historical receipt is being used to promote current/new standing without fresh execution evidence; " +
			"load-bearing drift requires a new receipt",
		Severity: llmcheat.SeverityHigh}}
}

//nolint:gochecknoinits // package registration is the production plugin contract.
func init() { llmcheat.Register(&detector{}) }
