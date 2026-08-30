// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

// Package receiptsubjectheadmismatch detects receipt material whose subject SHA
// contradicts the head/commit SHA it purports to certify.
package receiptsubjectheadmismatch

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "receipt-subject-head-mismatch"
	category  = "governed-execution-integrity"
)

var (
	subjectRe = regexp.MustCompile(`(?i)(?:subject[_-]?sha|subject[_-]?commit)\s*[=:]\s*["']?([0-9a-f]{40})`)
	headRe    = regexp.MustCompile(`(?i)(?:head[_-]?sha|commit[_-]?sha|certified[_-]?sha)\s*[=:]\s*["']?([0-9a-f]{40})`)
)

var extensions = map[string]bool{
	".json": true, ".jsonl": true, ".toml": true, ".yml": true, ".yaml": true, ".txt": true, ".log": true, ".md": true,
}

type detector struct{}

func (d *detector) ID() string       { return patternID }
func (d *detector) Category() string { return category }
func (d *detector) Detect(path string, content []byte) []llmcheat.Match {
	if len(content) == 0 || !extensions[strings.ToLower(filepath.Ext(path))] {
		return nil
	}
	text := string(content)
	subject := subjectRe.FindStringSubmatchIndex(text)
	head := headRe.FindStringSubmatchIndex(text)
	if subject == nil || head == nil {
		return nil
	}
	subjectSHA := strings.ToLower(text[subject[2]:subject[3]])
	headSHA := strings.ToLower(text[head[2]:head[3]])
	if subjectSHA == headSHA {
		return nil
	}
	line := uint(1 + strings.Count(text[:subject[0]], "\n"))
	return []llmcheat.Match{{PatternID: patternID, Category: category, Path: path, Line: line,
		Message:  "receipt subject SHA does not equal the head/commit SHA it claims to certify; standing cannot cross an identity mismatch",
		Severity: llmcheat.SeverityHigh}}
}

//nolint:gochecknoinits // package registration is the production plugin contract.
func init() { llmcheat.Register(&detector{}) }
