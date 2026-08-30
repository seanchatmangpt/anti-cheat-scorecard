// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

// Package exactheadclaimwithfloatingref detects exact-subject claims that still
// select a floating branch ref. Exact-head evidence is only meaningful when the
// subject itself is bound to immutable identity.
package exactheadclaimwithfloatingref

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "exact-head-claim-with-floating-ref"
	category  = "governed-execution-integrity"
)

var (
	exactClaimRe = regexp.MustCompile(`(?i)\b(exact[- ]head|exact sha|exact subject|admitted subject|exact commit)\b`)
	floatingRefRe = regexp.MustCompile(
		`(?im)(?:\bref\s*:\s*(?:main|master)\b|` +
			`\bbranch\s*[:=]\s*["']?(?:main|master)\b|` +
			`@(?:main|master)\b|checkout\s+(?:main|master)\b)`,
	)
	fullSHARe = regexp.MustCompile(`(?i)\b[0-9a-f]{40}\b`)
)

var extensions = map[string]bool{
	".md": true, ".txt": true, ".yml": true, ".yaml": true, ".toml": true, ".json": true, ".sh": true, ".bash": true,
}

type detector struct{}

func (d *detector) ID() string       { return patternID }
func (d *detector) Category() string { return category }

func (d *detector) Detect(path string, content []byte) []llmcheat.Match {
	if len(content) == 0 || !extensions[strings.ToLower(filepath.Ext(path))] {
		return nil
	}
	text := string(content)
	if !exactClaimRe.MatchString(text) || fullSHARe.MatchString(text) {
		return nil
	}
	loc := floatingRefRe.FindStringIndex(text)
	if loc == nil {
		return nil
	}
	line := uint(1 + strings.Count(text[:loc[0]], "\n"))
	return []llmcheat.Match{{PatternID: patternID, Category: category, Path: path, Line: line,
		Message: "artifact claims exact-subject evidence while selecting a floating main/master ref; " +
			"bind the admitted subject to an immutable 40-hex commit SHA",
		Severity: llmcheat.SeverityHigh}}
}

//nolint:gochecknoinits // package registration is the production plugin contract.
func init() { llmcheat.Register(&detector{}) }
