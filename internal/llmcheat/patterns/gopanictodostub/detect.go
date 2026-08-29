// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package gopanictodostub implements the "go-panic-todo-stub" llmcheat
// Pattern: it flags Go source files (excluding _test.go files) whose body
// contains a panic() call whose string argument reads like a placeholder
// for real logic — panic("TODO...", panic("not implemented...", or
// panic("unimplemented...", matched case-insensitively. This is a very
// common shape an LLM (or a human under deadline pressure) leaves behind
// when a function is scaffolded but never actually implemented: the
// function signature type-checks and the package builds, but calling the
// function crashes the caller instead of doing real work.
package gopanictodostub

import (
	"bufio"
	"bytes"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID       = "go-panic-todo-stub"
	patternCategory = "hollow-implementation"
)

// stubPanicRe matches a panic( call whose string literal argument begins
// with one of the known placeholder phrases, case-insensitively. Optional
// whitespace is allowed between the opening paren and the quote (Go permits
// panic( "TODO") just as well as panic("TODO")), and gofmt/goimports never
// collapse the "panic(" identifier's case since it is a Go keyword-like
// builtin, so only the placeholder phrase itself needs the (?i:...) scope.
var stubPanicRe = regexp.MustCompile(`panic\(\s*"(?i:TODO|not implemented|unimplemented)`)

// detector is the real, stateless implementation of llmcheat.Pattern for
// this pattern. It holds no fields because Detect is a pure function of its
// arguments: the type exists only to give the interface methods a receiver.
type detector struct{}

func (detector) ID() string { return patternID }

func (detector) Category() string { return patternCategory }

// Detect scans path's content line-by-line (only for .go files, and never
// for _test.go files, per the pattern's scope) and returns one Match per
// line that contains a stub-shaped panic() call. Line numbers are 1-based
// and computed from a real running counter over the actual scanned lines,
// not fabricated or left at zero.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	if filepath.Ext(path) != ".go" {
		return nil
	}
	if strings.HasSuffix(path, "_test.go") {
		return nil
	}

	var matches []llmcheat.Match

	scanner := bufio.NewScanner(bytes.NewReader(content))
	// Source lines can be long (e.g. a wrapped panic message); raise the
	// scanner's buffer well above bufio's 64KiB default so a single
	// unusually long line doesn't cause a silent bufio.ErrTooLong scan
	// failure that would make this detector miss real matches.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNum := uint(0)
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		loc := stubPanicRe.FindStringIndex(line)
		if loc == nil {
			continue
		}

		snippet := strings.TrimSpace(line)
		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  patternCategory,
			Path:      path,
			Line:      lineNum,
			Message: fmt.Sprintf(
				"stub panic() found instead of a real implementation: %s",
				snippet,
			),
			Severity: llmcheat.SeverityHigh,
		})
	}

	return matches
}

func init() {
	llmcheat.Register(detector{})
}
