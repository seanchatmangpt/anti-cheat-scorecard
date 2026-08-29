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

// Package overclaimingsuperlative implements the "overclaiming-superlative"
// llmcheat.Pattern.
//
// It flags unqualified absolute-superlative claims — "100%", "fully",
// "completely", "guaranteed" (and its verb forms), "always works"-shaped
// claims, and "never fails"-shaped claims — found in comment/doc text with
// no adjacent qualifier on the same line: a link, a "see" citation, a file
// reference, or a number-with-unit that shows the claim was derived from an
// actual measured count (e.g. "98.7% of 10,000 fuzz runs").
//
// Scope is intentionally comment/doc text, not arbitrary code: a string
// literal or identifier containing one of these words is not, by itself,
// an overclaiming comment. "Doc text" is decided with a deliberately
// lightweight, best-effort heuristic (recognized single-line comment
// prefixes across common languages, a simple /* ... */ block-comment state
// machine, and "every line counts" for prose file extensions like .md) —
// not a real per-language lexer. That is a stated limitation, not a hidden
// one: a language this heuristic doesn't recognize (e.g. an unusual
// comment syntax) will under-scan rather than over-scan.
package overclaimingsuperlative

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID       = "overclaiming-superlative"
	patternCategory = "fabricated-claims"
)

// docFileExts are file extensions whose entire content is prose/docs, so
// every line is treated as doc text without needing a comment prefix.
var docFileExts = map[string]bool{
	".md":   true,
	".mdx":  true,
	".txt":  true,
	".rst":  true,
	".adoc": true,
}

// lineCommentPrefixes are single-line comment markers recognized across the
// languages this tool's target repos actually use: Go/Rust/TS/JS/C-family
// "//", shell/Python/Ruby/TOML/YAML "#", SQL/Lua/Haskell "--", Lisp/asm ";",
// TeX "%".
var lineCommentPrefixes = []string{"//", "#", "--", ";", "%"}

const (
	blockCommentStart = "/*"
	blockCommentEnd   = "*/"
)

// trigger is one absolute-superlative phrase this pattern flags: a
// human-readable label for Match.Message plus the compiled, case-insensitive
// regexp that detects it.
type trigger struct {
	label string
	re    *regexp.Regexp
}

var triggers = []trigger{
	{`"100%"`, regexp.MustCompile(`(?i)\b100\s?%`)},
	{`"fully"`, regexp.MustCompile(`(?i)\bfully\b`)},
	{`"completely"`, regexp.MustCompile(`(?i)\bcompletely\b`)},
	{`"guaranteed"`, regexp.MustCompile(`(?i)\bguarantee(?:d|s|ing)?\b`)},
	{`an absolute "always ..." claim`, regexp.MustCompile(`(?i)\balways\s+(?:works?|worked|working|passes?|passed|succeeds?|succeeded|correct|perfect|reliable|accurate)\b`)},
	{`an absolute "never ..." claim`, regexp.MustCompile(`(?i)\bnever\s+(?:fails?|failed|failing|breaks?|broke|broken|crashes?|crashed|errors?|erred)\b`)},
}

// Qualifier patterns: any of these present on the same line suppresses
// every trigger match on that line, since the claim is treated as
// substantiated rather than bare assertion.
var (
	qualifierURL = regexp.MustCompile(`https?://\S+`)
	qualifierSee = regexp.MustCompile(`(?i)\bsee\b`)
	// A reference to a concrete file (receipts/fuzz-20260101.json, a
	// README, an .rq query, etc.) — a citation the reader can go check.
	qualifierFileCite = regexp.MustCompile(`(?i)\b[\w./-]+\.(?:json|md|txt|csv|log|ya?ml|toml|rq|ttl)\b`)
	// A number followed (within up to two words) by a countable unit —
	// the signature of a percentage/claim actually derived from a real
	// measured count, e.g. "10,000 fuzz runs" or "5,000 CI runs".
	qualifierCountUnit = regexp.MustCompile(`(?i)\b\d[\d,]*(?:\.\d+)?\s+(?:\w+\s+){0,2}(?:runs?|tests?|cases?|samples?|trials?|attempts?|iterations?|requests?|instances?|scans?|checks?|users?|builds?|commits?|prs?|files?|calls?|executions?|invocations?|reviews?|benchmarks?|records?|rows?|jobs?|queries?)\b`)
)

func hasQualifier(line string) bool {
	return qualifierURL.MatchString(line) ||
		qualifierSee.MatchString(line) ||
		qualifierFileCite.MatchString(line) ||
		qualifierCountUnit.MatchString(line)
}

// isDocExt reports whether path's extension marks the whole file as prose.
func isDocExt(path string) bool {
	return docFileExts[strings.ToLower(filepath.Ext(path))]
}

// isLineCommentStart reports whether the trimmed line begins with one of
// the recognized single-line comment prefixes.
func isLineCommentStart(trimmed string) bool {
	for _, p := range lineCommentPrefixes {
		if strings.HasPrefix(trimmed, p) {
			return true
		}
	}
	return false
}

// detector is the real, unexported Pattern implementation for
// "overclaiming-superlative". It holds no state beyond its methods: Detect
// is a pure function of (path, content), as the llmcheat.Pattern contract
// requires.
type detector struct{}

func (detector) ID() string       { return patternID }
func (detector) Category() string { return patternCategory }

// Detect scans content line-by-line, classifies each line as doc-like or
// not (see the package doc comment for the exact heuristic), and — for
// doc-like lines with no qualifier anywhere on the line — reports every
// absolute-superlative trigger phrase found as a Match with a real 1-based
// line number.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	var matches []llmcheat.Match

	wholeFileIsDoc := isDocExt(path)
	inBlockComment := false

	lines := strings.Split(string(content), "\n")
	for i, raw := range lines {
		lineNum := uint(i + 1)
		trimmed := strings.TrimSpace(raw)

		lineIsDoc := wholeFileIsDoc
		if inBlockComment {
			lineIsDoc = true
		}

		startsBlock := strings.Contains(trimmed, blockCommentStart)
		endsBlock := strings.Contains(trimmed, blockCommentEnd)

		if !lineIsDoc {
			switch {
			case isLineCommentStart(trimmed):
				lineIsDoc = true
			case strings.HasPrefix(trimmed, "*"):
				// Continuation line of a /** ... */ doc block.
				lineIsDoc = true
			case startsBlock:
				lineIsDoc = true
			}
		}

		// Update block-comment state for the *next* line based on what
		// this line opened/closed.
		switch {
		case startsBlock && !endsBlock:
			inBlockComment = true
		case endsBlock:
			inBlockComment = false
		}

		if !lineIsDoc || trimmed == "" {
			continue
		}

		if hasQualifier(trimmed) {
			continue
		}

		for _, t := range triggers {
			if !t.re.MatchString(trimmed) {
				continue
			}
			matches = append(matches, llmcheat.Match{
				PatternID: patternID,
				Category:  patternCategory,
				Path:      path,
				Line:      lineNum,
				Message:   "unqualified absolute superlative claim (" + t.label + ") with no nearby qualifier (a count, a link, or a citation)",
				Severity:  llmcheat.SeverityMedium,
			})
		}
	}

	return matches
}

func init() {
	llmcheat.Register(detector{})
}
