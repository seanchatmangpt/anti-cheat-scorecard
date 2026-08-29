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

// Package hedgelanguagemasking implements the
// "hedge-language-masking-uncertainty" llmcheat.Pattern: it flags comment
// and doc lines that pair a hedging phrase ("should work", "probably fine",
// "I believe", "likely correct", "seems to", "presumably") with a nearby
// definite-outcome word ("works"/"passes"/"correct"/"complete"). That
// combination — confident-sounding vocabulary wrapped around an admission of
// uncertainty — is a real, observed LLM-cheat tell: the surface reads like a
// verified claim ("...and the tests probably pass") while the hedge word
// discloses that no such verification actually happened.
package hedgelanguagemasking

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID       = "hedge-language-masking-uncertainty"
	patternCategory = "fabricated-claims"
)

// hedgePhraseRegex matches any of the six hedging phrases named in the
// pattern's description, case-insensitively, on a word boundary so
// "presumably" doesn't also fire on "presumablyx" or similar noise.
var hedgePhraseRegex = regexp.MustCompile(`(?i)\b(should\s+work|probably\s+fine|i\s+believe|likely\s+correct|seems\s+to|presumably)\b`)

// outcomeWordRegex matches the definite-outcome vocabulary the pattern
// description names ("works"/"passes"/"correct"/"complete"), including the
// ordinary inflections a real comment would use (worked/working would be a
// stretch and is deliberately excluded to keep this precise rather than
// over-broad; the four stated words and their closest verb/adjective forms
// are included).
var outcomeWordRegex = regexp.MustCompile(`(?i)\b(works?|passes?|correct(?:ly)?|complete(?:d)?)\b`)

// commentPrefixes are the line-start markers that identify a "comment/doc
// line" across the common languages this multi-language, dependency-free
// tool is expected to scan (Go/C/Java-style //, block-comment continuation
// *, Python/shell/Ruby #, SQL/Lua --, Lisp ;, HTML/XML <!-- -->, and
// markdown blockquote/docstring markers). This is a deliberate heuristic,
// not a real per-language parser — good enough to identify "this line is
// prose commentary, not executable code" for the purpose of this pattern.
var commentPrefixes = []string{
	"///", "//", "/*", "*/", "*", "#", "--", ";;", ";", "%", "<!--", "-->", `"""`, "'''", ">",
}

// docExtensions are file extensions whose entire content is prose/doc text,
// so every non-blank line counts as a "doc line" regardless of comment
// syntax (a markdown README has no "//" prefix but is still documentation).
var docExtensions = map[string]bool{
	".md":       true,
	".markdown": true,
	".rst":      true,
	".txt":      true,
	".adoc":     true,
}

// detector is the real, stateless implementation of llmcheat.Pattern for
// this pattern. It holds no fields because Detect is a pure function of its
// arguments; a value receiver is enough and lets init() register a single
// zero-value instance.
type detector struct{}

func (detector) ID() string { return patternID }

func (detector) Category() string { return patternCategory }

// commentLine pairs a source line with its 1-based line number, kept
// together while a contiguous run of comment/doc lines ("a block") is
// accumulated so a hedge phrase on one line can be matched against an
// outcome word on a nearby line within the same block.
type commentLine struct {
	num  uint
	text string
}

// Detect scans content line-by-line, groups contiguous comment/doc lines
// into blocks, and — for every block that contains at least one
// definite-outcome word anywhere in it — reports a Match for every line in
// that block that itself contains a hedging phrase. Grouping into blocks
// (rather than requiring both signals on the exact same line) is the real
// implementation of the pattern description's "nearby": a hedge on one
// comment line immediately followed by an outcome claim on the next line of
// the same comment is exactly the pattern this detector exists to catch.
func (d detector) Detect(path string, content []byte) []llmcheat.Match {
	isDoc := docExtensions[strings.ToLower(filepath.Ext(path))]

	var matches []llmcheat.Match
	var block []commentLine

	flush := func() {
		if len(block) == 0 {
			return
		}
		joined := make([]string, len(block))
		for i, cl := range block {
			joined[i] = cl.text
		}
		if outcomeWordRegex.MatchString(strings.Join(joined, "\n")) {
			for _, cl := range block {
				hedge := hedgePhraseRegex.FindString(cl.text)
				if hedge == "" {
					continue
				}
				matches = append(matches, llmcheat.Match{
					PatternID: patternID,
					Category:  patternCategory,
					Path:      path,
					Line:      cl.num,
					Message: fmt.Sprintf(
						"hedging phrase %q appears alongside a definite-outcome claim in this comment/doc block — confidence language may be masking real uncertainty about whether it actually works",
						hedge,
					),
					Severity: llmcheat.SeverityMedium,
				})
			}
		}
		block = block[:0]
	}

	lines := strings.Split(string(content), "\n")
	for i, raw := range lines {
		lineNum := uint(i + 1) //nolint:gosec // line count from a real split, never overflows uint
		trimmed := strings.TrimSpace(raw)

		var relevant bool
		switch {
		case isDoc:
			relevant = trimmed != ""
		case trimmed != "":
			relevant = hasCommentPrefix(trimmed)
		}

		if relevant {
			block = append(block, commentLine{num: lineNum, text: raw})
		} else {
			flush()
		}
	}
	flush()

	return matches
}

// hasCommentPrefix reports whether a trimmed line starts with one of the
// recognized comment markers.
func hasCommentPrefix(trimmed string) bool {
	for _, prefix := range commentPrefixes {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	return false
}

func init() {
	llmcheat.Register(detector{})
}
