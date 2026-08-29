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

// Package claimalivewithoutreceipt implements the "claim-alive-without-receipt"
// llmcheat.Pattern: it flags comment / doc-string / markdown-prose lines that
// assert a strong completion status ("ALIVE", "done", "complete", "finished",
// "working") with no nearby (same line, or within 3 lines before/after)
// reference to evidence backing that claim — a receipt path, a test name, the
// phrase "verified by", a commit hash, or a file path.
//
// Deliberately out of scope: ordinary string literals meant for end users
// (log messages, CLI help text, etc.) — only comment/doc-string/markdown
// prose is scanned for the status-word claim itself (evidence, by contrast,
// is searched across the whole nearby lines, since evidence is often a real
// code reference rather than more prose).
package claimalivewithoutreceipt

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "claim-alive-without-receipt"
	category  = "fabricated-claims"
)

// statusWordRe matches a strong, unqualified completion/status claim as a
// whole word, case-insensitively (the shared standing vocabulary spells it
// "ALIVE"; ordinary prose spells the rest lower-case).
var statusWordRe = regexp.MustCompile(`(?i)\b(alive|done|completed|complete|finished|working)\b`)

// evidenceRe matches any of the five evidence kinds named in the pattern
// description: a receipt reference, a test name/path, the phrase
// "verified by", a commit-hash-shaped hex token, or a file path with a
// recognized source/doc/lock extension.
var evidenceRe = regexp.MustCompile(`(?i)(` +
	`\breceipts?\b` + // receipt / receipts
	`|verified\s+by` + // "verified by ..."
	`|::\s*test\w*` + // pytest-style ::test_foo
	`|\btest_[A-Za-z0-9_]+` + // test_login_flow
	`|[A-Za-z0-9_]+_test\b` + // login_test
	`|\btests?/` + // tests/ or test/ path segment
	`|\b[0-9a-f]{7,40}\b` + // git-style commit hash
	`|\b[A-Za-z0-9_][A-Za-z0-9_./\\-]{1,120}\.(?:go|py|rs|js|jsx|ts|tsx|ttl|rq|md|markdown|json|toml|ya?ml|txt|lock|sh|rb|java|kt|c|cc|cpp|h|hpp|proto|cfg|ini|sql|css|html)\b` + // file path with a recognized extension
	`)`)

// evidenceWindow is how many lines before/after a claim line are searched
// for nearby evidence, per the pattern description ("same or adjacent 3
// lines").
const evidenceWindow = 3

// detector is the unexported implementation of llmcheat.Pattern for this
// pattern. It holds no state: Detect is a pure function of its arguments.
type detector struct{}

func (detector) ID() string { return patternID }

func (detector) Category() string { return category }

func init() {
	llmcheat.Register(detector{})
}

// Detect scans content line by line. It first classifies which lines are
// "prose" eligible for a status-word claim (comment text, doc-string text,
// or — for markdown files — any line outside a fenced code block), then for
// each status-word hit on an eligible line checks the surrounding raw lines
// (eligible or not — evidence is frequently real code, not more prose) for
// an evidence reference.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	if len(content) == 0 {
		return nil
	}

	lines := splitLines(content)
	prose := classifyProseLines(path, lines)

	var matches []llmcheat.Match
	for i, text := range prose {
		if text == "" {
			continue
		}
		loc := statusWordRe.FindStringIndex(text)
		if loc == nil {
			continue
		}
		word := text[loc[0]:loc[1]]
		if hasNearbyEvidence(lines, i) {
			continue
		}
		lineNo := uint(i + 1) // 1-based
		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      lineNo,
			Message: fmt.Sprintf(
				"status claim %q on line %d has no nearby evidence (receipt path, test name, \"verified by\", commit hash, or file path) within %d lines",
				word, lineNo, evidenceWindow,
			),
			Severity: severityFor(word),
		})
	}
	return matches
}

// severityFor triages by how strong/official the claimed word is. "ALIVE"
// mirrors a standing-vocabulary crown claim and gets the highest severity;
// "complete"/"finished" are strong but generic; "done"/"working" are the
// weakest/most casual of the five.
func severityFor(word string) llmcheat.Severity {
	switch strings.ToLower(word) {
	case "alive":
		return llmcheat.SeverityHigh
	case "complete", "completed", "finished":
		return llmcheat.SeverityMedium
	default: // "done", "working"
		return llmcheat.SeverityLow
	}
}

// hasNearbyEvidence reports whether any raw line in [i-evidenceWindow,
// i+evidenceWindow] (inclusive, clamped to the file) contains an evidence
// reference. Evidence is searched across raw lines regardless of whether
// they were classified as prose, since evidence is commonly a real code
// reference (an import path, a test invocation) rather than more comment
// text.
func hasNearbyEvidence(lines []string, i int) bool {
	lo := i - evidenceWindow
	if lo < 0 {
		lo = 0
	}
	hi := i + evidenceWindow
	if hi > len(lines)-1 {
		hi = len(lines) - 1
	}
	for j := lo; j <= hi; j++ {
		if evidenceRe.MatchString(lines[j]) {
			return true
		}
	}
	return false
}

// splitLines splits content into lines, dropping a trailing '\r' from each
// (so CRLF files behave the same as LF files) and never returning a
// trailing empty line caused solely by a final '\n'.
func splitLines(content []byte) []string {
	raw := strings.Split(string(content), "\n")
	if len(raw) > 0 && raw[len(raw)-1] == "" {
		raw = raw[:len(raw)-1]
	}
	out := make([]string, len(raw))
	for i, l := range raw {
		out[i] = strings.TrimSuffix(l, "\r")
	}
	return out
}

// isMarkdownPath reports whether path names a markdown file by extension.
func isMarkdownPath(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".md", ".markdown":
		return true
	default:
		return false
	}
}

// classifyProseLines returns, for every line, the substring of that line
// that counts as "prose" eligible for a status-word claim: comment text or
// doc-string text for ordinary source files, or any non-fenced-code text for
// markdown files. A line that is not prose-eligible maps to "".
func classifyProseLines(path string, lines []string) []string {
	out := make([]string, len(lines))
	if isMarkdownPath(path) {
		classifyMarkdownProseLines(lines, out)
		return out
	}
	classifyCommentLines(lines, out)
	return out
}

// classifyMarkdownProseLines marks every line outside a fenced code block
// (delimited by a line whose trimmed content starts with ``` or ~~~) as
// prose text (the line itself); fenced lines, including the fence
// delimiters, are left as "".
func classifyMarkdownProseLines(lines []string, out []string) {
	inFence := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			inFence = !inFence
			continue // the fence delimiter line itself is not prose
		}
		if inFence {
			continue
		}
		out[i] = line
	}
}

// classifyCommentLines marks each line's comment-or-doc-string substring
// (line comments "//"/"#", block comments "/* ... */", and triple-quoted
// "\"\"\"..." / "”'..." doc-strings) as prose text. It is a line-oriented
// heuristic, not a real tokenizer: it does not understand ordinary string
// literals, so a "//" or "#" that happens to appear inside a non-comment
// string can be misread as a comment start. The one specific case guarded
// against is a "//" immediately preceded by ':' (a URL scheme such as
// "https://"), which is common enough to be worth excluding explicitly.
func classifyCommentLines(lines []string, out []string) {
	inBlockComment := false
	tripleQuoteOpen := "" // "" | `"""` | `'''`

	for i, line := range lines {
		switch {
		case inBlockComment:
			if end := strings.Index(line, "*/"); end >= 0 {
				out[i] = line[:end]
				inBlockComment = false
			} else {
				out[i] = line
			}
			continue

		case tripleQuoteOpen != "":
			if end := strings.Index(line, tripleQuoteOpen); end >= 0 {
				out[i] = line[:end]
				tripleQuoteOpen = ""
			} else {
				out[i] = line
			}
			continue
		}

		// Not currently inside a block comment or open triple-quote: look
		// for whichever comment/doc-string construct starts earliest.
		lineCommentIdx := findLineCommentIdx(line)
		blockStartIdx := strings.Index(line, "/*")
		tripleIdx, tripleMarker := findTripleQuoteStart(line)

		type candidate struct {
			idx  int
			kind byte // 'l' line, 'b' block, 't' triple
		}
		var best *candidate
		consider := func(idx int, kind byte) {
			if idx < 0 {
				return
			}
			if best == nil || idx < best.idx {
				best = &candidate{idx: idx, kind: kind}
			}
		}
		consider(lineCommentIdx, 'l')
		consider(blockStartIdx, 'b')
		consider(tripleIdx, 't')

		if best == nil {
			continue // plain code line, nothing to classify
		}

		switch best.kind {
		case 'l':
			markerLen := 1 // "#"
			if line[best.idx] == '/' {
				markerLen = 2 // "//"
			}
			out[i] = line[best.idx+markerLen:]

		case 'b':
			rest := line[best.idx+2:]
			if end := strings.Index(rest, "*/"); end >= 0 {
				out[i] = rest[:end]
			} else {
				out[i] = rest
				inBlockComment = true
			}

		case 't':
			rest := line[best.idx+len(tripleMarker):]
			if end := strings.Index(rest, tripleMarker); end >= 0 {
				out[i] = rest[:end]
			} else {
				out[i] = rest
				tripleQuoteOpen = tripleMarker
			}
		}
	}
}

// findLineCommentIdx returns the index of the earliest "//" or "#" in line
// that looks like a real comment start rather than part of a URL scheme
// ("http://", "https://"), or -1 if there is none.
func findLineCommentIdx(line string) int {
	best := -1
	if idx := findSlashSlashIdx(line); idx >= 0 {
		best = idx
	}
	if idx := strings.IndexByte(line, '#'); idx >= 0 {
		if best == -1 || idx < best {
			best = idx
		}
	}
	return best
}

// findSlashSlashIdx returns the index of the earliest "//" in line that is
// not immediately preceded by ':' (a URL scheme), or -1 if there is none.
func findSlashSlashIdx(line string) int {
	start := 0
	for {
		rel := strings.Index(line[start:], "//")
		if rel == -1 {
			return -1
		}
		abs := start + rel
		if abs > 0 && line[abs-1] == ':' {
			start = abs + 2
			continue
		}
		return abs
	}
}

// findTripleQuoteStart returns the earliest index of a triple-quote
// doc-string delimiter (`"""` or `”'`) in line and which marker it was, or
// (-1, "") if neither appears.
func findTripleQuoteStart(line string) (int, string) {
	dIdx := strings.Index(line, `"""`)
	sIdx := strings.Index(line, `'''`)
	switch {
	case dIdx >= 0 && (sIdx < 0 || dIdx <= sIdx):
		return dIdx, `"""`
	case sIdx >= 0:
		return sIdx, `'''`
	default:
		return -1, ""
	}
}
