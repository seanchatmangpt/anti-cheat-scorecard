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

// Package unverifiedbenchmarknumbers implements the "unverified-benchmark-numbers"
// llmcheat.Pattern: it flags a specific-looking performance number (a
// duration like "96ms"/"3.2s"/"p95 203ms", or a speedup like "10x faster")
// that appears in a comment, doc string, or markdown line with no adjacent
// reference — within 3 lines either side — to a benchmark script, receipt
// file, or raw command output that would let a reader actually check the
// number.
package unverifiedbenchmarknumbers

import (
	"bufio"
	"bytes"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "unverified-benchmark-numbers"
	category  = "fabricated-claims"
)

// durationRe finds a number immediately followed (optionally separated by a
// single space) by a duration unit: ms/ns/µs/us/sec(s)/second(s)/min(s)/
// minute(s), or a bare "s". Capture group 1 is the numeric literal, group 2
// the unit token actually matched.
var durationRe = regexp.MustCompile(`(?i)\b(\d+(?:\.\d+)?)\s?(ms|ns|µs|us|secs?|seconds?|mins?|minutes?|s)\b`)

// multiplierRe finds a bare "<number>x" token, e.g. "10x", "2.5x".
var multiplierRe = regexp.MustCompile(`(?i)\b\d+(?:\.\d+)?x\b`)

// speedupWordRe matches the comparison vocabulary that turns a bare "<n>x"
// token into a speedup/slowdown *claim* rather than an incidental use of the
// letter x (grid dimensions, resolutions, etc.).
var speedupWordRe = regexp.MustCompile(`(?i)\b(faster|slower|quicker|speedup|speed[- ]?up|improvement|more efficient|less efficient|better performance)\b`)

// referenceRe matches the vocabulary that indicates a nearby line actually
// points at something checkable: a benchmark script, a receipt/results
// file, or raw command output.
var referenceRe = regexp.MustCompile(`(?i)(benchmark|receipts?/|scripts?/|\.sh\b|\.json\b|\.log\b|\.csv\b|\.txt\b|raw output|command output|\$\s|profil(?:e|ed|ing)|measured|reproduc)`)

// commentPrefixRe recognizes a same-line comment marker across the common
// languages this repo and its ecosystem actually contain source in (Go, C,
// Rust, JS/TS, Python, shell, SQL, Lisp, HTML/markdown comments).
var commentPrefixRe = regexp.MustCompile(`^\s*(//|#|/\*|\*|--|;;|<!--)`)

// docExt is the set of file extensions whose entire content is prose/docs,
// so every line (not just comment-prefixed ones) is in scope.
var docExt = map[string]bool{
	".md":       true,
	".markdown": true,
	".rst":      true,
	".txt":      true,
	".adoc":     true,
}

// yearRe recognizes a bare 4-digit year (1900-2099) so "...common in the
// 1990s" doesn't get misread as a "1990 seconds" duration claim by the bare
// "s" alternative in durationRe.
var yearRe = regexp.MustCompile(`^(19|20)\d{2}$`)

type detector struct{}

func (detector) ID() string { return patternID }

func (detector) Category() string { return category }

// Detect scans content line by line. A line is in scope if the whole file
// is doc-shaped (markdown/rst/txt/adoc) or the line itself starts with a
// recognized comment marker. An in-scope line that contains a specific
// duration or speedup number, with no reference token anywhere in the
// 7-line window centered on it (3 lines each side), produces one Match.
func (d detector) Detect(path string, content []byte) []llmcheat.Match {
	lines := splitLines(content)
	wholeFileIsDoc := docExt[strings.ToLower(filepath.Ext(path))]

	var matches []llmcheat.Match
	for i, line := range lines {
		if !wholeFileIsDoc && !commentPrefixRe.MatchString(line) {
			continue
		}
		token, ok := findPerfClaim(line)
		if !ok {
			continue
		}
		if hasNearbyReference(lines, i) {
			continue
		}
		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      uint(i + 1), //nolint:gosec // i is a bounded line index, never negative
			Message: "unverified performance claim \"" + token + "\" with no benchmark script, receipt " +
				"file, or raw command output referenced within 3 lines",
			Severity: llmcheat.SeverityMedium,
		})
	}
	return matches
}

// findPerfClaim reports whether line contains a specific-looking
// performance number, and if so returns the matched token for the Match
// message.
func findPerfClaim(line string) (token string, ok bool) {
	if m := durationRe.FindStringSubmatch(line); m != nil {
		unit := m[2]
		isDecade := strings.EqualFold(unit, "s") && yearRe.MatchString(m[1])
		// "1990s" / "2020s" reads as a decade, not a duration, when the
		// unit is the bare "s" alternative and the number is a 4-digit
		// year. Every other unit (ms, sec, minute, ...) cannot also read
		// as a plural-year suffix, so only the bare "s" case needs this
		// guard.
		if !isDecade {
			return m[0], true
		}
	}
	if multiplierRe.MatchString(line) && speedupWordRe.MatchString(line) {
		return multiplierRe.FindString(line) + " " + speedupWordRe.FindString(line), true
	}
	return "", false
}

// hasNearbyReference reports whether any line in the window
// [idx-3, idx+3] (clamped to the slice bounds) contains a reference to a
// benchmark script, receipt/results file, or raw command output.
func hasNearbyReference(lines []string, idx int) bool {
	start := idx - 3
	if start < 0 {
		start = 0
	}
	end := idx + 3
	if end > len(lines)-1 {
		end = len(lines) - 1
	}
	for j := start; j <= end; j++ {
		if referenceRe.MatchString(lines[j]) {
			return true
		}
	}
	return false
}

// splitLines splits content into lines without the trailing newline,
// tolerating both LF and CRLF line endings (bufio.Scanner's default
// ScanLines splitter strips a trailing \r), including a final line that has
// no trailing newline at all.
func splitLines(content []byte) []string {
	var lines []string
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

func init() {
	llmcheat.Register(detector{})
}
