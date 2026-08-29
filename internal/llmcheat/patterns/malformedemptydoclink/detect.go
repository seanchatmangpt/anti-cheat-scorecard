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

// Package malformedemptydoclink implements the
// "malformed-or-empty-doc-link" llmcheat.Pattern: it flags inline Markdown
// links (`[text](target)`, including image links `![text](target)`) whose
// target is a citation-shaped reference pointing nowhere real — an empty
// target `()`, a bare in-page fragment `(#)` with no real anchor name, or a
// well-known placeholder token ("TODO", "TBD", "link", "FIXME", "xxx") left
// behind instead of a real path or URL.
//
// This only scans .md files: the malformed-link shape only means something
// against Markdown's own link grammar, and running the same regex over
// arbitrary source would misfire on unrelated `[...](...)` -shaped text
// (e.g. Rust attribute-like syntax or math notation) that isn't a Markdown
// link at all.
//
// A real link title (`[text](url "title")`) and an angle-bracketed URL
// (`[text](<url>)`) are both normalized away before classification, so a
// legitimately-titled or space-escaped real link is never misclassified as
// empty. A non-empty in-page anchor (`(#some-real-heading)`) is left alone —
// only a bare, nameless `#` is flagged.
package malformedemptydoclink

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
	patternID       = "malformed-or-empty-doc-link"
	patternCategory = "determinism-and-provenance-violation"
)

// linkRe matches an inline Markdown link (optionally an image link, via the
// optional leading "!"): `[link text](target)`. The target group is
// non-greedy up to the first ")" — real Markdown link targets containing an
// unescaped ")" are rare enough that this pragmatic simplification (shared
// with this package's sibling detectors) is an acceptable trade-off for a
// pure, single-pass, line-addressable scan.
var linkRe = regexp.MustCompile(`!?\[([^\]]*)\]\(([^)]*)\)`)

// placeholderTokens is the curated set of citation-shaped-but-empty target
// tokens named in this pattern's assignment, compared case-insensitively
// after trailing punctuation is trimmed (so "TODO." and "TODO:" both match
// "TODO", but "TODO.md" — a real, if oddly named, filename — does not).
var placeholderTokens = map[string]bool{
	"TODO":  true,
	"TBD":   true,
	"LINK":  true,
	"FIXME": true,
	"XXX":   true,
}

// detector is the real, stateless malformed-or-empty-doc-link Pattern
// implementation. It holds no fields because Detect is a pure function of
// its (path, content) arguments — a zero value is the whole of it, which is
// exactly what init() registers below.
type detector struct{}

func (detector) ID() string { return patternID }

func (detector) Category() string { return patternCategory }

// Detect scans a Markdown (.md) file line by line for inline links whose
// target is empty, a bare "#" fragment, or a known placeholder token. Files
// whose extension is not ".md" are never scanned (the Markdown link grammar
// this pattern keys off of doesn't apply to them).
func (d detector) Detect(path string, content []byte) []llmcheat.Match {
	if !strings.EqualFold(filepath.Ext(path), ".md") {
		return nil
	}

	var matches []llmcheat.Match

	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var lineNum uint
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, sub := range linkRe.FindAllStringSubmatch(line, -1) {
			linkText := sub[1]
			rawTarget := sub[2]

			reason, bad := classifyTarget(normalizeTarget(rawTarget))
			if !bad {
				continue
			}

			matches = append(matches, llmcheat.Match{
				PatternID: patternID,
				Category:  patternCategory,
				Path:      path,
				Line:      lineNum,
				Message: fmt.Sprintf(
					"markdown link [%s](%s) %s — a citation-shaped reference pointing nowhere real",
					linkText, rawTarget, reason,
				),
				Severity: llmcheat.SeverityMedium,
			})
		}
	}

	return matches
}

// normalizeTarget strips the surface variation that a real link target can
// legitimately carry — surrounding whitespace, an angle-bracket escape
// (`<url with spaces>`), and a trailing quoted or parenthesized title
// (`url "title"`) — down to the bare target string classifyTarget judges.
func normalizeTarget(raw string) string {
	t := strings.TrimSpace(raw)
	if strings.HasPrefix(t, "<") {
		t = strings.TrimPrefix(t, "<")
		if idx := strings.IndexByte(t, '>'); idx != -1 {
			t = t[:idx]
		}
	}
	t = stripTitle(t)
	return strings.TrimSpace(t)
}

// stripTitle removes an optional trailing link title from a target, e.g.
// `docs/DESIGN.md "the design doc"` -> `docs/DESIGN.md`, `TODO 'fill in'` ->
// `TODO`. It looks for the first run of whitespace immediately followed by
// a quote or an opening paren, which is where Markdown's title syntax
// begins; a target with no such marker is returned unchanged.
func stripTitle(raw string) string {
	for i := 0; i < len(raw); i++ {
		if raw[i] != ' ' && raw[i] != '\t' {
			continue
		}
		rest := strings.TrimLeft(raw[i:], " \t")
		if len(rest) > 0 && (rest[0] == '"' || rest[0] == '\'' || rest[0] == '(') {
			return raw[:i]
		}
	}
	return raw
}

// classifyTarget reports whether a normalized link target is malformed or
// empty in the specific, curated sense this pattern detects, and if so, a
// human-readable reason describing why.
func classifyTarget(target string) (reason string, bad bool) {
	if target == "" {
		return "has an empty target", true
	}
	if target == "#" {
		return `targets a bare "#" fragment with no real anchor name`, true
	}

	trimmedPunct := strings.Trim(target, ".,:;!?")
	if placeholderTokens[strings.ToUpper(trimmedPunct)] {
		return fmt.Sprintf("targets the placeholder token %q instead of a real path or URL", trimmedPunct), true
	}

	return "", false
}

func init() {
	llmcheat.Register(detector{})
}
