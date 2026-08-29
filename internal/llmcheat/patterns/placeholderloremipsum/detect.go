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

// Package placeholderloremipsum implements the "placeholder-lorem-ipsum-in-code"
// llmcheat.Pattern: it flags "lorem ipsum" boilerplate and other generic
// keyboard-mash/copy-paste placeholder tokens ("foo bar baz", "xxx yyy zzz",
// repeated "asdf") when they appear inside a string literal or a comment in
// a non-fixture, non-test, non-mock source file. Such text is a strong
// signal that a description, docstring, or error message was never actually
// written for the real content it claims to describe.
package placeholderloremipsum

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "placeholder-lorem-ipsum-in-code"
	category  = "hollow-implementation"
)

// excludedPathSubstrings mark a file as a fixture, test, or mock file, out
// of scope for this pattern: placeholder/lorem-ipsum text is expected and
// legitimate there (it is often the deliberate point of the fixture).
var excludedPathSubstrings = []string{"/test", "/fixture", "/fixtures", "/mock"}

var (
	// stringLiteralRe matches a double-, single-, or backtick-quoted string
	// literal, honoring backslash escapes inside double/single quotes.
	stringLiteralRe = regexp.MustCompile(`"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|` + "`[^`]*`")

	loremIpsumRe    = regexp.MustCompile(`(?i)lorem\s+ipsum`)
	fooBarBazRe     = regexp.MustCompile(`(?i)\bfoo\b[\s,]+\bbar\b[\s,]+\bbaz\b`)
	xxxYyyZzzRe     = regexp.MustCompile(`(?i)\bxxx\b[\s,]+\byyy\b[\s,]+\bzzz\b`)
	asdfAdjacentRe  = regexp.MustCompile(`(?i)(?:asdf){2,}`)
	asdfSeparatedRe = regexp.MustCompile(`(?i)\basdf\b(?:[\s,]+asdf\b){1,}`)

	blockCommentOpen  = "/*"
	blockCommentClose = "*/"
	htmlCommentOpen   = "<!--"
	htmlCommentClose  = "-->"
)

// detector is the real, stateless implementation of llmcheat.Pattern for
// this pattern. It has no fields because Detect is a pure function of its
// arguments; it exists as a named type only so it can implement the
// interface and be registered.
type detector struct{}

func init() {
	llmcheat.Register(detector{})
}

func (detector) ID() string       { return patternID }
func (detector) Category() string { return category }

// Detect scans content line by line. For every line it extracts the text
// that lives inside string literals and inside line/block/HTML comments
// (never raw code — an identifier or keyword is never checked), then tests
// that extracted text against the placeholder-token patterns described in
// the package doc comment.
func (d detector) Detect(path string, content []byte) []llmcheat.Match {
	if isExcludedPath(path) {
		return nil
	}

	var matches []llmcheat.Match
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var lineNo uint
	inBlockComment := false
	inHTMLComment := false

	for scanner.Scan() {
		lineNo++
		line := scanner.Text()

		var texts []string

		switch {
		case inBlockComment:
			texts = append(texts, line)
			if strings.Contains(line, blockCommentClose) {
				inBlockComment = false
			}
		case inHTMLComment:
			texts = append(texts, line)
			if strings.Contains(line, htmlCommentClose) {
				inHTMLComment = false
			}
		default:
			texts = append(texts, extractStringAndCommentTexts(line)...)

			if idx := strings.Index(line, blockCommentOpen); idx >= 0 {
				rest := line[idx+len(blockCommentOpen):]
				if end := strings.Index(rest, blockCommentClose); end >= 0 {
					texts = append(texts, rest[:end])
				} else {
					texts = append(texts, rest)
					inBlockComment = true
				}
			}
			if idx := strings.Index(line, htmlCommentOpen); idx >= 0 {
				rest := line[idx+len(htmlCommentOpen):]
				if end := strings.Index(rest, htmlCommentClose); end >= 0 {
					texts = append(texts, rest[:end])
				} else {
					texts = append(texts, rest)
					inHTMLComment = true
				}
			}
		}

		matches = append(matches, checkTexts(path, lineNo, texts)...)
	}

	return matches
}

// isExcludedPath reports whether path names a fixture/test/mock file this
// pattern must not scan.
func isExcludedPath(path string) bool {
	lower := strings.ToLower(path)
	for _, s := range excludedPathSubstrings {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// extractStringAndCommentTexts pulls out every string-literal body on line,
// plus the body of a trailing "//"/"#" comment (found outside any string
// literal, so a URL like "http://example.com" inside a quoted string never
// gets misread as a comment marker) and a full-line "--"/";;"/"*"
// (doc-comment continuation) comment.
func extractStringAndCommentTexts(line string) []string {
	var texts []string

	spans := stringLiteralRe.FindAllStringIndex(line, -1)
	masked := []byte(line)
	for _, sp := range spans {
		lit := line[sp[0]:sp[1]]
		texts = append(texts, strings.Trim(lit, `"'`+"`"))
		for i := sp[0]; i < sp[1]; i++ {
			masked[i] = ' '
		}
	}
	maskedLine := string(masked)

	for _, p := range []string{"//", "#"} {
		if idx := strings.Index(maskedLine, p); idx >= 0 {
			texts = append(texts, line[idx+len(p):])
			break
		}
	}

	trimmed := strings.TrimSpace(line)
	for _, p := range []string{"--", ";;"} {
		if strings.HasPrefix(trimmed, p) {
			texts = append(texts, strings.TrimPrefix(trimmed, p))
			break
		}
	}
	if strings.HasPrefix(trimmed, "*") && !strings.HasPrefix(trimmed, "*/") {
		texts = append(texts, strings.TrimPrefix(trimmed, "*"))
	}

	return texts
}

// checkTexts runs every extracted text snippet from one line through
// checkOne and turns each distinct hit into a Match, deduplicated by reason
// so a line with the same placeholder phrase split across two string
// literals doesn't produce redundant matches.
func checkTexts(path string, lineNo uint, texts []string) []llmcheat.Match {
	var out []llmcheat.Match
	seen := map[string]bool{}
	for _, text := range texts {
		if strings.TrimSpace(text) == "" {
			continue
		}
		reason, ok := checkOne(text)
		if !ok || seen[reason] {
			continue
		}
		seen[reason] = true
		out = append(out, llmcheat.Match{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      lineNo,
			Message:   reason,
			Severity:  llmcheat.SeverityMedium,
		})
	}
	return out
}

// checkOne tests one extracted string-literal/comment body against every
// known placeholder shape, returning the first matching reason.
func checkOne(text string) (string, bool) {
	switch {
	case loremIpsumRe.MatchString(text):
		return `placeholder "lorem ipsum" boilerplate found in a string literal or comment`, true
	case fooBarBazRe.MatchString(text):
		return `generic placeholder tokens "foo bar baz" found in a string literal or comment`, true
	case xxxYyyZzzRe.MatchString(text):
		return `generic placeholder tokens "xxx yyy zzz" found in a string literal or comment`, true
	case asdfAdjacentRe.MatchString(text), asdfSeparatedRe.MatchString(text):
		return `repeated keyboard-mash placeholder "asdf" found in a string literal or comment`, true
	case hasGenericTripleRepeat(text):
		return "the same short placeholder-shaped token is repeated 3+ times in a string literal or comment", true
	}
	return "", false
}

// hasGenericTripleRepeat reports whether text contains the same
// case-insensitive token (2+ characters) repeated three or more times in a
// row, separated only by whitespace and/or commas — e.g. "asdf asdf asdf",
// "test test test", "xxx xxx xxx". This generalizes beyond the three named
// example phrases to the broader shape "a generic token was mashed/pasted
// repeatedly instead of real content being written".
func hasGenericTripleRepeat(text string) bool {
	fields := strings.FieldsFunc(text, func(r rune) bool {
		return r == ' ' || r == ',' || r == '\t'
	})

	run := 1
	for i := 1; i < len(fields); i++ {
		if len(fields[i]) >= 2 && strings.EqualFold(fields[i], fields[i-1]) {
			run++
			if run >= 3 {
				return true
			}
		} else {
			run = 1
		}
	}
	return false
}
