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

// Package lockfilechecksummismatch implements the
// "lockfile-checksum-mismatch" llmcheat.Pattern: it flags a lockfile-shaped
// document (TOML or JSON key = "value" / "key": "value" syntax; typically
// *.lock.toml, *.lock.json, Cargo.lock-, poetry.lock-, or package-lock.json
// -shaped content, though this scans by content rather than filename — see
// below) that records two DIFFERENT sha256 (64 hex chars) or sha1 (40 hex
// chars) values under the same checksum-shaped key name for what looks like
// the same named subject.
//
// "Same named subject" is approximated the same cheap, language-agnostic way
// selfcontradictingstatus approximates "same scope": rather than a real
// TOML/JSON parser, this package tracks the value of the most recently seen
// "name" key (`name = "..."` or `"name": "..."`) as the current subject, and
// groups every subsequent checksum-shaped key assignment by (key name,
// current subject) until the next "name" line updates the subject. This is
// exactly the shape a repeated [[package]] / object-array lockfile entry
// takes in practice, and is what the pattern's own dirty/clean examples
// exercise.
//
// This pattern is not gated on filepath.Ext: its own description defines
// applicability as "*.lock.toml, *.lock.json, OR containing
// checksum/digest/sha256 keys" -- a strict filename allowlist would exclude
// real lockfiles that don't use either literal suffix (Cargo.lock,
// poetry.lock, package-lock.json, requirements.txt --hash entries). Instead,
// applicability falls naturally out of the content match itself: a file with
// no checksum/digest/hash/sha-named hex assignment simply produces zero
// candidate entries and therefore zero matches, which is the correct answer
// for an irrelevant file too.
package lockfilechecksummismatch

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "lockfile-checksum-mismatch"
	category  = "generated-artifact-tampering"
)

// nameLineRe matches a "name" key assignment in either TOML (`name =
// "pkg"`) or JSON (`"name": "pkg"`) syntax, capturing the quoted value as
// the subject that following checksum-shaped keys get attributed to.
var nameLineRe = regexp.MustCompile(`(?i)^\s*"?name"?\s*[:=]\s*"([^"]*)"`)

// checksumLineRe matches a `key = "value"` / `"key": "value"` assignment
// whose value is EXACTLY a 40-hex-char (sha1) or 64-hex-char (sha256)
// string -- the closing quote must immediately follow the hex run, so a
// shorter, longer, or non-hex value never matches. Group 1 is the raw key
// name; group 2 is the hex value.
var checksumLineRe = regexp.MustCompile(`(?i)^\s*"?([A-Za-z0-9_.\-]+)"?\s*[:=]\s*"([0-9a-fA-F]{40}|[0-9a-fA-F]{64})"`)

// checksumKeyWords is what a key name must contain (case-insensitively) for
// its hex-shaped value to be treated as a checksum/digest field at all, per
// the pattern description.
var checksumKeyWords = []string{"checksum", "digest", "hash", "sha"}

// entry is one occurrence of a checksum-shaped key assignment.
type entry struct {
	hexRaw string // as written in the file (case preserved, for messages)
	line   uint
}

// group collects every entry seen for one (lowercased key name, subject)
// pair, in file order.
type group struct {
	key     string
	subject string
	entries []entry
}

// detector is the unexported implementation of llmcheat.Pattern for this
// package. It holds no state: Detect is a pure function of its arguments.
type detector struct{}

func (detector) ID() string { return patternID }

func (detector) Category() string { return category }

func init() {
	llmcheat.Register(detector{})
}

// Detect scans content line by line, tracking the current "subject" (the
// most recently seen name = "..." value) and collecting every
// checksum/digest/hash/sha-named hex assignment into groups keyed by (key
// name, subject). For each group with two or more entries, every entry
// after the first whose hex value differs from the first entry's hex value
// is reported as a Match -- the same key name, for the same named subject,
// disagreeing on the checksum it asserts is an internally self-contradictory
// lockfile, independent of what the "true" value should have been.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	if len(content) == 0 {
		return nil
	}
	if bytes.IndexByte(content, 0) != -1 {
		// Binary content (a null byte present) -- nothing meaningful to
		// scan as line-oriented key/value text.
		return nil
	}

	groups, order := collectGroups(content)

	var matches []llmcheat.Match
	for _, gk := range order {
		g := groups[gk]
		if len(g.entries) < 2 {
			continue
		}
		baseline := g.entries[0]
		for _, e := range g.entries[1:] {
			if strings.EqualFold(e.hexRaw, baseline.hexRaw) {
				continue // identical value repeated verbatim -- not a contradiction
			}
			matches = append(matches, llmcheat.Match{
				PatternID: patternID,
				Category:  category,
				Path:      path,
				Line:      e.line,
				Message:   mismatchMessage(g.key, g.subject, baseline, e),
				Severity:  llmcheat.SeverityHigh,
			})
		}
	}

	return matches
}

// collectGroups scans content line by line and returns every (key,
// subject) group with two or more checksum-shaped entries, plus the group
// keys in first-seen order (so Detect's output is deterministic and does
// not depend on Go's randomized map iteration order).
func collectGroups(content []byte) (map[string]*group, []string) {
	groups := map[string]*group{}
	var order []string

	var subject string

	scanner := bufio.NewScanner(bytes.NewReader(content))
	// Allow long lines (e.g. minified/generated content) without the
	// scanner erroring out, while still bounding memory use per line.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var lineNo uint
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()

		if m := nameLineRe.FindStringSubmatch(line); m != nil {
			subject = m[1]
			continue
		}

		m := checksumLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key := m[1]
		if !isChecksumKey(key) {
			continue
		}

		gk := strings.ToLower(key) + "\x00" + subject
		g, ok := groups[gk]
		if !ok {
			g = &group{key: strings.ToLower(key), subject: subject}
			groups[gk] = g
			order = append(order, gk)
		}
		g.entries = append(g.entries, entry{hexRaw: m[2], line: lineNo})
	}

	return groups, order
}

// isChecksumKey reports whether key contains (case-insensitively) any of
// checksumKeyWords.
func isChecksumKey(key string) bool {
	lower := strings.ToLower(key)
	for _, w := range checksumKeyWords {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

// mismatchMessage builds a human-readable explanation naming both
// conflicting values and their line numbers.
func mismatchMessage(key, subject string, baseline, mismatch entry) string {
	subjDesc := subject
	if subjDesc == "" {
		subjDesc = "(no preceding name = line)"
	} else {
		subjDesc = fmt.Sprintf("%q", subjDesc)
	}
	return fmt.Sprintf(
		"key %q for subject %s has conflicting values: %q on line %d vs %q on line %d",
		key, subjDesc, baseline.hexRaw, baseline.line, mismatch.hexRaw, mismatch.line,
	)
}
