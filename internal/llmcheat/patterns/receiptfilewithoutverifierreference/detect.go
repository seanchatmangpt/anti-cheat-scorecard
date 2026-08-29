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

// Package receiptfilewithoutverifierreference implements the
// "receipt-file-without-verifier-reference" llmcheat.Pattern: it flags JSON
// files living under a "receipts/" directory that declare no key by which
// their own claims could be checked.
//
// A "receipt" is only evidence if something can actually replay or verify
// it. A JSON blob under receipts/ that asserts a status ("ALIVE", "commit":
// "abc123", ...) but names no schema, no verifier script/command, and no
// verification record is not falsifiable — it is a status claim wearing a
// receipt's file extension. This pattern flags any receipts/*.json file
// whose top-level JSON object has none of the recognized verifier-reference
// keys: "schema", "verifier", "verified_by", "verification",
// "receipt_schema", "$schema". A file that fails to parse as a JSON object
// at all is flagged too, for the same underlying reason: it cannot be
// mechanically re-verified either.
package receiptfilewithoutverifierreference

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "receipt-file-without-verifier-reference"
	category  = "generated-artifact-tampering"
)

// verifierKeys are the top-level JSON keys that count as a declared way to
// check a receipt's own claims. Presence of any one of these is enough to
// clear the pattern; the exact verification mechanism they point to is not
// evaluated here (that is the concern of whatever verifier they name).
var verifierKeys = []string{
	"schema",
	"verifier",
	"verified_by",
	"verification",
	"receipt_schema",
	"$schema",
}

// detector is the unexported implementation of llmcheat.Pattern for this
// pattern. It holds no state: Detect is a pure function of its arguments.
type detector struct{}

func (detector) ID() string { return patternID }

func (detector) Category() string { return category }

func init() {
	llmcheat.Register(detector{})
}

// Detect reports at most one Match per file: either a "failed to parse as a
// JSON object" finding, or (if it did parse as an object) a "no verifier
// key" finding. It only runs on files whose path names a receipts/*.json
// file; every other path is left alone (zero matches, not an error).
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	if !isReceiptJSONPath(path) {
		return nil
	}

	// Best-effort parse: unmarshal into a map of raw top-level values. This
	// fails both for genuinely malformed JSON (a syntax error) and for
	// syntactically valid JSON whose top-level value isn't an object (an
	// array, string, number, bool, or null) — in both cases the file has no
	// top-level keys to check, so it is reported as a malformed receipt.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(content, &top); err != nil {
		return []llmcheat.Match{{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      lineForParseError(content, err),
			Message: fmt.Sprintf(
				"receipt file %q does not parse as a JSON object (%v) — a receipt that cannot be mechanically re-parsed cannot be verified",
				path, err,
			),
			Severity: llmcheat.SeverityHigh,
		}}
	}

	if hasVerifierKey(top) {
		return nil
	}

	return []llmcheat.Match{{
		PatternID: patternID,
		Category:  category,
		Path:      path,
		Line:      firstContentLine(content),
		Message: fmt.Sprintf(
			"receipt file %q declares no verifier-reference key (looked for one of: %s) — a receipt with no declared way to check it is not falsifiable",
			path, strings.Join(verifierKeys, ", "),
		),
		Severity: llmcheat.SeverityMedium,
	}}
}

// hasVerifierKey reports whether top contains any of the recognized
// verifier-reference keys, exact-case (JSON object keys are case-sensitive;
// the recognized keys are the conventional lower_snake_case / JSON-Schema
// "$schema" spellings, not arbitrary case variants).
func hasVerifierKey(top map[string]json.RawMessage) bool {
	for _, k := range verifierKeys {
		if _, ok := top[k]; ok {
			return true
		}
	}
	return false
}

// isReceiptJSONPath reports whether path names a JSON file inside a
// "receipts" directory anywhere in the path, e.g. "receipts/foo.json",
// "docs/receipts/foo.json", or "a/b/receipts/c/foo.json". The path is
// normalized to forward slashes (Windows-safe) and given a leading slash
// before the substring check so a path segment match at the very start of
// the path (no parent directory) is found the same way a nested one is.
func isReceiptJSONPath(path string) bool {
	if strings.ToLower(filepath.Ext(path)) != ".json" {
		return false
	}
	normalized := "/" + strings.TrimPrefix(filepath.ToSlash(path), "/")
	return strings.Contains(normalized, "/receipts/")
}

// firstContentLine returns the 1-based line number of the first
// non-whitespace byte in content, which for a well-formed JSON object is
// the line the opening "{" is on. Defaults to line 1 for empty or
// all-whitespace content.
func firstContentLine(content []byte) uint {
	line := uint(1)
	for _, b := range content {
		switch b {
		case '\n':
			line++
			continue
		case ' ', '\t', '\r':
			continue
		default:
			return line
		}
	}
	return line
}

// lineForParseError returns the 1-based line number a JSON parse error
// occurred on, using the byte offset carried by *json.SyntaxError or
// *json.UnmarshalTypeError (both of Go's encoding/json error types for this
// call site). Falls back to line 1 when the error carries no offset (e.g.
// io.ErrUnexpectedEOF surfaces with no offset field).
func lineForParseError(content []byte, err error) uint {
	var offset int64 = -1
	switch e := err.(type) {
	case *json.SyntaxError:
		offset = e.Offset
	case *json.UnmarshalTypeError:
		offset = e.Offset
	}
	if offset < 0 {
		return 1
	}
	if offset > int64(len(content)) {
		offset = int64(len(content))
	}
	return lineForOffset(content, offset)
}

// lineForOffset converts a 0-based byte offset into content into a 1-based
// line number by counting newlines strictly before that offset.
func lineForOffset(content []byte, offset int64) uint {
	line := uint(1)
	for i := int64(0); i < offset && i < int64(len(content)); i++ {
		if content[i] == '\n' {
			line++
		}
	}
	return line
}
