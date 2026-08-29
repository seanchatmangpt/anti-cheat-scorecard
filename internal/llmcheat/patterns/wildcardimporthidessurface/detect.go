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

// Package wildcardimporthidessurface implements the
// "wildcard-import-hides-surface" llmcheat.Pattern: it flags any import
// statement that pulls an entire module's/package's exported surface into
// a file's namespace without naming the individual symbols used —
//
//   - Python: `from <module> import *`
//   - Rust:   `use <path>::*;` (also `pub use ...::*;`)
//   - Go:     a dot-import, `import . "pkg"`, whether written as a single
//     statement or as a `. "pkg"` line inside a parenthesized import block
//
// Each of these makes it impossible to tell, by reading the file alone,
// which names it actually uses versus which arrived along for the ride —
// exactly the ambiguity an LLM (or a human under deadline pressure) can
// exploit to leave dead/unused surface undetected, since nothing in the
// import statement itself names what's really needed.
//
// Two Rust spellings are excluded as idiomatic, not flagged: `use
// super::*;` (the standard way to bring a parent module's items into a
// child module/tests module) and any `...::prelude::*;` import (the
// standard way to consume a crate's own curated prelude, e.g.
// `std::prelude::*` or a project's own `crate::prelude::*`). Both
// re-export a small, deliberately-curated surface by convention, which is
// a materially different risk profile from an arbitrary module glob.
// Python and Go have no such carve-out in this detector: neither language
// has an equivalently idiomatic "prelude" convention for the constructs
// this pattern targets.
//
// This is a line-oriented heuristic scanner, not a full parser for any of
// the three languages (no tokenizer, no AST) — it is accurate for
// realistically-formatted source while remaining a small, dependency-free,
// pure function as required by the llmcheat contract. A full-line comment
// (`#` in Python, `//` in Rust/Go) is skipped so that a mention of the
// pattern in prose (e.g. explaining why it is deliberately NOT used) is
// not itself flagged.
package wildcardimporthidessurface

import (
	"bufio"
	"bytes"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "wildcard-import-hides-surface"
	category  = "complexity-and-surface-obfuscation"
)

// pythonWildcardImportRe matches `from <module> import *`, optionally
// followed by a trailing `#`-comment. <module> may be a dotted absolute
// path (`a.b.c`) or a relative one (`.`, `.utils`, `..pkg`).
var pythonWildcardImportRe = regexp.MustCompile(`^\s*from\s+([\w.]+)\s+import\s+\*\s*(?:#.*)?$`)

// rustWildcardUseRe matches `use <path>::*;`, optionally prefixed by `pub`
// or `pub(...)` visibility. <path> is captured so its final `::`-segment
// can be checked against the super/prelude exclusion.
var rustWildcardUseRe = regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?use\s+([\w:]+)::\*\s*;`)

// goImportBlockStartRe / goImportBlockEndRe delimit a parenthesized Go
// `import ( ... )` block so block-form dot-imports can be told apart from
// an unrelated line that merely starts with a dot elsewhere in the file.
var goImportBlockStartRe = regexp.MustCompile(`^\s*import\s*\(\s*$`)
var goImportBlockEndRe = regexp.MustCompile(`^\s*\)\s*$`)

// goDotImportSingleRe matches a single-statement Go dot-import:
// `import . "pkg"`.
var goDotImportSingleRe = regexp.MustCompile(`^\s*import\s+\.\s+"([^"]+)"\s*$`)

// goDotImportBlockLineRe matches a dot-import line inside a parenthesized
// import block: `. "pkg"`.
var goDotImportBlockLineRe = regexp.MustCompile(`^\s*\.\s+"([^"]+)"\s*$`)

// detector is the unexported Pattern implementation. It carries no state:
// Detect is a pure function of (path, content).
type detector struct{}

func (detector) ID() string       { return patternID }
func (detector) Category() string { return category }

// Detect dispatches on the file's extension (.py, .rs, .go) and reports
// every wildcard/dot import found, each with its real 1-based line number.
// Any other file extension yields zero matches: this pattern's three
// target constructs are all language-specific syntax, so there is no
// meaningful "any text content" mode to fall back to.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".py":
		return detectPython(path, content)
	case ".rs":
		return detectRust(path, content)
	case ".go":
		return detectGo(path, content)
	default:
		return nil
	}
}

func detectPython(path string, content []byte) []llmcheat.Match {
	var matches []llmcheat.Match

	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var lineNum uint
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		m := pythonWildcardImportRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		module := m[1]
		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      lineNum,
			Message: "`from " + module + " import *` hides exactly which names this file uses from " +
				module + ", making it impossible to tell real usage from dead/unused surface",
			Severity: llmcheat.SeverityMedium,
		})
	}
	return matches
}

func detectRust(path string, content []byte) []llmcheat.Match {
	var matches []llmcheat.Match

	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var lineNum uint
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}

		m := rustWildcardUseRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		modPath := m[1]
		segments := strings.Split(modPath, "::")
		last := segments[len(segments)-1]
		if last == "super" || last == "prelude" {
			// Idiomatic: `use super::*;` and any `...::prelude::*;` are the
			// standard Rust way to bring a parent module's, or a crate's
			// own curated prelude's, items into scope — excluded per spec.
			continue
		}
		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      lineNum,
			Message: "`use " + modPath + "::*;` glob-imports an entire module's surface, hiding which " +
				"specific items this file actually uses",
			Severity: llmcheat.SeverityMedium,
		})
	}
	return matches
}

func detectGo(path string, content []byte) []llmcheat.Match {
	var matches []llmcheat.Match

	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var lineNum uint
	inImportBlock := false
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}

		if !inImportBlock && goImportBlockStartRe.MatchString(line) {
			inImportBlock = true
			continue
		}
		if inImportBlock {
			if goImportBlockEndRe.MatchString(line) {
				inImportBlock = false
				continue
			}
			if m := goDotImportBlockLineRe.FindStringSubmatch(line); m != nil {
				matches = append(matches, goDotImportMatch(path, lineNum, m[1]))
			}
			continue
		}

		if m := goDotImportSingleRe.FindStringSubmatch(line); m != nil {
			matches = append(matches, goDotImportMatch(path, lineNum, m[1]))
		}
	}
	return matches
}

func goDotImportMatch(path string, lineNum uint, pkg string) llmcheat.Match {
	return llmcheat.Match{
		PatternID: patternID,
		Category:  category,
		Path:      path,
		Line:      lineNum,
		Message: `import . "` + pkg + `"` + " dot-imports " + pkg + "'s entire exported surface into this " +
			"file's unqualified namespace, hiding which names are actually used",
		Severity: llmcheat.SeverityMedium,
	}
}

func init() {
	llmcheat.Register(detector{})
}
