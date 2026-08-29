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

// Package teraundefinedtemplatevariable implements the
// "tera-undefined-template-variable" llmcheat.Pattern: it scans .tera
// template files for `{{ varname }}` / `{{ varname.field }}` expressions
// that reference a variable nothing in the visible file ever defines. A
// generated Tera template that silently references a variable no caller
// was ever wired to pass (and that isn't one of Tera's own builtins or this
// project's conventional SPARQL-result context variables) is a strong
// signal the template was produced without actually exercising the
// rendering pipeline end to end — the classic "looks plausible, was never
// run" shape this tool exists to catch.
package teraundefinedtemplatevariable

import (
	"bufio"
	"bytes"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID = "tera-undefined-template-variable"
	category  = "generated-artifact-tampering"
)

// allowedVarNames are names a .tera template may reference in a {{ }}
// expression without a corresponding {% set name = %} anywhere in the same
// file: Tera's own implicit loop context and template-inheritance builtins
// (loop, self, super), Tera's built-in global functions/objects (config,
// now, range, throw), the two boolean literals, and this project's own
// conventional SPARQL-result rendering context variables (sparql_results,
// row, rows — injected by the ggen/SPARQL rendering pipeline these
// templates are rendered under, never locally `{% set %}` in the template
// itself).
var allowedVarNames = map[string]bool{
	"loop":           true,
	"self":           true,
	"super":          true,
	"config":         true,
	"now":            true,
	"range":          true,
	"throw":          true,
	"sparql_results": true,
	"row":            true,
	"rows":           true,
	"true":           true,
	"false":          true,
}

var (
	// setRe matches a `{% set varname = ` tag (with or without the `{%-`
	// whitespace-trim variant) and captures varname. It deliberately does
	// not require a matching `%}` on the same line — the RHS expression is
	// irrelevant, only that varname was defined somewhere in the file.
	setRe = regexp.MustCompile(`\{%-?\s*set\s+([A-Za-z_][A-Za-z0-9_]*)\s*=`)

	// varRe matches the two token shapes named in this pattern's
	// description: a bare `{{ varname` and a dotted `{{ varname.field`
	// reference. Capturing just the leading identifier after `{{` handles
	// both — `field`, any filter (`| foo`), any index (`[0]`), or any call
	// syntax (`(...)`) that follows is irrelevant; only the root variable
	// name is what needs a definition.
	varRe = regexp.MustCompile(`\{\{-?\s*([A-Za-z_][A-Za-z0-9_]*)`)
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

// Detect scans .tera files only. It first collects every variable name
// defined anywhere in the file via `{% set varname = %}` (a whole-file
// pass, since Tera has no block-scoping this pattern needs to model — a
// `{% set %}` earlier or later in the file still counts as a definition),
// then scans line by line for `{{ varname` / `{{ varname.field` references
// and flags any whose root name is neither defined nor in the builtin
// allowlist.
func (d detector) Detect(path string, content []byte) []llmcheat.Match {
	if !strings.EqualFold(filepath.Ext(path), ".tera") {
		return nil
	}

	defined := collectSetVariables(content)

	var matches []llmcheat.Match
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var lineNo uint
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()

		// Dedup within a line: the same undefined variable referenced
		// twice on one line (e.g. "{{ x }} and {{ x }}") should produce one
		// match for that line, not two identical ones.
		reportedOnLine := map[string]bool{}

		for _, m := range varRe.FindAllStringSubmatch(line, -1) {
			name := m[1]
			if defined[name] || allowedVarNames[name] || reportedOnLine[name] {
				continue
			}
			reportedOnLine[name] = true

			matches = append(matches, llmcheat.Match{
				PatternID: patternID,
				Category:  category,
				Path:      path,
				Line:      lineNo,
				Message: `template variable "` + name + `" is referenced in a {{ }} expression but has no ` +
					`corresponding {% set ` + name + ` = %} anywhere in this file and is not a known Tera ` +
					`builtin or conventional context variable`,
				Severity: llmcheat.SeverityMedium,
			})
		}
	}

	return matches
}

// collectSetVariables returns the set of variable names defined anywhere in
// content via a `{% set varname = %}` tag.
func collectSetVariables(content []byte) map[string]bool {
	defined := map[string]bool{}
	for _, m := range setRe.FindAllSubmatch(content, -1) {
		defined[string(m[1])] = true
	}
	return defined
}
