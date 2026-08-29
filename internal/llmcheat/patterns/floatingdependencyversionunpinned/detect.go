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

// Package floatingdependencyversionunpinned implements the
// "floating-dependency-version-unpinned" llmcheat.Pattern: it flags a
// manifest-declared dependency version specifier that is a FLOATING range
// rather than an exact pin, in each of five dependency-manifest shapes:
//
//   - package.json / yarn-shaped: npm caret ("^1.2.3"), tilde ("~1.2.3"),
//     wildcard ("*"), an unbounded ">=" range, an "x"/"*" version-segment
//     wildcard ("1.2.x"), or the "latest" dist-tag, inside a
//     dependencies/devDependencies/peerDependencies/optionalDependencies/
//     bundledDependencies object.
//   - Cargo.toml: a dependency version string (bare "1.2.3", or the
//     "version" field of an inline table) that does not start with the
//     explicit exact-pin operator "=" -- Cargo treats every other bare or
//     operator-prefixed version requirement (including a plain "1.2.3") as
//     a floating compatible-update range by default.
//   - requirements.txt (and *requirements*.txt variants): a PEP 508
//     requirement using ">=" with no upper bound ("<"/"<=") and no exact
//     "==" pin, or the "~=" compatible-release operator.
//   - pyproject.toml: the same PEP 508 floating-range check as
//     requirements.txt, applied to each quoted string inside a
//     `dependencies = [...]` array under [project], or inside any
//     `<group> = [...]` array under a [project.optional-dependencies]-named
//     table.
//   - go.mod-shaped require lines: a require entry whose version field is
//     the literal "latest" pseudo-version, which floats to whatever is
//     newest at resolution time instead of naming a pinned module version.
//
// This matters even when a lockfile (package-lock.json, Cargo.lock,
// poetry.lock, go.sum) exists elsewhere in the repository, because the
// MANIFEST is the source of truth for a fresh dependency resolve (a clean
// `npm install` without --frozen-lockfile, a `cargo update`, a `pip install
// -r requirements.txt`, a `poetry lock --no-update` re-run, or `go get -u`);
// a floating manifest specifier makes that fresh resolve non-deterministic
// even though the currently-committed lockfile happens to be pinned, which
// breaks byte-for-byte build reproducibility.
//
// Each of the five shapes is dispatched purely by filename (see Detect), so
// this package never needs a real JSON/TOML parser: it scans line-by-line
// with regular expressions, tracking just enough block/section state (a
// dependencies-object brace, a Cargo/pyproject TOML section header, a
// pyproject array's open/close, a go.mod require( ) block) to know which
// lines are dependency-version-shaped at all. That is deliberately the same
// cheap, dependency-free approach the sibling lockfilechecksummismatch and
// selfcontradictingstatus patterns use.
package floatingdependencyversionunpinned

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
	patternID = "floating-dependency-version-unpinned"
	category  = "determinism-and-provenance-violation"
)

// ---- package.json ----------------------------------------------------

// depsSectionHeaderRe matches the opening line of a dependency-map object
// in a (pretty-printed, one-key-per-line) package.json, e.g.
// `"dependencies": {`.
var depsSectionHeaderRe = regexp.MustCompile(
	`^"(?:dependencies|devDependencies|peerDependencies|optionalDependencies|bundledDependencies|bundleDependencies)"\s*:\s*\{\s*$`)

// jsonStringKVRe matches one `"key": "value"` line inside such an object.
var jsonStringKVRe = regexp.MustCompile(`^"([^"]+)"\s*:\s*"([^"]*)"\s*,?\s*$`)

// npmWildcardSegmentRe matches a version whose trailing segment is an "x"
// or "*" wildcard, e.g. "1.2.x" or "1.x".
var npmWildcardSegmentRe = regexp.MustCompile(`(?i)^[0-9]+(\.[0-9]+)*\.(x|\*)$`)

// classifyNPMVersion reports whether an npm/yarn version specifier floats,
// and a short human-readable reason if so.
func classifyNPMVersion(v string) (floating bool, reason string) {
	switch {
	case v == "":
		return false, ""
	case v == "*":
		return true, `wildcard "*" resolves to whatever is newest at install time`
	case v == "latest":
		return true, `dist-tag "latest" resolves to whatever is newest at install time`
	case strings.HasPrefix(v, "^"):
		return true, `caret range allows any semver-compatible minor/patch upgrade`
	case strings.HasPrefix(v, "~"):
		return true, `tilde range allows any semver-compatible patch upgrade`
	case strings.HasPrefix(v, ">=") && !strings.Contains(v, "<"):
		return true, `unbounded ">=" range has no upper bound`
	case npmWildcardSegmentRe.MatchString(v):
		return true, `"x"/"*" version-segment wildcard`
	default:
		return false, ""
	}
}

func detectPackageJSON(path string, content []byte) []llmcheat.Match {
	var matches []llmcheat.Match
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var lineNum uint
	inDeps := false
	for scanner.Scan() {
		lineNum++
		trimmed := strings.TrimSpace(scanner.Text())

		if !inDeps {
			if depsSectionHeaderRe.MatchString(trimmed) {
				inDeps = true
			}
			continue
		}
		if trimmed == "}" || trimmed == "}," {
			inDeps = false
			continue
		}

		m := jsonStringKVRe.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		name, version := m[1], m[2]
		floating, reason := classifyNPMVersion(version)
		if !floating {
			continue
		}
		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      lineNum,
			Message: fmt.Sprintf(
				"dependency %q uses floating version specifier %q (%s); pin an exact version instead",
				name, version, reason),
			Severity: llmcheat.SeverityMedium,
		})
	}
	return matches
}

// ---- Cargo.toml --------------------------------------------------------

// tomlSectionHeaderRe matches a bracketed TOML section/table header line,
// e.g. `[dependencies]`, `[dev-dependencies]`, `[project]`,
// `[project.optional-dependencies]`.
var tomlSectionHeaderRe = regexp.MustCompile(`^\[([^\]]+)\]$`)

// cargoBareVersionRe matches `name = "version"`.
var cargoBareVersionRe = regexp.MustCompile(`^([A-Za-z0-9_\-]+)\s*=\s*"([^"]*)"\s*$`)

// cargoInlineTableVersionRe matches `name = { version = "version", ... }`
// (in either field order, since `[^}]*` is greedy-safe here: the version
// field is the only quoted "version = ..." assignment expected per line).
var cargoInlineTableVersionRe = regexp.MustCompile(
	`^([A-Za-z0-9_\-]+)\s*=\s*\{[^}]*\bversion\s*=\s*"([^"]*)"[^}]*\}`)

// classifyCargoVersion reports whether a Cargo dependency version
// requirement floats. Cargo's own default semantics make this simple: a
// version requirement is an exact pin only when it uses the explicit "="
// operator; every other form (a bare "1.2.3", or any of "^"/"~"/"*"/">="/
// "<" ranges) resolves to a compatible-update range that `cargo update` (a
// fresh resolve without Cargo.lock) is free to move within.
func classifyCargoVersion(v string) (floating bool, reason string) {
	switch {
	case v == "":
		return false, ""
	case strings.HasPrefix(v, "="):
		return false, ""
	case strings.HasPrefix(v, "^"):
		return true, `explicit caret range allows any semver-compatible minor/patch upgrade`
	case strings.HasPrefix(v, "~"):
		return true, `explicit tilde range allows any semver-compatible patch upgrade`
	case strings.HasPrefix(v, "*") || strings.Contains(v, "*"):
		return true, `wildcard requirement matches any version in that position`
	case strings.HasPrefix(v, ">=") || strings.HasPrefix(v, ">") ||
		strings.HasPrefix(v, "<=") || strings.HasPrefix(v, "<"):
		return true, `comparison range has no exact "=" pin`
	default:
		return true, `bare version requirement has no exact "=" pin, so Cargo treats it as a floating compatible-update (caret) range by default`
	}
}

func detectCargoToml(path string, content []byte) []llmcheat.Match {
	var matches []llmcheat.Match
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var lineNum uint
	inDeps := false
	for scanner.Scan() {
		lineNum++
		trimmed := strings.TrimSpace(scanner.Text())

		if hm := tomlSectionHeaderRe.FindStringSubmatch(trimmed); hm != nil {
			inDeps = strings.Contains(strings.ToLower(hm[1]), "dependencies")
			continue
		}
		if !inDeps {
			continue
		}

		var name, version string
		if m := cargoInlineTableVersionRe.FindStringSubmatch(trimmed); m != nil {
			name, version = m[1], m[2]
		} else if m := cargoBareVersionRe.FindStringSubmatch(trimmed); m != nil {
			name, version = m[1], m[2]
		} else {
			continue
		}

		floating, reason := classifyCargoVersion(version)
		if !floating {
			continue
		}
		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      lineNum,
			Message: fmt.Sprintf(
				"dependency %q uses floating version requirement %q (%s); pin with an exact \"=\" version instead",
				name, version, reason),
			Severity: llmcheat.SeverityMedium,
		})
	}
	return matches
}

// ---- requirements.txt / pyproject.toml (shared PEP 508 classifier) -----

// pySpecNameRe extracts the leading requirement/package name (with an
// optional "[extra]" marker) from a PEP 508 requirement spec string, e.g.
// "requests[security]>=2.0.0".
var pySpecNameRe = regexp.MustCompile(
	`^([A-Za-z0-9][A-Za-z0-9_.\-]*(?:\[[A-Za-z0-9,_\-]+\])?)\s*(==|>=|<=|~=|!=|>|<)`)

// classifyPythonSpec reports whether a PEP 508 requirement spec string
// (e.g. "flask==2.1.3", "requests>=2.0.0", "numpy~=1.21") names a
// recognizable package with a floating version range, along with the
// package name and a reason. name == "" means the line/string was not a
// recognizable versioned requirement spec at all (no name/operator match).
func classifyPythonSpec(spec string) (name string, floating bool, reason string) {
	m := pySpecNameRe.FindStringSubmatch(spec)
	if m == nil {
		return "", false, ""
	}
	name = m[1]

	hasExact := strings.Contains(spec, "==")
	hasUpperBound := strings.Contains(spec, "<")
	hasCompatible := strings.Contains(spec, "~=")
	hasLowerUnbounded := strings.Contains(spec, ">=")

	switch {
	case hasExact:
		return name, false, ""
	case hasCompatible:
		return name, true, `compatible-release operator "~=" allows any matching minor/patch upgrade`
	case hasLowerUnbounded && !hasUpperBound:
		return name, true, `unbounded ">=" lower bound has no upper bound and no exact "==" pin`
	default:
		return name, false, ""
	}
}

func pythonSpecMatch(path string, lineNum uint, rawSpec string) (llmcheat.Match, bool) {
	name, floating, reason := classifyPythonSpec(rawSpec)
	if name == "" || !floating {
		return llmcheat.Match{}, false
	}
	return llmcheat.Match{
		PatternID: patternID,
		Category:  category,
		Path:      path,
		Line:      lineNum,
		Message: fmt.Sprintf(
			"requirement %q for %q has a floating version specifier (%s); pin an exact version with \"==\" instead",
			rawSpec, name, reason),
		Severity: llmcheat.SeverityMedium,
	}, true
}

// ---- requirements.txt ---------------------------------------------------

func isRequirementsTxt(base string) bool {
	lower := strings.ToLower(base)
	return strings.HasSuffix(lower, ".txt") && strings.Contains(lower, "requirements")
}

func detectRequirementsTxt(path string, content []byte) []llmcheat.Match {
	var matches []llmcheat.Match
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var lineNum uint
	for scanner.Scan() {
		lineNum++
		trimmed := strings.TrimSpace(scanner.Text())
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "-") {
			continue
		}
		// Strip a trailing inline "# comment" (pip allows these after a
		// requirement spec, e.g. "flask>=2.0.0  # web framework").
		if idx := strings.Index(trimmed, "#"); idx >= 0 {
			trimmed = strings.TrimSpace(trimmed[:idx])
		}
		if m, ok := pythonSpecMatch(path, lineNum, trimmed); ok {
			matches = append(matches, m)
		}
	}
	return matches
}

// ---- pyproject.toml ------------------------------------------------------

// pyArrayOpenRe matches the start of a `key = [` array assignment, whether
// or not it closes on the same line, e.g. `dependencies = [` or
// `dev = ["pytest>=7.0"]`.
var pyArrayOpenRe = regexp.MustCompile(`^"?([A-Za-z0-9_\-]+)"?\s*=\s*\[`)

// quotedStringRe extracts every double-quoted string literal on a line.
var quotedStringRe = regexp.MustCompile(`"([^"]*)"`)

func detectPyprojectToml(path string, content []byte) []llmcheat.Match {
	var matches []llmcheat.Match
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var lineNum uint
	section := ""
	inArray := false

	scanQuotedStrings := func(line string) {
		for _, sm := range quotedStringRe.FindAllStringSubmatch(line, -1) {
			if m, ok := pythonSpecMatch(path, lineNum, sm[1]); ok {
				matches = append(matches, m)
			}
		}
	}

	for scanner.Scan() {
		lineNum++
		trimmed := strings.TrimSpace(scanner.Text())

		if hm := tomlSectionHeaderRe.FindStringSubmatch(trimmed); hm != nil {
			section = strings.ToLower(hm[1])
			inArray = false
			continue
		}

		isDepsSection := section == "project" || strings.Contains(section, "optional-dependencies")
		if !isDepsSection {
			continue
		}

		if inArray {
			scanQuotedStrings(trimmed)
			if strings.Contains(trimmed, "]") {
				inArray = false
			}
			continue
		}

		am := pyArrayOpenRe.FindStringSubmatch(trimmed)
		if am == nil {
			continue
		}
		key := am[1]
		// Under plain [project], only the "dependencies" array is a
		// requirement list (other arrays there, e.g. "classifiers" or
		// "keywords", are not versioned dependency specs). Under an
		// [project.optional-dependencies]-named table every array is a
		// named extras group of requirement specs.
		if section == "project" && key != "dependencies" {
			continue
		}
		scanQuotedStrings(trimmed)
		if !strings.Contains(trimmed, "]") {
			inArray = true
		}
	}
	return matches
}

// ---- go.mod --------------------------------------------------------------

// goRequireEntryRe matches one "<module/path> <version>" pair, the shape a
// require line has both in single-line form (`require module/path v1.2.3`,
// with the leading "require " already stripped) and inside a
// `require (\n\tmodule/path v1.2.3\n)` block.
var goRequireEntryRe = regexp.MustCompile(`^(\S+(?:/\S+)+)\s+(\S+)`)

func detectGoMod(path string, content []byte) []llmcheat.Match {
	var matches []llmcheat.Match
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var lineNum uint
	inRequireBlock := false
	for scanner.Scan() {
		lineNum++
		trimmed := strings.TrimSpace(scanner.Text())

		switch {
		case trimmed == "require (":
			inRequireBlock = true
			continue
		case inRequireBlock && trimmed == ")":
			inRequireBlock = false
			continue
		}

		var body string
		switch {
		case inRequireBlock:
			body = trimmed
		case strings.HasPrefix(trimmed, "require "):
			body = strings.TrimSpace(strings.TrimPrefix(trimmed, "require "))
		default:
			continue
		}
		// Drop a trailing "// indirect" or similar line comment before
		// matching, so it never gets captured as part of the version.
		body = strings.TrimSpace(strings.SplitN(body, "//", 2)[0])

		m := goRequireEntryRe.FindStringSubmatch(body)
		if m == nil {
			continue
		}
		modPath, version := m[1], m[2]
		if version != "latest" {
			continue
		}
		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      lineNum,
			Message: fmt.Sprintf(
				"require %q uses the floating \"latest\" pseudo-version instead of a pinned module version",
				modPath),
			Severity: llmcheat.SeverityMedium,
		})
	}
	return matches
}

// ---- Pattern implementation ----------------------------------------------

// detector implements llmcheat.Pattern. It carries no state: Detect
// dispatches purely on the incoming path's base filename to one of the
// five pure scanners above.
type detector struct{}

func (detector) ID() string       { return patternID }
func (detector) Category() string { return category }

// Detect scans content for a floating (non-exact-pinned) dependency version
// specifier, per the file-shape dispatch documented on the package.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	base := strings.ToLower(filepath.Base(path))
	switch {
	case base == "package.json":
		return detectPackageJSON(path, content)
	case base == "cargo.toml":
		return detectCargoToml(path, content)
	case base == "pyproject.toml":
		return detectPyprojectToml(path, content)
	case isRequirementsTxt(base):
		return detectRequirementsTxt(path, content)
	case base == "go.mod":
		return detectGoMod(path, content)
	default:
		return nil
	}
}

func init() {
	llmcheat.Register(detector{})
}
