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

// Package errormessagewrongcontext implements the
// "error-message-wrong-context" llmcheat Pattern: it flags a string literal
// passed directly to an error-raising call (Python's raise <Error>(...), Go's
// errors.New(...) / panic(...), or JS/TS's throw new <Error>(...)) whose text
// mentions a function/identifier-looking token (camelCase or snake_case,
// e.g. "parseInput" or "compute_value") that does NOT match the name of the
// function the call is actually inside.
//
// This is a very specific, very common LLM-generated-code smell: an error
// message copy-pasted (by the model, or by a human pattern-matching off a
// nearby example) from a *different* function's error path and left
// un-edited, so the message now names the wrong function entirely — a
// diagnostic surface that actively misleads whoever reads the error later.
// It is deliberately NOT restricted to one file extension: the four call
// shapes it recognizes span Python, Go, and JavaScript/TypeScript source, and
// none of them collide with legitimate syntax in the others' files, so
// running the same scan over any text content is safe and correct.
package errormessagewrongcontext

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"regexp"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID       = "error-message-wrong-context"
	patternCategory = "complexity-and-surface-obfuscation"
)

// funcDefPattern pairs a regexp that recognizes one language's function
// (or method) definition header with the index of the capture group holding
// the function's own name.
type funcDefPattern struct {
	re *regexp.Regexp
}

// funcDefPatterns is deliberately ordered but not exclusive-choice-sensitive:
// each shape is syntactically distinct enough (leading keyword) that at most
// one ever matches a given real source line. Every regexp is anchored to the
// (whitespace-trimmed) start of the line so a name mentioned only inside a
// call's arguments — not as the definition itself — can never be
// mis-captured as "the enclosing function".
var funcDefPatterns = []funcDefPattern{
	// Go: func Name(...) ... or func (recv Type) Name(...) ...
	{re: regexp.MustCompile(`^func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(`)},
	// Python: def name(...):
	{re: regexp.MustCompile(`^def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(`)},
	// JS/TS: [export] [async] function name(...) {
	{re: regexp.MustCompile(`^(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(`)},
	// JS/TS: [export] const/let/var name = [async] (...) [: Type] => {
	{re: regexp.MustCompile(`^(?:export\s+)?(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*(?::\s*[\w<>\[\],. ]+\s*)?=>`)},
}

// callTriggerRe matches the opening of one of the four error-raising call
// shapes named in this pattern's spec, up to and including its "(". It is
// intentionally a little more general than the four literal examples
// (e.g. "raise ValueError(" also matches "raise KeyError(", "throw new
// Error(" also matches "throw new TypeError(") since the underlying smell —
// a hardcoded string handed straight to *some* error constructor — is
// identical regardless of which concrete exception type is used.
var callTriggerRe = regexp.MustCompile(
	`\b(?:raise\s+[A-Za-z_][A-Za-z0-9_.]*\s*\(|errors\.New\s*\(|panic\s*\(|throw\s+new\s+[A-Za-z_][A-Za-z0-9_.]*\s*\()`,
)

// stringLitAfterCallRe matches a quoted string literal that appears
// (allowing only whitespace and an optional single-letter string prefix,
// e.g. Python's f"..." / r"...") immediately after an error-call's opening
// paren. Supporting three quote styles covers Python/Go's '"'.../"'...'" and
// JS/TS's optional backtick template-literal form.
var stringLitAfterCallRe = regexp.MustCompile(
	"^\\s*[a-zA-Z]?(\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*'|`[^`]*`)",
)

// identifierTokenRe finds function/identifier-looking words inside an error
// message: snake_case (contains an underscore) or camelCase (lowercase
// start, an uppercase letter later). Plain English words never match either
// shape, which is what keeps this detector from firing on ordinary prose
// error text ("invalid input", "not found", ...).
var identifierTokenRe = regexp.MustCompile(
	`\b[a-z][a-zA-Z0-9]*_[a-zA-Z0-9_]*\b|\b[a-z][a-z0-9]*[A-Z][a-zA-Z0-9]*\b`,
)

// detector is the real, stateless implementation of llmcheat.Pattern for
// this pattern. It holds no fields because Detect is a pure function of its
// arguments: the type exists only to give the interface methods a receiver.
type detector struct{}

func (detector) ID() string { return patternID }

func (detector) Category() string { return patternCategory }

// Detect scans path's content line-by-line, tracking the most recently seen
// enclosing function/method name, and flags any error-raising call whose
// string-literal argument mentions a different function's name. Line numbers
// are 1-based and computed from a real running counter over the actual
// scanned lines.
//
// The "enclosing function" tracking is a deliberately simple heuristic (the
// last function-definition header line seen, valid until the next one) — it
// does not parse braces/indentation to know when a function body ends. This
// is sufficient for the shape this pattern targets (a message near the top
// of the function whose error path it belongs to) and keeps the detector a
// dependency-free, single-pass line scanner rather than a real parser.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	var matches []llmcheat.Match

	scanner := bufio.NewScanner(bytes.NewReader(content))
	// Source lines can be long; raise the scanner's buffer well above
	// bufio's 64KiB default so a single unusually long line doesn't cause a
	// silent bufio.ErrTooLong scan failure that would make this detector
	// miss real matches.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	currentFuncName := ""
	lineNum := uint(0)
	for scanner.Scan() {
		lineNum++
		rawLine := scanner.Text()
		trimmed := strings.TrimSpace(rawLine)

		for _, fp := range funcDefPatterns {
			if m := fp.re.FindStringSubmatch(trimmed); m != nil {
				currentFuncName = m[1]
				break
			}
		}

		loc := callTriggerRe.FindStringIndex(rawLine)
		if loc == nil {
			continue
		}

		rest := rawLine[loc[1]:]
		litMatch := stringLitAfterCallRe.FindStringSubmatch(rest)
		if litMatch == nil {
			continue
		}
		quoted := litMatch[1]
		// Strip the outer quote/backtick characters to get the message body
		// the identifier scan should run over.
		messageBody := quoted
		if len(messageBody) >= 2 {
			messageBody = messageBody[1 : len(messageBody)-1]
		}

		tokens := identifierTokenRe.FindAllString(messageBody, -1)
		if len(tokens) == 0 {
			continue
		}

		mismatched := make([]string, 0, len(tokens))
		for _, tok := range tokens {
			if currentFuncName != "" && strings.EqualFold(tok, currentFuncName) {
				// Self-reference — the message correctly names its own
				// enclosing function (e.g. "computeTotal: invalid input"
				// inside func computeTotal()). Not a mismatch.
				continue
			}
			mismatched = append(mismatched, tok)
		}
		if len(mismatched) == 0 {
			continue
		}

		enclosing := currentFuncName
		if enclosing == "" {
			enclosing = "<top-level>"
		}
		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  patternCategory,
			Path:      path,
			Line:      lineNum,
			Message: fmt.Sprintf(
				"error message in %s() mentions %q, which does not match the enclosing function — looks copy-pasted from a different function's error path: %s",
				enclosing, mismatched[0], trimmed,
			),
			Severity: llmcheat.SeverityMedium,
		})
	}

	return matches
}

func init() {
	llmcheat.Register(detector{})
}
