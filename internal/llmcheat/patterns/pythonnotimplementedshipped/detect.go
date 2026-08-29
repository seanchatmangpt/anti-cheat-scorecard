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

// Package pythonnotimplementedshipped implements the
// "python-notimplemented-shipped" llmcheat.Pattern: it flags a Python
// function that raises bare NotImplementedError as if it were a real,
// concrete implementation, when it is neither declared abstract via an
// @abstractmethod-family decorator nor nested inside a class that itself
// derives from ABC/ABCMeta/Protocol. That shape is a classic hollow
// implementation — code that type-checks, imports, and even looks callable,
// but explodes the moment anything actually invokes it — shipped without the
// language-level markers ("this is intentionally abstract") that would make
// the same raise legitimate.
package pythonnotimplementedshipped

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

// patternID and category are the two identifiers this detector self-registers
// under; they must stay in sync with what ID()/Category() return.
const (
	patternID = "python-notimplemented-shipped"
	category  = "hollow-implementation"
)

func init() {
	llmcheat.Register(&detector{})
}

// detector is the unexported llmcheat.Pattern implementation. It holds no
// state of its own (state lives entirely on the stack built fresh inside
// each Detect call), so a single shared instance is safe to register once.
type detector struct{}

func (d *detector) ID() string       { return patternID }
func (d *detector) Category() string { return category }

var (
	// classHeaderRe captures a class statement's optional base-class/
	// metaclass parenthesized argument list, e.g. "class Foo(ABC):" or
	// "class Foo(Base, metaclass=ABCMeta):".
	classHeaderRe = regexp.MustCompile(`^\s*class\s+\w+\s*(?:\(([^)]*)\))?\s*:`)

	// defHeaderRe matches a (possibly async) function/method definition
	// header, e.g. "def save(self, data):" or "async def save(self):".
	defHeaderRe = regexp.MustCompile(`^\s*(?:async\s+)?def\s+(\w+)\s*\(`)

	// decoratorAbstractRe matches an @abstractmethod-family decorator,
	// including a qualified form like "@abc.abstractmethod".
	decoratorAbstractRe = regexp.MustCompile(
		`^\s*@\s*(?:[\w.]+\.)?(?:abstractmethod|abstractproperty|abstractclassmethod|abstractstaticmethod)\b`)

	// decoratorAnyRe matches any decorator line at all, used only to decide
	// whether a non-decorator, non-blank, non-comment line should clear a
	// previously-seen abstract-decorator flag.
	decoratorAnyRe = regexp.MustCompile(`^\s*@`)

	// raiseNotImplementedRe matches "raise NotImplementedError", with or
	// without a call/args ("raise NotImplementedError" or
	// "raise NotImplementedError(\"msg\")"), and regardless of what (if
	// anything) precedes it on the line — this lets one-liner defs like
	// "def save(self): raise NotImplementedError" match on the def's own
	// line.
	raiseNotImplementedRe = regexp.MustCompile(`\braise\s+NotImplementedError\b`)

	// abstractBaseRe finds an ABC/ABCMeta/Protocol marker inside a class's
	// base-class argument list, e.g. "ABC", "abc.ABC", "metaclass=ABCMeta",
	// or "typing.Protocol".
	abstractBaseRe = regexp.MustCompile(`\b(?:ABC|ABCMeta|Protocol)\b`)
)

// scope is one open indentation-delimited block (a class or a def) that the
// current line is nested inside.
type scope struct {
	kind             string // "class" or "def"
	indent           int
	name             string
	isAbstractClass  bool // kind == "class": derives from ABC/ABCMeta/Protocol
	isAbstractMethod bool // kind == "def": decorated with @abstractmethod-family
}

// Detect is a pure function: it scans .py content line by line, tracking an
// indentation-based stack of enclosing class/def scopes (Python has no other
// notion of block nesting), and flags every "raise NotImplementedError"
// whose nearest enclosing function is not itself abstractmethod-decorated
// and is not nested inside an ABC/ABCMeta/Protocol-derived class.
func (d *detector) Detect(path string, content []byte) []llmcheat.Match {
	if !strings.EqualFold(filepath.Ext(path), ".py") {
		return nil
	}

	var matches []llmcheat.Match
	var stack []scope
	pendingAbstractDecorator := false

	lines := strings.Split(string(content), "\n")
	for i, rawLine := range lines {
		lineNo := uint(i + 1) //nolint:gosec // i is bounded by len(lines), never near uint overflow

		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			// Blank and whole-line-comment lines carry no indentation
			// information worth tracking: skip them entirely. The next
			// real code line's own indent still correctly closes any
			// scopes that ended, regardless of what a stray comment's
			// indentation looked like.
			continue
		}

		indent := indentWidth(rawLine)

		// Close every open scope whose body has ended: a line at or above
		// its header's indentation means that scope's body is finished.
		for len(stack) > 0 && indent <= stack[len(stack)-1].indent {
			stack = stack[:len(stack)-1]
		}

		codeLine := stripLineComment(rawLine)

		switch {
		case classHeaderRe.MatchString(codeLine):
			m := classHeaderRe.FindStringSubmatch(codeLine)
			bases := ""
			if len(m) > 1 {
				bases = m[1]
			}
			stack = append(stack, scope{
				kind:            "class",
				indent:          indent,
				name:            strings.TrimSpace(trimmed),
				isAbstractClass: abstractBaseRe.MatchString(bases),
			})
			pendingAbstractDecorator = false

		case defHeaderRe.MatchString(codeLine):
			m := defHeaderRe.FindStringSubmatch(codeLine)
			name := ""
			if len(m) > 1 {
				name = m[1]
			}
			stack = append(stack, scope{
				kind:             "def",
				indent:           indent,
				name:             name,
				isAbstractMethod: pendingAbstractDecorator,
			})
			pendingAbstractDecorator = false

		case decoratorAbstractRe.MatchString(codeLine):
			pendingAbstractDecorator = true
			continue // decorator lines never themselves contain the raise

		case decoratorAnyRe.MatchString(codeLine):
			// Some other decorator (e.g. @property, @staticmethod): keep
			// any already-seen abstractmethod decorator pending, since
			// Python allows stacking multiple decorators before one def.

		default:
			pendingAbstractDecorator = false
		}

		if !raiseNotImplementedRe.MatchString(codeLine) {
			continue
		}

		enclosingDef, class, ok := nearestFunctionAndClass(stack)
		if !ok {
			// A bare "raise NotImplementedError" at module scope (not
			// inside any function) is out of this pattern's stated scope.
			continue
		}
		if enclosingDef.isAbstractMethod {
			continue
		}
		if class != nil && class.isAbstractClass {
			continue
		}

		fnLabel := enclosingDef.name
		if fnLabel == "" {
			fnLabel = "<anonymous>"
		}
		matches = append(matches, llmcheat.Match{
			PatternID: patternID,
			Category:  category,
			Path:      path,
			Line:      lineNo,
			Message: fmt.Sprintf(
				"function %q raises bare NotImplementedError but is shipped as a concrete method: "+
					"it is not @abstractmethod-decorated and not nested inside a class deriving from ABC/ABCMeta/Protocol",
				fnLabel),
			Severity: llmcheat.SeverityHigh,
		})
	}

	return matches
}

// nearestFunctionAndClass returns the innermost "def" scope on the stack
// (the function the current line is inside) and, if one exists further down
// the same stack, the nearest enclosing "class" scope. ok is false when the
// stack contains no "def" scope at all (i.e. we are at module scope).
func nearestFunctionAndClass(stack []scope) (def scope, class *scope, ok bool) {
	defIdx := -1
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i].kind == "def" {
			defIdx = i
			def = stack[i]
			ok = true
			break
		}
	}
	if !ok {
		return scope{}, nil, false
	}
	for i := defIdx - 1; i >= 0; i-- {
		if stack[i].kind == "class" {
			c := stack[i]
			return def, &c, true
		}
	}
	return def, nil, true
}

// indentWidth computes a line's leading-whitespace width, expanding tabs to
// the next multiple of 8 (the conventional Python/terminal tab stop) so that
// tab- and space-indented blocks at the same logical depth compare equal.
func indentWidth(line string) int {
	width := 0
	for _, r := range line {
		switch r {
		case ' ':
			width++
		case '\t':
			width += 8 - (width % 8)
		default:
			return width
		}
	}
	return width
}

// stripLineComment returns line with a trailing "# ..." comment removed,
// honoring single- and double-quoted string literals so that a '#' inside a
// string (e.g. a URL fragment or format string) is not mistaken for the
// start of a comment. It does not attempt to understand triple-quoted
// strings or line-continuations — a deliberate, documented simplification
// for a heuristic line-scanner, not a full Python tokenizer.
func stripLineComment(line string) string {
	inSingle, inDouble := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '\\' && (inSingle || inDouble) && i+1 < len(line):
			i++ // skip the escaped character
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case c == '#' && !inSingle && !inDouble:
			return line[:i]
		}
	}
	return line
}
