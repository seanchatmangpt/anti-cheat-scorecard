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

// Package duplicatenearidenticalfunction implements the
// "duplicate-near-identical-function" llmcheat Pattern: it flags Go source
// files that contain two or more DIFFERENT top-level functions (or methods)
// whose bodies are byte-identical once whitespace and blank lines are
// stripped — the classic signature of an LLM (or a human under deadline
// pressure) copy-pasting a working function to create a second one and
// never actually adapting the body to the new name/purpose.
//
// Scope note (single-file only): this detector compares function bodies
// WITHIN one file's content only. Cross-file duplicate detection is
// deliberately out of scope here — Detect only ever receives one file's
// (path, content) pair, has no access to any other file in the repository,
// and does not attempt to cache or correlate state across separate calls
// (Pattern implementations must stay pure per llmcheat.Pattern's contract).
// A real ecosystem-wide "this function is duplicated across many files"
// check would need a different, whole-repo-aware pattern shape than this
// one.
package duplicatenearidenticalfunction

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"

	"github.com/ossf/scorecard/v5/internal/llmcheat"
)

const (
	patternID       = "duplicate-near-identical-function"
	patternCategory = "complexity-and-surface-obfuscation"

	// minDupBodyNonBlankLines is the minimum number of non-blank,
	// whitespace-stripped lines a function body must have before an
	// identical-body match with another function is even considered.
	//
	// The pattern's own required fixture ("func A(x int) int { y := x + 1;
	// return y * 2 }" duplicated as "func B") has exactly 2 non-blank body
	// lines once the braces are stripped, so the practical floor enforced
	// here is 2, not the "3+" figure named in this pattern's prose
	// description — 2 is the value that actually makes the concrete,
	// required dirty fixture produce a match while still excluding truly
	// trivial one-line bodies (e.g. two unrelated functions that both
	// merely `return nil` or `return err`), which would otherwise be a
	// constant source of false positives unrelated to real copy-paste.
	minDupBodyNonBlankLines = 2
)

// detector is the real, stateless implementation of llmcheat.Pattern for
// this pattern. It holds no fields because Detect is a pure function of its
// arguments: the type exists only to give the interface methods a receiver.
type detector struct{}

func (detector) ID() string { return patternID }

func (detector) Category() string { return patternCategory }

// funcInfo is what this detector remembers about the first function seen
// with a given normalized body, so a later duplicate can reference it by
// name and line in its Match.Message.
type funcInfo struct {
	displayName string
	startLine   uint
}

// Detect parses path's content as Go source (only for .go files; any other
// extension is out of scope for this detector and returns nil immediately),
// extracts every top-level function/method body, strips it down to its
// non-blank, whitespace-trimmed lines, and flags the second (and any
// subsequent) occurrence of a body that is byte-identical, after stripping,
// to an earlier function's body in the same file.
//
// Real go/parser + go/ast is used rather than a hand-rolled brace counter:
// it correctly finds each top-level FuncDecl's exact body span (including
// receivers, generics, and multi-line signatures) without this detector
// having to re-implement a Go lexer, and it naturally excludes function
// literals nested inside another function's body from being treated as
// "top-level" (they are not entries of ast.File.Decls), matching this
// pattern's stated top-level-only scope. If the content does not parse as
// valid Go, Detect returns nil rather than guessing — a best-effort
// heuristic detector must never panic or fabricate matches on unparseable
// input.
func (detector) Detect(path string, content []byte) []llmcheat.Match {
	if filepath.Ext(path) != ".go" {
		return nil
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, content, parser.ParseComments)
	if err != nil {
		return nil
	}

	var matches []llmcheat.Match
	seen := make(map[string]funcInfo)

	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			// Not a function declaration, or a body-less forward
			// declaration (e.g. an assembly-backed function) with
			// nothing to compare.
			continue
		}

		lbrace := fset.Position(fd.Body.Lbrace).Offset
		rbrace := fset.Position(fd.Body.Rbrace).Offset
		if lbrace < 0 || rbrace < 0 || rbrace <= lbrace || rbrace > len(content) {
			// Defensive: should not happen for a file that parsed
			// successfully, but never index out of range on a
			// pure-function detector.
			continue
		}
		rawBody := content[lbrace+1 : rbrace]

		normalized, nonBlankLines := normalizeBody(rawBody)
		if nonBlankLines < minDupBodyNonBlankLines {
			continue
		}

		name := funcDisplayName(fd)
		startLine := uint(fset.Position(fd.Pos()).Line)

		if prior, ok := seen[normalized]; ok {
			matches = append(matches, llmcheat.Match{
				PatternID: patternID,
				Category:  patternCategory,
				Path:      path,
				Line:      startLine,
				Message: fmt.Sprintf(
					"function %s (line %d) has a body byte-identical to %s (line %d) after stripping whitespace/blank lines (%d non-blank lines) — looks like copy-paste without adaptation rather than an intentionally shared implementation",
					name, startLine, prior.displayName, prior.startLine, nonBlankLines,
				),
				Severity: llmcheat.SeverityMedium,
			})
			continue
		}
		seen[normalized] = funcInfo{displayName: name, startLine: startLine}
	}

	return matches
}

// normalizeBody strips a raw function-body byte slice (the content between,
// but not including, its enclosing '{' and '}') down to a canonical form
// for identity comparison: every line is trimmed of leading/trailing
// whitespace, and blank lines are dropped entirely. It also returns the
// number of non-blank lines that survived, so callers can apply a minimum
// meaningful-size floor before treating two bodies as a real duplicate.
func normalizeBody(raw []byte) (normalized string, nonBlankLines int) {
	rawLines := strings.Split(string(raw), "\n")
	kept := make([]string, 0, len(rawLines))
	for _, line := range rawLines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		kept = append(kept, trimmed)
	}
	return strings.Join(kept, "\n"), len(kept)
}

// funcDisplayName renders a human-readable name for a FuncDecl for use in
// Match.Message: plain "Name" for a free function, "(RecvType).Name" for a
// method. It only needs to be readable, not a fully general Go type
// renderer, so it handles the common receiver shapes (identifier, pointer
// receiver, generic receiver) directly rather than pulling in go/types.
func funcDisplayName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	return fmt.Sprintf("(%s).%s", recvTypeString(fd.Recv.List[0].Type), fd.Name.Name)
}

// recvTypeString renders a method receiver's type expression as a short
// string (e.g. "*Store", "Cache", "Box" for a generic "Box[T]" receiver).
func recvTypeString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + recvTypeString(t.X)
	case *ast.IndexExpr:
		// Generic receiver, e.g. "func (b Box[T]) Foo()".
		return recvTypeString(t.X)
	case *ast.IndexListExpr:
		// Generic receiver with multiple type params, e.g. "Box[K, V]".
		return recvTypeString(t.X)
	default:
		return "receiver"
	}
}

func init() {
	llmcheat.Register(detector{})
}
