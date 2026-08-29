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

// Package syntaxgraph projects parsed source syntax into a deterministic,
// queryable graph. It is the Go analogue of the source->graph boundary used
// by ash_r2rml: source text is parsed once, syntax is walked in source order,
// and consumers query canonical nodes/containment edges rather than guessing
// semantic structure from regular expressions.
//
// The first adapter uses the standard Go parser/AST. The graph contract is
// deliberately parser-neutral so Tree-sitter or other language adapters can
// implement the same projection without changing anti-cheat detectors.
package syntaxgraph

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"reflect"
	"strings"
)

// Node is one syntax object in deterministic pre-order.
type Node struct {
	Kind      string
	Role      string
	Value     string
	ID        int
	ParentID  int
	StartByte int
	EndByte   int
	Line      uint
}

// Edge is a canonical relationship between syntax objects.
type Edge struct {
	Predicate string
	From      int
	To        int
}

// Graph is the admitted syntax projection for one source file.
type Graph struct {
	Path     string
	Language string
	Nodes    []Node
	Edges    []Edge
}

// ParseGo parses Go source and returns its syntax graph. A partially parsed
// file is not admitted: parser errors are returned to the caller so a broken
// syntax tree cannot quietly become semantic evidence.
func ParseGo(path string, content []byte) (*Graph, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, content, parser.ParseComments|parser.AllErrors)
	if err != nil {
		return nil, fmt.Errorf("parse Go syntax %s: %w", path, err)
	}

	g := &Graph{Path: path, Language: "go"}
	stack := make([]int, 0, 32)

	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			return true
		}

		parent := -1
		if len(stack) > 0 {
			parent = stack[len(stack)-1]
		}
		id := len(g.Nodes)
		start := fset.PositionFor(n.Pos(), false)
		end := fset.PositionFor(n.End(), false)
		kind := strings.TrimPrefix(reflect.TypeOf(n).String(), "*ast.")
		role, value := classify(fset, n)
		g.Nodes = append(g.Nodes, Node{
			Kind:      kind,
			Role:      role,
			Value:     value,
			ID:        id,
			ParentID:  parent,
			StartByte: start.Offset,
			EndByte:   end.Offset,
			Line:      uint(start.Line),
		})
		if parent >= 0 {
			g.Edges = append(g.Edges, Edge{Predicate: "contains", From: parent, To: id})
		}
		stack = append(stack, id)
		return true
	})

	return g, nil
}

func classify(fset *token.FileSet, n ast.Node) (string, string) {
	switch x := n.(type) {
	case *ast.Ident:
		return "identifier", x.Name
	case *ast.BasicLit:
		return "literal", x.Value
	case *ast.SelectorExpr:
		return "selector", render(fset, x)
	case *ast.CallExpr:
		return "call", render(fset, x.Fun)
	case *ast.IfStmt:
		return "if-condition", render(fset, x.Cond)
	case *ast.BinaryExpr:
		return "binary", render(fset, x)
	case *ast.CompositeLit:
		return "composite", render(fset, x.Type)
	case *ast.FuncDecl:
		if x.Name != nil {
			return "function", x.Name.Name
		}
	}
	return "node", ""
}

func render(fset *token.FileSet, n any) string {
	var b bytes.Buffer
	if err := printer.Fprint(&b, fset, n); err != nil {
		return ""
	}
	return b.String()
}

// Descendants returns every node transitively contained by ancestorID in
// deterministic source order.
func (g *Graph) Descendants(ancestorID int) []Node {
	out := make([]Node, 0)
	for _, n := range g.Nodes {
		if n.ID == ancestorID {
			continue
		}
		for parent := n.ParentID; parent >= 0; parent = g.Nodes[parent].ParentID {
			if parent == ancestorID {
				out = append(out, n)
				break
			}
		}
	}
	return out
}

// Digest binds the source graph's identity. It is stable for identical path,
// parser language, node order, node facts, and containment edges.
func (g *Graph) Digest() string {
	h := sha256.New()
	writeField := func(v string) {
		_, _ = fmt.Fprintf(h, "%d:%s|", len(v), v)
	}
	writeField(g.Path)
	writeField(g.Language)
	for _, n := range g.Nodes {
		writeField(fmt.Sprintf("%d", n.ID))
		writeField(fmt.Sprintf("%d", n.ParentID))
		writeField(n.Kind)
		writeField(n.Role)
		writeField(n.Value)
		writeField(fmt.Sprintf("%d", n.Line))
		writeField(fmt.Sprintf("%d", n.StartByte))
		writeField(fmt.Sprintf("%d", n.EndByte))
	}
	for _, e := range g.Edges {
		writeField(fmt.Sprintf("%d", e.From))
		writeField(e.Predicate)
		writeField(fmt.Sprintf("%d", e.To))
	}
	return hex.EncodeToString(h.Sum(nil))
}
