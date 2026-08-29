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

package syntaxgraph

import "testing"

func TestParseGoWalksCanonicalSyntaxGraph(t *testing.T) {
	source := []byte(`package p
import "net/http/httptest"
func TestChicago(t *testing.T) {
	if true { t.Skip("not production") }
	_ = httptest.NewServer(nil)
}
`)
	g, err := ParseGo("tests/chicago/runtime_test.go", source)
	if err != nil {
		t.Fatalf("ParseGo: %v", err)
	}
	if g.Language != "go" || len(g.Nodes) == 0 {
		t.Fatalf("unexpected graph: %#v", g)
	}
	if len(g.Edges) != len(g.Nodes)-1 {
		t.Fatalf("containment edges=%d nodes=%d, want tree edge count nodes-1", len(g.Edges), len(g.Nodes))
	}

	wantCalls := map[string]bool{"t.Skip": false, "httptest.NewServer": false}
	for _, n := range g.Nodes {
		if n.Role == "call" {
			if _, ok := wantCalls[n.Value]; ok {
				wantCalls[n.Value] = true
			}
		}
	}
	for call, found := range wantCalls {
		if !found {
			t.Errorf("syntax graph missing call %q", call)
		}
	}
}

func TestDigestIsDeterministicAndContentSensitive(t *testing.T) {
	a := []byte("package p\nfunc f(){ println(true) }\n")
	g1, err := ParseGo("p.go", a)
	if err != nil {
		t.Fatal(err)
	}
	g2, err := ParseGo("p.go", a)
	if err != nil {
		t.Fatal(err)
	}
	if g1.Digest() != g2.Digest() {
		t.Fatalf("same source produced different graph digests: %s != %s", g1.Digest(), g2.Digest())
	}

	g3, err := ParseGo("p.go", []byte("package p\nfunc f(){ println(false) }\n"))
	if err != nil {
		t.Fatal(err)
	}
	if g1.Digest() == g3.Digest() {
		t.Fatal("different syntax produced identical graph digest")
	}
}

func TestMalformedGoIsNotAdmitted(t *testing.T) {
	if _, err := ParseGo("broken.go", []byte("package p\nfunc {")); err == nil {
		t.Fatal("malformed Go syntax was admitted")
	}
}
