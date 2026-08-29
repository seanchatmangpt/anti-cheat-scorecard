// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package prematureoptioncollapse

import "testing"

func TestDetectFlagsSingleOptionWithoutExploration(t *testing.T) {
	got := newDetector().Detect("PLAN.md", []byte("Selected approach: rewrite the generator. This is the only viable option.\n"))
	if len(got) != 1 {
		t.Fatalf("got %d matches, want 1: %+v", len(got), got)
	}
	if got[0].Category != "option-space-collapse" || got[0].PatternID != patternID {
		t.Fatalf("unexpected match: %+v", got[0])
	}
}

func TestDetectAcceptsSelectionAfterAlternativeCensus(t *testing.T) {
	content := []byte("Options: preserve current generator, patch the pack, or rewrite.\nComparison: patching preserves the most reversible options.\nSelected approach: patch the pack.\nFallback: preserve the current generator and revert this patch.\n")
	if got := newDetector().Detect("PLAN.md", content); len(got) != 0 {
		t.Fatalf("got %+v, want no match", got)
	}
}

func TestDetectAcceptsNearbyFalsifierAndReserve(t *testing.T) {
	content := []byte("Falsifier: reject the route if replay diverges.\nReserve: switch to the prior pack.\nWe chose the generated path.\n")
	if got := newDetector().Detect("receipt.txt", content); len(got) != 0 {
		t.Fatalf("got %+v, want no match", got)
	}
}

func TestDetectSkipsNormativeRuleText(t *testing.T) {
	content := []byte("Rule: detect the phrase only viable option when no alternatives are recorded.\n")
	if got := newDetector().Detect("RULES.md", content); len(got) != 0 {
		t.Fatalf("got %+v, want no match for detector definition", got)
	}
}

func TestDetectSkipsSourceCode(t *testing.T) {
	content := []byte("const msg = \"the solution is deterministic\"\n")
	if got := newDetector().Detect("main.go", content); len(got) != 0 {
		t.Fatalf("got %+v, want no match outside evidence-bearing paths", got)
	}
}
