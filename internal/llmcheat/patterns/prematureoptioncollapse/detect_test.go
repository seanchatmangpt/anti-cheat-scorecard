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
	t.Parallel()
	content := []byte("Selected approach: rewrite the generator. This is the only viable option.\n")
	got := newDetector().Detect("PLAN.md", content)
	if len(got) != 1 {
		t.Fatalf("got %d matches, want 1: %+v", len(got), got)
	}
	if got[0].Category != "option-space-collapse" || got[0].PatternID != patternID {
		t.Fatalf("unexpected match: %+v", got[0])
	}
}

func TestDetectAcceptsSelectionAfterAlternativeCensus(t *testing.T) {
	t.Parallel()
	content := []byte(
		"Options: preserve current generator, patch the pack, or rewrite.\n" +
			"Comparison: patching preserves the most reversible options.\n" +
			"Selected approach: patch the pack.\n" +
			"Fallback: preserve the current generator and revert this patch.\n",
	)
	if got := newDetector().Detect("PLAN.md", content); len(got) != 0 {
		t.Fatalf("got %+v, want no match", got)
	}
}

func TestDetectAcceptsNearbyFalsifierAndReserve(t *testing.T) {
	t.Parallel()
	content := []byte(
		"Falsifier: reject the route if replay diverges.\n" +
			"Reserve: switch to the prior pack.\n" +
			"We chose the generated path.\n",
	)
	if got := newDetector().Detect("receipt.txt", content); len(got) != 0 {
		t.Fatalf("got %+v, want no match", got)
	}
}

func TestDetectSkipsNormativeRuleText(t *testing.T) {
	t.Parallel()
	content := []byte("Rule: detect the phrase only viable option when no alternatives are recorded.\n")
	if got := newDetector().Detect("RULES.md", content); len(got) != 0 {
		t.Fatalf("got %+v, want no match for detector definition", got)
	}
}

func TestDetectSkipsSourceCode(t *testing.T) {
	t.Parallel()
	content := []byte("const msg = \"the solution is deterministic\"\n")
	if got := newDetector().Detect("main.go", content); len(got) != 0 {
		t.Fatalf("got %+v, want no match outside evidence-bearing paths", got)
	}
}
