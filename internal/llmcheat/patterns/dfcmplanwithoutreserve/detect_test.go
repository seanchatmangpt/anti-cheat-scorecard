// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package dfcmplanwithoutreserve

import (
	"strings"
	"testing"
)

func TestDetectFlagsDfCMPlanWithNoReserveOrRollback(t *testing.T) {
	t.Parallel()
	content := []byte("# DfCM execution plan\nPrimary: replace the generator today.\n")
	got := newDetector().Detect("PLAN.md", content)
	if len(got) != 1 {
		t.Fatalf("got %d matches, want 1: %+v", len(got), got)
	}
}

func TestDetectFlagsMissingRollbackOnly(t *testing.T) {
	t.Parallel()
	content := []byte("DfCM implementation plan\nPrimary: patch producer\nReserve: keep current pack\n")
	got := newDetector().Detect("PLAN.md", content)
	if len(got) != 1 || !strings.Contains(got[0].Message, "rollback") {
		t.Fatalf("unexpected matches: %+v", got)
	}
}

func TestDetectFlagsMissingReserveOnly(t *testing.T) {
	t.Parallel()
	content := []byte(
		"Design for Combinatorial Maximalism strategy\n" +
			"Primary: patch producer\n" +
			"Rollback: revert the commit\n",
	)
	got := newDetector().Detect("PLAN.md", content)
	if len(got) != 1 || !strings.Contains(got[0].Message, "reserve") {
		t.Fatalf("unexpected matches: %+v", got)
	}
}

func TestDetectAcceptsCompleteDfCMPlan(t *testing.T) {
	t.Parallel()
	content := []byte(
		"DfCM execution plan\n" +
			"Primary: patch producer\n" +
			"Reserve: use prior pack\n" +
			"Alternative: regenerate from source\n" +
			"Rollback: revert the patch\n" +
			"Replay: rerun the receipt\n",
	)
	if got := newDetector().Detect("PLAN.md", content); len(got) != 0 {
		t.Fatalf("got %+v, want no match", got)
	}
}

func TestDetectSkipsDefinitionWithoutPlan(t *testing.T) {
	t.Parallel()
	content := []byte("DfCM means Design for Combinatorial Maximalism.\n")
	if got := newDetector().Detect("GLOSSARY.md", content); len(got) != 0 {
		t.Fatalf("got %+v, want no match", got)
	}
}
