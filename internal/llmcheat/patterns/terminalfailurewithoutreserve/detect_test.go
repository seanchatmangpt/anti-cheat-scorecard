// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package terminalfailurewithoutreserve

import "testing"

func TestDetectFlagsStopOnFirstFailure(t *testing.T) {
	t.Parallel()
	got := newDetector().Detect("RUNBOOK.md", []byte("Stop on first failure.\n"))
	if len(got) != 1 {
		t.Fatalf("got %d matches, want 1: %+v", len(got), got)
	}
}

func TestDetectFlagsCannotContinueWithoutBoundary(t *testing.T) {
	t.Parallel()
	got := newDetector().Detect("receipt.txt", []byte("The build failed; cannot continue.\n"))
	if len(got) != 1 {
		t.Fatalf("got %d matches, want 1: %+v", len(got), got)
	}
}

func TestDetectAcceptsReservePromotion(t *testing.T) {
	t.Parallel()
	content := []byte(
		"If the build fails, stop this lane.\n" +
			"Reserve: continue with the documentation and replay lane.\n",
	)
	if got := newDetector().Detect("PLAN.md", content); len(got) != 0 {
		t.Fatalf("got %+v, want no match", got)
	}
}

func TestDetectAcceptsTypedTransportBoundary(t *testing.T) {
	t.Parallel()
	content := []byte("Cannot continue on this transport.\nBLOCKED[DNS_GITHUB_UNRESOLVED]\n")
	if got := newDetector().Detect("receipt.txt", content); len(got) != 0 {
		t.Fatalf("got %+v, want no match", got)
	}
}

func TestDetectAcceptsRCARepairRoute(t *testing.T) {
	t.Parallel()
	content := []byte(
		"On failure: stop the destructive step.\n" +
			"RCA: classify the exact transition, repair, then requeue.\n",
	)
	if got := newDetector().Detect("RUNBOOK.md", content); len(got) != 0 {
		t.Fatalf("got %+v, want no match", got)
	}
}
