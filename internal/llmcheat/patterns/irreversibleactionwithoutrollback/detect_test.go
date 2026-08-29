// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package irreversibleactionwithoutrollback

import "testing"

func TestDetectFlagsForcePushWithoutRecovery(t *testing.T) {
	t.Parallel()
	got := newDetector().Detect("release.sh", []byte("git push origin main --force\n"))
	if len(got) != 1 {
		t.Fatalf("got %d matches, want 1: %+v", len(got), got)
	}
}

func TestDetectFlagsDestroyWithoutSnapshot(t *testing.T) {
	t.Parallel()
	got := newDetector().Detect("ops.md", []byte("Run terraform destroy -auto-approve after the migration.\n"))
	if len(got) != 1 {
		t.Fatalf("got %d matches, want 1: %+v", len(got), got)
	}
}

func TestDetectAcceptsDestructiveActionWithRollback(t *testing.T) {
	t.Parallel()
	content := []byte(
		"Snapshot the database first.\n" +
			"Rollback: restore snapshot db-pre-migration.\n" +
			"DROP TABLE legacy_events;\n",
	)
	if got := newDetector().Detect("migration.sql", content); len(got) != 0 {
		t.Fatalf("got %+v, want no match", got)
	}
}

func TestDetectAcceptsCanaryRecoveryRoute(t *testing.T) {
	t.Parallel()
	content := []byte(
		"Canary deletion on one namespace.\n" +
			"Recovery: recreate from the pinned manifest.\n" +
			"kubectl delete deployment old-api\n",
	)
	if got := newDetector().Detect("deploy.sh", content); len(got) != 0 {
		t.Fatalf("got %+v, want no match", got)
	}
}

func TestDetectSkipsExplicitProhibition(t *testing.T) {
	t.Parallel()
	content := []byte("Do not run git push --force; the policy forbids rewriting protected history.\n")
	if got := newDetector().Detect("POLICY.md", content); len(got) != 0 {
		t.Fatalf("got %+v, want no match", got)
	}
}
