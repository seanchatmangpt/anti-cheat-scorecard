// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package replayclaimwithoutevidence

import "testing"

func TestDetect(t *testing.T) {
	t.Parallel()
	d := &detector{}
	tests := []struct {
		name, body string
		want       int
	}{
		{"bare claim", "Replay verified successfully.", 1},
		{"receipt bound", "Replay verified successfully; receipt digest sha256:abc123 recorded.", 0},
		{"not claim", "Replay is required before promotion.", 0},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := len(d.Detect("receipt.md", []byte(tc.body))); got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}
}
