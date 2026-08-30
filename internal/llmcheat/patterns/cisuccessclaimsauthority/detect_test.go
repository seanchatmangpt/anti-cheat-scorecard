// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package cisuccessclaimsauthority

import "testing"

func TestDetect(t *testing.T) {
	t.Parallel()
	d := &detector{}
	tests := []struct {
		name, body string
		want       int
	}{
		{"authority leap", "CI passed, therefore the current head is ALIVE.", 1},
		{"transport only", "CI is evidence transport, not authority.", 0},
		{"plain pass", "CI passed all tests.", 0},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := len(d.Detect("STATUS.md", []byte(tc.body))); got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}
}
