// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package exactheadclaimwithfloatingref

import "testing"

func TestDetect(t *testing.T) {
	t.Parallel()
	d := &detector{}
	tests := []struct {
		name string
		body string
		want int
	}{
		{"floating", "Exact head must be verified.\nref: main\n", 1},
		{"pinned", "Exact head must be verified.\nref: 0123456789abcdef0123456789abcdef01234567\n", 0},
		{"no exact claim", "ref: main\n", 0},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := len(d.Detect("court.yml", []byte(tc.body))); got != tc.want {
				t.Fatalf("Detect() matches = %d, want %d", got, tc.want)
			}
		})
	}
}
