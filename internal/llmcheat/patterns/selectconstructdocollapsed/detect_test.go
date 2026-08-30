// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package selectconstructdocollapsed

import "testing"

func TestDetect(t *testing.T) {
	t.Parallel()
	d := &detector{}
	tests := []struct {
		name, body string
		want       int
	}{
		{"collapsed", "SELECT, CONSTRUCT, and DO run in the same function.", 1},
		{"separate", "SELECT, CONSTRUCT, and DO are distinct stages.", 0},
		{"partial", "SELECT and CONSTRUCT share parsing only.", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := len(d.Detect("ARCH.md", []byte(tc.body))); got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}
}
