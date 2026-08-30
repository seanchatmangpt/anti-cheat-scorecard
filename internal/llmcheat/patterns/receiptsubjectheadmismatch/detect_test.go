// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package receiptsubjectheadmismatch

import "testing"

func TestDetect(t *testing.T) {
	t.Parallel()
	d := &detector{}
	a := "0123456789abcdef0123456789abcdef01234567"
	b := "89abcdef0123456789abcdef0123456789abcdef"
	tests := []struct {
		name, body string
		want       int
	}{
		{"mismatch", "subject_sha = \"" + a + "\"\nhead_sha = \"" + b + "\"\n", 1},
		{"same", "subject_sha = \"" + a + "\"\nhead_sha = \"" + a + "\"\n", 0},
		{"incomplete", "subject_sha = \"" + a + "\"\n", 0},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := len(d.Detect("receipt.toml", []byte(tc.body))); got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}
}
