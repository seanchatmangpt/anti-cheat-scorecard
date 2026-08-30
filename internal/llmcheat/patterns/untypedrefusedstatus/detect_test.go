// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package untypedrefusedstatus

import "testing"

func TestDetect(t *testing.T) {
	t.Parallel()
	d := &detector{}
	tests := []struct {
		name, body string
		want       int
	}{
		{"untyped", "status: REFUSED\nreason: unavailable\n", 1},
		{"typed", "status: REFUSED[AUTHORITY_UNAVAILABLE]\n", 0},
		{"vocabulary mention", "Allowed values: UNKNOWN, ALIVE, REFUSED.\n", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := len(d.Detect("receipt.yml", []byte(tc.body))); got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}
}
