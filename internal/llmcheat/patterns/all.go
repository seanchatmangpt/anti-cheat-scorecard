// Copyright 2026 anti-cheat-scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package patterns is the single aggregation point for every real
// internal/llmcheat.Pattern implementation. Each pattern lives in its own
// subpackage (internal/llmcheat/patterns/<id>/) so 50 of them can be
// authored concurrently by independent agents with zero symbol-collision
// risk; this file is the one place — written and maintained centrally, not
// by any pattern-writing agent — that blank-imports every subpackage so its
// init() (which calls llmcheat.Register) actually runs.
//
// checks/raw/anti_cheat.go blank-imports this package so the real registry
// is populated before internal/llmcheat.All() is called.
package patterns

// This blank-import block is appended to as each pattern subpackage lands —
// see the per-pattern subpackages under this directory for the real
// detection logic.
