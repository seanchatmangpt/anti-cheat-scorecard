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

package raw

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/internal/llmcheat"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns" // registers every pattern via init()
)

// maxAntiCheatFileBytes bounds how much of any single file is read for
// pattern scanning. Generated lockfiles, vendored bundles, and other huge
// non-authored files are exactly the kind of thing a hand-written cheat
// pattern would never appear in, and reading them in full would dominate
// scan wall-clock for zero real detection value.
const maxAntiCheatFileBytes = 2 << 20 // 2 MiB

// antiCheatSkipDirs are path segments that never contain hand-authored
// source worth scanning for cheat patterns — vendored/generated/build output.
var antiCheatSkipDirs = []string{
	"/vendor/", "/node_modules/", "/.git/", "/dist/", "/build/",
	"/target/", "/.next/", "/venv/", "/.venv/", "/__pycache__/",
}

// antiCheatScanExtensions are the file extensions worth running pattern
// detectors against. Deliberately broad across languages and evidence/report
// formats: fabricated standing often lives in receipts, logs, SARIF, JSON,
// or prose rather than in application source.
var antiCheatScanExtensions = map[string]bool{
	".go": true, ".py": true, ".rs": true, ".ts": true, ".tsx": true,
	".js": true, ".jsx": true, ".ex": true, ".exs": true, ".java": true,
	".rb": true, ".ttl": true, ".rq": true, ".shacl": true, ".tera": true,
	".sh": true, ".bash": true, ".toml": true, ".yml": true, ".yaml": true,
	".md": true, ".txt": true, ".log": true, ".json": true, ".jsonl": true,
	".sarif": true,
}

func shouldScanForAntiCheat(path string) (bool, error) {
	slashed := "/" + filepath.ToSlash(path) + "/"
	for _, skip := range antiCheatSkipDirs {
		if strings.Contains(slashed, skip) {
			return false, nil
		}
	}
	return antiCheatScanExtensions[strings.ToLower(filepath.Ext(path))], nil
}

// AntiCheat retrieves the raw data for the Anti-Cheat check: it walks every
// non-vendored, non-generated text file in the repository via the real
// RepoClient (github/gitlab/localdir — all three, since llmcheat patterns
// depend on nothing but file content) and runs every registered
// internal/llmcheat pattern detector against each one.
func AntiCheat(c *checker.CheckRequest) (checker.AntiCheatData, error) {
	paths, err := c.RepoClient.ListFiles(shouldScanForAntiCheat)
	if err != nil {
		return checker.AntiCheatData{}, fmt.Errorf("listing files for anti-cheat scan: %w", err)
	}

	patterns := llmcheat.All()
	var matches []checker.AntiCheatMatch

	for _, path := range paths {
		reader, err := c.RepoClient.GetFileReader(path)
		if err != nil {
			// A file listed but unreadable (broken symlink, race with a
			// concurrent checkout mutation) is skipped, not fatal — this
			// mirrors how the other raw collectors in this directory treat
			// individual unreadable files, and a hard-abort here would let
			// one broken symlink hide every other file's real findings.
			continue
		}
		content, err := io.ReadAll(io.LimitReader(reader, maxAntiCheatFileBytes))
		reader.Close()
		if err != nil {
			continue
		}
		// A binary file that slipped past the extension filter (rare, but a
		// mislabeled extension is real) is skipped rather than scanned —
		// pattern detectors are text/regex-shaped and a NUL byte is the
		// standard cheap binary signal.
		if bytes.IndexByte(content, 0) != -1 {
			continue
		}

		for _, p := range patterns {
			for _, m := range p.Detect(path, content) {
				matches = append(matches, checker.AntiCheatMatch{
					PatternID: m.PatternID,
					Category:  m.Category,
					Path:      m.Path,
					Line:      m.Line,
					Message:   m.Message,
					Severity:  string(m.Severity),
				})
			}
		}
	}

	return checker.AntiCheatData{Matches: matches}, nil
}
