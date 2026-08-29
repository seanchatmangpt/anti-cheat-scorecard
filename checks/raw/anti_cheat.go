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

const maxAntiCheatFileBytes = 2 << 20 // 2 MiB

var antiCheatSkipDirs = []string{
	"/vendor/", "/node_modules/", "/.git/", "/dist/", "/build/",
	"/target/", "/.next/", "/venv/", "/.venv/", "/__pycache__/",
}

// Evidence formats are intentionally scanned alongside source. In particular,
// JSON/JSONL acceptance fixtures and machine receipts are first-class inputs:
// excluding them would let a synthetic Boolean court or claim-only receipt
// evade the production Anti-Cheat check simply by using a data extension.
var antiCheatScanExtensions = map[string]bool{
	".go": true, ".py": true, ".rs": true, ".ts": true, ".tsx": true,
	".js": true, ".jsx": true, ".ex": true, ".exs": true, ".java": true,
	".rb": true, ".ttl": true, ".rq": true, ".shacl": true, ".tera": true,
	".sh": true, ".bash": true, ".toml": true, ".yml": true, ".yaml": true,
	".md": true, ".json": true, ".jsonl": true, ".txt": true,
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
			continue
		}
		content, err := io.ReadAll(io.LimitReader(reader, maxAntiCheatFileBytes))
		reader.Close()
		if err != nil {
			continue
		}
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
