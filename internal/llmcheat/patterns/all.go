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

// Package patterns is the production aggregation point for every real
// internal/llmcheat.Pattern implementation. checks/raw/anti_cheat.go blank
// imports this package, so a detector directory that is not imported here is
// dead code in the shipped Anti-Cheat check even if its package tests pass.
package patterns

import (
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/claimalivewithoutreceipt"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/claimverifiedwithoutrun"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/deadalternativebranch"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/emptycatchswallow"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/fabricatedcitation"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/fixturesmuggledintoprod"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/generatedbannermissingtoolref"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/generatedfilemanualfixcomment"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/gopanictodostub"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/handeditedgeneratedfilemarker"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/hedgelanguagemasking"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/interactiononlyassertion"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/jsjestmockowned"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/nonchicagoevidence"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/overclaimingsuperlative"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/placeholderloremipsum"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/pythonhollowfunction"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/pythonnotimplementedshipped"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/pythonunittestmockowned"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/rustmockalltraitmock"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/rusttodounimplementedmacro"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/selfcontradictingstatus"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/standingvocabularymisuse"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/tautologicalassertion"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/teraundefinedtemplatevariable"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/tsthrownotimplemented"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/unverifiedbenchmarknumbers"
)
