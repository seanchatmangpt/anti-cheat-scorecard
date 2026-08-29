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
// subpackage (internal/llmcheat/patterns/<id>/) so detectors can be authored
// independently while this package provides the one production registration
// bridge consumed by checks/raw/anti_cheat.go.
//
// This list is regenerated from the real directories on disk (each verified
// to have a genuine detect.go, not an empty in-progress directory) — not
// hand-maintained incrementally, which is exactly how the previous version
// of this file silently fell behind: 20 real, already-committed, already
// individually-tested pattern packages existed on disk without ever being
// blank-imported here, meaning their init() never ran and they were never
// actually registered at runtime despite passing their own unit tests (which
// call the detector directly, bypassing the registry). Caught and fixed in
// the same commit that completed pattern #50 — see git history.
package patterns

import (
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/alwaystrueoracle"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/authoritytierviolation"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/claimalivewithoutreceipt"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/claimverifiedwithoutrun"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/contractsignaturedrift"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/deadalternativebranch"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/declaredinvariantnotenforced"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/duplicatenearidenticalfunction"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/emptycatchswallow"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/errormessagewrongcontext"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/fabricatedcitation"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/fixturesmuggledintoprod"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/floatingdependencyversionunpinned"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/generatedbannermissingtoolref"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/generatedfilemanualfixcomment"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/godfunctionhidesstub"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/gopanictodostub"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/gosyntaxgraphchicago"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/handeditedgeneratedfilemarker"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/hedgelanguagemasking"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/interactiononlyassertion"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/jsjestmockowned"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/lockfilechecksummismatch"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/lockfilehandeditedwithouttoolrun"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/malformedemptydoclink"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/misleadingfunctionnamevsbody"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/nonchicagoacceptancelaundering"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/nonchicagoevidence"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/nondeterministicsourceindeterministicpath"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/overclaimingsuperlative"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/placeholderloremipsum"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/pythonhollowfunction"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/pythonnotimplementedshipped"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/pythonunittestmockowned"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/rdfblanknodestatusclaim"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/receiptfilewithoutverifierreference"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/rustmockalltraitmock"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/rusttodounimplementedmacro"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/selfcontradictingstatus"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/shaclvacuousshape"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/silentdefaultfallbackmasksfailure"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/skippedtestpresentedpassing"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/sparqlselectstarindecisionquery"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/sparqlunusedselectvariable"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/standingvocabularymisuse"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/tautologicalassertion"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/teraundefinedtemplatevariable"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/tsthrownotimplemented"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/ttlclaimtriplewithoutreceipt"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/ttlprefixdeclaredunused"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/unreceipteddoaction"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/unverifiedbenchmarknumbers"
	_ "github.com/ossf/scorecard/v5/internal/llmcheat/patterns/wildcardimporthidessurface"
)
