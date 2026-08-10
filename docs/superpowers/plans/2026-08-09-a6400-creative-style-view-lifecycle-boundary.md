# α6400 Creative Style View-Lifecycle Boundary Implementation Plan

> **For agentic workers:** Use `superpowers:test-driven-development` for every
> production change and `superpowers:verification-before-completion` before
> publishing. This plan is executed in the current session; no subagents are
> authorized.

**Goal:** Add a deterministic, fail-closed report that reproduces the typed
Creative Style process-element activation substrate, both alternative view
registration rows, the conditional AppConfig table-identity implication, and
the generic event-to-loader/factory boundary.

**Architecture:** Keep cross-module lifecycle evidence in a standalone
contract/exporter. Validate the two authenticated ELF sources directly, pin
existing local-view/runtime reports as dependencies, express provider and
AppConfig joins as conditions, and reject every runtime, Creative Look,
installability, recovery, or camera promotion.

**Tech stack:** Python 3, `unittest`, pyelftools, Capstone, deterministic JSON,
Markdown, PowerShell, Git.

## Global constraints

- Work only in the current α6400 analysis worktree and branch.
- Static/offline only; never access a camera, execute Sony camera binaries,
  enter updater/service mode, write partitions, or generate installable files.
- Pin VU2 SHA-256 `1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2`
  and libObj SHA-256 `60ffd2b0f31f4bc139a7c13a4f62c25cdeb6a531ad5ef35df48471e6e36e88b1`.
- Treat all VU2-to-libObj symbol bindings as conditional.
- Treat `AppConfig.so` route selection and successful dynamic loading as
  runtime-unresolved.
- Pin corrected ViewIdSoTable singleton storage `0x14250D4` and reject
  `0x13A50D4`.
- Do not claim a selected registration row, factory invocation, returned
  ViewCreativeStyle identity, menu activation, Creative Look behavior,
  installability, recovery validation, or camera-test eligibility.
- Never stage firmware binaries, raw disassembly, keys, or reconstructive data.

## File structure

| Path | Action | Responsibility |
|---|---|---|
| `pmca/analysis/creative_style_view_lifecycle_boundary.py` | Create | Exact schema, normalizer, report builder, narrative contract, fail-closed claims. |
| `tools/static/export_a6400_creative_style_view_lifecycle_boundary.py` | Create | Read-only two-ELF static validator and deterministic exporter. |
| `tests/analysis/test_creative_style_view_lifecycle_boundary.py` | Create | Contract, real-source, mutation, transaction, and deterministic tests. |
| `analysis/a6400-creative-style-view-lifecycle-boundary.json` | Create | Checked fail-closed report. |
| `analysis/a6400a-updater-and-creative-style-deep-dive.md` | Modify | Bounded lifecycle paragraph and unresolved boundary. |

## Task 1: Define the exact fail-closed contract

### RED

- Create `tests/analysis/test_creative_style_view_lifecycle_boundary.py`.
- Add `test_expected_boundary_pins_typed_activation_and_runtime_stop` that
  imports the missing contract, normalizes `EXPECTED_EXPORT`, and asserts:
  slot 25/cell `0x90EDEC`, base ABI
  `CmnViewProcessDataElementNormal::execProcWithCondition(int)`, alias
  `view/CREATIVE_STYLE`, both component rows in order, corrected singleton
  `0x14250D4`, conditional identity true, runtime row selection false, factory
  invocation false, exact readiness, and unresolved-edge identifier.
- Run that one test and observe import failure for the missing module.

### GREEN

- Create `pmca/analysis/creative_style_view_lifecycle_boundary.py` with schema
  version 1, exact top-level fields, immutable constants, deep-copy
  normalization, deterministic report construction, and strict claim checks.
- Require an explicit `conditions` list for every conditional positive.
- Add tests rejecting unknown fields, wrong row order, stale singleton address,
  true runtime/provider/factory/Creative Look/installability/camera claims, and
  mutation of dependency digests.
- Run the contract tests green.

Production breaks caught: a lifecycle promotion, route collapse, wrong
singleton arithmetic, or an unqualified conditional identity.

## Task 2: Validate the typed VU2 activation and registration substrate

### RED

- Add a real-source exporter test that imports the missing exporter and expects
  a raw export equal to the exact normalized contract.
- Observe import failure.

### GREEN

- Create `tools/static/export_a6400_creative_style_view_lifecycle_boundary.py`.
- Validate source identity, ELF mappings, EXIDX owners, relocations, dynsym,
  PLT symbols, and exact instruction/register dataflow for:
  - typed element slot 25 and base ABI;
  - `0x489218` alias wrapper and unchanged `r1`;
  - manager lookup/condition bridge and manager vtable slot 20;
  - caller `[0x2DC1E4,0x2DC228)`, backup ID `0x003E000B`, and branch values 1/2;
  - both exact `IdSoTable::add` rows and shared receiver provenance; and
  - local `ViewCreativeStyleToInstance` dependency facts.
- Add in-memory source mutations for each operand, relocation, literal, branch,
  and call target above; require the exact static validator to reject them.
- Run focused tests green.

Production breaks caught: a row assembled from unjoined strings, a wrong vtable
slot, a rewritten branch, a clobbered caller condition, or a different table
receiver.

## Task 3: Validate conditional table identity and generic loader reachability

### RED

- Add contract tests for the exact implication steps and source mutation tests
  for the AppConfig selector, ViewConfig vptr/slot, getInstance return literal,
  wrapper table store, event literal/parameters, event handler compare,
  `dlopen`, `dlsym`, and indirect factory call.
- Observe failures because the exporter does not yet emit those sections.

### GREEN

- Validate from libObj:
  - AppConfig selector remains BSS/runtime-unresolved;
  - AppConfig's ViewConfig field and `+0x14` thunk;
  - authenticated VU2 ViewConfig RTTI/vptr and slot `+0x14` target;
  - libObj getInstance candidate return storage `0x14250D4`;
  - wrapper `+0x08` table store and same-pointer implication;
  - conditional `openView` helper Event ID `0x11012001`, destination 4, tag 0,
    key 6 resolved ID, and key 26 caller condition;
  - destination-4 event comparison; and
  - generic record lookup, `dlopen(component,0x101)`, `dlsym(factory)`, and
    indirect factory ABI.
- Keep provider binding, active row, event delivery, loader success, factory
  invocation, and returned object identity false.
- Run focused tests green and refactor shared validators only after green.

Production breaks caught: an unsupported unconditional join, stale pointer,
wrong event route, or loader facts emitted without source dataflow.

## Task 4: Publish the deterministic report and bounded prose

### RED

- Add tests requiring the checked report and deep-dive wording; observe failure
  because neither exists.

### GREEN

- Build raw export and checked report in memory, validate both, then atomically
  write them. Add a failure/no-partial-write test.
- Regenerate
  `analysis/a6400-creative-style-view-lifecycle-boundary.json`.
- Add one bounded deep-dive paragraph that distinguishes typed publication,
  alternative rows, conditional table identity, and unresolved runtime factory
  invocation.
- Add phrase guards rejecting claims of a selected row, proven runtime factory
  call, Creative Look equivalence, or camera readiness.
- Regenerate twice and compare canonical hashes.

## Task 5: Verify and publish

- Run focused lifecycle, view/model, model-request-transport, and runtime-binding
  tests.
- Run the complete analysis suite and `tests/safe` suite.
- Run `py_compile`, `git diff --check`, repository artifact/proprietary guards,
  and deterministic regeneration checks.
- Inspect every changed file and confirm no Sony binary, raw payload, key, or
  operational device instruction is staged.
- Commit intentionally in reviewable slices, push the current feature branch,
  and verify local/upstream/remote commit identity.

## Acceptance

The plan is complete when the new report is source-derived, mutation-tested,
deterministic, conditionally truthful, fully fail-closed, and published with all
gates green. It advances the static lifecycle substrate but does not complete
the wider Creative Look or recovery objective.
