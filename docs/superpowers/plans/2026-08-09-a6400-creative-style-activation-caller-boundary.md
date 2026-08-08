# α6400 Creative Style Activation-Caller Boundary Implementation Plan

> Execute this plan test-first and keep every claim bounded to authenticated,
> read-only static evidence. Do not access a camera, execute Sony binaries, or
> create updater/package/flash artifacts.

**Goal:** Reproduce the concrete VU2 process-data manager singleton and
manager-slot-20 ABI, inventory every canonical slot-`0x50` call in fully
decoded VU2 exidx owners, and fail closed because none proves manager receiver
identity plus process ID 42 and condition provenance.

**Architecture:** Add a standalone analysis contract and a read-only ELF
exporter that consumes the checked view-lifecycle report as a digest-pinned
dependency. The exporter validates source bytes, relocations, owner ranges,
manager accessor/constructor dataflow, the exact canonical call inventory, and
bounded direct-inbound counts. The normalized report retains all incomplete,
indirect, noncanonical, and runtime paths as unresolved.

**Tools:** Python 3, `unittest`, pyelftools, Capstone, repository static-analysis
helpers, JSON, SHA-256, and `apply_patch`.

---

## Task 1: Add the failing contract and report tests

**Files:**

- Create: `tests/analysis/test_creative_style_activation_caller_boundary.py`
- Create: `pmca/analysis/creative_style_activation_caller_boundary.py`

1. Write a contract test that imports the future module and asserts:
   source SHA/size, lifecycle dependency digest, manager object `0xB06BB0`,
   manager vptr `0x905930`, manager bridge `0x4390BC`, typed wrapper
   `0x489218`, 28,869 complete owners, 1,594 incomplete/terminal owners,
   16 canonical sites, zero accepted candidates, and the exact unresolved
   readiness value.
2. Write report mutation cases that promote caller, menu activation, factory,
   Creative Look, installability, recovery, or camera eligibility and require
   rejection. Include a contradictory narrative mutation.
3. Run:

   `python -m unittest -v tests.analysis.test_creative_style_activation_caller_boundary`

   Expected RED: import/module or required-field failure.
4. Implement only the fail-closed contract constants, normalizer, report
   builder, validator, canonical JSON digest helper, and narrative digest.
5. Rerun the focused test. Expected: contract-level tests pass while exporter
   tests remain absent.

## Task 2: Add failing manager singleton and bridge exporter tests

**Files:**

- Modify: `tests/analysis/test_creative_style_activation_caller_boundary.py`
- Create: `tools/static/export_a6400_creative_style_activation_caller_boundary.py`

1. Write a real-source exporter test guarded by dependency/source availability.
2. Write in-memory source mutations for:
   singleton instance GOT relocation/cell, accessor constructor receiver or
   call, accessor return register, manager vtable-header GOT cell, constructor
   vptr store, manager slot-20 relocation/cell, and typed slot-25 dependency.
3. Run the focused test and observe RED because the exporter/validators are
   missing.
4. Implement source/dependency loading and exact validators using existing
   static helpers. Require:
   - source SHA-256 and size;
   - lifecycle report validation and canonical digest;
   - accessor owner, PIC base, guard/instance GOT relocations, retained receiver
     into constructor and return;
   - manager constructor owner, vtable GOT relocation, `+8` address point, and
     offset-zero store; and
   - manager/typed vtable cells and owner targets.
5. Rerun focused tests. Expected: singleton/bridge tests pass.

## Task 3: Add failing bounded caller-inventory tests

**Files:**

- Modify: `tests/analysis/test_creative_style_activation_caller_boundary.py`
- Modify: `tools/static/export_a6400_creative_style_activation_caller_boundary.py`
- Modify: `pmca/analysis/creative_style_activation_caller_boundary.py`

1. Add expected exact records for the 16 canonical calls, including owner
   start/end, vptr-load site, slot-load site, call site, receiver register, and
   provenance booleans.
2. Add tests for 28,869 fully decoded and 1,594 incomplete/terminal owners,
   zero accepted candidates, direct inbound count zero for `0x4390BC` and
   `0x489218`, and explicit incomplete scan scope.
3. Add a source mutation that changes one canonical `+0x50` slot operand and
   require inventory mismatch. Add a control-transfer mutation at one call and
   require rejection.
4. Run focused tests and observe RED because the scan is not implemented.
5. Implement the exact matcher:
   `[receiver+0] -> vptr`, `[vptr+0x50] -> call register`, then `BLX` of that
   register, with register-write rejection between steps.
6. Implement bounded provenance classification. Accept only exact manager
   object/accessor receiver, vptr, ID 42, and condition provenance. The baseline
   must yield zero accepted candidates.
7. Implement direct-inbound scans with the completeness flag preserved.
8. Rerun focused tests. Expected: all focused exporter and mutation tests pass.

## Task 4: Generate and pin the checked report

**Files:**

- Modify: `tools/static/export_a6400_creative_style_activation_caller_boundary.py`
- Create: `analysis/a6400-creative-style-activation-caller-boundary.json`
- Modify: `tests/analysis/test_creative_style_activation_caller_boundary.py`

1. Add deterministic raw-export/report generation. Build and validate all data
   before either write, then use temporary files plus atomic replace.
2. Generate the ignored raw artifact under
   `.artifacts/creative-style-activation-caller-boundary/a6400-v2.00/` and the
   checked report under `analysis/`.
3. Add checked-report validation, raw/report digest, deterministic rerun, and
   failure-before-write tests.
4. Run the focused test and regenerate twice. Expected: byte-identical outputs.

## Task 5: Update the deep-dive boundary

**Files:**

- Modify: `analysis/a6400a-updater-and-creative-style-deep-dive.md`
- Modify: `tests/analysis/test_creative_style_activation_caller_boundary.py`

1. Add one bounded paragraph after the existing lifecycle discussion. State:
   concrete manager object/vptr, exact fully decoded/incomplete counts, exact
   16-site canonical inventory, zero accepted ID-42 manager candidates, and the
   non-whole-program scope.
2. Explicitly preserve false menu activation, runtime view/factory, Creative
   Look, output, installability, recovery, and camera eligibility claims.
3. Add positive phrase assertions and reject stale/promotional phrases.
4. Run the focused test. Expected: PASS.

## Task 6: Verify the slice and repository

**Files:**

- Verify all files above.

1. Run focused activation-caller tests.
2. Run the view-model, lifecycle, interaction, selector, transport, runtime,
   recovery/transition, decisions, and safety suites that share claims.
3. Run the complete analysis suite:

   `python -m unittest discover -s tests\analysis`

4. Run the complete safety suite:

   `python -m unittest discover -s tests\safe`

5. Run `python -m py_compile` on every new/modified Python file.
6. Regenerate the report twice and compare SHA-256 values.
7. Run `git diff --check`, inspect `git status --short`, and confirm no firmware
   source, device path, updater command, key material, or package artifact is
   tracked.

## Task 7: Commit and push the verified milestone

1. Review the final diff and commit only the intended contract, exporter,
   tests, report, docs, and design/plan files.
2. Use a concise evidence-oriented commit message.
3. Push `feature/a6400-updater-re-lab` to origin.
4. Verify local HEAD, upstream tracking SHA, and remote branch SHA match.
5. Do not open a PR unless separately requested.
