# α6400 Creative Style Root Consumer Plan

## Objective

Trace exact local consumers of the separately named
`cmnViewSettingNodeRootCreativeStyle` import in `viewUnified7.so` without treating
loader cells or symbol presence as UI-selection evidence.

This plan is static/offline only. It does not authorize Sony code execution,
camera/USB access, device or partition writes, package construction, flashing, raw
instruction or byte output, or key-material output.

## Task 1: Fail-Closed Contract Tests

Use TDD to require:

- exact `viewUnified7.so` identity and source-unchanged read-only mode;
- dynamic symbol index 544 as global/default/undefined
  `cmnViewSettingNodeRootCreativeStyle` with no PLT relocation;
- both exact `.rel.dyn` records for that symbol:
  - index 3858, `R_ARM_GLOB_DAT`, site `0x72434` in `.got`; and
  - index 3859, `R_ARM_ABS32`, site `0x805cc` in `.data`;
- exact and covering dynamic/static symbol absence at the `.data` cell, so it is
  retained only as loader-initialized untyped data;
- canonical linkage to the UI layout-header GOT-boundary artifact;
- complete coverage of 1,358 `.ARM.exidx`-bounded executable ranges in both Thumb
  and ARM modes using exact cell-address provenance through literal loads,
  PC-relative arithmetic, and MOVW/MOVT construction;
- exact zero accepted local loads/owners for both cells and zero ordered path from
  pinned layout/orientation roots; and
- rejection of fabricated consumers, unknown-base guesses, arbitrary pointer
  scans, adjacency inference, unsafe fields, output escape, digest forgery,
  installation, or camera testing.

The contract must keep Creative Style selection, layout/orientation selection,
coordinate transform, hit-test, and touch-selection claims false. External-module
and unknown-base consumers remain unresolved.

## Task 2: Deterministic Static Export and Report

Implement a read-only ELF/Capstone exporter that derives the two relocations,
symbol attributes, absence of a PLT entry, section membership, symbol coverage,
bounded executable-range count, provenance-backed accepted candidates, and prior
digest from the pinned source. Do not output instruction text or bytes.

Write only a safe ignored raw artifact beneath a fixed repository artifact root;
reject literal, resolved, symlink, and dangling-symlink output-root escape. Commit a
safe report that describes a bounded negative consumer search, not absence of all
runtime consumers.

## Task 3: Review and Verification

Independently review the relocation indices/types, symbol attributes, section and
coverage facts, range enumeration, addressing provenance, zero-result scope,
prior-digest linkage, and containment. Re-run the exact exporter, verify source
hashes before and after, run focused and full analysis/safe tests, compile changed
modules, and run `git diff --check` before committing.

If clean, continue with typed resource registrations or a cross-module owner that
can be named independently. Recovery remains `BLOCKED_STATIC_EVIDENCE`; this result
is not installable or camera-test eligible.
