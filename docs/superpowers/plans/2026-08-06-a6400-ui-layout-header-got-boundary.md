# α6400 UI Layout-Header GOT Boundary Plan

## Objective

Correctly bound the five verified `viewUnified7.so` layout-vtable-header references
as loader relocation slots and determine whether typed ELF metadata provides a
consumer, factory, resource registration, selection, or touch path.

This plan is static/offline only. It does not authorize Sony code execution,
camera/USB access, device or partition writes, package construction, flashing, raw
instruction or byte output, or key-material output.

## Task 1: Fail-Closed Contract Tests

Use TDD to create a metadata contract that requires:

- exact `viewUnified7.so` identity and source-unchanged read-only mode;
- `.got` bounds `0x71b0c–0x724f0` and the exact five unsymbolized
  `R_ARM_RELATIVE` records:
  - relocation index 1629, site `0x72288`, addend/header `0x70f10`;
  - relocation index 1633, site `0x72298`, addend/header `0x70fb0`;
  - relocation index 1684, site `0x7236c`, addend/header `0x71060`;
  - relocation index 1739, site `0x72468`, addend/header `0x71110`;
  - relocation index 1744, site `0x7247c`, addend/header `0x70e58`;
- `r_info_sym == 0`, no exact or covering dynamic object symbol for each GOT cell
  or referenced header, and exactly 194 unsymbolized relative GOT entries in the
  bounded section;
- canonical linkage to the prior layout-vtable and slot-34-dispatch artifacts;
- exact separation from nearby named `R_ARM_GLOB_DAT` imports, including the
  independent Creative Style root at site `0x72434`, relocation index 3858; and
- rejection of any inference based only on address adjacency, fabricated object or
  table membership, unsafe fields, output escape, digest forgery, installation, or
  camera testing.

The contract must keep typed consumer, factory/resource owner, orientation/layout
selector, coordinate transform, hit-test, and touch-selection claims false.

## Task 2: Deterministic Static Export and Report

Implement a read-only ELF metadata exporter that derives section bounds,
relocation indices/types/symbol indices/addends, dynamic-symbol coverage results,
the total unsymbolized relative GOT population, and the exact named neighboring
imports from the pinned source. Do not scan arbitrary pointers or treat neighboring
relocations as a record schema.

Write only a safe ignored raw artifact beneath a fixed repository artifact root;
reject literal, resolved, symlink, and dangling-symlink output-root escape. Commit a
safe report that calls this a loader/GOT metadata boundary rather than an object or
factory boundary and leaves external, nonlocal, and runtime pointer consumers
unresolved.

## Task 3: Review and Verification

Independently review the relocation indexing, symbol absence, GOT count, named
neighbor separation, prior-digest linkage, negative claims, and containment. Re-run
the exact exporter, verify source hashes before and after, run focused and full
analysis/safe tests, compile changed modules, and run `git diff --check` before
committing.

If clean, continue through typed named imports/exports or other exact resource
registrations; do not infer touch or selection from GOT adjacency. Recovery remains
`BLOCKED_STATIC_EVIDENCE`; this result is not installable or camera-test eligible.
