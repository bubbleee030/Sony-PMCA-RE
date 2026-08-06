# α6400 Creative Style Registry Consumer Plan

## Objective

Establish the exact 415-entry default setting-root registry containing Creative
Style and bound its cross-module data publications without promoting data
relocations to typed selector, state, persistence, or Creative Look calls.

This plan is static/offline only. It does not authorize Sony code execution,
camera/USB access, device or partition writes, package construction, flashing, raw
instruction or byte output, or key-material output.

## Task 1: Fail-Closed Contract Tests

Use TDD to require:

- exact identities for `CautionConfig.so`, `viewUnified2.so`, `viewUnified4.so`, and
  `viewUnified7.so`, plus source-unchanged read-only mode;
- a globally sorted bounded inventory over firmware `lib`, `bin`, `sabin`, and
  `sbin`: 799 regular files, 324 ELF files, and 150 shared objects, with a canonical
  inventory digest;
- exact global STT_OBJECT dynsym 11778 `cmnViewSettingNodesRootDefault` at ELF
  `0xb8a380`, size 1660, `.data`;
- exactly 415 `R_ARM_ABS32` records whose sites, sorted by address, cover every
  4-byte registry offset `0x0–0x678`; relocation indices are not required to be
  contiguous and must retain their source-derived min/max/order;
- all 415 targets are distinct defined global STT_OBJECT symbols named
  `cmnViewSettingNodeRoot*`, each size 40;
- Creative Style is exact registry slot 15 / offset `0x3c`, relocation index 87605,
  site `0xb8a3bc`, target dynsym 31507 `cmnViewSettingNodeRootCreativeStyle`;
- only the four exact modules above reference the registry or Creative Style
  globals in the bounded inventory;
- exact cross-module relocation inventories:
  - `viewUnified2.so`: registry dynsym 392/GLOB_DAT index 130801/GOT `0x948aa0`;
    Creative Style dynsym 901/GLOB_DAT index 130926/GOT `0x94b674`, plus 51
    `R_ARM_ABS32` `.data` records at indices 130927–130977;
  - `viewUnified4.so`: Creative Style dynsym 1113 plus six `R_ARM_ABS32` `.data`
    records at indices 29687–29692; and
  - `viewUnified7.so`: Creative Style dynsym 544, GLOB_DAT index 3858/GOT
    `0x72434`, and ABS32 index 3859/`.data` `0x8056c`;
- zero JUMP_SLOT/PLT relocation for either registry global in every bounded module;
- zero exact/covering dynsym/symtab ownership for the consumer ABS32 data cells; and
- canonical linkage to the Creative Style definition and root-consumer artifacts.

Reject inferred direct callers, selector/state/persistence/processing/output paths,
Creative Look promotion, arbitrary pointer scans, unsafe fields, output escape,
installation, or camera testing.

## Task 2: Deterministic Static Export and Report

Implement a read-only ELF exporter that derives the inventory, registry schema,
target symbol attributes, Creative Style slot, four-module reference scope,
cross-module relocation inventories, PLT absence, cell symbol coverage, prior
digests, and unchanged source identities. Do not rely on relocation index
contiguity or address adjacency alone.

Write only a safe ignored raw artifact beneath a fixed repository artifact root;
reject literal, resolved, symlink, dangling-symlink, and pre-creation ancestor
escape. Commit a compact safe report that establishes a typed registry and data
publication only; indirect data-cell consumers remain unresolved.

## Task 3: Review and Verification

Independently review inventory scope/digest, all 415 registry entries, Creative slot,
module inventories, symbol coverage, PLT absence, prior linkage, negative claims,
and containment. Re-run the exact exporter, verify all source hashes before and
after, run focused and full analysis/safe tests, compile changed modules, and run
`git diff --check` before committing.

If clean, continue only from a provenance-backed data-cell load or selector/state
dispatch. Recovery remains `BLOCKED_STATIC_EVIDENCE`; this result is not installable
or camera-test eligible.
