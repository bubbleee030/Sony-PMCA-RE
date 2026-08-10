# α6400 Widget Hit-Test Vtable Plan

## Objective

Establish the target-native generic widget hit-test vtable family and its one exact
RTTI-typed `LayoutableWidgetBase` boundary without inferring menu touch selection
from vtable membership alone.

This plan is static/offline only. It does not authorize Sony code execution,
camera/USB access, device or partition writes, package construction, flashing, raw
instruction or byte output, or key-material output.

## Task 1: Fail-Closed Contract Tests

Use TDD to require:

- exact `viewUnified2.so` identity and source-unchanged read-only mode;
- exact undefined dynamic symbols `WidgetBase::sys_isHit` (dynsym 1086) and
  `Widget::isHit` (dynsym 66);
- exactly 407 `R_ARM_ABS32` references to each symbol, forming 407 adjacent
  `sys_isHit`/`isHit` cells (814 records total);
- all 407 families retain consecutive named `onDump -> sys_isHit -> isHit` entries;
- the exact RTTI-backed table:
  - `_ZTI20LayoutableWidgetBase` cell ELF `0x90501c`, relocation index 89099;
  - address point ELF `0x905024` / analysis `0x915024`, relocation index 36807;
  - `sys_isHit` slot 36 at ELF `0x9050b4` / analysis `0x9150b4`, relocation index
    102061; and
  - `isHit` slot 37 at ELF `0x9050b8` / analysis `0x9150b8`, relocation index
    102468, followed by named `setHitMargin` slot 38 relocation index 102875;
- exactly 397/407 families retain named `setHitMargin` next; the ten exception
  `sys_isHit` sites are `0x92d114`, `0x92ec5c`, `0x9319ec`, `0x9324cc`,
  `0x9328bc`, `0x9384dc`, `0x93b134`, `0x93b4cc`, `0x93ca84`, and `0x93de64`;
- exactly one table has a dynamically named RTTI pointer; the other 406 headers
  remain local/untyped and must not acquire class/object identities; and
- canonical linkage to the touchpad-terminal and touch-API-caller artifacts, whose
  ordered root-path results remain empty.

Reject fabricated RTTI/class/object identity, provenance-free indirect dispatch,
menu hit-test/touch-selection/coordinate/gesture promotion, arbitrary pointer scans,
unsafe fields, output escape, installation, or camera testing.

## Task 2: Deterministic Static Export and Report

Implement a read-only ELF exporter that derives both dynamic symbols, all 814
relocations, adjacent slot families, typed RTTI row, aggregate `setHitMargin`
population/exceptions, prior digests, and unchanged source identity. Do not output
instruction text or bytes and do not scan arbitrary pointer values.

Write only a safe ignored raw artifact beneath a fixed repository artifact root;
reject literal, resolved, symlink, dangling-symlink, and pre-creation ancestor
escape. Commit a compact safe report that establishes generic target-native hit-test
infrastructure only; local widget identity and menu-selection dispatch remain
unresolved.

## Task 3: Review and Verification

Independently review symbol/relocation indices, all 407 pairs, slot numbering, RTTI
typing, ten exceptions, prior linkage, behavior claims, and containment. Re-run the
exact exporter, verify source hashes before and after, run focused and full
analysis/safe tests, compile changed modules, and run `git diff --check` before
committing.

If clean, continue from a provenance-backed virtual dispatch through slot 37 or a
typed menu widget/resource owner. Recovery remains `BLOCKED_STATIC_EVIDENCE`; this
result is not installable or camera-test eligible.
