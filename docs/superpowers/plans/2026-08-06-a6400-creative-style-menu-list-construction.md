# α6400 Creative Style Menu-List Construction Plan

## Objective

Establish whether the 51 `cmnViewSettingNodeRootCreativeStyle` references in
`viewUnified2.so` participate in concrete menu composition by identifying exact
root-pointer spans passed to the imported `CmnViewSettingNode` constructor. Bound
the owning startup initializers and the `ViewStlrec` virtual-table owner without
promoting list membership into selected-value, rendering, touch, commit, or
persistence behavior.

This plan is static/offline only. It does not authorize Sony code execution,
camera or USB access, device or partition writes, package construction, flashing,
raw instruction or byte output, or key-material output.

## Task 1: Fail-Closed Contract Tests

Use TDD to require:

- exact `viewUnified2.so` identity and canonical links to the Creative Style
  definition-registration and registry-consumer reports;
- 6,824 root-pointer `R_ARM_ABS32` relocations, 321 maximal contiguous relocation
  runs, 51 Creative Style occurrences across 47 runs, while explicitly refusing
  to treat maximal relocation runs as constructor-sized arrays;
- the exact `CmnViewSettingNode::CmnViewSettingNode(CmnViewSettingNode**, int,
  CmnViewSettingProperties const*)` dynamic binding at PLT `0x154024`;
- three provenance-backed constructor calls with `r1` loaded through the pinned
  GOT cell, `r2` equal to the exact list size, and null `r3`:
  `0x1d9f88` using four roots at `0x951284`, `0x62b3c4` using four roots at
  `0xb068d8`, and `0x65be9c` using two roots at `0xb06910`;
- exact list members and relocation identities: White Balance, ISO Sensitivity,
  Creative Style, and Picture Effect Wheel for both four-entry lists; White
  Balance and Creative Style for the two-entry list;
- exact object-storage provenance in `r0` for all three constructor calls;
- exact local definition sites for `r0` through `r3`, with each six-site
  preparation/call chain reachable and joined by direct fallthrough with unique
  predecessors in the bounded intra-owner CFG;
- two complete 196-byte, 87-item startup initializer owners referenced from
  `.init_array` cells `0x8b5640` and `0x8b5648`;
- the `ViewStlrec` single-inheritance RTTI object and its base link to
  `ViewBaseForMR`, followed by the actual vtable header, address point `0x8ded90`,
  slot 61 target `0x1ccda8`, the relocation shape of the observed slot-0-through-61
  prefix with the later table end left unestablished, and the complete
  exception-index owner that contains the first constructor site, without
  assigning semantics to the unnamed slot override;
- explicit negative claims for selected-state lookup, renderer binding, touch
  routing, commit/persistence, Creative Look equivalence, installability, and
  camera-test eligibility.

Reject unsafe fields, output escape, inferred list boundaries from mere relocation
adjacency, runtime behavior claims, arbitrary-pointer scans, or cross-module
absence claims.

## Task 2: Deterministic Static Export and Report

Implement a read-only ELF/Capstone exporter that derives root-relocation
inventory, the constructor binding, exact call-argument provenance, list members,
startup-owner completeness, and the bounded `ViewStlrec` RTTI/table shape. Emit no
instruction text or bytes.

Write only a safe ignored export beneath a fixed repository artifact root; reject
literal, resolved, symlink, dangling-symlink, and pre-creation ancestor escape.
Commit a compact report that distinguishes constructor-bounded list sizes from
larger contiguous relocation runs.

## Task 3: Review and Verification

Independently review constructor argument flow, list boundaries, relocation and
section identities, owner completeness, vtable classification, claims, and output
containment. Re-run the exact exporter, verify the source hash before and after,
run focused and full analysis/safe tests, compile changed Python modules, and run
`git diff --check` before committing.

If clean, treat this as concrete menu-composition evidence and pivot to the
selected-state/value consumer path. Recovery remains `BLOCKED_STATIC_EVIDENCE`;
this result is not installable or camera-test eligible.
