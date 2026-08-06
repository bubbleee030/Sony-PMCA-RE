# α6400 Orientation Object/Table Boundary Plan

## Objective

Establish the exact initializer chain and offset-zero table stores for the stable
orientation/AF object at `0xb2eff4`, compare both stored targets against the
previously pinned Widget-compatible address points, and bound storage consumers
within the complete helper prefix. Determine whether this object provides concrete evidence for menu
touch/UI routing without promoting incomplete graph coverage.

This plan is static/offline only. It does not authorize Sony code execution,
camera/USB access, device or partition writes, package construction, flashing,
raw instruction or byte output, or key-material output.

## Task 1: Fail-Closed Contract Tests

Use TDD to require:

- exact `viewUnified2.so` identity and canonical linkage to the generic slot-37
  dispatch and orientation/AF helper artifacts;
- the complete local initializer owner `0x30e9cc..0x30e9e8`, with 28 bytes, 14
  decoded items, no calls, and one final offset-zero store at `0x30e9da`;
- the complete derived initializer owner `0x30e9e8..0x30ea0c`, with 36 bytes, 17
  decoded items, the direct base call `0x30e9f0->0x30e9cc`, and one final
  offset-zero overwrite at `0x30e9fe`;
- exact source-cell identities: `.got` `0x949d70`, `R_ARM_RELATIVE` relocation
  index 57,459, and target `0x8e6118` in `.data.rel.ro` for the base store; `.got`
  `0x94c1f4`, `R_ARM_RELATIVE` relocation index 59,685, and target `0x8e6228` in
  `.data.rel.ro` for the derived overwrite;
- zero matches for both stored targets against all 407 pinned Widget-compatible
  table address points;
- exact RTTI identities: base `AfOrientImpl` typeinfo `0x8e6108` and address
  point `0x8e6118`; derived `AfImplForOrientationRegisterAF` typeinfo
  `0x8e6360`, relocation-backed base-type link to `0x8e6108`, and address point
  `0x8e6228`;
- two 66-slot vtable windows: the abstract base has 63 named
  `__cxa_pure_virtual` references plus three relative relocations, while the
  derived table has 67 relative relocations including RTTI;
- the derived slot-37 cell `0x8e62bc`, `R_ARM_RELATIVE` relocation index 20,029,
  and local target `0x30c578`, with no defined dynamic-symbol name;
- exact direct guard/object materialization, offset-zero load, initializer call,
  unresolved subsequent receiver calls, and the bounded storage-consumer digest
  `d45002a0c1e392f1958022bc6ee86e636d0a6d3c1646a1c35953910a1a762984`;
- explicit scope limited to the complete `0x35f424..0x35f470` helper prefix and
  refusal to infer storage-to-UI, focus-coordinate, or Creative Style paths from
  this slice or across modules.

Reject claims of Widget identity, hit-test behavior, touch routing, menu selection,
transitive graph absence, unrelated table provenance, arbitrary pointer scans,
unsafe fields, output escape, installation, or camera testing.

## Task 2: Deterministic Static Export and Report

Implement a read-only ELF/Capstone exporter that derives the two complete
initializer records, table-source relocations, Widget-address-point comparison,
bounded relocation shape, helper-prefix storage-consumer inventory, and conservative
direct graph results. Emit no instruction text or bytes.

Write only a safe ignored raw artifact beneath a fixed repository artifact root;
reject literal, resolved, symlink, dangling-symlink, and pre-creation ancestor
escape. Commit a compact report that records the AF-specific base/derived
vtables, the local derived slot-37 target, and the negative Widget match.

## Task 3: Review and Verification

Independently review store provenance, initializer completeness, relocation and
section identity, table comparison, consumer inventory, graph limits, claims, and
containment. Re-run the exact exporter, verify the source hash before and after,
run focused and full analysis/safe tests, compile changed modules, and run
`git diff --check` before committing.

If clean, treat the orientation/AF helper as a bounded false lead for concrete
menu touch and pivot to the selected-state/menu consumer path. Recovery remains
`BLOCKED_STATIC_EVIDENCE`; this result is not installable or camera-test eligible.
