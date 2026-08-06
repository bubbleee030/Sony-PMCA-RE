# α6400 UI Vtable and Picture Profile Interface Plan

## Objective

Preserve two newly established typed-interface boundaries and use them as the next
safe roots for static selector/state research:

1. the unnamed vertical-layout forwarding owner is virtual slot 34 in five exact
   RTTI-backed `LG_viewtridial` layout vtables; and
2. Picture Profile clone and inherited selection/state methods occupy exact typed
   slots in the `CmnViewSettingNodePictureProfile` vtable.

The work remains static and offline. It does not authorize Sony camera-binary
execution, camera/USB access, device or partition writes, packaging, flashing, or
printing proprietary bytes, disassembly, or key material.

## Task 1: UI Vtable Contract Tests

Create fail-closed tests that require:

- exact `viewUnified7.so` identity and read-only/source-unchanged mode;
- five exact RTTI class names and RTTI, vtable-header, address-point, end, and
  registration addresses;
- typed relocation evidence for every accepted vtable header/slot;
- exact zero-based slot 34 targeting Thumb `0x529cd`, normalized owner `0x529cc`;
- bounded typed metadata for adjacent slots 32, 33, and 35;
- rejection of arbitrary pointer scans, incomplete/overlapping tables, forged RTTI,
  reordered membership, bytes/disassembly/device/write fields, unsafe output paths,
  unpinned digests, and selector/touch promotion; and
- all installability and camera-test flags false.

Capture the expected failing tests before implementation.

## Task 2: UI Vtable Export and Report

Implement a deterministic ELF metadata exporter using `.rel.dyn`, dynamic symbols,
RTTI records, section membership, and file-backed `PT_LOAD` addends. Every table
boundary must be reconstructed from typed evidence; do not accept an integer merely
because it resembles a function pointer.

The report may establish:

- `common_layout_virtual_dispatch_hook_found=true`;
- five exact target-native layout interface types; and
- the existing vertical factory and forwarding owner.

It must keep orientation/layout object selection, coordinate transformation, touch
hit testing, touch selection, installability, and camera-test eligibility false.
Conclude only that a common virtual dispatch hook exists; no ordered state-to-object
selection path is established.

## Task 3: Picture Profile Interface Contract Tests

Create fail-closed tests that require:

- exact `CautionConfig.so` identity and read-only/source-unchanged mode;
- exact vtable identity: ELF `0xb01d20`, analysis `0xb11d20`, `STT_OBJECT`, 268
  bytes/67 words, with 66 typed `.rel.dyn` records;
- exact clone relocation index, slot/offset, virtual index, symbol, Thumb target,
  normalized owner, and function size;
- exact adjacent update/init/getSubNode typed slots;
- exact inherited selected-item/state/set-selected slot groups, retained only as
  generic interface metadata;
- the single exact `R_ARM_GLOB_DAT` relocation naming the vtable;
- exact constructor/copy-constructor aliases; and
- rejection of fabricated PP1-PP9 bindings, selected-slot paths, persistence,
  processing/output paths, interface/state reuse, Creative Look promotion, unsafe
  fields, unpinned digests, and escaping output.

Capture the expected failing tests before implementation.

## Task 4: Picture Profile Interface Export and Report

Implement a deterministic ELF metadata exporter. Reuse the prior clone and hand-off
artifacts only through their canonical normalizers and pinned digests. Record no
arbitrary pointer values or instruction text.

The report may establish that clone, generic selection/state methods, and the
Picture Profile vtable are linked as typed interface metadata. It must not claim
that the inherited generic methods select PP1-PP9, that state is reusable for
Creative Look, or that persistence/processing/output behavior exists.

## Task 5: Review and Verification

Independently review each slice, rerun both exporters against the pinned local ELF
files, confirm source hashes before and after, run focused tests, then all analysis
and safe tests, compile affected modules, and run `git diff --check`. Commit the UI
and Picture Profile slices separately only after clean signoff.

## Next Decision

- For UI, trace only indirect calls whose object/vtable evidence resolves to the
  five exact slot-34 entries, then require an ordered path from a pinned orientation
  or layout-mode root before promoting selection.
- For Picture Profile, trace typed consumers of the vtable GOT or inherited generic
  selection slots and require an exact path to a PP1-PP9 node/global before claiming
  selected-profile state.
- If either trace stops at unresolved indirect dispatch, preserve the terminal and
  move to typed cross-module/resource registration; do not fall back to arbitrary
  pointer scanning.

External recovery remains `BLOCKED_STATIC_EVIDENCE`, and no result under this plan
is installable or camera-test eligible.
