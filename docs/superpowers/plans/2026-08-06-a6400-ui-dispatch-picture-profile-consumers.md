# α6400 UI Dispatch and Picture Profile Consumer Plan

## Objective

Preserve the first bounded consumer searches rooted at the verified UI and Picture
Profile typed interfaces:

- determine whether `viewUnified7.so` contains a structurally exact local virtual
  dispatch through layout vtable slot 34; and
- determine whether the 14 inherited Picture Profile selection/state/setter methods
  contain a typed path to PP1-PP9 nodes or properties.

This plan is static/offline only. It does not authorize Sony code execution,
camera/USB access, device writes, package construction, flashing, raw instruction or
byte output, or key-material output.

## Task 1: UI Slot-34 Dispatch Tests and Export

Use TDD to create a fail-closed metadata contract and deterministic static exporter
that require:

- exact `viewUnified7.so` identity and source-unchanged mode;
- the five exact address points, slot cells, shared Thumb target/owner, RTTI header
  relocations, and one typed incoming address-point reference per table;
- a structural virtual-call rule that requires receiver-vptr load, slot `+0x88`
  load, and an indirect call using that loaded value within one bounded function;
- exact zero accepted local candidates;
- explicit bounded rejection metadata for the stack-based `+0x88` load and the
  PC-literal precedents without instruction text or bytes;
- exact zero direct inbound owner edges and zero direct paths from the pinned
  orientation/layout-mode roots; and
- rejection of fabricated dispatches, arbitrary pointer scans, unsafe fields,
  unpinned digests, output escape, selector/touch promotion, installation, or camera
  testing.

The report must conclude only that no local structurally exact dispatch was found;
external, cross-module, callback, and nonlocal indirect routes remain unresolved.

## Task 2: Picture Profile Generic Consumer Tests and Export

Use TDD to create a fail-closed metadata contract and deterministic static exporter
that require:

- exact `CautionConfig.so` identity and source-unchanged mode;
- the 14 exact generic method slots, relocation indices, ELF/analysis owners, symbol
  names, and bounded function sizes;
- exact zero named direct-control-flow edges out of the 14 bounded ranges;
- exact zero dynamic typed relocations and PP1-PP9 node/property references within
  those ranges;
- exact separation of the Picture Profile construction and copy-construction PLT,
  relocation, and GOT bindings;
- canonical digest linkage to the hand-off, clone, and vtable-interface artifacts;
  and
- rejection of fabricated PP bindings, selected-state/persistence/processing/output
  paths, reuse/Creative Look promotion, unsafe fields, digest forgery, and output
  escape.

The report may establish that the 14 methods are generic base-class interface code.
It must keep selected-profile state and every higher behavior claim false.

## Task 3: Review, Verification, and Next Route

Independently review both slices. Re-run exact exporters, verify source hashes before
and after, run focused and full analysis/safe tests, compile the changed modules, and
run `git diff --check`. Commit the slices separately only after clean signoff.

If both local consumer searches remain empty, continue with typed cross-module
imports/exports, resource factory registration, or exact object-construction owners.
Do not broaden to arbitrary pointer scanning or infer runtime behavior from vtable
membership alone.

Recovery remains `BLOCKED_STATIC_EVIDENCE`; neither result is installable or
camera-test eligible.
