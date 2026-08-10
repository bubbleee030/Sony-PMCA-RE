# α6400-Native Creative Look View Adapter Plan

## Objective

Add the fixed-memory view and platform-adapter layer required to use the
portable Creative Look core behind an α6400-native interface. This remains a
host-verified source implementation; no Sony view, storage, processing, or
camera binary is linked in this milestone.

## Native frame contract

- Logical coordinates use signed 32-bit milli-units (`1000` units per logical
  pixel), avoiding floating point and soft-float runtime dependencies.
- Viewports are exactly `1600 × 900` landscape or `900 × 1600` portrait.
- Catalog/base/editor/value columns remain `6/4/2/7` landscape and
  `3/3/1/5` portrait.
- One fixed 20-element frame buffer covers the largest axis picker.
- Every element carries a rectangle, kind, action, argument, value, enabled
  state, modified marker, and stable result/restriction status.

## Interaction

- Rebuild the frame from current state for every touch, so stale caller frames
  cannot dispatch an obsolete action.
- Hit-test logical milli-unit coordinates and call only the matching native-core
  transition.
- Disabled controls return their exact restriction result without changing
  state.
- Out-of-frame touches return a stable no-hit result without changing state.

## Abstract platform adapters

- A presentation callback receives a validated, stack-built frame.
- A storage callback reads/writes exactly the 164-byte core blob.
- Callback failure maps to a stable adapter error and never partially mutates
  state.
- Adapter structs contain only caller-owned context/function pointers. They
  assign no Sony class, event ID, Backup record, filesystem path, or processor.

## Verification

1. Compile core and adapter together as strict C99 host and freestanding
   objects with zero undefined symbols.
2. Compare every native element rectangle and state attribute with Python
   frames across all four screens and three orientations.
3. Drive the complete Custom-base and axis-edit workflow exclusively through
   native hit-testing.
4. Verify BW/SE, movie, and global-mode disabled controls return exact reasons.
5. Exercise presentation and persistence callbacks, including failure and
   rollback behavior.
6. Run focused, full-analysis, safety, compile, and whitespace gates before
   publication.

## Gates

Processing, recovery, camera eligibility, and installability remain false. The
adapter layer contains no camera transport, USB, Sony binary execution,
firmware packaging, updater, dynamic loading, or partition operation.
