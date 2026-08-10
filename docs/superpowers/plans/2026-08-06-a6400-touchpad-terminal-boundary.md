# α6400 Touchpad Terminal Boundary Plan

## Objective

Refine the existing `ViewSettingMenuEventSwitch` “touchpad reconfiguration” path
so only independently verified direct/typed edges are retained, and determine
whether its terminal owners reach any exact touch API, coordinate transform,
hit-test, gesture, or selection dispatcher.

This plan is static/offline only. It does not authorize Sony code execution,
camera/USB access, device or partition writes, package construction, flashing, raw
instruction or byte output, or key-material output.

## Task 1: Fail-Closed Contract Tests

Use TDD to require:

- exact `viewUnified2.so` identity and source-unchanged read-only mode;
- canonical linkage to UI graph artifact digest
  `d19fc94fd52583f3d321535fd8b6a01aa03f4efc0c4dadde52adce3a9d246f22`;
- only the two independently verified path edges:
  - owner `0x22355e`, site `0x223b36` -> `0x21c644`; and
  - owner `0x21c644`, site `0x21c770` -> `0x1626cc`;
- exact `.ARM.exidx` ranges for the four bounded terminal owners:
  `0x162608–0x162760`, `0x41b244–0x41b290`, `0x41add8–0x41ae68`, and
  `0x2b3f7c–0x2b3f98`, with no dynamic-symbol identity or relocation inside any
  range;
- the one exact narrow internal edge at site `0x41b24e` from owner `0x41b244` to
  `0x2b3f7c`, whose callee has zero direct calls;
- zero unsymbolized `R_ARM_RELATIVE` reverse references whose addend equals any of
  the four owner starts across all 137,966 `.rel.dyn` entries;
- exact PLT/JUMP_SLOT metadata for these four APIs:
  - `InputService::forceReleaseTp`, rel.plt index 43, GOT `0x944758`, PLT `0x14e6c8`;
  - `InputService::setTpEnableArea`, index 154, GOT `0x944914`, PLT `0x14ecac`;
  - `CmnViewTPAreaEnableUtil::setTouchPadEnableAreaToOff`, index 1730, GOT
    `0x9461b4`, PLT `0x15404c`;
  - `CmnViewTPAreaEnableUtil::setTouchPadEnabAreaForEvfOn`, index 2101, GOT
    `0x946780`, PLT `0x1553f4`;
- complete bounded Thumb decoding of those four owner ranges with exact zero direct
  calls to any of the four PLT targets; and
- rejection of fabricated final path links, vtable/object ownership, named touch
  calls, coordinate/hit-test/selection promotion, unsafe fields, output escape,
  installation, or camera testing.

The prior path label may remain historical context only. The new report must state
that its final two links are not independently proven and that no specific touch
configuration or menu-touch behavior is established at this boundary.

## Task 2: Deterministic Static Export and Report

Implement a read-only ELF/Capstone exporter that derives the path-edge subset,
function ranges, relocation absence, reverse-reference population/result, internal
edge, decoded PLT bindings, and zero direct-call result from the pinned source and
prior artifact. Do not emit instruction text or bytes.

Write only a safe ignored raw artifact beneath a fixed repository artifact root;
reject literal, resolved, symlink, and dangling-symlink output-root escape. Commit a
safe report that leaves touch configuration, coordinate transform, hit-test,
gesture, selection/state dispatch, and all higher UI behaviors false.

## Task 3: Review and Verification

Independently review every edge site, range, relocation count, PLT mapping, decoder
coverage, prior digest, negative claim, and containment gate. Re-run the exact
exporter, verify source hashes before and after, run focused and full analysis/safe
tests, compile changed modules, and run `git diff --check` before committing.

If clean, continue only through a separately typed input-event/resource boundary.
Recovery remains `BLOCKED_STATIC_EVIDENCE`; this result is not installable or
camera-test eligible.
