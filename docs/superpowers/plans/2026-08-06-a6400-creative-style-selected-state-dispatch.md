# α6400 Creative Style Selected-State Dispatch Plan

## Objective

Separate the shared product/menu-graph selector from the operational selected-item
interface inherited by `CmnViewSettingNodeCreativeStyle`. Pin the exact virtual
dispatches for selected-item lookup, state lookup, selection, unselection, and
reinitialization without promoting them into a located model value, renderer,
menu event, commit, persistence write, or first-class Creative Look path.

This plan is static/offline only. It does not authorize Sony code execution,
camera or USB access, device or partition writes, package construction, flashing,
raw instruction or byte output, or key-material output.

## Task 1: Fail-Closed Contract Tests

Use TDD to require:

- the exact α6400 2.00 `CautionConfig.so` identity and Creative Style vtable;
- the shared `BackupManager::Bkup_Read(int, void*)` PLT binding used once by the
  Creative Style and Picture Profile `_getSubNode()` selectors;
- exact argument provenance for both calls: backup ID `0x01070316` in `r0` and a
  stack-local output address in `r1`;
- explicit classification of that common read as product/menu-graph selection,
  not the current user-selected Creative Style or Picture Profile value;
- the exact 22 indirect dispatch edges made by the selected, state, set-selected,
  and update methods inherited through the Creative Style vtable;
- named table-word targets including `getSubNode`, `getSelectedItem`,
  `getSRNumById`, `getState`, `isItemSelected`, `setItemSelected`,
  `setItemUnselected`, and `init`;
- explicit negative claims for selected model-value storage and getter/setter,
  renderer binding, menu-event binding, touch routing, commit/persistence,
  Creative Look equivalence, installability, and camera-test eligibility.

Reject unsafe/reconstructive fields, output escape, direct-call promotion of
indirect edges, and any claim that the common product selector is a user setting.

## Task 2: Deterministic Static Export and Report

Implement a read-only ELF/Capstone exporter that resolves the two PLT calls,
their argument provenance, the Creative Style vtable bindings, and bounded
virtual-dispatch dataflow. Emit only structured method, table-word, receiver-role,
and call-site records; emit no instruction text or bytes.

Write only a safe ignored export beneath a fixed repository artifact root and
commit a compact report that distinguishes a real generic selected-item control
interface from the still-missing Creative Style model value and persistence path.

## Task 3: Review and Verification

Independently review the PLT identity, call arguments, vtable word numbering,
dispatch receiver roles, source stability, claims, and output containment. Re-run
the exact exporter, focused and full analysis/safe tests, Python compilation, and
`git diff --check` before committing.

If clean, pivot from the child-node selection dispatch to the model value and
commit boundary. Recovery remains `BLOCKED_STATIC_EVIDENCE`; this result is not
installable or camera-test eligible.
