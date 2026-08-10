# α6400 Typed Touch API Caller Plan

## Objective

Inventory a narrow, exact set of direct callers for target touch configuration and
shooting-focus coordinate APIs in `viewUnified2.so`, then test whether any known
caller is directly reachable from pinned menu or ViewStlrec roots.

This plan is static/offline only. It does not authorize Sony code execution,
camera/USB access, device or partition writes, package construction, flashing, raw
instruction or byte output, or key-material output.

## Task 1: Fail-Closed Contract Tests

Use TDD to require:

- exact `viewUnified2.so` identity and source-unchanged read-only mode;
- canonical linkage to the prior UI traversal and touchpad-terminal artifacts;
- exact decoded JUMP_SLOT/GOT/PLT bindings for the prior four touch APIs plus:
  - `setResourceTpSettings`, rel.plt index 249, GOT `0x944a90`, PLT `0x14f1b4`;
  - `getNewCoordinatesForFocusPointOnTouchPad`, index 232, GOT `0x944a4c`, PLT
    `0x14f0c8`;
- exact direct call sites and `.ARM.exidx` owner ranges for the bounded six-API
  caller set, including:
  - resource configuration owner `0x240768`, site `0x2407d0`;
  - focus-coordinate sites `0x1c17f8`, `0x1c19c6`, `0x1c5304`, `0x1c64de`,
    `0x61edb6`, `0x61eeb6`, and `0x61f4da`;
  - prior configuration/release caller sites `0x1f48da`, `0x621998`, `0x65c388`,
    `0x366564`, `0x3665d8`, `0x2038c8`, `0x621994`, `0x65c384`, `0x2bfc48`,
    `0x2c67d6`, `0x2c6a96`, `0x2c6b72`, `0x2c6d86`, `0x62199e`, and `0x65c38e`;
- explicit classification of configuration/release versus shooting-coordinate
  APIs without promoting either to menu touch behavior;
- exact scan accounting: known direct callers are limited to completely decoded
  exidx owners, while 1,593 incompletely decoded owners remain unresolved;
- direct-only depth-32 paths from `ViewSettingMenuEventSwitch` and the three pinned
  ViewStlrec roots to every known caller, with exact zero paths; and
- independent zero-target confirmation in the prior 2,046-edge UI traversal.

Keep Widget hit-testing/vtable dispatch, gesture configuration, unresolved
indirect/cross-module calls, coordinate transforms, menu hit tests, and selection
dispatch false/unresolved. Reject fabricated callers/paths, arbitrary pointer scans,
name-only behavior promotion, unsafe fields, output escape, installation, or camera
testing.

## Task 2: Deterministic Static Export and Report

Implement a read-only ELF/Capstone exporter that derives the six exact PLT bindings,
complete-owner direct caller sites/ranges, incomplete-owner accounting, caller
classification, prior-digest linkage, direct root paths, and prior-traversal target
check. Do not emit instruction text or bytes.

Write only a safe ignored raw artifact beneath a fixed repository artifact root;
reject literal, resolved, symlink, dangling-symlink, and pre-creation ancestor
escape. Commit a safe report that establishes shooting-focus coordinate
infrastructure but not a menu touch-coordinate, hit-test, or selection route.

## Task 3: Review and Verification

Independently review all PLT/GOT mappings, call sites, owner ranges, decode coverage,
classification, root traversal, prior edge cross-check, negative claims, and
containment. Re-run the exact exporter, verify source hashes before and after, run
focused and full analysis/safe tests, compile changed modules, and run
`git diff --check` before committing.

If clean, continue through a separately typed hit-test or event-resource boundary.
Recovery remains `BLOCKED_STATIC_EVIDENCE`; this result is not installable or
camera-test eligible.
