# α6400 Picture Profile Initializer Registration Plan

## Objective

Trace the narrow typed loader-registration boundary that owns the verified PP1–PP9
construction references after the inherited generic selection/state/setter bodies
proved empty of local PP consumers.

This plan is static/offline only. It does not authorize Sony code execution,
camera/USB access, device or partition writes, package construction, flashing, raw
instruction or byte output, or key-material output.

## Task 1: Fail-Closed Contract Tests

Use TDD to create a metadata contract that requires:

- exact `CautionConfig.so` identity and source-unchanged read-only mode;
- `.init_array` at ELF `0xaa6290`, size 24, with six exact typed
  `R_ARM_RELATIVE` entries and normalized Thumb owners;
- entry/relocation index 3 at `0xaa629c`, Thumb target `0x8251f9`, ELF owner
  `0x8251f8`, and analysis owner `0x8351f8`;
- the exact `.ARM.exidx` owner range `0x8251f8–0x93aff4` with both ELF and analysis
  coordinates;
- canonical linkage to the prior handoff and generic-consumer artifacts, including
  the 18 PP1–PP9 constructor-parameter references all owned by analysis
  `0x8351f8`;
- a bounded typed dynamic-symbol scan of regular ELF files under firmware `lib`,
  `bin`, `sabin`, and `sbin`, with a canonical inventory identity digest; only
  `CautionConfig.so` may define the exact Picture Profile class/node/property names,
  and no direct named cross-module import may be reported;
- exact system-only `DT_NEEDED` results and no exact Picture Profile symbol whose
  name combines persistence verbs such as save/load/store/persist/read/write; and
- rejection of fabricated registration/state paths, arbitrary pointer scans,
  unsafe fields, output escape, digest forgery, installation, or camera testing.

The contract must distinguish loader registration of a broad construction batch
from selection state, UI dispatch, persistence, image processing, and output.

## Task 2: Deterministic Static Export and Report

Implement a read-only ELF metadata exporter using local parsing dependencies. Pin
the exact initializer relocation records, prior-artifact digests, bounded ELF scan
scope, inventory digest, named-symbol result, and unchanged source identities.

Write only a safe ignored raw artifact beneath a fixed repository artifact root.
Reject literal, resolved, symlink, and dangling-symlink output-root escape. Commit a
safe report with readiness `STATIC_CONSTRUCTION_REGISTRATION_ONLY`, all higher
behavior claims false, and an explicit statement that the broad initializer range
does not establish a selected-state or Creative Look path.

## Task 3: Review and Verification

Independently review the typed initializer mapping, cross-module scan scope,
inventory digest, negative claims, and containment behavior. Re-run the exact
exporter, verify source hashes before and after, run focused and full analysis/safe
tests, compile changed modules, and run `git diff --check` before committing.

If clean, continue from typed registration consumers or indirect vtable callers.
Do not return to the empty generic method bodies or broaden into arbitrary pointer
scanning. Recovery remains `BLOCKED_STATIC_EVIDENCE`; this result is not installable
or camera-test eligible.
