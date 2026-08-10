# α6400 Creative Style View-Lifecycle Boundary Design

## Status and safety boundary

Approved under the standing instruction to follow the recommended static path.
This slice is static and offline. It does not authorize camera access, Sony
camera-binary execution, updater or service-mode entry, partition writes,
firmware or package generation, installation, or operational camera steps.

The wider objective remains a distinct, first-class Creative Look experience.
Creative Style is examined only as target-native lifecycle substrate; no
Creative Look equivalence or implementation readiness is inferred.

## Decision

Create a standalone, fail-closed Creative Style view-lifecycle boundary rather
than enlarging the existing view/model report. The new artifact will reproduce
the exact typed `execProcWithCondition(int)` to `openView` bridge, the two
alternative `view/CREATIVE_STYLE` registration rows, the conditional AppConfig
table-identity route, and the generic event-to-loader/factory ABI.

The artifact must keep these separate:

- statically typed UI/process-data publication;
- statically present alternative registration records;
- a conditional AppConfig and provider-binding identity join; and
- actual runtime selection, loading, factory invocation, and view activation.

Only the first two are unconditional positive evidence. The third is positive
only under explicitly named conditions. The fourth remains unproven.

## Considered approaches

### Selected: standalone lifecycle boundary

Use a dedicated contract, read-only two-ELF exporter, mutation tests, checked
report, and bounded deep-dive paragraph. This keeps conditional cross-module
binding out of the local view/model contract and gives every route-selection
and runtime claim an explicit false field.

### Rejected: extend the existing view/model report

That report owns the local `ViewCreativeStyle` type, process-data getter/setter,
five-field commit, and controller mode. Adding AppConfig, EventManager,
IdSoTable, `dlopen`, and `dlsym` would mix local ABI evidence with conditional
loader state and make review harder.

### Rejected: prose-only note

Prose would not fail if a slot, literal, registration branch, provider symbol,
or loader handoff changed. It would also make it too easy to promote a
conditional table identity into runtime invocation.

## Evidence baseline

Pinned sources are the authenticated α6400 Taiwan/region-0 2.00 modules:

- `lib/viewUnified2.so`, size 11,530,552, SHA-256
  `1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2`;
- `lib/libObj.so`, size 20,860,436, SHA-256
  `60ffd2b0f31f4bc139a7c13a4f62c25cdeb6a531ad5ef35df48471e6e36e88b1`.

Exact typed activation substrate in `viewUnified2.so`:

- `CmnViewProcessDataElementCustomCreativeStyle` vtable address point
  `0x90ED88`;
- slot 25 cell `0x90EDEC`, `.rel.dyn[40033]`, R_ARM_RELATIVE to Thumb entry
  `0x489219` / normalized `0x489218`;
- base slot 25 cell `0x906F9C`, `.rel.dyn[130362]`, R_ARM_ABS32 to
  `CmnViewProcessDataElementNormal::execProcWithCondition(int)`;
- wrapper literal cell `0x489228` and PIC add `0x48921C` resolve
  `view/CREATIVE_STYLE` at `0x7AC312`;
- call `0x489220` reaches the `viewManagerIf::openView(char const*,int)` PLT;
  the wrapper does not write `r1`, so it forwards the caller's condition.

The generic process-data manager bridge is local owner
`[0x4390BC,0x4390D4)`: it preserves input `r2` as the condition, looks up the
process element by input `r1`, and invokes element slot 25 at `0x4390CE`.
Manager vtable slot 20 cell `0x905980` points to that bridge. No typed caller
that supplies process ID 42 and a concrete condition is established.

Exact alternative registration rows are in owner `[0x40B9D4,0x40F1EC)` and
use the same retained table receiver:

- branch value 1: `view/CREATIVE_STYLE`, `viewCreativeStyle.so`,
  `ViewCreativeStyleToInstance` at add site `0x40BD76`;
- branch value 2: `view/CREATIVE_STYLE`, `viewUnified2.so`,
  `ViewCreativeStyleToInstance` at add site `0x40DBD6`.

Caller `[0x2DC1E4,0x2DC228)` obtains the receiver through
`ViewIdSoTable::getInstance`, reads backup ID `0x003E000B`, selects branch
value 1 or 2, calls the registration owner, and returns the same receiver.
The runtime backup value and active row are unresolved.

`viewUnified2.so` imports `ViewIdSoTable::getInstance`, `IdGenerator::Get`,
`IdSoTable::add`, and `viewManagerIf::openView`; `libObj.so` provides matching
default-visible definitions in the pinned pair. Because `viewUnified2.so`
does not declare `libObj.so` in DT_NEEDED and ELF interposition/load order is
not closed, those providers are candidates, not unconditional bindings.

## Conditional AppConfig table identity

The conditional chain may be reported only as an implication:

1. the runtime selector equals `AppConfig.so`;
2. the AppConfig loader successfully obtains the authenticated VU2
   `initializeViewConfig` and `getViewConfig` exports;
3. VU2's `ViewIdSoTable::getInstance` PLT binds to the pinned libObj provider;
4. AppConfig slot `+0x14` forwards through its stored ViewConfig object;
5. VU2 ViewConfig slot `+0x14` executes `[0x2DC1E4,0x2DC228)` and returns the
   exact ViewIdSoTable singleton receiver; and
6. the wrapper constructor stores that returned pointer at wrapper `+0x08`,
   the table used by the generic loader.

Under those conditions, the registration receiver and loader table are the
same pointer. The corrected libObj singleton storage is `0x14250D4`; the prior
`0x13A50D4` value was an arithmetic error and must be rejected by tests.

The selector buffer at `0x1424D78`, its runtime population, load order,
interposition, and successful dynamic calls remain unresolved. Therefore the
identity is not an unconditional startup fact.

## Generic event and loader boundary

Conditionally on `viewManagerIf::openView` binding to the pinned libObj
provider, wrapper `0x3F2BE4` reaches owner `[0x3F2B0C,0x3F2BE4)`. The owner:

- resolves the alias with `IdGenerator::Get`;
- creates Event ID `0x11012001`, destination 4, tag 0;
- adds the resolved ID under key 6 and the forwarded condition under key 26;
- pushes through the configured EventManager path.

The destination-4 handler compares Event ID `0x11012001` and calls generic
loader owner `[0x845FE8,0x84636C)`. Its record helper `[0x845E00,0x845FE8)`
obtains component and factory strings from the runtime table, calls
`dlopen(component, 0x101)`, calls `dlsym(handle, factory)`, and invokes the
resolved function pointer with `(id, context)`. No source-derived dataflow
selects either Creative Style row, proves a successful factory call, or proves
that the returned object is `ViewCreativeStyle` at runtime.

The local factory remains independently established by the existing
view/model report: `ViewCreativeStyleToInstance` allocates 0x194 bytes and
calls the local constructor. Availability is not invocation.

## Architecture

### Contract and report

`pmca/analysis/creative_style_view_lifecycle_boundary.py` owns exact constants,
normalization, report construction, narrative hashing, and fail-closed claim
validation. The checked report is
`analysis/a6400-creative-style-view-lifecycle-boundary.json`.

The report digest-pins the current view/model and runtime-binding reports. It
does not inherit positive runtime claims from either dependency.

### Read-only exporter

`tools/static/export_a6400_creative_style_view_lifecycle_boundary.py` reads only
the two pinned regular, non-symlink ELF files and the checked dependencies. It
validates exact ELF source identities before and after analysis, derives all
instruction, relocation, symbol, string, owner, and dataflow records from the
sources, builds both outputs in memory, validates them, and writes JSON only
under ignored `.artifacts` plus the checked report through atomic replacement.

### Claim boundary

Positive unconditional claims are limited to:

- typed Creative Style process-element slot-25 publication;
- typed manager lookup-to-slot-25 bridge;
- exact alternative registration rows;
- generic event-to-loader/factory ABI availability; and
- local Creative Style factory availability through the pinned dependency.

Conditional positive claims are limited to:

- AppConfig-route registration-table/loader-table pointer identity; and
- event-to-generic-loader reachability under the named provider bindings.

The following remain false: runtime branch selection, provider binding,
registration consumption, factory invocation, returned ViewCreativeStyle
identity, menu-root activation to slot 25, runtime view activation, first-class
Creative Look equivalence, renderer/output behavior, installability, recovery
validation, and camera-test eligibility.

Readiness is
`TYPED_CREATIVE_STYLE_VIEW_LIFECYCLE_SUBSTRATE_PROVEN__RUNTIME_SELECTION_AND_FACTORY_INVOCATION_UNRESOLVED`.
The first unresolved boundary is
`menu-or-process-activation-and-runtime-binding-to-selected-registration-and-factory-invocation`.

## Testing strategy

- Begin with a failing contract import test and observe RED.
- Pin slot indices, relocations, symbols, literal dataflow, branch-specific row
  arguments, provider-candidate status, corrected singleton arithmetic,
  conditional identity steps, event fields, and loader calls.
- Run one real pinned-source export.
- Mutate in-memory source bytes at each critical instruction/control site and
  require a specific exporter failure: slot-25 relocation/entry, alias PIC
  source, base ABI symbol, branch selector, both add rows, getInstance return
  literal, AppConfig thunk, ViewConfig slot, Event literal, `dlopen`, `dlsym`,
  and indirect factory call.
- Mutate every conditional/runtime claim and dependency digest and require
  report rejection.
- Regenerate twice, compare hashes, then run focused, full analysis, safety,
  compile, diff, and proprietary-artifact gates.

## Acceptance

This slice is complete when the checked report mechanically reproduces the
typed activation and registration substrate, expresses the AppConfig table
identity only as a named implication, reaches the generic loader/factory ABI,
rejects all runtime and Creative Look promotions, regenerates deterministically,
and passes the full gates. It does not complete the wider objective and cannot
authorize camera testing.
