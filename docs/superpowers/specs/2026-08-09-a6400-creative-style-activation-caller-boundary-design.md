# α6400 Creative Style Activation-Caller Boundary Design

## Status and safety boundary

Approved under the standing instruction to follow the recommended static path.
This slice is static and offline. It does not authorize camera access, Sony
camera-binary execution, updater or service-mode entry, partition writes,
firmware or package generation, installation, or operational camera steps.

The wider objective remains a distinct, first-class Creative Look experience.
Creative Style is examined only as target-native lifecycle substrate; no
Creative Look equivalence or implementation readiness is inferred.

## Decision

Create a standalone, fail-closed activation-caller boundary for the existing
Creative Style process-data route. The artifact will pin the concrete
`CmnViewProcessDataMgr` singleton and vptr, reproduce manager slot 20 and the
typed element slot 25 handoff, and perform a bounded function-aware search for
the missing caller that would supply process ID 42 plus a runtime condition.

The artifact must distinguish four facts:

- the manager singleton object and manager vtable are statically identified;
- manager slot 20 is the typed `execProcWithCondition` bridge;
- fully decoded VU2 owners contain a finite inventory of canonical virtual
  calls at slot offset `0x50`; and
- no inventoried call is accepted as a manager activation call without exact
  receiver identity, process ID 42, and condition provenance.

The bounded negative is not a whole-program absence claim. Decode-incomplete
or terminal exception-index owners, noncanonical dispatch forms, indirect
callbacks, dynamically initialized object fields, and cross-module/runtime
delivery remain unresolved.

## Considered approaches

### Selected: standalone activation-caller boundary

Use a dedicated contract, one-ELF read-only exporter, mutation tests, checked
report, and bounded deep-dive paragraph. This directly tests the missing edge
left false by the view-lifecycle report without mixing caller-search scope into
the already validated loader and registration chain.

### Rejected: continue from the CautionConfig selected-state graph

The Creative Style root is constructed and published into fixed menu lists,
but generic selection stops at an opaque child receiver/callback before any
VU2 process ID, manager object, or condition is produced. That path is more
semantic but currently reaches a weaker static boundary.

### Rejected: extend the generic loader route

The lifecycle report already proves a conditional event-to-loader/factory ABI.
Further loader work cannot establish who invokes process ID 42 and therefore
would not close the activation edge selected for this slice.

### Rejected: prose-only negative

Prose would not fail when the singleton cell, constructor vptr store, manager
slot, candidate dispatch inventory, or scan coverage changed. The boundary
needs mechanically reproduced scope and mutation tests.

## Evidence baseline

The sole binary source is authenticated α6400 Taiwan/region-0 firmware 2.00
`lib/viewUnified2.so`, size 11,530,552, SHA-256
`1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2`.

The existing lifecycle report is a strict dependency. It already pins:

- `CmnViewProcessDataElementCustomCreativeStyle` vptr `0x90ED88`;
- typed element slot 25 cell `0x90EDEC` to owner entry `0x489218`;
- the `view/CREATIVE_STYLE` alias and condition-preserving `openView` call;
- manager vptr `0x905930`, slot 20 cell `0x905980`, and bridge
  `[0x4390BC,0x4390D4)`; and
- `typed_process_id_42_caller_proven = false`.

The new exporter will independently reproduce the manager instance identity:

- accessor owner `[0x158350,0x1583AC)`;
- PIC base `0x9446A0`;
- guard GOT cell `0x94D228`, R_ARM_RELATIVE to `0xB06BAC`;
- instance GOT cell `0x94D990`, R_ARM_RELATIVE to static object `0xB06BB0`;
- constructor call at `0x158372` and return of the same retained receiver at
  `0x15838A`;
- manager constructor body `[0x43905C,0x43907E)` inside exact exception-index
  owner `[0x43905C,0x4390BC)`;
- vtable-header GOT cell `0x94B104`, R_ARM_RELATIVE to `0x905928`; and
- the constructor add/store that installs address point `0x905930` at object
  offset zero.

These facts establish a concrete manager object and type. They do not prove
that any later opaque receiver is that object.

## Bounded caller scan

The exporter will parse every `.ARM.exidx` owner in VU2 and divide it into:

- fully decoded owners, whose first instruction equals the range start and
  whose final instruction ends exactly at the range end; and
- decode-incomplete or terminal owners, which remain outside the negative
  universe.

Within fully decoded owners, a canonical slot-20 virtual call requires this
exact local data shape:

1. load a candidate receiver vptr from `[receiver + 0]`;
2. without overwriting that vptr register, load the call register from
   `[vptr + 0x50]`; and
3. invoke the same register with `BLX`.

The checked baseline contains 28,869 fully decoded owners, 1,594
decode-incomplete/terminal owners, and 16 canonical slot-`0x50` call sites.
Every site will be represented by exact owner range, vptr-load site,
slot-load site, call site, receiver register, and bounded provenance flags.

An activation candidate is accepted only if all of these are true:

- receiver provenance resolves to static manager object `0xB06BB0` or to the
  exact return of accessor `0x158350`;
- the receiver vptr is proven to be `0x905930`;
- `r1` is proven to be process ID 42 at the call; and
- `r2` has a bounded input/producer provenance and is forwarded as the runtime
  condition.

The baseline accepts zero candidates. A mere `+0x50` slot match, nearby call
to the manager accessor, or common register name is insufficient.

The exporter will separately report direct inbound transfers to bridge
`0x4390BC` and typed wrapper `0x489218`. Their baseline counts are zero, but
the global direct scan is explicitly incomplete because of the 1,594 excluded
owners. Therefore the report may say only that no direct inbound transfer was
found in the decoded scan, not that no caller exists.

## Contract and report shape

The raw contract and checked report will contain:

- pinned source identity and lifecycle-report dependency digest;
- manager singleton/accessor/constructor/vtable evidence;
- manager slot-20 and typed slot-25 dependency joins;
- exact exidx owner coverage counts;
- the 16 canonical call records and zero accepted candidates;
- direct-inbound scan records and their incomplete-scope flag;
- explicit unresolved universes;
- negative behavior/readiness claims; and
- a narrative SHA-256 so contradictory promotion prose fails closed.

Positive claims are limited to static manager identity, the typed bridge, and
the reproduced bounded inventory. These remain false:

- a process ID 42 activation caller;
- a menu-root or selected-state activation join;
- runtime `openView` delivery;
- factory invocation or returned `ViewCreativeStyle` identity;
- first-class Creative Look equivalence;
- processing or output behavior;
- installability, recovery, and camera-test eligibility.

## Validation and mutation strategy

Tests will be written before implementation. They will cover:

- contract normalization and promotion rejection;
- exact dependency digest and narrative digest;
- singleton PIC/GOT relocation and constructor-return dataflow;
- manager vptr GOT relocation and constructor store;
- manager slot-20 and typed slot-25 relocations;
- exidx coverage and exact 16-site inventory;
- zero accepted candidates and incomplete-scope wording;
- source-byte mutations at the singleton cell, constructor vptr path, manager
  slot cell, one canonical slot-load operand, and one direct-control site; and
- deterministic regeneration plus deep-dive phrase guards.

Mutations operate on in-memory byte arrays or test adapters only. The firmware
source is never modified.

## Stop condition and next experiment

This slice stops with
`PROCESS_ID_42_ACTIVATION_CALLER_UNRESOLVED_IN_BOUNDED_STATIC_SCAN`.

The next static experiment should target only one of two missing universes:

1. decode and classify the 1,594 incomplete/terminal exidx owners without
   weakening owner boundaries; or
2. find a relocation-backed publication or object-field write that carries
   manager object `0xB06BB0` into an indirect callback/receiver, then trace that
   exact receiver to slot 20 with `r1 = 42`.

Neither next step may infer activation from slot offset, root name, alias
string, or adjacent data alone.
