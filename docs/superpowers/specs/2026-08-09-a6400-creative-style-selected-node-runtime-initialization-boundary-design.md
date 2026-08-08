# α6400 Creative Style Selected-Node Runtime Initialization Boundary Design

## Status and scope

This design continues the approved static/offline α6400 research program. It
extends the checked selected-node identity artifact with the root-initialization
and action-delivery evidence immediately surrounding the already proven static
Creative Style path.

Creative Style remains target-native substrate only. This work must not promote
it to first-class Creative Look, infer imaging semantics, authorize installation,
relax recovery gates, or make camera testing eligible.

## Objective

Upgrade `analysis/a6400-creative-style-selected-node-identity-boundary.json` to
answer two narrower questions:

1. Does `ViewSettingMenu` initialize the exact product root stored at `+0x1A0`
   through the typed setting-node lifecycle interface?
2. Is selector `10` statically delivered through `ViewSettingMenu::ProductAction`
   to the existing slot-64 action dispatcher?

The strongest current answer is split. Root initialization and generic one-based
ordinal assignment are statically evidenced, conditional on dynamic provider
binding. The live selected ordinals `1,5,2` and receiver-proven selector-10
delivery remain unresolved.

## Approaches considered

### 1. Extend the selected-node artifact to schema 2 — selected

Add root-initialization and action-delivery sections to the existing contract,
exporter, tests, checked report, and deep-dive text. These facts refine that
artifact's current first unresolved boundary and share its exact VU2/Caution
sources and dependencies.

### 2. Add another standalone boundary report

This would isolate the new scan, but it would duplicate source identities,
ViewSettingMenu vtable facts, negative claims, and the `1,5,2` verdict. The
result would be harder to audit without adding an independent acceptance gate.

### 3. Fold the evidence back into the activation-caller report

That report already contains manager identity, process-data activation, and a
large caller scan. Adding recursive setting-node initialization would recreate
the complexity that the selected-node artifact was introduced to avoid.

## Evidence architecture

### 1. Exact root-initialization call

Within typed `ViewSettingMenu` slot-54 owner `[0x2108B0,0x210D20)`, preserve the
existing proof that `0x210986` returns a product root and `0x21098C` stores that
same pointer at receiver `+0x1A0`. Extend the trace through:

- `0x210992`: load the exact root vptr;
- `0x210994`: load virtual target `vptr+0x08`;
- `0x210996 -> 0x2084EC`: build the root-list initialization argument;
- `0x21099A..0x2109A0`: load the default-root count;
- `0x2109A2`: restore the exact product root as `r0`;
- `0x2109A4`: invoke the saved `vptr+0x08` target.

Helper `[0x2084EC,0x208548)` must be validated as a cached four-byte pointer-list
copy using exactly these VU2 dynamic bindings:

- GOT `0x948AA0`, relocation 130801, `R_ARM_GLOB_DAT`, dynsym 392,
  `cmnViewSettingNodesRootDefault`;
- GOT `0x94B8E4`, relocation 130996, `R_ARM_GLOB_DAT`, dynsym 937,
  `cmnViewSettingNodesNumOfRootDefault`.

The helper's returned list pointer must reach call argument `r1`; the count
loaded through the second binding must reach `r2`. Runtime contents and provider
identity remain unobserved.

### 2. Candidate lifecycle and ordinal semantics

In authenticated `CautionConfig.so`, validate the base interface address point
`0xAB9400` and its `+0x08` cell `0xAB9408`: relocation 6168,
`R_ARM_ABS32`, dynsym 3892,
`CmnViewSettingNode::initSettingNode(CmnViewSettingNode**, int)`, owner
`[0x7C6AEA,0x7C6B20)`.

The candidate implementation must call the same receiver's lifecycle slots
`+0xE8`, `+0xF8`, and `+0xEC`. Validate the base `init` cell `0xAB94F8`,
relocation 76320, dynsym 72371, owner `[0x7C732C,0x7C744C)`. Its bounded body
must prove:

- child parent assignment at `child+0x10`;
- monotonically increasing one-based ordinal assignment at `child+0x20`;
- selected-ordinal initialization at `child+0x18`;
- recursive subtree initialization through `vptr+0xF8`;
- conditional selected-state test through `vptr+0x94` followed by
  `setItemSelected` through `vptr+0xB8`;
- final selected-child query through `vptr+0x28`.

When no selected child is returned, the body calls `vptr+0xFC`. Validate base
cell `0xAB94FC`, relocation 77509, dynsym 57258, and owner
`[0x7C744C,0x7C747A)`. That routine queries selectable child one through
`vptr+0x38` and invokes `setItemSelected` through `vptr+0xB8`, or leaves the
selected ordinal at `-1`.

These facts establish a generic runtime mechanism that assigns child identity
and restores/falls back to selection. They do not establish that the three
live selected ordinals equal `1,5,2` when action selector 10 executes.

### 3. ProductAction-to-slot-64 interface

Validate the `ViewSettingMenu` address point `0x8E2270` with:

- slot 37 cell `0x8E2304`, relocation 86865, `R_ARM_ABS32`, dynsym 2323,
  `ViewBaseProduct::ProductAction(int)`;
- slot 64 cell `0x8E2370`, relocation 17858, target `0x21355E`.

Validate dynsym 2323 as the exact Thumb symbol range
`[0x2F1350,0x2F135E)` inside EXIDX owner `[0x2F12EC,0x2F135E)`. Its entire
six-instruction body must load the incoming receiver vptr, load `vptr+0x100`,
and call that target without writing `r1`. This proves that a
`ProductAction(10)` call on a `ViewSettingMenu` receiver would reach the known
selector-10 dispatcher case; it does not prove that such a call occurs.

Run a function-aware VU2 scan over the exact `.ARM.exidx` universe already used
by the activation artifact. Record 28,869 fully decoded owners and 1,594
incomplete/terminal owners. Inventory the six bounded canonical virtual
slot-37 call sites currently found in fully decoded owners, but accept a
candidate only if both receiver provenance to address point `0x8E2270` and
selector value `10` are proven. The accepted set remains empty and
whole-program absence remains false. Cross-module, noncanonical, incomplete,
and runtime callback delivery remain outside the negative scan.

## Verdict and next boundary

New positive claims:

- `viewsettingmenu_product_root_init_call_found = true`;
- `candidate_recursive_one_based_ordinal_assignment_found = true`;
- `productaction_forwards_selector_to_slot_64_found = true`.

Claims that remain false:

- runtime provider binding for the VU2/Caution lifecycle interfaces;
- `runtime_selected_ordinal_triplet_1_5_2_proven`;
- runtime selected node equals the Creative Style root;
- `viewsettingmenu_productaction_10_delivery_proven`;
- process ID 42 activation, ViewCreativeStyle factory invocation, first-class
  Creative Look, processing/output behavior, installability, recovery, and
  camera-test eligibility.

The first unresolved boundary becomes:

`viewsettingmenu-live-selected-ordinals-1-5-2-and-productaction-10-delivery`

## Fail-closed validation

The exporter must validate exact source/dependency identities; owners;
instruction classes and operands; register preservation; virtual offsets;
helper dataflow; GOT relocation index/type/symbol; vtable relocation
index/type/symbol; recursive ordinal/state writes; and the bounded call-scan
universe. Every source mutation operates on an in-memory byte array or decoder
adapter, never a firmware file.

The normalizer must exact-match schema 2 and reject any positive runtime
selection, selector delivery, provider binding, process activation, Creative
Look, processing/output, installability, recovery, or camera claim. Narrative
text remains digest-pinned.

## Testing and acceptance

Tests are written before implementation. They must reject mutations to the
root vptr/call arguments, helper list/count bindings, lifecycle vtable cells,
ordinal/state stores, recursive and fallback calls, ProductAction slot/forwarder,
scan counts, receiver/selector acceptance, dependency digests, and narrative.

Acceptance requires deterministic checked-report regeneration, exact equality
with a fresh authenticated-source export, focused and cross-slice passes, full
analysis and safety passes, Python compilation, `git diff --check`, a clean
worktree, and synchronized local/upstream/remote commit identities. No Sony
binary, camera, updater, USB, partition, or package action is introduced.
