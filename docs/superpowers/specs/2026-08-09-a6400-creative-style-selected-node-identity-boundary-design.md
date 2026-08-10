# α6400 Creative Style Selected-Node Identity Boundary Design

## Status and scope

This design continues the approved static/offline α6400 research program. It
adds a fail-closed evidence artifact for the menu-node identity immediately
upstream of the already validated process-data activation boundary.

Creative Style is used only as target-native substrate. The artifact must not
promote Creative Style to first-class Creative Look, infer image-processing
semantics, authorize installation, relax recovery gates, or make camera testing
eligible.

## Objective

Create a standalone deterministic report that answers one question:

> Can the runtime selected-node pointer used by the ViewSettingMenu action be
> statically joined to the constructed Creative Style root?

The strongest current answer is conditional. A concrete three-level static
menu graph reaches the Creative Style root at zero-based child indices `0`, `4`,
and `1`, but the corresponding one-based runtime selected ordinals `1`, `5`,
and `2` and the event/menu action that choose them are not statically
established.

## Approaches considered

### 1. Standalone selected-node identity artifact — selected

Add a focused schema, exporter, report, and tests that depend on the existing
activation, definition, and menu-list reports. This keeps the constructor graph,
runtime selection mechanism, and unresolved index state isolated from the
already-large activation report.

### 2. Extend the activation-caller report

This would avoid one artifact, but it would combine manager identity, property
dispatch, a 1,748-constructor graph, and runtime selection state in one module.
That is harder to audit and makes unrelated schema changes more likely.

### 3. Document the result without a validator

This is smallest, but it cannot reject operand, relocation, list-index, or
narrative regressions and is not acceptable for a positive static path.

## Evidence architecture

The new artifact will use the authenticated `viewUnified2.so` and
`CautionConfig.so` sources already pinned by the dependency reports. It will
digest-pin and validate these reports before exporting:

- `analysis/a6400-creative-style-activation-caller-boundary.json`;
- `analysis/a6400-creative-style-definition-registration.json`;
- `analysis/a6400-creative-style-menu-list-construction.json`.

The normalized report will contain five bounded sections.

### 1. Product-root selection

Validate the `BackupManager::Bkup_Read` call in owner
`[0x208648, 0x2088F0)`, record ID `0x01070316`, the byte-to-TBH selector, its
75 indexed values, and the default return root `0xB09B5C`. Record all 49 unique
return values, including the null value for selector 32, without assigning human
meanings to the other product roots.

Validate that ViewSettingMenu slot 54 calls this helper at `0x210986` and stores
the exact return value to the same receiver at `+0x1A0` at `0x21098C`.

### 2. Constructor graph

Decode the oversized `.ARM.exidx` owner `[0x213B8C, 0x228BA4)` with a
control-flow-aware Thumb traversal. Direct branches must skip embedded literal
pools; calls are recorded but not followed. The pinned traversal currently has
23,355 reachable instructions and 1,748 direct calls to the generic
`CmnViewSettingNode::C1` PLT entry.

Forward constant dataflow over that reachable graph must recover all four
constructor arguments at the three nodes on the Creative Style path:

| Node | Constructor call | Child list | Count |
|---|---:|---:|---:|
| default product root `0xB09B5C` | `0x21EE7E` | `0x957C80` | 5 |
| first selected child `0xB152A8` | `0x21EDCA` | `0x956B78` | 8 |
| second selected child `0xB12364` | `0x21EAFA` | `0x9548BC` | 6 |

The report will also preserve the exact properties-object argument for each
constructor and the generic constructor PLT/dynsym identity. Runtime provider
binding remains false.

### 3. Relocation-backed Creative Style path

Validate this exact three-edge path:

1. root list index 0, cell `0x957C80`, `R_ARM_RELATIVE` relocation 64482,
   target `0xB152A8`;
2. first-child list index 4, cell `0x956B88`, `R_ARM_RELATIVE` relocation
   64238, target `0xB12364`;
3. second-child list index 1, cell `0x9548C0`, `R_ARM_ABS32` relocation
   130947, dynsym 901, symbol `cmnViewSettingNodeRootCreativeStyle`.

The final symbol is joined to the existing authenticated Creative Style root
definition and construction report. The report may claim a static
membership/reachability candidate only. It may not claim that the dynamic
loader selected a particular provider or that a runtime pointer equality was
observed.

### 4. Runtime selected-child mechanism

Validate helper `[0x207C4A, 0x207C8C)` as three consecutive same-result
virtual calls through vptr offset `+0x28`, with the final selected child
returned to the caller. Join the helper call in the activation action to the
same receiver whose `+0x1A0` field holds the product root.

Record the CautionConfig candidate implementation of
`CmnViewSettingNode::getSelectedItem(CmnViewSettingNode**)` as conditional
provider evidence. Its bounded body calls virtual `getSubNode`, reads a
one-based runtime selected ordinal from `this+0x18`, requires it to be positive,
clamps it to the child count, subtracts one, and returns one child pointer. The
base `getSubNode` candidate exposes list/count at `this+4` and `this+8`.

This establishes that zero-based list indices `0`, `4`, and `1`—equivalently
runtime ordinals `1`, `5`, and `2`—would return the Creative Style root. It does
not establish that those ordinal values are live when selector-10 action
processing executes.

### 5. Verdict and next boundary

The positive claim is:

`creative_style_static_selected_child_path_0_4_1_found = true`

The following remain false:

- runtime selected-ordinal triplet `1,5,2` proven;
- runtime selected node equals the constructed Creative Style root;
- process ID 42 activation accepted;
- ViewCreativeStyle factory invocation or returned object identity;
- first-class Creative Look interface, state, axes, rendering, or output;
- installability, recovery validation, or camera-test eligibility.

The first unresolved boundary becomes:

`viewsettingmenu-runtime-selected-ordinal-triplet-1-5-2-and-action-provenance`

## Fail-closed validation

The exporter must validate instruction class and operands, exact call targets,
receiver preservation, field offsets, literal addresses and values, branch/TBH
control flow, exception-index owner bounds, reachable-code traversal, constructor
argument dataflow, relocation index/type/symbol/addend, dependency digests, and
source identity.

The normalizer must exact-match the bounded evidence contract and reject any
positive runtime, Creative Look, processing/output, recovery, installability,
or camera claim. Narrative fields will use an exact digest contract so prose
cannot contradict the structural booleans.

## Testing

Tests will be written before implementation and will include:

- schema/normalizer rejection for every promoted runtime or product claim;
- source-byte mutations for the backup ID, TBH/default root, slot-54 call/store,
  all three constructor calls/arguments, each list index/cell/relocation, and
  each virtual selected-child call;
- dependency-digest and narrative mutations;
- a real-source export test when authenticated artifacts are available;
- deterministic double regeneration and checked-report equality;
- focused activation/definition/menu-list cross-slice tests;
- full analysis, safety, Python compilation, and `git diff --check` before the
  milestone commit and push.

All mutation tests operate on in-memory byte arrays or adapters. The exporter
remains read-only and no Sony executable, camera, updater, USB, or partition
operation is introduced.

## Acceptance criteria

The milestone is accepted only when the checked report reproducibly proves the
static `0 → 4 → 1` membership path and simultaneously rejects runtime-selection
and Creative Look promotion. Any unresolved constructor argument, relocation,
provider binding, selected-ordinal value, or dependency mismatch must fail the
export rather than weaken or infer the claim.
