# α6400 Creative Style Selected-Node Runtime Initialization Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade the selected-node artifact to prove `ViewSettingMenu` root initialization, candidate recursive one-based ordinal assignment, and ProductAction selector forwarding while keeping live ordinals `1,5,2` and receiver-proven selector-10 delivery unresolved.

**Architecture:** Extend the existing selected-node contract/exporter/report to schema 2. Add exact VU2 root-list initialization and ProductAction evidence plus conditional CautionConfig lifecycle semantics; retain the existing static `0 → 4 → 1` membership proof and all fail-closed product/recovery gates.

**Tech Stack:** Python 3, `unittest`, pyelftools, Capstone, deterministic JSON, existing `pmca.analysis` validators and static-export helpers.

## Global Constraints

- Static/offline analysis only; never execute a Sony binary or access a camera/device.
- Never add USB, updater/service-mode, partition-write, flash/package-generation, or raw-key capability.
- Creative Style remains target-native substrate and cannot satisfy first-class Creative Look acceptance.
- Runtime selected ordinals, selector-10 delivery, process activation, processing/output, installability, recovery, and camera eligibility remain false.
- Every positive field requires exact source-byte, control-flow, dataflow, relocation, and dependency validation.
- Source mutations operate on in-memory byte arrays or adapters, never on firmware files.
- Use `apply_patch` for repository edits.

---

### Task 1: Define the schema-2 contract with RED tests

**Files:**
- Modify: `pmca/analysis/creative_style_selected_node_identity_boundary.py`
- Modify: `tests/analysis/test_creative_style_selected_node_identity_boundary.py`

**Interfaces:**
- Consumes: the current schema-1 selected-node constants and validators.
- Produces: schema-2 `ROOT_INITIALIZATION`, `CANDIDATE_LIFECYCLE`, and `PRODUCTACTION_DELIVERY` sections through the existing normalize/build/validate functions.

- [ ] **Step 1: Add the failing schema-2 report test**

Add assertions equivalent to:

```python
report = validate_creative_style_selected_node_identity_boundary_report(
    build_creative_style_selected_node_identity_boundary_report(self.raw)
)
self.assertEqual(report["schema_version"], 2)
self.assertTrue(report["claims"]["viewsettingmenu_product_root_init_call_found"])
self.assertTrue(
    report["claims"]["candidate_recursive_one_based_ordinal_assignment_found"]
)
self.assertTrue(report["claims"]["productaction_forwards_selector_to_slot_64_found"])
self.assertFalse(report["claims"]["runtime_selected_ordinal_triplet_1_5_2_proven"])
self.assertFalse(report["claims"]["viewsettingmenu_productaction_10_delivery_proven"])
self.assertEqual(
    report["first_unresolved_boundary"],
    "viewsettingmenu-live-selected-ordinals-1-5-2-and-productaction-10-delivery",
)
```

- [ ] **Step 2: Run the focused module and confirm RED**

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest -v tests.analysis.test_creative_style_selected_node_identity_boundary
```

Expected: failure because the checked schema is still 1 and the three new
sections/claims do not exist.

- [ ] **Step 3: Add exact schema-2 constants and normalization**

Add exact records for:

```python
ROOT_INITIALIZATION = {
    "slot_54_owner": {"start": 0x2108B0, "end": 0x210D20, "complete": True},
    "root_field_offset": 0x1A0,
    "root_vptr_load_site": 0x210992,
    "init_slot_load_site": 0x210994,
    "init_slot_offset": 0x08,
    "list_helper_call_site": 0x210996,
    "list_helper_target": 0x2084EC,
    "count_load_site": 0x21099E,
    "root_receiver_restore_site": 0x2109A2,
    "init_call_site": 0x2109A4,
}
```

Represent the two helper bindings exactly as relocation records for GOT
`0x948AA0`/`0x94B8E4`, and represent the candidate lifecycle and ProductAction
records exactly as specified in the design. Keep runtime binding and accepted
delivery false.

- [ ] **Step 4: Add fail-closed claim and narrative mutations**

Table-drive every new positive and negative claim. Reject at least these prose
mutations:

```python
for text in (
    "The live selected ordinals are 1, 5, and 2.",
    "ViewSettingMenu receives ProductAction selector 10 at runtime.",
    "Process ID 42 and Creative Look are active.",
    "The package is installable and camera testing is eligible.",
):
    mutated = copy.deepcopy(report)
    mutated["conclusion"] = text
    with self.assertRaises(ValueError):
        validate_creative_style_selected_node_identity_boundary_report(mutated)
```

- [ ] **Step 5: Run the contract tests and commit**

Run the focused test until green, then stage only the contract and test:

```powershell
git add pmca/analysis/creative_style_selected_node_identity_boundary.py tests/analysis/test_creative_style_selected_node_identity_boundary.py
git commit -m "extend selected-node runtime boundary contract"
```

---

### Task 2: Validate root initialization and lifecycle semantics

**Files:**
- Modify: `tools/static/export_a6400_creative_style_selected_node_identity_boundary.py`
- Modify: `tests/analysis/test_creative_style_selected_node_identity_boundary.py`

**Interfaces:**
- Consumes: schema-2 constants from Task 1 and authenticated VU2/Caution blobs.
- Produces: `_validate_root_initialization(view, deps) -> dict` and `_validate_candidate_lifecycle(caution, deps) -> dict`, called by `_metadata_from_blobs`.

- [ ] **Step 1: Add RED source-mutation tests for the VU2 call**

Mutate one operand/control edge at each of `0x210992`, `0x210994`, `0x210996`,
`0x21099E`, `0x2109A2`, and `0x2109A4`. Mutate the list/count GOT relocation
site, type, symbol, or helper dataflow. Require a label-specific `RuntimeError`.

- [ ] **Step 2: Implement the exact root-initialization validator**

Require the root stored at `+0x1A0` to remain the receiver of `vptr+0x08`.
Validate helper owner `[0x2084EC,0x208548)`, `count*4` allocation, pointer-copy
loop, and exact bindings:

```python
EXPECTED_ROOT_BINDINGS = (
    (130801, 0x948AA0, 21, 392, "cmnViewSettingNodesRootDefault"),
    (130996, 0x94B8E4, 21, 937, "cmnViewSettingNodesNumOfRootDefault"),
)
```

Require helper return to call `r1`, count value to call `r2`, root pointer to
call `r0`, and the saved virtual target to the indirect call register.

- [ ] **Step 3: Add RED lifecycle mutation tests**

Mutate candidate vtable cells `0xAB9408`, `0xAB94F8`, or `0xAB94FC`; their
relocation indices/types/symbols; lifecycle calls `+0xE8/+0xF8/+0xEC`;
parent/ordinal/state stores `+0x10/+0x20/+0x18/+0x24`; recursive call `+0xF8`;
selected-state test `+0x94`; selection call `+0xB8`; final selected-child query
`+0x28`; or fallback selectable-child query `+0x38`. Every mutation must fail.

- [ ] **Step 4: Implement the candidate lifecycle validator**

Pin these interface records:

```python
EXPECTED_LIFECYCLE = {
    "init_setting_node": (0xAB9408, 6168, 2, 3892, 0x7C6AEA, 0x7C6B20),
    "init": (0xAB94F8, 76320, 2, 72371, 0x7C732C, 0x7C744C),
    "set_head_selected": (0xAB94FC, 77509, 2, 57258, 0x7C744C, 0x7C747A),
}
```

Validate exact registers and memory operands, not only offsets or mnemonics.
Label every implementation as a runtime-provider candidate and keep the live
ordinal triplet false.

- [ ] **Step 5: Run focused tests and commit**

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest -v tests.analysis.test_creative_style_selected_node_identity_boundary
.\.venv\Scripts\python.exe -m py_compile pmca\analysis\creative_style_selected_node_identity_boundary.py tools\static\export_a6400_creative_style_selected_node_identity_boundary.py tests\analysis\test_creative_style_selected_node_identity_boundary.py
```

Then commit:

```powershell
git add tools/static/export_a6400_creative_style_selected_node_identity_boundary.py tests/analysis/test_creative_style_selected_node_identity_boundary.py
git commit -m "trace selected-node runtime initialization"
```

---

### Task 3: Validate ProductAction forwarding and bounded delivery scan

**Files:**
- Modify: `tools/static/export_a6400_creative_style_selected_node_identity_boundary.py`
- Modify: `tests/analysis/test_creative_style_selected_node_identity_boundary.py`

**Interfaces:**
- Consumes: the authenticated VU2 ELF context and existing ViewSettingMenu identity.
- Produces: `_validate_productaction_delivery(view, deps) -> dict` with exact interface metadata, bounded call inventory, and an empty accepted-candidate list.

- [ ] **Step 1: Add RED interface-mutation tests**

Mutate slot-37 cell/relocation/symbol, ProductAction dynsym owner/size, receiver
vptr load, `+0x100` slot load, call register, `r1` preservation, or slot-64
cell/target. Require the exporter to fail before report normalization.

- [ ] **Step 2: Implement exact ProductAction forwarding validation**

Require:

```python
PRODUCTACTION_INTERFACE = {
    "viewsettingmenu_address_point": 0x8E2270,
    "slot_37_cell": 0x8E2304,
    "slot_37_relocation_index": 86865,
    "productaction_symbol_index": 2323,
    "productaction_symbol_range": {"start": 0x2F1350, "end": 0x2F135E},
    "productaction_exidx_owner": {"start": 0x2F12EC, "end": 0x2F135E},
    "slot_64_cell": 0x8E2370,
    "slot_64_relocation_index": 17858,
    "slot_64_target": 0x21355E,
}
```

Decode all six ProductAction symbol-range instructions, independently validate
the enclosing EXIDX owner, and prove incoming `r1` is untouched before the
indirect slot-64 transfer.

- [ ] **Step 3: Add RED bounded-scan mutations**

Mutate the expected fully decoded/incomplete counts, delete or fabricate one of
the six canonical slot-37 calls, attach address point `0x8E2270` to a receiver,
or assign selector `10`. The first three mutations must reject evidence drift;
the latter two must reject unsafe promotion.

- [ ] **Step 4: Implement the function-aware scan**

Decode each `.ARM.exidx` owner completely. Accept only the structural sequence
`receiver -> vptr`, `vptr+0x94 -> function`, and `blx function`, allowing
register-preserving moves between those instructions. Record the six exact VU2
calls in fully decoded owners. Prove receiver provenance and selector value
independently; emit no accepted candidate unless both are established. Preserve:

```python
{
    "fully_decoded_owner_count": 28869,
    "incomplete_or_terminal_owner_count": 1594,
    "canonical_slot_37_call_count": 6,
    "accepted_candidates": [],
    "whole_program_absence_proven": False,
}
```

- [ ] **Step 5: Run focused tests and commit**

Run the focused module and Python compilation, then:

```powershell
git add tools/static/export_a6400_creative_style_selected_node_identity_boundary.py tests/analysis/test_creative_style_selected_node_identity_boundary.py
git commit -m "bound ProductAction selector delivery"
```

---

### Task 4: Regenerate and document the checked evidence

**Files:**
- Modify: `analysis/a6400-creative-style-selected-node-identity-boundary.json`
- Modify: `analysis/a6400a-updater-and-creative-style-deep-dive.md`
- Modify: `tests/analysis/test_creative_style_selected_node_identity_boundary.py`

**Interfaces:**
- Consumes: schema-2 exporter/report builders from Tasks 1–3.
- Produces: deterministic checked JSON and conservative deep-dive wording.

- [ ] **Step 1: Add RED checked-report and atomicity tests**

Require the checked JSON to equal a fresh authenticated-source report. Build it
twice in memory and require identical canonical digests. Force lifecycle
validation failure and assert the checked file hash does not change.

- [ ] **Step 2: Regenerate through the existing validated atomic writer**

Run:

```powershell
.\.venv\Scripts\python.exe tools\static\export_a6400_creative_style_selected_node_identity_boundary.py
```

Validate the serialized report and rerun generation; require identical file
SHA-256 values.

- [ ] **Step 3: Update the deep dive without runtime promotion**

State exactly that the product root is initialized through the typed virtual
interface; candidate Caution semantics assign one-based ordinals and perform
generic selection restoration/fallback; live ordinals `1,5,2` and selector-10
delivery remain unresolved; and process ID 42, factory execution, Creative Look,
processing/output, recovery, installability, and camera eligibility remain
false.

- [ ] **Step 4: Run cross-slice tests and commit**

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest -v tests.analysis.test_creative_style_selected_node_identity_boundary tests.analysis.test_creative_style_activation_caller_boundary tests.analysis.test_creative_style_definition_registration tests.analysis.test_creative_style_selected_state_dispatch tests.analysis.test_creative_style_menu_list_construction
```

Then commit:

```powershell
git add analysis/a6400-creative-style-selected-node-identity-boundary.json analysis/a6400a-updater-and-creative-style-deep-dive.md tests/analysis/test_creative_style_selected_node_identity_boundary.py
git commit -m "publish selected-node runtime boundary"
```

---

### Task 5: Verify and publish the milestone

**Files:**
- Verify only; modify prior-task files solely to fix failures inside this specification.

**Interfaces:**
- Consumes: every output from Tasks 1–4.
- Produces: a verified clean branch synchronized with its GitHub upstream.

- [ ] **Step 1: Run focused and cross-slice verification**

Run the selected-node, activation, definition, selected-state, menu-list,
view-lifecycle, and interaction suites. Record exact pass counts.

- [ ] **Step 2: Run full analysis and safety suites**

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests\analysis -t .
.\.venv\Scripts\python.exe -m unittest discover -s tests\safe -t .
```

No required authenticated-source test may be skipped when its local sources are
available.

- [ ] **Step 3: Run deterministic and static hygiene checks**

Compile all changed Python files, regenerate twice, validate checked equality,
run `git diff --check`, and require `git status --short` to contain only the
planned files before the final commit.

- [ ] **Step 4: Commit verification-only corrections if needed**

If verification requires an in-scope correction, stage only the affected plan
files and commit:

```powershell
git commit -m "harden selected-node runtime evidence"
```

Do not create an empty commit.

- [ ] **Step 5: Push and verify exact identities**

Push `feature/a6400-updater-re-lab`, then require local `HEAD`, upstream SHA,
and `git ls-remote` SHA to match. Keep the overall goal active because
first-class Creative Look and verified exact-region recovery remain incomplete.
