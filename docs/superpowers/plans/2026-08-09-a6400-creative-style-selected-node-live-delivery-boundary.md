# α6400 Creative Style Selected-Node Live Delivery Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the authenticated selected-node report to schema 3 with a source-derived selected-ordinal writer inventory and provenance classifications for every canonical VU2 ProductAction caller.

**Architecture:** Keep the existing selected-node contract as the single evidence owner. Add one CautionConfig writer-analysis unit and deepen the existing VU2 ProductAction scan; compose their results only in the report verdict, preserving separate conditional/runtime claims and all safety gates.

**Tech Stack:** Python 3, `pyelftools`, Capstone ARM/Thumb decoding, `unittest`, deterministic JSON reports, Markdown evidence documentation, Git.

## Global Constraints

- Static/offline analysis only; do not execute Sony binaries or access a camera, USB device, updater, partition, or package writer.
- Treat Creative Style only as target-native substrate; do not promote it to first-class Creative Look.
- Keep runtime provider binding, live selected ordinals, selected-node identity, process-ID 42 activation, factory invocation, processing/output binding, installability, recovery validation, and camera-test eligibility false unless an exact authenticated chain independently closes them.
- Treat decode-incomplete owners, noncanonical dispatch, cross-module loading, and runtime callbacks as unresolved universes, never as whole-program absence.
- Mutate only in-memory byte arrays or decoder adapters in source-mutation tests; never modify firmware artifacts.
- Preserve deterministic report generation and exact dependency-digest validation.

---

## File structure

- Modify `pmca/analysis/creative_style_selected_node_identity_boundary.py`: schema-3 constants, normalization, report claims, readiness, and narrative contract.
- Modify `tools/static/export_a6400_creative_style_selected_node_identity_boundary.py`: source-derived selected-ordinal writer validation and deeper ProductAction caller provenance.
- Modify `tests/analysis/test_creative_style_selected_node_identity_boundary.py`: TDD contract, source mutations, inventory completeness, and promotion guards.
- Modify `analysis/a6400-creative-style-selected-node-identity-boundary.json`: deterministically regenerated checked report.
- Modify `analysis/a6400a-updater-and-creative-style-deep-dive.md`: bounded findings and revised first unresolved edge.
- Reference `docs/superpowers/specs/2026-08-09-a6400-creative-style-selected-node-live-delivery-boundary-design.md`: approved design and acceptance contract.

### Task 1: Source-derived selected-ordinal writer inventory

**Files:**
- Modify: `tests/analysis/test_creative_style_selected_node_identity_boundary.py`
- Modify: `pmca/analysis/creative_style_selected_node_identity_boundary.py`
- Modify: `tools/static/export_a6400_creative_style_selected_node_identity_boundary.py`

**Interfaces:**
- Consumes: existing `CANDIDATE_LIFECYCLE`, authenticated Caution context, `_require_owner`, `_require_text`, Capstone operand/register metadata.
- Produces: `SELECTED_ORDINAL_WRITERS`, `_validate_selected_ordinal_writers(context, deps) -> dict`, and export field `selected_ordinal_writers`.

- [ ] **Step 1: Write the schema-3 contract test first**

Add assertions that the normalized report is schema 3 and contains exactly these five bounded writes:

```python
expected_sites = [0x7C6C00, 0x7C70AA, 0x7C7358, 0x7C73CE, 0x7C7470]
writers = report["selected_ordinal_writers"]
self.assertEqual(writers["field_offset"], 0x18)
self.assertEqual(
    [item["site"] for item in writers["writers"]],
    expected_sites,
)
self.assertTrue(writers["typed_owner_inventory_complete"])
self.assertTrue(writers["parent_selected_ordinal_from_child_one_based_field_proven"])
self.assertFalse(writers["candidate_provider_conditional_ordinal_triplet_proven"])
self.assertFalse(writers["runtime_selected_ordinal_triplet_1_5_2_proven"])
```

Require these roles in site order:

```python
[
    "selected-item-cache-clamp",
    "parent-selected-ordinal-from-child-one-based-field",
    "root-default-minus-one",
    "child-default-minus-one",
    "fallback-missing-child-minus-one",
]
```

- [ ] **Step 2: Run the focused test and observe RED**

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.analysis.test_creative_style_selected_node_identity_boundary -v
```

Expected: failure because schema 2 lacks `selected_ordinal_writers`.

- [ ] **Step 3: Add source-mutation tests for every writer**

Use the existing `_mutated_blob_context`/decoder-mutation helpers. Mutate one operand or instruction at each site and require a specific `RuntimeError`:

```python
for site in (0x7C6C00, 0x7C70AA, 0x7C7358, 0x7C73CE, 0x7C7470):
    with self.subTest(site=hex(site)):
        context = self._mutated_caution_blob_context(site)
        with self.assertRaisesRegex(RuntimeError, "selected-ordinal writer"):
            validator(context, deps)
```

Also mutate the value producers:

- `0x7C6BFC` clamp transfer;
- `0x7C70A4` load of child one-based ordinal `+0x20`;
- `0x7C70A6` resolved-parent load;
- `0x7C734E` and `0x7C73CA` minus-one producers;
- `0x7C746C` fallback `-1` producer.

Each mutation must reject the corresponding role/dataflow rather than merely changing an expected dictionary.

- [ ] **Step 4: Add exact schema-3 constants**

Define `SELECTED_ORDINAL_WRITERS` with one record per site. Each record includes:

```python
{
    "site": 0x7C70AA,
    "owner": {"start": 0x7C705A, "end": 0x7C70DA, "complete": True},
    "destination_identity": "resolved-super-item",
    "destination_register": "r3",
    "source_identity": "selected-child-one-based-ordinal",
    "source_register": "r2",
    "source_field_offset": 0x20,
    "role": "parent-selected-ordinal-from-child-one-based-field",
    "typed_lifecycle_path": True,
}
```

The other four records use their decoded identities:

- `0x7C6C00`: same `this` in `r4`, clamped selected ordinal in `r3`;
- `0x7C7358`: root `this` in `r0`, `-1` in `r3`;
- `0x7C73CE`: resolved child in `r0`, `-1` in `r3`;
- `0x7C7470`: fallback root `this` in `r4`, `-1` in `r3`.

Keep both conditional and runtime triplet claims false unless the exporter proves the three concrete selection calls on the exact `[0,4,1]` child chain.

- [ ] **Step 5: Implement the minimal writer validator**

Add `_validate_selected_ordinal_writers(context, deps)` that:

1. validates the exact four symbol owners `[0x7C6BD2,0x7C6C16)`, `[0x7C705A,0x7C70DA)`, `[0x7C732C,0x7C744C)`, and `[0x7C744C,0x7C747A)`;
2. decodes each owner completely;
3. tracks `this`, resolved-super-item, and resolved-child receiver identities;
4. validates each store's base, source register, displacement `0x18`, and producer;
5. scans the bounded owner set for any additional `STR`/`STR.W` to a proven setting-node `+0x18` receiver and fails if the derived sites differ from the five expected sites;
6. returns a deep copy of the derived records and explicit unresolved triplet verdicts.

Integrate the result in `_metadata_from_blobs`:

```python
document["selected_ordinal_writers"] = _validate_selected_ordinal_writers(
    caution_context, deps
)
```

- [ ] **Step 6: Update normalization and promotion guards**

Bump the report schema to 3. Exact-match `selected_ordinal_writers`, reject unknown fields, and reject either conditional or runtime triplet promotion unless it matches the authenticated export. Keep all product, processing, recovery, and camera claims false.

- [ ] **Step 7: Run focused tests to GREEN**

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.analysis.test_creative_style_selected_node_identity_boundary -v
```

Expected: all selected-node tests pass, including real-source export when artifacts are available.

- [ ] **Step 8: Compile and commit Task 1**

Run:

```powershell
.\.venv\Scripts\python.exe -m py_compile pmca\analysis\creative_style_selected_node_identity_boundary.py tools\static\export_a6400_creative_style_selected_node_identity_boundary.py tests\analysis\test_creative_style_selected_node_identity_boundary.py
```

Commit:

```powershell
git add pmca/analysis/creative_style_selected_node_identity_boundary.py tools/static/export_a6400_creative_style_selected_node_identity_boundary.py tests/analysis/test_creative_style_selected_node_identity_boundary.py
git commit -m "trace selected ordinal writers"
```

### Task 2: ProductAction caller provenance and bounded refutations

**Files:**
- Modify: `tests/analysis/test_creative_style_selected_node_identity_boundary.py`
- Modify: `pmca/analysis/creative_style_selected_node_identity_boundary.py`
- Modify: `tools/static/export_a6400_creative_style_selected_node_identity_boundary.py`

**Interfaces:**
- Consumes: `_canonical_slot_37_calls(context, deps)`, `PRODUCTACTION_DELIVERY`, VU2 `.dynsym`, `.rel.dyn`, `.ARM.exidx`, and decoded register-write data.
- Produces: classified caller fields `receiver_origin`, `selector_origin`, `owner_identity`, `address_taken_records`, and `rejection_reason` for each canonical call.

- [ ] **Step 1: Write failing classification assertions**

Require exactly six records and these bounded group classifications:

```python
calls = report["productaction_delivery"]["canonical_slot_37_calls"]
self.assertEqual(len(calls), 6)
self.assertEqual(
    [item["rejection_reason"] for item in calls],
    [
        "receiver-untyped-and-selector-call-clobbered",
        "receiver-untyped-and-selector-call-clobbered",
        "receiver-untyped-and-selector-call-clobbered",
        "receiver-untyped-and-selector-call-clobbered",
        "af-helper-return-receiver-and-selector-call-clobbered",
        "entry-r2-receiver-and-helper-return-selector",
    ],
)
self.assertEqual(report["productaction_delivery"]["accepted_candidates"], [])
self.assertFalse(
    report["claims"]["viewsettingmenu_productaction_10_delivery_proven"]
)
```

The `0x3E1328` record must state selector origin `helper-return-0x3E1300`, not an immediate; the `0x35F67A` record must preserve the exact named AF wrapper owner.

- [ ] **Step 2: Run the focused test and observe RED**

Run the selected-node unittest module. Expected: failure because current caller records lack classification fields.

- [ ] **Step 3: Add caller-provenance mutation tests**

Mutate source/dataflow at:

- `0x310CDE` entry receiver capture and one call from each branch group;
- `0x35F670` helper call and `0x35F674` returned-receiver vptr load;
- `0x3E11DE` entry `r2 -> r5` capture, `0x3E1300` helper-result capture, `0x3E131A` selector transfer, and `0x3E1328` indirect call;
- dynsym owner data for `_ZN27CmnWrpOrientationRegisterAF26getRecallRegisteredAfFrameEv`;
- any address-taken relocation record emitted for a caller owner.

Each mutation must fail source validation. Add a normalizer mutation that changes only `rejection_reason` and require rejection.

- [ ] **Step 4: Implement bounded provenance tracking**

Extend `_canonical_slot_37_calls` with a small identity lattice:

```python
{
    "kind": "entry-argument" | "helper-return" | "immediate" |
            "call-clobbered" | "unknown",
    "register": "r0" | "r1" | "r2" | "r4" | "r5" | "sb",
    "producer_site": int | None,
    "value": int | None,
}
```

Track only the instructions needed by the six fully decoded owners. Invalidate caller-saved registers across calls unless the call's return in `r0` is immediately captured. Resolve the named AF owner from `.dynsym`; do not infer a semantic name for unnamed owners. Enumerate relocation-backed address-taken records exactly, but do not use their presence alone as receiver identity.

Set `receiver_identity_proven` only when the exact receiver is joined to AP `0x8E2270`; set `selector_10_proven` only for a live immediate/dataflow value 10 at the call. Derive `accepted` from both booleans.

- [ ] **Step 5: Exact-match the classified inventory**

Update `CANONICAL_SLOT_37_CALLS` and `PRODUCTACTION_DELIVERY` to the source-derived records. Preserve:

```python
"fully_decoded_owner_count": 28_869,
"incomplete_or_terminal_owner_count": 1_594,
"accepted_candidates": [],
"whole_program_absence_proven": False,
```

Expose unresolved universes explicitly:

```python
[
    "decode-incomplete-or-terminal-exidx-owners",
    "noncanonical-virtual-dispatch",
    "indirect-callback-or-runtime-initialized-receiver",
    "cross-module-or-loader-mediated-delivery",
]
```

- [ ] **Step 6: Run focused and cross-slice tests**

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.analysis.test_creative_style_selected_node_identity_boundary tests.analysis.test_creative_style_activation_caller_boundary tests.analysis.test_creative_style_selected_state_dispatch tests.analysis.test_creative_style_definition_registration tests.analysis.test_creative_style_menu_list_construction -v
```

Expected: all pass.

- [ ] **Step 7: Compile and commit Task 2**

Run `py_compile` for the three modified Python files and `git diff --check` for the Task 2 paths. Commit:

```powershell
git add pmca/analysis/creative_style_selected_node_identity_boundary.py tools/static/export_a6400_creative_style_selected_node_identity_boundary.py tests/analysis/test_creative_style_selected_node_identity_boundary.py
git commit -m "classify ProductAction delivery candidates"
```

### Task 3: Deterministic report, narrative, and acceptance verification

**Files:**
- Modify: `analysis/a6400-creative-style-selected-node-identity-boundary.json`
- Modify: `analysis/a6400a-updater-and-creative-style-deep-dive.md`
- Modify if narrative hashes require it: `pmca/analysis/creative_style_selected_node_identity_boundary.py`
- Modify if phrase guards require it: `tests/analysis/test_creative_style_selected_node_identity_boundary.py`

**Interfaces:**
- Consumes: schema-3 exporter output from Tasks 1 and 2.
- Produces: deterministic checked report, fail-closed deep-dive wording, and final verified branch state.

- [ ] **Step 1: Add narrative regression assertions before editing prose**

Require the deep dive to state all of the following concepts:

```text
five bounded selected-ordinal writers
child one-based ordinal is copied into its resolved parent selected-ordinal field
no source-derived live 1,5,2 triplet
six canonical ProductAction callers remain rejected
decode-incomplete and runtime callback universes remain unresolved
```

Reject stale wording that calls the triplet live, claims ProductAction(10)
delivery, or promotes first-class Creative Look/recovery/camera readiness.

- [ ] **Step 2: Run the narrative test and observe RED**

Run the selected-node unittest module. Expected: phrase assertion failure before the Markdown is updated.

- [ ] **Step 3: Regenerate the report from authenticated sources**

Run:

```powershell
.\.venv\Scripts\python.exe tools\static\export_a6400_creative_style_selected_node_identity_boundary.py
```

Validate the report through `validate_creative_style_selected_node_identity_boundary_report` and capture its canonical digest for the final handoff.

- [ ] **Step 4: Update the deep-dive boundary wording**

Replace the current broad boundary paragraph around lines 533–581 with the schema-3 result. State exact positive mechanisms and the earliest remaining unresolved edge. Do not call a conditional provider route runtime evidence and do not infer imaging semantics.

- [ ] **Step 5: Prove deterministic regeneration**

Hash the checked JSON, regenerate it again, and require the SHA-256 to be identical. Run the report validator after both generations.

- [ ] **Step 6: Run focused verification**

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.analysis.test_creative_style_selected_node_identity_boundary tests.analysis.test_creative_style_activation_caller_boundary tests.analysis.test_creative_style_selected_state_dispatch tests.analysis.test_creative_style_definition_registration tests.analysis.test_creative_style_menu_list_construction tests.analysis.test_creative_style_view_lifecycle_boundary tests.analysis.test_creative_style_interaction_surface -v
```

Expected: all pass.

- [ ] **Step 7: Run full analysis and safety verification**

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests\analysis -p "test_*.py"
```

Then:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests\safe -p "test_*.py"
```

Expected: both suites pass with no skipped safety gate caused by this change.

- [ ] **Step 8: Run final static checks**

Run `py_compile` on every modified Python file, `git diff --check`, the report validator, and `git status --short`. Confirm no artifact, binary, updater, device, or unrelated file entered the diff.

- [ ] **Step 9: Commit the report and narrative**

```powershell
git add analysis/a6400-creative-style-selected-node-identity-boundary.json analysis/a6400a-updater-and-creative-style-deep-dive.md pmca/analysis/creative_style_selected_node_identity_boundary.py tools/static/export_a6400_creative_style_selected_node_identity_boundary.py tests/analysis/test_creative_style_selected_node_identity_boundary.py
git commit -m "publish selected-node live delivery boundary"
```

- [ ] **Step 10: Push and verify exact synchronization**

Push `feature/a6400-updater-re-lab`, fetch the remote branch, and require local HEAD, upstream HEAD, and `refs/remotes/origin/feature/a6400-updater-re-lab` to be the same SHA with ahead/behind `0 0`. Report the exact commit SHA, report SHA-256, test counts, and remaining first unresolved boundary.

## Execution choice

The repository is already a linked worktree. This session will use inline execution with `superpowers:executing-plans`, because unrequested subagent dispatch is not permitted by the active coordination rules. Each task retains its own RED/GREEN/commit checkpoint.
