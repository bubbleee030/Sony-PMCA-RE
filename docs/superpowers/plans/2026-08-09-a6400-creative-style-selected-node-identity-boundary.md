# α6400 Creative Style Selected-Node Identity Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a deterministic fail-closed artifact that proves the static ViewSettingMenu child path `0 → 4 → 1` reaches the Creative Style root while keeping the corresponding runtime selected ordinals `1 → 5 → 2` and all activation/product claims unresolved.

**Architecture:** Add a standalone analysis contract and static exporter rather than expanding the activation-caller report. The exporter will join a backup-selected product root, a control-flow-aware 1,748-constructor graph, three relocation-backed list edges, and the candidate `getSelectedItem` implementation; the normalized report will distinguish static membership from runtime selection.

**Tech Stack:** Python 3, `unittest`, pyelftools, Capstone, deterministic JSON, existing `pmca.analysis` report/validator conventions.

## Global Constraints

- Static/offline analysis only; never execute a Sony binary or access a camera/device.
- Never add USB, updater/service-mode, partition-write, flash/package-generation, or raw-key capability.
- Creative Style remains target-native substrate and cannot satisfy first-class Creative Look acceptance.
- Runtime selection, process-ID activation, processing/output, installability, recovery, and camera eligibility remain false.
- Every positive field requires exact source-byte, control-flow, dataflow, relocation, and dependency validation.
- Source mutations operate on in-memory byte arrays or adapters, never on firmware files.
- Use `apply_patch` for repository edits.

---

### Task 1: Add the selected-node report contract

**Files:**
- Create: `pmca/analysis/creative_style_selected_node_identity_boundary.py`
- Create: `tests/analysis/test_creative_style_selected_node_identity_boundary.py`

**Interfaces:**
- Consumes: validated activation, Creative Style definition, and menu-list report digests.
- Produces: `normalize_creative_style_selected_node_identity_boundary_export(document: dict) -> dict`, `build_creative_style_selected_node_identity_boundary_report(raw: dict) -> dict`, and `validate_creative_style_selected_node_identity_boundary_report(document: dict) -> dict`.

- [ ] **Step 1: Write the failing normalized-contract test**

Add a fixture with the exact public shape and assertions:

```python
def test_exact_static_path_is_positive_but_runtime_selection_is_false(self):
    report = validate_creative_style_selected_node_identity_boundary_report(
        build_creative_style_selected_node_identity_boundary_report(self.raw)
    )
    self.assertEqual(report["schema_version"], 1)
    self.assertEqual(report["static_path"]["zero_based_indices"], [0, 4, 1])
    self.assertEqual(report["runtime_selection"]["required_one_based_ordinals"], [1, 5, 2])
    self.assertTrue(report["claims"]["creative_style_static_selected_child_path_0_4_1_found"])
    self.assertFalse(report["claims"]["runtime_selected_ordinal_triplet_1_5_2_proven"])
    self.assertFalse(report["claims"]["runtime_selected_node_is_creative_style_root_proven"])
    self.assertFalse(report["claims"]["process_id_42_activation_accepted"])
    self.assertFalse(report["claims"]["first_class_creative_look_proven"])
    self.assertEqual(
        report["first_unresolved_boundary"],
        "viewsettingmenu-runtime-selected-ordinal-triplet-1-5-2-and-action-provenance",
    )
```

- [ ] **Step 2: Run the new test and confirm RED**

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest -v tests.analysis.test_creative_style_selected_node_identity_boundary
```

Expected: import failure because the contract module does not exist.

- [ ] **Step 3: Implement the minimal exact schema and normalizer**

Define immutable constants for schema version 1, dependency records, the source records, the five evidence sections, claims, readiness, first unresolved boundary, and narrative hash. Implement exact key-set/type/value checks; do not accept unknown keys.

The normalized claims must be exactly:

```python
CLAIMS = {
    "product_root_selector_found": True,
    "default_product_root_constructor_found": True,
    "creative_style_static_selected_child_path_0_4_1_found": True,
    "candidate_get_selected_item_semantics_found": True,
    "runtime_constructor_provider_binding_proven": False,
    "runtime_selected_ordinal_triplet_1_5_2_proven": False,
    "runtime_selected_node_is_creative_style_root_proven": False,
    "process_id_42_activation_accepted": False,
    "viewcreative_style_factory_invocation_proven": False,
    "first_class_creative_look_proven": False,
    "processing_or_output_binding_proven": False,
    "installable": False,
    "recovery_validated": False,
    "camera_test_eligible": False,
}
```

- [ ] **Step 4: Add fail-closed schema and narrative mutation tests**

Use table-driven mutations that flip every positive/negative claim, alter `[0,4,1]`, alter `[1,5,2]`, change the first unresolved boundary, change a dependency digest, and replace the conclusion with each prohibited claim:

```python
for text in (
    "The runtime selected node is Creative Style.",
    "Process ID 42 is activated.",
    "Creative Look is implemented.",
    "The package is installable and camera testing is eligible.",
):
    mutated = copy.deepcopy(report)
    mutated["conclusion"] = text
    with self.assertRaises(ValueError):
        validate_creative_style_selected_node_identity_boundary_report(mutated)
```

- [ ] **Step 5: Run the contract tests and commit**

Run the focused test until all cases pass, then:

```powershell
git add pmca/analysis/creative_style_selected_node_identity_boundary.py tests/analysis/test_creative_style_selected_node_identity_boundary.py
git commit -m "add selected-node identity contract"
```

---

### Task 2: Implement the control-flow-aware static exporter

**Files:**
- Create: `tools/static/export_a6400_creative_style_selected_node_identity_boundary.py`
- Modify: `tests/analysis/test_creative_style_selected_node_identity_boundary.py`

**Interfaces:**
- Consumes: contract constants and validators from Task 1; shared ELF helpers from the existing activation/menu-list exporters.
- Produces: `FileAdapter.metadata() -> dict`, `build_raw_export(adapter=None) -> dict`, `build_report(adapter=None) -> dict`, `write_report(report: dict) -> None`, and a read-only CLI `main()`.

- [ ] **Step 1: Add RED tests for source and dependency enforcement**

Test that `build_raw_export()` rejects a wrong VU2 digest, wrong CautionConfig digest, stale activation digest, stale definition digest, stale menu-list digest, and symlink/non-regular inputs.

- [ ] **Step 2: Add RED tests for product-root selection**

Mutate in-memory bytes or decoded instructions for:

- backup ID literal cell `0x20882C` (`0x01070316`);
- backup-read call `0x20865A` and its PLT symbol;
- TBH selector at `0x208668` and value bound 75;
- default root materialization `0x20881A/0x20881C → 0xB09B5C`;
- slot-54 call `0x210986 → 0x208648`;
- same-receiver store `0x21098C → [r4+0x1A0]`.

Each mutation must raise a label-specific `RuntimeError`.

- [ ] **Step 3: Implement exact product-root validation**

Decode owner `[0x208648,0x2088F0)`, parse the 75-entry TBH table as data rather than instructions, resolve every landing block, and emit the exact selector-value/return-root mapping plus 49 unique returns. Validate the slot-54 receiver capture, call, return preservation, and store.

- [ ] **Step 4: Add RED tests for the constructor graph**

Mutate one branch-over-literal-pool edge, each of the three C1 calls, each node/list/count/properties argument, and the generic C1 PLT relocation. Assert the exporter rejects traversal counts other than 23,355 reachable instructions, 1,748 C1 calls, or unresolved target constructor arguments.

- [ ] **Step 5: Implement reachable Thumb traversal and constant dataflow**

Implement a bounded one-instruction decoder rooted at `0x213B8C`:

```python
def _reachable_thumb_cfg(context, start=0x213B8C, end=0x228BA4):
    # Calls fall through without following their target.
    # Returns stop. Direct conditional branches add target and fallthrough.
    # Direct unconditional branches add only the target.
    # Every successor must remain inside the exact EXIDX owner.
    return instructions_by_site, successors
```

Run forward constant propagation with intersection at merges. Capture `r0..r3` immediately before direct C1 PLT calls and require:

```python
EXPECTED_CONSTRUCTORS = {
    0x21EE7E: (0xB09B5C, 0x957C80, 5, 0xB1A36C),
    0x21EDCA: (0xB152A8, 0x956B78, 8, 0xB1A3D4),
    0x21EAFA: (0xB12364, 0x9548BC, 6, 0xB1A394),
}
```

- [ ] **Step 6: Add RED relocation-path tests**

Mutate each cell/addend/index/type/symbol independently:

```python
EXPECTED_PATH = (
    (0, 0x957C80, 64482, 23, 0, 0xB152A8),
    (4, 0x956B88, 64238, 23, 0, 0xB12364),
    (1, 0x9548C0, 130947, 2, 901, 0),
)
```

The last record must resolve dynsym 901 exactly to the undefined symbol `cmnViewSettingNodeRootCreativeStyle`.

- [ ] **Step 7: Implement the relocation-backed path validator**

Require each cell to fall inside the constructor-bounded list range, require its exact list index, and follow only validated `R_ARM_RELATIVE` targets. Join the final ABS32 symbol to the authenticated definition dependency without asserting runtime symbol resolution.

- [ ] **Step 8: Add RED selected-child mechanism tests**

Mutate the root load `[this+0x1A0]`, any of the three vptr loads, any `+0x28` target load, an indirect-call register, an output pointer transfer, the candidate `getSelectedItem` selected-ordinal load `+0x18`, its positivity/clamp/subtract-one flow, or candidate `getSubNode` list/count loads `+4/+8`.

- [ ] **Step 9: Implement selected-child and candidate-provider validation**

Validate `[0x207C4A,0x207C8C)` as exactly three chained calls whose output receiver becomes the next input and whose final child is returned. Validate CautionConfig dynsym/vtable slots 10 and 60 plus owners `0x7C6BD2` and `0x7C72CC`; label them conditional candidates and keep provider/runtime identity false.

- [ ] **Step 10: Run focused exporter tests and commit**

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest -v tests.analysis.test_creative_style_selected_node_identity_boundary
.\.venv\Scripts\python.exe -m py_compile pmca\analysis\creative_style_selected_node_identity_boundary.py tools\static\export_a6400_creative_style_selected_node_identity_boundary.py tests\analysis\test_creative_style_selected_node_identity_boundary.py
```

Then commit:

```powershell
git add tools/static/export_a6400_creative_style_selected_node_identity_boundary.py tests/analysis/test_creative_style_selected_node_identity_boundary.py
git commit -m "trace Creative Style selected-node path"
```

---

### Task 3: Generate and integrate the checked evidence

**Files:**
- Create: `analysis/a6400-creative-style-selected-node-identity-boundary.json`
- Modify: `analysis/a6400a-updater-and-creative-style-deep-dive.md`
- Modify: `tests/analysis/test_creative_style_selected_node_identity_boundary.py`

**Interfaces:**
- Consumes: `build_report()` and the validator from Tasks 1–2.
- Produces: a checked deterministic report and conservative deep-dive narrative.

- [ ] **Step 1: Add RED checked-report and deterministic-regeneration tests**

Require the checked JSON to equal a fresh real-source report. Run the builder twice in memory and assert canonical equality and identical evidence digest. Add a failure-before-write test by corrupting a dependency through an adapter and asserting the checked file hash remains unchanged.

- [ ] **Step 2: Implement validated atomic report writing**

Build and validate the complete raw/report objects before any write. Write a temporary JSON beside the destination, validate the serialized result, and replace exactly `analysis/a6400-creative-style-selected-node-identity-boundary.json`. Do not write firmware or other analysis reports.

- [ ] **Step 3: Generate the report twice and verify determinism**

Run the exporter twice and compare SHA-256 hashes of the checked JSON. Validate it through the contract module after each run.

- [ ] **Step 4: Update the deep dive conservatively**

Add a section stating:

- default product-root construction and the static list path `0 → 4 → 1` are proven;
- candidate base semantics translate that path to one-based runtime ordinals `1 → 5 → 2`;
- no runtime event/selected-state proof establishes those ordinal values;
- process ID 42 activation, factory invocation, Creative Look, processing/output, recovery, installability, and camera eligibility remain unproven/false;
- the next experiment is selected-ordinal mutation/caller provenance, not firmware modification.

- [ ] **Step 5: Run cross-slice tests and commit**

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest -v tests.analysis.test_creative_style_selected_node_identity_boundary tests.analysis.test_creative_style_activation_caller_boundary tests.analysis.test_creative_style_definition_registration tests.analysis.test_creative_style_menu_list_construction
```

Then commit:

```powershell
git add analysis/a6400-creative-style-selected-node-identity-boundary.json analysis/a6400a-updater-and-creative-style-deep-dive.md tests/analysis/test_creative_style_selected_node_identity_boundary.py
git commit -m "publish selected-node identity evidence"
```

---

### Task 4: Verify and publish the milestone

**Files:**
- Verify only; modify prior task files solely to fix failures within this spec.

**Interfaces:**
- Consumes: all outputs from Tasks 1–3.
- Produces: a verified local branch and synchronized GitHub branch.

- [ ] **Step 1: Run focused and cross-slice verification**

Run the new test module, activation/definition/menu-list modules, view-lifecycle and interaction modules, and any dependency tests named by failures. Record exact pass counts.

- [ ] **Step 2: Run full analysis and safety suites**

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests\analysis -t .
.\.venv\Scripts\python.exe -m unittest discover -s tests\safe -t .
```

Expected: all tests pass; no skip may conceal a required authenticated-source test when local sources are available.

- [ ] **Step 3: Run static hygiene checks**

Run Python compilation for every changed Python file, regenerate the report twice, validate checked equality, run `git diff --check`, and inspect `git status --short` for only intended changes.

- [ ] **Step 4: Commit any verification-only corrections**

If verification required a correction, stage only files in this plan and commit:

```powershell
git commit -m "harden selected-node identity evidence"
```

If no correction was needed, do not create an empty commit.

- [ ] **Step 5: Push and verify remote identity**

Push `feature/a6400-updater-re-lab`, then require local `HEAD`, upstream tracking SHA, and `git ls-remote` SHA to match exactly. Report the final commit range and preserve the overall goal as active because first-class Creative Look and verified recovery remain incomplete.
