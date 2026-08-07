# α6400 Evidence Corrections and Runtime Binding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Correct the α6400 Creative Style substrate evidence, replace false UI-factory provenance with the real vertical-classical factory, and document the generic ModelManager runtime-binding boundary without promoting it to a native Creative Look pipeline.

**Architecture:** Keep corrections in the smallest authoritative evidence unit: refine the existing selector contract in place, add focused static contracts for the vertical-classical factory and ModelManager runtime binding, and have UI/feature/recovery summaries consume only validated outputs. Every positive claim is pinned to module identity plus bounded control/data-flow metadata; every unresolved runtime, touch, Creative Look, installability, and recovery claim remains fail-closed.

**Tech Stack:** Python 3 via `.venv\Scripts\python.exe`, `unittest`, `pyelftools`, Capstone, immutable JSON evidence reports, Markdown research summaries, Git.

## Global Constraints

- Use only the canonical repository `C:\Users\Bubble\ChatGPT\Sony\Sony-PMCA-RE-a6400-analysis`; never treat `C:\ChatGPT` as canonical.
- Static/offline only: do not access a camera, execute Sony camera binaries, write USB or camera partitions, enter updater/service mode, build an installable package, or flash firmware.
- Preserve all unrelated user changes and existing uncommitted work.
- Never export raw firmware instructions, reconstructive byte arrays, raw key material, decrypted payloads, or installable artifacts.
- Creative Look remains the product goal; Creative Style is only the α6400-native substrate and Creative Style emulation remains a fallback.
- Keep `runtime_execution_proven=false`, `installable=false`, `camera_test_eligible=false`, and `creative_look_equivalence_found=false` throughout this slice.
- Keep exact Taiwan/region-0 firmware 2.00 recovery at `BLOCKED_STATIC_EVIDENCE` until a separately validated external restoration path exists.
- Build every checked-in JSON report through its validator/exporter; do not edit generated JSON by hand.
- Use test-first implementation and mutation tests that fail when any claimed byte-level relationship is corrupted.
- Use `.\.venv\Scripts\python.exe` for all Python commands because the system interpreter does not provide the pinned analysis dependencies.
- Save only reviewed local Git commits; do not push or open a pull request unless the user later asks.

---

### Task 1: Correct Selector Table Initialization and Static Setter/Getter Joins

**Files:**
- Modify: `pmca/analysis/creative_style_selector_code.py`
- Modify: `tools/static/export_a6400_creative_style_selector_code.py`
- Modify: `tests/analysis/test_creative_style_selector_code.py`
- Regenerate: `analysis/a6400-creative-style-selector-code.json`

**Interfaces:**
- Consumes: pinned `lib/viewUnified2.so` identity from `SOURCE`, existing `normalize_creative_style_selector_code_export(document: dict) -> dict`, and the selector/getter validators already in the exporter.
- Produces: `record_id_tables`, `static_setter_getter_family_join_found`, `numeric_record_ids_resolved`, and `record_id_source_initialization_resolved` in `EXPECTED_EXPORT`; `build_creative_style_selector_code_report(export_document: dict) -> dict`; the runtime transaction/index and human-label claims remain false.

- [ ] **Step 1: Add failing schema and semantic tests for four initialized table families**

Add assertions that the normalized export contains four setter/getter families, bounded row counts, read-only source locations, equal scalar ID rows, and conservative claims:

```python
def test_four_record_id_tables_are_initialized_and_value_identical(self):
    report = self.module.EXPECTED_EXPORT
    tables = report["record_id_tables"]
    self.assertEqual([item["row_count"] for item in tables], [7, 20, 20, 20])
    self.assertTrue(all(item["setter_getter_values_equal"] for item in tables))
    self.assertTrue(report["claims"]["numeric_record_ids_resolved"])
    self.assertTrue(report["claims"]["record_id_source_initialization_resolved"])
    self.assertTrue(report["claims"]["static_setter_getter_family_join_found"])
    self.assertFalse(report["claims"]["dynamic_setter_getter_record_join_found"])
    self.assertFalse(report["claims"]["human_field_names_resolved"])
```

Add exact expected metadata for setter sources `0x7B8560`, `0x7B82F8`, `0x7B8348`, `0x7B8398`, getter sources `0x7B8544`, `0x7B84F4`, `0x7B857C`, `0x7B85CC`, destinations `+0xF8`, `+0xA8`, `+0x58`, `+0x08`, and total row count 67.

- [ ] **Step 2: Run the focused test and confirm the old unresolved contract fails**

Run:

```powershell
& '.\.venv\Scripts\python.exe' -m unittest tests.analysis.test_creative_style_selector_code -v
```

Expected: FAIL because `record_id_tables` and `static_setter_getter_family_join_found` are absent and the old claims remain false.

- [ ] **Step 3: Add normalized scalar table metadata and fail-closed claims**

In `creative_style_selector_code.py`, introduce an exact constant with one entry per family. Store numeric record IDs only as bounded integers; do not store raw source bytes:

```python
RECORD_ID_TABLE_SPECS = [
    {
        "role": "selector-code",
        "row_count": 7,
        "setter": {"source": 0x7B8560, "destination_offset": 0xF8},
        "getter": {"source": 0x7B8544, "destination_offset": 0xF8},
    },
    {
        "role": "argument-3",
        "row_count": 20,
        "setter": {"source": 0x7B82F8, "destination_offset": 0xA8},
        "getter": {"source": 0x7B84F4, "destination_offset": 0xA8},
    },
    {
        "role": "argument-4",
        "row_count": 20,
        "setter": {"source": 0x7B8348, "destination_offset": 0x58},
        "getter": {"source": 0x7B857C, "destination_offset": 0x58},
    },
    {
        "role": "argument-5",
        "row_count": 20,
        "setter": {"source": 0x7B8398, "destination_offset": 0x08},
        "getter": {"source": 0x7B85CC, "destination_offset": 0x08},
    },
]
```

Populate each `record_ids` tuple from the validated scalar words read by the exporter, then update the exact export fields and claim discipline:

```python
"numeric_record_ids_resolved": True,
"record_id_source_initialization_resolved": True,
"static_setter_getter_family_join_found": True,
"dynamic_setter_getter_record_join_found": False,
"human_field_names_resolved": False,
```

Do not rename ABI roles `argument-3`, `argument-4`, or `argument-5` to conventional picture-adjustment labels.

- [ ] **Step 4: Validate all copy sites, read-only containment, and family equality in the exporter**

Add helpers with explicit inputs and return types:

```python
def _read_scalar_words(blob, mappings, source: int, count: int) -> tuple[int, ...]:
    """Read bounded little-endian scalar IDs from a validated mapped range."""

def _validate_record_id_tables(elf, blob, mappings, deps) -> list[dict]:
    """Validate setter/getter copy sites and return normalized scalar metadata."""
```

For each family, require source containment in `.rodata [0x666968, 0x812DEE)`, exact count, exact destination, exact copy/call sites, and `setter_values == getter_values`. Validate setter backup sites `0x489556/0x48955A`, `0x489570/0x489574`, `0x489584/0x489588`, `0x489594/0x489598` and getter output transfers for fields 3/4/5, while retaining the fixed `0x01070762` write/read/output-2 join.

- [ ] **Step 5: Add mutation coverage for every new evidence edge**

Add table-driven mutations that alter one source, count, destination, copy site, ID load/call, getter output store, or scalar family value and assert `RuntimeError`:

```python
for family, field in itertools.product(range(4), ("setter_source", "getter_source")):
    with self.subTest(family=family, field=field):
        with self.assertRaises(RuntimeError):
            self.exporter._validate_record_id_tables(
                elf, mutated_blob(family, field), mappings, deps
            )
```

Also assert the normalizer rejects any mutation that sets runtime index equality, human field names, selected-menu identity, renderer effects, or Creative Look equivalence to true.

- [ ] **Step 6: Run focused tests and regenerate the selector report**

Run:

```powershell
& '.\.venv\Scripts\python.exe' -m unittest tests.analysis.test_creative_style_selector_code -v
& '.\.venv\Scripts\python.exe' tools\static\export_a6400_creative_style_selector_code.py
& '.\.venv\Scripts\python.exe' -c "from pmca.analysis.creative_style_selector_code import write_creative_style_selector_code_report; write_creative_style_selector_code_report()"
& '.\.venv\Scripts\python.exe' -m unittest tests.analysis.test_creative_style_selector_code -v
```

Expected: all selector tests pass; the regenerated report promotes only static initialization/numeric-domain equality and retains runtime/semantic negatives.

- [ ] **Step 7: Commit the selector correction**

```powershell
git add pmca/analysis/creative_style_selector_code.py tools/static/export_a6400_creative_style_selector_code.py tests/analysis/test_creative_style_selector_code.py analysis/a6400-creative-style-selector-code.json
git commit -m "analysis: correct creative style record tables"
```

---

### Task 2: Replace False UI Owners with the Real Vertical-Classical Factory

**Files:**
- Modify: `pmca/analysis/vertical_layout_factory_trace.py`
- Modify: `tools/static/export_a6400_vertical_layout_factory.py`
- Modify: `tests/analysis/test_vertical_layout_factory_trace.py`
- Regenerate: `analysis/a6400-vertical-layout-factory.json`
- Modify: `pmca/analysis/ui_factory_owner_registration.py`
- Modify: `tools/static/export_a6400_ui_factory_owner_registration.py`
- Modify: `tests/analysis/test_ui_factory_owner_registration.py`
- Regenerate: `analysis/a6400-ui-factory-owner-registration.json`
- Modify: `pmca/analysis/ui_dispatch.py`
- Modify: `tests/analysis/test_ui_dispatch.py`
- Modify: `tools/ghidra/export_a6400_ui_dispatch.py`
- Regenerate: `analysis/a6400-ui-dispatch-boundary.json`
- Modify: `pmca/analysis/target_features.py`
- Modify: `tests/analysis/test_target_features.py`
- Regenerate: `analysis/a6400-target-features.json`
- Create: `tools/static/regenerate_a6400_ui_evidence_reports.py`

**Interfaces:**
- Consumes: pinned `viewUnified7.so`, `viewUnified2.so`, `master_camera.uxc`, and `viewStlrec.uxc` identities already used by `ui_dispatch.py`.
- Produces: the strengthened existing `normalize_vertical_layout_factory_export(document: dict) -> dict`, `summarize_vertical_layout_factory_export(document: dict) -> dict`, `validate_vertical_layout_factory_report(document: object) -> dict`, and a UI report reference keyed by the canonical vertical-factory and owner-registration report digests.

- [ ] **Step 1: Write failing vertical-factory contract tests**

Create tests for the exact owner, five vertical-classical arms, wrapper, five address-taken registrations, and unresolved runtime invocation:

```python
def test_vertical_subset_and_registration_boundary(self):
    normalized = normalize_vertical_layout_factory_export(raw_export())
    self.assertEqual(normalized["factory"]["owner"], {"start": 0x52840, "end": 0x529B8})
    self.assertEqual(normalized["factory"]["total_constructor_arm_count"], 12)
    self.assertEqual(len(normalized["factory"]["vertical_classical_arms"]), 5)
    self.assertFalse(normalized["claims"]["runtime_factory_invocation_proven"])
    self.assertFalse(normalized["claims"]["orientation_to_factory_join_proven"])
```

Pin group ID `0x1B906244`; class IDs and constructor sites: `0x61DC811C -> 0x52934`, `0x186C17F6 -> 0x52944`, `0x8E7FDF88 -> 0x52914`, `0x7BE1C309 -> 0x52954`, `0xBDBC36BD -> 0x52924`.

- [ ] **Step 2: Run the new suite and confirm the module is absent**

Run:

```powershell
& '.\.venv\Scripts\python.exe' -m unittest tests.analysis.test_vertical_layout_factory_trace tests.analysis.test_ui_factory_owner_registration -v
```

Expected: FAIL because the existing contracts omit the 12-arm owner, group/class decision tree, relocation indices, and runtime-invocation negative.

- [ ] **Step 3: Implement the fail-closed vertical-factory evidence schema**

Strengthen the existing focused schema so its positive claims stop at constructor selection and registration:

```python
CLAIMS = {
    "vertical_layout_factory_found": True,
    "five_wrapper_registrations_found": True,
    "runtime_factory_invocation_proven": False,
    "view_unified2_to_factory_edge_found": False,
    "orientation_to_factory_join_proven": False,
    "portrait_geometry_proven": False,
    "touch_coordinate_transform_proven": False,
    "menu_selection_dispatch_proven": False,
}

def normalize_vertical_layout_factory_export(document: dict) -> dict:
    if document != EXPECTED_EXPORT:
        raise VerticalLayoutFactoryTraceError("vertical factory export differs")
    return copy.deepcopy(document)
```

Represent the four invalid old offsets explicitly: `0x181F18` as an internal conditional branch, and `0x24222C`, `0x3BA6DC`, `0x651684` as non-instruction-boundary second halfwords. Represent `0x37B614`, `0x37AA18`, `0x37B5E0`, `0x37B648`, and `0x37B578` as constructor/vptr-material paths with `class_id_load=False`.

- [ ] **Step 4: Implement byte-level factory and relocation validation**

In the static exporter, pin module size/digest before decoding and validate:

```python
def _validate_factory(blob, mappings, deps, exidx, plt_symbols) -> dict:
    """Validate owner, group/class decision tree, allocations, and constructors."""

def _validate_wrapper_registrations(elf, blob, mappings, deps, rels) -> dict:
    """Validate wrapper forwarding plus five R_ARM_RELATIVE address-taken cells."""
```

Require wrapper call `0x529D6 -> 0x52840`. In `ui_factory_owner_registration`, extend the existing five relocation records with exact `.rel.dyn` indices `1268, 1286, 1305, 1327, 1349` at sites `0x70EE8, 0x70FA0, 0x71040, 0x710F0, 0x711A0`, normalized pointer `0x529CC`. Require no direct `viewUnified2.so -> viewUnified7.so` dependency or edge, but phrase that result as a bounded no-join, not a global absence.

- [ ] **Step 5: Add mutation tests for owners, boundaries, arms, and registrations**

Test altered group/class literals, compare/branch sites, constructor calls, wrapper forwarding, relocation type/index/site/target, and invalid-boundary classifications:

```python
with self.assertRaises(RuntimeError):
    self.exporter._validate_wrapper_registrations(
        elf, blob, mappings, deps, mutate_relocation(index=1268, target=0x529CE)
    )
```

Also assert registration cells cannot promote `runtime_factory_invocation_proven`, geometry, touch, or menu selection.

- [ ] **Step 6: Remove `uxc_owner_functions` from UI dispatch and consume the new report**

Delete `_UXC_OWNER_FUNCTIONS`, `_UXC_OWNER_FIELDS`, and `uxc_owner_functions` from the UI schema and tests. Add exact fields:

```python
_TOP_FIELDS = (_TOP_FIELDS - {"uxc_owner_functions"}) | {
    "invalid_offset_classifications",
    "vertical_factory_reference",
}
```

The reference must carry only the canonical report digest, `resource_reference_count=10`, `vertical_constructor_arm_count=5`, `wrapper_registration_count=5`, and false runtime/orientation joins. Preserve each UXC class-ID occurrence as `semantic="reference-only"`.

- [ ] **Step 7: Correct target-feature derivation and stale terminal labels**

Update `target_features.py` and tests so derived UI status uses the vertical-factory report and no longer treats `0x1B9B6A` or `0x1BB30E` as a factory handoff. Pin `0x1B9B6A` as a local branch landing and `0x1BB30E` as the exposure-mode getter PLT call. Keep orientation selector, portrait/landscape geometry, control-direction transform, touch transform, hit test, and menu-selection false.

- [ ] **Step 8: Run focused suites and regenerate all four reports**

Run:

```powershell
& '.\.venv\Scripts\python.exe' -m unittest tests.analysis.test_vertical_layout_factory_trace tests.analysis.test_ui_factory_owner_registration tests.analysis.test_ui_dispatch tests.analysis.test_target_features -v
& '.\.venv\Scripts\python.exe' tools\static\regenerate_a6400_ui_evidence_reports.py
& '.\.venv\Scripts\python.exe' -m unittest tests.analysis.test_vertical_layout_factory_trace tests.analysis.test_ui_factory_owner_registration tests.analysis.test_ui_dispatch tests.analysis.test_target_features -v
```

The deterministic `build_report()` helpers added to the four validators are called by `regenerate_a6400_ui_evidence_reports.py`. It validates each full document and atomically replaces only `a6400-vertical-layout-factory.json`, `a6400-ui-factory-owner-registration.json`, `a6400-ui-dispatch-boundary.json`, and `a6400-target-features.json`.

- [ ] **Step 9: Commit the corrected UI provenance**

```powershell
git add pmca/analysis/vertical_layout_factory_trace.py tools/static/export_a6400_vertical_layout_factory.py tests/analysis/test_vertical_layout_factory_trace.py analysis/a6400-vertical-layout-factory.json pmca/analysis/ui_factory_owner_registration.py tools/static/export_a6400_ui_factory_owner_registration.py tests/analysis/test_ui_factory_owner_registration.py analysis/a6400-ui-factory-owner-registration.json pmca/analysis/ui_dispatch.py tests/analysis/test_ui_dispatch.py tools/ghidra/export_a6400_ui_dispatch.py analysis/a6400-ui-dispatch-boundary.json pmca/analysis/target_features.py tests/analysis/test_target_features.py analysis/a6400-target-features.json tools/static/regenerate_a6400_ui_evidence_reports.py
git commit -m "analysis: correct vertical layout provenance"
```

---

### Task 3: Add the Generic ModelManager Runtime-Binding Contract

**Files:**
- Create: `pmca/analysis/creative_style_runtime_binding.py`
- Create: `tools/static/export_a6400_creative_style_runtime_binding.py`
- Create: `tests/analysis/test_creative_style_runtime_binding.py`
- Create: `analysis/a6400-creative-style-runtime-binding.json`

**Interfaces:**
- Consumes: `analysis/a6400-creative-style-model-request-transport.json` as a pinned upstream report, exact `libObj.so` identity, and canonical-digest conventions used by adjacent Creative Style contracts.
- Produces: `normalize_creative_style_runtime_binding_export(document: dict) -> dict`, `summarize_creative_style_runtime_binding_export(document: dict) -> dict`, `build_creative_style_runtime_binding_report(export_document: dict) -> dict`, and `validate_creative_style_runtime_binding_report(document: object) -> dict`.

- [ ] **Step 1: Write failing contract tests for the generic binding boundary**

Create tests that separate proven generic machinery from unresolved identities:

```python
def test_generic_loader_and_executor_are_proven_without_modelcamera_identity(self):
    claims = self.module.CLAIMS
    self.assertTrue(claims["model_camera_name_split_proven"])
    self.assertTrue(claims["generic_dynamic_loader_chain_proven"])
    self.assertTrue(claims["generic_executor_schedule_path_proven"])
    self.assertTrue(claims["destination_4_default_receiver_reached"])
    self.assertFalse(claims["model_camera_numeric_id_resolved"])
    self.assertFalse(claims["record_is_modelcamera_proven"])
    self.assertFalse(claims["executor_is_modelcamera_proven"])
    self.assertFalse(claims["five_field_consumption_proven"])
    self.assertFalse(claims["native_creative_look_pipeline_proven"])
```

- [ ] **Step 2: Run the new suite and confirm the contract is absent**

Run:

```powershell
& '.\.venv\Scripts\python.exe' -m unittest tests.analysis.test_creative_style_runtime_binding -v
```

Expected: ERROR importing `pmca.analysis.creative_style_runtime_binding`.

- [ ] **Step 3: Implement the exact evidence and report schemas**

Define focused sections for `id_generator`, `model_manager_records`, `dynamic_loader`, `modelcamera_candidate`, `generic_executor`, `destination_4`, `claims`, and `evidence_digest`. The negative claim set must include:

```python
UNPROVEN_CLAIMS = (
    "model_camera_numeric_id_resolved",
    "record_is_modelcamera_proven",
    "executor_is_modelcamera_proven",
    "concrete_operation_38_handler_proven",
    "five_field_consumption_proven",
    "live_view_binding_proven",
    "still_jpeg_binding_proven",
    "movie_binding_proven",
    "native_creative_look_pipeline_proven",
    "runtime_execution_proven",
    "installable",
)
```

Validate the upstream report path and canonical digest, but do not copy its large transport body into the new report.

- [ ] **Step 4: Validate `model/CAMERA` splitting and unresolved ID registration**

Pin `IdGenerator::Get [0x402DB4,0x402EC4)`, splitter `[0x402424,0x4024A0)`, map lookup `0x402E0A -> 0x402BEC`, `IdTable::findId` at `0x402E34` with owner `[0x4002AE,0x4002E4)`, and `SetTable [0x402C66,0x402C7E)` with store `0x402C7A`. Validate the only static extracted call `0x37FD10` registers `view`, not `model`, then keep the `model` table and `CAMERA` row numeric value unresolved.

- [ ] **Step 5: Validate record construction and the dynamic loader chain**

Add bounded validators for the manager map at `+0x88`, lookup `[0x84903E,0x849088)`, record construction `[0x849D88,0x849E58)`, size `0x24`, executor initialization at `0x8410CE`, and activation `[0x841124,0x8411A4)`:

```python
DYNAMIC_LOADER = {
    "component_path_load": {"site": 0x841130, "record_offset": 0x10},
    "dlopen_call": 0x841132,
    "symbol_name_load": {"site": 0x84113C, "record_offset": 0x14},
    "dlsym_call": 0x841140,
    "factory_call": 0x84114C,
    "executor_store": {"site": 0x84114E, "record_offset": 0x1C},
}
```

Validate the `dlopen` and `dlsym` relocations/symbols and the descriptor-derived key/path/symbol fields, while keeping the provider that populates the exact runtime descriptor unresolved.

- [ ] **Step 6: Validate ModelCamera compatibility without claiming record identity**

Pin the co-located bounded strings `@M00B`, `modelCamera.so`, and `ModelCameraToInstance` at `.rodata 0xF03447`; factory `[0x4D32E0,0x4D3304)`; RTTI/vptr evidence; and slot cell `0x1341B08 -> [0x3FE6B4,0x3FE6DC)`. Require absence of a static relocation/dataflow join from the manifest triple to the runtime descriptor, so compatible candidate evidence cannot set `record_is_modelcamera_proven`.

- [ ] **Step 7: Validate the generic scheduler and destination-4 default path**

Pin the candidate branch keys 6/7/8, secondary Event creation, executor Event store `0x843018`, virtual slot load/call `0x843028/0x84302A`, fixed scheduler Event ID `0x11004001`, destination 4, tag 0, receiver `0x846710`, and default predicate call `0x8468D2`. Assert the slot does not read the incoming Event/Creative Style fields and that `0x11004001` has no dedicated switch case.

- [ ] **Step 8: Add mutation tests across every runtime-binding boundary**

Cover the splitter, map/row lookup, record offsets, loader symbols/relocations, factory result store, vtable slot, scheduler Event header, destination mask, receiver comparisons, and default call. For semantic protections:

```python
for claim in self.module.UNPROVEN_CLAIMS:
    mutated = copy.deepcopy(self.module.EXPECTED_EXPORT)
    mutated["claims"][claim] = True
    with self.subTest(claim=claim), self.assertRaises(
        self.module.CreativeStyleRuntimeBindingError
    ):
        self.module.normalize_creative_style_runtime_binding_export(mutated)
```

- [ ] **Step 9: Run focused tests and generate the runtime-binding report**

Run:

```powershell
& '.\.venv\Scripts\python.exe' -m unittest tests.analysis.test_creative_style_runtime_binding -v
& '.\.venv\Scripts\python.exe' tools\static\export_a6400_creative_style_runtime_binding.py
& '.\.venv\Scripts\python.exe' -m unittest tests.analysis.test_creative_style_runtime_binding -v
```

Expected: all tests pass; exporter `main()` writes the bounded raw artifact and atomically regenerates the validator-built checked-in report; the report proves generic name lookup, loader, executor, scheduler, and default routing while all identity/pipeline/runtime/installability claims remain false.

- [ ] **Step 10: Commit the runtime-binding contract**

```powershell
git add pmca/analysis/creative_style_runtime_binding.py tools/static/export_a6400_creative_style_runtime_binding.py tests/analysis/test_creative_style_runtime_binding.py analysis/a6400-creative-style-runtime-binding.json
git commit -m "analysis: map creative style runtime binding"
```

---

### Task 4: Sharpen the Interaction Surface and Recovery False-Lead Boundary

**Files:**
- Modify: `pmca/analysis/creative_style_interaction_surface.py`
- Modify: `tools/static/export_a6400_creative_style_interaction_surface.py`
- Modify: `tests/analysis/test_creative_style_interaction_surface.py`
- Regenerate: `analysis/a6400-creative-style-interaction-surface.json`
- Modify: `pmca/analysis/cxd90045_transition_report.py`
- Modify: `tests/analysis/test_cxd90045_transition_report.py`
- Regenerate: `analysis/a6400-cxd90045-transition-boundary.json`
- Modify: `pmca/analysis/recovery_path.py`
- Modify: `tests/analysis/test_recovery_path.py`
- Regenerate: `analysis/a6400-stock-200-recovery.json`
- Create: `tools/static/regenerate_a6400_interaction_recovery_reports.py`

**Interfaces:**
- Consumes: the existing interaction and CXD90045 report validators plus their pinned artifacts.
- Produces: exact generic `Widget* -> PAS_BtnCombo::cast` evidence and a `packaged_selector_scan` recovery object; neither changes touch readiness or stock-recovery eligibility.

- [ ] **Step 1: Write failing tests for the corrected widget-cast boundary**

Assert the thunk/interworking/PLT/cast chain and unresolved field provenance:

```python
def test_widget_lookup_only_reaches_generic_btncombo_cast(self):
    edge = self.module.EXPECTED_EXPORT["post_lookup_widget_cast"]
    self.assertEqual(edge["thunk_owner"], {"start": 0x599C54, "end": 0x599C60})
    self.assertEqual(edge["symbol"], "_ZN12PAS_BtnCombo4castEPN2ux6wgtsys6WidgetE")
    self.assertTrue(edge["generic_widget_type_filter_proven"])
    self.assertFalse(self.module.CLAIMS["creative_style_touch_route_found"])
    self.assertFalse(self.module.CLAIMS["menu_selection_dispatch_found"])
    self.assertFalse(self.module.CLAIMS["field_0x14c_concrete_type_resolved"])
```

- [ ] **Step 2: Run the interaction suite and confirm the new edge is absent**

Run:

```powershell
& '.\.venv\Scripts\python.exe' -m unittest tests.analysis.test_creative_style_interaction_surface -v
```

Expected: FAIL because the report does not yet expose the exact cast boundary.

- [ ] **Step 3: Implement and mutation-test the interaction correction**

Validate call `0x5CE128 -> 0x599C54`, tail `0x599C5C -> 0x1501AC`, interworking veneer `0x1501B0`, GOT `0x944F48`, `.rel.plt[551]`, cast owner `[0x599510,0x59953C)`, virtual type slot `+0x190`, and original-widget-or-null result. Record no direct `ViewCreativeStyle+0x14C` store in the bounded derived/default-base constructor owners, stopping at unresolved external `ViewBase::C2` from `0x2F29FC`. Add mutations for call target, gate/veneer, relocation, symbol, virtual slot, type comparison, and constructor sites.

- [ ] **Step 4: Write failing recovery tests for the packaged selector scan**

Extend the transition report schema expectation with:

```python
"packaged_selector_scan": {
    "updater_flag_state_proven": True,
    "lsi_notification_proven": True,
    "packaged_flag_consumer_proven": True,
    "nflasha1_selector_join_proven": False,
    "updater_partition_selector_present": False,
    "bootin_direct_updater_selector": False,
    "external_or_opaque_selector_unresolved": True,
}
```

Assert `recovery_validated`, `camera_test_eligible`, and `installable` remain false and readiness remains `BLOCKED_STATIC_EVIDENCE`.

- [ ] **Step 5: Run transition and recovery tests and confirm schema failure**

Run:

```powershell
& '.\.venv\Scripts\python.exe' -m unittest tests.analysis.test_cxd90045_transition_report tests.analysis.test_recovery_path -v
```

Expected: FAIL because `packaged_selector_scan` is not in the exact schema.

- [ ] **Step 6: Implement the packaged-selector false-lead evidence**

Increment the transition schema version and validate the four bounded `libObj.so` consumer owners, parsed `up.sh`/nested updater component coverage, crypter flag-file evidence, and `bootin.elf` modes `normal`, `adj`, and `usbj`. State only that no parsable recovered component joins flag/LSI state to `/dev/nflasha1`; preserve the possibility of an unavailable partition, boot component, or opaque runtime boundary.

- [ ] **Step 7: Thread the transition reference into strict stock recovery**

Update `recovery_path.py` so the canonical transition-report digest and conservative selector-scan result are validated inputs. Keep the required exact TW/region-0 version `2.00` target and all recovery/camera/installability flags false.

- [ ] **Step 8: Run focused suites and regenerate interaction/recovery reports**

Run:

```powershell
& '.\.venv\Scripts\python.exe' -m unittest tests.analysis.test_creative_style_interaction_surface tests.analysis.test_cxd90045_transition_report tests.analysis.test_recovery_path -v
& '.\.venv\Scripts\python.exe' tools\static\export_a6400_creative_style_interaction_surface.py
& '.\.venv\Scripts\python.exe' tools\static\regenerate_a6400_interaction_recovery_reports.py
& '.\.venv\Scripts\python.exe' -m unittest tests.analysis.test_creative_style_interaction_surface tests.analysis.test_cxd90045_transition_report tests.analysis.test_recovery_path -v
```

`regenerate_a6400_interaction_recovery_reports.py` calls newly added deterministic builders, validates each result, and atomically replaces only the interaction, transition, and stock-recovery JSON reports. It reads bounded metadata and never executes a Sony binary.

- [ ] **Step 9: Commit the interaction and recovery boundary update**

```powershell
git add pmca/analysis/creative_style_interaction_surface.py tools/static/export_a6400_creative_style_interaction_surface.py tests/analysis/test_creative_style_interaction_surface.py analysis/a6400-creative-style-interaction-surface.json pmca/analysis/cxd90045_transition_report.py tests/analysis/test_cxd90045_transition_report.py analysis/a6400-cxd90045-transition-boundary.json pmca/analysis/recovery_path.py tests/analysis/test_recovery_path.py analysis/a6400-stock-200-recovery.json tools/static/regenerate_a6400_interaction_recovery_reports.py
git commit -m "analysis: sharpen touch and recovery boundaries"
```

---

### Task 5: Reconcile Downstream Creative Look, UI, and Recovery Summaries

**Files:**
- Modify: `analysis/a6400a-updater-and-creative-style-deep-dive.md`
- Modify: `analysis/a6400-updater-re-report.md`
- Modify: `analysis/a6400-feasibility-report.md`
- Modify: report-validation tests that pin phrases or authoritative digests discovered by `rg`

**Interfaces:**
- Consumes: corrected selector, vertical-factory, UI-dispatch, target-feature, interaction, runtime-binding, transition, and stock-recovery reports.
- Produces: consistent human-readable synthesis with Creative Look as the first-class goal and Creative Style explicitly labeled as substrate/fallback.

- [ ] **Step 1: Find every stale owner/factory/table/runtime claim**

Run:

```powershell
rg -n "uxc_owner_functions|0x181f18|0x24222c|0x3ba6dc|0x651684|record_id_source_initialization_resolved|dynamic_record_ids_resolved|Creative Look|Creative Style|BLOCKED_STATIC_EVIDENCE" analysis pmca tests
```

Classify each match against the authoritative corrected report before editing it.

- [ ] **Step 2: Add failing summary-consistency assertions**

In the closest existing report test, assert summaries contain the corrected distinctions:

```python
self.assertIn("Creative Look remains the product goal", text)
self.assertIn("Creative Style is the target-native substrate", text)
self.assertIn("registration does not prove runtime invocation", text)
self.assertIn("static table equality does not prove a runtime transaction", text)
self.assertIn("BLOCKED_STATIC_EVIDENCE", text)
```

Also assert stale `viewUnified2` factory/owner language is absent.

- [ ] **Step 3: Run the affected summary tests and confirm failure**

Run the exact modules located in Step 2 with:

```powershell
& '.\.venv\Scripts\python.exe' -m unittest tests.analysis.test_target_features tests.analysis.test_recovery_path -v
```

Expected: FAIL on one or more new phrase/digest assertions until the Markdown and derived metadata are reconciled.

- [ ] **Step 4: Update the deep dive and feasibility narrative**

Write the following evidence hierarchy consistently:

```text
Product target: first-class Creative Look experience and α7 V-like interaction.
Target-native substrate: Creative Style typed setter/getter, persistence, UI scaffold, and generic model request.
Proven additions: static record-ID tables, real vertical-classical factory registration, generic runtime loader/scheduler boundaries.
Unresolved boundary: runtime descriptor identity, field consumption, image pipeline, touch routing, and orientation-to-factory invocation.
Fallback only: Creative Style-based visual emulation if native Creative Look behavior cannot be established.
```

Correct selector numeric-ID wording, remove invalid UI owner/factory wording, and include the new runtime-binding/default-receiver boundary.

- [ ] **Step 5: Update the updater report without weakening recovery**

Record the updater flag/LSI/consumer false leads and explicitly state that the missing `/dev/nflasha1` selector join blocks an exact external restore procedure. Include no operational camera/updater commands.

- [ ] **Step 6: Run summary tests and a stale-claim scan**

Run:

```powershell
& '.\.venv\Scripts\python.exe' -m unittest tests.analysis.test_target_features tests.analysis.test_recovery_path -v
rg -n "reference-owner-only|master-layout factory|vertical-info factory|dynamic record IDs remain unresolved" analysis pmca tests
```

Expected: tests pass and the stale-claim scan has no positive claim that contradicts the corrected contracts.

- [ ] **Step 7: Commit downstream reconciliation**

```powershell
git add analysis/a6400a-updater-and-creative-style-deep-dive.md analysis/a6400-updater-re-report.md analysis/a6400-feasibility-report.md tests/analysis
git commit -m "docs: reconcile creative look evidence boundaries"
```

---

### Task 6: Full Verification, Independent Review, and Local Checkpoint

**Files:**
- Review: all files changed by Tasks 1-5
- Modify only if verification or review identifies a concrete defect

**Interfaces:**
- Consumes: all focused task outputs and local commits.
- Produces: a clean, reviewed local branch checkpoint with no push or pull request.

- [ ] **Step 1: Compile every changed Python file**

Run:

```powershell
$changedPython = git diff --name-only ec3b429..HEAD -- '*.py'
& '.\.venv\Scripts\python.exe' -m py_compile $changedPython
```

Expected: exit code 0 and no output.

- [ ] **Step 2: Run focused suites together**

Run:

```powershell
& '.\.venv\Scripts\python.exe' -m unittest tests.analysis.test_creative_style_selector_code tests.analysis.test_vertical_layout_factory_trace tests.analysis.test_ui_factory_owner_registration tests.analysis.test_ui_dispatch tests.analysis.test_target_features tests.analysis.test_creative_style_runtime_binding tests.analysis.test_creative_style_interaction_surface tests.analysis.test_cxd90045_transition_report tests.analysis.test_recovery_path -v
```

Expected: all focused tests pass.

- [ ] **Step 3: Run the complete analysis and safety suites**

Run:

```powershell
& '.\.venv\Scripts\python.exe' -m unittest discover -s tests\analysis -p 'test_*.py'
& '.\.venv\Scripts\python.exe' -m unittest discover -s tests\safety -p 'test_*.py'
```

Expected: both suites pass with zero failures and zero errors.

- [ ] **Step 4: Verify report consistency, repository safety, and formatting**

Run:

```powershell
git diff --check
git status --short
rg -n "camera_test_eligible.*true|installable.*true|creative_look_equivalence_found.*true|runtime_execution_proven.*true" analysis pmca tests
rg -n "BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|key_material|decrypted_payload|installable_package" . --glob '!*.pyc'
```

Expected: `git diff --check` is clean; only intended files are changed; no forbidden positive claims, private-key blocks, reconstructive payload fields, or installable artifacts appear.

- [ ] **Step 5: Request independent read-only review**

Give a reviewer the approved spec, plan, diff, and exact constraints. Require findings ordered by severity and ask them to verify selector initialization, Thumb boundaries, vertical-factory registrations, runtime-binding non-promotions, recovery gating, and mutation-test coverage. The reviewer must not edit files.

- [ ] **Step 6: Apply only verified review fixes and rerun affected/full tests**

For each concrete finding, reproduce it with a failing test, apply the minimum correction, rerun the focused suite, then rerun Steps 1-4. If review is clean, make no speculative edits.

- [ ] **Step 7: Create the final local checkpoint if review fixes changed the tree**

```powershell
git add pmca tools tests analysis docs/superpowers/plans/2026-08-07-a6400-evidence-corrections-runtime-binding.md
git commit -m "analysis: finalize a6400 evidence corrections"
```

If the tree is already clean because Tasks 1-5 were committed without review fixes, do not create an empty commit.

- [ ] **Step 8: Report status without pushing**

Report the local commit IDs, focused/full/safety test counts, corrected positive findings, unresolved Creative Look/touch/runtime/recovery boundaries, and confirm that no camera operation, package creation, push, or pull request occurred.
