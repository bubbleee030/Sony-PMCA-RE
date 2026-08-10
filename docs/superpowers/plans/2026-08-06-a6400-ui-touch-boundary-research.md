# α6400 UI and Touch Boundary Research Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recover the α6400 orientation-to-layout, control-direction, touch-coordinate, hit-test, and menu-selection boundaries needed to reproduce the α7 V-generation interface experience without executing camera binaries.

**Architecture:** Define the desired interface as a fail-closed behavior contract, export bounded indirect-call and resource-reference evidence from pinned α6400 modules, correlate that evidence without treating names as behavior, and integrate only proven boundaries into the existing target-feature report. All Ghidra work is read-only; generated intermediate data stays ignored and only normalized addresses, hashes, classifications, and conclusions enter Git.

**Tech Stack:** Python 3, `unittest`, JSON, Ghidra/PyGhidra with JDK 21, Thumb static analysis, existing `pmca.analysis` validators, Git.

## Global Constraints

- The canonical workspace is `C:\Users\Bubble\ChatGPT`; never use `C:\ChatGPT` as the canonical location.
- The repository is `C:\Users\Bubble\ChatGPT\Sony\Sony-PMCA-RE-a6400-analysis`.
- The current phase is static and offline.
- Do not connect a camera, execute Sony camera binaries, write USB or camera partitions, enter updater/service mode, or flash firmware.
- Do not print or commit raw key material, Sony binaries, decrypted payloads, disassembly dumps, or reconstructive byte arrays.
- Preserve unrelated user changes and keep generated proprietary artifacts below ignored `.artifacts/` directories.
- Identical α7 V code is not required; interface and behavior fidelity are the success criteria.
- Creative Look and external recovery are separate plans; this plan must not implement a Creative Style fallback or claim installability.
- Every positive claim requires pinned target evidence; unresolved virtual, indirect, or UXC dispatch remains unestablished.

---

## File structure

| Path | Action | Responsibility |
|---|---|---|
| `pmca/analysis/modern_ui_contract.py` | Create | Validate the fixed modern-interface behavior contract. |
| `tests/analysis/test_modern_ui_contract.py` | Create | Prove exact contract membership and fail-closed status handling. |
| `analysis/a6400-modern-ui-contract.json` | Create | Record required experience behaviors without donor-code assumptions. |
| `pmca/analysis/ui_dispatch.py` | Create | Normalize and validate bounded indirect-call/UI-dispatch evidence. |
| `tests/analysis/test_ui_dispatch.py` | Create | Exercise direct, virtual, table, UXC, and unresolved evidence rules. |
| `tools/ghidra/export_a6400_ui_dispatch.py` | Create | Export addresses and classifications from pinned read-only Ghidra programs. |
| `pmca/analysis/uxc_references.py` | Create | Find exact target names/class IDs in UXC resources without asserting semantics. |
| `tests/analysis/test_uxc_references.py` | Create | Test bounded name/ID reference discovery and truncation rejection. |
| `analysis/a6400-ui-dispatch-boundary.json` | Create | Store normalized target-only dispatch evidence and unresolved boundaries. |
| `pmca/analysis/target_features.py` | Modify | Require the new indirect/UXC trace while rejecting capability promotion. |
| `tests/analysis/test_target_features.py` | Modify | Pin the new report and negative claim behavior. |
| `analysis/a6400-target-features.json` | Modify | Add only evidence produced by this plan. |
| `analysis/a6400a-updater-and-creative-style-deep-dive.md` | Modify | Explain new paths, negative searches, and remaining portability gaps. |

### Task 1: Encode the modern-interface behavior contract

**Files:**
- Create: `pmca/analysis/modern_ui_contract.py`
- Create: `tests/analysis/test_modern_ui_contract.py`
- Create: `analysis/a6400-modern-ui-contract.json`

**Interfaces:**
- Consumes: no earlier task output.
- Produces: `validate_modern_ui_contract(document: dict) -> dict` and the exact behavior IDs consumed by Tasks 4 and 5.

- [ ] **Step 1: Write the failing contract tests**

```python
import copy
import json
import unittest
from pathlib import Path

from pmca.analysis.modern_ui_contract import (
    ModernUiContractError,
    validate_modern_ui_contract,
)

ROOT = Path(__file__).resolve().parents[2]


class ModernUiContractTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(
            (ROOT / "analysis/a6400-modern-ui-contract.json").read_text("utf-8")
        )

    def test_contract_contains_exact_required_behaviors(self):
        validated = validate_modern_ui_contract(self.document)
        self.assertEqual(
            [item["id"] for item in validated["behaviors"]],
            [
                "shooting-layout-landscape",
                "shooting-layout-portrait-shutter-up",
                "shooting-layout-portrait-shutter-down",
                "orientation-layout-selection",
                "control-direction-transform",
                "touch-coordinate-transform",
                "menu-touch-hit-test",
                "menu-touch-selection",
                "ui-state-persistence",
            ],
        )

    def test_contract_rejects_unproven_implementation_status(self):
        candidate = copy.deepcopy(self.document)
        candidate["behaviors"][3]["status"] = "TARGET_NATIVE"
        with self.assertRaises(ModernUiContractError):
            validate_modern_ui_contract(candidate)
```

- [ ] **Step 2: Run the focused test and confirm the missing module failure**

Run:

```powershell
python -m unittest tests.analysis.test_modern_ui_contract -v
```

Expected: `ERROR` with `ModuleNotFoundError: No module named 'pmca.analysis.modern_ui_contract'`.

- [ ] **Step 3: Implement the exact validator and initial contract**

```python
BEHAVIOR_IDS = (
    "shooting-layout-landscape",
    "shooting-layout-portrait-shutter-up",
    "shooting-layout-portrait-shutter-down",
    "orientation-layout-selection",
    "control-direction-transform",
    "touch-coordinate-transform",
    "menu-touch-hit-test",
    "menu-touch-selection",
    "ui-state-persistence",
)
STATUSES = {
    "TARGET_NATIVE",
    "TARGET_REIMPLEMENTABLE",
    "DONOR_COMPATIBLE",
    "APPROXIMATION_ONLY",
    "HARDWARE_BLOCKED",
    "UNESTABLISHED",
}


class ModernUiContractError(ValueError):
    pass


def validate_modern_ui_contract(document: dict) -> dict:
    if set(document) != {"schema_version", "target", "reference", "behaviors"}:
        raise ModernUiContractError("contract fields are not exact")
    if document["schema_version"] != 1 or document["target"] != "ILCE-6400":
        raise ModernUiContractError("contract identity is invalid")
    if document["reference"] != "ILCE-7M5-interface-behavior":
        raise ModernUiContractError("contract reference is invalid")
    if [item.get("id") for item in document["behaviors"]] != list(BEHAVIOR_IDS):
        raise ModernUiContractError("contract behavior order is invalid")
    for item in document["behaviors"]:
        if set(item) != {"id", "status", "evidence", "acceptance"}:
            raise ModernUiContractError("behavior fields are not exact")
        if item["status"] not in STATUSES:
            raise ModernUiContractError("behavior status is invalid")
        if item["status"] != "UNESTABLISHED" and not item["evidence"]:
            raise ModernUiContractError("established behavior requires evidence")
        if not isinstance(item["acceptance"], str) or not item["acceptance"].strip():
            raise ModernUiContractError("behavior acceptance text is required")
    return copy.deepcopy(document)
```

Create the JSON with all nine behaviors set to `UNESTABLISHED`, empty evidence arrays, and concrete acceptance statements: correct geometry for each orientation, synchronized visible/control/touch transforms, dispatched menu selection, and persistent state. Do not copy α7 V code addresses into this target contract.

- [ ] **Step 4: Run focused tests and validate the committed JSON**

Run:

```powershell
python -m unittest tests.analysis.test_modern_ui_contract -v
python -c "import json; from pathlib import Path; from pmca.analysis.modern_ui_contract import validate_modern_ui_contract; p=Path('analysis/a6400-modern-ui-contract.json'); validate_modern_ui_contract(json.loads(p.read_text('utf-8'))); print('contract valid')"
```

Expected: all tests pass and `contract valid` prints.

- [ ] **Step 5: Commit the contract**

```powershell
git add pmca/analysis/modern_ui_contract.py tests/analysis/test_modern_ui_contract.py analysis/a6400-modern-ui-contract.json
git commit -m "analysis: define a6400 modern UI contract"
```

### Task 2: Add a fail-closed UI dispatch evidence model

**Files:**
- Create: `pmca/analysis/ui_dispatch.py`
- Create: `tests/analysis/test_ui_dispatch.py`
- Create: `analysis/a6400-ui-dispatch-boundary.json`

**Interfaces:**
- Consumes: behavior IDs from `pmca.analysis.modern_ui_contract.BEHAVIOR_IDS`.
- Produces: `normalize_ui_dispatch_export(raw: dict) -> dict` and `validate_ui_dispatch_report(document: dict) -> dict` for Tasks 3–5.

- [ ] **Step 1: Write failing schema and semantic-promotion tests**

```python
def test_unresolved_indirect_edge_does_not_establish_selection(self):
    report = fixture_report(
        edges=[{
            "caller": "0x22355e",
            "site": "0x2237a2",
            "callee": None,
            "kind": "unresolved-indirect",
            "owner": "ViewSettingMenu",
        }],
        claims={"coordinate_consumer_found": False,
                "menu_selection_dispatch_found": False,
                "orientation_layout_selector_found": False},
    )
    self.assertFalse(validate_ui_dispatch_report(report)["claims"]["menu_selection_dispatch_found"])


def test_positive_claim_requires_matching_resolved_path(self):
    report = fixture_report(edges=[], claims={
        "coordinate_consumer_found": False,
        "menu_selection_dispatch_found": True,
        "orientation_layout_selector_found": False,
    })
    with self.assertRaises(UiDispatchError):
        validate_ui_dispatch_report(report)
```

Add cases rejecting raw instruction bytes, disassembly text, unknown edge kinds, duplicate sites, non-Thumb-normalized addresses, mismatched target digest, and a UXC name reference promoted to a dispatch edge.

- [ ] **Step 2: Run the focused test and verify the missing-module failure**

Run: `python -m unittest tests.analysis.test_ui_dispatch -v`

Expected: `ERROR` because `pmca.analysis.ui_dispatch` does not exist.

- [ ] **Step 3: Implement exact types and validation rules**

```python
EDGE_KINDS = {
    "direct",
    "vtable-slot",
    "function-pointer-table",
    "uxc-reference-only",
    "unresolved-indirect",
}
CLAIM_KEYS = {
    "coordinate_consumer_found",
    "menu_selection_dispatch_found",
    "orientation_layout_selector_found",
}


def _claim_has_support(document: dict, claim: str) -> bool:
    required_semantic = {
        "coordinate_consumer_found": "coordinate-consumer",
        "menu_selection_dispatch_found": "menu-selection-dispatch",
        "orientation_layout_selector_found": "orientation-layout-selection",
    }[claim]
    return any(
        path["semantic"] == required_semantic
        and path["resolved"] is True
        and all(edge in {item["id"] for item in document["edges"]}
                for edge in path["edge_ids"])
        for path in document["paths"]
    )
```

The report must require schema version 1, the pinned `viewUnified2.so` SHA-256, fixed roots for `ViewSettingMenu` and `ViewStlrec`, normalized edges, paths, UXC references, negative searches, and exactly the three claims above. Reject forbidden keys `raw`, `bytes`, `payload`, `disassembly`, `private_key`, and `hex_dump` recursively.

- [ ] **Step 4: Add the baseline report and run tests**

Initialize the committed report from existing evidence: include the two established direct semantic boundaries, six bounded negative searches, and empty indirect/UXC resolved paths. Keep all three new claims false. Run:

```powershell
python -m unittest tests.analysis.test_ui_dispatch -v
python -m unittest tests.analysis.test_target_features -v
```

Expected: all tests pass; no existing false capability is promoted.

- [ ] **Step 5: Commit the evidence model**

```powershell
git add pmca/analysis/ui_dispatch.py tests/analysis/test_ui_dispatch.py analysis/a6400-ui-dispatch-boundary.json
git commit -m "analysis: model indirect UI dispatch evidence"
```

### Task 3: Export indirect-call and vtable evidence from pinned modules

**Files:**
- Create: `tools/ghidra/export_a6400_ui_dispatch.py`
- Modify: `tests/analysis/test_ui_dispatch.py`
- Local only: `.artifacts/ui-trace/a6400-v2.00/raw-ui-dispatch.json`

**Interfaces:**
- Consumes: pinned roots and target digests from `analysis/a6400-ui-dispatch-boundary.json`.
- Produces: a raw bounded JSON export accepted by `normalize_ui_dispatch_export(raw)`; it never emits instruction bytes or decompiler text.

- [ ] **Step 1: Add failing normalization fixtures for each dispatch form**

```python
raw = {
    "program": "viewUnified2.so",
    "sha256": VIEW_UNIFIED2_SHA256,
    "edges": [
        {"caller": 0x22355E, "site": 0x2237A2, "target": 0x8DED88,
         "kind": "vtable-slot", "slot": 12, "owner": "ViewSettingMenu"},
        {"caller": 0x1AB000, "site": 0x1AB112, "target": None,
         "kind": "unresolved-indirect", "slot": None, "owner": "ViewStlrec"},
    ],
}
normalized = normalize_ui_dispatch_export(raw)
self.assertEqual(normalized["edges"][0]["site"], "0x2237a2")
self.assertIsNone(normalized["edges"][1]["callee"])
```

Add rejection tests for addresses outside the program image, a target digest mismatch, non-integer raw addresses, and more than 10,000 exported edges.

- [ ] **Step 2: Run the focused normalization tests and confirm failure**

Run: `python -m unittest tests.analysis.test_ui_dispatch -v`

Expected: the new exporter-normalization tests fail because the accepted raw shape is not implemented yet.

- [ ] **Step 3: Implement the bounded Ghidra exporter**

The post-script must:

```python
ROOTS = (0x22355E, 0x1AB41C, 0x1AB2D2, 0x1B1E76)
MAX_FUNCTIONS = 4096
MAX_EDGES = 10000
ALLOWED_KINDS = {
    "direct", "vtable-slot", "function-pointer-table", "unresolved-indirect"
}
```

For each root, walk bounded references and p-code call operations. For direct calls, record the normalized destination. For `CALLIND`, record the call site, containing function, inferred vtable/table base and slot only when the value is statically constant; otherwise use `unresolved-indirect`. Resolve vtable ownership through symbol/RTTI references, but emit only owner names and addresses. Sort by `(caller, site, kind, target)` and write JSON atomically to the explicit output argument.

The script must refuse a writable program, refuse a program name/digest mismatch supplied through its arguments, cap traversal, and omit decompiler text, instruction bytes, strings unrelated to the root set, and raw memory.

- [ ] **Step 4: Run the exporter read-only and normalize the result**

Run the existing pinned PyGhidra environment outside the ordinary sandbox only because JPype/Ghidra requires it; do not enable network or camera access:

```powershell
$repo = 'C:\Users\Bubble\ChatGPT\Sony\Sony-PMCA-RE-a6400-analysis'
$ghidra = 'C:\Users\Bubble\ChatGPT\Sony\Sony-PMCA-RE-a6400-ghidra-tool'
$env:JAVA_HOME = "$repo\.artifacts\tools\microsoft-jdk-21.0.12\extracted\jdk-21.0.12+8"
$env:APPDATA = 'C:\Users\Bubble\ChatGPT\Sony\Sony-PMCA-RE-a6400-ghidra-home\AppData\Roaming'
$env:LOCALAPPDATA = 'C:\Users\Bubble\ChatGPT\Sony\Sony-PMCA-RE-a6400-ghidra-home\AppData\Local'
& "$repo\.artifacts\ghidra-python\Scripts\python.exe" -m pyghidra.ghidra_launch --install-dir $ghidra ghidra.app.util.headless.AnalyzeHeadless 'C:\Users\Bubble\ChatGPT\Sony\Sony-PMCA-RE-a6400-ghidra' a6400-ui-thumb -process viewUnified2.so -readOnly -noanalysis -scriptPath "$repo\tools\ghidra" -postScript export_a6400_ui_dispatch.py "$repo\.artifacts\ui-trace\a6400-v2.00\raw-ui-dispatch.json" viewUnified2.so 1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2
```

Verify the source module digest before and after the run. Normalize the export through `normalize_ui_dispatch_export`; do not copy it into Git until Task 4 correlates and curates it.

- [ ] **Step 5: Commit the exporter and tests only**

```powershell
git add tools/ghidra/export_a6400_ui_dispatch.py tests/analysis/test_ui_dispatch.py pmca/analysis/ui_dispatch.py
git commit -m "analysis: export bounded a6400 UI dispatch edges"
```

### Task 4: Correlate UXC references, vtables, layouts, and coordinate consumers

**Files:**
- Create: `pmca/analysis/uxc_references.py`
- Create: `tests/analysis/test_uxc_references.py`
- Modify: `analysis/a6400-ui-dispatch-boundary.json`
- Modify: `analysis/a6400-modern-ui-contract.json`

**Interfaces:**
- Consumes: normalized edges from Task 3 and the fixed layout names/class IDs already pinned in `analysis/a6400-target-features.json`.
- Produces: `scan_exact_references(blob: bytes, names: tuple[str, ...], class_ids: tuple[int, ...]) -> list[dict]` and curated paths/negative searches for Task 5.

- [ ] **Step 1: Write failing bounded UXC reference tests**

```python
def test_finds_exact_name_and_little_endian_class_id_without_semantic_promotion(self):
    blob = b"prefix\x00Layoutlayout_CMN_M_REC_VERTICAL_CLASSICAL_INFO_LR\x00" + (0x61DC811C).to_bytes(4, "little")
    refs = scan_exact_references(
        blob,
        ("Layoutlayout_CMN_M_REC_VERTICAL_CLASSICAL_INFO_LR",),
        (0x61DC811C,),
    )
    self.assertEqual([item["kind"] for item in refs], ["name", "class-id"])
    self.assertTrue(all(item["semantic"] == "reference-only" for item in refs))
```

Add tests for duplicate occurrences, UTF-8 boundary matching, input-size cap, missing names, class-ID endianness, and deterministic offset ordering.

- [ ] **Step 2: Run the focused tests and verify the missing-module failure**

Run: `python -m unittest tests.analysis.test_uxc_references -v`

Expected: `ERROR` because the scanner module does not exist.

- [ ] **Step 3: Implement the exact-reference scanner and correlator rules**

```python
MAX_UXC_SIZE = 2 * 1024 * 1024


def scan_exact_references(blob: bytes, names: tuple[str, ...], class_ids: tuple[int, ...]) -> list[dict]:
    if len(blob) > MAX_UXC_SIZE:
        raise UxcReferenceError("UXC input exceeds size cap")
    results = []
    for name in names:
        needle = name.encode("utf-8")
        start = 0
        while (offset := blob.find(needle, start)) >= 0:
            results.append({"kind": "name", "value": name, "offset": offset,
                            "semantic": "reference-only"})
            start = offset + 1
    for class_id in class_ids:
        needle = class_id.to_bytes(4, "little")
        start = 0
        while (offset := blob.find(needle, start)) >= 0:
            results.append({"kind": "class-id", "value": f"0x{class_id:08x}",
                            "offset": offset, "semantic": "reference-only"})
            start = offset + 1
    return sorted(results, key=lambda item: (item["offset"], item["kind"], item["value"]))
```

Correlation may promote a UXC reference into a resolved path only when an executable reference loads the same record/class ID and reaches a layout attach, coordinate read, hit-test, or selection side effect. Name proximity alone remains `uxc-reference-only`.

- [ ] **Step 4: Curate positive and negative target findings**

Scan only the pinned `master_camera.uxc` and `viewStlrec.uxc` copies. Cross-reference their exact offsets with Task 3 executable references. Search specifically for:

- roll/orientation state reaching one of the five vertical layout class IDs;
- layout-mode state reaching `0x181f18` or `0x24222c`;
- touch X/Y reads reaching a hit-test rectangle or widget target;
- hit-test success reaching a menu selection/state-change dispatch; and
- landscape/portrait state reaching control-direction or touch-coordinate transforms.

For each target, record a resolved path or a bounded negative search with root count, resolved count, edge kinds traversed, depth cap, and target. Update contract status only for a fully supported behavior; otherwise leave it `UNESTABLISHED`.

- [ ] **Step 5: Run focused tests and commit the correlation layer**

```powershell
python -m unittest tests.analysis.test_uxc_references tests.analysis.test_ui_dispatch tests.analysis.test_modern_ui_contract -v
git add pmca/analysis/uxc_references.py tests/analysis/test_uxc_references.py analysis/a6400-ui-dispatch-boundary.json analysis/a6400-modern-ui-contract.json
git commit -m "analysis: correlate a6400 UXC and UI dispatch evidence"
```

### Task 5: Integrate the indirect trace into the strict target report

**Files:**
- Modify: `pmca/analysis/target_features.py`
- Modify: `tests/analysis/test_target_features.py`
- Modify: `analysis/a6400-target-features.json`

**Interfaces:**
- Consumes: validated Task 2 report and Task 1 contract.
- Produces: schema version 3 target evidence that later Creative Look work can extend without weakening existing false claims.

- [ ] **Step 1: Write failing integration and anti-promotion tests**

```python
def test_indirect_trace_matches_standalone_report(self):
    validated = validate_target_feature_report(self.document)
    standalone = json.loads((REPOSITORY_ROOT / "analysis/a6400-ui-dispatch-boundary.json").read_text("utf-8"))
    self.assertEqual(validated["ui_indirect_trace"], standalone)


def test_uxc_reference_only_cannot_establish_orientation_selector(self):
    candidate = copy.deepcopy(self.document)
    candidate["ui_indirect_trace"]["claims"]["orientation_layout_selector_found"] = True
    with self.assertRaises(TargetFeatureError):
        validate_target_feature_report(candidate)
```

Also test schema version 3, exact field membership, standalone digest consistency, and rejection of positive modern-menu/touch flags without corresponding validated path semantics.

- [ ] **Step 2: Run the integration tests and verify failure**

Run: `python -m unittest tests.analysis.test_target_features -v`

Expected: failures because schema version 2 has no `ui_indirect_trace` field.

- [ ] **Step 3: Add schema version 3 and nested validation**

Import and call `validate_ui_dispatch_report` and `validate_modern_ui_contract`. Require the committed target report's `ui_indirect_trace` object to equal the standalone validated report. Keep:

```python
if document["vertical_ui"]["modern_vertical_menu_established"] is not False:
    raise TargetFeatureError("Modern vertical menu was overclaimed")
if document["touch_ui"]["full_setting_menu_touch_established"] is not False:
    raise TargetFeatureError("Full setting-menu touch was overclaimed")
```

unless this plan produced the complete required path semantics. A partial orientation selector or coordinate consumer may be recorded without flipping the complete-feature booleans.

- [ ] **Step 4: Run focused and full analysis tests**

Run:

```powershell
python -m unittest tests.analysis.test_target_features tests.analysis.test_ui_dispatch tests.analysis.test_modern_ui_contract tests.analysis.test_uxc_references -v
python -m unittest discover -s tests/analysis -v
```

Expected: all tests pass. Record the exact count and duration; do not reuse the earlier 262-test result.

- [ ] **Step 5: Commit the integrated report**

```powershell
git add pmca/analysis/target_features.py tests/analysis/test_target_features.py analysis/a6400-target-features.json
git commit -m "analysis: integrate a6400 indirect UI trace"
```

### Task 6: Document conclusions and verify the UI/touch milestone

**Files:**
- Modify: `analysis/a6400a-updater-and-creative-style-deep-dive.md`
- Modify when evidence changes: `analysis/feature-compatibility.json`
- Modify when evidence changes: `analysis/a6400-feasibility-report.md`

**Interfaces:**
- Consumes: all validated reports from Tasks 1–5.
- Produces: the reviewed UI/touch boundary milestone and explicit next target for the Creative Look plan.

- [ ] **Step 1: Add a results section with exact evidence boundaries**

Document:

- every new resolved virtual/table path with ordered offsets and semantic endpoint;
- every bounded negative search with traversal type and cap;
- whether orientation selection, coordinate consumption, hit testing, and selection dispatch are individually established;
- which behavior-contract items changed status and why; and
- why a name, vtable, resource reference, or status/configuration call was not promoted.

Do not include raw decompiler output, instruction bytes, proprietary resource bodies, or raw keys.

- [ ] **Step 2: Update compatibility only from validated evidence**

If no complete path was found, retain `vertical-layout-selection`, `vertical-input-transform`, and `touch-event-routing` as unresolved and strengthen their precise boundary text. If a complete path was found, update only that dependency and cite `analysis/a6400-ui-dispatch-boundary.json`; do not mark the whole modern interface ready.

- [ ] **Step 3: Run the complete verification set**

```powershell
python -m compileall -q pmca tests
python -m unittest discover -s tests/analysis -v
git diff --check
git status --short
```

Expected: compile exit 0, all analysis tests pass, no whitespace errors, and only planned files changed before the final commit.

- [ ] **Step 4: Scan the candidate diff for forbidden content**

```powershell
git diff --numstat
git diff --name-only | Select-String -Pattern '\.(so|dat|bin|exe|dll|img|key)$'
rg -n "private_key|raw_payload|hex_dump|BEGIN .*PRIVATE KEY" pmca tests analysis tools/ghidra
```

Expected: no proprietary binary is changed. Review every text match and require it
to be a rejection rule or negative test—not committed key/payload content. Source
scripts must contain only bounded metadata logic.

- [ ] **Step 5: Commit the milestone**

```powershell
git add analysis/a6400a-updater-and-creative-style-deep-dive.md analysis/feature-compatibility.json analysis/a6400-feasibility-report.md
git commit -m "docs: report a6400 UI and touch boundary"
```

Do not push, create a PR, connect a camera, or begin the Creative Look plan until this task's review checkpoint is accepted.
