# α6400 First-Class Creative Look Research Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Determine and prototype offline the strongest evidence-supported path to a first-class Creative Look experience on α6400—its own interface, ten base looks, persistent state, eight separately assessed adjustment axes, and verified image-pipeline bindings—without relabeling Creative Style as Creative Look.

**Architecture:** Model Creative Look as independent interface, state, base-look, axis, and pipeline layers; authenticate target and donor evidence before tracing it; export bounded metadata from pinned modules; and classify every layer through the approved hardware capability gate. Creative Style remains isolated as a fallback result that cannot satisfy native Creative Look acceptance tests.

**Tech Stack:** Python 3, `unittest`, JSON, Ghidra/PyGhidra with JDK 21, existing firmware manifests and strict validators, Git.

## Global Constraints

- The canonical workspace is `C:\Users\Bubble\ChatGPT`; never use `C:\ChatGPT` as the canonical location.
- The repository is `C:\Users\Bubble\ChatGPT\Sony\Sony-PMCA-RE-a6400-analysis`.
- Execute this plan only after the UI/touch boundary plan reaches its review checkpoint.
- The phase is static/offline: no camera connection, Sony camera-binary execution, partition writes, service/updater mode, or firmware flashing.
- Never print or commit raw keys, Sony binaries, decrypted payloads, disassembly dumps, or reconstructive tables.
- Preserve unrelated user changes; keep proprietary/generated material under ignored `.artifacts/` directories.
- Creative Look is a first-class workflow. Creative Style recipes or the existing selector patch are the last fallback and must not be labeled native Creative Look.
- Do not claim exact Sony colorimetry without authenticated tables or controlled measurement.
- Exclude features that require absent processor, sensor, memory, peripheral, or acceleration capability; do not use one blocked axis to reject unrelated layers.
- External stock-2.00 recovery is handled by the following plan and remains mandatory before any future camera test.

---

## File structure

| Path | Action | Responsibility |
|---|---|---|
| `pmca/analysis/creative_look_stack.py` | Create | Validate ten looks, eight axes, five layers, and fallback separation. |
| `tests/analysis/test_creative_look_stack.py` | Create | Enforce exact membership, evidence, and native-claim gates. |
| `analysis/a6400-creative-look-stack.json` | Create | Store layer-by-layer target compatibility and evidence. |
| `pmca/analysis/creative_look_sources.py` | Create | Classify target/donor artifacts without reading unsupported opaque data as code. |
| `tests/analysis/test_creative_look_sources.py` | Create | Test digest, availability, extracted/opaque, and mismatch states. |
| `analysis/a6400-creative-look-sources.json` | Create | Pin evidence availability for α6400, α6400A, α6700, and α7 V. |
| `pmca/analysis/creative_look_trace.py` | Create | Normalize bounded graph/handler/persistence/pipeline evidence. |
| `tests/analysis/test_creative_look_trace.py` | Create | Reject graph names or selectors promoted into processing claims. |
| `tools/ghidra/export_creative_look_boundaries.py` | Create | Export target/donor addresses and classifications from read-only programs. |
| `analysis/a6400-creative-look-boundary.json` | Create | Store normalized Creative Look layer evidence and negative searches. |
| `pmca/analysis/target_features.py` | Modify | Integrate Creative Look evidence without weakening existing false claims. |
| `tests/analysis/test_target_features.py` | Modify | Pin Creative Look layer and anti-fallback behavior. |
| `analysis/a6400-target-features.json` | Modify | Add verified Creative Look research results. |
| `analysis/a6400a-updater-and-creative-style-deep-dive.md` | Modify | Report native/reimplementation findings before fallback results. |
| `analysis/a6400-creative-look-guide.md` | Modify | Reframe recipes explicitly as fallback-only if still retained. |

### Task 1: Define the first-class Creative Look stack contract

**Files:**
- Create: `pmca/analysis/creative_look_stack.py`
- Create: `tests/analysis/test_creative_look_stack.py`
- Create: `analysis/a6400-creative-look-stack.json`

**Interfaces:**
- Consumes: no earlier Creative Look task output.
- Produces: `validate_creative_look_stack(document: dict) -> dict`, `LOOK_IDS`, `AXIS_IDS`, and `LAYER_IDS` for every later task.

- [ ] **Step 1: Write failing exact-membership and anti-fallback tests**

```python
import copy
import json
import unittest
from pathlib import Path

from pmca.analysis.creative_look_stack import (
    CreativeLookStackError,
    validate_creative_look_stack,
)

ROOT = Path(__file__).resolve().parents[2]


class CreativeLookStackTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(
            (ROOT / "analysis/a6400-creative-look-stack.json").read_text("utf-8")
        )

    def test_exact_looks_axes_and_layers(self):
        result = validate_creative_look_stack(self.document)
        self.assertEqual(result["looks"], ["ST", "PT", "NT", "VV", "VV2", "FL", "IN", "SH", "BW", "SE"])
        self.assertEqual(result["axes"], ["contrast", "highlights", "shadows", "fade", "saturation", "sharpness", "sharpness_range", "clarity"])
        self.assertEqual(list(result["layers"]), ["interface", "state", "base_looks", "adjustment_axes", "pipeline_binding"])

    def test_creative_style_fallback_cannot_set_native_claim(self):
        candidate = copy.deepcopy(self.document)
        candidate["fallback"]["creative_style_available"] = True
        candidate["native_creative_look_established"] = True
        with self.assertRaises(CreativeLookStackError):
            validate_creative_look_stack(candidate)
```

Add tests requiring eight separate axis records, rejecting omitted/nonzero-unavailable axes, rejecting duplicate look IDs, and requiring all five layers to be `TARGET_NATIVE`, `TARGET_REIMPLEMENTABLE`, or `DONOR_COMPATIBLE` before `native_creative_look_established` may become true.

- [ ] **Step 2: Run tests and verify the missing-module failure**

Run: `python -m unittest tests.analysis.test_creative_look_stack -v`

Expected: `ERROR` with missing `pmca.analysis.creative_look_stack`.

- [ ] **Step 3: Implement the strict stack validator**

```python
LOOK_IDS = ("ST", "PT", "NT", "VV", "VV2", "FL", "IN", "SH", "BW", "SE")
AXIS_IDS = ("contrast", "highlights", "shadows", "fade", "saturation", "sharpness", "sharpness_range", "clarity")
LAYER_IDS = ("interface", "state", "base_looks", "adjustment_axes", "pipeline_binding")
STATUSES = {
    "TARGET_NATIVE", "TARGET_REIMPLEMENTABLE", "DONOR_COMPATIBLE",
    "APPROXIMATION_ONLY", "HARDWARE_BLOCKED", "UNESTABLISHED",
}
NATIVE_CAPABLE = {"TARGET_NATIVE", "TARGET_REIMPLEMENTABLE", "DONOR_COMPATIBLE"}


def _native_stack_complete(document: dict) -> bool:
    return all(document["layers"][layer]["status"] in NATIVE_CAPABLE for layer in LAYER_IDS)
```

Require exact fields: schema/identity, ordered looks/axes, ordered layers, per-axis records, per-output pipeline records (`live_view`, `still_jpeg`, `movie`), fallback policy, and native claim. Each non-`UNESTABLISHED` status requires at least one bounded evidence reference. A fallback reference may appear only under `fallback`, never as evidence for a native-capable layer.

- [ ] **Step 4: Create and validate the baseline report**

Set all five layers and all eight axes to `UNESTABLISHED`; keep the existing three-axis Creative Style knowledge only in `fallback`; set `native_creative_look_established` false. Run:

```powershell
python -m unittest tests.analysis.test_creative_look_stack -v
python -c "import json; from pathlib import Path; from pmca.analysis.creative_look_stack import validate_creative_look_stack; validate_creative_look_stack(json.loads(Path('analysis/a6400-creative-look-stack.json').read_text('utf-8'))); print('stack valid')"
```

Expected: all tests pass and `stack valid` prints.

- [ ] **Step 5: Commit the stack contract**

```powershell
git add pmca/analysis/creative_look_stack.py tests/analysis/test_creative_look_stack.py analysis/a6400-creative-look-stack.json
git commit -m "analysis: define first-class Creative Look stack"
```

### Task 2: Gate target and donor evidence by authenticated availability

**Files:**
- Create: `pmca/analysis/creative_look_sources.py`
- Create: `tests/analysis/test_creative_look_sources.py`
- Create: `analysis/a6400-creative-look-sources.json`

**Interfaces:**
- Consumes: committed firmware manifests/reports and caller-supplied ignored paths.
- Produces: `classify_artifact(path: Path | None, expected_size: int, expected_sha256: str, extracted: bool) -> dict` and `validate_creative_look_sources(document: dict) -> dict`.

- [ ] **Step 1: Write failing source-state tests**

```python
def test_authenticated_opaque_donor_cannot_supply_executable_evidence(self):
    result = classify_artifact(
        fixture_path,
        expected_size=len(payload),
        expected_sha256=hashlib.sha256(payload).hexdigest(),
        extracted=False,
    )
    self.assertEqual(result["state"], "AUTHENTICATED_OPAQUE")
    self.assertFalse(result["executable_evidence_available"])


def test_digest_mismatch_fails_closed(self):
    with self.assertRaises(CreativeLookSourceError):
        classify_artifact(fixture_path, len(payload), "00" * 32, extracted=True)
```

Add states `UNAVAILABLE`, `AUTHENTICATED_OPAQUE`, and `AUTHENTICATED_EXTRACTED`; reject caller-provided `extracted=True` unless the path is inside an ignored `.artifacts/decrypted/` root and the file matches its pinned digest.

- [ ] **Step 2: Run the focused tests and confirm failure**

Run: `python -m unittest tests.analysis.test_creative_look_sources -v`

Expected: missing-module error.

- [ ] **Step 3: Implement digest-first classification**

```python
def _sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def classify_artifact(path, expected_size, expected_sha256, extracted):
    if path is None or not path.exists():
        return {"state": "UNAVAILABLE", "executable_evidence_available": False}
    if path.stat().st_size != expected_size:
        raise CreativeLookSourceError("artifact size mismatch")
    actual = _sha256_file(path)
    if actual != expected_sha256:
        raise CreativeLookSourceError("artifact digest mismatch")
    parts = tuple(part.lower() for part in path.resolve().parts)
    inside_decrypted = any(
        parts[index:index + 2] == (".artifacts", "decrypted")
        for index in range(len(parts) - 1)
    )
    if extracted and not inside_decrypted:
        raise CreativeLookSourceError("extracted artifact is outside ignored storage")
    state = "AUTHENTICATED_EXTRACTED" if extracted else "AUTHENTICATED_OPAQUE"
    return {"state": state, "executable_evidence_available": extracted}
```

The real sources report must list α6400, α6400A, α6700, and α7 V independently, cite existing committed manifest/report paths, record no absolute ignored path, and state that opaque FDAT payloads provide format evidence but not donor function/table evidence.

- [ ] **Step 4: Validate real local availability without changing evidence claims**

Run the classifier against existing ignored artifacts. Expect α6400 extracted modules to be available, α6400A only where already authenticated, and α6700/α7 V to remain opaque or unavailable unless an authenticated decryption result now exists. Never infer decryption from entropy, strings, or filename alone.

- [ ] **Step 5: Commit source classification**

```powershell
python -m unittest tests.analysis.test_creative_look_sources -v
git add pmca/analysis/creative_look_sources.py tests/analysis/test_creative_look_sources.py analysis/a6400-creative-look-sources.json
git commit -m "analysis: gate Creative Look donor evidence"
```

### Task 3: Trace base-look graphs, state handlers, and pipeline sinks

**Files:**
- Create: `pmca/analysis/creative_look_trace.py`
- Create: `tests/analysis/test_creative_look_trace.py`
- Create: `tools/ghidra/export_creative_look_boundaries.py`
- Create: `analysis/a6400-creative-look-boundary.json`
- Local only: `.artifacts/creative-look-trace/<model>/raw-boundaries.json`

**Interfaces:**
- Consumes: Task 2 authenticated source states and pinned α6400 `CautionConfig.so` evidence.
- Produces: `normalize_creative_look_export(raw: dict) -> dict` and `validate_creative_look_boundary(document: dict) -> dict`.

- [ ] **Step 1: Write failing semantic-boundary tests**

```python
def test_selector_to_menu_graph_is_not_a_pipeline_binding(self):
    report = fixture_boundary(
        paths=[{
            "source": "0x7db958",
            "sink": "0xb836cc",
            "semantic": "menu-graph-selection",
            "resolved": True,
        }],
        claims={"base_look_processing_found": False, "pipeline_binding_found": False},
    )
    self.assertFalse(validate_creative_look_boundary(report)["claims"]["pipeline_binding_found"])


def test_pipeline_claim_requires_preview_or_output_sink(self):
    candidate = fixture_boundary(paths=[], claims={
        "base_look_processing_found": False,
        "pipeline_binding_found": True,
    })
    with self.assertRaises(CreativeLookTraceError):
        validate_creative_look_boundary(candidate)
```

Add tests rejecting Creative Style UI nodes as Creative Look processing, opaque donor offsets, raw tables, unbounded path counts, and a claim that omits live-view/still/movie scope.

- [ ] **Step 2: Run tests and verify failure**

Run: `python -m unittest tests.analysis.test_creative_look_trace -v`

Expected: missing-module failure.

- [ ] **Step 3: Implement the validator and bounded exporter contract**

Require exact path semantics:

```python
SEMANTICS = {
    "menu-graph-selection",
    "preset-state-read",
    "preset-state-write",
    "axis-range-validation",
    "base-look-table-load",
    "live-view-sink",
    "still-jpeg-sink",
    "movie-sink",
    "unresolved",
}
```

The Ghidra exporter must start from the pinned α6400 selector function `0x7db958`, compiled graph `0xb836cc`, graph constructors, creative-style node handlers, and any authenticated donor Creative Look roots. Export only function/site/table addresses, bounded scalar metadata, symbols, reference kinds, and output-module identity. Never export table contents, decompiler text, instructions, or raw data. Donor roots are skipped with an explicit `source-not-extracted` negative result when Task 2 says executable evidence is unavailable.

- [ ] **Step 4: Execute target traces and conditional donor traces**

Run the exporter through the same read-only/no-analysis PyGhidra environment used by the UI plan. Target searches must distinguish:

- graph/menu construction from image-processing paths;
- preset reads from writes and default/reset handling;
- table address loads from mere string/name references; and
- live-view, still JPEG, and movie consumers.

Run a donor trace only for an `AUTHENTICATED_EXTRACTED` source. Normalize results into `analysis/a6400-creative-look-boundary.json`, retaining false claims and exact bounded negative searches when no sink is proven.

- [ ] **Step 5: Commit tooling and normalized evidence**

```powershell
python -m unittest tests.analysis.test_creative_look_trace -v
git add pmca/analysis/creative_look_trace.py tests/analysis/test_creative_look_trace.py tools/ghidra/export_creative_look_boundaries.py analysis/a6400-creative-look-boundary.json
git commit -m "analysis: trace Creative Look stack boundaries"
```

### Task 4: Map interface, persistence, and all eight axes independently

**Files:**
- Modify: `analysis/a6400-creative-look-stack.json`
- Modify: `analysis/a6400-creative-look-boundary.json`
- Modify: `tests/analysis/test_creative_look_stack.py`
- Modify: `tests/analysis/test_creative_look_trace.py`

**Interfaces:**
- Consumes: Task 3 normalized paths and Task 1 stack schema.
- Produces: per-layer/per-axis capability classifications consumed by Task 5.

- [ ] **Step 1: Add failing tests for independent axis evidence**

```python
def test_each_axis_has_separate_ui_state_and_pipeline_evidence(self):
    result = validate_creative_look_stack(self.document)
    self.assertEqual(
        set(result["axis_records"]),
        {"contrast", "highlights", "shadows", "fade", "saturation", "sharpness", "sharpness_range", "clarity"},
    )
    for axis, record in result["axis_records"].items():
        self.assertEqual(set(record), {"status", "ui", "state", "pipeline", "evidence", "blocker"})


def test_supported_three_axis_creative_style_is_not_eight_axis_creative_look(self):
    candidate = copy.deepcopy(self.document)
    for axis in ("contrast", "saturation", "sharpness"):
        candidate["axis_records"][axis]["status"] = "TARGET_NATIVE"
        candidate["axis_records"][axis]["evidence"] = ["creative-style-only"]
    candidate["native_creative_look_established"] = True
    with self.assertRaises(CreativeLookStackError):
        validate_creative_look_stack(candidate)
```

- [ ] **Step 2: Run tests and verify the new requirements fail**

Run: `python -m unittest tests.analysis.test_creative_look_stack tests.analysis.test_creative_look_trace -v`

Expected: failures until per-axis semantics are enforced.

- [ ] **Step 3: Trace and classify every axis**

For each axis, require evidence for four separate boundaries: UI handler, state record/default/range, processing sink, and output scope. Classify using only:

- `TARGET_NATIVE` when an α6400 primitive has matching semantics;
- `TARGET_REIMPLEMENTABLE` when verified target primitives can compose the behavior and resource bounds are known;
- `DONOR_COMPATIBLE` only after full donor ABI mapping;
- `APPROXIMATION_ONLY` when only a different control can mimic part of the result;
- `HARDWARE_BLOCKED` with a specific missing primitive; or
- `UNESTABLISHED` when evidence cannot distinguish the options.

Do not silently map highlights/shadows to contrast, sharpness range to sharpness, or clarity to sharpening.

- [ ] **Step 4: Map the first-class interface/state workflow**

Record independent acceptance for menu entry, ten-preset browser, edit screen, reset-to-default, copy/select behavior, range display, persistence, and mode restrictions. The UI/touch plan may satisfy navigation primitives, but it does not automatically satisfy Creative Look state or processing.

- [ ] **Step 5: Validate and commit classifications**

```powershell
python -m unittest tests.analysis.test_creative_look_stack tests.analysis.test_creative_look_trace -v
git add analysis/a6400-creative-look-stack.json analysis/a6400-creative-look-boundary.json tests/analysis/test_creative_look_stack.py tests/analysis/test_creative_look_trace.py pmca/analysis/creative_look_stack.py pmca/analysis/creative_look_trace.py
git commit -m "analysis: classify Creative Look layers and axes"
```

### Task 5: Integrate Creative Look evidence without promoting fallback behavior

**Files:**
- Modify: `pmca/analysis/target_features.py`
- Modify: `tests/analysis/test_target_features.py`
- Modify: `analysis/a6400-target-features.json`

**Interfaces:**
- Consumes: validated Task 1 and Task 3 reports.
- Produces: the next exact target-feature schema version with nested Creative Look stack/boundary evidence.

- [ ] **Step 1: Write failing integration tests**

```python
def test_creative_look_stack_matches_standalone_report(self):
    validated = validate_target_feature_report(self.document)
    standalone = json.loads((REPOSITORY_ROOT / "analysis/a6400-creative-look-stack.json").read_text("utf-8"))
    self.assertEqual(validated["creative_look_stack"], standalone)


def test_default_creative_style_graph_cannot_promote_native_creative_look(self):
    candidate = copy.deepcopy(self.document)
    candidate["creative_rendering"]["target_selector_graph"] = "Default"
    candidate["creative_rendering"]["native_creative_look_established"] = True
    with self.assertRaises(TargetFeatureError):
        validate_target_feature_report(candidate)
```

Also require the standalone boundary report, source state report, exact ten looks/eight axes, and recursive forbidden-key rejection.

- [ ] **Step 2: Run tests and confirm schema integration fails**

Run: `python -m unittest tests.analysis.test_target_features -v`

Expected: failure because the new nested reports are absent.

- [ ] **Step 3: Implement nested validation and claim equivalence**

Import the three new validators and require object equality with committed reports. `creative_rendering.native_creative_look_established` may equal true only when `creative_look_stack.native_creative_look_established` is true and the boundary report proves the required processing/output bindings. Leave `selector_mutation_tested` false for camera behavior; offline patch tests do not change it.

- [ ] **Step 4: Run focused and full analysis suites**

```powershell
python -m unittest tests.analysis.test_target_features tests.analysis.test_creative_look_stack tests.analysis.test_creative_look_sources tests.analysis.test_creative_look_trace tests.analysis.test_creative_style_patch -v
python -m unittest discover -s tests/analysis -v
```

Expected: all tests pass with Creative Style fallback explicitly separated.

- [ ] **Step 5: Commit integrated evidence**

```powershell
git add pmca/analysis/target_features.py tests/analysis/test_target_features.py analysis/a6400-target-features.json
git commit -m "analysis: integrate first-class Creative Look evidence"
```

### Task 6: Report the strongest supported Creative Look outcome

**Files:**
- Modify: `analysis/a6400a-updater-and-creative-style-deep-dive.md`
- Modify: `analysis/a6400-creative-look-guide.md`
- Modify when evidence changes: `analysis/feature-compatibility.json`
- Modify when evidence changes: `analysis/a6400-feasibility-report.md`

**Interfaces:**
- Consumes: Tasks 1–5.
- Produces: a reviewed Creative Look milestone and exact blockers for the recovery plan and later research.

- [ ] **Step 1: Put native/reimplementation results before fallback recipes**

Document interface, state, base-look, axis, and pipeline results separately. For every unsupported axis or output, state whether it is hardware-blocked, approximation-only, or unestablished and cite the normalized evidence path. Keep all ten looks visible even when their processing representation is unresolved.

- [ ] **Step 2: Reframe the existing guide as fallback-only**

Add a prominent statement that the recipe table does not reproduce the Creative Look interface, persistence model, eight-axis adjustment system, or authenticated base tables. Retain it only as a user-entered contingency after native/reimplementation work for the corresponding layer fails.

- [ ] **Step 3: Run verification and forbidden-artifact scans**

```powershell
python -m compileall -q pmca tests
python -m unittest discover -s tests/analysis -v
git diff --check
git status --short
git diff --name-only | Select-String -Pattern '\.(so|dat|bin|exe|dll|img|key)$'
rg -n "private_key|raw_payload|hex_dump|BEGIN .*PRIVATE KEY" pmca tests analysis tools/ghidra
```

Expected: compile exit 0, all tests pass, no formatting defects, and no
proprietary binary changes. Review text matches and allow only rejection rules or
negative tests, never committed key/payload content.

- [ ] **Step 4: Commit the Creative Look milestone**

```powershell
git add analysis/a6400a-updater-and-creative-style-deep-dive.md analysis/a6400-creative-look-guide.md analysis/feature-compatibility.json analysis/a6400-feasibility-report.md
git commit -m "docs: report first-class Creative Look boundary"
```

Do not push, open a PR, connect a camera, or create an installable image. Proceed next to the external stock-2.00 recovery research plan.
