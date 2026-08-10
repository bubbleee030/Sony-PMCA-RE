# α6400 Mouse-Post Producer Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task in the current session. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a deterministic, fail-closed report that reproduces the bounded static search for producers of the α6400 `WidgetSystem::postMouse*` APIs and names the exact unresolved raw-input and queue-processor invocation boundary.

**Architecture:** Keep the firmware-universe producer scan in a standalone contract and exporter that depend on, but do not enlarge, the existing Creative Style interaction report. Build all metadata in memory, validate exact source identities and scan coverage, atomically publish only metadata, and reject any discovered producer or runtime promotion until separately reviewed.

**Tech Stack:** Python 3, `unittest`, pyelftools, Capstone, deterministic JSON, Markdown, PowerShell, Git.

## Global Constraints

- Work only in `C:\Users\Bubble\ChatGPT\Sony\Sony-PMCA-RE-a6400-analysis` on the isolated `feature/a6400-updater-re-lab` worktree.
- Static/offline only: no camera connection, Sony camera-binary execution, USB access, service or updater mode, partition writes, firmware generation, package generation, or installation.
- Pin the α6400 Taiwan/region-0 2.00 inventory at 799 regular files, 324 ELF files, 150 shared objects, and canonical SHA-256 `52ec5e8baf523878a417e3a61f9f16484634a9075d1c6afca2ca8c25940d827c`.
- Pin `lib/libObj.so` at size 20,860,436 and SHA-256 `60ffd2b0f31f4bc139a7c13a4f62c25cdeb6a531ad5ef35df48471e6e36e88b1`.
- Pin the interaction dependency canonical export SHA-256 `cd7c0f1df911248492ddb6542d2b9f225b7ec4a408a910fe896722a83277fa53`.
- Preserve 59,614 EXIDX owners, 56,271 fully decoded owners, and 3,343 incomplete owners as separate coverage values.
- Do not turn a bounded negative scan into a global absence claim.
- Keep raw-input delivery, runtime execution, Creative Style touch identity, first-class Creative Look behavior, installability, recovery validation, and camera test eligibility false.
- Never stage Sony binaries, firmware contents, raw disassembly, decompiler text, key material, reconstructive payloads, or executable artifacts.

---

## File structure

| Path | Action | Responsibility |
|---|---|---|
| `pmca/analysis/mouse_post_producer_boundary.py` | Create | Own exact constants, schema normalization, report derivation, and fail-closed claim validation. |
| `tools/static/export_a6400_mouse_post_producer_boundary.py` | Create | Reproduce the read-only firmware inventory, symbol, publication, and direct-call scans; write validated outputs atomically. |
| `tests/analysis/test_mouse_post_producer_boundary.py` | Create | Pin the contract, real exporter, scan mutation rejection, deterministic output, and no-partial-write behavior. |
| `analysis/a6400-mouse-post-producer-boundary.json` | Create | Store only the checked report summary and fail-closed conclusion. |
| `analysis/a6400a-updater-and-creative-style-deep-dive.md` | Modify | Integrate the bounded producer result after the existing public mouse-post pipeline discussion. |

## Exact interfaces

`pmca.analysis.mouse_post_producer_boundary` produces:

```python
PUBLIC_APIS: tuple[dict, ...]
EXPECTED_EXPORT: dict
CLAIMS: dict
READINESS: str
FIRST_UNRESOLVED_BOUNDARY: str

def normalize_mouse_post_producer_boundary_export(document: dict) -> dict: ...
def summarize_mouse_post_producer_boundary_export(document: dict) -> dict: ...
def build_mouse_post_producer_boundary_report(document: dict) -> dict: ...
def validate_mouse_post_producer_boundary_report(document: dict) -> dict: ...
```

`tools.static.export_a6400_mouse_post_producer_boundary` produces:

```python
def scan_firmware_symbol_universe() -> dict: ...
def scan_libobj_publications() -> dict: ...
def build_raw_export(adapter=None) -> dict: ...
def build_outputs(adapter=None) -> dict[Path, dict]: ...
def write_outputs_atomic(outputs: dict[Path, dict]) -> None: ...
```

`build_raw_export()` uses the real read-only adapter by default. Tests may pass a complete fake adapter only to exercise normalization and output transactions without repeating the slow firmware scan. One integration test must always use the real adapter.

### Exact public API records

```python
PUBLIC_APIS = (
    {
        "role": "move",
        "symbol": "_ZN2ux6wgtsys12WidgetSystem13postMouseMoveEhssNS_4core8MsecTimeE",
        "dynsym_index": 2976,
        "entry": 0x5F2151,
        "normalized_entry": 0x5F2150,
        "size": 0x90,
        "short_name": "postMouseMove",
    },
    {
        "role": "press",
        "symbol": "_ZN2ux6wgtsys12WidgetSystem14postMousePressEhhNS_4core8MsecTimeE",
        "dynsym_index": 2773,
        "entry": 0x5F21E1,
        "normalized_entry": 0x5F21E0,
        "size": 0x68,
        "short_name": "postMousePress",
    },
    {
        "role": "release",
        "symbol": "_ZN2ux6wgtsys12WidgetSystem16postMouseReleaseEhhNS_4core8MsecTimeE",
        "dynsym_index": 3785,
        "entry": 0x5F2249,
        "normalized_entry": 0x5F2248,
        "size": 0x68,
        "short_name": "postMouseRelease",
    },
)
```

### Exact negative boundary

```python
FIRST_UNRESOLVED_BOUNDARY = (
    "external-computed-or-opaque-input-producer-and-queue-processor-invocation"
)
READINESS = "PUBLIC_MOUSE_POST_PIPELINE_PROVEN__RAW_INPUT_PRODUCER_UNRESOLVED"
CLAIMS = {
    "public_mouse_post_api_definitions_found": True,
    "public_api_to_existing_queue_delivery_dependency_found": True,
    "bounded_static_producer_inventory_complete": True,
    "raw_mouse_input_producer_found": False,
    "queue_processor_invocation_found": False,
    "runtime_mouse_input_delivery_proven": False,
    "creative_style_touch_route_found": False,
    "creative_look_touch_route_found": False,
    "runtime_execution_proven": False,
}
```

---

### Task 1: Define the fail-closed producer-boundary contract

**Files:**
- Create: `pmca/analysis/mouse_post_producer_boundary.py`
- Create: `tests/analysis/test_mouse_post_producer_boundary.py`

**Interfaces:**
- Consumes: the design's exact inventory/source/API/coverage constants and the existing interaction report digest.
- Produces: the exact contract functions and constants listed above.

- [ ] **Step 1: Write the failing exact-contract test**

Create `MousePostProducerBoundaryContractTests` with a test named
`test_expected_boundary_pins_api_scope_and_unresolved_producer`:

```python
def test_expected_boundary_pins_api_scope_and_unresolved_producer(self):
    from pmca.analysis.mouse_post_producer_boundary import (
        EXPECTED_EXPORT,
        FIRST_UNRESOLVED_BOUNDARY,
        PUBLIC_APIS,
        READINESS,
        normalize_mouse_post_producer_boundary_export,
    )

    validated = normalize_mouse_post_producer_boundary_export(EXPECTED_EXPORT)
    self.assertEqual(tuple(validated["public_apis"]), PUBLIC_APIS)
    self.assertEqual(validated["first_unresolved_boundary"], FIRST_UNRESOLVED_BOUNDARY)
    self.assertEqual(validated["readiness"], READINESS)
    self.assertEqual(validated["libobj_publication_scan"]["owner_count"], 59614)
    self.assertEqual(validated["libobj_publication_scan"]["complete_owner_count"], 56271)
    self.assertEqual(validated["libobj_publication_scan"]["incomplete_owner_count"], 3343)
    self.assertFalse(validated["claims"]["raw_mouse_input_producer_found"])
    self.assertFalse(validated["claims"]["queue_processor_invocation_found"])
```

Production change caught: omitting, broadening, or promoting the exact producer boundary.

- [ ] **Step 2: Run the test and verify RED**

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest -v tests.analysis.test_mouse_post_producer_boundary.MousePostProducerBoundaryContractTests.test_expected_boundary_pins_api_scope_and_unresolved_producer
```

Expected: import failure for the missing `pmca.analysis.mouse_post_producer_boundary` module.

- [ ] **Step 3: Implement the minimal schema and normalizer**

Create the module with exact top-level export fields:

```python
_EXPORT_FIELDS = {
    "schema_version",
    "analysis_mode",
    "firmware_inventory",
    "source",
    "interaction_dependency",
    "public_apis",
    "symbol_universe",
    "libobj_publication_scan",
    "queue_processor",
    "first_unresolved_boundary",
    "readiness",
    "claims",
    "truncated",
}
```

Use schema version 1 and require:

```python
analysis_mode = {
    "read_only": True,
    "static_elf_metadata": True,
    "source_unchanged": True,
    "camera_access": False,
    "binary_execution": False,
}
```

Define `EXPECTED_EXPORT` with empty candidate lists for every scan method. Reject unknown fields, wrong types, incorrect ordering, digest changes, missing incomplete coverage, nonempty producer lists, or any positive unsupported claim. Return a deep copy.

- [ ] **Step 4: Run the exact-contract test and verify GREEN**

Run the Step 2 command.

Expected: one passing test.

- [ ] **Step 5: Add failing promotion and deep-copy tests**

Add:

```python
def test_boundary_rejects_fabricated_producers_and_runtime_promotion(self):
    mutations = (
        ("external_import", lambda d: d["symbol_universe"]["external_imports"].append({"module": "lib/fake.so", "role": "move"})),
        ("direct_call", lambda d: d["libobj_publication_scan"]["direct_inbound_calls"]["move"].append({"owner_start": 1, "owner_end": 2, "site": 1})),
        ("runtime", lambda d: d["claims"].__setitem__("runtime_mouse_input_delivery_proven", True)),
    )
    for label, mutate in mutations:
        candidate = copy.deepcopy(EXPECTED_EXPORT)
        mutate(candidate)
        with self.subTest(label=label), self.assertRaises(ValueError):
            normalize_mouse_post_producer_boundary_export(candidate)

def test_validated_boundary_is_a_deep_copy(self):
    validated = normalize_mouse_post_producer_boundary_export(EXPECTED_EXPORT)
    validated["public_apis"][0]["role"] = "changed"
    self.assertEqual(EXPECTED_EXPORT["public_apis"][0]["role"], "move")
```

Production changes caught: accepting an external producer, accepting a direct caller, returning mutable contract state, or promoting runtime delivery.

- [ ] **Step 6: Run the contract class and verify GREEN**

```powershell
.\.venv\Scripts\python.exe -m unittest -v tests.analysis.test_mouse_post_producer_boundary.MousePostProducerBoundaryContractTests
```

Expected: all contract tests pass.

- [ ] **Step 7: Commit the contract task**

```powershell
git add pmca/analysis/mouse_post_producer_boundary.py tests/analysis/test_mouse_post_producer_boundary.py
git commit -m "analysis: define mouse post producer boundary"
```

---

### Task 2: Implement the read-only source-derived exporter

**Files:**
- Create: `tools/static/export_a6400_mouse_post_producer_boundary.py`
- Modify: `tests/analysis/test_mouse_post_producer_boundary.py`

**Interfaces:**
- Consumes: Task 1 constants/normalizer, registry-consumer `_inventory()` for exact source inventory, the pinned interaction report, pyelftools, Capstone, and existing static ELF helpers.
- Produces: `scan_firmware_symbol_universe()`, `scan_libobj_publications()`, and `build_raw_export()`.

- [ ] **Step 1: Write the failing real-export test**

Add `MousePostProducerBoundaryExporterTests`:

```python
def test_real_export_matches_exact_boundary_when_available(self):
    if not self.exporter.sources_available() or not self.exporter.dependencies_available():
        self.skipTest("pinned source or parser dependencies are unavailable")
    self.assertEqual(self.exporter.build_raw_export(), self.exporter.EXPECTED_EXPORT)
```

Load the exporter with `importlib.util.spec_from_file_location` in `setUpClass`, following existing static-exporter tests.

Production change caught: an exporter that copies constants without reproducing the pinned source-derived boundary.

- [ ] **Step 2: Run the real-export test and verify RED**

```powershell
.\.venv\Scripts\python.exe -m unittest -v tests.analysis.test_mouse_post_producer_boundary.MousePostProducerBoundaryExporterTests.test_real_export_matches_exact_boundary_when_available
```

Expected: failure because the exporter file does not exist.

- [ ] **Step 3: Implement exact inventory and interaction dependencies**

Import `FIRMWARE_ROOT` and `_inventory` from
`tools.static.export_a6400_creative_style_registry_consumers`. Require the
returned inventory to equal the Task 1 constant and retain the sorted ELF path
list. Load and validate
`analysis/a6400-creative-style-interaction-surface.json`; require canonical
export SHA-256
`cd7c0f1df911248492ddb6542d2b9f225b7ec4a408a910fe896722a83277fa53`,
the existing static pipeline claim true, and raw producer false.

- [ ] **Step 4: Implement `scan_firmware_symbol_universe()`**

For every inventory ELF path:

1. parse `.dynsym`;
2. record exact matches to the three mangled symbols;
3. classify `defined` from `st_shndx`;
4. preserve module path, index, value, size, binding, visibility, and role; and
5. reject parser errors or symlinks.

For all 799 regular files, count only the three exact ASCII short names. Return:

```python
{
    "elf_file_count": 324,
    "matches": [
        # Three exact lib/libObj.so definitions in public API order.
    ],
    "external_definitions": [],
    "external_imports": [],
    "short_name_occurrences": [
        {"role": "move", "short_name": "postMouseMove", "modules": ["lib/libObj.so"], "occurrence_count": 1},
        {"role": "press", "short_name": "postMousePress", "modules": ["lib/libObj.so"], "occurrence_count": 1},
        {"role": "release", "short_name": "postMouseRelease", "modules": ["lib/libObj.so"], "occurrence_count": 1},
    ],
}
```

- [ ] **Step 5: Implement `scan_libobj_publications()`**

Open the pinned libObj source and compute `.ARM.exidx` ranges. For the three
normalized API entries and queue processor `0x5F2964`, collect:

- decoded direct branches from every owner range;
- `.rel.dyn` records whose absolute, symbol-defined, or signed place-relative
  value resolves to a target;
- aligned words in allocated non-`SHT_NOBITS` sections, excluding the API's own
  `.dynsym` value cells;
- ADR or explicit PC arithmetic materializations;
- PC-literal-plus-PC-add materializations; and
- bounded MOVW/MOVT materializations with no intervening destination-register
  write.

Return exact empty lists plus:

```python
{
    "scan_methods": [
        "decoded-direct-branch",
        "dynamic-relocation-target",
        "allocated-aligned-pointer",
        "adr-or-pc-immediate",
        "pc-literal-add",
        "movw-movt",
    ],
    "owner_count": 59614,
    "complete_owner_count": 56271,
    "incomplete_owner_count": 3343,
    "direct_inbound_calls": {"move": [], "press": [], "release": [], "queue_processor": []},
    "relocation_publications": {"move": [], "press": [], "release": [], "queue_processor": []},
    "aligned_pointer_publications": {"move": [], "press": [], "release": [], "queue_processor": []},
    "address_materializations": {"move": [], "press": [], "release": [], "queue_processor": []},
}
```

Cache the completed scan only under `(inventory_sha256, libobj_sha256)`. Validate
both digests before cache lookup and verify them again after the scan.

- [ ] **Step 6: Build and validate the raw document**

`build_raw_export()` must derive every source field, merge the two scan results,
populate queue processor owner `[0x5F2964, 0x5F2A38)`, and call
`normalize_mouse_post_producer_boundary_export()` before returning. It must
reject any nonempty producer/publication list rather than silently changing the
negative contract.

- [ ] **Step 7: Run the real-export test and verify GREEN**

Run the Step 2 command with a 10-minute timeout.

Expected: one passing real-source test; no source file changes.

- [ ] **Step 8: Write failing scan-mutation tests**

Add an adapter fixture containing a deep copy of the real expected symbol and
publication results. Add one table-driven test that injects each of:

```python
("external-import", ("symbol_universe", "external_imports"))
("short-name-file", ("symbol_universe", "short_name_occurrences"))
("direct-caller", ("libobj_publication_scan", "direct_inbound_calls"))
("relocation", ("libobj_publication_scan", "relocation_publications"))
("aligned-pointer", ("libobj_publication_scan", "aligned_pointer_publications"))
("address-materialization", ("libobj_publication_scan", "address_materializations"))
("processor-caller", ("libobj_publication_scan", "direct_inbound_calls", "queue_processor"))
```

Each mutation must make `build_raw_export(fake_adapter)` raise `RuntimeError` or
the contract error with a label identifying the affected scan class.

- [ ] **Step 9: Run mutation and focused tests and verify GREEN**

```powershell
.\.venv\Scripts\python.exe -m unittest -v tests.analysis.test_mouse_post_producer_boundary
```

Expected: all contract, real-export, and mutation tests pass.

- [ ] **Step 10: Commit the exporter task**

```powershell
git add tools/static/export_a6400_mouse_post_producer_boundary.py tests/analysis/test_mouse_post_producer_boundary.py
git commit -m "analysis: trace mouse post producer inventory"
```

---

### Task 3: Generate the checked report and integrate the boundary narrative

**Files:**
- Modify: `pmca/analysis/mouse_post_producer_boundary.py`
- Modify: `tools/static/export_a6400_mouse_post_producer_boundary.py`
- Modify: `tests/analysis/test_mouse_post_producer_boundary.py`
- Create: `analysis/a6400-mouse-post-producer-boundary.json`
- Modify: `analysis/a6400a-updater-and-creative-style-deep-dive.md`

**Interfaces:**
- Consumes: Task 2's validated raw export.
- Produces: deterministic checked report, atomic output transaction, and bounded human narrative.

- [ ] **Step 1: Write the failing checked-report test**

```python
def test_checked_report_is_exact_and_fail_closed(self):
    report = validate_mouse_post_producer_boundary_report(
        json.loads(REPORT.read_text(encoding="utf-8"))
    )
    self.assertEqual(report["readiness"], READINESS)
    self.assertFalse(report["camera_executed"])
    self.assertFalse(report["installable"])
    self.assertFalse(report["camera_test_eligible"])
    self.assertFalse(report["claims"]["raw_mouse_input_producer_found"])
    self.assertFalse(report["claims"]["queue_processor_invocation_found"])
```

Production change caught: missing checked output or a report that promotes the bounded scan.

- [ ] **Step 2: Run the checked-report test and verify RED**

Run only the new test.

Expected: file-not-found failure for
`analysis/a6400-mouse-post-producer-boundary.json`.

- [ ] **Step 3: Implement report summary and validation**

The checked report contains exactly:

```python
{
    "schema_version",
    "analysis_scope",
    "camera_policy",
    "camera_executed",
    "installable",
    "camera_test_eligible",
    "source",
    "interaction_dependency",
    "summary",
    "claims",
    "readiness",
    "first_unresolved_boundary",
    "conclusion",
}
```

Summary fields are canonical export SHA-256, firmware/ELF counts, API count,
owner coverage counts, external symbol-consumer count, publication-candidate
count, and queue-processor-candidate count. `conclusion` must explicitly say
that incomplete decode coverage and unscanned arbitrary computed/runtime paths
prevent a global absence claim.

- [ ] **Step 4: Implement all-results-before-write output**

`build_outputs()` builds and validates in memory:

1. ignored raw artifact
   `.artifacts/mouse-post-producer-boundary/a6400-v2.00/raw-mouse-post-producer-boundary.json`; and
2. checked report `analysis/a6400-mouse-post-producer-boundary.json`.

`write_outputs_atomic()` must stage both results, flush and `fsync` both, and
perform `os.replace` only after both documents have passed validation. Reject
symlinks, nonregular existing destinations, or output paths outside the two
fixed roots.

- [ ] **Step 5: Add failing transaction and determinism tests**

Use temporary approved roots. Patch the final report validator to raise after
the raw document is built; assert neither destination changes. Run
`build_outputs(fake_adapter)` twice and assert canonical bytes are identical.

Production changes caught: partial report replacement and nondeterministic metadata.

- [ ] **Step 6: Implement the minimal transaction behavior and verify GREEN**

Run the full producer-boundary test module.

Expected: report, transaction, determinism, exporter, and contract tests pass.

- [ ] **Step 7: Update and test the deep-dive narrative**

Insert one paragraph immediately after the existing postMouse pipeline paragraph.
Require these phrases in the contract test:

```text
59,614 exception-index owners
56,271 fully decoded
3,343 incomplete
no decoded direct caller or static publication
does not prove that no runtime or computed producer exists
```

Reject phrases claiming `no raw input producer exists`, `runtime touch proven`,
or `Creative Style touch proven`.

- [ ] **Step 8: Regenerate and verify deterministic report bytes**

```powershell
.\.venv\Scripts\python.exe tools\static\export_a6400_mouse_post_producer_boundary.py
$before = (Get-FileHash -Algorithm SHA256 analysis\a6400-mouse-post-producer-boundary.json).Hash
.\.venv\Scripts\python.exe tools\static\export_a6400_mouse_post_producer_boundary.py
if ($before -ne (Get-FileHash -Algorithm SHA256 analysis\a6400-mouse-post-producer-boundary.json).Hash) { throw 'nondeterministic mouse-post boundary report' }
```

Expected exporter summary:

```text
A6400_MOUSE_POST_PRODUCER_BOUNDARY|apis=3|external=0|publications=0|processor=0|runtime=0|camera_access=0|binary_execution=0
```

- [ ] **Step 9: Commit the report integration task**

```powershell
git add pmca/analysis/mouse_post_producer_boundary.py tools/static/export_a6400_mouse_post_producer_boundary.py tests/analysis/test_mouse_post_producer_boundary.py analysis/a6400-mouse-post-producer-boundary.json analysis/a6400a-updater-and-creative-style-deep-dive.md
git commit -m "analysis: bound mouse post producer edge"
```

---

### Task 4: Verify and publish the slice

**Files:**
- Modify only if a verification failure reveals a real omission in Tasks 1–3.

**Interfaces:**
- Consumes: all three implementation commits and the pre-existing interaction/recovery reports.
- Produces: a pushed, deterministic, non-installable evidence slice ready for the next static trace.

- [ ] **Step 1: Run focused producer and interaction tests**

```powershell
.\.venv\Scripts\python.exe -m unittest -v tests.analysis.test_mouse_post_producer_boundary tests.analysis.test_creative_style_interaction_surface
```

Expected: all tests pass.

- [ ] **Step 2: Run recovery and safety regression gates**

```powershell
.\.venv\Scripts\python.exe -m unittest -v tests.analysis.test_cxd90045_transition_report tests.analysis.test_recovery_path
.\.venv\Scripts\python.exe -m unittest discover -s tests\safe -v
```

Expected: 35 recovery/transition tests and 58 safety tests pass.

- [ ] **Step 3: Run complete analysis**

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests\analysis
```

Expected: every analysis test passes. Any failure blocks publication.

- [ ] **Step 4: Run static and artifact guards**

```powershell
.\.venv\Scripts\python.exe -m py_compile pmca\analysis\mouse_post_producer_boundary.py tools\static\export_a6400_mouse_post_producer_boundary.py tests\analysis\test_mouse_post_producer_boundary.py
git diff --check
git status --short
git diff --name-only | Select-String -Pattern '\.(so|dat|bin|exe|dll|img|key)$'
rg -n "raw_mouse_input_producer_found[^\n]*true|queue_processor_invocation_found[^\n]*true|runtime_mouse_input_delivery_proven[^\n]*true|camera_test_eligible[^\n]*true|installable[^\n]*true" pmca tests analysis docs
```

Expected: no whitespace or proprietary-artifact defects and no positive runtime,
camera, or installation claim outside explicit rejection tests or plan text.

- [ ] **Step 5: Review exact scope and avoid a verification-only commit**

Confirm that the implementation changes only the five Task 3 product files plus
the already committed design/plan documents. If verification exposes no
omission, do not create an empty verification commit.

- [ ] **Step 6: Push and verify remote identity**

```powershell
git push origin feature/a6400-updater-re-lab
$local = git rev-parse HEAD
$upstream = git rev-parse '@{u}'
$remote = (git ls-remote origin refs/heads/feature/a6400-updater-re-lab -split '\s+')[0]
if ($local -ne $upstream -or $local -ne $remote) { throw 'remote identity differs' }
git status --short --branch
```

Expected: local, upstream, and remote SHAs match; the worktree is clean.

- [ ] **Step 7: Report the exact handoff**

Report commit IDs, changed files, focused/full/safety counts, deterministic
report hash, unchanged readiness, and the next unresolved boundary. Do not
claim the wider α7 V-like interface, first-class Creative Look processing,
restoration, or camera eligibility is complete.
