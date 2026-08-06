# α6400 External Stock-2.00 Recovery Research Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish, or reduce to precise blockers, a safe external path that can restore the exact original regional α6400 2.00 firmware from a laptop or another independent recovery mechanism even when a modified UI/runtime cannot start.

**Architecture:** Authenticate the complete stock restore source, model recovery failure states, reuse existing updater/trust-boundary evidence to map version/signature/write gates, classify candidate external entry paths, and emit a fail-closed readiness decision. Static evidence can prepare a future validation design but cannot mark recovery validated; no camera-connected step exists in this plan.

**Tech Stack:** Python 3, `unittest`, JSON, existing updater/transition/trust-boundary reports, static PE/Ghidra metadata where required, Markdown, Git.

## Global Constraints

- The canonical workspace is `C:\Users\Bubble\ChatGPT`; never use `C:\ChatGPT` as the canonical location.
- The repository is `C:\Users\Bubble\ChatGPT\Sony\Sony-PMCA-RE-a6400-analysis`.
- Execute this plan after the UI/touch and Creative Look research checkpoints; it remains a hard gate before any later camera test.
- The phase is static/offline: no camera connection, Sony camera-binary execution, USB/camera partition writes, service/updater mode, or firmware flashing.
- Do not print or commit raw keys, Sony binaries, decrypted payloads, partition contents, disassembly dumps, or reconstructive byte arrays.
- Keep official firmware and all generated artifacts under ignored `.artifacts/` paths; commit only metadata, hashes, bounded reports, source, tests, and non-operational documentation.
- Preserve unrelated user changes.
- A settings reset is not a firmware recovery path.
- Recovery must be external and independent of the modified normal UI/runtime.
- An official updater, USB recovery/updater mode, independently bootable maintenance path, or combination may qualify only after exact entry, write, verification, and failure behavior are understood.
- Static research cannot set `recovery_validated=true`; that requires a separate future design, fresh authorization, physical supervision, and validation before any feature payload.

---

## File structure

| Path | Action | Responsibility |
|---|---|---|
| `pmca/analysis/stock_restore.py` | Create | Validate the exact stock-2.00 source bundle and provenance. |
| `tests/analysis/test_stock_restore.py` | Create | Test digest, identity, completeness, and forbidden raw fields. |
| `analysis/a6400-stock-200-bundle.json` | Create | Record the immutable regional stock restore inputs. |
| `pmca/analysis/recovery_scenarios.py` | Create | Validate required failure scenarios and coverage classifications. |
| `tests/analysis/test_recovery_scenarios.py` | Create | Ensure every failure state is explicit and fail-closed. |
| `analysis/a6400-recovery-scenarios.json` | Create | Store scenario coverage and exact blockers. |
| `pmca/analysis/recovery_path.py` | Create | Validate external entry, updater gates, write scope, and readiness. |
| `tests/analysis/test_recovery_path.py` | Create | Reject runtime-dependent, partially scoped, or unvalidated recovery. |
| `analysis/a6400-stock-200-recovery.json` | Create | Store candidate paths, gate evidence, and final readiness false/true fields. |
| `tools/ghidra/export_a6400_restore_gates.py` | Create | Export bounded static metadata for stock updater/recovery gate tracing. |
| `pmca/analysis/decisions.py` | Modify | Source the recovery capability from the strict readiness report. |
| `tests/analysis/test_decisions.py` | Modify | Pin recovery status and reject unsupported feasibility promotion. |
| `analysis/feature-evidence.json` | Modify | Cite the exact recovery report without claiming validation. |
| `analysis/a6400-updater-re-report.md` | Modify | Explain the external stock restore boundary and remaining gaps. |
| `docs/superpowers/runbooks/a6400-stock-200-recovery-readiness.md` | Create | Human-readable static readiness checklist; contains no camera commands. |

### Task 1: Authenticate the complete stock α6400 2.00 restore bundle

**Files:**
- Create: `pmca/analysis/stock_restore.py`
- Create: `tests/analysis/test_stock_restore.py`
- Create: `analysis/a6400-stock-200-bundle.json`

**Interfaces:**
- Consumes: `analysis/firmware-manifest.json`, `analysis/reports/a6400-tw-v2.00.json`, and `analysis/a6400-target-features.json`.
- Produces: `validate_stock_restore_bundle(document: dict) -> dict` and `verify_stock_restore_files(document: dict, artifact_root: Path) -> dict` for later tasks.

- [ ] **Step 1: Write failing exact-bundle tests**

```python
import copy
import json
import unittest
from pathlib import Path

from pmca.analysis.stock_restore import (
    StockRestoreError,
    validate_stock_restore_bundle,
)

ROOT = Path(__file__).resolve().parents[2]


class StockRestoreTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(
            (ROOT / "analysis/a6400-stock-200-bundle.json").read_text("utf-8")
        )

    def test_bundle_is_exact_regional_v200_source(self):
        validated = validate_stock_restore_bundle(self.document)
        self.assertEqual(validated["model_id"], "0x81030011")
        self.assertEqual(validated["region"], "TW")
        self.assertEqual(validated["version"], "2.00")
        self.assertEqual(validated["source_kind"], "official-sony-updater")

    def test_bundle_rejects_raw_firmware_material(self):
        candidate = copy.deepcopy(self.document)
        candidate["raw_payload"] = "forbidden"
        with self.assertRaises(StockRestoreError):
            validate_stock_restore_bundle(candidate)
```

Add tests requiring exact outer-updater digest, embedded firmware digest/offset/size, stock component manifest reference, official source URL, acquisition provenance, and no absolute ignored path. Reject missing or duplicate components and forbidden keys recursively.

- [ ] **Step 2: Run tests and verify missing-module failure**

Run: `python -m unittest tests.analysis.test_stock_restore -v`

Expected: missing `pmca.analysis.stock_restore`.

- [ ] **Step 3: Implement bundle validation and on-disk verification**

```python
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
FORBIDDEN_KEYS = {"raw", "bytes", "payload", "private_key", "key_material", "hex_dump"}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_file(path: Path, expected_size: int, expected_sha256: str) -> None:
    if not path.is_file() or path.stat().st_size != expected_size:
        raise StockRestoreError("stock source size mismatch")
    digest = _sha256_file(path)
    if digest != expected_sha256:
        raise StockRestoreError("stock source digest mismatch")
```

`verify_stock_restore_files` may read only caller-specified files below ignored `.artifacts/sony-firmware/`; it returns sizes/digests and never file bytes. Cross-check identity values against the existing validated target report rather than duplicating unverified constants.

- [ ] **Step 4: Create the real bundle report and verify ignored originals**

Populate the report from committed provenance and the exact existing regional updater. Rehash the ignored original and embedded stock payload read-only; report a mismatch as failure and do not replace/download/mutate the artifact in this plan.

Run:

```powershell
python -m unittest tests.analysis.test_stock_restore -v
python -c "import json; from pathlib import Path; from pmca.analysis.stock_restore import validate_stock_restore_bundle; validate_stock_restore_bundle(json.loads(Path('analysis/a6400-stock-200-bundle.json').read_text('utf-8'))); print('stock bundle valid')"
```

Expected: all tests pass and `stock bundle valid` prints.

- [ ] **Step 5: Commit authenticated metadata only**

```powershell
git add pmca/analysis/stock_restore.py tests/analysis/test_stock_restore.py analysis/a6400-stock-200-bundle.json
git commit -m "analysis: authenticate a6400 stock 2.00 bundle"
```

### Task 2: Model mandatory recovery failure scenarios

**Files:**
- Create: `pmca/analysis/recovery_scenarios.py`
- Create: `tests/analysis/test_recovery_scenarios.py`
- Create: `analysis/a6400-recovery-scenarios.json`

**Interfaces:**
- Consumes: Task 1 stock bundle identity.
- Produces: `validate_recovery_scenarios(document: dict) -> dict` and exact `SCENARIO_IDS` consumed by Tasks 4–5.

- [ ] **Step 1: Write failing exact-scenario tests**

```python
SCENARIO_IDS = (
    "modified-ui-runtime-failure",
    "interrupted-feature-update",
    "nonbooting-application-layer",
    "version-or-downgrade-rejection",
    "boot-chain-failure",
    "power-loss-during-stock-restore",
)


def test_every_required_scenario_is_explicit(self):
    validated = validate_recovery_scenarios(self.document)
    self.assertEqual([item["id"] for item in validated["scenarios"]], list(SCENARIO_IDS))
    self.assertTrue(all(item["status"] == "UNESTABLISHED" for item in validated["scenarios"]))
```

Add tests requiring `entry_available`, `runtime_independent`, `write_scope_known`, `verification_available`, `power_loss_behavior_known`, `evidence`, and `blocker` on every scenario. A `RECOVERABLE` scenario requires every boolean except the scenario-specific power-loss field where inapplicable; `UNRECOVERABLE` requires direct evidence, not absence.

- [ ] **Step 2: Run tests and verify failure**

Run: `python -m unittest tests.analysis.test_recovery_scenarios -v`

Expected: missing-module error.

- [ ] **Step 3: Implement fail-closed scenario validation**

```python
STATUSES = {"RECOVERABLE", "PARTIAL", "UNRECOVERABLE", "UNESTABLISHED"}


def _can_be_recoverable(item: dict) -> bool:
    required = (
        "entry_available",
        "runtime_independent",
        "write_scope_known",
        "verification_available",
    )
    return all(item[field] is True for field in required) and bool(item["evidence"])
```

Reject `RECOVERABLE` when `_can_be_recoverable` is false. Reject empty blockers for `PARTIAL`/`UNESTABLISHED`. Reject operational camera commands, drive letters, USB write commands, or partition payloads from the committed report.

- [ ] **Step 4: Create the baseline scenario report**

Initialize all six scenarios as `UNESTABLISHED`. Use existing updater evidence only to narrow blockers; do not claim independent entry or recovery validation from the normal no-camera updater path.

- [ ] **Step 5: Run tests and commit**

```powershell
python -m unittest tests.analysis.test_recovery_scenarios -v
git add pmca/analysis/recovery_scenarios.py tests/analysis/test_recovery_scenarios.py analysis/a6400-recovery-scenarios.json
git commit -m "analysis: model a6400 recovery failure states"
```

### Task 3: Map stock updater, version, signature, and write-scope gates

**Files:**
- Create: `pmca/analysis/recovery_path.py`
- Create: `tests/analysis/test_recovery_path.py`
- Create: `tools/ghidra/export_a6400_restore_gates.py`
- Create: `analysis/a6400-stock-200-recovery.json`
- Local only: `.artifacts/recovery-trace/a6400-v2.00/raw-restore-gates.json`

**Interfaces:**
- Consumes: Task 1 bundle, existing updater gate/crypto/transition reports, and Task 2 scenarios.
- Produces: `validate_recovery_report(document: dict) -> dict` and `normalize_restore_gate_export(raw: dict) -> dict`.

- [ ] **Step 1: Write failing gate-separation and readiness tests**

```python
def test_host_acceptance_does_not_prove_camera_or_boot_acceptance(self):
    report = fixture_recovery_report(
        gates={
            "host_updater": "ESTABLISHED",
            "transport": "UNESTABLISHED",
            "camera_updater": "UNESTABLISHED",
            "boot_chain": "UNESTABLISHED",
            "runtime_integrity": "UNESTABLISHED",
        },
        recovery_validated=False,
    )
    self.assertFalse(validate_recovery_report(report)["recovery_validated"])


def test_static_evidence_cannot_mark_recovery_validated(self):
    candidate = fixture_recovery_report(recovery_validated=True)
    with self.assertRaises(RecoveryPathError):
        validate_recovery_report(candidate)
```

Add tests requiring exact signed ranges, model/version checks, write targets, ordering, verification stage, downgrade/reinstall behavior, and power-loss behavior to be individually `ESTABLISHED`, `PARTIAL`, or `UNESTABLISHED`. Reject an aggregate “bypass” field and recursive raw/private-key fields.

- [ ] **Step 2: Run tests and verify failure**

Run: `python -m unittest tests.analysis.test_recovery_path -v`

Expected: missing-module error.

- [ ] **Step 3: Implement the strict recovery report validator**

```python
GATE_IDS = (
    "host_updater",
    "transport",
    "camera_updater",
    "boot_chain",
    "runtime_integrity",
)
DETAIL_IDS = (
    "signed_ranges",
    "model_check",
    "version_check",
    "write_scope",
    "write_order",
    "post_write_verification",
    "downgrade_or_reinstall",
    "power_loss_behavior",
)
```

`recovery_validated` must be literal false in this static plan. `camera_test_eligible` must also remain false. A candidate path marked `READY_FOR_FUTURE_VALIDATION_DESIGN` requires an authenticated Task 1 bundle, runtime-independent entry evidence, complete known write scope/order, verification evidence, and no scenario incorrectly marked recoverable.

- [ ] **Step 4: Export bounded static restore-gate metadata**

The Ghidra post-script may inspect the pinned official Windows updater and extracted target updater components read-only. Export only function/site addresses, imported API names already allowlisted by existing static reports, comparison constants expressed as bounded scalars, signed-range references, and normalized call relationships. Do not execute the updater, emit disassembly/bytes, reconstruct a package, or export cryptographic material.

Correlate the export with:

- `analysis/a6400-updater-gates.json`;
- `analysis/a6400-updater-crypto-boundary.json`;
- `analysis/a6400-updater-transition-boundary.json`;
- `analysis/a6400-warm-boot-boundary.json`; and
- `analysis/a6400-trust-boundary.json`.

Record contradictions as separate hypotheses. Existing host wrapper/version-skip evidence must not be promoted to camera updater, boot, downgrade, or recovery acceptance.

- [ ] **Step 5: Normalize, test, and commit**

```powershell
python -m unittest tests.analysis.test_recovery_path tests.analysis.test_stock_restore tests.analysis.test_recovery_scenarios -v
git add pmca/analysis/recovery_path.py tests/analysis/test_recovery_path.py tools/ghidra/export_a6400_restore_gates.py analysis/a6400-stock-200-recovery.json
git commit -m "analysis: map a6400 stock restore gates"
```

### Task 4: Classify external runtime-independent entry candidates

**Files:**
- Modify: `analysis/a6400-stock-200-recovery.json`
- Modify: `analysis/a6400-recovery-scenarios.json`
- Modify: `tests/analysis/test_recovery_path.py`
- Modify: `tests/analysis/test_recovery_scenarios.py`

**Interfaces:**
- Consumes: Task 3 gate evidence.
- Produces: explicit candidate classifications and scenario coverage for Task 5.

- [ ] **Step 1: Add failing exact-candidate tests**

```python
def test_candidate_paths_are_independent_and_non_equivalent(self):
    result = validate_recovery_report(self.report)
    self.assertEqual(
        [item["id"] for item in result["candidates"]],
        ["official-updater-reinstall", "usb-recovery-or-updater-mode", "independent-maintenance-path"],
    )
    for candidate in result["candidates"]:
        self.assertEqual(
            set(candidate),
            {"id", "status", "entry_layer", "runtime_independent", "stock_source", "write_scope", "verification", "evidence", "blocker"},
        )
```

Add tests rejecting `runtime_independent=true` when entry occurs after normal application startup, rejecting a maintenance path inferred only from a string, and rejecting candidate aggregation that hides distinct gate failures.

- [ ] **Step 2: Run tests and verify the stricter candidate rules fail**

Run: `python -m unittest tests.analysis.test_recovery_path tests.analysis.test_recovery_scenarios -v`

Expected: failures until candidates and scenario links are exact.

- [ ] **Step 3: Trace each candidate to its earliest trusted entry layer**

For each candidate, record:

- what host action selects it, if known statically;
- the earliest camera-side component that receives control;
- whether normal UI/runtime code must boot first;
- model/version/signature checks before any write;
- exact known/unknown write scope and order;
- post-write verification/commit behavior; and
- which Task 2 failure scenarios it could cover.

A string, dormant menu item, or host API reference is `UNESTABLISHED` until its control flow and entry layer are proven.

- [ ] **Step 4: Update scenario statuses without claiming validation**

Use `PARTIAL` only when static evidence proves some required fields. Keep `RECOVERABLE` unavailable in this phase because recovery has not been independently validated. If evidence shows a path cannot cover boot-chain failure, record that limitation rather than broadening the path.

- [ ] **Step 5: Run tests and commit classifications**

```powershell
python -m unittest tests.analysis.test_recovery_path tests.analysis.test_recovery_scenarios -v
git add analysis/a6400-stock-200-recovery.json analysis/a6400-recovery-scenarios.json tests/analysis/test_recovery_path.py tests/analysis/test_recovery_scenarios.py pmca/analysis/recovery_path.py pmca/analysis/recovery_scenarios.py
git commit -m "analysis: classify external a6400 recovery paths"
```

### Task 5: Integrate a fail-closed recovery readiness decision

**Files:**
- Modify: `pmca/analysis/decisions.py`
- Modify: `tests/analysis/test_decisions.py`
- Modify: `analysis/feature-evidence.json`
- Create: `docs/superpowers/runbooks/a6400-stock-200-recovery-readiness.md`

**Interfaces:**
- Consumes: validated Task 1–4 reports.
- Produces: a repository-wide recovery capability status and a human-readable static readiness report with no operational camera steps.

- [ ] **Step 1: Write failing decision-integration tests**

```python
def test_recovery_decision_cannot_be_feasible_without_validation(self):
    evidence = load_real_evidence()
    recovery = next(item for item in evidence["capabilities"] if item["id"] == "recovery")
    self.assertNotEqual(recovery["status"], "FEASIBLE")
    self.assertIn("analysis/a6400-stock-200-recovery.json", [item["source"] for item in recovery["evidence"]])


def test_recovery_report_remains_static_and_camera_ineligible(self):
    report = validate_recovery_report(load_recovery_report())
    self.assertFalse(report["recovery_validated"])
    self.assertFalse(report["camera_test_eligible"])
```

- [ ] **Step 2: Run focused tests and verify failure**

Run: `python -m unittest tests.analysis.test_decisions tests.analysis.test_recovery_path -v`

Expected: failure until the new source is allowlisted and the recovery decision is sourced from the strict report.

- [ ] **Step 3: Integrate exact recovery evidence**

Add `analysis/a6400-stock-200-recovery.json`, `analysis/a6400-recovery-scenarios.json`, and `analysis/a6400-stock-200-bundle.json` to the approved internal source set. Derive the recovery capability summary and next action from their validated fields. Do not allow a manually edited `FEASIBLE` status when `recovery_validated` is false.

- [ ] **Step 4: Write the non-operational readiness document**

The document must list:

- authenticated stock bundle identity/digests by reference;
- each candidate path and earliest established entry layer;
- known/unknown model, version, signature, write, ordering, verification, and power-loss behavior;
- all six failure scenarios and current coverage;
- explicit stop conditions;
- why no camera command is supplied; and
- the exact evidence required before drafting a separate physical validation design.

It must not contain USB identifiers discovered from a live camera, partition-write commands, service-mode instructions, firmware payload paths, or wording that invites an unvalidated attempt.

- [ ] **Step 5: Run focused tests and commit readiness integration**

```powershell
python -m unittest tests.analysis.test_decisions tests.analysis.test_recovery_path tests.analysis.test_recovery_scenarios tests.analysis.test_stock_restore -v
git add pmca/analysis/decisions.py tests/analysis/test_decisions.py analysis/feature-evidence.json docs/superpowers/runbooks/a6400-stock-200-recovery-readiness.md
git commit -m "analysis: gate a6400 recovery readiness"
```

### Task 6: Report the recovery boundary and verify the full research program

**Files:**
- Modify: `analysis/a6400-updater-re-report.md`
- Modify: `analysis/a6400-feasibility-report.md`
- Modify: `analysis/a6400a-updater-and-creative-style-deep-dive.md`

**Interfaces:**
- Consumes: every report and validator from this plan plus the completed UI/touch and Creative Look plans.
- Produces: the final static/offline program checkpoint and an exact next decision; it does not produce a camera-test plan.

- [ ] **Step 1: Document recovery outcome without euphemism**

State whether an external stock-2.00 route is merely a candidate, ready for a future validation design, or blocked. Explain why settings reset is insufficient, which failure states remain uncovered, and whether the path is independent of the modified runtime. Keep `camera_test_eligible=false` and `installable=false` unless a later separately authorized phase changes them.

- [ ] **Step 2: Run the complete fresh verification suite**

```powershell
python -m compileall -q pmca tests
python -m unittest discover -s tests/analysis -v
git diff --check
git status --short
```

Expected: compile exit 0, all analysis tests pass, no whitespace errors, and only planned files changed.

- [ ] **Step 3: Verify originals and scan for forbidden artifacts**

Rehash the exact stock updater and extracted stock payload through `verify_stock_restore_files`. Then run:

```powershell
git diff --numstat
git diff --name-only | Select-String -Pattern '\.(so|dat|bin|exe|dll|img|key)$'
rg -n "private_key|raw_payload|hex_dump|BEGIN .*PRIVATE KEY|Write-.*Partition|flash firmware" pmca tests analysis tools/ghidra docs/superpowers/runbooks
```

Expected: source digests match and no proprietary/installable artifact changes.
Review every text match and allow only rejection rules, negative tests, or explicit
prohibitions; the readiness document must contain no operational write path.

- [ ] **Step 4: Commit the static recovery milestone**

```powershell
git add analysis/a6400-updater-re-report.md analysis/a6400-feasibility-report.md analysis/a6400a-updater-and-creative-style-deep-dive.md
git commit -m "docs: report a6400 stock recovery boundary"
```

- [ ] **Step 5: Stop at the physical-validation gate**

If the report is `READY_FOR_FUTURE_VALIDATION_DESIGN`, request a new design and fresh authorization before drafting or executing camera steps. If it is blocked or unestablished, continue static research from the exact blocker. In every case, do not connect the α6400, execute camera binaries, write partitions, flash firmware, push, or create a PR without a new user request.
