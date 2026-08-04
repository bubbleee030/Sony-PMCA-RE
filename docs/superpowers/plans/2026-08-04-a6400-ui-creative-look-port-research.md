# Sony α6400 UI and Creative Look Port Research Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and run a reproducible offline firmware lab that pushes beyond historical PMCA/fwtool limitations toward α6400-compatible vertical UI, touch-menu, and all-ten-Creative-Look outcomes without connecting a camera.

**Architecture:** Extend the existing metadata-only analysis package with authenticated α7 V donor support, bounded Sony DAT and PE-overlay structure mapping, pinned external-tool baselines, quarantined mutation/signature experiments, feature compatibility mapping, and α6400 Creative Style translations. Original Sony inputs stay immutable and ignored; every generated candidate stays under an ignored `NOT_FOR_INSTALL` quarantine, while Git receives only source, synthetic tests, hashes, schemas, structured evidence, and reports.

**Tech Stack:** Windows 11, PowerShell 7, Python 3.13 standard library, unittest, dataclasses, pathlib, hashlib, json, struct, subprocess, Git, GitHub CLI, Sony-PMCA-RE, and pinned fwtool.py revisions.

## Global Constraints

- Execute inline in the existing linked worktree; do not dispatch subagents.
- After this plan is committed, create branch `feature/a6400-ui-creative-look-research` from that planning commit; approved design commit `7a9ee6c` remains its ancestor.
- Keep the α6400 and NEX-C3 disconnected and unchanged for the entire plan.
- Do not query camera PnP state, change drivers, enter service/updater mode, access removable camera media, or send USB commands.
- Authenticate the α6400 2.00, α6700 2.00, and α7 V 2.00 packages using exact Sony Taiwan page metadata before analysis.
- Original files under `.artifacts/sony-firmware/` are read-only; mutation sources must be disposable copies under `.artifacts/analysis-inputs/`.
- Generated binary outputs live only under `.artifacts/quarantine/`, include `NOT_FOR_INSTALL` in the filename, and receive provenance sidecars.
- Never copy a package or candidate to an SD-card root, camera-visible directory, Sony updater discovery path, or USB device.
- Never commit Sony firmware, extracted proprietary components, decrypted payloads, arbitrary firmware strings, hex dumps, or generated candidate images.
- Treat model mismatch, unknown regions, failed decryption, invalid signatures, and ambiguous output as research branches; they stop compatibility claims and camera execution, not offline investigation.
- Separate host-updater acceptance, camera-updater acceptance, bootloader acceptance, and runtime integrity in every result.
- An offline-valid candidate is not safe to install and must not be described as a release.
- Any camera-connected work requires a new design, credible α6400 recovery method, fresh approval, and physical supervision.

---

## File Map

| Path | Action | Responsibility |
|---|---|---|
| `pmca/analysis/sources.py` | Modify | Add exact Sony Taiwan α7 V 2.00 provenance. |
| `pmca/analysis/ranges.py` | Create | Validate non-overlapping byte ranges and compute preserved unknown ranges. |
| `pmca/analysis/dat.py` | Create | Parse bounded Sony DAT outer chunks without extracting payload bytes. |
| `pmca/analysis/fingerprints.py` | Create | Stream-scan approved regions for allowlisted executable/filesystem/container magics. |
| `pmca/analysis/tooling.py` | Create | Validate pinned tool provenance and execute narrow offline baseline commands. |
| `pmca/analysis/quarantine.py` | Create | Apply bounded patches to disposable copies and write metadata-only provenance sidecars. |
| `pmca/analysis/signatures.py` | Create | Model PE Authenticode-excluded ranges and mutation coverage impact. |
| `pmca/analysis/features.py` | Create | Validate feature markers, dependency claims, and three-model compatibility matrices. |
| `pmca/analysis/candidates.py` | Create | Build a quarantined candidate only from a digest-pinned, dependency-complete patch specification. |
| `pmca/analysis/creative_looks.py` | Create | Validate all-ten-look recipes and translate modern adjustments to α6400 controls. |
| `firmware_structure.py` | Create | Emit deterministic DAT/PE/magic structure reports from manifest-approved artifacts. |
| `firmware_tool_baseline.py` | Create | Run only pinned fwtool unpack baselines against disposable local inputs. |
| `firmware_lab.py` | Create | Run named mutation/signature experiments and candidate validation offline. |
| `creative_look_recipes.py` | Create | Validate recipe JSON and render an α6400 on-camera setup guide. |
| `tests/analysis/test_ranges.py` | Create | Test range validation and unknown-byte preservation. |
| `tests/analysis/test_dat.py` | Create | Test Sony DAT chunks, truncation, duplicate chunks, and FDAT boundaries. |
| `tests/analysis/test_fingerprints.py` | Create | Test bounded cross-chunk magic scanning and output limits. |
| `tests/analysis/test_tooling.py` | Create | Test pinned-revision, command, timeout, path, and output gates. |
| `tests/analysis/test_quarantine.py` | Create | Test original immutability, patch preconditions, paths, and sidecars. |
| `tests/analysis/test_signatures.py` | Create | Test PE signed/excluded range classification and mutation impact. |
| `tests/analysis/test_features.py` | Create | Test evidence levels, dependencies, and compatibility result rules. |
| `tests/analysis/test_candidates.py` | Create | Test digest pinning, preimage hashes, unresolved-dependency rejection, and candidate quarantine. |
| `tests/analysis/test_creative_looks.py` | Create | Test all ten looks, α6400 ranges, mappings, missing axes, and rendering. |
| `tests/analysis/test_cli.py` | Modify | Lock down the four new offline CLI surfaces. |
| `tests/analysis/test_real_reports.py` | Modify | Require bounded α7 V and new real-package reports. |
| `analysis/firmware-manifest.json` | Modify | Add authenticated α7 V metadata and locally measured SHA-256. |
| `analysis/reports/a7v-tw-v2.00.json` | Create | Add bounded α7 V metadata report. |
| `analysis/structures/*.json` | Create | Store metadata-only three-model chunk, overlay, and magic maps. |
| `analysis/tool-provenance.json` | Create | Record exact repositories and commit hashes for evaluated tools. |
| `analysis/tool-baselines/*.json` | Create | Record deterministic success/failure stage summaries without proprietary bytes. |
| `analysis/signature-experiments.json` | Create | Record mutation matrix, enforcement hypotheses, and results. |
| `analysis/feature-compatibility.json` | Create | Record vertical UI, touch-menu, and Creative Look dependency evidence. |
| `analysis/creative-look-recipes.json` | Create | Store official mappings and sourced experimental α6400 recipes. |
| `analysis/a6400-creative-look-guide.md` | Create | Render the ten-look on-camera setup guide. |
| `analysis/feature-evidence.json` | Modify | Replace superseded conclusions with new evidence-backed outcomes. |
| `analysis/a6400-feasibility-report.md` | Modify | Integrate donor, bypass, UI, recovery, and recipe findings. |

## Task 1: Authenticate and Add the Vertical-UI Donor

**Files:**

- Modify: `pmca/analysis/sources.py`
- Modify: `tests/analysis/test_sources.py`
- Modify: `analysis/firmware-manifest.json`
- Create: `analysis/reports/a7v-tw-v2.00.json`
- Modify: `tests/analysis/test_real_reports.py`

**Interfaces:**

- Consumes: `get_source(key: str) -> SourceSpec`, `firmware_manifest.py`, and `firmware_inspect.py`.
- Produces: source key `a7v-tw-v2.00` for `ILCE-7M5`, version `2.00`, filename `BODYDATA.DAT`, size `376_540_720`, release date `2026-05-14`, and the exact Sony Taiwan page URL.

- [ ] **Step 1: Switch to the execution branch and establish the baseline**

Run:

```powershell
git switch -c feature/a6400-ui-creative-look-research
& .\.venv\Scripts\python.exe -m unittest discover -s tests\analysis -p 'test_*.py' -v
& .\.venv\Scripts\python.exe -m unittest discover -s tests\safe -p 'test_*.py' -v
```

Expected: the new branch contains this plan and approved design commit `7a9ee6c`; all existing 71 analysis and 58 safe tests pass.

- [ ] **Step 2: Write the failing α7 V source test**

Add to `tests/analysis/test_sources.py`:

```python
def test_a7v_vertical_ui_donor_is_exactly_allowlisted(self):
    source = get_source("a7v-tw-v2.00")
    self.assertEqual(source.model, "ILCE-7M5")
    self.assertEqual(source.region, "TW")
    self.assertEqual(source.version, "2.00")
    self.assertEqual(source.filename, "BODYDATA.DAT")
    self.assertEqual(source.advertised_size, 376_540_720)
    self.assertEqual(source.release_date, "2026-05-14")
    self.assertEqual(
        source.page_url,
        "https://www.sony.com.tw/zh/electronics/support/"
        "e-mount-body-ilce-7-series/ilce-7m5/software/00377086",
    )
```

- [ ] **Step 3: Run the source test and verify red**

Run:

```powershell
& .\.venv\Scripts\python.exe -m unittest tests.analysis.test_sources -v
```

Expected: FAIL with `SourceError: Firmware source is not allowlisted`.

- [ ] **Step 4: Add the exact source entry and verify green**

Add an immutable `SourceSpec` entry with the values asserted above to `_SOURCES` in `pmca/analysis/sources.py`, then run:

```powershell
& .\.venv\Scripts\python.exe -m unittest tests.analysis.test_sources tests.analysis.test_manifest -v
```

Expected: all source and manifest tests pass.

- [ ] **Step 5: Acquire the official package into the ignored corpus**

Open only:

```text
https://www.sony.com.tw/zh/electronics/support/e-mount-body-ilce-7-series/ilce-7m5/software/00377086
```

Accept Sony's download terms and save `BODYDATA.DAT` to:

```text
.artifacts\sony-firmware\a7v-tw-v2.00\BODYDATA.DAT
```

Before saving, require `git check-ignore -v` to match `/.artifacts/`. After saving, require an exact size of `376540720` bytes. Do not copy the file to removable media.

- [ ] **Step 6: Record, verify, and report the donor**

Run:

```powershell
$acquiredAt = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
& .\.venv\Scripts\python.exe .\firmware_manifest.py add --source a7v-tw-v2.00 --file .artifacts\sony-firmware\a7v-tw-v2.00\BODYDATA.DAT --artifacts-root .artifacts --manifest analysis\firmware-manifest.json --acquired-at $acquiredAt
New-Item -ItemType Directory -Force .artifacts\analysis-inputs\a7v-tw-v2.00 | Out-Null
Copy-Item -LiteralPath .artifacts\sony-firmware\a7v-tw-v2.00\BODYDATA.DAT -Destination .artifacts\analysis-inputs\a7v-tw-v2.00\BODYDATA.DAT
& .\.venv\Scripts\python.exe .\firmware_manifest.py verify --file .artifacts\analysis-inputs\a7v-tw-v2.00\BODYDATA.DAT --artifacts-root .artifacts --manifest analysis\firmware-manifest.json
& .\.venv\Scripts\python.exe .\firmware_inspect.py inspect --source a7v-tw-v2.00 --file .artifacts\analysis-inputs\a7v-tw-v2.00\BODYDATA.DAT --artifacts-root .artifacts --manifest analysis\firmware-manifest.json --report analysis\reports\a7v-tw-v2.00.json
```

- [ ] **Step 7: Extend the committed-report test and commit**

Add `a7v-tw-v2.00.json` to `REPORT_NAMES`, add `ILCE-7M5` and `ILCE7M5` only if the fixed scanner emits those labels, and assert the report digest matches the manifest. Run the analysis suite, `git diff --check`, verify `git ls-files .artifacts` is empty, then commit:

```powershell
git add pmca/analysis/sources.py tests/analysis/test_sources.py tests/analysis/test_real_reports.py analysis/firmware-manifest.json analysis/reports/a7v-tw-v2.00.json
git commit -m "analysis: authenticate a7v vertical-ui donor"
```

**Reviewer gate:** The commit contains metadata and source only; the donor bytes remain ignored.

## Task 2: Map Sony DAT Chunks and Preserve Unknown Regions

**Files:**

- Create: `pmca/analysis/ranges.py`
- Create: `pmca/analysis/dat.py`
- Create: `firmware_structure.py`
- Create: `tests/analysis/test_ranges.py`
- Create: `tests/analysis/test_dat.py`
- Modify: `tests/analysis/test_cli.py`
- Create: `analysis/structures/a6700-tw-v2.00.json`
- Create: `analysis/structures/a7v-tw-v2.00.json`

**Interfaces:**

- Produces `ByteRange(label: str, offset: int, size: int, evidence: str)`.
- Produces `validate_ranges(file_size: int, ranges: tuple[ByteRange, ...]) -> tuple[ByteRange, ...]`.
- Produces `unknown_ranges(file_size: int, known: tuple[ByteRange, ...]) -> tuple[ByteRange, ...]`.
- Produces `DatChunk(kind: str, header_offset: int, payload_offset: int, size: int)`.
- Produces `parse_dat_chunks(path: Path, max_chunks: int = 4096) -> tuple[DatChunk, ...]`.

- [ ] **Step 1: Write failing range-ledger tests**

Create tests covering sorted output, negative offsets, integer overflow, overlap, beyond-EOF ranges, gaps before/between/after known ranges, and a complete range with no unknown bytes. A representative test is:

```python
def test_unknown_ranges_cover_every_unclaimed_byte():
    known = (
        ByteRange("header", 0, 8, "synthetic"),
        ByteRange("payload", 12, 4, "synthetic"),
    )
    self.assertEqual(
        unknown_ranges(20, known),
        (
            ByteRange("unknown", 8, 4, "computed complement"),
            ByteRange("unknown", 16, 4, "computed complement"),
        ),
    )
```

- [ ] **Step 2: Run range tests red, implement, and run green**

Run the new test module and require an import failure. Implement frozen dataclasses and overflow-safe comparisons using `offset <= file_size - size`; never add offsets before bounds are proven. Rerun until all range tests pass.

- [ ] **Step 3: Write failing DAT parser tests**

Build synthetic data with:

```python
DAT_MAGIC = b"\x89UFU\r\n\x1a\n"

def chunk(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I4s", len(payload), kind) + payload

fixture = (
    DAT_MAGIC
    + chunk(b"DATV", b"\x01\x00\x00\x00")
    + chunk(b"PROV", b"\x01\x00\x00\x00")
    + chunk(b"UDID", b"camera-id")
    + chunk(b"FDAT", b"encrypted-payload")
)
```

Assert exact header/payload offsets, bounded chunk count, rejection of wrong magic, truncated headers, payload beyond EOF, non-ASCII kinds, absent FDAT, duplicate FDAT, and bytes after the last chunk classified as unknown.

- [ ] **Step 4: Implement the bounded DAT parser**

Parse only eight-byte headers and seek across payloads. Do not return payload bytes. Require exactly one `FDAT`; permit other four-character ASCII chunk kinds; preserve their boundaries without interpreting `UDID`. Rerun range and DAT tests.

- [ ] **Step 5: Add the narrow structure CLI**

Implement:

```text
firmware_structure.py map --source SOURCE --file FILE --artifacts-root ROOT --manifest MANIFEST --report REPORT
```

It verifies the manifest entry, emits only chunk kind, header offset, payload offset, size, and unknown ranges, and rejects `--extract`, `--decrypt`, `--patch`, `--usb`, `--camera`, arbitrary token, and abbreviated options. Add CLI tests for exact parsing and one-line expected errors.

- [ ] **Step 6: Run the parser on α6700 and α7 V copies**

Generate the two committed structure reports. For α6700, require the already observed outer sequence and boundaries:

```text
DATV header=8 payload=16 size=4
PROV header=20 payload=28 size=4
UDID header=32 payload=40 size=108
FDAT header=148 payload=156 size=1024017680
```

Do not assume α7 V matches; record its actual bounded result.

- [ ] **Step 7: Verify and commit**

Run the focused tests plus `git diff --check`, then commit source, tests, CLI, and two metadata reports:

```powershell
git commit -m "analysis: map sony dat container boundaries"
```

**Reviewer gate:** Every byte is either in a validated chunk range or an explicit unknown range; no payload bytes appear in Git.

## Task 3: Map the α6400 PE Overlay and Scan Allowlisted Magics

**Files:**

- Create: `pmca/analysis/fingerprints.py`
- Create: `tests/analysis/test_fingerprints.py`
- Modify: `firmware_structure.py`
- Modify: `tests/analysis/test_cli.py`
- Create: `analysis/structures/a6400-tw-v2.00.json`
- Modify: `analysis/structures/a6700-tw-v2.00.json`
- Modify: `analysis/structures/a7v-tw-v2.00.json`

**Interfaces:**

- Produces `MagicSpec(label: str, value: bytes, alignment: int | None)`.
- Produces `MagicHit(label: str, offset: int)`.
- Produces `scan_magics(path: Path, ranges: tuple[ByteRange, ...], specs: tuple[MagicSpec, ...], max_hits: int = 64) -> tuple[MagicHit, ...]`.

- [ ] **Step 1: Write failing streaming-scanner tests**

Test a magic wholly inside a chunk, split across two 1 MiB reads, outside an approved range, duplicated beyond `max_hits`, alignment-required, empty specs, and overlapping ranges rejected before reading. Fixed magics are:

```python
MAGICS = (
    MagicSpec("sony-dat", b"\x89UFU\r\n\x1a\n", None),
    MagicSpec("pe", b"MZ", None),
    MagicSpec("elf", b"\x7fELF", None),
    MagicSpec("squashfs-le", b"hsqs", 4),
    MagicSpec("squashfs-be", b"sqsh", 4),
    MagicSpec("gzip", b"\x1f\x8b\x08", None),
    MagicSpec("xz", b"\xfd7zXZ\x00", None),
    MagicSpec("zip", b"PK\x03\x04", None),
    MagicSpec("cpio-newc", b"070701", None),
)
```

- [ ] **Step 2: Implement the scanner with bounded carry**

Read one fixed-size buffer at a time, retain only `max_magic_length - 1` carry bytes, return offsets only, and stop with a validation error rather than truncate unreported hits. Rerun scanner tests.

- [ ] **Step 3: Extend PE structure mapping**

Use the existing `parse_pe_summary` result to emit PE header range, section-table boundary, certificate table, and overlay. For the authenticated α6400 updater, require observed values to remain consistent with its manifest digest:

```text
PE32 machine=332 sections=5 overlay_offset=452608
certificate_offset=314220688 certificate_size=10024
```

Scan only the overlay and known DAT `FDAT` ranges. Do not scan arbitrary whole files when a narrower validated range exists.

- [ ] **Step 4: Generate three deterministic structure reports**

Run `firmware_structure.py map` twice for each model, compare SHA-256 of the JSON outputs, then replace the committed reports. Treat magic hits as candidate structure evidence, never proof that an embedded image is valid.

- [ ] **Step 5: Test and commit**

Run range, DAT, fingerprint, CLI, and real-report tests, then commit:

```powershell
git commit -m "analysis: map updater overlays and firmware magics"
```

**Reviewer gate:** The report is reconstructively useless: labels and bounded offsets only, with no bytes or arbitrary strings.

## Task 4: Reproduce Historical Tool Limits at Pinned Revisions

**Files:**

- Create: `pmca/analysis/tooling.py`
- Create: `firmware_tool_baseline.py`
- Create: `tests/analysis/test_tooling.py`
- Modify: `tests/analysis/test_cli.py`
- Create: `analysis/tool-provenance.json`
- Create: `analysis/tool-baselines/ma1co-fwtool.json`
- Create: `analysis/tool-baselines/joeording3-fwtool.json`
- Create: `analysis/tool-baselines/ironpayne22-fwtool.json`

**Interfaces:**

- Produces `ToolSpec(name: str, repo_url: str, commit: str, entrypoint: str)`.
- Produces `run_unpack_baseline(spec: ToolSpec, python: Path, checkout: Path, input_path: Path, output_dir: Path, timeout_seconds: int = 300) -> dict`.
- Output fields are exact: `tool`, `commit`, `input_sha256`, `exit_code`, `timed_out`, `stage`, `error_class`, `safe_summary`.

- [ ] **Step 1: Write failing provenance and runner tests**

Require forty-character lowercase commit hashes, HTTPS GitHub repository URLs, relative entrypoints, checkouts under `.artifacts/tools/`, inputs under `.artifacts/analysis-inputs/`, outputs under `.artifacts/tool-output/`, no symlinks, no shell execution, a command beginning with the configured Python executable and exact entrypoint, and timeout termination. Use a synthetic fixture tool that returns exit code 3 and writes a harmless text marker.

- [ ] **Step 2: Implement a narrow subprocess runner**

Build the argument vector exactly as:

```python
[
    str(python),
    str(checkout / spec.entrypoint),
    "unpack",
    "-f",
    str(input_path),
    "-o",
    str(output_dir),
]
```

Use `shell=False`, a finite timeout, captured text capped at 64 KiB, and an allowlist that records only known stage/error phrases. Never include extracted file names or data in the committed summary.

- [ ] **Step 3: Pin and acquire the three tool revisions**

Record and clone only these revisions below ignored `.artifacts/tools/`:

```text
ma1co/fwtool.py      cdba742b73eed5981480c326aeb30033aabf0223
joeording3/fwtool.py c351060721547f6b65d6c969d863f486662f9424
ironpayne22/fwtool.py bc32b106833f64bf105164d49f2f181b0cf39a47
```

Use detached checkouts and verify `git rev-parse HEAD` exactly. Record the repository, commit, acquisition time, and license path in `analysis/tool-provenance.json`.

- [ ] **Step 4: Run the baseline matrix**

Run all three tools against disposable α6400, α6700, and α7 V inputs. Output directories remain ignored. The committed summaries must distinguish wrapper parsing, DAT parsing, decrypter selection, decryption, partition parsing, and extraction stages. A message such as `No decrypter found` is recorded as a precise stage result and becomes input to Task 5.

- [ ] **Step 5: Verify determinism and commit**

Run each failed baseline twice and require identical normalized JSON. Run tooling and CLI tests, scan the committed JSON for absolute user paths and proprietary filenames beyond the three official package filenames, then commit:

```powershell
git commit -m "analysis: reproduce pinned firmware tool limits"
```

**Reviewer gate:** A tool's `unsupported` or decrypter error is a reproduced baseline, not the final research conclusion.

## Task 5: Build the Offline Mutation, Signature, and Candidate Lab

**Files:**

- Create: `pmca/analysis/quarantine.py`
- Create: `pmca/analysis/signatures.py`
- Create: `pmca/analysis/candidates.py`
- Create: `firmware_lab.py`
- Create: `tests/analysis/test_quarantine.py`
- Create: `tests/analysis/test_signatures.py`
- Create: `tests/analysis/test_candidates.py`
- Modify: `tests/analysis/test_cli.py`
- Create: `analysis/signature-experiments.json`

**Interfaces:**

- Produces `Patch(offset: int, expected_sha256: str, replacement: bytes)` where `expected_sha256` hashes the exact preimage range.
- Produces `apply_quarantined_patches(source: Path, artifacts_root: Path, output: Path, patches: tuple[Patch, ...], hypothesis_id: str) -> dict`.
- Produces `PeCoverage(signed: tuple[ByteRange, ...], excluded: tuple[ByteRange, ...])`.
- Produces `pe_authenticode_coverage(path: Path) -> PeCoverage`.
- Produces `classify_patch_impact(patches: tuple[Patch, ...], coverage: PeCoverage) -> tuple[str, ...]`.
- Produces `CandidateSpec(source_key: str, parent_sha256: str, patches: tuple[Patch, ...], unresolved_dependencies: tuple[str, ...])`.
- Produces `build_candidate(spec: CandidateSpec, source: Path, artifacts_root: Path, output: Path) -> dict`.

- [ ] **Step 1: Write failing quarantine tests**

Test rejection of a source outside `.artifacts/analysis-inputs/`, an output outside `.artifacts/quarantine/`, an output without `NOT_FOR_INSTALL`, an original source under `.artifacts/sony-firmware/`, symlinks, overlapping patches, incorrect preimage hashes, out-of-range patches, duplicate hypothesis IDs, and sidecars containing replacement bytes. Test that a successful synthetic mutation changes only the requested bytes and leaves the source digest unchanged.

- [ ] **Step 2: Implement immutable patching and metadata-only sidecars**

Copy through a temporary file in the quarantine directory, verify all preimages before writing, flush and atomically rename, and write a JSON sidecar containing parent/output digests, offsets, sizes, preimage/replacement SHA-256 values, hypothesis ID, and `installable: false`. Never serialize replacement bytes.

- [ ] **Step 3: Write failing PE coverage tests**

Construct a minimal signed PE32 fixture. Assert Authenticode coverage excludes the checksum field, the certificate-table directory entry, and the certificate blob while covering headers, sections, and overlay bytes outside those exclusions. Assert a patch spanning signed and excluded ranges is classified `mixed`.

- [ ] **Step 4: Implement PE coverage and mutation impact**

Reuse bounded PE header validation from `pmca.analysis.static`; calculate ranges using subtraction through `unknown_ranges` rather than arithmetic shortcuts. State explicitly that host Authenticode coverage does not establish camera boot-signature coverage.

- [ ] **Step 5: Write failing candidate-builder tests**

Test rejection when parent digest differs, any dependency remains unresolved, a patch preimage differs, output naming/path is unsafe, or a patch affects a range classified as unknown without an evidence reference. Test one fully synthetic dependency-complete candidate that is produced under quarantine with `installable: false`.

- [ ] **Step 6: Implement the candidate gate**

`build_candidate` calls `apply_quarantined_patches` only when every dependency is resolved and every patch is digest-pinned. It returns a structured rejection report for real firmware when prerequisites are missing; it never relaxes gates based on model name or a command-line flag.

- [ ] **Step 7: Run the real offline experiment matrix**

Create metadata-only records for these named experiments against disposable copies:

```text
a6400-pe-certificate-byte       mutate one excluded certificate byte
a6400-pe-overlay-byte           mutate one signed overlay byte
a6700-datv-version-byte         mutate one DATV payload byte
a6700-udid-field-byte           mutate one bounded UDID payload byte
a6700-fdat-first-block-byte     mutate one FDAT byte
a7v-datv-version-byte           mutate one DATV payload byte
a7v-udid-field-byte             mutate one bounded UDID payload byte
a7v-fdat-first-block-byte       mutate one FDAT byte
```

For each, record parent/output digests, signed-range impact when knowable, historical-tool stage before and after mutation, and whether the result discriminates a model, container, decrypter, signature, or parser hypothesis. Do not execute any Sony updater and do not present a candidate to a camera.

- [ ] **Step 8: Test and commit**

Run quarantine, signature, candidate, tooling, and CLI tests. Confirm every generated binary is ignored and every sidecar says `installable: false`, then commit source, tests, and `analysis/signature-experiments.json`:

```powershell
git commit -m "analysis: test signature and model-gate hypotheses offline"
```

**Reviewer gate:** The lab makes local bypass hypotheses testable but cannot turn missing evidence into an installable α6400 image.

## Task 6: Map UI Dependencies and Build Evidence-Gated Port Candidates

**Files:**

- Create: `pmca/analysis/features.py`
- Create: `tests/analysis/test_features.py`
- Create: `analysis/feature-compatibility.json`

**Interfaces:**

- Produces `FeatureEvidence(level: str, source: str, claim: str)` where level is `CONFIRMED`, `PARTIAL`, `INFERRED`, or `INSUFFICIENT_EVIDENCE`.
- Produces `FeatureBoundary(name: str, target: str, dependencies: tuple[str, ...], evidence: tuple[FeatureEvidence, ...])`.
- Produces `validate_compatibility_matrix(document: dict) -> dict`.
- Produces `candidate_readiness(boundary: FeatureBoundary) -> tuple[bool, tuple[str, ...]]`.

- [ ] **Step 1: Write failing evidence and dependency tests**

Require exact feature IDs:

```python
FEATURE_IDS = (
    "vertical-orientation-state",
    "vertical-layout-selection",
    "vertical-render-transform",
    "vertical-input-transform",
    "touch-menu-widgets",
    "touch-event-routing",
    "creative-look-base-tables",
    "creative-look-adjustment-axes",
)
```

Test rejection of unknown levels, missing features, duplicate dependencies, circular dependencies, `CONFIRMED` without an observation from an official document or authenticated artifact, and readiness when any dependency is unresolved.

- [ ] **Step 2: Implement deterministic validation and readiness**

Normalize features in `FEATURE_IDS` order. Readiness is true only when the feature and every transitive dependency has at least one `CONFIRMED` evidence item and no `INSUFFICIENT_EVIDENCE` item. `PARTIAL` and `INFERRED` remain reportable but cannot authorize candidate building.

- [ ] **Step 3: Gather three-model feature evidence**

Use official Sony documentation to establish behavior and hardware facts. Use the structure reports, tool baselines, and ignored extracted outputs—if any—to record implementation boundaries. Scan only allowlisted ASCII and UTF-16 marker families for:

```text
Vertical Display, Creative Look, Touch Operation, orientation, rotate, portrait
```

Treat a hit as a locator hypothesis; confirm it only with executable/resource references or repeated structure. Treat absence from encrypted data as no result, not feature absence.

- [ ] **Step 4: Evaluate port strategies in fixed order**

For each UI boundary, record the first evidence-supported option among direct component reuse, resource-table transplant, α6400 subsystem patch, or α6400-specific reimplementation. The compatibility entry must enumerate architecture, imports, relocations, memory, display geometry, input coordinates, dependent services, and signature layer. Unknown dependencies remain explicit.

- [ ] **Step 5: Exercise the candidate gate**

If the matrix produces a dependency-complete, digest-pinned patch specification, pass it to `build_candidate` and keep the result quarantined. Otherwise call the same API with the unresolved dependency tuple and commit the structured rejection evidence. This produces one deterministic outcome rather than silently skipping candidate construction.

- [ ] **Step 6: Test and commit**

Run feature and candidate tests, validate `analysis/feature-compatibility.json`, and commit:

```powershell
git commit -m "analysis: map ui port dependencies"
```

**Reviewer gate:** Feature existence on α7 V or α6700 is never presented as α6400 executable compatibility.

## Task 7: Deliver All Ten α6400 Creative Look Translations

**Files:**

- Create: `pmca/analysis/creative_looks.py`
- Create: `creative_look_recipes.py`
- Create: `tests/analysis/test_creative_looks.py`
- Modify: `tests/analysis/test_cli.py`
- Create: `analysis/creative-look-recipes.json`
- Create: `analysis/a6400-creative-look-guide.md`

**Interfaces:**

- Produces `ModernLook(code: str, base: str, contrast: int, highlights: int, shadows: int, fade: int, saturation: int, sharpness: int, sharpness_range: int, clarity: int, wb_kelvin: int | None, wb_shift_ab: int, wb_shift_gm: int, source: str)`.
- Produces `A6400Recipe(code: str, creative_style: str, contrast: int, saturation: int, sharpness: int, wb_kelvin: int | None, wb_shift_ab: int, wb_shift_gm: int, confidence: str, unrepresented_axes: tuple[str, ...])`.
- Produces `translate_to_a6400(look: ModernLook) -> A6400Recipe`.
- Produces `render_recipe_guide(document: dict) -> str`.

- [ ] **Step 1: Write failing schema and mapping tests**

Require exactly:

```python
LOOK_CODES = ("ST", "PT", "NT", "VV", "VV2", "FL", "IN", "SH", "BW", "SE")
DIRECT_STYLE_MAP = {
    "ST": "Standard",
    "PT": "Portrait",
    "NT": "Neutral",
    "VV": "Vivid",
    "BW": "B/W",
    "SE": "Sepia",
}
INFERRED_STYLE_MAP = {
    "VV2": "Clear",
    "FL": "Deep",
    "IN": "Neutral",
    "SH": "Light",
}
```

Test unique codes, all ten present, α6400 contrast/saturation/sharpness in `-3..3`, valid Creative Style names, WB Kelvin in `2500..9900` when set, WB shifts in `-9..9`, source URLs using HTTPS, direct mappings marked at least `PARTIAL`, inferred mappings marked `INFERRED`, and missing modern axes listed rather than dropped.

- [ ] **Step 2: Run red, implement validation and translation, run green**

Translation carries contrast, saturation, and sharpness with clamping; records `highlights`, `shadows`, `fade`, `sharpness_range`, and `clarity` in `unrepresented_axes` whenever nonzero; preserves WB values; and never claims numerical color-transform equivalence.

- [ ] **Step 3: Build the sourced recipe catalog**

Use Sony's Creative Look documentation and portal for official definitions. Use `https://sonyfilmsimulations.com/en/` only for recipes that publish the base Creative Look, all adjustment values used, WB, and a stable recipe URL. Store third-party entries with `source_kind: community-experiment` and never convert them into Sony defaults.

The catalog must include a practical default α6400 entry for every look. Use zero adjustments for the six direct base mappings unless an official source states otherwise. Use these conservative starting translations for the four non-native bases, all labeled `INFERRED`:

```text
VV2: Clear   contrast=0  saturation=+1 sharpness=0
FL:  Deep    contrast=-1 saturation=0  sharpness=0
IN:  Neutral contrast=-2 saturation=-2 sharpness=-1
SH:  Light   contrast=-1 saturation=-1 sharpness=-1
```

These are starting points for later controlled JPEG validation, not exact Sony formulas.

- [ ] **Step 4: Render the on-camera setup guide**

Implement:

```text
creative_look_recipes.py render --recipes analysis\creative-look-recipes.json --output analysis\a6400-creative-look-guide.md
```

The guide explains that six direct looks use existing base styles and the four inferred looks occupy four of the α6400's six Style Boxes. It lists exact LCD-selectable settings, confidence, missing axes, sources, and a fixed future validation protocol: same lens, scene, exposure, lighting, white balance, JPEG settings, and no postprocessing.

- [ ] **Step 5: Test and commit**

Run recipe and CLI tests, render twice and compare SHA-256, then commit:

```powershell
git commit -m "analysis: translate all creative looks for a6400"
```

**Reviewer gate:** All ten looks are usable as direct or inferred α6400 settings, and none is labeled an exact Sony colorimetric match without measurement.

## Task 8: Integrate Evidence, Verify the Lab, and Report the Strongest Outcome

**Files:**

- Modify: `analysis/feature-evidence.json`
- Modify: `analysis/a6400-feasibility-report.md`
- Verify: every file created or modified in Tasks 1–7.

**Interfaces:**

- Consumes: authenticated manifest, three structure reports, tool baselines, signature experiments, feature compatibility matrix, and Creative Look catalog.
- Produces: the final reproducible offline result and exact next gate.

- [ ] **Step 1: Update the evidence document claim by claim**

For each existing capability, replace superseded claims with the strongest supported evidence. Creative Look emulation must be at least `PARTIAL` because the six direct mappings and four explicit Style Box approximations are delivered. UI and signature statuses follow actual Tasks 4–6 results; do not preserve `INSUFFICIENT_EVIDENCE` merely because the old tool failed, and do not promote a status without a compatible boundary.

- [ ] **Step 2: Render the integrated report**

Run `firmware_decisions.py render`, then add human-readable sections for donor correction, exact tool revisions, format discoveries, signature/model-gate experiments, candidate-build result, vertical/touch dependency matrix, Creative Look guide, recovery gap, and the camera-execution gate. Every negative result includes the tested hypothesis and exact stopping layer.

- [ ] **Step 3: Invoke verification and code-review workflows**

Read and apply `superpowers:verification-before-completion` and `superpowers:requesting-code-review`. Because execution is inline, perform the review locally without dispatching a subagent.

- [ ] **Step 4: Run the complete verification suite**

Run:

```powershell
& .\.venv\Scripts\python.exe -m unittest discover -s tests\safe -p 'test_*.py' -v
& .\.venv\Scripts\python.exe -m unittest discover -s tests\analysis -p 'test_*.py' -v
& .\.venv\Scripts\python.exe -m compileall -q pmca firmware_manifest.py firmware_inspect.py firmware_decisions.py firmware_structure.py firmware_tool_baseline.py firmware_lab.py creative_look_recipes.py tests
git diff --check
git ls-files .artifacts
git status --short --branch
```

Expected: every safe and analysis test passes; compilation exits zero; diff check is clean; no `.artifacts` file is tracked.

- [ ] **Step 5: Reverify original firmware immutability and determinism**

Run `firmware_manifest.py verify` for all three originals and all three disposable inputs. Regenerate every committed metadata report and Markdown guide to ignored temporary paths and require byte-for-byte SHA-256 matches with committed outputs.

- [ ] **Step 6: Scan tracked changes for proprietary or camera-reaching content**

Require no new tracked file over 1 MiB, no tracked firmware-like extension, and no runtime imports or calls for `pmca.usb`, `pmca.commands`, `pmca.shell`, service mode, updater mode, driver changes, removable media, or firmware write operations. Allow documentation to name these only as prohibited boundaries or researched historical behavior.

- [ ] **Step 7: Commit the integrated report and finish the branch**

Commit evidence and report after all verification is fresh:

```powershell
git commit -m "docs: report a6400 ui and creative-look port research"
```

Then invoke `superpowers:finishing-a-development-branch` and present the user with the verified capability results, exact unresolved barrier if any, Creative Look guide location, commit list, test counts, and branch integration choices.

**Final gate:** State plainly whether the result is a native port candidate, α6400-specific reimplementation candidate, practical Creative Look approximation, or a precisely located unresolved barrier. Do not ask the user to connect the α6400 from this plan.
