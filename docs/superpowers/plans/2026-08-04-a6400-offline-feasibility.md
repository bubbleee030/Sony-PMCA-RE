# Sony α6400 Offline Firmware Feasibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Build a deterministic, fail-closed, offline evidence pipeline that compares official Taiwan α6400 2.00 and α6700 2.00 firmware packages and produces evidence-backed Creative Look and UI feasibility decisions without connecting to a camera.

**Architecture:** Keep firmware binaries in an ignored quarantine directory and commit only source provenance, hashes, bounded metadata, tests, and reports. A standard-library Python package validates artifacts, performs bounded static inspection, and renders a decision report from explicit evidence records. The runtime contains no PMCA USB, service, shell, updater, driver, settings-write, or firmware-write dependency.

**Tech Stack:** Windows 11, PowerShell 7, Python 3.13 standard library, unittest, dataclasses, pathlib, hashlib, json, struct, math, and Git worktrees.

## Global Constraints

- Work in a new linked worktree at C:\Users\Bubble\ChatGPT\Sony\Sony-PMCA-RE-a6400-analysis on branch feature/a6400-offline-feasibility.
- Keep the α6400 disconnected for the entire plan. Do not query Windows PnP state, change a driver, enter service or updater mode, modify settings, or send a USB command.
- Accept firmware only from the exact Sony Taiwan URLs and metadata defined in pmca/analysis/sources.py.
- Never flash the α6700 package to the α6400.
- Add /.artifacts/ to .gitignore before downloading either firmware package.
- Never commit firmware bytes, extracted proprietary content, arbitrary strings, base64 blobs, or hex dumps.
- Treat a locally recorded SHA-256 as an integrity baseline after acquisition, not as proof that Sony published that digest.
- Do not import pmca.usb, pmca.commands, pmca.shell, pmca.safe, updater-shell code, or any driver, service, settings-write, or firmware-write module from the analysis runtime.
- Analyze copies under .artifacts only. Verify each input SHA-256 before and after every real-package run.
- Fail closed on a source, filename, size, model, version, path, digest, format, or schema mismatch.
- A BLOCKED or INSUFFICIENT_EVIDENCE conclusion is a valid successful research outcome.
- Any later camera-connected work requires a separate approved design and recovery runbook.

---

## File Map

| Path | Action | Responsibility |
|---|---|---|
| .gitignore | Modify | Ignore the complete local firmware and temporary-analysis quarantine. |
| pmca/analysis/__init__.py | Create | Define the offline analysis package without re-exporting PMCA runtime APIs. |
| pmca/analysis/sources.py | Create | Store the two exact approved Sony Taiwan source specifications. |
| pmca/analysis/manifest.py | Create | Validate quarantined artifact paths, sizes, filenames, hashes, and deterministic manifest data. |
| pmca/analysis/static.py | Create | Perform bounded PE/raw metadata, entropy, and allowlisted-token inspection. |
| pmca/analysis/report.py | Create | Build and atomically write deterministic metadata-only JSON reports. |
| pmca/analysis/decisions.py | Create | Validate feature evidence and render the final feasibility decision report. |
| firmware_manifest.py | Create | Expose add and verify operations for the two approved firmware artifacts. |
| firmware_inspect.py | Create | Inspect one manifest-approved artifact and write one metadata-only report. |
| firmware_decisions.py | Create | Validate evidence JSON and render the human-readable feasibility report. |
| tests/analysis/__init__.py | Create | Mark the analysis tests as a package. |
| tests/analysis/test_sources.py | Create | Test the immutable approved-source table. |
| tests/analysis/test_manifest.py | Create | Test path, filename, size, digest, symlink, and manifest gates. |
| tests/analysis/test_static.py | Create | Test bounded PE/raw parsing, entropy, and token summaries. |
| tests/analysis/test_report.py | Create | Test input immutability, deterministic JSON, and output restrictions. |
| tests/analysis/test_decisions.py | Create | Test required capabilities, statuses, evidence, inference labels, and Markdown rendering. |
| tests/analysis/test_cli.py | Create | Test the three narrow CLI surfaces and expected failures. |
| analysis/firmware-manifest.json | Create during acquisition | Record official provenance and locally measured artifact integrity metadata. |
| analysis/reports/a6400-tw-v2.00.json | Create during real analysis | Store bounded α6400 package metadata only. |
| analysis/reports/a6700-tw-v2.00.json | Create during real analysis | Store bounded α6700 package metadata only. |
| analysis/feature-evidence.json | Create after inspection | Store cited observations and explicitly labelled inferences. |
| analysis/a6400-feasibility-report.md | Generate after inspection | Present one decision for every required feature track. |

## Task 1: Create the Isolated Offline-Analysis Worktree

**Files:**

- Verify: docs/superpowers/specs/2026-08-04-a6400-firmware-feasibility-design.md
- Verify: docs/superpowers/plans/2026-08-04-a6400-offline-feasibility.md

**Interfaces:**

- Consumes: master commit containing the approved specification and this plan.
- Produces: clean feature/a6400-offline-feasibility worktree with a Python 3.13 environment.

- [ ] **Step 1: Read the required worktree skill**

Invoke superpowers:using-git-worktrees. Confirm the main checkout is a normal repository, not a linked worktree or submodule.

- [ ] **Step 2: Verify the main checkout and exact remote mapping**

Run:

    Set-Location C:\Users\Bubble\ChatGPT\Sony\Sony-PMCA-RE
    git status --short --branch
    git remote -v
    git log -2 --oneline

Expected: master is clean; origin is https://github.com/bubbleee030/Sony-PMCA-RE.git; upstream is https://github.com/ma1co/Sony-PMCA-RE.git; the approved design and this plan are the newest commits.

- [ ] **Step 3: Verify the target path is absent and create the linked worktree**

Run:

    $target = 'C:\Users\Bubble\ChatGPT\Sony\Sony-PMCA-RE-a6400-analysis'
    if (Test-Path -LiteralPath $target) { throw "Target already exists: $target" }
    git worktree add $target -b feature/a6400-offline-feasibility
    git -C $target status --short --branch

Expected: the new path exists on feature/a6400-offline-feasibility with no working-tree changes.

- [ ] **Step 4: Create the isolated environment and install the already-reviewed dependencies**

Run from the new worktree:

    py -3.13 -m venv .venv
    & .\.venv\Scripts\python.exe -m pip install --upgrade pip
    & .\.venv\Scripts\python.exe -m pip install -r requirements-safe.txt

Expected: Python 3.13 is available. Analysis code will use the standard library even though the existing safe test suite needs the reviewed USB packages.

- [ ] **Step 5: Run the existing baseline**

Run:

    & .\.venv\Scripts\python.exe -m unittest discover -s tests\safe -v

Expected: 58 tests pass and no camera is connected or queried.

**Reviewer gate:** Both the main checkout and new worktree must be clean, and the new worktree must be inside C:\Users\Bubble\ChatGPT\Sony before Task 2.

## Task 2: Add the Artifact Quarantine and Approved Source Table

**Files:**

- Modify: .gitignore
- Create: pmca/analysis/__init__.py
- Create: pmca/analysis/sources.py
- Create: tests/analysis/__init__.py
- Create: tests/analysis/test_sources.py

**Interfaces:**

- Consumes: no analysis runtime.
- Produces: SourceSpec dataclass and get_source(key: str) -> SourceSpec.

- [ ] **Step 1: Write the source-table tests**

Create tests/analysis/__init__.py as an empty file. Create tests/analysis/test_sources.py with:

    import unittest

    from pmca.analysis.sources import SourceError, get_source


    class SourceTests(unittest.TestCase):
        def test_a6400_tw_source_is_exact(self):
            source = get_source("a6400-tw-v2.00")
            self.assertEqual(source.model, "ILCE-6400")
            self.assertEqual(source.region, "TW")
            self.assertEqual(source.version, "2.00")
            self.assertEqual(source.filename, "Update_ILCE6400V200.exe")
            self.assertEqual(source.advertised_size, 314_230_712)
            self.assertEqual(
                source.page_url,
                "https://www.sony.com.tw/zh/electronics/support/"
                "e-mount-body-ilce-6000-series/ilce-6400/downloads/00016145",
            )

        def test_a6700_tw_source_is_exact(self):
            source = get_source("a6700-tw-v2.00")
            self.assertEqual(source.model, "ILCE-6700")
            self.assertEqual(source.region, "TW")
            self.assertEqual(source.version, "2.00")
            self.assertEqual(source.filename, "BODYDATA.DAT")
            self.assertEqual(source.advertised_size, 1_024_017_848)
            self.assertEqual(
                source.page_url,
                "https://www.sony.com.tw/zh/electronics/support/"
                "e-mount-body-ilce-6000-series/ilce-6700/software/00298440",
            )

        def test_unknown_source_fails_closed(self):
            with self.assertRaises(SourceError):
                get_source("a6700-us-latest")


    if __name__ == "__main__":
        unittest.main()

- [ ] **Step 2: Run the source tests and confirm the package is missing**

Run:

    & .\.venv\Scripts\python.exe -m unittest tests.analysis.test_sources -v

Expected: FAIL with ModuleNotFoundError for pmca.analysis.

- [ ] **Step 3: Implement the immutable source table**

Create pmca/analysis/__init__.py with only this docstring:

    """Offline, metadata-only Sony firmware feasibility helpers."""

Create pmca/analysis/sources.py with a frozen SourceSpec dataclass, a private mapping containing only the two exact records above, SourceError(ValueError), and:

    def get_source(key: str) -> SourceSpec:
        try:
            return _SOURCES[key]
        except KeyError as error:
            raise SourceError("Firmware source is not allowlisted") from error

Do not expose a function that accepts an arbitrary URL or constructs a URL from user input.

- [ ] **Step 4: Ignore the complete quarantine**

Add exactly this line to .gitignore:

    /.artifacts/

Run:

    git check-ignore -v .artifacts\sony-firmware\sentinel.bin

Expected: .gitignore identifies /.artifacts/ as the matching rule.

- [ ] **Step 5: Run tests and commit**

Run:

    & .\.venv\Scripts\python.exe -m unittest tests.analysis.test_sources -v
    git diff --check
    git add .gitignore pmca/analysis/__init__.py pmca/analysis/sources.py tests/analysis/__init__.py tests/analysis/test_sources.py
    git commit -m "analysis: allowlist Sony firmware sources"

Expected: 3 tests pass and the focused commit succeeds.

**Reviewer gate:** The source module must contain two fixed HTTPS page URLs only and no downloader.

## Task 3: Implement Fail-Closed Artifact Manifests

**Files:**

- Create: pmca/analysis/manifest.py
- Create: firmware_manifest.py
- Create: tests/analysis/test_manifest.py
- Modify: tests/analysis/test_cli.py

**Interfaces:**

- Consumes: get_source(key: str) -> SourceSpec.
- Produces:
  - sha256_file(path: pathlib.Path, chunk_size: int = 1_048_576) -> str
  - record_artifact(source_key: str, artifact: pathlib.Path, artifacts_root: pathlib.Path, acquired_at: str) -> dict
  - load_manifest(path: pathlib.Path) -> dict
  - write_manifest(path: pathlib.Path, data: dict) -> None
  - verify_manifest_entry(entry: dict, artifact: pathlib.Path, artifacts_root: pathlib.Path) -> None

- [ ] **Step 1: Write path, size, digest, and symlink tests**

Create tests/analysis/test_manifest.py. Use tempfile.TemporaryDirectory and small SourceSpec objects patched into get_source. Cover:

    def test_record_artifact_rejects_outside_root(self):
        with self.assertRaises(ManifestError):
            record_artifact("fixture", outside_file, artifacts_root, acquired_at)

    def test_record_artifact_rejects_symlink(self):
        with self.assertRaises(ManifestError):
            record_artifact("fixture", linked_file, artifacts_root, acquired_at)

    def test_record_artifact_rejects_wrong_filename_and_size(self):
        for candidate in (wrong_name, wrong_size):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ManifestError):
                    record_artifact("fixture", candidate, artifacts_root, acquired_at)

    def test_record_and_verify_round_trip(self):
        entry = record_artifact("fixture", artifact, artifacts_root, acquired_at)
        self.assertEqual(entry["sha256"], hashlib.sha256(b"firmware").hexdigest())
        verify_manifest_entry(entry, artifact, artifacts_root)

    def test_verify_rejects_changed_bytes(self):
        entry = record_artifact("fixture", artifact, artifacts_root, acquired_at)
        artifact.write_bytes(b"changed!")
        with self.assertRaises(ManifestError):
            verify_manifest_entry(entry, artifact, artifacts_root)

Also verify deterministic JSON ordering, schema_version equals 1, no unrecognized top-level fields, and duplicate source keys are rejected.

- [ ] **Step 2: Run the manifest tests and confirm failure**

Run:

    & .\.venv\Scripts\python.exe -m unittest tests.analysis.test_manifest -v

Expected: FAIL because pmca.analysis.manifest does not exist.

- [ ] **Step 3: Implement manifest validation**

Implement ManifestError(ValueError). Check the raw artifact and artifacts-root paths with Path.is_symlink() before resolution and reject either link. Then resolve both with Path.resolve(strict=True), require the resolved artifact to be a regular file, and require resolved_artifact.relative_to(resolved_root) to succeed. Validate the exact allowlisted filename and advertised size before hashing. Use binary reads in 1 MiB chunks.

record_artifact returns only:

    {
        "source_key": source.key,
        "manufacturer": "Sony",
        "model": source.model,
        "region": source.region,
        "version": source.version,
        "source_page": source.page_url,
        "filename": source.filename,
        "advertised_size": source.advertised_size,
        "measured_size": artifact.stat().st_size,
        "sha256": sha256_file(artifact),
        "acquired_at": acquired_at,
    }

write_manifest writes UTF-8 JSON with sort_keys=True, indent=2, one trailing newline, and os.replace from a temporary sibling file. It must reject a manifest path below .artifacts.

- [ ] **Step 4: Add the narrow manifest CLI and its surface tests**

Create firmware_manifest.py with only two subcommands:

    firmware_manifest.py add --source SOURCE --file FILE --artifacts-root ROOT --manifest MANIFEST --acquired-at ISO8601
    firmware_manifest.py verify --file FILE --artifacts-root ROOT --manifest MANIFEST

The CLI must not accept a URL, download flag, camera option, driver, model override, expected size, or expected digest. Add tests/analysis/test_cli.py that patches manifest functions and verifies only add and verify parse.

- [ ] **Step 5: Run tests and commit**

Run:

    & .\.venv\Scripts\python.exe -m unittest tests.analysis.test_manifest tests.analysis.test_cli -v
    git diff --check
    git add pmca/analysis/manifest.py firmware_manifest.py tests/analysis/test_manifest.py tests/analysis/test_cli.py
    git commit -m "analysis: gate firmware artifact manifests"

Expected: all manifest and CLI tests pass.

**Reviewer gate:** No CLI argument may override allowlisted source metadata, and no artifact outside .artifacts may be recorded.

## Task 4: Build the Bounded Static Inspector

**Files:**

- Create: pmca/analysis/static.py
- Create: tests/analysis/test_static.py

**Interfaces:**

- Consumes: a regular manifest-approved pathlib.Path.
- Produces:
  - shannon_entropy(block: bytes) -> float
  - parse_pe_summary(path: pathlib.Path) -> dict | None
  - scan_entropy(path: pathlib.Path, window_size: int = 1_048_576) -> dict
  - scan_allowlisted_tokens(path: pathlib.Path, tokens: tuple[bytes, ...], max_offsets: int = 8) -> list[dict]
  - inspect_artifact(path: pathlib.Path, source_key: str) -> dict

- [ ] **Step 1: Write synthetic static-inspection tests**

Create tests/analysis/test_static.py with fixtures generated in memory. Cover:

- empty input entropy equals 0.0;
- 256 equally distributed byte values have entropy 8.0 within six decimal places;
- MZ without a valid PE offset returns None;
- a minimal PE32 fixture reports machine, section_count, optional_header_kind, certificate_offset, certificate_size, and overlay_offset without returning raw bytes;
- a raw DAT fixture is labelled opaque-dat;
- token scanning returns token labels, counts, and at most eight offsets;
- arbitrary printable strings not in the token allowlist never appear in output; and
- a 3 MiB fixture is processed as three windows without an unbounded read.

The allowed token tuple for real sources is:

    (
        b"ILCE-6400",
        b"ILCE6400",
        b"ILCE-6700",
        b"ILCE6700",
        b"2.00",
        b"BODYDATA.DAT",
        b"Update_ILCE6400V200",
    )

- [ ] **Step 2: Run the static tests and confirm failure**

Run:

    & .\.venv\Scripts\python.exe -m unittest tests.analysis.test_static -v

Expected: FAIL because pmca.analysis.static does not exist.

- [ ] **Step 3: Implement bounded entropy and token scanning**

Read at most window_size bytes per entropy iteration. shannon_entropy uses math.log2 and returns a float rounded to six decimal places only when serializing. Token scanning carries at most max_token_length - 1 bytes between chunks so boundary-spanning hits are detected. Store only allowlisted token labels, counts, and bounded offsets.

- [ ] **Step 4: Implement strict PE metadata parsing**

Use struct.unpack_from on bounded header buffers. Require MZ, a nonnegative e_lfanew below 16 MiB, PE\0\0, a supported optional-header magic of 0x10B or 0x20B, and section-table bounds within the file size. Report numeric metadata only. Do not return section payloads, certificate bytes, arbitrary strings, or a hex preview.

If a file is not a valid supported PE, return None and allow inspect_artifact to label it opaque-dat. Invalid PE claims must not crash or be silently treated as valid.

- [ ] **Step 5: Run tests and commit**

Run:

    & .\.venv\Scripts\python.exe -m unittest tests.analysis.test_static -v
    git diff --check
    git add pmca/analysis/static.py tests/analysis/test_static.py
    git commit -m "analysis: add bounded firmware metadata scanner"

Expected: all static-inspection tests pass.

**Reviewer gate:** Search static.py for read() calls. Every call must include an explicit maximum size except the one-byte EOF probe in a loop.

## Task 5: Add Deterministic, Immutable Report Generation

**Files:**

- Create: pmca/analysis/report.py
- Create: firmware_inspect.py
- Create: tests/analysis/test_report.py
- Modify: tests/analysis/test_cli.py

**Interfaces:**

- Consumes: manifest entry, verified artifact path, artifacts root, report path.
- Produces:
  - analyze_verified_artifact(entry: dict, artifact: pathlib.Path, artifacts_root: pathlib.Path) -> dict
  - write_report(path: pathlib.Path, report: dict, artifacts_root: pathlib.Path) -> None

- [ ] **Step 1: Write deterministic and immutable report tests**

Create tests/analysis/test_report.py. Patch inspect_artifact with deterministic metadata and assert:

- verify_manifest_entry runs before inspection;
- the artifact SHA-256 is identical before and after inspection;
- a changed file raises ReportError;
- two calls return equal dictionaries;
- JSON output is byte-for-byte deterministic;
- output below artifacts_root/sony-firmware is rejected;
- output below artifacts_root/analysis-runs is permitted for ignored repeatability checks;
- output containing keys named raw, bytes, payload, base64, hex_dump, or strings is rejected recursively; and
- reports contain schema_version, source_key, filename, size, sha256, format, pe, entropy, and token_hits only.

- [ ] **Step 2: Run tests and confirm failure**

Run:

    & .\.venv\Scripts\python.exe -m unittest tests.analysis.test_report -v

Expected: FAIL because pmca.analysis.report does not exist.

- [ ] **Step 3: Implement report safety and atomic writes**

analyze_verified_artifact records the input digest, verifies the manifest, calls inspect_artifact, hashes the input again, and raises ReportError if the digest changed. Validate the recursive output-key denylist before returning.

write_report requires a .json suffix, rejects paths below artifacts_root/sony-firmware, permits ignored temporary outputs below artifacts_root/analysis-runs, creates the parent directory, writes stable UTF-8 JSON to a temporary sibling, fsyncs it, and replaces the target with os.replace. Any other output must resolve outside artifacts_root.

- [ ] **Step 4: Add the inspection CLI**

Create firmware_inspect.py with one command:

    firmware_inspect.py inspect --source SOURCE --file FILE --artifacts-root ROOT --manifest MANIFEST --report REPORT

It loads exactly one source entry from the manifest, verifies the artifact, writes the report, and prints only source key, size, SHA-256, format label, and report path. It has no USB, driver, camera, patch, extract, decrypt, output-bytes, or arbitrary-token argument.

Extend tests/analysis/test_cli.py to verify the exact surface and clean one-line failures without tracebacks for expected validation errors.

- [ ] **Step 5: Run tests and commit**

Run:

    & .\.venv\Scripts\python.exe -m unittest tests.analysis.test_report tests.analysis.test_cli -v
    git diff --check
    git add pmca/analysis/report.py firmware_inspect.py tests/analysis/test_report.py tests/analysis/test_cli.py
    git commit -m "analysis: generate immutable metadata reports"

Expected: report and CLI tests pass.

**Reviewer gate:** A report must be sufficient to compare format and entropy evidence but incapable of reconstructing any firmware region.

## Task 6: Acquire and Register the Two Official Packages

**Files:**

- Create: analysis/firmware-manifest.json
- Never stage: .artifacts/sony-firmware/a6400-tw-v2.00/Update_ILCE6400V200.exe
- Never stage: .artifacts/sony-firmware/a6700-tw-v2.00/BODYDATA.DAT

**Interfaces:**

- Consumes: official Sony Taiwan pages and firmware_manifest.py.
- Produces: committed provenance and locally measured integrity metadata for two ignored artifacts.

- [ ] **Step 1: Confirm the camera is disconnected and artifact paths are ignored**

Ask the operator to confirm the α6400 is disconnected. Then run:

    New-Item -ItemType Directory -Force .artifacts\sony-firmware\a6400-tw-v2.00 | Out-Null
    New-Item -ItemType Directory -Force .artifacts\sony-firmware\a6700-tw-v2.00 | Out-Null
    git check-ignore -v .artifacts\sony-firmware\a6400-tw-v2.00\Update_ILCE6400V200.exe
    git check-ignore -v .artifacts\sony-firmware\a6700-tw-v2.00\BODYDATA.DAT

Expected: both paths match /.artifacts/. If either does not, stop before download.

- [ ] **Step 2: Download α6400 2.00 through Sony Taiwan**

Open only:

    https://www.sony.com.tw/zh/electronics/support/e-mount-body-ilce-6000-series/ilce-6400/downloads/00016145

Accept Sony's download terms in the browser and save Update_ILCE6400V200.exe directly to:

    .artifacts\sony-firmware\a6400-tw-v2.00\Update_ILCE6400V200.exe

Do not launch the updater. Expected size: 314,230,712 bytes.

- [ ] **Step 3: Download α6700 2.00 through Sony Taiwan**

Open only:

    https://www.sony.com.tw/zh/electronics/support/e-mount-body-ilce-6000-series/ilce-6700/software/00298440

Accept Sony's download terms in the browser and save BODYDATA.DAT directly to:

    .artifacts\sony-firmware\a6700-tw-v2.00\BODYDATA.DAT

Do not copy it to a memory card. Expected size: 1,024,017,848 bytes.

- [ ] **Step 4: Record both entries**

Generate one UTC acquisition timestamp and use it for the two commands:

    $acquiredAt = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    & .\.venv\Scripts\python.exe .\firmware_manifest.py add --source a6400-tw-v2.00 --file .artifacts\sony-firmware\a6400-tw-v2.00\Update_ILCE6400V200.exe --artifacts-root .artifacts --manifest analysis\firmware-manifest.json --acquired-at $acquiredAt
    & .\.venv\Scripts\python.exe .\firmware_manifest.py add --source a6700-tw-v2.00 --file .artifacts\sony-firmware\a6700-tw-v2.00\BODYDATA.DAT --artifacts-root .artifacts --manifest analysis\firmware-manifest.json --acquired-at $acquiredAt

Expected: two entries with exact filenames, sizes, official page URLs, and locally computed SHA-256 digests.

- [ ] **Step 5: Verify quarantine and manifest**

Run:

    & .\.venv\Scripts\python.exe .\firmware_manifest.py verify --file .artifacts\sony-firmware\a6400-tw-v2.00\Update_ILCE6400V200.exe --artifacts-root .artifacts --manifest analysis\firmware-manifest.json
    & .\.venv\Scripts\python.exe .\firmware_manifest.py verify --file .artifacts\sony-firmware\a6700-tw-v2.00\BODYDATA.DAT --artifacts-root .artifacts --manifest analysis\firmware-manifest.json
    git status --short --ignored
    git ls-files .artifacts

Expected: both verify; .artifacts is ignored; git ls-files .artifacts prints nothing.

- [ ] **Step 6: Commit metadata only**

Run:

    git add analysis/firmware-manifest.json
    git diff --cached --check
    git commit -m "analysis: record official firmware provenance"

Expected: the commit contains one small JSON manifest and no firmware.

**Reviewer gate:** Inspect git show --stat --oneline HEAD. Reject the commit if it contains a binary, a file under .artifacts, or an unexpectedly large file.

## Task 7: Produce Reproducible Real-Package Metadata Reports

**Files:**

- Create: analysis/reports/a6400-tw-v2.00.json
- Create: analysis/reports/a6700-tw-v2.00.json
- Create: tests/analysis/test_real_reports.py

**Interfaces:**

- Consumes: verified manifest entries and ignored official packages.
- Produces: two deterministic, bounded, metadata-only reports.

- [ ] **Step 1: Write the committed-report validation test**

Create tests/analysis/test_real_reports.py to load both JSON files and assert:

- schema_version equals 1;
- source_key matches the filename;
- measured size and SHA-256 match analysis/firmware-manifest.json;
- allowed top-level keys are exact;
- no recursively denied output key exists;
- serialized report size is below 128 KiB;
- token labels are from the fixed allowlist; and
- no string value exceeds 512 characters.

The test must open the two exact committed report paths and fail when they do not exist.

- [ ] **Step 2: Run the report test and confirm the files are missing**

Run:

    & .\.venv\Scripts\python.exe -m unittest tests.analysis.test_real_reports -v

Expected: FAIL with FileNotFoundError for the first report. This proves the test is exercising the real committed paths.

- [ ] **Step 3: Run each analysis twice into ignored temporary reports**

Run:

    New-Item -ItemType Directory -Force .artifacts\analysis-runs | Out-Null
    & .\.venv\Scripts\python.exe .\firmware_inspect.py inspect --source a6400-tw-v2.00 --file .artifacts\sony-firmware\a6400-tw-v2.00\Update_ILCE6400V200.exe --artifacts-root .artifacts --manifest analysis\firmware-manifest.json --report .artifacts\analysis-runs\a6400-run1.json
    & .\.venv\Scripts\python.exe .\firmware_inspect.py inspect --source a6400-tw-v2.00 --file .artifacts\sony-firmware\a6400-tw-v2.00\Update_ILCE6400V200.exe --artifacts-root .artifacts --manifest analysis\firmware-manifest.json --report .artifacts\analysis-runs\a6400-run2.json
    & .\.venv\Scripts\python.exe .\firmware_inspect.py inspect --source a6700-tw-v2.00 --file .artifacts\sony-firmware\a6700-tw-v2.00\BODYDATA.DAT --artifacts-root .artifacts --manifest analysis\firmware-manifest.json --report .artifacts\analysis-runs\a6700-run1.json
    & .\.venv\Scripts\python.exe .\firmware_inspect.py inspect --source a6700-tw-v2.00 --file .artifacts\sony-firmware\a6700-tw-v2.00\BODYDATA.DAT --artifacts-root .artifacts --manifest analysis\firmware-manifest.json --report .artifacts\analysis-runs\a6700-run2.json

- [ ] **Step 4: Prove determinism and create the committed reports through the CLI**

Run:

    if ((Get-FileHash .artifacts\analysis-runs\a6400-run1.json -Algorithm SHA256).Hash -ne (Get-FileHash .artifacts\analysis-runs\a6400-run2.json -Algorithm SHA256).Hash) { throw 'α6400 report is nondeterministic' }
    if ((Get-FileHash .artifacts\analysis-runs\a6700-run1.json -Algorithm SHA256).Hash -ne (Get-FileHash .artifacts\analysis-runs\a6700-run2.json -Algorithm SHA256).Hash) { throw 'α6700 report is nondeterministic' }
    & .\.venv\Scripts\python.exe .\firmware_inspect.py inspect --source a6400-tw-v2.00 --file .artifacts\sony-firmware\a6400-tw-v2.00\Update_ILCE6400V200.exe --artifacts-root .artifacts --manifest analysis\firmware-manifest.json --report analysis\reports\a6400-tw-v2.00.json
    & .\.venv\Scripts\python.exe .\firmware_inspect.py inspect --source a6700-tw-v2.00 --file .artifacts\sony-firmware\a6700-tw-v2.00\BODYDATA.DAT --artifacts-root .artifacts --manifest analysis\firmware-manifest.json --report analysis\reports\a6700-tw-v2.00.json

- [ ] **Step 5: Run the real-report test**

    & .\.venv\Scripts\python.exe -m unittest tests.analysis.test_real_reports -v

Expected: both reports pass all size, schema, digest, and content restrictions.

- [ ] **Step 6: Commit bounded reports**

Run:

    git add analysis/reports/a6400-tw-v2.00.json analysis/reports/a6700-tw-v2.00.json tests/analysis/test_real_reports.py
    git diff --cached --check
    git commit -m "analysis: compare official firmware metadata"

Expected: the reports are each below 128 KiB and contain no raw firmware content.

**Reviewer gate:** Manually inspect both JSON files. Unknown or opaque structure must remain labelled unknown or opaque; do not infer a signature boundary from entropy alone.

## Task 8: Implement Evidence Validation and Decision Rendering

**Files:**

- Create: pmca/analysis/decisions.py
- Create: firmware_decisions.py
- Create: tests/analysis/test_decisions.py
- Modify: tests/analysis/test_cli.py

**Interfaces:**

- Consumes: analysis/feature-evidence.json.
- Produces:
  - validate_evidence(document: dict) -> dict
  - render_markdown(document: dict) -> str

- [ ] **Step 1: Write decision-schema tests**

Create tests/analysis/test_decisions.py. Define the required capability IDs:

    REQUIRED_CAPABILITIES = (
        "creative-look-discovery",
        "creative-look-emulation",
        "touch-menu",
        "vertical-ui",
        "signature-enforcement",
        "hardware-dependencies",
        "recovery",
    )

Test that validate_evidence requires exactly these IDs; one of FEASIBLE, PARTIAL, BLOCKED, or INSUFFICIENT_EVIDENCE; a nonempty summary; at least one evidence item; and an explicit next_action.

Each evidence item must be:

    {
        "kind": "OBSERVATION" or "INFERENCE",
        "source": a nonempty official URL or committed report path,
        "claim": a nonempty statement,
    }

Test rejection of unknown statuses, missing capabilities, duplicate capabilities, unsupported kinds, empty claims, and an INFERENCE presented without at least one OBSERVATION in the same capability.

- [ ] **Step 2: Run tests and confirm failure**

Run:

    & .\.venv\Scripts\python.exe -m unittest tests.analysis.test_decisions -v

Expected: FAIL because pmca.analysis.decisions does not exist.

- [ ] **Step 3: Implement validation and deterministic rendering**

Implement DecisionError(ValueError). validate_evidence returns a normalized deep copy ordered by REQUIRED_CAPABILITIES. render_markdown produces:

- title and generation source;
- one section per capability in the required order;
- status, summary, evidence list with visible OBSERVATION or INFERENCE labels; and
- next permitted action.

The renderer must not add a conclusion absent from the evidence JSON.

- [ ] **Step 4: Add the decision CLI**

Create firmware_decisions.py with:

    firmware_decisions.py render --evidence analysis\feature-evidence.json --output analysis\a6400-feasibility-report.md

The CLI accepts no camera, package, patch, executable, shell, URL, or status override. Extend test_cli.py to verify only render is available.

- [ ] **Step 5: Run tests and commit**

Run:

    & .\.venv\Scripts\python.exe -m unittest tests.analysis.test_decisions tests.analysis.test_cli -v
    git diff --check
    git add pmca/analysis/decisions.py firmware_decisions.py tests/analysis/test_decisions.py tests/analysis/test_cli.py
    git commit -m "analysis: validate firmware feasibility decisions"

Expected: decision and CLI tests pass.

**Reviewer gate:** Every inference must remain visibly labelled in both JSON and Markdown.

## Task 9: Build the Evidence Matrix and Final Feasibility Report

**Files:**

- Create: analysis/feature-evidence.json
- Create: analysis/a6400-feasibility-report.md

**Interfaces:**

- Consumes: official Sony Help Guide URLs, approved specification, two metadata reports, and repository architecture evidence.
- Produces: one validated decision for every required capability.

- [ ] **Step 1: Record official feature observations**

Create analysis/feature-evidence.json with schema_version 1 and all seven capability IDs. Cite these official sources where relevant:

    https://www.sony.com.tw/zh/electronics/support/e-mount-body-ilce-6000-series/ilce-6400/downloads/00016145
    https://www.sony.com.tw/zh/electronics/support/e-mount-body-ilce-6000-series/ilce-6700/software/00298440
    https://helpguide.sony.net/ilc/2320/v1/en/contents/0411B_creative_look.html
    https://helpguide.sony.net/ilc/2320/v1/en/contents/211h_touchpanel_settings.html
    https://helpguide.sony.net/ilc/2320/v1/en/contents/221h_touch_function_icon.html

Use committed report paths as sources for package observations. Label every architectural interpretation as INFERENCE.

- [ ] **Step 2: Assign evidence-bounded statuses**

For each capability, choose only the strongest status supported by observations:

- FEASIBLE only when a compatible, bounded interface and safe implementation path are demonstrated;
- PARTIAL when an agreed useful subset is supported;
- BLOCKED when a specific signature, hardware, or recovery constraint is demonstrated; or
- INSUFFICIENT_EVIDENCE when the package metadata cannot establish compatibility.

Do not upgrade a status because a feature exists on α6700. Existence on the donor is evidence of the target behavior, not compatibility with α6400.

- [ ] **Step 3: Validate and render**

Run:

    & .\.venv\Scripts\python.exe .\firmware_decisions.py render --evidence analysis\feature-evidence.json --output analysis\a6400-feasibility-report.md
    & .\.venv\Scripts\python.exe -m unittest tests.analysis.test_decisions tests.analysis.test_real_reports -v

Expected: validation passes and the Markdown contains seven ordered capability sections.

- [ ] **Step 4: Perform an evidence review**

For every Markdown claim, locate its matching JSON evidence item. Confirm that:

- observations state only what the cited source or report directly shows;
- inferences are labelled;
- lack of plaintext is not called proof of feature absence;
- entropy is not called proof of encryption;
- an identified signature region is not called a bypass; and
- no status authorizes camera access.

- [ ] **Step 5: Commit the evidence and report**

Run:

    git add analysis/feature-evidence.json analysis/a6400-feasibility-report.md
    git diff --cached --check
    git commit -m "docs: report a6400 firmware feasibility"

Expected: the commit contains human-readable evidence and no firmware bytes.

**Reviewer gate:** The report may recommend a separate Creative Look design, but it must not contain camera-execution steps.

## Task 10: Run the Full Offline Safety and Reproducibility Gate

**Files:**

- Verify all files created or modified in Tasks 2–9.

**Interfaces:**

- Consumes: complete offline analysis branch.
- Produces: verified branch ready for integration and a camera-safe research conclusion.

- [ ] **Step 1: Read the required verification and review skills**

Invoke superpowers:verification-before-completion and superpowers:requesting-code-review.

- [ ] **Step 2: Run the full unit suite**

Run:

    & .\.venv\Scripts\python.exe -m unittest discover -s tests\safe -p 'test_*.py' -v
    & .\.venv\Scripts\python.exe -m unittest discover -s tests\analysis -p 'test_*.py' -v
    & .\.venv\Scripts\python.exe -m compileall -q pmca firmware_manifest.py firmware_inspect.py firmware_decisions.py tests

Expected: all existing 58 safe tests and every analysis test pass; compileall exits 0.

- [ ] **Step 3: Verify both real artifacts and regenerate reports**

Run the two firmware_manifest.py verify commands from Task 6. Regenerate both committed JSON reports to ignored temporary paths and require their SHA-256 values to match the committed reports.

Expected: input hashes match the manifest and generated reports are byte-for-byte deterministic.

- [ ] **Step 4: Scan for forbidden runtime reachability**

Run:

    rg -n "pmca\.(usb|commands|shell|safe)|CameraShell|senser|service.?mode|updater.?mode|writeFirmware|writeFile|writeMemory|writeBackup|setTerminal|Zadig|WinUSB" pmca\analysis firmware_manifest.py firmware_inspect.py firmware_decisions.py

Expected: zero matches. Test names and design documentation are outside this runtime-only scan.

- [ ] **Step 5: Prove no proprietary artifacts are tracked**

Run:

    git check-ignore -v .artifacts\sony-firmware\a6400-tw-v2.00\Update_ILCE6400V200.exe
    git check-ignore -v .artifacts\sony-firmware\a6700-tw-v2.00\BODYDATA.DAT
    git ls-files .artifacts
    $changed = @(git diff --name-only master...HEAD)
    $changed | ForEach-Object { Get-Item -LiteralPath $_ } | Where-Object { -not $_.PSIsContainer -and $_.Length -gt 1048576 } | Select-Object FullName,Length
    $changed | Where-Object { $_ -match '\.(exe|dat|bin|img|fw|elf|so|squashfs)$' }

Expected: both binaries are ignored; git ls-files .artifacts prints nothing; no new tracked file exceeds 1 MiB; no tracked firmware-like extension is present.

- [ ] **Step 6: Verify repository and report consistency**

Run:

    git diff --check
    git status --short --branch
    & .\.venv\Scripts\python.exe .\firmware_decisions.py render --evidence analysis\feature-evidence.json --output .artifacts\analysis-runs\final-report.md
    if ((Get-FileHash analysis\a6400-feasibility-report.md -Algorithm SHA256).Hash -ne (Get-FileHash .artifacts\analysis-runs\final-report.md -Algorithm SHA256).Hash) { throw 'Decision report is nondeterministic' }

Expected: clean feature branch and identical report hashes.

- [ ] **Step 7: Perform inline safety review**

Review the complete branch diff against the approved specification. Reject:

- any camera interaction;
- any artifact downloader accepting arbitrary URLs;
- any raw-byte or arbitrary-string report output;
- any unlabelled inference;
- any claim that the donor firmware can be installed on α6400; and
- any next action that bypasses the separate design and recovery gate.

Fix every finding in a focused commit, then repeat Steps 2–7.

- [ ] **Step 8: State the result and finish the branch**

Report the seven capability statuses exactly as rendered. Explicitly state that the α6400 remained disconnected. Invoke superpowers:finishing-a-development-branch and let the user choose local merge, push/PR, or preserving the branch.

**Final gate:** End this plan after the offline report. Creative Look implementation and any UI work require their own approved designs based on the resulting evidence.
