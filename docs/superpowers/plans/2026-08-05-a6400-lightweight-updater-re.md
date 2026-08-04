# α6400 Lightweight Updater Reverse-Engineering Implementation Plan

> **For Codex:** Execute this plan in the existing
> `C:\Users\Bubble\ChatGPT\Sony\Sony-PMCA-RE-a6400-analysis` worktree on
> `feature/a6400-updater-re-lab`. Keep every camera disconnected.

**Goal:** Build a reproducible static and sandboxed dynamic analysis path for the
official α6400 2.00 Windows updater without a persistent virtual machine.

**Architecture:** Portable tools authenticate and inspect ignored firmware copies.
A dedicated Sandboxie box is validated with a synthetic probe before it may launch
the official updater. The updater receives no elevation, network, camera, or direct
host-write access. Observations and inferences remain separate.

**Tech stack:** Python 3, unittest, PowerShell, Ghidra/JDK, x64dbg, Sysinternals
signature utilities where useful, Sandboxie Plus 1.18.1, Git.

---

## Task 1: Record Host and Tool Provenance

**Files:**

- Modify: `analysis/tool-provenance.json`
- Create: `analysis/host-isolation-provenance.json`
- Create: `tests/analysis/test_host_isolation_provenance.py`

1. Write a failing schema test requiring bounded version, source, SHA-256,
   Authenticode, installation-path category, and purpose fields.
2. Add the verified Sandboxie package, service, driver, restore-point result, and
   host-storage ceiling without committing the local log or absolute usernames.
3. Download portable tools only from their official release sources into ignored
   `.artifacts/tools/` directories, then record exact versions and digests.
4. Run the focused test, `git diff --check`, and commit metadata only.

## Task 2: Implement the Sandbox Policy Contract

**Files:**

- Create: `pmca/analysis/sandbox_policy.py`
- Create: `sandbox_policy.py`
- Create: `tests/analysis/test_sandbox_policy.py`
- Create locally only: `.artifacts/sandbox/a6400-updater/Sandboxie.ini`

1. Write failing tests for an exact policy: dropped administrator rights, denied
   network/device access, no writable host mapping, fixed process allowlist, and
   bounded trace/output paths.
2. Implement deterministic policy rendering and validation. Reject permissive or
   unknown settings rather than silently defaulting.
3. Render the local Sandboxie configuration and validate it before loading it.
4. Commit only source and tests; keep machine-specific configuration ignored.

## Task 3: Validate Containment with a Synthetic Probe

**Files:**

- Create: `analysis/fixtures/sandbox_probe.ps1`
- Create: `pmca/analysis/sandbox_probe.py`
- Create: `tests/analysis/test_sandbox_probe.py`

1. Write tests for a synthetic probe that attempts only harmless temporary-file,
   registry, network, device-listing, child-process, and elevation checks.
2. Run it outside the sandbox against disposable paths to prove the result parser.
3. Run it inside the dedicated box and require denial/virtualization for every
   protected capability.
4. Reset the box and repeat; reports must be deterministic and contain no host
   secrets or broad environment dumps.

## Task 4: Extend Static α6400 Updater Characterization

**Files:**

- Create: `pmca/analysis/updater_pe.py`
- Create: `firmware_updater.py`
- Create: `tests/analysis/test_updater_pe.py`
- Create: `analysis/reports/a6400-updater-static.json`

1. Write synthetic PE tests for imports, resources, certificates, overlays,
   embedded executable candidates, and signed/excluded byte ranges.
2. Implement bounded parsers that emit offsets, lengths, hashes, and allowlisted
   identifiers, never raw firmware bytes.
3. Reverify the official updater digest before and after inspection.
4. Compare repository results with Ghidra/x64dbg metadata and document only
   corroborated observations.

## Task 5: Run the Official Updater to the No-Camera Boundary

**Files:**

- Create: `pmca/analysis/updater_trace.py`
- Create: `tests/analysis/test_updater_trace.py`
- Create: `analysis/reports/a6400-updater-no-camera.json`

1. Write tests for a bounded trace normalizer using synthetic event fixtures.
2. Revalidate the Sandboxie policy and empty-box state.
3. Confirm through Windows device enumeration that no Sony camera is present.
4. Launch the verified updater in the sandbox without elevation or network.
5. Record process, file, registry, device-open, and termination events only through
   normalized hashes and allowlisted API/category names.
6. Repeat from a clean box and require the same no-camera boundary.

## Task 6: Build a User-Mode Transport Harness

**Files:**

- Create: `pmca/analysis/updater_transport.py`
- Create: `tests/analysis/test_updater_transport.py`
- Create: `analysis/updater-transport-observations.json`

1. Derive the smallest observed device/API boundary from Task 5; do not guess a
   protocol or install a USB driver.
2. Write synthetic request/response contract tests with strict length, ordering,
   timeout, and model-identity validation.
3. Implement a user-mode harness that can replay only explicitly recorded synthetic
   responses and cannot enumerate or open physical USB devices.
4. Use the harness only inside the sandbox. Unexpected commands terminate the run
   and become new observations for a later fixture revision.

## Task 7: Map Wrapper, Decryption, Model, and Signature Gates

**Files:**

- Create: `analysis/a6400-updater-gates.json`
- Create: `analysis/a6400-updater-re-report.md`
- Create: `tests/analysis/test_updater_gate_report.py`

1. Record host-wrapper, transport, camera-updater, boot, and runtime-integrity gates
   as separate layers.
2. Label each claim `OBSERVATION`, `INFERENCE`, or `UNRESOLVED` with provenance.
3. Continue alternate offline hypotheses when one parser/decryption path fails;
   never promote ambiguous bytes to a key, signature boundary, or patch.
4. Identify the next static or emulated experiment for each unresolved gate and
   relate evidence to vertical UI, full touch UI, and all Creative Looks.

## Task 8: Verify, Commit, Push, and Coordinate Any Reboot

1. Run all safe and analysis tests, compile checks, firmware digest verification,
   deterministic-report checks, and forbidden-artifact scans.
2. Inspect the complete branch diff for raw Sony bytes, secrets, device identifiers,
   executable artifacts, and host-specific paths.
3. Commit focused changes and push `feature/a6400-updater-re-lab`.
4. Before any restart, use the Codex task API to verify every other local task is
   finished, stop analysis processes, checkpoint Git state, and record the exact
   continuation command. If another task remains active, defer restart.
5. Do not connect or write to the α6400. A physical-camera phase requires its own
   recovery-backed design and explicit approval.
