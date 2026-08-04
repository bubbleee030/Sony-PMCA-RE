# Sony α6400 Lightweight Updater Reverse-Engineering Design

## Status

Approved design addendum for the existing offline α6400 UI and Creative Look
research. It replaces the proposed persistent Windows virtual machine with a
static-first host lab and a restricted Sandboxie execution environment.

This design authorizes reversible host-side setup and analysis. It does not
authorize connecting a camera, installing a Sony camera/updater driver, entering
camera updater mode, or writing firmware.

## Objective

Reverse engineer the official α6400 Windows updater far enough to identify its
container handling, model gates, key derivation, decryption, signature checks, and
USB protocol without allocating a full guest operating-system image.

Unknown data, failed decryption, model mismatch, and ambiguous output stop the
affected interpretation or execution path. They do not end the research: the lab
pivots to another offline hypothesis while keeping the camera disconnected.

## Selected Isolation Model

The lab uses two tiers:

1. Static tools run against verified, read-only copies of official packages.
   Portable Ghidra, x64dbg support files, extraction tools, and repository scripts
   require no camera, driver, administrator access, or firmware execution.
2. Dynamic execution runs only inside a dedicated Sandboxie box. The box drops
   administrator rights, denies hardware and network access, exposes no writable
   host folder, and retains output inside the box until individual metadata or log
   files are reviewed and recovered.

The updater is never granted elevation. An elevation request, Sony driver install,
direct device open, or escape from the intended sandbox policy terminates that run.
The next research path is user-mode API emulation or a synthetic USB-response
harness, not relaxed containment.

## Host Preparation

- Create a Windows restore point before installing Sandboxie's host driver.
- Install Sandboxie Plus only through the verified Windows Package Manager entry.
- Verify Authenticode signatures and installed service/driver state.
- Keep Microsoft Defender enabled and create no broad exclusions.
- Prefer portable analysis tools and keep their files below the ignored lab root.
- Target 15–30 GiB of ordinary use with a 40 GiB working ceiling. Large memory
  dumps require an explicit evidence need and are deleted only after their relevant
  hashes and findings are recorded.

## Firmware and Output Boundaries

Official Sony packages, extracted components, decrypted payloads, keys, dumps, and
candidate firmware images stay below Git-ignored `.artifacts/` paths. They are not
published or committed.

Git may contain original analysis code, synthetic fixtures, tests, hashes,
provenance, bounded metadata, and human-readable findings. Before every commit, the
candidate change set is scanned for firmware-like extensions, unexpectedly large
files, secrets, device identifiers, and proprietary byte regions.

## Reboot Coordination

A reboot is allowed without another operator confirmation, but it is never issued
while another Codex task or relevant background job is active. Immediately before
reboot the lab must:

1. query the Codex task list and wait until every other active local task finishes;
2. stop analysis processes and confirm no firmware file is being transformed;
3. run the relevant tests and verify the Git worktree state;
4. commit a human-readable checkpoint containing the exact next action; and
5. record whether Windows reports a pending restart.

Because the Codex desktop app is not registered for automatic startup and an active
turn is not guaranteed to resume, a restart is deferred when continued unattended
work is possible without it.

## Dynamic-Analysis Sequence

1. Authenticate and rehash the original α6400 updater.
2. Characterize imports, resources, embedded executables, certificates, entropy,
   and wrapper boundaries without launching it.
3. Build a synthetic test executable to prove the Sandboxie restrictions and trace
   collection behavior.
4. Launch the official updater in the same box with the camera disconnected.
5. Record process creation, file and registry virtualization, attempted network and
   device access, and clean termination at the expected no-camera state.
6. Add user-mode hooks or a synthetic transport only after the observed API boundary
   is reproducible.
7. Preserve observations separately from inferences and rerun each important result
   from a clean sandbox snapshot.

## Failure and Recovery

- A sandboxed process crash is preserved as evidence and the box is reset.
- A host crash or unexpected driver behavior stops dynamic analysis until Windows,
  Sandboxie, the repository, and the firmware hashes are reverified.
- Any host file or registry write outside the intended Sandboxie paths is treated as
  a containment failure; official-updater execution does not resume under that
  policy.
- A request for physical-camera access remains a separate future design requiring a
  verified model-specific recovery method and explicit operator approval.

## Acceptance Criteria

The lightweight lab is ready when:

- the restore point and signed Sandboxie installation are verified;
- portable-tool provenance and hashes are recorded;
- the dedicated box passes negative tests for administrator, network, device, and
  writable-host access;
- the official updater reaches only a bounded, reproducible disconnected-camera
  state;
- no Sony binary or sensitive output is tracked by Git; and
- the reboot barrier can identify and wait for other active Codex tasks.

