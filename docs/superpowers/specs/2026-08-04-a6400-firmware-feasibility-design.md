# Sony α6400 Firmware Feasibility Study Design

## Status

Approved design for an offline, read-only feasibility study. This document does not
authorize connecting the α6400, changing its Windows driver, entering service or
updater mode, modifying settings, or writing firmware.

## Objective

Determine whether an original Taiwan-region ILCE-6400 running firmware 2.00 can
safely gain either of these outcomes:

1. close visual equivalents of all ten α6700 Creative Looks, selectable through the
   camera's existing LCD controls after setup; and
2. the newer touch-controllable and vertical-orientation user interface.

The study must produce evidence-backed feasibility decisions without interacting
with the user's α6400. A partial Creative Look result is worthwhile even if the new
UI is infeasible. Creative Look behavior only needs to affect JPEGs, video, and RAW
previews; it does not need to alter underlying RAW sensor data. A close visual match
is acceptable when exact α6700 colorimetry cannot be verified without an α6700 body.

## Context and Hard Constraints

- The α6400 is the user's only dependable camera and remains disconnected for this
  entire study.
- Sony Taiwan publishes firmware 2.00 as the current ILCE-6400 firmware.
- Sony's α6700 implements the requested Creative Look and touch-interface features,
  but its firmware is a comparison source only and must never be flashed to the
  α6400.
- Sony-PMCA-RE identifies the α6400-class signed firmware architecture as
  incompatible with its older custom-updater execution path.
- No signature bypass or camera experiment is allowed without a separately proven,
  model-specific recovery method.
- Sony firmware binaries and extracted proprietary content must not be committed or
  redistributed.

## Trusted Sources

### Firmware and Feature Sources

- Sony Taiwan ILCE-6400 firmware 2.00:
  <https://www.sony.com.tw/zh/electronics/support/e-mount-body-ilce-6000-series/ilce-6400/downloads/00016145>
- Sony Taiwan ILCE-6700 firmware 2.00:
  <https://www.sony.com.tw/zh/electronics/support/e-mount-body-ilce-6000-series/ilce-6700/software/00298440>
- Sony α6700 Creative Look help:
  <https://helpguide.sony.net/ilc/2320/v1/en/contents/0411B_creative_look.html>
- Sony α6700 touch-panel settings:
  <https://helpguide.sony.net/ilc/2320/v1/en/contents/211h_touchpanel_settings.html>
- Sony α6700 touch-function icons:
  <https://helpguide.sony.net/ilc/2320/v1/en/contents/221h_touch_function_icon.html>

Third-party research may identify hypotheses or tooling, but it cannot replace an
official firmware source, establish a package's authenticity, or authorize a camera
operation.

### Code Sources

- Development repository: <https://github.com/bubbleee030/Sony-PMCA-RE>
- Historical upstream: <https://github.com/ma1co/Sony-PMCA-RE>
- Local main checkout:
  `C:\Users\Bubble\ChatGPT\Sony\Sony-PMCA-RE`
- Preserved rehearsal worktree:
  `C:\Users\Bubble\ChatGPT\Sony\Sony-PMCA-RE-nex-c3-safe`

The standalone development repository is `origin`. The historical project remains
available as `upstream` for attribution and comparison.

## Considered Approaches

### Parameter-Only Creative Look Emulation

Map the ten α6700 looks (`ST`, `PT`, `NT`, `VV`, `VV2`, `FL`, `IN`, `SH`, `BW`, and
`SE`) onto existing α6400 Creative Style or Picture Profile slots. This is the safest
and most likely useful outcome because selection remains on the camera's LCD. It does
not provide the new menu framework and may not permit friendly custom names.

### Offline Firmware Comparison

Compare official α6400 and α6700 packages to identify container structure,
signatures, processor architecture, model gates, partitions, resources, UI code,
touch-event handling, color tables, and hardware dependencies. This provides the
evidence needed to decide whether either requested feature can cross the model
boundary.

### Direct Cross-Model Firmware or UI Transplant

Directly installing the α6700 package is rejected. The models have different image
processors, sensors, controls, and signed firmware. A component-level UI experiment
also remains prohibited unless later evidence establishes a compatible boundary and
a verified α6400 recovery path.

## Selected Strategy

Use a staged combination:

1. perform the offline firmware comparison;
2. pursue parameter-level Creative Look emulation when supported by evidence;
3. evaluate the new UI independently; and
4. stop the UI track if it requires an unrecoverable signature bypass or incompatible
   hardware.

An optional third firmware may be introduced as a bridge donor only when the α6400
and α6700 comparison cannot distinguish a feature from an architecture change. Its
model, purpose, and official source must be approved and added to the manifest before
download.

## Architecture

### Firmware Corpus

Official packages are stored below a repository-local, Git-ignored
`.artifacts/sony-firmware/` directory. The implementation plan must add the entire
directory to `.gitignore` before any package is downloaded.

A committed text manifest records, for every package:

- manufacturer and model;
- region and official source URL;
- advertised firmware version and release date;
- downloaded filename and exact byte size;
- SHA-256 digest; and
- acquisition timestamp.

The manifest contains metadata only, never firmware bytes or extracted proprietary
content.

### Static Package Inspector

Purpose-specific read-only tools inspect copies of the official packages. They may
report:

- container boundaries and file signatures;
- compression or encryption indicators;
- entropy and section maps;
- processor and executable-format evidence;
- model, version, and partition identifiers;
- printable strings and resource indexes; and
- cryptographic signature regions and signed-data boundaries when identifiable.

The inspector accepts input paths and a report destination only. It has no camera,
USB, driver, service-mode, updater-mode, or firmware-write dependency. It never
patches or overwrites an input package.

### Feature Mapper

The mapper connects official feature definitions to package evidence in five areas:

1. Creative Look tone, color, and sharpness parameters;
2. corresponding α6400 Creative Style and Picture Profile controls;
3. menu rendering and touch-event handling;
4. orientation detection and vertical layouts; and
5. image-processor, display-controller, and other hardware dependencies.

Absence of a readable string is not evidence that a feature is absent. Conclusions
must distinguish observed facts from inferences.

### Decision Report

Each requested capability receives exactly one status:

- `FEASIBLE`: evidence supports a safe implementation using compatible interfaces;
- `PARTIAL`: a useful subset can be delivered within the agreed behavior;
- `BLOCKED`: a known signature, hardware, or recovery constraint prevents work; or
- `INSUFFICIENT EVIDENCE`: the available packages cannot support a conclusion.

Each status includes its evidence, uncertainty, and the next permitted action.

## Data Flow

1. Download from the exact approved Sony URL into the ignored artifact directory.
2. Record file metadata and SHA-256 before parsing.
3. Verify the advertised model, version, filename, and size against Sony's page.
4. Copy the package to an analysis-only input location under the ignored directory.
5. Run static inspectors against the copy.
6. Commit only reproducible metadata, tool source, tests, and human-readable reports.
7. Map evidence to the two feature tracks and assign decision statuses.

No data flow reaches a USB device or camera.

## Safety and Error Handling

The study fails closed on:

- a source URL outside the approved official Sony pages;
- a filename, size, model, version, or digest mismatch;
- truncated or malformed package structure;
- an unknown container treated as a known one;
- an uncertain signature boundary presented as proven;
- an analyzer attempting to modify its input;
- any runtime import of PMCA USB, service, shell, updater, driver, or firmware-write
  capabilities; or
- any Sony binary or extracted proprietary content appearing in Git's candidate
  changes.

Errors report only paths, metadata, offsets, and diagnostic summaries needed for
reproduction. Tools must not automatically try alternate decryption, patching,
camera access, or more permissive commands after an error.

Because this phase never changes the camera, its recovery action is to stop the
analyzer and preserve the original package plus recorded digest. Any later
camera-connected phase requires a new approved design and runbook with exact identity
gates and a recovery method that does not depend on the donor NEX-C3.

## Testing

Testing uses synthetic fixtures before official packages:

- valid minimal containers for each supported parser path;
- malformed, truncated, high-entropy, and unexpected inputs;
- input immutability checks using before-and-after SHA-256;
- deterministic-report tests that run each analysis twice;
- model/version mismatch tests;
- output allowlist tests for metadata and reports; and
- runtime scans forbidding USB, service-mode, driver, shell, updater, and write
  capability imports.

Real-package smoke tests operate only on ignored local copies. They verify hashes
before and after analysis and compare repeat runs for identical results. Test logs
must not embed proprietary firmware regions.

## Acceptance Criteria

The offline phase is complete only when:

- official α6400 2.00 and α6700 2.00 packages are authenticated and analyzed;
- the package manifest and all reports are reproducible;
- analyzers pass malformed-input and immutability tests;
- Git contains no Sony firmware binary or extracted proprietary content;
- runtime scans find no camera-access or write capability in the analysis path;
- the α6400 has remained disconnected and unchanged; and
- the decision report covers Creative Look discovery and emulation, touch-menu
  compatibility, vertical UI compatibility, signature enforcement, model-specific
  dependencies, and recovery availability.

The phase may conclude successfully with `BLOCKED` or `INSUFFICIENT EVIDENCE`
results. Success means the evidence and safety gates are complete, not that a feature
port is possible.

## Subsequent Gates

If Creative Look emulation is `FEASIBLE` or `PARTIAL`, it receives its own approved
design and implementation plan. It must prefer ordinary on-camera settings before
any settings write from a computer.

The UI track cannot proceed to a camera-connected experiment unless all of these are
demonstrated first:

- compatible α6400 executable and component boundaries;
- a model-specific method that preserves firmware signature requirements or a proven
  and bounded execution method;
- exact write scope and rollback behavior; and
- a verified α6400 recovery mechanism capable of handling boot failure.

Without those conditions, the UI result is `BLOCKED` and the α6400 remains
untouched.
