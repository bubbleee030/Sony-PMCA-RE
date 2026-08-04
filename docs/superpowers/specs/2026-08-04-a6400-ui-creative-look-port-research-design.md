# Sony α6400 UI and Creative Look Port Research Design

## Status

Approved design for an evidence-first, offline engineering lab. The lab is intended
to push past the limitations of the historical Sony-PMCA-RE and fwtool.py code where
the available firmware evidence permits it. It does not authorize connecting a
camera, changing a camera driver, entering service or updater mode, or installing a
candidate image on the user's α6400.

Failures such as model mismatch, unknown container regions, failed decryption,
invalid signatures, and ambiguous parser output stop claims and camera execution;
they do not stop offline research. Each becomes a reverse-engineering branch.

## Objective

Find and develop as much of a technically credible path as possible for an original
Taiwan-region ILCE-6400 running firmware 2.00 to gain:

1. a user interface that rotates for portrait orientation;
2. touch control of menus and on-screen camera controls; and
3. all ten modern Sony Creative Looks (`ST`, `PT`, `NT`, `VV`, `VV2`, `FL`, `IN`,
   `SH`, `BW`, and `SE`).

The preferred result is a native α6400-compatible implementation. If a direct port
is not possible, the lab will pursue an α6400-specific reimplementation. If firmware
implementation remains blocked, it will provide the closest evidence-backed
Creative Style and white-balance recipes that the α6400 can select on-camera.

The work is not complete merely because an existing tool reports that the model is
unsupported. That message is an input to the research, not its conclusion.

## Current Evidence and Donor Choice

- The α6400 firmware corpus contains Sony Taiwan firmware 2.00 as a Windows updater.
- The α6700 corpus contains Sony firmware 2.00 as `BODYDATA.DAT` and remains useful
  for Creative Look and modern touch-menu comparison.
- The α6700 documentation does not establish Sony's true rotating information UI.
- Sony's ILCE-7M5 (α7 V) documentation explicitly describes **Vertical Display**:
  monitor and viewfinder information rotate, control directions rotate, and side
  touch icons are repositioned.
- Sony Taiwan ILCE-7M5 firmware 2.00 is therefore the approved vertical-UI donor.
- Sony-PMCA-RE identifies the α6400-class `CXD90045` architecture as using signed
  firmware outside its historical custom-updater support.
- Reports of service-shell or language-setting changes on newer cameras demonstrate
  settings access, not arbitrary firmware execution. The two mechanisms must remain
  separate in the evidence model.

### Primary Sources

- Sony Taiwan ILCE-6400 firmware 2.00:
  <https://www.sony.com.tw/zh/electronics/support/e-mount-body-ilce-6000-series/ilce-6400/downloads/00016145>
- Sony Taiwan ILCE-6700 firmware 2.00:
  <https://www.sony.com.tw/zh/electronics/support/e-mount-body-ilce-6000-series/ilce-6700/software/00298440>
- Sony Taiwan ILCE-7M5 firmware 2.00:
  <https://www.sony.com.tw/zh/electronics/support/e-mount-body-ilce-7-series/ilce-7m5/software/00377086>
- Sony ILCE-7M5 Vertical Display help:
  <https://helpguide.sony.net/ilc/2540/v1/en/contents/251h_vertical_ui_display.html>
- Sony α6700 Creative Look help:
  <https://helpguide.sony.net/ilc/2320/v1/en/contents/0411B_creative_look.html>
- Sony Creative Look portal:
  <https://electronics.sony.com/creativelook>
- Sony α6700 menu and touch operation help:
  <https://helpguide.sony.net/ilc/2320/v1/en/contents/0201B_using_menu.html>
- Sony α6400 Creative Style help:
  <https://helpguide.sony.net/ilc/1810/v1/en/contents/TP0002264693.html>
- Sony α6400 touch-operation help:
  <https://helpguide.sony.net/ilc/1810/v1/en/contents/TP0002273547.html>
- Sony-PMCA-RE compatibility statement:
  <https://github.com/ma1co/Sony-PMCA-RE#readme>
- fwtool.py device definitions:
  <https://github.com/ma1co/fwtool.py/blob/master/devices.yml>
- fwtool.py new-format parsing issue:
  <https://github.com/ma1co/fwtool.py/issues/45>
- Sony Film Simulations community recipe catalog (experimental source):
  <https://sonyfilmsimulations.com/en/>

Third-party recipes and reverse-engineering discussions may establish hypotheses or
test vectors. They cannot establish official colorimetry, firmware authenticity, or
camera safety by themselves.

## Considered Approaches

### Existing-Tool-Only Study

Run Sony-PMCA-RE and fwtool.py unchanged and report their first error. This is
rejected because the known tools predate the donor formats and their support tables
are not proof that further offline analysis is impossible.

### Direct Cross-Flash

Rename or modify an α6700 or α7 V package and present it to the α6400. This is
rejected for the offline phase. It would combine unknown model checks, different
processors and peripherals, signed boot enforcement, and an unproven recovery path
in the user's only dependable camera.

### Evidence-First Offline Engineering Lab

Authenticate the three-model corpus, reproduce the exact parser and model-gate
failures, extend the tooling, compare components, investigate signature enforcement,
prototype α6400-specific transformations, and test every candidate locally. This is
the selected approach because it supports aggressive research without treating the
camera itself as a parser, signature, or boot experiment.

## Architecture

### 1. Isolated Development Line

Create a fresh isolated branch from the completed
`feature/a6400-offline-feasibility` branch. Preserve the prior reports as the
baseline and keep unrelated user work unchanged. The implementation may use the
existing linked worktree; it must not create a worktree inside another worktree.

Only source code, tests, manifests, hashes, provenance, and human-readable research
reports are committed. Sony binaries, extracted proprietary components, decrypted
payloads, generated candidate images, and large diagnostic dumps remain ignored.

### 2. Firmware Corpus and Provenance Manager

Store official firmware below the ignored directory:

`.artifacts/sony-firmware/<model>-<region>-<version>/`

The manager authenticates each download using:

- exact official Sony URL;
- manufacturer, model, region, version, and release date;
- advertised and observed filename and byte size;
- SHA-256 digest; and
- acquisition timestamp.

The new α7 V package is downloaded only from the approved Sony Taiwan page. The
existing α6400 and α6700 files are rehashed before use. Every transformation operates
on a disposable copy while retaining the original digest.

### 3. Three-Camera Comparison Model

The α6400 is the target, the α6700 is the modern touch/Creative Look reference, and
the α7 V is the verified Vertical Display donor. The comparison records, where
observable:

- image processor and executable architecture;
- container and partition structure;
- boot and update metadata;
- display dimensions, pixel formats, and rendering resources;
- orientation-sensor inputs and layout selection;
- touch event routing, menu widgets, and control bindings;
- Creative Look tables, tone curves, matrices, and adjustable axes; and
- model- and hardware-specific dependencies.

Feature presence must be separated from architecture generation. A component that
exists only in the α7 V image is not automatically portable to the α6400.

### 4. Firmware-Format Lab

Pin the exact revisions of Sony-PMCA-RE, fwtool.py, and any evaluated forks. First
reproduce their behavior unchanged. Record the precise byte offset, stage, exception,
and assumption at which each tool stops.

Then build evidence-based extensions or replacement parsers for:

- wrapper and update-container headers;
- encrypted or compressed regions;
- checksums, hashes, certificates, and signatures;
- model and version allowlists;
- partition tables and filesystem images;
- executable and resource indexes; and
- deterministic repacking of understood synthetic structures.

Unknown data is retained and bounded rather than silently discarded. Candidate
interpretations require corroboration from at least two independent observations,
such as repeated structures across versions, a known checksum relationship,
executable references, or a matching official updater behavior.

### 5. Signature and Model-Gate Research

Map every discovered enforcement layer independently:

1. host updater checks;
2. transport or update-protocol checks;
3. camera updater checks;
4. bootloader or secure-boot checks; and
5. runtime component integrity checks.

The lab may patch local copies of host updater code, build malformed and corrected
synthetic packages, substitute model metadata, test checksum and signed-range
hypotheses, and develop offline validators. It may investigate historical
vulnerabilities, service interfaces, signing mistakes, downgrade paths, and bounded
execution mechanisms where supported by evidence.

An invalid signature is a research result: determine what generated it, what verifies
it, which bytes are covered, and whether any unsigned or incorrectly verified region
exists. It is a hard stop only for claiming installability or presenting the image to
a camera.

### 6. UI Port and Reimplementation Lab

For vertical UI and full touch menus, identify the smallest functional boundaries:

- orientation state acquisition;
- layout selection and coordinate transforms;
- rotated text/icon assets or runtime rendering;
- input-coordinate rotation;
- menu widget touch handlers;
- touch capture, focus, gesture, and dispatch layers; and
- persistence of orientation and touch settings.

For each boundary, test in this preference order:

1. compatible direct component reuse;
2. data/resource-table transplant;
3. patching an existing α6400 subsystem; and
4. α6400-specific reimplementation using its existing orientation sensor and touch
   hardware.

Static similarity alone is insufficient. A port candidate must identify imports,
relocations, memory requirements, dependent services, display assumptions, and input
interfaces before being described as executable-compatible.

### 7. Creative Look Lab

The Creative Look track is independent so it can produce useful results even if the
UI track remains unresolved.

Use Sony's definitions as the authoritative behavior model. Preserve vetted
community recipes, including their source, camera model, Creative Look base, white
balance, color filter, and all eight modern adjustment axes. Translate each recipe
to the α6400's available base Creative Style plus contrast, saturation, sharpness,
and white-balance controls.

Direct base mappings are evaluated first:

- `ST` → Standard;
- `PT` → Portrait;
- `NT` → Neutral;
- `VV` → Vivid;
- `BW` → Black & White; and
- `SE` → Sepia.

`VV2`, `FL`, `IN`, and `SH` receive experimental α6400 Style Box translations. The
report must state that the α6400 lacks modern highlight, shadow, fade, sharpness
range, and clarity axes, so translations may be close visual approximations rather
than identical processing.

Each recipe receives a confidence level and a repeatable visual validation protocol.
Unknown lighting, white balance, lenses, and postprocessing prevent random web JPEGs
from serving as exact reference measurements.

### 8. Evidence Ledger and Reporting

Every conclusion is tagged as:

- `CONFIRMED`: directly reproduced from primary artifacts or official documentation;
- `PARTIAL`: a working subset or approximation is demonstrated;
- `INFERRED`: multiple observations support the interpretation but direct execution
  is unavailable; or
- `INSUFFICIENT_EVIDENCE`: available artifacts cannot distinguish the hypotheses.

An error does not automatically become `INSUFFICIENT_EVIDENCE`. The report first
records the attempts made to parse, decrypt, validate, bypass, or reimplement it.
Negative results include exact tool revisions, commands, offsets, fixtures, and
falsified hypotheses so later work does not repeat them.

## Data Flow

1. Acquire the α7 V donor from the approved Sony URL into the ignored artifact tree.
2. Rehash and authenticate all three original packages.
3. Copy each package into a model-specific disposable analysis directory.
4. Run historical tools unchanged and capture deterministic baseline failures.
5. Feed copies through progressively extended inspectors, preserving unknown bytes.
6. Build cross-model structure, architecture, UI, input, and color comparisons.
7. Send model mismatches, decryption failures, signature failures, and ambiguous
   regions into their corresponding research branches.
8. Exercise transformation and bypass hypotheses on synthetic fixtures and local
   package copies.
9. Store generated binaries in an ignored quarantine directory with conspicuous
   `NOT_FOR_INSTALL` naming and provenance sidecars.
10. Commit only reproducible source, fixtures that contain no Sony bytes, tests,
    manifests, hashes, and reports.

No data flow reaches USB, an SD card, a camera, or a Sony camera update directory.

## Safety and Error Handling

### Research Boundary

The α6400 and NEX-C3 remain disconnected. No camera identity, driver, service mode,
updater mode, storage, or firmware is touched. This boundary permits exhaustive local
analysis; it does not restrict reverse engineering of formats, model gates,
encryption, signatures, or updater logic.

### Input Integrity

Original firmware inputs are read-only. Before and after every analysis or
transformation session, verify their SHA-256 digests. Mutation code receives only a
new disposable copy and refuses an original-path input.

### Failure Routing

- Model mismatch → locate and classify each model check; test substitutions locally.
- Unknown region → bound it, compare entropy and repetitions, search references, and
  preserve it through round trips.
- Failed decryption → verify algorithm assumptions, key derivation, block boundaries,
  padding, and version changes; test against synthetic vectors.
- Invalid signature → identify verifier, signed range, certificate chain, and update
  layer; investigate bypass hypotheses offline.
- Ambiguous output → retain competing interpretations and design discriminating
  tests; do not pick the most convenient interpretation.

These conditions stop a compatibility or safety claim until resolved. They do not
silently terminate the research program.

### Candidate Quarantine

Locally generated images are not described as firmware releases and are never placed
where Sony software or a camera could discover them. Their sidecars record parent
digests, transformations, understood and opaque ranges, validation results, and
unresolved risks. An offline structurally valid image is not labeled safe to install.

### Camera Execution Gate

Any future camera-connected phase requires a separate approved design and explicit
fresh authorization. Before even proposing it, the research must provide:

- a repeatable offline build and validation result;
- understood target model and hardware boundaries;
- exact write scope and signature-enforcement behavior;
- a recovery method capable of handling a non-booting α6400; and
- a preflight review that treats the α6400 as the user's only dependable camera.

## Testing Strategy

### Parser and Container Tests

- minimal valid synthetic containers for every understood structure;
- truncated, malformed, overlapping, and high-entropy inputs;
- integer-boundary, length, offset, and alignment cases;
- deterministic parse and report output;
- unknown-region preservation during round trips; and
- before-and-after original-file digest verification.

### Cryptographic and Gate Tests

- known synthetic hash, checksum, encryption, and signature vectors;
- signed-range mutation tests to determine covered bytes;
- model/version substitution fixtures;
- negative cases for wrong keys, padding, certificates, hashes, and identifiers;
- reproducible local host-updater bypass experiments; and
- separation of updater acceptance from boot acceptance in every report.

### Cross-Model and UI Tests

- architecture and executable-format classification;
- import, relocation, symbol/string, resource, and call-reference comparisons;
- layout and touch-coordinate transform fixtures for landscape and both portrait
  orientations;
- dependency checklists for every proposed donor component; and
- synthetic stubs or harnesses for interfaces that can be modeled without Sony
  hardware.

### Creative Look Tests

- recipe schema and range validation;
- deterministic translation from modern eight-axis recipes to α6400 controls;
- explicit detection of unrepresentable axes;
- official-source and third-party-source separation;
- confidence scoring; and
- a future controlled JPEG comparison protocol using fixed exposure, white balance,
  lens, lighting, and no postprocessing.

### Repository Safety Tests

- Git candidate-change scan for firmware, decrypted content, and large binary blobs;
- runtime scan preventing camera/USB/write modules from entering offline commands;
- artifact-path and provenance-sidecar checks; and
- full existing test-suite regression runs.

## Deliverables

1. Authenticated three-model firmware manifest and provenance report.
2. Reproducible firmware-format and cryptographic inspection tools.
3. Baseline results for historical tools plus documented extensions or replacements.
4. Model-gate, signature-enforcement, and custom-updater research report.
5. Cross-model architecture and feature-dependency matrix.
6. Vertical UI and touch-menu port/reimplementation assessment with candidate methods
   where evidence supports them.
7. Creative Look recipe catalog, α6400 translations, confidence levels, and validation
   protocol.
8. Quarantined offline candidate transformations when supported by evidence.
9. Updated main feasibility report that distinguishes confirmed, partial, inferred,
   and insufficient-evidence conclusions.

## Acceptance Criteria

The offline phase is complete when:

- the α6400, α6700, and verified vertical-UI α7 V packages are authenticated;
- every existing-tool failure has been reproduced and routed to an investigated
  format, cryptographic, model-gate, or compatibility branch;
- new parsers and validators are covered by deterministic synthetic tests;
- each desired function has a dependency map and the strongest supported outcome:
  native port, α6400 reimplementation, practical approximation, or a precisely
  located unresolved barrier;
- model and signature bypass hypotheses have been tested as far as local artifacts
  and synthetic execution permit;
- all ten Creative Looks have either a native implementation finding or a sourced
  α6400 translation with an explicit confidence level;
- the repository contains no Sony firmware or extracted proprietary bytes;
- the full test suite passes and original firmware digests remain unchanged; and
- both cameras remain disconnected and unchanged.

The phase may identify a final barrier, but it may not stop at an inherited
`unsupported` message. A barrier is acceptable only after the relevant hypotheses,
tooling extensions, and offline bypass or reimplementation paths have been exercised
and documented.

## Subsequent Gate

After the offline report is reviewed, camera testing is considered only if the
evidence supports a bounded experiment and a credible α6400 recovery path. That work
requires a new design, exact preflight and rollback procedures, fresh user approval,
and physical supervision at the laptop and camera. This specification provides no
authorization to perform it.
