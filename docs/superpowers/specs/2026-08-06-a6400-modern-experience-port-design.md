# Sony α6400 Modern Experience Port Design

## Status and precedence

This design was approved on 2026-08-06. It refines the UI and Creative Look
objectives in `2026-08-04-a6400-ui-creative-look-port-research-design.md`.
Where the two documents differ, this document controls the product goal and
recovery gate. The earlier document remains the detailed provenance and offline
firmware-lab baseline.

The current phase is static and offline. It does not authorize connecting a
camera, executing Sony camera binaries, writing camera or USB partitions,
entering updater/service mode, or flashing firmware.

## Product goal

Retain the ILCE-6400 hardware and the functions its processor can support while
making its user experience approach the α7 V generation:

1. the same modern interface structure and visual layout where the α6400 display
   and rendering services can represent it;
2. the same navigation and usage patterns, including portrait-orientation
   layouts and coherent control/touch behavior;
3. Creative Look as a first-class workflow with its own menu, preset selection,
   persistence, and adjustment model; and
4. continued access to stable α6400-native shooting functions.

Identical α7 V machine code is not required. Behavioral and interface fidelity
are the success criteria. A target-native implementation is preferred whenever
donor components are incompatible.

Creative Style recipes that imitate Creative Look are a last fallback. They are
not the primary Creative Look design and must never be presented as native
Creative Look processing.

## Scope boundaries

### In scope

- α7 V-like shooting and settings layouts;
- landscape and both portrait orientations;
- menu and on-screen-control touch routing where the α6400 touch hardware can
  supply the needed input;
- rotated control directions and coordinate transforms that remain aligned with
  the visible layout;
- Creative Look menu structure, preset selection, state storage, base-look
  processing, and every adjustment axis that can be implemented using verified
  α6400 pipeline primitives;
- α6400-specific adapters or reimplementations; and
- an external, independently usable recovery route to exact stock α6400 2.00.

### Out of scope

- features requiring absent hardware or a newer processor, including donor AI
  autofocus acceleration, additional sensor pixels, unsupported sensor readout
  modes, or processor-specific codecs;
- blind α7 V or α6700 cross-flashing;
- cosmetic claims that a resource reskin supplies the corresponding behavior;
- claiming exact Creative Look colorimetry without authenticated tables or
  controlled measurement; and
- any camera-connected experiment during the current phase.

## Selected approach

Use a target-native experience port. Treat α7 V behavior and resources as the
interface contract, then satisfy that contract through existing α6400 services,
dormant α6400 components, compatible data resources, or narrowly bounded
α6400-specific implementations.

Two alternatives remain research probes, not the default architecture:

- A direct donor-component transplant may be evaluated only after its ABI,
  imports, relocations, memory use, dependent services, and hardware assumptions
  are proven compatible.
- A resource-only reskin may help identify layout assets but cannot satisfy the
  project without matching navigation, state, touch, orientation, and processing
  behavior.

## Research architecture

### 1. Interface behavior contract

Describe the desired α7 V-generation experience independently of its binaries:

- screen hierarchy and layout geometry;
- menu grouping and navigation transitions;
- landscape and portrait state transitions;
- control-wheel, button, and touch behavior;
- visible availability, caution, and disabled states; and
- state persistence across mode and power transitions.

Each behavior receives a stable identifier so target evidence can satisfy it
without implying donor-code identity.

### 2. α6400 UI and input boundary map

Extend the pinned α6400 static traces beyond direct calls into virtual calls,
vtable ownership, UXC/data bindings, event tables, layout factories, resource
lookups, and coordinate consumers. Recover separately:

- orientation-state production and subscription;
- orientation-to-layout selection;
- layout construction and attachment;
- display-coordinate transforms;
- physical-control direction transforms;
- touch coordinate capture and hit testing;
- menu selection dispatch; and
- settings persistence.

A layout name, touch-named symbol, or dormant factory is evidence of presence,
not evidence that the complete feature is wired into production.

### 3. Compatibility adapters

For every behavior-contract item, choose the smallest supported implementation:

1. reuse an already active α6400 component;
2. activate a compatible dormant α6400 component;
3. adapt a compatible data/resource table;
4. extend an α6400 subsystem through a digest-pinned, bounded patch site; or
5. record a precise hardware, ABI, or evidence blocker.

No donor executable is called compatible until its architecture, imports,
relocations, memory requirements, service dependencies, and error paths have all
been mapped to target equivalents.

### 4. Creative Look stack

Treat Creative Look as five separable layers:

1. **Interface:** Creative Look entry point, preset browser, edit screen, reset,
   copy, and selection behavior.
2. **State:** preset identifiers, per-look adjustment records, defaults, range
   validation, and persistence.
3. **Base looks:** authenticated tables or an evidence-backed target-native
   representation for `ST`, `PT`, `NT`, `VV`, `VV2`, `FL`, `IN`, `SH`, `BW`,
   and `SE`.
4. **Adjustment axes:** contrast, highlights, shadows, fade, saturation,
   sharpness, sharpness range, and clarity, implemented only where a verified
   α6400 image-pipeline primitive or safe equivalent exists.
5. **Pipeline binding:** live-view preview, still JPEG, and supported movie paths,
   with mode restrictions reported explicitly.

The existing dormant Creative Style graph is useful target evidence, but changing
its selector does not by itself satisfy the Creative Look stack. Creative Style
translation is considered only after the native and target-reimplementation paths
for a specific layer are exhausted.

### 5. Hardware capability gate

Every proposed feature is classified as:

- `TARGET_NATIVE`: the α6400 already provides the required primitive;
- `TARGET_REIMPLEMENTABLE`: the behavior can be built from verified α6400
  primitives within known resource limits;
- `DONOR_COMPATIBLE`: donor data or code has a fully mapped target ABI;
- `APPROXIMATION_ONLY`: the desired result cannot be represented exactly; or
- `HARDWARE_BLOCKED`: it requires absent processor, sensor, memory, peripheral,
  or acceleration capability.

One hardware-blocked feature does not block unrelated interface or Creative Look
work.

## External stock-2.00 recovery gate

The rollback requirement is not an in-camera settings reset. It is an external
recovery procedure capable of restoring the exact original regional α6400 2.00
firmware using a laptop or another independent recovery mechanism.

Before any modified payload may be proposed for camera testing, the recovery path
must demonstrate all of the following:

1. **Known-good source:** an immutable copy of the exact official regional α6400
   2.00 updater and every required stock component, identified by size and SHA-256.
2. **Independent entry:** recovery does not depend on the modified menu, normal UI,
   or the modified runtime starting successfully.
3. **Complete write scope:** the required partitions/components, ordering,
   version checks, signature checks, and power-loss behavior are understood.
4. **Stock authenticity:** the resulting target state is byte- or
   structure-verified against authenticated stock 2.00 expectations wherever the
   device permits verification.
5. **Failure coverage:** the procedure addresses a broken UI/runtime, interrupted
   update, non-booting application layer, and rejected-version/downgrade cases; any
   state it cannot recover is stated explicitly.
6. **Operational safety:** stable power, cable, host environment, exact commands,
   stop conditions, logs, and human supervision are defined in a separate future
   camera-test design.
7. **Independent validation:** the recovery mechanism is validated before the
   feature payload, rather than being attempted for the first time after a feature
   failure.

Possible mechanisms may include an official updater/reinstall route, a verified
USB recovery or updater mode, an independently bootable maintenance path, or a
combination. A normal settings reset, an unverified service menu, or a recovery
procedure that requires the modified application to boot does not pass this gate.

The current offline phase may analyze and prototype this route, but it may not test
it on a camera. Until a later explicitly approved phase validates recovery, every
generated runtime artifact remains quarantined and `NOT_FOR_INSTALL`.

## Data and decision flow

1. Record an α7 V behavior-contract item.
2. Trace the corresponding α6400 UI, state, input, or imaging boundaries.
3. Classify required primitives through the hardware capability gate.
4. Select the smallest compatible target implementation.
5. Validate parsers, mappings, layouts, transforms, and patch descriptions on
   synthetic fixtures or disposable offline copies.
6. Record positive and negative evidence without promoting names or static
   similarity into runtime claims.
7. Keep candidate binaries outside updater/camera-visible locations.
8. Advance a camera-test proposal only when both the feature evidence gate and the
   external stock-2.00 recovery gate pass.

## Error handling and claim discipline

- Unresolved indirect dispatch keeps the related behavior unestablished.
- Missing donor decryption prevents donor implementation claims but does not stop
  target-native tracing.
- ABI or hardware mismatches reject that component, not the overall experience
  goal.
- Unsupported Creative Look axes remain individually blocked and visible; they are
  not silently discarded.
- Signature, package, or version-gate failures stop installability claims.
- An incomplete recovery route stops every camera-connected feature experiment.

Evidence levels remain `CONFIRMED`, `PARTIAL`, `INFERRED`, and
`INSUFFICIENT_EVIDENCE`. Offline byte mutation proves only that the offline file
changed as intended; it does not prove camera behavior or safety.

## Verification strategy

### UI and input

- direct, virtual, indirect, and UXC/data-driven call-graph tests;
- vtable and layout-factory ownership checks;
- landscape, portrait-shutter-up, and portrait-shutter-down layout fixtures;
- matching render, wheel/button direction, and touch-coordinate transform tests;
- state-transition and persistence models; and
- negative tests that reject status reads or configuration calls as menu dispatch.

### Creative Look

- schema tests for ten base looks and eight distinct axes;
- range, default, reset, copy, and persistence tests;
- explicit mode-support matrices for preview, stills, and movies;
- authenticated-table provenance and digest checks;
- tests that prevent a Creative Style selector or recipe from being labeled native
  Creative Look; and
- future controlled color comparison under fixed lens, exposure, illumination,
  white balance, output settings, and viewing conditions.

### Recovery and repository safety

- stock-source provenance and digest validation;
- offline modeling of version, signature, write-order, and interrupted-update
  behavior;
- fail-closed recovery readiness reports;
- scans preventing Sony binaries, decrypted payloads, raw keys, or installable
  candidates from entering Git;
- full analysis-suite regression tests; and
- confirmation that no camera, USB/camera partition, or Sony binary execution was
  involved.

## Milestones and acceptance

### Milestone A: target UI/input boundary

The orientation-to-layout selector, coordinate consumer, hit-test path, and menu
selection dispatcher are either recovered with pinned evidence or each reduced to a
precise unresolved boundary.

### Milestone B: modern interface mapping

The α7 V behavior contract is mapped to target-native, target-reimplementable,
donor-compatible, approximation-only, or hardware-blocked components without
claiming that donor presence proves portability.

### Milestone C: first-class Creative Look design

The UI, state, base looks, axes, and pipeline bindings are separately mapped. A
Creative Style approximation is used only for layers proven infeasible after the
native/reimplementation investigation.

### Milestone D: external stock recovery

A reproducible procedure for restoring exact regional α6400 2.00 exists independently
of the modified runtime and has a separately approved validation plan. Static
research completion alone does not satisfy this milestone.

### Milestone E: camera-test eligibility

A future camera experiment may be designed only when its exact write scope,
signature/package behavior, feature validation, and external stock-2.00 recovery
all pass. That future design requires fresh user authorization and physical
supervision. This document does not authorize it.
