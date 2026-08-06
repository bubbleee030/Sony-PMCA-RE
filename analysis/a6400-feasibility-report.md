# Sony α6400 Firmware Feasibility Decisions

Generation source: validated evidence document (schema version 1).

## creative-look-discovery

Status: `PARTIAL`

Summary: The visible Creative Look control surface and an α6400 translation boundary are defined, but Sony's internal preset tables and processing code remain inaccessible.

Evidence:
- **OBSERVATION** — `https://helpguide.sony.net/ilc/2320/v1/en/contents/0411B_creative_look.html`: Sony documents ten Creative Look bases, six Custom Look slots, and eight adjustment axes on ILCE-6700.
- **OBSERVATION** — `analysis/creative-look-recipes.json`: The committed translation catalog records six direct semantic mappings and four explicitly inferred Style Box approximations for ILCE-6400.
- **OBSERVATION** — `analysis/feature-compatibility.json`: The authenticated bounded marker scan found no plaintext feature locator in the α6400 overlay or either donor FDAT and labels absence from encrypted data as no result.
- **INFERENCE** — `analysis/feature-compatibility.json`: The visible behavior and target-side approximation boundary are known, but no authenticated firmware table, loader, or image-pipeline integration point has been located.

Next permitted action: Map the target's native settings-node, preset-storage, and image-pipeline interfaces for a first-class Creative Look experience; keep the Creative Style guide as the final fallback.

## creative-look-emulation

Status: `PARTIAL`

Summary: A practical no-firmware approximation is delivered for all ten named looks, while exact colorimetry and five donor-only adjustment axes remain unsupported.

Evidence:
- **OBSERVATION** — `https://helpguide.sony.net/ilc/1810/v1/en/contents/TP0002264693.html`: ILCE-6400 Creative Style provides Standard, Portrait, Neutral, Vivid, B/W, Sepia, six Style Boxes, and contrast, saturation, and sharpness adjustments.
- **OBSERVATION** — `analysis/creative-look-recipes.json`: The catalog maps ST, PT, NT, VV, BW, and SE directly and supplies bounded inferred recipes for VV2, FL, IN, and SH without modifying firmware.
- **OBSERVATION** — `analysis/a6400-creative-look-guide.md`: The deterministic guide preserves white-balance instructions, clamps target values to the documented α6400 range, and calls out every donor axis that cannot be represented.
- **INFERENCE** — `analysis/creative-look-recipes.json`: This is a practical approximation candidate, not a native Creative Look port or proof of a Sony-exact visual match.

Next permitted action: Keep the recipes as a reversible fallback and prioritize static research of a first-class Creative Look control surface and persistence model; do not flash the camera.

## touch-menu

Status: `PARTIAL`

Summary: The α6400 has shooting touch plus pinned settings-menu status/configuration paths, but no menu coordinate consumer, hit test, selection dispatcher, or safe extension point is established.

Evidence:
- **OBSERVATION** — `https://helpguide.sony.net/ilc/1810/v1/en/contents/TP0002280339.html`: Sony documents that touching a subject on the α6400 monitor starts Touch Tracking, confirming target touch coordinates reach a shooting subsystem.
- **OBSERVATION** — `https://helpguide.sony.net/ilc/2320/v1/en/contents/211h_touchpanel_settings.html`: Sony documents separate shooting-screen, footer-icon, playback-screen, and menu-screen touch controls on ILCE-6700.
- **OBSERVATION** — `analysis/feature-compatibility.json`: The bounded target trace reaches touch-status and touch-pad configuration helpers but finds no executable menu coordinate, hit-test, selection, widget-binding, or production resource-touch path.
- **INFERENCE** — `analysis/feature-compatibility.json`: An α6400-specific subsystem extension is more plausible than donor reuse, but the requested full touch menu is not currently implementable from authenticated evidence.

Next permitted action: Resolve selected terminal indirect calls and the cross-module layout/resource boundary using read-only metadata; retain the no-camera gate.

## vertical-ui

Status: `PARTIAL`

Summary: The α6400 exposes three-way orientation state and five pinned vertical-layout class IDs, but orientation-based selection, verified portrait geometry, rendering, and input transforms remain unestablished.

Evidence:
- **OBSERVATION** — `https://helpguide.sony.net/ilc/1810/v1/en/contents/TP0002278024.html`: Sony documents horizontal, vertical shutter-up, and vertical shutter-down orientation detection for α6400 Switch V/H AF Area.
- **OBSERVATION** — `https://helpguide.sony.net/ilc/2540/v1/en/contents/251h_vertical_ui_display.html`: Sony documents α7 V Vertical Display rotating shooting information, control-wheel directions, and touch operations to match monitor orientation.
- **OBSERVATION** — `analysis/feature-compatibility.json`: Five target vertical-layout class IDs and UXC references are pinned, while bounded searches find no orientation-to-layout selector or control/touch transform path; only vertical-orientation-state is ready.
- **INFERENCE** — `analysis/feature-compatibility.json`: Orientation sensing and target layout identities can be reused conceptually, but neither donor transplantation nor an α6400-specific implementation has a complete executable path or safe patch boundary.

Next permitted action: Resolve the target orientation-to-layout and layout-to-render/input paths before implementation; later require verified signing and independent external recovery.

## signature-enforcement

Status: `PARTIAL`

Summary: Host Authenticode coverage and donor DAT parser/checksum boundaries are measured, but camera-side signature enforcement, decryption, and any safe bypass remain unresolved.

Evidence:
- **OBSERVATION** — `analysis/structures/a6400-tw-v2.00.json`: The α6400 updater is a PE32 wrapper with a 313,778,104-byte overlay and a 10,024-byte certificate table; Authenticode exclusions are structurally identifiable.
- **OBSERVATION** — `analysis/signature-experiments.json`: Digest-pinned one-byte mutations distinguish host-signed overlay bytes from excluded certificate bytes, while the pinned tool still stops at wrapper parsing for both α6400 variants.
- **OBSERVATION** — `analysis/signature-experiments.json`: Donor DATV, UDID, and FDAT mutations stop at version, device-descriptor, or checksum validation and every experimental output is quarantined and marked installable false.
- **INFERENCE** — `analysis/signature-experiments.json`: The experiments locate integrity-sensitive layers but do not bypass the updater wrapper, select a decrypter, prove model compatibility, or establish the camera's signature boundary.

Next permitted action: Stop at wrapper/decrypter/signature ambiguity; do not convert quarantined mutations into updater inputs or attempt camera execution.

## hardware-dependencies

Status: `PARTIAL`

Summary: Target orientation, touch, and Creative Style capabilities are confirmed, but donor ABI, graphics, memory, image-processor, and controller compatibility are unknown.

Evidence:
- **OBSERVATION** — `analysis/feature-compatibility.json`: The matrix confirms α6400 orientation consumers, touch tracking, six Style Boxes, and three adjustable Creative Style axes.
- **OBSERVATION** — `analysis/structures/a6700-tw-v2.00.json`: The α6700 donor is a fully bounded Sony DAT container whose FDAT payload remains opaque at the unsupported decrypter boundary.
- **OBSERVATION** — `analysis/structures/a7v-tw-v2.00.json`: The actual vertical-UI donor is also a fully bounded Sony DAT container with an opaque FDAT payload and a different package size.
- **INFERENCE** — `analysis/feature-compatibility.json`: Existing target peripherals make an α6400-specific design conceivable, but they do not prove compatible UI frameworks, firmware ABI, resource formats, memory budgets, or image-processing tables.

Next permitted action: Treat every unverified ABI, memory, resource, and controller boundary as unresolved until authenticated target internals are available.

## recovery

Status: `BLOCKED`

Summary: Camera-side execution remains prohibited because no independently verified laptop-based route can yet restore the exact original Taiwan/region-0 α6400 2.00 firmware identity after a failed modified image.

Evidence:
- **OBSERVATION** — `https://www.sony.com.tw/zh/electronics/support/e-mount-body-ilce-6000-series/ilce-6400/downloads/00016145`: Sony warns that power loss during the α6400 update may make the camera inoperable and documents only the official updater workflow.
- **OBSERVATION** — `analysis/feature-compatibility.json`: The real candidate gate rejected an empty guessed-patch set with eleven unresolved dependencies, including updater wrapper, decryption, signature layer, and camera recovery path.
- **OBSERVATION** — `analysis/signature-experiments.json`: All mutation experiments are offline-only, camera_executed is false, installable is false, and outputs are quarantined.
- **INFERENCE** — `analysis/feature-compatibility.json`: Without an independently demonstrated external restore path to the pinned original regional 2.00 updater identity and a nonessential test body, a camera-side experiment cannot satisfy the study's safety gate.

Next permitted action: End at offline artifacts; require a separately verified laptop-based recovery to the pinned original Taiwan/region-0 α6400 2.00 identity and a nonessential test body before any future camera-side proposal.

# Integrated Offline Research Result

## Outcome classification

- Native donor port candidate: **no**. No authenticated donor executable, resource range, relocation boundary, or compatible firmware ABI was recovered.
- α6400-specific reimplementation candidate: **conceptually partial, not build-ready**. Target orientation, five vertical-layout class identities, UXC references, and two bounded settings-menu paths are confirmed, but selector, geometry, rendering, coordinate, hit-test, selection, widget, and image-processing integration paths remain incomplete.
- Practical Creative Look approximation: **available only as the final fallback**. Six direct Creative Style mappings and four clearly inferred Style Box recipes cover all ten named Creative Looks without firmware modification; the primary goal remains a first-class Creative Look interface and usage model.
- Camera execution: **blocked**. No candidate image was built, no output is installable, and neither camera was accessed.

## Donor correction

ILCE-6700 firmware remains the behavioral donor for Creative Look and newer touch controls. It is not evidence for the requested full vertical shooting display. The actual official vertical-display donor used here is ILCE-7M5 (α7 V), whose Help Guide states that shooting information, control-wheel directions, and touch operations rotate with monitor orientation. This correction prevents flipped touch-icon placement from being mistaken for a portrait UI.

## Pinned historical-tool baselines

| Tool | Exact revision | α6400 stopping layer | α6700 stopping layer | α7 V stopping layer |
|---|---|---|---|---|
| ma1co/fwtool.py | `cdba742b73eed5981480c326aeb30033aabf0223` | `wrapper-parsing / unknown-installer` | `decrypter-selection / no-decrypter` | `decrypter-selection / no-decrypter` |
| joeording3/fwtool.py | `c351060721547f6b65d6c969d863f486662f9424` | `wrapper-parsing / unknown-installer` | `decrypter-selection / no-decrypter` | `decrypter-selection / no-decrypter` |
| ironpayne22/fwtool.py | `bc32b106833f64bf105164d49f2f181b0cf39a47` | `wrapper-parsing / unknown-installer` | `decrypter-selection / no-decrypter` | `decrypter-selection / no-decrypter` |

Hypothesis tested: a maintained fork might already parse these newer packages. Result: all three exact revisions stop at the same package-specific boundaries. This is a bounded negative result, not proof that decryption is impossible.

## Authenticated package structures

| Source | SHA-256-pinned size | Outer format | Strongest authenticated boundary |
|---|---:|---|---|
| α6400 TW 2.00 | 314,230,712 bytes | PE32 updater | Five PE sections; overlay at 452,608; certificate at 314,220,688 (10,024 bytes); embedded Sony DAT magic at updater offset 715,220 is only a locator, not a validated extracted image |
| α6700 TW 2.00 | 1,024,017,848 bytes | Sony DAT | Exact full-cover chunks: DATV, PROV, UDID, FDAT, DEND; FDAT starts at 156 and remains opaque |
| α7 V TW 2.00 | 376,540,720 bytes | Sony DAT | Exact full-cover chunks: DATV, PROV, UDID, FDAT, DEND; FDAT starts at 148 and remains opaque |

Hypothesis tested: visible executable or compressed-file signatures might identify portable code/resources. Result: raw magic scans were noisy and non-structural. The authenticated ASCII/UTF-16 marker scan found no requested feature strings, but because the searched payloads are encrypted or opaque, the exact conclusion is **absence from encrypted data is no result**.

## Signature, model-gate, and checksum experiments

All experiments used same-length, digest-pinned disposable copies. Outputs are in ignored quarantine, carry metadata sidecars, are named `NOT_FOR_INSTALL`, and are marked `installable: false`.

| Mutation | Hypothesis | Observed stopping layer | Supported conclusion |
|---|---|---|---|
| α6400 PE certificate byte | Certificate bytes are excluded from host Authenticode digest coverage | Historical tool remained at `wrapper-parsing / unknown-installer`; host impact `excluded` | Host exclusion mapped; no camera-signature or parser bypass |
| α6400 PE overlay byte | Payload overlay is host Authenticode-covered | Historical tool remained at `wrapper-parsing / unknown-installer`; host impact `signed` | Host coverage mapped; no updater-wrapper bypass |
| Donor DATV byte | DAT version header is validated before decryption | `dat-parsing / wrong-data-version` | Version parser is sensitive; does not establish a valid alternate version |
| Donor UDID byte | Device descriptor participates in model/container validation | `dat-parsing / invalid-device-descriptor` | Descriptor parser is sensitive; model mismatch is still a hard stop |
| Donor FDAT byte | Encrypted payload is integrity checked | `dat-parsing / checksum-mismatch` | Payload checksum is enforced by the historical tool; no decryption or signature bypass |

The exact stopping boundary is therefore earlier than any portable UI or color-table analysis: α6400 wrapper parsing, donor decrypter selection, and then uncharacterized camera-side signature/model enforcement. Changing bytes only moved failures earlier.

## Candidate-build gate

A real candidate gate was invoked with no guessed patches. It returned `rejected`, `installable: false`, and created no firmware file. Its eleven unresolved dependencies are:

1. `evidence:vertical-layout-selection`
2. `evidence:vertical-render-transform`
3. `evidence:vertical-input-transform`
4. `evidence:touch-menu-widgets`
5. `evidence:touch-event-routing`
6. `evidence:creative-look-base-tables`
7. `evidence:creative-look-adjustment-axes`
8. `a6400-updater-wrapper`
9. `firmware-decryption`
10. `signature-layer`
11. `camera-recovery-path`

This is deliberately not a model-mismatch bypass. Unknown containers, unavailable decryption, invalid signatures, and ambiguous parser output remain hard stops.

## Vertical UI and touch dependency matrix

| Component | Strongest target evidence | Result | Exact unresolved boundary |
|---|---|---|---|
| Vertical orientation state | α6400 detects horizontal and both vertical orientations | Ready for conceptual reuse | None at the state-detection boundary |
| Vertical layout selection | Five target class IDs occur in both pinned UXC resources and have executable owners | Not ready | A depth-32 mixed-call search traversed resolved direct edges but found no path from the three orientation/layout roots to a factory or class-ID owner; unresolved indirect terminals and cross-module selection remain open |
| Vertical render transform | Target vertical-layout identities are pinned | Not ready | Exact geometry, renderer/compositor path, resources, clipping, and relocations unestablished |
| Vertical input transform | Orientation-aware AF exists; bounded UI trace is pinned | Not ready | No control-direction or touch-coordinate transform, hit-test ABI, or dispatcher path established |
| Touch event routing | Settings-menu paths reach touch status and touch-pad configuration | Not ready for menus | No coordinate consumer, hit test, selection dispatcher, or safe extension point established |
| Touch menu widgets | Known resource-touch owners were searched from the menu root | Not ready | No reached production resource binding; widget framework, bindings, icons, and geometry remain unestablished |

## Creative Look result

The practical guide is [`a6400-creative-look-guide.md`](a6400-creative-look-guide.md). Direct semantic mappings are ST→Standard, PT→Portrait, NT→Neutral, VV→Vivid, BW→B/W, and SE→Sepia. Bounded Style Box approximations are VV2→Clear `(0,+1,0)`, FL→Deep `(-1,0,0)`, IN→Neutral `(-2,-2,-1)`, and SH→Light `(-1,-1,-1)`, expressed as α6400 contrast/saturation/sharpness values.

These recipes do not claim Sony-exact colorimetry. ILCE-6700 exposes eight adjustment axes while α6400 Creative Style exposes three; highlights, shadows, fade, sharpness range, and clarity cannot be represented directly. The guide preserves those gaps and supplies a fixed comparison protocol rather than hiding them.

## Recovery gap and camera-execution gate

No verified α6400 modified-firmware restore path was demonstrated. The official updater warning says interrupted updating can make the camera inoperable, and this α6400 is the user's only working main camera. The NEX-C3 driver rehearsal does not prove α6400 firmware recovery and cannot satisfy this gate. An in-camera factory-reset feature is not required, but an independent laptop-based route back to the exact original Taiwan/region-0 α6400 2.00 updater identity pinned in this repository is mandatory.

Camera execution remains prohibited until all of the following exist independently:

- a digest-pinned, model-specific candidate with authenticated source ranges and no ambiguous parser result;
- successful container decryption and reconstruction with every integrity/signature layer understood;
- a verified external restore procedure that returns a nonessential α6400 body to the exact original regional 2.00 firmware and pinned updater identity after a deliberately failed test;
- independent review of the patch, recovery runbook, power plan, and rollback evidence.

Until then, continue only static first-class Creative Look and UI research. The reversible Creative Style guide remains the final fallback, and the α6400 must not be connected for this research branch.
