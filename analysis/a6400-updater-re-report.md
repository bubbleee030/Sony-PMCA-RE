# Sony α6400 Updater Enforcement Gate Report

## Safety boundary

- Camera policy: `physically-disconnected`
- Camera executed: `false`
- Physical transport observed: `false`
- Bypass established: `false`
- Installable output: `false`
- Signed updater engine SHA-256: `8f2e8b229ef9e49a874cbf920301aba078727cebc490c891a992de60ff8a3528`

No physical camera transport command was observed. All command and status findings below are static observations from the signed updater engine unless explicitly labeled otherwise.

## host-wrapper

Status: `PARTIAL`

The outer α6400 updater was mapped far enough to identify its signed Sony engine and the engine's FirmwareData DAT integrity parser, but no authenticated writable firmware image was recovered.

Evidence:

- **OBSERVATION** — `analysis/a6400-updater-static.json`: The updater wrapper contains a signed Sony System Software Updater engine whose SHA-256 is pinned by this report.
- **OBSERVATION** — `ghidra:signed-updater-engine:FUN_004012d0`: The engine searches for FirmwareData*.dat, verifies a trailing DEND marker and CRC, and parses DATV, PROV, FDAT, and UDID container tags.
- **OBSERVATION** — `ghidra:signed-updater-engine:FUN_00408a20,FUN_00409c40`: ModelName.ini supplies display text appended to the updater window; these references do not perform the enforcement comparison.
- **INFERENCE** — `ghidra:signed-updater-engine:FUN_004012d0`: The host engine appears to integrity-check and stage an opaque DAT rather than decrypting feature binaries in this function.
- **UNRESOLVED** — `offline-static-analysis`: The complete wrapper-to-FirmwareData extraction path and any additional host authenticity checks are not yet characterized.

Next offline experiment: Trace every caller and data reference around the DAT buffer, CRC result, and updater resource extraction without executing the updater against a device.

Feature relevance: This layer must yield authenticated target and donor contents before Vertical UI, full touch UI, or Creative Looks code and resources can be compared.

## transport

Status: `PARTIAL`

The updater's Windows storage and SCSI boundary is statically mapped, while the disconnected run proved that no physical device was opened and no protocol exchange was observed.

Evidence:

- **OBSERVATION** — `analysis/a6400-updater-no-camera.json`: The sandboxed disconnected-camera run recorded zero device-open groups and did not reach a camera protocol boundary.
- **OBSERVATION** — `ghidra:signed-updater-engine:FUN_004073b0,FUN_00407500,FUN_00407770`: The signed engine opens a selected storage volume and issues DeviceIoControl requests 0x002d1400 and 0x002d0c00.
- **OBSERVATION** — `ghidra:signed-updater-engine:FUN_00407a50`: A 0x44-byte pass-through structure with a 0x2c-byte header and 0x12-byte sense region is submitted through DeviceIoControl request 0x0004d014.
- **INFERENCE** — `analysis/updater-transport-observations.json`: Request 0x0004d014 and the observed structure are consistent with Windows SCSI_PASS_THROUGH_DIRECT transport.
- **UNRESOLVED** — `offline-static-analysis`: Exact command descriptor block bytes, response lengths, retry semantics, and a real-camera trace remain unobserved.

Next offline experiment: Recover the command descriptor construction and response parsing statically, then model only exact recovered exchanges in the synthetic fail-closed harness.

Feature relevance: Transport knowledge can explain how an official package is delivered, but it does not establish that newer UI or color-processing components are compatible with α6400 hardware or firmware.

## camera-updater

Status: `PARTIAL`

The host-side command state machine and returned model/version error codes are visible, but the enforcing camera logic and any bypass remain unknown.

Evidence:

- **OBSERVATION** — `ghidra:signed-updater-engine:FUN_00406a70,FUN_004061c0`: The host state machine uses command IDs 0x01, 0x10, 0x20, 0x30, 0x40, 0x100, and 0x200 for initialization, guard, version, mode switch, write, completion, and state operations.
- **OBSERVATION** — `ghidra:signed-updater-engine:FUN_00405a50`: The host validates response format/status value 1 and requires the returned command field to match the requested command.
- **OBSERVATION** — `ghidra:signed-updater-engine:FUN_004061c0,FUN_004071b0`: Requests use a zero-initialized 32-byte header followed by optional data: data length is at offset 0x00, a firmware-derived 16-bit value at 0x04, command at 0x06, and a wrapping sequence value at 0x0a.
- **OBSERVATION** — `ghidra:signed-updater-engine:FUN_00408b30`: Returned statuses 0x140 and 0x141 select the invalid-model error path, while 0x142 selects the invalid-version error path.
- **INFERENCE** — `ghidra:signed-updater-engine:FUN_00406a70,FUN_00408b30`: Because these errors are decoded from the guard response, model and version enforcement likely occurs in the camera updater rather than through the display-only ModelName.ini value.
- **UNRESOLVED** — `camera-updater-firmware`: The camera-side comparison inputs, signature decision, anti-rollback behavior, command authorization, and failure recovery state machine have not been recovered.
- **UNRESOLVED** — `offline-static-analysis`: No change that safely bypasses statuses 0x140, 0x141, or 0x142 has been identified or tested.

Next offline experiment: Map the 32-byte host command header and guard-response fields exactly, then search authenticated updater contents for the corresponding camera-side dispatcher and status constants.

Feature relevance: Passing this gate would only permit package acceptance; it would not supply α6400-compatible Vertical UI, touch widgets, event routing, or Creative Look image-processing tables.

## boot

Status: `INSUFFICIENT_EVIDENCE`

No authenticated α6400 boot chain, recovery loader, firmware signature root, partition map, or rollback path has been recovered.

Evidence:

- **OBSERVATION** — `analysis/signature-experiments.json`: All mutations remain quarantined, camera execution is false, and no experiment produced an installable image.
- **INFERENCE** — `analysis/feature-compatibility.json`: Host package acceptance cannot demonstrate that a modified image would pass camera boot verification or remain recoverable.
- **UNRESOLVED** — `camera-boot-chain`: Boot ROM trust anchors, stage signatures, partition redundancy, rollback counters, and an independently verified unbrick route are unknown.

Next offline experiment: Recover authenticated partition and signature metadata from firmware contents and validate a restore path on a nonessential α6400 body before considering any camera execution.

Feature relevance: Even a correctly ported feature would be unusable if the modified image cannot boot or if a failed boot cannot be recovered.

## runtime-integrity

Status: `INSUFFICIENT_EVIDENCE`

No authenticated α6400 runtime loader, module ABI, code-signing policy, integrity monitor, memory budget, or UI/image-pipeline extension boundary is available.

Evidence:

- **OBSERVATION** — `analysis/feature-compatibility.json`: The dependency matrix contains no authenticated α6400 layout selector, portrait renderer, menu-wide touch dispatcher, widget binding, or Creative Look processing table.
- **OBSERVATION** — `analysis/structures/a6700-tw-v2.00.json,analysis/structures/a7v-tw-v2.00.json`: The donor FDAT regions remain opaque, so executable modules, resources, relocations, and processor-specific dependencies have not been identified.
- **INFERENCE** — `analysis/feature-compatibility.json`: Existing α6400 orientation and limited touch capabilities make target-specific implementation conceivable but do not prove a compatible donor ABI or safe patch boundary.
- **UNRESOLVED** — `target-runtime`: Runtime signature checks, module loading, watchdog behavior, graphics resources, input routing, image-processor interfaces, and memory limits remain unknown.

Next offline experiment: After authenticated decryption, build symbol and structure maps for target UI, input, graphics, and color-pipeline components before proposing any patch site.

Feature relevance: This is the layer where Vertical UI, full touch UI, and Creative Looks must actually execute; none of their target integration points has been recovered.

## Requested-feature assessment

- **Vertical UI — `NATIVE_PORT_UNSUPPORTED`.** Orientation state exists on α6400, but the portrait layout selector, renderer transform, rotated hit testing, resources, and ABI are unlocated.
- **Full touch UI — `NATIVE_PORT_UNSUPPORTED`.** Shooting-screen touch exists, but menu-wide dispatch, widgets, bindings, geometry, and a safe extension point are unlocated.
- **Creative Looks — `NATIVE_PORT_UNSUPPORTED`.** Practical Creative Style approximations exist, but native base tables, extra adjustment axes, color-pipeline code, and processor compatibility are unlocated.

## Current conclusion

Static reverse engineering moved the boundary from an unknown Windows wrapper to a mapped host parser, storage transport, command state machine, and camera-returned model/version statuses. That is meaningful progress, but it is not a bypass: decryption, camera-side enforcement, boot trust, recovery, runtime integrity, and all native feature integration points remain unresolved.
