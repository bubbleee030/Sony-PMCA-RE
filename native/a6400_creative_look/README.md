# α6400 Creative Look Native Core, Bridge, and Target Shell

This directory contains the portable C99 state, interaction, and offline
integration layers plus a neutral target shell layer for the α6400 Creative
Look work. The code is allocation-free, freestanding-compatible, and
fixed-memory. Product state and
public wire/data fields use fixed-width integers. Pointer-bearing records follow
the compiling ABI: hosted tests exercise their host layouts, while a separately
compiled ARM probe pins their 32-bit target layouts.

The bridge is an **offline integration simulator and ABI contract**. It is not
camera-ready or installable firmware, and it supplies no device procedure. Its
callbacks are exercised by host fixtures only; no Sony runtime binding or
execution is established. The only executable bridge manifest profile is
`CL_EXECUTION_PROFILE_OFFLINE_HOST`. A tracked ARM compile/ABI target profile
exists, but it is not a Sony target-runtime execution profile or binding. The
target shell and relocatable ARM object do not change that boundary.

## Verified ARM target-object evidence

The exact four production modules—core, view, bridge, and target shell—compile
independently with the digest-verified official Arm GNU Toolchain 15.2.Rel1
Windows x86_64-hosted AArch32 bare-metal ZIP. The pinned compiler identifies
itself as `arm-none-eabi` GCC `15.2.1`; the official archive SHA-256 is
`7936cac895611023ffb22a64b8e426098c7104cb689778c1894572ca840b9ece`.
The archive digest is pinned from the official checksum companion; this is not
an OpenPGP-authentication claim. Before executing any tool, the exporter
requires the exact configured path and pinned SHA-256 for the compiler, linker,
`readelf`, `nm`, `objdump`, assembler, and `cc1`. It never selects a tool from
ambient `PATH`.

All four objects use the exact freestanding C99 flags recorded in the target
profile and combine naturally with `arm-none-eabi-ld -r`. Fresh static evidence
establishes one ELF32, little-endian ARM EABI5 `ET_REL` object with ARMv7-A,
Thumb-2, VFPv3-D16, softfp calls, four-byte `wchar_t`, integer-sized enums, and
eight-byte stack alignment. `Tag_ABI_VFP_args` is absent, and `nm -u -P` is
byte-for-byte empty. The test-only ABI probe is compiled and hashed separately;
it is not linked into the production object. No Sony or camera binary is
executed by this build or inspection.

The pinned 32-bit ARM public layouts are:

| Record | Size | Alignment | Additional pinned offsets |
|---|---:|---:|---|
| `cl_state` | 155 | 1 | — |
| `cl_binding_record` | 36 | 1 | — |
| `cl_integration_manifest` | 228 | 2 | — |
| `cl_processing_snapshot` | 164 | 4 | — |
| `cl_bridge_report` | 64 | 4 | — |
| `cl_bridge_adapters` | 60 | 4 | — |
| `cl_bridge` | 692 | 4 | `adapters = 632` |
| `cl_target_identity` | 16 | 4 | pointers `0, 4, 8`; publication status `12` |
| `cl_target_shell` | 1200 | 4 | bridge `0`; frame `692`; sink `1184`; context `1188`; marker `1192`; valid `1196`; delivering `1197`; reserved `1198` |

The probe also pins `CL_TARGET_SHELL_ABI_VERSION = 1` and
`CL_TARGET_PUBLICATION_PROPOSED_UNPUBLISHED = 0`.

This is target-compilation and ABI evidence only. An `ET_REL` object is neither
an executable nor a loadable camera component, and the evidence does not prove
Sony loader compatibility, menu reachability, provider construction, or device
execution.

## Neutral target shell

A caller owns the address-stable `cl_target_shell` storage and must provide it
as all zeroes on first use. That record owns one embedded bridge, one complete
copied presentation frame, initialization/frame-valid/delivery markers, and the
exact input sink/context pair retained during an admitted attachment. After
successful initialization, the record is self-bound to its own address and is
non-relocatable: byte-copying or moving an initialized or closed historical
shell does not create another valid shell.

Initialization requires the caller's lifecycle, presentation, and input
adapter entries—including their contexts—to be zero. The shell copies the
manifest and adapter records by value, installs its own synchronous wrappers
for those three domains, and passes caller-provided persistence, model, and
output callbacks/contexts through unchanged as borrowed values for the shell
lifetime. The provider retains ownership of those injected contexts and their
resources. The shell copies every presented frame by value, retains the
attached input pair only until
detach completes, forwards events only through that retained pair, and rejects
delivery before attachment or after completed close. A post-attach
synchronization error remains open and deliverable because embedded bridge state,
not the return code, is authoritative.

The target shell's const metadata API exposes these proposed identities:

| Identity field | Exact value |
|---|---|
| Logical alias | `view/CREATIVE_LOOK` |
| Component label | `viewCreativeLook.so` |
| Proposed factory label | `ViewCreativeLookToInstance` |
| Publication status | `CL_TARGET_PUBLICATION_PROPOSED_UNPUBLISHED` (`0`) |

The exact 67 string bytes occupy `.rodata.str1.4`, an allocated `AMS` section
with no write or execute flag. The local 16-byte pointer/status record occupies
`.data.rel.ro.local`, which is `WA` in the relocatable object because its three
pointers require relocation; callers receive only a const identity pointer.
These are bounded offline metadata, not registrations. The factory label is not
an exported, local, or undefined symbol; no constructor, init array,
dynamic-loader call, Sony menu root, `openView` route, provider binding, or
factory publication is present. Exact Sony lifecycle, menu/resource insertion,
input delivery, persistence provider, model provider, and output-provider joins
remain runtime-unbound.

## Portable product behavior

`creative_look_core.c` and `creative_look_view.c` remain authoritative for:

- the fixed `ST, PT, NT, VV, VV2, FL, FL2, FL3, IN, SH, BW, SE` order;
- six independent Custom slots;
- landscape and both portrait orientations;
- catalog, Custom-base, editor, and axis-picker screens;
- all eight exact adjustment ranges and unknown/default sentinels;
- modified markers, per-Look reset, and the complete restriction matrix;
- fixed 20-element frames, logical milli-unit layout, and touch hit-testing;
  and
- a strict 164-byte, versioned, CRC-32-protected persistence blob.

The runtime state is 155 bytes. The complete portable layer performs no
allocation, file I/O, dynamic loading, networking, USB access, image
processing, or firmware operation.

## Six-adapter bridge boundary

`creative_look_bridge.c` coordinates exactly six caller-owned synchronous
adapters. Host fixtures provide every callback and retain ownership of their
contexts. Initialization copies the adapter structs, including their context
pointers, but those pointers remain borrowed from and owned by the adapter
provider for the complete bridge session. The bridge does not acquire ownership
of a provider's target resources; the adapters remain responsible for completing
actual teardown inside `detach` and `close`.

| Adapter | Exact bridge contract |
|---|---|
| Lifecycle | `open(context, initial_state)` and `close(context)`; every successful open receives exactly one close. |
| Presentation | `present(context, frame)` receives a validated, stack-built frame. |
| Input | `attach(context, sink, sink_context)` and `detach(context)` register the bridge-owned canonical touch/orientation sink only for the attached interval. |
| Persistence | `load(context, blob, 164)` and `save(context, blob, 164)` exchange the exact encoded state. |
| Model request | `submit(context, snapshot)` receives one complete immutable processing snapshot. |
| Output | `apply(context, kind, snapshot)` independently addresses live view, still JPEG, and movie. |

Every pointer the bridge passes into any adapter callback is borrowed, valid
only for that synchronous callback invocation, and must not be retained because
of the invocation. This rule covers lifecycle `initial_state`, presentation
`frame`, persistence load/save blob buffers, and model/output `snapshot`. An
adapter-owned `context` is merely passed back to its owner; its pre-existing
lifetime and ownership do not come from the callback.

The sole retention exemption is the input `sink` plus `sink_context` pair
registered by a successful `attach`. The input adapter may retain that pair only
until `detach` completes, the bridge storage must outlive that interval, and the
adapter must never invoke the pair after detach.

Callbacks must not reenter the bridge or deliver input while any adapter
callback, attach, or detach is active. The busy guard rejects that attempt
without nested state or report mutation.

## Open, event, synchronization, and close contract

Open has one fixed transaction:

1. load persistence into an exact default candidate or decode an exact
   164-byte blob;
2. call lifecycle open with that candidate;
3. commit state revision `1` and, only when processing-ready, processing
   revision `1` plus a retained snapshot;
4. present the initial frame as an admission gate;
5. attach the canonical input sink; and
6. synchronize every initially dirty domain.

For missing storage, the observable callback order is `load, open, present,
attach, save, model, live_view, still_jpeg, movie`. A processing-ready restored
blob omits only `save`. A restored unconfigured Custom picker calls exactly
`load, open, present, attach`, begins at processing revision `0`, retains an
all-zero snapshot, and creates no model/output work. Presentation or attach
failure closes an already-opened lifecycle; a failed attach is atomic and is
not detached.

Touch and orientation events enter only through the registered canonical sink.
The bridge applies each event to a candidate, validates it, and commits it only
after all checks pass. Invalid, restricted, and no-hit events leave state,
revisions, dirtiness, and callbacks unchanged. A successful change increments
the state revision and dirties presentation and persistence. A
processing-relevant change increments the processing revision and replaces the
retained processing snapshot only when the resulting selection is
processing-ready.

Selecting an unconfigured Custom slot is a valid staged UI state on the
Custom-base picker. It synchronizes only presentation and persistence, does not
create a processing revision, and preserves both an older retained snapshot and
any older failed processing-domain dirtiness. Mode changes made in the picker
are staged too. Explicit sync/retry may still retry the byte-identical older
snapshot. Selecting a valid Custom base completes the state, creates one current
full-state processing revision, and coalesces older dirty processing work to
that newest snapshot. This also applies after a restored picker starts at
processing revision `0`.

Synchronization always attempts dirty domains in this order: presentation,
persistence, model request, live view, still JPEG, movie. Each domain has its
own dirty bit and raw result. A failure does not stop later independent domains;
only successful domains clear. Retry uses the retained byte-identical snapshot
for model and output work at the same processing revision, while presentation
and persistence retries use current state. If a newer processing change arrives
first, the bridge replaces the retained snapshot once and coalesces outstanding
model and output work to the new desired revision.

Close always attempts input detach first and lifecycle close second, even when
detach reports a diagnostic failure. Both callbacks must complete teardown
before returning. Close retains state and unsynchronized dirty bits for offline
inspection; a new open requires bridge reinitialization.

## Complete processing snapshots

The bridge retains the complete immutable snapshot by value. Model and output
callbacks synchronously receive a const pointer to that bridge-owned snapshot
and must not retain it. The snapshot contains the bridge ABI version,
processing revision, effective built-in base, three-output mask, and the
complete `cl_state`: selected Look, all six Custom bases, all `18 × 8`
adjustment bytes, screen/orientation/editor state, and mode flags. This boundary
does not translate Creative Look state into the five Creative Style setter
integers.

## Persistence layout

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | `CLK1` magic |
| 4 | 1 | schema version (`1`) |
| 5 | 1 | selected Look (`0..17`) |
| 6 | 1 | screen |
| 7 | 1 | orientation |
| 8 | 1 | editing axis or `0xff` |
| 9 | 1 | four mode bits |
| 10 | 6 | Custom bases (`0..11` or `0xff`) |
| 16 | 144 | 18 × 8 signed adjustment bytes (`0x80` = Default) |
| 160 | 4 | little-endian CRC-32 over bytes `0..159` |

This is an exact host persistence format, not a Sony storage binding. No safe
α6400 BK4 164-byte record or dynamic-store identity has been proved. The bridge
assigns no Backup record, filesystem path, or other target persistence
provider.

## Evidence, runtime, and safety status

Evidence and execution are independent manifest axes. `UNBOUND`,
`STATIC_CANDIDATE`, or `STATIC_PROVEN` evidence never enables a callback. The
only executable manifest accepted by this milestone uses the exact
`CL_EXECUTION_PROFILE_OFFLINE_HOST` profile and marks all six records
`CL_BINDING_RUNTIME_HOST_SIMULATED`. Simulation is not Sony runtime evidence,
and there is no target-executable runtime state.

The compile-time and manifest safety gates remain exactly false:

- `CL_PROCESSING_BINDING_UNBOUND = 0`
- `CL_RECOVERY_VALIDATED = 0`
- `CL_CAMERA_TEST_ELIGIBLE = 0`
- `CL_INSTALLABLE = 0`

The exact Sony view lifecycle/provider registration is unresolved. There is no
proved target persistence identity, model provider, or live-view/still-JPEG/
movie output sink. Donor decryption and runnable donor processing provenance are
unresolved. Stock recovery remains unvalidated, including exact restoration of
the TW/region-0 2.00 firmware state.

Target persistence and target processing are separate future milestones. A
future persistence adapter must first prove a feature-owned path/identity,
mount lifecycle, 164-byte temp-write/flush/rename atomic flow, and recovery
behavior without taking an existing Backup record. A future processing
milestone must independently prove a full-state Creative Look consumer for live
view, still encoding, or movie; the complete snapshots and host-simulated sinks
do not establish that consumer.
Neither milestone follows from the ARM target object or neutral shell.

## Objective coverage and remaining gates

| Objective | Current evidence/status |
|---|---|
| 12 built-in Looks | Bridge-exercised offline |
| 6 Custom slots | Bridge-exercised offline |
| 8 adjustment axes | Bridge-exercised offline at minimum, default, and maximum |
| Landscape plus both portrait orientations | Bridge-exercised offline |
| Exact 164-byte host persistence | Bridge-exercised through host load/save adapters only |
| Sony runtime publication/binding | Absent and unproven; the three proposed identity strings are offline metadata in the no-write string section |
| Model and three output sinks | Host-simulated only |
| Donor decryption/processing provenance | Unresolved |
| Recovery | Unverified |
| Exact TW/region-0 2.00 restoration | Unverified |
| Camera eligibility/installability | False |

The overall α6400-native project goal remains incomplete while the Sony
bindings, processing sinks, donor provenance, exact stock restoration, and
recovery gates remain unproven or false.

## Offline verification

The native analysis suites compile the core, view, bridge, and target shell as
a host shared library and strict hosted/freestanding C99 objects with warnings
treated as errors. They execute the six adapters, shell-retained canonical
sink, lifecycle failures, complete frame copies and snapshots, exact
persistence, per-domain retries, exhaustive product matrix, host/ARM ABI
layouts, relocatable links, undefined-symbol gates, analyzer, and
operational-capability mutations entirely offline.

The real target exporter additionally re-verifies the pinned tools and all
eight production inputs, compiles four ARM objects plus the separate ABI probe,
records per-object and combined symbol inventories, validates complete section
and relocation coverage, proves the exact identity string section and local
pointer-record relocation chain, and republishes nothing unless fresh
normalized evidence equals the tracked profile.

The production allowlist is exactly four `.c` files plus their four matching
`.h` files. All eight undergo source-capability and literal include-closure
scans. The combined object undergoes byte, complete-symbol-table, and complete
relocation scans that reject menu, loader, storage, Sony processing/encoder,
device, updater, flash, package, and install capabilities. The three exact
proposed identity strings are the sole allowed Sony-style identity data. These
checks are static evidence; they do not publish a Sony factory or satisfy the
overall α6400-native goal.
