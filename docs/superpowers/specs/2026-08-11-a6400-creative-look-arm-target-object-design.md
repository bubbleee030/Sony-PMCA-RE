# α6400 Creative Look ARM Target-Object Design

## Status and scope

This design was approved on 2026-08-11. It extends the approved first-class
Creative Look product contract and the host-only integration ABI. It is the
first target-compilation milestone, not a target-runtime milestone.

The authorized output is a freestanding ARM relocatable object (`ET_REL`) plus
static inspection evidence. This design does not authorize a shared library,
firmware image, updater package, Sony process execution, camera access, service
mode, USB traffic, partition writes, or installation. The four bridge safety
claims remain false: processing binding, recovery validation, camera-test
eligibility, and installability.

## Objective

Prove two narrow facts without weakening the existing evidence boundary:

1. the portable Creative Look core, view, and bridge compile and naturally
   combine under an α6400-compatible ARMv7-A/Thumb-2 C ABI; and
2. a distinct, target-owned Creative Look shell can coordinate bridge
   lifecycle, frame copying, and canonical input delivery without publishing a
   Sony menu entry or pretending that an unresolved Sony factory ABI is known.

The result advances the α6400-native implementation. It does not prove that
Sony's loader constructs the shell, that Sony input reaches it, or that any
image-processing output consumes Creative Look state.

## Authoritative target profile

The target profile is pinned to the authenticated Taiwan/region-0 2.00
`lib/viewUnified2.so`, SHA-256
`1e2867b6fcbfe1fc627a5fa30fd8751cbc02a8650632ee962675609ba4b6e7f2`.
Its ELF attributes establish:

- ELF32, little-endian, ARM, EABI version 5;
- ARMv7-A Application profile with ARM and Thumb-2 instructions;
- VFPv3-D16 instructions;
- no hard-float procedure-call tag, therefore softfp argument passing;
- four-byte `wchar_t` and integer-sized enums; and
- eight-byte stack alignment.

The original module identifies Sony CE Linux GCC 4.5.1. The new object does not
claim binary equivalence with that compiler. Compatibility is bounded to a
freestanding C ABI, explicit target attributes, fixed-width public records,
natural relocatable linking, and the absence of compiler runtime dependencies.
No C++ ABI, exceptions, RTTI, Sony vtable, or Sony object layout is introduced.

## Toolchain acquisition and trust

Use the official Arm GNU Toolchain 15.2.Rel1 Windows x86_64 AArch32 bare-metal
ZIP from Arm's GitLab generic-package release endpoint:

```text
https://gitlab.arm.com/api/v4/projects/tooling%2Fgnu-toolchains-for-arm/packages/generic/gnu-toolchain/15.2.rel1/arm-gnu-toolchain-15.2.rel1-mingw-w64-x86_64-arm-none-eabi.zip
```

Its official `.sha256asc` companion is the same URL with `.sha256asc`
appended and publishes archive SHA-256
`7936cac895611023ffb22a64b8e426098c7104cb689778c1894572ca840b9ece`.
Parse that exact companion record and reject the archive before extraction if
the measured digest differs. Store the verified archive and extracted compiler
only under ignored `.artifacts/toolchains/`; never commit toolchain binaries.

The verifier pins the expected release, archive name, compiler target triple,
and measured digest in a small tracked metadata contract. It must reject a
missing checksum, malformed checksum, wrong archive name, wrong digest,
unexpected compiler target, or unsupported compiler version. It must never use
an arbitrary `arm-none-eabi-*` executable found first on `PATH` when the pinned
toolchain directory is configured.

The bare-metal toolchain is selected only to produce a freestanding relocatable
object with the required ARM attributes. It is not evidence that the α6400 runs
a bare-metal application and it must not link a C library, startup object, board
support package, or executable image.

## Compilation contract

Compile `creative_look_core.c`, `creative_look_view.c`,
`creative_look_bridge.c`, and the target shell independently with the verified
compiler. The intended flags are:

```text
-std=c99 -Wall -Wextra -Werror -pedantic
-ffreestanding -fno-builtin -fPIC -Os
-march=armv7-a -mthumb -mfpu=vfpv3-d16 -mfloat-abi=softfp
-mabi=aapcs-linux
-fno-unwind-tables -fno-asynchronous-unwind-tables
```

The implementation test must fail closed if the selected compiler rejects a
flag. A flag may be changed only with a documented compiler diagnostic and a
replacement that preserves the pinned ELF/EABI/softfp contract.

Combine the four objects naturally with the matching
`arm-none-eabi-ld -r`. The combined output must be `ET_REL`, never `ET_EXEC` or
`ET_DYN`. `readelf` must establish ELF32/little-endian/ARM/EABI5 and the target
attribute set. `nm -u` must be empty without symbol fabrication, filtering, or
an undefined-symbol allowlist. In particular, no `__aeabi_*`, allocation,
filesystem, dynamic-loader, networking, USB, device, updater, flash, or process
symbol may remain unresolved.

The target build emits no `.so`, `.elf` executable, `.bin`, package, partition,
or flashable artifact. Tests must reject any output extension or ELF type that
would contradict this boundary.

## ABI contract

The ARM test compiles an ABI probe using the public headers and asserts the
actual 32-bit target layouts rather than assuming host layouts:

| Record | Size | Alignment |
|---|---:|---:|
| `cl_state` | 155 | 1 |
| `cl_binding_record` | 36 | 1 |
| `cl_integration_manifest` | 228 | 2 |
| `cl_processing_snapshot` | 164 | 4 |
| `cl_bridge_report` | 64 | 4 |
| `cl_bridge_adapters` | 60 | 4 |
| `cl_bridge` | 692 | 4 |

`offsetof(cl_bridge, adapters)` must be 632. Fixed-width serialized records
remain identical to the host contract. Pointer-bearing structures are target
ABI structures and therefore intentionally differ from their 64-bit host
layout.

Cross-module callback return values and public result fields remain fixed-width
`int32_t`. The compile gate must preserve enum representation as integer-sized;
short-enum compilation is not allowed.

## Neutral target shell

Add `creative_look_target.h/.c` as a small, allocation-free C layer around an
embedded `cl_bridge`. Its exported names use the neutral `cl_target_shell_*`
prefix. It must not export `ViewCreativeLookToInstance`, a mangled Sony symbol,
an ELF constructor, or a dynamic-loader entry point.

The shell owns:

- one bridge object;
- one copied `cl_view_frame` for the most recently presented frame;
- validity and open-state flags; and
- the exact input sink/context pair retained only during a successful attach.

The shell exposes synchronous initialization, open, close, event delivery, and
read-only access to its copied frame and bridge state/report. Initialization
requires an already validated host-simulated manifest and caller-provided
adapters. The shell replaces only the lifecycle, presentation, and input
adapter contexts needed to exercise shell ownership; persistence, model, and
output remain caller-injected host/static adapters.

Presentation copies the complete borrowed frame by value before returning.
Input attach retains the sink/context only until detach completes. Delivery is
rejected before attach and after detach. All borrowed bridge callback pointers
remain synchronous-only. The shell cannot turn an unbound adapter into a target
runtime binding and cannot change any manifest evidence/runtime state.

The shell contains proposed identity metadata for offline inspection only:

- logical alias `view/CREATIVE_LOOK`;
- component label `viewCreativeLook.so`;
- proposed factory label `ViewCreativeLookToInstance`; and
- publication status `PROPOSED_UNPUBLISHED`.

These strings are design identities, not loader registrations. Tests must prove
that the proposed factory label is not an exported symbol and that no Sony
registration, `dlopen`, or `dlsym` reference is introduced.

## Evidence boundary and rejected approaches

### Reusing Creative Style

The existing Creative Style root, process-data element, five-integer setter,
`@M00B` request, and factory are useful structural references. Their values do
not encode the first-class Creative Look state. This design forbids replacing,
renaming, or hijacking them.

### Publishing a new menu root now

The selected-node identity, process-ID allocation, registration-row choice,
provider binding, loader invocation, and close/lifecycle route are not fully
joined. Publishing a root would overstate reachability and is excluded.

### Exporting a Sony-named factory stub

The exact Sony `ViewManager`/base-view construction ABI and runtime loader
binding are unresolved. A symbol with the expected name could be mistaken for
an integration-ready factory. The neutral shell is used instead.

### Binding persistence or processing now

Target-native feature-owned files under `/setting` are the strongest future
persistence substrate, but no Creative Look path/owner/mount-lifecycle contract
is proved. Existing Backup records are already owned and no safe 164-byte ID is
available. Processing is weaker: no full-state Creative Look consumer reaches
live view, still encoding, or movie. Both remain separate future milestones.

## Verification strategy

Development is test-driven. Tests must first fail for missing target profile,
missing target shell exports, wrong layouts, unresolved symbols, or forbidden
outputs before production code is added.

Required verification includes:

1. official archive checksum and exact compiler identity;
2. hosted C99 tests of shell lifecycle, frame-copy lifetime, attach/detach
   lifetime, stale-sink rejection, event forwarding, and reentrancy failure;
3. freestanding ARM compilation of all four C modules;
4. natural ARM relocatable link and empty `nm -u`;
5. ELF header, ARM attribute, section, relocation, symbol, and output-type
   validation;
6. mutation tests for hard-float, wrong architecture, executable/shared output,
   one deliberate undefined symbol, exported proposed factory, forbidden Sony
   loader references, and incorrect ABI offsets;
7. the existing native core/view/bridge suite, safety suite, Python compilation,
   and diff checks; and
8. full analysis discovery at the publication gate, with any timeout reported
   exactly rather than treated as success.

The source allowlist for the target object is limited to the five Creative Look
headers/sources and generated test-only ABI probes. No Sony binary is executed
to produce or validate the object.

## Acceptance criteria

The milestone is accepted only when all of the following are true:

- the official toolchain archive is digest-verified before extraction;
- the exact four production modules compile with the pinned target profile;
- the naturally linked object is ARM EABI5 `ET_REL` with the expected target
  attributes and no unresolved symbols;
- target ABI sizes, alignment, and adapter offset match the table above;
- the neutral shell passes hosted ownership/lifecycle tests;
- no Sony factory, menu, persistence, processing, device, package, or install
  binding appears in production symbols or references;
- all safety values remain zero; and
- documentation labels the output target-compiled but runtime-unbound.

Completion of this milestone does not satisfy the overall project goal. The
next independent implementation priorities are a caller-injected atomic file
persistence adapter and a separately proven still-processing consumer; neither
is implied by this object.
