# α6400 Creative Look Native Core

This directory contains the portable C99 state and interaction core for the
offline α6400-native Creative Look implementation. It is allocation-free,
freestanding-compatible, and uses only fixed-width integer fields.

It implements:

- the fixed `ST, PT, NT, VV, VV2, FL, FL2, FL3, IN, SH, BW, SE` order;
- six independent Custom slots;
- landscape and both portrait orientations;
- catalog, Custom-base, editor, and axis-picker states;
- all eight exact adjustment ranges and unknown/default sentinels;
- modified markers, per-Look reset, and the complete restriction matrix; and
- a strict 164-byte, versioned, CRC-32-protected persistence blob.

`creative_look_view.c` adds a fixed 20-element presentation frame, integer
layout in logical milli-units, stale-frame-resistant touch dispatch, and
caller-owned presentation/storage callbacks. It remains allocation-free and
does not name or link any Sony class, event, storage record, or processor.

The runtime state is 155 bytes. It performs no allocation, file I/O, dynamic
loading, networking, USB access, image processing, or firmware operation.

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

This blob has no assigned α6400 Backup record, filesystem path, or Sony storage
identity. A future persistence adapter must prove that target binding before it
can consume or emit the blob on camera.

## Integration boundary

The core and view adapter are the portable product-state and interaction
layers only. A future target integration still needs to bind:

1. the α6400 view/factory lifecycle to this state;
2. concrete target touch/orientation delivery to `cl_view_touch` and
   `cl_view_present`;
3. a proven target persistence record to `cl_storage_load`/`cl_storage_save`;
   and
4. the selected Look and eight axes to live-view, still-JPEG, and movie
   processing consumers.

The compile-time boundary remains unambiguous:

- `CL_PROCESSING_BINDING_UNBOUND = 0`
- `CL_RECOVERY_VALIDATED = 0`
- `CL_CAMERA_TEST_ELIGIBLE = 0`
- `CL_INSTALLABLE = 0`

No camera build, package, or test is authorized by this source.

## Offline verification

`tests/analysis/test_creative_look_native_core.py` and
`tests/analysis/test_creative_look_native_view.py` compile the sources as a
host shared library and as freestanding C99 objects with warnings treated as
errors. They compare transitions and all four native frames against the Python
reference model, drive touch-only interaction, exercise adapter failures, and
mutation-test the persistence decoder.
