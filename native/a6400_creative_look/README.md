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

The core is the native product-state layer only. A future target adapter still
needs to bind:

1. the α6400 view/factory lifecycle to this state;
2. concrete touch and orientation events to its transition functions;
3. a proven target persistence record to `cl_encode`/`cl_decode`; and
4. the selected Look and eight axes to live-view, still-JPEG, and movie
   processing consumers.

The compile-time boundary remains unambiguous:

- `CL_PROCESSING_BINDING_UNBOUND = 0`
- `CL_RECOVERY_VALIDATED = 0`
- `CL_CAMERA_TEST_ELIGIBLE = 0`
- `CL_INSTALLABLE = 0`

No camera build, package, or test is authorized by this source.

## Offline verification

`tests/analysis/test_creative_look_native_core.py` compiles the source twice:
as a host shared library for behavioral conformance and as a freestanding C99
object with warnings treated as errors. It then compares the native transitions
to the Python reference model and mutation-tests the persistence decoder.
