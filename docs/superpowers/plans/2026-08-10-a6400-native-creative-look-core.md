# α6400-Native Creative Look Core Plan

## Objective

Implement the already-validated Creative Look product behavior as portable C99
source suitable for later integration into an α6400-native view/model adapter.
The core is built and executed only as a host-side offline test artifact in this
milestone. It is not packaged for a camera.

## ABI and state

- Fixed membership: 12 built-ins, six Custom slots, eight axes.
- Fixed-memory state with no allocation, I/O, threads, exceptions, or runtime
  library dependency beyond integer types.
- Exact screens and orientations from the Python reference model.
- Exact mode restrictions and per-axis ranges.
- `INT8_MIN` represents an unknown/default axis value; no Sony default number
  is invented.
- Custom-base unset and editing-axis unset use explicit byte sentinels.
- Every mutation returns a stable result code and leaves invalid input
  fail-closed.

## Persistence

Define a 164-byte little-endian version-1 blob:

- four-byte `CLK1` magic;
- version, selected Look, screen, orientation, editing axis, and mode bits;
- six Custom-base bytes;
- 144 adjustment bytes (`18 * 8`); and
- CRC-32 over the first 160 bytes.

Decode rejects wrong size, magic, version, CRC, enum values, ranges,
inconsistent Custom/editor state, invalid restriction state, and reserved mode
bits. This is a portable persistence format only; no α6400 Backup record ID or
filesystem location is assigned without evidence.

## Safety boundary

Compile-time capability constants remain:

- processing binding: unbound;
- recovery validated: false;
- camera-test eligible: false; and
- installable: false.

The core exposes no camera transport, firmware, updater, partition, package,
loader, dynamic-library, or image-processing function.

## Verification

1. Write tests that compile the source as a strict C99 shared library and a
   freestanding object with warnings as errors.
2. Drive the same Custom/edit/restriction/reset/orientation sequence through
   Python and C, then require identical logical state.
3. Round-trip the exact persistence blob and reject mutations to every field
   class and the CRC.
4. Scan source imports/tokens to enforce the safety boundary.
5. Run focused, full-analysis, safety, compile, deterministic, and whitespace
   gates before publication.
