# α6400 dispatcher-table container provenance plan

## Goal

Classify the `.data.rel.ro` containers that address-take the three verified
generic model-sequence dispatchers, then test whether any exact RTTI, dynamic
symbol, constructor/factory, registration, or Creative Style edge identifies a
concrete owner.

## Static sources

- exact `lib/viewUnified4.so`, size `2,614,628`, SHA-256
  `0fe8f852b0f028ac7d1d55c613726b3949879cf7fdd44074e525ae302a6f2e62`;
- exact `lib/viewUnified7.so`, size `541,024`, SHA-256
  `c48cde43ff22d808ad23c42019ddae516fff7da060004eb81ed2bb85012aa538`;
- the committed generic owner-provenance contract at commit `5886a7f`.

The work remains offline and read-only. It must not access a camera, execute a
Sony camera binary, write a device or USB partition, package or flash firmware,
or emit proprietary bytes, disassembly, or key material.

## Tasks

1. Add fail-closed tests for exact relocation sites, contiguous table windows,
   section ownership, and bounded incoming references to each table base.
2. Classify typed RTTI/vtable evidence only when the ABI header, relocation
   kinds, dynamic object symbol, and type name agree. Otherwise retain the
   weaker `.data.rel.ro` function-pointer-table classification.
3. Record exact `*ToInstance` symbols without treating their names as a proven
   factory/vptr relationship. Keep equal field offsets and neighboring
   relocations structural unless receiver provenance joins them.
4. Test the VU7 table container against the separate `+0x14c` utility
   initializer without inferring class identity from the shared offset.
5. Recheck Creative Style root/type publications for typed or relocation-backed
   edges into the table containers, owners, or initializer.
6. Emit a deterministic report, run real-export, full analysis, safety,
   compilation, diff, and independent-review gates, then commit only the scoped
   research files.

## Acceptance boundary

Positive table membership, RTTI, and constructor links require exact static
edges. Missing or partially decoded references must be described as
non-exhaustive evidence, not proof of absence. No result may promote a generic
dispatcher to Creative Style, a final model commit, renderer, touch route,
persistence path, Creative Look equivalence, installability, or camera-test
eligibility without a separate exact binding.

## Result

- `ViewFocusArea_C`, `ViewCustomZebra`, and `ViewFocusArea` own the three
  dispatchers as typed primary-vtable slot-64 overrides.
- VU7's `ViewFocusArea` primary table also owns the utility initializer at slot
  54; VMI and a secondary vtable place `WrapperSettingUtil` at `+0x140`.
- The VU4 primary callable-slot ranges end before their `-0x28` secondary-table
  headers: 94 slots for `ViewFocusArea_C` and 87 for `ViewCustomZebra`.
- No typed primary-vtable relocation names Creative Style; broader root-edge
  absence is not assessed by this slice. Model commit, renderer, touch,
  persistence, and Creative Look remain unproven.
