# α6400 UI Owner Registration and Picture Profile Clone Plan

## Objective

Continue the offline α6400 UI/touch and first-class Creative Look research at the
two smallest unresolved boundaries left by the verified layout-factory and Picture
Profile hand-off slices:

1. determine whether typed ELF relocation or symbol evidence registers the unnamed
   `viewUnified7.so` owner at `0x529cc`, which directly forwards to the five-way
   vertical layout factory at `0x52840`; and
2. bind `CmnViewSettingNodePictureProfile::clone()` to its exact copy-constructor
   import and typed interface registration without promoting clone evidence into
   selected-slot state, persistence, processing, or Creative Look support.

This plan remains static and offline. It does not authorize executing Sony camera
code, connecting a camera, writing USB or camera storage, packaging firmware,
flashing, or printing proprietary bytes or key material.

## Evidence Baseline

- `lib/viewUnified7.so`: 541,024 bytes, SHA-256
  `c48cde43ff22d808ad23c42019ddae516fff7da060004eb81ed2bb85012aa538`.
- Factory range `0x52840-0x529b8`; sole direct caller range
  `0x529cc-0x529e8`; exact edge `0x529d6 -> 0x52840`.
- No direct caller of `0x529cc`, no symbol/export name, and no direct path from
  the orientation or layout-mode owners to `0x529cc` or `0x52840` within depth 32.
- `lib/CautionConfig.so`: 12,070,800 bytes, SHA-256
  `bfd1bd7bad0ab3478b894da5dbb51c15464b1bedc4201240ccb61cd743150ef7`.
- Picture Profile clone range `0x7ebbe0-0x7ebc04` in analysis coordinates, with
  exact direct edges `0x7ebbe8 -> 0x7c7528` and
  `0x7ebbf0 -> 0x7c3540`.
- The second clone target is mapped by ELF PLT relocation metadata to the Picture
  Profile copy constructor. PP1-PP9 property-list references remain construction
  metadata only.

## Task 1: UI Owner Registration Tests

Create fail-closed tests for a metadata-only UI owner-registration export. Require:

- exact source identity and read-only/source-unchanged mode;
- exact `.ARM.exidx` owner ranges and forwarding edge;
- exact zero direct callers of `0x529cc`;
- typed relocation, symbol, or section-membership evidence for any accepted indirect
  registration reference;
- an explicit empty result when no typed registration is present;
- exact direct-path negative summaries for the pinned orientation and layout-mode
  roots, bounded to depth 32;
- rejection of arbitrary pointer scans, bytes, disassembly, writable/device fields,
  unbounded graphs, forged digests, and promoted selector/touch claims; and
- strict ignored-artifact output containment.

The tests must fail before implementation.

## Task 2: UI Owner Registration Export

Implement a deterministic ELF/Capstone metadata exporter using section offsets,
`.ARM.exidx`, dynamic/static symbols, and typed relocation records. Do not treat an
integer equal to `0x529cc` or `0x529cd` in arbitrary data as a pointer unless an ELF
relocation or typed symbol/section record establishes that interpretation.

Write only normalized addresses, owner ranges, edge types, relocation types,
symbol names when present, counts, and completeness flags to the ignored artifact.
Hash the exact source before and after and fail if it changes.

## Task 3: UI Report and Claim Gate

Commit a normalized report that distinguishes:

- `vertical_layout_factory_found=true`;
- `factory_forwarding_owner_found=true`;
- `orientation_layout_selector_found=false`;
- `touch-coordinate-transform=false`;
- `menu-touch-hit-test=false`; and
- `menu-touch-selection=false`.

If no typed registration is found, conclude only that the bounded typed evidence
stops at an unnamed forwarding owner. Do not claim that no indirect, callback,
dataflow, or cross-module route exists.

## Task 4: Picture Profile Clone Tests

Create fail-closed tests for a metadata-only clone boundary. Require:

- exact source identity and read-only/source-unchanged mode;
- exact clone owner/range and exactly two direct edges;
- exact PLT relocation mapping of the copy edge to
  `CmnViewSettingNodePictureProfile`'s copy constructor;
- semantic classification of the other imported target only when its exact dynamic
  symbol supports it;
- typed relocation or symbol evidence for any vtable/interface registration;
- explicit separation from PP1-PP9 construction-only property-list references; and
- all selected-slot, persistence, processing, output, interface-reuse, state-reuse,
  and first-class Creative Look claims false.

The tests must fail before implementation.

## Task 5: Picture Profile Clone Export and Report

Implement the smallest deterministic static exporter that satisfies Task 4. Prefer
ELF relocation and symbol evidence; use the existing read-only/no-analysis Ghidra
artifact only for edges that cannot be represented accurately by ELF metadata.
Every committed count and digest must reconstruct from the ignored raw artifact.

The conclusion must say that node-copy behavior is established only if the exact
copy-constructor mapping verifies. It must not imply selected-profile state,
persistence, processing, or Creative Look behavior.

## Task 6: Review and Verification

Run focused tests, then the full analysis and safe suites, compile the affected
modules, run `git diff --check`, and rehash both exact source modules. Request an
independent read-only review for each slice. Commit the UI and Picture Profile slices
separately only after clean review and verification.

## Next Decision

- If typed UI registration exists, trace its owning table/class and the first
  ordered state input without crossing an indirect ambiguity.
- If no typed UI registration exists, search cross-module imports/exports and
  resource-declared factories before considering any arbitrary data scan.
- If a Picture Profile vtable/interface registration exists, trace only its typed
  call sites toward a selected-slot read/write boundary.
- If clone evidence stops at construction/interface metadata, move to the module
  that consumes Picture Profile configuration and require a paired save/load path
  before claiming persistence.

External recovery remains `BLOCKED_STATIC_EVIDENCE`; no candidate becomes
installable or camera-test eligible under this plan.
