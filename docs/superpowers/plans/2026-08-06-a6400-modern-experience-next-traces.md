# α6400 Modern Experience Next Static Traces

**Goal:** Resolve the smallest high-value α6400 UI boundary and independently map reusable first-class preset/state infrastructure for a future Creative Look experience, without promoting incomplete metadata into feature or recovery claims.

## Constraints

- Use only the canonical repository under `C:\Users\Bubble\ChatGPT`.
- Static/offline only: no camera access, Sony camera-binary execution, USB or partition writes, firmware packaging, or flashing.
- Keep Sony binaries, raw graphs, disassembly, and proprietary resources under ignored `.artifacts/` roots.
- Commit metadata summaries and validators only; never print or commit raw key material.
- Creative Style remains fallback-only and cannot establish first-class Creative Look.
- Recovery remains `BLOCKED_STATIC_EVIDENCE`; no result here may set `installable`, `recovery_validated`, or `camera_test_eligible`.

## Task 1: Resolve the orientation/layout twin terminals

**Source:** exact α6400 2.00 `lib/viewUnified2.so`, size `11530552`, SHA-256 `1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2`.

**Pinned tracks:**

- Orientation track: root `0x1bb41c`, direct predecessor through `0x1b9b44`, terminal site `0x1b9b6a`.
- Layout-attach track: root/caller `0x1bb2d2`, terminal site `0x1bb30e`.

Steps:

1. Add failing exact-membership, address, provenance, ambiguity, and anti-promotion tests.
2. Implement a strict metadata validator for exactly these two tracks.
3. Extend the read-only Ghidra boundary only enough to classify a unique constant vtable/function-pointer target; preserve every ambiguous result as `UNRESOLVED`.
4. Export a bounded ignored artifact and derive a committed summary with no instructions, bytes, decompiler text, or table contents.
5. Set `orientation_layout_selector_found` and `orientation-layout-selection` true only if one complete ordered path connects a confirmed orientation handler to a layout attach/factory or pinned vertical-layout owner. Two independently resolved terminals are insufficient without the connecting path.
6. Run focused and full tests, safety scans, independent review, and commit.

## Task 2: Trace reusable Picture Profile preset/state infrastructure

**Source:** exact α6400 2.00 `lib/CautionConfig.so`, SHA-256 `bfd1bd7bad0ab3478b894da5dbb51c15464b1bedc4201240ccb61cd743150ef7`.

**Pinned roots:** Picture Profile selector, clone/copy, Gamma, and Color Mode subnode functions, plus named `PP1` through `PP9` global nodes. Normalize Thumb-tagged ELF addresses before applying the pinned load bias.

Steps:

1. Add failing tests for exact roots/nodes, call/reference bounds, source identity, Creative Style exclusion, and false processing/output claims.
2. Implement a strict Picture Profile trace validator and bounded exporter contract.
3. Export only metadata for direct calls, data references, and unresolved indirect edges; do not export resource/table contents.
4. Treat named slots, copy classes, or UXC references as candidates only. Persistence requires a separately identified state write/read path; output binding requires a static path into live-view, still-JPEG, or movie processing.
5. Classify only reusable target interface/state primitives. Keep `base_look_processing`, `live_view_binding`, `still_jpeg_binding`, and `movie_binding` false unless independently proven.
6. Run focused and full tests, safety scans, independent review, and commit separately from Task 1.

## Review checkpoint

After both traces, compare their results against `analysis/a6400-modern-ui-contract.json` and `analysis/a6400-creative-look-stack.json`. Promote only the exact behavior/layer supported by a complete typed path. If both remain unresolved, preserve the negative result and select the next smallest boundary rather than broadening the search or designing camera steps.
