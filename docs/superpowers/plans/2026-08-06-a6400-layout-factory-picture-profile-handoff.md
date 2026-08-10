# α6400 Layout Factory and Picture Profile Hand-off Traces

**Goal:** Resolve the smallest remaining target-native hand-offs for portrait UI construction and first-class preset/state reuse, without treating factories, compiled node construction, or resource names as complete behavior.

## Constraints

- Work only under the canonical `C:\Users\Bubble\ChatGPT` workspace.
- Static/offline only: no camera access, Sony camera-binary execution, USB/device/partition writes, packaging, or flashing.
- Keep binaries, raw graphs, disassembly, and proprietary resource contents under ignored `.artifacts/` roots.
- Commit only bounded metadata, validators, tests, and conclusions; never commit reconstructive code/data or raw key material.
- Creative Style remains fallback-only. Picture Profile may be evaluated only as target-native reusable infrastructure, not as Creative Look proof.
- Recovery remains `BLOCKED_STATIC_EVIDENCE`; every report must keep `installable` and `camera_test_eligible` false.

## Task 1: Trace the `viewUnified7.so` vertical-layout factory hand-off

**Source:** exact α6400 2.00 `lib/viewUnified7.so`, size `541024`, SHA-256 `c48cde43ff22d808ad23c42019ddae516fff7da060004eb81ed2bb85012aa538`.

**Pinned factory:** function `0x52840`, with one call to each vertical-classical constructor:

- header-manual-info at site `0x52914`;
- error at site `0x52924`;
- info at site `0x52934`;
- footer at site `0x52944`;
- manual at site `0x52954`.

**Pinned upstream terminals:**

- `getCameraOrientation()` owners `0x2d2c6` and `0x30750`;
- status-orientation owners `0x189dc`, `0x1b070`, and `0x1c56c`;
- `UserGetLayoutMode()` has 28 sites across 15 owners and no direct owner overlap with `0x52840`.

Steps:

1. Add failing exact-identity, exact-five-constructor, graph-bound, ambiguity, and anti-promotion tests.
2. Implement a read-only/no-analysis metadata exporter and validator rooted at `0x52840`, its bounded reverse callers, and only the pinned orientation/layout-mode owners.
3. Export direct local call edges and unresolved indirect terminals only; retain branch/value classification as metadata, never instructions, bytes, or decompiler text.
4. Establish `vertical_layout_factory_found` only for the exact five-way factory. Keep `orientation_layout_selector_found`, touch-coordinate transformation, hit testing, and touch selection false unless one ordered path connects an orientation read through selector/state propagation to `0x52840` or an equivalent attach owner.
5. Run focused and full offline tests, safety scans, independent review, and commit separately.

## Task 2: Trace the Picture Profile construction-to-state hand-off

**Source:** exact α6400 2.00 `lib/CautionConfig.so`, size `12070800`, SHA-256 `bfd1bd7bad0ab3478b894da5dbb51c15464b1bedc4201240ccb61cd743150ef7`.

**Pinned construction owner:** `_INIT_3` at analysis address `0x8351f8` (ELF address `0x8251f8`), with exactly two constructor-parameter references to each PP1–PP9 node at sites `0x85285e` through `0x85297a`.

**Pinned hand-off candidates:**

- PP property-list objects: PP1 `0x9816b0`, PP2 `0x981728`, PP3 `0x9817a0`, PP4 `0x981818`, PP5 `0x981890`, PP6 `0x981908`, PP7 `0x981980`, PP8 `0x9df610`, PP9 `0x981a40`; each has size `120`.
- shared subnode callee `0x7c81a0`;
- clone callees `0x7c7528` and `0x7c3540`;
- `share/app/viewPictureProfile.uxc`, size `1292`, SHA-256 `66a66c2b800331e8a76246321888a3264f0249b48aa51df86c8686d4076f2d71`.

Steps:

1. Add failing exact-membership, object-size, reference-type, resource-identity, and anti-promotion tests.
2. Implement a metadata-only exporter/validator restricted to the 18 constructor-parameter sites, references to/from the nine property-list objects, the five existing PP roots, and exact UXC class/resource references.
3. Classify interface support only when a UXC class/resource reference is owned by a PP menu handler that reaches selector/copy roots.
4. Classify state support only when an ordered selected-slot/clone path reaches a specific property-list read and a same-family setter/write. Constructor wiring alone is insufficient.
5. Classify persistence only when the same state path reaches an identified configuration-save writer and a matching load/readback path.
6. Keep base-look processing, live-view, still-JPEG, movie, and first-class Creative Look claims false unless independently proven.
7. Run focused and full offline tests, safety scans, independent review, and commit separately.

## Review checkpoint

Compare both reports with `analysis/a6400-modern-ui-contract.json` and `analysis/a6400-creative-look-stack.json`. Promote only a fully typed, ordered path satisfying the relevant acceptance rule. Otherwise preserve the bounded primitive, record the exact missing hand-off, and select the next smallest owner rather than broadening the search.
