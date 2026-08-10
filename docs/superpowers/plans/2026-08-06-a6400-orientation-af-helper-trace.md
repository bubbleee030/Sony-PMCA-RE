# α6400 Orientation/AF Helper Trace Plan

## Objective

Establish the exact `CmnWrpOrientationRegisterAF` wrapper cluster, the bounded
control-flow/dataflow of helper `0x35f424`, and the stable local object storage
returned to the already-proven slot-37-shaped virtual dispatch. Seek a concrete
constructor/vtable/type identity without promoting an unresolved match.

This plan is static/offline only. It does not authorize Sony code execution,
camera/USB access, device or partition writes, package construction, flashing,
raw instruction or byte output, or key-material output.

## Task 1: Fail-Closed Contract Tests

Use TDD to require:

- exact `viewUnified2.so` identity and canonical linkage to the committed
  generic slot-37 dispatch artifact `bf4e9ea3ea1f4841bdcda6ecdf337a9cb064be2b560ace7b533a6a5e7f83f12f`;
- exactly 42 defined global `CmnWrpOrientationRegisterAF` methods, aggregate
  `st_size` 780, and member-table digest
  `9949b0d1da4a57aa2645e00ef7d7b3c8e404761e4bedf488fbb078d897467c2c`;
- exactly 62 direct branches to helper `0x35f424`: 42 typed member sites with
  digest `a0dd30d96733d977fe2c486522773926690195b64838c66d3cfa641f6f07590b`
  and 20 non-member sites with digest
  `b0189feb776434dd5abcdf17ebfaf4408e5b8d9217c9c86b66336a231199fbd1`;
- the 17 exact class-method `R_ARM_JUMP_SLOT` relocation indices and zero
  `.rel.dyn` addends resolving to the 42 member entries;
- exact getter binding: dynsym 1718, rel.plt 254, GOT `0x944aa4`, PLT
  `0x14f1fc`, 15 sites/13 owners, callsite digest
  `f513997145508f2955d32846568272e0aea973fa4f836a33dd59151bf1900e7b`;
- exact setter binding: dynsym 2248, rel.plt 211, GOT `0x9449f8`, PLT
  `0x14efa8`, 42 sites/31 owners, callsite digest
  `fab457060ad1312bc20965ffd865b6eb472887877b1f0bea2fe5f877cae1a8a8`;
- helper exidx range `0x35f424–0x35f494`, with a 76-byte CFG-decoded prefix and
  36 bytes of trailing literal/table data explicitly excluded from linear
  negative coverage;
- two normal CFG branches converging at return `0x35f462`, with every normal
  path rematerializing returned `r0` as local `.bss` storage `0xb2eff4`;
- guard storage `0xb2eff0`, initialization-only GOT participation at `0x9446a0`,
  and the local call to `0x30e9e8` receiving object storage `0xb2eff4`;
- entry `r0/r1/r2` overwritten before use and no LR/callsite-indexed selection;
- no matching class constructor/destructor/ZTV/ZTI/ZTS dynamic symbol, no named
  relocation for the object/guard storage, and no established concrete type,
  vtable, RTTI, selection result, gesture, or menu-touch behavior.

Reject fabricated CFG completeness, constructor/vtable/type identity, arbitrary
pointer scans, unsafe fields, output escape, installation, or camera testing.

## Task 2: Deterministic Static Export and Report

Create a read-only ELF/Capstone exporter that derives the member inventory,
helper-call partition, JUMP_SLOT bindings, bounded CFG/dataflow facts, relocation
correlation, and explicit coverage exclusions. Do not emit instruction text or
bytes, and do not count the literal/table tail as decoded code.

Write only a safe ignored artifact beneath a fixed repository artifact root with
literal/resolved/symlink/pre-creation containment. Commit a compact safe report
that establishes a stable helper-returned local object anchor but leaves its
constructor, concrete widget class, vtable, RTTI, and UI-selection semantics
unresolved.

## Task 3: Review and Verification

Independently review member selection, digests, helper caller partition, CFG
boundaries, returned-object provenance, guard/init evidence, getter/setter
bindings, exclusions, behavior limits, and containment. Re-run the exact exporter,
verify source hashes before/after, run focused and full analysis/safe tests, compile
changed modules, and run `git diff --check` before committing.

If clean, continue with CFG-aware analysis of local callee `0x30e9e8` plus
relocation/object-reference tracing from `.bss` storage `0xb2eff4`. Recovery remains
`BLOCKED_STATIC_EVIDENCE`; this result is not installable or camera-test eligible.
