# α6400 Creative Style Definition and Registration Plan

## Objective

Establish the target-native Creative Style root, publication data graph, typed class
interface, and broad loader boundary in `CautionConfig.so`, while separating those
facts from unproven root construction, selected state, persistence, image
processing, output, or Creative Look behavior.

This plan is static/offline only. It does not authorize Sony code execution,
camera/USB access, device or partition writes, package construction, flashing, raw
instruction or byte output, or key-material output.

## Task 1: Fail-Closed Contract Tests

Use TDD to require:

- exact `CautionConfig.so` identity and source-unchanged read-only mode;
- defined global STT_OBJECT dynsym 31507 `cmnViewSettingNodeRootCreativeStyle` at
  ELF `0xc5ae38`, size 40, `.bss`, with analysis coordinate `0xc6ae38`;
- typed root properties at dynsym 59076 (`0xc10a38`, size 8, `.bss`) and property
  list at dynsym 64985 (`0xa54050`, size 96, `.rodata`);
- exact publication relocation `.rel.dyn` index 87605, `R_ARM_ABS32`, site
  `0xb8a3bc` -> root symbol 31507, located at offset `0x3c` inside global STT_OBJECT
  dynsym 11778 `cmnViewSettingNodesRootDefault` (`0xb8a380`, size 1660, `.data`);
- distinct root/property/list GOT bindings at relocation indices 87604, 170252,
  and 175923 with exact sites `0xb1111c`, `0xb3a864`, and `0xb3d498`;
- exact C1/C2 aliases at Thumb `0x7dba41`, size 52; selector `_getSubNode` at Thumb
  `0x7db959`, size 232; their exact PLT/JUMP_SLOT records and decoded stubs;
- Creative Style vtable dynsym 63566 at `0xac8900`, size 268, address point
  `0xac8908`, with 67 words/66 typed relocations and exact GLOB_DAT binding index
  134297/GOT `0xb28a90`;
- exact class-interface parity only for inherited selection slots 12–14/39–41,
  state slots 21–23, setter slots 48–51/63, lifecycle slots 58/60–62, and own clone
  slot 59 at relocation index 81185 / ELF owner `0x7db934` / analysis `0x7eb934`;
- canonical linkage to the verified Picture Profile vtable/generic-consumer and
  initializer-registration artifacts;
- broad loader registration only through `.init_array` index 3 at `0xaa629c` ->
  Thumb `0x8251f9`, exidx owner ELF `0x8251f8` / analysis `0x8351f8`; and
- zero Creative Style dynamic symbols combining its exact name fragments with
  save/load/write/read/store/restore/persist/serialize verbs.

Reject fabricated root constructor calls, selected-state/persistence/processing/
output paths, Creative Look promotion, unsafe fields, output escape, digest forgery,
installation, or camera testing.

## Task 2: Deterministic Static Export and Report

Implement a read-only ELF metadata exporter that derives all symbols, sections,
relocations, object containment, PLT bindings, vtable interface slots, prior
digests, initializer linkage, and bounded negative symbol scan from the pinned
source. Do not infer constructor invocation from a PLT binding or broad initializer
membership.

Write only a safe ignored raw artifact beneath a fixed repository artifact root;
reject literal, resolved, symlink, dangling-symlink, and pre-creation ancestor
escape. Commit a safe report with publication and class-interface evidence true,
but root constructor binding, selected state, persistence, processing, output, and
first-class Creative Look false.

## Task 3: Review and Verification

Independently review symbol indices/attributes, section membership, object-relative
publication, GOT/PLT mappings, vtable slots, prior linkage, broad loader scope,
negative claims, and containment. Re-run the exact exporter, verify source hashes
before and after, run focused and full analysis/safe tests, compile changed modules,
and run `git diff --check` before committing.

If clean, continue from a provenance-validated path jointly tying the exact root,
properties/list, and C1/selector to state consumers. Recovery remains
`BLOCKED_STATIC_EVIDENCE`; this result is not installable or camera-test eligible.
