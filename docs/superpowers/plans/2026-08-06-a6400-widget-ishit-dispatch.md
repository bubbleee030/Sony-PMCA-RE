# α6400 Widget `isHit` Dispatch Plan

## Objective

Establish exact local virtual-call shapes through widget vtable slot 37 (`+0x94`)
and determine whether any accepted dispatch owner is directly connected to pinned UI
roots or known touch-API caller owners.

This plan is static/offline only. It does not authorize Sony code execution,
camera/USB access, device or partition writes, package construction, flashing, raw
instruction or byte output, or key-material output.

## Task 1: Fail-Closed Contract Tests

Use TDD to require:

- exact `viewUnified2.so` identity and source-unchanged read-only mode;
- canonical linkage to the widget-hit-test-vtable and touch-API-caller artifacts;
- complete `.ARM.exidx` accounting: 30,463 entries = 28,869 fully decoded + 1,593
  decode-incomplete + one terminal-without-successor;
- a structural rule confined to one bounded owner: receiver-vptr load, function load
  from `[vptr + 0x94]`, and indirect call through the same loaded register;
- the exact ten accepted slot-load/call pairs in five ELF-coordinate owners:
  - owner `0x310cd8`: `0x310d02->0x310d06`, `0x310d70->0x310d74`,
    `0x310d9e->0x310da2`, `0x310dcc->0x310dd0`;
  - owner `0x35f66c`: `0x35f676->0x35f67a`;
  - owner `0x3e11d4`: `0x3e1322->0x3e1328`;
  - owner `0x56cf24`: `0x56cf8a->0x56cfa4`, `0x56cfca->0x56cfe8`;
  - owner `0x5b7424`: `0x5b748a->0x5b74a4`, `0x5b74ca->0x5b74e8`;
- source-derived receiver-vptr load sites for every accepted record;
- nine exact stack-derived `+0x94` rejection sites `0x237926`, `0x2397a4`,
  `0x2c0bb4`, `0x2c2c3e`, `0x4c3450`, `0x4c3cd4`, `0x53258a`, `0x5333ac`,
  and `0x54de94`; the earlier five-site subset remains highlighted only as recon
  history and is not the complete rejection population;
- exactly 361 direct PC-relative `+0x94` false positives, with a canonical address
  digest but no instruction text or bytes;
- explicit `0x10000` analysis-load-bias mappings for every pinned root and known
  touch caller, mechanically linked to the prior artifacts, with graph traversal
  performed only in normalized ELF coordinates;
- direct-only depth-32 zero paths from `ViewSettingMenuEventSwitch` and the three
  pinned ViewStlrec roots to accepted owners; and
- zero direct paths in either direction between accepted owners and the exact 16
  known touch-API caller owners.

Reject fabricated receiver provenance, arbitrary pointer scans, concrete
widget/vtable/object identity, coordinate/hit-result/gesture/menu-selection
promotion, unsafe fields, output escape, installation, or camera testing.

## Task 2: Deterministic Static Export and Report

Implement a read-only ELF/Capstone exporter that derives exidx coverage, accepted
vptr/slot/call records, bounded rejection metadata, canonical PC-literal digest,
prior digests, and direct path results. Do not emit instruction text or bytes and do
not classify incomplete owners as negative coverage.

Write only a safe ignored raw artifact beneath a fixed repository artifact root;
reject literal, resolved, symlink, dangling-symlink, and pre-creation ancestor
escape. Commit a compact safe report that establishes generic slot-37-shaped
dispatch only; concrete widget identity and menu touch selection remain unresolved.

## Task 3: Review and Verification

Independently review the structural register provenance, ten accepted records, nine
stack rejections, 361-literal digest, coverage accounting, both path searches,
prior linkage, behavior claims, and containment. Re-run the exact exporter, verify
source hashes before and after, run focused and full analysis/safe tests, compile
changed modules, and run `git diff --check` before committing.

If clean, continue from a typed owner/object reference for one accepted dispatcher.
Recovery remains `BLOCKED_STATIC_EVIDENCE`; this result is not installable or
camera-test eligible.
