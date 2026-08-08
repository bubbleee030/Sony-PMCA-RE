# α6400 Mouse-Post Producer Boundary Design

## Status and relationship to existing work

Approved under the standing instruction to follow the recommended static path.
This design extends the touch-input workstream without changing the α7 V
Creative Look contract, target-feature availability, or recovery gate.

The work remains static and offline. It does not authorize camera access, Sony
camera-binary execution, updater or service-mode entry, partition writes,
firmware generation, installation, or operational camera instructions.

## Decision

Create a standalone, fail-closed mouse-post producer-boundary artifact instead
of enlarging the Creative Style interaction exporter. The artifact records what
the authenticated target corpus establishes about producers of
`WidgetSystem::postMouseMove`, `postMousePress`, and `postMouseRelease`, and
where the evidence stops.

The boundary is useful only if it distinguishes four statements:

- the three public APIs are defined in the target corpus;
- their records can enter the already validated queue and widget-delivery path;
- a bounded static scan does not identify a producer or queue-processor
  invocation; and
- the negative scan is not a proof that no runtime, computed, opaque, or
  out-of-corpus producer exists.

Only the first two statements are positive static evidence. Raw input delivery,
actual runtime input, Creative Style object identity, and Creative Look behavior
remain unestablished.

## Considered approaches

### Selected: standalone boundary report

Use a dedicated validator, read-only exporter, tests, and checked report. Pin a
dependency on the current Creative Style interaction report so the producer
boundary cannot be interpreted without the already validated queue/delivery
chain. This keeps the slow corpus scan out of the interaction exporter's source
mutation loop and gives the negative scope an explicit contract.

### Rejected: fold the scan into the interaction exporter

This would place a firmware-universe publication scan inside an exporter that
already validates unrelated layout, cast, constructor, grid, selection, and
delivery facts. It would couple the scan to every interaction mutation test and
make the first unresolved edge harder to review.

### Rejected: prose-only deep-dive update

Prose would document the current result but would not reproduce source identity,
ELF-universe membership, symbol scope, or direct-call coverage. A later edit
could promote API presence to raw-input delivery without a mechanical failure.

## Evidence baseline

The source universe is the authenticated α6400 Taiwan/region-0 2.00
`nflasha15_unpacked` tree already used by the registry-consumer inventory:

- 799 regular files;
- 324 ELF files;
- 150 shared objects; and
- canonical inventory SHA-256
  `52ec5e8baf523878a417e3a61f9f16484634a9075d1c6afca2ca8c25940d827c`.

The pinned `lib/libObj.so` identity is size 20,860,436 and SHA-256
`60ffd2b0f31f4bc139a7c13a4f62c25cdeb6a531ad5ef35df48471e6e36e88b1`.

The current bounded observations are:

- the three exact dynamic symbols are defined only by `lib/libObj.so`;
- the short names `postMouseMove`, `postMousePress`, and `postMouseRelease`
  occur only in that file;
- no relocation or allocated aligned word outside each symbol-table record
  publishes the three entry points;
- no decoded direct branch in the 59,614 `.ARM.exidx` owner ranges targets the
  three entry points;
- 56,271 owners decode completely and 3,343 do not, so whole-owner direct-call
  absence is not claimed for the incomplete subset;
- the queue processor owner `[0x5f2964,0x5f2a38)` likewise has no decoded direct
  caller, relocation, allocated aligned pointer, or dynamic symbol; and
- bounded ADR, PC-relative literal/add, and MOVW/MOVT materialization scans find
  no reference to the API entries or queue processor.

These observations locate the next edge; they do not establish global non-use.

## Architecture

### 1. Exact contract and checked report

`pmca/analysis/mouse_post_producer_boundary.py` owns immutable source identities,
the expected export shape, normalization, summary, and report validation. The
checked report is `analysis/a6400-mouse-post-producer-boundary.json`.

The report depends on the canonical export digest from
`analysis/a6400-creative-style-interaction-surface.json`, currently
`cd7c0f1df911248492ddb6542d2b9f225b7ec4a408a910fe896722a83277fa53`.
The dependency joins the producer scan to the established
public-API-to-queue-to-hit/delivery chain, without copying that chain or
weakening any of its false claims.

### 2. Read-only exporter

`tools/static/export_a6400_mouse_post_producer_boundary.py` performs three
bounded scans:

1. validate the canonical 799-file inventory and enumerate the 324 ELF dynamic
   symbol tables;
2. validate exact short-name occurrence scope across all regular files; and
3. validate libObj direct-call, relocation, allocated-pointer, and bounded
   address-materialization scope for the three API entries and queue processor.

The exporter reads only regular, non-symlink source files. It hashes the pinned
sources before and after analysis, builds and validates all metadata in memory,
and writes only JSON under the ignored `.artifacts` root plus the derived
checked report through an atomic replacement.

The expensive source scans are pure functions returning immutable records. A
cache may be keyed only by the validated canonical inventory digest and pinned
libObj SHA-256; a changed inventory or source must be rejected before a cached
result is used.

### 3. Claim boundary

The positive claims are limited to:

- `public_mouse_post_api_definitions_found=true`;
- `public_api_to_existing_queue_delivery_dependency_found=true`; and
- `bounded_static_producer_inventory_complete=true` for the explicitly named
  scan methods and source universe.

The following remain false:

- `raw_mouse_input_producer_found`;
- `queue_processor_invocation_found`;
- `runtime_mouse_input_delivery_proven`;
- `creative_style_touch_route_found`;
- `creative_look_touch_route_found`;
- `runtime_execution_proven`;
- `installable`; and
- `camera_test_eligible`.

Readiness is
`PUBLIC_MOUSE_POST_PIPELINE_PROVEN__RAW_INPUT_PRODUCER_UNRESOLVED`. The first
unresolved edge is
`external-computed-or-opaque-input-producer-and-queue-processor-invocation`.

### 4. Human-readable integration

Update `analysis/a6400a-updater-and-creative-style-deep-dive.md` with one bounded
paragraph after the existing mouse-post pipeline discussion. It must state that
the producer scan is negative only within the named symbol, direct-branch,
relocation, aligned-pointer, and address-materialization methods. It must not
describe the result as proof of no runtime producer.

## Data model

The raw export contains exactly:

- `schema_version`;
- `analysis_mode`;
- `firmware_inventory`;
- `source`;
- `interaction_dependency`;
- `public_apis`;
- `symbol_universe`;
- `libobj_publication_scan`;
- `queue_processor`;
- `first_unresolved_boundary`;
- `claims`; and
- `truncated`.

Each public API record contains its role, exact symbol, dynsym index, Thumb
entry, normalized entry, size, and symbol-definition scope. The symbol-universe
record contains only module paths, symbol roles, definition/import status, and
short-name file counts. It does not contain file contents.

The libObj scan records method names, owner-coverage counts, and empty or
populated metadata lists. Any producer candidate must be preserved with its
site, containing owner, method that found it, and completeness classification;
the exporter must then fail until the contract is deliberately reviewed and
updated.

## Error handling and claim discipline

- Reject any inventory count or canonical digest change.
- Reject missing, duplicated, reordered, hidden, undefined, or additional
  postMouse symbols.
- Reject any external ELF import or definition of the exact symbols until it is
  independently classified.
- Reject any additional short-name file occurrence until it is classified.
- Reject any direct call, relocation, allocated pointer, or bounded address
  materialization to an API entry or queue processor until reviewed.
- Record incomplete owner coverage explicitly; never convert it to a global
  absence claim.
- Reject a report that sets a runtime, Creative Style, Creative Look,
  installability, or camera-eligibility claim true.
- Never store firmware contents, disassembly text, decompiler text, keys,
  reconstructive data, or executable payloads in the checked artifact.

## Testing strategy

### Contract tests

- require the exact source, inventory, API order, scan methods, owner counts,
  unresolved-edge identifier, and fail-closed claims;
- reject fabricated external consumers, missing incomplete-owner counts, and
  any runtime or feature promotion; and
- prove validated values are deep copies.

### Exporter tests

- run the real pinned-source export when dependencies and artifacts exist;
- mutate an in-memory scan result to add a direct caller, external import,
  short-name file, relocation, pointer publication, and queue-processor
  publication, requiring a specific validation failure for each;
- mutate the interaction dependency digest and require failure; and
- prove source identities are unchanged by the exporter.

Slow firmware and decode scans may be replaced in mutation tests only after one
real integration export proves the complete fixture. Tests assert validation
outcomes, not mock call counts.

### Integration verification

- regenerate twice and compare canonical output hashes;
- run the focused producer-boundary tests and existing interaction tests;
- run the complete analysis and safety suites;
- run `py_compile`, `git diff --check`, and proprietary-artifact guards; and
- confirm the branch remains non-installable and camera-ineligible.

## Acceptance

This slice is complete when the standalone report mechanically reproduces the
bounded producer inventory, depends on the current interaction evidence,
identifies the exact unresolved producer/processor edge, rejects every tested
promotion, regenerates deterministically, and passes the full analysis and
safety gates. It does not complete the wider goal and cannot authorize camera
testing.
