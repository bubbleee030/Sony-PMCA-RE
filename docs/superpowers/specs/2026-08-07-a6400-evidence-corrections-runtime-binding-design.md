# Sony α6400 Evidence Corrections and Runtime Binding Design

## Status and precedence

This design was approved on 2026-08-07. It is a corrective research slice
under `2026-08-06-a6400-modern-experience-port-design.md`; it does not replace
that document's product goal, hardware exclusions, or external stock-recovery
gate.

The phase remains static and offline. It does not authorize connecting a
camera, executing Sony camera binaries, entering service or updater mode,
writing camera or USB partitions, constructing an installable package, or
flashing firmware. The canonical repository is
`C:\Users\Bubble\ChatGPT\Sony\Sony-PMCA-RE-a6400-analysis`.

## Problem statement

Independent byte-level review found two classes of defects in the current
evidence contracts and exposed one additional runtime boundary that should be
recorded separately.

First, the Creative Style selector report classifies four frame-relative
backup-record ID families as having unresolved initialization and unresolved
numeric IDs. The setter and getter actually copy fixed, value-identical tables
from pinned read-only storage before their backup calls. The static numeric ID
domains and setter/getter table-value equality are therefore established, while
the runtime equality of their independently supplied indices remains
unestablished.

Second, the UI-dispatch and derived target-feature reports treat several
`viewUnified2.so` offsets as class-ID owners or layout factories. Exact Thumb
instruction-boundary and EXIDX-owner validation disproves those labels:

- `0x181f18` is an internal conditional branch, not a function or factory;
- `0x24222c` is the second halfword of a Thumb-2 instruction;
- five alleged per-class ID sites are constructor/vptr-material paths rather
  than class-ID loads; and
- `0x3ba6dc` and `0x651684` are also second halves of Thumb-2 instructions.

A real factory exists in pinned `viewUnified7.so` at `0x52840..0x529b8`. It has
twelve allocation/constructor arms, five of which select the vertical-classical
layout classes. Five address-taken registrations of wrapper `0x529cc` are
proven, but their runtime invoker and any orientation-to-factory join remain
unresolved.

Third, the operation-38 path now has enough exact evidence to describe the
generic ModelManager registration, dynamic loader, executor, and destination-4
boundaries without claiming that the candidate record is ModelCamera or that a
Creative Style field reaches an imaging pipeline.

## Selected architecture

Use three focused evidence units and update downstream summaries from their
validated outputs.

### 1. Correct the existing selector-code contract in place

Keep the existing selector-code module, exporter, report, and tests because the
new findings refine the same typed setter/getter contract. Add exact metadata
and validators for:

- the four setter and four getter table-copy sources and destinations;
- table length, read-only-section containment, and value equality by family;
- the fixed numeric ID rows, represented as bounded scalar metadata rather than
  raw firmware bytes;
- selector argument 1 and ABI fields 3, 4, and 5 reaching their exact backup
  families and getter output positions; and
- the distinction between a static family/value join and an actual runtime
  write-followed-by-read transaction.

The report may promote numeric-ID initialization and static table equality. It
must not promote conventional field names such as contrast, saturation, or
sharpness without a separate label/resource/configuration dataflow edge. It
must keep menu-selected-state identity, runtime index equality, renderer/output
effects, and Creative Look equivalence false.

### 2. Correct UI-dispatch provenance and derived feature summaries

Remove the stale `viewUnified2.so` function/factory-owner interpretation rather
than renaming it cosmetically. Preserve only independently verified facts:

- each of the five vertical-classical IDs occurs once in each pinned UXC
  resource;
- the real `viewUnified7.so` factory owner, group/class literal comparisons,
  five constructor arms, wrapper, and five address-taken wrapper registrations;
- the absence of a proven static `viewUnified2.so` dependency or edge to that
  factory; and
- the exact negative instruction-boundary classifications for the four invalid
  offsets.

The UI report and every derived target-feature/report copy must use the same
corrected vocabulary. A UXC occurrence is a resource reference, not a runtime
owner. An address-taken wrapper registration is not a runtime invocation. The
orientation selector, portrait geometry, control-direction transform, touch
coordinate transform, hit test, and menu selection must remain unresolved.

The existing Creative Style interaction report should be sharpened, not
duplicated. Its bounded widget chain may state that the post-lookup thunk
resolves through the interworking PLT path to `PAS_BtnCombo::cast(Widget*)`.
The cast proves a generic widget-type filter only. Direct initialization of
`ViewCreativeStyle+0x14c` is absent from the bounded derived/default-base
constructors, while the external `ViewBase` constructor keeps concrete field
provenance unresolved.

### 3. Add a focused ModelManager runtime-binding contract

Create a separate evidence module, exporter, report, and test suite rather than
expanding the already large operation-38 transport exporter. The new unit will
consume the transport report only as a pinned upstream reference and validate
the next generic boundaries in `libObj.so`:

- `model/CAMERA` splitting into IdGenerator table `model` and row `CAMERA`;
- `SetTable` and `IdTable::findId`, while retaining the unresolved numeric ID;
- ModelManager descriptor, record-map, factory, and executor lifecycle;
- `dlopen(record+0x10)`, `dlsym(record+0x14)`, the indirect factory call, and
  the returned executor stored at `record+0x1c`;
- the runtime provider boundary that supplies descriptor key, component path,
  and symbol;
- the co-located ModelCamera manifest triple, factory, RTTI, and vtable as a
  compatible candidate without asserting record identity;
- generic executor slot `+0x18`, which schedules event `0x11004001` rather than
  consuming the incoming secondary Event; and
- the destination-4 path into receiver `0x846710`, where `0x11004001` has no
  dedicated switch case and reaches a generic default predicate.

The contract must distinguish proven generic machinery from unresolved
identity. It must keep all of the following false: numeric `model/CAMERA` ID,
record equals ModelCamera, executor equals ModelCamera, concrete operation-38
handler, five-field consumption, live-view binding, still-JPEG binding, movie
binding, native Creative Look processing, runtime behavior, and installability.

## Recovery-boundary update

The recovery evidence should record the new bounded false leads without
weakening the strict gate:

- packaged updater flag-state production and LSI notification are present;
- parsed consumers exist in `up.sh`, `libObj.so`, the nested update body, and
  updater components;
- `bootin.elf` is bounded to normal, adjustment, and USB-charge application
  modes and has no direct updater-selector reference; and
- no recovered parsable component joins updater flag state or the LSI message
  to an `nflasha1` next-boot selector.

The selector may reside in an unavailable updater partition, boot component, or
opaque boundary, so global absence is not claimed. Recovery remains
`BLOCKED_STATIC_EVIDENCE`, with `recovery_validated=false`,
`camera_test_eligible=false`, and `installable=false`.

## Data flow

1. Verify each pinned module's size and SHA-256 before decoding.
2. Validate instruction boundaries, owners, relocations, and direct dataflow
   before assigning semantic labels to an address.
3. Normalize only bounded scalar metadata, symbols, relationships, and negative
   claim flags; never export proprietary instructions, byte arrays, or key
   material.
4. Build each checked-in report from its validator rather than editing JSON by
   hand.
5. Update downstream target-feature and deep-dive summaries only from validated
   report fields.
6. Keep recovery and camera-test gates independent of feature progress.

## Failure handling and claim discipline

- A source digest or size mismatch aborts export.
- A requested offset that is not an instruction boundary cannot be a function,
  factory, caller, or owner.
- Incomplete decoding cannot support a global absence claim.
- A relocation or address-taken cell proves registration/reference only, not
  invocation.
- Identical static tables prove value-domain equality, not runtime argument
  equality or a write/read transaction.
- A conventional Creative Style field order cannot establish human labels.
- A manifest string, factory symbol, RTTI object, and compatible vtable do not
  prove that a runtime descriptor selected that factory.
- A generic scheduler or default event receiver cannot be promoted to a
  Creative Style or Creative Look pipeline handler.
- Missing updater-selector evidence leaves recovery blocked and forbids camera
  testing.

## Verification strategy

### Selector-code corrections

- Mutation tests must alter every table source/copy site, table size, read-only
  range, family value, ID load, backup call, and getter-output transfer.
- Tests must reject promotion of human field names or runtime setter/getter
  equality.
- The fixed `0x01070762` write/read/output join remains independently pinned.

### UI-dispatch corrections

- Tests must assert instruction-boundary and EXIDX-owner truth for every former
  owner/factory offset.
- Tests must reject the stale `uxc_owner_functions` interpretation and any
  downstream copy of it.
- The real `viewUnified7.so` factory tests must cover the group comparison,
  five class comparisons, constructor calls, wrapper forwarding, and five
  relocation-backed wrapper registrations.
- Negative tests must keep orientation, geometry, touch, and menu-selection
  joins false.

### Runtime binding

- Mutation tests must cover name splitting, IdGenerator lookup, record map and
  descriptor fields, dynamic-loader relocations, factory result storage,
  executor virtual dispatch, generic scheduling header, destination-4 routing,
  and default-case selection.
- Tests must separately reject record/ModelCamera identity, literal numeric ID,
  five-field consumption, and imaging-pipeline claims.

### Repository and safety

- Regenerate all affected reports and validate their canonical digests.
- Run focused suites first, then the complete analysis and repository-safety
  suites using the repository `.venv`.
- Run Python compilation and `git diff --check`.
- Confirm the worktree contains no Sony binaries, installable output, raw key
  material, or unrelated user changes.
- Obtain independent code review before the final local checkpoint commit.

## Acceptance criteria

This slice is complete when:

1. no checked-in report labels the four invalid UI offsets as callable
   owners/factories or treats the five constructor paths as class-ID loads;
2. the selector report proves fixed table initialization and numeric ID domains
   while retaining runtime and human-semantic negatives;
3. the real vertical-classical factory and its unresolved invocation boundary
   are represented fail-closed;
4. the generic ModelManager loader/executor/destination-4 path is represented
   without a ModelCamera or pipeline identity promotion;
5. the recovery report records the packaged flag/LSI boundary and keeps exact
   TW/region-0 2.00 recovery unvalidated;
6. affected downstream summaries agree with their authoritative reports;
7. focused, full analysis, and safety verification pass; and
8. the result is saved only as a reviewed local Git checkpoint, with no push or
   pull request unless the user later requests one.
