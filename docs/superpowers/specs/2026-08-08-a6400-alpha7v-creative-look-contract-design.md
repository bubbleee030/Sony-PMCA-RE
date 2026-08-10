# α6400 α7 V Creative Look Contract Correction Design

## Status and precedence

Approved on 2026-08-08. This design is a focused correction to
`2026-08-06-a6400-modern-experience-port-design.md`. Where the two documents
differ on Creative Look membership, ranges, workflow, or visibility, this
document controls. The earlier design continues to control the wider modern UI,
touch, hardware-capability, and recovery architecture.

The work remains static and offline. It does not authorize camera access, Sony
camera-binary execution, updater/service-mode entry, partition writes, firmware
generation, or installation.

## Decision

Represent the complete α7 V Creative Look experience from the outset, including
capabilities that are not yet implementable on the α6400. An unproven item is
visible in the product contract but disabled and accompanied by a stable reason.
It is never hidden, silently dropped, substituted with Creative Style, or
treated as runnable merely because it is visible.

This is an evidence-gated visible contract:

- **reference presence** says what the α7 V-like experience must contain;
- **target evidence** says what the α6400 static analysis has established;
- **offline availability** says what an offline model or future UI prototype may
  enable; and
- **camera eligibility** remains controlled only by the independent stock-2.00
  recovery gate.

These four states must not be collapsed into one boolean.

## Authoritative reference behavior

The reference is Sony's ILCE-7M5 Creative Look Help Guide:

`https://helpguide.sony.net/ilc/2540/v1/en/contents/0411B_creative_look.html`

The fixed built-in look order is:

`ST`, `PT`, `NT`, `VV`, `VV2`, `FL`, `FL2`, `FL3`, `IN`, `SH`, `BW`, `SE`.

The interface also contains six numbered Custom Look boxes. A Custom Look lets
the user choose one of the built-in looks as its base and retain different
adjustments. The contract does not include a generic `copy` operation because
the reference guide does not specify one.

The eight axes and exact ranges are:

| Axis | Minimum | Maximum |
|---|---:|---:|
| Contrast | -9 | +9 |
| Highlights | -9 | +9 |
| Shadows | -9 | +9 |
| Fade | 0 | 9 |
| Saturation | -9 | +9 |
| Sharpness | 0 | 9 |
| Sharpness Range | 1 | 5 |
| Clarity | 0 | 9 |

The reference workflow also includes:

- selecting a built-in or Custom Look;
- entering the eight-axis editor;
- showing a modified marker when a value differs from its default;
- resetting all adjustments for one look; and
- choosing a built-in base for each Custom Look.

The reference restrictions are recorded as desired behavior, not claimed α6400
behavior:

- Creative Look is unavailable in Intelligent Auto;
- it is unavailable while Picture Profile is not Off;
- it is unavailable during Flexible ISO Log shooting;
- Saturation is unavailable for `BW` and `SE`; and
- Sharpness Range is unavailable in movie mode.

## Considered approaches

### Selected: evidence-gated visible contract

Keep every reference item visible, but enable an operation only when its exact
UI, state, processing, output, and mode dependencies are proven. This preserves
the product goal without inventing runtime behavior.

### Rejected: hide unproven items

This is conservative at the presentation layer, but it erases the intended
α7 V experience and makes missing capabilities harder to track. It contradicts
the approved visibility policy.

### Rejected: optimistic offline prototype

An interactive approximation could be built quickly, but without a strict
capability contract it would blur reference behavior, fallback recipes, and
target-native evidence. Visual work can follow later after the data contract is
fail-closed.

## Contract architecture

### 1. Reference catalog

The reference catalog is immutable product intent. It contains exactly twelve
built-in looks, six Custom slots, eight axis definitions, workflow actions, and
reference restriction rules. Membership, order, ranges, and rule identifiers
are exact and schema-validated.

Reference membership never counts as α6400 implementation evidence.

### 2. Target capability records

Each look, Custom slot, axis, workflow action, restriction, and output binding
has an independent target capability record. A record includes:

- `status`: the existing target capability classification;
- `ui`, `state`, and `pipeline` boundary booleans where applicable;
- bounded evidence records with source, path identifier, level, and claim; and
- a nonempty blocker whenever capability is not fully established.

The current state remains fail-closed:

- no native Creative Look base table is established;
- no complete first-class Creative Look state model is established;
- none of the eight axes has a complete UI-to-state-to-processing chain;
- live-view, still-JPEG, and movie bindings remain unestablished; and
- Creative Style mappings remain approximation-only fallback evidence.

Recent static findings about Creative Style, Picture Profile tone/detail nodes,
and the embedded PAS grid may be encoded only at their exact proven scope. They
must not promote a Creative Look record unless they establish the required
Creative Look identity and full boundary chain.

### 3. Presentation availability

Every reference item has `visibility = VISIBLE`. Availability is derived rather
than authored freely:

- a built-in look is enabled only when its base representation, selectable
  state, and required output bindings are established;
- a Custom slot is enabled only when base selection, per-slot state,
  adjustments, reset, and persistence are established;
- an axis is enabled only when its UI, state/range/default, and processing
  boundaries are all established; and
- a workflow operation is enabled only when all of its own dependencies are
  established.

Until then, availability is `DISABLED_UNPROVEN`. The record carries one or more
stable reason codes rather than prose-only state. Initial reason codes are:

- `BASE_LOOK_REPRESENTATION_UNPROVEN`
- `CUSTOM_LOOK_STATE_UNPROVEN`
- `AXIS_UI_UNPROVEN`
- `AXIS_STATE_UNPROVEN`
- `AXIS_PIPELINE_UNPROVEN`
- `WORKFLOW_DISPATCH_UNPROVEN`
- `PERSISTENCE_UNPROVEN`
- `MODE_MATRIX_UNPROVEN`
- `LIVE_VIEW_BINDING_UNPROVEN`
- `STILL_JPEG_BINDING_UNPROVEN`
- `MOVIE_BINDING_UNPROVEN`

The global camera-safety state is not reused as an item reason. A complete
offline implementation can still be non-installable because recovery is a
separate gate.

### 4. Fallback separation

The Creative Style recipe catalog remains a separate fallback artifact. It may
contain only representations actually expressible by α6400 Creative Style and
must retain `APPROXIMATION_ONLY` or weaker confidence.

`FL2` and `FL3` are present in the first-class reference catalog but have no
invented fallback recipe. Their fallback entries remain absent or explicitly
unrepresented until sourced settings and an honest α6400 translation exist.
Likewise, modern-only default values must not use an out-of-range sentinel such
as Sharpness Range `0`; absent or unproven defaults are represented explicitly,
not as valid axis values.

### 5. Safety and recovery state

The Creative Look contract must consume, not weaken, the existing recovery
result. Until exact Taiwan/region-0 stock 2.00 restoration is independently
verified:

- `camera_test_eligible` remains false;
- `installable` remains false;
- recovery remains `BLOCKED_STATIC_EVIDENCE`;
- no installable package or flash candidate is generated; and
- no camera-connected test design may begin.

Official target 2.00 documentation indicating that version 2.00 or later needs
no update is negative evidence for same-version reinstall, not a recovery path.

## Data flow

1. Load the immutable α7 V reference catalog.
2. Validate exact membership, ranges, workflow, and restriction rules.
3. Load the bounded α6400 capability evidence.
4. Derive presentation availability and reason codes without mutating evidence.
5. Keep fallback recipes in their separate approximation namespace.
6. Produce target summaries that distinguish visible intent, enabled offline
   capability, native runtime evidence, and installability.
7. Reject any report that promotes visibility or fallback data into native
   Creative Look support.

## Error handling and claim discipline

- Unknown, missing, duplicated, or reordered catalog members are rejected.
- Axis values outside the exact α7 V range are rejected.
- Unproven defaults are represented as unknown, not coerced into a valid value.
- A visible item with no capability evidence remains disabled.
- A native-capable status requires confirmed bounded evidence.
- A disabled item requires at least one stable reason code.
- `BW`/`SE` Saturation and movie Sharpness Range rules are reference rules until
  a target mode/state path implements them.
- Static string, RTTI, vtable, resource, or registration presence alone never
  establishes invocation or processing behavior.
- Creative Style translations never establish native Creative Look.
- Recovery failure or uncertainty blocks camera eligibility regardless of
  feature completeness.

## Verification strategy

### Reference-contract tests

- require the exact twelve-look order and six Custom identifiers;
- require the exact eight axes and numeric ranges;
- require modified-marker, per-look reset, and Custom-base-selection actions;
- require all documented restriction rules; and
- reject the stale ten-look catalog and unsupported `copy_select` action.

### Availability tests

- require every reference item to remain visible;
- require all currently unproven items to be disabled with reason codes;
- prove that partial UI, state, or pipeline evidence cannot enable an axis;
- prove that fallback recipes cannot enable native entries; and
- prove that camera eligibility is independent and remains false.

### Migration and integration tests

- migrate the Creative Look stack schema without accepting version-1 stale
  membership;
- update downstream target-feature and feasibility summaries from validated
  data, not hand-edited claims;
- keep the α6700 recipe translation artifact explicitly fallback-only;
- reject Sharpness, Sharpness Range, or Clarity values under the former incorrect
  ranges; and
- run focused analysis tests, the full analysis suite, the safety suite,
  deterministic regeneration checks, and `git diff --check`.

## Planned implementation scope

1. **Reference correction:** introduce the exact α7 V catalog and migrate the
   first-class Creative Look stack contract.
2. **Availability projection:** derive visible/disabled records and reason codes
   from fail-closed capability evidence.
3. **Fallback cleanup:** keep the ten-look α6700-era recipes separate, correct
   invalid modern ranges/default representation, and do not fabricate `FL2` or
   `FL3` translations.
4. **Downstream reconciliation:** regenerate feature summaries and human-readable
   reports from the corrected contracts.
These four slices form one bounded implementation plan. UI/touch trace encoding
and recovery research remain separate existing workstreams with their own specs
and plans. They continue toward the full objective, but they are dependencies of
this contract only through validated evidence and readiness fields. This design
does not silently absorb them into a large mixed implementation.

Every slice remains offline, reviewable, and separately fail-closed.

## Acceptance

This design slice is complete when:

- the repository's authoritative product contract names all twelve α7 V looks,
  six Custom slots, eight exact ranges, and documented workflow/restrictions;
- every reference item is visible in the derived offline contract;
- no unproven item is enabled or presented as target-native;
- the fallback catalog is clearly separate and contains no fabricated `FL2` or
  `FL3` behavior;
- stale ten-look/copy/range assumptions are rejected by tests;
- downstream reports preserve all unresolved runtime, output, touch-delivery,
  installability, and recovery boundaries; and
- camera testing and installability remain false pending independently verified
  exact stock Taiwan/region-0 2.00 recovery.
