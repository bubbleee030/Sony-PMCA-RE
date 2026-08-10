# α6400-Native Creative Look Integration ABI Design

## Status and precedence

This design was approved on 2026-08-11. It extends the approved
`2026-08-06-a6400-modern-experience-port-design.md` and
`2026-08-08-a6400-alpha7v-creative-look-contract-design.md` documents. Those
documents continue to control the product contract, target-evidence discipline,
and recovery gate. This document controls the first source-only integration ABI
between the portable Creative Look core/view implementation and future α6400
platform bindings.

The milestone is static and offline. It does not authorize camera access, Sony
camera-binary execution, firmware packaging, updater or service-mode entry,
partition writes, or installation. It does not add a target-execution profile.

## Objective

Build a fixed-memory, host-executable coordinator around the existing
`creative_look_core` and `creative_look_view` modules. The coordinator exercises
the complete first-class experience across six explicit platform boundaries:

1. view lifecycle;
2. frame presentation;
3. touch and orientation input delivery;
4. exact Creative Look state persistence;
5. full-state model requests; and
6. independent live-view, still-JPEG, and movie output synchronization.

The coordinator must expose integration behavior and failure handling without
assigning any Sony class, event ID, process-data ID, Backup record, filesystem
path, processor, or output service identity.

## Selected architecture

Use three layers with one-way dependencies:

1. **Portable product layer:** the existing `creative_look_core.h/.c` and
   `creative_look_view.h/.c` remain authoritative for catalog membership,
   Custom slots, axes, restrictions, persistence encoding, frame construction,
   and touch hit-testing.
2. **Evidence-gated bridge:** new `creative_look_bridge.h/.c` files own
   lifecycle, input registration, desired-state revisions, synchronization
   dirtiness, adapter invocation, and deterministic retry.
3. **Host fixture layer:** tests supply in-memory platform adapters and call
   logs. No host fixture is compiled into production source.

The bridge does not translate Creative Look into the existing five-integer
Creative Style setter. Model and output adapters receive a complete immutable
Creative Look snapshot instead.

## Rejected approaches

### Header-only binding manifest

A manifest alone would document callback shapes but could not verify lifecycle
ordering, state changes, partial synchronization failure, or retry behavior. It
would leave the most important integration semantics untested.

### One monolithic platform callback

A single callback would make a minimal host demo possible, but it would collapse
six independently unresolved Sony boundaries into one success value. It would
also prevent precise dirty-state retry and evidence attribution.

### Sony-named target stubs

Stubs naming candidate Sony classes, records, events, or processing services
would convert unresolved static leads into source-level claims. This milestone
therefore defines no target implementation and no target runtime profile.

## Binding manifest

### Separate evidence and execution axes

Every binding record has independent evidence and runtime fields. Neither field
is ordered; validation uses exact enum membership and equality.

Evidence states are:

- `CL_BINDING_EVIDENCE_UNBOUND`: no target identity is assigned;
- `CL_BINDING_EVIDENCE_STATIC_CANDIDATE`: a bounded static candidate exists but
  runtime identity is not proven; and
- `CL_BINDING_EVIDENCE_STATIC_PROVEN`: the exact static binding contract has
  been reproduced and digest-pinned.

Runtime states are:

- `CL_BINDING_RUNTIME_DISABLED`: no callback may be invoked; and
- `CL_BINDING_RUNTIME_HOST_SIMULATED`: the callback is an offline host fixture.

There is intentionally no target-executable runtime state. A future target
profile requires a separate approved design after recovery validation.

### Six exact binding records

The manifest contains exactly one record, in fixed order, for:

1. `CL_BINDING_LIFECYCLE`;
2. `CL_BINDING_PRESENTATION`;
3. `CL_BINDING_INPUT`;
4. `CL_BINDING_PERSISTENCE`;
5. `CL_BINDING_MODEL_REQUEST`;
6. `CL_BINDING_OUTPUT`.

Each record contains:

- binding kind;
- evidence state;
- runtime state; and
- a 32-byte canonical evidence digest.

`UNBOUND` evidence requires an all-zero digest. `STATIC_CANDIDATE` and
`STATIC_PROVEN` require a nonzero digest. The digest identifies a checked static
report; it does not enable execution.

The manifest also contains:

- ABI version `1`;
- execution profile `CL_EXECUTION_PROFILE_OFFLINE_HOST`;
- exact binding count `6`;
- `processing_binding_proven = 0`;
- `recovery_validated = 0`;
- `camera_test_eligible = 0`; and
- `installable = 0`.

Manifest validation rejects any other execution profile, any promoted safety
field, duplicate or reordered bindings, invalid enum value, or digest/status
contradiction.

## Adapter interfaces

All adapters are caller-owned structs containing only a context pointer and
function pointers. Callbacks are synchronous. They must not retain pointers
passed by the bridge except for the input sink and sink context explicitly
registered by a successful `attach`. That pair may be retained only until
`detach` completes; the bridge storage must outlive that interval and the
adapter must never invoke the pair afterward.

Callbacks must not reenter a bridge entry point or deliver an input event while
`attach`, `detach`, or another adapter callback is active. The bridge also owns
a busy guard and rejects such attempts deterministically rather than allowing
nested mutation of state, dirtiness, or the last report.

### Lifecycle adapter

The lifecycle adapter provides:

- `open(context, initial_state)`; and
- `close(context)`.

Both callbacks are required for a host-simulated lifecycle binding. The bridge
calls `close` exactly once for each successful `open`, including cleanup after a
later presentation or input-attachment failure. A nonzero `close` result is a
diagnostic failure, but `close` must still have completed teardown before it
returns.

### Presentation adapter

The bridge reuses the existing `cl_view_adapter`. Its `present` callback receives
a validated, stack-built `cl_view_frame`. Initial presentation is an admission
gate: if it fails, the bridge closes and the caller must reinitialize before a
new open attempt. After open succeeds, a failed presentation remains dirty and
can be retried without reconstructing platform state.

### Input adapter

The input adapter provides:

- `attach(context, sink, sink_context)`; and
- `detach(context)`.

`attach` registers one bridge-owned sink. A successful return authorizes the
adapter to retain the sink pair until detach. A failed attach is atomic and must
retain no sink. `detach` must make the sink unreachable before returning even
when it returns a nonzero diagnostic result.

Host fixtures deliver only canonical events through the registered sink:

- touch at logical milli-unit `x/y` coordinates; or
- orientation changed to one of the three existing `cl_orientation` values.

Canonical events have zero reserved bytes. Touch events also have `value = 0`.
Orientation events have `x = 0`, `y = 0`, and a valid orientation value. Any
other representation is rejected atomically.

The adapter does not define a Sony raw-event layout or coordinate transform.
The future target adapter must perform that target-specific translation before
calling the canonical sink.

### Persistence adapter

The bridge reuses the existing `cl_storage_adapter` callbacks and exact
`CL_BLOB_SIZE = 164` encoding. For bridge startup only, load callback results are
interpreted as:

- `0`: a full blob was supplied and must decode successfully;
- `1`: no prior value exists, so the exact default state is used; and
- any other value: adapter failure, so open fails closed.

Save success is exactly `0`. A save failure leaves persistence dirty. The bridge
never assigns a Backup record or filesystem path.

### Model-request adapter

The model adapter provides one `submit(context, snapshot)` callback. The
snapshot is immutable for the call and contains:

- bridge ABI version;
- processing revision;
- a complete by-value `cl_state`;
- effective base look for the selected built-in or Custom slot; and
- a three-bit desired output mask for live view, still JPEG, and movie.

The complete state preserves all twelve built-ins, all six Custom bases, all
`18 × 8` adjustment bytes, mode flags, and selection. No field is reduced to or
identified with the five Creative Style setter arguments.

A state is processing-ready when the selected Look is built-in or the selected
Custom slot has a built-in base. Selecting an unconfigured Custom slot is a
valid staged UI state on `CL_SCREEN_CUSTOM_BASE`, but it is not
processing-ready: `CL_UNSET` is never an effective base and no model or output
callback may receive it. A later base selection creates the processing change
and its snapshot includes every state and mode change accumulated while staged.

The bridge retains the complete snapshot by value when it creates a processing
revision. UI-only changes, including selection of an unconfigured Custom slot,
may update current state, presentation, and persistence, but they never rewrite
the retained processing snapshot. Model and output retries for a revision
therefore receive byte-identical payloads. If a new processing change occurs
while an older revision is still dirty, the bridge coalesces to the newest
desired processing revision: it replaces the retained snapshot once, keeps the
relevant domains dirty, and does not replay the older revision. A restored
unconfigured Custom state starts at processing revision `0` with no valid
retained processing work.

### Output adapter

The output adapter provides `apply(context, output_kind, snapshot)`. The bridge
invokes it independently for:

- `CL_OUTPUT_LIVE_VIEW`;
- `CL_OUTPUT_STILL_JPEG`; and
- `CL_OUTPUT_MOVIE`.

Each channel has an independent dirty bit and result. Success on one output
never promotes or clears another. The callback shape establishes integration
semantics only; it does not claim that an α6400 processing sink is known.

## Bridge state

`cl_bridge` is allocation-free and owns all mutable coordination state by value:

- one `cl_state`;
- one retained immutable `cl_processing_snapshot` for the latest completed
  processing revision, or all-zero storage when no processing revision exists;
- one validated manifest copy;
- one adapter-set copy;
- monotonic state and processing revisions;
- an initialization marker plus open, input-attached, busy, and opened-once
  flags;
- dirty bits for presentation, persistence, model request, live view, still
  JPEG, and movie; and
- the most recent operation report with raw callback diagnostics.

The bridge exposes read-only access to its current `cl_state`, revisions, dirty
mask, and last report. It exposes no mutable state pointer.

## Lifecycle and data flow

### Initialization

Bridge storage must be all-zero before its first `cl_bridge_init`. Initialization
validates the manifest and callback completeness, copies the manifest and adapter
structs, initializes default state, marks the bridge initialized, clears
revisions and dirtiness, and performs no callback. Reinitialization is allowed
only after a prior session is closed or admission has failed. Initialization of
a busy bridge returns `CL_ERR_BUSY`; initialization of an open/attached bridge
returns `CL_ERR_ALREADY_OPEN`; both are mutation-free so a live sink or resource
cannot be orphaned.

All six binding records must be `HOST_SIMULATED` at initialization. This ensures
the host milestone exercises every boundary. Static evidence may remain
`UNBOUND`; simulation is not evidence. One initialization admits at most one
open/close lifecycle session. A second open after close requires reinitializing
the bridge, so a revision cannot be reused for a different payload in one
adapter session.

### Open

Open performs these steps in order:

1. initialize an exact default candidate state;
2. call persistence load;
3. decode and validate a supplied blob, or retain the default for a missing
   value;
4. call lifecycle open with the candidate;
5. commit the candidate to bridge state;
6. create state revision `1`;
7. if the candidate is processing-ready, create processing revision `1`, build
   the retained processing snapshot, and mark model and all three outputs dirty;
   otherwise retain processing revision `0`, all-zero snapshot storage, and no
   model/output work;
8. mark persistence dirty only when no prior blob existed;
9. build and present the initial frame as an admission gate;
10. attach the canonical input sink; and
11. attempt all initially dirty synchronizations.

If lifecycle open fails, no state is opened. If presentation or input attach
fails after lifecycle open, the bridge calls lifecycle close, returns to closed
state, and retains both the primary and cleanup callback results. Failed attach
is atomic, so that path never calls detach. Initial presentation failure is not
left dirty or retryable; admission cleanup clears the provisional dirty mask,
and reopening requires reinitialization. An initial
post-attach synchronization failure instead leaves the bridge open and the
failed domain dirty.

### Canonical touch event

For every touch event, the bridge:

1. rejects the event unless open;
2. copies current state to a candidate;
3. applies `cl_view_touch` to the candidate;
4. leaves state and all dirty bits unchanged for invalid, restricted, or no-hit
   results;
5. validates a successful candidate;
6. rejects before mutation if the state revision would overflow;
7. determines whether the candidate is processing-ready and creates processing
   work only when it became ready or processing-relevant fields changed while
   ready; only that case separately rejects if the processing revision would
   overflow;
8. commits the candidate and increments the state revision;
9. marks presentation and persistence dirty;
10. if processing work was created, increments the processing revision,
    replaces the retained snapshot, and marks model plus all three outputs
    dirty; an unconfigured Custom selection preserves the prior retained bytes
    and creates no processing dirtiness; and
11. invokes deterministic synchronization.

Processing-relevant fields are selected Look, Custom bases, all adjustments,
and mode bits, but they create work only for a processing-ready candidate.
Screen, editing-axis, orientation, and the staged selection of an unconfigured
Custom slot do not create a model or output request. Selecting that Custom's
valid base creates the deferred processing revision.

### Orientation event

A valid orientation event updates only orientation, increments state revision,
and marks presentation plus persistence dirty. Invalid values do not change
state.

### Mode update

`cl_bridge_set_mode` applies the existing `cl_set_mode` transition. A real mode
change always increments the state revision and dirties presentation plus
persistence. It increments the processing revision and dirties model plus all
three outputs only when the resulting state is processing-ready. A mode change
while an unconfigured Custom picker is staged is deferred; the later base
selection creates one snapshot containing the latest modes. A no-op update
produces no new revision or callback.

### Synchronization order

`cl_bridge_sync` attempts dirty domains in this fixed order:

1. presentation;
2. persistence;
3. model request;
4. live view;
5. still JPEG;
6. movie.

Only successful domains are cleared. A failure never prevents later independent
domains from being attempted. The report records attempted, succeeded, failed,
and remaining-dirty masks plus raw callback results for every domain.

State is the desired source of truth. A successful core transition is never
rolled back after an external callback failure because synchronous callbacks may
already have produced irreversible side effects. Instead, failed domains remain
dirty and `cl_bridge_retry` repeats the retained snapshot for that exact
processing revision. Callbacks must be idempotent for a repeated
`(processing_revision, output_kind)` pair within one initialized bridge session.
Persistence and presentation always use current state; model and output always
use the retained processing snapshot. Synchronization and retry never invoke a
processing callback when processing revision is `0` or no valid retained
snapshot exists. Snapshot construction fails closed if effective-base
resolution yields `CL_UNSET`.

### Close

Close detaches input first and closes lifecycle second. It attempts both even if
detach returns a nonzero diagnostic, records both results, clears open/attached
flags, and retains state for offline inspection. The adapter contracts require
both callbacks to complete teardown regardless of diagnostic result, so the
bridge never loses cleanup ownership. Close does not silently clear
unsynchronized dirty bits. The bridge cannot reopen until `cl_bridge_init` starts
a new adapter session.

## Results and error handling

Bridge entry points return a `cl_result` and fill a caller-supplied fixed
`cl_bridge_report` when an operation can reach platform callbacks.

The core transition result remains exact. The report separately stores raw
`int32_t` callback results for:

- lifecycle open and close;
- input attach and detach;
- persistence load; and
- each of the six synchronization domains.

Every unattempted field is `CL_CALLBACK_NOT_ATTEMPTED`. The report also states:

- whether desired state committed;
- state and processing revision;
- attempted, succeeded, failed, and dirty masks; and
- the exact operation result and opened state.

New bridge-specific results distinguish invalid manifest, incomplete binding,
closed/open lifecycle misuse, reinitialization required, busy/reentrant use,
input attachment failure, and adapter synchronization failure. Result mapping
is exact: manifest rejection is `CL_ERR_MANIFEST`; incomplete callbacks are
`CL_ERR_BINDING`; blob decode is `CL_ERR_BLOB`; persistence-load,
presentation, persistence-save, model, output, and detach diagnostics are
`CL_ERR_ADAPTER`; lifecycle open/close diagnostics are `CL_ERR_LIFECYCLE`; and
attach failure is `CL_ERR_INPUT_ATTACHMENT`. Cleanup close failure takes
precedence over the presentation/attach failure that triggered cleanup. During
normal close, close failure takes precedence over detach failure. If desired
state committed but synchronization failed, the bridge returns
`CL_ERR_ADAPTER` and explicitly sets `state_committed = 1`. Callers therefore
never need to infer mutation from the return code alone. Closed/open misuse maps
to `CL_ERR_NOT_OPEN`/`CL_ERR_ALREADY_OPEN`; reopening a closed session maps to
`CL_ERR_REINIT_REQUIRED`; a guarded reentrant call maps to `CL_ERR_BUSY`; and
revision overflow maps to `CL_ERR_REVISION`.

Integer revisions fail closed on overflow: the triggering operation is rejected
before state mutation. This prevents revision reuse in idempotent adapters.

## Fixed-memory and ABI constraints

- C99 source with no C library dependency beyond fixed-width and size types.
- No allocation, flexible arrays, file I/O, dynamic loading, threads, atomics,
  networking, USB, or firmware operations.
- No floating point.
- Public wire/data structs use explicit fixed-width fields and reserved bytes.
  Pointer-bearing adapter and bridge structs follow the compiling platform ABI;
  they are not claimed byte-identical across 32-bit and 64-bit hosts.
- Cross-module callback result signatures use `int32_t`, not an enum-sized
  return type.
- Public size/offset/alignment query functions expose bridge, adapter offset,
  alignment, manifest, snapshot, event, and report values for host ABI tests.
- Host and freestanding compilation use warnings as errors.
- The combined core, view, and bridge relocatable object has zero undefined
  symbols.

## Verification strategy

### Contract and compilation

- Assert exact enum values, struct sizes, binding order, ABI version, and safety
  zeros.
- Compile core, view, and bridge as strict hosted and freestanding C99.
- Resolve the compiler-matching linker through `gcc -print-prog-name=ld`, link
  them into one relocatable object, and require zero undefined symbols. The gate
  must not fabricate, allowlist, or filter a symbol, and unavailable symbol
  inspection is a verification failure.
- Run GCC static analysis and repository safety-token scans.

### Manifest validation

- Accept a six-binding offline-host manifest with independent simulated runtime
  and unbound evidence.
- Reject missing, duplicate, reordered, promoted, or unknown records.
- Reject nonzero evidence digests for `UNBOUND` and zero digests for candidate or
  proven evidence.
- Prove that `STATIC_PROVEN` alone cannot enable runtime or any safety flag.

### Lifecycle and input

- Verify exact open/load/present/attach order and detach/close order.
- Inject failures at every step and assert cleanup calls, state, flags, and
  reports.
- Verify missing storage calls
  `load, open, present, attach, save, model, live_view, still_jpeg, movie`.
  Processing-ready restored storage omits only `save`; a legitimately restored
  unconfigured Custom picker calls exactly `load, open, present, attach` and
  starts at processing revision `0`.
- Verify presentation failure calls `load, open, present, close`; attach failure
  calls `load, open, present, attach, close`; and neither leaves a retained
  sink.
- Deliver touch and all three orientations only through the registered sink.
- Reject sink calls during attach/detach or after detach while the bridge storage
  is still alive.

### Product coverage

- Select every one of the twelve built-ins.
- Configure every Custom slot with every valid built-in base.
- Exercise every axis minimum, default, and maximum.
- Exercise landscape and both portrait orientations.
- Verify all existing restriction results and no-hit atomicity.

### Persistence, model, and outputs

- Verify exact 164-byte save/load bytes and corruption rejection.
- Verify a missing blob creates and persists exact default state.
- Assert that model snapshots contain the complete native state, effective base,
  output mask, and processing revision.
- Assert distinct live-view, still-JPEG, and movie calls and dirty bits.
- Inject one failure per domain and prove successful domains clear while failed
  domains retry the same revision.
- After an output failure, apply a screen-only or orientation-only change and
  prove the retry snapshot remains byte-identical to the failed snapshot.
- Prove screen navigation and orientation do not emit processing requests.
- Prove unconfigured Custom selection preserves a prior retained snapshot,
  emits only presentation/persistence, and that base completion emits the first
  current full-state snapshot, including modes staged during the picker.

### Safety

- Require processing binding, recovery validation, camera eligibility, and
  installability to remain zero in headers, manifests, reports, and tests.
- Reject Sony class names, event IDs, process-data IDs, Backup identities,
  partition paths, updater commands, and camera transport in bridge source.
- Run the full analysis and safety suites before publication.

## Acceptance criteria

The milestone is complete only when:

1. the fixed-memory bridge exercises all six host-simulated bindings;
2. all twelve Looks, six Custom slots, eight axes, and three orientations pass
   through the bridge rather than bypassing it;
3. persistence, model, and three output channels have independent deterministic
   dirty/retry behavior;
4. a complete native state snapshot replaces any five-value Creative Style
   assumption at this integration boundary;
5. evidence status never enables host or target execution implicitly;
6. no target execution profile or Sony binding identity exists in source; and
7. every recovery, camera, and installability gate remains false.

This milestone advances the α6400-native implementation architecture. It does
not establish target processing, target persistence, runtime view registration,
or camera-test eligibility.
