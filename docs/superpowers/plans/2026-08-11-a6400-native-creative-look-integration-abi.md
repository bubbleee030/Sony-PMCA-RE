# α6400-Native Creative Look Integration ABI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an allocation-free, host-executable Creative Look coordinator that exercises lifecycle, presentation, canonical input, persistence, full-state model submission, and three independent output channels without assigning a Sony runtime identity.

**Architecture:** Keep the existing native core and view modules authoritative for product behavior, then add one fixed-memory `creative_look_bridge` layer. The bridge separates static evidence status from host-simulation status, owns revisions and dirty domains, registers a canonical input sink, and retries failed platform synchronization without rolling back desired state.

**Tech Stack:** C99, Python 3 `unittest`, `ctypes`, GCC hosted/freestanding compilation, repository safety tests.

## Global Constraints

- The approved design is `docs/superpowers/specs/2026-08-11-a6400-native-creative-look-integration-abi-design.md`.
- The milestone is static and offline; no camera access or Sony camera-binary execution.
- Do not add a target-executable runtime profile.
- Do not name a Sony class, event ID, process-data ID, Backup record, filesystem path, processor, or output service.
- Keep `CL_PROCESSING_BINDING_UNBOUND`, `CL_RECOVERY_VALIDATED`, `CL_CAMERA_TEST_ELIGIBLE`, and `CL_INSTALLABLE` equal to `0`.
- C99 only; no allocation, floating point, file I/O, dynamic loading, threads, atomics, networking, USB, updater, or partition operation.
- Source mutations and test doubles operate only in host memory.
- New production behavior follows strict red-green-refactor TDD.

---

## File map

| Path | Responsibility |
|---|---|
| `native/a6400_creative_look/creative_look_core.h` | Add bridge-specific `cl_result` values without changing existing values. |
| `native/a6400_creative_look/creative_look_view.h` | Pin existing presentation/storage callback returns to `int32_t`. |
| `native/a6400_creative_look/creative_look_bridge.h` | Public ABI: manifest, six adapters, events, snapshots, reports, bridge state, and entry points. |
| `native/a6400_creative_look/creative_look_bridge.c` | Manifest validation, lifecycle, event transitions, revision comparison, dirty synchronization, and retry. |
| `native/a6400_creative_look/README.md` | Document the bridge boundary, host-only execution status, and remaining Sony/recovery gaps. |
| `tests/analysis/creative_look_native_abi.py` | Shared natural-alignment `ctypes` declarations, strict compiler helpers, and callback-lifetime utilities for all native suites. |
| `tests/analysis/test_creative_look_native_core.py` | Import the shared `NativeState` declaration without changing existing core coverage. |
| `tests/analysis/test_creative_look_native_view.py` | Import shared state/frame/adapter declarations without changing existing view coverage. |
| `tests/analysis/test_creative_look_native_bridge.py` | Compile/load the real C sources and verify every public bridge behavior through real callbacks. |

The bridge stays in one `.c` file for this milestone because lifecycle, event
commit, and dirty synchronization share private invariants. Split it only if the
implementation exceeds roughly 900 readable lines after refactoring.

---

### Task 1: Public contract and fail-closed manifest

**Files:**
- Modify: `native/a6400_creative_look/creative_look_core.h`
- Modify: `native/a6400_creative_look/creative_look_view.h`
- Create: `native/a6400_creative_look/creative_look_bridge.h`
- Create: `native/a6400_creative_look/creative_look_bridge.c`
- Create: `tests/analysis/creative_look_native_abi.py`
- Modify: `tests/analysis/test_creative_look_native_core.py`
- Modify: `tests/analysis/test_creative_look_native_view.py`
- Create: `tests/analysis/test_creative_look_native_bridge.py`

**Interfaces:**
- Consumes: `cl_state`, `cl_view_adapter`, `cl_storage_adapter`, and existing core/view size and transition functions.
- Produces: all public bridge types, `cl_bridge_manifest_host`, `cl_bridge_validate_manifest`, and size-query functions used by every later task.

- [ ] **Step 1: Write the failing contract-file test**

Add a new `unittest.TestCase` whose first test names the production break: removing
either bridge source must fail the native contract.

```python
ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "native" / "a6400_creative_look"
BRIDGE_H = NATIVE / "creative_look_bridge.h"
BRIDGE_C = NATIVE / "creative_look_bridge.c"

class CreativeLookNativeBridgeTests(unittest.TestCase):
    def test_bridge_contract_sources_exist(self):
        self.assertTrue(BRIDGE_H.is_file())
        self.assertTrue(BRIDGE_C.is_file())
```

- [ ] **Step 2: Run the test and verify the intended red state**

Run:

```powershell
& '.\.venv\Scripts\python.exe' -m unittest tests.analysis.test_creative_look_native_bridge.CreativeLookNativeBridgeTests.test_bridge_contract_sources_exist -v
```

Expected: `FAIL` because `creative_look_bridge.h` and `.c` do not exist.

- [ ] **Step 3: Define exact public enums and fixed data structs**

Extend `cl_result` without renumbering `CL_OK` through `CL_ERR_ADAPTER`:

```c
CL_ERR_MANIFEST = -11,
CL_ERR_BINDING = -12,
CL_ERR_LIFECYCLE = -13,
CL_ERR_NOT_OPEN = -14,
CL_ERR_ALREADY_OPEN = -15,
CL_ERR_REVISION = -16,
CL_ERR_INPUT_ATTACHMENT = -17,
CL_ERR_REINIT_REQUIRED = -18,
CL_ERR_BUSY = -19
```

Create `creative_look_bridge.h` with these exact constants and enum values:

```c
enum {
    CL_BRIDGE_ABI_VERSION = 1,
    CL_BRIDGE_BINDING_COUNT = 6,
    CL_BRIDGE_OUTPUT_MASK = 7,
    CL_STORAGE_MISSING = 1
};

#define CL_CALLBACK_NOT_ATTEMPTED ((int32_t)INT32_MIN)

typedef enum cl_binding_kind {
    CL_BINDING_LIFECYCLE = 0,
    CL_BINDING_PRESENTATION = 1,
    CL_BINDING_INPUT = 2,
    CL_BINDING_PERSISTENCE = 3,
    CL_BINDING_MODEL_REQUEST = 4,
    CL_BINDING_OUTPUT = 5
} cl_binding_kind;

typedef enum cl_binding_evidence {
    CL_BINDING_EVIDENCE_UNBOUND = 0,
    CL_BINDING_EVIDENCE_STATIC_CANDIDATE = 1,
    CL_BINDING_EVIDENCE_STATIC_PROVEN = 2
} cl_binding_evidence;

typedef enum cl_binding_runtime {
    CL_BINDING_RUNTIME_DISABLED = 0,
    CL_BINDING_RUNTIME_HOST_SIMULATED = 1
} cl_binding_runtime;

typedef enum cl_execution_profile {
    CL_EXECUTION_PROFILE_OFFLINE_HOST = 0
} cl_execution_profile;

typedef enum cl_output_kind {
    CL_OUTPUT_LIVE_VIEW = 0,
    CL_OUTPUT_STILL_JPEG = 1,
    CL_OUTPUT_MOVIE = 2
} cl_output_kind;

typedef enum cl_input_kind {
    CL_INPUT_TOUCH = 0,
    CL_INPUT_ORIENTATION = 1
} cl_input_kind;

typedef enum cl_sync_domain {
    CL_SYNC_PRESENTATION = 1,
    CL_SYNC_PERSISTENCE = 2,
    CL_SYNC_MODEL_REQUEST = 4,
    CL_SYNC_LIVE_VIEW = 8,
    CL_SYNC_STILL_JPEG = 16,
    CL_SYNC_MOVIE = 32
} cl_sync_domain;
```

Change the three existing callback return typedefs in `creative_look_view.h`
from implementation-defined `int` spelling to `int32_t`; behavior and callback
arguments remain unchanged. All new cross-module callback results likewise use
`int32_t`. Bridge public functions may continue returning the existing
`cl_result` because caller and implementation compile against the same header.

Define the fixed records exactly:

```c
typedef struct cl_binding_record {
    uint8_t kind;
    uint8_t evidence;
    uint8_t runtime;
    uint8_t reserved;
    uint8_t evidence_sha256[32];
} cl_binding_record;

typedef struct cl_integration_manifest {
    uint16_t abi_version;
    uint8_t execution_profile;
    uint8_t binding_count;
    cl_binding_record bindings[CL_BRIDGE_BINDING_COUNT];
    uint8_t processing_binding_proven;
    uint8_t recovery_validated;
    uint8_t camera_test_eligible;
    uint8_t installable;
    uint8_t reserved[4];
} cl_integration_manifest;

typedef struct cl_input_event {
    int32_t x;
    int32_t y;
    uint8_t kind;
    uint8_t value;
    uint8_t reserved[2];
} cl_input_event;

typedef struct cl_processing_snapshot {
    uint16_t abi_version;
    uint8_t effective_base;
    uint8_t output_mask;
    uint32_t processing_revision;
    cl_state state;
    uint8_t reserved[1];
} cl_processing_snapshot;

typedef struct cl_bridge_report {
    int32_t transition_result;
    int32_t lifecycle_open_result;
    int32_t lifecycle_close_result;
    int32_t input_attach_result;
    int32_t input_detach_result;
    int32_t persistence_load_result;
    int32_t sync_results[CL_BRIDGE_BINDING_COUNT];
    uint32_t state_revision;
    uint32_t processing_revision;
    uint8_t attempted;
    uint8_t succeeded;
    uint8_t failed;
    uint8_t dirty;
    uint8_t state_committed;
    uint8_t opened;
    uint8_t reserved[2];
} cl_bridge_report;
```

`cl_bridge_report` is exactly 64 bytes. Every scalar callback field and every
`sync_results` entry is initialized to `CL_CALLBACK_NOT_ATTEMPTED`; attempted
callbacks retain their raw `int32_t` return. Synchronization indices are exactly
presentation, persistence, model, live view, still JPEG, and movie in that
order.

Add declarations for:

```c
size_t cl_binding_record_size(void);
size_t cl_integration_manifest_size(void);
size_t cl_input_event_size(void);
size_t cl_processing_snapshot_size(void);
size_t cl_bridge_report_size(void);
cl_result cl_bridge_manifest_host(cl_integration_manifest *manifest);
cl_result cl_bridge_validate_manifest(const cl_integration_manifest *manifest);
```

- [ ] **Step 4: Implement host manifest creation and exact validation**

In `creative_look_bridge.c`, implement loops locally rather than calling
`memset`/`memcmp`. `cl_bridge_manifest_host` must zero the full manifest, write
ABI/profile/count, and write each binding kind in index order with
`UNBOUND + HOST_SIMULATED`.

`cl_bridge_validate_manifest` must reject:

- null pointer;
- ABI/profile/count mismatch;
- binding kind not equal to its array index;
- unknown evidence/runtime values;
- nonzero reserved bytes;
- nonzero digest for `UNBOUND`;
- all-zero digest for candidate/proven evidence; and
- any nonzero processing/recovery/camera/installable field.

Return `CL_ERR_MANIFEST` for every manifest-contract rejection.

- [ ] **Step 5: Extract the shared native ABI harness**

Move the duplicated `NativeState`, `NativeElement`, `NativeFrame`, view/storage
adapter declarations, constants, and strict compiler helpers from the core and
view tests into `tests/analysis/creative_look_native_abi.py`. Both existing test
modules and the new bridge test import that helper. Use `ctypes.CFUNCTYPE` on
Windows; never use `WINFUNCTYPE`. Mirror normal C alignment and do not use
`_pack_`; `NativeState` already has byte-only natural layout.

The helper must compile hosted objects/libraries with exactly
`-std=c99 -Wall -Wextra -Werror -pedantic -I <native-dir>`. It must retain every
`CFUNCTYPE` object on the owning fixture for the full native-call lifetime and
set `argtypes`/`restype` for every exported function before use. Callback bodies
must capture Python exceptions and return a nonzero result instead of allowing
an exception to escape through C. Give persistence load and save distinct
callback type aliases even though their return types match.
The guard accepts a per-callback exception result: persistence load must use a
value other than `0` and `CL_STORAGE_MISSING`, while other adapters may use `1`.
Attach clears a provisional sink in `finally` unless it completed successfully;
detach clears the retained sink in `finally` even when fixture code raises.

- [ ] **Step 6: Replace the existence test with real compile/behavior tests**

Compile core, view, and bridge into one host shared library in `setUpClass`.
Declare matching `ctypes.Structure` types. Test literal sizes:

```python
self.assertEqual(lib.cl_binding_record_size(), 36)
self.assertEqual(lib.cl_integration_manifest_size(), 228)
self.assertEqual(lib.cl_input_event_size(), 12)
self.assertEqual(lib.cl_processing_snapshot_size(), 164)
self.assertEqual(lib.cl_bridge_report_size(), 64)
```

Create a host manifest and assert exact binding order, all runtime fields equal
`HOST_SIMULATED`, all evidence fields/digests zero, and all safety fields zero.
Table-mutate every field listed in Step 4 and assert `CL_ERR_MANIFEST`.

- [ ] **Step 7: Run focused core/view/bridge tests**

Run:

```powershell
& '.\.venv\Scripts\python.exe' -m unittest tests.analysis.test_creative_look_native_core tests.analysis.test_creative_look_native_view tests.analysis.test_creative_look_native_bridge -v
```

Expected: all tests pass with no compiler warnings.

- [ ] **Step 8: Commit the manifest contract**

```powershell
git add native/a6400_creative_look/creative_look_core.h native/a6400_creative_look/creative_look_view.h native/a6400_creative_look/creative_look_bridge.h native/a6400_creative_look/creative_look_bridge.c tests/analysis/creative_look_native_abi.py tests/analysis/test_creative_look_native_core.py tests/analysis/test_creative_look_native_view.py tests/analysis/test_creative_look_native_bridge.py
git commit -m "add Creative Look bridge manifest"
```

---

### Task 2: Six adapters and lifecycle transaction

**Files:**
- Modify: `native/a6400_creative_look/creative_look_bridge.h`
- Modify: `native/a6400_creative_look/creative_look_bridge.c`
- Modify: `tests/analysis/test_creative_look_native_bridge.py`

**Interfaces:**
- Consumes: validated manifest and existing view/storage adapters from Task 1.
- Produces: adapter structs, `cl_bridge`, `cl_bridge_init`, `cl_bridge_open`, `cl_bridge_close`, and read-only bridge accessors.

- [ ] **Step 1: Write failing lifecycle-order tests using real C callbacks**

Define complete `ctypes.CFUNCTYPE` callbacks that append literal entries to one
Python call log. Do not assert that callbacks merely exist; assert bridge state
and exact externally visible order:

```python
bridge = fixture.initialized_bridge(load_result=CL_STORAGE_MISSING)
report = Report()
self.assertEqual(lib.cl_bridge_open(byref(bridge), byref(report)), CL_OK)
self.assertEqual(
    fixture.calls,
    ["load", "open", "present", "attach"],
)
self.assertEqual(lib.cl_bridge_dirty_mask(byref(bridge)), 0x3E)
self.assertEqual(report.opened, 1)
self.assertEqual(lib.cl_bridge_close(byref(bridge), byref(report)), CL_OK)
self.assertEqual(fixture.calls[-2:], ["detach", "close"])
```

At this task boundary synchronization is not implemented: missing storage leaves
persistence/model/live/still/movie dirty (`0x3E`), while restored storage leaves
only model/live/still/movie dirty (`0x3C`). Task 4 replaces these prefix checks
with the final full startup sequences. Add separate tests for load error, corrupt
loaded blob, lifecycle-open failure, presentation failure, and input-attach
failure. Presentation failure must be exactly
`load, open, present, close`; attach failure must be exactly
`load, open, present, attach, close`. Each test asserts every raw report field,
cleanup result, dirty mask, and closed state.

- [ ] **Step 2: Run the lifecycle tests and verify red**

Run the new test methods individually. Expected: missing adapter/bridge type or
missing `cl_bridge_init/open/close` symbol.

- [ ] **Step 3: Add exact callback and adapter types**

Define these signatures in the header:

```c
typedef int32_t (*cl_lifecycle_open_fn)(void *, const cl_state *);
typedef int32_t (*cl_lifecycle_close_fn)(void *);
typedef int32_t (*cl_input_sink_fn)(
    void *, const cl_input_event *, cl_bridge_report *
);
typedef int32_t (*cl_input_attach_fn)(void *, cl_input_sink_fn, void *);
typedef int32_t (*cl_input_detach_fn)(void *);
typedef int32_t (*cl_model_submit_fn)(void *, const cl_processing_snapshot *);
typedef int32_t (*cl_output_apply_fn)(
    void *, uint8_t, const cl_processing_snapshot *
);
```

Add `cl_lifecycle_adapter`, `cl_input_adapter`, `cl_model_adapter`, and
`cl_output_adapter` structs, then aggregate them with the existing
`cl_view_adapter` and `cl_storage_adapter`:

```c
typedef struct cl_lifecycle_adapter {
    void *context;
    cl_lifecycle_open_fn open;
    cl_lifecycle_close_fn close;
} cl_lifecycle_adapter;

typedef struct cl_input_adapter {
    void *context;
    cl_input_attach_fn attach;
    cl_input_detach_fn detach;
} cl_input_adapter;

typedef struct cl_model_adapter {
    void *context;
    cl_model_submit_fn submit;
} cl_model_adapter;

typedef struct cl_output_adapter {
    void *context;
    cl_output_apply_fn apply;
} cl_output_adapter;

typedef struct cl_bridge_adapters {
    cl_lifecycle_adapter lifecycle;
    cl_view_adapter presentation;
    cl_input_adapter input;
    cl_storage_adapter persistence;
    cl_model_adapter model;
    cl_output_adapter output;
} cl_bridge_adapters;
```

Expose a concrete fixed-memory `cl_bridge` containing state, an immutable
retained processing snapshot, manifest, adapters, two revisions, last report,
dirty/open/attached/busy/opened-once/initialized flags. Keep the data prefix exactly 632
bytes before the pointer-bearing adapter set, avoiding implicit pointer-alignment
padding on ordinary 32-bit and 64-bit GCC hosts:

```c
typedef struct cl_bridge {
    cl_integration_manifest manifest;
    cl_bridge_report last_report;
    uint32_t state_revision;
    uint32_t processing_revision;
    cl_processing_snapshot retained_processing_snapshot;
    cl_state state;
    uint8_t dirty_mask;
    uint8_t opened;
    uint8_t input_attached;
    uint8_t busy;
    uint8_t opened_once;
    uint8_t initialized;
    uint8_t reserved[7];
    cl_bridge_adapters adapters;
} cl_bridge;
```

Add these exact declarations:

```c
size_t cl_bridge_size(void);
size_t cl_bridge_adapters_offset(void);
size_t cl_bridge_alignment(void);
cl_result cl_bridge_init(
    cl_bridge *, const cl_integration_manifest *, const cl_bridge_adapters *
);
cl_result cl_bridge_open(cl_bridge *, cl_bridge_report *);
cl_result cl_bridge_close(cl_bridge *, cl_bridge_report *);
const cl_state *cl_bridge_state(const cl_bridge *);
const cl_bridge_report *cl_bridge_last_report(const cl_bridge *);
uint32_t cl_bridge_state_revision(const cl_bridge *);
uint32_t cl_bridge_processing_revision(const cl_bridge *);
uint8_t cl_bridge_dirty_mask(const cl_bridge *);
```

Implement the alignment query with a C99 `offsetof` probe struct. Add compile-time
typedef assertions plus host tests for every fixed-data size, the adapter offset
`632`, and the reported bridge alignment. Do not hard-code total `cl_bridge`
size because pointer/function-pointer size is platform-dependent.

- [ ] **Step 4: Implement initialization and callback completeness validation**

`cl_bridge_init` must validate the manifest, require all six runtime records to
be `HOST_SIMULATED`, and require every callback:

- lifecycle open/close;
- presentation present;
- input attach/detach;
- persistence load/save;
- model submit; and
- output apply.

Require all-zero bridge storage before first initialization. Before mutation,
reject reentrant/busy init as `CL_ERR_BUSY` and live open/attached init as
`CL_ERR_ALREADY_OPEN`. Copy the caller structs through locals so reinitialization
may safely use the bridge's existing manifest/adapters, initialize default state,
set `initialized = 1`, and invoke no callback. Reinitialization after close or
failed admission is allowed. Return `CL_ERR_BINDING` for incomplete adapters.
Runtime-state validation occurs here, not later in `cl_bridge_open`.

- [ ] **Step 5: Implement open and close cleanup semantics**

Open must use a local candidate and a local 164-byte blob. Interpret load return
`0` as decode-required, `1` as exact default, and all other values as failure.
After lifecycle open succeeds, commit state at state/processing revision `1`,
build the retained processing snapshot, present the initial frame, attach the
internal sink, set open/attached flags, and leave the initial non-presentation
dirty bits for Task 4 synchronization. Initial presentation is an admission gate
and is not dirty/retryable. A failed attach must retain no sink. On either
failure, call close, clear the provisional dirty mask, and report both the
primary and cleanup raw results.

Attach failure is contractually atomic. Detach and close must complete teardown
even when returning a diagnostic failure. Close must attempt detach before
close, must attempt close after detach failure, and must clear open/attached
flags without clearing dirty bits. One initialization permits one open; an open
after close returns `CL_ERR_REINIT_REQUIRED`.

Use a busy guard around every callback. Reentrant bridge entry or input delivery
from attach/detach/present/load/save/model/output returns `CL_ERR_BUSY` without
state, report, or dirty mutation.

- [ ] **Step 6: Run lifecycle tests and mutation checks**

Run the focused module. Then locally mutate one callback pointer to null at a
time through the ctypes fixture and assert `cl_bridge_init == CL_ERR_BINDING`.
Assert repeated open returns `CL_ERR_ALREADY_OPEN` and close-before-open returns
`CL_ERR_NOT_OPEN` without callbacks. Assert reopen-after-close returns
`CL_ERR_REINIT_REQUIRED`.

Pin exact result precedence:

- manifest invalid -> `CL_ERR_MANIFEST`;
- incomplete callbacks -> `CL_ERR_BINDING`;
- load callback failure -> `CL_ERR_ADAPTER`;
- loaded blob decode failure -> `CL_ERR_BLOB`;
- lifecycle open/close failure -> `CL_ERR_LIFECYCLE`;
- attach failure -> `CL_ERR_INPUT_ATTACHMENT`;
- detach failure -> `CL_ERR_ADAPTER` unless close also fails, in which case
  `CL_ERR_LIFECYCLE` wins;
- initial present and all post-open synchronization callback failures ->
  `CL_ERR_ADAPTER`; and
- cleanup close failure overrides an admission present/attach failure.

For failed attach, use a fixture self-check that clears any provisional sink
before returning nonzero; do not claim the bridge can observe a private retained
pointer. Test detach and close diagnostic failures and prove the fixture has
made the sink/resource unreachable before returning. Retain all
`CFUNCTYPE` objects as fixture attributes. Copy frames with
`NativeFrame.from_buffer_copy(frame.contents)`, snapshots with
`ProcessingSnapshot.from_buffer_copy(snapshot.contents)`, save input with
`ctypes.string_at(data, size)`, and load bytes only after size validation using
`ctypes.memmove`. Inject load, attach, and detach exceptions: load must fail open
as `CL_ERR_ADAPTER`, while attach/detach must still leave the fixture sink and
resource unreachable.

- [ ] **Step 7: Commit lifecycle support**

```powershell
git add native/a6400_creative_look/creative_look_bridge.h native/a6400_creative_look/creative_look_bridge.c tests/analysis/test_creative_look_native_bridge.py
git commit -m "add Creative Look bridge lifecycle"
```

---

### Task 3: Canonical input, revisions, and processing-change classification

**Files:**
- Modify: `native/a6400_creative_look/creative_look_bridge.h`
- Modify: `native/a6400_creative_look/creative_look_bridge.c`
- Modify: `tests/analysis/test_creative_look_native_bridge.py`

**Interfaces:**
- Consumes: internal input sink and open bridge from Task 2.
- Produces: `cl_bridge_handle_event`, `cl_bridge_set_mode`, state/processing revisions, and exact dirty classification.

- [ ] **Step 1: Write failing event-delivery tests**

Capture the sink and sink context supplied to `attach`. Deliver a catalog touch
through that function pointer and assert the bridge, not the fake, changes state.
Drive coordinates from the real frame rectangles:

```python
frame = fixture.presented_frames[-1]
vv = next(element for element in frame.elements[:frame.count]
          if element.kind == CL_UI_KIND_LOOK and element.primary == CL_LOOK_VV)
event = InputEvent(vv.x + 1, vv.y + 1, CL_INPUT_TOUCH, 0, (0, 0))
result = fixture.deliver(event)
self.assertEqual(result, CL_OK)
self.assertEqual(fixture.state().selected_look, CL_LOOK_VV)
```

Add literal assertions for:

- state revision increments once;
- processing revision increments for Look/base/axis/mode changes;
- orientation increments only state revision;
- screen/editor navigation does not increment processing revision;
- restricted/no-hit/invalid events change neither revision nor state;
- a captured sink called after close, while bridge storage remains alive,
  returns `CL_ERR_NOT_OPEN`;
- delivery during attach/detach or another callback returns `CL_ERR_BUSY`;
- state revision `UINT32_MAX` rejects every real change before mutation; and
- processing revision `UINT32_MAX` rejects only processing changes, while a
  screen/orientation-only change can still commit if state revision permits.

- [ ] **Step 2: Run event tests and verify red**

Expected: missing `cl_bridge_handle_event`/`cl_bridge_set_mode` symbols or no
revision/dirty behavior.

- [ ] **Step 3: Implement report reset and selective state comparison helpers**

Implement private loops that compare only:

- selected Look;
- all six Custom bases;
- all `18 × 8` adjustments; and
- mode bits.

Do not compare screen, editing axis, or orientation for processing changes. Add a
private report initializer that writes `CL_CALLBACK_NOT_ATTEMPTED` to all six
sync results and all five lifecycle/input/load results without `memset`.

- [ ] **Step 4: Implement canonical event handling**

`cl_bridge_handle_event` must accept only canonical touch and orientation
records. Require zero reserved bytes; touch requires `value = 0`; orientation
requires `x = y = 0` and value in `{0, 1, 2}`. Use a candidate state and call
real core transitions. Check state overflow for every real change and processing
overflow only after detecting a processing-relevant change. On success:

- increment state revision;
- mark presentation and persistence dirty;
- if processing-relevant fields changed, increment processing revision and mark
  model/live/still/movie dirty, replacing the retained processing snapshot
  exactly once;
- set `report.state_committed = 1`; and
- call the private synchronization entry added as a no-op shell until Task 4.

The internal sink passed to the input adapter delegates to this public function.
Declare it exactly as:

```c
cl_result cl_bridge_handle_event(
    cl_bridge *, const cl_input_event *, cl_bridge_report *
);
```

- [ ] **Step 5: Implement mode updates with no-op detection**

`cl_bridge_set_mode` must apply `cl_set_mode` to a candidate. If the mode bits are
unchanged, return `CL_OK` with `state_committed = 0`, unchanged revisions, and no
callback attempt. A real change dirties all six synchronization domains.

Declare it exactly as:

```c
cl_result cl_bridge_set_mode(
    cl_bridge *, uint8_t mode, int enabled, cl_bridge_report *
);
```

- [ ] **Step 6: Run focused tests and compare with existing native behavior**

Run bridge, core, and view modules. The bridge touch flow must reach the same
states as direct `cl_view_touch` for built-in selection, Custom-base selection,
axis editing, reset, and catalog navigation.

- [ ] **Step 7: Commit canonical input handling**

```powershell
git add native/a6400_creative_look/creative_look_bridge.h native/a6400_creative_look/creative_look_bridge.c tests/analysis/test_creative_look_native_bridge.py
git commit -m "add Creative Look bridge input flow"
```

---

### Task 4: Dirty synchronization, full-state snapshots, and retry

**Files:**
- Modify: `native/a6400_creative_look/creative_look_bridge.h`
- Modify: `native/a6400_creative_look/creative_look_bridge.c`
- Modify: `tests/analysis/test_creative_look_native_bridge.py`

**Interfaces:**
- Consumes: dirty masks and revisions from Task 3.
- Produces: `cl_bridge_sync`, `cl_bridge_retry`, snapshot construction, persistence/model/output calls, and per-domain reports.

Add these exact public declarations before writing the tests:

```c
cl_result cl_bridge_sync(cl_bridge *, cl_bridge_report *);
cl_result cl_bridge_retry(cl_bridge *, cl_bridge_report *);
```

- [ ] **Step 1: Write failing deterministic synchronization tests**

After one processing-changing touch, assert exact callback order:

```python
self.assertEqual(
    fixture.calls[-6:],
    ["present", "save", "model", "live_view", "still_jpeg", "movie"],
)
self.assertEqual(report.attempted, 0x3F)
self.assertEqual(report.succeeded, 0x3F)
self.assertEqual(report.failed, 0)
self.assertEqual(report.dirty, 0)
```

Capture the model and output snapshots by value inside callbacks. Assert:

- ABI version `1`;
- output mask `7`;
- processing revision equals the report;
- selected Look and all six Custom bases match bridge state;
- all `18 × 8` adjustment bytes match;
- effective base equals the selected built-in or selected Custom base; and
- all three output callbacks receive byte-identical snapshots and distinct
  literal output kinds `0`, `1`, `2`.

- [ ] **Step 2: Write failing partial-failure/retry tests**

Make persistence and still-JPEG callbacks fail once. Assert presentation, model,
live, and movie still run and clear. Assert dirty mask equals
`CL_SYNC_PERSISTENCE | CL_SYNC_STILL_JPEG`. On `cl_bridge_retry`, assert only
`save` and `still_jpeg` run, both receive the same revision/state, and dirty mask
becomes zero.

Also assert screen-only and orientation-only changes call only `present` and
`save`. Add the critical immutable-retry test: fail model or an output at
processing revision N, capture the snapshot bytes, apply a screen-only and then
orientation-only change, retry, and assert the adapter receives byte-identical
snapshot bytes with the same revision N. Then create a newer processing change
while N remains dirty and assert the bridge coalesces to one retained snapshot
for revision N+1 rather than replaying N.

- [ ] **Step 3: Run synchronization tests and verify red**

Expected: dirty bits remain set or callbacks/snapshots are absent.

- [ ] **Step 4: Implement retained snapshot and effective-base construction**

Build and store one `cl_processing_snapshot` when open creates revision 1 and
whenever a processing-relevant change creates a newer revision. Never rebuild it
for a retry or UI-only change. For a built-in selected Look, effective base is
that Look. For a Custom Look, use
`custom_bases[selected_look - CL_BUILT_IN_LOOK_COUNT]`; reject `CL_UNSET` as
`CL_ERR_STATE` before committing the processing change or invoking
model/output callbacks. A newer processing change replaces the retained
snapshot and coalesces all already-dirty model/output domains to the new desired
revision.

- [ ] **Step 5: Implement all six synchronization domains**

`cl_bridge_sync` must process dirty bits in exact order and continue after every
failure. Store each callback's raw `int32_t` return in the corresponding report
slot. Clear only successful bits. Set the overall result to
`CL_ERR_ADAPTER` if any attempted callback fails.

Persistence uses `cl_encode` into a local 164-byte array and then invokes the
existing save callback directly. Presentation uses `cl_view_build` and invokes
the existing present callback directly. This preserves raw callback results that
`cl_storage_save`/`cl_view_present` would normalize away. Model uses the retained
snapshot callback. Output uses three independent calls and bits, all with that
same retained snapshot.

- [ ] **Step 6: Integrate initial-open synchronization**

When startup load returns missing, mark persistence dirty. For both missing and
restored state, mark model/live/still/movie dirty. After admission present and
attach succeed, call synchronization starting after presentation so it is not
presented twice. Sync failure leaves the bridge open, returns `CL_ERR_ADAPTER`,
and retains failed dirty bits for retry. Replace Task 2's prefix-only assertions
with the final exact sequences: missing storage calls
`load, open, present, attach, save, model, live_view, still_jpeg, movie`; restored
storage calls the same sequence without `save`. Add an initial post-attach sync
failure test proving the bridge remains open with only failed domains dirty.

- [ ] **Step 7: Run focused tests and mutation checks**

For each domain, mutate success to failure and assert only that domain remains
dirty. Mutate output kind order and assert literal call-log expectations fail.
Mutate snapshot copy to omit the last adjustment byte and assert byte-for-byte
snapshot checks fail.

- [ ] **Step 8: Commit synchronization and retry**

```powershell
git add native/a6400_creative_look/creative_look_bridge.h native/a6400_creative_look/creative_look_bridge.c tests/analysis/test_creative_look_native_bridge.py
git commit -m "add Creative Look bridge synchronization"
```

---

### Task 5: Exhaustive product coverage and freestanding ABI verification

**Files:**
- Modify: `tests/analysis/test_creative_look_native_bridge.py`
- Modify: `native/a6400_creative_look/creative_look_bridge.c` only for defects exposed by the new failing tests

**Interfaces:**
- Consumes: complete bridge API from Tasks 1–4.
- Produces: exhaustive contract evidence across all catalog/state/orientation combinations and toolchain modes.

- [ ] **Step 1: Write the exhaustive bridge-flow test**

Use only captured input-sink events and `cl_bridge_set_mode`; do not mutate bridge
state directly. Cover literal contract sets:

```python
BUILT_INS = tuple(range(12))
CUSTOMS = tuple(range(12, 18))
AXIS_CASES = (
    (0, -9, 9), (1, -9, 9), (2, -9, 9), (3, 0, 9),
    (4, -9, 9), (5, 0, 9), (6, 1, 5), (7, 0, 9),
)
ORIENTATIONS = (0, 1, 2)
```

For every built-in, select through its rendered rectangle. For every Custom
slot and every built-in base, select the Custom and base through rendered
rectangles. For every axis, set literal minimum and maximum through the axis
picker. Verify every transition appears in a persisted blob and full snapshot.

- [ ] **Step 2: Run the exhaustive test and verify red if any path bypasses bridge**

Expected on a complete implementation: pass. If it passes immediately, perform
the required mutation check by temporarily skipping one Custom slot or output
snapshot copy and confirm the test fails, then restore production code.

- [ ] **Step 3: Add restriction and atomicity matrices**

Test the existing exact restrictions through bridge-delivered events:

- Intelligent Auto;
- Picture Profile not Off;
- Flexible ISO Log;
- BW/SE Saturation; and
- movie Sharpness Range.

For each rejection, assert state bytes, revisions, dirty mask, and callback log
are unchanged. Repeat for no-hit and invalid orientation.

- [ ] **Step 4: Add strict compile/link/analyzer tests**

First compile and link the hosted shared library with the exact common flags
`-std=c99 -Wall -Wextra -Werror -pedantic -I <native-dir>`, treating any warning
as failure. Assert `creative_look_bridge.c` directly includes only
`creative_look_bridge.h`; its transitive dependencies come from that public
header.

Then compile all three C modules freestanding. All object paths must live in one
test-owned temporary directory. Resolve the exact linker selected by GCC with
`gcc -print-prog-name=ld` and invoke that executable for the relocatable link;
never use an arbitrary `ld` from `PATH`, fabricate a symbol definition, or
allowlist/filter an undefined symbol:

```powershell
gcc -std=c99 -Wall -Wextra -Werror -pedantic -I native/a6400_creative_look -ffreestanding -fno-builtin -c native/a6400_creative_look/creative_look_core.c -o <tmp>/creative_look_core.o
gcc -std=c99 -Wall -Wextra -Werror -pedantic -I native/a6400_creative_look -ffreestanding -fno-builtin -c native/a6400_creative_look/creative_look_view.c -o <tmp>/creative_look_view.o
gcc -std=c99 -Wall -Wextra -Werror -pedantic -I native/a6400_creative_look -ffreestanding -fno-builtin -c native/a6400_creative_look/creative_look_bridge.c -o <tmp>/creative_look_bridge.o
$linker = (& gcc -print-prog-name=ld).Trim()
& $linker -r <tmp>/creative_look_core.o <tmp>/creative_look_view.o <tmp>/creative_look_bridge.o -o <tmp>/creative_look_native.o
nm -u <tmp>/creative_look_native.o
gcc -std=c99 -Wall -Wextra -Werror -pedantic -I native/a6400_creative_look -fanalyzer -c native/a6400_creative_look/creative_look_bridge.c -o <tmp>/creative_look_bridge_analyzer.o
```

Tests must use temporary directories and assert `nm -u` is empty. Missing `nm`
is a verification failure, not a silent pass. A mutation object with a deliberate
undefined symbol must be rejected. Tests must also assert compilation succeeds
without warning text. The ctypes ABI test asserts every wire size, natural field
offset, `Bridge.adapters.offset == 632`, the C offset query, and the C alignment
query. It must not hard-code total bridge size.

- [ ] **Step 5: Run all native tests**

```powershell
& '.\.venv\Scripts\python.exe' -m unittest tests.analysis.test_creative_look_native_core tests.analysis.test_creative_look_native_view tests.analysis.test_creative_look_native_bridge -v
```

- [ ] **Step 6: Commit exhaustive verification**

```powershell
git add tests/analysis/test_creative_look_native_bridge.py native/a6400_creative_look/creative_look_bridge.c
git commit -m "verify Creative Look bridge coverage"
```

---

### Task 6: Documentation, safety contract, and publication gates

**Files:**
- Modify: `native/a6400_creative_look/README.md`
- Modify: `tests/analysis/test_creative_look_native_bridge.py`

**Interfaces:**
- Consumes: verified bridge behavior from Tasks 1–5.
- Produces: user-facing integration boundary documentation and final repository evidence.

- [ ] **Step 1: Write the failing safety behavior test**

Add a test that compiles and calls `cl_bridge_manifest_host`, then asserts all
four safety fields are zero and that setting any one nonzero makes
`cl_bridge_validate_manifest` return `CL_ERR_MANIFEST`. This tests validator
behavior rather than grepping prose.

Add a source-safety scan restricted to production bridge files for APIs that
would create operational capability:

```python
forbidden = (
    "system(", "popen(", "CreateProcess", "ShellExecute", "dlopen(",
    "libusb", "CreateFile", "DeviceIoControl", "/dev/", "nflasha",
)
```

Assert none occurs. Do not reject explanatory README prose.

- [ ] **Step 2: Run the new safety test and verify red if coverage is absent**

Expected: fail until the test is registered and any unsafe source token is
removed.

- [ ] **Step 3: Update the native README**

Document:

- the six adapters;
- the evidence/runtime separation;
- complete-state snapshots rather than five Creative Style values;
- deterministic dirty retry;
- exact host-only execution profile; and
- unresolved Sony lifecycle, storage identity, model/output sinks, and stock
  recovery.

State explicitly that the bridge is an integration simulator and ABI contract,
not camera-ready firmware.

- [ ] **Step 4: Run focused, full analysis, and safety suites**

```powershell
& '.\.venv\Scripts\python.exe' -m unittest tests.analysis.test_creative_look_native_core tests.analysis.test_creative_look_native_view tests.analysis.test_creative_look_native_bridge -v
& '.\.venv\Scripts\python.exe' -m unittest discover -s tests\analysis
& '.\.venv\Scripts\python.exe' -m unittest discover -s tests\safe
git diff --check
```

Required result: zero failures, zero errors, and clean whitespace.

- [ ] **Step 5: Audit objective coverage against current sources**

Record the final evidence table in the handoff:

- 12-Look catalog: bridge-exercised offline;
- six Custom slots: bridge-exercised offline;
- eight axes: bridge-exercised offline;
- landscape and both portrait orientations: bridge-exercised offline;
- persistence: exact 164-byte host adapter exercised;
- Sony runtime identities: absent/unproven;
- processing outputs: host-simulated only;
- exact TW/region-0 2.00 restoration: unverified;
- camera eligibility/installability: false.

Do not mark the overall project goal complete while the final four rows remain
unproven or false.

- [ ] **Step 6: Commit documentation and safety coverage**

```powershell
git add native/a6400_creative_look/README.md tests/analysis/test_creative_look_native_bridge.py
git commit -m "document Creative Look bridge boundary"
```

- [ ] **Step 7: Verify final branch scope**

```powershell
git status -sb
git log --oneline origin/master..HEAD
git diff --stat origin/master...HEAD
git diff --check origin/master...HEAD
```

Expected: only the approved spec, this plan, native bridge/core/README files, and
bridge/safety tests differ from `origin/master`; the worktree is clean.
