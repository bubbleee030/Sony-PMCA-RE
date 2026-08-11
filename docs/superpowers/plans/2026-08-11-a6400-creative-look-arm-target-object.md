# α6400 Creative Look ARM Target-Object Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use
> `superpowers:subagent-driven-development` to execute this plan task-by-task,
> `superpowers:test-driven-development` for every production change, and
> `superpowers:verification-before-completion` before any completion claim.

**Goal:** Compile the existing first-class Creative Look implementation into a
verified α6400-compatible ARMv7-A/Thumb-2 relocatable object and add a neutral,
non-published target shell that proves lifecycle/frame/input ownership without
claiming Sony runtime integration.

**Architecture:** Keep core/view/bridge behavior unchanged. Add a fixed-memory
`cl_target_shell` around the bridge, compile all four modules with a
digest-verified official Arm GNU toolchain, and verify the combined `ET_REL`
object entirely by static ELF/ABI/symbol inspection. No target executable,
shared object, firmware package, Sony loader binding, persistence provider, or
processing sink is added.

**Tech stack:** C99, Python 3 `unittest`, `ctypes`, Arm GNU Toolchain
15.2.Rel1 AArch32 bare-metal, `readelf`, `nm`, `objdump`, repository safety
tests.

## Global constraints

- Approved design:
  `docs/superpowers/specs/2026-08-11-a6400-creative-look-arm-target-object-design.md`.
- Static/offline only. Never access a camera or execute a Sony camera binary.
- Produce only temporary/ignored ARM `.o` files. Never emit `.so`, executable
  ELF, raw binary, package, partition image, or flashable output.
- Keep all manifest runtimes host-simulated and all four safety values zero.
- Do not export `ViewCreativeLookToInstance` or any Sony-mangled symbol.
- Do not publish a menu root, registration row, process ID, Backup record,
  `/setting` path, image-processing handler, or output sink.
- Use official Arm primary sources only. Verify SHA-256 before extraction.
- Toolchains and built objects live only under ignored `.artifacts/` or an
  automatically cleaned temporary directory.
- Reject unsafe ZIP entries before extraction. The pinned digest is an
  independently reviewed contract; this milestone does not claim OpenPGP
  verification.
- Production remains allocation-free, I/O-free, dynamic-loader-free,
  thread-free, and fixed-memory.
- All production changes begin with an observed failing test.

## File map

| Path | Responsibility |
|---|---|
| `analysis/a6400-creative-look-arm-target-profile.json` | Pinned target ELF attributes, official toolchain identity/digest, exact compile/link contract, and fail-closed capability claims. |
| `pmca/analysis/creative_look_arm_target_profile.py` | Validate the tracked target/toolchain contract and normalized raw build evidence. |
| `tools/static/export_a6400_creative_look_arm_target.py` | Compile/link using an explicit verified toolchain directory and export normalized static evidence; no target execution. |
| `native/a6400_creative_look/creative_look_target.h` | Neutral target-shell public C ABI and proposed-unpublished identity metadata. |
| `native/a6400_creative_look/creative_look_target.c` | Shell lifecycle, frame copy, input sink lifetime, and bridge delegation. |
| `native/a6400_creative_look/README.md` | Target-compiled/runtime-unbound status and remaining persistence/processing/runtime gates. |
| `tests/analysis/test_creative_look_arm_target.py` | Contract validation, hosted shell behavior, target ABI compile/link/ELF checks, mutations, and safety scans. |
| `tests/analysis/creative_look_native_abi.py` | Extend the shared hosted fixture only if needed for the target shell; do not duplicate existing bridge declarations. |

The generated raw build record belongs under ignored
`.artifacts/analysis-output/`; the tracked JSON contains normalized evidence and
the digest of the raw record, never an object file.

---

### Task 1: Pin and validate the official target/toolchain contract

**Files:**

- Create: `analysis/a6400-creative-look-arm-target-profile.json`
- Create: `pmca/analysis/creative_look_arm_target_profile.py`
- Create: `tests/analysis/test_creative_look_arm_target.py`

**Step 1: Write the failing profile-existence and validation tests**

- Assert the three files exist.
- Load the JSON and call a real validator.
- Assert exact target hash, ELF class/data/machine/EABI, CPU architecture,
  Thumb-2, VFPv3-D16, softfp call ABI, `wchar_t`, enum, and stack alignment.
- Assert the official archive basename, Arm primary-source URLs, exact SHA-256,
  target triple, release, compile flags, link mode, output type, and four zero
  safety claims.

Run the one test and record RED because the files do not exist.

**Step 2: Acquire the checksum contract**

- Fetch the official `.sha256asc` companion only.
- Pin its source URL and exact parsed digest.
- Download the official ZIP to ignored `.artifacts/toolchains/downloads/`.
- Measure its SHA-256 and abort before extraction unless it equals the pinned
  official digest.
- Extract to a release-specific ignored directory and resolve all tools by
  absolute path from there.

No tracked code may auto-download during imports or ordinary unit tests.

**Step 3: Implement a strict pure validator**

The validator must reject:

- wrong target/library hash;
- missing or changed mandatory target attributes and any prohibited target
  attribute value; benign extra compiler attributes are recorded;
- non-official or non-HTTPS URLs;
- malformed or wrong archive digest;
- target triple/version drift;
- omitted hardening/target flag or added `-mfloat-abi=hard`;
- output other than `ET_REL`/`.o`;
- an undefined-symbol allowlist;
- any runtime/installability safety promotion; and
- narrative/digest mismatches.

Mutation-test each class independently.

**Step 4: Green and commit**

Run the focused profile tests, `py_compile`, validator round-trip, and
`git diff --check`. Commit only the three scoped files.

---

### Task 2: Compile the existing core/view/bridge as real ARM objects

**Files:**

- Create: `tools/static/export_a6400_creative_look_arm_target.py`
- Modify: `tests/analysis/test_creative_look_arm_target.py`
- Modify only if evidence schema requires it:
  `pmca/analysis/creative_look_arm_target_profile.py`
  and `analysis/a6400-creative-look-arm-target-profile.json`

**Step 1: Write target-builder RED tests before the exporter**

Tests invoke the exporter with an explicit pinned toolchain directory and fail
because the exporter/API is absent. The test owns a temporary output directory
and asserts no output is written outside it.

**Step 2: Implement explicit tool resolution and source allowlisting**

- Resolve compiler, linker, `readelf`, `nm`, and `objdump` by absolute path.
- Reject missing, relative, outside-toolchain, wrong-target, or wrong-version
  binaries.
- Compile exactly `creative_look_core.c`, `creative_look_view.c`, and
  `creative_look_bridge.c`; additionally hash and safety-scan their exact three
  public headers. Reject an unapproved source or header.
- Invoke subprocesses without a shell and capture complete diagnostics.
- Never continue after a command failure.

**Step 3: Compile and naturally link**

- Compile each source independently with the exact design flags.
- Link with the matching `ld -r` without fabricated symbols or filters.
- Run `nm -u` and require byte-for-byte empty normalized output.
- Require no `__aeabi_*` definition/reference, startup symbol, libc/libgcc
  dependency, initializer, or finalizer.

**Step 4: Verify ELF and the actual 32-bit ABI**

Create a test-only ABI probe using compile-time array assertions for:

- sizes/alignment `155/1`, `36/1`, `228/2`, `164/4`, `64/4`, `60/4`,
  `692/4`; and
- `offsetof(cl_bridge, adapters) == 632`.

Compile the probe with the same target flags. Inspect header/attributes and
require ELF32, little-endian ARM, EABI5, ARMv7-A, Thumb-2, VFPv3-D16, softfp,
four-byte wchar/enum, and eight-byte stack alignment.
Require `Tag_ABI_VFP_args` to be absent, while recording and permitting benign
modern-compiler attributes outside the mandatory/prohibited set.

**Step 5: Add mutation coverage**

Each of these must fail:

- substitute hard-float;
- substitute ARMv6 or remove Thumb;
- link as executable/shared object;
- add one deliberate undefined symbol;
- add one `__aeabi_*` reference;
- change one ABI size/offset;
- add an unapproved source;
- use a bare `arm-none-eabi-gcc` resolved from `PATH`; and
- request a `.so`, `.elf`, `.bin`, or package output.

**Step 6: Export normalized evidence and commit**

The normalized record includes commands, tool hashes/versions, source hashes,
ELF attributes, layouts, sections, relocations, symbols, safety scan, and raw
record digest. It must not include absolute user paths or object bytes.

Run focused tests and diff checks. Commit the scoped exporter/tests/schema
changes.

---

### Task 3: Add the neutral Creative Look target shell with TDD

**Files:**

- Create: `native/a6400_creative_look/creative_look_target.h`
- Create: `native/a6400_creative_look/creative_look_target.c`
- Modify: `tests/analysis/test_creative_look_arm_target.py`
- Modify if shared declarations are required:
  `tests/analysis/creative_look_native_abi.py`

**Step 1: Write missing-export RED tests**

The hosted fixture must require these neutral APIs before they exist:

- `cl_target_shell_size`, `cl_target_shell_alignment`;
- `cl_target_shell_init`, `open`, `close`, `deliver`;
- copied-frame, bridge-state, and last-report read-only accessors; and
- an identity metadata accessor returning proposed-unpublished status.

Observe RED for missing files/exports.

**Step 2: Define the public target-shell ABI**

Use fixed-width status fields and an embedded bridge/frame. The public identity
record contains only the three proposed labels and an explicit unpublished
status. It contains no function pointer named as a Sony factory.

Initialization accepts a validated host manifest and caller-owned adapters,
requires caller lifecycle/presentation/input entries to be zero, installs
shell-owned wrappers for those entries, and remains mutation-free on invalid
input. Caller persistence/model/output functions, contexts, and resources must
outlive the initialized/open shell and remain caller-owned. It cannot promote
evidence/runtime/safety.

**Step 3: Implement lifecycle and ownership**

- `open` delegates exactly once and exposes the resulting bridge report.
- presentation copies the full frame before returning;
- attach retains the bridge sink/context only until detach completes;
- `deliver` calls only the currently retained sink;
- close attempts detach then lifecycle close through the bridge;
- shell open/attached state mirrors the embedded bridge rather than return
  codes: a post-attach sync error remains open/deliverable until close, while
  any completed close invalidates delivery even when teardown reports error;
- first initialization requires all-zero storage, live reinitialization is
  rejected without mutation, and reinitialization is permitted after close or
  any pre-attachment open failure when the embedded bridge is not
  busy/open/attached;
- delivery before attach/after detach and reentrant delivery fail without
  mutation; and
- borrowed callback pointers are never retained except the exact attached
  sink/context pair.

**Step 4: Exhaustive hosted behavior tests**

Verify:

- open ordering plus pre-attachment load failure and post-attachment
  persistence/model/output synchronization failure behavior; lifecycle,
  presentation, attach, detach, close, and callback-reentrancy failure
  precedence remains covered by the existing bridge suite because the shell's
  fixed wrappers have no production failure-injection seam;
- copied-frame byte independence after the callback returns;
- all 12 built-ins, 6 Custom slots, 8 axis min/default/max values, and 3
  orientations through only the retained input sink;
- stale-sink rejection and post-attach-error delivery/close behavior;
- busy/reentrancy rejection through caller-injected persistence/model/output
  callbacks;
- exact manifest immutability and all four safety zeros; and
- identity labels are returned but never treated as runtime bindings.

Perform and restore a mutation that retains a borrowed frame pointer instead of
copying it; the lifetime test must turn RED.

**Step 5: Green and commit**

Run the full hosted native suite, strict hosted/freestanding compilation,
analyzer, natural host `ld -r`/empty `nm -u`, pycompile, and diff checks. Commit
only shell/test files.

---

### Task 4: Include the shell in the ARM target-object evidence

**Files:**

- Modify: `tools/static/export_a6400_creative_look_arm_target.py`
- Modify: `tests/analysis/test_creative_look_arm_target.py`
- Modify: `pmca/analysis/creative_look_arm_target_profile.py`
- Modify: `analysis/a6400-creative-look-arm-target-profile.json`

**Step 1: Record RED for an absent shell object**

Require four ARM production objects and prove the current three-source exporter
fails the new contract.

**Step 2: Compile/link/inspect all four modules**

Add `creative_look_target.c` to the compile allowlist and
`creative_look_target.h` to the dependency allowlist. Regenerate normalized
evidence and require the same ELF/ABI/symbol/safety contracts across all four
sources and all four headers.

**Step 3: Enforce the non-publication boundary**

Fail if symbols or relocations contain:

- `ViewCreativeLookToInstance` as an exported or undefined symbol (its one
  designated metadata-string occurrence is permitted);
- `dlopen`, `dlsym`, `IdSoTable`, `IdGenerator`, or `openView` references;
- constructor/init-array publication;
- Backup/Fsys/Sony path references;
- processing/encoder symbols; or
- device/updater/flash/package operations.

The proposed factory label may appear only as read-only identity data returned
by the neutral metadata API.

**Step 4: Mutation tests and commit**

Temporarily export the proposed Sony factory symbol and prove rejection, then
restore it. Also mutate the output ELF type and one safety field. Run focused
tests and commit the normalized evidence slice.

---

### Task 5: Documentation, independent review, and publication verification

**Files:**

- Modify: `native/a6400_creative_look/README.md`
- Modify only for test hardening:
  `tests/analysis/test_creative_look_arm_target.py`

**Step 1: Update exact user-facing status**

Document:

- real ARMv7-A/Thumb-2 EABI5 target compilation;
- exact target ABI layouts and verified official toolchain identity;
- neutral shell ownership and proposed-unpublished identities;
- runtime-unbound menu/lifecycle/input/provider status;
- persistence and processing as separate future milestones; and
- unchanged recovery/camera/installability gates.

Avoid the phrases “camera-ready,” “Sony factory implemented,” “installable,” or
“processing supported” except in explicit negative statements.

**Step 2: Independent read-only review**

Review design, plan, production C, profile, exporter, normalized evidence, tests,
and README. Fix every concrete Critical/Important finding through new RED/GREEN
tests, then repeat review until clean.

**Step 3: Run final verification**

Run, from the repository virtual environment:

1. focused ARM target/shell tests;
2. complete native core/view/bridge/target suite;
3. complete safety suite;
4. `py_compile` for all changed Python;
5. fresh official-toolchain build/export/validation;
6. `git diff --check` and tracked-scope review; and
7. full `python -m unittest discover -s tests/analysis` with a generous timeout.

If full analysis times out, report the exact timeout and do not call it green.
No test may be filtered or silently skipped at publication time. Tests may
explicitly skip the real ARM compile on machines lacking the pinned toolchain,
but this milestone is not accepted locally unless the real gate ran and passed.

**Step 4: Publish without broadening the goal**

Commit the final documentation/test hardening. Confirm a clean worktree and
scope-only log. Push the branch, open a focused PR, verify checks, address review
findings, and merge only after the verified evidence remains unchanged. The
overall α7 V-like first-class goal remains incomplete after merge.

## Deferred follow-on plans

1. **Target-native persistence:** caller-injected feature-owned atomic file
   adapter with temporary-write, flush, rename, corruption handling, and an
   evidence-backed `/setting` namespace owner. Do not allocate a Backup ID.
2. **Processing:** separately trace a full-state still-processing consumer from
   a concrete parameter field into `MprIf::EncodeStill`; keep live view, movie,
   and eight axes unbound until proven.
3. **Sony view publication:** only after unique process ID, root/list consumer,
   provider binding, registration selection, factory ABI, close lifecycle, and
   input delivery are proven.
