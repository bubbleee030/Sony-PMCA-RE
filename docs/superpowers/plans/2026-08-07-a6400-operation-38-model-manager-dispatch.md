# α6400 Operation-38 ModelManager Dispatch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the fail-closed static Creative Style request evidence through the exact tag-0 producer path, audit the producer/consumer receiver identity, and bound the ModelManager request-event candidate without claiming a queue-to-consumer join, concrete model record, executor handler, Creative Look equivalence, runtime behavior, or installability unless those joins are proven.

**Architecture:** Keep the existing canonical Python evidence module as the closed contract, extend the static ELF exporter with instruction/dataflow validators, regenerate the JSON report from that contract, and update the deep-dive with only proven conclusions. The Event header, queue/consumer identity boundary, and ModelManager candidate dispatch are separate metadata objects so later model-record work can strengthen the last boundary without weakening prior checks.

**Tech Stack:** Python 3, `unittest`, Capstone, pyelftools, pinned offline α6400 firmware ELF metadata, JSON, Markdown.

## Global Constraints

- Use only `C:\Users\Bubble\ChatGPT\Sony\Sony-PMCA-RE-a6400-analysis`; `C:\ChatGPT` is not canonical.
- Preserve all unrelated and existing user changes.
- Static/offline only: no camera access, Sony binary execution, USB/device/partition writes, firmware packaging, or flashing.
- Do not emit raw key material or reconstructive proprietary bytes/disassembly.
- Recovery remains `BLOCKED_STATIC_EVIDENCE`; camera testing and installability remain false.
- Creative Look is the first-class target; Creative Style emulation remains fallback-only.
- Do not push or open a PR unless the user asks.

---

### Task 1: Event header and tag-zero queue contract

**Files:**
- Modify: `tests/analysis/test_creative_style_model_request_transport.py`
- Modify: `pmca/analysis/creative_style_model_request_transport.py`
- Modify: `tools/static/export_a6400_creative_style_model_request_transport.py`

**Interfaces:**
- Consumes: the existing `SHARED_LIBOBJ_TRANSPORT`, `SHARED_REQUEST_TO_EVENT_QUEUE_JOIN`, `EXPECTED_EXPORT`, and exporter decoding helpers.
- Produces: `OPERATION_38_EVENT_HEADER` and `OPERATION_38_QUEUE_DISPATCH` entries in `EXPECTED_EXPORT`.

- [x] **Step 1: Write the failing contract tests**

  Add assertions that the request builder uses Event ID `0x11004003`, destination `2`, and queue tag `0`; that `Event::Event` stores those values at `Event+4`, `Event+8`, and `Event+9`; and that later parameter-list methods do not promote a header mutation.

- [x] **Step 2: Run the focused test and confirm RED**

  Run `python -m unittest tests.analysis.test_creative_style_model_request_transport -v`. Expected: failure because the new metadata keys do not exist.

- [x] **Step 3: Add the minimal contract metadata**

  Add exact owner/site/offset/value fields and conservative claims:

  ```python
  "operation_38_event_header_proven": True
  "operation_38_tag_zero_queue_path_proven": True
  "operation_38_indirect_queue_callbacks_bypassed": True
  ```

  Preserve `literal_operation_38_event_field_proven=False` because Event key 8 still contains an opaque mapping result.

- [x] **Step 4: Add fail-closed exporter validation**

  Validate builder argument setup, constructor stores, Event ID/destination/tag accessors, the `EventManager::push` tag comparisons, tag-0 fallback branch, and direct queue helper target. Require unindexed memory operands and exact owner bounds.

- [x] **Step 5: Add mutation tests and confirm GREEN**

  Corrupt the builder ID/destination/tag, constructor offsets, queue tag branch, and fallback target one at a time. Each mutation must make the exporter reject the source; then rerun the focused suite.

### Task 2: Producer/consumer receiver identity and destination-two candidate routing

**Files:**
- Modify: `tests/analysis/test_creative_style_model_request_transport.py`
- Modify: `pmca/analysis/creative_style_model_request_transport.py`
- Modify: `tools/static/export_a6400_creative_style_model_request_transport.py`

**Interfaces:**
- Consumes: `OPERATION_38_QUEUE_DISPATCH` and the proven EventManager receiver from the shared request continuation.
- Produces: exact producer and consumer receiver expressions, an explicit false same-instance claim until a UtilityManager-to-outer back-reference is proven, and a separately bounded destination-bit-2 ModelManager candidate route.

- [x] **Step 1: Write failing identity-boundary tests**

  Assert the producer’s UtilityManager/global provenance, the consumer’s thread-local outer/EventManager provenance, the missing equality join, tag-0 consumer pop, central dispatcher call, `Event::getDest`, destination mask `2`, receiver `[outer+4]`, and direct ModelManager-owned dispatch call.

- [x] **Step 2: Confirm RED**

  Run the focused test module and verify the new identity-boundary assertions fail only because the metadata/validators are absent.

- [x] **Step 3: Implement exact join validators**

  Validate relocation type/address, constructor/store/load offsets, both symbolic receiver expressions, pop and dispatcher direct edges, destination mask/branch, ModelManager object construction, and receiver layout. Keep `same_event_manager_instance_proven` and `operation_38_queue_to_consumer_identity_proven` false unless a concrete assignment closes the join.

- [x] **Step 4: Add mutation coverage and confirm GREEN**

  Mutate the GOT cell/relocation, outer-object store, queue index, pop target, dispatcher target, destination mask, receiver offset, and ModelManager dispatch target. Require every mutation to fail closed.

### Task 3: Request-event branch and conditional executor boundary

**Files:**
- Modify: `tests/analysis/test_creative_style_model_request_transport.py`
- Modify: `pmca/analysis/creative_style_model_request_transport.py`
- Modify: `tools/static/export_a6400_creative_style_model_request_transport.py`

**Interfaces:**
- Consumes: destination-two ModelManager event dispatch and Event ID `0x11004003`.
- Produces: `OPERATION_38_MODEL_MANAGER_DISPATCH`, proving key-7/key-8 reads, registry lookup, and conditional generic executor dispatch while leaving concrete record/handler identity unresolved.

- [x] **Step 1: Write failing branch tests**

  Assert the request Event ID gate, key `6`, key `7`, and key `8` reads, key-7 registry lookup, construction of a secondary Event whose ID derives from opaque key 8, and the conditional executor helper/virtual-call boundary.

- [x] **Step 2: Confirm RED**

  Run the focused suite and verify failure is caused by the missing `operation_38_model_manager_dispatch` contract.

- [x] **Step 3: Implement the minimal exact validators**

  Pin direct calls, branch targets, literal arithmetic, parameter keys, register preservation, lookup owner, new Event argument flow, record executor offset, state/event stores, and virtual slot. Keep both valid-record and fallback routes explicit.

- [x] **Step 4: Add mutation coverage and confirm GREEN**

  Mutate the Event-ID gate, keys 7/8, lookup call, secondary Event arguments, executor offset, and virtual slot. Each must cause deterministic rejection.

### Task 4: Report, documentation, and independent trace integration

**Files:**
- Modify: `analysis/a6400-creative-style-model-request-transport.json`
- Modify: `analysis/a6400a-updater-and-creative-style-deep-dive.md`
- Modify: `pmca/analysis/creative_style_model_request_transport.py`

**Interfaces:**
- Consumes: all three new contract objects plus read-only parallel-agent results.
- Produces: canonical digest/report and a conservative research checkpoint.

- [x] **Step 1: Update readiness and conclusion**

  Subsequent evidence refinement uses readiness `OPERATION_38_CONFIG_ROUTE_TO_PRODUCER_IDENTITY_UNRESOLVED`: exact tag 0 bypasses all three queue indirect callbacks, and both selector comparison ABIs and their AppConfig/non-AppConfig routes are bounded. No factory-result capture or store joins either route to the later producer/consumer EventManager dataflow, so all route identity claims remain false. The runtime BSS route selector remains unresolved, and ModelManager delivery plus the model/CAMERA key-7 record binding remain bounded candidates.

- [x] **Step 2: Integrate only independently proven stronger results**

  If a parallel trace proves original `@M00B` mapping or a concrete record/handler with bounded dataflow and relocation/vtable provenance, add a separate test-first contract. Otherwise preserve the negative claims.

- [x] **Step 3: Regenerate the canonical JSON report**

  Build the report through the module/exporter path, update the evidence digest, and ensure unsafe/reconstructive fields remain rejected.

- [x] **Step 4: Update the deep-dive**

  Correct the old statement that queue indirect calls are the operation-38 blocker. Record the exact Event header, tag-zero producer queue path, missing consumer-identity join, ModelManager candidate branch, and next concrete experiment without claiming runtime behavior.

### Task 5: Verification, review, and local checkpoint

**Files:**
- Verify all modified files.

**Interfaces:**
- Consumes: completed implementation and documentation.
- Produces: fresh test evidence, independent read-only review, and one local commit.

- [x] **Step 1: Run focused and mutation tests**

  Run `python -m unittest tests.analysis.test_creative_style_model_request_transport -v` and confirm every mutation rejection test passes.

- [x] **Step 2: Run full static/safety verification**

  Run the repository’s full analysis suite, safe suite, `py_compile` for changed Python files, and `git diff --check`.

- [x] **Step 3: Request independent code review**

  Give a read-only reviewer the base SHA `1f50566`, requirements from this plan, and the current working diff. Fix all Critical/Important findings test-first and rerun verification.

- [x] **Step 4: Create a local checkpoint**

  Stage only the intended files and commit with a narrow analysis message. Do not push.
