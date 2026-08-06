# α6400 offline receiver/control trace plan

**Goal:** Narrow the missing pre-normal-runtime selector and pre-2.00 installing-receiver boundary using only already-acquired offline artifacts, while keeping every recovery and camera-eligibility flag false.

**Safety boundary:** The camera remains physically disconnected. Do not execute Sony camera binaries, issue device commands, write partitions, build an updater, expose raw firmware/key material, or infer α6400 recovery from a different-model control sample.

## Evidence outcome from inventory

- The exact ILCE-6400 TW/region-0 2.00 stock updater is present and authenticated.
- No original ILCE-6400 package older than 2.00 exists in the repository artifacts or `D:\Downloads` inventory.
- ILCE-6400A EU 1.01 is the only older close-family receiver control. Its model ID is `0x81030017`, not the original α6400 ID `0x81030011`.
- The α6400A updater partition is a structural control only. It cannot establish target acceptance, target write scope, recovery, or selector behavior.

## Task 1: Commit a fail-closed offline source inventory

Create a strict metadata-only report and validator that distinguish the exact target, missing exact pre-2.00 source, and non-transferable controls. Reject any report that promotes the α6400A or α7 III samples into target recovery evidence.

Files:

- Create `analysis/a6400-offline-receiver-inventory.json`
- Create `pmca/analysis/offline_receiver_inventory.py`
- Create `tests/analysis/test_offline_receiver_inventory.py`

## Task 2: Map the control-sample bootstrap graph

Record digest-pinned script/binary identities and bounded invocation edges only: updater init, boot-validity check, mode dispatcher, production/UFP branches, preparation, receiver, input feeder, and reboot boundary. Do not preserve command arguments, device paths, payload bytes, or write recipes.

Files:

- Create `analysis/a6400a-updater-control-bootstrap.json`
- Create `pmca/analysis/updater_control_bootstrap.py`
- Create `tests/analysis/test_updater_control_bootstrap.py`

## Task 3: Export a bounded static `sauu` control graph

Use Ghidra as a read-only analyzer, never as an emulator. Start from the already identified guard, comparison, signature, and caller roots. Preserve unresolved direct/indirect edges and cap functions, depth, and calls. Add write-orchestrator or completion roots only when independently identified; otherwise keep them `UNESTABLISHED`.

Files:

- Create `tools/ghidra/export_a6400a_sauu_control.py`
- Extend `pmca/analysis/updater_control_bootstrap.py`
- Extend `tests/analysis/test_updater_control_bootstrap.py`
- Update `analysis/a6400a-updater-control-bootstrap.json`

## Task 4: Integrate without promoting recovery

Update the recovery reports only with architecture-control evidence. The exact α6400 pre-2.00 receiver and pre-normal selector remain missing; all three recovery candidates, all six scenarios, `recovery_validated`, and `camera_test_eligible` remain unchanged.

## Verification

Run focused tests, byte-compilation, the full analysis suite, `git diff --check`, a tracked-artifact/private-key/installable scan, and a read-only review before each commit.
