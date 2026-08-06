# α6400 stock-2.00 recovery readiness

This is a static evidence checkpoint, not a recovery procedure. The camera remained physically disconnected. No camera code ran, no storage was changed, and no firmware was installed.

## Decision

- Readiness: `BLOCKED_STATIC_EVIDENCE`
- `recovery_validated=false`
- `camera_test_eligible=false`
- `installable=false`

The exact stock source is authenticated, but no external route is established that is independent of a failed normal runtime and has complete, verified restoration behavior.

## Authenticated stock identity

The authoritative record is [`analysis/a6400-stock-200-bundle.json`](../../../analysis/a6400-stock-200-bundle.json).

- Source key: `a6400-tw-v2.00`
- Camera: `ILCE-6400`
- Model ID: `0x81030011`
- Region: `TW`, region code `0`
- Version: `2.00`
- Official updater SHA-256: `ea460cbec5f8b62119630f0a653eeca4f4ffad887670e60c0fd9c0345e6b30a6`
- Embedded stock container SHA-256: `78a6881eddd16609758951c80d533ac82042858eac919bd94453941ba6b766f2`

These digests identify the recovery source. They do not prove that the camera will accept a same-version reinstall or that the update covers every damaged component.

## Candidate paths

| Candidate | Earliest established layer | Runtime-independent | Write scope | Verification | Result |
|---|---|---:|---|---|---|
| `official-updater-reinstall` | Windows host updater only | No | Unestablished | Unestablished | `UNESTABLISHED` |
| `usb-recovery-or-updater-mode` | Windows host mode-switch boundary only | No | Unestablished | Unestablished | `UNESTABLISHED` |
| `independent-maintenance-path` | Unlocated | No | Unestablished | Unestablished | `UNESTABLISHED` |

The official host engine maps DAT parsing, transfer state, mode switching, and model/version return statuses. Those observations stop at the host boundary. The camera-side receiver that installs 2.00 predates the available post-install 2.00 components and has not been located.

## Gate status

- Stock bundle identity: established.
- Host updater and transport boundaries: partial.
- Camera updater gate: partial only because the host decodes returned model/version statuses; the enforcing camera logic is unavailable.
- Runtime-independent entry: unestablished.
- Signed ranges and trust anchor: unestablished.
- Same-version reinstall or downgrade acceptance: unestablished.
- Complete write scope and ordering: unestablished.
- Post-write verification and commit behavior: unestablished.
- Restart, resume, rollback, and safe terminal behavior after power loss: unestablished.

## Mandatory failure scenarios

Every scenario was assessed against all three candidates and remains `UNESTABLISHED`:

- `modified-ui-runtime-failure`
- `interrupted-feature-update`
- `nonbooting-application-layer`
- `version-or-downgrade-rejection`
- `boot-chain-failure`
- `power-loss-during-stock-restore`

The exact matrix is in [`analysis/a6400-recovery-scenarios.json`](../../../analysis/a6400-recovery-scenarios.json), and the gate/candidate report is in [`analysis/a6400-stock-200-recovery.json`](../../../analysis/a6400-stock-200-recovery.json).

## Stop conditions

Stop before any physical validation design while any of the following remains unresolved:

- the earliest camera-side updater entry and its independence from the normal UI/runtime;
- the authentic earlier receiver that installs version 2.00, or equivalent bounded evidence;
- model, region, version, and authenticity checks before modification;
- complete write scope, ordering, commit point, and post-write verification;
- exact same-version reinstall acceptance; or
- safe behavior for interruption and power loss.

No camera instructions are supplied because the current evidence cannot bound the damage or prove recovery after a failed attempt. A settings reset is not firmware restoration.

## Evidence required for a later phase

A separate future-validation design may be drafted only after static evidence establishes all of the following:

1. A runtime-independent entry path and its earliest trusted camera component.
2. The exact 2.00 installing receiver or equivalent transition evidence.
3. Complete model, region, version, authenticity, write-scope, ordering, commit, and terminal-verification behavior.
4. Bounded restart, resume, rollback, or safe failure behavior for interruption and power loss.
5. A reviewed transition of the strict report out of `BLOCKED_STATIC_EVIDENCE` without setting `recovery_validated` from static evidence alone.

Physical validation would still require fresh user authorization, direct supervision, a separately reviewed design, and no feature modification before stock recovery itself had been validated.
