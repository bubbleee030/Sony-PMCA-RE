# NEX-C3 Safe Service Rehearsal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and verify a fail-closed Windows 11 workflow that uses the donor NEX-C3 to rehearse a reversible WinUSB/service-mode cycle, authenticates, performs exactly one ProductInfo/READ_HASP read, and returns the camera to its original Microsoft mass-storage driver without changing firmware, settings, or stored camera data.

**Architecture:** Keep the safe path separate from the existing unrestricted `pmca-console.py` commands. Pure policy and state modules sit below a small dependency-injected workflow; allowlisted transport wrappers reject unapproved packets immediately before USB I/O. A read-only Windows PnP probe gates every phase, while Zadig driver changes remain manual and are checked before the next command runs.

**Tech Stack:** Python 3.13, existing Sony-PMCA-RE USB/Senser classes, `unittest`, PyUSB 1.3.1, `libusb-package` 1.0.30.0, Windows CIM/PowerShell for read-only PnP status, Zadig for manual per-device WinUSB binding, and local Git only.

## Global Constraints

- Work from a new Git worktree and local feature branch. Do not stash, delete, or commit the untracked prototypes in the current checkout.
- Do not push, add credentials, or change the `origin` remote. Local commits are sufficient.
- Disconnect the α6400 for all NEX-C3 hardware steps. This plan never addresses the α6400 USB device.
- Never import or invoke `senserShellCommand`, `CameraShell`, firmware update, file control, memory dump, backup/adjust, terminal, test-mode, or sonar code from the new CLI.
- Permit normal-mode Sony external command `(group=1, subcommand=1)` only.
- Permit service packet `pFunc=0x0010`, `category=0`, `command=0x001f`, selector byte `0` only. Reject an output file object and all alternate payload lengths.
- Authentication may use only the existing fixed `SonySenserAuthDevice.start()`, `.authenticate()`, and `.stop()` sequence; do not expose its raw packet method through the CLI.
- The accepted USB identities are exactly normal `054c:0490` and service `054c:02a9` or `054c:0336`. Require exactly one matching connected Sony device.
- Never install, remove, or replace a driver from Python. The operator performs only the exact-instance Zadig changes described in the runbook.
- Do not write READ_HASP response bytes to disk or print them. Print only response length and SHA-256.
- Fail closed on malformed output, unknown driver service, unknown Sony PID, zero/multiple devices, model mismatch, failed authentication, timeout, or an invalid state transition.
- Do not proceed to α6400 research unless the NEX-C3 is fully restored, mounts normally, and passes the camera functional checklist.

---

## File Map

| Path | Action | Responsibility |
|---|---|---|
| `.gitignore` | Modify | Ignore local `.venv/` environments. |
| `requirements-safe.txt` | Create | Pin the tested Windows safe-path runtime dependencies. |
| `pmca/usb/driver/generic/libusb.py` | Modify | Accept an explicit PyUSB backend while preserving the existing default. |
| `pmca/safe/__init__.py` | Create | Define the safe package without re-exporting unrestricted PMCA APIs. |
| `pmca/safe/policy.py` | Create | Pure normal/service packet allowlists and denial exception. |
| `pmca/safe/state.py` | Create | PnP snapshot parsing, USB-state classification, redaction, and exact-device gates. |
| `pmca/safe/windows.py` | Create | Run a fixed read-only Windows CIM query and return typed snapshots. |
| `pmca/safe/transport.py` | Create | Explicit libusb backend plus allowlisted identity and service device wrappers. |
| `pmca/safe/workflow.py` | Create | Dependency-injected `status`, `enter`, and `probe` state machine. |
| `safe_service.py` | Create | Narrow CLI exposing only `status`, `enter`, and `probe`. |
| `tests/safe/test_libusb_backend.py` | Create | Verify explicit backend forwarding and backward compatibility. |
| `tests/safe/test_policy.py` | Create | Exhaustive allowed/denied packet tests. |
| `tests/safe/test_state.py` | Create | PnP parsing and state-gate tests. |
| `tests/safe/test_windows.py` | Create | Fixed-command, JSON, timeout, and error tests. |
| `tests/safe/test_transport.py` | Create | Prove wrappers deny before touching fake USB transports. |
| `tests/safe/test_workflow.py` | Create | Fake-device state-machine, auth, hashing, cleanup, and timeout tests. |
| `tests/safe/test_cli.py` | Create | CLI surface and secret-output tests. |
| `docs/superpowers/runbooks/nex-c3-driver-recovery.md` | Create | Exact driver checkpoints, recovery, and hardware acceptance checklist. |

## Task 1: Create the Isolated Worktree and Reproduce the Baseline

**Files:**

- Verify: `docs/superpowers/specs/2026-08-04-nex-c3-service-rehearsal-design.md`
- Preserve untouched in original checkout: `SAFE_MODE.md`, `safe_info.py`, `safe_service.py`, `test_safe_info.py`, `test_safe_service.py`

- [ ] **Step 1: Read the required worktree skill**

Invoke `superpowers:using-git-worktrees` before running any worktree command.

- [ ] **Step 2: Confirm the original checkout and commit boundary**

Run from `C:\Users\Bubble\ChatGPT\Sony-PMCA-RE`:

```powershell
git status --short --branch
git log -2 --oneline
git remote -v
```

Expected: `master` is ahead of `origin/master`; the approved design and this plan are committed locally; the six prototype files remain untracked; `origin` still points to official Sony-PMCA-RE.

- [ ] **Step 3: Create a sibling worktree without touching untracked files**

```powershell
git worktree add C:\Users\Bubble\ChatGPT\Sony-PMCA-RE-nex-c3-safe -b feature/nex-c3-safe-service
git -C C:\Users\Bubble\ChatGPT\Sony-PMCA-RE-nex-c3-safe status --short --branch
```

Expected: clean `feature/nex-c3-safe-service` worktree.

- [ ] **Step 4: Create an empty virtual environment in the worktree**

```powershell
Set-Location C:\Users\Bubble\ChatGPT\Sony-PMCA-RE-nex-c3-safe
py -3.13 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
```

Expected: `.venv` is created. Do not install from the untracked prototype `requirements-safe.txt`; Task 2 creates the reviewed dependency file inside this worktree.

**Reviewer gate:** Verify the original checkout still contains all six untracked prototypes and has no new modifications before Task 2.

## Task 2: Make the Generic USB Context Accept an Explicit libusb Backend

**Files:**

- Modify: `.gitignore`
- Create: `requirements-safe.txt`
- Modify: `pmca/usb/driver/generic/libusb.py`
- Create: `tests/safe/__init__.py`
- Create: `tests/safe/test_libusb_backend.py`

- [ ] **Step 1: Write the failing backend-forwarding tests**

Create `tests/safe/__init__.py` as an empty file. Add `tests/safe/test_libusb_backend.py`:

```python
import unittest
from unittest.mock import patch

from pmca.usb.driver.generic import libusb


class LibusbBackendTests(unittest.TestCase):
    @patch.object(libusb.usb.core, "find")
    def test_explicit_backend_is_forwarded(self, find):
        backend = object()
        find.return_value = []

        list(libusb._listDevices(0x054C, libusb.USB_CLASS_MSC, backend))

        find.assert_called_once_with(
            find_all=True, idVendor=0x054C, backend=backend
        )

    @patch.object(libusb.usb.core, "find")
    def test_omitted_backend_preserves_existing_discovery(self, find):
        find.return_value = []

        list(libusb._listDevices(0x054C, libusb.USB_CLASS_MSC))

        find.assert_called_once_with(find_all=True, idVendor=0x054C)

    @patch.object(libusb, "_listDevices")
    def test_context_passes_its_backend(self, list_devices):
        backend = object()
        list_devices.return_value = []

        context = libusb.MscContext(backend=backend)
        list(context.listDevices(0x054C))

        list_devices.assert_called_once_with(
            0x054C, libusb.USB_CLASS_MSC, backend
        )


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Create and install the reviewed safe environment**

Create `requirements-safe.txt` with:

```text
comtypes==1.4.16
libusb-package==1.0.30.0
pycryptodomex==3.23.0
pyusb==1.3.1
pywin32==312
```

Add this exact line to `.gitignore`:

```text
/.venv/
```

```powershell
& .\.venv\Scripts\python.exe -m pip install -r requirements-safe.txt
```

- [ ] **Step 3: Run the tests and confirm they fail for the missing parameter**

```powershell
& .\.venv\Scripts\python.exe -m unittest tests.safe.test_libusb_backend -v
```

Expected: `TypeError` because `_listDevices` and `MscContext` do not yet accept `backend`.

- [ ] **Step 4: Implement optional backend injection without changing existing callers**

Change `pmca/usb/driver/generic/libusb.py` so `_UsbContext`, all three contexts, and `_listDevices` accept `backend=None`. The core behavior must be:

```python
class _UsbContext(BaseUsbContext):
 def __init__(self, name, classType, driverClass, backend=None):
  super(_UsbContext, self).__init__('libusb-%s' % name, classType)
  self._driverClass = driverClass
  self._backend = backend

 def listDevices(self, vendor):
  return _listDevices(vendor, self.classType, self._backend)


def _listDevices(vendor, classType, backend=None):
 """Lists all detected USB devices."""
 kwargs = dict(find_all=True, idVendor=vendor)
 if backend is not None:
  kwargs['backend'] = backend
 for dev in usb.core.find(**kwargs):
  interface = next((interface for config in dev for interface in config), None)
  if interface and interface.bInterfaceClass == classType:
   yield UsbDeviceHandle(dev, dev.idVendor, dev.idProduct)
```

Each public context constructor passes `backend` to `_UsbContext`; `MscContext.openDevice` remains unchanged.

- [ ] **Step 5: Run the test**

```powershell
& .\.venv\Scripts\python.exe -m unittest tests.safe.test_libusb_backend -v
```

Expected: 3 tests pass.

- [ ] **Step 6: Commit the compatibility layer**

```powershell
git add .gitignore requirements-safe.txt pmca/usb/driver/generic/libusb.py tests/safe/__init__.py tests/safe/test_libusb_backend.py
git commit -m "usb: support explicit libusb backend"
```

**Reviewer gate:** Existing callers that construct `MscContext()`, `MtpContext()`, or `VendorSpecificContext()` with no argument must behave exactly as before.

## Task 3: Implement the Packet Allowlist Before Any Hardware Workflow

**Files:**

- Create: `pmca/safe/__init__.py`
- Create: `pmca/safe/policy.py`
- Create: `tests/safe/test_policy.py`

- [ ] **Step 1: Write exhaustive failing policy tests**

Create table-driven tests that cover the single accepted payloads and every explicitly forbidden family. The essential assertions are:

```python
import struct
import unittest

from pmca.safe.policy import PolicyViolation, validate_identity_query, validate_service_read


class PolicyTests(unittest.TestCase):
    def test_allows_only_get_model_info(self):
        payload = struct.pack("<IHH8x", 0, 1, 0)
        self.assertEqual(
            validate_identity_query(1, payload),
            "DevInfoSender/GetModelInfo",
        )

    def test_denies_other_external_commands_and_malformed_headers(self):
        denied = [
            (1, struct.pack("<IHH8x", 0, 2, 0)),
            (2, struct.pack("<IHH8x", 0, 1, 0)),
            (1, struct.pack("<IHH8x", 1, 1, 0)),
            (1, struct.pack("<IHH8x", 0, 1, 1)),
            (1, b"short"),
        ]
        for group, payload in denied:
            with self.subTest(group=group, payload=payload):
                with self.assertRaises(PolicyViolation):
                    validate_identity_query(group, payload)

    def test_allows_only_read_hasp_selector_zero(self):
        payload = struct.pack("<HHB", 0, 0x001F, 0)
        self.assertEqual(
            validate_service_read(0x0010, payload, None),
            "ProductInfo/READ_HASP",
        )

    def test_denies_every_unsafe_service_family(self):
        payload = struct.pack("<HHB", 0, 0x001F, 0)
        for pfunc in (0x0020, 0x0030, 0x0040, 0xFF00, 0xFF01, 0xFF02, 0xFF03):
            with self.subTest(pfunc=pfunc):
                with self.assertRaises(PolicyViolation):
                    validate_service_read(pfunc, payload, None)

    def test_denies_terminal_change_selector_length_and_output_sink(self):
        denied = [
            (0x0010, struct.pack("<HHB", 0, 0x00F1, 0), None),
            (0x0010, struct.pack("<HHB", 0, 0x001F, 1), None),
            (0x0010, struct.pack("<HH", 0, 0x001F), None),
            (0x0010, struct.pack("<HHBB", 0, 0x001F, 0, 0), None),
            (0x0010, struct.pack("<HHB", 0, 0x001F, 0), object()),
        ]
        for pfunc, payload, sink in denied:
            with self.subTest(pfunc=pfunc, payload=payload):
                with self.assertRaises(PolicyViolation):
                    validate_service_read(pfunc, payload, sink)
```

- [ ] **Step 2: Run the tests and confirm the module is missing**

```powershell
& .\.venv\Scripts\python.exe -m unittest tests.safe.test_policy -v
```

Expected: import failure for `pmca.safe.policy`.

- [ ] **Step 3: Implement the pure fail-closed validators**

Create an empty `pmca/safe/__init__.py`. Implement `pmca/safe/policy.py`:

```python
import struct


class PolicyViolation(RuntimeError):
    pass


def validate_identity_query(group, payload):
    if len(payload) < 16:
        raise PolicyViolation("Sony command header is truncated")
    data_size, subcommand, direction = struct.unpack_from("<IHH", payload)
    if (group, subcommand) != (1, 1):
        raise PolicyViolation("Sony external command is not allowlisted")
    if direction != 0 or data_size != 0:
        raise PolicyViolation("GetModelInfo must be a zero-data read")
    return "DevInfoSender/GetModelInfo"


def validate_service_read(pfunc, payload, output_sink=None):
    if output_sink is not None:
        raise PolicyViolation("streaming service output is forbidden")
    if pfunc != 0x0010 or len(payload) != 5:
        raise PolicyViolation("service packet is not allowlisted")
    category, command = struct.unpack_from("<HH", payload)
    if (category, command) != (0, 0x001F) or payload[4] != 0:
        raise PolicyViolation("only ProductInfo/READ_HASP selector zero is allowed")
    return "ProductInfo/READ_HASP"
```

- [ ] **Step 4: Run the policy suite**

```powershell
& .\.venv\Scripts\python.exe -m unittest tests.safe.test_policy -v
```

Expected: all tests pass.

- [ ] **Step 5: Commit the policy boundary**

```powershell
git add pmca/safe/__init__.py pmca/safe/policy.py tests/safe/test_policy.py
git commit -m "safe: add fail-closed packet policy"
```

**Reviewer gate:** Search the allowlist for forbidden constants and verify they appear only in negative tests:

```powershell
rg -n "0x0020|0x0030|0x0040|0xFF00|0xFF01|0xFF02|0xFF03|0x00F1" pmca/safe tests/safe
```

## Task 4: Add Read-Only Windows Device-State Detection

**Files:**

- Create: `pmca/safe/state.py`
- Create: `pmca/safe/windows.py`
- Create: `tests/safe/test_state.py`
- Create: `tests/safe/test_windows.py`

- [ ] **Step 1: Write failing state tests**

Test JSON objects shaped as `DeviceID`, `Service`, and `Name`. Cover case-insensitive IDs/services, a single CIM object versus a list, zero/multiple matches, unknown Sony PID, invalid VID/PID, and serial redaction. Use these required states:

```python
class UsbState(Enum):
    NORMAL_MSC = "NORMAL_MSC"
    NORMAL_WINUSB = "NORMAL_WINUSB"
    SERVICE_UNBOUND = "SERVICE_UNBOUND"
    SERVICE_WINUSB = "SERVICE_WINUSB"
    UNKNOWN = "UNKNOWN"
```

The required happy assertions are:

```python
self.assertEqual(classify(snap("USBSTOR")), UsbState.NORMAL_MSC)
self.assertEqual(classify(snap("WinUSB")), UsbState.NORMAL_WINUSB)
self.assertEqual(classify(snap("", pid=0x02A9)), UsbState.SERVICE_UNBOUND)
self.assertEqual(classify(snap("WinUSB", pid=0x0336)), UsbState.SERVICE_WINUSB)
```

Also require `require_one(snapshots, expected)` to raise `DeviceGateError` unless there is exactly one accepted Sony PID and it has the expected state.

- [ ] **Step 2: Implement pure snapshot parsing and classification**

`pmca/safe/state.py` must define frozen `DeviceSnapshot`, `UsbState`, `DeviceGateError`, `parse_pnp_records(records)`, `classify(snapshot)`, `require_one(snapshots, expected)`, and `redacted_instance(instance_id)`. Parsing uses this case-insensitive pattern:

```python
USB_ID = re.compile(r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", re.IGNORECASE)
ACCEPTED_PIDS = frozenset((0x0490, 0x02A9, 0x0336))
```

Classification rules are exact:

```python
if snapshot.vid != 0x054C or snapshot.pid not in ACCEPTED_PIDS:
    return UsbState.UNKNOWN
service = snapshot.service.casefold()
if snapshot.pid == 0x0490:
    if service == "usbstor":
        return UsbState.NORMAL_MSC
    if service == "winusb":
        return UsbState.NORMAL_WINUSB
elif service == "winusb":
    return UsbState.SERVICE_WINUSB
elif service in ("", "usbccgp"):
    return UsbState.SERVICE_UNBOUND
return UsbState.UNKNOWN
```

`redacted_instance` returns a 12-character SHA-256 prefix, never the raw instance ID.

- [ ] **Step 3: Write failing Windows provider tests**

Mock `subprocess.run`. Assert the provider:

- invokes Windows PowerShell with `-NoProfile -NonInteractive`;
- contains only `Get-CimInstance`, `Where-Object`, `Select-Object`, and `ConvertTo-Json` operations;
- uses a 10-second timeout;
- accepts empty output as no devices;
- normalizes a single JSON object to one snapshot;
- raises `DeviceProbeError` for timeout, nonzero exit, or malformed JSON.

- [ ] **Step 4: Implement the fixed read-only probe**

`pmca/safe/windows.py` must keep its command constant private and accept a runner for tests:

```python
_PNP_QUERY = (
    "$ErrorActionPreference='Stop'; "
    "@(Get-CimInstance Win32_PnPEntity | "
    "Where-Object { $_.DeviceID -like 'USB\\VID_054C&PID_*' } | "
    "Select-Object DeviceID,Service,Name) | ConvertTo-Json -Compress"
)


class DeviceProbeError(RuntimeError):
    pass


def list_sony_usb_devices(runner=subprocess.run):
    try:
        result = runner(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _PNP_QUERY],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise DeviceProbeError("Windows device query timed out") from exc
    if result.returncode != 0:
        raise DeviceProbeError("Windows device query failed")
    if not result.stdout.strip():
        return []
    try:
        records = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise DeviceProbeError("Windows device query returned invalid JSON") from exc
    return parse_pnp_records(records if isinstance(records, list) else [records])
```

- [ ] **Step 5: Run both suites**

```powershell
& .\.venv\Scripts\python.exe -m unittest tests.safe.test_state tests.safe.test_windows -v
```

Expected: all state/provider tests pass without touching USB.

- [ ] **Step 6: Commit device-state detection**

```powershell
git add pmca/safe/state.py pmca/safe/windows.py tests/safe/test_state.py tests/safe/test_windows.py
git commit -m "safe: gate Windows USB device states"
```

**Reviewer gate:** `pmca/safe/windows.py` must contain no `pnputil`, `devcon`, registry writes, WMI mutation methods, or driver-install commands.

## Task 5: Add Allowlisted USB Transport Wrappers

**Files:**

- Create: `pmca/safe/transport.py`
- Create: `tests/safe/test_transport.py`

- [ ] **Step 1: Write denial-before-I/O tests**

Use fake parent calls or mocked drivers to assert:

- valid GetModelInfo reaches the base method once;
- invalid external commands never reach the base method;
- valid READ_HASP reaches `SonySenserDevice.sendSenserPacket` once;
- invalid pFunc, command, selector, length, and `oData` never reach it;
- `make_libusb_backend()` returns `libusb_package.get_libusb1_backend()` and raises `TransportUnavailable` when it returns `None`.

Patch the exact base methods so the ordering is observable:

```python
with patch.object(SonyMscExtCmdDevice, "sendSonyExtCommand", return_value=b"ok") as send:
    result = AllowlistedIdentityDevice(driver).sendSonyExtCommand(1, valid, 0x2000)
    self.assertEqual(result, b"ok")
    send.assert_called_once()

with patch.object(SonySenserDevice, "sendSenserPacket") as send:
    with self.assertRaises(PolicyViolation):
        AllowlistedSenserDevice(driver).sendSenserPacket(0xFF03, valid)
    send.assert_not_called()
```

- [ ] **Step 2: Implement the narrow wrappers and explicit backend factory**

`pmca/safe/transport.py` must contain only these hardware-facing abstractions:

```python
import libusb_package

from pmca.safe.policy import validate_identity_query, validate_service_read
from pmca.usb.sony import SonyMscExtCmdDevice, SonySenserDevice


class TransportUnavailable(RuntimeError):
    pass


def make_libusb_backend():
    backend = libusb_package.get_libusb1_backend()
    if backend is None:
        raise TransportUnavailable("bundled libusb backend is unavailable")
    return backend


class AllowlistedIdentityDevice(SonyMscExtCmdDevice):
    def sendSonyExtCommand(self, cmd, data, bufferSize):
        validate_identity_query(cmd, data)
        return super().sendSonyExtCommand(cmd, data, bufferSize)


class AllowlistedSenserDevice(SonySenserDevice):
    def sendSenserPacket(self, pFunc, data, oData=None):
        validate_service_read(pFunc, data, oData)
        return super().sendSenserPacket(pFunc, data, oData)
```

- [ ] **Step 3: Run transport and policy tests together**

```powershell
& .\.venv\Scripts\python.exe -m unittest tests.safe.test_policy tests.safe.test_transport -v
```

Expected: all pass.

- [ ] **Step 4: Commit the transport boundary**

```powershell
git add pmca/safe/transport.py tests/safe/test_transport.py
git commit -m "safe: enforce allowlists at USB transport"
```

**Reviewer gate:** The policy call must occur before `super()` in both wrappers, and no unrestricted device object may be returned by a public helper.

## Task 6: Implement the Dependency-Injected State Machine

**Files:**

- Create: `pmca/safe/workflow.py`
- Create: `tests/safe/test_workflow.py`

- [ ] **Step 1: Write failing tests with fake PnP and USB adapters**

Define fake adapters with call logs; do not mock at the raw USB byte level. Cover:

- `status()` returns the one classified state and redacted instance token;
- `enter("NEX-C3")` requires `NORMAL_WINUSB`, exact normal PID, and identity model `NEX-C3`;
- a wrong acknowledgement, `NORMAL_MSC`, service state, unknown state, zero devices, or multiple devices makes no USB calls;
- enter calls `start`, then `authenticate`; while polling, only an empty device list is retried, `NORMAL_WINUSB` may persist briefly, `SERVICE_UNBOUND`/`SERVICE_WINUSB` succeeds, and every other populated state fails immediately;
- failed enter authentication calls `stop` once and re-raises;
- `probe("NEX-C3")` requires `SERVICE_WINUSB` and service PID `02a9` or `0336`;
- probe calls `start`, `authenticate`, exactly one `readHasp`, and `stop` in `finally`;
- a read failure still calls `stop`;
- output contains only PID, length, and lowercase SHA-256—not raw response bytes.

The returned types must be:

```python
@dataclass(frozen=True)
class StatusSummary:
    state: UsbState
    vid: int
    pid: int
    instance_token: str


@dataclass(frozen=True)
class ProbeSummary:
    pid: int
    response_length: int
    sha256: str
```

- [ ] **Step 2: Implement adapters with no unrestricted shell path**

Define protocols or small interfaces for:

```python
class DeviceSource(Protocol):
    def snapshots(self) -> list[DeviceSnapshot]:
        raise NotImplementedError

    def open_normal(self) -> "NormalSession":
        raise NotImplementedError

    def open_service(self) -> "ServiceSession":
        raise NotImplementedError

    def sleep(self, seconds: float) -> None:
        raise NotImplementedError
```

The real adapter uses `MscContext(backend=backend)` for PID `0490` and `VendorSpecificContext(backend=backend)` for service PIDs. It requires exactly one PyUSB device, wraps normal mode in `AllowlistedIdentityDevice`, and wraps service mode in `AllowlistedSenserDevice`. It exposes purpose-specific operations only:

```python
class NormalSession:
    def __init__(self, device: AllowlistedIdentityDevice):
        self.device = device

    def identity(self) -> CameraInfo:
        return SonyExtCmdCamera(self.device).getCameraInfo()

    def request_transition(self) -> None:
        auth = SonySenserAuthDevice(self.device.driver)
        auth.start()
        try:
            auth.authenticate()
        except Exception:
            auth.stop()
            raise


class ServiceSession:
    def __init__(self, device: AllowlistedSenserDevice):
        self.device = device

    def read_hasp(self) -> bytes:
        auth = SonySenserAuthDevice(self.device.driver)
        auth.start()
        try:
            auth.authenticate()
            return SonySenserCamera(self.device).readHasp()
        finally:
            auth.stop()
```

`NormalSession.device` is always an `AllowlistedIdentityDevice`; `ServiceSession.device` is always an `AllowlistedSenserDevice`. The source constructs those wrappers privately and never returns a raw driver.

- [ ] **Step 3: Implement transition guards and summaries**

The core methods must follow this structure:

```python
ACK = "NEX-C3"


def _require_ack(value):
    if value != ACK:
        raise WorkflowError("exact acknowledgement NEX-C3 is required")


class SafeServiceWorkflow:
    def __init__(self, source):
        self.source = source

    def status(self):
        snapshot = require_one(self.source.snapshots())
        return StatusSummary(
            classify(snapshot), snapshot.vid, snapshot.pid,
            redacted_instance(snapshot.instance_id),
        )

    def enter(self, acknowledgement):
        _require_ack(acknowledgement)
        require_one(self.source.snapshots(), UsbState.NORMAL_WINUSB)
        session = self.source.open_normal()
        info = session.identity()
        if info.modelName != ACK:
            raise WorkflowError("connected camera is not NEX-C3")
        session.request_transition()
        for _ in range(20):
            self.source.sleep(0.5)
            snapshots = self.source.snapshots()
            if not snapshots:
                continue
            snapshot = require_one(snapshots)
            state = classify(snapshot)
            if state in (UsbState.SERVICE_UNBOUND, UsbState.SERVICE_WINUSB):
                return StatusSummary(
                    state, snapshot.vid, snapshot.pid,
                    redacted_instance(snapshot.instance_id),
                )
            if state != UsbState.NORMAL_WINUSB:
                raise WorkflowError("unexpected USB state during transition")
        raise WorkflowError("service-mode enumeration timed out")

    def probe(self, acknowledgement):
        _require_ack(acknowledgement)
        snapshot = require_one(self.source.snapshots(), UsbState.SERVICE_WINUSB)
        response = self.source.open_service().read_hasp()
        return ProbeSummary(
            pid=snapshot.pid,
            response_length=len(response),
            sha256=hashlib.sha256(response).hexdigest(),
        )
```

If `require_one` needs to support no expected state for `status()`, make `expected=None` explicit and test it. Do not weaken the accepted PID set.

- [ ] **Step 4: Run the state-machine tests**

```powershell
& .\.venv\Scripts\python.exe -m unittest tests.safe.test_workflow -v
```

Expected: all fake-device tests pass and do not require a connected camera.

- [ ] **Step 5: Run all safe unit tests**

```powershell
& .\.venv\Scripts\python.exe -m unittest discover -s tests -p 'test_*.py' -v
```

Expected: all tests pass.

- [ ] **Step 6: Commit the workflow**

```powershell
git add pmca/safe/workflow.py tests/safe/test_workflow.py
git commit -m "safe: add NEX-C3 service state machine"
```

**Reviewer gate:** Trace every public method from entry to USB I/O. There must be no route to a raw driver, `SonySenserDevice`, `SonySenserCamera`, `_sendAuthPacket`, or unrestricted command argument.

## Task 7: Add the Narrow CLI and Secret-Safe Output

**Files:**

- Create: `safe_service.py`
- Create: `tests/safe/test_cli.py`

- [ ] **Step 1: Write failing CLI tests**

Patch `build_workflow()` with a fake. Assert:

- only `status`, `enter`, and `probe` parse;
- unknown subcommands and extra arguments fail with exit code 2;
- `enter` and `probe` require `--ack NEX-C3`;
- `status` prints state, VID:PID, and redacted instance token;
- `probe` prints only service PID, response length, and SHA-256;
- raw response marker bytes and a full fake PnP instance ID never appear on stdout or stderr;
- `PolicyViolation`, `DeviceGateError`, `DeviceProbeError`, `TransportUnavailable`, and `WorkflowError` return exit code 1 with concise messages and no traceback.

- [ ] **Step 2: Implement the CLI surface**

Use `argparse` with exact subparsers:

```python
def build_parser():
    parser = argparse.ArgumentParser(
        description="Fail-closed NEX-C3 service-mode rehearsal"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="read Windows USB state only")
    for name in ("enter", "probe"):
        command = commands.add_parser(name)
        command.add_argument("--ack", required=True, metavar="NEX-C3")
    return parser
```

`main(argv=None, workflow=None)` supports injection. `build_workflow()` constructs the fixed Windows device source and explicit libusb backend. The formatter uses:

```python
print(f"USB state: {summary.state.value}")
print(f"USB ID: {summary.vid:04x}:{summary.pid:04x}")
print(f"Instance token: {summary.instance_token}")
```

For probe:

```python
print("Allowlisted read completed")
print(f"Service PID: {summary.pid:04x}")
print(f"Response length: {summary.response_length}")
print(f"Response SHA-256: {summary.sha256}")
```

The CLI contains no generic packet, filename, address, terminal, backup, firmware, or shell option.

- [ ] **Step 3: Run CLI and full unit suites**

```powershell
& .\.venv\Scripts\python.exe -m unittest tests.safe.test_cli -v
& .\.venv\Scripts\python.exe -m unittest discover -s tests -p 'test_*.py' -v
```

Expected: all pass.

- [ ] **Step 4: Exercise read-only help without a camera**

```powershell
& .\.venv\Scripts\python.exe .\safe_service.py --help
```

Expected: help lists only `status`, `enter`, and `probe`.

- [ ] **Step 5: Commit the CLI**

```powershell
git add safe_service.py tests/safe/test_cli.py
git commit -m "safe: add constrained NEX-C3 rehearsal CLI"
```

**Reviewer gate:** Run `rg -n "shell|firmware|backup|memory|terminal|file" safe_service.py`; any match must be explanatory text, not a callable command.

## Task 8: Write and Review the Manual Driver/Recovery Runbook

**Files:**

- Create: `docs/superpowers/runbooks/nex-c3-driver-recovery.md`

- [ ] **Step 1: Write the prerequisites and hard stops**

The runbook must begin with:

```markdown
# NEX-C3 WinUSB Service Rehearsal and Recovery

This procedure changes only Windows' driver binding for the connected NEX-C3. It does
not install firmware or add camera features. Stop immediately on any unexpected USB ID,
camera warning, failed test, or incomplete driver restoration.

## Preconditions

- α6400 physically disconnected.
- Exactly one Sony USB camera connected.
- NEX-C3 battery fully charged; memory card removed; Sony desktop apps closed.
- Camera confirmed operational before starting: power, menu, shutter, playback.
- All automated tests in the implementation plan pass.
- Zadig obtained from its official site and run as administrator only at the named steps.
```

- [ ] **Step 2: Document the exact normal-mode driver checkpoint**

Include these commands and expected result:

```powershell
& .\.venv\Scripts\python.exe .\safe_service.py status
```

Expected: `NORMAL_MSC`, `054c:0490`, one redacted instance token. In Zadig: Options → List All Devices; select only the row whose USB ID is `054C:0490`; record the current driver as Microsoft USB mass storage/`USBSTOR`; choose `WinUSB`; replace only that device. Do not select hubs, composite parents, the α6400, or any service PID.

Re-run `status`; expected: `NORMAL_WINUSB`, `054c:0490`, same physical NEX-C3.

- [ ] **Step 3: Document transition and service binding**

```powershell
& .\.venv\Scripts\python.exe .\safe_service.py enter --ack NEX-C3
```

Expected: only `SERVICE_UNBOUND` or `SERVICE_WINUSB`, with ID `054c:02a9` or `054c:0336`. If unbound, refresh Zadig, select only that newly appearing exact service PID, bind it to `WinUSB`, then run:

```powershell
& .\.venv\Scripts\python.exe .\safe_service.py status
```

Expected: `SERVICE_WINUSB` and the same service PID. Any other state is a hard stop.

- [ ] **Step 4: Document the single read and immediate exit**

```powershell
& .\.venv\Scripts\python.exe .\safe_service.py probe --ack NEX-C3
```

Expected: `Allowlisted read completed`, service PID, response length, and SHA-256 only. No response dump or camera data file is created. Then turn the camera off, disconnect USB, remove the battery for 30 seconds, reinstall the battery, and start normally.

- [ ] **Step 5: Document normal-driver restoration**

Reconnect in normal mass-storage mode. In Device Manager, update only the present `054C:0490` NEX-C3 device to the Microsoft USB Mass Storage driver. If necessary, uninstall only that exact present device instance, do **not** select driver-package deletion, disconnect/reconnect, then choose the Microsoft in-box USB Mass Storage driver. Do not remove unrelated WinUSB/libusb packages.

Run:

```powershell
& .\.venv\Scripts\python.exe .\safe_service.py status
```

Expected: `NORMAL_MSC`, `054c:0490`.

- [ ] **Step 6: Add the acceptance and emergency recovery checklists**

Acceptance must require all boxes:

```markdown
- [ ] Windows mounts the camera/storage normally.
- [ ] Safe status reports NORMAL_MSC and 054c:0490.
- [ ] Camera powers on without a warning.
- [ ] Menu navigation works.
- [ ] Shutter captures one test photo after reinserting the memory card.
- [ ] Playback shows the test photo.
- [ ] Power-off and second power-on both work normally.
```

Emergency recovery must say: close the CLI and Zadig; power off; disconnect; remove battery for 30 seconds; reconnect only after normal boot; restore only the exact present `054C:0490` instance to Microsoft USB Mass Storage. If the NEX-C3 still fails after battery removal and normal-driver restoration, stop—do not try terminal, memory, firmware, or α6400 recovery commands.

- [ ] **Step 7: Review and commit the runbook**

```powershell
git diff --check
git add docs/superpowers/runbooks/nex-c3-driver-recovery.md
git commit -m "docs: add NEX-C3 driver recovery runbook"
```

**Reviewer gate:** A second reader must be able to identify the selected device by VID:PID at every Zadig/Device Manager step, and every risky step must have an immediately adjacent expected state and stop condition.

## Task 9: Perform the Full Software Safety Review

**Files:**

- Verify all implementation and test files from Tasks 2–8.

- [ ] **Step 1: Invoke the required verification skill**

Use `superpowers:verification-before-completion` before claiming implementation readiness.

- [ ] **Step 2: Run the complete isolated test suite**

```powershell
& .\.venv\Scripts\python.exe -m unittest discover -s tests -p 'test_*.py' -v
& .\.venv\Scripts\python.exe -m compileall -q pmca safe_service.py tests
git diff --check
```

Expected: all tests pass; compileall and diff check exit 0.

- [ ] **Step 3: Scan the new runtime for forbidden capability reachability**

```powershell
rg -n "senserShellCommand|CameraShell|writeFirmware|writeFile|deleteFile|readFile|readMemory|writeMemory|readBackup|writeBackup|saveBackup|setTerminalEnable|SONY_PFUNC_(FirmwareUpdate|AdjustControl|TestMode|FileControl|Sonar|MemoryDump)" pmca/safe safe_service.py
```

Expected: zero matches. Negative tests may reference numeric forbidden pFuncs, but runtime code must not import or name the unsafe methods.

- [ ] **Step 4: Audit the CLI surface**

```powershell
& .\.venv\Scripts\python.exe .\safe_service.py --help
& .\.venv\Scripts\python.exe .\safe_service.py enter --help
& .\.venv\Scripts\python.exe .\safe_service.py probe --help
```

Expected: only three subcommands and the exact acknowledgement option; no arbitrary command/data/file/address arguments.

- [ ] **Step 5: Inspect the commit series and clean worktree**

```powershell
git log --oneline master..HEAD
git status --short --branch
```

Expected: five focused implementation/documentation commits and no uncommitted files except ignored `.venv/` and generated `__pycache__` files.

- [ ] **Step 6: Request code review**

Invoke `superpowers:requesting-code-review`. Fix all safety-boundary findings before any hardware execution, rerun every command in Steps 2–5, and commit fixes separately.

**Reviewer gate:** Hardware work is prohibited until tests, forbidden-capability scan, CLI audit, and code review all pass.

## Task 10: Execute the NEX-C3 Hardware Rehearsal and Stop at the α6400 Gate

**Files:**

- Follow: `docs/superpowers/runbooks/nex-c3-driver-recovery.md`
- Do not create camera-response artifacts.

- [ ] **Step 1: Confirm the operator is present and prerequisites are satisfied**

Read the runbook aloud/onscreen. Confirm the α6400 is disconnected, the donor is the only Sony USB camera, its battery is full, the memory card is removed, and the preflight functional checks pass.

- [ ] **Step 2: Run read-only `status` in `NORMAL_MSC`**

Do not change a driver unless the output is exactly one NEX-C3 at `054c:0490` and `NORMAL_MSC`.

- [ ] **Step 3: Manually bind normal PID to WinUSB and verify**

Use Zadig only as documented. Stop unless the next `status` is `NORMAL_WINUSB` at `054c:0490`.

- [ ] **Step 4: Request service transition and verify enumeration**

Run `enter --ack NEX-C3`. Stop unless the resulting single device is `054c:02a9` or `054c:0336` in `SERVICE_UNBOUND` or `SERVICE_WINUSB`.

- [ ] **Step 5: If required, manually bind only the service PID to WinUSB**

Re-run `status`; stop unless it is `SERVICE_WINUSB`.

- [ ] **Step 6: Run the single allowlisted probe**

Run `probe --ack NEX-C3` once. Record only whether it succeeded, response length, and SHA-256 in the conversation; do not save raw output to a file.

- [ ] **Step 7: Power-cycle and restore the Microsoft mass-storage driver**

Follow the runbook exactly. Do not delete a driver package. Stop and recover if `NORMAL_MSC` is not restored.

- [ ] **Step 8: Complete every camera/Windows acceptance check**

If any check fails, report the exact observable symptom and remain stopped. Do not attach the α6400.

- [ ] **Step 9: State the research conclusion accurately**

A successful rehearsal demonstrates only that the constrained Windows driver, transition, authentication, single read, and recovery workflow works on the NEX-C3. It does **not** demonstrate that α6400 firmware can accept the newer vertical touch UI or Creative Looks, and it does not authorize any α6400 write or cross-model firmware action.

**Final gate:** End this plan here. Any α6400 research requires a separate approved design based on read-only model-specific evidence and a recovery path that does not depend on the NEX-C3.
