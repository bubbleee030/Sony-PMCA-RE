"""Pure Windows USB state classification and exact-device gates."""

import hashlib
import re
from dataclasses import dataclass
from enum import Enum


USB_ID = re.compile(
    r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})",
    re.IGNORECASE,
)
SONY_VENDOR_ID = 0x054C
NORMAL_PID = 0x0490
SERVICE_PIDS = frozenset((0x02A9, 0x0336))
ACCEPTED_PIDS = frozenset((NORMAL_PID, *SERVICE_PIDS))


class DeviceGateError(RuntimeError):
    """Raised when connected-device state is not exactly approved."""


class UsbState(Enum):
    NORMAL_MSC = "NORMAL_MSC"
    NORMAL_WINUSB = "NORMAL_WINUSB"
    SERVICE_UNBOUND = "SERVICE_UNBOUND"
    SERVICE_WINUSB = "SERVICE_WINUSB"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class DeviceSnapshot:
    instance_id: str
    vid: int
    pid: int
    service: str
    name: str


def parse_pnp_records(records):
    """Convert CIM dictionaries into validated snapshots."""
    snapshots = []
    for record in records:
        if not isinstance(record, dict):
            raise DeviceGateError("Windows returned a malformed device record")
        instance_id = record.get("DeviceID")
        if not isinstance(instance_id, str):
            raise DeviceGateError("Windows device record has no string DeviceID")
        match = USB_ID.search(instance_id)
        if match is None:
            raise DeviceGateError("Windows device record has an invalid USB ID")
        service = record.get("Service") or ""
        name = record.get("Name") or ""
        if not isinstance(service, str) or not isinstance(name, str):
            raise DeviceGateError("Windows device record fields are malformed")
        snapshots.append(
            DeviceSnapshot(
                instance_id=instance_id,
                vid=int(match.group(1), 16),
                pid=int(match.group(2), 16),
                service=service,
                name=name,
            )
        )
    return snapshots


def classify(snapshot):
    """Classify one snapshot without guessing unknown drivers or identities."""
    if snapshot.vid != SONY_VENDOR_ID or snapshot.pid not in ACCEPTED_PIDS:
        return UsbState.UNKNOWN
    service = snapshot.service.casefold()
    if snapshot.pid == NORMAL_PID:
        if service == "usbstor":
            return UsbState.NORMAL_MSC
        if service == "winusb":
            return UsbState.NORMAL_WINUSB
    elif service == "winusb":
        return UsbState.SERVICE_WINUSB
    elif service in ("", "usbccgp"):
        return UsbState.SERVICE_UNBOUND
    return UsbState.UNKNOWN


def require_one(snapshots, expected=None):
    """Require exactly one accepted device in an optional exact state."""
    if len(snapshots) != 1:
        raise DeviceGateError(
            "expected exactly one connected Sony camera device"
        )
    snapshot = snapshots[0]
    state = classify(snapshot)
    if state is UsbState.UNKNOWN:
        raise DeviceGateError("connected Sony USB identity or driver is not approved")
    if expected is not None and state is not expected:
        raise DeviceGateError(
            f"expected USB state {expected.value}, received {state.value}"
        )
    return snapshot


def redacted_instance(instance_id):
    """Return a stable local correlation token without exposing the USB serial."""
    return hashlib.sha256(instance_id.encode("utf-8")).hexdigest()[:12]
