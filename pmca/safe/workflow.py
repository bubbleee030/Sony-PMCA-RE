"""Purpose-specific NEX-C3 service transition and read workflow."""

import hashlib
import time
from dataclasses import dataclass

from pmca.safe.state import (
    DeviceGateError,
    SERVICE_PIDS,
    SONY_VENDOR_ID,
    UsbState,
    classify,
    redacted_instance,
    require_one,
)
from pmca.safe.transport import (
    AllowlistedIdentityDevice,
    AllowlistedSenserDevice,
)
from pmca.safe.windows import list_sony_usb_devices
from pmca.usb.driver.generic.libusb import MscContext, VendorSpecificContext
from pmca.usb.sony import (
    SonyExtCmdCamera,
    SonySenserAuthDevice,
    SonySenserCamera,
)


ACK = "NEX-C3"
NORMAL_PID = 0x0490


class WorkflowError(RuntimeError):
    """Raised when a safe workflow transition cannot continue."""


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


def _require_ack(value):
    if value != ACK:
        raise WorkflowError("exact acknowledgement NEX-C3 is required")


class NormalSession:
    """Expose only identity and the fixed authentication transition."""

    def __init__(
        self,
        device,
        auth_factory=SonySenserAuthDevice,
        camera_factory=SonyExtCmdCamera,
    ):
        self.device = device
        self._auth_factory = auth_factory
        self._camera_factory = camera_factory

    def identity(self):
        return self._camera_factory(self.device).getCameraInfo()

    def request_transition(self):
        auth = self._auth_factory(self.device.driver)
        auth.start()
        try:
            auth.authenticate()
        except Exception:
            auth.stop()
            raise


class ServiceSession:
    """Expose only one authenticated allowlisted READ_HASP operation."""

    def __init__(
        self,
        device,
        auth_factory=SonySenserAuthDevice,
        camera_factory=SonySenserCamera,
    ):
        self.device = device
        self._auth_factory = auth_factory
        self._camera_factory = camera_factory

    def read_hasp(self):
        auth = self._auth_factory(self.device.driver)
        auth.start()
        try:
            auth.authenticate()
            return self._camera_factory(self.device).readHasp()
        finally:
            auth.stop()


class RealDeviceSource:
    """Open only exact normal/service USB identities through libusb."""

    def __init__(
        self,
        backend,
        snapshot_provider=list_sony_usb_devices,
        sleeper=time.sleep,
        msc_context_factory=MscContext,
        service_context_factory=VendorSpecificContext,
        identity_device_factory=AllowlistedIdentityDevice,
        service_device_factory=AllowlistedSenserDevice,
    ):
        self.backend = backend
        self._snapshot_provider = snapshot_provider
        self._sleeper = sleeper
        self._msc_context_factory = msc_context_factory
        self._service_context_factory = service_context_factory
        self._identity_device_factory = identity_device_factory
        self._service_device_factory = service_device_factory

    def snapshots(self):
        return self._snapshot_provider()

    def sleep(self, seconds):
        self._sleeper(seconds)

    def _open_exact(self, context_factory, accepted_pids, device_factory):
        context = context_factory(self.backend)
        handles = list(context.listDevices(SONY_VENDOR_ID))
        if len(handles) != 1:
            raise DeviceGateError(
                "expected exactly one approved Sony libusb device"
            )
        handle = handles[0]
        if (
            handle.idVendor != SONY_VENDOR_ID
            or handle.idProduct not in accepted_pids
        ):
            raise DeviceGateError("Sony libusb identity is not approved")
        driver = context.openDevice(handle)
        return device_factory(driver)

    def open_normal(self):
        device = self._open_exact(
            self._msc_context_factory,
            frozenset((NORMAL_PID,)),
            self._identity_device_factory,
        )
        return NormalSession(device)

    def open_service(self):
        device = self._open_exact(
            self._service_context_factory,
            SERVICE_PIDS,
            self._service_device_factory,
        )
        return ServiceSession(device)


class SafeServiceWorkflow:
    """Enforce the approved state machine around purpose-specific sessions."""

    def __init__(self, source):
        self.source = source

    @staticmethod
    def _summary(snapshot):
        return StatusSummary(
            state=classify(snapshot),
            vid=snapshot.vid,
            pid=snapshot.pid,
            instance_token=redacted_instance(snapshot.instance_id),
        )

    def status(self):
        snapshot = require_one(self.source.snapshots())
        return self._summary(snapshot)

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
            if state in (
                UsbState.SERVICE_UNBOUND,
                UsbState.SERVICE_WINUSB,
            ):
                return self._summary(snapshot)
            if state is not UsbState.NORMAL_WINUSB:
                raise WorkflowError(
                    "unexpected USB state during transition"
                )
        raise WorkflowError("service-mode enumeration timed out")

    def probe(self, acknowledgement):
        _require_ack(acknowledgement)
        snapshot = require_one(
            self.source.snapshots(),
            UsbState.SERVICE_WINUSB,
        )
        response = self.source.open_service().read_hasp()
        return ProbeSummary(
            pid=snapshot.pid,
            response_length=len(response),
            sha256=hashlib.sha256(response).hexdigest(),
        )
