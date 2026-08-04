import hashlib
import unittest
from collections import namedtuple

from pmca.safe.state import DeviceGateError, DeviceSnapshot, UsbState
from pmca.safe.workflow import (
    NormalSession,
    RealDeviceSource,
    SafeServiceWorkflow,
    ServiceSession,
    WorkflowError,
)


CameraInfo = namedtuple("CameraInfo", "modelName")


def snapshot(state):
    values = {
        UsbState.NORMAL_MSC: (0x0490, "USBSTOR"),
        UsbState.NORMAL_WINUSB: (0x0490, "WinUSB"),
        UsbState.SERVICE_UNBOUND: (0x02A9, ""),
        UsbState.SERVICE_WINUSB: (0x02A9, "WinUSB"),
        UsbState.UNKNOWN: (0x9999, "mystery"),
    }
    pid, service = values[state]
    return DeviceSnapshot(
        instance_id=f"USB\\VID_054C&PID_{pid:04X}\\SECRET123",
        vid=0x054C,
        pid=pid,
        service=service,
        name="NEX-C3",
    )


class FakeNormalSession:
    def __init__(self, model="NEX-C3", transition_error=None):
        self.model = model
        self.transition_error = transition_error
        self.identity_count = 0
        self.transition_count = 0

    def identity(self):
        self.identity_count += 1
        return CameraInfo(self.model)

    def request_transition(self):
        self.transition_count += 1
        if self.transition_error:
            raise self.transition_error


class FakeServiceSession:
    def __init__(self, response=b"hasp-response", error=None):
        self.response = response
        self.error = error
        self.read_count = 0

    def read_hasp(self):
        self.read_count += 1
        if self.error:
            raise self.error
        return self.response


class FakeSource:
    def __init__(self, states, normal=None, service=None):
        self.states = list(states)
        self.normal = normal or FakeNormalSession()
        self.service = service or FakeServiceSession()
        self.snapshot_count = 0
        self.open_normal_count = 0
        self.open_service_count = 0
        self.sleeps = []

    def snapshots(self):
        self.snapshot_count += 1
        if not self.states:
            return []
        value = self.states.pop(0)
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [snapshot(value)]

    def open_normal(self):
        self.open_normal_count += 1
        return self.normal

    def open_service(self):
        self.open_service_count += 1
        return self.service

    def sleep(self, seconds):
        self.sleeps.append(seconds)


class FakeAuth:
    def __init__(self, events, auth_error=None):
        self.events = events
        self.auth_error = auth_error

    def start(self):
        self.events.append("start")

    def authenticate(self):
        self.events.append("authenticate")
        if self.auth_error:
            raise self.auth_error

    def stop(self):
        self.events.append("stop")


class FakeIdentityCamera:
    def __init__(self, events):
        self.events = events

    def getCameraInfo(self):
        self.events.append("identity")
        return CameraInfo("NEX-C3")


class FakeServiceCamera:
    def __init__(self, events, response=b"hasp", error=None):
        self.events = events
        self.response = response
        self.error = error

    def readHasp(self):
        self.events.append("read_hasp")
        if self.error:
            raise self.error
        return self.response


class WorkflowTests(unittest.TestCase):
    def test_status_returns_classified_state_and_redacted_instance(self):
        source = FakeSource([UsbState.NORMAL_MSC])

        summary = SafeServiceWorkflow(source).status()

        self.assertEqual(summary.state, UsbState.NORMAL_MSC)
        self.assertEqual((summary.vid, summary.pid), (0x054C, 0x0490))
        self.assertEqual(len(summary.instance_token), 12)
        self.assertNotIn("SECRET123", summary.instance_token)

    def test_acknowledgement_must_be_exact_before_usb_calls(self):
        for method in ("enter", "probe"):
            source = FakeSource([UsbState.NORMAL_WINUSB])
            workflow = SafeServiceWorkflow(source)

            with self.subTest(method=method):
                with self.assertRaisesRegex(WorkflowError, "exact acknowledgement"):
                    getattr(workflow, method)("nex-c3")
                self.assertEqual(source.snapshot_count, 0)
                self.assertEqual(source.open_normal_count, 0)
                self.assertEqual(source.open_service_count, 0)

    def test_enter_requires_normal_winusb_before_opening_usb(self):
        for state in (
            UsbState.NORMAL_MSC,
            UsbState.SERVICE_UNBOUND,
            UsbState.SERVICE_WINUSB,
            UsbState.UNKNOWN,
        ):
            source = FakeSource([state])

            with self.subTest(state=state):
                with self.assertRaises(DeviceGateError):
                    SafeServiceWorkflow(source).enter("NEX-C3")
                self.assertEqual(source.open_normal_count, 0)

    def test_enter_rejects_model_mismatch_before_transition(self):
        normal = FakeNormalSession(model="ILCE-6400")
        source = FakeSource([UsbState.NORMAL_WINUSB], normal=normal)

        with self.assertRaisesRegex(WorkflowError, "not NEX-C3"):
            SafeServiceWorkflow(source).enter("NEX-C3")

        self.assertEqual(normal.identity_count, 1)
        self.assertEqual(normal.transition_count, 0)

    def test_enter_retries_only_empty_or_temporarily_normal_state(self):
        source = FakeSource(
            [
                UsbState.NORMAL_WINUSB,
                None,
                UsbState.NORMAL_WINUSB,
                UsbState.SERVICE_UNBOUND,
            ]
        )

        summary = SafeServiceWorkflow(source).enter("NEX-C3")

        self.assertEqual(summary.state, UsbState.SERVICE_UNBOUND)
        self.assertEqual(summary.pid, 0x02A9)
        self.assertEqual(source.normal.transition_count, 1)
        self.assertEqual(source.sleeps, [0.5, 0.5, 0.5])

    def test_enter_fails_immediately_on_populated_unexpected_state(self):
        for unexpected in (
            UsbState.UNKNOWN,
            [
                snapshot(UsbState.SERVICE_UNBOUND),
                snapshot(UsbState.SERVICE_WINUSB),
            ],
        ):
            source = FakeSource([UsbState.NORMAL_WINUSB, unexpected])

            with self.subTest(unexpected=unexpected):
                with self.assertRaises((DeviceGateError, WorkflowError)):
                    SafeServiceWorkflow(source).enter("NEX-C3")
                self.assertEqual(source.sleeps, [0.5])

    def test_enter_times_out_after_twenty_empty_polls(self):
        source = FakeSource([UsbState.NORMAL_WINUSB] + [None] * 20)

        with self.assertRaisesRegex(WorkflowError, "timed out"):
            SafeServiceWorkflow(source).enter("NEX-C3")

        self.assertEqual(len(source.sleeps), 20)

    def test_probe_requires_service_winusb_before_opening_usb(self):
        for state in (
            UsbState.NORMAL_MSC,
            UsbState.NORMAL_WINUSB,
            UsbState.SERVICE_UNBOUND,
            UsbState.UNKNOWN,
        ):
            source = FakeSource([state])

            with self.subTest(state=state):
                with self.assertRaises(DeviceGateError):
                    SafeServiceWorkflow(source).probe("NEX-C3")
                self.assertEqual(source.open_service_count, 0)

    def test_probe_hashes_one_response_without_returning_bytes(self):
        response = b"secret-hasp-response"
        service = FakeServiceSession(response=response)
        source = FakeSource([UsbState.SERVICE_WINUSB], service=service)

        summary = SafeServiceWorkflow(source).probe("NEX-C3")

        self.assertEqual(summary.pid, 0x02A9)
        self.assertEqual(summary.response_length, len(response))
        self.assertEqual(summary.sha256, hashlib.sha256(response).hexdigest())
        self.assertFalse(hasattr(summary, "response"))
        self.assertEqual(service.read_count, 1)


class SessionTests(unittest.TestCase):
    def test_normal_session_identity_uses_allowlisted_device(self):
        events = []
        device = object()
        session = NormalSession(
            device,
            auth_factory=lambda driver: FakeAuth(events),
            camera_factory=lambda received: (
                self.assertIs(received, device) or FakeIdentityCamera(events)
            ),
        )

        info = session.identity()

        self.assertEqual(info.modelName, "NEX-C3")
        self.assertEqual(events, ["identity"])

    def test_normal_transition_starts_then_authenticates(self):
        events = []
        driver = object()
        device = type("Device", (), {"driver": driver})()
        session = NormalSession(
            device,
            auth_factory=lambda received: (
                self.assertIs(received, driver) or FakeAuth(events)
            ),
        )

        session.request_transition()

        self.assertEqual(events, ["start", "authenticate"])

    def test_normal_transition_stops_on_authentication_failure(self):
        events = []
        error = RuntimeError("auth failed")
        device = type("Device", (), {"driver": object()})()
        session = NormalSession(
            device,
            auth_factory=lambda driver: FakeAuth(events, error),
        )

        with self.assertRaisesRegex(RuntimeError, "auth failed"):
            session.request_transition()

        self.assertEqual(events, ["start", "authenticate", "stop"])

    def test_service_session_always_stops_after_one_read(self):
        events = []
        driver = object()
        device = type("Device", (), {"driver": driver})()
        session = ServiceSession(
            device,
            auth_factory=lambda received: (
                self.assertIs(received, driver) or FakeAuth(events)
            ),
            camera_factory=lambda received: (
                self.assertIs(received, device) or FakeServiceCamera(events)
            ),
        )

        result = session.read_hasp()

        self.assertEqual(result, b"hasp")
        self.assertEqual(
            events,
            ["start", "authenticate", "read_hasp", "stop"],
        )

    def test_service_session_stops_when_read_fails(self):
        events = []
        device = type("Device", (), {"driver": object()})()
        session = ServiceSession(
            device,
            auth_factory=lambda driver: FakeAuth(events),
            camera_factory=lambda received: FakeServiceCamera(
                events,
                error=RuntimeError("read failed"),
            ),
        )

        with self.assertRaisesRegex(RuntimeError, "read failed"):
            session.read_hasp()

        self.assertEqual(
            events,
            ["start", "authenticate", "read_hasp", "stop"],
        )


class FakeHandle:
    def __init__(self, pid):
        self.idVendor = 0x054C
        self.idProduct = pid


class FakeContext:
    def __init__(self, handles):
        self.handles = handles
        self.opened = []

    def listDevices(self, vendor):
        self.vendor = vendor
        return list(self.handles)

    def openDevice(self, handle):
        self.opened.append(handle)
        return f"driver-{handle.idProduct:04x}"


class RealSourceTests(unittest.TestCase):
    def test_real_source_opens_only_exact_normal_pid(self):
        context = FakeContext([FakeHandle(0x0490)])
        wrapped = object()
        source = RealDeviceSource(
            backend=object(),
            snapshot_provider=lambda: [],
            msc_context_factory=lambda backend: context,
            identity_device_factory=lambda driver: (
                self.assertEqual(driver, "driver-0490") or wrapped
            ),
        )

        session = source.open_normal()

        self.assertIs(session.device, wrapped)
        self.assertEqual(context.vendor, 0x054C)

    def test_real_source_rejects_zero_multiple_or_wrong_normal_handles(self):
        cases = [
            [],
            [FakeHandle(0x02A9)],
            [FakeHandle(0x0490), FakeHandle(0x0490)],
            [FakeHandle(0x0490), FakeHandle(0x02A9)],
        ]
        for handles in cases:
            context = FakeContext(handles)
            source = RealDeviceSource(
                backend=object(),
                snapshot_provider=lambda: [],
                msc_context_factory=lambda backend, current=context: current,
            )
            with self.subTest(pids=[handle.idProduct for handle in handles]):
                with self.assertRaises(DeviceGateError):
                    source.open_normal()

    def test_real_source_opens_only_accepted_service_pids(self):
        for pid in (0x02A9, 0x0336):
            context = FakeContext([FakeHandle(pid)])
            wrapped = object()
            source = RealDeviceSource(
                backend=object(),
                snapshot_provider=lambda: [],
                service_context_factory=lambda backend, current=context: current,
                service_device_factory=lambda driver: wrapped,
            )

            with self.subTest(pid=pid):
                self.assertIs(source.open_service().device, wrapped)

    def test_real_source_delegates_snapshots_and_sleep(self):
        events = []
        expected = [snapshot(UsbState.NORMAL_MSC)]
        source = RealDeviceSource(
            backend=object(),
            snapshot_provider=lambda: expected,
            sleeper=lambda seconds: events.append(seconds),
        )

        self.assertIs(source.snapshots(), expected)
        source.sleep(0.5)
        self.assertEqual(events, [0.5])


if __name__ == "__main__":
    unittest.main()
