import struct
import unittest
from unittest.mock import patch

from pmca.safe.policy import PolicyViolation
from pmca.safe.transport import (
    AllowlistedIdentityDevice,
    AllowlistedSenserDevice,
    TransportUnavailable,
    make_libusb_backend,
)
from pmca.usb.sony import SonyMscExtCmdDevice, SonySenserDevice


class FakeDriver:
    def __init__(self):
        self.reset_count = 0
        self.commands = []

    def reset(self):
        self.reset_count += 1

    def sendCommand(self, command):
        self.commands.append(command)
        return (0, 0, 0)


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.driver = FakeDriver()
        self.identity_payload = struct.pack("<IHH8x", 0, 1, 0)
        self.service_payload = struct.pack("<HHB", 0, 0x001F, 0)

    def test_valid_identity_query_reaches_transport(self):
        with patch.object(
            SonyMscExtCmdDevice,
            "sendSonyExtCommand",
            return_value=b"identity",
        ) as send:
            result = AllowlistedIdentityDevice(
                self.driver
            ).sendSonyExtCommand(1, self.identity_payload, 0x2000)

        self.assertEqual(result, b"identity")
        send.assert_called_once_with(1, self.identity_payload, 0x2000)

    def test_invalid_identity_query_never_reaches_transport(self):
        with patch.object(SonyMscExtCmdDevice, "sendSonyExtCommand") as send:
            with self.assertRaises(PolicyViolation):
                AllowlistedIdentityDevice(
                    self.driver
                ).sendSonyExtCommand(2, self.identity_payload, 0x2000)

        send.assert_not_called()

    def test_valid_service_read_reaches_transport(self):
        with patch.object(
            SonySenserDevice,
            "sendSenserPacket",
            return_value=(1, b"hasp"),
        ) as send:
            result = AllowlistedSenserDevice(
                self.driver
            ).sendSenserPacket(0x0010, self.service_payload)

        self.assertEqual(result, (1, b"hasp"))
        send.assert_called_once_with(0x0010, self.service_payload, None)

    def test_invalid_service_packets_never_reach_transport(self):
        denied = [
            (0xFF03, self.service_payload, None),
            (0x0010, struct.pack("<HHB", 0, 0x00F1, 0), None),
            (0x0010, struct.pack("<HHB", 0, 0x001F, 1), None),
            (0x0010, self.service_payload[:-1], None),
            (0x0010, self.service_payload, object()),
        ]
        with patch.object(SonySenserDevice, "sendSenserPacket") as send:
            for pfunc, payload, sink in denied:
                with self.subTest(pfunc=pfunc, payload=payload, sink=sink):
                    with self.assertRaises(PolicyViolation):
                        AllowlistedSenserDevice(
                            self.driver
                        ).sendSenserPacket(pfunc, payload, sink)

        send.assert_not_called()

    def test_backend_factory_returns_bundled_backend(self):
        backend = object()
        with patch(
            "pmca.safe.transport.libusb_package.get_libusb1_backend",
            return_value=backend,
        ):
            self.assertIs(make_libusb_backend(), backend)

    def test_backend_factory_rejects_missing_backend(self):
        with patch(
            "pmca.safe.transport.libusb_package.get_libusb1_backend",
            return_value=None,
        ):
            with self.assertRaisesRegex(
                TransportUnavailable,
                "bundled libusb backend is unavailable",
            ):
                make_libusb_backend()


if __name__ == "__main__":
    unittest.main()
