import hashlib
import unittest

from pmca.safe.state import (
    DeviceGateError,
    DeviceSnapshot,
    UsbState,
    classify,
    parse_pnp_records,
    redacted_instance,
    require_one,
)


def snapshot(service, pid=0x0490, vid=0x054C):
    return DeviceSnapshot(
        instance_id=f"USB\\VID_{vid:04X}&PID_{pid:04X}\\SECRET123",
        vid=vid,
        pid=pid,
        service=service,
        name="NEX-C3",
    )


class StateTests(unittest.TestCase):
    def test_classifies_normal_mass_storage(self):
        self.assertEqual(classify(snapshot("USBSTOR")), UsbState.NORMAL_MSC)

    def test_classifies_normal_winusb_case_insensitively(self):
        self.assertEqual(classify(snapshot("winusb")), UsbState.NORMAL_WINUSB)

    def test_classifies_unbound_service_pids(self):
        for service in ("", "usbccgp"):
            for pid in (0x02A9, 0x0336):
                with self.subTest(service=service, pid=pid):
                    self.assertEqual(
                        classify(snapshot(service, pid=pid)),
                        UsbState.SERVICE_UNBOUND,
                    )

    def test_classifies_bound_service_pids(self):
        for pid in (0x02A9, 0x0336):
            with self.subTest(pid=pid):
                self.assertEqual(
                    classify(snapshot("WinUSB", pid=pid)),
                    UsbState.SERVICE_WINUSB,
                )

    def test_unknown_vendor_pid_or_driver_is_unknown(self):
        cases = [
            snapshot("USBSTOR", vid=0x1234),
            snapshot("USBSTOR", pid=0x9999),
            snapshot("libusb0"),
            snapshot("USBSTOR", pid=0x02A9),
        ]
        for item in cases:
            with self.subTest(item=item):
                self.assertEqual(classify(item), UsbState.UNKNOWN)

    def test_parses_case_insensitive_usb_identity(self):
        records = [
            {
                "DeviceID": "usb\\vid_054c&pid_0490\\SECRET123",
                "Service": "USBSTOR",
                "Name": "NEX-C3",
            }
        ]

        result = parse_pnp_records(records)

        self.assertEqual(
            result,
            [
                DeviceSnapshot(
                    instance_id=records[0]["DeviceID"],
                    vid=0x054C,
                    pid=0x0490,
                    service="USBSTOR",
                    name="NEX-C3",
                )
            ],
        )

    def test_rejects_malformed_pnp_records(self):
        records = [
            {},
            {"DeviceID": "USB\\NOT_A_USB_ID", "Service": "", "Name": ""},
            {"DeviceID": 7, "Service": "", "Name": ""},
            {
                "DeviceID": "USB\\VID_054C&PID_02A9\\A",
                "Service": 0,
                "Name": "Sony service device",
            },
        ]
        for record in records:
            with self.subTest(record=record):
                with self.assertRaises(DeviceGateError):
                    parse_pnp_records([record])

    def test_require_one_accepts_exact_expected_state(self):
        item = snapshot("WinUSB")

        self.assertIs(
            require_one([item], UsbState.NORMAL_WINUSB),
            item,
        )

    def test_require_one_rejects_zero_multiple_unknown_and_wrong_state(self):
        denied = [
            ([], None),
            ([snapshot("USBSTOR"), snapshot("USBSTOR")], None),
            ([snapshot("USBSTOR", pid=0x9999)], None),
            ([snapshot("libusb0")], None),
            ([snapshot("USBSTOR")], UsbState.NORMAL_WINUSB),
        ]
        for snapshots, expected in denied:
            with self.subTest(snapshots=snapshots, expected=expected):
                with self.assertRaises(DeviceGateError):
                    require_one(snapshots, expected)

    def test_instance_redaction_is_stable_hash_not_secret(self):
        instance_id = "USB\\VID_054C&PID_0490\\SECRET123"

        token = redacted_instance(instance_id)

        self.assertEqual(
            token,
            hashlib.sha256(instance_id.encode("utf-8")).hexdigest()[:12],
        )
        self.assertNotIn("SECRET123", token)
        self.assertEqual(len(token), 12)


if __name__ == "__main__":
    unittest.main()
