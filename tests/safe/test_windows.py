import json
import subprocess
import unittest

from pmca.safe.state import DeviceSnapshot
from pmca.safe.windows import DeviceProbeError, list_sony_usb_devices


class Result:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class CapturingRunner:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        return self.result


class WindowsProbeTests(unittest.TestCase):
    def test_queries_windows_read_only_and_parses_single_object(self):
        record = {
            "DeviceID": "USB\\VID_054C&PID_0490\\SECRET123",
            "Service": "USBSTOR",
            "Name": "NEX-C3",
        }
        runner = CapturingRunner(Result(stdout=json.dumps(record)))

        devices = list_sony_usb_devices(runner=runner)

        self.assertEqual(
            devices,
            [
                DeviceSnapshot(
                    instance_id=record["DeviceID"],
                    vid=0x054C,
                    pid=0x0490,
                    service="USBSTOR",
                    name="NEX-C3",
                )
            ],
        )
        argv, kwargs = runner.calls[0]
        self.assertEqual(argv[:3], ["powershell.exe", "-NoProfile", "-NonInteractive"])
        self.assertEqual(argv[3], "-Command")
        self.assertIn("Get-CimInstance Win32_PnPEntity", argv[4])
        self.assertNotIn("Set-CimInstance", argv[4])
        self.assertNotIn("Remove-CimInstance", argv[4])
        self.assertEqual(kwargs["timeout"], 10)
        self.assertTrue(kwargs["capture_output"])
        self.assertTrue(kwargs["text"])
        self.assertFalse(kwargs["check"])

    def test_normalizes_json_array(self):
        records = [
            {
                "DeviceID": "USB\\VID_054C&PID_02A9\\A",
                "Service": "WinUSB",
                "Name": "Sony service device",
            },
            {
                "DeviceID": "USB\\VID_054C&PID_0336\\B",
                "Service": "",
                "Name": "Sony service device",
            },
        ]

        devices = list_sony_usb_devices(
            runner=CapturingRunner(Result(stdout=json.dumps(records)))
        )

        self.assertEqual([device.pid for device in devices], [0x02A9, 0x0336])

    def test_empty_output_means_no_devices(self):
        devices = list_sony_usb_devices(runner=CapturingRunner(Result(stdout="  ")))

        self.assertEqual(devices, [])

    def test_timeout_is_wrapped_without_command_output(self):
        def timeout_runner(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

        with self.assertRaisesRegex(DeviceProbeError, "timed out"):
            list_sony_usb_devices(runner=timeout_runner)

    def test_nonzero_exit_is_wrapped_without_stderr(self):
        runner = CapturingRunner(Result(stderr="SECRET ERROR", returncode=1))

        with self.assertRaisesRegex(DeviceProbeError, "query failed") as caught:
            list_sony_usb_devices(runner=runner)

        self.assertNotIn("SECRET ERROR", str(caught.exception))

    def test_malformed_json_is_wrapped(self):
        runner = CapturingRunner(Result(stdout="not-json"))

        with self.assertRaisesRegex(DeviceProbeError, "invalid JSON"):
            list_sony_usb_devices(runner=runner)


if __name__ == "__main__":
    unittest.main()
