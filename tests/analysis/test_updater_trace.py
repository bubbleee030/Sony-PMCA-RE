import copy
import tempfile
import unittest
from pathlib import Path

from pmca.analysis.updater_trace import (
    TraceError,
    build_no_camera_run,
    build_reproduced_trace_report,
    build_updater_command,
    normalize_monitor_events,
    validate_updater_trace_report,
)


UPDATER_DIGEST = "e" * 64
POLICY_DIGEST = "a" * 64


def _observation(**changes):
    value = {
        "updater_sha256": UPDATER_DIGEST,
        "sandbox_policy_sha256": POLICY_DIGEST,
        "camera_present": False,
        "sandboxed": True,
        "elevated": False,
        "network_blocked": True,
        "launched": True,
        "termination": "exited",
        "exit_code": 2,
        "process_roles": ["sandbox-helper", "updater"],
    }
    value.update(changes)
    return value


class UpdaterTraceTests(unittest.TestCase):
    def test_updater_command_is_exact_and_contains_no_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            start = root / "Start.exe"
            updater = root / "Update_ILCE6400V200.exe"
            start.write_bytes(b"start")
            updater.write_bytes(b"updater")

            self.assertEqual(
                build_updater_command(start, updater),
                [
                    str(start.resolve()),
                    "/box:A6400UpdaterLab",
                    "/silent",
                    "/wait",
                    "/hide_window",
                    str(updater.resolve()),
                ],
            )

            wrong = root / "renamed.exe"
            wrong.write_bytes(b"updater")
            with self.assertRaises(TraceError):
                build_updater_command(start, wrong)

    def test_monitor_events_are_aggregated_without_raw_paths_or_ids(self):
        events = [
            {
                "type": 0x0002000A,
                "pid": 1234,
                "tid": 7,
                "box": "A6400UpdaterLab",
                "process": "Update_ILCE6400V200.exe",
                "message": r"\Device\USBPDO-7\VID_054C&PID_1234",
            },
            {
                "type": 0x0002000A,
                "pid": 1234,
                "tid": 8,
                "box": "A6400UpdaterLab",
                "process": "Update_ILCE6400V200.exe",
                "message": r"\Device\USBPDO-7\VID_054C&PID_1234",
            },
            {
                "type": 0x0000000A,
                "pid": 1234,
                "tid": 9,
                "box": "A6400UpdaterLab",
                "process": "Update_ILCE6400V200.exe",
                "message": r"\Device\HarddiskVolume3\Windows\System32\kernel32.dll",
            },
            {
                "type": 0x0001000B,
                "pid": 1234,
                "tid": 10,
                "box": "A6400UpdaterLab",
                "process": "Update_ILCE6400V200.exe",
                "message": r"\REGISTRY\USER\S-1-5-21\Software\Sony",
            },
        ]

        normalized = normalize_monitor_events(events)

        self.assertEqual(
            normalized[0],
            {
                "category": "device-open",
                "outcome": "denied",
                "process_role": "updater",
                "count": 2,
                "unique_target_count": 1,
                "target_sha256": normalized[0]["target_sha256"],
            },
        )
        self.assertEqual(len(normalized[0]["target_sha256"]), 1)
        self.assertEqual(len(normalized[0]["target_sha256"][0]), 64)
        self.assertEqual(normalized[1]["category"], "file")
        self.assertEqual(normalized[2]["category"], "registry")
        rendered = repr(normalized)
        self.assertNotIn("USBPDO", rendered)
        self.assertNotIn("Sony", rendered)
        self.assertNotIn("1234", rendered)

    def test_unknown_or_cross_box_monitor_events_are_hard_errors(self):
        base = {
            "type": 0x0001000A,
            "pid": 1,
            "tid": 1,
            "box": "A6400UpdaterLab",
            "process": "Update_ILCE6400V200.exe",
            "message": r"C:\Windows\System32\kernel32.dll",
        }
        cases = []
        wrong_box = copy.deepcopy(base)
        wrong_box["box"] = "DefaultBox"
        cases.append(wrong_box)
        unknown_type = copy.deepcopy(base)
        unknown_type["type"] = 0x00010055
        cases.append(unknown_type)
        unbounded = copy.deepcopy(base)
        unbounded["message"] = "x" * 2049
        cases.append(unbounded)
        extra = copy.deepcopy(base)
        extra["raw"] = "not allowed"
        cases.append(extra)

        for event in cases:
            with self.subTest(event=event):
                with self.assertRaises(TraceError):
                    normalize_monitor_events([event])

    def test_two_safe_runs_reproduce_the_no_camera_boundary(self):
        denied_device = [
            {
                "type": 0x0002000A,
                "pid": 20,
                "tid": 2,
                "box": "A6400UpdaterLab",
                "process": "Update_ILCE6400V200.exe",
                "message": r"\Device\USBPDO-1",
            }
        ]
        first = build_no_camera_run(denied_device, _observation())
        second = build_no_camera_run(
            denied_device,
            _observation(termination="timeout-terminated", exit_code=None),
        )

        report = build_reproduced_trace_report((first, second))

        self.assertEqual(report["boundary"], "no-camera-boundary")
        self.assertTrue(report["boundary_reproduced"])
        self.assertTrue(report["passed"])
        self.assertEqual(report["run_count"], 2)
        self.assertEqual(validate_updater_trace_report(report), report)

    def test_accessible_device_or_camera_presence_cannot_pass(self):
        allowed_device = [
            {
                "type": 0x0001000A,
                "pid": 20,
                "tid": 2,
                "box": "A6400UpdaterLab",
                "process": "Update_ILCE6400V200.exe",
                "message": r"\Device\USBPDO-1",
            }
        ]
        run = build_no_camera_run(allowed_device, _observation())
        self.assertEqual(run["boundary"], "device-access-observed")
        self.assertFalse(run["passed"])

        with self.assertRaises(TraceError):
            build_no_camera_run([], _observation(camera_present=True))

    def test_report_tampering_is_rejected(self):
        first = build_no_camera_run([], _observation())
        second = build_no_camera_run([], _observation())
        report = build_reproduced_trace_report((first, second))
        cases = []

        extra = copy.deepcopy(report)
        extra["raw_events"] = []
        cases.append(extra)
        contradicted = copy.deepcopy(report)
        contradicted["passed"] = False
        cases.append(contradicted)
        duplicate = copy.deepcopy(report)
        duplicate["runs"].append(copy.deepcopy(duplicate["runs"][0]))
        duplicate["run_count"] = 3
        cases.append(duplicate)

        for document in cases:
            with self.subTest(document=document):
                with self.assertRaises(TraceError):
                    validate_updater_trace_report(document)


if __name__ == "__main__":
    unittest.main()
