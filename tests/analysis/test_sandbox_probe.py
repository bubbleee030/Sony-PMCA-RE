import copy
import tempfile
import unittest
from pathlib import Path

from pmca.analysis.sandbox_probe import (
    SandboxProbeError,
    build_probe_command,
    normalize_probe_report,
    parse_raw_probe_output,
    validate_probe_script,
    validate_probe_report,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def inside_raw():
    return {
        "schema_version": 1,
        "sandbox_dll_loaded": True,
        "file_write_succeeded": True,
        "registry_write_succeeded": True,
        "network_connected": False,
        "device_read_succeeded": False,
        "child_effect_observed": False,
        "token_is_admin": False,
    }


def inside_host():
    return {
        "host_file_exists": False,
        "host_registry_value_exists": False,
        "listener_accepted": False,
    }


class SandboxProbeTests(unittest.TestCase):
    def test_contained_observations_normalize_to_a_passing_report(self):
        report = normalize_probe_report(inside_raw(), inside_host())

        self.assertTrue(report["sandboxed"])
        self.assertTrue(report["passed"])
        self.assertEqual(
            [(item["name"], item["outcome"], item["passed"]) for item in report["checks"]],
            [
                ("sandbox_identity", "detected", True),
                ("file_write", "virtualized", True),
                ("registry_write", "virtualized", True),
                ("network", "denied", True),
                ("device_access", "denied", True),
                ("child_process", "denied", True),
                ("elevation", "dropped", True),
            ],
        )
        self.assertEqual(validate_probe_report(report), report)

    def test_denied_file_and_registry_writes_are_also_contained(self):
        raw = inside_raw()
        raw["file_write_succeeded"] = False
        raw["registry_write_succeeded"] = False

        report = normalize_probe_report(raw, inside_host())

        self.assertTrue(report["passed"])
        self.assertEqual(report["checks"][1]["outcome"], "denied")
        self.assertEqual(report["checks"][2]["outcome"], "denied")

    def test_outside_or_escaped_observations_fail_closed(self):
        raw = inside_raw()
        raw.update(
            {
                "sandbox_dll_loaded": False,
                "network_connected": True,
                "device_read_succeeded": True,
                "child_effect_observed": True,
                "token_is_admin": True,
            }
        )
        host = inside_host()
        host.update(
            {
                "host_file_exists": True,
                "host_registry_value_exists": True,
                "listener_accepted": True,
            }
        )

        report = normalize_probe_report(raw, host)

        self.assertFalse(report["passed"])
        self.assertEqual(
            [item["outcome"] for item in report["checks"]],
            [
                "absent",
                "host-write-observed",
                "host-write-observed",
                "accessible",
                "accessible",
                "accessible",
                "retained",
            ],
        )

    def test_unsafe_or_ambiguous_raw_observations_are_rejected(self):
        cases = []

        unknown_raw = inside_raw()
        unknown_raw["username"] = "example"
        cases.append((unknown_raw, inside_host()))

        missing_raw = inside_raw()
        del missing_raw["network_connected"]
        cases.append((missing_raw, inside_host()))

        non_boolean = inside_raw()
        non_boolean["sandbox_dll_loaded"] = 1
        cases.append((non_boolean, inside_host()))

        boolean_schema = inside_raw()
        boolean_schema["schema_version"] = True
        cases.append((boolean_schema, inside_host()))

        unknown_host = inside_host()
        unknown_host["target_path"] = "C:/Users/example"
        cases.append((inside_raw(), unknown_host))

        for raw, host in cases:
            with self.subTest(raw=raw, host=host):
                with self.assertRaises(SandboxProbeError):
                    normalize_probe_report(raw, host)

    def test_report_tampering_is_rejected(self):
        report = normalize_probe_report(inside_raw(), inside_host())
        cases = []

        extra = copy.deepcopy(report)
        extra["raw_output"] = "secret"
        cases.append(extra)

        wrong_order = copy.deepcopy(report)
        wrong_order["checks"].reverse()
        cases.append(wrong_order)

        false_overall = copy.deepcopy(report)
        false_overall["passed"] = False
        cases.append(false_overall)

        impossible_outcome = copy.deepcopy(report)
        impossible_outcome["checks"][3]["outcome"] = "maybe"
        cases.append(impossible_outcome)

        for document in cases:
            with self.subTest(document=document):
                with self.assertRaises(SandboxProbeError):
                    validate_probe_report(document)

    def test_committed_probe_is_pinned_and_commands_do_not_use_a_shell(self):
        script = REPOSITORY_ROOT / "analysis" / "fixtures" / "sandbox_probe.ps1"
        self.assertEqual(validate_probe_script(script), script.resolve())

        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            powershell = temporary_root / "powershell.exe"
            start = temporary_root / "Start.exe"
            powershell.write_bytes(b"fixture")
            start.write_bytes(b"fixture")

            outside = build_probe_command(powershell, script)
            inside = build_probe_command(powershell, script, start)

        common = [
            str(powershell.resolve()),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script.resolve()),
        ]
        self.assertEqual(outside, common)
        self.assertEqual(
            inside,
            [
                str(start.resolve()),
                "/box:A6400UpdaterLab",
                "/silent",
                "/wait",
                "/hide_window",
                *common,
            ],
        )

    def test_raw_probe_output_is_bounded_and_exact(self):
        raw = inside_raw()
        import json

        self.assertEqual(parse_raw_probe_output(json.dumps(raw)), raw)
        for value in (
            "",
            "not-json",
            json.dumps(raw) + "\nextra",
            "x" * 8193,
            json.dumps({**raw, "path": "C:/Users/example"}),
        ):
            with self.subTest(value=value[:80]):
                with self.assertRaises(SandboxProbeError):
                    parse_raw_probe_output(value)

    def test_committed_containment_report_is_valid(self):
        import json

        path = REPOSITORY_ROOT / "analysis" / "a6400-sandbox-probe.json"
        document = json.loads(path.read_text(encoding="utf-8"))

        self.assertTrue(document["passed"])
        self.assertEqual(validate_probe_report(document), document)


if __name__ == "__main__":
    unittest.main()
