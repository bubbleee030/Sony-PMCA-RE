import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import safe_service
from pmca.safe.policy import PolicyViolation
from pmca.safe.state import DeviceGateError, UsbState
from pmca.safe.transport import TransportUnavailable
from pmca.safe.windows import DeviceProbeError
from pmca.safe.workflow import ProbeSummary, StatusSummary, WorkflowError


class FakeWorkflow:
    def __init__(self):
        self.calls = []
        self.status_result = StatusSummary(
            state=UsbState.NORMAL_MSC,
            vid=0x054C,
            pid=0x0490,
            instance_token="abc123def456",
        )
        self.enter_result = StatusSummary(
            state=UsbState.SERVICE_UNBOUND,
            vid=0x054C,
            pid=0x02A9,
            instance_token="fed654cba321",
        )
        self.probe_result = ProbeSummary(
            pid=0x02A9,
            response_length=19,
            sha256="a" * 64,
        )

    def status(self):
        self.calls.append(("status",))
        if isinstance(self.status_result, Exception):
            raise self.status_result
        return self.status_result

    def enter(self, acknowledgement):
        self.calls.append(("enter", acknowledgement))
        if isinstance(self.enter_result, Exception):
            raise self.enter_result
        return self.enter_result

    def probe(self, acknowledgement):
        self.calls.append(("probe", acknowledgement))
        if isinstance(self.probe_result, Exception):
            raise self.probe_result
        return self.probe_result


def run_cli(argv, workflow):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = safe_service.main(argv, workflow=workflow)
    return code, stdout.getvalue(), stderr.getvalue()


class CliTests(unittest.TestCase):
    def test_status_prints_only_safe_summary(self):
        workflow = FakeWorkflow()

        code, stdout, stderr = run_cli(["status"], workflow)

        self.assertEqual(code, 0)
        self.assertEqual(workflow.calls, [("status",)])
        self.assertIn("USB state: NORMAL_MSC", stdout)
        self.assertIn("USB ID: 054c:0490", stdout)
        self.assertIn("Instance token: abc123def456", stdout)
        self.assertNotIn("SECRET123", stdout)
        self.assertEqual(stderr, "")

    def test_enter_requires_ack_and_prints_resulting_state(self):
        workflow = FakeWorkflow()

        code, stdout, stderr = run_cli(
            ["enter", "--ack", "NEX-C3"],
            workflow,
        )

        self.assertEqual(code, 0)
        self.assertEqual(workflow.calls, [("enter", "NEX-C3")])
        self.assertIn("USB state: SERVICE_UNBOUND", stdout)
        self.assertIn("USB ID: 054c:02a9", stdout)
        self.assertEqual(stderr, "")

    def test_probe_prints_hash_and_length_without_raw_response(self):
        workflow = FakeWorkflow()

        code, stdout, stderr = run_cli(
            ["probe", "--ack", "NEX-C3"],
            workflow,
        )

        self.assertEqual(code, 0)
        self.assertEqual(workflow.calls, [("probe", "NEX-C3")])
        self.assertIn("Allowlisted read completed", stdout)
        self.assertIn("Service PID: 02a9", stdout)
        self.assertIn("Response length: 19", stdout)
        self.assertIn(f"Response SHA-256: {'a' * 64}", stdout)
        self.assertNotIn("raw-secret-response", stdout)
        self.assertEqual(stderr, "")

    def test_only_three_subcommands_parse(self):
        parser = safe_service.build_parser()
        for argv in (["shell"], ["firmware"], ["probe", "--data", "00"]):
            with self.subTest(argv=argv):
                with redirect_stderr(io.StringIO()):
                    with self.assertRaisesRegex(SystemExit, "2"):
                        parser.parse_args(argv)

    def test_enter_and_probe_require_ack_argument(self):
        parser = safe_service.build_parser()
        for command in ("enter", "probe"):
            with self.subTest(command=command):
                with redirect_stderr(io.StringIO()):
                    with self.assertRaisesRegex(SystemExit, "2"):
                        parser.parse_args([command])

    def test_status_workflow_does_not_load_libusb_backend(self):
        with patch("safe_service.make_libusb_backend") as make_backend:
            workflow = safe_service.build_workflow("status")

        make_backend.assert_not_called()
        self.assertIsNone(workflow.source.backend)

    def test_usb_commands_load_the_explicit_libusb_backend(self):
        backend = object()
        for command in ("enter", "probe"):
            with self.subTest(command=command):
                with patch(
                    "safe_service.make_libusb_backend",
                    return_value=backend,
                ) as make_backend:
                    workflow = safe_service.build_workflow(command)

                make_backend.assert_called_once_with()
                self.assertIs(workflow.source.backend, backend)

    def test_backend_construction_error_has_no_traceback(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        error = TransportUnavailable("backend missing")
        with patch("safe_service.build_workflow", side_effect=error):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = safe_service.main(["status"])

        self.assertEqual(code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "Error: backend missing\n")
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_expected_safety_errors_have_no_traceback(self):
        errors = [
            PolicyViolation("packet denied"),
            DeviceGateError("device denied"),
            DeviceProbeError("query failed"),
            TransportUnavailable("backend missing"),
            WorkflowError("state denied"),
        ]
        for error in errors:
            workflow = FakeWorkflow()
            workflow.status_result = error

            with self.subTest(error=error):
                code, stdout, stderr = run_cli(["status"], workflow)
                self.assertEqual(code, 1)
                self.assertEqual(stdout, "")
                self.assertEqual(stderr, f"Error: {error}\n")
                self.assertNotIn("Traceback", stderr)


if __name__ == "__main__":
    unittest.main()
