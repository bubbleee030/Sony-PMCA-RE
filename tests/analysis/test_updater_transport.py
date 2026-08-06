import ast
import copy
import json
import unittest
from pathlib import Path

from pmca.analysis.updater_transport import (
    SyntheticTransportHarness,
    TransportHarnessError,
    validate_synthetic_transcript,
    validate_transport_observations,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def valid_transcript():
    return {
        "schema_version": 1,
        "transport": "synthetic-replay-only",
        "camera_access": "forbidden",
        "model": "ILCE-6400",
        "exchanges": [
            {
                "sequence": 0,
                "operation": "synthetic-identity-query",
                "request_hex": "01020304",
                "response_hex": "494c43452d36343030",
                "timeout_ms": 1000,
                "elapsed_ms": 4,
            },
            {
                "sequence": 1,
                "operation": "synthetic-status-query",
                "request_hex": "1011",
                "response_hex": "0001",
                "timeout_ms": 500,
                "elapsed_ms": 2,
            },
        ],
    }


def valid_observations():
    return {
        "schema_version": 1,
        "subject": "ILCE-6400 firmware updater transport boundary",
        "camera_policy": "physically-disconnected",
        "dynamic_boundary": {
            "classification": "OBSERVATION",
            "source": "analysis/a6400-updater-no-camera.json",
            "boundary": "no-camera-boundary",
            "camera_present": False,
            "device_open_group_count": 0,
            "protocol_reached": False,
        },
        "static_boundary": [
            {
                "classification": "OBSERVATION",
                "component_role": "signed-updater-engine",
                "sha256": "8" * 64,
                "evidence": [
                    "imports:CreateFileW,DeviceIoControl",
                    "ioctl:0x002d0c00",
                    "ioctl:0x002d1400",
                    "ioctl:0x0004d014",
                ],
            },
            {
                "classification": "OBSERVATION",
                "component_role": "signed-storage-identity-helper",
                "sha256": "f" * 64,
                "evidence": [
                    "imports:SetupDiEnumDeviceInterfaces,DeviceIoControl",
                    "exports:XpStgDevGetVenIdAndProdId",
                ],
            },
        ],
        "harness": {
            "classification": "OBSERVATION",
            "mode": "synthetic-replay-only",
            "physical_device_enumeration": "not-implemented",
            "physical_device_open": "not-implemented",
            "unknown_request_action": "terminate",
            "model_mismatch_action": "terminate",
        },
        "inferences": [
            {
                "classification": "INFERENCE",
                "claim": "The updater engine is consistent with a mass-storage and SCSI pass-through transport boundary.",
                "basis": ["ioctl:0x0004d014", "string:FirmwareData*.dat"],
            }
        ],
        "unresolved": [
            {
                "classification": "UNRESOLVED",
                "gate": "camera-command-payload",
                "next_experiment": "Map the three DeviceIoControl call sites statically before adding any non-synthetic fixture.",
            }
        ],
        "conclusion": "No physical transport command has been observed; protocol replay remains synthetic only.",
    }


class UpdaterTransportTests(unittest.TestCase):
    def test_valid_transcript_is_deep_copied(self):
        document = valid_transcript()

        validated = validate_synthetic_transcript(document)

        self.assertEqual(validated, document)
        self.assertIsNot(validated, document)
        self.assertIsNot(validated["exchanges"], document["exchanges"])

    def test_exact_ordered_synthetic_replay_completes(self):
        harness = SyntheticTransportHarness(valid_transcript())

        identity = harness.exchange(
            "synthetic-identity-query",
            bytes.fromhex("01020304"),
            model="ILCE-6400",
            expected_response_length=9,
            timeout_ms=1000,
        )
        status = harness.exchange(
            "synthetic-status-query",
            bytes.fromhex("1011"),
            model="ILCE-6400",
            expected_response_length=2,
            timeout_ms=500,
        )

        self.assertEqual(identity, b"ILCE-6400")
        self.assertEqual(status, b"\x00\x01")
        self.assertTrue(harness.complete)
        self.assertFalse(harness.terminated)

    def test_unknown_or_out_of_order_request_terminates_replay(self):
        cases = [
            ("unknown-command", bytes.fromhex("01020304")),
            ("synthetic-status-query", bytes.fromhex("1011")),
            ("synthetic-identity-query", bytes.fromhex("01020305")),
        ]
        for operation, request in cases:
            with self.subTest(operation=operation, request=request):
                harness = SyntheticTransportHarness(valid_transcript())
                with self.assertRaises(TransportHarnessError):
                    harness.exchange(
                        operation,
                        request,
                        model="ILCE-6400",
                        expected_response_length=9,
                        timeout_ms=1000,
                    )
                self.assertTrue(harness.terminated)
                with self.assertRaises(TransportHarnessError):
                    harness.exchange(
                        "synthetic-identity-query",
                        bytes.fromhex("01020304"),
                        model="ILCE-6400",
                        expected_response_length=9,
                        timeout_ms=1000,
                    )

    def test_model_length_and_timeout_mismatch_terminate_replay(self):
        cases = [
            {"model": "ILCE-6700", "expected_response_length": 9, "timeout_ms": 1000},
            {"model": "ILCE-6400", "expected_response_length": 8, "timeout_ms": 1000},
            {"model": "ILCE-6400", "expected_response_length": 9, "timeout_ms": 999},
        ]
        for arguments in cases:
            with self.subTest(arguments=arguments):
                harness = SyntheticTransportHarness(valid_transcript())
                with self.assertRaises(TransportHarnessError):
                    harness.exchange(
                        "synthetic-identity-query",
                        bytes.fromhex("01020304"),
                        **arguments,
                    )
                self.assertTrue(harness.terminated)

    def test_fixture_timeout_terminates_without_returning_response(self):
        document = valid_transcript()
        document["exchanges"][0]["elapsed_ms"] = 1001
        harness = SyntheticTransportHarness(document)

        with self.assertRaises(TransportHarnessError):
            harness.exchange(
                "synthetic-identity-query",
                bytes.fromhex("01020304"),
                model="ILCE-6400",
                expected_response_length=9,
                timeout_ms=1000,
            )
        self.assertTrue(harness.terminated)

    def test_malformed_or_non_synthetic_transcripts_are_rejected(self):
        cases = []
        extra = valid_transcript()
        extra["usb_backend"] = "libusb"
        cases.append(extra)
        physical = valid_transcript()
        physical["camera_access"] = "allowed"
        cases.append(physical)
        skipped = valid_transcript()
        skipped["exchanges"][1]["sequence"] = 2
        cases.append(skipped)
        bad_hex = valid_transcript()
        bad_hex["exchanges"][0]["request_hex"] = "abc"
        cases.append(bad_hex)
        bad_model = valid_transcript()
        bad_model["model"] = "ILCE-6700"
        cases.append(bad_model)
        boolean_timeout = valid_transcript()
        boolean_timeout["exchanges"][0]["timeout_ms"] = True
        cases.append(boolean_timeout)

        for document in cases:
            with self.subTest(document=document):
                with self.assertRaises(TransportHarnessError):
                    validate_synthetic_transcript(document)

    def test_module_has_no_physical_device_or_process_entry_points(self):
        source_path = REPOSITORY_ROOT / "pmca" / "analysis" / "updater_transport.py"
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])

        self.assertTrue(imported_roots.isdisjoint({
            "ctypes", "subprocess", "socket", "usb", "win32api", "win32file", "wmi"
        }))
        source = source_path.read_text(encoding="utf-8").casefold()
        for forbidden in ("createfile", "deviceiocontrol", "setupdigetclassdevs", "libusb"):
            self.assertNotIn(forbidden, source)

    def test_transport_observations_reject_claim_promotion(self):
        document = valid_observations()
        self.assertEqual(validate_transport_observations(document), document)

        cases = []
        promoted = valid_observations()
        promoted["dynamic_boundary"]["protocol_reached"] = True
        cases.append(promoted)
        mislabeled = valid_observations()
        mislabeled["inferences"][0]["classification"] = "OBSERVATION"
        cases.append(mislabeled)
        installable = valid_observations()
        installable["harness"]["physical_device_open"] = "implemented"
        cases.append(installable)
        extra = valid_observations()
        extra["raw_request"] = "deadbeef"
        cases.append(extra)

        for candidate in cases:
            with self.subTest(candidate=candidate):
                with self.assertRaises(TransportHarnessError):
                    validate_transport_observations(candidate)

    def test_committed_transport_observations_are_valid(self):
        path = REPOSITORY_ROOT / "analysis" / "updater-transport-observations.json"
        document = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(validate_transport_observations(document), document)


if __name__ == "__main__":
    unittest.main()
