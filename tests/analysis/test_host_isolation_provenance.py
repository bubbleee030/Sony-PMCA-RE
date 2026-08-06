import copy
import json
import unittest
from pathlib import Path

from pmca.analysis.host_provenance import (
    HostProvenanceError,
    validate_host_isolation_provenance,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def valid_document():
    return {
        "schema_version": 1,
        "host": {
            "platform": "windows-x64",
            "storage_ceiling_gib": 40,
            "camera_policy": "physically-disconnected",
            "reboot_barrier": "all-other-codex-tasks-finished",
        },
        "isolation": {
            "name": "Sandboxie Plus",
            "version": "1.18.1",
            "source": "winget:Sandboxie.Plus",
            "archive_verification": "winget-sha256-verified",
            "authenticode": "valid",
            "restore_point": "created",
            "service": "running",
            "driver": "running",
        },
        "tools": [
            {
                "name": "ghidra",
                "version": "12.1.2",
                "source_url": "https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.2_build",
                "archive": "ghidra_12.1.2_PUBLIC_20260605.zip",
                "sha256": "b" * 64,
                "verification": "published-sha256",
                "path_category": ".artifacts/tools/ghidra-12.1.2",
                "purpose": "static-disassembly-and-decompilation",
            }
        ],
    }


class HostIsolationProvenanceTests(unittest.TestCase):
    def test_valid_document_is_deep_copied(self):
        document = valid_document()
        validated = validate_host_isolation_provenance(document)

        self.assertEqual(validated, document)
        self.assertIsNot(validated, document)
        self.assertIsNot(validated["tools"], document["tools"])

    def test_unsafe_or_incomplete_metadata_is_rejected(self):
        cases = []

        unknown_top_level = valid_document()
        unknown_top_level["local_path"] = "C:/Users/example"
        cases.append(unknown_top_level)

        missing_driver_state = valid_document()
        del missing_driver_state["isolation"]["driver"]
        cases.append(missing_driver_state)

        bad_digest = valid_document()
        bad_digest["tools"][0]["sha256"] = "not-a-digest"
        cases.append(bad_digest)

        unsafe_source = valid_document()
        unsafe_source["tools"][0]["source_url"] = "http://example.com/tool.zip"
        cases.append(unsafe_source)

        absolute_path = valid_document()
        absolute_path["tools"][0]["path_category"] = "C:/tools/ghidra"
        cases.append(absolute_path)

        wrong_camera_policy = valid_document()
        wrong_camera_policy["host"]["camera_policy"] = "camera-may-connect"
        cases.append(wrong_camera_policy)

        boolean_schema = valid_document()
        boolean_schema["schema_version"] = True
        cases.append(boolean_schema)

        traversing_archive = valid_document()
        traversing_archive["tools"][0]["archive"] = "../ghidra.zip"
        cases.append(traversing_archive)

        for document in cases:
            with self.subTest(document=document):
                with self.assertRaises(HostProvenanceError):
                    validate_host_isolation_provenance(document)

    def test_duplicate_tool_names_are_rejected(self):
        document = valid_document()
        document["tools"].append(copy.deepcopy(document["tools"][0]))

        with self.assertRaises(HostProvenanceError):
            validate_host_isolation_provenance(document)

    def test_committed_document_is_valid(self):
        path = REPOSITORY_ROOT / "analysis" / "host-isolation-provenance.json"
        document = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(validate_host_isolation_provenance(document), document)


if __name__ == "__main__":
    unittest.main()
