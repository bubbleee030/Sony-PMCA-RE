import json
import unittest
from datetime import datetime
from pathlib import Path

from firmware_tool_baseline import SOURCE_KEYS, validate_baseline_report
from pmca.analysis.tooling import TOOL_SPECS


ROOT = Path(__file__).resolve().parents[2]
EXPECTED_OUTCOMES = {
    "a6400-tw-v2.00": (
        "wrapper-parsing",
        "unknown-installer",
        "tool rejected the updater wrapper format",
    ),
    "a6700-tw-v2.00": (
        "decrypter-selection",
        "no-decrypter",
        "tool reported no compatible decrypter",
    ),
    "a7v-tw-v2.00": (
        "decrypter-selection",
        "no-decrypter",
        "tool reported no compatible decrypter",
    ),
}


class RealToolBaselineTests(unittest.TestCase):
    def test_provenance_matches_fixed_specs(self):
        document = json.loads(
            (ROOT / "analysis" / "tool-provenance.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(set(document), {"schema_version", "tools"})
        self.assertEqual(document["schema_version"], 1)
        self.assertEqual([item["name"] for item in document["tools"]], list(TOOL_SPECS))
        for item in document["tools"]:
            spec = TOOL_SPECS[item["name"]]
            self.assertEqual(item["repo_url"], spec.repo_url)
            self.assertEqual(item["commit"], spec.commit)
            self.assertEqual(item["entrypoint"], spec.entrypoint)
            self.assertEqual(item["license_path"], "LICENSE.txt")
            timestamp = item["acquired_at"]
            self.assertEqual(
                datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                .isoformat()
                .replace("+00:00", "Z"),
                timestamp,
            )

    def test_normalized_matrices_match_manifest_and_reproduced_limits(self):
        manifest = json.loads(
            (ROOT / "analysis" / "firmware-manifest.json").read_text(
                encoding="utf-8"
            )
        )
        digests = {
            entry["source_key"]: entry["sha256"] for entry in manifest["artifacts"]
        }

        for tool_key in TOOL_SPECS:
            with self.subTest(tool=tool_key):
                path = ROOT / "analysis" / "tool-baselines" / f"{tool_key}.json"
                serialized = path.read_text(encoding="utf-8")
                report = json.loads(serialized)
                self.assertIs(validate_baseline_report(report), report)
                self.assertNotIn("C:\\Users\\", serialized)
                self.assertNotIn("/home/", serialized)
                self.assertEqual(
                    tuple(item["source_key"] for item in report["results"]),
                    SOURCE_KEYS,
                )
                for item in report["results"]:
                    source_key = item["source_key"]
                    baseline = item["baseline"]
                    self.assertEqual(baseline["input_sha256"], digests[source_key])
                    self.assertEqual(baseline["exit_code"], 1)
                    self.assertFalse(baseline["timed_out"])
                    self.assertEqual(
                        (
                            baseline["stage"],
                            baseline["error_class"],
                            baseline["safe_summary"],
                        ),
                        EXPECTED_OUTCOMES[source_key],
                    )


if __name__ == "__main__":
    unittest.main()
