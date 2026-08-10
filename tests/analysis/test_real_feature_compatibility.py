import json
import unittest
from pathlib import Path

from pmca.analysis.features import FEATURE_IDS, validate_compatibility_matrix


class RealFeatureCompatibilityTests(unittest.TestCase):
    def test_committed_matrix_is_valid_and_only_orientation_state_is_ready(self):
        path = Path("analysis/feature-compatibility.json")
        document = validate_compatibility_matrix(
            json.loads(path.read_text(encoding="utf-8"))
        )

        ready = tuple(item["id"] for item in document["features"] if item["ready"])
        self.assertEqual(ready, (FEATURE_IDS[0],))
        self.assertEqual(document["candidate_result"]["status"], "rejected")
        self.assertFalse(document["candidate_result"]["installable"])
        self.assertTrue(
            all(
                count == 0
                for scope in document["marker_scan"]["scopes"]
                for field in ("ascii_hits", "utf16le_hits")
                for count in scope[field].values()
            )
        )
        by_id = {item["id"]: item for item in document["features"]}
        self.assertTrue(
            any(
                evidence["source"]
                == "analysis/a6400-creative-look-boundary.json"
                for evidence in by_id["creative-look-base-tables"]["evidence"]
            )
        )
        self.assertTrue(
            any(
                evidence["source"]
                == "analysis/a6400-creative-look-boundary.json"
                for evidence in by_id["creative-look-adjustment-axes"]["evidence"]
            )
        )


if __name__ == "__main__":
    unittest.main()
