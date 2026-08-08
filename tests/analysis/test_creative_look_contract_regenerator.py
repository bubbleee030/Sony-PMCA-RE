import json
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.static import regenerate_a6400_creative_look_contract_reports as regen


def _serialized(value):
    if isinstance(value, dict):
        return (json.dumps(value, indent=2) + "\n").encode("utf-8")
    return value.encode("utf-8")


class CreativeLookContractRegeneratorTests(unittest.TestCase):
    def test_build_reports_is_deterministic_and_returns_exactly_five_outputs(self):
        first = regen.build_reports()
        second = regen.build_reports()

        self.assertEqual(
            tuple(first),
            (
                regen.STACK_PATH,
                regen.GUIDE_PATH,
                regen.EVIDENCE_PATH,
                regen.TARGET_PATH,
                regen.FEASIBILITY_PATH,
            ),
        )
        self.assertEqual(
            {path: _serialized(value) for path, value in first.items()},
            {path: _serialized(value) for path, value in second.items()},
        )

    def test_checked_outputs_match_the_in_memory_build(self):
        reports = regen.build_reports()

        self.assertEqual(
            {path: path.read_bytes() for path in regen.OUTPUT_PATHS},
            {path: _serialized(value) for path, value in reports.items()},
        )

    def test_validation_failure_leaves_all_five_outputs_byte_identical(self):
        before = {path: path.read_bytes() for path in regen.OUTPUT_PATHS}

        with patch.object(
            regen,
            "validate_target_feature_report",
            side_effect=RuntimeError("synthetic target validation failure"),
        ), self.assertRaisesRegex(RuntimeError, "synthetic target"):
            regen.main()

        self.assertEqual(
            {path: path.read_bytes() for path in regen.OUTPUT_PATHS}, before
        )

    def test_recovery_validation_failure_leaves_outputs_byte_identical(self):
        before = {path: path.read_bytes() for path in regen.OUTPUT_PATHS}

        with patch.object(
            regen,
            "validate_recovery_report",
            side_effect=RuntimeError("synthetic recovery validation failure"),
        ), self.assertRaisesRegex(RuntimeError, "synthetic recovery"):
            regen.main()

        self.assertEqual(
            {path: path.read_bytes() for path in regen.OUTPUT_PATHS}, before
        )


if __name__ == "__main__":
    unittest.main()
