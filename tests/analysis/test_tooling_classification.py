import unittest

from pmca.analysis.tooling import _classify


class ToolingClassificationTests(unittest.TestCase):
    def test_unknown_exe_is_a_wrapper_parsing_failure(self):
        self.assertEqual(
            _classify(1, "Exception: Unknown exe file"),
            (
                "wrapper-parsing",
                "unknown-installer",
                "tool rejected the updater wrapper format",
            ),
        )


if __name__ == "__main__":
    unittest.main()
