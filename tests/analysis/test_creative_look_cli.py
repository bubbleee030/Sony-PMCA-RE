import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import creative_look_recipes
from tests.analysis.test_creative_looks import synthetic_document


class CreativeLookCliTests(unittest.TestCase):
    def test_render_writes_deterministic_markdown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recipes = root / "recipes.json"
            output = root / "guide.md"
            recipes.write_text(json.dumps(synthetic_document()), encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = creative_look_recipes.main(
                    ["render", "--recipes", str(recipes), "--output", str(output)]
                )

            self.assertEqual(result, 0)
            self.assertTrue(output.read_text(encoding="utf-8").startswith("# α6400"))
            self.assertEqual(
                stdout.getvalue(),
                "represented=10 unrepresented=2 community=0\n",
            )

    def test_only_render_and_exact_options_are_accepted(self):
        for subcommand in ("download", "camera", "flash", "install"):
            with self.subTest(subcommand=subcommand):
                with (
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    creative_look_recipes.main([subcommand])


if __name__ == "__main__":
    unittest.main()
