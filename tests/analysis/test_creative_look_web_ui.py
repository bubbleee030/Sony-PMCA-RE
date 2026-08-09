import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from pmca.analysis.creative_look_stack import (
    AXIS_DEFINITIONS,
    BUILT_IN_LOOK_IDS,
    CUSTOM_LOOK_IDS,
)
from pmca.experience.creative_look import CreativeLookExperience, save_experience
from pmca.experience.creative_look_web import (
    ASSET_DIRECTORY,
    render_creative_look_html,
    write_creative_look_html,
)


ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "creative_look_experience.py"
CHECKED_UI = ROOT / "analysis" / "a6400-creative-look-offline-ui.html"


def _bootstrap(html: str) -> dict:
    match = re.search(
        r'<script id="creative-look-bootstrap" type="application/json">(.*?)</script>',
        html,
        re.DOTALL,
    )
    if match is None:
        raise AssertionError("bootstrap document is missing")
    return json.loads(match.group(1))


class CreativeLookWebUiTests(unittest.TestCase):
    def test_renderer_is_self_contained_and_fail_closed(self):
        html = render_creative_look_html(CreativeLookExperience.new())

        self.assertTrue(html.startswith("<!doctype html>\n"))
        self.assertIn('id="creative-look-app"', html)
        self.assertIn('id="creative-look-bootstrap"', html)
        self.assertIn("default-src 'none'", html)
        self.assertIn("connect-src 'none'", html)
        self.assertIn("frame-ancestors 'none'", html)
        self.assertNotRegex(html, r"<(?:script|img)[^>]+src=")
        self.assertNotRegex(html, r"<link\b")
        self.assertNotRegex(html, r"https?://|XMLHttpRequest|WebSocket|fetch\s*\(")
        self.assertNotIn("camera_command", html)
        self.assertNotIn("firmware_command", html)

        bootstrap = _bootstrap(html)
        self.assertEqual(bootstrap["schema_version"], 1)
        self.assertTrue(bootstrap["offline_only"])
        self.assertEqual(bootstrap["processing_binding"], "UNBOUND_TARGET")
        self.assertEqual(
            bootstrap["safety"],
            {
                "recovery_validated": False,
                "camera_test_eligible": False,
                "installable": False,
            },
        )
        self.assertEqual(
            bootstrap["contract"]["built_in_looks"], list(BUILT_IN_LOOK_IDS)
        )
        self.assertEqual(
            bootstrap["contract"]["custom_slots"], list(CUSTOM_LOOK_IDS)
        )
        self.assertEqual(
            {
                axis_id: (record["minimum"], record["maximum"])
                for axis_id, record in bootstrap["contract"]["axes"].items()
            },
            AXIS_DEFINITIONS,
        )
        self.assertEqual(
            bootstrap["initial_state"], CreativeLookExperience.new().to_document()
        )

    def test_renderer_escapes_script_terminators_in_embedded_state(self):
        experience = CreativeLookExperience.new()
        experience.adjustments["ST"]["contrast"] = 2
        html = render_creative_look_html(experience)
        bootstrap = _bootstrap(html)
        self.assertEqual(bootstrap["initial_state"]["adjustments"]["ST"]["contrast"], 2)
        self.assertEqual(html.count("</script>"), 2)

    def test_output_is_html_only_atomic_and_deterministic(self):
        experience = CreativeLookExperience.new()
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            first = directory / "first.html"
            second = directory / "second.html"
            write_creative_look_html(first, experience)
            write_creative_look_html(second, experience)
            self.assertEqual(first.read_bytes(), second.read_bytes())

            with self.assertRaises(ValueError):
                write_creative_look_html(directory / "state.json", experience)
            link = directory / "linked.html"
            try:
                link.symlink_to(first)
            except OSError:
                self.skipTest("symlink creation is unavailable")
            with self.assertRaises(ValueError):
                write_creative_look_html(link, experience)

    def test_javascript_core_executes_complete_product_flow(self):
        source = ASSET_DIRECTORY / "creative_look_app.js"
        experience = CreativeLookExperience.new()
        with tempfile.TemporaryDirectory() as temporary_directory:
            state_path = Path(temporary_directory) / "state.json"
            state_path.write_text(
                json.dumps(experience.to_document()), encoding="utf-8"
            )
            script = r"""
const fs = require('fs');
const api = require(process.argv[1]);
const state = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const contract = {
  built_in_looks: ['ST','PT','NT','VV','VV2','FL','FL2','FL3','IN','SH','BW','SE'],
  custom_slots: ['Custom1','Custom2','Custom3','Custom4','Custom5','Custom6'],
  orientations: ['landscape','portrait_shutter_up','portrait_shutter_down'],
  modes: ['intelligent_auto','picture_profile_not_off','flexible_iso_log','movie_mode'],
  axes: {
    contrast:{minimum:-9,maximum:9}, highlights:{minimum:-9,maximum:9},
    shadows:{minimum:-9,maximum:9}, fade:{minimum:0,maximum:9},
    saturation:{minimum:-9,maximum:9}, sharpness:{minimum:0,maximum:9},
    sharpness_range:{minimum:1,maximum:5}, clarity:{minimum:0,maximum:9}
  }
};
const core = api.createCore(contract);
let next = core.validateState(state);
next = core.transition(next, {type:'SET_ORIENTATION', orientation:'portrait_shutter_down'});
next = core.transition(next, {type:'SELECT_LOOK', look:'Custom1'});
if (next.screen !== 'custom_base') throw new Error('Custom base screen missing');
next = core.transition(next, {type:'SELECT_CUSTOM_BASE', base:'VV'});
next = core.transition(next, {type:'OPEN_AXIS', axis:'contrast'});
next = core.transition(next, {type:'SET_AXIS', axis:'contrast', value:3});
if (next.adjustments.Custom1.contrast !== 3 || next.screen !== 'editor') throw new Error('axis flow failed');
next = core.transition(next, {type:'BACK_TO_CATALOG'});
next = core.transition(next, {type:'SELECT_LOOK', look:'BW'});
let rejected = false;
try { core.transition(next, {type:'OPEN_AXIS', axis:'saturation'}); } catch (error) { rejected = /BW_SE/.test(error.message); }
if (!rejected) throw new Error('BW saturation was not rejected');
next = core.transition(next, {type:'BACK_TO_CATALOG'});
next = core.transition(next, {type:'SET_MODE', mode:'movie_mode', value:true});
next = core.transition(next, {type:'SELECT_LOOK', look:'ST'});
rejected = false;
try { core.transition(next, {type:'OPEN_AXIS', axis:'sharpness_range'}); } catch (error) { rejected = /MOVIE/.test(error.message); }
if (!rejected) throw new Error('movie sharpness range was not rejected');
next = core.transition(next, {type:'SET_MODE', mode:'intelligent_auto', value:true});
if (next.screen !== 'catalog') throw new Error('global restriction did not return to catalog');
next = core.transition(next, {type:'SET_MODE', mode:'intelligent_auto', value:false});
next = core.transition(next, {type:'SELECT_LOOK', look:'Custom1'});
next = core.transition(next, {type:'RESET_SELECTED'});
if (next.adjustments.Custom1.contrast !== null) throw new Error('reset failed');
if (next.processing_binding !== 'UNBOUND_TARGET' || next.safety.installable !== false) throw new Error('safety mutated');
const serialized = core.serialize(next);
if (core.validateState(JSON.parse(serialized)).orientation !== 'portrait_shutter_down') throw new Error('persistence failed');
console.log('CREATIVE_LOOK_WEB_CORE_OK');
"""
            result = subprocess.run(
                ["node", "-e", script, str(source), str(state_path)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("CREATIVE_LOOK_WEB_CORE_OK", result.stdout)

    def test_cli_web_output_matches_checked_artifact(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            state = directory / "state.json"
            output = directory / "prototype.html"
            save_experience(state, CreativeLookExperience.new())
            result = subprocess.run(
                [
                    sys.executable,
                    str(CLI),
                    "web",
                    "--state",
                    str(state),
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("offline_only=true", result.stdout)
            self.assertEqual(output.read_bytes(), CHECKED_UI.read_bytes())


if __name__ == "__main__":
    unittest.main()
