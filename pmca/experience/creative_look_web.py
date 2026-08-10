"""Render the α6400-native Creative Look model as one offline HTML file."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from pmca.analysis.creative_look_stack import (
    AXIS_DEFINITIONS,
    AXIS_IDS,
    BUILT_IN_LOOK_IDS,
    CUSTOM_LOOK_IDS,
)
from pmca.experience.creative_look import (
    MODE_FIELDS,
    CreativeLookExperience,
    CreativeLookExperienceError,
    Orientation,
)


ASSET_DIRECTORY = Path(__file__).with_name("web")

LOOK_LABELS = {
    "ST": "Standard",
    "PT": "Portrait",
    "NT": "Neutral",
    "VV": "Vivid",
    "VV2": "Vivid 2",
    "FL": "Film",
    "FL2": "Film 2",
    "FL3": "Film 3",
    "IN": "Instant",
    "SH": "Soft High-key",
    "BW": "Black & White",
    "SE": "Sepia",
}

AXIS_LABELS = {
    "contrast": "Contrast",
    "highlights": "Highlights",
    "shadows": "Shadows",
    "fade": "Fade",
    "saturation": "Saturation",
    "sharpness": "Sharpness",
    "sharpness_range": "Sharpness Range",
    "clarity": "Clarity",
}

MODE_LABELS = {
    "intelligent_auto": "Intelligent Auto",
    "picture_profile_not_off": "Picture Profile active",
    "flexible_iso_log": "Flexible ISO Log",
    "movie_mode": "Movie mode",
}

# Navigation-only swatches. They intentionally do not represent Sony processing.
LOOK_SWATCHES = {
    "ST": ("#657382", "#384651"),
    "PT": ("#d09a87", "#704a52"),
    "NT": ("#8a908a", "#4a504d"),
    "VV": ("#ef7138", "#954eaa"),
    "VV2": ("#de3c5c", "#2c78c5"),
    "FL": ("#8da57d", "#495c50"),
    "FL2": ("#d5a55d", "#654c52"),
    "FL3": ("#4d7f91", "#ba705c"),
    "IN": ("#d3b07f", "#736451"),
    "SH": ("#d9d7c9", "#969b9d"),
    "BW": ("#d5d5d5", "#343434"),
    "SE": ("#c59b63", "#5d4029"),
}

CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'none'",
        "script-src 'unsafe-inline'",
        "style-src 'unsafe-inline'",
        "img-src data: blob:",
        "connect-src 'none'",
        "font-src 'none'",
        "media-src 'none'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
    )
)


def _contract() -> dict:
    return {
        "built_in_looks": list(BUILT_IN_LOOK_IDS),
        "custom_slots": list(CUSTOM_LOOK_IDS),
        "orientations": [orientation.value for orientation in Orientation],
        "modes": list(MODE_FIELDS),
        "look_labels": dict(LOOK_LABELS),
        "axis_labels": dict(AXIS_LABELS),
        "mode_labels": dict(MODE_LABELS),
        "axes": {
            axis_id: {
                "minimum": AXIS_DEFINITIONS[axis_id][0],
                "maximum": AXIS_DEFINITIONS[axis_id][1],
                "label": AXIS_LABELS[axis_id],
            }
            for axis_id in AXIS_IDS
        },
        "look_swatches": {
            look_id: {"start": colors[0], "end": colors[1]}
            for look_id, colors in LOOK_SWATCHES.items()
        },
        "storage_key": "a6400.creative-look.offline.v1",
    }


def _script_safe_json(document: dict) -> str:
    return (
        json.dumps(document, ensure_ascii=False, separators=(",", ":"))
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def render_creative_look_html(experience: CreativeLookExperience) -> str:
    """Return a deterministic, network-isolated HTML prototype."""

    # Round-trip validation prevents callers from injecting an invalid state object.
    initial_state = CreativeLookExperience.from_document(
        experience.to_document()
    ).to_document()
    bootstrap = {
        "schema_version": 1,
        "offline_only": True,
        "target": "ILCE-6400",
        "reference": "ILCE-7M5",
        "processing_binding": "UNBOUND_TARGET",
        "safety": {
            "recovery_validated": False,
            "camera_test_eligible": False,
            "installable": False,
        },
        "contract": _contract(),
        "initial_state": initial_state,
    }
    css = (ASSET_DIRECTORY / "creative_look_app.css").read_text(encoding="utf-8")
    javascript = (ASSET_DIRECTORY / "creative_look_app.js").read_text(
        encoding="utf-8"
    )
    return (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '  <meta charset="utf-8">\n'
        '  <meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">\n'
        f'  <meta http-equiv="Content-Security-Policy" content="{CONTENT_SECURITY_POLICY}">\n'
        '  <meta name="creative-look-offline-only" content="true">\n'
        "  <title>α6400 Creative Look — Offline Prototype</title>\n"
        f"  <style>\n{css}\n  </style>\n"
        "</head>\n"
        '<body data-orientation="landscape">\n'
        '  <main id="creative-look-app" aria-live="polite">\n'
        '    <p class="boot-message">Loading offline Creative Look prototype…</p>\n'
        "  </main>\n"
        '  <script id="creative-look-bootstrap" type="application/json">'
        f"{_script_safe_json(bootstrap)}</script>\n"
        f"  <script>\n{javascript}\n  </script>\n"
        "</body>\n"
        "</html>\n"
    )


def write_creative_look_html(
    path: Path, experience: CreativeLookExperience
) -> None:
    """Atomically write one non-symlink HTML prototype."""

    path = Path(path)
    if path.suffix.casefold() != ".html" or path.is_symlink():
        raise CreativeLookExperienceError(
            "prototype output must be a non-symlink HTML file"
        )
    if path.exists() and not path.is_file():
        raise CreativeLookExperienceError("prototype output is not a regular file")
    path.parent.mkdir(parents=True, exist_ok=True)
    content = render_creative_look_html(experience)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
