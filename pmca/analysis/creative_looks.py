"""Conservative, fallback-only Creative Style recipes for ILCE-6400."""

from copy import deepcopy
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit

from .creative_look_stack import BUILT_IN_LOOK_IDS, REFERENCE_SOURCE


LOOK_CODES = ("ST", "PT", "NT", "VV", "VV2", "FL", "IN", "SH", "BW", "SE")
UNREPRESENTED_LOOK_CODES = ("FL2", "FL3")
CREATIVE_STYLE_SOURCE = (
    "https://helpguide.sony.net/ilc/1810/v1/en/contents/TP0002264693.html"
)
DIRECT_STYLE_MAP = {
    "ST": "Standard",
    "PT": "Portrait",
    "NT": "Neutral",
    "VV": "Vivid",
    "BW": "B/W",
    "SE": "Sepia",
}
INFERRED_STYLE_MAP = {
    "VV2": "Clear",
    "FL": "Deep",
    "IN": "Neutral",
    "SH": "Light",
}
UNREPRESENTED_AXES = (
    "highlights",
    "shadows",
    "fade",
    "sharpness_range",
    "clarity",
)
VALIDATION_PROTOCOL = (
    "same lens",
    "same scene",
    "same exposure",
    "same lighting",
    "same white balance",
    "same JPEG settings",
    "no postprocessing",
)
_TOP_FIELDS = {
    "schema_version",
    "artifact_role",
    "native_claim_basis",
    "reference_source",
    "creative_style_source",
    "represented_reference_looks",
    "unrepresented_reference_looks",
    "defaults",
    "community_experiments",
    "disclaimer",
    "validation_protocol",
}
_DEFAULT_FIELDS = {"source_kind", "modern", "a6400", "note"}
_COMMUNITY_FIELDS = {"title", "source_kind", "modern", "a6400", "note"}
_MODERN_FIELDS = {
    "code",
    "base",
    "contrast",
    "highlights",
    "shadows",
    "fade",
    "saturation",
    "sharpness",
    "sharpness_range",
    "clarity",
    "wb_kelvin",
    "wb_shift_ab",
    "wb_shift_gm",
    "source",
}
_RECIPE_FIELDS = {
    "code",
    "creative_style",
    "contrast",
    "saturation",
    "sharpness",
    "wb_kelvin",
    "wb_shift_ab",
    "wb_shift_gm",
    "confidence",
    "unrepresented_axes",
}
_VALID_STYLES = set(DIRECT_STYLE_MAP.values()) | set(INFERRED_STYLE_MAP.values())
_AXIS_RANGES = {
    "contrast": (-9, 9),
    "highlights": (-9, 9),
    "shadows": (-9, 9),
    "fade": (0, 9),
    "saturation": (-9, 9),
    "sharpness": (0, 9),
    "sharpness_range": (1, 5),
    "clarity": (0, 9),
}


class CreativeLookError(ValueError):
    """Raised when fallback metadata violates the fixed contract."""


@dataclass(frozen=True, slots=True)
class ModernLook:
    code: str
    base: str
    contrast: int | None
    highlights: int | None
    shadows: int | None
    fade: int | None
    saturation: int | None
    sharpness: int | None
    sharpness_range: int | None
    clarity: int | None
    wb_kelvin: int | None
    wb_shift_ab: int
    wb_shift_gm: int
    source: str


@dataclass(frozen=True, slots=True)
class A6400Recipe:
    code: str
    creative_style: str
    contrast: int
    saturation: int
    sharpness: int
    wb_kelvin: int | None
    wb_shift_ab: int
    wb_shift_gm: int
    confidence: str
    unrepresented_axes: tuple[str, ...]


def _bounded_text(value: object, name: str, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or "\r" in value
        or "\n" in value
        or not value.isprintable()
    ):
        raise CreativeLookError(f"{name} must be bounded single-line text")
    return value


def _https_url(value: object, name: str) -> str:
    value = _bounded_text(value, name, maximum=1024)
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.port is not None
    ):
        raise CreativeLookError(f"{name} must be an HTTPS URL")
    return value


def _integer(value: object, minimum: int, maximum: int, name: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise CreativeLookError(f"{name} is outside the supported range")
    return value


def _optional_integer(
    value: object, minimum: int, maximum: int, name: str
) -> int | None:
    if value is None:
        return None
    return _integer(value, minimum, maximum, name)


def _validate_wb(kelvin: object, ab: object, gm: object) -> None:
    if kelvin is not None:
        _integer(kelvin, 2500, 9900, "White-balance Kelvin")
    _integer(ab, -9, 9, "White-balance A/B shift")
    _integer(gm, -9, 9, "White-balance G/M shift")


def _modern(value: object) -> ModernLook:
    if isinstance(value, ModernLook):
        look = value
    elif isinstance(value, dict) and set(value) == _MODERN_FIELDS:
        look = ModernLook(**value)
    else:
        raise CreativeLookError("Reference adjustment fields do not match schema version 2")
    if look.code not in LOOK_CODES or look.base not in BUILT_IN_LOOK_IDS:
        raise CreativeLookError("Reference look code or base is unknown")
    for field, (minimum, maximum) in _AXIS_RANGES.items():
        _optional_integer(
            getattr(look, field), minimum, maximum, f"Reference Look {field}"
        )
    _validate_wb(look.wb_kelvin, look.wb_shift_ab, look.wb_shift_gm)
    _https_url(look.source, "Reference Look source")
    return look


def _recipe(value: object) -> A6400Recipe:
    if isinstance(value, A6400Recipe):
        recipe = value
    elif isinstance(value, dict) and set(value) == _RECIPE_FIELDS:
        axes = value["unrepresented_axes"]
        if not isinstance(axes, list):
            raise CreativeLookError("Serialized unrepresented axes must be a list")
        recipe = A6400Recipe(
            **{key: item for key, item in value.items() if key != "unrepresented_axes"},
            unrepresented_axes=tuple(axes),
        )
    else:
        raise CreativeLookError("α6400 recipe fields do not match schema version 2")
    if recipe.code not in LOOK_CODES or recipe.creative_style not in _VALID_STYLES:
        raise CreativeLookError("α6400 recipe code or Creative Style is unknown")
    expected_style = DIRECT_STYLE_MAP.get(
        recipe.code, INFERRED_STYLE_MAP.get(recipe.code)
    )
    if recipe.creative_style != expected_style:
        raise CreativeLookError("α6400 recipe Creative Style does not match its code")
    for field in ("contrast", "saturation", "sharpness"):
        _integer(getattr(recipe, field), -3, 3, f"α6400 {field}")
    _validate_wb(recipe.wb_kelvin, recipe.wb_shift_ab, recipe.wb_shift_gm)
    expected_confidence = "PARTIAL" if recipe.code in DIRECT_STYLE_MAP else "INFERRED"
    if recipe.confidence != expected_confidence:
        raise CreativeLookError("α6400 recipe confidence overstates the mapping")
    if (
        len(set(recipe.unrepresented_axes)) != len(recipe.unrepresented_axes)
        or any(axis not in UNREPRESENTED_AXES for axis in recipe.unrepresented_axes)
    ):
        raise CreativeLookError("Unrepresented axes are invalid")
    return recipe


def translate_to_a6400(look: ModernLook) -> A6400Recipe:
    """Translate a concrete reference experiment into bounded α6400 controls."""

    look = _modern(look)
    if any(getattr(look, field) is None for field in ("contrast", "saturation", "sharpness")):
        raise CreativeLookError("Translation requires concrete representable axes")
    style = DIRECT_STYLE_MAP.get(look.code, INFERRED_STYLE_MAP.get(look.code))
    if style is None:
        raise CreativeLookError("No α6400 base mapping exists")
    missing = tuple(
        axis
        for axis in UNREPRESENTED_AXES
        if getattr(look, axis) not in (None, 0)
    )
    return A6400Recipe(
        code=look.code,
        creative_style=style,
        contrast=max(-3, min(3, look.contrast)),
        saturation=max(-3, min(3, look.saturation)),
        sharpness=max(-3, min(3, look.sharpness)),
        wb_kelvin=look.wb_kelvin,
        wb_shift_ab=look.wb_shift_ab,
        wb_shift_gm=look.wb_shift_gm,
        confidence="PARTIAL" if look.code in DIRECT_STYLE_MAP else "INFERRED",
        unrepresented_axes=missing,
    )


def _serialized_recipe(recipe: A6400Recipe) -> dict:
    value = asdict(recipe)
    value["unrepresented_axes"] = list(recipe.unrepresented_axes)
    return value


def _validate_entry(value: object, community: bool) -> tuple[ModernLook, A6400Recipe]:
    fields = _COMMUNITY_FIELDS if community else _DEFAULT_FIELDS
    if not isinstance(value, dict) or set(value) != fields:
        raise CreativeLookError("Recipe entry fields do not match schema version 2")
    expected_kind = (
        "community-experiment"
        if community
        else "creative-style-fallback-approximation"
    )
    if value["source_kind"] != expected_kind:
        raise CreativeLookError("Recipe source kind is incorrect")
    if community:
        _bounded_text(value["title"], "Community recipe title", maximum=128)
    _bounded_text(value["note"], "Recipe note")
    modern = _modern(value["modern"])
    recipe = _recipe(value["a6400"])
    if modern.code != recipe.code:
        raise CreativeLookError("Reference and α6400 recipe codes differ")
    if community or all(
        getattr(modern, field) is not None
        for field in ("contrast", "saturation", "sharpness")
    ):
        expected = translate_to_a6400(modern)
        if recipe != expected:
            raise CreativeLookError("α6400 translation does not match the source settings")
    return modern, recipe


def validate_recipe_document(document: object) -> dict:
    """Validate and normalize the separate Creative Style fallback catalog."""

    if not isinstance(document, dict) or set(document) != _TOP_FIELDS:
        raise CreativeLookError("Recipe document fields do not match schema version 2")
    if document["schema_version"] != 2 or type(document["schema_version"]) is not int:
        raise CreativeLookError("Unsupported recipe schema version")
    if document["artifact_role"] != "CREATIVE_STYLE_FALLBACK":
        raise CreativeLookError("Recipe artifact role is invalid")
    if document["native_claim_basis"] is not False:
        raise CreativeLookError("Fallback recipes cannot establish a native claim")
    if document["reference_source"] != REFERENCE_SOURCE:
        raise CreativeLookError("Creative Look reference source is invalid")
    if document["creative_style_source"] != CREATIVE_STYLE_SOURCE:
        raise CreativeLookError("Creative Style source is invalid")
    represented = document["represented_reference_looks"]
    unrepresented = document["unrepresented_reference_looks"]
    if represented != list(LOOK_CODES) or unrepresented != list(
        UNREPRESENTED_LOOK_CODES
    ):
        raise CreativeLookError("Fallback coverage membership or order is invalid")
    if set(represented) & set(unrepresented) or set(represented + unrepresented) != set(
        BUILT_IN_LOOK_IDS
    ):
        raise CreativeLookError("Fallback coverage overlaps or omits reference looks")

    defaults = document["defaults"]
    if not isinstance(defaults, list) or len(defaults) != len(LOOK_CODES):
        raise CreativeLookError("Recipe defaults must contain ten represented looks")
    by_code = {}
    for value in defaults:
        modern, _ = _validate_entry(value, community=False)
        if modern.code in by_code:
            raise CreativeLookError("Default look codes must be unique")
        by_code[modern.code] = deepcopy(value)
    if set(by_code) != set(LOOK_CODES):
        raise CreativeLookError("Default look code set is not exact")

    community = document["community_experiments"]
    if not isinstance(community, list) or len(community) > 50:
        raise CreativeLookError("Community recipe list is invalid")
    for value in community:
        _validate_entry(value, community=True)
    _bounded_text(document["disclaimer"], "Recipe disclaimer", maximum=1024)
    if document["validation_protocol"] != list(VALIDATION_PROTOCOL):
        raise CreativeLookError("Recipe validation protocol is not fixed")
    normalized = deepcopy(document)
    normalized["defaults"] = [by_code[code] for code in LOOK_CODES]
    return normalized


def _wb_text(recipe: A6400Recipe) -> str:
    base = "Auto" if recipe.wb_kelvin is None else f"{recipe.wb_kelvin} K"
    return f"{base}; A/B {recipe.wb_shift_ab:+d}, G/M {recipe.wb_shift_gm:+d}"


def render_recipe_guide(document: dict) -> str:
    """Render deterministic fallback-only instructions for represented mappings."""

    document = validate_recipe_document(document)
    lines = [
        "# α6400 Creative Look Translation Guide",
        "",
        "## Fallback-only status",
        "",
        "The authoritative α7 V-like contract contains 12 built-in looks, six Custom slots, and an eight-axis adjustment model. This separate Creative Style artifact represents only ten looks as APPROXIMATION_ONLY / LAST_RESORT_ONLY; it does not reproduce the Creative Look interface, and FL2 and FL3 have no fallback representation.",
        "",
        "These settings are practical starting points, not exact Sony colorimetric matches; no Sony-exact colorimetry or authenticated base-look tables are established. Six mappings use existing α6400 Creative Styles; VV2, FL, IN, and SH use four Style Boxes. Nothing in this guide establishes native Creative Look support, runtime processing, installability, recovery, or camera-test eligibility.",
        "",
        "## On-camera setup",
        "",
        "Open MENU → Camera Settings1 → Creative Style. Select the named style directly for ST, PT, NT, VV, BW, and SE. For VV2, FL, IN, and SH, assign the listed style and values to Style Box 1, 2, 3, and 4 respectively.",
        "",
        "| Look | α6400 Creative Style | Contrast | Saturation | Sharpness | White balance | Confidence | Unavailable nonzero reference axes |",
        "|---|---|---:|---:|---:|---|---|---|",
    ]
    for value in document["defaults"]:
        recipe = _recipe(value["a6400"])
        missing = ", ".join(recipe.unrepresented_axes) or "none in this starting preset"
        lines.append(
            f"| {recipe.code} | {recipe.creative_style} | {recipe.contrast:+d} | "
            f"{recipe.saturation:+d} | {recipe.sharpness:+d} | {_wb_text(recipe)} | "
            f"{recipe.confidence} | {missing} |"
        )
    lines.extend(
        [
            "",
            "PARTIAL means the target has a semantically corresponding base style but has not been colorimetrically measured. INFERRED means the style and values are conservative approximations for later JPEG comparison.",
            "",
            "## Sources",
            "",
            f"- α7 V Creative Look reference: {document['reference_source']}",
            f"- α6400 Creative Style reference: {document['creative_style_source']}",
        ]
    )
    if document["community_experiments"]:
        lines.extend(
            [
                "",
                "## Optional community experiments",
                "",
                "These entries are community experiments, not Sony defaults. Their unavailable axes are listed rather than silently discarded.",
                "",
                "| Title | Base | α6400 style | C/S/Sh | WB | Unavailable nonzero axes | Source |",
                "|---|---|---|---|---|---|---|",
            ]
        )
        for value in document["community_experiments"]:
            modern = _modern(value["modern"])
            recipe = _recipe(value["a6400"])
            missing = ", ".join(recipe.unrepresented_axes) or "none"
            lines.append(
                f"| {value['title']} | {modern.base} | {recipe.creative_style} | "
                f"{recipe.contrast:+d}/{recipe.saturation:+d}/{recipe.sharpness:+d} | "
                f"{_wb_text(recipe)} | {missing} | {modern.source} |"
            )
    lines.extend(
        [
            "",
            "## Future controlled validation",
            "",
            "Compare α6400 and a supported Creative Look camera using all fixed conditions:",
            "",
        ]
    )
    lines.extend(f"- {condition}" for condition in document["validation_protocol"])
    lines.extend(
        [
            "",
            "Judge JPEG pairs under controlled viewing before changing one setting at a time. Do not promote any recipe to an exact match without measurement.",
            "",
        ]
    )
    return "\n".join(lines)
