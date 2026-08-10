"""Deterministic offline α6400-native Creative Look experience model.

This module models the requested interaction and persistence contract only. It has
no camera transport, firmware packaging, Sony-binary execution, or processing
binding capability.
"""

from __future__ import annotations

import json
import math
import os
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from pmca.analysis.creative_look_stack import (
    AXIS_DEFINITIONS,
    AXIS_IDS,
    BUILT_IN_LOOK_IDS,
    CUSTOM_LOOK_IDS,
)


LOOK_IDS = (*BUILT_IN_LOOK_IDS, *CUSTOM_LOOK_IDS)
MODE_FIELDS = (
    "intelligent_auto",
    "picture_profile_not_off",
    "flexible_iso_log",
    "movie_mode",
)
MAX_STATE_BYTES = 256 * 1024


class CreativeLookExperienceError(ValueError):
    """Raised for malformed state or an unavailable offline interaction."""


class Orientation(str, Enum):
    LANDSCAPE = "landscape"
    PORTRAIT_SHUTTER_UP = "portrait_shutter_up"
    PORTRAIT_SHUTTER_DOWN = "portrait_shutter_down"


class Screen(str, Enum):
    CATALOG = "catalog"
    CUSTOM_BASE = "custom_base"
    EDITOR = "editor"
    AXIS_PICKER = "axis_picker"


@dataclass(frozen=True)
class Rect:
    x: float
    y: float
    width: float
    height: float

    @property
    def center(self) -> tuple[float, float]:
        return self.x + self.width / 2, self.y + self.height / 2

    def contains(self, x: float, y: float) -> bool:
        return (
            self.x <= x <= self.x + self.width
            and self.y <= y <= self.y + self.height
        )

    def inside(self, width: float, height: float) -> bool:
        return (
            self.x >= 0
            and self.y >= 0
            and self.width > 0
            and self.height > 0
            and self.x + self.width <= width
            and self.y + self.height <= height
        )

    def overlaps(self, other: "Rect") -> bool:
        return (
            min(self.x + self.width, other.x + other.width) > max(self.x, other.x)
            and min(self.y + self.height, other.y + other.height)
            > max(self.y, other.y)
        )


@dataclass(frozen=True)
class UiElement:
    identifier: str
    kind: str
    rect: Rect
    enabled: bool = True
    reason: str | None = None
    value: int | str | None = None
    modified: bool = False


@dataclass(frozen=True)
class ExperienceFrame:
    orientation: Orientation
    screen: Screen
    width: int
    height: int
    columns: int
    elements: tuple[UiElement, ...]

    def element(self, identifier: str) -> UiElement:
        for element in self.elements:
            if element.identifier == identifier:
                return element
        raise CreativeLookExperienceError(f"unknown UI element: {identifier}")

    def to_document(self) -> dict:
        return {
            "orientation": self.orientation.value,
            "screen": self.screen.value,
            "coordinate_space": "offline_prototype_logical_units",
            "viewport": {"width": self.width, "height": self.height},
            "columns": self.columns,
            "elements": [
                {
                    "id": element.identifier,
                    "kind": element.kind,
                    "rect": {
                        "x": element.rect.x,
                        "y": element.rect.y,
                        "width": element.rect.width,
                        "height": element.rect.height,
                    },
                    "enabled": element.enabled,
                    "reason": element.reason,
                    "value": element.value,
                    "modified": element.modified,
                }
                for element in self.elements
            ],
        }


class CreativeLookExperience:
    """In-memory first-class UI/state prototype with fail-closed bindings."""

    processing_binding = "UNBOUND_TARGET"
    camera_test_eligible = False
    installable = False
    recovery_validated = False

    def __init__(
        self,
        *,
        selected_look: str,
        screen: Screen,
        orientation: Orientation,
        editing_axis: str | None,
        custom_bases: dict[str, str | None],
        adjustments: dict[str, dict[str, int | None]],
        modes: dict[str, bool],
    ):
        self.selected_look = selected_look
        self.screen = screen
        self.orientation = orientation
        self.editing_axis = editing_axis
        self.custom_bases = custom_bases
        self.adjustments = adjustments
        self.modes = modes

    @classmethod
    def new(cls) -> "CreativeLookExperience":
        return cls(
            selected_look="ST",
            screen=Screen.CATALOG,
            orientation=Orientation.LANDSCAPE,
            editing_axis=None,
            custom_bases={slot: None for slot in CUSTOM_LOOK_IDS},
            adjustments={
                look_id: {axis_id: None for axis_id in AXIS_IDS}
                for look_id in LOOK_IDS
            },
            modes={field: False for field in MODE_FIELDS},
        )

    def set_orientation(self, orientation: Orientation | str) -> None:
        try:
            self.orientation = Orientation(orientation)
        except (TypeError, ValueError) as error:
            raise CreativeLookExperienceError("orientation is invalid") from error

    def set_mode(self, **changes: bool) -> None:
        if not changes or not set(changes).issubset(MODE_FIELDS):
            raise CreativeLookExperienceError("mode fields are invalid")
        if any(type(value) is not bool for value in changes.values()):
            raise CreativeLookExperienceError("mode values must be boolean")
        self.modes.update(changes)
        if self._mode_unavailable():
            self.back_to_catalog()
            return
        if self.screen is Screen.AXIS_PICKER and not self._axis_enabled(
            self.editing_axis
        )[0]:
            self.screen = Screen.EDITOR
            self.editing_axis = None

    def select_look(self, look_id: str) -> None:
        self._require_mode_available()
        if look_id not in LOOK_IDS:
            raise CreativeLookExperienceError("look identifier is invalid")
        self.selected_look = look_id
        self.editing_axis = None
        if look_id in CUSTOM_LOOK_IDS and self.custom_bases[look_id] is None:
            self.screen = Screen.CUSTOM_BASE
        else:
            self.screen = Screen.EDITOR

    def select_custom_base(self, slot_id: str, base_look: str) -> None:
        self._require_mode_available()
        if slot_id not in CUSTOM_LOOK_IDS or base_look not in BUILT_IN_LOOK_IDS:
            raise CreativeLookExperienceError("Custom base selection is invalid")
        self.custom_bases[slot_id] = base_look
        if self.selected_look == slot_id:
            self.screen = Screen.EDITOR
            self.editing_axis = None

    def open_axis(self, axis_id: str) -> None:
        self._require_mode_available()
        enabled, reason = self._axis_enabled(axis_id)
        if not enabled:
            raise CreativeLookExperienceError(reason or "axis is unavailable")
        self.screen = Screen.AXIS_PICKER
        self.editing_axis = axis_id

    def set_axis(self, axis_id: str, value: int | None) -> None:
        self._require_mode_available()
        enabled, reason = self._axis_enabled(axis_id)
        if not enabled:
            raise CreativeLookExperienceError(reason or "axis is unavailable")
        if value is not None:
            if type(value) is not int:
                raise CreativeLookExperienceError("axis value must be an integer")
            minimum, maximum = AXIS_DEFINITIONS[axis_id]
            if not minimum <= value <= maximum:
                raise CreativeLookExperienceError("axis value is out of range")
        self.adjustments[self.selected_look][axis_id] = value
        self.screen = Screen.EDITOR
        self.editing_axis = None

    def reset_selected_look(self) -> None:
        self._require_mode_available()
        self.adjustments[self.selected_look] = {
            axis_id: None for axis_id in AXIS_IDS
        }

    def is_modified(self, look_id: str) -> bool:
        if look_id not in LOOK_IDS:
            raise CreativeLookExperienceError("look identifier is invalid")
        return any(value is not None for value in self.adjustments[look_id].values())

    def back_to_catalog(self) -> None:
        self.screen = Screen.CATALOG
        self.editing_axis = None

    def frame(self) -> ExperienceFrame:
        width, height = self._viewport()
        if self.screen is Screen.CATALOG:
            columns = 6 if self.orientation is Orientation.LANDSCAPE else 3
            unavailable = self._mode_unavailable()
            items = [
                UiElement(
                    identifier=f"look:{look_id}",
                    kind="look",
                    rect=Rect(0, 0, 1, 1),
                    enabled=not unavailable,
                    reason="CREATIVE_LOOK_MODE_UNAVAILABLE" if unavailable else None,
                    value=(
                        self.custom_bases[look_id]
                        if look_id in CUSTOM_LOOK_IDS
                        else look_id
                    ),
                    modified=self.is_modified(look_id),
                )
                for look_id in LOOK_IDS
            ]
        elif self.screen is Screen.CUSTOM_BASE:
            columns = 4 if self.orientation is Orientation.LANDSCAPE else 3
            items = [
                UiElement(
                    identifier=f"base:{look_id}",
                    kind="custom_base",
                    rect=Rect(0, 0, 1, 1),
                    value=look_id,
                )
                for look_id in BUILT_IN_LOOK_IDS
            ]
        elif self.screen is Screen.EDITOR:
            columns = 2 if self.orientation is Orientation.LANDSCAPE else 1
            items = []
            for axis_id in AXIS_IDS:
                enabled, reason = self._axis_enabled(axis_id)
                items.append(
                    UiElement(
                        identifier=f"axis:{axis_id}",
                        kind="axis",
                        rect=Rect(0, 0, 1, 1),
                        enabled=enabled,
                        reason=reason,
                        value=self.adjustments[self.selected_look][axis_id],
                        modified=(
                            self.adjustments[self.selected_look][axis_id] is not None
                        ),
                    )
                )
            items.extend(
                [
                    UiElement("action:reset", "action", Rect(0, 0, 1, 1)),
                    UiElement("action:catalog", "action", Rect(0, 0, 1, 1)),
                ]
            )
        elif self.screen is Screen.AXIS_PICKER:
            axis_id = self.editing_axis
            enabled, reason = self._axis_enabled(axis_id)
            if not enabled:
                raise CreativeLookExperienceError(reason or "axis is unavailable")
            columns = 7 if self.orientation is Orientation.LANDSCAPE else 5
            minimum, maximum = AXIS_DEFINITIONS[axis_id]
            values: tuple[int | None, ...] = (None, *range(minimum, maximum + 1))
            items = [
                UiElement(
                    identifier=(
                        f"axis-value:{axis_id}:default"
                        if value is None
                        else f"axis-value:{axis_id}:{value}"
                    ),
                    kind="axis_value",
                    rect=Rect(0, 0, 1, 1),
                    value="default" if value is None else value,
                    modified=value is not None,
                )
                for value in values
            ]
        else:  # pragma: no cover - Enum construction and state validation prevent this
            raise CreativeLookExperienceError("screen is invalid")
        elements = self._layout(items, columns, width, height)
        return ExperienceFrame(
            orientation=self.orientation,
            screen=self.screen,
            width=width,
            height=height,
            columns=columns,
            elements=elements,
        )

    def touch(self, x: float, y: float) -> bool:
        if not all(type(value) in (int, float) for value in (x, y)):
            raise CreativeLookExperienceError("touch coordinates must be numeric")
        frame = self.frame()
        for element in frame.elements:
            if not element.rect.contains(float(x), float(y)):
                continue
            if not element.enabled:
                return False
            if element.identifier.startswith("look:"):
                self.select_look(element.identifier.removeprefix("look:"))
            elif element.identifier.startswith("base:"):
                self.select_custom_base(
                    self.selected_look, element.identifier.removeprefix("base:")
                )
            elif element.identifier.startswith("axis:"):
                self.open_axis(element.identifier.removeprefix("axis:"))
            elif element.identifier.startswith("axis-value:"):
                _, axis_id, encoded = element.identifier.split(":", 2)
                self.set_axis(axis_id, None if encoded == "default" else int(encoded))
            elif element.identifier == "action:reset":
                self.reset_selected_look()
            elif element.identifier == "action:catalog":
                self.back_to_catalog()
            else:  # pragma: no cover - frame generation owns all identifiers
                raise CreativeLookExperienceError("touch action is unsupported")
            return True
        return False

    def to_document(self) -> dict:
        return {
            "schema_version": 1,
            "offline_only": True,
            "target": "ILCE-6400",
            "reference": "ILCE-7M5",
            "processing_binding": self.processing_binding,
            "selected_look": self.selected_look,
            "screen": self.screen.value,
            "orientation": self.orientation.value,
            "editing_axis": self.editing_axis,
            "custom_bases": dict(self.custom_bases),
            "adjustments": {
                look_id: dict(values) for look_id, values in self.adjustments.items()
            },
            "modes": dict(self.modes),
            "safety": {
                "recovery_validated": self.recovery_validated,
                "camera_test_eligible": self.camera_test_eligible,
                "installable": self.installable,
            },
        }

    @classmethod
    def from_document(cls, document: object) -> "CreativeLookExperience":
        fields = {
            "schema_version",
            "offline_only",
            "target",
            "reference",
            "processing_binding",
            "selected_look",
            "screen",
            "orientation",
            "editing_axis",
            "custom_bases",
            "adjustments",
            "modes",
            "safety",
        }
        if not isinstance(document, dict) or set(document) != fields:
            raise CreativeLookExperienceError("experience state fields are not exact")
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != 1
            or document["offline_only"] is not True
            or document["target"] != "ILCE-6400"
            or document["reference"] != "ILCE-7M5"
            or document["processing_binding"] != "UNBOUND_TARGET"
        ):
            raise CreativeLookExperienceError("experience identity or binding is invalid")
        if document["selected_look"] not in LOOK_IDS:
            raise CreativeLookExperienceError("selected look is invalid")
        try:
            screen = Screen(document["screen"])
            orientation = Orientation(document["orientation"])
        except (TypeError, ValueError) as error:
            raise CreativeLookExperienceError("screen or orientation is invalid") from error
        editing_axis = document["editing_axis"]
        if editing_axis is not None and editing_axis not in AXIS_IDS:
            raise CreativeLookExperienceError("editing axis is invalid")
        if (screen is Screen.AXIS_PICKER) != (editing_axis is not None):
            raise CreativeLookExperienceError("axis picker state is inconsistent")

        custom_bases = document["custom_bases"]
        if not isinstance(custom_bases, dict) or set(custom_bases) != set(
            CUSTOM_LOOK_IDS
        ):
            raise CreativeLookExperienceError("Custom slot membership is invalid")
        for base in custom_bases.values():
            if base is not None and base not in BUILT_IN_LOOK_IDS:
                raise CreativeLookExperienceError("Custom base is invalid")

        adjustments = document["adjustments"]
        if not isinstance(adjustments, dict) or set(adjustments) != set(LOOK_IDS):
            raise CreativeLookExperienceError("adjustment membership is invalid")
        for look_id, values in adjustments.items():
            if not isinstance(values, dict) or set(values) != set(AXIS_IDS):
                raise CreativeLookExperienceError("axis membership is invalid")
            for axis_id, value in values.items():
                if value is None:
                    continue
                if type(value) is not int:
                    raise CreativeLookExperienceError("axis state is not an integer")
                minimum, maximum = AXIS_DEFINITIONS[axis_id]
                if not minimum <= value <= maximum:
                    raise CreativeLookExperienceError("axis state is out of range")

        modes = document["modes"]
        if (
            not isinstance(modes, dict)
            or set(modes) != set(MODE_FIELDS)
            or any(type(value) is not bool for value in modes.values())
        ):
            raise CreativeLookExperienceError("mode state is invalid")
        if document["safety"] != {
            "recovery_validated": False,
            "camera_test_eligible": False,
            "installable": False,
        }:
            raise CreativeLookExperienceError("camera safety state is invalid")
        if (
            document["selected_look"] in CUSTOM_LOOK_IDS
            and custom_bases[document["selected_look"]] is None
            and screen in {Screen.EDITOR, Screen.AXIS_PICKER}
        ):
            raise CreativeLookExperienceError("unconfigured Custom slot cannot be edited")

        experience = cls(
            selected_look=document["selected_look"],
            screen=screen,
            orientation=orientation,
            editing_axis=editing_axis,
            custom_bases=dict(custom_bases),
            adjustments={
                look_id: dict(values) for look_id, values in adjustments.items()
            },
            modes=dict(modes),
        )
        if experience._mode_unavailable() and screen is not Screen.CATALOG:
            raise CreativeLookExperienceError(
                "unavailable Creative Look mode must remain on the catalog screen"
            )
        if screen is Screen.AXIS_PICKER and not experience._axis_enabled(
            editing_axis
        )[0]:
            raise CreativeLookExperienceError("restricted axis cannot remain open")
        return experience

    def _resolved_base_look(self) -> str | None:
        if self.selected_look in BUILT_IN_LOOK_IDS:
            return self.selected_look
        return self.custom_bases[self.selected_look]

    def _axis_enabled(self, axis_id: str | None) -> tuple[bool, str | None]:
        if axis_id not in AXIS_IDS:
            raise CreativeLookExperienceError("axis identifier is invalid")
        if self._mode_unavailable():
            return False, "CREATIVE_LOOK_MODE_UNAVAILABLE"
        if axis_id == "saturation" and self._resolved_base_look() in {"BW", "SE"}:
            return False, "BW_SE_SATURATION_UNAVAILABLE"
        if axis_id == "sharpness_range" and self.modes["movie_mode"]:
            return False, "MOVIE_SHARPNESS_RANGE_UNAVAILABLE"
        return True, None

    def _mode_unavailable(self) -> bool:
        return any(
            self.modes[field]
            for field in (
                "intelligent_auto",
                "picture_profile_not_off",
                "flexible_iso_log",
            )
        )

    def _require_mode_available(self) -> None:
        if self._mode_unavailable():
            raise CreativeLookExperienceError("CREATIVE_LOOK_MODE_UNAVAILABLE")

    def _viewport(self) -> tuple[int, int]:
        if self.orientation is Orientation.LANDSCAPE:
            return 1600, 900
        return 900, 1600

    @staticmethod
    def _layout(
        items: list[UiElement], columns: int, width: int, height: int
    ) -> tuple[UiElement, ...]:
        rows = math.ceil(len(items) / columns)
        margin_x = width * 0.025
        margin_y = height * 0.025
        gap_x = width * 0.012
        gap_y = height * 0.012
        cell_width = (width - 2 * margin_x - (columns - 1) * gap_x) / columns
        cell_height = (height - 2 * margin_y - (rows - 1) * gap_y) / rows
        laid_out = []
        for index, item in enumerate(items):
            row, column = divmod(index, columns)
            rect = Rect(
                round(margin_x + column * (cell_width + gap_x), 6),
                round(margin_y + row * (cell_height + gap_y), 6),
                round(cell_width, 6),
                round(cell_height, 6),
            )
            laid_out.append(
                UiElement(
                    identifier=item.identifier,
                    kind=item.kind,
                    rect=rect,
                    enabled=item.enabled,
                    reason=item.reason,
                    value=item.value,
                    modified=item.modified,
                )
            )
        return tuple(laid_out)


def save_experience(path: Path, experience: CreativeLookExperience) -> None:
    path = Path(path)
    if path.suffix.casefold() != ".json" or path.is_symlink():
        raise CreativeLookExperienceError("state output must be a non-symlink JSON file")
    if path.exists() and not path.is_file():
        raise CreativeLookExperienceError("state output is not a regular file")
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(
        experience.to_document(), sort_keys=True, indent=2, ensure_ascii=False
    ) + "\n"
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


def load_experience(path: Path) -> CreativeLookExperience:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise CreativeLookExperienceError("state input must be a real regular file")
    if path.stat().st_size > MAX_STATE_BYTES:
        raise CreativeLookExperienceError("state input exceeds the size limit")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CreativeLookExperienceError("state input is not valid UTF-8 JSON") from error
    return CreativeLookExperience.from_document(document)
