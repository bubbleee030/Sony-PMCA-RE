"""Fail-closed contract for the ILCE-6400 modern UI research target."""

from __future__ import annotations

import copy
import unicodedata


BEHAVIOR_IDS = (
    "shooting-layout-landscape",
    "shooting-layout-portrait-shutter-up",
    "shooting-layout-portrait-shutter-down",
    "orientation-layout-selection",
    "control-direction-transform",
    "touch-coordinate-transform",
    "menu-touch-hit-test",
    "menu-touch-selection",
    "ui-state-persistence",
)
STATUSES = {
    "TARGET_NATIVE",
    "TARGET_REIMPLEMENTABLE",
    "DONOR_COMPATIBLE",
    "APPROXIMATION_ONLY",
    "HARDWARE_BLOCKED",
    "UNESTABLISHED",
}
_DOCUMENT_FIELDS = {"schema_version", "target", "reference", "behaviors"}
_BEHAVIOR_FIELDS = {"id", "status", "evidence", "acceptance"}
_MAX_TEXT_CHARS = 2048


class ModernUiContractError(ValueError):
    """Raised when the modern UI behavior contract is malformed or overclaimed."""


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ModernUiContractError(f"{label} must be nonempty text")
    if len(value) > _MAX_TEXT_CHARS:
        raise ModernUiContractError(f"{label} exceeds the text size limit")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise ModernUiContractError(f"{label} contains a control character")
    return value


def validate_modern_ui_contract(document: dict) -> dict:
    """Return an isolated validated copy of the fixed behavior contract."""

    if not isinstance(document, dict) or set(document) != _DOCUMENT_FIELDS:
        raise ModernUiContractError("contract fields are not exact")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise ModernUiContractError("contract schema version is invalid")
    if document["target"] != "ILCE-6400":
        raise ModernUiContractError("contract target is invalid")
    if document["reference"] != "ILCE-7M5-interface-behavior":
        raise ModernUiContractError("contract reference is invalid")

    behaviors = document["behaviors"]
    if not isinstance(behaviors, list):
        raise ModernUiContractError("contract behaviors must be a list")
    if [item.get("id") if isinstance(item, dict) else None for item in behaviors] != list(
        BEHAVIOR_IDS
    ):
        raise ModernUiContractError("contract behavior order is invalid")

    for item in behaviors:
        if set(item) != _BEHAVIOR_FIELDS:
            raise ModernUiContractError("behavior fields are not exact")
        if not isinstance(item["status"], str) or item["status"] not in STATUSES:
            raise ModernUiContractError("behavior status is invalid")
        evidence = item["evidence"]
        if not isinstance(evidence, list):
            raise ModernUiContractError("behavior evidence must be a list")
        for source in evidence:
            _require_text(source, "Behavior evidence")
        if item["status"] != "UNESTABLISHED" and not evidence:
            raise ModernUiContractError("established behavior requires evidence")
        _require_text(item["acceptance"], "Behavior acceptance")

    return copy.deepcopy(document)
