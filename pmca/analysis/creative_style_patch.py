"""Fail-closed patch for the native a6400 Creative Style graph selector."""

from __future__ import annotations

import hashlib


A6400_V200_CAUTION_CONFIG_SIZE = 12_070_800
A6400_V200_CAUTION_CONFIG_SHA256 = (
    "bfd1bd7bad0ab3478b894da5dbb51c15464b1bedc4201240ccb61cd743150ef7"
)
TARGET_SELECTOR_FILE_OFFSET = 0x7DB9B7
TYPE_EMNT_SELECTOR_BYTE = 0x1E
DEFAULT_GRAPH_SELECTOR_BYTE = 0x37


class CreativeStylePatchError(ValueError):
    """Raised when the source is not the exact verified a6400 v2.00 library."""


def patch_creative_style_default_graph(
    image: bytes,
    *,
    expected_source_sha256: str = A6400_V200_CAUTION_CONFIG_SHA256,
    expected_source_size: int = A6400_V200_CAUTION_CONFIG_SIZE,
) -> bytes:
    """Expose the firmware-native Default style graph with one verified byte edit.

    This does not add modern Creative Look processing axes. It switches the
    existing a6400 selector from TypeEmnt to Default, which exposes the dormant
    native Real/style-box graph discovered in the official v2.00 firmware.
    """

    if len(image) != expected_source_size:
        raise CreativeStylePatchError(
            "source size mismatch: expected "
            f"{expected_source_size}, got {len(image)}"
        )

    actual_sha256 = hashlib.sha256(image).hexdigest()
    if actual_sha256.lower() != expected_source_sha256.lower():
        raise CreativeStylePatchError(
            "source SHA-256 mismatch: input is not the verified a6400 v2.00 "
            "CautionConfig.so"
        )

    selector = image[TARGET_SELECTOR_FILE_OFFSET]
    if selector != TYPE_EMNT_SELECTOR_BYTE:
        raise CreativeStylePatchError(
            "unexpected selector byte at verified offset: expected "
            f"0x{TYPE_EMNT_SELECTOR_BYTE:02x}, got 0x{selector:02x}"
        )

    patched = bytearray(image)
    patched[TARGET_SELECTOR_FILE_OFFSET] = DEFAULT_GRAPH_SELECTOR_BYTE
    return bytes(patched)
