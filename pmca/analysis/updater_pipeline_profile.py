"""Fail-closed geometry for the alpha 6400 updater transcode boundary.

This module performs integer checks only. It has no camera transport,
cryptographic primitive, executable loader, or firmware writer.
"""


class UpdaterPipelineProfileError(ValueError):
    """Raised when observed updater geometry is inconsistent or unknown."""


def _positive_int(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise UpdaterPipelineProfileError(f"{label} is invalid")
    return value


def describe_updater_pipeline(
    *,
    raw_fdat_bytes: int,
    decoded_fdat_bytes: int,
    header_bytes: int,
    updater_image_bytes: int,
    firmware_archive_bytes: int,
    outer_trailer_bytes: int,
) -> dict:
    """Describe the proven geometry without implementing the transform."""
    values = {
        "raw_fdat_bytes": raw_fdat_bytes,
        "decoded_fdat_bytes": decoded_fdat_bytes,
        "header_bytes": header_bytes,
        "updater_image_bytes": updater_image_bytes,
        "firmware_archive_bytes": firmware_archive_bytes,
        "outer_trailer_bytes": outer_trailer_bytes,
    }
    for label, value in values.items():
        _positive_int(value, label)

    if outer_trailer_bytes != 0x110 or raw_fdat_bytes <= outer_trailer_bytes:
        raise UpdaterPipelineProfileError("Outer protection geometry is unknown")
    ciphertext_bytes = raw_fdat_bytes - outer_trailer_bytes
    if ciphertext_bytes % 0x400:
        raise UpdaterPipelineProfileError("Outer ciphertext is not frame aligned")
    if header_bytes != 0x200:
        raise UpdaterPipelineProfileError("Decoded header size is unknown")
    if decoded_fdat_bytes != header_bytes + updater_image_bytes + firmware_archive_bytes:
        raise UpdaterPipelineProfileError("Decoded FDAT layout is inconsistent")

    return {
        "raw_fdat_bytes": raw_fdat_bytes,
        "ciphertext_bytes": ciphertext_bytes,
        "decoded_fdat_bytes": decoded_fdat_bytes,
        "outer_trailer_bytes": outer_trailer_bytes,
        "crypter_decrypt_mode": "aes-128-ecb",
        "crypter_key_family": "historical-first-stage",
        "raw_remainder_mode": "aes-cbc",
        "pre_crypter_transform": (
            "generation4-to-legacy-ecb-transcode-required"
        ),
        "pre_crypter_transform_implementation": "unresolved",
        "camera_executed": False,
        "installable": False,
    }
