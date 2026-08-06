"""Metadata-only characterization of opaque Sony FDAT protection regions."""

import copy
import hashlib
import math
import re


class ProtectionError(ValueError):
    """Raised when a protection profile or claim exceeds the evidence boundary."""


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_SAMPLE_WINDOW = 65_536
_AES_BLOCK_SIZE = 16
_ENCRYPTED_BLOCK_SIZE = 1024
_TRAILER_SUFFIX_SIZES = (256, 384, 512)
_TOP_FIELDS = {
    "schema_version",
    "subject",
    "camera_policy",
    "camera_executed",
    "decryption_established",
    "installable",
    "artifacts",
    "historical_tool_probe",
    "source_survey",
    "observations",
    "inferences",
    "unresolved",
    "conclusion",
}
_ARTIFACT_FIELDS = {"source_key", "sha256", "fdat_offset", "fdat_size", "profile"}
_PROFILE_FIELDS = {
    "size",
    "aes_block_aligned",
    "sample_profile",
    "trailer_candidates",
    "boundary_metadata",
}
_SAMPLE_FIELDS = {
    "sample_bytes",
    "entropy_bits_per_byte",
    "total_16_byte_blocks",
    "unique_16_byte_blocks",
    "adjacent_equal_16_byte_blocks",
}
_TRAILER_FIELDS = {"encrypted_size", "prefix_size", "suffix_size", "trailer_size"}
_BOUNDARY_FIELDS = {
    "prefix_sha256",
    "prefix_entropy_bits_per_byte",
    "prefix_unique_bytes",
    "prefix_all_zero",
    "suffix_sha256",
    "suffix_entropy_bits_per_byte",
    "suffix_unique_bytes",
    "suffix_all_zero",
    "cryptographic_role_established",
}
_PROBE_FIELDS = {"repository", "commit", "module", "results"}
_PROBE_RESULT_FIELDS = {
    "source_key",
    "shared_stage_result",
    "block_declared_size",
    "internal_version",
    "model_id",
    "region",
    "firmware_offset",
    "firmware_size",
    "filesystem_count",
    "known_cbc_key_result",
}
_SURVEY_FIELDS = {
    "performed_at",
    "upstream_forks_surveyed",
    "forks_with_new_decrypter_paths",
    "recent_implementation_repository",
    "recent_implementation_commit",
    "recent_implementation_result",
    "new_decrypter_paths_found",
}
_CLAIM_FIELDS = {"classification", "source", "claim"}
_FORBIDDEN_KEYS = {
    "raw",
    "raw_payload",
    "bytes",
    "payload",
    "base64",
    "hex_dump",
    "decrypted",
    "private" + "_key",
}
_ARTIFACTS = {
    "a6700-tw-v2.00": "d3c7db5b9b40c89b11ecf03addf0f6ff1d9b917acf9f55e46360462e86db847c",
    "a7v-tw-v2.00": "098290778a84236a0f2be44ac8398fd428d522b5c2c6676f19df23d09ee293d6",
    "a7s3-jp-v2.15": "e3e11308c4b0dd661c2c2231bd5a4ccdbd5320976694bd2ed8b19d3e89617c01",
    "a7s3-jp-v3.01": "0dcbc601d73b319cd03283363c156fec1efebf61a8e2855be11453603dc08d73",
}


def _bounded_int(value: object, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ProtectionError(f"{label} is invalid")
    return value


def _bounded_text(value: object, label: str, maximum: int = 1000) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or "\r" in value
        or "\n" in value
        or not value.isprintable()
    ):
        raise ProtectionError(f"{label} is invalid")
    return value


def _require_fields(value: object, fields: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise ProtectionError(f"{label} fields are invalid")
    return value


def _reject_reconstructive_fields(value: object) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str) or key.casefold() in _FORBIDDEN_KEYS:
                raise ProtectionError("Protection report contains a forbidden field")
            _reject_reconstructive_fields(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_reconstructive_fields(nested)


def classify_trailer_geometry(fdat_size: int) -> list[dict]:
    """Return allowlisted trailer geometries that leave 1024-byte blocks."""
    _bounded_int(fdat_size, 1, 8 * 1024**4, "FDAT size")
    candidates = []
    for suffix_size in _TRAILER_SUFFIX_SIZES:
        trailer_size = _AES_BLOCK_SIZE + suffix_size
        encrypted_size = fdat_size - trailer_size
        if encrypted_size > 0 and encrypted_size % _ENCRYPTED_BLOCK_SIZE == 0:
            candidates.append(
                {
                    "encrypted_size": encrypted_size,
                    "prefix_size": _AES_BLOCK_SIZE,
                    "suffix_size": suffix_size,
                    "trailer_size": trailer_size,
                }
            )
    return candidates


def _sample_positions(size: int) -> list[tuple[int, int]]:
    if size <= 3 * _SAMPLE_WINDOW:
        return [(0, size)]
    middle = (size - _SAMPLE_WINDOW) // 2
    middle -= middle % _AES_BLOCK_SIZE
    return [
        (0, _SAMPLE_WINDOW),
        (middle, _SAMPLE_WINDOW),
        (size - _SAMPLE_WINDOW, _SAMPLE_WINDOW),
    ]


def _entropy(data: bytes) -> float:
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    size = len(data)
    return round(
        -sum((count / size) * math.log2(count / size) for count in counts if count),
        6,
    )


def characterize_fdat_region(stream, offset: int, size: int) -> dict:
    """Sample a bounded FDAT region and emit statistics, never region contents."""
    _bounded_int(offset, 0, 8 * 1024**4, "FDAT offset")
    _bounded_int(size, 1, 8 * 1024**4, "FDAT size")
    if not all(hasattr(stream, method) for method in ("read", "seek", "tell")):
        raise ProtectionError("FDAT stream is not seekable")

    original_position = stream.tell()
    try:
        stream.seek(0, 2)
        stream_size = stream.tell()
        if offset + size > stream_size:
            raise ProtectionError("FDAT region exceeds the stream")
        candidates = classify_trailer_geometry(size)
        boundary_metadata = None
        if len(candidates) == 1:
            candidate = candidates[0]
            stream.seek(offset)
            prefix = stream.read(candidate["prefix_size"])
            stream.seek(offset + size - candidate["suffix_size"])
            suffix = stream.read(candidate["suffix_size"])
            if (
                not isinstance(prefix, bytes)
                or len(prefix) != candidate["prefix_size"]
                or not isinstance(suffix, bytes)
                or len(suffix) != candidate["suffix_size"]
            ):
                raise ProtectionError("FDAT boundary metadata is truncated")
            boundary_metadata = {
                "prefix_sha256": hashlib.sha256(prefix).hexdigest(),
                "prefix_entropy_bits_per_byte": _entropy(prefix),
                "prefix_unique_bytes": len(set(prefix)),
                "prefix_all_zero": not any(prefix),
                "suffix_sha256": hashlib.sha256(suffix).hexdigest(),
                "suffix_entropy_bits_per_byte": _entropy(suffix),
                "suffix_unique_bytes": len(set(suffix)),
                "suffix_all_zero": not any(suffix),
                "cryptographic_role_established": False,
            }

        sampled = bytearray()
        for relative_offset, length in _sample_positions(size):
            stream.seek(offset + relative_offset)
            chunk = stream.read(length)
            if not isinstance(chunk, bytes) or len(chunk) != length:
                raise ProtectionError("FDAT sample is truncated")
            sampled.extend(chunk)
    finally:
        stream.seek(original_position)

    blocks = [
        bytes(sampled[position : position + _AES_BLOCK_SIZE])
        for position in range(0, len(sampled), _AES_BLOCK_SIZE)
        if len(sampled[position : position + _AES_BLOCK_SIZE]) == _AES_BLOCK_SIZE
    ]
    adjacent_equal = sum(left == right for left, right in zip(blocks, blocks[1:]))
    return {
        "size": size,
        "aes_block_aligned": size % _AES_BLOCK_SIZE == 0,
        "sample_profile": {
            "sample_bytes": len(sampled),
            "entropy_bits_per_byte": _entropy(bytes(sampled)),
            "total_16_byte_blocks": len(blocks),
            "unique_16_byte_blocks": len(set(blocks)),
            "adjacent_equal_16_byte_blocks": adjacent_equal,
        },
        "trailer_candidates": candidates,
        "boundary_metadata": boundary_metadata,
    }


def _validate_profile(value: object, fdat_size: int) -> None:
    profile = _require_fields(value, _PROFILE_FIELDS, "FDAT profile")
    if profile["size"] != fdat_size:
        raise ProtectionError("FDAT profile size does not match")
    if type(profile["aes_block_aligned"]) is not bool:
        raise ProtectionError("FDAT AES alignment flag is invalid")
    if profile["aes_block_aligned"] != (fdat_size % _AES_BLOCK_SIZE == 0):
        raise ProtectionError("FDAT AES alignment flag is inconsistent")

    sample = _require_fields(profile["sample_profile"], _SAMPLE_FIELDS, "Sample profile")
    sample_bytes = _bounded_int(sample["sample_bytes"], 1, 3 * _SAMPLE_WINDOW, "Sample size")
    entropy = sample["entropy_bits_per_byte"]
    if type(entropy) not in (int, float) or not math.isfinite(entropy) or not 0 <= entropy <= 8:
        raise ProtectionError("Sample entropy is invalid")
    total_blocks = _bounded_int(
        sample["total_16_byte_blocks"], 1, sample_bytes // _AES_BLOCK_SIZE, "Sample block count"
    )
    _bounded_int(sample["unique_16_byte_blocks"], 1, total_blocks, "Unique sample blocks")
    _bounded_int(
        sample["adjacent_equal_16_byte_blocks"], 0, max(total_blocks - 1, 0), "Adjacent sample blocks"
    )

    candidates = profile["trailer_candidates"]
    if not isinstance(candidates, list) or len(candidates) > len(_TRAILER_SUFFIX_SIZES):
        raise ProtectionError("Trailer candidates are invalid")
    for candidate in candidates:
        _require_fields(candidate, _TRAILER_FIELDS, "Trailer candidate")
    if candidates != classify_trailer_geometry(fdat_size):
        raise ProtectionError("Trailer candidates exceed structural evidence")
    boundary = profile["boundary_metadata"]
    if len(candidates) != 1:
        if boundary is not None:
            raise ProtectionError("Ambiguous boundary metadata was promoted")
        return
    _require_fields(boundary, _BOUNDARY_FIELDS, "Boundary metadata")
    for field in ("prefix_sha256", "suffix_sha256"):
        if not isinstance(boundary[field], str) or not _DIGEST.fullmatch(boundary[field]):
            raise ProtectionError("Boundary digest is malformed")
    for field, size in (
        ("prefix_entropy_bits_per_byte", candidates[0]["prefix_size"]),
        ("suffix_entropy_bits_per_byte", candidates[0]["suffix_size"]),
    ):
        value = boundary[field]
        if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 8:
            raise ProtectionError("Boundary entropy is invalid")
    _bounded_int(
        boundary["prefix_unique_bytes"],
        1,
        min(256, candidates[0]["prefix_size"]),
        "Prefix unique-byte count",
    )
    _bounded_int(
        boundary["suffix_unique_bytes"],
        1,
        min(256, candidates[0]["suffix_size"]),
        "Suffix unique-byte count",
    )
    for field in ("prefix_all_zero", "suffix_all_zero"):
        if type(boundary[field]) is not bool:
            raise ProtectionError("Boundary zero flag is invalid")
    if boundary["cryptographic_role_established"] is not False:
        raise ProtectionError("Boundary cryptographic role was overclaimed")


def validate_protection_report(document: object) -> dict:
    """Validate donor evidence while preserving failure and uncertainty labels."""
    _require_fields(document, _TOP_FIELDS, "Protection report")
    _reject_reconstructive_fields(document)
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise ProtectionError("Protection report schema is unsupported")
    if document["subject"] != "Sony donor FDAT protection boundary":
        raise ProtectionError("Protection report subject is invalid")
    if document["camera_policy"] != "physically-disconnected":
        raise ProtectionError("Protection report camera policy is invalid")
    for field in ("camera_executed", "decryption_established", "installable"):
        if document[field] is not False:
            raise ProtectionError(f"{field} must remain false")

    artifacts = document["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != len(_ARTIFACTS):
        raise ProtectionError("Protection artifacts are incomplete")
    seen = set()
    for artifact in artifacts:
        _require_fields(artifact, _ARTIFACT_FIELDS, "Protection artifact")
        source_key = artifact["source_key"]
        digest = artifact["sha256"]
        if source_key not in _ARTIFACTS or source_key in seen:
            raise ProtectionError("Protection artifact source is invalid")
        if digest != _ARTIFACTS[source_key] or not _DIGEST.fullmatch(digest):
            raise ProtectionError("Protection artifact digest is invalid")
        seen.add(source_key)
        _bounded_int(artifact["fdat_offset"], 0, 8 * 1024**4, "FDAT offset")
        size = _bounded_int(artifact["fdat_size"], 1, 8 * 1024**4, "FDAT size")
        _validate_profile(artifact["profile"], size)
    if seen != set(_ARTIFACTS):
        raise ProtectionError("Protection artifact sources are incomplete")

    probe = _require_fields(document["historical_tool_probe"], _PROBE_FIELDS, "Historical probe")
    _bounded_text(probe["repository"], "Historical repository", 256)
    if not isinstance(probe["commit"], str) or not _COMMIT.fullmatch(probe["commit"]):
        raise ProtectionError("Historical commit is invalid")
    if probe["module"] != "fwtool/sony/fdat.py":
        raise ProtectionError("Historical probe module is invalid")
    results = probe["results"]
    if not isinstance(results, list) or len(results) != len(_ARTIFACTS):
        raise ProtectionError("Historical probe results are incomplete")
    result_map = {}
    for result in results:
        _require_fields(result, _PROBE_RESULT_FIELDS, "Historical probe result")
        source_key = result["source_key"]
        if source_key not in _ARTIFACTS or source_key in result_map:
            raise ProtectionError("Historical probe source is invalid")
        result_map[source_key] = result
        if result["shared_stage_result"] not in {"HEADER_MATCH", "HEADER_MISMATCH"}:
            raise ProtectionError("Historical shared-stage result is invalid")
        if result["known_cbc_key_result"] not in {
            "BLOCK_CHECKSUM_MISMATCH",
            "NO_DECRYPTER_FOUND_AFTER_KEY_TRIALS",
        }:
            raise ProtectionError("Historical CBC-key result is invalid")

    match = result_map.get("a6700-tw-v2.00")
    mismatch = result_map.get("a7v-tw-v2.00")
    a7s3_v215 = result_map.get("a7s3-jp-v2.15")
    a7s3_v301 = result_map.get("a7s3-jp-v3.01")
    if match is None or mismatch is None or a7s3_v215 is None or a7s3_v301 is None:
        raise ProtectionError("Historical probe results are incomplete")
    if match != {
        "source_key": "a6700-tw-v2.00",
        "shared_stage_result": "HEADER_MATCH",
        "block_declared_size": 1020,
        "internal_version": "2.00",
        "model_id": "0x20030001",
        "region": 0,
        "firmware_offset": 1253888,
        "firmware_size": 1018763264,
        "filesystem_count": 2,
        "known_cbc_key_result": "BLOCK_CHECKSUM_MISMATCH",
    }:
        raise ProtectionError("α6700 shared-stage claim exceeds the probe")
    if mismatch != {
        "source_key": "a7v-tw-v2.00",
        "shared_stage_result": "HEADER_MISMATCH",
        "block_declared_size": None,
        "internal_version": None,
        "model_id": None,
        "region": None,
        "firmware_offset": None,
        "firmware_size": None,
        "filesystem_count": None,
        "known_cbc_key_result": "BLOCK_CHECKSUM_MISMATCH",
    }:
        raise ProtectionError("α7 V shared-stage claim exceeds the probe")
    if a7s3_v215 != {
        "source_key": "a7s3-jp-v2.15",
        "shared_stage_result": "HEADER_MATCH",
        "block_declared_size": 1020,
        "internal_version": "2.15",
        "model_id": "0x91030083",
        "region": 0,
        "firmware_offset": 1253888,
        "firmware_size": 641965056,
        "filesystem_count": 2,
        "known_cbc_key_result": "NO_DECRYPTER_FOUND_AFTER_KEY_TRIALS",
    }:
        raise ProtectionError("α7S III 2.15 shared-stage claim exceeds the probe")
    if a7s3_v301 != {
        "source_key": "a7s3-jp-v3.01",
        "shared_stage_result": "HEADER_MATCH",
        "block_declared_size": 1020,
        "internal_version": "3.01",
        "model_id": "0x91030083",
        "region": 0,
        "firmware_offset": 1253888,
        "firmware_size": 734976000,
        "filesystem_count": 2,
        "known_cbc_key_result": "NO_DECRYPTER_FOUND_AFTER_KEY_TRIALS",
    }:
        raise ProtectionError("α7S III 3.01 shared-stage claim exceeds the probe")

    survey = _require_fields(document["source_survey"], _SURVEY_FIELDS, "Source survey")
    _bounded_text(survey["performed_at"], "Source survey date", 32)
    _bounded_int(survey["upstream_forks_surveyed"], 1, 1000, "Surveyed fork count")
    if survey["forks_with_new_decrypter_paths"] != 0 or survey["new_decrypter_paths_found"] != 0:
        raise ProtectionError("Source survey promotes an unsupported decrypter path")
    _bounded_text(survey["recent_implementation_repository"], "Recent implementation repository", 256)
    if not isinstance(survey["recent_implementation_commit"], str) or not _COMMIT.fullmatch(
        survey["recent_implementation_commit"]
    ):
        raise ProtectionError("Recent implementation commit is invalid")
    _bounded_text(survey["recent_implementation_result"], "Recent implementation result")

    for field, classification in (
        ("observations", "OBSERVATION"),
        ("inferences", "INFERENCE"),
        ("unresolved", "UNRESOLVED"),
    ):
        claims = document[field]
        if not isinstance(claims, list) or not 1 <= len(claims) <= 16:
            raise ProtectionError(f"{field} claims are invalid")
        for claim in claims:
            _require_fields(claim, _CLAIM_FIELDS, "Protection claim")
            if claim["classification"] != classification:
                raise ProtectionError("Protection claim classification is invalid")
            _bounded_text(claim["source"], "Protection claim source", 256)
            _bounded_text(claim["claim"], "Protection claim")
    _bounded_text(document["conclusion"], "Protection conclusion")
    return copy.deepcopy(document)
