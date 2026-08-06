"""Validate bounded α6400A updater bootstrap control evidence."""

from collections import deque
from copy import deepcopy
import hashlib
import json
import re


class UpdaterControlBootstrapError(ValueError):
    """Raised when control-sample evidence is malformed or promoted to target proof."""


_FORBIDDEN_KEYS = {
    "device_path",
    "firmware_path",
    "key_material",
    "partition_bytes",
    "private_key",
    "raw_bytes",
    "raw_command",
    "raw_payload",
    "write_command",
}

_SAUU_PROGRAM = "sauu"
_SAUU_SHA256 = "d79af0e6958e47c9b50622b1bedb4afe86b7384e3513ffd62ce09f9e2c18a322"
_SAUU_FILE_SIZE = 84428
_SAUU_ADDRESS_MIN = 0x8000
_SAUU_ADDRESS_MAX = 0x1BEA4
_SAUU_MAX_FUNCTIONS = 1024
_SAUU_MAX_CALLS = 4096
_SAUU_MAX_DEPTH = 8
_SAUU_ROOTS = (
    ("guard-dispatch", 0xDF5C),
    ("model-compare", 0xDEA2),
    ("region-compare", 0xDE84),
    ("version-compare", 0xDEC0),
    ("verification-key-hash", 0x10368),
    ("signature-verifier", 0x104E0),
    ("signature-workflow-caller", 0x10A88),
)
_SAUU_TOP_FIELDS = {
    "schema_version",
    "program",
    "sha256",
    "file_size",
    "analysis_mode",
    "roots",
    "functions",
    "calls",
    "unresolved_direct_calls",
    "unresolved_indirect_calls",
    "max_depth",
    "truncated",
}
_SAUU_CALL_KINDS = {"direct", "unresolved-direct", "unresolved-indirect"}
_SHA256_RE = re.compile(r"[0-9a-f]{64}")

EXPECTED_BOOTSTRAP = {
    "schema_version": 1,
    "subject": "ILCE-6400A persistent updater bootstrap architecture control",
    "camera_policy": "physically-disconnected",
    "camera_executed": False,
    "sony_binary_executed": False,
    "installable": False,
    "source": {
        "id": "a6400a-eu-v1.01",
        "model": "ILCE-6400A",
        "model_id": "0x81030017",
        "version": "1.01",
        "updater_partition_sha256": "c9040270ad886214c5656894b90fb1e839a3ab942cb65726633d8f1f1221c093",
        "role": "different-model-architecture-control",
    },
    "target": {
        "model": "ILCE-6400",
        "model_id": "0x81030011",
        "version": "2.00",
        "architecture_transfer_proven": False,
        "recovery_supported": False,
        "camera_test_eligible": False,
    },
    "artifacts": [
        {
            "id": "updater-init",
            "name": "sbin/init",
            "size": 1451,
            "sha256": "23773fcd4c931b4d5df84d367090191c956c9a531f045f6bb9699cbe419dc693",
            "kind": "shell-script",
        },
        {
            "id": "boot-validity-check",
            "name": "usr/bin/is_valid_boot.sh",
            "size": 483,
            "sha256": "51a9aec51413eead0debd856afa60ad06ad4726bab2502a11415fe5c3a3a1b8a",
            "kind": "shell-script",
        },
        {
            "id": "mode-dispatcher",
            "name": "usr/bin/UdtrMain.sh",
            "size": 2174,
            "sha256": "001220e5fa3b5242a48a107223dcf99d505225ef59d88872c7829135494418d9",
            "kind": "shell-script",
        },
        {
            "id": "production-branch",
            "name": "usr/bin/execute_prod.sh",
            "size": 874,
            "sha256": "b4757905611421b212033aa2a1f15f5539466ce89097c13b64234476fa9ab4d8",
            "kind": "shell-script",
        },
        {
            "id": "ufp-branch",
            "name": "usr/bin/execute_ufp.sh",
            "size": 2030,
            "sha256": "274112942c49135999b39e0c750209d0d0f7a2cfa35269ac2f40c38486a2d428",
            "kind": "shell-script",
        },
        {
            "id": "usb-preparation",
            "name": "usr/bin/prepare-usb.sh",
            "size": 421,
            "sha256": "356b8d57144752dc8eb013f84b7af1937c7616cbd558c56b9df44bd19792b55f",
            "kind": "shell-script",
        },
        {
            "id": "production-engine",
            "name": "usr/bin/sen.elf",
            "size": 22604,
            "sha256": "c257e5fc9a7f5738af8f4c5125527a9a0e7c0325a86ba51fc6413d5853706aaa",
            "kind": "elf-control-binary",
        },
        {
            "id": "system-update-receiver",
            "name": "usr/bin/sauu",
            "size": 84428,
            "sha256": "d79af0e6958e47c9b50622b1bedb4afe86b7384e3513ffd62ce09f9e2c18a322",
            "kind": "elf-control-binary",
        },
        {
            "id": "input-feeder",
            "name": "usr/bin/sdfileinput.elf",
            "size": 49536,
            "sha256": "3bb68f04e7eb633bb08099277c36ea388c4e4a0ecb786ef1c2cb1c160d64f4cb",
            "kind": "elf-control-binary",
        },
        {
            "id": "reboot-boundary",
            "name": "usr/bin/ud_reboot.elf",
            "size": 8804,
            "sha256": "dd584cc4854f336992d85a4bebf68288b76feabeeb699b276c6943460d39f7e2",
            "kind": "elf-control-binary",
        },
    ],
    "edges": [
        {"caller": "updater-init", "callee": "boot-validity-check", "kind": "STATIC_SCRIPT_REFERENCE"},
        {"caller": "updater-init", "callee": "mode-dispatcher", "kind": "STATIC_SCRIPT_REFERENCE"},
        {"caller": "mode-dispatcher", "callee": "production-branch", "kind": "STATIC_SCRIPT_REFERENCE"},
        {"caller": "mode-dispatcher", "callee": "ufp-branch", "kind": "STATIC_SCRIPT_REFERENCE"},
        {"caller": "production-branch", "callee": "usb-preparation", "kind": "STATIC_SCRIPT_REFERENCE"},
        {"caller": "production-branch", "callee": "production-engine", "kind": "STATIC_SCRIPT_REFERENCE"},
        {"caller": "ufp-branch", "callee": "usb-preparation", "kind": "STATIC_SCRIPT_REFERENCE"},
        {"caller": "ufp-branch", "callee": "system-update-receiver", "kind": "STATIC_SCRIPT_REFERENCE"},
        {"caller": "ufp-branch", "callee": "input-feeder", "kind": "STATIC_SCRIPT_REFERENCE"},
        {"caller": "ufp-branch", "callee": "reboot-boundary", "kind": "STATIC_SCRIPT_REFERENCE"},
    ],
    "sauu_control_export": {
        "program": "sauu",
        "program_sha256": "d79af0e6958e47c9b50622b1bedb4afe86b7384e3513ffd62ce09f9e2c18a322",
        "canonical_export_sha256": "0e80cb19f9d4f227f04503e6d3f6ace4f1b0c7fe6194e2a3c7ede89a8ed9ad38",
        "analysis_mode": {"read_only": True, "noanalysis": True},
        "function_count": 37,
        "call_count": 71,
        "unresolved_direct_calls": 0,
        "unresolved_indirect_calls": 3,
        "max_depth": 2,
        "truncated": False,
        "root_resolutions": [
            {"id": "guard-dispatch", "source_address": 0xDF5C, "resolution": "function", "function_address": 0xDF5C},
            {"id": "model-compare", "source_address": 0xDEA2, "resolution": "function", "function_address": 0xDEA2},
            {"id": "region-compare", "source_address": 0xDE84, "resolution": "function", "function_address": 0xDE84},
            {"id": "version-compare", "source_address": 0xDEC0, "resolution": "function", "function_address": 0xDEC0},
            {"id": "verification-key-hash", "source_address": 0x10368, "resolution": "function", "function_address": 0x10368},
            {"id": "signature-verifier", "source_address": 0x104E0, "resolution": "function", "function_address": 0x104E0},
            {"id": "signature-workflow-caller", "source_address": 0x10A88, "resolution": "instruction-only", "function_address": None},
        ],
        "write_orchestrator_identified": False,
        "completion_verification_identified": False,
        "target_transferable": False,
    },
    "sauu_boundaries": [
        {"id": "guard-dispatch", "status": "BOUNDED_CONTROL", "address": 0xDF5C, "semantic": "model-region-version guard handler"},
        {"id": "model-compare", "status": "BOUNDED_CONTROL", "address": 0xDEA2, "semantic": "model comparison helper"},
        {"id": "region-compare", "status": "BOUNDED_CONTROL", "address": 0xDE84, "semantic": "region comparison helper"},
        {"id": "version-compare", "status": "BOUNDED_CONTROL", "address": 0xDEC0, "semantic": "version comparison helper"},
        {"id": "verification-key-hash", "status": "BOUNDED_CONTROL", "address": 0x10368, "semantic": "verification-key hash workflow"},
        {"id": "signature-verifier", "status": "BOUNDED_CONTROL", "address": 0x104E0, "semantic": "package signature verification helper"},
        {"id": "signature-workflow-caller", "status": "BOUNDED_CONTROL", "address": 0x10A88, "semantic": "signature workflow instruction site; no containing function resolved"},
        {"id": "write-orchestrator", "status": "UNESTABLISHED", "address": None, "semantic": "complete ordered stock write workflow"},
        {"id": "completion-verification", "status": "UNESTABLISHED", "address": None, "semantic": "post-write verification and safe terminal state"},
    ],
    "conclusion": "The different-model control proves a persistent updater boot script chain into an enforced receiver and signature workflow. It does not identify the original α6400 pre-normal selector, installing receiver, complete write order, completion verification, or recovery behavior.",
}


def _reject_forbidden_fields(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise UpdaterControlBootstrapError("Control graph keys must be text")
            normalized = key.strip().lower().replace("-", "_")
            if normalized in _FORBIDDEN_KEYS:
                raise UpdaterControlBootstrapError(
                    "Raw, secret, device, or operational fields are forbidden"
                )
            _reject_forbidden_fields(item)
    elif isinstance(value, list):
        for item in value:
            _reject_forbidden_fields(item)


def _require_exact_fields(value: object, fields: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise UpdaterControlBootstrapError(f"{label} fields are not exact")
    return value


def _sauu_address(value: object, label: str) -> int:
    if (
        type(value) is not int
        or not _SAUU_ADDRESS_MIN <= value < _SAUU_ADDRESS_MAX
        or value % 2
    ):
        raise UpdaterControlBootstrapError(f"{label} is outside pinned sauu code")
    return value


def _bounded_count(value: object, maximum: int, label: str) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise UpdaterControlBootstrapError(f"{label} is invalid")
    return value


def normalize_sauu_control_export(document: object) -> dict:
    """Validate and canonicalize a metadata-only, bounded sauu control graph."""

    _reject_forbidden_fields(document)
    export = _require_exact_fields(document, _SAUU_TOP_FIELDS, "sauu export")
    if export["schema_version"] != 1 or type(export["schema_version"]) is not int:
        raise UpdaterControlBootstrapError("sauu export schema is invalid")
    if (
        export["program"] != _SAUU_PROGRAM
        or export["sha256"] != _SAUU_SHA256
        or not _SHA256_RE.fullmatch(export["sha256"])
        or export["file_size"] != _SAUU_FILE_SIZE
        or type(export["file_size"]) is not int
    ):
        raise UpdaterControlBootstrapError("sauu export identity is invalid")
    if export["analysis_mode"] != {"read_only": True, "noanalysis": True}:
        raise UpdaterControlBootstrapError("sauu export was not read-only/noanalysis")
    if export["truncated"] is not False:
        raise UpdaterControlBootstrapError("truncated sauu control evidence is invalid")

    roots = export["roots"]
    if not isinstance(roots, list) or len(roots) != len(_SAUU_ROOTS):
        raise UpdaterControlBootstrapError("sauu roots are incomplete")
    normalized_roots = []
    for item, (expected_id, expected_source) in zip(roots, _SAUU_ROOTS):
        root = _require_exact_fields(
            item,
            {"id", "source_address", "resolution", "function_address"},
            "sauu root",
        )
        if root["id"] != expected_id or root["source_address"] != expected_source:
            raise UpdaterControlBootstrapError("sauu root identity or order is invalid")
        _sauu_address(root["source_address"], "sauu root source")
        if expected_id == "signature-workflow-caller":
            if root["resolution"] != "instruction-only" or root["function_address"] is not None:
                raise UpdaterControlBootstrapError(
                    "unresolved sauu instruction root was promoted to a function"
                )
        else:
            if root["resolution"] != "function":
                raise UpdaterControlBootstrapError("sauu function root is unresolved")
            _sauu_address(root["function_address"], "sauu root function")
        normalized_roots.append(dict(root))

    functions = export["functions"]
    if not isinstance(functions, list) or not 1 <= len(functions) <= _SAUU_MAX_FUNCTIONS:
        raise UpdaterControlBootstrapError("sauu function set is invalid")
    normalized_functions = []
    function_addresses = set()
    for item in functions:
        function = _require_exact_fields(item, {"address", "depth"}, "sauu function")
        address = _sauu_address(function["address"], "sauu function address")
        depth = _bounded_count(function["depth"], _SAUU_MAX_DEPTH, "sauu function depth")
        if address in function_addresses:
            raise UpdaterControlBootstrapError("sauu function addresses are duplicated")
        function_addresses.add(address)
        normalized_functions.append({"address": address, "depth": depth})
    if not {
        item["function_address"]
        for item in normalized_roots
        if item["function_address"] is not None
    }.issubset(
        function_addresses
    ):
        raise UpdaterControlBootstrapError("sauu roots are disconnected from graph")

    calls = export["calls"]
    if not isinstance(calls, list) or len(calls) > _SAUU_MAX_CALLS:
        raise UpdaterControlBootstrapError("sauu call set is invalid")
    normalized_calls = []
    sites = set()
    for item in calls:
        call = _require_exact_fields(
            item, {"caller", "site", "target", "kind"}, "sauu call"
        )
        caller = _sauu_address(call["caller"], "sauu call owner")
        site = _sauu_address(call["site"], "sauu call site")
        if caller not in function_addresses or site in sites:
            raise UpdaterControlBootstrapError("sauu call is disconnected or duplicated")
        sites.add(site)
        kind = call["kind"]
        if kind not in _SAUU_CALL_KINDS:
            raise UpdaterControlBootstrapError("sauu call kind is invalid")
        if kind == "direct":
            target = _sauu_address(call["target"], "sauu call target")
            if target not in function_addresses:
                raise UpdaterControlBootstrapError("sauu direct call target is absent")
        else:
            if call["target"] is not None:
                raise UpdaterControlBootstrapError("unresolved sauu call has a target")
            target = None
        normalized_calls.append(
            {"caller": caller, "site": site, "target": target, "kind": kind}
        )

    root_addresses = {
        item["function_address"]
        for item in normalized_roots
        if item["function_address"] is not None
    }
    adjacency = {address: set() for address in function_addresses}
    for item in normalized_calls:
        if item["kind"] == "direct":
            adjacency[item["caller"]].add(item["target"])
    shortest_depths = {address: 0 for address in root_addresses}
    queue = deque(sorted(root_addresses))
    while queue:
        caller = queue.popleft()
        for target in sorted(adjacency[caller]):
            candidate_depth = shortest_depths[caller] + 1
            if target not in shortest_depths:
                shortest_depths[target] = candidate_depth
                queue.append(target)
    declared_depths = {
        item["address"]: item["depth"] for item in normalized_functions
    }
    if set(shortest_depths) != function_addresses or shortest_depths != declared_depths:
        raise UpdaterControlBootstrapError(
            "sauu functions are unrooted or have inconsistent shortest depths"
        )

    unresolved_direct = _bounded_count(
        export["unresolved_direct_calls"], _SAUU_MAX_CALLS, "unresolved direct count"
    )
    unresolved_indirect = _bounded_count(
        export["unresolved_indirect_calls"],
        _SAUU_MAX_CALLS,
        "unresolved indirect count",
    )
    if unresolved_direct != sum(
        item["kind"] == "unresolved-direct" for item in normalized_calls
    ) or unresolved_indirect != sum(
        item["kind"] == "unresolved-indirect" for item in normalized_calls
    ):
        raise UpdaterControlBootstrapError("sauu unresolved call counts disagree")
    max_depth = _bounded_count(export["max_depth"], _SAUU_MAX_DEPTH, "maximum depth")
    if max_depth != max(item["depth"] for item in normalized_functions):
        raise UpdaterControlBootstrapError("sauu maximum depth disagrees")

    normalized_functions.sort(key=lambda item: item["address"])
    normalized_calls.sort(
        key=lambda item: (
            item["caller"],
            item["site"],
            item["kind"],
            -1 if item["target"] is None else item["target"],
        )
    )
    normalized = {
        "schema_version": 1,
        "program": _SAUU_PROGRAM,
        "sha256": _SAUU_SHA256,
        "file_size": _SAUU_FILE_SIZE,
        "analysis_mode": {"read_only": True, "noanalysis": True},
        "roots": normalized_roots,
        "functions": normalized_functions,
        "calls": normalized_calls,
        "unresolved_direct_calls": unresolved_direct,
        "unresolved_indirect_calls": unresolved_indirect,
        "max_depth": max_depth,
        "truncated": False,
    }
    if normalized != export:
        raise UpdaterControlBootstrapError("sauu export is not canonical")
    return deepcopy(normalized)


def summarize_sauu_control_export(document: object) -> dict:
    """Derive a digest-pinned summary without retaining the raw call graph."""

    normalized = normalize_sauu_control_export(document)
    encoded = (
        json.dumps(normalized, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return {
        "program": normalized["program"],
        "program_sha256": normalized["sha256"],
        "canonical_export_sha256": hashlib.sha256(encoded).hexdigest(),
        "analysis_mode": deepcopy(normalized["analysis_mode"]),
        "function_count": len(normalized["functions"]),
        "call_count": len(normalized["calls"]),
        "unresolved_direct_calls": normalized["unresolved_direct_calls"],
        "unresolved_indirect_calls": normalized["unresolved_indirect_calls"],
        "max_depth": normalized["max_depth"],
        "truncated": False,
        "root_resolutions": deepcopy(normalized["roots"]),
        "write_orchestrator_identified": False,
        "completion_verification_identified": False,
        "target_transferable": False,
    }


def validate_updater_control_bootstrap(document: object) -> dict:
    """Return an isolated graph only for the exact non-transferable control result."""

    _reject_forbidden_fields(document)
    if not isinstance(document, dict) or document != EXPECTED_BOOTSTRAP:
        raise UpdaterControlBootstrapError(
            "Updater control bootstrap is not the pinned fail-closed result"
        )
    return deepcopy(document)
