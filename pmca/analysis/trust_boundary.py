"""Fail-closed source and report checks for the alpha 6400 trust boundary."""

import ast
import copy
import re


class TrustBoundaryError(ValueError):
    """Raised when trust-boundary evidence is malformed or overclaimed."""


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_TOP_FIELDS = {
    "schema_version",
    "subject",
    "camera_policy",
    "camera_executed",
    "bypass_established",
    "installable",
    "host_verification",
    "updater_shell",
    "camera_guard",
    "service_acquisition",
    "observations",
    "inferences",
    "unresolved",
    "conclusion",
}
_HOST_FIELDS = {
    "engine_sha256",
    "component_count",
    "mapped_images_scanned",
    "firmware_verifier_import_hits",
    "mapped_key_marker_hits",
    "data_protection_imports",
    "dynamic_libraries",
    "dynamic_symbols",
    "evidence_sources",
}
_SHELL_FIELDS = {
    "repository",
    "target_architecture",
    "supported_body_architectures",
    "generation_four_decryption_commit",
    "generation_four_decryption_date",
    "generation_four_encrypt",
    "generation_four_body_present",
    "target_header_present",
    "unsupported_architecture_skip_commit",
    "signed_architecture_documentation_commit",
    "latest_updater_shell_commit",
}
_GUARD_FIELDS = {
    "protocol_version",
    "candidate_scope",
    "initial_sequence_payload_bytes",
    "success_before_eof_permitted",
    "camera_decrypted_prefix_bytes",
    "full_resend_after_reconnect",
    "full_resend_candidate_scope",
    "command_sequence",
    "guard_precedes_mode_switch",
    "camera_rejection_statuses",
    "host_firmware_verifier_located",
}
_SERVICE_FIELDS = {
    "status",
    "camera_connected",
    "camera_executed",
    "separate_from_fdat_guard",
    "authentication_hash_variants",
    "implementation_has_mutating_commands",
    "allowed_operations",
    "forbidden_operations",
    "acquisition_sequence",
    "compatibility_source",
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
_EXPECTED_BODY_ARCHITECTURES = [
    "CXD4105",
    "CXD4115",
    "CXD4115_ilc",
    "CXD4120",
    "CXD4132",
    "CXD90014",
]
_UPDATE_SEQUENCE = [
    "init",
    "checkGuard",
    "getFirmwareVersion",
    "switchMode",
    "write" + "Firmware",
    "complete",
]
_READ_CAPABILITIES = ["readFile", "readMemory"]
_ALLOWED_SERVICE_OPERATIONS = [
    "identity",
    "read-file",
    "read-memory",
    "read-bootrom",
]
_FORBIDDEN_SERVICE_OPERATIONS = [
    "interactive-shell",
    "write-file",
    "write-memory",
    "write-backup",
    "firmware-update",
]


def _require_fields(value: object, fields: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise TrustBoundaryError(f"{label} fields are invalid")
    return value


def _bounded_text(value: object, label: str, maximum: int = 1000) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or "\r" in value
        or "\n" in value
        or not value.isprintable()
    ):
        raise TrustBoundaryError(f"{label} is invalid")
    return value


def _positive_int(value: object, label: str, maximum: int = 10_000) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise TrustBoundaryError(f"{label} is invalid")
    return value


def _reject_reconstructive_fields(value: object) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str) or key.casefold() in _FORBIDDEN_KEYS:
                raise TrustBoundaryError("Trust-boundary report contains a forbidden field")
            _reject_reconstructive_fields(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_reconstructive_fields(nested)


def _literal_assignment(tree: ast.AST, name: str) -> object:
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in node.targets
        ):
            try:
                return ast.literal_eval(node.value)
            except (TypeError, ValueError) as exc:
                raise TrustBoundaryError(f"{name} is not a literal") from exc
    raise TrustBoundaryError(f"{name} was not found")


def _function(tree: ast.AST, name: str) -> ast.FunctionDef:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise TrustBoundaryError(f"Function {name} was not found")


def characterize_pmca_sources(
    *,
    pack_source: str,
    fdat_source: str,
    usb_command_source: str,
    service_backend_source: str,
    updater_protocol_source: str,
) -> dict:
    """Derive the updater-shell and read-only service split from source text."""
    sources = (pack_source, fdat_source, usb_command_source, updater_protocol_source, service_backend_source)
    if any(not isinstance(source, str) or not source for source in sources):
        raise TrustBoundaryError("Source text is invalid")
    try:
        pack_tree, fdat_tree, usb_tree, updater_tree, service_tree = map(ast.parse, sources)
    except SyntaxError as exc:
        raise TrustBoundaryError("Source text is not valid Python") from exc

    body_files = _literal_assignment(pack_tree, "bodyFiles")
    if not isinstance(body_files, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in body_files.items()
    ):
        raise TrustBoundaryError("Updater-shell body map is invalid")
    body_architectures = list(body_files)

    fourth_generation = None
    for node in ast.walk(fdat_tree):
        if isinstance(node, ast.ClassDef) and node.name == "AesCbcCrypter":
            fourth_generation = node
            break
    if fourth_generation is None:
        raise TrustBoundaryError("Fourth-generation crypter was not found")
    encrypt_method = _function(fourth_generation, "encrypt")
    unsupported = any(
        isinstance(node, ast.Raise)
        and isinstance(node.exc, ast.Call)
        and node.exc.args
        and isinstance(node.exc.args[0], ast.Constant)
        and node.exc.args[0].value == "Encryption not supported"
        for node in ast.walk(encrypt_method)
    )
    if not unsupported:
        raise TrustBoundaryError("Fourth-generation encryption boundary changed")
    if not any(
        isinstance(node, ast.Constant) and node.value == "CXD90045"
        for node in ast.walk(fdat_tree)
    ):
        raise TrustBoundaryError("Fourth-generation architecture was not found")

    update_function = _function(usb_tree, "firmwareUpdateCommandInternal")
    ordered_calls = sorted(
        (
            node.lineno,
            node.func.attr,
        )
        for node in ast.walk(update_function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "dev"
        and node.func.attr in _UPDATE_SEQUENCE
    )
    update_sequence = [name for _, name in ordered_calls]
    if update_sequence != _UPDATE_SEQUENCE:
        raise TrustBoundaryError("Firmware update call sequence changed")

    send_write = _function(updater_tree, "_sendWriteCommands")
    initial_window_is_zero = any(
        isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "windowSize"
            for target in node.targets
        )
        and isinstance(node.value, ast.Constant)
        and node.value.value == 0
        for node in send_write.body
    )
    if not initial_window_is_zero:
        raise TrustBoundaryError("Updater write handshake changed")

    guard_can_finish_before_eof = any(
        isinstance(node, ast.If)
        and isinstance(node.test, ast.Compare)
        and isinstance(node.test.left, ast.Name)
        and node.test.left.id == "status"
        and any(isinstance(child, ast.Break) for child in ast.walk(node))
        and not any(
            isinstance(child, ast.Name) and child.id == "written"
            for child in ast.walk(node.test)
        )
        for node in ast.walk(send_write)
    )
    if not guard_can_finish_before_eof:
        raise TrustBoundaryError("Updater guard termination changed")

    reseeks = [
        node
        for node in ast.walk(update_function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "file"
        and node.func.attr == "seek"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "offset"
    ]
    recursive_restart = any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "firmwareUpdateCommandInternal"
        for node in ast.walk(update_function)
    )
    if len(reseeks) != 2 or not recursive_restart:
        raise TrustBoundaryError("Updater-mode FDAT restart changed")
    service_class = next(
        (
            node
            for node in ast.walk(service_tree)
            if isinstance(node, ast.ClassDef) and node.name == "SenserPlatformBackend"
        ),
        None,
    )
    if service_class is None:
        raise TrustBoundaryError("Service backend was not found")
    service_methods = {
        node.name for node in service_class.body if isinstance(node, ast.FunctionDef)
    }
    if not set(_READ_CAPABILITIES).issubset(service_methods):
        raise TrustBoundaryError("Read-only service capabilities are incomplete")
    service_function = _function(usb_tree, "senserShellCommand")
    service_calls = {
        node.func.id
        for node in ast.walk(service_function)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }

    return {
        "updater_shell_body_architectures": body_architectures,
        "generation_four_architecture": "CXD90045",
        "generation_four_encrypt": "not-supported",
        "firmware_update_sequence": update_sequence,
        "service_read_capabilities": _READ_CAPABILITIES.copy(),
        "guard_initial_window_bytes": 0,
        "guard_can_finish_before_eof": guard_can_finish_before_eof,
        "full_fdat_reseek_after_updater_reconnect": True,
        "guard_precedes_mode_switch": update_sequence.index("checkGuard")
        < update_sequence.index("switchMode"),
        "service_path_is_separate": "firmwareUpdateCommandInternal" not in service_calls,
    }


def _validate_claims(document: dict) -> None:
    for field, classification in (
        ("observations", "OBSERVATION"),
        ("inferences", "INFERENCE"),
        ("unresolved", "UNRESOLVED"),
    ):
        claims = document[field]
        if not isinstance(claims, list) or not 1 <= len(claims) <= 24:
            raise TrustBoundaryError(f"{field} claims are invalid")
        for claim in claims:
            _require_fields(claim, _CLAIM_FIELDS, "Trust-boundary claim")
            if claim["classification"] != classification:
                raise TrustBoundaryError("Trust-boundary claim classification is invalid")
            _bounded_text(claim["source"], "Trust-boundary claim source", 300)
            _bounded_text(claim["claim"], "Trust-boundary claim")


def validate_trust_boundary_report(document: object) -> dict:
    """Validate evidence without converting absence-of-evidence into a bypass."""
    _require_fields(document, _TOP_FIELDS, "Trust-boundary report")
    _reject_reconstructive_fields(document)
    if document["schema_version"] != 1:
        raise TrustBoundaryError("Trust-boundary schema is unsupported")
    if document["subject"] != "ILCE-6400 updater and service trust boundary":
        raise TrustBoundaryError("Trust-boundary subject is invalid")
    if document["camera_policy"] != "physically-disconnected":
        raise TrustBoundaryError("Trust-boundary camera policy is invalid")
    for field in ("camera_executed", "bypass_established", "installable"):
        if document[field] is not False:
            raise TrustBoundaryError(f"{field} must remain false")

    host = _require_fields(document["host_verification"], _HOST_FIELDS, "Host verification")
    if not isinstance(host["engine_sha256"], str) or not _DIGEST.fullmatch(
        host["engine_sha256"]
    ):
        raise TrustBoundaryError("Host engine digest is invalid")
    if host["engine_sha256"] != (
        "8f2e8b229ef9e49a874cbf920301aba078727cebc490c891a992de60ff8a3528"
    ):
        raise TrustBoundaryError("Host engine digest is unknown")
    if _positive_int(host["component_count"], "Component count") != 29:
        raise TrustBoundaryError("Host component inventory is incomplete")
    if _positive_int(host["mapped_images_scanned"], "Mapped image count") != 30:
        raise TrustBoundaryError("Mapped image inventory is incomplete")
    if host["firmware_verifier_import_hits"] != 0:
        raise TrustBoundaryError("Host verifier claim exceeds the scan")
    if host["mapped_key_marker_hits"] != 0:
        raise TrustBoundaryError("Mapped key-marker claim exceeds the scan")
    expected_data_protection = [
        "CRYPT32.dll!CryptProtectData",
        "CRYPT32.dll!CryptUnprotectData",
    ]
    if host["data_protection_imports"] != expected_data_protection:
        raise TrustBoundaryError("Host data-protection imports are invalid")
    if host["dynamic_libraries"] != [
        "FirmwareUpdaterImg.dll",
        "XpStorageDevice_WinXp2k.dll",
    ]:
        raise TrustBoundaryError("Host dynamic-library evidence is invalid")
    if host["dynamic_symbols"] != [
        "InitializeConditionVariable",
        "SleepConditionVariableCS",
        "WakeAllConditionVariable",
        "XpStgDevGetVenIdAndProdId",
    ]:
        raise TrustBoundaryError("Host dynamic-symbol evidence is invalid")
    evidence_sources = host["evidence_sources"]
    if not isinstance(evidence_sources, list) or not 1 <= len(evidence_sources) <= 12:
        raise TrustBoundaryError("Host evidence sources are invalid")
    for source in evidence_sources:
        _bounded_text(source, "Host evidence source", 300)

    shell = _require_fields(document["updater_shell"], _SHELL_FIELDS, "Updater shell")
    if shell["repository"] != "https://github.com/ma1co/Sony-PMCA-RE":
        raise TrustBoundaryError("Updater-shell repository is invalid")
    if shell["target_architecture"] != "CXD90045":
        raise TrustBoundaryError("Updater-shell target architecture is invalid")
    if shell["supported_body_architectures"] != _EXPECTED_BODY_ARCHITECTURES:
        raise TrustBoundaryError("Updater-shell body architectures are invalid")
    for field in (
        "generation_four_decryption_commit",
        "unsupported_architecture_skip_commit",
        "signed_architecture_documentation_commit",
        "latest_updater_shell_commit",
    ):
        value = shell[field]
        if not isinstance(value, str) or not _COMMIT.fullmatch(value):
            raise TrustBoundaryError(f"{field} is invalid")
    if shell["generation_four_decryption_commit"] != (
        "9d1ccf489c11fcaf445b4fa717e3413617d99c76"
    ):
        raise TrustBoundaryError("Generation-four decryption provenance changed")
    if shell["generation_four_decryption_date"] != "2019-03-21":
        raise TrustBoundaryError("Generation-four decryption date is invalid")
    if shell["generation_four_encrypt"] != "not-supported":
        raise TrustBoundaryError("Generation-four encryption was overclaimed")
    if shell["generation_four_body_present"] is not False:
        raise TrustBoundaryError("Generation-four updater body was overclaimed")
    if shell["target_header_present"] is not False:
        raise TrustBoundaryError("Target updater header was overclaimed")
    if shell["unsupported_architecture_skip_commit"] != (
        "0aaf3265de3502791c1e92b2e33ad52e423485ef"
    ):
        raise TrustBoundaryError("Unsupported-architecture provenance changed")
    if shell["signed_architecture_documentation_commit"] != (
        "ee47d5a2582444091184eeec1fa94d89040d7d51"
    ):
        raise TrustBoundaryError("Signed-architecture provenance changed")
    if shell["latest_updater_shell_commit"] != (
        "0ce3c7e8fed88bcd855a80a75eadc518c2e324cb"
    ):
        raise TrustBoundaryError("Updater-shell history boundary changed")

    guard = _require_fields(document["camera_guard"], _GUARD_FIELDS, "Camera guard")
    if guard != {
        "protocol_version": "0x0100",
        "candidate_scope": "first-negotiated-fdat-chunk",
        "initial_sequence_payload_bytes": 0,
        "success_before_eof_permitted": True,
        "camera_decrypted_prefix_bytes": 512,
        "full_resend_after_reconnect": True,
        "full_resend_candidate_scope": "entire-fdat",
        "command_sequence": _UPDATE_SEQUENCE,
        "guard_precedes_mode_switch": True,
        "camera_rejection_statuses": {
            "0x140": "invalid-model",
            "0x141": "invalid-region",
            "0x142": "invalid-version",
        },
        "host_firmware_verifier_located": False,
    }:
        raise TrustBoundaryError("Camera-guard evidence is invalid")

    service = _require_fields(
        document["service_acquisition"], _SERVICE_FIELDS, "Service acquisition"
    )
    if service["status"] != "read-only-candidate":
        raise TrustBoundaryError("Service acquisition status is invalid")
    if service["camera_connected"] is not False or service["camera_executed"] is not False:
        raise TrustBoundaryError("Service acquisition execution was overclaimed")
    if service["separate_from_fdat_guard"] is not True:
        raise TrustBoundaryError("Service and updater paths were conflated")
    if service["authentication_hash_variants"] != ["faulty-sha1", "sha256"]:
        raise TrustBoundaryError("Service authentication evidence is invalid")
    if service["implementation_has_mutating_commands"] is not True:
        raise TrustBoundaryError("Service implementation capability map is invalid")
    if service["allowed_operations"] != _ALLOWED_SERVICE_OPERATIONS:
        raise TrustBoundaryError("Service allowlist is invalid")
    if service["forbidden_operations"] != _FORBIDDEN_SERVICE_OPERATIONS:
        raise TrustBoundaryError("Service denylist is invalid")
    if service["acquisition_sequence"] != [
        "authenticate",
        "read-identity",
        "read-partition-metadata",
        "read-bootrom",
        "hash-and-verify",
        "disconnect",
    ]:
        raise TrustBoundaryError("Service acquisition sequence is invalid")
    _bounded_text(service["compatibility_source"], "Service compatibility source", 300)

    _validate_claims(document)
    _bounded_text(document["conclusion"], "Trust-boundary conclusion")
    return copy.deepcopy(document)
