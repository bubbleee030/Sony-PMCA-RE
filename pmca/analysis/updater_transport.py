"""Synthetic-only replay boundary for offline updater transport research."""

import copy
import re


class TransportHarnessError(ValueError):
    """Raised when replay evidence or a synthetic exchange is not exact."""


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_OPERATION = re.compile(r"synthetic-[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_HEX = re.compile(r"(?:[0-9a-f]{2})+\Z")
_TRANSCRIPT_FIELDS = {
    "schema_version",
    "transport",
    "camera_access",
    "model",
    "exchanges",
}
_EXCHANGE_FIELDS = {
    "sequence",
    "operation",
    "request_hex",
    "response_hex",
    "timeout_ms",
    "elapsed_ms",
}
_OBSERVATION_FIELDS = {
    "schema_version",
    "subject",
    "camera_policy",
    "dynamic_boundary",
    "static_boundary",
    "harness",
    "inferences",
    "unresolved",
    "conclusion",
}
_DYNAMIC_FIELDS = {
    "classification",
    "source",
    "boundary",
    "camera_present",
    "device_open_group_count",
    "protocol_reached",
}
_STATIC_FIELDS = {"classification", "component_role", "sha256", "evidence"}
_HARNESS_FIELDS = {
    "classification",
    "mode",
    "physical_device_enumeration",
    "physical_device_open",
    "unknown_request_action",
    "model_mismatch_action",
}
_INFERENCE_FIELDS = {"classification", "claim", "basis"}
_UNRESOLVED_FIELDS = {"classification", "gate", "next_experiment"}
_STATIC_ROLES = {
    "signed-updater-engine",
    "signed-storage-identity-helper",
}
_EVIDENCE_PREFIXES = ("imports:", "exports:", "ioctl:", "string:")


def _bounded_text(value: object, label: str, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or not value.isprintable()
        or "\r" in value
        or "\n" in value
        or "\\" in value
    ):
        raise TransportHarnessError(f"{label} is invalid")
    return value


def _positive_int(value: object, label: str, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise TransportHarnessError(f"{label} is invalid")
    return value


def _synthetic_bytes(value: object, label: str) -> bytes:
    if (
        not isinstance(value, str)
        or not 2 <= len(value) <= 8192
        or len(value) % 2
        or not _HEX.fullmatch(value)
    ):
        raise TransportHarnessError(f"{label} is invalid")
    return bytes.fromhex(value)


def validate_synthetic_transcript(document: object) -> dict:
    """Validate and copy an exact transcript containing only synthetic bytes."""
    if not isinstance(document, dict) or set(document) != _TRANSCRIPT_FIELDS:
        raise TransportHarnessError("Synthetic transcript fields are invalid")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise TransportHarnessError("Synthetic transcript schema is unsupported")
    if document["transport"] != "synthetic-replay-only":
        raise TransportHarnessError("Synthetic transcript transport is invalid")
    if document["camera_access"] != "forbidden":
        raise TransportHarnessError("Synthetic transcript camera policy is invalid")
    if document["model"] != "ILCE-6400":
        raise TransportHarnessError("Synthetic transcript model is invalid")

    exchanges = document["exchanges"]
    if not isinstance(exchanges, list) or not 1 <= len(exchanges) <= 64:
        raise TransportHarnessError("Synthetic exchanges are invalid")
    operations = set()
    for expected_sequence, exchange in enumerate(exchanges):
        if not isinstance(exchange, dict) or set(exchange) != _EXCHANGE_FIELDS:
            raise TransportHarnessError("Synthetic exchange fields are invalid")
        if (
            type(exchange["sequence"]) is not int
            or exchange["sequence"] != expected_sequence
        ):
            raise TransportHarnessError("Synthetic exchange sequence is invalid")
        operation = exchange["operation"]
        if not isinstance(operation, str) or not _OPERATION.fullmatch(operation):
            raise TransportHarnessError("Synthetic exchange operation is invalid")
        if operation in operations:
            raise TransportHarnessError("Synthetic exchange operation is duplicated")
        operations.add(operation)
        _synthetic_bytes(exchange["request_hex"], "Synthetic request")
        _synthetic_bytes(exchange["response_hex"], "Synthetic response")
        _positive_int(exchange["timeout_ms"], "Synthetic timeout", 10_000)
        elapsed = exchange["elapsed_ms"]
        if type(elapsed) is not int or not 0 <= elapsed <= 60_000:
            raise TransportHarnessError("Synthetic elapsed time is invalid")
    return copy.deepcopy(document)


class SyntheticTransportHarness:
    """Replay a fixed transcript without any operating-system transport backend."""

    def __init__(self, transcript: object):
        self._transcript = validate_synthetic_transcript(transcript)
        self._position = 0
        self._terminated = False

    @property
    def complete(self) -> bool:
        return self._position == len(self._transcript["exchanges"])

    @property
    def terminated(self) -> bool:
        return self._terminated

    def _stop(self, message: str):
        self._terminated = True
        raise TransportHarnessError(message)

    def exchange(
        self,
        operation: str,
        request: bytes,
        *,
        model: str,
        expected_response_length: int,
        timeout_ms: int,
    ) -> bytes:
        """Return the next exact synthetic response or terminate permanently."""
        if self._terminated:
            raise TransportHarnessError("Synthetic replay is already terminated")
        if self.complete:
            self._stop("Synthetic replay has no remaining exchange")
        if not isinstance(request, bytes):
            self._stop("Synthetic request type is invalid")
        if type(expected_response_length) is not int or expected_response_length <= 0:
            self._stop("Synthetic expected response length is invalid")
        if type(timeout_ms) is not int or timeout_ms <= 0:
            self._stop("Synthetic timeout is invalid")

        fixture = self._transcript["exchanges"][self._position]
        expected_request = bytes.fromhex(fixture["request_hex"])
        response = bytes.fromhex(fixture["response_hex"])
        if model != self._transcript["model"]:
            self._stop("Synthetic model identity mismatch")
        if operation != fixture["operation"]:
            self._stop("Synthetic exchange ordering or operation mismatch")
        if request != expected_request:
            self._stop("Synthetic request bytes mismatch")
        if timeout_ms != fixture["timeout_ms"]:
            self._stop("Synthetic timeout contract mismatch")
        if expected_response_length != len(response):
            self._stop("Synthetic response length contract mismatch")
        if fixture["elapsed_ms"] > timeout_ms:
            self._stop("Synthetic exchange exceeded its timeout")

        self._position += 1
        return response


def _validate_evidence(values: object, label: str) -> list[str]:
    if not isinstance(values, list) or not 1 <= len(values) <= 16:
        raise TransportHarnessError(f"{label} is invalid")
    result = []
    for value in values:
        text = _bounded_text(value, label, 160)
        if not text.startswith(_EVIDENCE_PREFIXES):
            raise TransportHarnessError(f"{label} kind is invalid")
        result.append(text)
    if len(set(result)) != len(result):
        raise TransportHarnessError(f"{label} is duplicated")
    return result


def validate_transport_observations(document: object) -> dict:
    """Validate bounded transport evidence without promoting inferred protocol data."""
    if not isinstance(document, dict) or set(document) != _OBSERVATION_FIELDS:
        raise TransportHarnessError("Transport observation fields are invalid")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise TransportHarnessError("Transport observation schema is unsupported")
    if document["subject"] != "ILCE-6400 firmware updater transport boundary":
        raise TransportHarnessError("Transport observation subject is invalid")
    if document["camera_policy"] != "physically-disconnected":
        raise TransportHarnessError("Transport camera policy is invalid")

    dynamic = document["dynamic_boundary"]
    if not isinstance(dynamic, dict) or set(dynamic) != _DYNAMIC_FIELDS:
        raise TransportHarnessError("Dynamic boundary fields are invalid")
    if dynamic != {
        "classification": "OBSERVATION",
        "source": "analysis/a6400-updater-no-camera.json",
        "boundary": "no-camera-boundary",
        "camera_present": False,
        "device_open_group_count": 0,
        "protocol_reached": False,
    }:
        raise TransportHarnessError("Dynamic boundary claim exceeds the evidence")

    components = document["static_boundary"]
    if not isinstance(components, list) or len(components) != len(_STATIC_ROLES):
        raise TransportHarnessError("Static boundary components are invalid")
    roles = set()
    for component in components:
        if not isinstance(component, dict) or set(component) != _STATIC_FIELDS:
            raise TransportHarnessError("Static boundary fields are invalid")
        if component["classification"] != "OBSERVATION":
            raise TransportHarnessError("Static boundary classification is invalid")
        role = component["component_role"]
        if role not in _STATIC_ROLES or role in roles:
            raise TransportHarnessError("Static boundary role is invalid or duplicated")
        roles.add(role)
        digest = component["sha256"]
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise TransportHarnessError("Static boundary digest is invalid")
        _validate_evidence(component["evidence"], "Static boundary evidence")
    if roles != _STATIC_ROLES:
        raise TransportHarnessError("Static boundary roles are incomplete")

    harness = document["harness"]
    if not isinstance(harness, dict) or set(harness) != _HARNESS_FIELDS:
        raise TransportHarnessError("Harness observation fields are invalid")
    if harness != {
        "classification": "OBSERVATION",
        "mode": "synthetic-replay-only",
        "physical_device_enumeration": "not-implemented",
        "physical_device_open": "not-implemented",
        "unknown_request_action": "terminate",
        "model_mismatch_action": "terminate",
    }:
        raise TransportHarnessError("Harness is not fail-closed")

    inferences = document["inferences"]
    if not isinstance(inferences, list) or not 1 <= len(inferences) <= 16:
        raise TransportHarnessError("Transport inferences are invalid")
    for inference in inferences:
        if not isinstance(inference, dict) or set(inference) != _INFERENCE_FIELDS:
            raise TransportHarnessError("Transport inference fields are invalid")
        if inference["classification"] != "INFERENCE":
            raise TransportHarnessError("Transport inference classification is invalid")
        _bounded_text(inference["claim"], "Transport inference claim")
        _validate_evidence(inference["basis"], "Transport inference basis")

    unresolved = document["unresolved"]
    if not isinstance(unresolved, list) or not 1 <= len(unresolved) <= 32:
        raise TransportHarnessError("Transport unresolved gates are invalid")
    gates = set()
    for gate in unresolved:
        if not isinstance(gate, dict) or set(gate) != _UNRESOLVED_FIELDS:
            raise TransportHarnessError("Transport unresolved fields are invalid")
        if gate["classification"] != "UNRESOLVED":
            raise TransportHarnessError("Transport unresolved classification is invalid")
        name = _bounded_text(gate["gate"], "Transport unresolved gate", 80)
        if name in gates or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
            raise TransportHarnessError("Transport unresolved gate is invalid")
        gates.add(name)
        _bounded_text(gate["next_experiment"], "Transport next experiment")

    if document["conclusion"] != (
        "No physical transport command has been observed; protocol replay remains "
        "synthetic only."
    ):
        raise TransportHarnessError("Transport conclusion is invalid")
    return copy.deepcopy(document)
