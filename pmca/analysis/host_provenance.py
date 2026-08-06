"""Validation for bounded host-isolation and portable-tool provenance."""

import copy
import re
from pathlib import PurePosixPath
from urllib.parse import urlparse


class HostProvenanceError(ValueError):
    """Raised when host isolation provenance is incomplete or unsafe."""


def validate_host_isolation_provenance(document: object) -> dict:
    """Return an independent provenance document after validation."""
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "host",
        "isolation",
        "tools",
    }:
        raise HostProvenanceError("Host provenance fields are invalid")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise HostProvenanceError("Host provenance schema version is unsupported")

    host = document["host"]
    if not isinstance(host, dict) or set(host) != {
        "platform",
        "storage_ceiling_gib",
        "camera_policy",
        "reboot_barrier",
    }:
        raise HostProvenanceError("Host fields are invalid")
    if host != {
        "platform": "windows-x64",
        "storage_ceiling_gib": 40,
        "camera_policy": "physically-disconnected",
        "reboot_barrier": "all-other-codex-tasks-finished",
    }:
        raise HostProvenanceError("Host safety policy is invalid")

    isolation = document["isolation"]
    isolation_fields = {
        "name",
        "version",
        "source",
        "archive_verification",
        "authenticode",
        "restore_point",
        "service",
        "driver",
    }
    if not isinstance(isolation, dict) or set(isolation) != isolation_fields:
        raise HostProvenanceError("Isolation fields are invalid")
    expected_isolation = {
        "name": "Sandboxie Plus",
        "version": "1.18.1",
        "source": "winget:Sandboxie.Plus",
        "archive_verification": "winget-sha256-verified",
        "authenticode": "valid",
        "restore_point": "created",
        "service": "running",
        "driver": "running",
    }
    if isolation != expected_isolation:
        raise HostProvenanceError("Isolation state is not the approved baseline")

    tools = document["tools"]
    if not isinstance(tools, list) or not tools:
        raise HostProvenanceError("At least one portable tool is required")
    tool_fields = {
        "name",
        "version",
        "source_url",
        "archive",
        "sha256",
        "verification",
        "path_category",
        "purpose",
    }
    names = set()
    digest_pattern = re.compile(r"[0-9a-f]{64}\Z")
    allowed_domains = {
        "github.com",
        "learn.microsoft.com",
        "download.sysinternals.com",
        "aka.ms",
    }
    allowed_verification = {
        "published-sha256",
        "release-asset-sha256",
        "authenticode",
    }
    for tool in tools:
        if not isinstance(tool, dict) or set(tool) != tool_fields:
            raise HostProvenanceError("Portable tool fields are invalid")
        name = tool["name"]
        if (
            not isinstance(name, str)
            or not 1 <= len(name) <= 64
            or not name.isprintable()
            or name in names
        ):
            raise HostProvenanceError("Portable tool name is invalid or duplicated")
        names.add(name)
        for field in ("version", "archive", "purpose"):
            value = tool[field]
            if (
                not isinstance(value, str)
                or not 1 <= len(value) <= 160
                or not value.isprintable()
            ):
                raise HostProvenanceError(f"Portable tool {field} is invalid")
        archive = tool["archive"]
        if (
            "/" in archive
            or "\\" in archive
            or ":" in archive
            or not archive.casefold().endswith(".zip")
        ):
            raise HostProvenanceError("Portable tool archive is invalid")
        source = tool["source_url"]
        parsed = urlparse(source) if isinstance(source, str) else None
        if (
            parsed is None
            or parsed.scheme != "https"
            or parsed.hostname not in allowed_domains
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise HostProvenanceError("Portable tool source URL is invalid")
        if (
            not isinstance(tool["sha256"], str)
            or not digest_pattern.fullmatch(tool["sha256"])
        ):
            raise HostProvenanceError("Portable tool digest is invalid")
        if tool["verification"] not in allowed_verification:
            raise HostProvenanceError("Portable tool verification is invalid")
        path = tool["path_category"]
        if not isinstance(path, str) or "\\" in path:
            raise HostProvenanceError("Portable tool path category is invalid")
        pure_path = PurePosixPath(path)
        if (
            pure_path.is_absolute()
            or len(pure_path.parts) != 3
            or pure_path.parts[:2] != (".artifacts", "tools")
            or pure_path.parts[2] in {"", ".", ".."}
        ):
            raise HostProvenanceError("Portable tool path category is invalid")

    return copy.deepcopy(document)
