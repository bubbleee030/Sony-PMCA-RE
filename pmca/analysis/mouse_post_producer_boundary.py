"""Fail-closed evidence contract for the bounded α6400 mouse-post producer scan."""

from __future__ import annotations

import copy
import hashlib
import json
import re


class MousePostProducerBoundaryError(ValueError):
    """Raised when evidence exceeds the bounded static producer result."""


FIRMWARE_INVENTORY = {
    "regular_file_count": 799,
    "elf_file_count": 324,
    "shared_object_count": 150,
    "canonical_sha256": (
        "52ec5e8baf523878a417e3a61f9f16484634a9075d1c6afca2ca8c25940d827c"
    ),
}
SOURCE = {
    "module": "lib/libObj.so",
    "size": 20_860_436,
    "sha256": "60ffd2b0f31f4bc139a7c13a4f62c25cdeb6a531ad5ef35df48471e6e36e88b1",
}
INTERACTION_DEPENDENCY = {
    "report": "analysis/a6400-creative-style-interaction-surface.json",
    "canonical_export_sha256": (
        "cd7c0f1df911248492ddb6542d2b9f225b7ec4a408a910fe896722a83277fa53"
    ),
    "static_post_api_to_widget_delivery_found": True,
    "raw_input_producer_found": False,
}

PUBLIC_APIS = (
    {
        "role": "move",
        "symbol": (
            "_ZN2ux6wgtsys12WidgetSystem13postMouseMoveEhssNS_4core8MsecTimeE"
        ),
        "dynsym_index": 2976,
        "entry": 0x5F2151,
        "normalized_entry": 0x5F2150,
        "size": 0x90,
        "short_name": "postMouseMove",
    },
    {
        "role": "press",
        "symbol": (
            "_ZN2ux6wgtsys12WidgetSystem14postMousePressEhhNS_4core8MsecTimeE"
        ),
        "dynsym_index": 2773,
        "entry": 0x5F21E1,
        "normalized_entry": 0x5F21E0,
        "size": 0x68,
        "short_name": "postMousePress",
    },
    {
        "role": "release",
        "symbol": (
            "_ZN2ux6wgtsys12WidgetSystem16postMouseReleaseEhhNS_4core8MsecTimeE"
        ),
        "dynsym_index": 3785,
        "entry": 0x5F2249,
        "normalized_entry": 0x5F2248,
        "size": 0x68,
        "short_name": "postMouseRelease",
    },
)

_SYMBOL_MATCHES = [
    {
        "role": api["role"],
        "module": SOURCE["module"],
        "dynsym_index": api["dynsym_index"],
        "symbol": api["symbol"],
        "defined": True,
        "entry": api["entry"],
        "size": api["size"],
        "binding": "STB_GLOBAL",
        "visibility": "STV_DEFAULT",
    }
    for api in PUBLIC_APIS
]
SYMBOL_UNIVERSE = {
    "elf_file_count": FIRMWARE_INVENTORY["elf_file_count"],
    "matches": _SYMBOL_MATCHES,
    "external_definitions": [],
    "external_imports": [],
    "short_name_occurrences": [
        {
            "role": api["role"],
            "short_name": api["short_name"],
            "modules": [SOURCE["module"]],
            "occurrence_count": 1,
        }
        for api in PUBLIC_APIS
    ],
}

_ROLES = ("move", "press", "release", "queue_processor")
_EMPTY_BY_ROLE = {role: [] for role in _ROLES}
LIBOBJ_PUBLICATION_SCAN = {
    "scan_methods": [
        "decoded-direct-branch",
        "dynamic-relocation-target",
        "allocated-aligned-pointer",
        "adr-or-pc-immediate",
        "pc-literal-add",
        "movw-movt",
    ],
    "owner_count": 59_614,
    "complete_owner_count": 56_271,
    "incomplete_owner_count": 3_343,
    "direct_inbound_calls": copy.deepcopy(_EMPTY_BY_ROLE),
    "relocation_publications": copy.deepcopy(_EMPTY_BY_ROLE),
    "aligned_pointer_publications": copy.deepcopy(_EMPTY_BY_ROLE),
    "address_materializations": copy.deepcopy(_EMPTY_BY_ROLE),
}
QUEUE_PROCESSOR = {
    "owner": {"start": 0x5F2964, "end": 0x5F2A38},
    "dynamic_symbol_definitions": [],
    "direct_inbound_calls": [],
    "relocation_publications": [],
    "aligned_pointer_publications": [],
    "address_materializations": [],
}

FIRST_UNRESOLVED_BOUNDARY = (
    "external-computed-or-opaque-input-producer-and-queue-processor-invocation"
)
READINESS = "PUBLIC_MOUSE_POST_PIPELINE_PROVEN__RAW_INPUT_PRODUCER_UNRESOLVED"
CLAIMS = {
    "public_mouse_post_api_definitions_found": True,
    "public_api_to_existing_queue_delivery_dependency_found": True,
    "bounded_static_producer_inventory_complete": True,
    "raw_mouse_input_producer_found": False,
    "queue_processor_invocation_found": False,
    "runtime_mouse_input_delivery_proven": False,
    "creative_style_touch_route_found": False,
    "creative_look_touch_route_found": False,
    "runtime_execution_proven": False,
}
CONCLUSION = (
    "The authenticated target defines three public WidgetSystem mouse-post APIs, and the "
    "pinned interaction dependency proves their static queue-to-widget delivery path. A "
    "bounded scan of 59,614 exception-index owners, including 56,271 fully decoded and "
    "3,343 incomplete owners, found no decoded direct caller or static publication for "
    "the APIs or queue processor. Incomplete decode coverage and arbitrary computed, "
    "runtime, external, or opaque paths were not exhausted, so this does not prove that "
    "no runtime or computed producer exists. Raw input delivery, Creative Style touch, "
    "Creative Look behavior, runtime execution, installability, recovery, and camera-test "
    "eligibility remain unestablished."
)

EXPECTED_EXPORT = {
    "schema_version": 1,
    "analysis_mode": {
        "read_only": True,
        "static_elf_metadata": True,
        "source_unchanged": True,
        "camera_access": False,
        "binary_execution": False,
    },
    "firmware_inventory": FIRMWARE_INVENTORY,
    "source": SOURCE,
    "interaction_dependency": INTERACTION_DEPENDENCY,
    "public_apis": list(PUBLIC_APIS),
    "symbol_universe": SYMBOL_UNIVERSE,
    "libobj_publication_scan": LIBOBJ_PUBLICATION_SCAN,
    "queue_processor": QUEUE_PROCESSOR,
    "first_unresolved_boundary": FIRST_UNRESOLVED_BOUNDARY,
    "readiness": READINESS,
    "claims": CLAIMS,
    "truncated": False,
}

_EXPORT_FIELDS = {
    "schema_version",
    "analysis_mode",
    "firmware_inventory",
    "source",
    "interaction_dependency",
    "public_apis",
    "symbol_universe",
    "libobj_publication_scan",
    "queue_processor",
    "first_unresolved_boundary",
    "readiness",
    "claims",
    "truncated",
}
_FORBIDDEN_KEYS = {
    "bytes",
    "disassembly",
    "instructions",
    "key_material",
    "private_key",
    "device_path",
    "flash_image",
    "package_bytes",
}


def _forbid_reconstructive_fields(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or key.casefold().replace("-", "_") in _FORBIDDEN_KEYS:
                raise MousePostProducerBoundaryError(
                    "forbidden reconstructive or unsafe evidence field"
                )
            _forbid_reconstructive_fields(child)
    elif isinstance(value, list):
        for child in value:
            _forbid_reconstructive_fields(child)


def normalize_mouse_post_producer_boundary_export(document: dict) -> dict:
    """Accept only the exact bounded, source-pinned negative producer result."""

    _forbid_reconstructive_fields(document)
    if not isinstance(document, dict) or set(document) != _EXPORT_FIELDS:
        raise MousePostProducerBoundaryError("producer-boundary export fields differ")
    if document != EXPECTED_EXPORT:
        raise MousePostProducerBoundaryError(
            "producer-boundary export differs from the pinned bounded result"
        )
    return copy.deepcopy(document)


def canonical_digest(document: dict) -> str:
    encoded = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _candidate_count(export, roles):
    scan = export["libobj_publication_scan"]
    return sum(
        len(scan[field][role])
        for field in (
            "direct_inbound_calls",
            "relocation_publications",
            "aligned_pointer_publications",
            "address_materializations",
        )
        for role in roles
    )


def summarize_mouse_post_producer_boundary_export(document: dict) -> dict:
    export = normalize_mouse_post_producer_boundary_export(document)
    return {
        "canonical_export_sha256": canonical_digest(export),
        "firmware_file_count": export["firmware_inventory"]["regular_file_count"],
        "elf_file_count": export["firmware_inventory"]["elf_file_count"],
        "public_api_count": len(export["public_apis"]),
        "owner_count": export["libobj_publication_scan"]["owner_count"],
        "complete_owner_count": export["libobj_publication_scan"][
            "complete_owner_count"
        ],
        "incomplete_owner_count": export["libobj_publication_scan"][
            "incomplete_owner_count"
        ],
        "external_symbol_consumer_count": len(
            export["symbol_universe"]["external_definitions"]
        )
        + len(export["symbol_universe"]["external_imports"]),
        "publication_candidate_count": _candidate_count(
            export,
            ("move", "press", "release"),
        ),
        "queue_processor_candidate_count": _candidate_count(
            export,
            ("queue_processor",),
        )
        + len(export["queue_processor"]["dynamic_symbol_definitions"]),
    }


def build_mouse_post_producer_boundary_report(document: dict) -> dict:
    export = normalize_mouse_post_producer_boundary_export(document)
    return {
        "schema_version": 1,
        "analysis_scope": "offline-static-mouse-post-producer-boundary",
        "camera_policy": "physically-disconnected",
        "camera_executed": False,
        "installable": False,
        "camera_test_eligible": False,
        "source": copy.deepcopy(export["source"]),
        "interaction_dependency": copy.deepcopy(export["interaction_dependency"]),
        "summary": summarize_mouse_post_producer_boundary_export(export),
        "claims": copy.deepcopy(export["claims"]),
        "readiness": READINESS,
        "first_unresolved_boundary": FIRST_UNRESOLVED_BOUNDARY,
        "conclusion": CONCLUSION,
    }


_REPORT_FIELDS = {
    "schema_version",
    "analysis_scope",
    "camera_policy",
    "camera_executed",
    "installable",
    "camera_test_eligible",
    "source",
    "interaction_dependency",
    "summary",
    "claims",
    "readiness",
    "first_unresolved_boundary",
    "conclusion",
}
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def validate_mouse_post_producer_boundary_report(document: dict) -> dict:
    _forbid_reconstructive_fields(document)
    if not isinstance(document, dict) or set(document) != _REPORT_FIELDS:
        raise MousePostProducerBoundaryError("producer-boundary report fields differ")
    expected = build_mouse_post_producer_boundary_report(EXPECTED_EXPORT)
    if document != expected:
        raise MousePostProducerBoundaryError(
            "producer-boundary report differs from the fail-closed result"
        )
    if _SHA256.fullmatch(document["summary"]["canonical_export_sha256"]) is None:
        raise MousePostProducerBoundaryError("producer-boundary report digest is invalid")
    return copy.deepcopy(document)
