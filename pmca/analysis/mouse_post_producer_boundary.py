"""Fail-closed evidence contract for the bounded α6400 mouse-post producer scan."""

from __future__ import annotations

import copy


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
