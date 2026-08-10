#include "creative_look_bridge.h"

typedef char cl_result_values_are_stable[
    (CL_ERR_MANIFEST == -11 &&
     CL_ERR_BINDING == -12 &&
     CL_ERR_LIFECYCLE == -13 &&
     CL_ERR_NOT_OPEN == -14 &&
     CL_ERR_ALREADY_OPEN == -15 &&
     CL_ERR_REVISION == -16 &&
     CL_ERR_INPUT_ATTACHMENT == -17 &&
     CL_ERR_REINIT_REQUIRED == -18 &&
     CL_ERR_BUSY == -19) ? 1 : -1
];
typedef char cl_binding_record_size_is_36[
    (sizeof(cl_binding_record) == 36u) ? 1 : -1
];
typedef char cl_integration_manifest_size_is_228[
    (sizeof(cl_integration_manifest) == 228u) ? 1 : -1
];
typedef char cl_input_event_size_is_12[
    (sizeof(cl_input_event) == 12u) ? 1 : -1
];
typedef char cl_processing_snapshot_size_is_164[
    (sizeof(cl_processing_snapshot) == 164u) ? 1 : -1
];
typedef char cl_bridge_report_size_is_64[
    (sizeof(cl_bridge_report) == 64u) ? 1 : -1
];

static int cl_digest_is_zero(const uint8_t digest[32])
{
    size_t index;

    for (index = 0u; index < 32u; ++index) {
        if (digest[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

size_t cl_binding_record_size(void)
{
    return sizeof(cl_binding_record);
}

size_t cl_integration_manifest_size(void)
{
    return sizeof(cl_integration_manifest);
}

size_t cl_input_event_size(void)
{
    return sizeof(cl_input_event);
}

size_t cl_processing_snapshot_size(void)
{
    return sizeof(cl_processing_snapshot);
}

size_t cl_bridge_report_size(void)
{
    return sizeof(cl_bridge_report);
}

cl_result cl_bridge_manifest_host(cl_integration_manifest *manifest)
{
    size_t index;
    uint8_t *bytes;

    if (manifest == NULL) {
        return CL_ERR_ARGUMENT;
    }

    bytes = (uint8_t *)manifest;
    for (index = 0u; index < sizeof(*manifest); ++index) {
        bytes[index] = 0u;
    }

    manifest->abi_version = CL_BRIDGE_ABI_VERSION;
    manifest->execution_profile = CL_EXECUTION_PROFILE_OFFLINE_HOST;
    manifest->binding_count = CL_BRIDGE_BINDING_COUNT;
    for (index = 0u; index < CL_BRIDGE_BINDING_COUNT; ++index) {
        manifest->bindings[index].kind = (uint8_t)index;
        manifest->bindings[index].evidence = CL_BINDING_EVIDENCE_UNBOUND;
        manifest->bindings[index].runtime =
            CL_BINDING_RUNTIME_HOST_SIMULATED;
    }

    return CL_OK;
}

cl_result cl_bridge_validate_manifest(const cl_integration_manifest *manifest)
{
    size_t index;

    if (manifest == NULL ||
        manifest->abi_version != CL_BRIDGE_ABI_VERSION ||
        manifest->execution_profile != CL_EXECUTION_PROFILE_OFFLINE_HOST ||
        manifest->binding_count != CL_BRIDGE_BINDING_COUNT) {
        return CL_ERR_MANIFEST;
    }

    for (index = 0u; index < CL_BRIDGE_BINDING_COUNT; ++index) {
        const cl_binding_record *binding = &manifest->bindings[index];
        const int digest_is_zero = cl_digest_is_zero(binding->evidence_sha256);

        if (binding->kind != (uint8_t)index ||
            binding->evidence > CL_BINDING_EVIDENCE_STATIC_PROVEN ||
            binding->runtime > CL_BINDING_RUNTIME_HOST_SIMULATED ||
            binding->reserved != 0u ||
            (binding->evidence == CL_BINDING_EVIDENCE_UNBOUND &&
             !digest_is_zero) ||
            (binding->evidence != CL_BINDING_EVIDENCE_UNBOUND &&
             digest_is_zero)) {
            return CL_ERR_MANIFEST;
        }
    }

    if (manifest->processing_binding_proven != 0u ||
        manifest->recovery_validated != 0u ||
        manifest->camera_test_eligible != 0u ||
        manifest->installable != 0u) {
        return CL_ERR_MANIFEST;
    }

    for (index = 0u; index < sizeof(manifest->reserved); ++index) {
        if (manifest->reserved[index] != 0u) {
            return CL_ERR_MANIFEST;
        }
    }

    return CL_OK;
}
