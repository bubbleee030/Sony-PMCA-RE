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
typedef char cl_bridge_adapters_offset_is_632[
    (offsetof(cl_bridge, adapters) == 632u) ? 1 : -1
];

typedef struct cl_bridge_alignment_probe {
    uint8_t prefix;
    cl_bridge bridge;
} cl_bridge_alignment_probe;

static void cl_zero_bytes(void *target, size_t size)
{
    size_t index;
    uint8_t *bytes = (uint8_t *)target;

    for (index = 0u; index < size; ++index) {
        bytes[index] = 0u;
    }
}

static int cl_bytes_are_zero(const void *source, size_t size)
{
    size_t index;
    const uint8_t *bytes = (const uint8_t *)source;

    for (index = 0u; index < size; ++index) {
        if (bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

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

static void cl_report_initialize(
    cl_bridge_report *report,
    const cl_bridge *bridge
)
{
    size_t index;

    report->transition_result = CL_OK;
    report->lifecycle_open_result = CL_CALLBACK_NOT_ATTEMPTED;
    report->lifecycle_close_result = CL_CALLBACK_NOT_ATTEMPTED;
    report->input_attach_result = CL_CALLBACK_NOT_ATTEMPTED;
    report->input_detach_result = CL_CALLBACK_NOT_ATTEMPTED;
    report->persistence_load_result = CL_CALLBACK_NOT_ATTEMPTED;
    for (index = 0u; index < CL_BRIDGE_BINDING_COUNT; ++index) {
        report->sync_results[index] = CL_CALLBACK_NOT_ATTEMPTED;
    }
    report->attempted = 0u;
    report->succeeded = 0u;
    report->failed = 0u;
    report->state_committed = 0u;
    report->reserved[0] = 0u;
    report->reserved[1] = 0u;
    if (bridge != NULL) {
        report->state_revision = bridge->state_revision;
        report->processing_revision = bridge->processing_revision;
        report->dirty = bridge->dirty_mask;
        report->opened = bridge->opened;
    } else {
        report->state_revision = 0u;
        report->processing_revision = 0u;
        report->dirty = 0u;
        report->opened = 0u;
    }
}

static int cl_state_changed(const cl_state *left, const cl_state *right)
{
    size_t look;
    size_t axis;

    if (left->selected_look != right->selected_look ||
        left->screen != right->screen ||
        left->orientation != right->orientation ||
        left->editing_axis != right->editing_axis ||
        left->modes != right->modes) {
        return 1;
    }
    for (look = 0u; look < CL_CUSTOM_LOOK_COUNT; ++look) {
        if (left->custom_bases[look] != right->custom_bases[look]) {
            return 1;
        }
    }
    for (look = 0u; look < CL_LOOK_COUNT; ++look) {
        for (axis = 0u; axis < CL_AXIS_COUNT; ++axis) {
            if (left->adjustments[look][axis] !=
                right->adjustments[look][axis]) {
                return 1;
            }
        }
    }
    return 0;
}

static int cl_processing_changed(const cl_state *left, const cl_state *right)
{
    size_t look;
    size_t axis;

    if (left->selected_look != right->selected_look ||
        left->modes != right->modes) {
        return 1;
    }
    for (look = 0u; look < CL_CUSTOM_LOOK_COUNT; ++look) {
        if (left->custom_bases[look] != right->custom_bases[look]) {
            return 1;
        }
    }
    for (look = 0u; look < CL_LOOK_COUNT; ++look) {
        for (axis = 0u; axis < CL_AXIS_COUNT; ++axis) {
            if (left->adjustments[look][axis] !=
                right->adjustments[look][axis]) {
                return 1;
            }
        }
    }
    return 0;
}

static int cl_adapters_complete(const cl_bridge_adapters *adapters)
{
    return adapters != NULL &&
        adapters->lifecycle.open != NULL &&
        adapters->lifecycle.close != NULL &&
        adapters->presentation.present != NULL &&
        adapters->input.attach != NULL &&
        adapters->input.detach != NULL &&
        adapters->persistence.load != NULL &&
        adapters->persistence.save != NULL &&
        adapters->model.submit != NULL &&
        adapters->output.apply != NULL;
}

static uint8_t cl_effective_base(const cl_state *state)
{
    if (state->selected_look < CL_BUILT_IN_LOOK_COUNT) {
        return state->selected_look;
    }
    return state->custom_bases[
        state->selected_look - CL_BUILT_IN_LOOK_COUNT
    ];
}

static void cl_update_retained_snapshot(cl_bridge *bridge)
{
    cl_processing_snapshot *snapshot =
        &bridge->retained_processing_snapshot;

    cl_zero_bytes(snapshot, sizeof(*snapshot));
    snapshot->abi_version = CL_BRIDGE_ABI_VERSION;
    snapshot->effective_base = cl_effective_base(&bridge->state);
    snapshot->output_mask = CL_BRIDGE_OUTPUT_MASK;
    snapshot->processing_revision = bridge->processing_revision;
    snapshot->state = bridge->state;
}

static void cl_synchronize_state(
    cl_bridge *bridge,
    cl_bridge_report *report
)
{
    (void)bridge;
    (void)report;
}

static int32_t cl_call_load(cl_bridge *bridge, uint8_t *blob)
{
    int32_t result;

    bridge->busy = 1u;
    result = bridge->adapters.persistence.load(
        bridge->adapters.persistence.context,
        blob,
        CL_BLOB_SIZE
    );
    bridge->busy = 0u;
    return result;
}

static int32_t cl_call_lifecycle_open(
    cl_bridge *bridge,
    const cl_state *candidate
)
{
    int32_t result;

    bridge->busy = 1u;
    result = bridge->adapters.lifecycle.open(
        bridge->adapters.lifecycle.context,
        candidate
    );
    bridge->busy = 0u;
    return result;
}

static int32_t cl_call_lifecycle_close(cl_bridge *bridge)
{
    int32_t result;

    bridge->busy = 1u;
    result = bridge->adapters.lifecycle.close(
        bridge->adapters.lifecycle.context
    );
    bridge->busy = 0u;
    return result;
}

static int32_t cl_call_present(
    cl_bridge *bridge,
    const cl_view_frame *frame
)
{
    int32_t result;

    bridge->busy = 1u;
    result = bridge->adapters.presentation.present(
        bridge->adapters.presentation.context,
        frame
    );
    bridge->busy = 0u;
    return result;
}

static int32_t cl_bridge_input_sink(
    void *context,
    const cl_input_event *event,
    cl_bridge_report *report
)
{
    return cl_bridge_handle_event((cl_bridge *)context, event, report);
}

static int32_t cl_call_attach(cl_bridge *bridge)
{
    int32_t result;

    bridge->busy = 1u;
    result = bridge->adapters.input.attach(
        bridge->adapters.input.context,
        cl_bridge_input_sink,
        bridge
    );
    bridge->busy = 0u;
    return result;
}

static int32_t cl_call_detach(cl_bridge *bridge)
{
    int32_t result;

    bridge->busy = 1u;
    result = bridge->adapters.input.detach(
        bridge->adapters.input.context
    );
    bridge->busy = 0u;
    return result;
}

static cl_result cl_publish_report(
    cl_bridge *bridge,
    cl_bridge_report *output,
    cl_bridge_report *operation,
    cl_result result
)
{
    operation->state_revision = bridge->state_revision;
    operation->processing_revision = bridge->processing_revision;
    operation->dirty = bridge->dirty_mask;
    operation->opened = bridge->opened;
    bridge->last_report = *operation;
    *output = *operation;
    return result;
}

static cl_result cl_cleanup_admission(
    cl_bridge *bridge,
    cl_bridge_report *output,
    cl_bridge_report *operation,
    cl_result primary_result
)
{
    const int32_t close_result = cl_call_lifecycle_close(bridge);

    operation->lifecycle_close_result = close_result;
    bridge->dirty_mask = 0u;
    bridge->opened = 0u;
    bridge->input_attached = 0u;
    if (close_result != 0) {
        primary_result = CL_ERR_LIFECYCLE;
    }
    return cl_publish_report(bridge, output, operation, primary_result);
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

size_t cl_bridge_size(void)
{
    return sizeof(cl_bridge);
}

size_t cl_bridge_adapters_offset(void)
{
    return offsetof(cl_bridge, adapters);
}

size_t cl_bridge_alignment(void)
{
    return offsetof(cl_bridge_alignment_probe, bridge);
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

cl_result cl_bridge_init(
    cl_bridge *bridge,
    const cl_integration_manifest *manifest,
    const cl_bridge_adapters *adapters
)
{
    size_t index;
    cl_integration_manifest manifest_copy;
    cl_bridge_adapters adapters_copy;
    cl_result result;

    if (bridge == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (bridge->initialization_marker ==
        CL_BRIDGE_INITIALIZATION_MARKER) {
        if (bridge->busy != 0u) {
            return CL_ERR_BUSY;
        }
        if (bridge->opened != 0u || bridge->input_attached != 0u) {
            return CL_ERR_ALREADY_OPEN;
        }
        if (bridge->opened_once == 0u) {
            return CL_ERR_STATE;
        }
    } else if (!cl_bytes_are_zero(bridge, sizeof(*bridge))) {
        return CL_ERR_STATE;
    }
    if (manifest == NULL) {
        return CL_ERR_MANIFEST;
    }
    manifest_copy = *manifest;
    result = cl_bridge_validate_manifest(&manifest_copy);
    if (result != CL_OK) {
        return result;
    }
    if (adapters == NULL) {
        return CL_ERR_BINDING;
    }
    adapters_copy = *adapters;
    if (!cl_adapters_complete(&adapters_copy)) {
        return CL_ERR_BINDING;
    }
    for (index = 0u; index < CL_BRIDGE_BINDING_COUNT; ++index) {
        if (manifest_copy.bindings[index].runtime !=
            CL_BINDING_RUNTIME_HOST_SIMULATED) {
            return CL_ERR_BINDING;
        }
    }

    cl_zero_bytes(bridge, sizeof(*bridge));
    bridge->manifest = manifest_copy;
    bridge->adapters = adapters_copy;
    result = cl_init(&bridge->state);
    if (result != CL_OK) {
        return result;
    }
    bridge->initialization_marker = CL_BRIDGE_INITIALIZATION_MARKER;
    cl_report_initialize(&bridge->last_report, bridge);
    return CL_OK;
}

cl_result cl_bridge_open(cl_bridge *bridge, cl_bridge_report *report)
{
    size_t index;
    uint8_t blob[CL_BLOB_SIZE];
    cl_state candidate;
    cl_view_frame frame;
    cl_bridge_report operation;
    cl_result result;
    int32_t callback_result;

    if (bridge == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (bridge->initialization_marker !=
        CL_BRIDGE_INITIALIZATION_MARKER) {
        return CL_ERR_STATE;
    }
    if (bridge->busy != 0u) {
        return CL_ERR_BUSY;
    }
    if (report == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (bridge->opened != 0u) {
        return CL_ERR_ALREADY_OPEN;
    }
    if (bridge->opened_once != 0u) {
        return CL_ERR_REINIT_REQUIRED;
    }

    bridge->opened_once = 1u;
    cl_report_initialize(&operation, bridge);
    result = cl_init(&candidate);
    operation.transition_result = result;
    if (result != CL_OK) {
        return cl_publish_report(bridge, report, &operation, result);
    }
    for (index = 0u; index < CL_BLOB_SIZE; ++index) {
        blob[index] = 0u;
    }

    callback_result = cl_call_load(bridge, blob);
    operation.persistence_load_result = callback_result;
    if (callback_result == 0) {
        result = cl_decode(&candidate, blob, CL_BLOB_SIZE);
        operation.transition_result = result;
        if (result != CL_OK) {
            return cl_publish_report(bridge, report, &operation, result);
        }
    } else if (callback_result != CL_STORAGE_MISSING) {
        return cl_publish_report(
            bridge, report, &operation, CL_ERR_ADAPTER
        );
    }

    callback_result = cl_call_lifecycle_open(bridge, &candidate);
    operation.lifecycle_open_result = callback_result;
    if (callback_result != 0) {
        return cl_publish_report(
            bridge, report, &operation, CL_ERR_LIFECYCLE
        );
    }

    bridge->state = candidate;
    bridge->state_revision = 1u;
    bridge->processing_revision = 1u;
    bridge->dirty_mask = (uint8_t)(
        CL_SYNC_MODEL_REQUEST |
        CL_SYNC_LIVE_VIEW |
        CL_SYNC_STILL_JPEG |
        CL_SYNC_MOVIE
    );
    if (operation.persistence_load_result == CL_STORAGE_MISSING) {
        bridge->dirty_mask = (uint8_t)(
            bridge->dirty_mask | CL_SYNC_PERSISTENCE
        );
    }
    cl_update_retained_snapshot(bridge);
    operation.state_committed = 1u;

    result = cl_view_build(&bridge->state, &frame);
    operation.transition_result = result;
    if (result != CL_OK) {
        return cl_cleanup_admission(
            bridge, report, &operation, result
        );
    }
    operation.attempted = CL_SYNC_PRESENTATION;
    callback_result = cl_call_present(bridge, &frame);
    operation.sync_results[0] = callback_result;
    if (callback_result != 0) {
        operation.failed = CL_SYNC_PRESENTATION;
        return cl_cleanup_admission(
            bridge, report, &operation, CL_ERR_ADAPTER
        );
    }
    operation.succeeded = CL_SYNC_PRESENTATION;

    callback_result = cl_call_attach(bridge);
    operation.input_attach_result = callback_result;
    if (callback_result != 0) {
        return cl_cleanup_admission(
            bridge, report, &operation, CL_ERR_INPUT_ATTACHMENT
        );
    }

    bridge->input_attached = 1u;
    bridge->opened = 1u;
    return cl_publish_report(bridge, report, &operation, CL_OK);
}

cl_result cl_bridge_close(cl_bridge *bridge, cl_bridge_report *report)
{
    cl_bridge_report operation;
    int32_t detach_result;
    int32_t close_result;
    cl_result result = CL_OK;

    if (bridge == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (bridge->initialization_marker !=
        CL_BRIDGE_INITIALIZATION_MARKER) {
        return CL_ERR_STATE;
    }
    if (bridge->busy != 0u) {
        return CL_ERR_BUSY;
    }
    if (report == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (bridge->opened == 0u) {
        return CL_ERR_NOT_OPEN;
    }

    cl_report_initialize(&operation, bridge);
    detach_result = cl_call_detach(bridge);
    operation.input_detach_result = detach_result;
    bridge->input_attached = 0u;

    close_result = cl_call_lifecycle_close(bridge);
    operation.lifecycle_close_result = close_result;
    bridge->opened = 0u;

    if (detach_result != 0) {
        result = CL_ERR_ADAPTER;
    }
    if (close_result != 0) {
        result = CL_ERR_LIFECYCLE;
    }
    return cl_publish_report(bridge, report, &operation, result);
}

cl_result cl_bridge_handle_event(
    cl_bridge *bridge,
    const cl_input_event *event,
    cl_bridge_report *report
)
{
    cl_bridge_report operation;
    cl_state candidate;
    cl_result result;
    int processing_change;

    if (bridge == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (bridge->initialization_marker !=
        CL_BRIDGE_INITIALIZATION_MARKER) {
        return CL_ERR_STATE;
    }
    if (bridge->busy != 0u) {
        return CL_ERR_BUSY;
    }
    if (event == NULL || report == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (bridge->opened == 0u || bridge->input_attached == 0u) {
        return CL_ERR_NOT_OPEN;
    }

    cl_report_initialize(&operation, bridge);
    if (event->reserved[0] != 0u || event->reserved[1] != 0u) {
        operation.transition_result = CL_ERR_ARGUMENT;
        return cl_publish_report(
            bridge, report, &operation, CL_ERR_ARGUMENT
        );
    }
    candidate = bridge->state;
    if (event->kind == CL_INPUT_TOUCH) {
        if (event->value != 0u) {
            operation.transition_result = CL_ERR_ARGUMENT;
            return cl_publish_report(
                bridge, report, &operation, CL_ERR_ARGUMENT
            );
        }
        result = cl_view_touch(&candidate, event->x, event->y);
    } else if (event->kind == CL_INPUT_ORIENTATION) {
        if (event->x != 0 || event->y != 0 ||
            event->value > CL_ORIENTATION_PORTRAIT_SHUTTER_DOWN) {
            operation.transition_result = CL_ERR_ARGUMENT;
            return cl_publish_report(
                bridge, report, &operation, CL_ERR_ARGUMENT
            );
        }
        result = cl_set_orientation(&candidate, event->value);
    } else {
        operation.transition_result = CL_ERR_ARGUMENT;
        return cl_publish_report(
            bridge, report, &operation, CL_ERR_ARGUMENT
        );
    }
    operation.transition_result = result;
    if (result != CL_OK) {
        return cl_publish_report(bridge, report, &operation, result);
    }
    result = cl_validate(&candidate);
    operation.transition_result = result;
    if (result != CL_OK) {
        return cl_publish_report(bridge, report, &operation, result);
    }
    if (!cl_state_changed(&bridge->state, &candidate)) {
        return cl_publish_report(bridge, report, &operation, CL_OK);
    }
    processing_change = cl_processing_changed(&bridge->state, &candidate);
    if (bridge->state_revision == UINT32_MAX ||
        (processing_change && bridge->processing_revision == UINT32_MAX)) {
        operation.transition_result = CL_ERR_REVISION;
        return cl_publish_report(
            bridge, report, &operation, CL_ERR_REVISION
        );
    }

    bridge->state = candidate;
    ++bridge->state_revision;
    bridge->dirty_mask = (uint8_t)(bridge->dirty_mask |
        CL_SYNC_PRESENTATION | CL_SYNC_PERSISTENCE);
    if (processing_change) {
        ++bridge->processing_revision;
        bridge->dirty_mask = (uint8_t)(bridge->dirty_mask |
            CL_SYNC_MODEL_REQUEST | CL_SYNC_LIVE_VIEW |
            CL_SYNC_STILL_JPEG | CL_SYNC_MOVIE);
        cl_update_retained_snapshot(bridge);
    }
    operation.state_committed = 1u;
    cl_synchronize_state(bridge, &operation);
    return cl_publish_report(bridge, report, &operation, CL_OK);
}

cl_result cl_bridge_set_mode(
    cl_bridge *bridge,
    uint8_t mode,
    int enabled,
    cl_bridge_report *report
)
{
    cl_bridge_report operation;
    cl_state candidate;
    cl_result result;

    if (bridge == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (bridge->initialization_marker !=
        CL_BRIDGE_INITIALIZATION_MARKER) {
        return CL_ERR_STATE;
    }
    if (bridge->busy != 0u) {
        return CL_ERR_BUSY;
    }
    if (report == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (bridge->opened == 0u) {
        return CL_ERR_NOT_OPEN;
    }

    cl_report_initialize(&operation, bridge);
    candidate = bridge->state;
    result = cl_set_mode(&candidate, mode, enabled);
    operation.transition_result = result;
    if (result != CL_OK) {
        return cl_publish_report(bridge, report, &operation, result);
    }
    if (candidate.modes == bridge->state.modes) {
        return cl_publish_report(bridge, report, &operation, CL_OK);
    }
    if (bridge->state_revision == UINT32_MAX ||
        bridge->processing_revision == UINT32_MAX) {
        operation.transition_result = CL_ERR_REVISION;
        return cl_publish_report(
            bridge, report, &operation, CL_ERR_REVISION
        );
    }

    bridge->state = candidate;
    ++bridge->state_revision;
    ++bridge->processing_revision;
    bridge->dirty_mask = (uint8_t)(bridge->dirty_mask |
        CL_SYNC_PRESENTATION | CL_SYNC_PERSISTENCE |
        CL_SYNC_MODEL_REQUEST | CL_SYNC_LIVE_VIEW |
        CL_SYNC_STILL_JPEG | CL_SYNC_MOVIE);
    cl_update_retained_snapshot(bridge);
    operation.state_committed = 1u;
    cl_synchronize_state(bridge, &operation);
    return cl_publish_report(bridge, report, &operation, CL_OK);
}

const cl_state *cl_bridge_state(const cl_bridge *bridge)
{
    return bridge == NULL ? NULL : &bridge->state;
}

const cl_bridge_report *cl_bridge_last_report(const cl_bridge *bridge)
{
    return bridge == NULL ? NULL : &bridge->last_report;
}

uint32_t cl_bridge_state_revision(const cl_bridge *bridge)
{
    return bridge == NULL ? 0u : bridge->state_revision;
}

uint32_t cl_bridge_processing_revision(const cl_bridge *bridge)
{
    return bridge == NULL ? 0u : bridge->processing_revision;
}

uint8_t cl_bridge_dirty_mask(const cl_bridge *bridge)
{
    return bridge == NULL ? 0u : bridge->dirty_mask;
}
