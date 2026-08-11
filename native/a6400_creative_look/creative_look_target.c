#include "creative_look_target.h"

typedef char cl_target_identity_status_is_32_bits[
    (sizeof(((cl_target_identity *)0)->publication_status) == 4u) ? 1 : -1
];
typedef char cl_target_shell_bridge_is_first[
    (offsetof(cl_target_shell, bridge) ==
     CL_TARGET_SHELL_ARM_BRIDGE_OFFSET) ? 1 : -1
];

#if UINTPTR_MAX == UINT32_MAX
typedef char cl_target_shell_arm_size_is_1200[
    (sizeof(cl_target_shell) == CL_TARGET_SHELL_ARM_SIZE) ? 1 : -1
];
typedef char cl_target_shell_arm_alignment_is_4[
    (offsetof(struct { char byte; cl_target_shell value; }, value) ==
     CL_TARGET_SHELL_ARM_ALIGNMENT) ? 1 : -1
];
typedef char cl_target_shell_arm_frame_offset_is_692[
    (offsetof(cl_target_shell, copied_frame) ==
     CL_TARGET_SHELL_ARM_FRAME_OFFSET) ? 1 : -1
];
typedef char cl_target_shell_arm_sink_offset_is_1184[
    (offsetof(cl_target_shell, retained_sink) ==
     CL_TARGET_SHELL_ARM_SINK_OFFSET) ? 1 : -1
];
typedef char cl_target_shell_arm_context_offset_is_1188[
    (offsetof(cl_target_shell, retained_sink_context) ==
     CL_TARGET_SHELL_ARM_SINK_CONTEXT_OFFSET) ? 1 : -1
];
typedef char cl_target_shell_arm_marker_offset_is_1192[
    (offsetof(cl_target_shell, initialization_marker) ==
     CL_TARGET_SHELL_ARM_MARKER_OFFSET) ? 1 : -1
];
typedef char cl_target_shell_arm_frame_valid_offset_is_1196[
    (offsetof(cl_target_shell, frame_valid) ==
     CL_TARGET_SHELL_ARM_FRAME_VALID_OFFSET) ? 1 : -1
];
typedef char cl_target_shell_arm_delivering_offset_is_1197[
    (offsetof(cl_target_shell, delivering) ==
     CL_TARGET_SHELL_ARM_DELIVERING_OFFSET) ? 1 : -1
];
typedef char cl_target_identity_arm_size_is_16[
    (sizeof(cl_target_identity) == CL_TARGET_IDENTITY_ARM_SIZE) ? 1 : -1
];
typedef char cl_target_identity_arm_alignment_is_4[
    (offsetof(struct { char byte; cl_target_identity value; }, value) ==
     CL_TARGET_IDENTITY_ARM_ALIGNMENT) ? 1 : -1
];
typedef char cl_target_identity_arm_status_offset_is_12[
    (offsetof(cl_target_identity, publication_status) ==
     CL_TARGET_IDENTITY_ARM_STATUS_OFFSET) ? 1 : -1
];
#endif

static const cl_target_identity cl_target_proposed_identity = {
    "view/CREATIVE_LOOK",
    "viewCreativeLook.so",
    "ViewCreativeLookToInstance",
    CL_TARGET_PUBLICATION_PROPOSED_UNPUBLISHED
};

static void cl_target_zero_bytes(void *value, size_t size)
{
    uint8_t *bytes = (uint8_t *)value;
    size_t index;
    for (index = 0u; index < size; ++index) {
        bytes[index] = 0u;
    }
}

static int cl_target_bytes_are_zero(const void *value, size_t size)
{
    const uint8_t *bytes = (const uint8_t *)value;
    size_t index;
    for (index = 0u; index < size; ++index) {
        if (bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int32_t cl_target_lifecycle_open(
    void *, const cl_state *
);
static int32_t cl_target_lifecycle_close(void *);
static int32_t cl_target_present(void *, const cl_view_frame *);
static int32_t cl_target_attach(void *, cl_input_sink_fn, void *);
static int32_t cl_target_detach(void *);

static int cl_target_shell_is_initialized(const cl_target_shell *shell)
{
    return shell != NULL &&
        shell->initialization_marker ==
            CL_TARGET_SHELL_INITIALIZATION_MARKER &&
        shell->bridge.initialization_marker ==
            CL_BRIDGE_INITIALIZATION_MARKER &&
        shell->bridge.adapters.lifecycle.context == shell &&
        shell->bridge.adapters.lifecycle.open == cl_target_lifecycle_open &&
        shell->bridge.adapters.lifecycle.close == cl_target_lifecycle_close &&
        shell->bridge.adapters.presentation.context == shell &&
        shell->bridge.adapters.presentation.present == cl_target_present &&
        shell->bridge.adapters.input.context == shell &&
        shell->bridge.adapters.input.attach == cl_target_attach &&
        shell->bridge.adapters.input.detach == cl_target_detach;
}

static int cl_target_caller_entries_are_zero(
    const cl_bridge_adapters *adapters
)
{
    return adapters->lifecycle.context == NULL &&
        adapters->lifecycle.open == NULL &&
        adapters->lifecycle.close == NULL &&
        adapters->presentation.context == NULL &&
        adapters->presentation.present == NULL &&
        adapters->input.context == NULL &&
        adapters->input.attach == NULL &&
        adapters->input.detach == NULL;
}

static int32_t cl_target_lifecycle_open(
    void *context,
    const cl_state *initial_state
)
{
    cl_target_shell *shell = (cl_target_shell *)context;
    return cl_target_shell_is_initialized(shell) && initial_state != NULL
        ? 0
        : 1;
}

static int32_t cl_target_lifecycle_close(void *context)
{
    return cl_target_shell_is_initialized((cl_target_shell *)context)
        ? 0
        : 1;
}

static int32_t cl_target_present(
    void *context,
    const cl_view_frame *frame
)
{
    cl_target_shell *shell = (cl_target_shell *)context;
    if (!cl_target_shell_is_initialized(shell) || frame == NULL) {
        return 1;
    }
    shell->copied_frame = *frame;
    shell->frame_valid = 1u;
    return 0;
}

static int32_t cl_target_attach(
    void *context,
    cl_input_sink_fn sink,
    void *sink_context
)
{
    cl_target_shell *shell = (cl_target_shell *)context;
    if (!cl_target_shell_is_initialized(shell) ||
        sink == NULL || sink_context == NULL ||
        shell->retained_sink != NULL ||
        shell->retained_sink_context != NULL) {
        return 1;
    }
    shell->retained_sink = sink;
    shell->retained_sink_context = sink_context;
    return 0;
}

static int32_t cl_target_detach(void *context)
{
    cl_target_shell *shell = (cl_target_shell *)context;
    if (!cl_target_shell_is_initialized(shell)) {
        return 1;
    }
    shell->retained_sink = NULL;
    shell->retained_sink_context = NULL;
    return 0;
}

size_t cl_target_shell_size(void)
{
    return sizeof(cl_target_shell);
}

size_t cl_target_shell_alignment(void)
{
    return offsetof(struct { char byte; cl_target_shell value; }, value);
}

cl_result cl_target_shell_init(
    cl_target_shell *shell,
    const cl_integration_manifest *manifest,
    const cl_bridge_adapters *adapters
)
{
    cl_integration_manifest manifest_copy;
    cl_bridge_adapters adapters_copy;
    cl_target_shell candidate;
    cl_result result;

    if (shell == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (cl_target_shell_is_initialized(shell)) {
        if (shell->bridge.busy != 0u || shell->delivering != 0u) {
            return CL_ERR_BUSY;
        }
        if (shell->bridge.opened != 0u ||
            shell->bridge.input_attached != 0u) {
            return CL_ERR_ALREADY_OPEN;
        }
        if (shell->bridge.opened_once == 0u ||
            shell->retained_sink != NULL ||
            shell->retained_sink_context != NULL) {
            return CL_ERR_STATE;
        }
    } else if (!cl_target_bytes_are_zero(shell, sizeof(*shell))) {
        return CL_ERR_STATE;
    }
    if (manifest == NULL) {
        return CL_ERR_MANIFEST;
    }
    manifest_copy = *manifest;
    if (adapters == NULL) {
        return CL_ERR_BINDING;
    }
    adapters_copy = *adapters;
    if (!cl_target_caller_entries_are_zero(&adapters_copy)) {
        return CL_ERR_BINDING;
    }

    adapters_copy.lifecycle.context = shell;
    adapters_copy.lifecycle.open = cl_target_lifecycle_open;
    adapters_copy.lifecycle.close = cl_target_lifecycle_close;
    adapters_copy.presentation.context = shell;
    adapters_copy.presentation.present = cl_target_present;
    adapters_copy.input.context = shell;
    adapters_copy.input.attach = cl_target_attach;
    adapters_copy.input.detach = cl_target_detach;

    cl_target_zero_bytes(&candidate, sizeof(candidate));
    result = cl_bridge_init(
        &candidate.bridge,
        &manifest_copy,
        &adapters_copy
    );
    if (result != CL_OK) {
        return result;
    }
    candidate.initialization_marker =
        CL_TARGET_SHELL_INITIALIZATION_MARKER;
    *shell = candidate;
    return CL_OK;
}

cl_result cl_target_shell_open(
    cl_target_shell *shell,
    cl_bridge_report *report
)
{
    if (shell == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (!cl_target_shell_is_initialized(shell)) {
        return CL_ERR_STATE;
    }
    if (report == NULL) {
        return CL_ERR_ARGUMENT;
    }
    return cl_bridge_open(&shell->bridge, report);
}

cl_result cl_target_shell_close(
    cl_target_shell *shell,
    cl_bridge_report *report
)
{
    int was_open;
    cl_result result;
    if (shell == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (!cl_target_shell_is_initialized(shell)) {
        return CL_ERR_STATE;
    }
    if (report == NULL) {
        return CL_ERR_ARGUMENT;
    }
    was_open = shell->bridge.opened != 0u;
    result = cl_bridge_close(&shell->bridge, report);
    if (was_open &&
        shell->bridge.opened == 0u &&
        shell->bridge.input_attached == 0u) {
        shell->retained_sink = NULL;
        shell->retained_sink_context = NULL;
        shell->delivering = 0u;
    }
    return result;
}

cl_result cl_target_shell_deliver(
    cl_target_shell *shell,
    const cl_input_event *event,
    cl_bridge_report *report
)
{
    int32_t callback_result;
    if (shell == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (!cl_target_shell_is_initialized(shell)) {
        return CL_ERR_STATE;
    }
    if (event == NULL || report == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (shell->bridge.busy != 0u || shell->delivering != 0u) {
        return CL_ERR_BUSY;
    }
    if (shell->bridge.opened == 0u ||
        shell->bridge.input_attached == 0u ||
        shell->retained_sink == NULL ||
        shell->retained_sink_context == NULL) {
        return CL_ERR_NOT_OPEN;
    }
    shell->delivering = 1u;
    callback_result = shell->retained_sink(
        shell->retained_sink_context,
        event,
        report
    );
    shell->delivering = 0u;
    return (cl_result)callback_result;
}

const cl_view_frame *cl_target_shell_copied_frame(
    const cl_target_shell *shell
)
{
    if (!cl_target_shell_is_initialized(shell) || shell->frame_valid == 0u) {
        return NULL;
    }
    return &shell->copied_frame;
}

const cl_state *cl_target_shell_bridge_state(const cl_target_shell *shell)
{
    return cl_target_shell_is_initialized(shell)
        ? cl_bridge_state(&shell->bridge)
        : NULL;
}

const cl_bridge_report *cl_target_shell_last_report(
    const cl_target_shell *shell
)
{
    return cl_target_shell_is_initialized(shell)
        ? cl_bridge_last_report(&shell->bridge)
        : NULL;
}

const cl_target_identity *cl_target_shell_identity(void)
{
    return &cl_target_proposed_identity;
}
