#ifndef A6400_CREATIVE_LOOK_TARGET_H
#define A6400_CREATIVE_LOOK_TARGET_H

#include "creative_look_bridge.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CL_TARGET_SHELL_ABI_VERSION = 1,
    CL_TARGET_PUBLICATION_PROPOSED_UNPUBLISHED = 0,
    CL_TARGET_SHELL_ARM_SIZE = 1200,
    CL_TARGET_SHELL_ARM_ALIGNMENT = 4,
    CL_TARGET_SHELL_ARM_BRIDGE_OFFSET = 0,
    CL_TARGET_SHELL_ARM_FRAME_OFFSET = 692,
    CL_TARGET_SHELL_ARM_SINK_OFFSET = 1184,
    CL_TARGET_SHELL_ARM_SINK_CONTEXT_OFFSET = 1188,
    CL_TARGET_SHELL_ARM_MARKER_OFFSET = 1192,
    CL_TARGET_SHELL_ARM_FRAME_VALID_OFFSET = 1196,
    CL_TARGET_SHELL_ARM_DELIVERING_OFFSET = 1197,
    CL_TARGET_IDENTITY_ARM_SIZE = 16,
    CL_TARGET_IDENTITY_ARM_ALIGNMENT = 4,
    CL_TARGET_IDENTITY_ARM_STATUS_OFFSET = 12
};

#define CL_TARGET_SHELL_INITIALIZATION_MARKER UINT32_C(0x434C5431)

typedef struct cl_target_identity {
    const char *logical_alias;
    const char *component_label;
    const char *proposed_factory_label;
    uint32_t publication_status;
} cl_target_identity;

/*
 * Storage becomes self-bound after successful initialization. It must remain
 * at the same address through open, close, and any permitted reinitialization;
 * byte-copying or relocating initialized or closed historical state does not
 * create another valid shell.
 */
typedef struct cl_target_shell {
    cl_bridge bridge;
    cl_view_frame copied_frame;
    cl_input_sink_fn retained_sink;
    void *retained_sink_context;
    uint32_t initialization_marker;
    uint8_t frame_valid;
    uint8_t delivering;
    uint8_t reserved[2];
} cl_target_shell;

size_t cl_target_shell_size(void);
size_t cl_target_shell_alignment(void);
cl_result cl_target_shell_init(
    cl_target_shell *,
    const cl_integration_manifest *,
    const cl_bridge_adapters *
);
cl_result cl_target_shell_open(cl_target_shell *, cl_bridge_report *);
cl_result cl_target_shell_close(cl_target_shell *, cl_bridge_report *);
cl_result cl_target_shell_deliver(
    cl_target_shell *, const cl_input_event *, cl_bridge_report *
);
const cl_view_frame *cl_target_shell_copied_frame(const cl_target_shell *);
const cl_state *cl_target_shell_bridge_state(const cl_target_shell *);
const cl_bridge_report *cl_target_shell_last_report(const cl_target_shell *);
const cl_target_identity *cl_target_shell_identity(void);

#ifdef __cplusplus
}
#endif

#endif
