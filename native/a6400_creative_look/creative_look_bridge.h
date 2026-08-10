#ifndef A6400_CREATIVE_LOOK_BRIDGE_H
#define A6400_CREATIVE_LOOK_BRIDGE_H

#include <limits.h>

#include "creative_look_view.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CL_BRIDGE_ABI_VERSION = 1,
    CL_BRIDGE_BINDING_COUNT = 6,
    CL_BRIDGE_OUTPUT_MASK = 7,
    CL_STORAGE_MISSING = 1
};

#define CL_CALLBACK_NOT_ATTEMPTED ((int32_t)INT32_MIN)
#define CL_BRIDGE_INITIALIZATION_MARKER UINT32_C(0x434C4231)

typedef enum cl_binding_kind {
    CL_BINDING_LIFECYCLE = 0,
    CL_BINDING_PRESENTATION = 1,
    CL_BINDING_INPUT = 2,
    CL_BINDING_PERSISTENCE = 3,
    CL_BINDING_MODEL_REQUEST = 4,
    CL_BINDING_OUTPUT = 5
} cl_binding_kind;

typedef enum cl_binding_evidence {
    CL_BINDING_EVIDENCE_UNBOUND = 0,
    CL_BINDING_EVIDENCE_STATIC_CANDIDATE = 1,
    CL_BINDING_EVIDENCE_STATIC_PROVEN = 2
} cl_binding_evidence;

typedef enum cl_binding_runtime {
    CL_BINDING_RUNTIME_DISABLED = 0,
    CL_BINDING_RUNTIME_HOST_SIMULATED = 1
} cl_binding_runtime;

typedef enum cl_execution_profile {
    CL_EXECUTION_PROFILE_OFFLINE_HOST = 0
} cl_execution_profile;

typedef enum cl_output_kind {
    CL_OUTPUT_LIVE_VIEW = 0,
    CL_OUTPUT_STILL_JPEG = 1,
    CL_OUTPUT_MOVIE = 2
} cl_output_kind;

typedef enum cl_input_kind {
    CL_INPUT_TOUCH = 0,
    CL_INPUT_ORIENTATION = 1
} cl_input_kind;

typedef enum cl_sync_domain {
    CL_SYNC_PRESENTATION = 1,
    CL_SYNC_PERSISTENCE = 2,
    CL_SYNC_MODEL_REQUEST = 4,
    CL_SYNC_LIVE_VIEW = 8,
    CL_SYNC_STILL_JPEG = 16,
    CL_SYNC_MOVIE = 32
} cl_sync_domain;

typedef struct cl_binding_record {
    uint8_t kind;
    uint8_t evidence;
    uint8_t runtime;
    uint8_t reserved;
    uint8_t evidence_sha256[32];
} cl_binding_record;

typedef struct cl_integration_manifest {
    uint16_t abi_version;
    uint8_t execution_profile;
    uint8_t binding_count;
    cl_binding_record bindings[CL_BRIDGE_BINDING_COUNT];
    uint8_t processing_binding_proven;
    uint8_t recovery_validated;
    uint8_t camera_test_eligible;
    uint8_t installable;
    uint8_t reserved[4];
} cl_integration_manifest;

typedef struct cl_input_event {
    int32_t x;
    int32_t y;
    uint8_t kind;
    uint8_t value;
    uint8_t reserved[2];
} cl_input_event;

typedef struct cl_processing_snapshot {
    uint16_t abi_version;
    uint8_t effective_base;
    uint8_t output_mask;
    uint32_t processing_revision;
    cl_state state;
    uint8_t reserved[1];
} cl_processing_snapshot;

typedef struct cl_bridge_report {
    int32_t transition_result;
    int32_t lifecycle_open_result;
    int32_t lifecycle_close_result;
    int32_t input_attach_result;
    int32_t input_detach_result;
    int32_t persistence_load_result;
    int32_t sync_results[CL_BRIDGE_BINDING_COUNT];
    uint32_t state_revision;
    uint32_t processing_revision;
    uint8_t attempted;
    uint8_t succeeded;
    uint8_t failed;
    uint8_t dirty;
    uint8_t state_committed;
    uint8_t opened;
    uint8_t reserved[2];
} cl_bridge_report;

typedef int32_t (*cl_lifecycle_open_fn)(void *, const cl_state *);
typedef int32_t (*cl_lifecycle_close_fn)(void *);
typedef int32_t (*cl_input_sink_fn)(
    void *, const cl_input_event *, cl_bridge_report *
);
typedef int32_t (*cl_input_attach_fn)(void *, cl_input_sink_fn, void *);
typedef int32_t (*cl_input_detach_fn)(void *);
typedef int32_t (*cl_model_submit_fn)(
    void *, const cl_processing_snapshot *
);
typedef int32_t (*cl_output_apply_fn)(
    void *, uint8_t, const cl_processing_snapshot *
);

typedef struct cl_lifecycle_adapter {
    void *context;
    cl_lifecycle_open_fn open;
    cl_lifecycle_close_fn close;
} cl_lifecycle_adapter;

typedef struct cl_input_adapter {
    void *context;
    cl_input_attach_fn attach;
    cl_input_detach_fn detach;
} cl_input_adapter;

typedef struct cl_model_adapter {
    void *context;
    cl_model_submit_fn submit;
} cl_model_adapter;

typedef struct cl_output_adapter {
    void *context;
    cl_output_apply_fn apply;
} cl_output_adapter;

typedef struct cl_bridge_adapters {
    cl_lifecycle_adapter lifecycle;
    cl_view_adapter presentation;
    cl_input_adapter input;
    cl_storage_adapter persistence;
    cl_model_adapter model;
    cl_output_adapter output;
} cl_bridge_adapters;

typedef struct cl_bridge {
    cl_integration_manifest manifest;
    cl_bridge_report last_report;
    uint32_t state_revision;
    uint32_t processing_revision;
    cl_processing_snapshot retained_processing_snapshot;
    uint32_t initialization_marker;
    cl_state state;
    uint8_t dirty_mask;
    uint8_t opened;
    uint8_t input_attached;
    uint8_t busy;
    uint8_t opened_once;
    uint8_t reserved[4];
    cl_bridge_adapters adapters;
} cl_bridge;

size_t cl_binding_record_size(void);
size_t cl_integration_manifest_size(void);
size_t cl_input_event_size(void);
size_t cl_processing_snapshot_size(void);
size_t cl_bridge_report_size(void);
size_t cl_bridge_size(void);
size_t cl_bridge_adapters_offset(void);
size_t cl_bridge_alignment(void);
cl_result cl_bridge_manifest_host(cl_integration_manifest *manifest);
cl_result cl_bridge_validate_manifest(const cl_integration_manifest *manifest);
cl_result cl_bridge_init(
    cl_bridge *, const cl_integration_manifest *, const cl_bridge_adapters *
);
cl_result cl_bridge_open(cl_bridge *, cl_bridge_report *);
cl_result cl_bridge_close(cl_bridge *, cl_bridge_report *);
cl_result cl_bridge_sync(cl_bridge *, cl_bridge_report *);
cl_result cl_bridge_retry(cl_bridge *, cl_bridge_report *);
cl_result cl_bridge_handle_event(
    cl_bridge *, const cl_input_event *, cl_bridge_report *
);
cl_result cl_bridge_set_mode(
    cl_bridge *, uint8_t mode, int enabled, cl_bridge_report *
);
const cl_state *cl_bridge_state(const cl_bridge *);
const cl_bridge_report *cl_bridge_last_report(const cl_bridge *);
uint32_t cl_bridge_state_revision(const cl_bridge *);
uint32_t cl_bridge_processing_revision(const cl_bridge *);
uint8_t cl_bridge_dirty_mask(const cl_bridge *);

#ifdef __cplusplus
}
#endif

#endif
