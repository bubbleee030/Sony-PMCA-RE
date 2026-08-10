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

size_t cl_binding_record_size(void);
size_t cl_integration_manifest_size(void);
size_t cl_input_event_size(void);
size_t cl_processing_snapshot_size(void);
size_t cl_bridge_report_size(void);
cl_result cl_bridge_manifest_host(cl_integration_manifest *manifest);
cl_result cl_bridge_validate_manifest(const cl_integration_manifest *manifest);

#ifdef __cplusplus
}
#endif

#endif
