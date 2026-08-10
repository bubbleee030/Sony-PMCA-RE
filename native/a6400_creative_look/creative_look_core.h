#ifndef A6400_CREATIVE_LOOK_CORE_H
#define A6400_CREATIVE_LOOK_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CL_BUILT_IN_LOOK_COUNT = 12,
    CL_CUSTOM_LOOK_COUNT = 6,
    CL_LOOK_COUNT = 18,
    CL_AXIS_COUNT = 8,
    CL_BLOB_SIZE = 164,
    CL_STATE_SCHEMA_VERSION = 1,
    CL_UNSET = 255
};

enum {
    CL_PROCESSING_BINDING_UNBOUND = 0,
    CL_RECOVERY_VALIDATED = 0,
    CL_CAMERA_TEST_ELIGIBLE = 0,
    CL_INSTALLABLE = 0
};

#define CL_AXIS_DEFAULT ((int8_t)-128)

typedef enum cl_result {
    CL_OK = 0,
    CL_ERR_ARGUMENT = -1,
    CL_ERR_STATE = -2,
    CL_ERR_MODE_UNAVAILABLE = -3,
    CL_ERR_LOOK = -4,
    CL_ERR_AXIS = -5,
    CL_ERR_VALUE = -6,
    CL_ERR_RESTRICTED = -7,
    CL_ERR_BLOB = -8,
    CL_ERR_NO_HIT = -9,
    CL_ERR_ADAPTER = -10,
    CL_ERR_MANIFEST = -11,
    CL_ERR_BINDING = -12,
    CL_ERR_LIFECYCLE = -13,
    CL_ERR_NOT_OPEN = -14,
    CL_ERR_ALREADY_OPEN = -15,
    CL_ERR_REVISION = -16,
    CL_ERR_INPUT_ATTACHMENT = -17,
    CL_ERR_REINIT_REQUIRED = -18,
    CL_ERR_BUSY = -19
} cl_result;

typedef enum cl_screen {
    CL_SCREEN_CATALOG = 0,
    CL_SCREEN_CUSTOM_BASE = 1,
    CL_SCREEN_EDITOR = 2,
    CL_SCREEN_AXIS_PICKER = 3
} cl_screen;

typedef enum cl_orientation {
    CL_ORIENTATION_LANDSCAPE = 0,
    CL_ORIENTATION_PORTRAIT_SHUTTER_UP = 1,
    CL_ORIENTATION_PORTRAIT_SHUTTER_DOWN = 2
} cl_orientation;

typedef enum cl_mode {
    CL_MODE_INTELLIGENT_AUTO = 0,
    CL_MODE_PICTURE_PROFILE_NOT_OFF = 1,
    CL_MODE_FLEXIBLE_ISO_LOG = 2,
    CL_MODE_MOVIE = 3
} cl_mode;

typedef enum cl_axis {
    CL_AXIS_CONTRAST = 0,
    CL_AXIS_HIGHLIGHTS = 1,
    CL_AXIS_SHADOWS = 2,
    CL_AXIS_FADE = 3,
    CL_AXIS_SATURATION = 4,
    CL_AXIS_SHARPNESS = 5,
    CL_AXIS_SHARPNESS_RANGE = 6,
    CL_AXIS_CLARITY = 7
} cl_axis;

typedef enum cl_look {
    CL_LOOK_ST = 0,
    CL_LOOK_PT = 1,
    CL_LOOK_NT = 2,
    CL_LOOK_VV = 3,
    CL_LOOK_VV2 = 4,
    CL_LOOK_FL = 5,
    CL_LOOK_FL2 = 6,
    CL_LOOK_FL3 = 7,
    CL_LOOK_IN = 8,
    CL_LOOK_SH = 9,
    CL_LOOK_BW = 10,
    CL_LOOK_SE = 11,
    CL_LOOK_CUSTOM1 = 12,
    CL_LOOK_CUSTOM2 = 13,
    CL_LOOK_CUSTOM3 = 14,
    CL_LOOK_CUSTOM4 = 15,
    CL_LOOK_CUSTOM5 = 16,
    CL_LOOK_CUSTOM6 = 17
} cl_look;

typedef struct cl_state {
    uint8_t selected_look;
    uint8_t screen;
    uint8_t orientation;
    uint8_t editing_axis;
    uint8_t custom_bases[CL_CUSTOM_LOOK_COUNT];
    int8_t adjustments[CL_LOOK_COUNT][CL_AXIS_COUNT];
    uint8_t modes;
} cl_state;

size_t cl_state_size(void);
size_t cl_blob_size(void);
uint32_t cl_capability_flags(void);

cl_result cl_init(cl_state *state);
cl_result cl_validate(const cl_state *state);
cl_result cl_axis_range(uint8_t axis, int8_t *minimum, int8_t *maximum);
cl_result cl_axis_status(const cl_state *state, uint8_t axis);
cl_result cl_is_modified(
    const cl_state *state,
    uint8_t look,
    int *modified
);
cl_result cl_set_orientation(cl_state *state, uint8_t orientation);
cl_result cl_set_mode(cl_state *state, uint8_t mode, int enabled);
cl_result cl_select_look(cl_state *state, uint8_t look);
cl_result cl_select_custom_base(
    cl_state *state,
    uint8_t custom_slot,
    uint8_t base_look
);
cl_result cl_open_axis(cl_state *state, uint8_t axis);
cl_result cl_set_axis(cl_state *state, uint8_t axis, int value);
cl_result cl_reset_selected(cl_state *state);
cl_result cl_back_to_catalog(cl_state *state);

cl_result cl_encode(
    const cl_state *state,
    uint8_t *output,
    size_t output_size
);
cl_result cl_decode(
    cl_state *state,
    const uint8_t *input,
    size_t input_size
);

#ifdef __cplusplus
}
#endif

#endif
