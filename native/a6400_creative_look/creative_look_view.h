#ifndef A6400_CREATIVE_LOOK_VIEW_H
#define A6400_CREATIVE_LOOK_VIEW_H

#include "creative_look_core.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    CL_UI_COORDINATE_SCALE = 1000,
    CL_UI_MAX_ELEMENTS = 20
};

typedef enum cl_ui_kind {
    CL_UI_KIND_LOOK = 0,
    CL_UI_KIND_CUSTOM_BASE = 1,
    CL_UI_KIND_AXIS = 2,
    CL_UI_KIND_AXIS_VALUE = 3,
    CL_UI_KIND_ACTION = 4
} cl_ui_kind;

typedef enum cl_ui_action {
    CL_UI_ACTION_NONE = 0,
    CL_UI_ACTION_SELECT_LOOK = 1,
    CL_UI_ACTION_SELECT_CUSTOM_BASE = 2,
    CL_UI_ACTION_OPEN_AXIS = 3,
    CL_UI_ACTION_SET_AXIS = 4,
    CL_UI_ACTION_RESET = 5,
    CL_UI_ACTION_CATALOG = 6
} cl_ui_action;

typedef struct cl_ui_element {
    int32_t x;
    int32_t y;
    int32_t width;
    int32_t height;
    int16_t value;
    int8_t status;
    uint8_t kind;
    uint8_t action;
    uint8_t primary;
    uint8_t enabled;
    uint8_t modified;
} cl_ui_element;

typedef struct cl_view_frame {
    int32_t width;
    int32_t height;
    uint8_t columns;
    uint8_t count;
    uint8_t reserved[2];
    cl_ui_element elements[CL_UI_MAX_ELEMENTS];
} cl_view_frame;

typedef int32_t (*cl_view_present_fn)(
    void *context,
    const cl_view_frame *frame
);

typedef int32_t (*cl_storage_load_fn)(
    void *context,
    uint8_t *data,
    size_t size
);

typedef int32_t (*cl_storage_save_fn)(
    void *context,
    const uint8_t *data,
    size_t size
);

typedef struct cl_view_adapter {
    void *context;
    cl_view_present_fn present;
} cl_view_adapter;

typedef struct cl_storage_adapter {
    void *context;
    cl_storage_load_fn load;
    cl_storage_save_fn save;
} cl_storage_adapter;

size_t cl_view_frame_size(void);
cl_result cl_view_build(const cl_state *state, cl_view_frame *frame);
cl_result cl_view_touch(cl_state *state, int32_t x, int32_t y);
cl_result cl_view_present(
    const cl_state *state,
    const cl_view_adapter *adapter
);
cl_result cl_storage_save(
    const cl_state *state,
    const cl_storage_adapter *adapter
);
cl_result cl_storage_load(
    cl_state *state,
    const cl_storage_adapter *adapter
);

#ifdef __cplusplus
}
#endif

#endif
