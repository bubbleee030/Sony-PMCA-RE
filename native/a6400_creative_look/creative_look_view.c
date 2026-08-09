#include "creative_look_view.h"

enum {
    CL_LANDSCAPE_WIDTH = 1600 * CL_UI_COORDINATE_SCALE,
    CL_LANDSCAPE_HEIGHT = 900 * CL_UI_COORDINATE_SCALE,
    CL_PORTRAIT_WIDTH = 900 * CL_UI_COORDINATE_SCALE,
    CL_PORTRAIT_HEIGHT = 1600 * CL_UI_COORDINATE_SCALE,
    CL_GLOBAL_MODE_MASK = 0x07u
};

typedef char cl_ui_element_size_is_24[
    (sizeof(cl_ui_element) == 24u) ? 1 : -1
];
typedef char cl_view_frame_size_is_492[
    (sizeof(cl_view_frame) == 492u) ? 1 : -1
];

static int32_t cl_divide_positive(int32_t value, uint8_t divisor)
{
#define CL_DIVIDE_CASE(number) case number: return value / number
    switch (divisor) {
        CL_DIVIDE_CASE(1);
        CL_DIVIDE_CASE(2);
        CL_DIVIDE_CASE(3);
        CL_DIVIDE_CASE(4);
        CL_DIVIDE_CASE(5);
        CL_DIVIDE_CASE(6);
        CL_DIVIDE_CASE(7);
        CL_DIVIDE_CASE(8);
        CL_DIVIDE_CASE(9);
        CL_DIVIDE_CASE(10);
        CL_DIVIDE_CASE(11);
        CL_DIVIDE_CASE(12);
        CL_DIVIDE_CASE(13);
        CL_DIVIDE_CASE(14);
        CL_DIVIDE_CASE(15);
        CL_DIVIDE_CASE(16);
        CL_DIVIDE_CASE(17);
        CL_DIVIDE_CASE(18);
        CL_DIVIDE_CASE(19);
        CL_DIVIDE_CASE(20);
        default: return 0;
    }
#undef CL_DIVIDE_CASE
}

static int32_t cl_divide_round_positive(int32_t value, uint8_t divisor)
{
    return cl_divide_positive(value + (int32_t)(divisor / 2u), divisor);
}

static int cl_global_mode_unavailable(const cl_state *state)
{
    return (state->modes & CL_GLOBAL_MODE_MASK) != 0u;
}

static void cl_clear_element(cl_ui_element *element)
{
    element->x = 0;
    element->y = 0;
    element->width = 0;
    element->height = 0;
    element->value = 0;
    element->status = CL_OK;
    element->kind = CL_UI_KIND_ACTION;
    element->action = CL_UI_ACTION_NONE;
    element->primary = 0u;
    element->enabled = 0u;
    element->modified = 0u;
}

static cl_result cl_append_element(
    cl_view_frame *frame,
    uint8_t kind,
    uint8_t action,
    uint8_t primary,
    int16_t value,
    cl_result status,
    uint8_t modified
)
{
    cl_ui_element *element;
    if (frame->count >= CL_UI_MAX_ELEMENTS) {
        return CL_ERR_STATE;
    }
    element = &frame->elements[frame->count];
    cl_clear_element(element);
    element->kind = kind;
    element->action = action;
    element->primary = primary;
    element->value = value;
    element->status = (int8_t)status;
    element->enabled = status == CL_OK ? 1u : 0u;
    element->modified = modified;
    ++frame->count;
    return CL_OK;
}

static cl_result cl_layout_frame(cl_view_frame *frame)
{
    uint8_t rows;
    int32_t margin_x;
    int32_t margin_y;
    int32_t gap_x;
    int32_t gap_y;
    int32_t available_width;
    int32_t available_height;
    int32_t cell_width;
    int32_t cell_height;
    uint8_t index;
    if (frame->columns == 0u || frame->count == 0u) {
        return CL_ERR_STATE;
    }
    rows = (uint8_t)cl_divide_positive(
        (int32_t)frame->count + frame->columns - 1,
        frame->columns
    );
    margin_x = frame->width / 40;
    margin_y = frame->height / 40;
    gap_x = (frame->width * 12) / 1000;
    gap_y = (frame->height * 12) / 1000;
    available_width = frame->width - 2 * margin_x -
        (int32_t)(frame->columns - 1u) * gap_x;
    available_height = frame->height - 2 * margin_y -
        (int32_t)(rows - 1u) * gap_y;
    cell_width = cl_divide_round_positive(
        available_width,
        frame->columns
    );
    cell_height = cl_divide_round_positive(available_height, rows);
    if (cell_width <= 0 || cell_height <= 0) {
        return CL_ERR_STATE;
    }
    for (index = 0u; index < frame->count; ++index) {
        const uint8_t row = (uint8_t)cl_divide_positive(index, frame->columns);
        const uint8_t column = (uint8_t)(index - row * frame->columns);
        cl_ui_element *element = &frame->elements[index];
        element->x = cl_divide_round_positive(
            margin_x * frame->columns +
                (int32_t)column * available_width +
                (int32_t)column * gap_x * frame->columns,
            frame->columns
        );
        element->y = cl_divide_round_positive(
            margin_y * rows +
                (int32_t)row * available_height +
                (int32_t)row * gap_y * rows,
            rows
        );
        element->width = cell_width;
        element->height = cell_height;
    }
    return CL_OK;
}

static cl_result cl_build_catalog(
    const cl_state *state,
    cl_view_frame *frame
)
{
    const cl_result status = cl_global_mode_unavailable(state)
        ? CL_ERR_MODE_UNAVAILABLE
        : CL_OK;
    uint8_t look;
    for (look = 0u; look < CL_LOOK_COUNT; ++look) {
        int modified = 0;
        int16_t value = look;
        cl_result result = cl_is_modified(state, look, &modified);
        if (result != CL_OK) {
            return result;
        }
        if (look >= CL_BUILT_IN_LOOK_COUNT) {
            const uint8_t base = state->custom_bases[
                look - CL_BUILT_IN_LOOK_COUNT
            ];
            value = base == CL_UNSET ? CL_AXIS_DEFAULT : (int16_t)base;
        }
        result = cl_append_element(
            frame,
            CL_UI_KIND_LOOK,
            CL_UI_ACTION_SELECT_LOOK,
            look,
            value,
            status,
            modified != 0 ? 1u : 0u
        );
        if (result != CL_OK) {
            return result;
        }
    }
    return CL_OK;
}

static cl_result cl_build_custom_base(cl_view_frame *frame)
{
    uint8_t look;
    for (look = 0u; look < CL_BUILT_IN_LOOK_COUNT; ++look) {
        const cl_result result = cl_append_element(
            frame,
            CL_UI_KIND_CUSTOM_BASE,
            CL_UI_ACTION_SELECT_CUSTOM_BASE,
            look,
            look,
            CL_OK,
            0u
        );
        if (result != CL_OK) {
            return result;
        }
    }
    return CL_OK;
}

static cl_result cl_build_editor(
    const cl_state *state,
    cl_view_frame *frame
)
{
    uint8_t axis;
    for (axis = 0u; axis < CL_AXIS_COUNT; ++axis) {
        const int8_t value = state->adjustments[state->selected_look][axis];
        const cl_result status = cl_axis_status(state, axis);
        const cl_result result = cl_append_element(
            frame,
            CL_UI_KIND_AXIS,
            CL_UI_ACTION_OPEN_AXIS,
            axis,
            value,
            status,
            value == CL_AXIS_DEFAULT ? 0u : 1u
        );
        if (result != CL_OK) {
            return result;
        }
    }
    if (
        cl_append_element(
            frame,
            CL_UI_KIND_ACTION,
            CL_UI_ACTION_RESET,
            0u,
            0,
            CL_OK,
            0u
        ) != CL_OK
    ) {
        return CL_ERR_STATE;
    }
    return cl_append_element(
        frame,
        CL_UI_KIND_ACTION,
        CL_UI_ACTION_CATALOG,
        0u,
        0,
        CL_OK,
        0u
    );
}

static cl_result cl_build_axis_picker(
    const cl_state *state,
    cl_view_frame *frame
)
{
    int8_t minimum;
    int8_t maximum;
    int value;
    cl_result result = cl_axis_range(
        state->editing_axis,
        &minimum,
        &maximum
    );
    if (result != CL_OK) {
        return result;
    }
    result = cl_append_element(
        frame,
        CL_UI_KIND_AXIS_VALUE,
        CL_UI_ACTION_SET_AXIS,
        state->editing_axis,
        CL_AXIS_DEFAULT,
        CL_OK,
        0u
    );
    if (result != CL_OK) {
        return result;
    }
    for (value = minimum; value <= maximum; ++value) {
        result = cl_append_element(
            frame,
            CL_UI_KIND_AXIS_VALUE,
            CL_UI_ACTION_SET_AXIS,
            state->editing_axis,
            (int16_t)value,
            CL_OK,
            1u
        );
        if (result != CL_OK) {
            return result;
        }
    }
    return CL_OK;
}

size_t cl_view_frame_size(void)
{
    return sizeof(cl_view_frame);
}

cl_result cl_view_build(const cl_state *state, cl_view_frame *frame)
{
    uint8_t index;
    cl_result result;
    if (state == NULL || frame == NULL) {
        return CL_ERR_ARGUMENT;
    }
    result = cl_validate(state);
    if (result != CL_OK) {
        return result;
    }
    frame->width = state->orientation == CL_ORIENTATION_LANDSCAPE
        ? CL_LANDSCAPE_WIDTH
        : CL_PORTRAIT_WIDTH;
    frame->height = state->orientation == CL_ORIENTATION_LANDSCAPE
        ? CL_LANDSCAPE_HEIGHT
        : CL_PORTRAIT_HEIGHT;
    frame->count = 0u;
    frame->reserved[0] = 0u;
    frame->reserved[1] = 0u;
    for (index = 0u; index < CL_UI_MAX_ELEMENTS; ++index) {
        cl_clear_element(&frame->elements[index]);
    }
    if (state->screen == CL_SCREEN_CATALOG) {
        frame->columns = state->orientation == CL_ORIENTATION_LANDSCAPE
            ? 6u
            : 3u;
        result = cl_build_catalog(state, frame);
    } else if (state->screen == CL_SCREEN_CUSTOM_BASE) {
        frame->columns = state->orientation == CL_ORIENTATION_LANDSCAPE
            ? 4u
            : 3u;
        result = cl_build_custom_base(frame);
    } else if (state->screen == CL_SCREEN_EDITOR) {
        frame->columns = state->orientation == CL_ORIENTATION_LANDSCAPE
            ? 2u
            : 1u;
        result = cl_build_editor(state, frame);
    } else {
        frame->columns = state->orientation == CL_ORIENTATION_LANDSCAPE
            ? 7u
            : 5u;
        result = cl_build_axis_picker(state, frame);
    }
    if (result != CL_OK) {
        return result;
    }
    return cl_layout_frame(frame);
}

static int cl_contains(
    const cl_ui_element *element,
    int32_t x,
    int32_t y
)
{
    return
        x >= element->x &&
        y >= element->y &&
        x <= element->x + element->width &&
        y <= element->y + element->height;
}

cl_result cl_view_touch(cl_state *state, int32_t x, int32_t y)
{
    cl_view_frame frame;
    uint8_t index;
    cl_result result;
    if (state == NULL) {
        return CL_ERR_ARGUMENT;
    }
    result = cl_view_build(state, &frame);
    if (result != CL_OK) {
        return result;
    }
    for (index = 0u; index < frame.count; ++index) {
        const cl_ui_element *element = &frame.elements[index];
        if (!cl_contains(element, x, y)) {
            continue;
        }
        if (element->enabled == 0u) {
            return (cl_result)element->status;
        }
        switch (element->action) {
            case CL_UI_ACTION_SELECT_LOOK:
                return cl_select_look(state, element->primary);
            case CL_UI_ACTION_SELECT_CUSTOM_BASE:
                if (
                    state->selected_look < CL_BUILT_IN_LOOK_COUNT ||
                    state->selected_look >= CL_LOOK_COUNT
                ) {
                    return CL_ERR_STATE;
                }
                return cl_select_custom_base(
                    state,
                    (uint8_t)(
                        state->selected_look - CL_BUILT_IN_LOOK_COUNT
                    ),
                    element->primary
                );
            case CL_UI_ACTION_OPEN_AXIS:
                return cl_open_axis(state, element->primary);
            case CL_UI_ACTION_SET_AXIS:
                return cl_set_axis(state, element->primary, element->value);
            case CL_UI_ACTION_RESET:
                return cl_reset_selected(state);
            case CL_UI_ACTION_CATALOG:
                return cl_back_to_catalog(state);
            default:
                return CL_ERR_STATE;
        }
    }
    return CL_ERR_NO_HIT;
}

cl_result cl_view_present(
    const cl_state *state,
    const cl_view_adapter *adapter
)
{
    cl_view_frame frame;
    cl_result result;
    if (state == NULL || adapter == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (adapter->present == NULL) {
        return CL_ERR_ADAPTER;
    }
    result = cl_view_build(state, &frame);
    if (result != CL_OK) {
        return result;
    }
    return adapter->present(adapter->context, &frame) == 0
        ? CL_OK
        : CL_ERR_ADAPTER;
}

cl_result cl_storage_save(
    const cl_state *state,
    const cl_storage_adapter *adapter
)
{
    uint8_t data[CL_BLOB_SIZE];
    cl_result result;
    if (state == NULL || adapter == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (adapter->save == NULL) {
        return CL_ERR_ADAPTER;
    }
    result = cl_encode(state, data, CL_BLOB_SIZE);
    if (result != CL_OK) {
        return result;
    }
    return adapter->save(adapter->context, data, CL_BLOB_SIZE) == 0
        ? CL_OK
        : CL_ERR_ADAPTER;
}

cl_result cl_storage_load(
    cl_state *state,
    const cl_storage_adapter *adapter
)
{
    uint8_t data[CL_BLOB_SIZE];
    cl_state candidate;
    cl_result result;
    if (state == NULL || adapter == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (adapter->load == NULL) {
        return CL_ERR_ADAPTER;
    }
    if (adapter->load(adapter->context, data, CL_BLOB_SIZE) != 0) {
        return CL_ERR_ADAPTER;
    }
    result = cl_decode(&candidate, data, CL_BLOB_SIZE);
    if (result != CL_OK) {
        return result;
    }
    *state = candidate;
    return CL_OK;
}
