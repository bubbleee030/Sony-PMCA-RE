#include "creative_look_core.h"

enum {
    CL_MODE_MASK_INTELLIGENT_AUTO = 1u << CL_MODE_INTELLIGENT_AUTO,
    CL_MODE_MASK_PICTURE_PROFILE = 1u << CL_MODE_PICTURE_PROFILE_NOT_OFF,
    CL_MODE_MASK_FLEXIBLE_ISO_LOG = 1u << CL_MODE_FLEXIBLE_ISO_LOG,
    CL_MODE_MASK_MOVIE = 1u << CL_MODE_MOVIE,
    CL_MODE_MASK_ALL = 0x0fu,
    CL_BLOB_PAYLOAD_SIZE = 160
};

static const int8_t cl_axis_minimums[CL_AXIS_COUNT] = {
    -9, -9, -9, 0, -9, 0, 1, 0
};

static const int8_t cl_axis_maximums[CL_AXIS_COUNT] = {
    9, 9, 9, 9, 9, 9, 5, 9
};

typedef char cl_state_size_is_155[(sizeof(cl_state) == 155u) ? 1 : -1];

static int cl_mode_unavailable(const cl_state *state)
{
    const uint8_t mask = (uint8_t)(
        CL_MODE_MASK_INTELLIGENT_AUTO |
        CL_MODE_MASK_PICTURE_PROFILE |
        CL_MODE_MASK_FLEXIBLE_ISO_LOG
    );
    return (state->modes & mask) != 0u;
}

static uint8_t cl_resolved_base(const cl_state *state)
{
    if (state->selected_look < CL_BUILT_IN_LOOK_COUNT) {
        return state->selected_look;
    }
    return state->custom_bases[
        state->selected_look - CL_BUILT_IN_LOOK_COUNT
    ];
}

static cl_result cl_axis_availability(const cl_state *state, uint8_t axis)
{
    const uint8_t base = cl_resolved_base(state);
    if (axis >= CL_AXIS_COUNT) {
        return CL_ERR_AXIS;
    }
    if (cl_mode_unavailable(state)) {
        return CL_ERR_MODE_UNAVAILABLE;
    }
    if (
        axis == CL_AXIS_SATURATION &&
        (base == CL_LOOK_BW || base == CL_LOOK_SE)
    ) {
        return CL_ERR_RESTRICTED;
    }
    if (
        axis == CL_AXIS_SHARPNESS_RANGE &&
        (state->modes & CL_MODE_MASK_MOVIE) != 0u
    ) {
        return CL_ERR_RESTRICTED;
    }
    return CL_OK;
}

static cl_result cl_validate_internal(const cl_state *state)
{
    size_t look;
    size_t axis;
    size_t slot;
    if (state->selected_look >= CL_LOOK_COUNT) {
        return CL_ERR_STATE;
    }
    if (state->screen > CL_SCREEN_AXIS_PICKER) {
        return CL_ERR_STATE;
    }
    if (state->orientation > CL_ORIENTATION_PORTRAIT_SHUTTER_DOWN) {
        return CL_ERR_STATE;
    }
    if (state->screen == CL_SCREEN_AXIS_PICKER) {
        if (state->editing_axis >= CL_AXIS_COUNT) {
            return CL_ERR_STATE;
        }
    } else if (state->editing_axis != CL_UNSET) {
        return CL_ERR_STATE;
    }
    for (slot = 0u; slot < CL_CUSTOM_LOOK_COUNT; ++slot) {
        const uint8_t base = state->custom_bases[slot];
        if (base != CL_UNSET && base >= CL_BUILT_IN_LOOK_COUNT) {
            return CL_ERR_STATE;
        }
    }
    for (look = 0u; look < CL_LOOK_COUNT; ++look) {
        for (axis = 0u; axis < CL_AXIS_COUNT; ++axis) {
            const int value = state->adjustments[look][axis];
            if (
                value != CL_AXIS_DEFAULT &&
                (value < cl_axis_minimums[axis] ||
                 value > cl_axis_maximums[axis])
            ) {
                return CL_ERR_STATE;
            }
        }
    }
    if ((state->modes & (uint8_t)~CL_MODE_MASK_ALL) != 0u) {
        return CL_ERR_STATE;
    }
    if (
        state->selected_look >= CL_BUILT_IN_LOOK_COUNT &&
        state->custom_bases[
            state->selected_look - CL_BUILT_IN_LOOK_COUNT
        ] == CL_UNSET &&
        (state->screen == CL_SCREEN_EDITOR ||
         state->screen == CL_SCREEN_AXIS_PICKER)
    ) {
        return CL_ERR_STATE;
    }
    if (cl_mode_unavailable(state) && state->screen != CL_SCREEN_CATALOG) {
        return CL_ERR_STATE;
    }
    if (
        state->screen == CL_SCREEN_AXIS_PICKER &&
        cl_axis_availability(state, state->editing_axis) != CL_OK
    ) {
        return CL_ERR_STATE;
    }
    return CL_OK;
}

static uint32_t cl_crc32(const uint8_t *data, size_t size)
{
    uint32_t crc = 0xffffffffu;
    size_t index;
    for (index = 0u; index < size; ++index) {
        unsigned bit;
        crc ^= data[index];
        for (bit = 0u; bit < 8u; ++bit) {
            const uint32_t mask = (uint32_t)-(int32_t)(crc & 1u);
            crc = (crc >> 1u) ^ (0xedb88320u & mask);
        }
    }
    return ~crc;
}

static void cl_write_u32_le(uint8_t *output, uint32_t value)
{
    output[0] = (uint8_t)(value & 0xffu);
    output[1] = (uint8_t)((value >> 8u) & 0xffu);
    output[2] = (uint8_t)((value >> 16u) & 0xffu);
    output[3] = (uint8_t)((value >> 24u) & 0xffu);
}

static uint32_t cl_read_u32_le(const uint8_t *input)
{
    return
        (uint32_t)input[0] |
        ((uint32_t)input[1] << 8u) |
        ((uint32_t)input[2] << 16u) |
        ((uint32_t)input[3] << 24u);
}

size_t cl_state_size(void)
{
    return sizeof(cl_state);
}

size_t cl_blob_size(void)
{
    return CL_BLOB_SIZE;
}

uint32_t cl_capability_flags(void)
{
    return 0u;
}

cl_result cl_init(cl_state *state)
{
    size_t look;
    size_t axis;
    size_t slot;
    if (state == NULL) {
        return CL_ERR_ARGUMENT;
    }
    state->selected_look = CL_LOOK_ST;
    state->screen = CL_SCREEN_CATALOG;
    state->orientation = CL_ORIENTATION_LANDSCAPE;
    state->editing_axis = CL_UNSET;
    for (slot = 0u; slot < CL_CUSTOM_LOOK_COUNT; ++slot) {
        state->custom_bases[slot] = CL_UNSET;
    }
    for (look = 0u; look < CL_LOOK_COUNT; ++look) {
        for (axis = 0u; axis < CL_AXIS_COUNT; ++axis) {
            state->adjustments[look][axis] = CL_AXIS_DEFAULT;
        }
    }
    state->modes = 0u;
    return CL_OK;
}

cl_result cl_validate(const cl_state *state)
{
    if (state == NULL) {
        return CL_ERR_ARGUMENT;
    }
    return cl_validate_internal(state);
}

cl_result cl_axis_range(uint8_t axis, int8_t *minimum, int8_t *maximum)
{
    if (minimum == NULL || maximum == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (axis >= CL_AXIS_COUNT) {
        return CL_ERR_AXIS;
    }
    *minimum = cl_axis_minimums[axis];
    *maximum = cl_axis_maximums[axis];
    return CL_OK;
}

cl_result cl_axis_status(const cl_state *state, uint8_t axis)
{
    if (state == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (cl_validate_internal(state) != CL_OK) {
        return CL_ERR_STATE;
    }
    return cl_axis_availability(state, axis);
}

cl_result cl_is_modified(
    const cl_state *state,
    uint8_t look,
    int *modified
)
{
    size_t axis;
    if (state == NULL || modified == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (cl_validate_internal(state) != CL_OK) {
        return CL_ERR_STATE;
    }
    if (look >= CL_LOOK_COUNT) {
        return CL_ERR_LOOK;
    }
    *modified = 0;
    for (axis = 0u; axis < CL_AXIS_COUNT; ++axis) {
        if (state->adjustments[look][axis] != CL_AXIS_DEFAULT) {
            *modified = 1;
            break;
        }
    }
    return CL_OK;
}

cl_result cl_set_orientation(cl_state *state, uint8_t orientation)
{
    cl_state candidate;
    if (state == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (cl_validate_internal(state) != CL_OK) {
        return CL_ERR_STATE;
    }
    if (orientation > CL_ORIENTATION_PORTRAIT_SHUTTER_DOWN) {
        return CL_ERR_ARGUMENT;
    }
    candidate = *state;
    candidate.orientation = orientation;
    *state = candidate;
    return CL_OK;
}

cl_result cl_set_mode(cl_state *state, uint8_t mode, int enabled)
{
    cl_state candidate;
    uint8_t mask;
    if (state == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (cl_validate_internal(state) != CL_OK) {
        return CL_ERR_STATE;
    }
    if (mode > CL_MODE_MOVIE || (enabled != 0 && enabled != 1)) {
        return CL_ERR_ARGUMENT;
    }
    mask = (uint8_t)(1u << mode);
    candidate = *state;
    if (enabled != 0) {
        candidate.modes = (uint8_t)(candidate.modes | mask);
    } else {
        candidate.modes = (uint8_t)(candidate.modes & (uint8_t)~mask);
    }
    if (cl_mode_unavailable(&candidate)) {
        candidate.screen = CL_SCREEN_CATALOG;
        candidate.editing_axis = CL_UNSET;
    } else if (
        candidate.screen == CL_SCREEN_AXIS_PICKER &&
        cl_axis_availability(&candidate, candidate.editing_axis) != CL_OK
    ) {
        candidate.screen = CL_SCREEN_EDITOR;
        candidate.editing_axis = CL_UNSET;
    }
    if (cl_validate_internal(&candidate) != CL_OK) {
        return CL_ERR_STATE;
    }
    *state = candidate;
    return CL_OK;
}

cl_result cl_select_look(cl_state *state, uint8_t look)
{
    cl_state candidate;
    if (state == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (cl_validate_internal(state) != CL_OK) {
        return CL_ERR_STATE;
    }
    if (cl_mode_unavailable(state)) {
        return CL_ERR_MODE_UNAVAILABLE;
    }
    if (look >= CL_LOOK_COUNT) {
        return CL_ERR_LOOK;
    }
    candidate = *state;
    candidate.selected_look = look;
    candidate.editing_axis = CL_UNSET;
    if (
        look >= CL_BUILT_IN_LOOK_COUNT &&
        candidate.custom_bases[look - CL_BUILT_IN_LOOK_COUNT] == CL_UNSET
    ) {
        candidate.screen = CL_SCREEN_CUSTOM_BASE;
    } else {
        candidate.screen = CL_SCREEN_EDITOR;
    }
    if (cl_validate_internal(&candidate) != CL_OK) {
        return CL_ERR_STATE;
    }
    *state = candidate;
    return CL_OK;
}

cl_result cl_select_custom_base(
    cl_state *state,
    uint8_t custom_slot,
    uint8_t base_look
)
{
    cl_state candidate;
    if (state == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (cl_validate_internal(state) != CL_OK) {
        return CL_ERR_STATE;
    }
    if (cl_mode_unavailable(state)) {
        return CL_ERR_MODE_UNAVAILABLE;
    }
    if (
        custom_slot >= CL_CUSTOM_LOOK_COUNT ||
        base_look >= CL_BUILT_IN_LOOK_COUNT
    ) {
        return CL_ERR_LOOK;
    }
    candidate = *state;
    candidate.custom_bases[custom_slot] = base_look;
    if (
        candidate.selected_look ==
        (uint8_t)(CL_BUILT_IN_LOOK_COUNT + custom_slot)
    ) {
        candidate.screen = CL_SCREEN_EDITOR;
        candidate.editing_axis = CL_UNSET;
    }
    if (cl_validate_internal(&candidate) != CL_OK) {
        return CL_ERR_STATE;
    }
    *state = candidate;
    return CL_OK;
}

cl_result cl_open_axis(cl_state *state, uint8_t axis)
{
    cl_state candidate;
    cl_result availability;
    if (state == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (cl_validate_internal(state) != CL_OK) {
        return CL_ERR_STATE;
    }
    availability = cl_axis_availability(state, axis);
    if (availability != CL_OK) {
        return availability;
    }
    candidate = *state;
    candidate.screen = CL_SCREEN_AXIS_PICKER;
    candidate.editing_axis = axis;
    if (cl_validate_internal(&candidate) != CL_OK) {
        return CL_ERR_STATE;
    }
    *state = candidate;
    return CL_OK;
}

cl_result cl_set_axis(cl_state *state, uint8_t axis, int value)
{
    cl_state candidate;
    cl_result availability;
    if (state == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (cl_validate_internal(state) != CL_OK) {
        return CL_ERR_STATE;
    }
    availability = cl_axis_availability(state, axis);
    if (availability != CL_OK) {
        return availability;
    }
    if (
        value != CL_AXIS_DEFAULT &&
        (value < cl_axis_minimums[axis] || value > cl_axis_maximums[axis])
    ) {
        return CL_ERR_VALUE;
    }
    candidate = *state;
    candidate.adjustments[candidate.selected_look][axis] = (int8_t)value;
    candidate.screen = CL_SCREEN_EDITOR;
    candidate.editing_axis = CL_UNSET;
    if (cl_validate_internal(&candidate) != CL_OK) {
        return CL_ERR_STATE;
    }
    *state = candidate;
    return CL_OK;
}

cl_result cl_reset_selected(cl_state *state)
{
    cl_state candidate;
    size_t axis;
    if (state == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (cl_validate_internal(state) != CL_OK) {
        return CL_ERR_STATE;
    }
    if (cl_mode_unavailable(state)) {
        return CL_ERR_MODE_UNAVAILABLE;
    }
    candidate = *state;
    for (axis = 0u; axis < CL_AXIS_COUNT; ++axis) {
        candidate.adjustments[candidate.selected_look][axis] = CL_AXIS_DEFAULT;
    }
    *state = candidate;
    return CL_OK;
}

cl_result cl_back_to_catalog(cl_state *state)
{
    cl_state candidate;
    if (state == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (cl_validate_internal(state) != CL_OK) {
        return CL_ERR_STATE;
    }
    candidate = *state;
    candidate.screen = CL_SCREEN_CATALOG;
    candidate.editing_axis = CL_UNSET;
    *state = candidate;
    return CL_OK;
}

cl_result cl_encode(
    const cl_state *state,
    uint8_t *output,
    size_t output_size
)
{
    size_t look;
    size_t axis;
    size_t slot;
    size_t offset = 16u;
    uint32_t checksum;
    if (state == NULL || output == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (output_size != CL_BLOB_SIZE) {
        return CL_ERR_BLOB;
    }
    if (cl_validate_internal(state) != CL_OK) {
        return CL_ERR_STATE;
    }
    output[0] = (uint8_t)'C';
    output[1] = (uint8_t)'L';
    output[2] = (uint8_t)'K';
    output[3] = (uint8_t)'1';
    output[4] = CL_STATE_SCHEMA_VERSION;
    output[5] = state->selected_look;
    output[6] = state->screen;
    output[7] = state->orientation;
    output[8] = state->editing_axis;
    output[9] = state->modes;
    for (slot = 0u; slot < CL_CUSTOM_LOOK_COUNT; ++slot) {
        output[10u + slot] = state->custom_bases[slot];
    }
    for (look = 0u; look < CL_LOOK_COUNT; ++look) {
        for (axis = 0u; axis < CL_AXIS_COUNT; ++axis) {
            output[offset] = (uint8_t)state->adjustments[look][axis];
            ++offset;
        }
    }
    checksum = cl_crc32(output, CL_BLOB_PAYLOAD_SIZE);
    cl_write_u32_le(&output[CL_BLOB_PAYLOAD_SIZE], checksum);
    return CL_OK;
}

cl_result cl_decode(
    cl_state *state,
    const uint8_t *input,
    size_t input_size
)
{
    cl_state candidate;
    size_t look;
    size_t axis;
    size_t slot;
    size_t offset = 16u;
    uint32_t expected_checksum;
    uint32_t actual_checksum;
    if (state == NULL || input == NULL) {
        return CL_ERR_ARGUMENT;
    }
    if (input_size != CL_BLOB_SIZE) {
        return CL_ERR_BLOB;
    }
    if (
        input[0] != (uint8_t)'C' ||
        input[1] != (uint8_t)'L' ||
        input[2] != (uint8_t)'K' ||
        input[3] != (uint8_t)'1' ||
        input[4] != CL_STATE_SCHEMA_VERSION
    ) {
        return CL_ERR_BLOB;
    }
    expected_checksum = cl_read_u32_le(&input[CL_BLOB_PAYLOAD_SIZE]);
    actual_checksum = cl_crc32(input, CL_BLOB_PAYLOAD_SIZE);
    if (expected_checksum != actual_checksum) {
        return CL_ERR_BLOB;
    }
    candidate.selected_look = input[5];
    candidate.screen = input[6];
    candidate.orientation = input[7];
    candidate.editing_axis = input[8];
    candidate.modes = input[9];
    for (slot = 0u; slot < CL_CUSTOM_LOOK_COUNT; ++slot) {
        candidate.custom_bases[slot] = input[10u + slot];
    }
    for (look = 0u; look < CL_LOOK_COUNT; ++look) {
        for (axis = 0u; axis < CL_AXIS_COUNT; ++axis) {
            const uint8_t encoded = input[offset];
            candidate.adjustments[look][axis] = encoded <= 127u
                ? (int8_t)encoded
                : (int8_t)((int16_t)encoded - 256);
            ++offset;
        }
    }
    if (cl_validate_internal(&candidate) != CL_OK) {
        return CL_ERR_BLOB;
    }
    *state = candidate;
    return CL_OK;
}
