import ctypes
import tempfile
import unittest
import zlib

from pmca.experience.creative_look import (
    AXIS_DEFINITIONS,
    AXIS_IDS,
    BUILT_IN_LOOK_IDS,
    CUSTOM_LOOK_IDS,
    CreativeLookExperience,
    CreativeLookExperienceError,
    Orientation,
)
from tests.analysis.creative_look_native_abi import (
    CORE_HEADER as HEADER,
    CORE_SOURCE as SOURCE,
    NativeState,
    assert_no_undefined_symbols,
    compile_freestanding_objects,
    compile_shared_library,
    configure_core_exports,
    unload_library,
)


CL_OK = 0
CL_ERR_ARGUMENT = -1
CL_ERR_LOOK = -4
CL_ERR_AXIS = -5
CL_ERR_VALUE = -6
CL_ERR_RESTRICTED = -7
CL_ERR_BLOB = -8
CL_DEFAULT = -128
CL_UNSET = 255
CL_BLOB_SIZE = 164

SCREEN_VALUES = {"catalog": 0, "custom_base": 1, "editor": 2, "axis_picker": 3}
ORIENTATION_VALUES = {
    "landscape": 0,
    "portrait_shutter_up": 1,
    "portrait_shutter_down": 2,
}
MODE_BITS = {
    "intelligent_auto": 1 << 0,
    "picture_profile_not_off": 1 << 1,
    "flexible_iso_log": 1 << 2,
    "movie_mode": 1 << 3,
}


class CreativeLookNativeCoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._temporary = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.library_path = compile_shared_library(
            cls._temporary.name, "creative_look_core", [SOURCE]
        )
        cls.object_path = compile_freestanding_objects(
            cls._temporary.name, [SOURCE]
        )[0]
        assert_no_undefined_symbols(cls.object_path, "native core")
        cls.core = ctypes.CDLL(str(cls.library_path))
        configure_core_exports(cls.core)

    @classmethod
    def tearDownClass(cls):
        unload_library(cls, "core")
        cls._temporary.cleanup()

    def _native_state(self):
        state = NativeState()
        self.assertEqual(self.core.cl_init(ctypes.byref(state)), CL_OK)
        return state

    def _assert_matches_python(self, native, reference):
        self.assertEqual(native.selected_look, (*BUILT_IN_LOOK_IDS, *CUSTOM_LOOK_IDS).index(reference.selected_look))
        self.assertEqual(native.screen, SCREEN_VALUES[reference.screen.value])
        self.assertEqual(native.orientation, ORIENTATION_VALUES[reference.orientation.value])
        self.assertEqual(
            native.editing_axis,
            CL_UNSET if reference.editing_axis is None else AXIS_IDS.index(reference.editing_axis),
        )
        self.assertEqual(
            list(native.custom_bases),
            [
                CL_UNSET if reference.custom_bases[slot] is None else BUILT_IN_LOOK_IDS.index(reference.custom_bases[slot])
                for slot in CUSTOM_LOOK_IDS
            ],
        )
        for look_index, look in enumerate((*BUILT_IN_LOOK_IDS, *CUSTOM_LOOK_IDS)):
            self.assertEqual(
                list(native.adjustments[look_index]),
                [
                    CL_DEFAULT if reference.adjustments[look][axis] is None else reference.adjustments[look][axis]
                    for axis in AXIS_IDS
                ],
            )
        expected_modes = sum(
            bit for mode, bit in MODE_BITS.items() if reference.modes[mode]
        )
        self.assertEqual(native.modes, expected_modes)
        self.assertEqual(self.core.cl_validate(ctypes.byref(native)), CL_OK)

    def test_contract_is_fixed_memory_and_safety_is_unbound(self):
        self.assertEqual(ctypes.sizeof(NativeState), 155)
        self.assertEqual(self.core.cl_state_size(), 155)
        self.assertEqual(self.core.cl_blob_size(), CL_BLOB_SIZE)
        self.assertEqual(self.core.cl_capability_flags(), 0)

        for axis_index, axis in enumerate(AXIS_IDS):
            minimum = ctypes.c_int8()
            maximum = ctypes.c_int8()
            self.assertEqual(
                self.core.cl_axis_range(
                    axis_index, ctypes.byref(minimum), ctypes.byref(maximum)
                ),
                CL_OK,
            )
            self.assertEqual(
                (minimum.value, maximum.value), AXIS_DEFINITIONS[axis]
            )

        source = SOURCE.read_text(encoding="utf-8")
        header = HEADER.read_text(encoding="utf-8")
        self.assertEqual(
            [line for line in source.splitlines() if line.startswith("#include")],
            ['#include "creative_look_core.h"'],
        )
        for forbidden in (
            "malloc(",
            "calloc(",
            "realloc(",
            "free(",
            "fopen(",
            "socket(",
            "dlopen(",
            "LoadLibrary",
            "libusb",
            "firmware_package",
            "partition_write",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("CL_PROCESSING_BINDING_UNBOUND = 0", header)
        self.assertIn("CL_RECOVERY_VALIDATED = 0", header)
        self.assertIn("CL_CAMERA_TEST_ELIGIBLE = 0", header)
        self.assertIn("CL_INSTALLABLE = 0", header)

    def test_native_transitions_match_the_python_reference_model(self):
        native = self._native_state()
        reference = CreativeLookExperience.new()
        self._assert_matches_python(native, reference)

        reference.set_orientation(Orientation.PORTRAIT_SHUTTER_DOWN)
        self.assertEqual(self.core.cl_set_orientation(ctypes.byref(native), 2), CL_OK)

        reference.select_look("Custom1")
        self.assertEqual(self.core.cl_select_look(ctypes.byref(native), 12), CL_OK)
        self._assert_matches_python(native, reference)

        reference.select_custom_base("Custom1", "VV")
        self.assertEqual(
            self.core.cl_select_custom_base(ctypes.byref(native), 0, 3), CL_OK
        )
        reference.open_axis("contrast")
        self.assertEqual(self.core.cl_open_axis(ctypes.byref(native), 0), CL_OK)
        reference.set_axis("contrast", 3)
        self.assertEqual(self.core.cl_set_axis(ctypes.byref(native), 0, 3), CL_OK)
        modified = ctypes.c_int()
        self.assertEqual(
            self.core.cl_is_modified(ctypes.byref(native), 12, ctypes.byref(modified)),
            CL_OK,
        )
        self.assertEqual(modified.value, 1)
        self._assert_matches_python(native, reference)

        reference.set_mode(movie_mode=True)
        self.assertEqual(self.core.cl_set_mode(ctypes.byref(native), 3, 1), CL_OK)
        before = bytes(native)
        self.assertEqual(
            self.core.cl_set_mode(ctypes.byref(native), 255, 1), CL_ERR_ARGUMENT
        )
        self.assertEqual(bytes(native), before)
        with self.assertRaises(CreativeLookExperienceError):
            reference.open_axis("sharpness_range")
        before = bytes(native)
        self.assertEqual(
            self.core.cl_axis_status(ctypes.byref(native), 6), CL_ERR_RESTRICTED
        )
        self.assertEqual(
            self.core.cl_open_axis(ctypes.byref(native), 6), CL_ERR_RESTRICTED
        )
        self.assertEqual(bytes(native), before)

        reference.back_to_catalog()
        self.assertEqual(self.core.cl_back_to_catalog(ctypes.byref(native)), CL_OK)
        reference.select_look("BW")
        self.assertEqual(self.core.cl_select_look(ctypes.byref(native), 10), CL_OK)
        with self.assertRaises(CreativeLookExperienceError):
            reference.open_axis("saturation")
        self.assertEqual(
            self.core.cl_open_axis(ctypes.byref(native), 4), CL_ERR_RESTRICTED
        )

        reference.reset_selected_look()
        self.assertEqual(self.core.cl_reset_selected(ctypes.byref(native)), CL_OK)
        self.assertEqual(
            self.core.cl_is_modified(ctypes.byref(native), 10, ctypes.byref(modified)),
            CL_OK,
        )
        self.assertEqual(modified.value, 0)
        reference.set_mode(intelligent_auto=True)
        self.assertEqual(self.core.cl_set_mode(ctypes.byref(native), 0, 1), CL_OK)
        self._assert_matches_python(native, reference)

    def test_every_look_custom_slot_axis_and_orientation_is_representable(self):
        for orientation in range(3):
            state = self._native_state()
            self.assertEqual(
                self.core.cl_set_orientation(ctypes.byref(state), orientation), CL_OK
            )
            self.assertEqual(state.orientation, orientation)

        for look in range(18):
            state = self._native_state()
            self.assertEqual(
                self.core.cl_select_look(ctypes.byref(state), look), CL_OK
            )
            if look >= 12:
                slot = look - 12
                self.assertEqual(
                    self.core.cl_select_custom_base(
                        ctypes.byref(state), slot, slot % 12
                    ),
                    CL_OK,
                )
            for axis_index, axis_id in enumerate(AXIS_IDS):
                restricted = look in (10, 11) and axis_id == "saturation"
                expected_status = CL_ERR_RESTRICTED if restricted else CL_OK
                self.assertEqual(
                    self.core.cl_axis_status(ctypes.byref(state), axis_index),
                    expected_status,
                )
                if restricted:
                    continue
                minimum, maximum = AXIS_DEFINITIONS[axis_id]
                for value in (minimum, maximum, CL_DEFAULT):
                    self.assertEqual(
                        self.core.cl_set_axis(
                            ctypes.byref(state), axis_index, value
                        ),
                        CL_OK,
                    )
            self.assertEqual(self.core.cl_validate(ctypes.byref(state)), CL_OK)

    def test_invalid_calls_leave_native_state_unchanged(self):
        state = self._native_state()
        cases = (
            (self.core.cl_set_orientation, (ctypes.byref(state), 3), CL_ERR_ARGUMENT),
            (self.core.cl_set_mode, (ctypes.byref(state), 0, 2), CL_ERR_ARGUMENT),
            (self.core.cl_set_mode, (ctypes.byref(state), 255, 1), CL_ERR_ARGUMENT),
            (self.core.cl_select_look, (ctypes.byref(state), 18), CL_ERR_LOOK),
            (
                self.core.cl_select_custom_base,
                (ctypes.byref(state), 6, 0),
                CL_ERR_LOOK,
            ),
            (
                self.core.cl_select_custom_base,
                (ctypes.byref(state), 0, 12),
                CL_ERR_LOOK,
            ),
            (self.core.cl_open_axis, (ctypes.byref(state), 8), CL_ERR_AXIS),
            (
                self.core.cl_set_axis,
                (ctypes.byref(state), 0, 10),
                CL_ERR_VALUE,
            ),
        )
        for function, arguments, expected in cases:
            before = bytes(state)
            self.assertEqual(function(*arguments), expected)
            self.assertEqual(bytes(state), before)

    def test_persistence_blob_round_trips_and_rejects_corruption(self):
        state = self._native_state()
        self.assertEqual(self.core.cl_select_look(ctypes.byref(state), 12), CL_OK)
        self.assertEqual(
            self.core.cl_select_custom_base(ctypes.byref(state), 0, 3), CL_OK
        )
        self.assertEqual(self.core.cl_set_axis(ctypes.byref(state), 0, 3), CL_OK)
        blob_type = ctypes.c_uint8 * CL_BLOB_SIZE
        blob = blob_type()
        self.assertEqual(
            self.core.cl_encode(ctypes.byref(state), blob, CL_BLOB_SIZE), CL_OK
        )
        encoded = bytes(blob)
        self.assertEqual(encoded[:4], b"CLK1")
        self.assertEqual(encoded[4], 1)
        self.assertEqual(
            encoded[160:164], zlib.crc32(encoded[:160]).to_bytes(4, "little")
        )

        decoded = self._native_state()
        self.assertEqual(
            self.core.cl_decode(ctypes.byref(decoded), blob, CL_BLOB_SIZE), CL_OK
        )
        self.assertEqual(bytes(decoded), bytes(state))

        def mutated(offset, value, repair_crc=True):
            candidate = bytearray(encoded)
            candidate[offset] = value
            if repair_crc:
                candidate[160:164] = zlib.crc32(candidate[:160]).to_bytes(4, "little")
            return blob_type.from_buffer_copy(candidate)

        cases = (
            mutated(0, ord("X")),
            mutated(4, 2),
            mutated(5, 18),
            mutated(6, 9),
            mutated(7, 9),
            mutated(8, 254),
            mutated(9, 0x80),
            mutated(10, 12),
            mutated(16, 127),
            mutated(160, encoded[160] ^ 0xFF, repair_crc=False),
        )
        for candidate in cases:
            output = self._native_state()
            original = bytes(output)
            self.assertEqual(
                self.core.cl_decode(
                    ctypes.byref(output), candidate, CL_BLOB_SIZE
                ),
                CL_ERR_BLOB,
            )
            self.assertEqual(bytes(output), original)


if __name__ == "__main__":
    unittest.main()
