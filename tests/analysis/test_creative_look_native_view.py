import ctypes
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from pmca.experience.creative_look import (
    AXIS_IDS,
    BUILT_IN_LOOK_IDS,
    CUSTOM_LOOK_IDS,
    CreativeLookExperience,
    Orientation,
)


ROOT = Path(__file__).resolve().parents[2]
NATIVE_DIRECTORY = ROOT / "native" / "a6400_creative_look"
CORE_SOURCE = NATIVE_DIRECTORY / "creative_look_core.c"
VIEW_SOURCE = NATIVE_DIRECTORY / "creative_look_view.c"

CL_OK = 0
CL_ERR_MODE_UNAVAILABLE = -3
CL_ERR_RESTRICTED = -7
CL_ERR_NO_HIT = -9
CL_ERR_ADAPTER = -10
CL_DEFAULT = -128
CL_UNSET = 255
CL_BLOB_SIZE = 164
CL_UI_MAX_ELEMENTS = 20

ACTION_SELECT_LOOK = 1
ACTION_SELECT_CUSTOM_BASE = 2
ACTION_OPEN_AXIS = 3
ACTION_SET_AXIS = 4
ACTION_RESET = 5
ACTION_CATALOG = 6

KIND_VALUES = {
    "look": 0,
    "custom_base": 1,
    "axis": 2,
    "axis_value": 3,
    "action": 4,
}

REASON_STATUS = {
    None: CL_OK,
    "CREATIVE_LOOK_MODE_UNAVAILABLE": CL_ERR_MODE_UNAVAILABLE,
    "BW_SE_SATURATION_UNAVAILABLE": CL_ERR_RESTRICTED,
    "MOVIE_SHARPNESS_RANGE_UNAVAILABLE": CL_ERR_RESTRICTED,
}


class NativeState(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("selected_look", ctypes.c_uint8),
        ("screen", ctypes.c_uint8),
        ("orientation", ctypes.c_uint8),
        ("editing_axis", ctypes.c_uint8),
        ("custom_bases", ctypes.c_uint8 * 6),
        ("adjustments", (ctypes.c_int8 * 8) * 18),
        ("modes", ctypes.c_uint8),
    ]


class NativeElement(ctypes.Structure):
    _fields_ = [
        ("x", ctypes.c_int32),
        ("y", ctypes.c_int32),
        ("width", ctypes.c_int32),
        ("height", ctypes.c_int32),
        ("value", ctypes.c_int16),
        ("status", ctypes.c_int8),
        ("kind", ctypes.c_uint8),
        ("action", ctypes.c_uint8),
        ("primary", ctypes.c_uint8),
        ("enabled", ctypes.c_uint8),
        ("modified", ctypes.c_uint8),
    ]


class NativeFrame(ctypes.Structure):
    _fields_ = [
        ("width", ctypes.c_int32),
        ("height", ctypes.c_int32),
        ("columns", ctypes.c_uint8),
        ("count", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 2),
        ("elements", NativeElement * CL_UI_MAX_ELEMENTS),
    ]


PresentCallback = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(NativeFrame)
)
StorageCallback = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
)


class ViewAdapter(ctypes.Structure):
    _fields_ = [("context", ctypes.c_void_p), ("present", PresentCallback)]


class StorageAdapter(ctypes.Structure):
    _fields_ = [
        ("context", ctypes.c_void_p),
        ("load", StorageCallback),
        ("save", StorageCallback),
    ]


class CreativeLookNativeViewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("gcc")
        if compiler is None:
            raise unittest.SkipTest("a C99 compiler is unavailable")
        cls._temporary = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        directory = Path(cls._temporary.name)
        cls.library_path = directory / "creative_look_view.dll"
        core_object = directory / "core.o"
        view_object = directory / "view.o"
        combined_object = directory / "combined.o"
        common = [
            compiler,
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pedantic",
            "-I",
            str(NATIVE_DIRECTORY),
        ]
        shared = subprocess.run(
            [
                *common,
                "-shared",
                "-o",
                str(cls.library_path),
                str(CORE_SOURCE),
                str(VIEW_SOURCE),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if shared.returncode != 0:
            raise AssertionError(shared.stderr)
        for source, output in ((CORE_SOURCE, core_object), (VIEW_SOURCE, view_object)):
            compiled = subprocess.run(
                [
                    *common,
                    "-ffreestanding",
                    "-fno-builtin",
                    "-c",
                    "-o",
                    str(output),
                    str(source),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            if compiled.returncode != 0:
                raise AssertionError(compiled.stderr)
        linker = shutil.which("ld")
        if linker is None:
            raise unittest.SkipTest("a relocatable-object linker is unavailable")
        linked = subprocess.run(
            [linker, "-r", "-o", str(combined_object), str(core_object), str(view_object)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if linked.returncode != 0:
            raise AssertionError(linked.stderr)
        symbol_tool = shutil.which("nm")
        if symbol_tool is not None:
            undefined = subprocess.run(
                [symbol_tool, "-u", str(combined_object)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            if undefined.returncode != 0 or undefined.stdout.strip():
                raise AssertionError(undefined.stderr or undefined.stdout)

        cls.library = ctypes.CDLL(str(cls.library_path))
        state_pointer = ctypes.POINTER(NativeState)
        frame_pointer = ctypes.POINTER(NativeFrame)
        cls.library.cl_init.argtypes = [state_pointer]
        cls.library.cl_init.restype = ctypes.c_int
        cls.library.cl_set_mode.argtypes = [state_pointer, ctypes.c_uint8, ctypes.c_int]
        cls.library.cl_set_mode.restype = ctypes.c_int
        cls.library.cl_select_look.argtypes = [state_pointer, ctypes.c_uint8]
        cls.library.cl_select_look.restype = ctypes.c_int
        cls.library.cl_select_custom_base.argtypes = [
            state_pointer,
            ctypes.c_uint8,
            ctypes.c_uint8,
        ]
        cls.library.cl_select_custom_base.restype = ctypes.c_int
        cls.library.cl_open_axis.argtypes = [state_pointer, ctypes.c_uint8]
        cls.library.cl_open_axis.restype = ctypes.c_int
        cls.library.cl_view_frame_size.restype = ctypes.c_size_t
        cls.library.cl_view_build.argtypes = [state_pointer, frame_pointer]
        cls.library.cl_view_build.restype = ctypes.c_int
        cls.library.cl_view_touch.argtypes = [
            state_pointer,
            ctypes.c_int32,
            ctypes.c_int32,
        ]
        cls.library.cl_view_touch.restype = ctypes.c_int
        cls.library.cl_view_present.argtypes = [
            state_pointer,
            ctypes.POINTER(ViewAdapter),
        ]
        cls.library.cl_view_present.restype = ctypes.c_int
        cls.library.cl_storage_save.argtypes = [
            state_pointer,
            ctypes.POINTER(StorageAdapter),
        ]
        cls.library.cl_storage_save.restype = ctypes.c_int
        cls.library.cl_storage_load.argtypes = [
            state_pointer,
            ctypes.POINTER(StorageAdapter),
        ]
        cls.library.cl_storage_load.restype = ctypes.c_int

    @classmethod
    def tearDownClass(cls):
        if os.name == "nt":
            import _ctypes

            handle = cls.library._handle
            cls.library = None
            _ctypes.FreeLibrary(handle)
        cls._temporary.cleanup()

    def _state(self):
        state = NativeState()
        self.assertEqual(self.library.cl_init(ctypes.byref(state)), CL_OK)
        return state

    def _frame(self, state):
        frame = NativeFrame()
        self.assertEqual(
            self.library.cl_view_build(ctypes.byref(state), ctypes.byref(frame)),
            CL_OK,
        )
        return frame

    @staticmethod
    def _center(element):
        return element.x + element.width // 2, element.y + element.height // 2

    def _assert_frame_matches_python(self, native, reference):
        native_frame = self._frame(native)
        reference_frame = reference.frame()
        self.assertEqual(native_frame.width, reference_frame.width * 1000)
        self.assertEqual(native_frame.height, reference_frame.height * 1000)
        self.assertEqual(native_frame.columns, reference_frame.columns)
        self.assertEqual(native_frame.count, len(reference_frame.elements))
        for index, reference_element in enumerate(reference_frame.elements):
            native_element = native_frame.elements[index]
            self.assertAlmostEqual(native_element.x, reference_element.rect.x * 1000, delta=2)
            self.assertAlmostEqual(native_element.y, reference_element.rect.y * 1000, delta=2)
            self.assertAlmostEqual(native_element.width, reference_element.rect.width * 1000, delta=2)
            self.assertAlmostEqual(native_element.height, reference_element.rect.height * 1000, delta=2)
            self.assertEqual(native_element.kind, KIND_VALUES[reference_element.kind])
            self.assertEqual(bool(native_element.enabled), reference_element.enabled)
            self.assertEqual(bool(native_element.modified), reference_element.modified)
            self.assertEqual(native_element.status, REASON_STATUS[reference_element.reason])
            identifier = reference_element.identifier
            if identifier.startswith("look:"):
                look_id = identifier.removeprefix("look:")
                self.assertEqual(native_element.action, ACTION_SELECT_LOOK)
                self.assertEqual(native_element.primary, (*BUILT_IN_LOOK_IDS, *CUSTOM_LOOK_IDS).index(look_id))
                if look_id in BUILT_IN_LOOK_IDS:
                    expected_value = BUILT_IN_LOOK_IDS.index(look_id)
                else:
                    expected_value = (
                        CL_DEFAULT
                        if reference_element.value is None
                        else BUILT_IN_LOOK_IDS.index(reference_element.value)
                    )
                self.assertEqual(native_element.value, expected_value)
            elif identifier.startswith("base:"):
                self.assertEqual(native_element.action, ACTION_SELECT_CUSTOM_BASE)
                self.assertEqual(native_element.primary, BUILT_IN_LOOK_IDS.index(identifier.removeprefix("base:")))
                self.assertEqual(native_element.value, native_element.primary)
            elif identifier.startswith("axis-value:"):
                _, axis_id, encoded = identifier.split(":", 2)
                self.assertEqual(native_element.action, ACTION_SET_AXIS)
                self.assertEqual(native_element.primary, AXIS_IDS.index(axis_id))
                self.assertEqual(native_element.value, CL_DEFAULT if encoded == "default" else int(encoded))
            elif identifier.startswith("axis:"):
                self.assertEqual(native_element.action, ACTION_OPEN_AXIS)
                self.assertEqual(native_element.primary, AXIS_IDS.index(identifier.removeprefix("axis:")))
                self.assertEqual(
                    native_element.value,
                    CL_DEFAULT
                    if reference_element.value is None
                    else reference_element.value,
                )
            elif identifier == "action:reset":
                self.assertEqual(native_element.action, ACTION_RESET)
            elif identifier == "action:catalog":
                self.assertEqual(native_element.action, ACTION_CATALOG)
            else:
                self.fail(f"unexpected reference element {identifier}")
        return native_frame

    def test_frames_match_python_across_orientations_and_screens(self):
        self.assertEqual(self.library.cl_view_frame_size(), ctypes.sizeof(NativeFrame))
        self.assertEqual(ctypes.sizeof(NativeElement), 24)
        self.assertEqual(ctypes.sizeof(NativeFrame), 492)

        for orientation_index, orientation in enumerate(Orientation):
            native = self._state()
            reference = CreativeLookExperience.new()
            native.orientation = orientation_index
            reference.set_orientation(orientation)
            self._assert_frame_matches_python(native, reference)

            self.assertEqual(
                self.library.cl_select_look(ctypes.byref(native), 12), CL_OK
            )
            reference.select_look("Custom1")
            self._assert_frame_matches_python(native, reference)

            self.assertEqual(
                self.library.cl_select_custom_base(
                    ctypes.byref(native), 0, 3
                ),
                CL_OK,
            )
            reference.select_custom_base("Custom1", "VV")
            self._assert_frame_matches_python(native, reference)

            self.assertEqual(
                self.library.cl_open_axis(ctypes.byref(native), 0), CL_OK
            )
            reference.open_axis("contrast")
            self._assert_frame_matches_python(native, reference)

    def test_touch_dispatch_closes_custom_base_axis_and_reset_flow(self):
        state = self._state()
        catalog = self._frame(state)
        x, y = self._center(catalog.elements[12])
        self.assertEqual(self.library.cl_view_touch(ctypes.byref(state), x, y), CL_OK)
        self.assertEqual((state.selected_look, state.screen), (12, 1))

        bases = self._frame(state)
        x, y = self._center(bases.elements[3])
        self.assertEqual(self.library.cl_view_touch(ctypes.byref(state), x, y), CL_OK)
        self.assertEqual((state.custom_bases[0], state.screen), (3, 2))

        editor = self._frame(state)
        x, y = self._center(editor.elements[0])
        self.assertEqual(self.library.cl_view_touch(ctypes.byref(state), x, y), CL_OK)
        self.assertEqual((state.screen, state.editing_axis), (3, 0))

        picker = self._frame(state)
        value_index = 1 + (3 - (-9))
        x, y = self._center(picker.elements[value_index])
        self.assertEqual(self.library.cl_view_touch(ctypes.byref(state), x, y), CL_OK)
        self.assertEqual((state.adjustments[12][0], state.screen), (3, 2))

        editor = self._frame(state)
        reset = editor.elements[8]
        x, y = self._center(reset)
        self.assertEqual(self.library.cl_view_touch(ctypes.byref(state), x, y), CL_OK)
        self.assertTrue(all(value == CL_DEFAULT for value in state.adjustments[12]))
        before = bytes(state)
        self.assertEqual(self.library.cl_view_touch(ctypes.byref(state), -1, -1), CL_ERR_NO_HIT)
        self.assertEqual(bytes(state), before)

    def test_disabled_controls_return_exact_restrictions(self):
        state = self._state()
        self.assertEqual(self.library.cl_select_look(ctypes.byref(state), 10), CL_OK)
        frame = self._frame(state)
        saturation = frame.elements[4]
        self.assertEqual((saturation.enabled, saturation.status), (0, CL_ERR_RESTRICTED))
        x, y = self._center(saturation)
        before = bytes(state)
        self.assertEqual(self.library.cl_view_touch(ctypes.byref(state), x, y), CL_ERR_RESTRICTED)
        self.assertEqual(bytes(state), before)

        state = self._state()
        self.assertEqual(self.library.cl_set_mode(ctypes.byref(state), 0, 1), CL_OK)
        frame = self._frame(state)
        self.assertTrue(all(element.enabled == 0 for element in frame.elements[: frame.count]))
        self.assertTrue(all(element.status == CL_ERR_MODE_UNAVAILABLE for element in frame.elements[: frame.count]))
        x, y = self._center(frame.elements[0])
        self.assertEqual(self.library.cl_view_touch(ctypes.byref(state), x, y), CL_ERR_MODE_UNAVAILABLE)

        state = self._state()
        self.assertEqual(self.library.cl_select_look(ctypes.byref(state), 3), CL_OK)
        self.assertEqual(self.library.cl_set_mode(ctypes.byref(state), 3, 1), CL_OK)
        frame = self._frame(state)
        sharpness_range = frame.elements[6]
        self.assertEqual(
            (sharpness_range.enabled, sharpness_range.status),
            (0, CL_ERR_RESTRICTED),
        )
        x, y = self._center(sharpness_range)
        before = bytes(state)
        self.assertEqual(
            self.library.cl_view_touch(ctypes.byref(state), x, y),
            CL_ERR_RESTRICTED,
        )
        self.assertEqual(bytes(state), before)

    def test_presentation_and_storage_callbacks_are_atomic(self):
        state = self._state()
        presented = []

        @PresentCallback
        def present(_context, frame_pointer):
            presented.append((frame_pointer.contents.width, frame_pointer.contents.count))
            return 0

        adapter = ViewAdapter(None, present)
        self.assertEqual(
            self.library.cl_view_present(ctypes.byref(state), ctypes.byref(adapter)),
            CL_OK,
        )
        self.assertEqual(presented, [(1600000, 18)])

        @PresentCallback
        def fail_present(_context, _frame_pointer):
            return 1

        failing_view = ViewAdapter(None, fail_present)
        self.assertEqual(
            self.library.cl_view_present(
                ctypes.byref(state), ctypes.byref(failing_view)
            ),
            CL_ERR_ADAPTER,
        )

        persisted = bytearray(CL_BLOB_SIZE)

        @StorageCallback
        def save(_context, data, size):
            persisted[:] = bytes(data[:size])
            return 0

        @StorageCallback
        def load(_context, data, size):
            ctypes.memmove(data, bytes(persisted), size)
            return 0

        storage = StorageAdapter(None, load, save)
        self.assertEqual(self.library.cl_select_look(ctypes.byref(state), 3), CL_OK)
        self.assertEqual(
            self.library.cl_storage_save(ctypes.byref(state), ctypes.byref(storage)),
            CL_OK,
        )
        state.selected_look = 0
        self.assertEqual(
            self.library.cl_storage_load(ctypes.byref(state), ctypes.byref(storage)),
            CL_OK,
        )
        self.assertEqual(state.selected_look, 3)

        @StorageCallback
        def fail_load(_context, _data, _size):
            return 1

        failing = StorageAdapter(None, fail_load, save)
        before = bytes(state)
        self.assertEqual(
            self.library.cl_storage_load(ctypes.byref(state), ctypes.byref(failing)),
            CL_ERR_ADAPTER,
        )
        self.assertEqual(bytes(state), before)

        @StorageCallback
        def fail_save(_context, _data, _size):
            return 1

        failing = StorageAdapter(None, load, fail_save)
        self.assertEqual(
            self.library.cl_storage_save(
                ctypes.byref(state), ctypes.byref(failing)
            ),
            CL_ERR_ADAPTER,
        )

        null_view = ViewAdapter()
        null_storage = StorageAdapter()
        self.assertEqual(
            self.library.cl_view_present(
                ctypes.byref(state), ctypes.byref(null_view)
            ),
            CL_ERR_ADAPTER,
        )
        self.assertEqual(
            self.library.cl_storage_load(
                ctypes.byref(state), ctypes.byref(null_storage)
            ),
            CL_ERR_ADAPTER,
        )
        self.assertEqual(
            self.library.cl_storage_save(
                ctypes.byref(state), ctypes.byref(null_storage)
            ),
            CL_ERR_ADAPTER,
        )

    def test_adapter_source_has_no_platform_or_processing_dependency(self):
        source = VIEW_SOURCE.read_text(encoding="utf-8")
        self.assertEqual(
            [line for line in source.splitlines() if line.startswith("#include")],
            ['#include "creative_look_view.h"'],
        )
        for forbidden in (
            "malloc(",
            "free(",
            "fopen(",
            "socket(",
            "dlopen(",
            "LoadLibrary",
            "libusb",
            "Backup_",
            "firmware",
            "partition",
            "processing_apply",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
