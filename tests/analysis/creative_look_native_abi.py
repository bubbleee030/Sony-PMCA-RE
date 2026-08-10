import ctypes
import os
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
NATIVE_DIRECTORY = ROOT / "native" / "a6400_creative_look"
CORE_SOURCE = NATIVE_DIRECTORY / "creative_look_core.c"
CORE_HEADER = NATIVE_DIRECTORY / "creative_look_core.h"
VIEW_SOURCE = NATIVE_DIRECTORY / "creative_look_view.c"
VIEW_HEADER = NATIVE_DIRECTORY / "creative_look_view.h"

CL_UI_MAX_ELEMENTS = 20


class NativeState(ctypes.Structure):
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
    ctypes.c_int32, ctypes.c_void_p, ctypes.POINTER(NativeFrame)
)
StorageLoadCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
)
StorageSaveCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
)


class ViewAdapter(ctypes.Structure):
    _fields_ = [("context", ctypes.c_void_p), ("present", PresentCallback)]


class StorageAdapter(ctypes.Structure):
    _fields_ = [
        ("context", ctypes.c_void_p),
        ("load", StorageLoadCallback),
        ("save", StorageSaveCallback),
    ]


def strict_c99_command():
    compiler = shutil.which("gcc")
    if compiler is None:
        raise unittest.SkipTest("a C99 compiler is unavailable")
    return [
        compiler,
        "-std=c99",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-I",
        str(NATIVE_DIRECTORY),
    ]


def _run_checked(command):
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr or completed.stdout)
    return completed


def compile_shared_library(directory, name, sources):
    output = Path(directory) / f"{name}.dll"
    _run_checked(
        [
            *strict_c99_command(),
            "-shared",
            "-o",
            str(output),
            *(str(source) for source in sources),
        ]
    )
    return output


def compile_freestanding_objects(directory, sources):
    objects = []
    for index, source in enumerate(sources):
        output = Path(directory) / f"native-{index}.o"
        _run_checked(
            [
                *strict_c99_command(),
                "-ffreestanding",
                "-fno-builtin",
                "-c",
                "-o",
                str(output),
                str(source),
            ]
        )
        objects.append(output)
    return objects


def compiler_linker():
    compiler = strict_c99_command()[0]
    completed = _run_checked([compiler, "-print-prog-name=ld"])
    linker = completed.stdout.strip()
    if not linker:
        raise AssertionError("gcc did not report its matching linker")
    return linker


def link_relocatable(directory, name, objects):
    output = Path(directory) / f"{name}.o"
    _run_checked(
        [
            compiler_linker(),
            "-r",
            "-o",
            str(output),
            *(str(object_path) for object_path in objects),
        ]
    )
    return output


def assert_no_undefined_symbols(object_path, label):
    symbol_tool = shutil.which("nm")
    if symbol_tool is None:
        raise AssertionError("nm is required to verify undefined symbols")
    completed = _run_checked([symbol_tool, "-u", str(object_path)])
    if completed.stdout.strip():
        raise AssertionError(
            f"{label} has undefined symbols:\n{completed.stdout}"
        )


def unload_library(owner, attribute):
    library = getattr(owner, attribute)
    if os.name == "nt":
        import _ctypes

        handle = library._handle
        setattr(owner, attribute, None)
        _ctypes.FreeLibrary(handle)
    else:
        setattr(owner, attribute, None)


def retain_callback(owner, callback_type, function):
    if not hasattr(owner, "_native_callbacks"):
        owner._native_callbacks = []
        owner._native_callback_errors = []

    def guarded(*arguments):
        try:
            return function(*arguments)
        except BaseException as error:
            owner._native_callback_errors.append(error)
            return 1

    callback = callback_type(guarded)
    owner._native_callbacks.append(callback)
    return callback


def configure_core_exports(library):
    state_pointer = ctypes.POINTER(NativeState)
    library.cl_state_size.argtypes = []
    library.cl_state_size.restype = ctypes.c_size_t
    library.cl_blob_size.argtypes = []
    library.cl_blob_size.restype = ctypes.c_size_t
    library.cl_capability_flags.argtypes = []
    library.cl_capability_flags.restype = ctypes.c_uint32
    library.cl_init.argtypes = [state_pointer]
    library.cl_init.restype = ctypes.c_int
    library.cl_validate.argtypes = [state_pointer]
    library.cl_validate.restype = ctypes.c_int
    library.cl_axis_range.argtypes = [
        ctypes.c_uint8,
        ctypes.POINTER(ctypes.c_int8),
        ctypes.POINTER(ctypes.c_int8),
    ]
    library.cl_axis_range.restype = ctypes.c_int
    library.cl_axis_status.argtypes = [state_pointer, ctypes.c_uint8]
    library.cl_axis_status.restype = ctypes.c_int
    library.cl_is_modified.argtypes = [
        state_pointer,
        ctypes.c_uint8,
        ctypes.POINTER(ctypes.c_int),
    ]
    library.cl_is_modified.restype = ctypes.c_int
    library.cl_set_orientation.argtypes = [state_pointer, ctypes.c_uint8]
    library.cl_set_orientation.restype = ctypes.c_int
    library.cl_set_mode.argtypes = [state_pointer, ctypes.c_uint8, ctypes.c_int]
    library.cl_set_mode.restype = ctypes.c_int
    library.cl_select_look.argtypes = [state_pointer, ctypes.c_uint8]
    library.cl_select_look.restype = ctypes.c_int
    library.cl_select_custom_base.argtypes = [
        state_pointer,
        ctypes.c_uint8,
        ctypes.c_uint8,
    ]
    library.cl_select_custom_base.restype = ctypes.c_int
    library.cl_open_axis.argtypes = [state_pointer, ctypes.c_uint8]
    library.cl_open_axis.restype = ctypes.c_int
    library.cl_set_axis.argtypes = [state_pointer, ctypes.c_uint8, ctypes.c_int]
    library.cl_set_axis.restype = ctypes.c_int
    library.cl_reset_selected.argtypes = [state_pointer]
    library.cl_reset_selected.restype = ctypes.c_int
    library.cl_back_to_catalog.argtypes = [state_pointer]
    library.cl_back_to_catalog.restype = ctypes.c_int
    library.cl_encode.argtypes = [
        state_pointer,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
    ]
    library.cl_encode.restype = ctypes.c_int
    library.cl_decode.argtypes = [
        state_pointer,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
    ]
    library.cl_decode.restype = ctypes.c_int


def configure_view_exports(library):
    state_pointer = ctypes.POINTER(NativeState)
    frame_pointer = ctypes.POINTER(NativeFrame)
    library.cl_view_frame_size.argtypes = []
    library.cl_view_frame_size.restype = ctypes.c_size_t
    library.cl_view_build.argtypes = [state_pointer, frame_pointer]
    library.cl_view_build.restype = ctypes.c_int
    library.cl_view_touch.argtypes = [
        state_pointer,
        ctypes.c_int32,
        ctypes.c_int32,
    ]
    library.cl_view_touch.restype = ctypes.c_int
    library.cl_view_present.argtypes = [
        state_pointer,
        ctypes.POINTER(ViewAdapter),
    ]
    library.cl_view_present.restype = ctypes.c_int
    library.cl_storage_save.argtypes = [
        state_pointer,
        ctypes.POINTER(StorageAdapter),
    ]
    library.cl_storage_save.restype = ctypes.c_int
    library.cl_storage_load.argtypes = [
        state_pointer,
        ctypes.POINTER(StorageAdapter),
    ]
    library.cl_storage_load.restype = ctypes.c_int
