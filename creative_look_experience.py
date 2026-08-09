"""Operate the static/offline α6400 Creative Look experience prototype."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from pmca.experience.creative_look import (
    CreativeLookExperience,
    CreativeLookExperienceError,
    Orientation,
    Screen,
    load_experience,
    save_experience,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)

    initialize = commands.add_parser("initialize", allow_abbrev=False)
    initialize.add_argument("--state", required=True, type=Path)

    orient = commands.add_parser("orient", allow_abbrev=False)
    orient.add_argument("--state", required=True, type=Path)
    orient.add_argument(
        "--orientation",
        required=True,
        choices=[orientation.value for orientation in Orientation],
    )

    frame = commands.add_parser("frame", allow_abbrev=False)
    frame.add_argument("--state", required=True, type=Path)
    frame.add_argument("--output", required=True, type=Path)

    touch = commands.add_parser("touch", allow_abbrev=False)
    touch.add_argument("--state", required=True, type=Path)
    touch.add_argument("--x", required=True, type=float)
    touch.add_argument("--y", required=True, type=float)

    demo = commands.add_parser("demo", allow_abbrev=False)
    demo.add_argument("--output", required=True, type=Path)
    return parser


def _write_json(path: Path, document: dict) -> None:
    path = Path(path)
    if path.suffix.casefold() != ".json" or path.is_symlink():
        raise CreativeLookExperienceError(
            "prototype output must be a non-symlink JSON file"
        )
    if path.exists() and not path.is_file():
        raise CreativeLookExperienceError("prototype output is not a regular file")
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _initialize(args: argparse.Namespace) -> None:
    if args.state.exists():
        raise CreativeLookExperienceError("state output already exists")
    experience = CreativeLookExperience.new()
    save_experience(args.state, experience)
    print(f"state={args.state} screen={experience.screen.value} offline_only=true")


def _orient(args: argparse.Namespace) -> None:
    experience = load_experience(args.state)
    experience.set_orientation(args.orientation)
    save_experience(args.state, experience)
    print(f"orientation={experience.orientation.value} offline_only=true")


def _frame(args: argparse.Namespace) -> None:
    experience = load_experience(args.state)
    _write_json(
        args.output,
        {
            "schema_version": 1,
            "offline_only": True,
            "processing_binding": experience.processing_binding,
            "safety": experience.to_document()["safety"],
            "frame": experience.frame().to_document(),
        },
    )
    print(
        f"frame={args.output} orientation={experience.orientation.value} "
        f"screen={experience.screen.value} offline_only=true"
    )


def _touch(args: argparse.Namespace) -> None:
    experience = load_experience(args.state)
    activated = experience.touch(args.x, args.y)
    save_experience(args.state, experience)
    print(
        f"activated={str(activated).lower()} screen={experience.screen.value} "
        "offline_only=true"
    )


def _demo(args: argparse.Namespace) -> None:
    catalogs = {}
    for orientation in Orientation:
        experience = CreativeLookExperience.new()
        experience.set_orientation(orientation)
        catalogs[orientation.value] = experience.frame().to_document()

    sample = CreativeLookExperience.new()
    sample.set_orientation(Orientation.PORTRAIT_SHUTTER_UP)
    sample.select_custom_base("Custom1", "VV")
    sample.select_look("Custom1")
    sample.set_axis("contrast", 3)
    sample.set_axis("clarity", 2)
    sample.screen = Screen.EDITOR
    _write_json(
        args.output,
        {
            "schema_version": 1,
            "offline_only": True,
            "sample_values_are_product_demo_only": True,
            "processing_binding": sample.processing_binding,
            "catalog_frames": catalogs,
            "sample_state": sample.to_document(),
            "sample_editor_frame": sample.frame().to_document(),
        },
    )
    print(
        f"demo={args.output} looks=12 custom=6 orientations=3 "
        "processing_binding=UNBOUND_TARGET"
    )


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    handlers = {
        "initialize": _initialize,
        "orient": _orient,
        "frame": _frame,
        "touch": _touch,
        "demo": _demo,
    }
    try:
        handlers[args.command](args)
    except (CreativeLookExperienceError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
