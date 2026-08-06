"""Render the fail-closed Sandboxie policy used by the updater analysis lab."""

import argparse
import sys
from pathlib import Path

from pmca.analysis.sandbox_policy import (
    INI_PATH,
    SandboxPolicyError,
    build_sandbox_policy,
    write_sandboxie_ini,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    subparsers = parser.add_subparsers(dest="command", required=True)
    render = subparsers.add_parser("render", allow_abbrev=False)
    render.add_argument("--profile", choices=("probe", "updater"), required=True)
    render.add_argument("--repository-root", type=Path, required=True)
    render.add_argument("--output", type=Path, required=True)
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        policy = build_sandbox_policy(args.profile)
        write_sandboxie_ini(args.output, policy, args.repository_root)
    except (OSError, SandboxPolicyError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(
        f"section={policy['section']} profile={policy['phase']} "
        f"output={INI_PATH} camera=disconnected"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
