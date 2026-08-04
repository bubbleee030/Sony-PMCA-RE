#!/usr/bin/env python3
"""Fail-closed NEX-C3 service-mode rehearsal CLI."""

import argparse
import sys

from pmca.safe.policy import PolicyViolation
from pmca.safe.state import DeviceGateError
from pmca.safe.transport import TransportUnavailable, make_libusb_backend
from pmca.safe.windows import DeviceProbeError
from pmca.safe.workflow import (
    RealDeviceSource,
    SafeServiceWorkflow,
    WorkflowError,
)


SAFE_ERRORS = (
    PolicyViolation,
    DeviceGateError,
    DeviceProbeError,
    TransportUnavailable,
    WorkflowError,
)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Fail-closed NEX-C3 service-mode rehearsal"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="read Windows USB state only")
    for name in ("enter", "probe"):
        command = commands.add_parser(name)
        command.add_argument("--ack", required=True, metavar="NEX-C3")
    return parser


def build_workflow(command):
    backend = None
    if command in ("enter", "probe"):
        backend = make_libusb_backend()
    elif command != "status":
        raise WorkflowError("unknown safe workflow command")
    return SafeServiceWorkflow(RealDeviceSource(backend))


def print_status(summary):
    print(f"USB state: {summary.state.value}")
    print(f"USB ID: {summary.vid:04x}:{summary.pid:04x}")
    print(f"Instance token: {summary.instance_token}")


def print_probe(summary):
    print("Allowlisted read completed")
    print(f"Service PID: {summary.pid:04x}")
    print(f"Response length: {summary.response_length}")
    print(f"Response SHA-256: {summary.sha256}")


def main(argv=None, workflow=None):
    args = build_parser().parse_args(argv)
    try:
        if workflow is None:
            workflow = build_workflow(args.command)
        if args.command == "status":
            print_status(workflow.status())
        elif args.command == "enter":
            print_status(workflow.enter(args.ack))
        else:
            print_probe(workflow.probe(args.ack))
    except SAFE_ERRORS as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
