"""Read-only Windows PnP discovery for connected Sony USB devices."""

import json
import subprocess

from pmca.safe.state import parse_pnp_records


_PNP_QUERY = (
    "$ErrorActionPreference='Stop'; "
    "@(Get-CimInstance Win32_PnPEntity | "
    "Where-Object { $_.DeviceID -like 'USB\\VID_054C&PID_*' } | "
    "Select-Object DeviceID,Service,Name) | ConvertTo-Json -Compress"
)


class DeviceProbeError(RuntimeError):
    """Raised when the read-only Windows device query cannot be trusted."""


def list_sony_usb_devices(runner=subprocess.run):
    """Return connected Sony USB PnP records from a fixed read-only query."""
    try:
        result = runner(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                _PNP_QUERY,
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise DeviceProbeError("Windows device query timed out") from exc
    if result.returncode != 0:
        raise DeviceProbeError("Windows device query failed")
    if not result.stdout.strip():
        return []
    try:
        records = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise DeviceProbeError(
            "Windows device query returned invalid JSON"
        ) from exc
    if not isinstance(records, list):
        records = [records]
    return parse_pnp_records(records)
