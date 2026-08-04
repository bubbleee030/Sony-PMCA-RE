"""Pure packet allowlists for the constrained camera workflow."""

import struct


class PolicyViolation(RuntimeError):
    """Raised before an unapproved packet reaches a USB transport."""


def validate_identity_query(group, payload):
    """Allow only DevInfoSender/GetModelInfo with a zero-data read header."""
    if len(payload) < 16:
        raise PolicyViolation("Sony command header is truncated")
    data_size, subcommand, direction = struct.unpack_from("<IHH", payload)
    if (group, subcommand) != (1, 1):
        raise PolicyViolation("Sony external command is not allowlisted")
    if direction != 0 or data_size != 0:
        raise PolicyViolation("GetModelInfo must be a zero-data read")
    if any(payload[16:]):
        raise PolicyViolation("GetModelInfo padding must contain only zero bytes")
    return "DevInfoSender/GetModelInfo"


def validate_service_read(pfunc, payload, output_sink=None):
    """Allow only ProductInfo/READ_HASP with selector zero and no sink."""
    if output_sink is not None:
        raise PolicyViolation("streaming service output is forbidden")
    if pfunc != 0x0010 or len(payload) != 5:
        raise PolicyViolation("service packet is not allowlisted")
    category, command = struct.unpack_from("<HH", payload)
    if (category, command) != (0, 0x001F) or payload[4] != 0:
        raise PolicyViolation(
            "only ProductInfo/READ_HASP selector zero is allowed"
        )
    return "ProductInfo/READ_HASP"
