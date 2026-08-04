"""Allowlisted USB wrappers for the constrained service rehearsal."""

import libusb_package

from pmca.safe.policy import validate_identity_query, validate_service_read
from pmca.usb.sony import SonyMscExtCmdDevice, SonySenserDevice


class TransportUnavailable(RuntimeError):
    """Raised when the bundled libusb backend cannot be loaded."""


def make_libusb_backend():
    """Return the bundled libusb backend instead of searching system DLLs."""
    backend = libusb_package.get_libusb1_backend()
    if backend is None:
        raise TransportUnavailable("bundled libusb backend is unavailable")
    return backend


class AllowlistedIdentityDevice(SonyMscExtCmdDevice):
    """MSC device that permits only the normal-mode identity query."""

    def sendSonyExtCommand(self, cmd, data, bufferSize):
        validate_identity_query(cmd, data)
        return super().sendSonyExtCommand(cmd, data, bufferSize)


class AllowlistedSenserDevice(SonySenserDevice):
    """Senser device that permits only ProductInfo/READ_HASP."""

    def sendSenserPacket(self, pFunc, data, oData=None):
        validate_service_read(pFunc, data, oData)
        return super().sendSenserPacket(pFunc, data, oData)
