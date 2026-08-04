import unittest
from unittest.mock import patch

from pmca.usb.driver.generic import libusb


class LibusbBackendTests(unittest.TestCase):
    @patch.object(libusb.usb.core, "find")
    def test_explicit_backend_is_forwarded(self, find):
        backend = object()
        find.return_value = []

        list(libusb._listDevices(0x054C, libusb.USB_CLASS_MSC, backend))

        find.assert_called_once_with(
            find_all=True, idVendor=0x054C, backend=backend
        )

    @patch.object(libusb.usb.core, "find")
    def test_omitted_backend_preserves_existing_discovery(self, find):
        find.return_value = []

        list(libusb._listDevices(0x054C, libusb.USB_CLASS_MSC))

        find.assert_called_once_with(find_all=True, idVendor=0x054C)

    @patch.object(libusb, "_listDevices")
    def test_context_passes_its_backend(self, list_devices):
        backend = object()
        list_devices.return_value = []

        context = libusb.MscContext(backend=backend)
        list(context.listDevices(0x054C))

        list_devices.assert_called_once_with(
            0x054C, libusb.USB_CLASS_MSC, backend
        )


if __name__ == "__main__":
    unittest.main()
