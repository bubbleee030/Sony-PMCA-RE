# NEX-C3 Service-Mode Rehearsal Design

## Objective

Prove a reversible Windows 11 USB-driver and Sony service-mode workflow on the
expendable NEX-C3 before considering the same workflow on the user's only working
ILCE-6400. The rehearsal ends after authentication and one allowlisted product-info
read. It does not modify camera firmware or settings.

## Scope

The rehearsal covers:

- positively identifying the NEX-C3 in normal mass-storage mode;
- recording its USB identity and current Microsoft driver binding;
- replacing only that device's Windows binding with WinUSB;
- temporarily entering Sony service mode;
- binding the newly enumerated Sony service-mode device to WinUSB;
- authenticating and executing one allowlisted read;
- exiting, power-cycling, and restoring normal mass-storage operation;
- verifying that Windows recognizes the camera and that the camera can still shoot.

It does not cover firmware dumping, terminal access, LCD rendering, touchscreen
input, Creative Look implementation, startup persistence, or any camera write.

## Selected Approach

Use WinUSB through Zadig rather than PMCA's legacy `libusb-win32` recommendation.
WinUSB is a Microsoft driver suitable for modern Windows, while PyUSB/libusb can
communicate with devices bound to it. UsbDk is excluded because installing a system
filter adds complexity and a broader failure surface.

The normal device must initially match all of these conditions:

- vendor ID `054C` (Sony);
- product ID `0490` (the connected NEX-C3);
- exactly one matching physical device;
- normal Microsoft USB mass-storage binding (`usbstor.inf`);
- model identity query returns `NEX-C3`.

After transition, the probe accepts exactly one Sony service-mode device with vendor
ID `054C` and a product ID from PMCA's known service-mode set: `02A9` or `0336`.
Any other identity or device count fails closed.

## Components

### Status Probe

Reports USB VID/PID, device instance, model, and active driver. It redacts the camera
serial and performs no transition. The existing `safe_info.py` provides the model
identity portion.

### Transition Client

A new, separate executable path will expose three explicit operations:

- `status`: inspect the current normal/service state without changing it;
- `enter`: validate the NEX-C3 identity, authenticate, and request temporary service
  mode;
- `probe`: authenticate an already-enumerated service device, execute one approved
  product-information read, report only a length and digest, then stop the session.

The client will not import or dispatch through PMCA's unrestricted interactive
`CameraShell`.

### Packet Policy

Normal-mode discovery permits only `DevInfoSender/GetModelInfo`.

Service-mode probing permits only:

- authentication packets required by Sony service mode; and
- service function `0x0010`, category `0x0000`, command `0x001F`
  (`ProductInfo/READ_HASP`) with selector zero.

The following service families are rejected before transport:

- firmware update (`0x0020`);
- adjustment/backup control (`0x0040`);
- test mode (`0xFF00`);
- file control (`0xFF01`);
- terminal/sonar (`0xFF02`);
- memory access (`0xFF03`);
- product-info terminal changes (`0x00F1`).

### Driver Procedure

Driver binding is a deliberate manual checkpoint:

1. Capture the current PnP device instance and `usbstor.inf` binding.
2. In Zadig, enable "List All Devices" and select only the instance matching
   `VID_054C&PID_0490`.
3. Install WinUSB for that exact instance.
4. Run `enter`; wait for the device to re-enumerate.
5. Select only the newly appearing Sony service-mode PID (`02A9` or `0336`) and bind
   it to WinUSB.
6. Run `probe`.
7. Stop the service session and power-cycle the camera.
8. Restore the normal device to Microsoft's USB Mass Storage Device driver.

No driver package is deleted from the Windows driver store.

## State and Data Flow

The workflow is a fail-closed state machine:

`NORMAL_MSC -> NORMAL_WINUSB -> TRANSITIONING -> SERVICE_UNBOUND -> SERVICE_WINUSB -> PROBED -> POWER_CYCLE -> NORMAL_MSC`

Each operation verifies its expected input state. A mismatch stops without trying a
fallback driver, broader device match, firmware command, or write operation.

The probe prints only model identity, USB state, response length, and a SHA-256
digest. It does not save service data or a firmware dump.

## Error Handling and Recovery

On any protocol error, timeout, unexpected PID, multiple Sony devices, or denied
packet, the client stops. It does not automatically retry with a different command.

Recovery sequence:

1. Close the probe and Zadig.
2. Turn off the NEX-C3 and disconnect USB.
3. Remove the battery for at least 30 seconds, then reinstall it.
4. In Device Manager, uninstall only the device instance whose recorded VID/PID and
   instance ID match the rehearsal device. Do not select removal of unrelated driver
   packages.
5. Reconnect the powered camera in Mass Storage mode.
6. Select Microsoft's "USB Mass Storage Device" driver if Windows does not restore
   `usbstor.inf` automatically.
7. Confirm `VID_054C&PID_0490`, `usbstor.inf`, mounted storage, and normal camera
   startup before any further work.

If the camera fails to start after a battery removal, the rehearsal stops. No stronger
recovery, firmware write, or α6400 experiment is attempted.

## Testing

Before hardware transition:

- unit-test every allowlisted packet;
- test rejection of firmware, adjustment, file, memory, terminal, malformed, and
  unknown packets;
- test exact NEX-C3 VID/PID/model gating;
- test rejection when zero or multiple Sony devices are present;
- test state-machine transitions using fake USB devices;
- run formatting/static checks and the full safety test suite.

Hardware acceptance checks:

- normal identity recorded before driver change;
- service authentication succeeds once;
- the single approved product-information read succeeds;
- service data is not written to disk;
- normal Microsoft driver is restored;
- camera mounts as storage after restoration;
- menus, shutter, playback, and image recording work normally.

## Success and Stop Conditions

Success means the NEX-C3 completes the full transition and restoration sequence with
all hardware acceptance checks passing.

The project stops before α6400 service mode if restoration is incomplete, the camera
behaves abnormally, an unexpected USB identity appears, or any safety test fails.

Passing this rehearsal demonstrates the Windows driver and service-authentication
workflow only. It does not prove that NEX-C3 UI or display code is compatible with the
α6400's CXD90045 platform.
