# NEX-C3 WinUSB Service Rehearsal and Recovery

This procedure changes only Windows' driver binding for the connected NEX-C3. It does
not install firmware or add camera features. Stop immediately on any unexpected USB ID,
camera warning, failed test, or incomplete driver restoration.

The procedure permits one service transition, authentication, and one
ProductInfo/READ_HASP read. It forbids firmware, settings, backup, file, memory, test,
terminal, sonar, and unrestricted shell operations.

## Preconditions

- α6400 physically disconnected.
- Exactly one Sony USB camera connected.
- NEX-C3 battery fully charged; memory card removed; Sony desktop apps closed.
- Camera confirmed operational before starting: power, menu, shutter, and playback.
- All automated tests in the implementation plan pass.
- Zadig obtained from its official site and run as administrator only at the named steps.
- Work from `C:\Users\Bubble\ChatGPT\Sony-PMCA-RE-nex-c3-safe`.

Do not continue if any precondition is false.

## 1. Confirm the Original Normal State

With the NEX-C3 connected in USB mass-storage mode, run:

```powershell
& .\.venv\Scripts\python.exe .\safe_service.py status
```

Required result:

```text
USB state: NORMAL_MSC
USB ID: 054c:0490
Instance token: <12 hexadecimal characters>
```

The token is a redacted correlation value, not the USB serial number. Stop if the state,
VID, PID, device count, or driver differs.

## 2. Bind Only Normal PID 054C:0490 to WinUSB

1. Open Zadig as administrator.
2. Select **Options → List All Devices**.
3. Select only the row whose USB ID is `054C:0490` and which corresponds to the connected
   NEX-C3.
4. Record the current binding as Microsoft USB mass storage / `USBSTOR`.
5. Select `WinUSB` as the replacement driver.
6. Replace the driver for that exact device only.

Do not select a USB hub, composite parent, storage card reader, α6400, or service PID.
Do not delete any driver package.

Re-run:

```powershell
& .\.venv\Scripts\python.exe .\safe_service.py status
```

Required result:

```text
USB state: NORMAL_WINUSB
USB ID: 054c:0490
```

Stop and follow **Emergency Recovery** if this exact state is not reported.

## 3. Request the One Service-Mode Transition

Run once:

```powershell
& .\.venv\Scripts\python.exe .\safe_service.py enter --ack NEX-C3
```

The command first reads the camera model through the allowlisted identity query. It will
refuse to transition unless the reported model is exactly `NEX-C3`.

Required resulting state is exactly one of:

```text
USB state: SERVICE_UNBOUND
USB ID: 054c:02a9
```

```text
USB state: SERVICE_UNBOUND
USB ID: 054c:0336
```

or the same PID in `SERVICE_WINUSB`. Stop on any other VID, PID, state, model, timeout,
warning, or multiple-device report.

## 4. Bind Only the Newly Appearing Service PID

Skip this section if `enter` already reported `SERVICE_WINUSB`.

1. Refresh Zadig's device list.
2. Select only the newly appearing `054C:02A9` or `054C:0336` row.
3. Select `WinUSB`.
4. Replace the driver for that exact service device only.

Then run:

```powershell
& .\.venv\Scripts\python.exe .\safe_service.py status
```

Required result is `SERVICE_WINUSB` with the same `054c:02a9` or `054c:0336` PID seen
after transition. Stop on any mismatch.

## 5. Perform the Single Allowlisted Read

Run once:

```powershell
& .\.venv\Scripts\python.exe .\safe_service.py probe --ack NEX-C3
```

Required output contains only:

```text
Allowlisted read completed
Service PID: 02a9 or 0336
Response length: <integer>
Response SHA-256: <64 hexadecimal characters>
```

The raw response must not be displayed, redirected, logged, or written to a file. Do not
run the probe repeatedly after a success.

Immediately after the read:

1. Turn the NEX-C3 off.
2. Disconnect USB.
3. Remove the battery for 30 seconds.
4. Reinstall the battery.
5. Start the camera normally without USB.

Stop and use **Emergency Recovery** if the camera shows a warning or fails to start.

## 6. Restore Microsoft USB Mass Storage

Reconnect the normally booted NEX-C3 in mass-storage mode.

1. Open Device Manager.
2. Locate only the present NEX-C3 device with USB ID `054C:0490`.
3. Update that device to the Microsoft in-box USB Mass Storage driver.
4. If Windows does not offer it, uninstall only that exact present device instance.
5. Do **not** select an option to delete the driver package.
6. Disconnect and reconnect the camera, then select the Microsoft USB Mass Storage
   driver if Windows asks.

Do not remove unrelated WinUSB/libusb packages or any USB hub, controller, card reader,
α6400, or service-mode device package.

Run:

```powershell
& .\.venv\Scripts\python.exe .\safe_service.py status
```

Required result:

```text
USB state: NORMAL_MSC
USB ID: 054c:0490
```

The rehearsal is not complete until this exact state is restored.

## 7. Acceptance Checklist

- [ ] Windows mounts the camera/storage normally.
- [ ] Safe status reports `NORMAL_MSC` and `054c:0490`.
- [ ] Camera powers on without a warning.
- [ ] Menu navigation works.
- [ ] Shutter captures one test photo after reinserting the memory card.
- [ ] Playback shows the test photo.
- [ ] Power-off and a second power-on both work normally.

If any box remains unchecked, stop. Do not attach or modify the α6400.

## Emergency Recovery

1. Close the safe CLI and Zadig.
2. Turn the NEX-C3 off.
3. Disconnect USB.
4. Remove the battery for 30 seconds.
5. Reinstall the battery and attempt a normal boot without USB.
6. Reconnect only after normal boot.
7. In Device Manager, restore only the exact present `054C:0490` NEX-C3 instance to
   Microsoft USB Mass Storage.
8. Do not delete a driver package.
9. Re-run `safe_service.py status` and require `NORMAL_MSC` at `054c:0490`.

If the NEX-C3 still fails after battery removal and normal-driver restoration, stop. Do
not try terminal, memory, firmware, backup, file, unrestricted shell, or α6400 recovery
commands.

## Meaning of a Successful Rehearsal

Success proves only that this constrained Windows driver, transition, authentication,
single-read, and recovery workflow works on the donor NEX-C3. It does not prove that the
α6400 can accept a newer vertical touch UI, touch menu control, Creative Looks, or
cross-model firmware. Any α6400 work requires a separate approved read-only design and a
model-specific recovery path.
