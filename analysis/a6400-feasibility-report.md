# Sony α6400 Firmware Feasibility Decisions

Generation source: validated evidence document (schema version 1).

## creative-look-discovery

Status: `PARTIAL`

Summary: The user-visible Creative Look behavior is documented, but its internal firmware implementation was not located.

Evidence:
- **OBSERVATION** — `https://helpguide.sony.net/ilc/2320/v1/en/contents/0411B_creative_look.html`: Sony documents ten named Creative Look presets, six Custom Look slots, and adjustable contrast, highlights, shadows, fade, saturation, sharpness, sharpness range, and clarity on ILCE-6700.
- **OBSERVATION** — `https://helpguide.sony.net/ilc/2320/v1/en/contents/221h_touch_function_icon.html`: Sony documents a Creative Look touch-function icon on both the still-image and movie shooting screens of ILCE-6700.
- **OBSERVATION** — `analysis/reports/a6700-tw-v2.00.json`: The bounded ILCE-6700 report labels BODYDATA.DAT as opaque-dat and records no hits for the fixed model, version, filename, and updater token allowlist.
- **INFERENCE** — `analysis/reports/a6700-tw-v2.00.json`: Official documentation is sufficient to define the visible Creative Look control surface, but this metadata-only scan does not locate preset tables, image-processing code, or an ILCE-6400 integration point.

Next permitted action: Prepare a separate offline design for approximate Creative Look targets based on the documented controls; do not access or modify the camera.

## creative-look-emulation

Status: `INSUFFICIENT_EVIDENCE`

Summary: Neither an exact nor a close on-camera Creative Look emulation path is demonstrated by the available evidence.

Evidence:
- **OBSERVATION** — `https://helpguide.sony.net/ilc/2320/v1/en/contents/0411B_creative_look.html`: Sony describes the intended appearance and adjustment ranges of Creative Looks but does not publish numerical color transforms or processing algorithms on this Help Guide page.
- **OBSERVATION** — `analysis/reports/a6400-tw-v2.00.json`: The bounded ILCE-6400 updater report records no hits for the fixed model, version, filename, and updater token allowlist.
- **OBSERVATION** — `analysis/reports/a6700-tw-v2.00.json`: The bounded ILCE-6700 package report records no hits for the same fixed token allowlist and does not expose raw firmware content.
- **INFERENCE** — `analysis/reports/a6700-tw-v2.00.json`: Package metadata alone cannot validate a visual match or demonstrate a compatible ILCE-6400 image-pipeline hook.

Next permitted action: Require a separate color-reference and algorithm-validation design before considering emulation; do not deploy code to the camera.

## touch-menu

Status: `INSUFFICIENT_EVIDENCE`

Summary: ILCE-6700 menu and shooting-screen touch behavior is documented, but ILCE-6400 compatibility is not established.

Evidence:
- **OBSERVATION** — `https://helpguide.sony.net/ilc/2320/v1/en/contents/211h_touchpanel_settings.html`: Sony documents separate ILCE-6700 touch enablement for the shooting screen, footer icons, playback screen, and menu screen, plus swipe actions and touch shooting functions.
- **OBSERVATION** — `https://www.sony.com.tw/zh/electronics/support/e-mount-body-ilce-6000-series/ilce-6400/downloads/00016145`: Sony lists animal Eye AF, RMT-P1BT support, and stability improvements for ILCE-6400 firmware 2.00; this release-note list does not document a touch-menu interface.
- **INFERENCE** — `analysis/reports/a6700-tw-v2.00.json`: The existence of touch menus on ILCE-6700 does not demonstrate reusable UI code, compatible touch-controller behavior, or an ILCE-6400 firmware interface.

Next permitted action: Obtain bounded evidence of an ILCE-6400 touch/UI interface in a separate study; do not test UI code on the camera.

## vertical-ui

Status: `INSUFFICIENT_EVIDENCE`

Summary: The official evidence covers flipped touch-icon placement, not a transplantable full portrait-oriented menu UI.

Evidence:
- **OBSERVATION** — `https://helpguide.sony.net/ilc/2320/v1/en/contents/211h_touchpanel_settings.html`: Sony documents an ILCE-6700 setting that flips left and right touch-function icon positions when the monitor is flipped.
- **OBSERVATION** — `https://helpguide.sony.net/ilc/2320/v1/en/contents/221h_touch_function_icon.html`: Sony documents touch-function icons on the left and right sides of the ILCE-6700 shooting screen and their show/hide swipe behavior.
- **INFERENCE** — `analysis/reports/a6700-tw-v2.00.json`: These user-facing descriptions and opaque package metadata do not establish full vertical menu rotation or a compatible ILCE-6400 rendering path.

Next permitted action: Find an official definition and bounded implementation interface for portrait UI behavior before any separate design; do not access the camera.

## signature-enforcement

Status: `INSUFFICIENT_EVIDENCE`

Summary: Package metadata shows a PE certificate table for the ILCE-6400 updater but does not establish camera-side signature enforcement or a bypass.

Evidence:
- **OBSERVATION** — `analysis/reports/a6400-tw-v2.00.json`: The ILCE-6400 Windows updater is parsed as a five-section PE with a nonzero certificate-table offset and size.
- **OBSERVATION** — `analysis/reports/a6700-tw-v2.00.json`: The ILCE-6700 BODYDATA.DAT package is labelled opaque-dat and has no PE summary in the bounded report.
- **INFERENCE** — `analysis/reports/a6400-tw-v2.00.json`: A PE certificate-table entry is not proof of the camera's enforcement boundary and does not provide a signature bypass.
- **INFERENCE** — `analysis/reports/a6700-tw-v2.00.json`: The different outer package formats do not support a direct donor-package transplant conclusion.

Next permitted action: Any further signed-container research requires a separate offline design and a verified recovery gate; do not attempt a bypass.

## hardware-dependencies

Status: `INSUFFICIENT_EVIDENCE`

Summary: The study does not establish whether ILCE-6400 hardware can support the requested ILCE-6700 UI and image-processing behavior.

Evidence:
- **OBSERVATION** — `https://helpguide.sony.net/ilc/2320/v1/en/contents/0411B_creative_look.html`: The Creative Look Help Guide page identifies the documented camera as ILCE-6700.
- **OBSERVATION** — `https://helpguide.sony.net/ilc/2320/v1/en/contents/211h_touchpanel_settings.html`: The Touch Panel Settings Help Guide page identifies the documented camera as ILCE-6700.
- **OBSERVATION** — `analysis/reports/a6400-tw-v2.00.json`: The ILCE-6400 artifact in this study is a Windows PE updater container.
- **OBSERVATION** — `analysis/reports/a6700-tw-v2.00.json`: The ILCE-6700 artifact in this study is an opaque DAT container.
- **INFERENCE** — `analysis/reports/a6700-tw-v2.00.json`: These sources do not determine touch-controller, display-orientation, memory, image-processor, or firmware-ABI compatibility between the two camera models.

Next permitted action: Require manufacturer architecture documentation or other non-invasive hardware evidence before revisiting compatibility; do not probe the camera.

## recovery

Status: `BLOCKED`

Summary: Camera-side experimentation is blocked because this study has no verified ILCE-6400 restore path for a failed modified firmware.

Evidence:
- **OBSERVATION** — `https://www.sony.com.tw/zh/electronics/support/e-mount-body-ilce-6000-series/ilce-6400/downloads/00016145`: Sony warns that sudden power loss during the ILCE-6400 update may make the camera inoperable and documents only the official updater workflow on this page.
- **OBSERVATION** — `https://www.sony.com.tw/zh/electronics/support/e-mount-body-ilce-6000-series/ilce-6700/software/00298440`: Sony warns not to remove power during the ILCE-6700 update and documents that non-applicable system software is rejected for the target model.
- **OBSERVATION** — `analysis/reports/a6400-tw-v2.00.json`: The bounded ILCE-6400 report contains package format, PE metadata, entropy windows, and allowlisted token hits; it does not demonstrate a restore operation.
- **INFERENCE** — `analysis/reports/a6400-tw-v2.00.json`: Without an independently verified restore path, the official inoperability warning and the lack of a demonstrated restore interface make camera-side firmware experiments unacceptable under this study's safety gate.

Next permitted action: End this study offline; require a separately validated ILCE-6400 recovery method and a nonessential test body before any camera-side proposal.
