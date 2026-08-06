# α6400A Updater and α6400 Creative Style Deep Dive

## Scope and safety state

- Analysis type: static and offline
- Camera connected or accessed: no
- Sony camera binary executed: no
- Camera transport or partition write: no
- Installable package produced: no
- Signature or model bypass established: no
- Offline patched runtime library produced: yes, ignored research artifact only

This report supersedes the older missing-updater-partition assumptions in
`a6400-updater-re-report.md`. It does not supersede that report's prohibition
on camera execution or its recovery requirements.

## Pinned source

The official ILCE-6400A Windows updater supplied for this study is:

- Download location: `D:\Downloads\Update_ILCE6400AV101.exe`
- Size: `324,175,032` bytes
- SHA-256: `fd6ae50755a9202a8b506b6b77aa27ab41ae717e96f05a0d4e2ad699b40d9ad1`
- Ignored byte-identical analysis copy:
  `.artifacts/sony-firmware/a6400a-eu-v1.01/Update_ILCE6400AV101.exe`

## What the α6400A firmware was needed for

The α6400A package is not a donor for the α6700 interface or modern Creative
Look. Its value is that it belongs to the same CXD90045 updater family as the
original α6400 and contains an authentic persistent camera updater partition.
That partition closes several previously unobserved enforcement boundaries.

| Field | Original α6400 TW 2.00 | α6400A 1.01 |
|---|---:|---:|
| Crypter family | `CXD90045` | `CXD90045` |
| Updater USB ID | `054c:03e2` | `054c:03e2` |
| FDAT model ID | `0x81030011` | `0x81030017` |
| Region | `0` | `0` |
| Partition layout | baseline | byte-identical `partinf.conf` |

The different FDAT model ID is intentional and remains enforced. Same SoC and
updater family do not make an α6400A package valid for an original α6400.

## Authentic updater partition

The α6400A `0400_updater/dev/nflasha1` image is now recovered:

- Size: `8,323,072` bytes
- SHA-256: `c9040270ad886214c5656894b90fb1e839a3ab942cb65726633d8f1f1221c093`
- It is byte-identical to the updater partition in the analyzed α7 III 4.04
  package.

The partition contains the updater initrd, `sauu`, shell orchestration, and
`/etc/VerificationKey.pem`. No private key material was recovered or printed.

## Camera-side authenticity boundary

Static ARM/Thumb analysis of authentic `sauu` recovered the following chain:

1. Function `0x10368` hashes the complete verification PEM with SHA-1.
2. It obtains an expected 20-byte digest from an OSAL synchronous service and
   rejects a mismatch. Replacing the PEM file alone therefore does not replace
   the trust anchor.
3. Function `0x104e0` loads the verified public key, SHA-256 hashes the candidate
   signed bytes, and calls `RSA_verify` with a 256-byte RSA signature.
4. Caller `0x10a88` defines the firmware record as:
   `encrypted body | 16-byte IV/trailer | 256-byte RSA signature`.
5. The signed range is the complete record except its final 256-byte signature,
   so the 16-byte IV/trailer is covered by the RSA/SHA-256 signature.

This establishes a real camera-updater signature boundary. It does not provide
a signing key, a valid custom signature, or an installable custom UFP.

## Model, region, and version guard

Guard handler `0xdf5c` produces the observed host status codes:

- `0x140`: model mismatch
- `0x141`: region mismatch
- `0x142`: version/current-firmware validity mismatch

The comparison functions are:

- `0xdea2`: incoming model versus current model
- `0xde84`: incoming region versus current region
- `0xdec0`: incoming major/minor version plus `IsCurrentFirmwareValid`

Current identity is read from the real camera partitions mounted at
`/tmp_updater/updater/current`:

- `/dev/nflasha2`: current version
- `/dev/nflasha1`: current model and region

The shared predicate at `0xdcc0` reads `/tmp_updater/accy/ACCY`, parses an ASCII
hex accessory list, and only relaxes those comparisons for a matching accessory
identifier. The α6400A package contains no `ACCY` file. This is not a general
service or camera-model bypass.

## What `sauu -s` actually does

Three factories create the same updater class:

- normal: mode `3`
- minor (`-m`): mode `5`, flag `1`
- version skip (`-s`): mode `7`, flag `1`

The mode number is stored in the package handler but does not disable the guard.
The shared flag triggers firmware-information method `0xfe34`, whose only
recovered effect is function `0x14638`: after an already-complete update it
removes mode flag files from `/dev/nflasha2`. It does not skip RSA, model, region,
or version comparisons.

Before launching `sauu -s`, `execute_ufp.sh` copies the current camera's `dat2`,
`dat3`, and `dat4` files to `/ramdsk`. That is part of the surrounding
host/service version-skip workflow. It is not an unsigned escape inside `sauu`,
which still reads and enforces the real partition identities.

## α6400A UI and color evidence

Exact symbol and resource comparisons between original α6400 2.00 and α6400A
1.01 found maintenance changes, not a modern interface transplant:

- `CautionConfig.so` adds Privacy Notice setting nodes and removes several older
  Wi-Fi-setting nodes.
- `viewUnified2.so` adds access-log deletion/sending and the Privacy Notice
  reference.
- Exact searches for `Creative Look` and `CreativeLook` return no files or
  symbols in either filesystem.

Therefore α6400A 1.01 does not supply α6700-style Creative Look or the requested
vertical/touch menu UI under an obvious dormant resource or symbol boundary.

## Native α6400 Creative Style selector

The original α6400 2.00 function
`CmnViewSettingNodeCreativeStyle::_getSubNodeEv` uses a Thumb `tbb` jump table.
Its original α6400 model slot selects the `TypeEmnt` graph with byte `0x1e` at
file offset `0x7db9b7`. The dormant `Default` graph is selected by byte `0x37`.

α6400A independently confirms the same selector structure: its corresponding
slot is at `0x7db9a3`, also originally `0x1e`; the shifted code and jump table
are otherwise equivalent apart from relocated literals.

The fail-closed offline patcher in `pmca/analysis/creative_style_patch.py`
requires the exact original α6400 2.00 size, SHA-256, and selector byte before
making the one-byte change.

Verified ignored output:

- Path:
  `.artifacts/patched-updater-lab/a6400-v2.00-native-creative-style/CautionConfig.so`
- Size: `12,070,800` bytes
- SHA-256: `9a2a773e164cdc13909e3b6e44dc9039e9afa9eb676cd50885e06b8aa1eeef21`
- Difference count: `1`
- Difference: offset `0x7db9b7`, `0x1e -> 0x37`

This exposes a firmware-native Creative Style graph already present in α6400
2.00. It does not add α6700 Creative Look processing, extra adjustment axes, a
new menu framework, or a valid package/signature.

## α6400 bounded UI-dispatch and UXC correlation

Read-only Ghidra analysis of the pinned α6400 2.00 `viewUnified2.so` used four
explicit roots: the `ViewSettingMenu` event switch at analysis address
`0x22355e`, plus three `ViewStlrec` source file offsets (`0x1ab41c`,
`0x1ab2d2`, and `0x1b1e76`) normalized to analysis addresses `0x1bb41c`,
`0x1bb2d2`, and `0x1c1e76`. The bounded export recorded 2,046 call sites:
1,697 resolved direct calls and 349 unresolved indirect calls. Unresolved
indirect calls were terminal blockers, never traversed graph edges. The search
depth cap was 32.

The two previously recovered direct `ViewSettingMenu` paths remain useful
semantic boundaries:

- `0x22355e -> 0x222f68 -> 0x43156c -> 0x1613f0`: `0x222f68` reads
  `ViewBase::GetEventId`; event `0x22` initializes recording state and reaches
  `CmnViewModelWrpTouchPanel::getInfoDataDetectMode`. The terminal value only
  contributes to setting availability/caution state.
- `0x22355e -> 0x21c644 -> 0x1626cc -> 0x41b244 -> 0x41ae08`:
  concurrent-HDMI display transitions reach EVF touch-pad area on/off helpers
  and may force-release the touch panel. This is display/input configuration,
  not menu selection.

A bounded static direct-call search resolved all 21 supplied
`ViewSettingMenu` candidate roots and found no path to the master layout factory
at `0x181f18`, the vertical-info layout factory at `0x24222c`, the function
owning the resource-touch call at requested offset `0x2307d0`, or the function
owning SampleView setup at requested offset `0x6666a4`. The earlier
`ViewStlrec` search resolved 10 of 25 supplied candidate addresses and found no
direct path to either layout factory.

The UXC scanner then found the same five little-endian layout class IDs in both
target resources: five references in `share/app/master_camera.uxc` and five in
`share/app/viewStlrec.uxc`. Exact vertical layout names were not present. These
ten findings are references only; they do not identify a selector predicate,
factory invocation, geometry, or executable dispatch.

Read-only executable cross-reference analysis mapped those IDs to the master
factory, the vertical-info factory, five individual class-ID owners, and two
functions that reference all five IDs. A depth-32 search from the three
`ViewStlrec` roots traversed resolved direct calls and treated every unresolved
indirect call as terminal. It found no path to any of those nine owners. The
matching `ViewSettingMenu` search also found no path to either known
touch/resource owner. In total, the committed report contains 17 bounded
negative searches: six earlier direct-call searches and 11 mixed-graph
searches with explicit terminal-indirect semantics.

No resolved virtual/table path was found, so none was promoted into the report.
All nine modern-interface behavior-contract items remain `UNESTABLISHED`:
landscape layout, both portrait layouts, orientation-based layout selection,
control-direction transform, touch-coordinate transform, menu hit testing,
menu selection dispatch, and UI-state persistence. The evidence therefore does
not establish full settings-menu touch or a modern vertical UI. Virtual targets
behind the 349 unresolved call sites and cross-module `viewUnified7.so` layout
selection remain open static-analysis questions, not positive capability
claims.

## Donor roles and remaining portability gap

- α6700: real behavioral donor for modern Creative Look and newer menu touch.
- α7 V: real behavioral donor for the requested vertical shooting display.
- α7 III: same-era Creative Style and updater-partition evidence; not a donor
  for α6700-style Creative Look or the newest vertical UI.
- α6400A: closest updater/trust-boundary control sample; not a modern UI donor.

Feature existence on a donor and feature portability to α6400 are different
claims. The target now has pinned vertical-layout class and UXC references, but
portability still lacks an orientation-to-layout selector, verified portrait
geometry, a menu coordinate consumer/hit-test/selection chain, widget
resources, Creative Look tables and axes, image-pipeline ABI, memory budget,
signature reconstruction, and an independently verified recovery path.

## Next safe experiments

1. Resolve selected `viewUnified2.so` indirect call sites and the cross-module
   `viewUnified7.so` layout boundary with read-only metadata only; require a
   complete ordered path before changing any UI behavior status.
2. Start the first-class Creative Look milestone by mapping the target's native
   settings-node, preset-storage, and image-pipeline interfaces to the ten-look,
   Custom Look, and adjustment-axis behavior contract. The existing Creative
   Style recipes remain the last fallback, not the primary design.
3. Use α6700 for Creative Look/menu behavior and α7 V for vertical-display
   behavior, without assuming donor code or hardware-dependent processing is
   portable to α6400.
4. Keep every modified runtime file outside a Sony updater package. Before any
   future camera test, independently demonstrate a laptop-based route that can
   restore the exact original Taiwan/region-0 α6400 2.00 updater identity
   pinned in this repository after failure; an in-camera factory-reset feature
   is not required, but an external recovery path is.
