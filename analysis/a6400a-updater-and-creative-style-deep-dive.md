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

## First-class Creative Look boundary result

The first-class investigation is now defined and traced independently of the
Creative Style fallback. Its exact contract contains the ten bases `ST`, `PT`,
`NT`, `VV`, `VV2`, `FL`, `IN`, `SH`, `BW`, and `SE`; eight separate axes; five
stack layers; eight workflow actions; and live-view, still-JPEG, and movie
outputs.

Read-only Ghidra analysis used the digest-pinned original α6400 2.00
`CautionConfig.so`. Correcting the ELF virtual-address mapping to Ghidra's
`+0x10000` image base resolved the Creative Style selector at analysis address
`0x7eb958` and the compiled `Default` graph at `0xb936cc`. The bounded export
found ten named Creative Style functions, one selector-to-graph data reference,
and nine direct calls, with no unresolved direct or indirect calls in this
scope. This proves a real menu-graph selection path only. It does not identify
a first-class Creative Look interface, state model, base-look table load, axis
processing path, or output sink.

Accordingly, all five Creative Look layers remain `UNESTABLISHED`; all eight
axes remain independently `UNESTABLISHED`; and live view, still JPEG, and movie
remain unsupported by positive pipeline evidence. The classifications are not
`HARDWARE_BLOCKED`: current evidence does not prove impossibility, but it also
does not support a target-native, target-reimplementation, or donor-compatible
claim. The α6700 and α7 V sources remain authenticated but opaque, so they
cannot supply donor functions, tables, offsets, or ABI evidence.

The normalized evidence is recorded in
`analysis/a6400-creative-look-boundary.json`, while the layer and workflow
contract is in `analysis/a6400-creative-look-stack.json`. Creative Style below
remains a last-resort approximation and cannot satisfy this acceptance gate.

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

### Product-graph selector versus current selection

The selector's input is now structurally resolved. Creative Style
`_getSubNode()` at `0x7db958` and Picture Profile `_getSubNode()` at `0x7dbc04`
each call the same imported `BackupManager::Bkup_Read(int, void*)` binding with
ID `0x01070316` and a zero-initialized one-byte stack-local output. Sharing this
read across two independent menu families establishes a product/menu-graph
configuration selector, not the user's currently selected Creative Style or
Picture Profile.

This also clarifies two different value domains: `0x43` is the shipped
read-only backup value selecting the α6400's `TypeEmnt` product graph, while
`0x1e` and `0x37` in the offline patch experiment are TBB dispatch-entry values
for the TypeEmnt and Default code paths. They are not persisted Creative Style
values.

The Creative Style vtable separately inherits 16 generic selected/state methods.
A bounded trace resolves 22 virtual-interface dispatches covering selected-item
lookup, state lookup, selection, unselection, and reinitialization. Four-byte
in-memory fields at offsets `0x18`, `0x20`, and `0x24` participate in that generic
state machinery. Ten callbacks on resolved child objects remain indirect and
their final implementations are not statically established. No model value,
model setter, renderer, menu-event, commit, or persistence binding has yet been
located inside that bounded settings-node slice. The fail-closed record is
`analysis/a6400-creative-style-selected-state-dispatch.json`.

### Generic model/cursor boundary

The next target-side layer is now pinned in the exact α6400 2.00
`viewUnified2.so`. Seven `CmnSettingNodeUtil` methods cover cursor movement,
value lookup, item-change cursor synchronization, belt-widget update, and the
named `setValueToModel()` helper. Across those methods, 22 exact four-byte
utility-field accesses and 17 bounded virtual-interface calls establish real
generic in-memory cursor/selection control rather than a resource-only menu.

`setValueToModel()` calls the defined `getProcIdForItem()` and
`getProcValIdForItem()` helpers, then reaches local targets at `0x2fe74c` and
`0x2fe806`. Those same targets occur in the ten-way local call surface of
`moveCursor()`. Both unnamed routines contain proven widget display-state calls
through `LayoutableWidgetBase::setDispState(bool)`, but also retain unresolved
virtual effects. They therefore cannot be classified as widget-only or as
model-commit terminals. The nearby `updateBeltWidget()` call resolves
through the PLT to a defined `PAS_MenuSelectBeltZako::updateWidget()` routine,
which also reaches `GEN_Icon::setImage()` and therefore proves widget-state and
content mutation, but not a terminal renderer/draw path.

This proves a generic menu-to-model boundary exists on α6400, which is useful
for reproducing a newer interaction pattern without importing a hardware-only
processor feature. At this stage it did not bind this helper instance to the Creative
Style root, identify the selected style's storage, prove a final setter or
commit, publish a menu event, reach a renderer, route touch, or reach
`BackupManager`/durable persistence. The fail-closed record is
`analysis/a6400-creative-style-model-cursor-boundary.json`.

Cross-module consumers narrow the ownership gap without closing it. Two exact
anonymous `.ARM.exidx` owners in `viewUnified4.so` call
`setCursorOnItemChange()` followed by `setValueToModel()`. A third owner in
`viewUnified7.so` calls those two helpers and then `getProcVal()`. These are
seven direct Thumb transfers across three ordered generic UI/model sequences.

The same two modules also import `cmnViewSettingNodeRootCreativeStyle`, but all
eight relocations are data-only `.data`/`.got` publications outside every one
of the three executable owners. None of the owners has a matching nonzero-sized
dynamic function symbol, and no typed or path-sensitive indirect edge binds a
Creative Style root cell back to a sequence. This is module co-containment, not
a Creative Style-specific model or commit path. The fail-closed record is
`analysis/a6400-creative-style-generic-model-consumers.json`.

Bounded owner provenance first established three exact `TBH` tails and receiver
paths. Its direct scan covers canonical decoded prefixes rather than every
unwind interval to completion, so the recorded predecessors remain positive
bounded evidence rather than exhaustive uniqueness claims. The fail-closed
predecessor record is `analysis/a6400-generic-model-owner-provenance.json`.

The surrounding Itanium RTTI and primary vtables now identify all three owners.
`viewUnified4.so` maps slot 64 to `ViewFocusArea_C` for the `+0x180` utility
sequence and to `ViewCustomZebra` for the `+0x188` sequence; Zebra's adjacent
slot 65 is the prior-return-split entry at `0x17a91c`. `viewUnified7.so` maps
slot 64 to `ViewFocusArea` and the separate utility initializer to slot 54 in
the same typed primary vtable. `ViewFocusArea` and `ViewFocusArea_C` both expose
`WrapperSettingUtil` as a public nonvirtual base at `+0x140`; VU7's secondary
vtable at that offset confirms the subobject layout, while its observed
`+0x14c` field remains structurally inside the wrapper rather than semantically
named by the static evidence.

The shared slot-64 pattern is therefore generic view behavior across Focus Area
and Custom Zebra, not a Creative Style owner. It proves a same-class static link
between VU7's initializer and dispatcher, but not runtime ordering or a concrete
same-instance execution. No typed primary-vtable relocation names Creative
Style; broader root-edge absence is not assessed by this slice. That generic-owner slice alone still
stops before selected-value storage, final commit, renderer, touch, or
persistence. The refined fail-closed record is
`analysis/a6400-dispatch-table-container-provenance.json`.

### Target-native Creative Style view/model binding

The ownership gap is now closed through a different, exact target-native path.
`viewUnified2.so` contains the SI RTTI type `ViewCreativeStyle`, a 94-slot
primary vtable, a secondary address point at object offset `0x28`, and the
defined `ViewCreativeStyleToInstance` entry. Its factory allocates `0x194`
bytes; the bounded constructor calls `ViewBaseForMR`, installs both vptrs, and
sets the model-request flag to false. Slot 54 attaches `@M00B` event 9 and `@M096` event 8,
then requests current-still-recording model operation 75. Slot 64 is an exact
20-case controller dispatcher.

Dispatcher case 16 directly calls both controller helpers, which use
process-data ID 42. `CmnViewProcessDataMgr` preserves that ID into its lookup and maps
index 42 to selector 45; the bounded 378-way factory dispatcher maps selector
45 to the singleton accessor that constructs the RTTI-typed
`CmnViewProcessDataElementCustomCreativeStyle`. This joins the concrete view to
the concrete Creative Style process element without relying on class-name
co-containment. The manager's read path reaches exact element vtable slot 10,
whose base signature is `getValue(int&,int&,int&,int&,int&,int,int)`. Its write
path reaches vtable slot 21, whose base signature is
`setValue(int,int,int,int,int)` and whose Creative Style override is bounded at
`0x4893ac..0x489644`.

That five-integer setter contains five bounded call sites to
`CmnViewModelIfWrapper::backupWrite`, five `ParamList::add` call sites, and a
bounded `@M00B` model-operation-38 request call site. This is the first verified
target-native Creative Style UI-to-typed-value-setter-to-backup/model-request
boundary.

The setter's first integer is now structurally bounded as a selector. Inputs 0
through 13 enter a 14-entry halfword branch table; index 12 reaches the error
path, while the other thirteen indices map exactly to persisted codes
`{0:1, 1:2, 2:3, 3:7, 4:8, 5:9, 6:4, 7:5, 8:10, 9:11, 10:12,
11:6, 13:14}`. Each accepted case allocates the same 0x14-byte `ParamBase`
holder and passes the mapped code to its constructor. The holder accessor then
supplies a one-byte local selector-code value.

That selector byte does not use the first fixed backup item. It is passed to a
table-selected dynamic backup record only when setter argument 2 is nonzero;
the record-ID table's field semantics remain unresolved. Fixed item
`0x01070762` instead receives the adjacent one-byte encoding of setter argument
2: nonpositive input leaves `0xff`, and positive `n` stores the low byte of
`n-1`. The getter captures its second direct output reference, preinitializes
that output to zero, reads the same item as a signed byte, skips the update for
signed `-1`, and otherwise stores the signed value plus one. This is an exact
typed setter/getter encode/decode boundary, but no admissible input range is
proven and a universal round trip is not claimed. It also does not prove that
the manager or view exposes that reference as selected style.

The four dynamic setter writes now have exact frame-relative geometry without
assigning numeric record IDs or human meanings. The selector code uses the
record word at `r7 + 0xf8 + 4*argument-2` and the byte at `r7 + 0x11e`.
Arguments 3 and 4 use record words at `r7 + 0xdc + 4*argument-2` and
`r7 + 0x8c + 4*argument-2`, with values at `r7 + 0x4` and `r7 + 0x140`.
Argument 5 uses the record word at `r7 + 0x3c + 4*argument-2` and the value at
`r7 + 0x144`. Ten branch-dependent getter reads likewise resolve only their
scratch-buffer pointers: three at `r7 + 0x134`, three at `r7 + 0x135`, two at
`r7 + 0x136`, and two at `r7 + 0x137`. Static evidence does not yet join any
of those getter reads to a dynamic setter record.

The five request additions use exact keys `[383, 386, 389, 392, 383]` and
holder roles `[selector-code, argument-3, argument-4-or-branch-default,
argument-5, selector-code]`. Argument 3 is captured directly, argument 4 comes
from the caller stack for normal selectors but is forced to zero for selector
11/13 construction, and argument 5 comes from the next caller-stack word.
These are positional dataflow roles only. Human field names, named preset
labels, the menu-selected-state join, the meanings of the three other dynamic
backup writes, and all renderer/live-view/JPEG/movie effects remain unresolved.
The fail-closed record is
`analysis/a6400-creative-style-selector-code.json`.

The negative label/state result is now bounded more tightly. The nineteen-step
case-0 scaffold contains no typed Creative Style process call, while case 16
uses process-data ID 42 through a separate path. Generic CautionConfig selected
state exists at object offset `+0x24`, but no root, menu-event, or process-data
edge joins it to this view. English resources contain Creative Style words,
but no table or resource-ID mapping binds those strings to the thirteen accepted
selector indices. The indices therefore cannot yet be named or treated as the
currently selected menu item.

The request transport is now bounded end to end through the queue, but not to a
handler. Its local wrapper gets `CmnMRUtil` and preserves request code 38 and
the same `ParamList` through a small helper into a bounded dispatcher. The
dispatcher computes the unsigned value `38-40`; because that wraps above 1, its
unsigned-higher branch necessarily reaches the sole named
`viewManagerIf::requestModelExecute` edge on the model-mapping helper's
normal-return path. The original `@M00B` string is replaced by that helper's
result, so model identity is not claimed across the edge.

The shared `libObj.so` request API captures code 38 in `r9` across its ID
generator call. Its `.ARM.attributes` section omits both
`Tag_ABI_PCS_R9_use` and `Tag_nodefaults`, making the effective ABI value zero
and `r9` the callee-saved `v6`; the exporter also rejects any local write in
the exact capture-to-use span. The API then passes code 38 into another mapper.
The mapper's opaque return, or a sentinel on alternate routes, becomes Event
parameter key 8; literal 38 is not proven in the Event. The builder constructs
the `Event`, attaches the `ParamList`, and adds its scalar parameters. Its
continuation preserves the Event, adds key 6, and reaches
`EventManager::push(Event*,true)` through an exact interworking PLT relocation.
The push owner then stops at three unresolved indirect calls. This proves an
operation-38-origin Event queue path, not a named operation-38 handler or a
renderer, live-view, still-JPEG, or movie sink. The fail-closed record is
`analysis/a6400-creative-style-model-request-transport.json`.

A separate controller field at object offset `0x15c` takes observed values
0 through 4 and is backed by item `0x01070763`. Slot 57 resets the field to zero
and persists that reset. The object field uses word stores while its backup
helper serializes one byte, so it is classified as controller mode rather than
the selected Creative Style value. `WrapperCreativeStyle` RTTI/vtable is
present, but no exact instantiation or view edge was found; the verified setter
uses the generic `WrapperSettingUtil` service instead.

The `viewCreativeStyle.so` and `ViewCreativeStyleToInstance` strings remain
unjoined to a static registration table. The bounded direct scan is incomplete,
and no `.rel.dyn`/`.rel.plt` relocation or `.init_array` target establishes the
route; no decoded direct call was found in the incomplete global scan. No exact
static edge therefore establishes the
external loader route. No touch-coordinate, hit-test, menu-selection, or
Creative Look eight-axis edge appears in this binding. The fail-closed record is
`analysis/a6400-creative-style-view-model-binding.json`.

### Target-native Creative Style interaction surface

The concrete view also owns a target-native interaction scaffold rather than
only a model boundary. Slot 54 installs layout key `0x1fa14683` through a local
layout-converter callback, then allocates and stores `CmnViewMenuData`,
`CmnMenuTableUtil`, and `CmnZakoMenuUtil` helpers. Dispatcher case 0 supplies
the menu-data and a local table expression to `initMenuData`, runs a fixed
index loop for values 0 through 18, and contains twelve bounded
`setGreyout(int,bool)` call sites. These are static construction/call-site
facts; the nineteen indices are not promoted to named items or a table
cardinality.

Case 16 passes the pre-existing pointer at object offset `0x14c` to
`CmnMenuTableUtil::_updateCursorForBeltWidget` with flags `(true,false)`, then
continues through menu-ID and branch-selected widget lookup boundaries. The
slice proves no construction, store, or typed cast for that pointer, so it
remains a `PAS_MenuDataSelectBelt*` interface
boundary rather than a concrete belt implementation. Case 13 separately uses
the word at `+0x190` to open `view/FNMENU` for value 3, open
`view/QUICK_NAVI` for value 2, or close `@V01D` otherwise. That navigation
selector is not selected Creative Style state. The preceding binding report
separately classifies the resettable controller-mode word at `+0x15c`.

The nearest concrete touchability lead does not yet solve touch. A typed
`ViewMovieRecPatch` path gets and checks a `PAS_BarCtrlDial`, then passes the
exact value false to `setTouchable(bool)` before entering Movie/Iris data
management. A typed `PAS_BarCtrlDialConverter` elsewhere forwards an incoming
value to the same setter, but the value semantics and all coordinate, hit-test,
gesture, selection, and Creative Style edges remain unresolved. This proves a
native UI scaffold and touchability-flag boundary, not a reusable touch
implementation. The fail-closed record is
`analysis/a6400-creative-style-interaction-surface.json`.

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

## Exact stock-recovery boundary

The exact stock source is now authenticated independently of feature work:

- Source key: `a6400-tw-v2.00`
- Identity: `ILCE-6400`, model `0x81030011`, `TW`, region code `0`, version
  `2.00`
- Official updater SHA-256:
  `ea460cbec5f8b62119630f0a653eeca4f4ffad887670e60c0fd9c0345e6b30a6`
- Embedded stock container SHA-256:
  `78a6881eddd16609758951c80d533ac82042858eac919bd94453941ba6b766f2`

This authenticates the exact stock updater/container source a prospective
restoration path would need to use; it does not establish complete restored
coverage or a way to perform that restoration. The strict result is
`BLOCKED_STATIC_EVIDENCE`, with `recovery_validated=false`,
`camera_test_eligible=false`, and `installable=false`.

All three candidates remain independently `UNESTABLISHED`:
`official-updater-reinstall`, `usb-recovery-or-updater-mode`, and
`independent-maintenance-path`. No runtime-independent camera entry, complete
write scope/order, or terminal verification has been proven. All six mandatory
failure scenarios also remain `UNESTABLISHED` for every candidate: modified UI
runtime failure, interrupted feature update, nonbooting application layer,
version/downgrade rejection, boot-chain failure, and power loss during stock
restore.

The recovered target-system updater components are post-install 2.00 artifacts.
The separately recovered α6400A updater partition is a control sample, not the
exact α6400 2.00 installing path. The pre-normal-runtime selector or authentic
earlier receiver that installs 2.00 is still missing. A settings or factory
reset changes configuration; it is not firmware restoration and cannot satisfy
this gate.

The α6400A control is now bounded further by a canonical read-only `sauu`
graph: 37 functions, 71 calls, three unresolved indirect calls, and maximum
depth two. It confirms model/region/version guards and a signature workflow in
the related model `0x81030017`, but no write orchestrator or completion
verification was identified and transfer to α6400 model `0x81030011` remains
false. The strict recovery report classifies this as `NON_TRANSFERABLE_CONTROL`
and derives no recovery promotion from it.

## Next safe experiments

1. Resolve the numeric dynamic-record IDs and join each setter write to its
   branch-dependent getter read. Continue the proven operation-38-origin queue
   path through the three indirect `EventManager::push` calls to a named model
   consumer before following any renderer/live-view/JPEG/movie path. Do not
   label an argument or output without an exact dataflow edge.
2. Compare that verified five-value ABI with the first-class Creative Look
   contract, then locate independent storage and processing boundaries for the
   three missing axes before changing any layer or axis from `UNESTABLISHED`.
3. Join the thirteen accepted selector indices to exact resource IDs and
   selected-state storage. Continue the settings-menu touch trace from real
   widget/event owners to a coordinate transform, hit test, and selection
   dispatcher. Existing wheel, repeat-key, cursor, widget, and touchability-flag
   behavior is not evidence of touch navigation.
4. Use α6700 for Creative Look/menu behavior and α7 V for vertical-display
   behavior, without assuming donor code or hardware-dependent processing is
   portable to α6400.
5. Keep every modified runtime file outside a Sony updater package. Continue
   static recovery research at the missing pre-normal-runtime selector or
   authentic earlier installing receiver. Do not draft camera steps until the
   strict report reaches a separately reviewed future-validation-design gate;
   a settings reset cannot substitute for the required external stock restore.
