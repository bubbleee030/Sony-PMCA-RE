# α6400 Creative Style interaction-surface plan

## Goal

Bound the target-native `ViewCreativeStyle` layout, menu-table, belt-cursor,
and navigation components, then test the nearest concrete touchability widget
candidate without promoting a flag setter to touch routing or Creative Look UI.

## Static source and safety

- exact `lib/viewUnified2.so`, size `11,530,552`, SHA-256
  `1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2`.
- offline metadata and bounded Thumb control flow only.
- no camera access, Sony-camera binary execution, device/USB writes, firmware
  packaging or flashing, proprietary byte output, disassembly output, or key
  material.

## Tasks

1. Pin the Creative Style layout key/callback and the three allocated menu
   helpers stored in the view object.
2. Pin case 0's menu-data initialization, 19-index loop, and twelve greyout
   call sites without assigning unknown item semantics.
3. Pin case 16's pre-existing belt pointer, menu-table cursor update, exact
   flags, and branch-selected widget IDs while keeping its concrete belt type
   and lifecycle unresolved.
4. Pin the `+0x190` navigation selector and record its two open routes plus one
   close route without assigning selected-state semantics.
5. Test the concrete `PAS_BarCtrlDial` touchability lead in `ViewMovieRecPatch`
   and its converter, preserving exact boolean/dataflow semantics.
6. Emit a deterministic report and run real-export, analysis, safety,
   compilation, diff, and independent-review gates.

## Acceptance boundary

The result may claim target-native layout/menu/belt scaffolding and a concrete
touchability-flag API only when every recorded owner, relocation, call, object
offset, literal, and argument is fail-closed. It must not claim that the belt
is constructed or typed by the Creative Style view, that `setTouchable` has a
coordinate/event route, or that any touch widget is safely reusable. Creative
Look layout equivalence, runtime behavior, installability, and camera-test
eligibility remain false.

## Result

- `ViewCreativeStyle` owns a native layout and three menu helpers.
- Its menu path initializes indices 0 through 18, has twelve greyout call
  sites, and updates a pre-existing belt through `CmnMenuTableUtil`.
- Navigation uses a `+0x190` selector for Function Menu, Quick Navi, and view
  closure; this slice does not label it as selected Creative Style state.
- The nearest typed dial candidate is hard-disabled by the proved Movie Rec
  path (`setTouchable(false)`), while the converter forwards an unknown flag.
- Coordinate input, hit testing, gestures, selection dispatch, Creative Style
  touch, Creative Look equivalence, runtime behavior, and installability remain
  unproven.
