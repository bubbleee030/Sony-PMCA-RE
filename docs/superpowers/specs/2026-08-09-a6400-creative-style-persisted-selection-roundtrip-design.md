# α6400 Creative Style persisted-selection roundtrip design

## Objective

Extend the authenticated selected-node boundary only far enough to reproduce
the `ViewSettingMenu` persisted-index restore/save machinery and determine
whether it establishes the exact Creative Style path `0 -> 4 -> 1`.

This remains offline static analysis. It must not execute Sony code, access a
camera, create an installable payload, or promote recovery or camera-test
eligibility.

## Source-derived route

The typed `ViewSettingMenu` slot-64 dispatcher has a selector-0 entry whose
landing tail-calls the selection driver. A conditional fallback in that driver
calls a bounded restore helper. The helper:

1. reads backup IDs `0x01070b75`, `0x01070b74`, and `0x01070910`;
2. preserves their effective order as three zero-based selectors;
3. normalizes a raw third value of zero to one;
4. resolves three successive `getSubItemByIndex` calls from `this+0x1a0`; and
5. calls the ancestor-selection helper on the resulting leaf.

The ancestor helper invokes `setItemSelected` on the leaf and each resolved
parent until it reaches `this+0x1a0`. Conditional on candidate generic
`CautionConfig.so` semantics, supplying effective indices `0,4,1` therefore
sets the Creative Style leaf and its two ancestors.

The reverse route is separately typed. `ViewSettingMenu` slot 57 obtains the
current selected index at each of the three levels and writes them back to the
same backup IDs through `ViewBaseForMR::Bkup_Write`.

## Fail-closed boundary

The static source does not establish that the three runtime backup values are
`0,4,1`, that selector 0 or slot 57 is invoked in a concrete execution, or
that selector 10 is later delivered to the same receiver. Provider
interposition remains possible for the generic node and backup interfaces.

Accordingly this milestone may prove a conditional persisted-selection
roundtrip and exact path predicate. It may not claim runtime Creative Style
selection, process-ID 42 activation, factory invocation, Creative Look,
processing/output behavior, installability, recovery, or camera eligibility.

## Implementation shape

Extend the existing selected-node report to schema 5 with one
`persisted_selection_roundtrip` section. Validate every positive field from
the pinned VU2/Caution sources, retain explicit conditional and unresolved
fields, add source-byte/relocation mutations, regenerate atomically, and keep
the existing report filename and dependency chain.
