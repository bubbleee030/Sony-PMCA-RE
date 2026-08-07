# α6400 Creative Style generic model-consumer plan

## Goal

Determine whether cross-module calls to the α6400 generic setting-node cursor
and model helpers are owned by a Creative Style-specific consumer, or only
co-contained with separately published Creative Style root data.

## Static sources

- exact `lib/viewUnified4.so`, size `2,614,628`, SHA-256
  `0fe8f852b0f028ac7d1d55c613726b3949879cf7fdd44074e525ae302a6f2e62`;
- exact `lib/viewUnified7.so`, size `541,024`, SHA-256
  `c48cde43ff22d808ad23c42019ddae516fff7da060004eb81ed2bb85012aa538`;
- the prior Creative Style registry-consumer and generic model/cursor reports as
  independent provenance boundaries.

All work remains read-only and offline. No camera access, Sony camera-binary
execution, device writes, firmware packaging, or installable output is allowed.

## Tasks

1. Add fail-closed tests for exact helper import/PLT bindings and paired generic
   cursor-change/model-update sequences.
2. Pin each sequence to its `.ARM.exidx` function owner and test whether a
   nonzero-sized dynamic symbol owns it.
3. Re-derive every `cmnViewSettingNodeRootCreativeStyle` relocation in the two
   modules and prove whether any cell lies inside a sequence owner.
4. Emit a report that separates generic UI/model control from Creative
   Style-specific binding, persistence, rendering, touch, and Creative Look.
5. Verify the real exporters, focused tests, full analysis suite, and safety
   suite before committing only the scoped files.

## Acceptance boundary

Paired generic helper calls may be claimed when their direct Thumb transfers,
PLT identities, order, and owners are exact. Creative Style-specific model
control remains false unless a Creative Style root relocation or another typed
Creative Style object is provenance-bound to the same executable owner. Mere
module co-containment is not sufficient.
