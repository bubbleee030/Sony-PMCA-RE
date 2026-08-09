# α6400 Creative Style persisted-selection roundtrip implementation plan

> Execute with TDD and fail closed. Static/offline only; no Sony execution,
> camera/device access, updater mode, partition writes, or installable output.

## Task 1: Add the schema-5 contract in RED

**Modify:**

- `tests/analysis/test_creative_style_selected_node_identity_boundary.py`
- `pmca/analysis/creative_style_selected_node_identity_boundary.py`

Add a contract test that requires a `persisted_selection_roundtrip` section
with the typed selector-0 restore route, exact backup IDs, effective-index
ordering, three-level `getSubItemByIndex` resolver, ancestor-selection helper,
typed slot-57 save route, and the exact conditional predicate `0,4,1`.

Require all runtime values/invocations, selector-10 delivery, process-ID 42,
factory, Creative Look, output, installability, recovery, and camera claims to
remain false. Run the new test and observe the expected schema-4 failure.

## Task 2: Implement source-derived restore/save validation

**Modify:**

- `tools/static/export_a6400_creative_style_selected_node_identity_boundary.py`
- `tests/analysis/test_creative_style_selected_node_identity_boundary.py`
- `pmca/analysis/creative_style_selected_node_identity_boundary.py`

Validate at minimum:

- selector 0 table entry `0x21356e` and tail `0x213690 -> 0x2114fc`;
- conditional restore call `0x2114e6 -> 0x208180`;
- backup-read helper `0x208118`, IDs `0x01070b75`, `0x01070b74`,
  `0x01070910`, success gates, and third-value zero-to-one normalization;
- three-index resolver `0x208078` with three slot-`0x20`
  `getSubItemByIndex` calls from receiver field `+0x1a0`;
- result forwarding to ancestor selection `0x207f7a`;
- ancestor `setItemSelected` and parent traversal through slot `0x1c` until
  `this+0x1a0`;
- slot-57 cell `0x8e2354 -> 0x210e70`;
- current-index extraction `0x2081d0` and backup-write helper `0x2080c4`;
- exact writeback mapping to the same three IDs; and
- candidate Caution interface cells for `getSubItemByIndex`,
  `getSuperItem`, `setItemSelected`, and `getIndexSelectedItem`.

Add table-driven source mutations for each control/data/relocation anchor and
require the validator to reject every mutation. Run focused tests to GREEN.

## Task 3: Regenerate and document without promotion

**Modify:**

- `analysis/a6400-creative-style-selected-node-identity-boundary.json`
- `analysis/a6400a-updater-and-creative-style-deep-dive.md`

Regenerate through the existing validated atomic writer. Require identical
report SHA-256 values across two runs and checked-report equality with a fresh
authenticated export.

Document that the roundtrip is structurally exact but runtime values and
delivery are unresolved. Do not claim runtime selection from backup-ID names
or the existence of the write route.

## Task 4: Verify, commit, and publish

Run:

```powershell
.\.venv\Scripts\python.exe -m unittest -v tests.analysis.test_creative_style_selected_node_identity_boundary tests.analysis.test_creative_style_activation_caller_boundary tests.analysis.test_creative_style_selected_state_dispatch tests.analysis.test_creative_style_definition_registration tests.analysis.test_creative_style_menu_list_construction tests.analysis.test_creative_style_view_lifecycle_boundary tests.analysis.test_creative_style_interaction_surface
.\.venv\Scripts\python.exe -m py_compile pmca\analysis\creative_style_selected_node_identity_boundary.py tools\static\export_a6400_creative_style_selected_node_identity_boundary.py tests\analysis\test_creative_style_selected_node_identity_boundary.py
git diff --check
```

Commit only the design, plan, schema/exporter/test, regenerated report, and
deep-dive files. Then run the full `tests\analysis` and `tests\safe` suites on
the committed state, push the approved branch, fetch it, and require local and
remote hashes plus ahead/behind `0 0` to match.
