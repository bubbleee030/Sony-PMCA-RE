# α6400 α7 V Creative Look Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the stale ten-look Creative Look model with an exact, evidence-gated α7 V contract containing twelve built-in looks, six Custom slots, eight correctly ranged axes, documented workflow and restrictions, and derived visible-but-disabled availability without promoting fallback recipes or camera eligibility.

**Architecture:** Keep immutable α7 V product intent, α6400 target evidence, derived offline presentation availability, Creative Style fallback recipes, and recovery safety as separate layers. Migrate the existing Creative Look stack to schema version 2, derive every availability record from validated target capabilities, keep the recipe catalog explicitly approximation-only, and regenerate downstream summaries from validated inputs before any checked-in output is replaced.

**Tech Stack:** Python 3, `unittest`, JSON, deterministic Markdown rendering, existing strict analysis validators, PowerShell, Git.

## Global Constraints

- The canonical repository is `C:\Users\Bubble\ChatGPT\Sony\Sony-PMCA-RE-a6400-analysis`.
- The phase remains static and offline: no camera connection, Sony camera-binary execution, service/updater mode, partition writes, firmware generation, or installation.
- The α7 V reference source is exactly `https://helpguide.sony.net/ilc/2540/v1/en/contents/0411B_creative_look.html`.
- Built-in order is exactly `ST, PT, NT, VV, VV2, FL, FL2, FL3, IN, SH, BW, SE`.
- Custom membership is exactly `Custom1` through `Custom6`.
- Axis ranges are exact: Contrast/Highlights/Shadows/Saturation `-9..9`; Fade/Sharpness/Clarity `0..9`; Sharpness Range `1..5`.
- Unproven defaults are represented as `null`, never coerced to an in-range value.
- Every reference item remains `VISIBLE`; current unproven capability remains `DISABLED_UNPROVEN` with stable reason codes.
- Creative Style recipes remain `APPROXIMATION_ONLY` and `LAST_RESORT_ONLY`; they cannot establish native Creative Look support.
- Do not fabricate `FL2` or `FL3` fallback recipes.
- `recovery_validated=false`, `camera_test_eligible=false`, `installable=false`, and readiness `BLOCKED_STATIC_EVIDENCE` remain exact until the independent recovery report changes through its own reviewed process.
- Preserve unrelated user changes and never stage proprietary firmware, binaries, raw disassembly, keys, or reconstructive payload data.

---

## File structure

| Path | Action | Responsibility |
|---|---|---|
| `pmca/analysis/creative_look_stack.py` | Modify | Validate the schema-v2 reference catalog, target capabilities, derived availability, fallback boundary, and safety snapshot. |
| `tests/analysis/test_creative_look_stack.py` | Modify | Pin exact α7 V membership/ranges/actions/restrictions and fail-closed availability derivation. |
| `analysis/a6400-creative-look-stack.json` | Modify | Store the migrated contract, all-currently-unproven capability records, derived presentation, and recovery snapshot. |
| `pmca/analysis/creative_looks.py` | Modify | Validate only the separate Creative Style fallback catalog and remove stale first-class range/default assumptions. |
| `tests/analysis/test_creative_looks.py` | Modify | Reject native promotion, stale ranges, fabricated FL2/FL3 recipes, and invalid unknown-default encodings. |
| `tests/analysis/test_real_creative_look_recipes.py` | Modify | Validate the committed fallback catalog as schema version 2. |
| `analysis/creative-look-recipes.json` | Modify | Migrate the ten represented recipes to an explicitly fallback-only artifact and record FL2/FL3 as unrepresented. |
| `creative_look_recipes.py` | Modify | Keep deterministic rendering while reporting represented and unrepresented counts. |
| `tests/analysis/test_creative_look_cli.py` | Modify | Pin CLI output and atomic guide rendering for schema version 2. |
| `analysis/a6400-creative-look-guide.md` | Modify | Render the corrected fallback-only guide with no native or twelve-look coverage claim. |
| `pmca/analysis/decisions.py` | Modify | Derive Creative Look discovery/emulation decision records from validated stack and fallback inputs. |
| `tests/analysis/test_decisions.py` | Modify | Require the α7 V source, 12+6 visible contract, disabled state, fallback gap, and unchanged recovery gate. |
| `analysis/feature-evidence.json` | Modify | Store only the derived Creative Look capability summaries plus existing unrelated decisions. |
| `pmca/analysis/target_features.py` | Modify | Migrate nested Creative Look evidence to target-feature schema version 5 without weakening target-native claims. |
| `tests/analysis/test_target_features.py` | Modify | Pin the new nested schema and reject visibility/fallback/native conflation. |
| `analysis/a6400-target-features.json` | Modify | Embed the validated schema-v2 Creative Look stack and corrected summary language. |
| `tools/static/regenerate_a6400_creative_look_contract_reports.py` | Create | Build and validate all Creative Look outputs in memory, then atomically replace them. |
| `tests/analysis/test_creative_look_contract_regenerator.py` | Create | Prove deterministic regeneration and no partial writes on validation failure. |
| `analysis/a6400-feasibility-report.md` | Modify | Regenerate the decision prefix and correct the integrated Creative Look narrative. |
| `analysis/a6400a-updater-and-creative-style-deep-dive.md` | Modify | Replace stale ten-look/copy/range wording while preserving all runtime and recovery blockers. |

### Task 1: Migrate the first-class Creative Look stack to schema version 2

**Files:**
- Modify: `pmca/analysis/creative_look_stack.py`
- Modify: `tests/analysis/test_creative_look_stack.py`
- Modify: `analysis/a6400-creative-look-stack.json`

**Interfaces:**
- Consumes: the approved contract design and the existing bounded target evidence records.
- Produces: `validate_creative_look_stack(document: dict) -> dict`, `derive_presentation_availability(document: dict) -> dict`, `BUILT_IN_LOOK_IDS`, `CUSTOM_LOOK_IDS`, `AXIS_DEFINITIONS`, `WORKFLOW_IDS`, `RESTRICTION_IDS`, and `REASON_CODES`.

- [ ] **Step 1: Write failing exact-reference tests**

Add constants and assertions equivalent to:

```python
BUILT_IN_LOOK_IDS = (
    "ST", "PT", "NT", "VV", "VV2", "FL",
    "FL2", "FL3", "IN", "SH", "BW", "SE",
)
CUSTOM_LOOK_IDS = tuple(f"Custom{index}" for index in range(1, 7))
AXIS_DEFINITIONS = {
    "contrast": (-9, 9),
    "highlights": (-9, 9),
    "shadows": (-9, 9),
    "fade": (0, 9),
    "saturation": (-9, 9),
    "sharpness": (0, 9),
    "sharpness_range": (1, 5),
    "clarity": (0, 9),
}
WORKFLOW_IDS = (
    "select_look",
    "edit_axes",
    "modified_marker",
    "reset_one_look",
    "select_custom_base",
)
RESTRICTION_IDS = (
    "intelligent_auto",
    "picture_profile_not_off",
    "flexible_iso_log",
    "bw_se_saturation",
    "movie_sharpness_range",
)
```

Tests must reject the old ten-look sequence, any reorder or duplicate, `copy_select`, missing Custom slots, a Sharpness minimum below `0`, Sharpness Range minimum below `1`, and Clarity minimum below `0`.

- [ ] **Step 2: Run the focused tests and verify schema-v1 failure**

Run:

```powershell
python -m unittest tests.analysis.test_creative_look_stack -v
```

Expected: failures showing the committed schema version, look membership, workflows, ranges, and presentation fields are stale.

- [ ] **Step 3: Implement exact reference and capability validation**

Set the document fields to:

```python
_DOCUMENT_FIELDS = {
    "schema_version",
    "target",
    "reference",
    "reference_catalog",
    "layers",
    "look_records",
    "custom_records",
    "workflow_records",
    "axis_records",
    "restriction_records",
    "pipeline_outputs",
    "presentation",
    "fallback",
    "safety",
    "native_creative_look_established",
}
```

Use these exact capability shapes:

```python
LOOK_CAPABILITY_FIELDS = {
    "status", "base_representation", "selectable_state",
    "output_bindings", "evidence", "blocker",
}
CUSTOM_CAPABILITY_FIELDS = {
    "status", "base_selection", "slot_state", "adjustments",
    "reset", "persistence", "evidence", "blocker",
}
AXIS_CAPABILITY_FIELDS = {
    "status", "ui", "state", "range", "default",
    "pipeline", "evidence", "blocker",
}
RESTRICTION_CAPABILITY_FIELDS = {
    "status", "implemented", "evidence", "blocker",
}
PRESENTATION_FIELDS = {"visibility", "availability", "reasons"}
```

The reference catalog contains the exact source URL, ordered built-ins, ordered Custom slots, ordered axis definitions with `default: null`, ordered workflows, and five exact reference restriction records. Reference membership cannot be used as target evidence.

- [ ] **Step 4: Derive availability and stable reason codes**

Implement `derive_presentation_availability()` as a pure function. Every record emits `visibility="VISIBLE"`. Emit `availability="ENABLED_OFFLINE"` only when all dependencies for that item are established; otherwise emit `DISABLED_UNPROVEN` and a deterministic ordered subset of:

```python
REASON_CODES = (
    "BASE_LOOK_REPRESENTATION_UNPROVEN",
    "CUSTOM_LOOK_STATE_UNPROVEN",
    "AXIS_UI_UNPROVEN",
    "AXIS_STATE_UNPROVEN",
    "AXIS_PIPELINE_UNPROVEN",
    "WORKFLOW_DISPATCH_UNPROVEN",
    "PERSISTENCE_UNPROVEN",
    "MODE_MATRIX_UNPROVEN",
    "LIVE_VIEW_BINDING_UNPROVEN",
    "STILL_JPEG_BINDING_UNPROVEN",
    "MOVIE_BINDING_UNPROVEN",
)
```

Reject authored presentation data unless it equals the derived result exactly. Add mutations proving that partial axis evidence, fallback coverage, or visibility alone cannot enable an item.

- [ ] **Step 5: Pin fallback and recovery separation in the stack**

Require fallback fields:

```python
{
    "creative_style_available": True,
    "status": "APPROXIMATION_ONLY",
    "policy": "LAST_RESORT_ONLY",
    "source": "analysis/creative-look-recipes.json",
    "represented_reference_looks": [
        "ST", "PT", "NT", "VV", "VV2", "FL", "IN", "SH", "BW", "SE"
    ],
    "unrepresented_reference_looks": ["FL2", "FL3"],
    "native_claim_basis": False,
}
```

Require the safety snapshot to name `analysis/a6400-stock-200-recovery.json`, carry a 64-hex report digest, and retain `BLOCKED_STATIC_EVIDENCE`, `recovery_validated=false`, `camera_test_eligible=false`, and `installable=false`. The stack validator checks the fail-closed snapshot shape; Task 3 performs the cross-report digest and value join without introducing a circular import through `target_features`.

- [ ] **Step 6: Migrate the committed stack and pass focused tests**

Populate all new target records as `UNESTABLISHED` with false boundaries, empty evidence, and nonempty blockers. Derive presentation so all 12 built-ins, six Custom slots, eight axes, and five workflows are visible and disabled. Run:

```powershell
python -m unittest tests.analysis.test_creative_look_stack -v
python -c "import json; from pathlib import Path; from pmca.analysis.creative_look_stack import validate_creative_look_stack; validate_creative_look_stack(json.loads(Path('analysis/a6400-creative-look-stack.json').read_text('utf-8'))); print('creative-look-stack-v2-valid')"
```

Expected: all focused tests pass and `creative-look-stack-v2-valid` prints.

- [ ] **Step 7: Commit the stack migration**

```powershell
git add pmca/analysis/creative_look_stack.py tests/analysis/test_creative_look_stack.py analysis/a6400-creative-look-stack.json
git commit -m "analysis: migrate alpha7v Creative Look contract"
```

### Task 2: Separate and correct the Creative Style fallback catalog

**Files:**
- Modify: `pmca/analysis/creative_looks.py`
- Modify: `tests/analysis/test_creative_looks.py`
- Modify: `tests/analysis/test_real_creative_look_recipes.py`
- Modify: `creative_look_recipes.py`
- Modify: `tests/analysis/test_creative_look_cli.py`
- Modify: `analysis/creative-look-recipes.json`
- Modify: `analysis/a6400-creative-look-guide.md`

**Interfaces:**
- Consumes: Task 1 `BUILT_IN_LOOK_IDS` and the existing ten representable α6400 Creative Style recipes.
- Produces: `validate_recipe_document(document: object) -> dict`, `render_recipe_guide(document: dict) -> str`, and an explicit fallback coverage record.

- [ ] **Step 1: Write failing fallback-boundary tests**

Require schema version 2 and top-level fields:

```python
_TOP_FIELDS = {
    "schema_version",
    "artifact_role",
    "native_claim_basis",
    "reference_source",
    "creative_style_source",
    "represented_reference_looks",
    "unrepresented_reference_looks",
    "defaults",
    "community_experiments",
    "disclaimer",
    "validation_protocol",
}
```

Tests must require `artifact_role="CREATIVE_STYLE_FALLBACK"`, `native_claim_basis=false`, represented order equal to the ten existing mappings, unrepresented order `FL2, FL3`, and no default entry for FL2 or FL3. Mutations that add an FL2/FL3 recipe, claim native coverage, or change the reference source back to the ILCE-6700 guide must fail.

- [ ] **Step 2: Add range and unknown-default regression tests**

Represent unknown first-class values as JSON `null`. Reject:

```python
{"sharpness": -1}
{"sharpness_range": 0}
{"clarity": -1}
```

when those fields claim α7 V values. Keep α6400 Creative Style output controls validated independently at `-3..3`. Existing legacy approximations for IN/SH remain target recipe values, not asserted α7 V Sharpness defaults.

- [ ] **Step 3: Run focused tests and observe the schema-v1 failures**

```powershell
python -m unittest tests.analysis.test_creative_looks tests.analysis.test_real_creative_look_recipes tests.analysis.test_creative_look_cli -v
```

Expected: failures for schema version, source, fallback role, FL2/FL3 coverage, and stale `0` Sharpness Range defaults.

- [ ] **Step 4: Implement the schema-v2 fallback validator**

Keep `A6400Recipe` exact and target-bounded. Replace the old assumption that every fallback entry contains a complete valid first-class `ModernLook` record with an explicit optional reference-adjustment record whose unknown fields are `None`. Translation validation compares only proven source values; committed target recipes remain independently validated and must carry `PARTIAL` for direct mappings or `INFERRED` for the existing bounded approximations.

The validator must ensure the union of represented and unrepresented reference look IDs equals Task 1 `BUILT_IN_LOOK_IDS`, with no overlap, and that fallback coverage never changes first-class availability.

- [ ] **Step 5: Migrate recipes and render the guide**

Change the Creative Look reference URL to the α7 V guide. Preserve only the ten existing α6400 recipes. Set unproven first-class defaults, including Sharpness Range, to `null`; do not coerce them to `0`. Render:

```powershell
python creative_look_recipes.py render --recipes analysis/creative-look-recipes.json --output analysis/a6400-creative-look-guide.md
```

Expected CLI summary:

```text
represented=10 unrepresented=2 community=2
```

The guide must state that the 12-look/6-Custom contract is authoritative, only ten fallback representations exist, FL2/FL3 are intentionally unrepresented, and nothing enables native Creative Look or camera testing.

- [ ] **Step 6: Run focused tests and deterministic render check**

```powershell
python -m unittest tests.analysis.test_creative_looks tests.analysis.test_real_creative_look_recipes tests.analysis.test_creative_look_cli -v
Copy-Item analysis/a6400-creative-look-guide.md $env:TEMP/a6400-creative-look-guide.before.md
python creative_look_recipes.py render --recipes analysis/creative-look-recipes.json --output analysis/a6400-creative-look-guide.md
Compare-Object (Get-Content $env:TEMP/a6400-creative-look-guide.before.md) (Get-Content analysis/a6400-creative-look-guide.md)
```

Expected: tests pass and `Compare-Object` prints nothing.

- [ ] **Step 7: Commit the fallback migration**

```powershell
git add pmca/analysis/creative_looks.py tests/analysis/test_creative_looks.py tests/analysis/test_real_creative_look_recipes.py creative_look_recipes.py tests/analysis/test_creative_look_cli.py analysis/creative-look-recipes.json analysis/a6400-creative-look-guide.md
git commit -m "analysis: separate Creative Style fallback catalog"
```

### Task 3: Derive and atomically regenerate downstream evidence

**Files:**
- Modify: `pmca/analysis/decisions.py`
- Modify: `tests/analysis/test_decisions.py`
- Modify: `pmca/analysis/target_features.py`
- Modify: `tests/analysis/test_target_features.py`
- Create: `tools/static/regenerate_a6400_creative_look_contract_reports.py`
- Create: `tests/analysis/test_creative_look_contract_regenerator.py`
- Modify: `analysis/feature-evidence.json`
- Modify: `analysis/a6400-target-features.json`
- Modify: `analysis/a6400-feasibility-report.md`
- Modify: `analysis/a6400a-updater-and-creative-style-deep-dive.md`

**Interfaces:**
- Consumes: Task 1 stack, Task 2 fallback catalog/guide, and validated `analysis/a6400-stock-200-recovery.json`.
- Produces: `derive_creative_look_capabilities(stack: dict, recipes: dict) -> tuple[dict, dict]`, target-feature schema version 5, and `build_reports() -> dict[Path, str | dict]` for atomic regeneration.

- [ ] **Step 1: Write failing derived-decision tests**

Add `derive_creative_look_capabilities()` returning the `creative-look-discovery` and `creative-look-emulation` records. Tests must require:

```python
discovery["status"] == "INSUFFICIENT_EVIDENCE"
"12 built-in looks" in discovery["summary"]
"six Custom slots" in discovery["summary"]
"visible" in discovery["summary"]
"disabled" in discovery["summary"]
emulation["status"] == "PARTIAL"
"10" in emulation["summary"]
"FL2" in emulation["summary"]
"FL3" in emulation["summary"]
```

Require the new α7 V URL in `_APPROVED_SOURCES` and reject the old ILCE-6700 URL as the authoritative discovery source. `validate_evidence()` must reject hand-edited Creative Look capability records that differ from the derived values.

- [ ] **Step 2: Write failing target-feature migration tests**

Change expected target-feature schema to version 5. Require embedded equality with the committed schema-v2 stack, all 26 presentation records visible and disabled (`12 + 6 + 8`), all five workflow actions disabled, fallback represented/unrepresented sets exact, and nested safety false. Mutations that set any of these must fail:

```python
candidate["creative_look_stack"]["presentation"]["looks"]["ST"]["availability"] = "ENABLED_OFFLINE"
candidate["creative_look_stack"]["fallback"]["native_claim_basis"] = True
candidate["creative_rendering"]["native_creative_look_established"] = True
candidate["installable"] = True
```

- [ ] **Step 3: Implement pure downstream builders**

Implement `derive_creative_look_capabilities()` from validated inputs. Extend `build_target_feature_report()` with an optional `creative_reports` mapping so the regenerator can inject the newly built stack rather than rereading a stale checked-in file. Keep the default path for existing callers.

Validate the Creative Look safety snapshot against the independently validated recovery report in the regenerator:

```python
recovery = validate_recovery_report(_load(RECOVERY_PATH))
assert stack["safety"]["readiness"] == recovery["readiness"]
assert stack["safety"]["recovery_validated"] is recovery["recovery_validated"]
assert stack["safety"]["camera_test_eligible"] is recovery["camera_test_eligible"]
assert stack["safety"]["installable"] is recovery["installable"]
```

Compute the safety digest from canonical UTF-8 JSON with sorted keys and compact separators, then require exact equality in the stack.

- [ ] **Step 4: Implement all-results-before-write regeneration**

`build_reports()` must build and validate, in memory, these outputs:

1. `analysis/a6400-creative-look-stack.json`
2. `analysis/a6400-creative-look-guide.md`
3. `analysis/feature-evidence.json`
4. `analysis/a6400-target-features.json`
5. the generated decision prefix of `analysis/a6400-feasibility-report.md`

Preserve the feasibility report suffix beginning at `# Integrated Offline Research Result`, but replace its generated prefix with `render_markdown(validated_evidence)`. Stage every output in its destination directory, flush and `fsync`, and call `os.replace` only after every build and validation succeeds.

Add tests that patch the final recovery or target validation to raise and assert byte-for-byte that none of the five outputs changed. Add a second test that runs `build_reports()` twice and compares canonical bytes.

- [ ] **Step 5: Correct human-readable Creative Look narratives**

Update the deep dive and integrated feasibility text to say:

- authoritative intent is 12 built-ins plus six Custom slots;
- all are visible in the offline contract but currently disabled;
- five workflows and five reference restrictions are recorded without target implementation claims;
- all eight UI/state/range/default/pipeline chains and three output bindings remain unestablished;
- only ten separate Creative Style fallback recipes exist;
- FL2/FL3 have no fallback representation;
- touch delivery, runtime factory invocation, native processing, installability, and exact stock recovery remain unresolved;
- recovery stays `BLOCKED_STATIC_EVIDENCE` and camera testing stays ineligible.

Remove stale wording for ten first-class looks, eight old workflow actions, `copy_select`, Sharpness `-9..9`, Sharpness Range `0..5`, and Clarity `-9..9`.

- [ ] **Step 6: Regenerate and run focused integration tests**

```powershell
python tools/static/regenerate_a6400_creative_look_contract_reports.py
python -m unittest tests.analysis.test_creative_look_contract_regenerator tests.analysis.test_decisions tests.analysis.test_target_features -v
```

Expected: the regenerator reports five outputs, camera access `0`, binary execution `0`; all tests pass.

- [ ] **Step 7: Commit downstream reconciliation**

```powershell
git add pmca/analysis/decisions.py tests/analysis/test_decisions.py pmca/analysis/target_features.py tests/analysis/test_target_features.py tools/static/regenerate_a6400_creative_look_contract_reports.py tests/analysis/test_creative_look_contract_regenerator.py analysis/feature-evidence.json analysis/a6400-target-features.json analysis/a6400-feasibility-report.md analysis/a6400a-updater-and-creative-style-deep-dive.md
git commit -m "analysis: derive alpha7v Creative Look readiness"
```

### Task 4: Verify the migration and preserve the safety boundary

**Files:**
- Modify only if a verification assertion exposes a real omission: files already listed in Tasks 1–3.

**Interfaces:**
- Consumes: all three implementation commits.
- Produces: a deterministic, tested, non-installable Creative Look contract migration ready for review.

- [ ] **Step 1: Run focused Creative Look tests**

```powershell
python -m unittest tests.analysis.test_creative_look_stack tests.analysis.test_creative_looks tests.analysis.test_real_creative_look_recipes tests.analysis.test_creative_look_cli tests.analysis.test_creative_look_contract_regenerator tests.analysis.test_decisions tests.analysis.test_target_features -v
```

Expected: every focused test passes.

- [ ] **Step 2: Run complete analysis and safety suites**

```powershell
python -m unittest discover -s tests/analysis -v
python -m unittest discover -s tests/safe -v
```

Expected: both suites pass. Any failure blocks completion and must be diagnosed before another change.

- [ ] **Step 3: Verify deterministic regeneration**

```powershell
$paths = @(
  'analysis/a6400-creative-look-stack.json',
  'analysis/a6400-creative-look-guide.md',
  'analysis/feature-evidence.json',
  'analysis/a6400-target-features.json',
  'analysis/a6400-feasibility-report.md'
)
$before = @{}; foreach ($path in $paths) { $before[$path] = (Get-FileHash -Algorithm SHA256 $path).Hash }
python tools/static/regenerate_a6400_creative_look_contract_reports.py
foreach ($path in $paths) { if ($before[$path] -ne (Get-FileHash -Algorithm SHA256 $path).Hash) { throw "nondeterministic report: $path" } }
```

Expected: no exception.

- [ ] **Step 4: Run claim and artifact guards**

```powershell
git diff --check
git status --short
git diff --name-only | Select-String -Pattern '\.(so|dat|bin|exe|dll|img|key)$'
rg -n "copy_select|ten first-class|ten built-in|sharpness_range[^\n]*0|camera_test_eligible[^\n]*true|installable[^\n]*true" pmca tests analysis docs
```

Expected: no whitespace defects, no proprietary binary changes, and no positive camera/installability claim. Matches for stale phrases are permitted only in explicit rejection tests or historical superseded specs that are labeled as such.

- [ ] **Step 5: Review the exact diff and route any failure back to its owning task**

If a real omission is found, return to the Task 1, 2, or 3 test cycle that owns the affected contract. Do not create an empty or mixed verification-only commit.

- [ ] **Step 6: Prepare the review handoff**

Report the branch, commit list, focused/full/safety test counts, deterministic hashes, exact files changed, and unchanged safety verdict. Do not claim runtime support, generate firmware, connect a camera, or draft operational camera steps.
