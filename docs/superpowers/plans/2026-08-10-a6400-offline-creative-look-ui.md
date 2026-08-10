# α6400 Offline Creative Look UI Implementation Plan

## Objective

Turn the validated `CreativeLookExperience` state machine into a usable,
self-contained offline touch prototype. The prototype must advance the
α6400-native product design without implying a target processing binding,
camera eligibility, recovery, or installability.

## Product behavior

- Render the exact 12-Look catalog and six Custom slots.
- Support landscape, portrait shutter-up, and portrait shutter-down layouts.
- Allow touch/click navigation through catalog, Custom-base selection,
  eight-axis editing, value selection, per-Look reset, and return navigation.
- Show modified markers and the documented mode restrictions.
- Persist strict version-1 state in browser local storage and support strict
  JSON import/export.
- Represent unknown Sony defaults as `Default`, never as invented numbers.
- Label visual swatches as navigation aids rather than Sony color references.

## Architecture

1. Add a deterministic Python HTML renderer that injects the canonical Python
   catalog, ranges, labels, initial state, and immutable safety metadata.
2. Keep CSS and JavaScript as reviewed source assets, then inline them into one
   generated HTML file so the prototype needs no server or network.
3. Put state transitions and validation in a testable JavaScript core. Browser
   rendering consumes that core; Node-based tests exercise the reducer and
   validation independently of the DOM.
4. Extend `creative_look_experience.py` with a `web` command that accepts an
   existing strict state file and writes only a non-symlink `.html` output.
5. Check in one deterministic generated prototype under `analysis/`.

## Verification

- Start with failing Python contract/CLI tests and Node interaction tests.
- Require an exact CSP with no network connection capability and reject
  external script, stylesheet, image, form, and frame dependencies.
- Exercise built-in selection, Custom-base selection, all axis ranges,
  restrictions, reset, orientation changes, persistence validation, and safety
  immutability through the JavaScript core.
- Verify deterministic checked-artifact regeneration.
- Render landscape and both portrait variants in a local browser and inspect
  screenshots for clipping, hierarchy, and touch target usability.
- Run focused tests, full analysis tests, the safety suite, Python compilation,
  JavaScript syntax checks, and `git diff --check` before publication.

## Non-goals and gates

- No Sony binary execution, camera transport, USB access, updater mode,
  partition writes, firmware packaging, or installable output.
- No claim that swatches reproduce Sony image processing.
- `processing_binding=UNBOUND_TARGET`, `recovery_validated=false`,
  `camera_test_eligible=false`, and `installable=false` are immutable.
- Camera testing remains forbidden until an independent exact ILCE-6400
  Taiwan/region-0 firmware 2.00 restoration path is verified.
