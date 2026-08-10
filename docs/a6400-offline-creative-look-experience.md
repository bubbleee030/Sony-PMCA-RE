# α6400 Offline Creative Look Experience

This is a deterministic, static/offline implementation of the first-class
Creative Look interaction and state contract. It intentionally has no camera
transport, Sony-binary execution, firmware packaging, or processing binding.

## Implemented experience

- all 12 α7 V reference Looks in their fixed order;
- six independent Custom slots with selectable built-in bases;
- the eight reference adjustment axes and exact ranges;
- unknown Sony defaults represented as `default`, never invented numeric values;
- modified markers and reset for each Look or Custom slot;
- Intelligent Auto, Picture Profile, Flexible ISO Log, BW/SE Saturation, and
  movie Sharpness Range restrictions;
- landscape, portrait shutter-up, and portrait shutter-down logical layouts;
- touch hit regions for catalog selection, Custom-base selection, axis opening,
  value selection, reset, and navigation; and
- strict, atomic JSON persistence of orientation, selection, Custom bases,
  adjustments, and mode state.

Every saved state and rendered frame records `offline_only=true` and
`processing_binding=UNBOUND_TARGET`. Recovery, camera eligibility, and
installability remain false.

## Offline commands

Create a new state file:

```powershell
.\.venv\Scripts\python.exe .\creative_look_experience.py initialize `
  --state .\creative-look-state.json
```

Select one of the three logical orientations:

```powershell
.\.venv\Scripts\python.exe .\creative_look_experience.py orient `
  --state .\creative-look-state.json `
  --orientation portrait_shutter_up
```

Render the current UI frame as deterministic JSON:

```powershell
.\.venv\Scripts\python.exe .\creative_look_experience.py frame `
  --state .\creative-look-state.json `
  --output .\creative-look-frame.json
```

Dispatch a logical touch using coordinates from that frame:

```powershell
.\.venv\Scripts\python.exe .\creative_look_experience.py touch `
  --state .\creative-look-state.json --x 120 --y 120
```

Generate the complete deterministic demo snapshot:

```powershell
.\.venv\Scripts\python.exe .\creative_look_experience.py demo `
  --output .\creative-look-demo.json
```

The checked example is
`analysis/a6400-creative-look-offline-experience-demo.json`.

Generate the self-contained offline touch UI:

```powershell
.\.venv\Scripts\python.exe .\creative_look_experience.py web `
  --state .\creative-look-state.json `
  --output .\creative-look-offline.html
```

Open the resulting HTML in a browser. It contains no external scripts, fonts,
images, stylesheets, forms, or network requests. The browser prototype supports
the full catalog, Custom-base workflow, all eight axis pickers, reset, the three
orientations, restriction test controls, local persistence, and strict JSON
import/export. Its swatches are navigation aids only and are explicitly not
Sony color-output references.

The deterministic checked prototype is
`analysis/a6400-creative-look-offline-ui.html`.

## Deliberate boundary

The implementation proves the offline product workflow and persistence model;
it does not claim that the α6400 currently invokes these layouts or processing
values. The next integration milestone is a target-native view/factory seam and
one proven processing vertical slice. No camera or installable firmware work is
permitted until independent restoration to exact ILCE-6400 Taiwan/region-0
firmware 2.00 is verified.
