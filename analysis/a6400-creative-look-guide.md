# α6400 Creative Look Translation Guide

These settings are practical starting points, not exact Sony colorimetric matches. Six looks use existing α6400 Creative Styles; VV2, FL, IN, and SH use four Style Boxes.

## On-camera setup

Open MENU → Camera Settings1 → Creative Style. Select the named style directly for ST, PT, NT, VV, BW, and SE. For VV2, FL, IN, and SH, assign the listed style and values to Style Box 1, 2, 3, and 4 respectively.

| Look | α6400 Creative Style | Contrast | Saturation | Sharpness | White balance | Confidence | Nonzero modern axes unavailable on α6400 |
|---|---|---:|---:|---:|---|---|---|
| ST | Standard | +0 | +0 | +0 | Auto; A/B +0, G/M +0 | PARTIAL | none in this starting preset |
| PT | Portrait | +0 | +0 | +0 | Auto; A/B +0, G/M +0 | PARTIAL | none in this starting preset |
| NT | Neutral | +0 | +0 | +0 | Auto; A/B +0, G/M +0 | PARTIAL | none in this starting preset |
| VV | Vivid | +0 | +0 | +0 | Auto; A/B +0, G/M +0 | PARTIAL | none in this starting preset |
| VV2 | Clear | +0 | +1 | +0 | Auto; A/B +0, G/M +0 | INFERRED | none in this starting preset |
| FL | Deep | -1 | +0 | +0 | Auto; A/B +0, G/M +0 | INFERRED | none in this starting preset |
| IN | Neutral | -2 | -2 | -1 | Auto; A/B +0, G/M +0 | INFERRED | none in this starting preset |
| SH | Light | -1 | -1 | -1 | Auto; A/B +0, G/M +0 | INFERRED | none in this starting preset |
| BW | B/W | +0 | +0 | +0 | Auto; A/B +0, G/M +0 | PARTIAL | none in this starting preset |
| SE | Sepia | +0 | +0 | +0 | Auto; A/B +0, G/M +0 | PARTIAL | none in this starting preset |

PARTIAL means the target has a semantically corresponding base style but has not been colorimetrically measured. INFERRED means the style and values are conservative approximations for later JPEG comparison.

## Sources

- Sony Creative Look definitions: https://helpguide.sony.net/ilc/2320/v1/en/contents/0411B_creative_look.html
- Sony α6400 Creative Style definitions: https://helpguide.sony.net/ilc/1810/v1/en/contents/TP0002264693.html

## Optional community experiments

These entries are community experiments, not Sony defaults. Their unavailable axes are listed rather than silently discarded.

| Title | Base | α6400 style | C/S/Sh | WB | Unavailable nonzero axes | Source |
|---|---|---|---|---|---|---|
| Winter Sunshine | ST | Standard | -2/+3/+3 | Auto; A/B +1, G/M +0 | highlights, shadows, sharpness_range, clarity | https://sonyfilmsimulations.com/en/recipe/winter-sunshine/ |
| Rainy Day | FL | Deep | +3/-2/+2 | Auto; A/B +1, G/M +0 | highlights, shadows, fade, sharpness_range, clarity | https://sonyfilmsimulations.com/en/recipe/rainy-day/ |

## Future controlled validation

Compare α6400 and a supported Creative Look camera using all of these fixed conditions:

- same lens
- same scene
- same exposure
- same lighting
- same white balance
- same JPEG settings
- no postprocessing

Judge JPEG pairs under controlled viewing before changing one setting at a time. Do not promote any recipe to an exact match without measurement.
