# VulnHub chart palette — decisions and validation record

Validated with the data-viz skill's `validate_palette.js`. Recorded here so a
future change can be re-checked rather than re-argued.

## Severity ramp — a *semantic heat* scale, not a categorical palette

Severity is an ordered risk state (critical → info). It is deliberately **not**
treated as a categorical palette, and it cannot be a single-hue ordinal ramp
either: security readers depend on the conventional red → orange → amber heat
semantics, and `--ordinal` requires a hue spread under 40° (ours is ~128°).

It is therefore the documented **multi-hue "semantic heat" sequential exception**,
which carries one hard obligation: *always ship a scale legend*. We do.

### Light mode (surface `#ffffff`)

| Severity | Hex | Role |
|---|---|---|
| Critical | `#b4232c` | deep red |
| High | `#e06d1f` | orange |
| Medium | `#f0c020` | amber |
| Low | `#2a78d6` | blue |
| Info | `#8a8886` | neutral grey |

Validator, 4 chromatic steps: **chroma floor PASS**, **CVD separation PASS**
(worst adjacent ΔE 16.4 deutan / 14.6 tritan — target ≥ 8), **normal-vision floor
PASS** (worst adjacent ΔE 17.5 — floor ≥ 15). Two findings stand, both accepted
with the documented relief:

- *Lightness band*: amber `#f0c020` sits above the categorical band. Expected —
  the band is a categorical gate and this is a heat ramp.
- *Contrast WARN*: amber is 1.71:1 on white. **The relief rule applies and is
  implemented**: visible text labels on every severity mark, plus a table view.

This ordering was chosen by sweeping six candidates and taking the one with the
widest adjacent separation; the conventional `#d03b3b/#ec835a/#fab219` set scored
only 13.6 normal-vision (below the 15 floor) and was rejected.

### Dark mode (surface `#16181d`)

| Severity | Hex |
|---|---|
| Critical | `#e0524a` |
| High | `#d9661a` |
| Medium | `#c98500` |
| Low | `#3987e5` |
| Info | `#9a9894` |

Validator: **lightness band PASS**, **chroma floor PASS**, **contrast PASS**
(all ≥ 3:1). The warm steps sit close on the adjacency measures — inside dark
mode's narrow L 0.48–0.67 band, red/orange/amber cannot be pulled apart while
staying in band and staying legible. Hue therefore does **not** carry severity on
its own anywhere in this application. Secondary encoding is mandatory and
implemented everywhere:

1. **Text label on every severity mark** — the pill always spells the word.
2. **Fixed position order**, critical → info, left to right and top to bottom, in
   every legend, stack and table. Position encodes severity independently of hue.
3. **2px surface gap** between stacked segments and adjacent bars.
4. **A table view** for every chart.

## Two-series categorical (opened vs remediated)

| Series | Light | Dark |
|---|---|---|
| Opened | `#2a78d6` | `#3987e5` |
| Remediated | `#eb6834` | `#f08030` |

**ALL CHECKS PASS in light** (CVD ΔE 24.7, normal 33.6, contrast ≥ 3:1) and all
separation/contrast checks pass in dark.

## Magnitude comparison (exposure by team, top vulnerabilities)

Teams and vulnerabilities are **nominal** categories, so a value-ramp across bars
is an anti-pattern — it would double-encode bar length as hue. One series, one
colour: categorical slot 1 (`#2a78d6` light, `#3987e5` dark) for every bar.

## Chrome

| Role | Light | Dark |
|---|---|---|
| Chart surface | `#ffffff` | `#16181d` |
| Page plane | `#f4f5f7` | `#0f1115` |
| Primary ink | `#0b0b0b` | `#f5f6f7` |
| Secondary ink | `#52514e` | `#c3c2b7` |
| Muted (axis) | `#898781` | `#898781` |
| Gridline | `#e6e7ea` | `#25282f` |
| Baseline | `#c3c2b7` | `#383c44` |

Gridlines and axes are solid hairlines one shade off the surface — never dashed.

## Re-running the checks

```
node scripts/validate_palette.js "#b4232c,#e06d1f,#f0c020,#2a78d6" --mode light --surface "#ffffff"
node scripts/validate_palette.js "#e0524a,#d9661a,#c98500,#3987e5" --mode dark  --surface "#16181d"
node scripts/validate_palette.js "#2a78d6,#eb6834" --mode light --surface "#ffffff"
```

## Text inks — added 2026-09-08

The ramp above is validated as *marks*, against a 3:1 mark floor. Several of
these values were also being used as **text**, where the floor is 4.5:1 at the
sizes the app actually renders. Those uses now have their own tokens; the chart
ramp and the two-series categorical set are unchanged.

| Token | Was | Now | Why |
|---|---|---|---|
| `--vh-muted` (light) | `#898781` | `#6e6c66` | table heads, meta lines, axis labels: 3.59:1 on the surface, 3.29:1 on the plane |
| `--vh-muted` (dark) | `#898781` | `#93918a` | 4.22:1 on `--vh-neutral-bg` |
| `--vh-bad` (dark) | `#e0524a` | `#e86c60` | status ink, 4.05:1 on its own `--vh-bad-bg` tint |
| `--vh-warn` (light) | `#a86413` | `#9c5c0f` | 4.25:1 on `--vh-warn-bg` |
| `--vh-link` | *(used `--vh-series-1`)* | `#1d62b8` light, `#3987e5` dark | link text was 4.05:1 on the plane |
| `--vh-btn-primary` | *(used `--vh-series-1`)* | `#1f68c2` light, `#2f74cc` dark | white label on the fill was 4.42:1 |

### Severity pills

The pill puts a label *on* a ramp step, so white is only legible on the dark
steps. Each step now names its label colour, and two steps take a pill-only
background — the chart ramp, the legend swatches and the stack segments still
use `--vh-sev-*` unchanged.

| Step | Light fill | Light label | Dark fill | Dark label | Ratio |
|---|---|---|---|---|---|
| Critical | `--vh-sev-critical` | `#ffffff` | `--vh-sev-critical` | `--vh-pill-ink` | 6.53 / 4.84 |
| High | `--vh-sev-high` | `--vh-pill-ink` | `--vh-sev-high` | `--vh-pill-ink` | 5.06 / 5.18 |
| Medium | `--vh-sev-medium` | `--vh-pill-ink` | `--vh-sev-medium` | `--vh-pill-ink` | 9.73 / 6.04 |
| Low | `--vh-pill-low` `#2168c0` | `#ffffff` | `#3987e5` | `--vh-pill-ink` | 5.52 / 5.10 |
| Info | `--vh-pill-info` `#6e6c66` | `#ffffff` | `#9a9894` | `--vh-pill-ink` | 5.25 / 6.44 |

`--vh-pill-ink` is `#1f1e1c` light, `#141312` dark.

### Re-checking

`node dev/designaudit.js [--theme=dark]` walks every screen at desktop and
phone widths and reports anything under the floor, alongside empty controls,
clipped text and undersized hit areas.
