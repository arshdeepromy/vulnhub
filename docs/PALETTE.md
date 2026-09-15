# VulnHub colour palette: tokens, themes and contrast record

This is the record of the colours the portal actually ships. Re-check a change
against it rather than re-arguing it. Every value below was read from the CSS
and every ratio was measured. Where a rule the palette depends on does not hold,
it says so.

**Files**
- `vulnhub-dashboard/assets/app.css`: the dark "attack surface" design. It holds the dark tokens on `:root, body.vh-app` and the component styles.
- `vulnhub-dashboard/assets/app-redesign.css`: component supplements, the few tokens the redesign adds, and the **light theme** under `:root[data-theme="light"]`.

## History

- **Up to 2026-09-08:** a light-first palette. It was validated with the
  data-viz skill's `validate_palette.js`: light severity steps
  `#b4232c / #e06d1f / #f0c020 / #2a78d6`, a dark mode on a `#16181d` surface,
  and white-on-fill severity pills.
- **2026-09-11:** replaced by the dark "attack surface" redesign. The dark
  `app.css` was already present in the first repository commit.
- **2026-09-13:** a light theme was added back as a token block in
  `app-redesign.css`. It reuses the old light severity steps for Critical to
  Low.

The dark ramp, the dark chrome and the light Info step have **not** been
through the validator. Results recorded before 2026-09-11 describe a palette
that no longer exists; see *Re-running the checks* at the end.

---

## Theme selection

- **Dark is the default.** The dark tokens sit on both `:root` and `body.vh-app`
  (`app.css`). No stylesheet has a `prefers-color-scheme` query, so an OS
  set to light still gets dark until the viewer switches.
- **Light** is `:root[data-theme="light"]` together with
  `:root[data-theme="light"] body.vh-app`. Both selectors are needed. A
  property set on `body` shadows the one inherited from `:root`, so overriding
  only `:root` would leave everything inside `body` dark. That showed up once
  as a lone white rail on otherwise dark content.
- **Before first paint**, an inline script in `templates/app.php` reads
  `localStorage['vh-theme']`, accepts only `dark` or `light`, and stamps
  `data-theme` on `<html>`. The Elementor page shell,
  `vulnhub-elementor/templates/page.php`, carries the same script.
- **The toggle** is `[data-vh-theme]`: the moon button in the rail and the
  Elementor "light/dark toggle" widget. `app.js` flips the attribute and
  writes `localStorage`.

---

## Tokens

### Surfaces and chrome

| Token | Dark (default) | Light |
|---|---|---|
| `--vh-plane` (page) | `#050810`, plus a radial `#0a1220 → #050810` glow painted on `body` | `#f4f5f7`, flat |
| `--vh-surface` (inputs, dense fills) | `#0b1220` | `#ffffff` |
| `--vh-raised` (cards) | `linear-gradient(rgba(14,21,38,.92), rgba(9,14,26,.92))` | `#ffffff` |
| `--vh-raised-solid` | `#0e1526` | `#ffffff` |
| `--vh-raised-2` (tab strip, help bubble) | `#121b2e` | `#f8f9fb` |
| `--vh-line` | `rgba(120,160,210,.14)` | `#e6e7ea` |
| `--vh-line-strong` / `--vh-line-2` | `rgba(120,160,210,.28)` | `#d3d5da` |
| `--vh-grid` (gridlines) | `rgba(120,160,210,.10)` | `#e6e7ea` |
| `--vh-baseline` | `rgba(120,160,210,.35)` | `#c3c2b7` |

Gridlines and axes are solid hairlines, never dashed. The decorative canvases
in `vh-motion.js` do draw dashed strokes, but they are not charts.

### Ink, link, accent, button

| Token | Dark | Light |
|---|---|---|
| `--vh-ink` | `#e6edf7` | `#0b0b0b` |
| `--vh-ink-2` | `#a3b1c6` | `#33322f` |
| `--vh-muted` | `#8593ab` | `#6e6c66` |
| `--vh-faint` (axis labels, table heads) | `#7d8aa3` | `#6e6c66` |
| `--vh-link` / `--vh-link-hover` | `#8fd7ff` / `#c8ecff` | `#1d62b8` / `#14488c` |
| `--vh-accent` / `--vh-accent-rgb` | `#5ee0ff` / `94,224,255` | `#1f68c2` / `31,104,194` |
| `--vh-accent-ink` (primary button label) | `#06101c` | `#ffffff` |
| `--vh-btn-primary` | gradient `#7fe8ff → #4fd3f5` | gradient `#2f74cc → #1f68c2` |
| `--vh-glow` | `0 0 10px var(--vh-accent)` | `0 0 10px rgba(accent,.5)` |

### Severity: a semantic heat scale

Severity is an ordered risk state, but it is deliberately a multi-hue heat
scale (red, orange, amber, blue, grey) rather than a single-hue ramp. Security
readers rely on the red-to-amber convention. The cost of that choice is that
hue must never carry severity on its own (see *Secondary encoding*).

| Step | Dark | Light |
|---|---|---|
| `--vh-sev-critical` | `#ff5a66` | `#b4232c` |
| `--vh-sev-high` | `#ff9a3c` | `#e06d1f` |
| `--vh-sev-medium` | `#f5d04a` | `#f0c020` |
| `--vh-sev-low` | `#5ea3ff` | `#2a78d6` |
| `--vh-sev-info` | `#7d8aa3` | `#6e6c66` (the same as muted and faint) |

Severity as **text** takes its own set, added 2026-09-16. The ramp above is
tuned for marks at 3:1; text needs 4.5:1, which orange and amber on white
never reach. Dark repeats the ramp (it is light enough to read as text);
light darkens each step to the same hue.

| Text token | Dark | Light | Light on surface / plane |
|---|---|---|---|
| `--vh-sev-critical-ink` | `#ff5a66` | `#b4232c` | 6.53 / 5.98 |
| `--vh-sev-high-ink` | `#ff9a3c` | `#9a4a0e` | 6.25 / 5.73 |
| `--vh-sev-medium-ink` | `#f5d04a` | `#7a5c00` | 6.25 / 5.73 |
| `--vh-sev-low-ink` | `#5ea3ff` | `#1d62b8` | 6.01 / 5.51 |
| `--vh-sev-info-ink` | `#7d8aa3` | `#6e6c66` | 5.25 / 4.81 |

Anything that prints a number or a sentence in a severity colour (the attack
path cards, vendor stats, exposure bands, the AWS read-out) uses these; charts
and pills keep the ramp.

### Series

| Token | Dark | Light |
|---|---|---|
| `--vh-series-1` | `#5ea3ff` (identical to sev-low) | `#2a78d6` |
| `--vh-series-2` | `#ff9a3c` (identical to sev-high) | `#eb6834` |

In dark mode the two series colours are the same hexes as Low and High
severity. A chart that puts a series next to a severity mark cannot tell them
apart by colour.

### Status

| Token | Dark | Light |
|---|---|---|
| `--vh-good` / `-ink` / `-bg` | `#4ade80` / `#86efac` / `rgba(74,222,128,.14)` | `#1f7a44` / `#186236` / `rgba(31,122,68,.10)` |
| `--vh-warn` / `-ink` / `-bg` | `#f5b04a` / `#ffd28a` / `rgba(245,176,74,.14)` | `#9c5c0f` / `#8a5009` / `rgba(240,192,32,.16)` |
| `--vh-bad` / `-ink` / `-bg` | `#ff5a66` / `#ff8c94` / `rgba(255,90,102,.14)` | `#b4232c` / `#93171f` / `rgba(180,35,44,.09)` |
| `--vh-neutral-bg` | `rgba(120,160,210,.10)` | `rgba(11,11,11,.05)` |
| `--vh-thead-bg` (table header band) | `rgba(7,11,20,.6)` | `#f4f5f7` |

`--vh-good-ink` and `--vh-warn-ink` are also defined in `app.css` as well as
`app-redesign.css`, so an Elementor page — which loads only `app.css` — still
has them.

### Severity pills

A pill is a **translucent tint with a coloured label**. The old solid fill with
a white label is gone.

| Pill | Fill | Label | Where set |
|---|---|---|---|
| Critical | `--vh-bad-bg` | `--vh-pill-fg-critical`: `#ff8c94` dark, `#93171f` light | tokens |
| High | `--vh-pill-high`: `rgba(255,154,60,.16)` dark, `rgba(224,109,31,.12)` light | `--vh-pill-fg-high`: `#ffb36b` dark, `#9a4a0e` light | tokens (2026-09-16) |
| Medium | `--vh-pill-medium`: `rgba(245,208,74,.16)` dark, `rgba(240,192,32,.20)` light | `--vh-pill-fg-medium`: `#f5d04a` dark, `#7a5c00` light | tokens (2026-09-16) |
| Low | `--vh-pill-low` | `--vh-pill-fg-low`: `#8fb8ff` dark, `#1d62b8` light | tokens |
| Info | `--vh-pill-info` | `--vh-pill-fg-info`: `#a3b1c6` dark, `#52514e` light | tokens |

All pill borders are literal dark `rgba(...)` values. `--vh-pill-ink`
(`#e6edf7` dark, `#0b0b0b` light) is still defined but nothing uses it.

---

## Where chart colours come from

- **PHP charts read CSS variables only.** `class-vh-dash-charts.php` maps
  severity through `severity_var()` and defaults series to
  `var(--vh-series-1)`. Donut slice gaps and line-end dots are outlined in
  `var(--vh-surface)`. `VulnHub_Dash_Widgets::palette()` returns variables
  only: series-1, series-2, sev-medium, good, sev-critical and muted. It feeds
  the OS-mix donut, so that categorical set borrows severity hues. The EOL and
  patching widgets and the ticket-status colours also use variables. A theme
  switch therefore recolours every server-rendered chart with no JS.
- **Hard-coded hex in PHP** is limited to brand colours: the product and vendor
  tiles, the OS badges (`#EE0000`, `#0078D4`) and a `#fff` glyph. None of these
  are data encodings.
- **`vh-motion.js` hard-codes dark values.** Its `SEV` table uses
  `255,90,102 / 255,154,60 / 245,208,74 / 94,163,255 / 74,222,128`, applied to
  the background canvases and tile glows. So do the flow-line colours and the
  OS badge glyph colours. They do not follow the light theme.
- `app.js` uses `#fff` as the canvas background when exporting a chart as an
  image.

---

## Secondary encoding: what holds and what does not

Because hue cannot separate the warm steps reliably, especially inside dark
mode's narrow lightness band, the palette depends on encodings other than
colour. Here is their actual state:

| Rule | Status | Detail |
|---|---|---|
| A text label on every severity mark | **Partly** | Pills always spell the word. Stacked-bar segments carry only `aria-label`, a tooltip and the scale legend. Line series rely on the legend. Segment bars print a count, not the severity, and hide it when the segment is under 34px. |
| Fixed order, critical → info | **Holds for severity charts** | `severity_order()` drives stacks and the scale legend. The trend legend runs Critical → Low with no Info. Segment bars take their order from the caller. |
| A 2px gap between adjacent segments | **Holds** | `.vh-stack__track` and `.vh-segbars__track` both use `gap: 2px`. Donut slices are stroked 2px in `--vh-surface`. In dark mode that stroke (`#0b1220`) is close to, but not exactly, the card colour. |
| A table view on every chart | **Does not hold** | Only `donut()`, `funnel()` and `coverage_bars()` add "View as table", plus a few widgets (top assets, patching, EOL). `line_chart`, `bar_chart`, `severity_stack` and `segment_bars` do not, so trend, age buckets, top vulnerabilities, family mix and team exposure have no table. They offer only the widget CSV export. |

---

## Measured contrast (WCAG)

The floors are 3:1 for marks and 4.5:1 for text. Translucent fills were
composited over the surface they sit on before measuring.
- **Dark** was measured on the card colour (`#0e1526`, the lighter and so worse case) and on the plane (`#050810`).
- **Light** was measured on `#ffffff` and `#f4f5f7`.

### Severity as marks

| Step | Dark card / plane | Light surface / plane |
|---|---|---|
| Critical | 5.99 / 6.59 | 6.53 / 5.98 |
| High | 8.61 / 9.48 | 3.29 / 3.02 (only just passes) |
| Medium | 12.14 / 13.35 | **1.71 / 1.57 (fails)** |
| Low | 7.07 / 7.78 | 4.42 / 4.05 |
| Info | 5.23 / 5.76 | 5.25 / 4.81 |

### Text inks

| Ink | Dark card / plane | Light surface / plane |
|---|---|---|
| `--vh-muted` | 5.86 / 6.45 | 5.25 / 4.81 |
| `--vh-faint` | 5.23 / 5.76 | 5.25 / 4.81 |
| `--vh-ink-2` | 8.37 / 9.21 | 12.82 / 11.75 |
| `--vh-link` | 11.55 / 12.71 | 6.01 / 5.51 |
| `--vh-series-1` used as text | 7.07 | **4.42 / 4.05 (fails)** |
| `--vh-series-2` used as text | 8.61 | **3.20 / 2.93 (fails)** |
| good / warn / bad | 10.44 / 9.70 / 5.99 | 5.35 / 5.31 / 6.53 |

### Pills (label on its own composited fill)

| Pill | Dark | Light |
|---|---|---|
| Critical | 6.95 | 7.60 |
| High | 7.85 | 5.48 (was 1.57 before the 2026-09-16 tokens) |
| Medium | 8.49 | 5.60 (was 1.40) |
| Low | 6.99 | 5.17 |
| Info | 6.80 | 6.80 |

### Other pairs

| Pair | Dark | Light |
|---|---|---|
| Status ink on its tint (good / warn / bad) | 9.81 / 9.93 / 6.95 | 6.46 / 5.95 / 7.60 |
| Status chip text on its tint (good / warn) | passes | 6.46 / 5.95 (was 1.23 / 1.30 with the dark literals) |
| Primary button label on its gradient | 10.89–13.55 | 4.68–5.50 |
| White count label on segment bars, over its `rgba(6,16,28,.55)` backing | 5.72 or better on every step | 5.72 or better on every step |
| Table header text on `--vh-thead-bg` | 5.50 | 4.81 (was ≈1.01 with the dark wash) |
| Input placeholder | 3.40 | 2.88 |
| Baseline / grid (decorative) | 1.89 / 1.16 | 1.79 / 1.24 |

---

## Known issues

These are defects against this record, not accepted exceptions. Most are in
the light theme, which was added as a token swap on top of a dark design that
had literal colours scattered through its component rules.

1. **Fixed 2026-09-16: high and medium pills used literal dark colours.**
   `.vh-pill--high` and `.vh-pill--medium` measured 1.57 and 1.40 in light.
   They now read `--vh-pill-high` / `--vh-pill-fg-high` and the medium pair,
   so light gets its own tint and a darker label (5.48 and 5.60) while dark is
   unchanged. Pill *borders* are still literal dark rgba, which is cosmetic
   rather than a contrast failure.
2. **Fixed 2026-09-16: the light table header was unreadable.**
   `.vh-table thead tr` had a literal `rgba(7,11,20,.6)` wash that composited
   over white to roughly the colour of its own text (≈1.01:1). The fill is now
   `--vh-thead-bg`, which light sets to the page plane (`#f4f5f7`, 4.81:1).
3. **Fixed 2026-09-16: literal status text.** `#86efac` and `#ffd28a` in
   `.vh-chip--good`, `.vh-chip--warn`, `.vh-state--good`, `.vh-flash--good`,
   `.vh-health--ok`, `.vh-health--warn`, `.vh-warn-note` and the tile delta now
   read `--vh-good-ink` / `--vh-warn-ink`, which light already defined
   (6.46 and 5.95, from 1.23 and 1.30).
4. **Fixed 2026-09-16: white count labels on segment bars.** A segment's fill
   is an inline style, so the label cannot choose an ink per step. It now sits
   on an `rgba(6,16,28,.55)` backing, which holds white at 5.72:1 or better
   over every step in both themes (it was as low as 1.50).
5. **Fixed 2026-09-16: severity used as text in light mode.** Vendor stats,
   exposure bands, the attack-path card numbers and the AWS read-out now use
   the `--vh-sev-*-ink` set above. `--vh-series-2` as text (3.20) is **not**
   fixed: it is still used raw for the "remediated" series label.
6. **The accent swap is dead code.** `body[data-vh-accent="emerald"|"violet"]`
   is styled but nothing sets the attribute. Even if something did, the light
   block's selector outranks it. The `.vh-themebtn` styles have no markup.
7. **Fixed 2026-09-16: the toggle's first click did nothing.**
   `currentTheme()` fell back to `prefers-color-scheme` when no theme was
   stamped, but the CSS renders dark in that case, so on a light-OS browser
   with no saved choice the first click computed "light → dark" and changed
   nothing. The fallback is now `dark`, matching what the stylesheet actually
   renders. The OS preference is still not honoured anywhere (see *Theme
   selection*).
8. **`vh-motion.js` reads `--vh-accent-rgb` once, at load**, and does not
   re-read it when the theme is toggled. Its severity and flow colours are
   dark literals (see *Where chart colours come from*).
9. **`login.css` is dark only.** It hard-codes `#050810` and `#e6edf7` and has
   no light variant.
10. **wp-admin has its own severity set.** `vulnhub-core/admin/assets/admin.css`
    defines `--vh-crit #b4232c`, `--vh-high #d97706`, `--vh-med #ca8a04`,
    `--vh-low #2563eb`, `--vh-info #64748b` and `--vh-ok #15803d`. The high
    and medium steps differ from the portal's.
11. **The Elementor editor canvas loads only `app.css`.** It does not load the
    redesign's tokens (such as `--vh-raised-2` and the `-ink` status tokens) or
    the light block. Elementor widgets on front-end pages also depend on
    `vulnhub-app` alone, not `vulnhub-app-redesign`.
12. **Dark-mode series and severity collide:** `series-1 = sev-low` and
    `series-2 = sev-high`.

---

## Re-running the checks

- **Palette separation and contrast:** the data-viz skill's
  `validate_palette.js`. The repository does not ship a `scripts/` directory.
  ```
  node validate_palette.js "#ff5a66,#ff9a3c,#f5d04a,#5ea3ff" --mode dark  --surface "#0e1526"
  node validate_palette.js "#b4232c,#e06d1f,#f0c020,#2a78d6" --mode light --surface "#ffffff"
  ```
- **In the running product:** `node dev/designaudit.js` walks the screens at
  desktop and phone widths. It reports text under the contrast floor, empty
  controls, clipped text and undersized hit areas. Dark is the default, so
  audit the light theme explicitly with `--theme=light`. Output goes to
  `dev/shots/design-audit[-<theme>].json`.
