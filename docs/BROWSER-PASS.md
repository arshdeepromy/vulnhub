# Browser pass

Rendering clean is not the same as working, and neither is visible from a
status code. This is the pass that actually drives the product.

For how the portal shell, views and stylesheets fit together, see
`docs/PORTAL.md`. This page is only about testing it in a real browser.

## Running it

Headless Chromium comes from Playwright, already on the box. `NODE_PATH` points
Node at the copy that ships with `@playwright/mcp`; there is nothing to install.

```bash
cd /path/to/vulnhub
export NODE_PATH=/usr/lib/node_modules/@playwright/mcp/node_modules

node dev/browserpass.js                  # 24 screens x desktop (1440) + phone (390)
node dev/browserpass.js --theme=dark     # the same, with data-theme stamped
node dev/browserpass.js --theme=light    # dark is the default, so light is the one to ask for
node dev/browserpass.js --only=assets    # every screen whose name CONTAINS "assets"
node dev/interact.js                     # 25 functional assertions
node dev/probe.js <url> <width>          # every element past the viewport, with ancestry
```

`--only` is a substring match, not an exact name: `--only=assets` runs
`assets`, `assets-needs-user`, `assets-eol` and `assets-no-edr`.

Do **not** run these under `sudo` — Playwright's browsers live in
`$HOME/.cache/ms-playwright` for the user that installed them, and root cannot see them.

`browserpass.js` writes `dev/shots/<screen>--<viewport>[-<theme>].png` plus a
report: `report.json`, or `report-<theme>.json` when `--theme` is given.

To look at the screenshots without a desktop session, serve the folder and open
it in any browser that can reach the box:

```bash
cd dev/shots && python3 -m http.server 8777 --bind 127.0.0.1
```

### How each script signs in

Every script hardcodes `http://localhost:8093` except where noted. None of them
reads `VULNHUB_URL`; they resolve the project root from `VULNHUB_ROOT`.

| Script | Signs in as | Credential |
|---|---|---|
| `browserpass.js`, `interact.js`, `probe.js`, `designaudit.js`, `elementorpass.js`, `dragpass.js`, `exportpass.js`, `lifecyclepass.js`, `ownerpass.js` | `admin` (administrator) at `wp-login.php` | `.admin_pass` |
| `boardpass.js`, `importpass.js`, `portaluser.js` | `portal.tester` (portal-only `vulnhub_admin`, no WordPress rights) | `.portal_test_pass` |
| `railhover.js` | no password — a session cookie you mint | `VH_COOKIE`; `VH_BASE` overrides the URL |

Passwords are read off disk and handed straight to the login form; they are
never printed. **Both password files are gitignored and must be recreated
(`chmod 600`) on a fresh checkout** — without them every password-based pass
stops at the `readFileSync` on its first line. `railhover.js`'s header shows how
to mint `VH_COOKIE` with `wp_generate_auth_cookie`. Note the cookie *name*
carries a hash of the site URL, and the site URL is derived per request from the
Host header, so a cookie minted for one host is not recognised on another.

## The scripts

| Script | What it checks |
|---|---|
| `browserpass.js` | Renders every screen in the table below at desktop and phone width; see *What it checks per screen*. |
| `interact.js` | 25 functional assertions: primary nav, totals, severity filter, search, hit, reset, pager, sort, theme toggle, account menu, chart table view, assets. |
| `probe.js` | Lists every element whose right edge is past the viewport at one URL and width, with its ancestry. |
| `designaudit.js` | Static design audit: controls with no readable label, text the colour of its background, text clipped by its own box, tap targets too small to hit. 20 screens; `--only=` and `--theme=`; writes `dev/shots/design-audit[-<theme>].json`. |
| `boardpass.js` | Dashboard board: packing leaves no measured gaps, a moved widget stays moved after reload, the board holds at a narrow viewport. |
| `dragpass.js` | Pointer-drag of a widget: it follows the pointer, a landing gap opens, the page auto-scrolls at the edge. |
| `exportpass.js` | Export control end to end: the product filter survives Apply, the CSV honours the filter, assets are versioned by mtime. |
| `importpass.js` | Pushes a very large CSV through Administration → Imports (chunked upload, progress panel), stops before importing and deletes the job. Takes an optional CSV path. |
| `lifecyclepass.js` | Patch-availability and end-of-life chart numbers equal the length of the list each links to; the lifecycle admin screen works in the portal and in wp-admin. |
| `ownerpass.js` | Search matches owner name, team, email and UPN, with counts checked against hand-written SQL. Holds no personal data in the file. |
| `portaluser.js` | A portal-only administrator: signs in through `/sign-in/`, sees no WordPress admin bar, sees the navigation and the admin sections, is kept out of wp-admin, and admin-post forms still save. |
| `railhover.js` | The rail is 64px collapsed, widens on hover and on keyboard focus, does not reflow the page when it widens, and is not a flyout at 390px. |
| `elementorpass.js` | Opens the real Elementor editor on the seeded documents and checks the VulnHub widget category and controls. |
| `form-audit.py` | curl-based: lands on each list the way a chart link would, rebuilds the GET form submission, and reports filters lost on Apply (see `docs/FILTERS.md`). |
| `shipshot.py` | JPEG-compresses and base64s a screenshot small enough to send over a tool channel. |

### Screens `browserpass.js` covers

24 screens: 12 portal views (dashboard; vulnerabilities plus critical, search,
overdue and no-patch filters; assets plus needs-user, EOL and no-EDR filters;
tickets; exceptions), 10 administration sections (overview, integrations,
imports, rules, teams, activity, audit, settings, lifecycle, appearance) and 2
Elementor pages (`/vulnhub-overview/`, `/vulnhub-estate/`).

**Not covered** — check these by hand or extend `PAGES`: `/products/`,
`/vendors/`, `/alerts/`, `/docs/`, `/departments/`, a vulnerability detail page
(`?vuln=<id>`), `/sign-in/`, the Vulnerabilities `?tab=products` and
`?tab=vuln_assets` tabs, and the administration sections added since the list
was written (people, Jira routing, documentation, threat context, AWS accounts,
AI access, advisory feeds, departments, and every `screen-*` mirror other than
lifecycle).

## What it checks per screen

- HTTP status, and how long the page took
- console errors and uncaught exceptions
- PHP fatals, warnings, notices and "critical error" text rendered into the DOM
- horizontal overflow of the document
- every element whose right edge is past the viewport, **excluding** anything
  inside an `overflow-x` scroller (that is a deliberate pattern, not a bug) and
  anything in WordPress's own admin bar
- a suspiciously thin body, which is what a half-rendered page looks like

## Result

**Last recorded run predates the redesign's icon rail and must not be read as
current.** The latest `dev/shots/report.json` (desktop and phone, no theme) has
48 captures with 12 flagged, all at phone width: the dashboard (one wide
element), all 10 administration sections (21–571px of overflow) and both
Elementor pages. `report-dark.json` is clean but older still. Re-run both themes
before quoting a result.

What *has* been verified since: the page column centres in the space right of
the rail at every width. Measured in headless Chromium at 390, 900, 1366, 1920,
2560 and 2880px on the dashboard, administration and vulnerabilities screens —
equal gutters either side at 1920 and wider, full width on a phone, no
horizontal overflow, sign-in still full-bleed. That was a one-off measurement,
not a run of the scripts above.

`interact.js`'s 25 assertions passed with no console errors when last run.

## Defects found and fixed

### 1. Primary navigation was unreachable on a phone *(historical)*

`.vh-nav` carried `flex: 1`, which is `flex: 1 1 0%`, so on a phone the
navigation collapsed into a ~30px scrollable sliver beside the account menu. It
was fixed with `flex: 1 0 100%`, and the rule has since been superseded by the
redesign.

The navigation is now a **64px icon rail** fixed to the left edge
(`app-redesign.css`, the "Vertical icon rail" block): 44px icon buttons with the
labels visually hidden, the light/dark toggle, Administration and the account
menu pinned to its foot. Hovering or focusing it widens it to 224px as an
overlay with the labels showing, without reflowing the page. **Below 768px** the
rail becomes a sticky, full-width top bar with a horizontally scrollable row of
40px icons. `railhover.js` is the test for all of that.

### 2. The account menu had markup but no styles at all

`details.vh-account` had never been given CSS: a disclosure triangle where the
avatar should be, and once opened, the name, email address and links dumped
inline into the bar. It is a positioned dropdown with a round initials avatar
(`app.css`). In the rail it opens to the right of the rail; on a phone it drops
below the top bar.

### 3. Chart table views were clipped rather than scrollable

Every chart that offers "View as table" needs that table to work: a five-column
table of team names is wider than a phone panel. The table sits in its own
`overflow-x` wrapper (`.vh-tableview__scroll`).

### 4. Chart axis labels were illegible on a phone *(regressed, re-fixed 2026-09-16)*

The SVGs scale their whole coordinate system to fit. A chart draws into a
900-unit viewBox, and a 390px phone leaves it about 310px of panel, so the
11px axis text in `app.css` landed at **3.8px** — measured, not estimated. A
mobile rule once compensated for this and did not survive the redesign
drop-in.

`app-redesign.css` now steps the nominal size with the viewport (18px under
768px, 24px under 560px, 26px under 430px), which puts the rendered size back
in the 9–14px range:

| Viewport | Chart width | Before | After |
|---|---|---|---|
| 390px | 310px | 3.8px | 9.0px |
| 430px | 350px | 4.3px | 10.1px |
| 560px | 480px | 5.9px | 12.8px |
| 767px | 695px | 8.5px | 13.9px |
| 1440px | 839px | 10.3px | 10.3px (unchanged) |

It does not go higher than 26px: a y-axis label is right-anchored 36 units in,
and past that a five-figure number reaches further left than the panel's own
padding. Charts in a narrow *desktop* widget (a 3- or 4-column panel) still
scale down the same way and are not covered by a viewport media query.

### 5. The portal's findings table could not be sorted at all

`Repo::findings()` has always accepted `orderby` and `order`; the portal never
passed them. The column headers are now links that toggle direction and carry
`aria-sort`, filters survive a sort, and the order is verified against the
database.

## Known, not bugs

- **The WordPress admin bar is not shown on portal views**, for anyone
  (`VulnHub_Dash_Portal::hide_wp_chrome_in_portal()`). vulnhub-elementor also
  hides it site-wide for portal-only users. `tidy_admin_bar()` still exists but
  only matters off the portal.
- **Findings and asset lists restack as cards below 640px**
  (`.vh-tablewrap--cards`): each row becomes a card with its column names as
  labels. Tickets, exceptions and the detail-page tables still scroll
  horizontally inside `.vh-tablewrap`, which is the intended pattern for those.
- Team names truncate in the "Exposure by team" panel at phone width. The full
  figures are in that panel's table view.
