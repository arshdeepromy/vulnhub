# Browser pass

Rendering clean is not the same as working, and neither is visible from a
status code. This is the pass that actually drives the product.

## Running it

Headless Chromium comes from Playwright, already on the box. `NODE_PATH` points
Node at the copy that ships with `@playwright/mcp`; there is nothing to install.

```bash
cd /srv/vulnhub
export NODE_PATH=/usr/local/lib/node_modules/@playwright/mcp/node_modules

node dev/browserpass.js                 # 17 screens x desktop + phone
node dev/browserpass.js --theme=dark    # the same, in dark
node dev/browserpass.js --only=assets   # one screen while iterating
node dev/interact.js                    # 25 functional assertions
node dev/probe.js <url> <width>         # every element past the viewport, with ancestry
```

Do **not** run these under `sudo` — Playwright's browsers live in
`/srv/.cache/ms-playwright`, and root cannot see them.

`browserpass.js` writes `dev/shots/<screen>--<viewport>[-dark].png` plus a
`report.json`. It logs in by reading `.admin_pass` off disk and handing it
straight to the login form; the password is never printed.

To look at the screenshots without a desktop session, serve the folder and open
it in any browser that can reach the box:

```bash
cd dev/shots && python3 -m http.server 8777 --bind 127.0.0.1
```

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

All 34 screens x 2 themes are clean, and all 25 interaction assertions pass with
no console errors. Five real defects were found and fixed on the way.

### 1. Primary navigation was unreachable on a phone

`.vh-nav` carries `flex: 1`, which is `flex: 1 1 0%`. A flex-basis of zero beats
`width: 100%`, so the mobile rule meant to give the nav its own row did nothing:
it collapsed into a ~30px scrollable sliver next to the account menu, with all
five section links — 886px of them — off-screen. `flex: 1 0 100%` fixes it.

This is the one that would never show up in a unit test and never show up in a
status code.

### 2. The account menu had markup but no styles at all

`details.vh-account` had never been given CSS. `details` fell back to its
defaults: a disclosure triangle where the avatar should be, and, once opened,
the display name, email address and links dumped inline into the topbar,
shoving the page sideways. On every page, for every signed-in user, desktop
included. It is now a positioned dropdown with a round initials avatar.

### 3. Chart table views were clipped rather than scrollable

Every chart offers "View as table" — the relief that keeps severity from
depending on hue alone, so it has to work. A five-column table of team names is
393px wide; the panel is 390px, with no scroller, so the last column was simply
cut off. The table now sits in its own `overflow-x` wrapper.

### 4. Chart axis labels were illegible on a phone

The SVGs scale their whole coordinate system to fit, taking 11px axis text down
to about 6px. The mobile rule now sets a larger nominal size so it lands back at
a readable one after the scale.

### 5. The portal's findings table could not be sorted at all

`Repo::findings()` has always accepted `orderby` and `order`, and wp-admin's
findings screen passes them. The portal never did — and since the portal is
where all VulnHub work happens, sorting was effectively missing from the
product. The column headers are now links that toggle direction and carry
`aria-sort`, filters survive a sort, and the order is verified against the
database rather than eyeballed.

## Known, not bugs

- WordPress's admin bar renders its own display name past 390px and clips it
  itself. It is WP chrome, shown only to administrators, and portal-only users
  already get a trimmed version from `VulnHub_Dash_Portal::tidy_admin_bar()`.
- The findings table scrolls horizontally on a phone. It is inside
  `.vh-tablewrap`, which is the intended pattern — but it does mean owner, due
  date and ticket, the three columns the product exists to show, are off-screen
  until you scroll. A card layout at phone widths is the right answer and
  belongs with the front-end redesign, not here.
- Team names truncate in the "Exposure by team" panel at phone width. The full
  figures are in that panel's table view.
