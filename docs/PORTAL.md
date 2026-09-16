# The portal: how the GUI is built

This covers the front-end application: what a request goes through, how the
shell is laid out, how screens and admin sections are registered, and where
the CSS and JS hang off it. Most of it lives in `vulnhub-dashboard`. Other
plugins add screens through the extension points described here rather than
by editing it.

Related documents:
- `docs/PALETTE.md`: colours, themes and contrast.
- `docs/ELEMENTOR.md`: Elementor widgets and the replaceable chrome.
- `docs/CORE-API.md`: the connector and wp-admin screen contracts.
- `docs/BROWSER-PASS.md`: driving the UI in a headless browser.
- The in-portal handbook (Docs → *Portal framework*, *Widget framework*): the developer-facing detail.

---

## The shape of it

The portal is **a WordPress page per screen, rendered by our own template**.
It is not a theme, and it is not a page builder canvas.

- Activating `vulnhub-dashboard` creates one page per view. Each page's content
  is only a shortcode, `[vulnhub_app view="vulnerabilities"]`. The page ids
  are stored in the option `vulnhub_dash_pages` (view → post id), and the
  dashboard page becomes the site's front page.
- `VulnHub_Dash_App::template_include()` runs at priority 99. For any
  singular page whose content carries the shortcode, it swaps the theme's
  template for `vulnhub-dashboard/templates/app.php`. That is why the product
  looks identical under any theme. The template still calls `wp_head()` and
  `wp_footer()`, so enqueued assets and other plugins behave normally.
- If a theme or block context renders the page without our template, the
  shortcode still draws the same view, just without the shell.

### Request flow

1. **`template_redirect`**: `VulnHub_Dash_Portal::guard_portal()` sends a
   logged-out visitor on any portal page (except sign-in) to `/sign-in/` with
   `redirect_to`. It compares paths first, so a deleted sign-in page cannot
   turn this into a redirect loop.
   `VulnHub_Dash_App::redirect_signed_in()` does the reverse: a signed-in
   user who can view the portal and lands on sign-in goes to the dashboard.
2. **`template_include`**: `view_for_post()` decides which view the page is for.
3. **`templates/app.php`** prints the document:
   - the pre-paint theme script;
   - the chrome, either `render_nav()` or an assigned Elementor header;
   - `do_action( 'vulnhub_portal_notice' )`;
   - `<main id="vh-main" class="vh-main">` containing `render_view()`;
   - the footer.
4. **`render_view()`**:
   - Sign-in is handled first (`VulnHub_Dash_Portal::render_login()`), before any access check.
   - Then `gate()` runs. A logged-out visitor gets a sign-in prompt. A signed-in account without `vulnhub_view` gets "You do not have access", not a redirect: sending an authenticated user back to a login form they have already passed is a loop they cannot break.
   - Then a contributed view renders itself if `vulnhub_dash_render_view_<view>` has a callback. This is checked **before** the built-in switch, so a contributed view can never fall through to the dashboard.
   - Otherwise the built-in switch runs: `admin`, `vulnerabilities`, `assets`, `tickets`, `exceptions`, `products`, `vendors`, and the dashboard as the default.

**Gotcha:** `view_for_post()` finds the view with a **literal** substring match
on `view="<name>"`, with double quotes. `view='assets'` or `view=assets` in the
page content silently renders the dashboard.

---

## Views

`vulnhub_dash_views()` in `vulnhub-dashboard.php` is the registry, in menu
order. Each entry is `title`, `slug`, `menu`, `icon` (an SVG path, 24-unit
viewBox) and optionally `hidden`.

| View | Slug | In the rail? |
|---|---|---|
| dashboard | `/vulnhub/` (also the front page) | yes |
| vulnerabilities | `/vulnerabilities/` | yes |
| assets | `/assets/` | yes |
| tickets | `/tickets/` | yes |
| exceptions | `/exceptions/` | yes |
| products | `/products/` | hidden; reached from "View all" on the Exposure by product widget |
| vendors | `/vendors/` | yes |
| eol_plan | `/eol-plan/` | yes; contributed by vulnhub-eos |
| sources | `/inventory-sources/` | yes; which register knows what, and what each is missing |
| admin | `/portal-admin/` | hidden; reached from the gear at the foot of the rail |
| login | `/sign-in/` | hidden |

**Contributed views.** A plugin adds a screen the portal owns by filtering
`vulnhub_dash_views` and answering `vulnhub_dash_render_view_<view>`. The
activation hook that creates pages has already run by then, so **the plugin
must create its own page** (containing `[vulnhub_app view="<view>"]`) and add
it to `vulnhub_dash_pages`. An entry with no mapped page is skipped by the
nav. Current users:
- vulnhub-alerts (`alerts`, inserted after Vulnerabilities)
- vulnhub-docs (`docs`)
- vulnhub-departments (`departments`, hidden)
- vulnhub-eos (`eol_plan`) — the EOL remediation plan; see `docs/EOS.md`

**Navigation-only links.** `vulnhub_portal_nav_extra` only adds a link, not a
view. Each entry takes `label`, `url`, an `icon` SVG path and `active`. This is
how the Elementor pages (*Security overview*, *Estate and ownership*) appear.

**Primary nav order today:** Dashboard, Vulnerabilities, Alerts, Assets,
EOL plan, Inventory sources, Tickets, Exceptions, Vendors, Docs, then the
nav-extra links.

`sources` is not a contributed view: it lives in vulnhub-dashboard
(`class-vh-dash-sources.php`) and registers itself through the same
`vulnhub_dash_views` filter anyway, inserting after `assets` so it sits beside
the register it compares. It creates its own page for the same reason a
contributed view must — activation ran long before the class existed.

---

## Filters live in the URL

Every list screen keeps its state in the querystring, which is what makes a
number on a widget able to open the list behind it. Two conventions hold
across the portal:

- **A control the form owns** round-trips through Apply as a form field.
- **A filter that only arrives from a link** is rendered as a **removable
  chip** saying what it means in words. A URL-only filter with no visible
  explanation is how a screen ends up lying about what it is showing.

The assets list understands, beyond the obvious `search` / `type` / `team` /
`site` / `life`:

| Parameter | Means |
|---|---|
| `known=<src>`, `only:<src>`, `not:<src>` | one system at a time: known by, *solely* known by, or not known by |
| `has=<a,b>` | known by **all** of these systems |
| `missing=<a,b>` | known by **none** of these systems |
| `hosting=<env>` | `aws`, `azure`, `gcp`, `cloud`, `onprem`, `unknown` — the same vocabulary the findings list uses |
| `coverage`, `endpoint`, `primary_source`, `operating_system`, `patch_group`, `eol` | scan/EDR state and the dashboard's drill-downs |

`has` and `missing` are what make *"in Tenable, but missing from the CMDB"*
expressible — one chip, two parameters, so removing the chip removes both
rather than half a sentence. They are implemented in `Repo::assets()` (see
`docs/CORE-API.md`), so they reach the list, its infinite-scroll endpoint and
the CSV export alike.

`hosting` is contributed by vulnhub-hosting through `vulnhub_assets_query`,
using the same classification the *Servers by hosting environment* widget
counts with and the row icons draw — so a filtered list, the icons and the
widget cannot disagree with each other. It classifies **every** asset, while
the widget counts only servers: every row now carries an environment icon, and
filtering by an icon only to watch rows vanish would be the wrong surprise. The
widget's exact set is one Type filter away.

The vulnerabilities list has its own vocabulary, beyond `search` / `severity` /
`team` / `department` / `age` / `life`:

| Parameter | Means |
|---|---|
| `fix=<class>` | `patch`, `remove`, `config`, `blocked_eol`, `await_fix`, `excepted` — what the work actually is (see `VH_Action` in `docs/CORE-API.md`) |
| `excepted=exclude\|only` | drop accepted risk from the list, or show only it |
| `patch_available=1\|0`, `support=eol\|insupport` | the narrower questions: did a vendor ship anything, is the platform still supported |
| `hosting=<env>`, `platform=<os>` | the same environment vocabulary as the assets list; platform is windows / linux / macos |
| `product`, `zone`, `route`, `delivery`, `poc`, `sev_not`, `asset` | URL-only drill-downs from the dashboard, each with a banner |

`fix` is the parameter name because **`action` belongs to WordPress**:
`admin-post.php` dispatches on it, the export form posts there, and a filter of
that name overwrote `vulnhub_export_csv` so the download led nowhere. Only the
argument passed to `Repo::findings()` still calls it `action`. Anything added to
that screen has to reach `VulnHub_Dash_Export` too — the export carries its own
list of arguments, and a filter missing from it makes the CSV stop matching the
screen without saying so.

### Marks on a row

`vulnhub_asset_hostname_mark` puts a small mark before a hostname —
`( string $html, array $asset )`, returning escaped markup. vulnhub-hosting
answers it with the environment icon, the visual partner of the `hosting`
filter above. Two rules, because this is the densest cell on the busiest
screen: the mark is decorative (`alt=""`, aria-hidden — the hostname beside it
already says what the row is), and an asset the rules cannot classify draws
**nothing**. A shrug-shaped icon on hundreds of rows reads as a finding about
the estate rather than an absence of information.

The environment for every asset resolves in **one memoised query** for the
estate, not one per row. Rows render individually and the infinite-scroll
endpoint renders a fresh batch per request, so there is no moment when a page's
ids are all known at once.

---

## The shell

### Rail

`render_nav()` still prints a `<header class="vh-topbar">`. The redesign turns
it into a vertical rail in CSS (`app-redesign.css`):

- **At 768px and wider**, the rail is fixed to the left edge and 64px wide. It
  holds a 36px brand tile, a column of 44px icon buttons whose text labels are
  visually hidden (`.vh-nav__txt`), and a bottom cluster: the light/dark
  toggle, the Administration gear (only with `vulnhub_manage`) and the account
  menu. The "Sample data" chip is hidden in the rail. The admin shell shows
  "MOCK DATA" instead.
- **Hovering the rail, or tabbing into it** (`:focus-within`), widens it to
  224px **as an overlay**. The page does not reflow, so no chart re-lays-out
  on a mouse move. That is also why the expanded rail has an opaque fill and a
  shadow. The `:focus-within` state matters: without it, a keyboard user tabs
  through buttons whose labels are still clipped to 1px.
- **Below 768px** the rail becomes a sticky full-width top bar with a
  horizontally scrolling row of 40px icons. The account menu drops down
  instead of opening to the side.

### Body classes

`VulnHub_Dash_App::body_class()` adds:

| Class | When |
|---|---|
| `vh-app` | always (set by the template's `body_class( 'vh-app' )`) |
| `vh-app-body` | any portal view |
| `vh-chrome-rail` | the portal drew its own rail, i.e. no Elementor Theme Builder header is assigned |
| `vh-login-body` | the sign-in view (full-bleed; `login.css` hangs off it) |

Sign-in also carries `vh-chrome-rail`, because `body_class()` does not
special-case it, but it draws no rail. CSS that reserves space for the rail
must exclude it.

### Page layout: how the column sits next to the rail

```css
body.vh-app { --vh-content-max: 1440px; }
body.vh-chrome-rail:not(.vh-login-body) { padding-left: 64px; }      /* reserve the rail */
.vh-chrome-rail .vh-main,
.vh-chrome-rail .vh-footer { max-width: var(--vh-content-max); margin-left: auto; margin-right: auto; }
@media (max-width: 767px) { body.vh-chrome-rail:not(.vh-login-body) { padding-left: 0; } }
```

This follows the usual pattern for an app with a fixed side nav. The **body**
reserves the nav's width, and the content column centres in the space that is
left, up to a maximum width. On a wide or zoomed-out window the gutters grow
evenly on both sides, and the footer lines up with the column above it.

*Found the hard way.* The rail used to be reserved with
`.vh-chrome-rail .vh-main { margin-left: 64px }`, which overrode `app.css`'s
`margin: 0 auto`. The results:
- Past 1440px of content, the column sat pinned against the rail and every extra pixel piled up on the right.
- The phone rule meant to remove the offset, `.vh-main { margin-left: 0 }`, lost on specificity, so phones had a 64px blank strip down the left.

Reserving the space on `body` fixed both. To widen or narrow the column,
change `--vh-content-max` rather than adding another `max-width`.

The admin shell's context bar and footer deliberately bleed to the edges of
`.vh-main` by cancelling its padding (`margin: -22px -26px 0`). If you change
`.vh-main`'s padding, change those too.

### Replacing the chrome

When `vulnhub_portal_has_custom_header` returns true (vulnhub-elementor does
this when a Theme Builder header is assigned):
- The template fires `vulnhub_portal_header` instead of `render_nav()`.
- `vh-chrome-rail` is **not** added, so the page loses the rail and its 64px reservation together.

The footer works the same way. The two chromes are mutually exclusive, and the
seeded Elementor header is a horizontal row. Sign-in draws neither. See
`docs/ELEMENTOR.md`.

---

## Access

- **Portal access** is `vulnhub_view`. Management screens need `vulnhub_manage`.
  Changing an asset's lifecycle needs `vulnhub_triage`.
- **The WordPress admin bar** is hidden on every portal page for everyone
  (`hide_wp_chrome_in_portal()`).
- **A portal-only user** is a runtime concept, not a role: logged in, holding
  `vulnhub_view`, without `manage_options`.
  - Any wp-admin screen redirects them to the portal. `admin-post.php` and `admin-ajax.php` are exempt, so portal forms still save.
  - Signing in sends them straight to the dashboard.
  - The `vh_from_portal` request flag, or a portal referer, keeps an admin-post handler's redirect in the portal rather than wp-admin (`keep_redirects_in_portal()`).

---

## The admin shell

`/portal-admin/?section=<slug>`, drawn by `VulnHub_Dash_Portal::render_admin()`.

- **Layout:**
  - **Context bar** (sticky): breadcrumb *Administration / group / section*, a MOCK DATA badge in mock mode, and connector health ("N connectors failing" or "idle").
  - **Side nav:** a *Filter sections…* box, then items grouped **Data**, **Integrations** and **Platform**. A red dot appears on *Integrations* when a connector's last run failed, and a **WP** badge on mirrored screens.
  - **Body:** the section title and summary, plus a *Saved* chip when the URL carries `vh_type=success&vh_msg=…`.
  - **Footer:** last-run times for Tenable, CMDB, Intune and Jira, plus the core and schema versions.
- **Registry:** `sections()` merges the built-ins with the mirrored screens,
  then applies `vulnhub_portal_sections`, then sorts by `order`. A section is
  `label`, `cap`, `group`, `order`, `summary` and an optional `screen`.
  An unknown `?section=` falls back to `overview`, which needs `vulnhub_manage`.
- **`group` must be `data`, `integrations` or `platform`.** Any other group is
  silently never rendered in the side nav.
- **Mirrored wp-admin screens.** Every page registered on `vulnhub_admin_pages`
  (other than the four the portal already handles natively) becomes the
  section `screen-<slug>`. It goes in the Integrations group, or Platform for
  auth and lifecycle screens, and is drawn by core's `render_screen()`. This
  is how Tenable, Intune, CMDB, Jira, Automation, Backup, Authentication and
  End of life are configurable from the portal with no portal code of their own.
- **Render order for the body:**
  1. If the section has `screen`, core's `render_screen()` draws it.
  2. Otherwise `vulnhub-dashboard/admin-views/<section>.php` is tried. That directory does not currently exist.
  3. Otherwise `do_action( 'vulnhub_render_portal_section', $section )` fires. It fires for **every** screen-less section, so a handler must check `$section`.
- **Current sections:**

  | Group | Sections |
  |---|---|
  | Data | Imports, Rules, Advisory feeds, Departments, Teams & SLAs, Threat context, Jira routing |
  | Integrations | Integrations, AWS accounts, and the mirrored Tenable, Intune, CMDB, Jira, Automation and Backup screens |
  | Platform | Admin overview, Your security, Authentication, End of life, People, AI access, Sync activity, Audit trail, Appearance, Settings, Documentation |

  *Your security* is the one section every account can open: it is registered
  at `vulnhub_view` by vulnhub-auth and shows the signed-in person their own
  two-factor enrolment, recovery codes and remembered browsers. Everything else
  in Platform needs a management capability.

- **Styling:** core's `admin.css` is **not** loaded on the portal; only
  `admin.js` is. `app.css` recolours `table.widefat`. Nothing makes wp-admin
  `.form-table` or `.wp-list-table` markup fit a phone, so wrap wide content
  yourself.

---

## Assets and cache busting

`VulnHub_Dash_App::assets()` **registers** its handles on every front-end
request and **enqueues** them only on portal views. An Elementor widget on an
ordinary page can depend on `vulnhub-app`, and `get_style_depends()` silently
drops a handle WordPress has never heard of.

| Handle | File | Notes |
|---|---|---|
| `vulnhub-app` | `assets/app.css` | dark design, tokens, components; kept as a clean drop-in |
| `vulnhub-app-redesign` | `assets/app-redesign.css` | depends on `vulnhub-app`: rail, layout, component supplements, admin shell, light theme |
| `vulnhub-app` | `assets/app.js` | depends on `wp-api-fetch`; localised as `VulnHubApp` (`nonce`, `restRoot`, `i18n`) |
| `vulnhub-motion` | `assets/vh-motion.js` | progressive motion layer |
| sign-in only | `login.css`, `login.js`, `attack-surface-bg.js`, Google Fonts (Space Grotesk, JetBrains Mono) | Elementor's frontend bundles are dequeued on sign-in, where they threw a ReferenceError |

**Versions are the plugin version plus the file's mtime** (`asset_ver()`).
Cloudflare caches CSS for hours, and a version that only moves on release
served fresh markup styled by stale CSS. vulnhub-core and vulnhub-elementor's
front-end stylesheet follow the same rule. **These do not yet**, and still
enqueue with bare version constants: vulnhub-alerts, vulnhub-docs,
vulnhub-backup, vulnhub-rules, vulnhub-import, vulnhub-threat, and the
Elementor editor's copy of `app.css`. An edit to their CSS or JS can be
invisible behind the CDN until the version constant moves. If a change "did
not land", check the `?ver=` on the file in the network tab first.

**Theme.** Dark by default; `data-theme="light"` on `<html>` swaps the tokens.
The choice is remembered in `localStorage['vh-theme']` and applied before first
paint. See `docs/PALETTE.md`.

---

## Behaviour: app.js and vh-motion.js

**`app.js`** is plain JavaScript with no build step. It binds to `data-vh-*`
attributes rather than classes, so markup can be restyled freely. Main areas:

- **Theme toggle** (`data-vh-theme`) and the shared tooltip (`#vh-tooltip`, `data-vh-tip`).
- **Dashboard editor:**
  - drag to reorder (pointer and keyboard on the grip);
  - width select (`data-vh-width`);
  - add and remove (`data-vh-add`, `data-vh-remove`);
  - saving through REST.

  `app-redesign.css` currently forces strict aligned rows, overriding the grid spans the JS packer writes.
- **Findings and assets tables:**
  - bulk select with "select all matching" (`data-vh-selbar`, `data-vh-tick`, `data-vh-selall`);
  - infinite scroll (`data-vh-infinite`, with a paged fallback);
  - expandable vulnerability and product rows (`data-vh-vuln-assets`, `data-vh-product-assets`);
  - owner-name masking (`data-vh-owner-toggle`).
- **Charts:** "View as table", copy table or TSV (`data-vh-copy`), and SVG/PNG export (`data-vh-export`).
- **Other:**
  - confirmation on anything with `data-vh-confirm` (a global handler: don't reuse that attribute for a control that confirms itself, or it asks twice);
  - the vendor drill-down modal;
  - the admin side-nav filter;
  - the Settings screen's tabs, help and dirty-state bar.

**`vh-motion.js`** is progressive: delete it and the portal still works,
statically. It provides:
- page fade transitions on in-app links;
- count-ups on tile values;
- per-widget background canvases keyed off `data-vh-widget`;
- OS glyph badges;
- empty-state orbits;
- particles along attack-path lines;
- a hover spotlight.

It does nothing but the instant fade under `prefers-reduced-motion`.

---

## The dashboard board

Detail is in the handbook's *Widget framework* page. The short version:

- **Registry.** `VulnHub_Dash_Widgets::all()` holds 38 widgets in core. Plugins
  add more on `vulnhub_dashboard_widgets`: attack paths (threat), servers by
  hosting environment (hosting) and department exposure (departments). Each
  entry names a render callback, an optional `data` callback for CSV export,
  its group, its default width and the data sources it `depends` on. The
  registry is memoised per request, so hook it early.
- **Layout** is per user, in user meta `vulnhub_dashboard_layout`. Widths snap
  to 3, 4, 6, 8 or 12 columns, and unknown ids are dropped on save. Widgets
  added to the default layout later are appended to existing boards once
  (`vulnhub_dashboard_seen`).
- **Caching.** Each widget's HTML is cached per host and locale: fresh for 15
  minutes, served stale for up to 6 hours while a background refresh runs. A
  finished sync busts only the widgets fed by what that connector moved
  (`bust_for_connector()`). A warm job and an hourly cron re-render the board
  so nobody waits on a cold widget.

**What we can act on** (`action_by_environment`, `action_by_os`) are worth a
note, because they are the two that answer "what do we do on Monday". One row
per hosting environment or per platform, each bar split by `VH_Action`'s
classes, every segment linking to the vulnerabilities list filtered to exactly
the rows it counted — so the number on screen is the number in the CSV you
export from there. Both carry a table view and the widget CSV export, and both
sit on the default board.

Two scoping decisions are deliberate and will look like bugs otherwise. The
environment rows count **servers and cloud instances only**, because that is
what the list's `hosting` filter matches — a bar counting laptops the list then
refuses to show is the one failure a drill-down cannot afford. And the platform
rows are per **platform**, not per release, because the findings list filters no
finer than `platform=windows|linux`; per-release actionability lives on the EOL
remediation plan, which is built around that question. The bars use a per-row
scale for the reason the patch-availability widget does: ~219,000 of 256,000
open findings are waiting on a distribution fix, and on a shared scale every
actionable segment renders as a sliver against them.

---

## Endpoints

### REST: `vulnhub-dashboard/v1`

Every route requires a logged-in user with `vulnhub_view`.

| Route | Purpose |
|---|---|
| `POST /layout`, `POST /layout/reset` | save or reset the current user's board |
| `GET /findings-more`, `GET /assets-more` | infinite-scroll row fragments, rebuilt from the same `$_GET` filters as the first page |
| `GET /vuln-assets?vuln=`, `GET /product-assets?product=` | lazy bodies for the *Vulnerability on assets* and *By product* tabs |
| `GET /vendor-drill` | the vendor card drill-down (paged, searchable, with its CSV export URL) |
| `GET /sync-status?connector=` | live connector progress for the admin cards; also reaps a stuck run |

### admin-post actions

| Action | Capability | Purpose |
|---|---|---|
| `vulnhub_save_layout` | view | Customise panel save or reset |
| `vulnhub_widget_csv` | view | one widget's rows as CSV (nonce `vulnhub_widget_csv_<id>`) |
| `vulnhub_export_csv` | view | list exports with the column picker |
| `vulnhub_set_lifecycle` | **triage** | decommission or return to service; returns to the filtered list it came from |
| `vulnhub_sources_csv` | view | the Inventory sources matrix and per-register figures as CSV |
| `vulnhub_eos_export_csv` | view | the EOL plan screen's filtered rows |
| `vulnhub_seed_elementor` | manage | recreate missing seeded Elementor documents |

---

## Times on screen

Every timestamp in the database is UTC; every timestamp on screen is the site's
timezone. Portal views get there through `vh_date()` and `vh_ago()`, and
date-only values (an EOL date, a plan deadline, a due date) through
`vh_date_only()`, which does not convert — so 31 Dec stays 31 Dec.

This only works if the site has a timezone. It did not: `timezone_string` was
empty, WordPress treated "local" as UTC, and every screen read twelve hours
behind on a New Zealand install. Settings now shows the timezone and says so
when it is unset. The rules for writing new code are in `docs/CORE-API.md`.

---

## Responsive patterns

- **Wide tables** sit in `.vh-tablewrap` (alias `.vh-table-wrap`) and scroll
  inside their own frame, never the page.
- **`.vh-tablewrap--cards`** restacks each row as a card under 640px, with
  `td[data-th]::before` labels. It is used on the Vulnerabilities findings
  table and the Assets list. Tickets, exceptions and detail tables still
  scroll.
- **Chart table views** use `.vh-tableview__scroll`.
- **Primary actions** never live at the bottom of a tall panel. The export
  control is anchored to its button in the panel header, not
  `position: fixed`, because `.vh-main` carries a transform and so becomes the
  containing block for fixed positioning.

---

## Testing the UI

Drive the real product. A status code says nothing about whether a screen
works. See `docs/BROWSER-PASS.md`.

| Script | Checks | Auth |
|---|---|---|
| `dev/browserpass.js [--only=<substring>] [--theme=dark\|light]` | 24 screens × desktop and phone: console errors, PHP errors in the DOM, overflow | `.admin_pass` |
| `dev/interact.js` | 25 functional assertions | `.admin_pass` |
| `dev/railhover.js` | rail is 64px collapsed, expands on hover and focus, causes no reflow, is not a flyout on a phone | `VH_COOKIE` (from `wp_generate_auth_cookie`), `VH_BASE` |
| `dev/designaudit.js [--only=] [--theme=]` | contrast, unlabeled controls, clipped text, small tap targets | `.admin_pass` |
| `dev/portaluser.js`, `boardpass.js`, `importpass.js` | the portal-only user, board packing, the large CSV import UI | `.portal_test_pass` |

`NODE_PATH` must point at the Playwright that ships with `@playwright/mcp`. Run
as the user that installed Playwright, not under `sudo`. The cookie name for a
`wp_generate_auth_cookie` value depends on the **request host**, because
`WP_HOME` is derived per request. From wp-cli, which has no host, it comes out
under a different hash, so compute
`wordpress_logged_in_<md5("http://<host>")>` for the host you are testing.

---

## Known GUI issues

Nothing found in the September 2026 audit is still open. What was found, and
what it took, is recorded below.

### Fixed 2026-09-16

- **The widget export menu rendered behind the widget.** `app.css` lifts every
  direct child of a widget above the decorative flow canvas with
  `.vh-w > * { position: relative; z-index: 1 }`, which makes the header and
  the body two stacking contexts at the same level — so the body, second in the
  DOM, painted over the header, and the menu's own `z-index: 25` could never
  escape the header's context. It only showed where a widget put something in
  the corner the menu drops into: *Vulnerabilities by severity and age* has
  `.vh-matrix__tools` (Copy table / Copy as TSV) absolutely positioned there,
  overlapping the open menu by 168x28px and taking the clicks. The header now
  outranks the body (`z-index: 3`).
- **Admin sections overflowed at phone width.** Every mirrored wp-admin screen
  pushed the page sideways at 390px: 12px of it was structural (the context bar
  and footer cancel 26px of `.vh-main` padding, but the phone rule sets 14px),
  the rest came from `.form-table` refusing to stack and from `wp-list-table`
  being wider than the screen. Core's `admin.css` is deliberately not loaded on
  the portal, so the portal stylesheet handles it: rows stack below 768px,
  controls cap at 100%, and wide tables scroll inside their own frame. Page
  overflow is now 0 on every section.
- **Chart axis labels in narrow widgets.** The phone fix only helped at phone
  widths; a three-column panel on a wide screen scales the same SVG down just
  as hard (3.9px at a 360px panel). `.vh-chart-wrap` is now a container-query
  context, so axis text follows the panel's own width: 9.3-11.7px across the
  range, with the viewport rules kept as the fallback.

- **Most widespread vulnerabilities** bars linked to
  `vulnerabilities?vuln_id=<id>`, which the screen never read, so every bar
  landed on the unfiltered list. They now link `vuln=<id>`, the vulnerability's
  detail page.
- **Links that bounced portal-only users.** The findings row *Except* link went
  to the wp-admin exceptions screen and the account menu's *Security & MFA*
  link to `profile.php`; both redirected a portal-only account back to the
  dashboard. *Except* now opens the portal's Exceptions view, which renders
  core's request form in place (`?new=1&finding=…`, and `?exception=…` for a
  decision), and `VulnHub_Dash_App::exceptions_url_in_portal()` keeps that
  screen's own links and its post-save redirect inside the portal. *Security &
  MFA* now opens **Administration → Your security**, a `vulnhub_view` section
  registered by vulnhub-auth that draws the same enrolment panel; its
  admin-post handlers return to the portal when the form was submitted there.
- **The theme toggle's first click did nothing** on a light-OS browser with no
  saved choice. The fallback now matches the stylesheet's dark default.
- **The headline *Past SLA* tile's sparkline plotted open highs.** It plots
  `findings_overdue` from the daily snapshot, which the snapshot has recorded
  all along.
