# VulnHub and Elementor

Elementor Pro is active on this install, and `vulnhub-elementor` connects the
two. It does two separate jobs and they are worth keeping separate in your
head.

For the portal shell these hook into, see `docs/PORTAL.md`.

## 1. A widget library

Fourteen widgets in a **VulnHub** category in the Elementor panel (registered in
`VulnHub_El_Widgets`). Every one is
a thin wrapper: the SQL, the rendering, the escaping and the accessibility work
already exist in `vulnhub-core` and `vulnhub-dashboard`, and the widget's only
job is to expose the choices worth making in an editor. **A widget that starts
growing its own query belongs in `Repo` instead.**

| Widget | What it draws |
| --- | --- |
| VulnHub dashboard board | The reader's own saved widget arrangement, exactly as the portal dashboard shows it |
| VulnHub panel | Any single one of the dashboard panels, at a chosen grid width — 36 in core, plus any another plugin registers on `vulnhub_dashboard_widgets` (vulnhub-threat, vulnhub-hosting and vulnhub-departments add one each) |
| VulnHub KPI tiles | A repeater of headline numbers, 21 measures to choose from |
| VulnHub Tenable coverage | Tenable coverage by any dimension, as bars, a donut, one meter or a table |
| VulnHub coverage gaps | The chase list: assets with no Tenable record or a stale scan |
| VulnHub device explorer | The estate, filtered, with the CMDB / Intune / Tenable identifiers each record carries |
| VulnHub teams and owners | A wall of teams with their assets, criticals and ownership gaps |
| VulnHub findings list | Open findings, optionally only critical or only past SLA |
| VulnHub navigation | The portal's primary nav, for a Theme Builder header |
| VulnHub account menu | Who is signed in, administration, sign out |
| VulnHub wordmark | The mark plus the configured organisation name |
| VulnHub data freshness | When each connector last ran |
| VulnHub light/dark toggle | The theme switch, remembered per browser |
| VulnHub data-source badge | "Sample data" or "Live data" |

Every widget that shows VulnHub data **refuses to render for anybody without
`vulnhub_view`** (or `manage_options`), and does so in the widget rather than on the page — a page
built from these can be published at any URL and will not leak. In the editor
it still draws, with a note, so the person laying the page out can see it.

Widgets depend on the `vulnhub-app` stylesheet. `VulnHub_Dash_App::assets()`
therefore *registers* it on every front-end request and only *enqueues* it on
portal views: `get_style_depends()` can only name a handle WordPress already
knows about, and an unregistered handle is dropped silently.

Widgets depend on `vulnhub-app` and `vulnhub-elementor` only — **not** on
`vulnhub-app-redesign` (`app-redesign.css`), which is where the redesign's
component and light-theme rules live. A widget on an Elementor page is therefore
styled by `app.css` alone, and can look different from the same panel inside the
portal. The editor canvas likewise loads only `app.css`, versioned by the plugin
constant rather than the file's mtime.

## 2. The chrome

The portal serves its own document through `template_include`, which is what
keeps it identical under any theme. That is not negotiable — the app is not a
page of content. The navigation and the footer strip are replaceable, so:

* `vulnhub-elementor` registers Elementor's core theme locations
  (`elementor/theme/register_locations`) plus one of its own,
  `vulnhub_notice`, for a standing banner above every portal view.
* `vulnhub-dashboard`'s `templates/app.php` asks `vulnhub_portal_has_custom_header` /
  `..._footer` and, if a Theme Builder template is assigned, prints it through
  `vulnhub_portal_header` / `vulnhub_portal_footer`. Otherwise it draws its own
  markup. **Switching this plugin off changes nothing.**
* **An assigned header replaces the icon rail outright.** `render_nav()` is
  skipped and `body_class()` no longer adds `vh-chrome-rail`, so the page does
  not reserve the rail's 64px either. The seeded header is a horizontal row, so
  the two chromes are alternatives, never combined.
* `vulnhub_portal_notice` fires between the chrome and `<main>` on every portal
  view, sign-in included.
* The location's rendered HTML is memoised per request. Both the filter and the
  action ask for it, and rendering a template twice is wrong as well as slow.

### Block themes

Twenty Twenty-Five renders through `wp_template` and never calls
`elementor_theme_do_location()`, so on a block theme a Theme Builder header is
assigned, valid and invisible. `VulnHub_El_Locations::template_include()`
(priority 98, one below the portal's 99) supplies the missing shell (`templates/page.php`) for any Elementor page —
but only when the theme is a block theme, only when a header or footer template
actually exists, and never for the portal's own views.

## Seeded content

On `init` the plugin creates four documents once, then leaves them alone.
Seeding is versioned by the `vulnhub_elementor_seeded` option against
`SEED_VERSION` (currently 2); created posts are marked `_vulnhub_seeded`, and
their ids are kept in the `vulnhub_elementor_documents` option:

* **VulnHub header** and **VulnHub footer** — Theme Builder templates,
  condition `include/general`.
* **Security overview** (`/vulnhub-overview/`) and **Estate and ownership**
  (`/vulnhub-estate/`) — Elementor pages built from VulnHub widgets, linked
  from the portal navigation (published documents only, labelled with the post
  title, through `vulnhub_portal_nav_extra`).

These are a starting point, not a managed asset. A later seed version will
update a document **only if it is still byte-identical to what the seeder last
wrote** (`_vulnhub_seed_hash`); the moment somebody edits one in Elementor it is
never touched again. Silently overwriting a person's header is a far worse
failure than a missing button. A refresh also clears Elementor's generated CSS.

Portal → Administration → Platform → **Appearance** (`vulnhub_manage`) lists all
four. *Edit in Elementor* shows only with `edit_pages`; *View* only for the two
pages. The recreate button posts `admin-post.php?action=vulnhub_seed_elementor`,
which clears the seed option and seeds again.

## Hooks it uses

These are fired by the portal shell in `vulnhub-dashboard` (`templates/app.php`
and `VulnHub_Dash_App::extra_nav_links()`); this plugin is the consumer that
answers them. `vulnhub_portal_nav_extra` links are also drawn by the Elementor
Navigation widget.

| Hook | Kind | Purpose |
| --- | --- | --- |
| `vulnhub_portal_has_custom_header` | filter (bool) | Is a replacement header available? |
| `vulnhub_portal_header` | action | Print it. |
| `vulnhub_portal_has_custom_footer` | filter (bool) | Is a replacement footer available? |
| `vulnhub_portal_footer` | action | Print it. |
| `vulnhub_portal_notice` | action | Anything above the main region of every portal view. |
| `vulnhub_portal_nav_extra` | filter (array) | Extra primary-nav destinations: `label`, `url`, `icon` (an SVG path), `active`. |

`vulnhub_portal_sections` and `vulnhub_render_portal_section` already existed;
the Appearance screen uses them, which is the intended way to add a portal
administration screen from another plugin.

## Gotchas found the hard way

* **`\Elementor\Widget_Base` does not exist at `plugins_loaded`.** Elementor
  fires `elementor/loaded` from `Plugin::instance()` while its own autoloader is
  still settling; requiring the widget base there is a fatal on every request.
  Load it inside the `elementor/widgets/register` callback.
* Same reason: the category slug lives on `VulnHub_El_Widgets`, not on the
  widget base, because `elementor/elements/categories_registered` fires before
  anything has required the base.
* `_elementor_conditions` alone does nothing. Elementor Pro keeps an
  option-level index (`elementor_pro_theme_builder_conditions`); without
  `->get_conditions_manager()->get_cache()->regenerate()` you get a template
  that exists, claims a condition, and never displays.
* `_elementor_data` must be written with `wp_slash()` — `update_post_meta()`
  unslashes, and the JSON is full of backslashes the moment a setting contains
  a quote.
* A widget with only an icon in it has empty `textContent`. Assert on
  `innerHTML` when testing that a widget drew something.
* The plugin header comment in `vulnhub-elementor.php` still says "twenty-one"
  dashboard panels; the registry has grown past that.

## Testing

```
node dev/elementorpass.js      # opens the real editor
node dev/browserpass.js        # includes el-overview and el-estate
```

`dev/elementorpass.js` reads the document ids from the
`vulnhub_elementor_documents` option through `wp.sh` by itself. `VH_DOCS` is an
optional override carrying the same JSON:

```
DOCS=$(./wp.sh eval 'echo wp_json_encode(get_option("vulnhub_elementor_documents"));')
VH_DOCS="$DOCS" node dev/elementorpass.js
```

Both scripts sign in with `.admin_pass`; see `docs/BROWSER-PASS.md`.
