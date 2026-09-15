# Task: make every dashboard widget and its drill-through report on in-service assets only

## Project

VulnHub — WordPress vulnerability & asset management app.

- Root: `/home/romy/vulnhub` (docker compose: `vulnhub-wp`, `vulnhub-db`, `vulnhub-wpcli`)
- Plugins: `/home/romy/vulnhub/wp/wp-content/plugins/vulnhub-*`
- Live: https://vulnhub.example.com/
- Helpers: `./wp.sh <wp-cli args>` · `./q.sh` (reads SQL on stdin) · `./lint.sh` (php -l across all plugins)
- DB prefix `wp_`, assets table `wp_vh_assets`, findings `wp_vh_findings`

Relevant files:

- `vulnhub-core/includes/functions.php` — lifecycle vocabulary and the scope helpers
- `vulnhub-core/includes/class-vh-lifecycle.php` — status changes + finding archive/restore sweep
- `vulnhub-core/includes/class-vh-coverage.php` — scan coverage scope
- `vulnhub-dashboard/includes/class-vh-dash-widgets.php` — all dashboard widgets
- `vulnhub-dashboard/includes/class-vh-dash-app.php` — /assets/, /vulnerabilities/ list pages + filters
- `vulnhub-dashboard/includes/class-vh-dash-portal.php` — drill-through URL builder
- `vulnhub-elementor/includes/widgets.php` — the "Estate and ownership" page widgets

## The rule we are enforcing

Every dashboard widget, and every report a user reaches by clicking that widget, must count in-service
assets only. Right now that is true for some widgets, silently untrue for others, and untestable for the rest.

## Current data (848 assets)

| lifecycle_status | count | counted as "in service" today |
|---|---|---|
| in_service | 512 | yes |
| unknown | 194 | yes |
| quarantine | 91 | yes |
| maintenance | 7 | yes |
| **subtotal shown by every report** | **804** | |
| spare | 18 | no |
| planned | 18 | no |
| retired | 4 | no |
| stock | 3 | no |
| missing | 1 | no |
| **hidden** | **44** | |

So "in service only" currently means "not spare/stock/planned/retired/missing". Only 512 of the 804
assets in every report are actually flagged In service.

## Read this before changing anything

Parts of the current behaviour are deliberate and documented. Do not flatten them without asking:

- `vh_lifecycle_statuses()` marks `in_service`, `quarantine`, `maintenance` and `unknown` as
  `in_service => true`.
- `vh_in_service_statuses()` answers "should this asset resolve to an owner".
- `vh_scannable_statuses()` is a deliberately narrower, admin-editable list (`in_service` + `unknown`)
  answering "should this asset have a Tenable scan". Its docblock explains why quarantine/maintenance
  are excluded there but not from ownership.
- `vh_unissued_statuses()` = spare/stock/planned.
- `Lifecycle::sweep()` archives findings when an asset leaves service and restores `prev_state` when it
  returns. That mechanism works — verified: all 44 out-of-service assets report zero open findings, and
  a quarantined host returns 0 rows on /vulnerabilities/.

The gap is that there is no third concept for "which assets do reporting widgets count", so widgets each
improvise, and three of them do not filter at all.

## Confirmed defects

### A. Remediation health counts the entire inventory
`class-vh-dash-widgets.php`, `render_remediation_health()` and `data_remediation_health()`:

```php
$owned  = SELECT COUNT(*) FROM {$a} WHERE owner_person_id > 0 OR team_id > 0
$assets = SELECT COUNT(*) FROM {$a}
```

No lifecycle predicate. The widget renders "Assets with an owner or team — 835 of 848" while the assets
page reports 804. Retired, spare, planned, in-stock and missing kit is in the denominator.

### B. "Estate by device type" donut reads 848
`asset_type_rows()`: `SELECT asset_type, COUNT(*) FROM {$a} GROUP BY asset_type` — no lifecycle predicate.
Donut centre shows 848.

### C. Estate and ownership page (`/vulnhub-estate/`) is unscoped
`vulnhub-elementor/includes/widgets.php` — the Device information explorer renders
"Showing 25 of 848 devices" with no lifecycle filter and no "N out of service hidden" notice.

Worse, it is internally inconsistent: the Acme Platform team card shows **ASSETS 655** (in-service
count is **611** — all 44 out-of-service assets belong to that team) while **UNOWNED 78** on the same card
*is* in-service scoped. One card, two definitions.

### D. "Platforms past end of life" label does not match its content
Subtitle says "In-service assets by the operating system release they run". Its largest bar,
Windows 10 22H2 = 104, breaks down as **19 in_service, 82 quarantine, 3 maintenance**. Either scope the
widget or stop calling it in-service.

### E. Ownership gaps is 94% noise
"Workstations and mobiles with nobody to chase" = 78 → **5 in_service, 59 quarantine, 13 unknown,
1 maintenance**. The docblock on `vh_lifecycle_statuses()` says the whole point of the in-service concept
is that "ownership expectations only apply to assets that are actually in service" — including quarantine
in that list defeats the stated intent.

### F. The `life` URL parameter fails open
`?life=bogus` (or any unrecognised value) silently returns the default in-service list instead of erroring.
Valid values are `all`, `retired_all`, and each status slug. A stale or mistyped link quietly returns
different data than it claims to.

### G. No widget passes lifecycle in its drill-through URL
Every `/assets/?...` link from a widget relies on the list page's default. Change that default and 15+
widgets silently change meaning with no test catching it. Drill-through URLs should state their scope.

### H. /vulnerabilities/ has no lifecycle filter at all
Its in-service correctness is purely a side effect of `Lifecycle::sweep()` archiving. There is no filter
control, no scope notice, and nothing to catch a sweep that misses. Add an explicit lifecycle filter and
the same "N out of service hidden" notice the assets page shows.

### I. `unknown` is doing most of the work
- "Coverage by source system → 146 by Tenable" → **0 in_service, all 146 unknown**.
- Most exposed asset `appsrv12.corp.example` (asset id 691, 6,635 open findings) is `lifecycle=unknown`,
  Tenable-only, no CMDB ref.
- The 194 unknown-lifecycle assets carry the large majority of the 228,107 open findings, so every
  findings widget is effectively a report on assets nobody has confirmed are in service.

## Decide these with me before writing code

1. Should `quarantine` and `maintenance` count as in service for **reporting** widgets? (They arguably
   should for ownership, but not for EOL or exposure.)
2. Should `unknown` count as in service? It is 194 assets and the bulk of the findings — excluding it
   changes almost every headline number.
3. Should widget denominators be 512, 804, or driven by a new admin-editable scope setting alongside
   `coverage_scope`?

Propose an answer with the trade-offs, ask me to confirm, then implement.

## Acceptance criteria

- One helper (e.g. `vh_reportable_statuses()` / `vh_reportable_sql()`) defines the reporting scope, with a
  filter hook, and every widget uses it. No inlined status lists anywhere.
- `remediation_health`, `assets_by_type` and the Elementor device explorer are scoped; their totals match
  the assets list header exactly.
- The Elementor team card's asset count and unowned count use the same scope as each other.
- Every widget drill-through URL carries an explicit `life=` value rather than relying on the page default.
- `/vulnerabilities/` gains a lifecycle filter and a scope notice matching the assets page.
- An unrecognised `life=` value is rejected visibly (notice or 400), never silently coerced to the default.
- Every widget that claims a scope in its subtitle actually applies it — or the subtitle changes.
- `./lint.sh` passes. No data migrations; this is a reporting fix only. Do not touch `prev_state` or the
  archive/restore semantics.

## Verify with

```bash
cd /home/romy/vulnhub
./q.sh <<'SQL'
SELECT lifecycle_status, COUNT(*) FROM wp_vh_assets GROUP BY lifecycle_status ORDER BY 2 DESC;
SQL
./lint.sh
```

And these URLs — widget number must equal the list header count in every case:

- https://vulnhub.example.com/ (Remediation health, Estate by device type, Platforms past EOL, Ownership gaps)
- https://vulnhub.example.com/assets/ · `?life=all` · `?life=retired_all` · `?life=in_service` · `?life=unknown`
- https://vulnhub.example.com/assets/?coverage=gap · `?needs_user=1` · `?eol=win10-22h2` · `?known=only:tenable`
- https://vulnhub.example.com/vulnerabilities/
- https://vulnhub.example.com/vulnhub-estate/

Baselines observed before the fix (for regression comparison):
`coverage=gap` 99 (56 in_service / 43 unknown) · `needs_user=1` 78 (5 / 13 unknown / 59 quarantine / 1
maintenance) · `eol=win10-22h2` 104 (19 / 82 quarantine / 3 maintenance) · `known=only:tenable` 146
(0 in_service / 146 unknown).

## Working style

Start by reading `vulnhub-core/includes/functions.php` and
`vulnhub-dashboard/includes/class-vh-dash-widgets.php` in full before proposing anything. Give me the
scope decision first, then a change plan, then the diff.

