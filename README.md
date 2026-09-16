# VulnHub

Vulnerability, asset and ownership intelligence — built as WordPress plugins so
there is no bespoke framework to maintain and security patching rides on
WordPress's own update channel.

The whole application is a Docker Compose stack plus a set of plugins. Clone the
repository anywhere, bring the stack up, and everything — WordPress, the
database, the cron worker — runs in containers; nothing is tied to a particular
host or path.

---

## Getting started

```bash
git clone https://github.com/arshdeepromy/vulnhub.git
cd vulnhub
cp .env.example .env          # set ports, DB name and secrets (see below)
docker compose up -d          # build and start the whole stack
docker compose ps             # confirm every service is running
```

The first boot installs WordPress and activates every VulnHub plugin. Open the
site at the port you set (default **8093**) and log in with the admin account
created on install.

**Set the site timezone before anyone reads a screen.** WordPress ships with it
empty, which makes "local time" mean UTC — every timestamp in the platform then
reads hours behind, on a tool whose whole job is telling you when something was
last seen:

```bash
docker compose run --rm --entrypoint wp wpcli option update timezone_string Pacific/Auckland
```

Stored data is always UTC and never needs migrating, so this is safe to set (or
change) at any time; it only affects display. Settings → System shows the
current timezone and warns when it is unset. Out of the box the platform runs on a deterministic mock
fleet, so every screen is populated before you connect a single real system —
see **Going live** below to switch a connector over to live data.

### Where things live

Everything is relative to the directory you cloned into — there is no absolute
path baked into the app:

| Path | What it holds |
|---|---|
| `wp/wp-content/plugins/vulnhub-*` | the VulnHub plugins (this repo) |
| `wp/wp-content/uploads/vulnhub-sync/` | staged raw sync data, per connector (see **Sync architecture**) |
| `docker-compose.yml` | the stack definition |
| `.env` / secret files | ports, DB name, and secrets — **not committed** |
| `docs/` | design docs and developer contracts |
| `dev/` | test and audit scripts (resolve the project root from `VULNHUB_ROOT`, defaulting to the repo) |

### Secrets

The stack reads its secrets from `.env` (copied from `.env.example`, never
committed):

```bash
cp .env.example .env
# then fill in — generate values with:
#   openssl rand -hex 16   # DB_PASS and DB_ROOT_PASS
#   openssl rand -hex 32   # VH_ENC_KEY
```

- `DB_PASS` / `DB_ROOT_PASS` — the database passwords
- `VH_ENC_KEY` — becomes `VULNHUB_ENCRYPTION_KEY`, the key that encrypts stored connector credentials at rest, so a database dump alone never exposes them

The dev/test scripts read their credentials from gitignored, `chmod 600` files
next to the compose file, never from the command line:

- `.admin_pass` — the admin password, used by most browser passes
  (`dev/browserpass.js`, `interact.js`, `probe.js`, `designaudit.js`, …);
- `.portal_test_pass` — the password of a portal-only test account, used by
  `boardpass.js`, `importpass.js` and `portaluser.js`;
- `VH_COOKIE` (environment) — a pre-minted logged-in cookie, used by
  `railhover.js`, which needs no password at all (`VH_BASE` overrides its URL).

The Node passes still assume `http://localhost:8093` and a fixed admin username;
`VULNHUB_URL` and `WP_ADMIN_USER` are **not** read by them (only the repo's
`dev/form-audit.py` honours `WP_ADMIN_USER`). Adjust the constant at the top of a
script if your install differs. See `docs/BROWSER-PASS.md`.

### Day-to-day

```bash
docker compose logs -f vulnhub-wp
./lint.sh                    # php -l across every plugin file
./check-pages.sh             # log in and fetch every screen, report PHP errors
./wp.sh <args>               # wp-cli inside the stack (resolves its own path)
```

| Service | Port | What it is |
|---|---|---|
| `vulnhub-wp` | **8093** | WordPress 7.x + the VulnHub plugins |
| `vulnhub-db` | internal | MariaDB 11 (`vh_` table prefix) |
| `vulnhub-redis` | internal | object cache |
| `vulnhub-cron` | — | runs `wp cron event run --due-now` every 60s (real cron, not page-load cron) |
| `vulnhub-mailhog` | **8094** | catches outbound mail |

The port mappings live in `docker-compose.yml`; change them there if 8093/8094
are taken on your host.

---

## The plugins

Each integration is its own plugin, so any one can be disabled or updated
without touching the rest. They all build against the contract in
`docs/CORE-API.md`. The principal ones:

| Plugin | Does |
|---|---|
| **vulnhub-core** | Data model (14 tables), connector framework, encrypted credential vault, ownership mapping engine, RBAC, REST API, the wp-admin screens |
| **vulnhub-tenable** | Tenable VM export API → assets, vulnerabilities, tags. Owns closure verification |
| **vulnhub-intune** | Microsoft Graph → managed devices, users, departments, offices, groups |
| **vulnhub-cmdb** | ServiceNow / Confluence / CSV → business service, team and site for non-user assets |
| **vulnhub-jira** | Ticket creation with real ADF, status sync, the automation engine, reopen-on-failed-verification |
| **vulnhub-auth** | TOTP MFA + recovery codes, Okta OIDC, Entra ID OIDC, generic OIDC, LDAP/AD |
| **vulnhub-dashboard** | The front-end application served at your own domain — every portal view (including **Inventory sources**, which compares the registers against each other), the dashboard board, and the portal **Administration** area (`/portal-admin/`), which mirrors core's wp-admin screens so nobody needs wp-admin |
| **vulnhub-threat** | CVE ids out of the scanner's own text, enriched from NVD, CISA KEV and FIRST EPSS, and turned into the route an attacker would have to take. Owns the attack-path widget |

The rest extend the platform the same way:

| Plugin | Does |
|---|---|
| **vulnhub-alerts** | Watches advisory and zero-day feeds (EUVD, MSRC, CISA, GitHub, Red Hat, Ubuntu, any RSS/JSON source) and matches them to software and OS actually in the estate. Adds the **Alerts** view |
| **vulnhub-aws** | Reads network exposure straight from AWS accounts — which instances the internet can reach, and on which ports |
| **vulnhub-backup** | Batched, resumable backup and restore as **one `.tar.gz`** (manifest, database, `wp-content`), with optional S3 push and retention (`docs/BACKUP.md`) |
| **vulnhub-departments** | Enriches existing people with their Entra department; adds a department filter, widget, page and export. Never creates people |
| **vulnhub-docs** | The built-in handbook and developer wiki, as the portal's **Docs** view |
| **vulnhub-elementor** | VulnHub data as 14 Elementor widgets, and the portal header/footer handed to the Elementor Pro Theme Builder (`docs/ELEMENTOR.md`) |
| **vulnhub-eos** | The end-of-support remediation programme: which end-of-life machines have a funded project and a date, and which do not. Splits the *Platforms past end of life* widget green/red and adds the **EOL plan** view (`docs/EOS.md`) |
| **vulnhub-hosting** | Classifies servers as cloud (AWS / Azure / GCP) or on-prem. One classification, three places: the *Servers by hosting environment* widget, the `hosting` filter on the assets and findings lists, and the environment icon beside every hostname |
| **vulnhub-import** | Streaming, resumable, de-duplicating CSV import (chunked browser upload, byte-offset checkpoints). Powers **Administration → Imports** |
| **vulnhub-mcp** | A machine-facing surface so an agent can read the estate, correct the CMDB and work the coverage-gap list. Adds **Administration → AI access** |
| **vulnhub-rules** | Ordered, testable rules that classify assets (environment, criticality, type, service, priority weight) before ownership mapping. Adds **Administration → Rules** |

---

## The ownership rule

The rule you asked for is enforced by the mapping engine and visible on every
screen: **a workstation or mobile device must resolve to a person**; everything
else resolves to a team. Current state on the sample fleet:

| Asset type | Total | Has a person | Has a team | Has a location |
|---|---|---|---|---|
| workstation | 64 | 62 | 64 | 62 |
| server | 22 | 22 | 22 | 22 |
| mobile | 18 | 17 | 18 | 17 |
| network | 8 | 8 | 8 | 8 |

The three workstations/mobiles without a person are deliberately planted
userless devices — they surface under **Ownership → Unresolved assets** and on
the dashboard's "Ownership gaps" panel, which is exactly the operational gap
list this rule exists to produce.

Rules are administrator-editable at **Administration → Teams & SLAs** in the
portal (wp-admin: **VulnHub → Ownership → Mapping rules**):
priority-ordered, each with a match condition and an assignment, and each able
to stop the chain. After the rules run, any asset with an owner but no team or
location inherits them from that person's Entra ID department and office.

---

## Closure verification

A ticket closing in Jira is treated as a claim, not proof. When Jira reports
`statusCategory: done`, the ticket is marked awaiting verification. After the
configured delay (**Administration → Settings → Closure verification delay**, default 24h — give
the scanner time to have run again), the Tenable plugin re-checks every covered
finding and records one of:

- **Verified fixed** — Tenable now reports FIXED, or no longer reports it at all on an asset that has since been rescanned.
- **Still detected** — the scanner still sees it. The finding flips back to `reopened`, and the Jira issue gets a comment and a transition back to open.
- **Cannot verify** — the asset has not been rescanned since the ticket closed, so remediation is unproven either way.

---

## Going live

Everything currently runs on a deterministic mock fleet: 112 assets, 56 people,
22 vulnerability definitions, 360 findings, 78 tickets. The mock payloads are
reshaped into the real vendor JSON and pushed through **the same normalisation
code the live path uses**, so switching over is a credential change, not a code
change.

Per connector, at **Administration → Integrations** in the portal (wp-admin:
**VulnHub → Integrations**):

1. Paste credentials (encrypted at rest with XChaCha20-Poly1305 using
   `VULNHUB_ENCRYPTION_KEY` from wp-config — a database dump alone does not
   expose them).
2. **Test connection**.
3. Untick *Use mock data*.
4. Set a sync schedule.

What each connector needs:

- **Tenable** — access key + secret key (Basic [16] role or the export privilege).
- **Intune/Entra** — tenant id, client id, client secret, and admin consent for
  `DeviceManagementManagedDevices.Read.All`, `User.Read.All`, `Group.Read.All`.
  The Intune screen lists these as a copyable checklist.
- **Jira** — site URL, account email, API token, default project key.
- **CMDB** — ServiceNow instance + token, or Confluence page ids, or just upload
  a CSV (the CSV path has a mapping UI and a dry-run preview).
- **Okta / Entra SSO** — the redirect URI to register is shown on
  **Administration → Authentication** (wp-admin: **VulnHub → Authentication → Single sign-on**).

---

## Sync architecture

Large scanner exports are downloaded to disk first, then processed off disk, so
a sync can never lose the whole run to a crash and never has to hold a
multi-hundred-thousand-row export in memory. The full design is in
`docs/SYNC.md`; the shape of it:

- **Two phases, two progress bars.** *Download* pulls the raw export chunk by
  chunk into `wp-content/uploads/vulnhub-sync/<connector>/` and shows bytes on
  disk (with a live rate and ETA); *Process* imports each chunk in bounded
  batches and shows records done against the total. The connector card also
  shows the exact last-sync date/time and how long the run took.
- **Resumable.** Every step writes a checkpoint to `state.json`, so a killed
  container or a reboot resumes from where it stopped rather than starting over.
  A 5-minute cron sweep picks up any run left mid-flight.
- **Self-cleaning.** Each raw chunk is deleted the moment it has been imported,
  a restarting download clears any half-written chunks from an interrupted run,
  and a completed run wipes its staging directory — so disk is freed as it goes,
  not only at the end.
- **Compact on disk.** Chunks are stored gzip-compressed (~13:1 on a Tenable
  export, which is mostly a plugin-metadata block repeated on every finding), so
  a multi-gigabyte download stages as a few hundred megabytes. Readers decompress
  transparently and still read older, uncompressed chunks.
- **Single-flight, heartbeat-guarded.** Only one sync runs at a time — a `flock`
  on the cron worker stops the 60-second loop stacking overlapping runs into an
  out-of-memory kill — and the import reports progress within each chunk, so a
  long-but-healthy run is never falsely reaped as stalled.
- **Incremental and gap-safe.** Most runs fetch what Tenable has *seen* since the
  last successful run (minus a 24-hour overlap): every finding a scan re-observed
  in that window — changed or not — plus findings fixed in it, and only the
  assets scanned in it. Findings that come back unchanged get a light "last seen"
  update instead of a full rewrite, and the summary counts them as *unchanged*.
  The watermark only advances on a successful run.
- **Periodic full resyncs.** An incremental run cannot see asset changes made
  without a rescan, or assets Tenable has deleted. A full resync re-reads the
  whole inventory: on the first sync, every *Full resync every N days* (default
  7), or on demand with **Full resync** on the connector card (or `full=true` on
  the sync endpoint). Full vs incremental is decided by the stored watermark, not
  by what is in the database — after emptying tables, request a full resync.
- **Reversible, scoped pruning.** A full resync retires assets Tenable has
  dropped — but *only* assets Tenable itself owns, never assets contributed by
  Intune, the CMDB or any other connector, and it aborts rather than retire an
  implausibly large slice in one run. Incremental runs never prune. A retired
  asset comes back on its own: the prune records what each asset was before it
  was retired, and the next sync that sees the asset again restores that status
  and its archived findings. Retiring it by hand instead drops that marker, so
  a deliberate decision is never undone.

---

## Analysing vulnerabilities

The **Vulnerabilities** page shows the same filtered findings three ways, as tabs
that carry every active filter between them (`?tab=products`, `?tab=vuln_assets`),
each with a de-duplicated CSV export that shows exactly what is being exported
(with a select-all count and a "select all matching the current filter" action):

- **Findings** — the raw per-asset, per-vulnerability rows.
- **By product** — the assets that a single update would remediate. Expanding a
  product shows every outdated asset; the export says "update to the highest
  available version X, anything below is affected by these N vulnerabilities",
  with the asset and owner list.
- **Vulnerability on assets** — grouped by vulnerability, each expandable to the
  affected assets and their owners. The export carries the vulnerability once and
  the affected assets once, not the solution text repeated on every row.

Separately, the dashboard's *Exposure by product* widget opens a full **Products**
page from its "View all" link.

A **Lifecycle support** (EOL / in-support) filter runs across the tabs. It means the OS or the
software *itself* is discontinued by the vendor (finding-level), not that an
asset happens to carry one unsupported component — see `docs/LIFECYCLE.md`.

---

## Comparing the registers

Four systems each hold part of the truth about the estate, and none of them
holds all of it. **Inventory sources** (`/inventory-sources/`) puts them side by
side: what each register knows, what only it knows, when it last claimed
anything, and — the point of the screen — a matrix of what each one is missing
that another has. Read a row across: *Tenable knows 42 machines the CMDB has no
record of.* Every cell links to exactly those assets, so a number becomes a
worklist rather than a talking point.

Above the matrix the largest gaps are written out as sentences, ranked by gaps
*into* a register that is supposed to be complete — the CMDB as the asset
register, Defender as the agent that should be on every endpoint — rather than
by raw size. Sorting by size alone leads with whichever system simply knows the
most, which is true and is nobody's next action.

The same comparison is available as filters on the assets list (`has` and
`missing`), so "in Tenable, missing from the CMDB" is a link you can keep, sort
and export.

**What it cannot tell you:** VulnHub holds an asset only once some source has
claimed it. A machine that none of these systems has ever seen appears nowhere
here — and nowhere else in the platform either. This compares registers against
each other, not against reality.

---

## Publishing on your own domain

The app is host-agnostic. `wp-config` derives `WP_HOME`/`WP_SITEURL` from the
request host and trusts `X-Forwarded-Proto` and `CF-Connecting-IP`, so the same
install serves `localhost:8093` in development and whatever domain fronts it in
production **without a config change** — every absolute URL is emitted for the
host the request actually arrived on, with no `localhost` leakage or mixed
content.

To put it on a public domain, point any HTTPS reverse proxy at the WordPress
container's port (default `8093`) and forward the standard headers:

- terminate TLS at the proxy;
- forward `Host` unchanged;
- set `X-Forwarded-Proto: https` (and pass `CF-Connecting-IP` if you sit behind
  Cloudflare) so WordPress builds `https://` URLs and logs the real client IP.

Any of nginx, Caddy, Traefik or a Cloudflare Tunnel does this; nothing in the
app is specific to a particular proxy.

Two things to do straight after the domain resolves:

1. **Turn on MFA** — Administration → Authentication → MFA policy → *Required for
   selected roles* (administrator at minimum). The TOTP implementation passes
   all 18 published RFC 6238 test vectors across SHA-1/256/512.
2. Consider putting an access gate (e.g. Cloudflare Access, or your proxy's own
   auth) in front of `/wp-admin` and `/wp-login.php` as a second layer.

See `docs/PERFORMANCE.md` for how the stack is tuned and why, and for how to
tell a slow server from a slow network in one number.

### A caching CDN and the CSS: assets are versioned by mtime.

A CDN in front of the site typically caches `wp-content` for hours, so a
stylesheet edit is invisible to anyone who loaded the portal recently: the HTML
is dynamic and arrives fresh, the CSS does not. That combination is worse than a
plain stale page, because new markup gets styled by old rules -- it is how a
finished popover can reach a browser looking like unstyled fieldsets.

`VulnHub_Dash_App::asset_ver()` appends each file's own mtime to the plugin
version, so the URL changes exactly when the bytes change and the edge treats it
as a new object. Nothing to purge, nothing to remember on deploy. New CSS or JS
in `vulnhub-dashboard/assets/` is covered once it is registered through
`asset_ver()`; a new *plugin* that enqueues its own assets needs the same
treatment, not a bare version constant. Every VulnHub plugin that ships assets
now does this — each with its own small helper rather than a shared dependency,
so a plugin can be disabled without taking the others' versioning with it.

Worth knowing when a change looks like it did not land: check the `?ver=` on the
stylesheet in the browser's network tab before re-reading the CSS.

---

## Design decisions worth knowing

- **Patch availability and end of life** — `docs/LIFECYCLE.md` covers how "can
  this be fixed?" is decided from Tenable's two disagreeing columns, why the
  end-of-life table is a checked-in file with a vendor URL per row rather than
  a feed, and why Windows is matched on build number rather than on what the
  inventory calls it (21 machines here are labelled Windows 11 and are running
  Windows 10).
- **End-of-support remediation** — `docs/EOS.md` covers how the retirement
  programme's workbook becomes the green/red split on the end-of-life widget:
  what counts as covered (remediated, or a project with a date still ahead),
  why an overdue plan is red rather than green, why coverage is computed when
  read rather than stored, and why an end-of-life machine the programme has
  never assessed appears in the list at all.
- **Backup** — `docs/BACKUP.md` covers why a backup is one `.tar.gz` rather
  than three files, why it is written with hand-rolled tar headers instead of
  PharData or `tar(1)`, and the three separate reasons the old backup screen
  made the whole app feel slow — none of which were the backup.
- **Coverage** — `docs/COVERAGE.md` covers what the Intune CSV import was
  losing (last check-in on all 848 devices, compliance, enrolment, join type,
  office), the CMDB's dropped `Last Scan Date` column, why every imported
  slashed date was being read two months wrong, how a coverage gap now splits
  into "live and unscanned" and "no recent contact", and why the biggest
  gap bucket by site — the 303 assets with no site at all — used to be
  unclickable.
- **Filters** — `docs/FILTERS.md` records the six ways a number on this
  platform used to disagree with the list behind it: coverage scope borrowing
  the ownership vocabulary so quarantined machines counted as unscanned work,
  list forms silently dropping the filter you arrived with, a "0 gaps" chip
  opening three rows, a filter with no control, and a closure-verification
  delay of zero that reopened every ticket it checked. `dev/filter-audit.php`
  and `dev/form-audit.py` re-check all of it and exit non-zero on failure.
- **Attack paths** — `docs/ATTACK-PATHS.md` covers how "how would somebody
  reach this" is answered without the scanner ever saying so: CVE ids scraped
  out of the title and description, the CVSS vector's `AV`/`PR`/`UI` read as an
  attacker's route, and why 7,395 network-exploitable findings on laptops are
  counted as *once inside* rather than at the perimeter. Also why the NVD year
  files are parsed with a line reader rather than `json_decode`, and why the
  refresh is a cron job and not a button.
- **Portal shell and layout** — `docs/PORTAL.md` covers how a view is routed,
  the 64px icon rail, the administration area and the extension points. The page
  column is capped at 1440px (`--vh-content-max` in `app-redesign.css`) and
  centres in the space right of the rail, so a wide or zoomed-out window grows
  equal gutters on both sides; below 768px the rail becomes a top bar and the
  column goes full width.
- **Chart palette** — `docs/PALETTE.md` records every colour token in the dark
  (default) and light themes, where charts take their colours from, measured
  contrast ratios, and why severity is treated as a *semantic heat* scale that
  should never carry meaning by hue alone. It is honest about where that rule
  does not yet hold (not every chart has a table view) and lists the known
  contrast failures in the light theme.
- **Credentials** — a blank secret field on submit means "keep the stored
  value"; secrets are never echoed back into a form, only a mask.
- **`tenable_uuid` is deliberately not UNIQUE.** It was, and that silently
  rejected every asset Tenable had never scanned. Schema v11 demoted it to a
  plain index; `Repo::upsert_asset()` already matches with `LIMIT 1`.
- **Plugins load alphabetically**, so `vulnhub-auth` and `vulnhub-dashboard` load
  *before* `vulnhub-core`. Neither may test for `vulnhub()` at file scope —
  both check on `plugins_loaded` instead. Getting this wrong silently disables
  the plugin.
- **Mock mode is not a stub.** It reshapes shared fixtures into genuine vendor
  payloads and runs them through the live normalisation path, which is what
  makes it evidence that the live path works.

