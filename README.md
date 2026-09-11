# VulnHub

Vulnerability, asset and ownership intelligence — built as WordPress plugins so
there is no bespoke framework to maintain and security patching rides on
WordPress's own update channel.

Clone this repo, add the plugins/themes it doesn't include (see below), and
bring it up with `docker compose up -d` from the repo root.

---

## Running it

```bash
cd /srv/vulnhub
docker compose ps            # stack status
docker compose logs -f wordpress
./lint.sh                    # php -l across every plugin file
./check-pages.sh             # log in and fetch every screen, report PHP errors
```

| Service | Port | What it is |
|---|---|---|
| `vulnhub-wp` | **8093** | WordPress 7.x + the seven VulnHub plugins |
| `vulnhub-db` | internal | MariaDB 11 (`vh_` table prefix) |
| `vulnhub-redis` | internal | object cache |
| `vulnhub-cron` | — | runs `wp cron event run --due-now` every 60s (real cron, not page-load cron) |
| `vulnhub-mailhog` | **8094** | catches outbound mail |

Admin: `admin` — password in `.admin_pass` (chmod 600, alongside `.db_pass` and
`.vh_enc_key`).

---

## The seven plugins

Each integration is its own plugin, so any one can be disabled or updated
without touching the rest. They all build against the contract in
`docs/CORE-API.md`.

| Plugin | Does |
|---|---|
| **vulnhub-core** | Data model (14 tables), connector framework, encrypted credential vault, ownership mapping engine, RBAC, REST API, admin portal |
| **vulnhub-tenable** | Tenable VM export API → assets, vulnerabilities, tags. Owns closure verification |
| **vulnhub-intune** | Microsoft Graph → managed devices, users, departments, offices, groups |
| **vulnhub-cmdb** | ServiceNow / Confluence / CSV → business service, team and site for non-user assets |
| **vulnhub-jira** | Ticket creation with real ADF, status sync, the automation engine, reopen-on-failed-verification |
| **vulnhub-auth** | TOTP MFA + recovery codes, Okta OIDC, Entra ID OIDC, generic OIDC, LDAP/AD |
| **vulnhub-dashboard** | The front-end application served at your own domain |
| **vulnhub-threat** | CVE ids out of the scanner's own text, enriched from NVD, CISA KEV and FIRST EPSS, and turned into the route an attacker would have to take. Owns the attack-path widget |

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

Rules are administrator-editable at **VulnHub → Ownership → Mapping rules**:
priority-ordered, each with a match condition and an assignment, and each able
to stop the chain. After the rules run, any asset with an owner but no team or
location inherits them from that person's Entra ID department and office.

---

## Closure verification

A ticket closing in Jira is treated as a claim, not proof. When Jira reports
`statusCategory: done`, the ticket is marked awaiting verification. After the
configured delay (**Settings → Closure verification delay**, default 24h — give
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

Per connector, at **VulnHub → Integrations**:

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
  **VulnHub → Authentication → Single sign-on**.

---

## Publishing behind a reverse proxy or tunnel

The app is designed to run correctly behind a reverse proxy or tunnel
(Cloudflare Tunnel, nginx, an ALB, etc.) with no config change: `wp-config`
derives `WP_HOME`/`WP_SITEURL` from the request's `Host` header at runtime,
and trusts `X-Forwarded-Proto` / `CF-Connecting-IP` (falling back to
`X-Forwarded-For`) to detect HTTPS and the real client IP. Verified by
replaying a request with a spoofed `Host` + `X-Forwarded-Proto: https`
header: every emitted absolute URL matched the spoofed host, with zero
`localhost` leakage and no mixed content — the same install serves both
`localhost:8093` and a public hostname unmodified.

To publish it, point your reverse proxy / tunnel's ingress at
`HTTP://localhost:8093` under whatever public hostname you want. For
Cloudflare Tunnel that's Zero Trust → Networks → Tunnels → your tunnel →
**Public Hostnames** → Add, with **Service** set to `HTTP://localhost:8093`.

Two things to do straight after it resolves:

1. **Turn on MFA** — VulnHub → Authentication → MFA policy → *Required for
   selected roles* (administrator at minimum). The TOTP implementation passes
   all 18 published RFC 6238 test vectors across SHA-1/256/512.
2. Consider putting Cloudflare Access in front of `/wp-admin` and `/wp-login.php`
   as a second gate.

See `docs/PERFORMANCE.md` for how the stack is tuned and why, and for how to
tell a slow server from a slow network in one number.

### Cloudflare caches the CSS. Assets are versioned by mtime.

Cloudflare serves `wp-content` with `cache-control: max-age=14400`, so a
stylesheet edit is invisible to anyone who loaded the portal in the last four
hours: the HTML is dynamic and arrives fresh, the CSS does not. That combination
is worse than a plain stale page, because new markup gets styled by old rules --
it is how a finished popover reached a browser looking like unstyled fieldsets.

`VulnHub_Dash_App::asset_ver()` appends each file's own mtime to the plugin
version, so the URL changes exactly when the bytes change and the edge treats it
as a new object. Nothing to purge, nothing to remember on deploy. New CSS or JS
in `vulnhub-dashboard/assets/` is covered automatically; a new *plugin* that
enqueues its own assets needs the same treatment, not a bare version constant.

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
- **Chart palette** — `docs/PALETTE.md` records every colour, the validator
  output that justifies it, and why severity is treated as a *semantic heat*
  scale that never carries meaning by hue alone (labels, fixed order, 2px gaps
  and a table view on every chart).
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

