# VulnHub — working notes for Claude

Vulnerability, asset and ownership intelligence, built as ~19 WordPress plugins
on a Docker Compose stack. `README.md` covers installing it. This file covers
**changing** it: the shape of the codebase, the rules that are not obvious from
reading it, and what "done" means here.

Read the doc for the area you are touching before you touch it. They are not
overviews — each one records why the code is the way it is, usually because the
obvious version was tried first and broke something.

## Orientation

| Plugin | Owns |
|---|---|
| `vulnhub-core` | Data model, `Repo`, connector base class, settings + encrypted secrets, scheduler, EOL/OS/vendor/product vocabularies, `VH_Action` |
| `vulnhub-dashboard` | The whole front end: portal shell, views, widgets, filters, CSV export |
| `vulnhub-tenable`, `-intune`, `-cmdb`, `-jira`, `-aws`, `-plerion`, `-departments` | Connectors to outside systems |
| `vulnhub-import` | Streaming, resumable, de-duplicating CSV import |
| `vulnhub-eos`, `-hosting`, `-rules`, `-threat`, `-alerts` | Analysis layered on the model |
| `vulnhub-auth`, `-backup`, `-docs`, `-elementor`, `-mcp` | Platform services |

| Doc | When |
|---|---|
| `docs/CORE-API.md` | **Before writing any integration.** Data model, `Repo`, connector contract |
| `docs/PORTAL.md` | Front end: request path, views, widgets, filter vocabulary |
| `docs/FILTERS.md` | Every number is a promise that clicking it gives exactly those rows |
| `docs/JIRA-OAUTH.md` | Jira OAuth 3LO connect flow, token refresh, the write allowlist, JSM requests and attachments |
| `docs/TICKETS.md` | Vulnerability vs scope tickets, the Raise Jira ticket dialog, per-asset outcomes, JSM readiness |
| `docs/SYNC.md` | Staged sync: download → process → finalize, watermarks, resumability |
| `docs/CMDB-ASSETS.md` | Jira Assets/AQL back end, attribute mapping, per-object-type mapping |
| `docs/COVERAGE.md`, `docs/LIFECYCLE.md` | What "not scanned" and "in service" mean, and to which assets |
| `docs/PLERION.md` | Cloud posture: cloud assets, CSPM findings kept out of the vulnerability model, the exposure map |
| `docs/AWS-NETWORK.md` | AWS SSO device login, what the network capture stores, and how the Cloud Network map is built |
| `docs/AWS-COST.md` | AWS cost snapshot (Cost Explorer, CloudWatch, Price List), the confirmed / needs-confirmation savings rules, and shared decisions |
| `docs/APPSTREAM.md` | AppStream duplicate cleanup: detecting one-shot streaming assets and deleting them through Tenable |
| `docs/EOS.md`, `docs/ATTACK-PATHS.md` | Retirement programme; reachability |
| `docs/BROWSER-PASS.md` | How to actually drive the product in a browser |
| `docs/PALETTE.md`, `docs/PERFORMANCE.md`, `docs/BACKUP.md` | Colour record, measured timings, backup/restore |

## Rules that cost us something to learn

**Never put a literal `%` in a SQL fragment.** `wpdb::prepare()` reads `%` as a
placeholder and, on a mismatch, emits only a *notice* — so the screen looks
right while the CSV export silently returns the wrong rows. Use `LOCATE()`
instead of `LIKE '%x%'`.

**A new filter is not done until it is in the export allow-lists.** A filter the
screen honours and the export drops means the CSV stops matching what the user
is looking at. Grep for the sibling filters in `class-vh-dash-export.php`.

**`action` is reserved.** Forms post to `admin-post.php`, where `action` names
the handler. A field of your own called `action` overwrites it. Name the wire
parameter something else and translate at the boundary.

**Leading backslash for global classes.** Most plugin files are namespaced
(`VulnHub\Core`). `class_exists('VH_Action')` passes while `VH_Action::foo()`
resolves to `VulnHub\Core\VH_Action` and fatals. Write `\VH_Action::foo()`.

**Storage is UTC, always.** Write with `vh_now()` (gmdate). Display through
`vh_date()` / `vh_ago()` / `vh_date_only()` / `wp_date()`, never by formatting a
stored string. Changing the site timezone must never require a data migration.

**Widget caches are epoch-keyed with stale-while-revalidate.** After anything
that writes, call `bust()`. When a number looks wrong, suspect the cache and
PHP's opcache (2s revalidate) before the code — re-read after flushing rather
than trusting one stale read. This has misled us twice.

**A cap by count is not a cap by size.** The Jira description bounded every
section it builds by count — 15 vulnerability definitions, 10 applications, 8
solution texts, 12 evidence bullets -- and each bound reads sensibly on its own.
They multiply. A selection that filled all of them built 36 KB into a field that
holds 32,767, and Jira refuses the whole issue: the ticket is not long, it does
not exist. Where a remote field has a hard limit, spend against a byte budget
and say what was left out, and keep the stop mark a whole block below the limit
— a check before appending is a check the next block still gets to cross.
Measure the worst case you can actually reach, not the one you can imagine:
ours was 30 KB across 29 real selections, and the 500-finding ticket that
looked fine was inside the limit by 1,600 bytes.

**Never hard-code a customer's column or vendor names.** Attribute names belong
to whoever built the source system. Detect them, let an operator override, and
log what was detected and what was not. A run that cannot explain its own
mapping is a run nobody can debug.

**A truncated read is indistinguishable from a shrunken source.** Any paging
loop that stops early and reports success will, once imported, look exactly like
an estate that lost machines. Prefer failing the whole fetch to importing a
partial set — and do not trust a `total` from an API that caps it.

## Data hygiene — this repository is public

No real hostnames, domains, company or supplier names, team names, ticket
prefixes or exported registers. Not in code, not in comments, not in docs, not
in commit messages, not in fixtures.

Placeholders in use: `appsrv01` / `wkstn…` / `cloud-…` for hosts,
`corp.example` for domains, `example.com` for addresses. Demo fixtures
(`sample-cmdb.csv`, `class-vh-mock.php`) are invented and stay invented.

Real data drops belong on the box and are gitignored (`dev/real-*.csv`,
`wp/wp-content/plugins/vulnhub-eos/data/`). If you need real data to reason
about something, read it from the live database — do not copy it into the tree.

Before committing anything that quotes real output, grep the diff for the
estate's own vocabulary. A comment explaining a bug with the hostname that
caused it is the usual way this leaks.

## Verifying a change

1. `./lint.sh` — every plugin PHP file, inside the container.
2. Prove the behaviour against real data. Connectors have `preview()` for a
   dry run; queries can be exercised through `Repo` directly.
3. If it renders, look at it: `docs/BROWSER-PASS.md`. A status code is not
   evidence that a screen works.
4. If it changes a number, click through from the number to the list to the
   CSV and confirm all three agree.

Done means: linted, exercised against real data, filters reach the export, docs
updated in the same commit, and nothing identifiable added to the repository.
