# Tickets

Two kinds of ticket share `vulnhub_tickets`:

| | Vulnerability ticket | Scope ticket |
|---|---|---|
| Raised from | a finding, or an automation | a filtered list on **Assets & owners** |
| Covers | findings (`ticket_findings`) | assets (`ticket_assets`) |
| `kind` | `vulnerability` | `tenable_coverage`, `defender_coverage`, `cmdb_gap`, `intune_gap`, `cleanup`, `other` |
| `provider` | `jira`, created and polled by `vulnhub-jira` | `jsm`, recorded and updated by hand |
| "Done" means | the scanner no longer sees the finding | per asset, see *Outcomes* |

The kinds come from `Tickets::kinds()` (filter `vulnhub_ticket_kinds`). Each one
names the test that decides whether an asset's ask has been met.

## The report at the top of the Tickets page

`VulnHub_Dash_Ticket_Report` draws two panels above the ticket list.

### Raised vs not raised

This panel covers open findings (`open`, `reopened`) on reporting-scope assets,
with accepted risk excluded. They are grouped by severity, patch availability
(`Repo::fix_route_sql()`: direct patch, update the app that ships it, or none)
and whether the finding is on a ticket (`ticket_id > 0`).

- **Controls:**
  - Severity checkboxes: `cov_c`, `cov_h`, `cov_m`, `cov_l`, plus `cov=1`.
    The default is critical and high.
  - Patch: `cov_patch` = `direct` (Patch available), `app` (Update the app that
    ships it), `no` (No fix) or `both` (All). `yes`, from before the split,
    still means either fix.
  - Operating system: `cov_os` = `any`, `eol` or `supported`. This is whether
    the host's OS is past vendor support (`Eol::eol_os_asset_ids()`). For
    example, End of life plus Patchable is what a patch can still fix on
    retired platforms.

  Both apply on change, and a `<noscript>` button covers browsers without
  scripting.
- **Every number is a link** to the Vulnerabilities list holding exactly those
  rows: `severity`, `state=open_any`, `excepted=exclude`, `patch_available`,
  `ticketed=yes|no`, and `os_eol=yes|no` when an OS is chosen.
- **The `ticketed` filter** is new on that list. It has a *Ticket* select and a
  banner, travels as `has_ticket` in `Repo::findings()`, and is on both export
  allow-lists. The CSV export and "Select all matching" (which drafts a ticket)
  therefore hold the same rows the number counted.
- **The `os_eol` filter** is also new on that list: an *Operating system*
  select (End-of-life OS / Supported OS) with a banner. It travels as
  `os_support` (`eol` | `supported`) in `Repo::findings()` and is on both
  export allow-lists. It asks about the host, unlike `support=eol`, which asks
  whether the finding itself is end of life.
- **Checked:** severity × patch × raised × OS combinations were compared
  between the widget, the list total and the export scope, and they agree. The
  latest check covered 32 combinations after the three-way patch split.
- **Jira descriptions:** when a ticket covers components, the Vendor
  remediation section names the applications to update ("Update Microsoft
  Power BI Desktop (ships libcurl)") before Tenable's component-level
  solution text.
- **Raising from it:** open a *not raised* number, select rows (or all
  matching, up to 500), then **Raise ticket for selected**.
- **Caching:** counts are cached for an hour. The cache key includes the widget
  epoch (moved by syncs and imports), the size of `ticket_findings` (moved by
  every raise) and the EOL OS asset list.
- **Asset counts:** when *Both* is chosen, the asset count is shown as "≤",
  because a machine can have patchable and unpatchable findings.

### Ticket report

Built from `facts()`: one row per ticket that has a key.

- **Severity:** the finding ticket's severity from its payload, otherwise the
  highest severity among its findings. Asset requests are grouped separately.
- **SLA:** the ticket's due date, ending at 23:59 site time on that day.
  - **Met:** closed by then.
  - **Closed late:** closed after it.
  - **Overdue:** still open after it.
  - **On track:** open and not yet due.
- **Time to resolve:** from when the ticket was recorded to its closure in Jira
  (`remote_closed_at`).

The panel shows:
- **Tiles:** failed SLA (overdue plus closed late), median time to resolve, and
  the critical median against the critical SLA.
- **SLA outcome by severity.** Each segment links to the Tickets list with
  `sla` and `tsev`. That filter is applied by id (`Tickets::query( ids )`) and
  explained in a banner.
- **Time to resolve** by severity, in the bands ≤7, 8–30, 31–90 and >90 days,
  with the median and average.
- **Critical tickets:** days taken, with the SLA marked. Open tickets and those
  closed in the last 90 days are included, longest first, top 25.
- **Raised vs resolved per week** for the last 12 weeks.

**CSV:** `admin-post.php?action=vulnhub_ticket_report_csv&set=coverage|tickets`
needs a nonce and `vulnhub_view`, and is audited as `export.ticket_report`.
- `coverage` has one row per severity × patch × raised, with its list link.
- `tickets` has one row per ticket: dates, SLA days, days open or to resolve,
  SLA outcome, days past due, verification, and counts.
- Both files have a BOM, and cells that could be read as formulas are
  neutralised.

## Open, Closed, All: the list is open tickets by default

Open versus closed is the first question the Tickets list answers, so it is a
tab rather than one value inside a filter. Day to day a closed ticket is in the
way, and "where did it go" deserves an obvious answer rather than a dropdown
nobody thinks to change.

- `tstate` = `open` (the default) | `closed` | `all`. It is not one of the
  names the filter form owns, so `hidden_filters()` writes it through Apply on
  its own.
- Each tab carries its own count, from `Tickets::state_counts()`. That counts
  under the filters still in force — search, request type, verification — but
  with `status_category`, `open` and `ids` stripped, since those are the axis
  being counted. It shares `Tickets::where_for()` with `Tickets::query()`, so a
  tab's number and the rows that tab shows cannot be built from two different
  filters. A count that disagrees with its own list is the fastest way to lose
  someone's trust in the screen.
- **The Status filter is the finer grain of the same axis**, so it no longer
  offers "Done" — that is the Closed tab. Picking Done from an old link still
  works and moves the tab to Closed; picking an open-side status while on
  Closed moves it back to Open. Two controls for one axis is how a filter
  starts disagreeing with a tab.
- **A drill-down from the report defaults to All, not Open.** Those links carry
  an explicit set of ids (Met SLA, for instance, is only ever about closed
  tickets), and narrowing them to open tickets would silently answer a
  question nobody asked with an empty table.
- **An empty Open tab says where the rows went**: "No open tickets match. 1
  closed ticket matches — it is on the Closed tab."
- The four tiles above the list are links now, one per `docs/FILTERS.md`:
  Open and Closed go to their tabs, and the two verification tiles go to All
  narrowed to that verification state. Each was checked to return exactly the
  number it shows.

## Raising a vulnerability ticket: review, then send

A person pressing **Ticket** or **Raise ticket for selected** gets **exactly one
Jira ticket**, and only after reviewing everything that will be sent. Grouping
into several tickets (per asset, per vulnerability, per asset and severity) is
only for automation, which calls `VulnHub_Jira_Ticketer::raise()` directly.

1. **Draft.** `POST /vulnhub/v1/tickets/draft` (filter `vulnhub_draft_ticket`)
   builds the issue once, with nothing sent to Jira:
   - **Selection.** Either `finding_ids`, or `all` plus the findings screen's
     `filters` when "All N matching findings" is selected. Filters are resolved
     on the server through `VulnHub_Dash_Export::findings_scope()`, the same
     query Export selected uses, so N means the same N. More than
     `VulnHub_Jira_Ticketer::max_findings()` (5,000; filter
     `vulnhub_ticket_max_findings`) is refused, not trimmed, and a short read
     is refused too. Ask for the limit through that method rather than
     repeating the number on a screen.
   - **Selection rules** (`plan()`): findings already on an open ticket are left
     out and named. A finding whose ticket is closed can be raised again. If
     every finding is already ticketed, nothing is drafted.
   - **The summary** (`summary()`) names what, what kind and where, for
     example `[CRITICAL] Microsoft Office — application vulnerability — Windows
     workstations — 32 vulnerabilities on 4 assets`.
     - **What:** the product someone updates. A bundled component is named by
       the application that ships it, and an OS package by its source package
       (`kernel`). Two products are joined with "and"; more reads "X and N
       other products".
     - **What kind:** the majority kind across the findings: unsupported
       software (a SEoL plugin), OS security update, OS package update,
       bundled library vulnerability, library vulnerability, or application
       vulnerability.
     - **Where:** OS platform plus asset type, for example "Windows
       workstations", "Linux servers", "Windows servers and workstations" or
       "Windows and Linux servers".
     - **Variants:** a single finding reads "title on host (Windows
       workstation)", and automation's per-vulnerability tickets read "title —
       N affected assets — platform".
   - **The issue.** `build_issue()` produces the exact `fields`: project, issue
     type, summary, priority, due date, labels, assignee, team and the ADF
     description. When a CSV is attached, the description lists no assets:
     it says how many are affected and points to the file, and each
     vulnerability shows "Detected on N assets" instead of host names. Without
     an attachment, every affected asset is listed.
   - **The attachment.** `VulnHub_Dash_Export::findings_csv()` builds the
     findings CSV in memory, with the same cells, escaping and BOM as the
     download. Columns start from `ticket_columns()` and can be changed in the
     review, which builds a fresh draft. A draft whose row count differs from
     its finding count carries a warning.
   - **The description has a byte budget**, because its section caps (15
     vulnerability definitions, 10 applications, 8 solution texts, 12 evidence
     bullets) are counts, and counts multiply: a selection that fills all of
     them built 36 KB, which Jira refuses outright. Each section that grows
     with the selection stops at `DESCRIPTION_BYTES` and says what it left
     out; the attachment carries every finding regardless. The mark sits a
     whole block below Jira's 32,767 because it is checked *before* a block is
     appended. Measured worst case across 29 real selections: 30 KB.
   - **Warnings** are shown for a project outside the allowlist, for a
     description near Jira's size limit, and for an attachment over what Jira
     accepts (`vulnhub_ticket_attachment_limit`, 10 MB) — that one matters
     because the file is uploaded *after* the issue is created, so the ticket
     would be raised with nothing attached.
   - **Storage.** The draft is stored for 30 minutes under a token
     (`vh_jira_draft_<hmac>`), tied to the user who built it.
2. **Review.** The dialog shows, from the draft itself:
   - the scope: tickets, findings and assets, plus what is left out
   - every field
   - the description rendered from the ADF that will be sent
     (`VulnHub_Jira_Adf::to_html()`)
   - **Edit description.** The description is also offered as editable text
     (`VulnHub_Jira_Adf::to_editable()`):
     - **Markup:** a blank line between paragraphs, `## Heading`, `- bullet`,
       `**bold**`, `` `code` ``, `[text](https://link)`, `---` for a rule, and
       ``` fences.
     - **Apply** rebuilds the draft with `description`.
       `VulnHub_Jira_Ticketer::apply_description_edit()` reads the text back
       into ADF (`from_editable()`, which is lossless for the generated
       description) and stores it in the draft. The preview, the stored draft
       and what Send transmits are the same document.
     - **The edit is kept** while the draft is rebuilt for other changes (due
       date, priority, columns), so changing the due date afterwards does not
       rewrite your text.
     - **Use the generated description** drops the edit, and so does an empty
       box.
     - **Length:** edits are capped at 30,000 characters, with a warning when
       text is cut.
     - **Both ticket types:** this applies to finding tickets and asset
       tickets.
   - the file: name, rows, columns and size, the first 8 rows, and a download
     of the exact file (`admin-post.php?action=vulnhub_ticket_draft_csv`)
   - what else is sent: the remote link back to VulnHub
   - the raw `fields` JSON

   Cancel sends nothing.
3. **Send.** `POST /vulnhub/v1/tickets` with `draft` (a raise without a draft
   token is refused). `send_draft()`:
   - Holds the site-wide manual-raise lock.
   - **Deletes the draft before sending,** so a second press finds nothing.
   - Re-plans the findings and **refuses if the selection changed** since the
     review.
   - Sends the stored fields with `exact` set, so a rejected field is reported
     rather than silently dropped and resent.
   - Then attaches the stored CSV (`POST /issue/{key}/attachments`) and adds the
     remote link.

   Each add is attempted once (see `docs/JIRA-OAUTH.md`). If the issue is
   created but the upload fails, the result says so and asks for the file to be
   attached by hand.

## Raising a scope ticket

**Raise Jira ticket** sits between the filters and the table on Assets & owners
(`VulnHub_Dash_Tickets::raise_button()`). It opens a `<dialog>` with two steps:

1. **The list that gets attached.** This uses the same column picker as Export
   CSV (`VulnHub_Dash_Export::column_picker()`), and those ticks are the
   columns of the CSV that ends up on the ticket — not just of the optional
   download. The step said "Download the list" and read as "export it and
   attach it by hand", which is the one thing it does not mean, so it now says
   what the ticks are for. *Download CSV* posts to
   `admin-post.php?action=vulnhub_ticket_scope` with `do=download`. That
   redirects to the ordinary export URL, so the file matches Export CSV exactly
   and is audited the same way. `wp_nonce_url()` escapes `&` as `&amp;`, which
   has to be undone before the redirect or the export gets no `view`.
2. **Describe the request:** request type, summary and notes. Then either:
   - **Review and create in Jira** (shown when the Jira connector is enabled).
     This posts `scope=assets` with the list's resolved filters (`f[]`), its raw
     query (`q[]`), the request type, summary, notes and the ticked columns to
     `POST /vulnhub/v1/tickets/draft`. `VulnHub_Dash_Tickets::draft_assets()`
     answers it (at priority 5, ahead of the finding drafter):
     - collects the whole asset list (`collect_assets()`)
     - builds the asset CSV (`VulnHub_Dash_Export::assets_csv()`)
     - has the ticketer build the issue (`build_scope_issue()`), with the same
       routing, issue type and allowlist as finding tickets. The description
       gives the ask, the notes, the filters in words and how the ticket is
       tracked. The assets are in the attached file, not the description; only
       without an attachment does it list the first 30 (with owner names,
       never emails). The
       label is the request type, for example `tenable-coverage`.

     The same review screen and Send as finding tickets are used (see above).
     On Send, `submit_scope_issue()` creates the issue exactly, records it as
     `provider = jira` with the kind, scope and notes, attaches the asset
     snapshot, attaches the CSV, and sends the browser to the ticket page.
   - **I already raised it in JSM** (collapsed when Jira is enabled). The
     operator enters the key of a request raised by hand. It must match
     `ABC-123` and must not already be recorded. `do=save` needs
     `vulnhub_raise_ticket`. Nothing is sent to Jira, and the ticket is recorded
     with `provider = jsm`.

Saving takes a snapshot of every asset the filters match. It pages through
`Repo::assets()` 500 rows at a time and **refuses** to save if the rows read do
not add up to the total, or if the total is over 10,000. A partial snapshot
would report the missing machines as never asked about.

Each `ticket_assets` row keeps the hostname, type, Tenable and Defender
coverage state, lifecycle status and sources *as they were when the ticket was
raised*. The ticket's `scope_json` keeps:

- `args`: the resolved export arguments
- `query`: the raw Assets-screen query, used by "Open this filter as it is today"
- `cols`: the columns picked
- `filters`: the filters in words

A merge moves `ticket_assets` rows to the surviving asset
(`Repo::merge_assets()`).

The link is the pasted URL if the operator pasted one. Otherwise it is the Jira
connector's site plus `/browse/KEY`. With neither, there is no link.

## Due dates

A ticket's Jira due date is counted **from the day it is raised**. It used to be
the earliest SLA due date of its findings, which is counted from first
detection, so any old finding put the ticket's due date in the past before
anyone had been asked.

- **Finding tickets:** today plus the **Organisation SLA** days for the
  ticket's highest severity (`vh_sla_days()`; defaults 7 / 30 / 90 / 180).
- **Asset tickets:** today plus **Asset request due in** days
  (`vh_asset_request_due_days()`, default 30).
- Both are set under Settings → Ownership (platform options `sla_*_days` and
  `asset_request_due_days`) and computed in the site's timezone
  (`vh_due_in_days()`).
- **The review shows the date as an editable field.** Changing it builds a fresh
  draft with `due_date`, so the description's SLA sentence always states the
  date that is sent. A date before today, or one that is not a real date, is
  refused (`vh_valid_due_date()`).

## Priority

Priority names belong to the Jira site and project: one site uses
Highest…Lowest, a service desk may allow only P1…P4. Sending a name the project
does not have makes Jira refuse the whole ticket ("Specify the Priority (name)
in the string format").

- **Send a priority by default** (Jira setting `send_priority`, default on):
  - **On:** the severity mapping (`priority_critical`…) is sent.
  - **Off:** no priority is sent and Jira applies the project default. Asset
    tickets have no severity, so they never get a mapped priority.
- **The review shows Priority as a dropdown** of the values the project allows
  for the ticket's issue type, read from create metadata
  (`VulnHub_Jira_Ticketer::allowed_priorities()`, cached for an hour), plus
  *Not set (Jira default: …)*. Changing it rebuilds the draft with `priority`
  (`none` for not set).
- **A priority the project does not allow is flagged** in the review before
  anything is sent.

## Urgency and Impact

Service desk projects often carry select fields named **Urgency** and
**Impact** on their create screen. The review offers them as dropdowns of the
options Jira lists for the project and issue type, starting at *Not set*.
Nothing is sent unless one is chosen.

- **Found by name,** from create metadata (`VulnHub_Jira_Ticketer::REVIEW_SELECTS`,
  `create_meta_summary()`, cached for an hour), never by custom field id,
  because ids differ on every site. A project without them shows no dropdown.
- **A choice travels as `selects[<slug>] = <option id>`** and is set on the
  issue as `{"id": …}` (`apply_review_selects()`). An id Jira did not list is
  ignored.
- **Applies to finding tickets and asset tickets.**

## Nothing sent to Jira names the product

Tickets arrive in Jira without any mark of where they came from. This covers
text, labels, file names and request metadata:

- **Descriptions and comments** are written in neutral terms, for example
  *These findings are re-checked against the vulnerability scanner after this
  ticket is closed*. That includes the reopen and verification comments, the
  automation note and comment, and the text added when findings are folded
  into an open ticket.
- **Labels** are neutral:
  - finding tickets: severity, asset type, `exploit-available`
  - asset tickets: the request type
- **Attachments** are named `findings-<date>.csv` or `assets-<kind>-<date>.csv`.
- **The optional web link** (off unless *Link tickets back* is set) is titled
  *Remediation record*.
- **Requests to Atlassian** carry the generic User-Agent
  `VulnHub_Jira_Client::USER_AGENT` rather than core's default, which names the
  product and its maintainer. The multipart boundary is neutral too.

The name of the OAuth app registered in the Atlassian developer console is set
there, not here, and shows under the connecting person's Connected apps.

Internal notification emails are not sent to Jira and are unaffected.

## Outcomes

`Tickets::outcome_sql( $kind )` classifies each asset against the **live** asset
row. The checks run in this order:

1. **Gone from inventory:** the asset row no longer exists.
2. **No longer matters:** the asset is out of service (a lifecycle status not in
   `vh_in_service_statuses()`, e.g. retired, spare, stock, missing). On Tenable
   and Defender tickets this also covers "out of scope" and "not a scanning
   target".
3. **Done:** the kind's test passes:
   - `tenable_coverage`: the coverage state is in `Coverage::in_tenable_states()`,
     the same definition the coverage figure uses.
   - `defender_coverage`: the Defender state is in `Defender_Coverage::covered_states()`.
   - `cmdb_gap` / `intune_gap`: the source is in `sources_json` (checked with
     `LOCATE`, never `LIKE '%…%'`).
4. **Still outstanding:** none of the above.

`cleanup` turns this around: gone or out of service *is* the ask, so both count
as Done. `other` has no test, so its assets are never marked Done automatically.

The ticket page (`/tickets/?ticket=ID`) shows tiles for each outcome, each
linking to `&outcome=`, and a table of every asset with its state then and now.
Outcomes are always calculated at read time, never stored, so they follow the
latest sync without a job to keep them current.

## Remediation progress: the bar under every ticket

A verification verdict is a snapshot — it says what the scanner held at the
moment somebody asked. The finding rows are refreshed by every sync. The two
drift apart the moment a sync lands after a check, and they did: SD-1234 read
*"Tenable shows 3 of 10 findings fixed, 7 not rescanned"* directly above a table
showing all ten `fixed`. Both were true, of different days — the check ran the
evening the ticket was raised, before the hosts had been rescanned; the sync two
nights later brought back ten fixes.

So the list and the ticket page now carry both, each with its own date.

- **The bar** (`VulnHub_Dash_Tickets::progress_html()`, fed by
  `Tickets::progress()`) counts **assets, not findings**: a ticket is handed to
  somebody as a list of machines to touch, so "6 of 10 assets fixed" is the
  sentence they are working to. A host counts only when *every* finding the
  ticket raised against it is fixed — one outstanding patch and the machine is
  not done. The findings ratio sits underneath as the smaller number.
  - Scope tickets have no findings, so theirs reads from
    `Tickets::asset_outcomes()` instead: assets **Done** over assets on the
    ticket, with anything retired or removed noted beside it.
  - `Tickets::progress()` takes a *list* of ticket ids and answers in one
    grouped query. The list renders fifty rows; this is not a per-row lookup.
  - Nothing is stored. The bar follows the latest sync the same way outcomes
    do, and its tooltip says how old that scan data is.
- **The last-check line leads with whichever answer is newer.**
  `VulnHub_Dash_Tickets::superseded()` asks one question: has a sync landed
  since this check ran, and did it change the count? If not, the verdict stands
  alone exactly as before. If it has, the cell flips:

  > **Tenable shows all 10 findings fixed — scan data 14 hours ago**
  > *the check 3 days ago said 3 of 10 fixed, 0 still detected, 7 not rescanned*

  The first attempt kept the verdict on top and appended the newer numbers
  underneath. That was worse: the loudest sentence in the cell still said "3 of
  10 fixed" beside a table showing ten, so the new line read as the
  contradiction rather than the correction. Today's answer has to lead.
  The verdict is not rewritten in today's numbers — nobody verified anything
  today — it keeps its own words under its own date, with a rule down the side
  marking it as the record it is.

  The remainder of the current sentence is deliberately *not* split into "still
  detected" and "not rescanned". That distinction comes from comparing each
  asset's scan time against the ticket, which is the verification run's job;
  a stored finding state cannot honestly make it.

## Checking tickets: Verify

The Tickets list has **Verify all tickets** and a **Verify** button on each
row, and the ticket page has one too. They are shown to people who can raise
tickets, when a scanner integration answers the check
(`VulnHub_Dash_Tickets::can_check()`).

- **Asking first.** **Verify all tickets** opens a dialog in the page
   (`check_dialog()`), not `window.confirm()`. The browser's own box could not
   say what this site will actually do — it promised "this launches one Tenable
   rescan" whatever the settings said — and had nowhere to put the per-ticket
   result that follows. The question comes from
   `verify_all_question()`, which reads the same `rescan_allowed()` the job
   enforces.
- **Start:** `POST /vulnhub/v1/tickets/check` with `ids[]` or `all`, plus
  `rescan` (filter `vulnhub_start_ticket_check`). `all` takes every ticket
  that has a key and is not yet verified fixed, at most 200. Asking for a
  rescan does not get one: the server decides.
- **Progress:** the same dialog becomes the progress view, and the browser
  polls `GET /vulnhub/v1/tickets/check/{job}` (filter
  `vulnhub_ticket_check_status`). The job id is kept for the tab, so leaving
  the page and coming back picks it up again — closing the dialog does not
  stop the run, and it says so.
  - The bar counts **both stages** a ticket goes through, read-from-Jira and
    re-checked, not just the second. One step runs per cron tick, so counting
    only the re-check leaves it at 0% for minutes of real work and reads as a
    hang. The ticket page keeps the inline panel, and the dialog falls back to
    it when it is not on the page.

`VulnHub_Tenable_Ticket_Check` runs the job one step per cron event and stores
it in the option `vh_ticket_check_<job>` (removed a day after it finishes). A
lock option stops two workers from running the same step, so the scan is
never launched twice. The steps are:

1. **Refresh.** Each ticket's status, assignee and newest comment are read
   through `vulnhub_refresh_ticket`. This only reads from Jira. A ticket
   recorded by hand keeps its recorded status.
   - **Who it is with.** `assignee` is often null on a service desk that
     routes by team: the work is carried by the Team field, not a person. So
     the Team field is requested too — by its id, resolved from the routing
     directory, never `*navigable`, which would fatten every page of a
     2,000-ticket sync — and kept as `payload_json.team_name`.
     `VulnHub_Jira_Connector::assigned_to()` answers with the assignee, or the
     team labelled as one. A column that reads `assignee` alone reports every
     ticket as unassigned while people are working them.
   - **The newest comment** is kept as `payload_json.last_comment` (author,
     body, created, and whether it is public), preserved across syncs the same
     way `last_check` is. The list draws it from there rather than reading
     live, so twenty rows are not twenty calls to Jira; it carries its own
     `seen_at` for that reason. Jira's timestamps arrive with the site's
     offset and are stored through `vh_to_mysql()` — left alone, a comment
     from this morning reads "in 12 hours".
2. **Rescan (Verify only, workstations only).**

   - **Off unless switched on.** **Scanning from Verify** (`rescan_enabled` on
     the Tenable connector) is off by default, and off means nothing is
     launched however Verify is pressed: `start()` turns a requested rescan
     into `rescan = false` before the job is even stored, so a job that was
     never allowed to scan cannot be resumed into scanning, and the last step
     before the launch asks again in case the setting changed while the job
     queued. A refusal is audited as `ticket.rescan_refused` and the panel
     says "No scan launched". An agent-based estate should leave this off:
     there is no network scan to aim, and the agent's own last result is the
     freshest thing there is. **Rescan with** is ignored while it is off.
   - Screens ask `vulnhub_ticket_rescan_allowed` rather than reading the
     setting, so the Verify copy describes what will happen rather than the
     default.

   The rest of the guard rail is decided by **each asset's own `asset_type`**,
   the server/workstation classification synced from Tenable, never by address.
   - **Allowed:** an asset qualifies only if all of these hold:
     - its type is in `VulnHub_Tenable_Schedules::RESCAN_ASSET_TYPES`
       (`workstation`). This is a constant, not a setting.
     - it is not agent-based (`has_agent = 0`)
     - it is known to Tenable and has an FQDN or IPv4
   - **Checked twice** by `VulnHub_Tenable_Ticket_Check::guard_assets()`: once
     when the job gathers asset ids, and again, re-reading those assets by id,
     immediately before the launch. A refused asset is audited as
     `ticket.rescan_refused`.
   - **Servers are never rescanned from VulnHub,** whatever the ticket covers.
     They are checked after their own scheduled scans (see below).
   - **Agent-based machines are not rescanned either,** because an agent scan
     cannot be narrowed to single machines.
   - **The launch.** The Tenable connector's **Rescan with** scan is launched
     once, with the allowed assets' addresses as `alt_targets`. That is the only
     place an address is used, because Tenable needs one to aim the scan. The
     job then polls `/scans/{id}/latest-status` every two minutes and moves on
     when the scan finishes, or after four hours.
   - **Skipped** with no scan chosen, no qualifying workstation, or when Tenable
     refuses the launch. The panel says which.
3. **Verify.**
   - **Finding tickets** go through `VulnHub_Tenable_Verifier::check_ticket()`.
     Scan freshness is read live from `GET /assets/{uuid}`, so a scan that
     finished a minute ago counts before the next sync. Only a *resolved*
     ticket's findings are stamped verified or still detected. An open ticket
     gets a progress line and nothing changes.
   - **Asset tickets** are summarised from their live outcomes.

   `judge_finding()` decides each finding in this order, and the order is the
   whole point:

   1. No Tenable identity on the asset → **unknown**, nothing can be rescanned.
   2. Tenable's state is **FIXED** → **fixed**. An explicit FIXED is the
      scanner's own positive statement, carrying its own date, so it counts
      whenever it was recorded.
   3. No scan since the ticket closed → **unknown**.
   4. No record of the finding at all, and the asset *has* been rescanned →
      **fixed**: the plugin no longer fires.
   5. Anything else → **open**, and on a resolved ticket the finding is
      reopened.

   Step 2 used to sit *below* step 3, which made it unreachable for any ticket
   closed after its fix had already been confirmed. SD-1234 closed with ten
   findings Tenable had marked FIXED, with dates, and every one came back
   "remediation is unproven" — purely because no scan had happened in the
   hours between the last sync and somebody pressing Close. Requiring a further
   rescan before believing FIXED adds nothing: had the vulnerability returned,
   a scan would have had to run to find it, and the state would read REOPENED.

   The freshness gate still guards the two readings that genuinely depend on a
   scan having run — an *absent* finding (absence only means something if
   somebody looked) and a still-open one (stale data must never be read as
   "still detected").

The result is stored on the ticket as `payload_json.last_check`
(`Tickets::set_last_check()`). `Tickets::upsert()` keeps it when a sync
replaces the rest of the payload. The list shows it in **Last check**, with
the due date.

## Automatic checks: after scheduled scans, and on the due date

Automatic checks never launch a scan. Once an hour (`vulnhub_ticket_check_due`),
`VulnHub_Tenable_Ticket_Check::run_due()`:

1. Refreshes Tenable's scan list and recent run history into the option
   `vh_tenable_schedules` (`VulnHub_Tenable_Schedules::refresh()`). Only
   enabled scans with a repeating rule are kept.
2. Plans every ticket that is not yet verified fixed (`plan_ticket()`),
   counting from its last check, or from when it was raised:
   - **After scans:** for each asset type the ticket covers, it takes the
     schedule chosen on the Tenable connector (**Servers are scanned by** and
     **Workstations are scanned by**). The ticket is checked at **10:00 site
     time on the morning after** that schedule's next run. For example, a
     Tuesday 09:00 run is checked on Wednesday at 10:00.
   - **On the due date:** at 10:00 on that date.
3. Starts one job, with no rescan, for every ticket whose moment has come.
4. Stores the next planned check as `payload_json.next_check` (`at` in UTC,
   plus the reason), which the list shows. Sync preserves it the same way it
   preserves `last_check`. A ticket is planned again after every check, so it
   keeps being checked after each scheduled run until it is verified fixed.

**Run times** come from the schedule's recurrence rule (`rrules`, `starttime`,
`timezone`; daily, weekly with `BYDAY` and `INTERVAL`, and monthly with
`BYMONTHDAY` or an ordinal `BYDAY`).
- **Run length** is the median of completed history runs. With no real runs to
  measure, it is taken as three hours. Agent-scan histories list rolling
  windows under placeholder ids (`00000000-…`), and those are not measured.
- **A real run still in progress** holds the check until it finishes.

**Why the schedules are chosen rather than detected.** Two sources were tried
and neither is reliable:
- A machine's `last_schedule_id` names whatever scan touched it last,
  inventory scans included, so workstations split across several schedules.
- Agent-scan histories carry placeholder run ids that findings never carry.

A check does not write to Jira itself. Whether a verification comments on or
reopens an issue is still the Jira connector's own setting.

## Changing a ticket's status without leaving VulnHub

**Change status** sits beside Status on the ticket page, for Jira-backed
tickets, behind `Caps::RAISE_TICKET` — the same bar as commenting, because
both write to somebody else's ticket.

- **The offered set is always read live.** Transition ids are workflow
  specific, and which ones exist depends on the issue's current status *and*
  on what the connecting account may do. `GET /vulnhub/v1/tickets/{id}/transitions`
  (filter `vulnhub_ticket_transitions`) asks Jira on open, so nothing is
  guessed from a status name — and the round trip stays off the page load.
- **Required fields are built from Jira's own answer.** The read expands
  `transitions.fields`, keeps only what that screen makes `required`, and drops
  the ones Jira fills itself (`summary`, `issuetype`, `project`, `reporter`).
  A field with `allowedValues` becomes a select of exactly those values — this
  is how a Close screen that demands a resolution gets the real resolution
  list rather than a guess.
- **What cannot be rendered honestly is refused, not hidden.** A cascading
  select, or an array-valued field like components, lands in `unsupported`:
  the transition is still offered, then declined with the reason and a pointer
  to Jira. Hiding it would read as "Jira will not allow this move", which is a
  different and untrue message.
- **The browser is not trusted.** `apply_transition()` re-reads the offered set
  before writing: it is the only way to know the transition is still valid and
  how to shape each value, and a workflow can move under a form that has been
  open a while. An unknown id, a missing required field and a value outside
  `allowedValues` are all refused before any write.
- **Closing a ticket the scanner disagrees with is allowed, and recorded.**
  Refusing outright would be the wrong call — a finding can be a false
  positive, or the work can be tracked elsewhere — but it is never silent. The
  dialog says how many findings are still unfixed and how old that scan data
  is, before the move; the `ticket.transition` audit entry keeps
  `findings_open` and `closed_with_open`.
- **The result is read straight back.** A successful move calls
  `refresh_ticket()`, so the status, its category, the resolution and — when
  the move closed the ticket — `mark_closed()` and the start of the
  verification clock all come from Jira rather than from what was asked for.
  The cached conversation is dropped at the same time.
- Writes are bounded by the project allowlist already:
  `refuse_outside_allowlist()` resolves the project from the issue key on every
  non-GET, transitions included. OAuth needs `write:jira-work`, which is in
  `DEFAULT_SCOPES`.
- A ticket recorded by hand (`provider = jsm`) has no Jira workflow, and keeps
  its own status form on the same page.

## Comments: reading and replying without leaving VulnHub

**View** on the Tickets list opens a dialog with the whole conversation, and
the same component is rendered inline on the ticket page — from one function
(`VulnHub_Dash_Tickets::comments_body()`), so the two cannot drift apart.

- **Reading:** `GET /vulnhub/v1/tickets/{id}/comments` (filter
  `vulnhub_ticket_comments`, `can_view`). Comments come back newest first and
  are drawn oldest first, because a conversation reads downwards towards the
  reply box. A comment body is set as text, never as HTML: it is somebody
  else's input arriving from another system. Reading also refreshes
  `last_comment`, since it is the freshest look anyone has had at the ticket.
- **Opening a ticket does not wait for Jira.** The round trip is the better
  part of a second and it was the only slow thing on the ticket page. Two
  changes, together:
  - The newest comment is already on the ticket row from the last refresh, so
    the panel is rendered *with it*, dated, by `comments_body()` — the markup
    mirrors `commentNode()` in `app.js` exactly, so the fetch replacing it is
    not a jump. No more empty "Loading…".
  - `VulnHub_Jira_Connector::comments()` caches a good read for five minutes
    (`COMMENTS_TTL`). Walking a list of tickets then costs one Jira call per
    ticket rather than one per click. Only a *successful* read is cached — a
    failure should be retried, not held. Posting a comment and refreshing a
    ticket both call `forget_comments()`, so the only staleness possible is
    somebody else's comment, for at most five minutes.
- **Replying:** `POST` the same route (filter `vulnhub_post_ticket_comment`,
  `can_raise`), with `body` and `public`.
  - **An internal note is the default, everywhere.** A reply notifies whoever
    raised the request and cannot be taken back, so the quiet option is the
    one a misclick lands on: the radio is checked, an absent `public`
    parameter means internal, and the box changes colour before Post is
    pressed when it is set to reply.
  - **Visibility needs the service desk API.** Only
    `POST /servicedeskapi/request/{key}/comment` can say whether the customer
    sees it; a comment added through the issue API is public. So every comment
    goes that way, and a 404 — an ordinary project, not a desk — falls back to
    the issue API *only for a public reply*. An internal note is refused there
    and says why, rather than being quietly posted where the customer reads
    it.
  - Writes are already bounded by the project allowlist, which
    `VulnHub_Jira_Client::refuse_outside_allowlist()` applies to every
    non-GET. Posting is audited as `ticket.comment` with its visibility.
  - A ticket recorded by hand (`provider = jsm`) has no issue to read or
    comment on, and says so rather than looking like a ticket nobody has
    commented on.

## Status

Nothing polls `jsm` rows: `VulnHub_Jira_Connector::tickets_to_poll()` selects
`provider = 'jira'`. Status is moved by hand on the ticket page
(`vulnhub_ticket_status`, `Tickets::set_manual_status()`), which refuses any
non-`jsm` row. The poller would overwrite a manual change on a `jira` row.
Manual statuses use the poller's own categories (`new` / `indeterminate` /
`done`), so tile counts and filters treat both providers alike.

## JSM integration, later

The table is ready for it. A JSM integration needs to:

- **Sync:** refresh `provider = 'jsm'` rows by key. JSM requests are Jira issues,
  so the Jira client's `search_jql()` and `normalise_issue()` already handle
  them. Pass the result to `Tickets::upsert()` with `provider => 'jsm'`.
- **React on save:** `do_action( 'vulnhub_scope_ticket_recorded', $ticket_id )`
  fires straight after a ticket is recorded.
- **Create:** fill in the key instead of having the operator type it. The dialog
  already has the request type, summary, notes and the CSV to attach.
