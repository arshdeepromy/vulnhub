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
(`Repo::patch_sql()`) and whether the finding is on a ticket (`ticket_id > 0`).

- **Controls:**
  - Severity checkboxes: `cov_c`, `cov_h`, `cov_m`, `cov_l`, plus `cov=1`.
    The default is critical and high.
  - Patch: `cov_patch` = `yes`, `no` or `both`.

  Both apply on change, and a `<noscript>` button covers browsers without
  scripting.
- **Every number is a link** to the Vulnerabilities list holding exactly those
  rows: `severity`, `state=open_any`, `excepted=exclude`, `patch_available`,
  and `ticketed=yes|no`.
- **The `ticketed` filter** is new on that list. It has a *Ticket* select and a
  banner, travels as `has_ticket` in `Repo::findings()`, and is on both export
  allow-lists. The CSV export and "Select all matching" (which drafts a ticket)
  therefore hold the same rows the number counted.
- **Checked:** all 24 severity × patch × raised combinations were compared
  between the widget, the list total and the export scope. They agree.
- **Raising from it:** open a *not raised* number, select rows (or all
  matching, up to 500), then **Raise ticket for selected**.
- **Caching:** counts are cached for an hour. The cache key includes the widget
  epoch (moved by syncs and imports) and the size of `ticket_findings` (moved by
  every raise).
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
     query Export selected uses, so N means the same N. More than 500 is
     refused, not trimmed, and a short read is refused too.
   - **Selection rules** (`plan()`): findings already on an open ticket are left
     out and named. A finding whose ticket is closed can be raised again. If
     every finding is already ticketed, nothing is drafted.
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
   - **Warnings** are shown for a project outside the allowlist and for a
     description near Jira's size limit.
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

1. **Download the list.** This uses the same column picker as Export CSV
   (`VulnHub_Dash_Export::column_picker()`). *Download CSV* posts to
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

## Checking tickets: Verify

The Tickets list has **Verify all tickets** and a **Verify** button on each
row, and the ticket page has one too. They are shown to people who can raise
tickets, when a scanner integration answers the check
(`VulnHub_Dash_Tickets::can_check()`).

- **Start:** `POST /vulnhub/v1/tickets/check` with `ids[]` or `all`, plus
  `rescan` (filter `vulnhub_start_ticket_check`). `all` takes every ticket
  that has a key and is not yet verified fixed, at most 200.
- **Progress:** the browser polls `GET /vulnhub/v1/tickets/check/{job}` (filter
  `vulnhub_ticket_check_status`). The job id is kept for the tab, so leaving
  the page and coming back picks it up again.

`VulnHub_Tenable_Ticket_Check` runs the job one step per cron event and stores
it in the option `vh_ticket_check_<job>` (removed a day after it finishes). A
lock option stops two workers from running the same step, so the scan is
never launched twice. The steps are:

1. **Refresh.** Each ticket's status is read through `vulnhub_refresh_ticket`.
   This only reads from Jira. A ticket recorded by hand keeps its recorded
   status.
2. **Rescan (Verify only, workstations only).** The rescan guard rail is
   decided by **each asset's own `asset_type`**, the server/workstation
   classification synced from Tenable, never by address.
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
