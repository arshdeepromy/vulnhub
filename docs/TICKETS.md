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
     description. When a CSV is attached, the description names the first 30
     assets and points to the file.
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
       gives the ask, the notes, the filters in words, the first 30 assets
       (with owner names, never emails) and how the ticket is tracked. The
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
