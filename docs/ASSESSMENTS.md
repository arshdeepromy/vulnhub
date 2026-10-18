# Supplier assessments register

Plugin: `vulnhub-assessments`. Portal page: **Assessments** (`/supplier-assessments/`),
placed after Exceptions in the navigation.

A register of supplier assessment decisions, entered by people:

- **Supplier assessments** — third-party information security assessments (TPISA).
  Rows are either *inherited* (a register handed over by a previous team) or
  *assessed by us*.
- **Not yet recorded** — assessment requests the Jira inbox holds
  (`vh_vulnhub_jira_inbox`, set `assessments`) that are neither linked from a
  row here nor recorded in the Exception register, and that nobody has set aside.

**Security exceptions do not live here.** The same request type also carries
exception requests (an allow-list change, offshore working, a legacy cipher).
Those go to the portal's **Exception register** as `policy`-scope exceptions
(see CORE-API.md, `exceptions` table), saved through core's
`Exceptions::record()` so they can never suppress a finding. This plugin serves
the form (`?exc=new[&jira=KEY]` to record, `?exc=<id>` to edit), pre-filled from
the inbox and the newest decision-like comment; the register shows a
*Record a security exception* button (`vulnhub_exceptions_page_actions`) and
an *Edit this record* link on each security exception
(`vulnhub_exception_edit_url`). The Assessments page links to the register
filtered to security exceptions (`/exceptions/?etype=policy`).

## Data

Table `{prefix}vulnhub_assessments` (db version option `vulnhub_assess_db`):

| Column | Meaning |
|---|---|
| `kind` | `supplier` (an older `exception` kind is no longer used) |
| `subject` | supplier or exception name |
| `source`, `origin` | `inherited` / `internal`; who it was inherited from |
| `raised_on`, `period_text` | exact date, or a period when no date is known |
| `requested_by` | who raised it |
| `reviewer`, `reviewed_on`, `review_summary` | the security review |
| `outcome` | see below |
| `approver`, `decided_on`, `conditions` | the decision |
| `review_due`, `ended_on` | look-again date; date it stopped applying |
| `jira_keys` | comma-separated issue keys; the first is the main one |
| `notes` | anything else |

Options: `vulnhub_assess_meta` (inherited register label, as-at date, the
register's own summary counts, notes), `vulnhub_assess_dismissed` (issue keys
set aside, with a reason).

Outcomes (filter `vulnhub_assess_outcomes`) and the group each counts in:

| Outcome | Group |
|---|---|
| approved, conditional | approved |
| rejected, not_approved | declined |
| awaiting_approval, in_review, awaiting_supplier | open |
| not_recorded, withdrawn, not_required | closed |

## Jira

Read-only and optional. Nothing here calls Jira: it reads the inbox table the
Jira plugin refreshes every 15 minutes.

- Every key links to the Jira site (connector client `site_url()`), and to the
  issue's page inside the portal when the inbox holds it.
- A **decision hint** is the newest stored comment that matches
  `vulnhub_assess_decision_pattern` and is not a question about a decision.
  It shows on open rows and on the not-yet-registered tab, and pre-fills the
  form; it is never saved by itself.

## Permissions

Reading: the portal's view capability. Add, edit, delete, set aside, put back:
`vulnhub_manage` (filter `vulnhub_assess_edit_cap`), nonce-checked, audited
(`assessment.created|updated|deleted|ticket_set_aside|ticket_restored|export|import`),
refused on a read-only replica copy.

## Export

*Export CSV* streams the rows the table shows, under the same filters, with a
UTF-8 BOM and formula-injection guard, including Jira links.

## Loading a register

```
docker exec -i vulnhub-wpcli wp --path=/var/www/html vulnhub assessments import /path/register.json [--replace] [--dry-run]
wp vulnhub assessments list [--kind=supplier|exception] [--format=table|csv|json]
wp vulnhub assessments missing
```

The import file names real suppliers, people and tickets, so it lives **outside
the repository**. Records match existing rows on kind + subject, and security exceptions
match on their Jira key, so a re-run updates rather than duplicates. Shape:

```json
{
  "meta": { "inherited_label": "Previous team", "inherited_as_at": "2025-04-30",
            "inherited_summary": { "approved": 12, "rejected": 2 }, "notes": [] },
  "records": [ { "kind": "supplier", "subject": "Example Ltd", "source": "internal",
                 "outcome": "approved", "approver": "A Person", "decided_on": "2026-01-31",
                 "jira_keys": "KEY-123" } ],
  "exceptions": [ { "title": "Example allow-list", "status": "approved", "reason": "compensating_control",
                    "justification": "At least twenty characters of why.", "approver_name": "A Person",
                    "decided_at": "2026-01-31", "decision_note": "Approved with conditions ...",
                    "jira_key": "KEY-125" } ],
  "dismissed": { "KEY-124": "Test ticket" }
}
```

When the inherited register's own summary counts disagree with its rows, the
page says so rather than picking one.

