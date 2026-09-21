# Scanning coverage

What "not scanned by Tenable" means, which assets it is asked about, and what
now gets imported so the answer holds up.

Companion to `docs/FILTERS.md`, which covers the scope rule that decides *which*
assets are expected to be scanned at all.

---

## What the Intune CSV import was losing

The Graph connector has always captured a device's last check-in. The CSV
importer mapped ten fields and none of them was a date, so an estate loaded
from a CSV had `last_intune_sync` NULL on **every single device** — 848 out of
848 here — and nothing to answer "when did anything last see this machine".

The two paths now produce the same asset record:

| Field | From | Was CSV capturing it? |
|---|---|---|
| Last check-in | `lastSyncDateTime` / "Last check-in" | **no** |
| Compliance state | `complianceState` | **no** |
| Enrolment date | `enrolledDateTime` | **no** |
| Join type | `joinType` | **no** |
| Enrolment type | `deviceEnrollmentType` | **no** |
| Ownership | `managedDeviceOwnerType` | **no** |
| Management state | `managementState` | **no** |
| Office / location | `officeLocation` | **no** |
| Device name, serial, OS, model, ids… | — | yes |

Header detection is unchanged in shape — the spellings the portal, Graph and
the older Devices report each use are all listed, and anything unrecognised is
still mappable by hand on the preview screen. On a realistic export
(`dev/import-intune-test.php`) 17 of 18 columns map with no help.

The check-in date is written to two columns on purpose. `last_seen` is the
estate-wide "something saw this", used by coverage; `last_intune_sync` is
Intune's own claim, kept separately so the two can be compared.

An office column, when the export has one, creates or matches a site. Intune's
own device export has no such column, but plenty of organisations join one on
first, and an Entra user export carries `officeLocation`.

## And what the CMDB import was losing

The live CMDB export has a **Last Scan Date** column. The schema had no alias
for it, so it was dropped. It now lands in its own `cmdb_last_scan` column —
not folded into `last_seen`, because which system is making the claim is the
whole point of the next section.

---

## Dates were being read two months wrong

`strtotime()` treats a slashed date as American, always. An Intune export
produced on a New Zealand machine writes `07/09/2026` meaning 7 September, and
PHP read it as 9 July. For a last check-in that is not cosmetic: it is the
field that decides whether an unscanned asset is reported as live work or as a
record nobody retired, against a 45-day window.

`vh_disambiguate_date()` now sits in front of every import date — Intune, CMDB
and the Tenable asset export, since they all go through `vh_to_mysql()`:

- a field above 12 settles it from the file itself, whatever the setting says;
- anything already unambiguous (ISO, dashes, a written month) is untouched;
- only genuinely ambiguous dates fall back to **Settings → Date order in
  imports**, which defaults to the site's *timezone* rather than its admin
  language — almost every install outside the US is left on `en_US`, so the
  language would have told every non-American customer their files were
  American.

This install has no WordPress timezone set, so the automatic answer was
"American". It has been set explicitly to **day first**. Setting the site
timezone to `Pacific/Auckland` under Settings → General would make the
automatic answer correct as well, and would fix every date WordPress displays.

---

## A coverage gap is now two different jobs

"Not in Tenable" used to be one red list. It is two problems with two owners:

| State | Means | Whose job |
|---|---|---|
| **Not in Tenable** | No scanner record, and something saw it recently — or nothing has ever dated it | Scanning. The machine is live and unscanned. |
| **No recent contact** | No scanner record, and nothing has dated it inside the contact window | Inventory. Almost always a record nobody retired. |

The window is **Settings → Last-contact window**, default 45 days —
deliberately longer than the 30-day scan window, because a laptop can sit in a
drawer for a month without being gone.

An asset with *no* contact date from any system stays in the first group. That
is the safe direction: absence of evidence is not evidence of absence, and
hiding it would repeat the mistake this whole feature exists to correct. On
this estate all 97 gaps are in that position today — nothing has ever carried a
check-in date — so the split changes nothing until an Intune sync or a CSV with
a check-in column arrives. The settings screen says so rather than showing a
feature that appears to do nothing.

---

## Agent coverage is not scan coverage

Tenable can reach an asset two ways: an agent checking in, or a network
scanner sweeping it. `Coverage` answers "does Tenable know this asset", which
either satisfies. It cannot answer "is there an agent on it", and an estate
that reports only the first cannot tell an agent rollout from a scanner sweep.

`Agent_Coverage` is that second dimension, in its own column
(`assets.agent_coverage_state`), recomputed on the same
`vulnhub_coverage_recalculated` hook as Defender's so the three states on one
row are never three different ages.

**Why not `assets.has_agent`.** That column means "has *an* agent". The
Defender and Intune importers both set it to `true` outright, for their own
agents — 87 assets here carry it while having no Tenable record at all. It is a
useful flag and a useless answer to this question.

**The evidence is `sources[]`.** Tenable's asset record lists an agent check-in
as `NESSUS_AGENT` and a network sweep as `NESSUS_SCAN`. That is already synced
into `raw_json`, so the dimension backfilled across the estate with no re-sync
and no extra API calls. `agent_uuid` is *not* the signal: it comes back null on
assets that demonstrably do have an agent.

**"No agent" splits in two, and that is the point.** An agent cannot be
installed on a hypervisor appliance, a service processor, or an OS older than
the agent supports. Chasing those is the waste this dimension exists to stop,
so they are `Agent out of scope` and are **not** counted as a gap; only
`Agent required` and `Agent — OS unknown` are.

| state | meaning | gap |
|---|---|---|
| `agent` | Tenable reports an agent checking in | no |
| `agent_required` | no agent, and this OS can run one | **yes** |
| `agent_os_unknown` | no agent, OS not in the support table | **yes** |
| `agent_out_of_scope` | no agent exists for this platform, or the OS is below its minimum | no |
| `out_of_scope` | not in service, or not a machine | no |

**Where supportability comes from.** `data/agent-support-*.csv`, curated by
hand and carrying the date it was checked. There is no Tenable API for it and
their documentation is an HTML page with no contract, so nothing reads it at
runtime: a docs redesign must never be able to silently reclassify an estate
overnight. The newest dated file wins, rows match as lowercase substrings in
file order (specific above general), and where a minimum is numeric the OS
string's own version is compared as a safety net — which is how `Ubuntu 16.04`
lands out of scope without anybody writing a row for it.

The Tenable settings screen states the table's date and row count, and says so
when it is over six months old. The parser tolerates a malformed row rather
than fataling on one: this file is edited by hand, and an unquoted comma in a
note makes a row wider than the header, which `array_combine()` turns into a
fatal error on every page of the site.

**On this estate**, at the time of writing: 642 with an agent, 134 agent
required, 140 agent out of scope, 93 OS unknown. Every Tenable-known asset is
agent-based — there is not one `NESSUS_SCAN` — so scan coverage and agent
coverage agree today and would silently diverge the moment network scanning is
used. The 93 unknown are a finding in their own right: their CMDB operating
system reads `Linux` or `Windows` with no version, which is too coarse to
decide anything.

Filter: `agent=` on Assets & owners (`gap` for anything needing one), a column
beside Scan coverage, both in the CSV export, and the `tenable_agent` ticket
kind to raise the rollout as work — where an asset counts as done once Tenable
reports an agent, and out-of-scope assets are excluded rather than left on
somebody's list forever.

## Agent online history — the part Tenable does not keep

**What Tenable actually holds.** `GET /scanners/{id}/agents` is the only place
in the API that says whether an agent is connected: `status` (`on`/`off`),
`last_connect`, `last_scanned`, `linked_on`, `health_state_name`, and
`asset_uuid` to join back. The asset record carries no online state at all —
only `first_seen`, `last_seen` and the scan dates. `GET /agents` without a
scanner id is refused (403); scanner 1 is the cloud scanner every linked agent
reports to.

**What it does not hold: history.** `status` is a snapshot of this instant and
`last_connect` is one timestamp. There is no uptime series anywhere in the API,
so "which hours was this machine up" cannot be asked of Tenable — it never
stored the answer. The only way to have it is to sample and write down what
changed, which is what `Agent_Status` does on the hourly
`vulnhub_poll_agent_status`.

**Transitions, not samples.** A row per poll over ~900 agents is ~22,000 rows a
day and answers nothing better: the state between two identical readings is not
in doubt. `vh_vulnhub_agent_status` gets a row only when an agent flips
on↔off — a few hundred a week — and `assets.agent_status`,
`agent_last_connect` and `agent_status_since` carry what is true now, so
"offline since" is one indexed read rather than a scan of the history.

The first reading of an asset is recorded as a change (the timeline needs an
opening state) but counted separately, so a first run reports "654 first
readings", not "654 machines just went down".

**Two dates, and the difference matters.** `agent_status_since` is when VulnHub
first saw the current state and can never reach back further than the polling
does. `agent_last_connect` is Tenable's own, and is the one worth quoting for a
dark agent — which is why the `agent_dark` filter measures from it. Dating
"dark for N days" from our own first reading would understate every agent that
was already off when sampling started.

**The honest limits.** Resolution is the poll interval. History begins the day
it is switched on; there is nothing to backfill from. And it says the *agent*
was connected, which is a good proxy for the machine being up and not the same
claim — a stopped agent service on a running server reads as offline, correctly
for scanning and misleadingly for anything else.

**On this estate** at first poll: 911 agents in 2.1s, 654 matched to assets,
513 online, 141 offline, the longest dark for 26 days. 105 have been dark over
a day, 46 over a week, none over 30 days.

Filter `agent_dark=` (1/7/14/30/90 days) on Assets & owners, "dark since …"
beside the agent chip in the list, and on the asset page the state, Tenable's
own last check-in, and the recorded changes behind a disclosure that says where
the history came from.

## Coverage by site

The site breakdown existed but could not be used:

- **The biggest bucket was unclickable.** 303 assets have no site, holding
  **53 coverage gaps — more than any named office.** The bar read
  "Unclassified" and went nowhere: `location_id = 0` is a real value, and the
  asset query's `! empty()` test silently ignored it.
- **There was no site control.** `location_id` could only arrive by clicking a
  chart, and pressing Apply threw it away (see `docs/FILTERS.md`).
- **Only the ten biggest sites were drawn.** Twelve are in use, so a small
  office with two machines and no scan — exactly the row worth seeing — fell
  off the bottom.

All three are fixed. The assets list has a **Site** control whose first option
is *No site recorded*; `location_id=none` is a first-class filter on both the
asset and the finding queries; the chart draws every site; and the unplaced bar
links to its own list.

An asset with no site is also now reported as an ownership gap next to the
missing-owner one, for the same reason: an asset nobody can place is an asset
nobody can send an engineer to. **297 in-service assets** are in that state.

---

## Checking it

```bash
# a realistic Intune export, through detection, mapping and import, then read back
docker compose cp dev/import-intune-test.php wpcli:/tmp/t.php && \
  docker compose exec -T wpcli wp eval-file /tmp/t.php

# every filter and every clickable number
docker compose cp dev/filter-audit.php wpcli:/tmp/fa.php && \
  docker compose exec -T wpcli wp eval-file /tmp/fa.php
python3 dev/form-audit.py
```

The import test creates one asset, one site and one person, prints what landed
on each column, and removes all three — so it is safe to run against a live
estate.
