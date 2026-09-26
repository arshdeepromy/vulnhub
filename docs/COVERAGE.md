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

**The evidence has to be this asset's own.** A record counts as *Agent
installed* only when it has a Tenable uuid **and** either Tenable's agent list
names it (`agent_status` on or off, or an `agent_last_connect`, written per
uuid by the hourly agent reading) or its raw record holds a `NESSUS_AGENT`
source inside a Tenable block whose `id` is that same uuid. A bare text search
of `raw_json` was the rule before, and it broke both ways:

- *Agent installed* beside *Not in Tenable*: a CMDB connector built a new
  record's raw data from a same-named match the asset store then rejected, so
  three records with no Tenable identity carried another machine's Tenable
  block. The connector now writes only its own `cmdb` block, and the copied
  blocks were removed (audit `asset.raw_cleaned`).
- *Agent required* with a live agent: `Repo::upsert_asset()` replaced the
  whole `raw_json` with whatever the current feed sent, so a posture sync
  after a Tenable sync erased the Tenable block. It now merges by feed key --
  each feed replaces only its own (`tenable`, `plerion`, `intune`, `cmdb`,
  `cloud`).

Recalculated when the rule changed: 64 records moved to *Agent installed*
(every one on Tenable's agent list), 3 moved off it; afterwards no record is
*Agent installed* while *Not in Tenable*, and none with a live agent reads
*Agent required*.

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

## Devices Defender found but could not identify are not servers

Defender's device discovery reports machines it has no sensor on. When it
cannot tell what one is — onboarding status *insufficient info* or
*unsupported*, a 40-hex device id for a name, "Linux, release unknown" — its
export still files many of them as servers, and they sat on the
servers-needing-an-agent list: switch and storage management interfaces,
VMware appliances (vCenter, NSX edges, ESXi management), out-of-band
controllers.

`Coverage::type_discovered_devices()` runs first in every `recalculate()`.
It only touches rows nothing else vouches for — Defender alone, still typed
server or unknown, no real name — and types them by the maker of the network
card Defender reports:

| Maker | Type |
|---|---|
| a network vendor (Mellanox, Cisco, Check Point, TP-Link, …) | network device |
| a server-hardware vendor, and no OS version | appliance — a management controller (iLO, iDRAC, a BMC) |
| VMware, and no OS version | appliance — a VMware virtual appliance |
| anything else with no OS version | unknown |

A VMware machine that reports a real OS version is left a server: it may be a
Linux VM nobody scans, which is a gap, not noise. On the live estate 53 rows
were retyped, and servers not in Tenable needing an agent went from 127 to 74.

---

## AWS: what Tenable and Defender can cover, and whether they do

The **AWS servers: Tenable and Defender coverage** widget
(`VulnHub_AWS_Coverage`, vulnhub-aws).

### What is in scope

Tenable Vulnerability Management reaches a machine through an agent or a
network scan, and both need an operating system that we run. In AWS that is an
**EC2 instance** and nothing else:

| In AWS | Tenable / Defender? | Why |
|---|---|---|
| EC2 instances (Windows, Linux, Elastic Beanstalk and EKS/ECS container hosts included) | **yes** — agent or scan | a VM with our OS on it |
| AppStream sessions | through the fleet's image | the hosts are AWS's; the image is ours and carries the agent (`docs/APPSTREAM.md`) |
| Lambda, Fargate/ECS tasks, RDS, DynamoDB, S3, load balancers, Transfer Family | **no** | no OS of ours; a network scan of a managed endpoint tests AWS's patching. Their risk is configuration, which the posture scan covers |
| The inline firewall's instances | set aside | vendor appliances: nothing takes an agent there |

So coverage is measured on EC2 instances, and the rest is listed under *In
AWS, and not Tenable's to scan* with a count per kind.

### Where the instances come from

The network capture (every instance with its state, Name tag and private
address, in the accounts the sign-in reaches) plus the posture inventory's EC2
list for accounts it cannot read. Running instances are counted; stopped ones
are shown apart (an agent reports when the machine is on). Instances in the
inline firewall's account — the account that owns the gateway load balancer,
never a name — are set aside as appliances.

### Every running instance is an asset

After every capture, `register_missing()` gives a running instance with no
record one of its own, so its gap is a row in a list and not only a number:
named by instance id, because a Name tag is not unique (an Elastic Beanstalk
environment names every instance the same, and a shared name would fold two
machines into one row). The tag goes to `business_service`. `retire_gone()`
retires those records when their instance disappears — only in accounts the
capture read, so a partial read retires nothing.

### What the capture tells each record

`enrich()`, after every capture. A record the posture inventory made is often
an instance id and nothing else; the capture holds the Name tag, private
address, region, platform (`platformDetails`, captured with instance type,
AMI and launch time) and state. The tag becomes the hostname when it is unique
among instances and no other asset already uses the name (else the id stays
and the list shows the tag beneath it, from `business_service`). A **stopped**
instance is `spare` — out of the reporting scope and the agent-gap lists — and
`in_service` again once it runs; only on records AWS or the posture inventory
made. Instances in the inline firewall's account become appliances. Address,
region and OS fill in where empty and never overwrite. AWS reports many Linux
instances only as "Linux/UNIX", too coarse for the agent support table, so
they read *Agent — OS unknown*; the distribution would need the AMI's details.

### Twins

The posture inventory names an instance with no Name tag by its id. A domain
controller Intune and Defender already knew as `ad01` came in a second time as
`i-0…`: one row said "Defender, not in AWS", the other "in AWS, no Defender",
and the machine read as a gap it is not. `link_twins()` joins them when the
instance's **private address matches exactly and** the Name tag is the
hostname, or the hostname followed by `-`, `_` or `.` (`appsrv01-p1aa`), and
exactly one row qualifies. The id-named row is merged into the twin
(`Duplicates::merge()` carries the instance id and cloud fields across) and
loses its instance id, so the next posture sync matches the twin, not the
retired row. Core's hostname rule never lets a bare instance id rename a
record a person named — the same rule it already had for `ip-10-…` names.

### Account and instance names

A ticket's reader works in the AWS console, where a machine is an account and
an instance name. Neither was on the record: the hostname is often an
instance id, a Windows default (`EC2AMAZ-…`) or a name only the OS knows, and
account numbers are not something anyone reads.

- **`assets.aws_instance_name`**: the instance's Name tag, from the capture or
  the posture inventory (`instances()`), written by `stamp_names()` after
  every AWS and posture sync. A bare instance id is not a name.
- **`assets.aws_account_name`**, beside the existing `cloud_account_id` (now
  also filled from the instance's account where the record had none).
- **Where names come from** (`VulnHub_AWS_Account_Names`, option
  `vulnhub_aws_account_names`): the posture inventory's integrations
  (`/v1/tenant/integrations`, cursor-paged; the number is `awsAccountId` there,
  `providerAccountId` on assets and findings) on every posture sync, and the
  sign-in's account list (`accountName`) on every AWS sync. Each reports
  through the `vulnhub_aws_account_names` action, so neither plugin depends on
  the other.
- **Kept, not mirrored.** An account a later read does not list keeps its
  name; an empty name never overwrites one; a record whose instance is no
  longer captured keeps its last instance name. Configured accounts whose
  label is still the "N known assets" placeholder, or empty, take the real
  name; a label somebody typed is left alone.
- Name stamping never counts as a coverage move, so it never triggers a
  recount.

**Checked** on first run (schema v35): 65 named accounts; every one of the 96
active records with an instance id got its account and account name, 93 an
instance name, and 30 of those differ from the hostname.

### Numbers, filters, export

- **`aws=ec2`** (running) and **`aws=ec2_stopped`** on Assets & owners, as an
  *AWS* control, through `vulnhub_assets_query`; in the asset CSV export.
- **`coverage=ok`** (Tenable holds it: `Coverage::in_tenable_states()`) and
  **`defender=ok`** (`Defender_Coverage::covered_states()`) beside the
  existing `gap` values, so the widget's two-by-two — Tenable yes/no against
  Defender yes/no — links every cell to exactly its rows.
- Every number on the widget is a `Repo::assets()` count with the arguments
  of the list it opens.
- A gap row that the internet can reach carries *open from outside*
  (`docs/ATTACK-PATHS.md`).

Checked on the live estate after linking and registering: 81 running, 12
stopped, 1 appliance set aside; both 49, Tenable only 12, Defender only 2,
neither 17 — each equal to its list.

---

### Records the CMDB made: placed by domain

A CMDB record for a cloud machine often carries only a hostname and a DNS
domain -- no address, no instance id -- so `link_twins()`, which needs the
address, never joined it, and the record exported with every AWS column
empty. `VulnHub_AWS_Coverage::link_by_domain()` fills that gap:

- **Account by domain.** Where everything after the host in the FQDN spells
  a known account name, dots for dashes (`appsrv01.cloud.corp.sit` in account
  `cloud-corp-sit`), the record is that account's: it gets the account id,
  provider AWS and the account's region, and `stamp_names()` carries the
  account name. Exact equality only; two accounts with the same name place
  nothing. It never overwrites an account a record already has.
- **Instance by name, inside that account.** The hostname against the Name
  tag, by the same rule as `link_twins()` (the tag is the hostname, or the
  hostname then `-`, `_` or `.`), or an `ip-a-b-c-d` hostname against the
  private address. Terminated instances never match. **Exactly one candidate
  links**; an instance already on an id-named record folds that record in, as
  `link_twins()` does. Several candidates, or an instance already on a record
  with a real name, are reported in the `aws.domain_placed` audit entry for a
  person to merge -- never guessed.
- Runs after every AWS, posture and CMDB sync. Additive; a second run moves
  nothing.

A placed record with no instance keeps the instance columns empty: the
account is proven by its domain, the machine is not. Such a record is
usually one the CMDB still lists after the instance went, which is worth
raising with the CMDB's owner rather than as an agent gap.

**Checked** on first run: 22 records placed on 4 accounts, 0 linked (none of
their names exists as an instance there), 3 reported (one instance already on
its own record, two hostnames matching both a stopped and a running
instance). Every placed record exports account id, account name and region.

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
