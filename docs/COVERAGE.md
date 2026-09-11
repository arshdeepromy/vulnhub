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
