# The end-of-support remediation programme

`vulnhub-eos` answers the question the *Platforms past end of life* widget
could not: **is anybody dealing with these?**

The lifecycle table already says a machine runs a release the vendor stopped
patching. It says nothing about whether that machine has a project and a date
against it. That answer lives in the End-of-Support Server Retirement
Programme — a spec and a reconciliation workbook maintained outside this
platform — and until this plugin it was invisible here.

---

## What the programme data is

The programme reconciles four systems (JSM Assets as the canonical inventory,
BigFix and SNOW as independent technical scans, and the Architecture team's
manual planning layer, which is the only source of *intent*) and produces one
row per server carrying a treatment plan, a timeframe, an environment tier and
a RAG rating.

Its five states, which this plugin stores verbatim:

| State | Meaning |
|---|---|
| In support | The OS is not past end of support. |
| Remediated | Was out of support; confirmed done. |
| Planned | Out of support, with a named project and an FY/quarter. |
| No plan | Out of support, identified, nothing scheduled (blank or TBD). |
| Visibility gap | Known to exist, but its real OS state cannot be verified — today, the AWS cohort neither scanner can reach. |

The programme's own RAG model combines environment criticality with that
state, and escalates anything overdue a level. VulnHub stores the RAG it is
given rather than recomputing it; the two are shown side by side so a
disagreement stays visible instead of being quietly reconciled.

**This is imported data, not live data.** Every screen says so, with the date
of the last import. The spec is explicit that the dashboard "reflects the data
as of the last upload, not real time", and a security screen that implies
otherwise is worse than one that admits its age.

---

## Coverage: the green/red rule

Everything visual in this feature reduces to one question, so it has one
definition, in `VH_EOS_Repo`:

| Coverage | Rows it covers |
|---|---|
| `covered` | **Remediated**, or **Planned with a deadline still ahead**. Also *In support* — it needs no remediation, so red would be a lie. |
| `overdue` | **Planned, but the deadline has passed.** Counted as red. |
| `uncovered` | No plan, TBD or blank, visibility gap, **or an end-of-life asset the programme has never assessed at all**. |

Two more filter values exist because the widget and the page have to reconcile:

- `not_covered` = `overdue` + `uncovered`. This is what the dashboard's red band
  counts and links to.
- `uncovered` on its own is the strict subset, excluding overdue.

A bar that says 9 must open a list of 9. That is the whole reason
`not_covered` exists as a filter value rather than being spelled two ways.

**Coverage is computed when it is read, never stored.** A plan whose quarter
ends tonight reads overdue tomorrow morning with nobody re-importing anything.
Storing it would mean the screen quietly goes stale the moment a date passes —
which is exactly the failure this feature exists to expose.

### The financial year

`VH_EOS_Repo::FY_START_MONTH = 4`. **FY26 runs 1 April 2025 → 31 March 2026**,
which is the convention the workbook itself uses (its "FY26 Q3" rows are dated
against Oct–Dec 2025). Quarters are Apr–Jun, Jul–Sep, Oct–Dec, Jan–Mar. A
timeframe naming only a year means the last day of that year, which is the most
generous reading and so the least likely to call something overdue unfairly.

`FY27`, `FY26 Q3`, `FY26Q3` and `FY 26 Q3` all parse. `TBD`, blank and anything
unparseable yield no deadline, which makes the row uncovered rather than
overdue — no date is not a missed date.

If the organisation's fiscal calendar differs, that one constant is the only
thing to change.

---

## The widget

*Platforms past end of life* now draws each expired release as two bands:
green for covered, red for not covered, each linking into the plan screen
filtered to exactly that slice (`?key=<release>&coverage=covered|not_covered`).
The red band's tooltip names how many of it are overdue rather than
never-planned, so the distinction survives without a third colour.

The split arrives through a filter in the dashboard rather than by editing the
widget:

```php
apply_filters( 'vulnhub_eol_bar_segments', array $segments, array $row, string $context );
apply_filters( 'vulnhub_eol_bar_legend',   array $legend,   string $context );
```

`$context` is `'platforms'` for the platform bars and empty for the software
bars, which therefore cannot be restyled by a consumer that only understands
operating systems. The two filters are paired deliberately: anything that
recolours the bands must relabel the key in the same breath, or the key
describes colours that are no longer on the chart.

**With the plugin inactive, or with no data imported, the widget renders
exactly as it did before.** `VH_EOS_Widget` checks both the class and
`VH_EOS_Repo::has_data()` before touching anything.

Coverage for every bar resolves in **two queries per render**, not one per bar:
one pass groups every reportable asset under its release key, then a single
`coverage_for_assets()` call covers the lot, memoised for the request. The
naive version was 12 full passes over the asset table for 12 bars.

---

## The EOL remediation plan screen

`/eol-plan/` (view `eol_plan`), in the rail. It opens with what the data is and
when it was imported, then:

- **Tiles** — in the programme / covered / overdue / not covered, each a filter
  link.
- **Forward workload by quarter** — what still needs action, green and red per
  quarter, with a table view of the same numbers.
- **The server table** — hostname, OS, environment and tier, treatment plan,
  timeframe with its due date and an overdue flag, state, RAG, owner team,
  site, open critical/high, last scan. Rows restack as cards under 640px.

### Filters

Programme filters: `coverage` (`covered` / `not_covered` / `overdue` /
`uncovered`), `state`, `timeframe`, `tier`, `rag`, `project`, and `key` (an EOL
release key, shown as a removable chip). Alongside them, the portal's own
vocabulary: `search`, `team`, `site`, `life`. Filters survive Apply and
sorting, exactly as the assets list does.

**Export CSV** covers the whole filtered set, not the visible page, through
`admin-post.php?action=vulnhub_eos_export_csv`. The filename names the filter,
and the button carries the count so you know what you are about to download.

---

## Importing

**Administration → Data → EOS remediation plan.** Upload the workbook's
*Reconciled* sheet as CSV; it previews first, and only commits when you say so.
Re-running is idempotent, and the intended cadence is monthly, matching the
programme's own refresh proposal.

Rows are matched to assets on **normalised hostname** — lower-cased, trimmed,
and cut at the first dot — with a fallback to the first label of an asset's
FQDN. That fallback is not decoration: one host matched only because the asset
is named `jira` while its FQDN is `wlgsrvjirarh1.…`.

**The import never creates assets.** A programme row with no matching asset is
kept and shown as *not in inventory*: the programme knowing about a server the
inventory does not is a finding in itself, and deleting the row would hide it.
A later sync that adds the asset relinks it — `relink()` runs on
`vulnhub_sync_complete` and `vulnhub_import_complete`.

### What the current import produced

Evidence rather than assertion, from the July 2026 workbook:

| | |
|---|---|
| Rows read / plan rows kept | 218 / **127** (91 blank padding rows skipped, 0 duplicates) |
| States | 85 planned, 25 remediated, 17 no plan |
| Coverage | **95 covered, 15 overdue, 17 uncovered** |
| Matched to an asset | **94** of 127 (33 not in inventory) |
| Servers on the plan screen | **136** — the 127 plus 9 end-of-life assets the programme has never assessed |

Those 9 are the ones worth looking at first: they are past end of life and
nobody has written them down anywhere.

---

## Storage

One table, `vh_vulnhub_eos_plan`, keyed by hostname, holding the programme's
columns plus a parsed `deadline`, the `asset_id` when matched, and a batch id
per import run. Coverage is not a column — see above.

---

## What this does not do

- It does not decide whether a plan is *credible*, only whether one exists with
  a date. A project named "Further Investigation Required" counts as planned
  until its quarter passes.
- It does not write back. The workbook stays the source of intent; VulnHub
  reads it.
- The programme's own Controls / Inherent risk / Residual risk fields are
  stored and displayed but not used in any calculation — the spec flags them as
  not yet consistently maintained, and inventing a score from them would be
  worse than showing them as-is.
