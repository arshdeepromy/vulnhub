# Attack paths

**VulnHub → Threat context**, and the *How an attacker gets in* widget.

The vulnerability table answers "how bad is it". This answers the question
that actually decides what gets worked on first: **how would somebody get to
it, and has anybody written the exploit yet.**

---

## The problem it solves

Tenable's export says nothing about reachability. It gives a severity, a
plugin id, a title and a description — and on this estate `cve_json` is empty
on all 11,746 definitions and `exploit_available` was `0` on every single one,
which is why the dashboard's own impact funnel read zero at every stage.

But the CVE ids are there: in the title for 9,650 definitions and in the
description for 11,532. And a CVE id is enough, because the CVSS v3 vector
attached to it is *exactly* a description of how an attacker reaches the bug:

| Metric | What it tells you |
|---|---|
| `AV` — attack vector | over a network, on the adjacent LAN, local, or physical |
| `PR` — privileges required | does the attacker need an account first |
| `UI` — user interaction | does a person have to open, click or visit something |

Nobody has to be clever about this. The vector already says it.

---

## Where the data comes from

Three public feeds, refreshed nightly. **None of them is told anything about
this estate** — the only traffic leaving the box is a request for a public
file, so no hostname, asset or finding is disclosed by running this.

| Feed | Gives | How it is fetched |
|---|---|---|
| **NVD** (via the `fkie-cad/nvd-json-data-feeds` mirror) | CVSS vector, reference tags, publication dates | 26 year files, ~100 MB compressed, streamed and filtered |
| **CISA KEV** | what is being exploited in the wild today | one JSON, ~1.7 MB |
| **FIRST EPSS** | today's probability of exploitation in the next 30 days | one gzipped CSV, ~2.6 MB |

Coverage on the current estate: **13,239 of 13,260** referenced CVE ids found
(99.8%), **12,143** of them carrying a CVSS v3 vector.

### Why the year files and not the NVD API

The API has no bulk-by-id endpoint. Paging every vector out of it one CVE at a
time is 13,000 requests — 22 hours unauthenticated, two hours with a key. The
year files are 26 downloads. The API is kept as a fallback for ids the year
files do not contain (currently 21 of them) and for any host without a
decompressor, capped at 200 ids per run so it can never eat a whole night.

### Why a line reader and not `json_decode`

The 2026 year file is 364 MB decompressed and PHP is on a 512 MB limit. The
feed is pretty-printed, so a CVE object opens on a line that is exactly four
spaces and a brace; the id is on the next line. That is enough to discard
~300,000 unwanted records per pass without ever decoding one.

If the feed's formatting ever changes, the parser returns zero records for a
file that downloaded fine — which is logged as an error and falls through to
the API, rather than silently reporting an empty estate.

---

## How a vulnerability is placed

**Per CVE**, straight from the vector, in this order:

```
UI:R (or PASSIVE/ACTIVE in v4)  →  user     delivered to a person
AV:N and PR:N and UI:N          →  edge     reachable by a stranger
anything else                   →  inside   needs a foothold first
no v3 vector                    →  unknown  not placed, and reported as such
```

Order matters. User interaction wins over everything: a bug that needs someone
to open a file arrives by phishing regardless of what the network metric says.

**Per definition**, the most reachable route any of its CVEs opens. A kernel
advisory bundling thirty CVEs is as exposed as its worst one, because the
patch is per-package, not per-CVE.

**Per finding**, the definition's route gated on whether the internet can
actually reach the machine — see below.

### Exploitable today

A definition enters the widget only if at least one of its CVEs is:

- on **CISA KEV** — 50 CVEs here, and the strongest evidence there is; or
- linked by NVD to a reference it has tagged **`Exploit`** — 1,289 here, each
  one a URL you can open and read; or
- scored **≥ 10% by EPSS** for today — 222 here.

All three are toggles, and the EPSS threshold is a number, on the settings
screen. EPSS is re-scored daily, which is what lets the widget say "today" and
mean it.

---

## The asset gate

This is the difference between a number that is true and a number that is
useful.

7,395 open findings on this estate are network-exploitable with no credentials
and no user interaction — and they are on **laptops**, which nothing on the
internet can open a socket to. Counting them at the perimeter would inflate
that lane from 5,361 to 12,756 and point remediation at the wrong work.

So they are not counted there. They move to the *inside* lane, where they can
genuinely be used, and the widget says so on the card rather than quietly
dropping them.

Which assets count as reachable is a setting (**Threat context → Which assets
the internet can reach**):

| Rule | Matches |
|---|---|
| `servers_and_cloud` *(default)* | servers, cloud instances, and anything tagged `internet-facing`, `dmz`, `public-facing`, `edge` or `perimeter` — **175 assets** here |
| `cloud_only` | cloud instances only |
| `tagged` | only the tags. Strictest, and where to move once tagging is trustworthy |
| `all` | assume no perimeter at all |

Verdicts live in `vulnhub_asset_exposure` with a `source` column. A rule pass
rewrites its own decisions and leaves anything marked `manual` alone.

---

## What it currently reports

| Lane | Open findings | Machines |
|---|---|---|
| Straight from the internet | 5,361 | 122 |
| Delivered to a person — email 128 · website 1,299 · download 6,109 | 7,536 | 478 |
| Usable once inside (incl. 7,395 moved from the edge lane) | 12,495 | 540 |
| Not placed — no CVSS v3 vector | 27,618 | — |

The email/website/download split is keyword matching on the NVD description,
and is coarse by design: it only ever refines a lane the vector already
decided, so getting it wrong moves a finding *within* a number, never between
lanes.

---

## Tables

| Table | Rows | Holds |
|---|---|---|
| `vulnhub_cve_intel` | 13,239 | one row per CVE: vector, KEV, EPSS, route |
| `vulnhub_vuln_paths` | 11,746 | one row per scanner definition: rolled-up route and evidence |
| `vulnhub_asset_exposure` | 848 | one row per asset: can the internet reach it, and why |

All three belong to `vulnhub-threat`. Nothing in core's schema changes, so
deactivating the plugin leaves the estate data exactly as it was.

The one exception is deliberate and switchable: with **"write the verdict back
to `exploit_available`"** on, the roll-up fills in core's own column, which is
what makes the impact funnel and anything else reading it stop reporting zero.
A future Tenable sync that carries the real field will overwrite it — and that
is correct, because the vendor's answer should beat an inference.

---

## Running it

```bash
./wp.sh vulnhub threat status      # feed freshness and coverage
./wp.sh vulnhub threat refresh     # download everything and re-place (~3 min)
./wp.sh vulnhub threat classify    # re-place from what is already downloaded
```

`refresh` is also a daily cron event. It runs in the **cron container**, not
in a web request: it downloads ~100 MB and rewrites 13,000 rows, which is
minutes of work with no timeout over it. The "Download the feeds again now"
button queues the event rather than doing the work inline, so the worst a
button press can do is wait a minute.

---

## Performance

`lanes()` measures 478 ms cold against 228,107 findings, and the widget is
transient-cached on top of that.

Everything is done with id lists rather than joins, for the reason recorded in
`Repo::findings()`: filtering 228,000 findings on a column that lives in a
13,000-row table makes the optimiser walk the findings table doing a
primary-key lookup per row. Resolving the small tables first turns each count
into an index range scan on `vuln_state_exc` — which already carries
`asset_id` as its last column, so the edge lane's asset gate is answered from
the index too. The three drill-downs measure 23–40 ms.

---

## The one edit outside this plugin

`Repo::findings()` gained a `vulnhub_findings_query` filter, so another plugin
can add a WHERE clause, its bound parameters and any joins it needs. That is
what makes `?route=edge&poc=1` work, and what makes every number on the widget
land on exactly the rows it counted. A number you cannot click is a number
nobody can act on.

The dashboard's findings screen passes `route` and `poc` through from the
query string. Both are inert when this plugin is not active.
