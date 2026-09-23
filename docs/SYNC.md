# Staged sync architecture

How a connector pulls a large scanner export without losing the run to a crash
or the container to an out-of-memory kill. The Tenable connector is the
reference implementation; the same pattern applies to any connector whose export
is too big to hold in memory.

The problem it solves: a naive "fetch everything, then import everything" sync of
a few hundred thousand findings either times out, runs the PHP worker out of
memory, or — if it dies at 90% — throws away all the work and starts from zero on
the next attempt. The staged sync splits the work into two phases that each
checkpoint to disk, so no single failure costs more than the step it happened on.

---

## The two phases

A run moves through three phases recorded in `state.json`: `download` →
`process` → `finalize`.

### 1. Download

The raw export is pulled chunk by chunk, exactly as the vendor hands it over, and
each chunk is written to disk under:

```
wp-content/uploads/vulnhub-sync/<connector>/
  assets-1.json  assets-2.json  …
  vulns-1.json   vulns-2.json   …
  state.json
```

The directory is created and guarded (`index.php` + `.htaccess Require all
denied`) so the raw scan data is never served back over HTTP. Chunks are written
to a `.part` temp file and renamed, so a chunk file is only ever seen complete —
a half-written chunk from a crash mid-write is never mistaken for a finished one.

**Chunks are stored gzip-compressed.** A vuln export is ~92% a plugin-metadata
block repeated on every finding, so it compresses ~13:1 — a multi-gigabyte
download lands as a few hundred megabytes on disk. The file keeps its `.json`
name but holds gzip bytes (`VH_Tenable_Store::GZIP_LEVEL`). Large vuln chunks are
streamed to disk raw by the client and then compressed **in place** by
`compress_chunk()`, a 1 MiB-buffered streaming gzip so peak memory is unchanged;
small, already-decoded asset chunks are gzipped in `save_chunk()`. Every reader
(`read_chunk()`, `stream_records()`) opens through `gzopen`, which transparently
reads both gzip and legacy plain-JSON chunks — so a resume that straddles this
change still reads chunks written before it.

Progress is reported as **bytes on disk**, with a live download rate and an ETA
derived from a stored estimate of the full/incremental export size
(`vulnhub_dl_est_full_*` / `..._incr_*`). The vendor does **not** send a total
chunk count or total size up front — Tenable exposes only `chunks_available`
during the run and the final count at `FINISHED` status — so the bar is an
estimate until the export finishes, then a true count.

### 2. Process

Each downloaded chunk is imported off disk in bounded batches through the **same
normalisation path the live sync uses**. Assets are processed first (so
vulnerabilities can attach to known assets), then vulnerabilities, which are the
headline record count shown on the processing bar.

A chunk is deleted the moment it has been imported (`delete_chunk()`), so disk is
freed as processing goes rather than only at the very end. This is safe against
resume: the checkpoint has already advanced past a chunk before it is deleted, so
a restart never looks for a chunk that is gone.

The import loop emits a progress heartbeat every `PROGRESS_HEARTBEAT` (2000)
findings, **not only once per chunk**. A single vuln chunk can hold tens of
thousands of records and take several minutes to import; without a mid-chunk
heartbeat the run-row would look frozen and the stall-reaper (below) would mark a
perfectly healthy import failed. The resume checkpoint stays per-chunk —
`records_done` is only a display counter, and a resumed chunk re-imports
idempotently through `upsert_finding()` — so the extra heartbeats cannot corrupt
a resume.

### 3. Finalize

Every run, full or incremental: per-asset roll-ups are recomputed, the run
summary is persisted, the watermark advances to when the run started, and the
staging directory is wiped. **Only a full resync** additionally retires assets
the scanner has dropped (see *Pruning* below) and records `last_full_sync_at`.

Scan-coverage states are stored on the asset, not computed per render, so they
are recalculated by the scheduler once the connector returns —
`Scheduler::run_sync()` for a scheduled run and `run_sync_now()` for every
manual one (the button, REST, MCP and the resume sweep). The manual path used
to skip it, which left an asset whose findings had just been imported reading
"Not in Tenable" until the nightly housekeeping run caught up.

---

## Resumability

Every step writes a checkpoint to `state.json` (atomic temp-file + rename, so a
checkpoint is never read back half-written). The state carries the phase, the
`since` watermark for the run, whether it is a full resync (`is_full`), and per-phase progress:

```jsonc
{
  "phase": "process",
  "since": 1726000000,
  "is_full": false,
  "download": { "assets_chunks": 4, "vuln_chunks": 37, "bytes": 812334102, "status": "done" },
  "process":  { "stage": "vulns", "chunk": 12, "records_done": 41000,
                "records_total": 220000, "asset_chunks": 4, "vuln_chunks": 37 }
}
```

If the container is killed or the host reboots mid-run, the sync resumes from the
exact chunk it stopped on instead of restarting the whole import. Two things
drive resumption:

- **`VulnHub_Scheduler::HOOK_RESUME`** — a 5-minute cron sweep (`resume_syncs()`)
  that picks up any connector left in a resumable phase.
- **`Connector::resumable_sync()`** — returns true while the phase is one of
  `download` / `process` / `finalize`.

A "Sync now" from the UI schedules `HOOK_SYNC_NOW` as a single WP-cron event
(`queue_sync()`), so the request returns immediately and the work runs in the
cron worker rather than the web request. A connector whose `async_sync()` is true
is **always** queued this way — including a full resync, which records the
request on the connector (`request_full_sync()`) and then queues the same run.
(`full=true` used to force the sync inline in the web request, and the staged
sync ignored the flag.) The MCP `vulnhub_sync_connector` tool routes the same
way; only connectors that sync inline (`async_sync()` false) still run inside the
request.

**Single-flight.** The cron container runs `wp cron event run` under `flock -n`,
so a run that lasts longer than the 60-second cron tick cannot be joined by a
second overlapping worker. Overlapping staged syncs would otherwise stack
multi-hundred-megabyte PHP processes into the container until the OOM killer took
one — which is how a run died at the download→process boundary. `-n` means the
next tick simply skips while a run is still going, and picks up again once it
finishes.

---

## Disk hygiene

Three mechanisms keep the staging area from growing without bound:

1. **Progressive deletion** — each raw chunk is `unlink`ed as soon as it is
   imported.
2. **Restart cleanup** — a (re)starting download calls `clear_chunks()`, which
   removes any leftover `*.json` chunks and half-written `*.part` files from an
   interrupted run while keeping `state.json`.
3. **Completion wipe** — a fully completed run calls `clear()`, removing chunks
   and state alike.

`bytes_on_disk()` powers the download readout and is also the number to watch if
you ever suspect a staging directory has been orphaned.

---

## Incremental runs

Most runs are incremental. "Incremental" means *what Tenable has seen since the
last sync*, not *what changed* — the distinction matters for sizing and for what
a run can miss.

### The window

- **Watermark with overlap.** `since_for_run()` returns the watermark of the last
  successful run minus a 24-hour overlap, so anything that changed right on the
  boundary is picked up twice rather than not at all.
- **Watermark advances only on success.** `advance_watermark()` runs in
  `finalize` and sets the watermark to when *that run started*. A failed or
  interrupted run never moves it, so the next run re-covers the same window.

### What each export returns

| Export | Filter sent | What Tenable returns |
|---|---|---|
| Vulnerabilities | `since` = watermark − 24h, `state` = OPEN, REOPENED, FIXED | OPEN/REOPENED findings **seen** on or after `since`, and FIXED findings **fixed** on or after `since` |
| Assets | `last_assessed` = max(`since`, now − `asset_days`) | Assets **scanned** (credentialed or not) after that time |

Tenable defines `since` per state: OPEN/REOPENED findings are included when they
were "seen on or after the since date", FIXED findings when they were "fixed on
or after the since date". It cannot be combined with `first_found`,
`last_found` or `last_fixed`.

So an incremental run re-downloads every finding a scan re-observed in the
window, **even if nothing about it changed**. Its size tracks how much of the
estate was scanned, not how much changed. A measured example (a live account,
one sync ~24h after the previous one): 21,662 findings on 570 assets in 63
seconds — 17,329 were still-open findings simply seen again, 2,856 were fixed in
the window, and 1,271 had been first found in the window (most already imported
by the overlapping previous run).

### What an incremental run cannot see

- **Asset changes without a rescan.** A hostname, tag or attribute changed in
  Tenable on an asset that was not scanned in the window is not in the asset
  export.
- **Deleted or terminated assets.** The asset export asks for
  `is_deleted: false, is_terminated: false`, and an incremental export only
  holds recently scanned hosts, so absence means nothing — pruning is left to
  full resyncs.
- **Findings on assets that were not rescanned** stay exactly as they were.
- **Vulnerability-definition updates** (exploit flag, VPR, solution text) only
  arrive when some finding for that plugin is seen again.

A periodic full resync (below) is what catches all of these.

### Skip-unchanged

`Repo::upsert_finding()` has a fast path, but it is not a no-op: every re-sent
finding still costs one light UPDATE of `last_found`, `last_fixed`,
`last_synced_at`, `updated_at` and `scan_uuid`. The full row rewrite (plugin
output parsing, product and path-zone derivation) happens only when the state,
severity or risk score changed, or the finding is being reopened or suppressed.
The fast path returns `unchanged: true`, and the run summary reports those as
`N unchanged` so an incremental run's numbers are not read as 20k updates.

---

### What "incremental" cannot mean here

Read the two sections above together and the limit is plain: `since` filters on
**when a finding was last seen**, not when it last changed. Tenable has no
filter for the second question. Asked for this tenant's own vocabulary:

```
GET /filters/workbenches/vulnerabilities   -> 67 filters
   the only time axes: tracking.first_found, tracking.last_found,
   and the plugin's own publication/modification dates
```

On an agent-based estate every agent checks in daily, so every open finding is
"seen" every day and comes back in every window. Measured on a genuine
incremental run here:

```
run 173  fresh incremental, since 2026-09-19 19:29
         221,403 findings imported -- 221,391 of them unchanged
         14m 36s
```

Twelve findings had actually moved. The stored download estimates say the same
thing from the other end: `vulnhub_dl_est_incr_tenable` is 3.9 GB against
`..._full_` 5.4 GB, so an incremental download is **73% of a full one**.

This is not a defect in the watermark and it is not fixable by narrowing the
window -- a one-hour window on a daily-reporting agent estate still returns
every finding the agents re-observed. It is a property of the API. What follows
from it is the rest of this page: the inventory question is asked separately
and cheaply (removals, below, and the two cadences after that), and the
expensive export is put on a schedule that matches how often its answer
actually changes.

## Full resyncs

A full resync re-reads everything the scanner holds: `since` = now −
`first_sync_days` (default 3650, i.e. all history), and the asset export bounded
only by the `asset_days` freshness window.

### When a run is full

Decided **once**, when a fresh run starts, by `full_sync_reason()` — and
carried in `state.json` as `is_full`, so a resumed run stays whatever it started
as. A run is full when any of these hold, checked in order:

1. **First sync.** The watermark is 0 — nothing has ever completed.
2. **Requested.** The option `vulnhub_full_sync_requested_<connector>` is set.
   Any of these set it: the **Full resync** button on the connector card,
   `POST vulnhub/v1/connectors/<id>/sync` with `full=true`, the MCP
   `vulnhub_sync_connector` tool with `full`, or calling
   `$connector->sync( array( 'full' => true ) )` directly.
3. **Scheduled.** `full_sync_days` (Tenable setting *Full resync every N days*,
   default 7; 0 turns the schedule off) have passed since `last_full_sync_at`.

The request flag is cleared only when a full run **completes**, so a request
survives being queued, an interrupted incremental run being resumed first, or
the full run itself dying part way. It lives in its own option rather than in
the connector's settings array on purpose: settings are saved whole from an
in-process copy, so a long sync saving its watermark at the end would write back
the copy it loaded at the start and silently erase a request made while it ran.

`last_full_sync_at` is written when a full run completes (the run's start time).
Installs whose first sync predates this field have a watermark but no timestamp;
the first read backfills it **once** from the watermark — it is stored, not
re-derived, because the watermark moves on every incremental run and would push
the next scheduled full resync away forever.

The download-size estimate behind the progress bar is kept per class
(`vulnhub_dl_est_full_*` / `..._incr_*`), chosen from the run's `is_full`.

### `asset_days` on a full resync

*Only import assets seen in the last N days* (default 90) is sent as
`last_assessed` = now − `asset_days`. An asset Tenable has not scanned in that
window is not in the export, is not refreshed, and — if Tenable is its only
source — is retired by pruning. Findings keep their full history either way:
the vulnerability export still uses `first_sync_days`. On an incremental run the
watermark window is almost always the narrower bound, so the setting has no
effect there. Check this value before a full resync: a short window (say 15
days) retires every Tenable-only asset that has gone quiet for longer.

### Starting from an empty database

Full-or-incremental is decided by the **stored watermark**, not by what is in the
tables. A brand-new install (watermark 0) pulls everything. But if the findings
or assets tables are emptied while the connector settings survive, the next run
is still incremental and fetches only the last day or so — nothing refills the
history. After clearing data, press **Full resync** (or send `full=true`).

---

## Pruning (Tenable-scoped, reversible, safeguarded)

On a **full resync only**, `Repo::retire_absent_tenable()` retires assets that
Tenable used to report and are absent from the full asset export (switch:
`prune_absent`, default on). Incremental runs never prune — their asset export
is only the recently scanned hosts. It is deliberately conservative:

- **Scoped to Tenable-owned assets.** Only assets with
  `primary_source = 'tenable'` and no id from any other connector
  (`intune_id`, `defender_id`, `azure_ad_device_id`, `azure_vm_id`,
  `aws_instance_id`, `gcp_instance_id`, `cmdb_id`, `cmdb_key` all empty) are
  candidates. Assets contributed by Intune, the CMDB, AWS, etc. are never
  touched.
- **Reversible, and reversed automatically.** Retirement goes through
  `Lifecycle::set( …, 'missing' )`: the row is not deleted, and its open
  findings are archived with their prior state remembered. The prune also
  records a **marker** for each asset it retires — the option
  `vulnhub_tenable_pruned_assets`, asset id → the lifecycle status it had
  before (plus when). Whenever a Tenable asset import (full *or* incremental)
  sees a marked asset again, `Repo::restore_pruned_tenable()` returns it to that
  exact status through `Lifecycle::set()`, so its archived findings come back
  from `prev_state`. This happens per asset chunk, before any findings are
  imported, and the sync log says `Returned N asset(s) to "<status>"…`.
- **A person's decision wins.** Only the prune's own retirements are undone.
  Any other lifecycle change to a marked asset — somebody marking it retired,
  lost, or even `missing` on purpose, or returning it to service by hand —
  fires `vulnhub_lifecycle_changed`, and `Repo::forget_pruned_tenable()` drops
  its marker, so a later scan leaves that decision alone. An asset whose status
  is no longer `missing` when it is seen just loses its marker. (The prune writes
  its markers *after* its own move, and the restore removes them *before* its
  move, so neither erases or re-triggers itself through that listener.)
  Retirements made before this marker existed have none and stay *missing*
  until someone returns them to service.
- **Safety abort.** If the set of "seen" uuids is empty, or more than 15% of the
  candidate assets would be retired in one run, the prune aborts and retires
  nothing — a truncated or failed export can't wipe the fleet.

---

## Removals: what the source says it dropped

Pruning infers removal from **absence**, which is why it only runs on a full
resync and needs the 15% abort. The asset export can also be asked the
question directly, and that is a different and better kind of evidence:

| filter | means |
|---|---|
| `is_deleted` + `deleted_at` | Tenable deleted the asset record, with the timestamp |
| `is_terminated` + `terminated_at` | the machine was terminated, with the timestamp |

`VulnHub_Tenable_Connector::sync_removals()` runs two small exports in the
finalize phase of **every** run -- incremental, full and assets-only -- and
hands the uuids to `Repo::retire_removed_tenable()`. Both cost seconds against
the vulnerability export's minutes.

Two exports and not one, because the flags are separate booleans: asking for
both true in a single export means deleted **and** terminated, a much smaller
set than the union.

**No safety abort, deliberately.** The prune aborts over 15% because a
truncated export makes the *absent* set longer, which is the direction that
wipes a fleet. Here truncation can only make the list shorter, and a short list
retires too few -- the safe direction. The reasoning is recorded on the method
so nobody adds the abort back by analogy.

Same scope and same marker as the prune: only assets Tenable owns outright
(`primary_source = 'tenable'` and no id from any other connector), retired
through `Lifecycle::set( …, 'missing' )` so their findings are archived with
`prev_state`, and every retirement recorded in `PRUNED_OPTION` so
`restore_pruned_tenable()` brings the asset and its findings back if Tenable
ever reports it again.

**What it found on first run here**, which is the reason it exists: Tenable had
deleted 766 assets and terminated 261 in the preceding 90 days. Twelve of those
were in this estate and **still counted as in service, carrying 108 open
findings** -- remediation work queued against machines that no longer exist.
Eleven were retired; the twelfth was left alone because another source also
knows it, which is the scope rule doing its job. Until this existed they would
have sat there until a full resync noticed they were absent, up to a week.

## Two cadences: the cheap half and the expensive half

The inventory changes by the minute and the findings do not. So they have
separate schedules, and a run consults both:

| setting | question | cost here |
|---|---|---|
| *Refresh assets every* (`assets_interval_hours`) | is the cheap half due? | ~3 s, 574 records |
| *Import findings at most every* (`findings_interval_hours`) | is the expensive half due? | ~15 min, 5 GB |

A **scheduled** run takes the assets-only path when the first is due and the
second is not. Everything else is unchanged: *Sync now* always imports
findings, *Sync assets only* never does, and a full resync ignores both --
"everything the source holds" cannot mean half of it.

**One test was not enough.** `assets_only_due()` shipped on its own, and it can
only ever *downgrade* a run that was going to happen anyway. With the connector
on an hourly schedule and assets due every hour, every single run became
assets-only and the vulnerability export never ran at all. The expensive half
needs its own "am I due" test, which is `findings_due()`, measured from
`sync_watermark` -- precisely "when a run last imported findings", because an
assets-only run deliberately does not advance it.

A worked example, from this estate:

```
connector schedule       hourly
assets every             1 h
findings at most every   24 h

cron tick          -> assets only          7 s
Sync now           -> assets + findings   ~15 min
Sync assets only   -> assets only          7 s
Full resync        -> everything          ~16 min
```

Twenty-three of every twenty-four scheduled runs are now seconds long, and the
inventory -- including anything Tenable has removed -- is never more than an
hour stale.

## Client polling limits

Because a large export can take a while to become ready on the vendor side, the
client polls patiently: `POLL_TIMEOUT_SECONDS = 3600` and
`POLL_MAX_ATTEMPTS = 1200`. `run_export()` accepts an `$on_poll` callback that
fires a heartbeat on every poll, so long gaps between chunks while the vendor
prepares the next batch are not mistaken for a stalled sync.

---

## Stall detection and status

`VulnHub_Logger::sync_status()` is what the connector card and the dashboard poll
for live progress. It reports the current phase, both progress bars (download
bytes/rate/ETA and processing records), the exact last-sync timestamp and
duration, and reaps a genuinely stuck run: a run whose heartbeat has been silent
past `STALL_SECONDS` (600s) is marked failed rather than left "syncing" forever.

For this to reap only *genuinely* stuck runs, every long-running phase must keep
its heartbeat fresh: the download reports per chunk and on every vendor poll
(`$on_poll`), and processing heartbeats every `PROGRESS_HEARTBEAT` findings within
a chunk. A big-but-healthy chunk import that reported only at the chunk boundary
would otherwise cross 600s of apparent silence and be falsely reaped.

---

## Adding staged sync to another connector

1. Route `do_sync()` to a staged path for live data and a direct path for mock.
   If the source supports incremental pulls, return `true` from
   `supports_full_sync()`, honour `request_full_sync()`, and decide full vs
   incremental once per fresh run, stored in the state.
2. Implement `download_to_disk()` / `process_from_disk()` / `finalize_sync()`
   against `VH_Tenable_Store` (or a per-connector store built the same way).
3. Return `true` from `resumable_sync()` while a run is in a resumable phase.
4. Report progress through `Logger::stage_progress()` so the shared UI renders
   both bars with no connector-specific front-end code.
