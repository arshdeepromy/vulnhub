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

On a **full** sync only, assets the scanner has dropped are retired (see
*Pruning* below), rollups are recomputed, the watermark is advanced, and the
staging directory is wiped.

---

## Resumability

Every step writes a checkpoint to `state.json` (atomic temp-file + rename, so a
checkpoint is never read back half-written). The state carries the phase, the
`since` watermark for the run, whether it is a full sync, and per-phase progress:

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
cron worker rather than the web request.

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

## Incremental and gap-safe

After the first successful full pull, syncs are incremental:

- **Watermark with overlap.** `since_for_run()` returns the last successful
  watermark minus a 24-hour overlap window, so a finding that changed right on the
  boundary is never skipped. The first sync looks back `first_sync_days` (default
  3650, i.e. effectively all history).
- **Watermark advances only on success.** `advance_watermark()` runs in
  `finalize`, so a failed or interrupted run never moves the boundary forward and
  never leaves a gap.
- **Vendor `since` covers both directions.** Tenable's `since` filter returns
  both still-open findings (by `last_found`) and newly fixed ones (by
  `last_fixed`), so an incremental pull sees closures as well as new detections.
- **Skip-unchanged.** `Repo::upsert_finding()` has a fast path that skips
  re-writing a finding whose state has not changed, so an incremental run touches
  only what actually moved.

---

## Pruning (Tenable-scoped, reversible, safeguarded)

On a full sync, `Repo::retire_absent_tenable()` retires assets that Tenable used
to report and no longer does. It is deliberately conservative:

- **Scoped to Tenable-owned assets.** Only assets with
  `primary_source = 'tenable'` and no id from any other connector
  (`intune_id`, `defender_id`, `azure_ad_device_id`, `azure_vm_id`,
  `aws_instance_id`, `gcp_instance_id`, `cmdb_id`, `cmdb_key` all empty) are
  candidates. Assets contributed by Intune, the CMDB, AWS, etc. are never
  touched.
- **Reversible.** Retirement sets `lifecycle_status = 'missing'`; it does not
  delete the row. If the asset reappears in a later scan it comes back.
- **Safety abort.** If the set of "seen" uuids is empty, or more than 15% of the
  candidate assets would be retired in one run, the prune aborts and retires
  nothing — a truncated or failed export can't wipe the fleet.

---

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
2. Implement `download_to_disk()` / `process_from_disk()` / `finalize_sync()`
   against `VH_Tenable_Store` (or a per-connector store built the same way).
3. Return `true` from `resumable_sync()` while a run is in a resumable phase.
4. Report progress through `Logger::stage_progress()` so the shared UI renders
   both bars with no connector-specific front-end code.
