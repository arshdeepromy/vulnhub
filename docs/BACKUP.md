# Backup and restore

`vulnhub-backup` takes the whole platform — every table and everything under
`wp-content` — and produces **one file you can download, keep, and hand back to
restore**. It runs in timed passes against a database that is already hundreds
of megabytes, so nothing here reads a whole anything into memory.

---

## The artifact

A finished backup is a single archive:

```
backup-<date>-<time>-<id>.tar.gz
  ├── manifest.json     what this is, and the checksums of the other two
  ├── db.sql.gz         the database dump
  └── wp-content.zip    everything under wp-content
```

`wp-content.zip` holds the whole tree — plugins, themes, uploads, mu-plugins,
languages and top-level drop-ins such as `object-cache.php`. Left out: the
backup store itself (`uploads/vulnhub-backup/` — a backup cannot contain
itself), WordPress's scratch folders (`upgrade/`, `cache/`) and `*.log`.

**Credentials are in the dump, encrypted — the key is not.** Connector secrets
live in `vh_options` as `vhenc1:` ciphertext, and the key that opens them is
`VULNHUB_ENCRYPTION_KEY`, injected from `.env` by `docker-compose.yml`. Neither
`.env` nor `wp-config.php` is inside the container's `wp-content`, and a key
stored beside its ciphertext protects nothing. **Keep `VH_ENC_KEY` somewhere
safe on its own**: restored onto a stack with a different key, every connector
credential has to be entered again.

It used to be a *folder* holding those three files, which meant "take a backup"
produced three things to download and keep together, and restoring meant
getting all three back into one place. One file is the whole point: download
it, store it, upload it, done.

The name is built in **site-local time** (`wp_date()`), because it is the one
timestamp somebody reads when choosing what to restore. Everything stored or
compared inside stays UTC — see the timezone rules in `docs/CORE-API.md`.

When packing finishes, the working folder is deleted and the archive's own
**sha256 and size are recorded on the job**, so a downloaded copy can be
verified against what the server believes it wrote.

### How it is written

A `package` phase sits between *files_archive* and *upload*. It streams 1MB at
a time into an appending `gzopen` handle and checkpoints its cursor (member
index + byte offset) like every other phase, so packing 150MB never has to fit
inside one pass or one request.

**Hand-written ustar headers plus `gzopen`** — not `PharData`, which builds an
uncompressed `.tar` first and compresses it afterwards (two passes, and a
second full-size copy on disk) and is unavailable anyway with `phar.readonly`
on. Not `tar(1)` either: most passes run in the cron container, a different
image from the web one, so "tar exists" is not a safe assumption for the code
path that produces your backups.

The result is a plain gzip-compressed tar. `gzip -t`, `tar -tvzf` and `tar -xzf`
all accept it, which matters: a backup you can only open with the thing that
broke is not much of a backup.

### Crash safety, and proving the result

Every phase appends to a file across passes and records its cursor in the job
row. The row is durable the moment MariaDB commits it; the appended bytes are
not, until the kernel writes them. A host that went down in between (a WSL VM
restart did exactly this) left the cursor ahead of the file: the next pass
carried on after a run of zero bytes, **every gzip reader stopped at those
zeros**, a restore would have loaded 46 of 62 tables — and the job still said
*done*. So:

- **sync before checkpoint.** `VulnHub_Backup_Storage::sync_file()` fsyncs the
  dump / archive and records its byte length in the cursor *before* the cursor
  is committed.
- **rewind on resume.** `rewind_to_checkpoint()` cuts a file that is longer
  than its checkpoint (a batch written but never recorded — it would land
  twice) and starts the phase over when it is shorter (bytes lost).
- **The zip resumes from what it really holds** — its `numFiles`, not the
  cursor — and must hold every listed file before the phase ends.
- **The dump is read back before the job moves on.** `count_dump()` reads
  `db.sql.gz` with the same reader a restore uses and fails the job unless it
  finds every table and row the export counted. `tables_total` and
  `rows_exported` go into `manifest.json` so a restore can check itself too.

To check a set by hand: `gzip -t db.sql.gz` (catches trailing garbage), then
count `^CREATE TABLE` and `^INSERT INTO` against the manifest.

### Downloading

The download links carry the core `wp_rest` nonce (`_wpnonce`). Without it the
REST API ignores the login cookie, treats the request as anonymous, and the
download answers **401 rest_forbidden**.

---

## Restoring

Upload the one file. Restore **sniffs the first bytes** rather than trusting
the extension:

- gzip magic → the new single-archive path
- `PK` → the old three-file `.zip` bundle
- anything else → refused, with a message naming what to upload

Folder-shaped backups already on disk still list, download per file, and
restore. **Backups taken before this change keep working** — a backup format
that strands your existing backups is a worse problem than the one it solves.

Before anything destructive happens, the manifest is read and each member's
sha256 is checked against it. A truncated archive is caught structurally (gzip
CRC, a short read mid-member, or a missing tar end marker) and refused. A
member whose path tries to escape the staging directory — `../../wp-config.php`
— is refused by name.

There is no checksum of the archive inside the archive, because a file cannot
contain its own hash; that is what the sha256 recorded on the job is for.

### Applying the dump

- **Inflated once, then seeked.** `gzseek()` on a read stream gets there by
  decompressing from the start, so every pass re-read everything before its
  offset — thousands of passes over a gigabyte. The dump is decompressed to
  `db.sql` in staging once, and each pass `fseek()`s straight to its offset.
- **Whole statements only.** Rows run to megabytes (plugin output on a
  finding); a fixed 64KB `gzgets()` handed back fragments, and a batch that
  ended mid-statement threw the fragment away. Lines are read whole, and a
  batch ends only between statements.
- **Failures are counted, not swallowed.** A failed statement is recorded and
  the dump carries on — a half-applied dump is worse than a complete one with
  a named gap — but the job ends **failed**, naming the count and first error,
  and also fails if the tables and rows applied differ from the manifest.
- **The object cache is flushed** once the dump is in, or Redis goes on
  serving the pre-restore options and users.

### The files swap

The restored `wp-content` is renamed into place and the old one moved into
staging, which is deleted when the job finishes. Before that, **the backup
store and anything at the top level the bundle does not carry are moved
back** — otherwise a restore deleted every local backup set (and the upload it
was restoring from), `object-cache.php` from older bundles, and the logs. The
swap is safe to resume if a pass dies between the rename and the phase change.

---

## Running one, and what it costs

**Administration → Backup → Backup now.** The click queues the job and returns
immediately; the panel then follows it, showing the phase, tables, rows, files
and bytes, and stops polling when the job reaches a terminal state.

A backup reads every table and every file, so **the app is slower while one
runs** — the screen says so, with the last run's real duration rather than a
vague warning. On the current dataset that is around a minute for ~145MB
(584k rows, 5,754 files).

### Three things that made this worse than it needed to be

Worth writing down, because each is the kind of thing that gets reintroduced by
a well-meaning change:

1. **The browser was attacking the server.** The old script polled every 5
   seconds and, for each running job, POSTed a pass that executes a
   **12-second** slice of the backup *inside that web request* — without
   waiting for the previous one to answer. Up to three overlapping requests
   each held a PHP worker and a database connection while dumping tables. Only
   one ever did work (the lease is an atomic conditional update) but the rest
   still cost the web tier. That, not the backup, is what made the app crawl.
   One pass is now in flight at a time, polling stops at a terminal state, and
   a failed poll backs off.

2. **`start_new()` ran a pass inline**, so the "Backup now" POST blocked for up
   to `WEB_BUDGET` (12s) before it could even redirect. It queues and returns;
   the panel picks the job up.

3. **A cron pass could hold the cron lock for four minutes.** `CLI_BUDGET` was
   240s while the cron container wraps `wp cron event run` in `flock -n` on a
   60-second tick, and passes chain — so a cron-driven backup repeatedly blocked
   the tick and scheduled syncs, plus the staged-sync resume sweep, were skipped
   meanwhile. It is now **45s**, comfortably under the tick, so a backup
   interleaves with syncs instead of starving them.

Browser-driven passes were kept deliberately, and the numbers justify it: a
browser-driven job finished in **82s wall for 55.8s of work**, while a
cron-only job took **1,318s wall for 18.75s of work**, because each cron pass
waits for the next 60-second tick.

### The lease

A job is claimed with an atomic conditional update and a 300-second lease, so
two workers can never run the same pass. If the browser that started a job goes
away mid-run, the job sits until its lease expires and the 5-minute sweep picks
it up — which is also the crash-recovery path, and is worth exercising
occasionally rather than trusting.

---

## In the portal

All three forms (backup, settings, delete) redirect through `vh_admin_url()`,
so the portal's own redirect filter keeps you on the screen you submitted from,
and they carry `vh_from_portal` in case the referer is stripped. They used to
redirect to a hardcoded `admin_url( 'admin.php' )`, which threw portal-only
accounts out to the dashboard mid-backup.

`backup.css` / `backup.js` enqueue on the portal section as well as the wp-admin
screen. They previously loaded only in wp-admin, which is why the portal copy
of this screen had no progress bar at all: nothing was polling.
