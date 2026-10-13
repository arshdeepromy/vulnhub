# Instance sync (one-way replication)

`vulnhub-replica` keeps one instance a read-only copy of another. The source
hands out a **sync key**. The copy is given the source's address, the key and
a frequency. After that, the copy pulls on its schedule. Nothing has to be
reconfigured on the copy: no scanner, ticketing, cloud or firewall credentials,
and no mapping work. It receives the data those integrations produced on the
source.

Both halves are in one plugin, so any instance can be a source, a copy, or
both (a chain).

## Setting it up

On the **source**: portal admin → **Instance sync** → *Create a sync key*. The
key (`vhr_…`) is shown once. Only its SHA-256 is stored. You can also run
`wp vulnhub-replica key-create --label="lab copy"`.

On the **copy**: Integrations → **Instance copy (one-way sync)**. Enter the
source address and the key, switch it on, pick a frequency and save. *Test
connection* reports the source's size and any code differences.

The two instances can be on different networks. The copy only makes outbound
HTTP(S) requests to the source. Use https when that path is not private: the
key and the data travel in the requests.

## What a run does

Each run has three phases, and each one can be resumed.

1. **Prepare.** The copy fingerprints every table it holds and posts the
   fingerprints to the source. The source fingerprints its own tables and
   works out what differs. It writes the differing rows as gzip'd JSON lines,
   one file per table, zips them and cuts the zip into fixed-size chunks
   (2–32 MB, set on the copy). It hashes each chunk with SHA-256. The copy
   drives this in time slices of about 20 seconds (`POST /jobs/{id}/step`), so
   the build never depends on the source's own cron. That cron may be busy for
   an hour with a scanner import.
2. **Download.** The manifest gives the chunk count, each chunk's size and
   hash, the total size and the total row count, before a byte is fetched. The
   progress bars on the connector card come from these numbers. Each chunk is
   streamed to disk and checked. A chunk already on disk and verified is never
   fetched again. A failed chunk is retried four times; after that the run
   stops and the next run carries on from the same chunk.
3. **Apply.** The chunks are joined and the whole archive is checked against
   the source's hash. Then it is unzipped one table at a time:
   - **Integer-keyed tables** are applied by key range, one transaction per
     range. Rows the source no longer has in the range are deleted, and the
     rest are upserted. Most rows in a changed range are usually unchanged,
     and an upsert of an unchanged row costs a key lookup. A delete-and-insert
     would rewrite every secondary index. The range is the unit of
     resumption: a killed run redoes at most the range it was in.
   - **Other tables** (composite or string keys) are rebuilt beside the live
     table and swapped in with `RENAME TABLE`. The swap only happens if the row
     count matches the manifest. A short file is not a smaller table.
   - Then the settings are applied (see *What travels*).

When it finishes, the copy tells the source to delete the package
(`DELETE /jobs/{id}`) and removes its own files. It busts the widget caches the
same way a connector does after it writes: they move to a new epoch and are
rebuilt in the background while the last ones keep serving. It records each
source connector's last run in its own run history (marked `source`), so
"last refreshed" lines read the source's times rather than "never". Then it
records a summary on the Instance sync screen.

### Fingerprints

A fingerprint is computed in the database, never in PHP.

- **Per row:** the first 64 bits of an MD5 over every shared column. NULL is
  kept distinct from the empty string.
- **Per bucket:** the row count and the XOR of the row hashes. A bucket is
  1,000 key values on an integer-keyed table; any other table is a single
  bucket.

XOR is order-free, so the database never sorts. A changed, added or removed
row changes its bucket.

The largest table here, about 480k rows, takes about 12 seconds to
fingerprint. Results are cached on disk, keyed on the table's own
last-write time. A table nothing has touched since the last run costs nothing.
The cache is only used when that write time is more than 5 seconds old,
because it has one-second resolution. The cache is on disk, not in the object
cache: that is an LRU with a memory cap, and a large table's fingerprints are
the first thing it would evict.

Changed buckets next to each other are merged into one range, up to 5,000
rows. On a first sync every bucket has changed. Without the cap the whole
table would be one transaction. Without merging it would be a thousand tiny
ones.

Fingerprints are only comparable over the same columns in the same order.
Both ends use the columns they share, in the source's order. Generated columns
are left out on both ends: they are computed by the database that holds them.

### Measured (Pi, both instances on one box)

| Run | Package | Rows | Time |
|---|---|---|---|
| First sync into a fresh install | 123 MB, 16 × 8 MB | 740k across 46 tables | 8 min (apply ~6 min) |
| ~12 min later, source busy | 58 MB, 8 chunks | 172k across 11 tables | 4 min |
| Next run | 1.7 MB, 1 chunk | 3k across 3 tables | 57 s |
| Nothing changed | 70 KB (settings only) | 0 | ~65 s, mostly fingerprinting a cold cache |

The copy's database in that test had a 256 MB buffer pool, so its apply times
are pessimistic.

## What travels, and what never does

**Tables.** Every `{prefix}vulnhub_*` table with a primary key, except those
that describe the instance rather than the estate:

- `audit` and `sync_runs`: each instance keeps its own history
- `mcp_tokens` and `replica_tokens`: credentials
- `backup_jobs` and `import_jobs`: that instance's own work

The list can be changed with the `vulnhub_replica_excluded_tables` filter. A
table the source has and the copy lacks, because a feature creates it on first
use, is created on the copy from the source's `SHOW CREATE TABLE`. Only a
single `CREATE TABLE` for exactly that name is accepted. Columns only one side
has are skipped.

**Settings.** `vulnhub_*` and `vh_*` options, except:

- secrets (`vulnhub_sec_*`, and anything named like a key, token, password or
  OAuth value)
- schema markers and seed flags: each instance migrates its own schema
- sign-in policy
- page ids
- cache epochs
- job and progress state
- the copy's own settings (`vulnhub_cfg_replica`, `vulnhub_cfg_mail`,
  `vulnhub_replica*`)

Connector settings (`vulnhub_cfg_*`) do travel, so links, mappings and
thresholds match. They are stripped of account identifiers (client ids,
access key ids, e-mail logins, export positions) and arrive **switched off**.
The platform-wide mock switch arrives off.

The same rules are checked again on the copy before anything is written. A
source running older rules still cannot write a secret or the copy's own
settings.

**Never:** WordPress users, posts, pages and the site's own options. The copy
keeps its own administrators and sign-in.

## Copy mode: a copy never acts on a real system

While the replica connector is switched on, `VulnHub_Replica_Guard` enforces
five independent things:

1. **No other connector syncs.** Core's `vulnhub_connector_sync_blocked`
   filter refuses them with a reason, including *Sync now* and mock runs.
2. **No VulnHub background job runs**, except the copy's own sync, widget
   cache warming and refresh, backups and imports, and the package sweep.
   Backups to S3 still meet guard 3. At
   `wp_loaded`, every other `vulnhub_*` or `vh_*` cron hook, plus
   `vulnhub_verify_closures` and `vulnhub_run_automations`, has its callbacks
   removed. This is deny-by-default, so a job added later is stopped on a copy
   without anyone remembering this list. This covers automations, closure
   verification, alert polling and digests, ticket checks, agent status,
   threat feeds, snapshots and housekeeping. Housekeeping is included because
   it would rework data the source already worked; the copy trims its own
   logs itself.
3. **Outbound HTTP goes to the source and nowhere else.** The site's own
   loopback, localhost and WordPress.org updates are also allowed. Extend the
   list with `vulnhub_replica_allowed_hosts`.
4. **Email is held** unless *Let this copy send email* is ticked. The copy
   holds real people's addresses.
5. **Connector settings arrive off and without credentials** (see above).

Coverage is not recalculated after a replica run: the copy received the
source's computed state. Core asks `Connector::recalculate_after_sync()`, and
the replica answers false.

A banner on every portal page and in wp-admin says the instance is a
read-only copy, which source it copies, and when it last synced. The Instance
sync screen counts what each guard has held back.

Changes made on a copy are overwritten at its next sync, because their
buckets no longer match.

## Safety rails

- **Shrink guard.** A source table that now has less than half the rows the
  copy has (over 1,000 rows) is held back and reported, not applied. An
  emptied source and a real clear-out look the same from the copy. Turn on
  *Allow a table to shrink by more than half* to accept it. The first sync
  and *Rebuild everything* are exempt.
- **Lost package.** If the source no longer has the package (expired after a
  day untouched, key revoked, replaced by a newer request, or the source was
  rebuilt), the copy asks for a new one once.
- **Back-off.** A failed run keeps its checkpoint. The resume sweep (every
  5 min) retries it after 15 minutes, not every 5.
- **One package per key.** A new request drops that key's previous package.
  Packages untouched for a day are swept daily (`vulnhub_replica_sweep`).
- **Self-sync refused.** Each instance has its own id
  (`vulnhub_replica_instance`, never copied). A copy pointed at itself
  refuses.
- **Interrupted runs.** A run killed mid-way leaves its row "running". The
  next run marks it failed ("Interrupted. Run #N carried on from its
  checkpoint.").

## Endpoints (source)

Namespace `vulnhub-replica/v1`. Every route needs the key in
`X-VulnHub-Replica-Token` (or `Authorization: Bearer`). No route accepts a
WordPress login. A key can read through these routes and do nothing else.

| Route | |
|---|---|
| `GET /manifest` | Instance id, plugin versions, tables (key, columns, approximate rows, DDL) |
| `POST /jobs` | Start a package from the copy's schema and fingerprints |
| `POST /jobs/{id}/step` | One build slice; returns `step`, `pct`, `note`, and the manifest when ready |
| `GET /jobs/{id}` | Status without working |
| `GET /jobs/{id}/chunks/{n}` | One chunk, raw bytes, `X-VulnHub-Chunk-Sha256` |
| `DELETE /jobs/{id}` | The copy has it |

Packages are kept in `wp-content/vulnhub-replica/`, outside uploads, with an
`.htaccess` deny. The `out/` directory holds the source's packages, `in/`
holds the copy's downloads and `fp/` holds the fingerprint cache.

## Command line

```bash
wp vulnhub-replica key-create --label="lab copy" [--days=90]
wp vulnhub-replica key-list
wp vulnhub-replica key-revoke <id>
wp vulnhub-replica sync [--full]     # copy side, in this process
wp vulnhub-replica status
wp vulnhub-replica sweep
```

## Bringing up a copy

A copy is an ordinary install of the same code: clone, `docker compose up`,
activate the plugins (including `vulnhub-replica`), then configure the
connector as above. The fresh install's mock fleet is replaced by the first
sync.

If the copy runs on the same host as the source, give it its own compose
project, container names, ports and network. The stock compose file hard-codes
the container names.

## Not yet

- Bucket width is fixed at 1,000 ids. When a source rewrites a column on a
  thin slice of rows spread across a table, most buckets change. A two-level
  fingerprint would narrow that.
- Deletes on a table without an integer key cost a full rebuild of that table.
  The largest such table here is about 37k rows.

