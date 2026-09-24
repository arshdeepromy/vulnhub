# AppStream: one record per fleet, and duplicate cleanup in Tenable

An AppStream fleet starts a fresh streaming instance on demand, each a new EC2
with a new random computer name. A Tenable agent baked into the image registers
a **brand-new asset every time** — dozens of one-shot records that all stand for
the same fleet, only one of which is alive now. This tool finds them, keeps the
most-recent, and deletes the rest through the Tenable API. A topbar bell
surfaces the count.

Plugin: `vulnhub-tenable`, `class-vh-tenable-appstream.php`. Screen: **AppStream
cleanup** (`/appstream-cleanup/`, view `appstream`, hidden — reached from the
bell).

## Detection

The signature is a **15-hex computer name with no NetBIOS name**
(`^[0-9a-f]{15}$`), overridable with the `vulnhub_tenable_appstream_regex`
option. `candidates()` selects live assets matching it (excluding rows already
dropped or de-duplicated), newest `last_seen` first.

`summary()` returns:

- `keep` — the most-recently-seen instance. It is **never** deletable; it is the
  one that "maps back to Tenable" (it usually still carries a `tenable_uuid`).
- `redundant` — everything older, each flagged `deletable` (has a `tenable_uuid`)
  and `stale` (unseen for > 7 days).
- `total`, `redundant_count`, `deletable_count`, `stale_count`.

Only assets with a `tenable_uuid` are deletable through Tenable; the same hex
name arriving from Defender/Intune has no Tenable record, so it is shown but
marked "no Tenable UUID".

## Deleting

`delete_one( $asset_id )` guards hard: it refuses the most-recent instance and
any row without a UUID, then calls `client()->delete_asset( $uuid )`. On success
the local row is marked `tenable_dropped_at` + `lifecycle_status = retired`, so
it leaves the candidate list, and `vulnhub_tenable_appstream_deleted` fires.

### Which delete route, and the field name that broke it

Tenable has two delete routes and only one of them is usable here.

`DELETE /assets/{uuid}` is scope-gated. On a key without the Administrator role
it answers `403 {"error":"Forbidden","message":"Insufficient scope"}` — which is
what this tenant does, on every asset. The supported route is the asynchronous
**bulk-delete job**, `POST /api/v2/assets/bulk-jobs/delete`, which the Scan
Operator role (or the `VM.VM_EXPLORE.VM_EXPLORE.DELETE` privilege) can run. That
is now the only call made; trying the single-asset route first bought nothing
but a guaranteed 403 per asset.

The job's filter field is **`host.id`**, not `id`:

```json
{ "query": { "or": [ { "field": "host.id", "operator": "eq", "value": "<uuid>" } ] } }
```

`id` is not in the asset filter vocabulary — `GET /filters/workbenches/assets`
lists `host.id` and no bare `id` — and Tenable rejects it with

```json
{"response":{"data":{},"error":{"title":"BAD_REQUEST","detail":"Bad Request"}}}
```

which names no field, says nothing about the filter, and is the whole reason
the first version of this tool looked like it worked and deleted nothing. Every
click returned HTTP 200 from our own REST route carrying a `failed` list nobody
had a reason to read closely.

### A 202 is not proof of a delete

The job is asynchronous: it answers `202` with the number of assets the filter
matched, and **a filter that matches nothing is still accepted**, with
`asset_count: 0`. So `delete_asset()` returns
`{ ok, deleted, status, count, message }` rather than a bare response, and
`deleted` is `count > 0`. A 2xx with `asset_count: 0` is reported honestly —
"Tenable holds no asset with that id" — and counted separately from a real
delete in the REST reply (`deleted` vs `gone`). Without that, the exact shape of
the `id`/`host.id` bug — accepted, zero matched, row quietly marked dropped —
reads as success.

Nothing deletes on its own. The panel's per-row **Delete** and **Delete all N
redundant** buttons each confirm first and call
`POST vulnhub-tenable/v1/appstream/delete` (`Caps::MANAGE`) with `{ ids: [...] }`;
the list route is `GET vulnhub-tenable/v1/appstream` (`Caps::VIEW`).

## The bell

`notify()` hooks `vulnhub_notifications` (see `docs/PORTAL.md`) and contributes a
`warn` notice — *"N assets are AppStream streaming instances. The most recent is
X; M stale duplicates can be deleted."* — with `count = deletable_count` and a
`url` to the panel. It is suppressed when there is nothing to act on
(`total < 2` or `deletable_count < 1`).

## The panel

`assets/appstream.{js,css}` fetch the summary and render: the stat row (total /
deletable / stale + the signature regex), the green **KEEP** card (most recent,
and whether it maps to Tenable), and the redundant table with per-row and bulk
delete. The status line after a run reads `N deleted`, plus
`M already gone from Tenable` and `K failed — <message from Tenable>` when
either applies. `manage`-less viewers see the list read-only.

## Verifying

`./lint.sh`; exercise `summary()` with `wp eval-file` against the live DB to
confirm the keep/redundant split **without deleting anything**. A real delete
calls the live Tenable API and removes the asset there — only ever triggered by
an operator's click, never as a test. Data hygiene: the hex names are not
sensitive, but never copy real hostnames or asset ids into the tree.

## One record per fleet

The cleanup above deletes stale session assets *in Tenable*. It never gave the
estate one thing to look at: every session was still a row here, Intune and
Defender added their own copies of each session, the image builder showed up
under `EC2AMAZ-…` names, and the Assets filter listed the fleet dozens of
times. There was nothing single to raise a golden-image ticket against or to
watch progress on. `VulnHub\Core\Fleets` (core) keeps each fleet as **one
asset record**.

### Discovery, from the AWS capture

AWS names every AppStream network interface after what it belongs to:
`AppStream 2.0 - fleet: <name> - <id>` and
`AppStream 2.0 - image-builder: <name> - <id>`. `Fleets::discover()` reads
those from the network capture: the fleets, their account, their subnets --
and, since the capture now records each subnet's `cidr`, the address ranges.
Image builders in the same account add their subnets to the range (they build
the image the fleet runs). `refresh_config()` folds that into the setting
`vulnhub_fleets` after every AWS sync; the busiest fleet of an account is its
*primary*. The definitions live in the setting, never in code: they name the
estate's own accounts and ranges.

Nothing is folded until the setting's `enabled` flag is on. `absorb( true )`
is the dry run: which rows, into which fleet.

### Membership

An address inside a fleet's ranges; when several fleets share a range, the
interface the capture holds for that address names the fleet, else the
primary. A record with no address (an old enrolment) belongs to the primary
fleet when its name is the 15-hex session name and it runs Windows.

### Routing, before matching

`Repo::upsert_asset()` asks the `vulnhub_asset_route` filter *before* it
matches anything:

- **The scanner** (`tenable`, `tenable-csv`): `fold` -- the record is written
  onto the fleet record, and only what a session may say about the fleet is
  kept (last seen and scanned, OS, agent, address, the newest session's
  Tenable id), and only when it is newer than what is held: sessions arrive
  in no order, and an older one must not wind the clock back. Its Tenable
  asset id is kept in `vulnhub_asset_aliases`.
- **Everything else** (Intune, the CMDB, Defender, …): `ignore` -- the call
  returns `{ id: 0, ignored: true }` and nothing is written. Asked first
  because matching is what goes wrong: an Intune enrolment would re-match, and
  un-retire, a folded row -- the way an earlier duplicate merge came undone on
  the next CMDB sync. The CMDB connector counts these as skipped, not failed.

The Tenable finding import looks assets up by Tenable id; for a session's id
it falls back to the alias table, so the finding lands on the fleet record.
`upsert_finding()` takes `newer_only` for fleet findings: a finding older than
the one held is not written.

### Latest scan wins

`Fleets::reconcile()` after every Tenable sync. All sessions run one image, so:

- a finding reported within two days of the newest session's scan is
  **current** -- restored to open if a session's retirement had archived it;
- an open finding older than that is **gone from the image** -- closed as
  fixed, dated by the scan that no longer saw it. If a later session reports
  it again it reopens the usual way.

The two-day window is because sessions run side by side and their agents scan
at different times.

This is what makes a golden-image upgrade read as progress: raise the ticket
against the fleet record, and as sessions on the new image are scanned, its
findings close.

Found on the first run: before the fleet record existed, every session's row
was retired when AWS terminated the instance, archiving its findings with it.
The image's *current* vulnerabilities were the hidden ones, while an older
session nobody had retired kept stale findings open. The reconcile restores
the first and closes the second.

### Folding what is already there

`Fleets::absorb()`: each member row's findings move to the fleet record
(`Duplicates::move_findings()`, newer copy wins, never deleted), its Tenable
id becomes an alias, and the row is retired with `duplicate_of` pointing at the
fleet record. Unlike `Duplicates::merge()`, nothing is copied onto the
survivor: a fleet record must not take on one session's instance id, serial or
sources.

### Where it shows

- **Lists** (`Repo::assets()`) leave out rows merged into another --
  retired with `duplicate_of` set -- unless retired assets are asked for, so
  the fleet appears once. A row the duplicate scan only *flagged* is still
  listed.
- **The fleet record**: `AppStream fleet: <name>`, type server,
  `primary_source = fleet`, tags `appstream`, `golden-image`, `fleet:<name>`.
  The Tenable removal sweeps never retire it (it carries the newest session's
  id, and sessions are terminated as a matter of course).
- **This screen** still lists folded sessions that Tenable holds, so the
  cleanup there keeps working.

### Checked on the live estate

36 rows (Tenable sessions, Intune enrolments, Defender image-builder records)
folded into one; 10 session ids kept as aliases. After the reconcile the
record held the image's 13 current findings, and 51 superseded ones were
closed. A simulated new session from Tenable folded into the record, the same
session from Intune was ignored, and an ordinary laptop was created as usual.
