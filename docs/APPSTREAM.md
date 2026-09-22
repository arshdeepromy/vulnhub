# AppStream duplicate cleanup (Tenable)

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
