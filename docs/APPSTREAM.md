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
any row without a UUID, then calls `client()->delete_asset( $uuid )`. That hits
`DELETE /assets/{uuid}` and falls back to a one-asset bulk-delete job if the
tenant has retired the single-asset route; a `404` counts as "already gone". On
success the local row is marked `tenable_dropped_at` + `lifecycle_status =
retired`, so it leaves the candidate list, and `vulnhub_tenable_appstream_deleted`
fires.

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
delete. `manage`-less viewers see the list read-only.

## Verifying

`./lint.sh`; exercise `summary()` with `wp eval-file` against the live DB to
confirm the keep/redundant split **without deleting anything**. A real delete
calls the live Tenable API and removes the asset there — only ever triggered by
an operator's click, never as a test. Data hygiene: the hex names are not
sensitive, but never copy real hostnames or asset ids into the tree.
