# Jira Service Management Assets as a CMDB source

The CMDB connector had three back ends: ServiceNow, a Confluence page and a CSV
upload. This adds a fourth — Jira Service Management **Assets** (formerly
Insight) — read-only, over one endpoint, with the same mapping screen and the
same dry run the CSV importer has always had.

The short version: an Assets object is flattened into a `name => value` row, and
from that point on it *is* a spreadsheet row. It goes through the same detector,
the same mapping, the same normaliser, the same identity matching and the same
lifecycle rules. There is one set of rules in this connector, not two.

---

## The one endpoint

```
POST https://api.atlassian.com/ex/jira/{cloudId}
       /jsm/assets/workspace/{workspaceId}/v1/object/aql
     ?startAt={n}&maxResults=50&includeAttributes=true

Authorization: Basic base64(email:api-token)
Content-Type:  application/json

{ "qlQuery": "objectSchemaId = 6 AND objectType IN (\"Servers\", \"Computing Devices\")" }
```

The response carries `values[]`, `total`, `startAt`, `maxResults` and `isLast`.

`maxResults` is capped server-side at **50**, so a workspace of ~1,200 objects
always arrives over ~24 requests. Pagination is not optional and is not a
performance nicety; without it you silently import the first 50 objects and
believe the register is 50 assets long.

It is a POST because AQL is a body, not because anything is written. There is no
PUT, PATCH or DELETE anywhere in this feature, and the operator's token is
scoped to five read-only scopes, so a write would be refused by Atlassian even
if a code path existed. Not having the code path is the stronger guarantee.

## Why `includeAttributes=true` is never dropped

Atlassian answers **401** both for a wrong token *and* for a valid token whose
scopes do not cover part of the request. Because this call always asks for
attributes, a token that is missing `read:cmdb-attribute:jira` fails here while
working perfectly in the browser — which reads as "the token is wrong" and sends
the operator back to re-paste a token that was never the problem.

The tempting fix is to retry without attributes on a 401. That call succeeds,
and imports ~1,200 objects carrying nothing but a label: an inventory that
reports success and is worse than it was before. So the retry does not exist.
The 401 message names all five scopes and says which one is usually missing.

The five scopes: `read:cmdb-object:jira`, `read:cmdb-attribute:jira`,
`read:cmdb-schema:jira`, `read:cmdb-type:jira`, `read:cmdb-icon:jira`.

## Flattening

`VulnHub_Cmdb_Assets_Client::flatten()` turns one object into a row.

Attribute *names* are not carried on each value. The AQL response describes the
columns once per page in `objectTypeAttributes[]`, and older responses inline an
`objectTypeAttribute` on each attribute instead. Both are read; an attribute
whose name cannot be learned either way is dropped rather than guessed at.

Values are polymorphic. The rules, in order:

| Assets value | Becomes |
|---|---|
| `user` | `Display Name - email@example.com` |
| `displayValue` / `value` | itself |
| `referencedObject` | its `label` |
| `status` | its `name` |
| several values | joined with `, ` |

The user case is the one that matters. An Assets user attribute's display value
is a person's *name*, and a name cannot be looked up in the people table. The
`Name - email` shape is what `vh_split_person()` already understands and what
the live CMDB export uses, so ownership resolves without a second code path.

Five synthetic columns are added for what lives on the object rather than in its
attributes, prefixed so they cannot collide with a real attribute:

`Assets Object Id`, `Assets Object Key`, `Assets Label`, `Assets Object Type`,
`Assets Updated`.

## Mapping: three layers, most specific first

Attribute names belong to whoever built the workspace. Nothing here hard-codes
them. `VulnHub_Cmdb_Connector::assets_mapping()` resolves each canonical field
from, in order:

1. **What the operator saved** — `assets_map`, filtered to attributes that still
   exist. A renamed attribute falls back to detection rather than to nothing.
2. **`VulnHub_Cmdb_Schema::detect_mapping()`** — the same alias table and the
   same populated-column preference the CSV importer uses.
3. **The object's own fields** — the five synthetic columns above, applied last
   so a workspace with a real `Name` or `Serial Number` attribute always wins
   over the object's generic label.

Each layer only fills what the layer above left empty, so correcting one field
on the screen never throws away the rest of the detection.

The mapping is kept in `assets_map`, **not** in `column_map`. Both are
`field => column`, but the columns come from different vocabularies — a
spreadsheet's headings and a workspace's attribute names — and sharing one key
would silently re-map the source the operator was not editing.

Every run logs the attribute names it actually saw and the mapping it used, and
notes the canonical fields nothing matched. That is what turns "ownership is
still empty" into "the support group attribute is called Service Owner Group".

## Object type is authoritative

`Servers` → `server`, `Computing Devices` → `workstation`. The object type is a
class a human chose in Assets, which is stronger evidence than anything inferred
from an OS string — and stronger than what `Schema::asset_type()` can make of
it, since "Computing Devices" matches none of its patterns. The record is marked
`asset_type_source = explicit`, which is what lets `reconcile_asset_type()`
treat it as authoritative against another connector's guess.

A type that says nothing useful yields an empty string, so the record keeps
whatever the operating system and hostname implied rather than being overwritten
with `unknown`.

## Pagination and the runaway guard

```
startAt = 0
loop: POST …?startAt={startAt}&maxResults=50&includeAttributes=true
      collect values[]; startAt += 50
until isLast, or a short page, or count >= total, or the page guard
```

The guard is `ceil(total / 50) + 5`, capped at 400 pages. The five pages of
headroom mean a healthy workspace never reaches it, so reaching it means the API
stopped advancing — and a set that stopped early is indistinguishable, once
imported, from a CMDB that has shrunk. So hitting the guard **fails the fetch**
and imports nothing, rather than returning a partial set.

429 and 5xx are not handled here at all: `VulnHub\Core\Http` already retries them
with exponential backoff and jitter and honours `Retry-After`.

## The secret

The API token is the only secret in this feature.

- Stored in the connector's encrypted credential vault, like every other
  connector secret. Never written to a file of its own.
- Sent only in the `Authorization` header. Never in a URL, never in a query
  string, never in the request body.
- Never logged — not to the run log, not to the PHP error log, not into an
  exception message. The error messages this connector produces are fixed
  strings plus the API's own error text.
- Never returned. The settings screen renders a masked hint
  (`Crypto::mask()`), never the value; the input starts blank and leaving it
  blank keeps the stored token.

## What the operator does

1. **Integrations → CMDB**: set *Source system* to
   **Jira Service Management Assets (AQL)**, fill in the account email, the
   token, the cloud id, the workspace id, the schema id and the object types,
   and save. Enable the connector.
2. **Test connection** → *"Connected. N objects match."*
3. **CMDB → Jira Assets → Fetch and preview**. This reads the workspace and
   stages a dry run: how many assets would be created, how many updated, what
   would be rejected, and the attribute mapping it inferred.
4. Correct anything wrong in the mapping and **Update and save as default** —
   scheduled syncs use the saved mapping from then on.
5. **Import these objects**.

The cloud id and workspace id are deployment-specific and are *not* baked into
the plugin as defaults. They identify a particular customer's Atlassian site,
and this repository is public.

Unlike the CSV path, an Assets import does not stage a copy of its rows for
replay. It has a live source to go back to, so a scheduled sync re-reads the
workspace instead of replaying a week-old snapshot of it.

## What mock mode exercises

`VulnHub_Cmdb_Mock::assets_page()` builds the real AQL envelope — page-level
`objectTypeAttributes`, `values[]`, `total`, `isLast` — from the shared fixture
fleet, and the connector reads it back through the same flattener the live path
uses. The fixture's attribute names are deliberately *not* the canonical field
names (`Service Owner Group`, `Primary IP Address`, `Technical Owner`), because
a fixture whose attributes are already called what the schema calls them would
prove the detector works on a workspace nobody has.

Servers and workstations only. Network gear is left out rather than filed under
one of the two object types the connector asks for: a fixture that mislabels a
switch as a server would quietly bless the same mistake in the normaliser.
