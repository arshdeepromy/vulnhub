# Akamai (the public edge)

`vulnhub-akamai` reads Akamai's OPEN APIs and answers the one question no AWS
API and no DNS record can: for a public name, **which property serves it, which
origin that property actually sends it to, and whether a WAF policy covers it**.
It is the middle of the chain the Internet exposure page draws —
public name → property → WAF policy → origin → Route 53 → AWS resource → asset
(see `docs/AWS-NETWORK.md` for the AWS half).

Read-only throughout. The API client needs nothing but READ on Property Manager
and Application Security; the connector never activates a property, never edits
a configuration, and never makes a request to any hostname it discovers.

## Credentials

Akamai does not issue bearer tokens. In Control Center, **ACCOUNT ADMIN →
Identity & access → API clients**, create a client with READ-ONLY on *Property
Manager (PAPI)* and *Application Security*, then download the credentials file —
the client secret is displayed once and cannot be recovered afterwards. It gives
four lines, which map to the four required settings:

| Credentials file | Setting |
| --- | --- |
| `host` (without `https://`) | API host |
| `client_token` | Client token |
| `access_token` | Access token |
| `client_secret` | Client secret (encrypted at rest) |

**Account switch key** is left blank for an ordinary account-level client. It is
only for a credential issued against one account that must read another, and it
rides along as `accountSwitchKey` on every request.

Creating an API client needs an admin role. A Full Viewer cannot — the *Create
user* and *Create client* controls are greyed out — which is why the first
import of this data was done by hand from console downloads.

## EG1-HMAC-SHA256, and why it is worth understanding

Every request carries an `Authorization: EG1-HMAC-SHA256 …` header whose
signature covers the method, host, path, query and body, so the secret never
travels and a captured request cannot be replayed against a different path.

```
signing key  = base64( HMAC-SHA256( timestamp, client_secret ) )
content hash = base64( SHA-256( body ) )          # POST only, first 128 KB
data to sign = method \t https \t host \t path?query \t canonical headers
               \t content hash \t auth header (no signature yet)
signature    = base64( HMAC-SHA256( data to sign, signing key ) )
```

Two details cost an afternoon if missed: the auth header *inside* the signed
data ends with a trailing semicolon and carries no signature (the signature is
appended after signing), and the timestamp is UTC `Ymd\THis+0000` and must be
within **30 seconds** of real time.

That last one is the trap. A host with a drifting clock fails *authentication*,
and the 401 reads like a credentials problem. So before blaming the key, check
the clock. `VulnHub_Akamai_Client::self_test()` signs Akamai's own published
test vector and compares the result; `test_connection()` runs it first, so a
broken signer is reported as a broken signer rather than as a rejected
credential.

Error bodies are RFC 7807 problem documents. The client shows `detail` (falling
back to `title`), because `title` alone is rarely actionable. Read the status:
**401 is the signature or the clock, 403 is a missing grant.**

## What a sync reads

Both halves are individually switchable, and both default on.

### Property origins (`read_properties`)

`/papi/v1/groups` gives every contract/group pair the credential can see — a
group can sit on several contracts and properties are listed per *pair*, so both
are needed. For each pair, `/papi/v1/properties`, then per property its
hostnames and its rule tree at the **active production version**. A property
with no production version is skipped: nothing live means nothing exposed, and a
staging-only property in an exposure list is noise. All PAPI calls send
`PAPI-Use-Prefixes: false` so ids come back bare.

The origin is read from the **rule tree**, not from the property's default
origin, and this is the whole reason the tree is fetched at all. A property
routinely serves several environments by matching a child rule on `hostname` and
setting its own `origin` behaviour there. Take the default and you silently
reassign every dev, test and preprod name to the production server — which is
exactly the bug the first hand-rolled importer shipped, collapsing two hundred
hostnames onto thirty-one origins. The walker collects `origin` under any
`hostname` criteria as a per-host override, keeps the first unconditional origin
as the default, and the per-host value wins. It also picks up `siteShield`
(`ssmap`) and `originType` on the way past.

Each hostname is run through `VulnHub_AWS_Domains::classify()`, so an origin
that names an ELB, an API Gateway or an EC2 instance is matched to the actual
AWS resource in inventory.

At most 400 properties are read per run; anything beyond that is counted and
reported rather than silently dropped.

### WAF coverage (`read_coverage`)

One call to `/appsec/v1/hostname-coverage`: every hostname the edge serves,
whether a security configuration covers it, which configuration and policy, and
whether it has a match target. Nothing else in this system knows this — DNS
resolving through the edge says only that the edge is in front, not that a
policy applies.

Response fields are read **defensively** through `pick()`, trying each spelling
the API has used, and rows with no recognisable hostname are counted and
reported in the sync message. A reader that stores blanks when a field is
renamed is worse than one that says out loud it found nothing.

## Storage — the same tables the hand import wrote

The connector calls `VulnHub_Domain_Import::store_properties()` and
`::store_waf()`, which are the *same* routines the manual import uses. Two ways
in with two storage routines is how the two quietly start disagreeing.

| Table | Holds |
| --- | --- |
| `vulnhub_edge_properties` | one row per property: origin, origin type, Site Shield map, production version, hostname count, matched AWS resource |
| `vulnhub_waf_coverage` | one row per hostname: covered, status, configuration, policy, match target |
| `vulnhub_aws_domains` | one row per hostname with `source = akamai`, carrying property, version, origin type, Site Shield and edge CNAME in `detail` |

Both tables are truncated and rewritten each run, and the domain rows go through
`replace_source( 'akamai', … )`, so a live sync **replaces** the hand-imported
snapshot rather than stacking on top of it. The only visible difference is the
`source` column: `akamai-api` for a sync, and the import label for a hand drop.
Nothing downstream reads that column to decide anything, so the Internet
exposure page does not care which produced the rows.

The connector refuses to run if `VulnHub_Domain_Import` or `VulnHub_AWS_Domains`
is missing — the domain store lives in `vulnhub-aws`, which is therefore a hard
dependency.

## Where the data surfaces

**Internet exposure** (`/internet-exposure/`, view `internet_exposure`) draws the
chain per public name and lists the gaps: names served by the edge with no
policy covering them, and internet-facing web-serving names that are not behind
the WAF at all. `VulnHub_Domain_Import::dangling()` and `::unprotected()` are
the two queries behind the Gaps tab.

## Known limits

- **No 429 handling.** The client does not read `Retry-After` or back off. A
  large account read at full tilt can be throttled by PAPI, and the affected
  properties simply count as failed reads for that run. Worth adding before this
  points at an estate much larger than the current one.
- **Production version only.** Staged changes are invisible here by design; a
  hostname moved to a new origin in staging still reports the live origin.
- **Coverage is a whole-account read.** There is no per-configuration filter, so
  a credential that cannot see Application Security fails that half entirely —
  `test_connection()` says so explicitly rather than letting the sync discover
  it.
- **No hostname is ever contacted.** Discovery is entirely from the API. The
  portal does not probe, resolve or connect to anything it finds.

## Gotchas worth keeping

- A group with several contracts needs one `properties` call per pair, not one
  per group.
- `PAPI-Use-Prefixes: false` on every PAPI call, or ids arrive prefixed and stop
  matching stored ones.
- `siteShield.ssmap` is sometimes an object (`value` or `name`) and sometimes a
  bare string.
- The clock. Really.
