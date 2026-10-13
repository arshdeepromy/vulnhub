# Plerion (cloud inventory & CSPM)

`vulnhub-plerion` reads Plerion's REST API — one read-only Bearer key, region host
`https://{region}.api.plerion.com` (setting `region`, default `us`) — and brings
two things into the portal from every account connected to the Plerion tenant,
with **no per-account role to assume**. The `providers` setting (default `AWS`)
limits both imports to those clouds.

## 1. Assets
`do_sync()` pages `/v1/tenant/assets` (filtered to `AWS::EC2::Instance`, so in
practice AWS only, whatever `providers` says) and imports
each as a first-class asset through `Repo::upsert_asset()`, keyed on its cloud
instance id (`aws_instance_id` / `azure_vm_id` / `gcp_instance_id`) so it **merges**
with the Tenable/Defender/CMDB record for the same box. `primary_source = plerion`,
hostname from the `Name` tag (else the resource name, else the instance id).

After the assets it reads `/v1/tenant/integrations` for AWS account names and
announces them on `vulnhub_aws_account_names` (see `docs/AWS-NETWORK.md`); a
failure there is logged and never fails the sync.

## 2. CSPM posture findings — isolated by construction
`/v1/tenant/findings` (FAILED only; `finding_severities`, default
`CRITICAL, HIGH`; switch off with `use_findings`) are stored in **their own
table** `vulnhub_plerion_findings`, keyed on the finding PRN, never the core
`findings` table. Rows not seen by a complete run are pruned at its end, so the
table is the current set, not a history. Because nothing writes them there, they can never appear on the
Vulnerabilities list, be selected into a ticket, or enter a JSM/Jira flow — the
isolation is structural, not a flag. Shown on the **Cloud Posture** page (view
`cspm`, `/cloud-posture/`, placed after Vulnerabilities in the menu), badged
CSPM · Plerion, with no raise-ticket control. It filters on `?severity=`,
`?account=`, `?rtype=` (resource type) and `?search=` (message, resource name or
detection id), 50 a page via `?p=`, and never lists exempted findings.

Each finding also carries a **cross-account grouping key** (`cause_key`, with
`cause_stem`, `cause_account` and `env_tier`), set on upsert by
`VulnHub_Plerion_Cause`: same detection, same resource type, same name once the
environment tier, account id, region, revision and CloudFormation suffix are
taken out. Cloud Posture also filters on `?cause=<key>` and `?detection=<id>`
(no on-page control: they arrive from the **Control gaps** page, and a banner
says so). The rules, the backfill and the page are in `docs/CONTROL-GAPS.md`.

## The exposure map, and why it is gone

There was a third page: **Cloud Exposure** (`/cloud-exposure/`), drawing an
Internet → in-front → internal map per account from a `sync_exposure()`
snapshot of `/v1/tenant/assets?isPubliclyExposed=true`.

It was removed once **Cloud Network** existed (`vulnhub-aws`,
`docs/AWS-NETWORK.md`). Both answer "what can the internet reach", but Plerion
publishes no security-group rules, so this one could only say *that* a resource
was exposed — never on which port, behind which balancer, or whether the
default route goes through inspection. Cloud Network reads the account's own
route tables, security groups, ENIs and listeners and answers all of that. Two
screens making the same claim with different evidence is worse than one,
particularly when the quieter one is the better informed.

Removed with it: the page class and its `exposure.js`, the `.vh-exp-*` half of
`plerion.css`, the `sync_exposure()` call and method, and the stored option —
an hourly API call and a 34 KB snapshot of account ids that nothing read any
more. The asset loop's own "N publicly exposed" count is unrelated and still
in the sync message. The page itself is in the trash rather than deleted.

## Pagination gotcha
Plerion sets `meta.total` and `meta.hasNextPage` **only on the first page**; on
cursor/subsequent pages `total` is `0` and `hasNextPage` is absent. Drive the
asset (page/perPage) loop by the first page's `total`, and the findings (cursor)
loop by "rows returned + a live cursor" — never by `hasNextPage`.

## Ops
Config lives in the connector settings (`Settings::set`/`set_secret('plerion', …)`);
the key is encrypted at rest. Enable + interval (default hourly) on the
Integrations screen. The sync refreshes assets, account names and CSPM findings
together; there is no exposure snapshot any more (see above).

## The Cloud Network map reads this inventory, and checks it

`vulnhub-aws`'s **Cloud Network** screen (`docs/AWS-NETWORK.md`) builds its
per-account tiers from `..._cloud_resources` — a Plerion resource inventory
(`account_id`, `region`, `kind`, `resource_type`, `resource_id`, `name`,
`exposed`, `risk`, `last_seen`) — and enriches each row from the AWS capture and
the asset store. **Nothing in the current code writes that table**: this
connector imports only instances and findings, and the table keeps whatever an
earlier writer left in it. Treat its contents as a dated snapshot until a writer
is restored.

That makes it a cross-check on what is stored here. A resource this inventory
lists as an internet-facing load balancer, which a direct AWS read of the same
account and region does not return, is badged **`stale?`** on that screen and
loses its `internet-facing` label rather than being drawn as a front door. It
has been deleted since the last Plerion sync, or the AWS role cannot read load
balancers — the badge does not claim which, only that the two sources disagree.

Worth knowing when reading either screen: a CSPM finding whose resource name
merely contains *CloudGuard* is **not** evidence that traffic is inspected.
Cloud Network used to treat it as such and label accounts as Check Point
inspected whose default route went straight out of an internet gateway; it now
decides that from the route table alone.

---
**It also fills in the accounts AWS cannot reach.** The inspection stack — the
gateway load balancer every workload VPC routes into, the firewall appliances
behind it, the transit-gateway hub — usually sits in a network account the
operator's SSO login has no assignment to. Because this connector is onboarded
centrally rather than per account, it can see that one, and
`VulnHub_AWS_Network::import_posture_network()` copies those load balancers,
transit gateways, auto-scaling groups and instances into the topology store with
`source = 'plerion'`. Accounts the AWS capture reads live are skipped. Without
it the middle of the Cloud Network flowchart is a blank. Note that nothing calls
it on a schedule: neither sync invokes it, so it has to be run by hand
(`wp eval 'VulnHub_AWS_Network::import_posture_network();'`) to refresh.

---

_Related:_ `vulnhub-aws` also has a **Resource Explorer** org-inventory option
(`VulnHub_AWS_Explorer`) that lists assets and security groups across the org from
one central identity via `resource-explorer-2:Search` — index only (ARN, type,
region, account, tags), not configuration. Store: `vulnhub_aws_inventory`.
