# Plerion (cloud inventory, CSPM & exposure)

`vulnhub-plerion` reads Plerion's REST API — one read-only Bearer key, region host
`https://{region}.api.plerion.com` — and brings three things into the portal, from
every connected AWS/Azure/GCP account, with **no per-account role to assume**.

## 1. Assets
`do_sync()` pages `/v1/tenant/assets` (filtered to compute instances) and imports
each as a first-class asset through `Repo::upsert_asset()`, keyed on its cloud
instance id (`aws_instance_id` / `azure_vm_id` / `gcp_instance_id`) so it **merges**
with the Tenable/Defender/CMDB record for the same box. `primary_source = plerion`.

## 2. CSPM posture findings — isolated by construction
`/v1/tenant/findings` (FAILED, severities configurable, default CRITICAL/HIGH) are
stored in **their own table** `vulnhub_plerion_findings`, never the core `findings`
table. Because nothing writes them there, they can never appear on the
Vulnerabilities list, be selected into a ticket, or enter a JSM/Jira flow — the
isolation is structural, not a flag. Shown on the **Cloud Posture** page (view
`cspm`, `/cloud-posture/`), badged CSPM · Plerion, with no raise-ticket control.

## 3. Exposure map
`sync_exposure()` snapshots `/v1/tenant/assets?isPubliclyExposed=true` per account
into option `vulnhub_plerion_exposure`. The **Cloud Exposure** page (view
`exposure`, `/cloud-exposure/`) draws an animated Internet → in-front → internal
map per account. Plerion exposes no security-group port rules, so this is an
exposure map, not a port-level flow diagram — the page says so.

## Pagination gotcha
Plerion sets `meta.total` and `meta.hasNextPage` **only on the first page**; on
cursor/subsequent pages `total` is `0` and `hasNextPage` is absent. Drive the
asset (page/perPage) loop by the first page's `total`, and the findings (cursor)
loop by "rows returned + a live cursor" — never by `hasNextPage`.

## Ops
Config lives in the connector settings (`Settings::set`/`set_secret('plerion', …)`);
the key is encrypted at rest. Enable + interval on the Integrations screen. The
hourly sync refreshes assets, CSPM findings and the exposure snapshot together.

---
_Related:_ `vulnhub-aws` also has a **Resource Explorer** org-inventory option
(`VulnHub_AWS_Explorer`) that lists assets and security groups across the org from
one central identity via `resource-explorer-2:Search` — index only (ARN, type,
region, account, tags), not configuration. Store: `vulnhub_aws_inventory`.
