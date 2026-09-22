# AWS: SSO login, network capture and the Cloud Network map

How VulnHub reads AWS with the operator's own SSO login, what it stores, and how
the Cloud Network screen draws one account's topology. Nothing here creates AWS
roles or stores long-lived keys — it borrows the person's Identity Center
session and reads with their permissions.

Plugin: `vulnhub-aws`. Screen: **Cloud Network** (`/cloud-network/`, view
`network`).

## Signing in with IAM Identity Center (SSO)

The AWS integration card takes an **SSO start URL** and **region**, saved as
ordinary settings (the org URL is never hard-coded). "Authenticate" runs the
OIDC device-authorization flow:

1. `register_client` → `start_device_authorization` returns a `verificationUri`
   the operator opens and approves in the browser.
2. The portal polls `create_token`; on approval it stores the access + refresh
   token (`class-vh-aws-sso.php`, `class-vh-aws-sso-auth.php`).
3. `sso_token()` refreshes silently when it is within 300 s of expiry and
   persists the new token; the card shows a **live expiry countdown**
   (`data-vh-sso-exp`) so the operator knows when to re-authenticate.

A sync iterates every account the login can see (`list_accounts`), prefers the
`ReadOnlyAccess` role (`list_roles` → `role_credentials`), and reads with those
short-lived credentials. `set_time_limit(0)` and per-account `progress()` /
`bump('processed')` keep the progress bar honest across dozens of accounts —
the earlier "0 records" bug was the 120 s PHP cap killing the loop before the
after-loop counter ran.

## What the capture stores

`VulnHub_AWS_Network::capture()` deletes the account+region slice and re-inserts
it, into four tables:

| Table | Holds |
|---|---|
| `..._aws_net_nodes` | instances (with name tag, private/public IP, subnet, VPC, state, SG ids), plus vpc / igw / nat / tgw / tgw-attach / pcx nodes |
| `..._aws_net_sgs` | security groups |
| `..._aws_net_rules` | SG rules (direction, protocol, port range, source) |
| `..._aws_net_routes` | route-table entries (dest CIDR → target type/id) |

Two capture quirks worth knowing: a `tgw-attach` row keeps the **TGW id in its
`name` column** (the VPC is in `vpc_id`); a `pcx` (peering) row is written on
**both** ends, so the same `pcx-…` id appearing under two accounts is the
cross-account link.

## `arch_graph( $account, $vpc )`

Builds the tiered picture the screen draws. Resources come from the Plerion
inventory table (`..._cloud_resources`) and are **enriched** by joining back to
the AWS capture and the asset store:

- **EC2**: Plerion stores the instance as a PRN in `resource_id` and the `i-…`
  id in `name`; we bridge on the `i-…` id to pull the real **Name tag, IPs,
  subnet, VPC, state** from `net_nodes`, the **Tenable/Defender** posture
  (`open_critical/high/…`, `defender_health`, `last_seen`) from `assets` keyed
  on `aws_instance_id`, and **Plerion CSPM** counts by resource name.
- Tiering: internet-exposed / ALB / API GW → **entry**; RDS / S3 / DynamoDB →
  **data**; everything else (EC2, Lambda, ECS) → **compute**.
- **Exposure**: an instance is `direct` only if it holds a public IP; an
  internet-open SG without a public IP is treated as fronted (LB / Check Point).
  `open_ports` is the real set of ports any SG opens to `0.0.0.0/0`.
- **Routing / inspection**: default routes to `igw` = direct, to `tgw` =
  inspected via the shared Check Point CloudGuard VPC. `inspected` is true when
  a `0.0.0.0/0 → tgw` route exists or a CloudGuard role is seen in Plerion.
- **`peers`** (cross-account): the TGW hub (accounts sharing this account's TGW
  id) and the named VPC peerings (`pcx` rows matched on both ends), which reveal
  the workload dependencies wired across account lines.

## The Cloud Network screen

`assets/network.js` renders four columns — **Internet & routing → Entry →
Compute → Data** — from the REST route `GET vulnhub-aws/v1/network`
(`Caps::VIEW`):

- **Icons, not ids.** Every node is a service icon (EC2, Lambda, S3, RDS,
  DynamoDB, ALB, API GW, Internet, IGW, NAT, TGW, Check Point) with its real
  Name tag and IP.
- **Collapsible groups.** Compute and Data collapse by kind — a header shows the
  icon, the count, and an aggregate exposed/critical badge; clicking reveals the
  members. A large fleet no longer renders as a wall.
- **Click a node** for a popup: configuration (instance, IPs, subnet, VPC,
  state, open ports), health (Defender health, lifecycle, last seen), and
  findings (Tenable crit/high/med/low + Plerion CSPM). The popup mounts on
  `document.body` so `position: fixed` centres it against the viewport.
- **Animated flow lines** connect the columns in the gaps: a top inbound band
  (`inbound <ports>`, `app traffic`, `reads · writes`, plus `via Check Point`
  when inspected) and a lower outbound band (`egress → NAT` / `egress → TGW`),
  each a coloured marching-ants arrow.
- **Cross-account connectivity** sits below the grid: the TGW hub (with the
  count and ids of the other accounts on it) and the named VPC peerings.

### The gap is a layout constraint, not spacing

A pill label is ~110px wide and is centred in the gap between two columns, so
**the gap is the label's entire budget**. The first version set `gap: 40px` and
drew the flow layer *under* the grid (`z-index: 0` against the grid's `1`), so
every label overhung its gap and the next column painted over the overhang:
`egress → NAT` rendered as `egress → NA`, `via Check Point` lost its last
letter, and the first gap carried three of them stacked.

Two rules keep it honest:

- The grid gap scales with the viewport — `clamp( 72px, 6.2vw, 124px )` — so a
  desktop gap holds a full label, and `.vh-flow` sits **above** the grid
  (`z-index: 2`, `pointer-events: none`), so a few px of overhang lands on the
  next column's 12px padding and stays readable instead of being clipped.
- `pill()` is given the measured gap and steps the wording down rather than
  overflowing it: full text, then a short form (`inbound tcp/443` → `tcp/443`,
  `via Check Point` → `Check Point`, `egress → NAT` → `NAT`,
  `reads · writes` → `r/w`), then an ellipsis, with the full text kept in a
  `<title>`. At 1440px the first two already fall back; below 900px the columns
  stack and the flow layer is hidden entirely.

Columns stay `align-items: start`. Stretching them to a common height was tried
and reverted: the routing column carries twice the cards of any other, so equal
heights bought three columns of void in exchange for a tidy bottom edge.

### The direct-vs-inspected story

This answers "what is allowed straight from the internet vs. what goes through
the firewall": the `inbound <ports>` pill is what an SG opens to `0.0.0.0/0` on
a public path (IGW); anything whose default route is the TGW is inspected by the
shared Check Point CloudGuard VPC before it reaches the workload. True per-ENI
port-to-port flow needs VPC Flow Logs / X-Ray, which the capture does not read —
the account-level lanes plus per-host SG ports are what the data supports.

## Verifying

`./lint.sh`; drive it per `docs/BROWSER-PASS.md` (mint a cookie, load
`/cloud-network/`, pick an account). Exercise `arch_graph()` directly with
`wp eval-file` against the live DB — never copy real account ids, hostnames or
peering names into the tree (`CLAUDE.md`, data hygiene).
