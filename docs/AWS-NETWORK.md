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
| `..._aws_net_nodes` | instances (with name tag, private/public IP, subnet, VPC, state, SG ids), plus vpc / igw / nat / tgw / tgw-attach / pcx / **eni / eip / elb** nodes |
| `..._aws_net_sgs` | security groups |
| `..._aws_net_rules` | SG rules (direction, protocol, port range, source) |
| `..._aws_net_routes` | route-table entries (dest CIDR → target type/id) |

Two capture quirks worth knowing: a `tgw-attach` row keeps the **TGW id in its
`name` column** (the VPC is in `vpc_id`); a `pcx` (peering) row is written on
**both** ends, so the same `pcx-…` id appearing under two accounts is the
cross-account link.

### ENI, EIP and ELB: why a port had no owner

The first capture read instances, gateways and rules, and that is not enough to
say anything true about exposure.

A security group is not an exposure. `sg-x opens tcp/443 to 0.0.0.0/0` is only
alarming if something is behind it *and* that something has a way in. The
binding between a group and a resource is the **network interface**, and for
everything that is not an EC2 instance — load balancers, VPC endpoints, RDS,
NAT gateways, Lambda in a VPC — the ENI is the *only* binding. Without it the
screen could show an open port but never say whose it was, so a group attached
to three private VPC endpoints looked exactly like one attached to a public
server.

`public_ip` had the same gap: it is only populated on instance rows, so an
account whose only public address sits on a NAT gateway or a balancer read as
having no public address at all.

So the capture now also reads:

| Reader | API | Gives |
|---|---|---|
| `capture_enis()` | `DescribeNetworkInterfaces` | the group-to-resource binding, private/public IP per interface, and the `description` AWS uses to say what an interface belongs to |
| `capture_addresses()` | `DescribeAddresses` | every Elastic IP, and the interface it is attached to |
| `capture_load_balancers()` | `DescribeLoadBalancers` + `DescribeListeners`, both API generations | scheme (internet-facing vs internal), DNS name, type, and the ports actually listened on |

A listener is a better answer than a security-group rule: it is what the
balancer accepts, stated by the service that owns it, and a network balancer
may carry no security group at all. Node types that need more than the fixed
columns carry a small JSON `detail` blob.

`eni_owner()` reads the interface description — AWS phrases it differently per
service (`Interface for NAT Gateway nat-…`, `VPC Endpoint Interface vpce-…`,
`ELB net/name/hash`) — and that is how an open port finally gets an owner.

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
  inspected via the shared Check Point CloudGuard VPC. **`inspected` is true
  only when a `0.0.0.0/0 → tgw` route exists.** It used to also flip on a
  Plerion finding whose resource name merely contained "CloudGuard", so an
  account whose default route went straight out of its internet gateway was
  labelled *inspected by Check Point* because it happened to hold an IAM role
  of that name — the screen asserting the opposite of its own routing table. A
  role name is not a data path. CloudGuard named in a finding is still shown,
  as its own quieter card that says it is not in the routing path.
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

### Top to bottom, not left to right

The four tiers used to be four columns side by side, and it kept running out of
room. One page width had to carry four columns *plus* the three gaps that hold
the flow labels, so columns narrowed to about 260px, card names ellipsised, and
every label fought for a gap barely wider than itself — at one point the gap was
40px for a ~110px label, and the next column painted over the overhang, so
`egress → NAT` rendered as `egress → NA`.

Widening the gaps only moved the problem: every pixel a label gained came off a
card. The axis was wrong. A page scrolls vertically and does not scroll
horizontally, so vertical space is the one axis there is spare of.

Each tier is now a full-width band stacked top to bottom, like a flowchart:

- A tier's cards flow **across** the band (`repeat( auto-fit, minmax( 240px,
  312px ) )`, `justify-content: center`) instead of down a narrow column, so
  they are wide enough for a real resource name and the tier reflows to fewer
  per row as the window narrows.
- Cards are centred, which gives the diagram a **spine**: a connector between
  two tiers runs down the middle and lands on a card rather than through the
  empty side of a left-packed row.
- A connector between two stacked tiers has the whole page width to place its
  label in, so labels are never shortened and the fit-to-gap logic the columns
  needed is gone.

`anchorX()` keeps the connector tied to the box it is about: the inbound line
leaves at the **centre of the internet gateway card** and the egress line at the
centre of the **NAT gateway card**, so "which box does this come out of" is
answered by where the line starts. Both share the gap between the routing tier
and the one below it, one pointing down and one up.

Below 900px the tiers stay stacked and each holds a single column of cards; the
connectors keep working, because nothing about them depends on the columns that
used to be there.

### The direct-vs-inspected story

This answers "what is allowed straight from the internet vs. what goes through
the firewall": the `inbound <ports>` pill is what an SG opens to `0.0.0.0/0` on
a public path (IGW); anything whose default route is the TGW is inspected by the
shared Check Point CloudGuard VPC before it reaches the workload. True per-ENI
port-to-port flow needs VPC Flow Logs / X-Ray, which the capture does not read —
the account-level lanes plus per-host SG ports are what the data supports.

## What the capture calls, and what a denied call looks like

Every reader is one signed Query-API call through `VulnHub_AWS_Client::query()`:

| Reader | Service | Action |
|---|---|---|
| `capture_instances()` | ec2 | `DescribeInstances` |
| `capture_security_groups()` | ec2 | `DescribeSecurityGroups` |
| `capture_infra()` | ec2 | `DescribeInternetGateways`, `DescribeNatGateways`, `DescribeTransitGateways`, `DescribeVpcPeeringConnections`, `DescribeTransitGatewayVpcAttachments` |
| `capture_routes()` | ec2 | `DescribeRouteTables` |
| `capture_enis()` | ec2 | `DescribeNetworkInterfaces` |
| `capture_addresses()` | ec2 | `DescribeAddresses` |
| `capture_load_balancers()` | elasticloadbalancing | `DescribeLoadBalancers` (2015-12-01 and 2012-06-01), `DescribeListeners` |

`ReadOnlyAccess` covers all of them, and the SSO sync prefers that role
(`ReadOnlyAccess`, then `ViewOnlyAccess`, `SecurityAudit`, `power-user`, then
whatever the login offers).

**A denied call is silent, and silence reads as "clean".** Every reader bails
on a non-OK response — `if ( empty( $res['ok'] ) ) { return $n; }` — and writes
no rows. Nothing distinguishes that from an account which genuinely holds none
of those objects, and the difference matters in the worst direction: without
`DescribeNetworkInterfaces` no open port can be attributed to anything, so a
real exposure reports *"attached to nothing the capture holds"*; without
`DescribeAddresses` an account's public IPs vanish and the screen says there
are none; without `DescribeLoadBalancers` every balancer the posture inventory
lists is badged `stale?`.

So when a tier looks suspiciously empty, confirm the call itself succeeded
before believing the screen — run the action through `query()` with
`wp eval-file` and check `ok` and `status`, rather than reading zero rows as
zero objects. A reader that records why it read nothing is the obvious
improvement here and is not built yet.

## Verifying

`./lint.sh`; drive it per `docs/BROWSER-PASS.md` (mint a cookie, load
`/cloud-network/`, pick an account). Exercise `arch_graph()` directly with
`wp eval-file` against the live DB — never copy real account ids, hostnames or
peering names into the tree (`CLAUDE.md`, data hygiene).
