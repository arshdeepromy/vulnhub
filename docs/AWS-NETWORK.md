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

### Address ranges

VPC and subnet nodes carry their `cidr` in `detail`. It is what lets an
address a scanner reports be placed in a subnet -- and so in whatever the
subnet is for, such as an AppStream fleet (`docs/APPSTREAM.md`).

### Which subnet uses which table, and what a balancer forwards to

Two more facts, both for `VulnHub_AWS_Exposure` (see `docs/ATTACK-PATHS.md`,
*Open to the internet, and vulnerable on that port*):

- **Route-table associations.** "Routes to an internet gateway" belongs to one
  subnet's table, not to the VPC: a public address in a private subnet has no
  way in. `capture_routes()` now records each association on the subnet node
  (`detail.route_table`) and the main table on the VPC node
  (`detail.main_route_table`), for subnets with no association of their own.
  A capture from before this falls back to "the VPC has an internet-gateway
  route somewhere", and the exposure list labels those rows `route: VPC-level`.
- **Load-balancer targets**, internet-facing balancers only.
  `detail.forwards` is listener → target groups (from the listener's default
  action), `detail.targets` is every registered target with the port it is
  sent traffic on (`DescribeTargetGroups` + `DescribeTargetHealth`; a classic
  balancer lists its instances and instance ports on itself). Without it a
  server published only through a balancer — the usual way — has no public
  address of its own and reads as unreachable. Until a capture has run with
  this, those listeners are reported as *not traced yet*.

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

## The Whole estate tab

The account map answers *how is this account wired*. This answers the question
an estate of dozens of accounts actually raises: **which way does traffic go,
and what stands in it.** `?tab=estate`, built by
`VulnHub_AWS_Network::estate_flow()` and served by `GET vulnhub-aws/v1/topology`.

It is a flowchart, not a tree. A tree answers "what is under here" one branch
at a time, which is the wrong question for a network: nobody wants to know what
is *inside* the internet. Three bands, stacked:

```
   where it goes        Internet                 On-premises
                            ^                         ^
   inline firewall      Check Point                    |
                            ^                          |
   how it leaves     inspected   transit   internet   NAT
   the VPC           endpoint    gateway   gateway    gateway
                         ^          ^         ^         ^
   workloads          VPC lanes, one group per route out
```

**The firewall is a band, not a lane.** It was a lane beside the others, which
put the appliance next to the path it actually stands in and left the transit
gateway looking like a peer of the internet gateway — when the hub is one of
the things sitting *behind* the firewall. Everything inspected now hands
upwards to it, and only it reaches the internet; the transit gateway keeps its
own edge to the corporate network, because that traffic never goes out to the
internet at all.

Read upwards from a workload for its exit; read down from the internet for
everything reachable that way.

### The lanes come from route tables, never from names

Each lane is the `0.0.0.0/0` route in a VPC's own route tables:

| Default route target | Lane | Goes to |
|---|---|---|
| a `vpce-` in `gatewayId` | inspection appliance | internet |
| a network interface | inline appliance | internet |
| a transit gateway | the hub | **on-premises** |
| an internet gateway | nothing in between | internet |
| a NAT gateway | outbound only | internet |

**The transit gateway is not an internet path.** It is how these workloads
reach the corporate network, and the hub's own account runs the outbound
security appliances that stand in it. Modelling it as a sibling of the internet
gateway — which an earlier draft of this screen did — gets the estate exactly
backwards.

**A VPC appears in every lane its route tables really have**, so one with a
public subnet and a private one is in two. The totals are therefore lane
memberships, not distinct VPCs, and the screen says so.

### Naming the appliance without matching on a name

A Gateway Load Balancer endpoint in a default route is an inline firewall in
the path, but the endpoint id alone says nothing about which firewall.
`capture_vpc_endpoints()` stores each endpoint's **`serviceName`**, and that is
the join: every VPC pointed at the same appliance carries the same service
string. Measured here, **106 endpoints across 23 accounts resolve to a single
service** — one firewall, the whole estate behind it, established from captured
data rather than asserted.

The appliances themselves are scoped to **the account that owns the load
balancer**, not to anything they are called. That matters: every auto-scaling
group in the estate arrives through the same import, and one of them is the
posture vendor's own scanning appliance in its own account — not a firewall,
not in anybody's path. Tying the set to the balancer's account is the
data-driven cut. Matching on names is the mistake recorded under *The
direct-vs-inspected story*, and it is not repeated here.

For the transit lane the screen names **the account** that owns the hub rather
than its appliances, because which appliance stands in that path is decided by
transit-gateway route tables, which live in that account. Listing them would
imply a mapping nothing has established.

### What the arrows say

An unlabelled arrow only says a path exists, which is the least useful true
thing a network diagram can tell you. Every connector carries text:

- **Workload to its lane: nothing.** The ports are already chips on the card an
  inch below the line, and printing them twice that close together is noise,
  not emphasis. This label existed and was removed.
- **Lane upwards**: `in tcp/443 tcp/22 · out ALL` — **both directions**,
  because "what can reach in" and "what can get out" are different questions
  and a firewall is bought to answer the second as much as the first. Read from
  the security-group rules admitting or allowing `0.0.0.0/0`; groups carry
  their own VPC, so rules attribute to a lane without going near an instance.
  `none` and `ALL` are spelled out, because nothing open and everything open
  look identical on a diagram that only draws the line.
- The lane with nothing in between also carries its count of **public
  addresses**, and the NAT lane says `outbound only` with the egress set.

### A public address has to name its owner

The same ports appear as chips on the workload card, and the public addresses
as a list. The first version of that list said `interface`, `nat gateway`,
`network load balancer` — which answers "what kind of thing is this" and not
the question anybody actually has, which is **which server do I go and look
at**.

Every address now resolves to the resource holding it:

| Evidence | Becomes |
|---|---|
| the interface's `instance` | the **server**, by its Name tag |
| `Interface for NAT Gateway nat-…` | that **NAT gateway** |
| `ELB app/<name>/…` or `ELB net/<name>/…` | that **load balancer**, by name |
| `VPC Endpoint Interface vpce-…` | that **endpoint** |
| `Created By Amazon Workspaces …` | a **WorkSpaces desktop** |

AWS writes the owner into the interface's own description for the services that
have no instance, and hands back the instance id for the ones that do. That is
also the only way a balancer's or a NAT gateway's address is found at all,
since neither is an instance.

Where the owner is a server the row goes further: its **hostname**, its open
**critical and high** counts from the asset register, and a link straight to
that asset. A public address stops being a fact and becomes a lead. On this
estate that resolves ten addresses to named machines — one of them carrying 10
critical and 39 high — which is a worklist rather than a diagram.

Labels are staggered rather than centred on each curve: several lanes converge
on the same destination, so centring puts their labels at the same height and
they overlap into something unreadable.

### A virtual appliance is a device, not a server

Resolving an address to its owner answered *which thing*, and immediately
raised the next question: the list then mixed real machines in with NAT
gateways, balancers and WorkSpaces desktops, all rendered identically. In a
rack none of those would be a server. They would be devices — something you
would find in the network cabinet, not the compute one.

So every node carries a `class`, from `VulnHub_AWS_Network::device_class()`:

| AWS construct | Rack equivalent | Class |
|---|---|---|
| internet gateway, NAT gateway, transit gateway | edge router | `network` |
| load balancer (application, network, gateway) | load balancer appliance | `network` |
| VPC endpoint (interface or gateway) | service port on a switch | `network` |
| auto-scaling group of appliances | an appliance pair | `network` |
| WorkSpaces desktop | a desk, not a rack | `desktop` |
| EC2 in the inspection stack | the firewall appliance | `network` |
| **any other EC2** | **a server** | `server` |
| elastic network interface | **not a device — it is a port** | — |

The last row is the one that matters. An ENI is how a device is *attached*;
drawing it beside its own owner double-counts the estate and is why the first
version of the list had eleven rows reading `unattached interface`. An ENI is
only ever shown when nothing claims it, and then it is exactly what it says:
an address with no owner, which is a finding rather than a node.

**An EC2 instance is a server.** It was briefly classed by `sourceDestCheck`,
on the reasoning that an instance forwarding traffic for other hosts is a hop
rather than a host. That is true of the packet and wrong about the estate: a
box that somebody patches, backs up and owns is a server whatever it does with
a route, and quietly moving a handful of them out of the server count made the
fleet look smaller than it is. The capture no longer reads the flag.

The single exception is the **inline firewall**, which is a vendor appliance
that happens to ship as an AMI. Nobody administers it as a server, and it is
the one EC2 that genuinely belongs in the network cabinet. It is picked out by
`inspection_stack()` — the account that owns the gateway load balancer — not
by what anything is named, for the same reason the lanes are not (see *Naming
the appliance without matching on a name*). That is an account-level answer:
a non-appliance instance in that account would be counted as a device, and
auto-scaling-group membership would be the exact signal if it were captured.

On this estate the firewall account is reachable by the posture vendor but not
by SSO, so its instances are not captured and the device count is **zero** —
the appliances appear instead as the scaling group on the firewall band, which
is already `network`. A zero is dropped from the header rather than printed:
"0 network devices" reads as a finding when it is an absence.

The entry-point list groups under **Servers**, then **Network devices**, then
**Virtual desktops** — servers first, because a public address on a server is
the one that needs patching. That ordering was briefly wrong in a way worth
recording: the comparator ranked with `order[ x.class ] || 9`, and `server`
ranks `0`, so the valid rank read as missing and servers sorted last. It is the
same falsy-zero trap `docs/FILTERS.md` records for `patch_available=0`. Rank
explicitly.

### The controls look like controls

The first version of this screen used bare `<summary>` elements with muted
text, and people tried to select them instead of clicking them — a caption and
a button should not be the same shape. Every disclosure on the diagram is now a
pill with a caret, a hover state and a focus ring. It is the same `<details>`
underneath, so keyboard and screen-reader behaviour are unchanged.


### Making it read as a network, not a table of boxes

The diagram was correct and inert, which is a poor combination for something
people are meant to *follow*. Three additions, none of which change a number:

- **Medallions.** Each node is a ringed disc rather than a 17px line icon,
  because at that size a glyph reads as a bullet point and a disc reads as a
  node. The ring then has somewhere to put risk: a lane admitting every port,
  or a workload group holding public addresses, gets a red ring and a slow
  pulse instead of another sentence.
- **The wires move, and carry the lane's colour.** A dashed stroke animating
  along the path shows direction without an arrowhead per segment, and
  colouring each by the lane it leaves means one glance separates inspected
  traffic from the paths that bypass inspection. Both stop under
  `prefers-reduced-motion`.
- **Every node answers on hover.** A card has to abbreviate — truncated
  appliance names, five ports of eleven, three VPCs of thirty-nine. The
  tooltip carries the unabbreviated version: full names, the whole inbound and
  outbound port lists, the account count, the largest VPCs. It is bound to
  focus as well as hover, or it is detail only a mouse can reach, and it is
  clamped into the viewport, because a tooltip running off the edge is the
  same as no tooltip.

### Tracing a path

Click any box and the whole flow through it lights: everything it reaches
upwards, everything that reaches it from below, and the wires between. Click it
again, press Escape, or click the background to clear.

Traversal runs **both directions** from the clicked node. The graph is a DAG
drawn bottom-up, so ancestors are the destinations and descendants are the
workloads feeding it; walking one way answers half the question. Selecting the
transit gateway, for instance, lights the corporate network *and* the internet —
because the hub hands off to the firewall, and the firewall is what reaches the
internet — along with the workload group behind it, and dims the four lanes that
have nothing to do with it.

Two decisions worth keeping:

- **The rest dims, it does not disappear.** The question is "where does this
  go", not "hide everything else"; the dimmed boxes are the context that makes
  the lit path mean something. Hiding them would also reflow the diagram under
  the reader, moving the very boxes they were looking at.
- **A control inside a card does not select.** Opening *Why this lane exists*
  or a VPC list would otherwise reroute the whole diagram as a side effect of
  reading one card. The handler ignores clicks that land on a `summary`, link,
  button or input.

Cards carry `role="button"`, a label, and Enter/Space, so the path can be traced
from the keyboard. The highlight is re-applied after every redraw, because the
wires are rebuilt from scratch whenever a card opens or the window resizes.

### Laying it out without hiding anything

Three things this got wrong first, each visible only by looking at the rendered
page rather than by asserting on the DOM:

- **The lane row must not wrap.** Five lanes at a fixed card width overflowed
  the page and the last one folded up into the band above, landing on top of
  it. The lanes are meant to read as alternatives, so fitting on one line is
  the point: they `flex: 1 1 0` and shrink instead, wrapping only below 1100px
  where the whole diagram stacks anyway.
- **Labels are HTML above the cards, not SVG beneath them.** The wire overlay
  sits *below* the bands so the lines do not paint across the boxes — which
  also meant a long curve passing behind a tall card took its label with it,
  out of sight. They are positioned elements in their own layer now, and being
  real boxes with measurable widths is what makes the next point possible.
- **Each label is anchored above the card its line leaves**, not at the middle
  of the curve. Midpoints of several long curves land in the same small gap
  beside the tall firewall card and pile up; source cards are spread across the
  width, so anchoring to them separates the labels for free — and puts each one
  beside the lane it describes, which is where a reader looks for it. A
  measured pass then nudges any remainder up or down until it clears both the
  other labels and every card.

Checked at 1280, 1600 and 1920 across all three environment views: lane band on
one row, no page overflow, no card overlapping another, no label overlapping a
label or sitting on a card, and no text clipped by its own box.

### `.vh-flow` was already taken

Every control on this screen was inert for a while, and the cause was a class
name. The container was given `vh-flow`, which this same stylesheet already
defines for the per-account map's animated flow-line layer:

```css
.vh-flow { position: absolute; inset: 0; z-index: 2; pointer-events: none; }
```

`pointer-events` inherits, so every card, disclosure and button inside the
diagram stopped accepting a click, while looking entirely normal. The namespace
is now `vh-estate-*`.

**It passed its own test, which is the part worth remembering.** The browser
pass clicked with `element.click()` from inside `page.evaluate()`, and a
synthetic click dispatches straight at the node without a hit test — so it
toggled the `<details>` happily while a real cursor could not. It is the same
trap as `click({ force: true })` in `docs/BROWSER-PASS.md`, wearing different
clothes. Clickability is now asserted with Playwright's own `.click()`, which
hit-tests and times out when something is in the way, and with an explicit
check that the container computes `pointer-events: auto`.

### Where the middle of the diagram comes from

The inspection stack usually sits in a network account that the operator's SSO
login has no assignment to — `list_roles` returns nothing for it — so the AWS
capture can never see the load balancer every other account routes into, nor
the appliances behind it, nor the transit gateway that owns the hub.

`import_posture_network()` fills that in from the cloud-posture inventory,
which is onboarded centrally rather than per account. Those rows are written
with `source = 'plerion'`, and the `source` column earns its place twice: it
keeps a neighbouring account's capture from deleting them (`capture()` now
clears only its own rows), and it is the honest label — an inventory record,
not a live read. Accounts the AWS capture already reads are skipped, because a
live read beats an inventory and importing both would draw each node twice.

### Production and non-production are drawn separately

They are different conversations: one is a live risk register, the other mostly
a housekeeping list, and averaging them hides both. On this estate the split
immediately surfaced **14 production VPCs whose default route goes straight out
of an internet gateway with no inspection in the way** — a number that was
invisible while every environment was drawn together.

AWS records no production flag, so the only evidence is naming.
`VulnHub_AWS_Environment` ships the generic words — prod, dev, test, sit, uat,
staging — and **tests the traps first**: `non-prod`, `nonprod`, `pre-prod` and
`preprod` all contain "prod", and a classifier that looks for production first
calls every one of them production. That is the worst available way to be
wrong, because it puts test systems on the production diagram.

Everything site-specific goes in the **Environment naming rules** setting on
the AWS connector, one `fragment = prod|nonprod` per line, matched before the
built-in words. It is a setting rather than code because an estate's
environment codes are its own vocabulary and this repository is public. A bare
fragment matches on a word boundary so a short code cannot match inside a
longer word; a `/regex/` is taken as written. Whatever it still cannot place is
reported rather than guessed at.

### Drawing

Bands are ordinary flow layout; only the connectors are SVG, in one overlay
measured off the rendered cards. Laying the cards out in SVG would mean
re-implementing text wrapping, and drawing the elbows in HTML would mean
building them out of borders. The overlay is redrawn on resize and whenever a
card is opened, because both move the boxes the lines are tied to. Below 760px
the bands stack and the wires are hidden — a connector drawn between two cards
in a single column says nothing the order does not.

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
| `capture_load_balancers()` | elasticloadbalancing | `DescribeLoadBalancers` (2015-12-01 and 2012-06-01), `DescribeListeners`; for internet-facing balancers also `DescribeTargetGroups` and `DescribeTargetHealth` |
| `capture_vpc_endpoints()` | ec2 | `DescribeVpcEndpoints` — Gateway Load Balancer endpoints only, for the `serviceName` that names the appliance |

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
