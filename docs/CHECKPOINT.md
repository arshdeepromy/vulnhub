# Check Point (firewall policy)

`vulnhub-checkpoint` reads Check Point management — a Smart-1 Cloud tenant or an
on-prem Security Management / Multi-Domain server — and answers one question
the scanners cannot: **which machines can the internet actually reach through
the firewall, on which ports, and which rule opens each one.** The answer feeds
the threat context's internet paths, so the *How an attacker gets in* widget and
the Vulnerabilities list's `expo` filter rank findings on those ports first.

## Read-only, three ways

1. **On the Check Point side** the API key belongs to a dedicated administrator
   whose permission profile is Read Only with *Management API Login* allowed.
2. **Every session** is opened with `login { "api-key": …, "read-only": true }`.
   A key with write rights still gets a session that cannot change anything and
   takes no locks. If the server ever reports a session that is not read-only,
   the client logs out and refuses to continue.
3. **The client** (`VulnHub_CheckPoint_Client::allowed()`) sends only `login`,
   `logout`, `keepalive` and `show-*`. Every Web API command is a POST, so the
   verb says nothing about writing; the command name does, and anything else —
   `publish`, `discard`, `set-*`, `add-*`, `delete-*`, `install-policy`,
   `run-script` — is refused before a request is built.

It talks only to the management API. It never connects to a gateway or to
anything a gateway protects.

## Setting it up

In SmartConsole (Smart-1 Cloud: Web SmartConsole from the Infinity Portal):

1. *Manage & Settings → Permissions & Administrators → Permission Profiles →
   New*: a Read Only profile; under *Management*, allow *Management API Login*.
2. *Administrators → New*: authentication method **API Key**, *Generate API
   key*, copy it, assign the profile. Publish.
3. *Manage & Settings → Blades → Management API → Advanced Settings*: allow
   API access from the address this platform calls from (or add it under
   *Trusted Clients*).

### Two ways to reach management

**Portal API key (the default).** The Client ID, Secret Key and Authentication
URL from the Check Point Portal API Keys page (service Smart-1 Cloud; an
account or a user key — a user key's URL ends in `/user`, and the host carries
the region, e.g. `cloudinfra-gw.ap.portal.checkpoint.com`). A run:

1. posts `{"clientId", "accessKey"}` to the Authentication URL and keeps the
   token (`data.token`, 30 minutes; a 401 fetches a new one once);
2. reads the Smart-1 Cloud service API on the same host under
   `/app/maas/api/v1/` — **GET only, and only `mgmt-service` and `gateways`**
   (that API can also register and delete gateways; the client cannot ask it
   to). Gateways are stored without the one-time registration token each
   record carries;
3. builds the Management API URL from the service details,
   `https://<service name>.maas.checkpoint.com/<sharedSecret>/web_api`
   (the service API documents `sharedSecret` as the part of the Web API URL
   that is also the `mgmt_cli` context), unless one is set;
4. logs in there read-only with the token as bearer and, if one is set, a
   SmartConsole administrator API key, then reads the policy as below.

The management server does **not** accept the portal token on its own: on a
real tenant `login` answered *400 Missing parameter: [[user and password] or
api-key is required.]* So the rule base needs a management login as well —
a read-only administrator's API key, or its **user name and password** (both
supported; the password is encrypted at rest). Test connection says plainly which
steps worked; when the login is refused the run still stores the gateways and
says the rule base was not read, and the Firewall policy page shows the
gateways with that note.

An Authentication URL pasted into the Management API URL box (an easy slip;
both come from the same page) is taken as the Authentication URL.

**Direct.** `https://<tenant>.maas.checkpoint.com/<context-id>/web_api` or
`https://<server>/web_api`, with a SmartConsole administrator's API key.

`/web_api` is appended to a Management API URL when it is missing.

In the portal, *Administration → Integrations → Check Point*:

| Setting | Value |
|---|---|
| How to reach management | Portal API key (default) or Direct |
| Authentication URL, Client ID, Secret Key | portal mode (secret encrypted at rest) |
| Management API URL | optional with a portal key; required for Direct |
| Management API key | a read-only administrator's API key (encrypted at rest) — or the next two |
| Management administrator user name / password | the same administrator by password (password encrypted at rest) |
| Domain | Multi-Domain servers only |
| Policy packages | comma separated, blank for all |

TLS is always verified. An on-prem server with a self-signed certificate needs a
certificate the box trusts; there is deliberately no "skip verification" switch.

*Test connection* opens a read-only session, counts gateways and packages, and
logs out.

## What a run reads

`show-gateways-and-servers`, `show-packages`, the object inventory
(`show-hosts`, `-networks`, `-address-ranges`, `-groups`,
`-groups-with-exclusion`, `-services-tcp`, `-services-udp`,
`-service-groups`, all `details-level: full`), then per package the first
access layer and every inline layer its rules apply (`show-access-rulebase`
with `use-object-dictionary`), and `show-nat-rulebase`.

Paging follows the house rule that a truncated read must fail the whole fetch:
`each()` and `rulebase()` walk to the server's `total`, and a short page or a
total that moves mid-read throws before anything is written. The previous
snapshot stays in place.

Tables: `vulnhub_cp_gateways`, `_objects`, `_rules`, `_nat` (the snapshot) and
`_exposure` (the verdicts). Rules and NAT are replaced whole each run; gateways
and objects are upserted and pruned by `last_seen` after a complete read.

## How exposure is worked out

`VulnHub_CheckPoint_Policy`, pure logic, no I/O.

- **Sources.** `Any`, the `Internet` object and security zones named as
  external → *anyone*. Public addresses → *listed* (counted). Private-only
  sources are internal traffic and ignored. A negated source covers the
  internet unless the column already did. Objects it cannot resolve (dynamic,
  updatable, domain objects, access roles) make a source *listed*, never
  *anyone*.
- **Destinations.** Hosts, networks, ranges, groups (nested), groups with
  exclusion, gateways. A rule to `Any` (or a negated destination) is **not**
  mapped onto machines — that would call the estate exposed — and is listed
  under *Broad rules* instead.
- **Services.** TCP/UDP ports and ranges, service groups, `Any`, negation.
  ICMP and other protocols open nothing that listens and are left out.
- **First match.** Rules are walked in order per machine address. An Accept
  opens the ports not already decided; a Drop or Reject whose source is
  *anyone* closes them for every rule below. Disabled rules are skipped.
- **Inline layers.** The parent rule narrows the inner rules (destination and
  service intersected; an *anyone* inner source under a *listed* parent becomes
  *listed*).
- **Static NAT and port forwards** (`nat_forwards()`). Automatic static NAT (a
  host's NAT settings) forwards every port, for anyone. A manual rule from one
  public original destination to one private address forwards only its
  **original service**, and only for its **original source**: the ports an
  access rule opens are intersected with the forward's, and a forward from
  listed sources makes the way *listed* even under a rule from Any. A forward
  whose original source is only private addresses, or whose public side is a
  private address, is internal and is not a way in. (Until 2026-10-12 every
  forward was treated as a whole-machine mapping, which called servers open on
  every port when one port was forwarded to them.)
- **Reached how.** A public machine address → `via: direct`; a NAT'ed private
  one → `via: nat`, `front` the public address. Allowed by policy with neither
  → *latent* (the policy would let it through if a route appeared).
- **Machines** are every reportable asset's `ipv4` and `ipv4s`. Private
  addresses reused at two sites match both.

Known limits, also printed on the page:

- Only the **first ordered layer** of each package is read. A later layer
  (application control, for example) can still block a port shown open here;
  it cannot open one shown closed.
- Which gateway a machine sits behind is not known, so every package is read
  against every machine and the answers combined.
- Time objects, install-on, VPN columns and access roles are ignored.

`wp vulnhub checkpoint-preview` runs the reader over the built-in sample policy
(documentation address ranges only) and prints what it concludes, writing
nothing. On the sample it shows: web on 80/443 through automatic NAT, SSH closed
by an earlier Drop despite a later Accept, the disabled rule ignored, partner
RDP as *listed* through manual NAT, the inline layer narrowed to one host and
*latent* (no NAT), and one broad rule.

## Which firewall is which

`VulnHub_CheckPoint_Sites::classify()` places every stored gateway — site,
platform (`aws`, `cluster`, `gateway`, `unknown`), cluster pair, and a
confidence — and keeps the evidence it used (shown under each row on the
Gateways tab). Strongest first:

1. an override (`wp vulnhub checkpoint-sites --set=<name> --site=<site>`,
   kept in the option `vulnhub_checkpoint_site_overrides`; `--site=''` clears);
2. AWS: an instance id or region in the name, an auto-scaling gateway, and an
   AWS auto-scaling group from the AWS capture sharing two or more name tokens
   (which names the account);
3. a location in the register named by a token — as the start of a word, or as
   a common city code (`city_codes()`, filterable). When several locations
   match, a cluster prefers a data-centre location and a single gateway prefers
   one that is not;
4. machines in the same /24 (skipped for the cloud management overlay range,
   100.100.0.0/16): their location, or a hostname word the token starts;
5. the gateway's description.

Nothing about an estate is in the code: places come from the location register
and asset names, codes are the public ones, overrides live on the box. It runs
after every Check Point run; `wp vulnhub checkpoint-sites` prints the verdicts
and evidence.

## Where it shows

- **Firewall policy** page (view `firewall`, `/firewall-policy/`, after Cloud
  Network): *Internet exposure* (machine, port, from, reached on, rule, and the
  critical/high findings on that port), *Broad rules*, *Static NAT*,
  *Gateways*.
- **`vulnhub_internet_paths`** (priority 20, merged into what AWS supplies, not
  replacing it): each way in with `firewall: policy`, `via: direct|nat`.
  `captured_at` gains `|cp:<stamp>` so the threat context's cache moves when a
  new policy is read. The widget labels `nat` ("through static NAT on …") and
  `policy` ("allowed by firewall policy").
- **`vulnhub_cloud_reachable_assets`** (priority 20, added to AWS's answer):
  the asset gate's evidence, e.g. *tcp/443 open to anyone on 198.51.100.10
  (Check Point Perimeter #1 Web in)*.

Exposure is recomputed from the stored snapshot (no API call) after every
Check Point run and whenever an asset-bearing connector (Tenable, CMDB, Intune,
AWS, Plerion, Defender) finishes, since addresses move with the register.
`wp vulnhub checkpoint-exposure` does the same by hand.

## In the network diagrams and on the asset page

`VulnHub_CheckPoint_Topology` reads only what is stored (the AWS capture's
nodes and route tables, the Check Point gateways and their site verdicts, the
asset and location registers).

**Cloud Network estate flowchart** (filter `vulnhub_aws_estate_flow`, added in
`VulnHub_AWS_Network::estate_flow()`):

- *Check Point — inline firewall* gains the gateways registered in Check Point
  for AWS (count, version, any not communicating), and lists AWS appliance
  groups named like Check Point (`CP` in the name) that no registered gateway
  matches — *Not registered in Check Point* — managed elsewhere, or left over.
- *On-premises* gains a *What is here* disclosure (topology.js `destCard()` now
  draws `meta` and `note` on a destination): each data-centre cluster with its
  site, every branch gateway with its site (or *site not known*), the networks
  AWS route tables send to the transit gateway (with how many VPCs), single-
  server routes resolved to named machines (a hostname that is only a digest
  shows the address instead), and every virtual private gateway (a
  site-to-site VPN straight into a VPC) with the networks it carries,
  summarised by /16. List values are one line per item.
- The *to the corporate network* edge is labelled with the networks it
  carries.

Which tunnel or link the transit gateway uses to reach a particular firewall
lives in the network account's transit-gateway route tables and VPN
connections, which the AWS capture does not read, so that last hop is said, not
drawn.

**Asset detail** (action `vulnhub_asset_detail_network`, fired at the end of
the identity panel): a *Network path* block — the firewall at the asset's
location (a cluster named once; the AWS gateways as one line), and for an AWS
instance the way out read from **its subnet's own route table** (the subnet
detail records it): through the gateway load-balancer endpoint, through the
transit gateway, straight to an internet gateway, or a NAT gateway; the
on-premises networks it reaches and any VPN gateway; and, once the policy is
read, the ports the firewall opens to it from outside.

## NAT and port forwards tab

The Firewall policy page's NAT tab lists **port forwards** first: manual NAT
rules that translate one public address on a named service to one internal
address ("WAN port → LAN port"), with who the rule applies to (original
source) and the NAT rule number (`<package> #<n>`) so it can be found in
SmartConsole. Then **whole-address translations**: automatic static NAT on host
objects and manual rules on any service. Rows whose original address is
private are marked *internal address*; disabled rules are marked. A forward
opens nothing by itself — the access rules decide, which Internet exposure
works out. (The first version listed only whole-address mappings, so no port
forward was visible.)

## Interface topology (`VulnHub_CheckPoint_Interfaces`)

Once the policy is read, the cluster and gateway objects carry their
interfaces, and each interface its topology: internal, DMZ or internet, and
for internal ones either "the network defined by the interface address and
mask" or a group of networks (its anti-spoofing list). That is the firewall's
own statement of what sits behind each interface, so it is used as fact, not
inferred from asset addresses. The model is built from the stored snapshot and
the AWS capture, and cached per policy read and AWS capture (transient
`vulnhub_cp_ifaces_<hash>`).

- **Where AWS comes in.** The internal interface whose topology lists the most
  AWS VPC ranges (at least three). A listed range counts as AWS only when it
  sits inside a VPC range; the RFC 1918 summaries overlap every VPC and say
  nothing.
- **AWS ↔ on-premises rules.** The accept rules in that gateway's installed
  package (inline layers walked) with an AWS range on one side and a private
  range outside every VPC, or Any, on the other. Same AWS test as above, so a
  rule that covers AWS only through `10.0.0.0/8` does not count. Each rule
  carries its direction, the names on each side, ports, and whether it opens
  every port or has Any on one side.
- **Placing an address** (`place()`): the most specific interface subnet it is
  on (directly connected), else the most specific network a topology lists it
  behind. Ranges wider than /16 are skipped as catch-alls.

Where it shows:

- **Cloud Network diagram.** The firewall band (relabelled *Firewalls*) gains a
  card for the on-premises firewall AWS comes in through: gateway and policy,
  interface and subnet, AWS ranges behind it, accept-rule counts by direction,
  rules open on every port. The transit-gateway lane's line to On-premises now
  runs through that card (`path-transit → fw-onprem → dest-onprem`, labelled
  with the rule count). On-premises → *What is here* adds *AWS comes in
  through*, *Rules between AWS and on-premises* (totals and the widest four),
  each data-centre cluster's directly connected segments, and each branch
  gateway's segment count.
- **Asset page → Network path.** *Network segment* (subnet, gateway, interface,
  site) or *Seen by the firewall* (the network object it is listed behind);
  *Site, by the firewall* for an on-premises asset with no location; for an AWS
  machine, *To and from on-premises* with the number of rules each way and up
  to four of them.
- **Firewall policy page.** Two tabs: *Interfaces* (every gateway's interfaces,
  what each faces, the networks behind it, AWS ranges, the entry interface
  marked) and *AWS ↔ on-premises* (the rules, filterable by direction or
  "every port or Any").

Gateways are listed once (`VulnHub_CheckPoint_Store::gateway_rows()`): after a
policy read the table holds the Smart-1 Cloud service's row and the management
server's row for each gateway; the service row is kept (it has the connection
status), named from the management row when blank, and cluster objects are
left out because their members stand for them.

Smart-1 Cloud refuses `session-name` / `session-description` on a read-only
login, so the client sends only `read-only` and `session-timeout`.

## Not yet

- Reading later ordered layers, and reading each package only against the
  networks behind its own gateway's interfaces.
- Interface topology for the AWS autoscaling gateways (they carry one or two
  interfaces and no useful topology).

