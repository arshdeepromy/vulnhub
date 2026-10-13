# Control gaps

The **Control gaps** page (view `control-gaps`, `/control-gaps/`, after Cloud
Posture in the rail) lists findings that repeat because one mistake was copied
into many places, and names the control that would stop it recurring.

The other screens answer *what is wrong, and where*. This one answers *what
keeps producing it*. A vendor connector role deployed by StackSet is the same
role in every account it reached; a function deployed to dev, test and prod is
the same code three times; a meeting client on 400 laptops is one update
policy. Fixing those rows one by one clears the screen until the next deploy.
Fixing the cause stops the rows arriving.

## The cross-account grouping key (Plerion)

`vulnhub-plerion/includes/class-vh-plerion-cause.php`. Every Plerion finding
carries four extra columns, set on upsert:

| Column | What |
|---|---|
| `cause_key` | `md5( detection_id | resource_type | stem )` — short enough to index and to carry in a URL |
| `cause_stem` | the resource name with everything that only says *where it runs* removed |
| `cause_account` | the account, from `account_id` or, when Plerion sends none (IAM findings), from the ARN inside `asset_prn` |
| `env_tier` | the first environment token found (`dev`, `test`, `sit`, `uat`, `staging`, `preprod`, `nonprod`, `prod`, `sandbox`) |

The stem is built by `VulnHub_Plerion_Cause::stem()`:

1. Strip CloudFormation's random suffix: an all-capitals run of 8–14 letters
   and digits after the last `-`/`_`, on a name that is not itself all
   capitals (`orders-api-ReadFunction-A1B2C3D4E5` → `orders-api-ReadFunction`).
   Checked before lower-casing — case is the only thing that tells the suffix
   from a word.
2. Lower-case. Drop a task-definition revision (`:14`). Replace a 12-digit
   account id with `{acct}` and a region (`ap-southeast-2`) with `{region}`.
3. Split on `- _ . /` and spaces and drop every token that is a tier
   (optionally followed by one or two digits, so `preprod2`, `dev1`).
   `non-prod` and `pre-prod` are joined first so they read as one token.
4. A name that was nothing but a tier keeps the tier as its stem, so every
   resource called `prod` does not become one group.

The tier list is deliberately short and filterable
(`vulnhub_plerion_cause_tiers`). Words that are sometimes a tier and sometimes
part of a real name (`live`, `dr`, `np`) are left out because they would merge
things that differ.

Resources with an empty name and no ARN (account-level CSPM checks such as
"no organisation trail") get an empty stem; the key is then the detection and
resource type, which is right — it is one setting, missing in N accounts. The
page shows the stem as *(account setting)*.

**Changing the rules.** Bump `VulnHub_Plerion_Cause::RULES`. The next request
that installs the Plerion table (`VulnHub_Plerion_Findings::install()`) sees the
option `vulnhub_plerion_cause_rules` differ and re-keys every stored row in one
transaction (about a second for a few thousand rows). `wp vulnhub
plerion-causes --dry-run` reports how many rows a change would re-key without
writing; without `--dry-run` it re-keys now.

## The three tabs

| Tab | Rows | Listed when |
|---|---|---|
| **Cloud causes** (`?tab=cloud`) | Plerion findings grouped by `cause_key` | the group spans `accounts` ≥ 3, **or** `resources` ≥ 5, **or** `tiers` ≥ 3 |
| **Cloud detections** (`?tab=detections`) | Plerion findings by detection, with the number of distinct causes behind them | always — this is the "340 findings, 171 fixes" view |
| **Hosts by product** (`?tab=hosts`) | Tenable product rows (the Exposure-by-product grouping, read from `summary_products`) | the product is on `assets` ≥ 5 machines |

Thresholds come from `VulnHub_Dash_Control_Gaps::thresholds()`, filterable as
`vulnhub_control_gap_thresholds`, and the page prints them under the tiles so a
reader knows what "repeated" means.

Rows are built once, by `VulnHub_Dash_Control_Gaps::rows( $tab )`, in one shape
for both the table and the CSV export (`view=control_gaps&tab=…`), so the file
always matches the screen.

## Every number opens exactly its rows

- A cloud cause's **Findings** links to Cloud Posture with `?cause=<key>`; a
  detection's links with `?detection=<id>`. Both groups count over the rows the
  Cloud Posture list shows (`is_exempted = 0`), so the link returns the number
  on the row. Cloud Posture shows a banner naming the cause or detection with a
  *Show all findings* link, and keeps the scope through *Filter* (hidden
  inputs).
- A host row links through `VulnHub_Dash_Widgets::product_findings_url()` — the
  same function the Exposure-by-product widget and the Products page now use,
  carrying `product`, `pkind`, `life=reportable`, `state=open_any`,
  `sev_not=info`, `excepted=exclude` (see `docs/FILTERS.md` §8 and §8a). The
  App update / Bundled counts add `comp=app|bundled` (§11).

## Suggested controls

Each row gets a **layer** and a **mechanism**. Layers, strongest first:

| Layer | Meaning |
|---|---|
| Org prevention | refused before it happens, in every account (SCP, RCP, declarative policy, device baseline) |
| Pipeline prevention | the build fails, so the bad version never ships (dependency bot, SCA gate) |
| Auto-remediation | it happens, then a service puts it back (patch policy, managed app updates, Config rule, Firewall Manager) |
| Exception | nothing to do but wait for a vendor; record it with a review date |
| Detect and ticket | a person has to notice and fix it |

Cloud rows map by Plerion detection id where one is known (its public
catalogue numbers — for example `PLERION-AWS-1178`, accounts able to leave the
organisation → SCP), else by the finding's source family (`ACCESS` → RCP on
STS, `IAM_ACCESS` → permission-boundary SCP, `CWPP` → pipeline, `CSPM` →
Config rule, `GRAPH`/`ATTACK_PATH` → no-auth SCP). A `CWPP` finding on an EC2
instance maps to patching instead, since a running instance is patched, not
rebuilt from a repository.

Host rows map by product kind: `os_package` and `os_update` → auto-remediation
(patch policy / update rings); `application` → managed app updates, or
*Exception* when more than half its findings are files shipped inside it;
an unattributed `library` → pipeline (find what ships it).

Both maps are filterable (`vulnhub_control_gap_cloud_control`,
`vulnhub_control_gap_host_control`). The suggestion is a starting point for a
person, not an instruction.

## Checked (2026-10-12, live data)

- Every cloud cause group (249) and every detection (35) against the total its
  `?cause=` / `?detection=` link opens on Cloud Posture: no mismatches.
- Host rows against the Vulnerabilities list they link to, including a `comp=bundled`
  split: same counts.
- Each tab's CSV against the screen: same row count (249, 35, 322).
- `wp vulnhub plerion-causes --dry-run` after the first backfill: 0 rows to re-key.

