# AWS cost and cost savings

Two portal screens in `vulnhub-aws`, both read from one stored snapshot:

| Screen | Slug | What it shows |
|---|---|---|
| AWS Cost | `/aws-cost/` | Last month, month so far, straight-line projection, Savings Plan coverage of EC2, 45-day daily spend, spikes, accounts, services, biggest usage lines, and what starts and stops instances |
| Cost Savings | `/aws-savings/` | Suggestions, split into *confirmed* and *needs confirmation*, each accepted or dropped with a click; running plan total; CSV of the accepted plan |

Neither screen calls AWS. **Refresh from AWS** (Manage or Run-sync permission)
queues `vulnhub_aws_cost_refresh` on the cron runner.

## Keeping it current

`VulnHub_AWS_Cost_Collector::after_sync()` listens on `vulnhub_sync_complete`.
After a **successful** `aws` sync — the one moment the SSO session is known to
be good — it queues a cost read unless auto-refresh is off, a read is already
running, or the newest snapshot is younger than the mode's floor:

| Mode (`vulnhub_aws_cost_auto`) | Floor |
|---|---|
| `daily` (default) | 20 hours |
| `weekly` | 160 hours |
| `off` | never automatic |

The choice sits beside **Refresh from AWS** on the dashboard. What the last
sync decided is kept in `vulnhub_aws_cost_auto_last` and shown under the
choice. A read counts as running while its progress (`vulnhub_aws_cost_progress`)
is `queued` with the event still scheduled, or has a heartbeat under ten minutes
old. A read that finds the SSO session expired is stored as `failed` with that
message and the screens keep showing the last complete snapshot. Decisions are keyed by suggestion id, so
they carry across reads; a suggestion that stops appearing moves to "no longer
in the latest data".

## Export

**Export HTML** on either page (View permission; the button only appears once
there is a snapshot, and the route answers 404 before then) downloads one
self-contained file, `vulnhub-aws-cost-<date read>.html`, from
`GET /cost/export?view=cost|savings`: both screens as tabs (`view` only picks
the tab it opens on), the
current snapshot embedded, the same two scripts in offline mode
(`VH_AWS_COST.offline`), VulnHub's dark and light tokens (`cost-export.css`),
starting in the viewer's system theme with a toggle. Refresh, auto-refresh and
progress are stripped from the embedded data. It loads nothing from the network. Accept / Drop in the file are a what-if that
totals a plan and downloads it as CSV — nothing is written back. Every export is
audit-logged as `aws_cost_export`. The file holds account IDs, instance names
and addresses, so treat it like the screens themselves.

## The snapshot (`class-vh-aws-cost-collector.php`)

Read-only, through the AWS SSO session (`VulnHub_AWS_Connector::read_session()`),
per account the login can see:

- **Cost Explorer**, filtered to the account being read (`LINKED_ACCOUNT`), so
  an account that can see others is never counted twice: service x usage type
  for last month and month-to-date, record type (Savings Plan covered vs on
  demand) for last month, and 45 days daily by service. Four requests per
  account. **Cost Explorer bills $0.01 per request** — that is why a read never
  runs on every sync, only on demand or at most once per auto-refresh floor.
- **EC2**: every instance (all states), volume and Elastic IP.
- **CloudWatch**: 14 days hourly CPU average/max and network per instance,
  summarised into a weekday x hour grid (site timezone) and bucket stats; 5-minute
  IOPS and throughput for io1/io2 volumes.
- **Schedulers**: Instance Scheduler stacks (hub parameters, including the tag
  key it reads), EventBridge rules and EventBridge Scheduler schedules that start
  or stop instances (`is_start_stop()` — a batch job "on a schedule" is not one).
- **AWS Price List** for exactly the instance types (by OS `operation` code, so
  RHEL and Windows are priced as such), the one-size-down and current-generation
  targets, EBS storage/IOPS/throughput, and idle public IPv4. A price that is
  ambiguous is stored as null.

Cost Explorer paging is followed to the end with back-off on throttling; a
query that still fails leaves that account marked `cost_ok: false`. A run with
no Cost Explorer data at all is stored as `failed` and never shown.

A partial read never replaces a complete one: to the screens a skipped account
would look like costs that vanished, and its suggestions like work that got
done. If any account was not fully read (`cost_ok` or `ec2_ok` false), the Price
List could not be read, or the SSO login listed fewer accounts than the last
complete read, the run is stored as `partial` and the dashboard says "the last
refresh was incomplete" above the last complete figures. Only the very first
read is shown despite gaps, flagged in its message.

Snapshots live in `{prefix}vulnhub_aws_cost_snapshots` (`started_at`,
`finished_at`, `status` ok|partial|failed, `message`, `data` JSON; schema
version in `vulnhub_aws_cost_db`, currently `1`). The newest six rows are kept
to compare against when a number moves; the screens read the newest `ok` one.

## Suggestions (`class-vh-aws-cost-recs.php`)

**Confirmed** — every input measured or from the Price List:

| Rule | Condition | Saving |
|---|---|---|
| Idle instance | ran ≥90% of the window, network < 0.05 MB/h, CPU p95 of the hourly max < 5% | compute + its disks |
| Stopped, still billed | stopped ≥ 30 days (or no activity in the window and no stop date) | its disks + Elastic IPs |
| Unused Elastic IP | not associated | idle IPv4 price x 730 |
| Unattached disk | volume `available` | the volume at list price |
| Off the schedule | non-production, ≥ 20 h/week more than the scheduled fleet and running through weekends | (its measured h/week − fleet h/week)/168 x price x 730 |
| gp2 → gp3 | per account, gp3 provisioned to gp2's own baseline (3 IOPS/GB to 16k; 250 MiB/s above 170 GB) | price difference, only where positive |

The *scheduled fleet* is measured: instances the Instance Scheduler has acted on
(`InstanceScheduler-LastAction`) that ran between 24 hours and 60% of the window
and no more than 10% of the weekend hours. Its median hours a week and the tag
values in use come from them. "Running through weekends" means at least a
quarter of the window's weekend hours.

Instances in an Auto Scaling group, EKS/ECS cluster, Elastic Beanstalk
environment or Karpenter node pool (by their AWS tags) are left out of the
idle, off-schedule and rightsizing rules — their size and hours belong to
whatever manages them. Each instance and disk gets at most one suggestion: one
already claimed by an earlier rule (idle, stopped, unattached, off-schedule)
is not offered again by a later one.

**Needs confirmation** — depends on something not measured here:

| Rule | Unmeasured | Saving shown |
|---|---|---|
| Rightsize one size down / current generation | memory; licensing; driver support | price difference ("if confirmed"); one size down only when CPU peak < 40% and p95 < 25% over a ≥90% window |
| io1/io2 → gp3 | bursts inside 5 minutes; peaks outside 14 days; durability needs | gp3 sized to measured peak ("if confirmed"); skipped above 16k IOPS or 1,000 MiB/s |
| Snapshots, NAT gateways, VPC endpoints, RDS backups, Config, CloudTrail data events, S3 Standard-IA | retention, architecture, compliance | none — today's cost only |

A suggestion with a missing price or a saving ≤ 0 is not made (RDS gp2 → gp3 is
not a rule because the two cost the same in the regions checked).

## Decisions

Stored in `vulnhub_aws_cost_decisions` (option), keyed by the suggestion id
(`sched:<instance>`, `gp3:<account>` …), shared across users, written to the
audit log as `aws_cost_decision`. The server looks the suggestion up in the
current snapshot before recording it. A decision whose suggestion no longer
appears is kept and shown as "no longer in the latest data — likely done"; it
can only be cleared (status `""`), and any other change is refused with 409.
The accepted plan (still-present and gone items) downloads as
`aws-savings-plan-<date>.csv` from the browser.

## REST (`vulnhub-aws/v1`)

`GET /cost`, `GET /cost/savings`, `GET /cost/progress` (View);
`POST /cost/decision` `{id, status: accepted|dismissed|"", note}` (Manage or Triage);
`POST /cost/refresh` and `POST /cost/settings` `{auto: daily|weekly|off}` (Manage or Run sync);
`GET /cost/export?view=cost|savings` (View) returns `text/html` as a download.

