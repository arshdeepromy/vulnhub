# Filters, and the audit that keeps them honest

Every number on this platform is a promise: *click me and you will get exactly
these rows*. Six things were breaking that promise. They are listed below with
what each one did, and the two scripts that would have caught them.

Re-run both after touching a list screen, a repo filter or a widget:

```bash
docker compose cp dev/filter-audit.php wpcli:/tmp/fa.php && \
  docker compose exec -T wpcli wp eval-file /tmp/fa.php   # numbers vs SQL, links vs lists
python3 dev/form-audit.py                                  # does Apply keep the filter
```

Both exit non-zero on failure, so they can gate a deploy.

---

## 1. Coverage scope was borrowing the ownership vocabulary

**The one that started this.** `Coverage::recalculate()` decided what counts as
in scope by calling `vh_in_service_statuses()` — a list written to answer a
completely different question: *should this asset resolve to an owner?*

A machine in quarantine still has an owner. A machine in a repair bay still has
an owner. Neither is on the network for Tenable to scan. Sharing one list put
**90 quarantined and 7 in-repair machines** into a 196-strong "not scanned by
Tenable" list, so half the work queue was machines that are off the network by
definition — and the servers somebody could actually go and fix were on page
three.

The fix is a second vocabulary, `vh_scannable_statuses()`, editable at
**VulnHub → Settings → Coverage scope**, defaulting to *in service* and
*unknown*:

| | before | after |
|---|---|---|
| Coverage gaps | 196 | **99** |
| Coverage | 76% | **86%** |
| Out of scope | 44 | 142 |

Ownership is untouched: everything still has to resolve to a person or a team,
quarantined kit included.

`unknown` stays in scope by default and that is deliberate — a device nobody has
classified is exactly the kind that goes unscanned, and excluding it would hide
the gap the feature exists to surface. It is now a *default* rather than a rule:
a hard-coded `lifecycle_status <> 'unknown'` in the recompute meant the Unknown
tick box on the settings screen did nothing whatsoever. Unticking it now moves
those 194 assets out of scope, as the control says it will.

The coverage widget names what scope is holding back — "97 assets are not
expected to be scanned and are excluded from this figure: 91 in quarantine, 18
planned, …" — each linking to its own list. A number that moves upward without
an explanation is a number somebody has to re-derive by hand.

---

## 2. Pressing Apply threw away the filter you arrived with

A GET form submits its own fields and nothing else. Every list screen is
reachable from a chart that applies a filter the form has no control for, so:

> Click **5,361** on the attack-path widget → 5,361 findings reachable from the
> internet. Narrow Severity to Critical → **2,459**.
>
> Not 11. Two thousand four hundred and fifty-nine — every critical finding in
> the estate, because `route` and `poc` were silently dropped and the screen
> quietly answered a different question.

The assets list did the same to `eol`, `location_id`, `primary_source`,
`operating_system` and `patch_group`. Those filters were displayed as removable
chips, which made it worse: the chip stayed on screen after the filter behind it
was gone.

`hidden_filters()` now re-submits anything in the query string the form cannot
express. Paging keys are deliberately excluded — page four of the old filter is
not page four of the new one. The same click now gives **11**.

### 2a. ...and then `product` was added to the wrong list

The same bug came back through the front door. `hidden_filters()` takes a list
of keys the *form owns* -- the ones it must not duplicate, because there is a
select for them. `product` was added to that list when the exposure-by-product
widget shipped, but no select was ever added to go with it. So the key was
skipped as a hidden field and had no control either, and it fell straight down
the gap:

> Click **libcurl** on the exposure-by-product widget → 11,637 findings.
> Narrow Asset type to Server → the whole estate's servers, libcurl gone.

Two things follow from this, and both are now true:

- The list is "the form has a control for this", not "this filter exists".
  A key belongs there only if `name="<key>"` appears in the same `<form>`.
  `dev/exportpass.js` fails if `product` stops being submitted.
- The export has to read the filter back under the name the screen holds it in.
  The findings export was missing `product_slug` -- so even once Apply kept the
  filter, Download CSV would have handed back all 228,000 rows. `defender` on
  the assets export had exactly this bug earlier; it is the second instance, so
  the export's argument list is now checked against the screen's, not assumed.

---

## 2b. Search could not find a person

The Owner column is the whole point of this application -- "who do I chase
about this?" -- and typing what it says into Search returned nothing. The
search matched vulnerability title, plugin id and CVE on one side, hostname
and FQDN on the other, and stopped there.

Both lists now include the owner: the person's display name, their email and
their UPN, and the team behind them. Team matters as much as person, because
on unassigned kit the team is the only thing the column shows -- searching
`Windows` has to find every asset whose owner cell reads "Platform Services
Windows", none of which has a person attached.

Email and UPN are matched but never displayed by the search. They are what a
ticket or an alert quotes, so pasting one in and getting that person's estate
is the obvious move.

The vulnerability list also gained `ipv4`, which the assets list already had.
The IP is on screen in both places; it was searchable in only one.

Resolved through the two small tables and handed to the big one as an id list,
which is how the existing search works and why it costs nothing: people holds
501 rows and teams 16, against 232,441 findings.

`dev/ownerpass.js` covers it, and takes its expected counts from hand-written
SQL at run time rather than from constants -- the estate is re-imported often
enough that a literal rots into a false failure.

---

### Still open: a short search term takes twelve seconds

Not caused by the above and not fixed by it. `bc` on the vulnerability list
takes ~12s, and so does any term broad enough to match a large share of one
side -- on this estate `bc` is worse than most, because every hostname begins
`wkstn` or `cloud-`.

The cause is not the size of the id list, which was the obvious suspect and
the wrong one: narrowing the lists by taking the complement when more than
half a table matches changed the row counts not at all and the timings not at
all. It is the shape of the predicate. `( f.vuln_id IN (...) OR f.asset_id IN
(...) )` is an OR across two different indexed columns, and MySQL cannot merge
them once the base predicate has already claimed an index -- EXPLAIN shows it
settling on `exc_state_sev` and filtering 200,548 rows by hand.

The fix is a UNION of the two branches so each can use its own index, which
means restructuring `findings()` around its ordering, paging and count. That
is a real change to the busiest query in the application and it should be done
deliberately, not folded into an unrelated one.

**Update, same day: this stopped mattering, and not for the reason above.**
`bc` now runs in 728ms rather than 12,777ms, with the query untouched. The
binding constraint was never the predicate shape -- it was that MariaDB had a
128MB buffer pool in front of a 491MB findings table, so every scan went to
disk. Resizing the pool fixed it seventeen-fold; the complement rewrite that
was supposed to fix it moved the timings not at all. See PERFORMANCE.md.

The OR-across-two-columns problem is still real and still visible in EXPLAIN,
and it will bite again if the estate outgrows the buffer pool. But it is no
longer worth restructuring the busiest query in the application over.

---

## 3. A "0 gaps" row opened a list of three

`coverage_slice_url()` only added `coverage=gap` when the row had gaps to show.
So the cloud row on the coverage chart read "0 gaps" and opened a list of three
cloud assets. `coverage=gap` is now unconditional: an empty list is the honest
answer to "show me the nothing".

---

## 4. The exception register had a filter nobody could reach

`view_exceptions()` read `status` from the query string and passed it to the
query, but the screen had no control for it. A register you can only narrow by
hand-editing the URL is a register nobody narrows. It has a Status select now.

---

## 5. Closure verification was set to fire instantly

`auto_verify_hours` was stored as **0**. The settings screen enforces a minimum
of 1 and the save handler clamps with `max(1, …)`, so nothing in the UI could
have written it — but the verifier read it with `max(0, …)` and honoured it.

A zero delay means the finding is re-checked against Tenable the moment Jira
closes the ticket, before the scanner has run again. Every closure comes back
*still detected* and every Jira issue gets reopened. That is exactly the failure
the help text on the settings screen warns about, running in production.

All three call sites now read through `vh_verification_delay_hours()`, which
treats 0 as "nobody chose this" and returns the documented 24. The stored value
has been repaired.

---

## 6. Severity-by-age: correct, but it did not say so

The cell counts *vulnerabilities*; the list it opens counts *asset findings*.
Eleven critical vulnerabilities are 1,201 findings. Both numbers are printed in
the cell and the caption explains it, so this is by design — but the link itself
said only "11". It now carries a label: *"11 critical vulnerabilities under 30
days — open the 1,201 asset findings behind them"*. The audit script exempts
this widget by name, with that reasoning attached.

---

## What was checked and found sound

Worth recording, so the next audit does not re-tread it:

- **Every filter argument on `Repo::assets()` and `Repo::findings()`** — 30 of
  them — produces exactly what the equivalent hand-written SQL produces. None is
  read-but-ignored.
- **Pagers** preserve every filter (they rebuild from `$_GET`).
- **Sort links** preserve every filter, including the new `route` / `poc`.
- **CSV export links** preserve every filter.
- **The wp-admin screens** only read what their own forms submit, so they have
  no equivalent of problem 2.
- **`patch_available=0`** survives a round trip. `'0'` is a real answer there —
  "no vendor fix exists" — and the `array_filter` that strips empty arguments
  uses a strict comparison specifically so it survives. The audit harness got
  this wrong before the application did.
