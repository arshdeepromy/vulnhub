# Patch availability and end of life

Two questions the severity number cannot answer, and the reason both are now
their own chart:

- **Can this be fixed at all?** A critical with a vendor patch is a change
  request. A critical with no patch is a compensating-control conversation.
  On this estate 202,327 of 228,107 open findings have no vendor fix, and
  they sit on **39 machines** — so the honest work item is "those 39", not
  "202,000 findings".
- **Is anybody still shipping fixes for this platform?** A machine past its
  operating system's end of life will not get a patch for the next critical
  either. That is a project, months ahead of the incident, and the only
  useful thing a dashboard can do is put the number in front of the person
  who writes the plans.

---

## Patch availability

### How it is decided

Tenable answers it in two columns and neither alone is enough:

| Column | Populated | What it means |
| --- | --- | --- |
| `patch_publication_date` | 2,187 of 11,746 vulns | Definitely a patch. Plenty of real fixes never get a date — "Update the affected packages" carries none. |
| `solution` | 11,745 of 11,746 | The human sentence. Its "no patch" case is one fixed string Tenable emits verbatim: `There is no known solution at this time.` — on 9,520 rows here. |

So the test is: **a patch date, or a solution that is not that sentence.**
Measured on this estate the two never co-occur (zero overlap), which is the
evidence that the string is a reliable marker rather than a coincidence.

That comes to 2,226 patchable of 11,746 vulnerabilities.

### Where it lives

`VulnHub\Core\Repo` holds the test twice, deliberately adjacent:

```php
Repo::patch_sql( 'v' )   // the SQL, for aggregates and for filtering
Repo::has_patch( $row )  // the same test against a row in memory
Repo::NO_SOLUTION        // the sentence itself
```

They are next to each other because the chart is drawn from an aggregate and
the list it links to is filtered row by row. **If you change one, change the
other in the same edit.** `dev/lifecyclepass.js` asserts that every segment of
the chart lands on a list of exactly that length, which is what catches a
divergence.

- `Repo::patch_matrix()` — severity × patchable, with three counts per cell
  (`vulns` / `findings` / `assets`). They answer three different questions and
  the honest "how many" depends on which was asked. **Scoped to
  `vh_reportable_sql()`**, because the vulnerability list defaults to the same
  reporting scope; when it was not, the chart promised 2,457 and the list
  delivered 2,453, which reads as a rounding error rather than a filter.
- `Repo::findings( [ 'patch_available' => '1' | '0' ] )` — the filter the chart
  segments link to. Note `'0'` is a real value; do not let an `array_filter`
  strip it.
- Findings rows hydrated by `Repo::findings()` carry `patch_publication_date`
  and `solution`, so `has_patch()` works on them without another query.

### The chart

`VulnHub_Dash_Patching` draws it with `VulnHub_Dash_Charts::segment_bars()` at
`'scale' => 'row'` — every row gets the full width. That matters: low severity
outnumbers critical fifty to one, so on a shared scale the critical bar is a 2%
sliver and its split is invisible. The absolute total still sits at the right
of every row, and the severity donut already answers "which severity is
largest", so nothing is lost by giving up the shared scale here.

---

## End of life

### The table

`wp-content/plugins/vulnhub-core/data/eol.php` — a checked-in table, 74 rows,
each with a `source` URL to the vendor's own lifecycle page. Every date was
verified against that page in September 2026.

It is a file, not a feed, because an external EOL API is one more thing to
authenticate, rate-limit, cache and be broken by, and the answer changes about
four times a year. The correction path is the Administration screen instead
(**VulnHub → End of life**, mirrored in the portal under Platform).

Corrections are stored **as differences**, in the `vulnhub_eol_overrides`
option, not as copies. Change one date and only that field is remembered, so
the next release's dates still reach every row nobody has touched. A shipped
row can be reverted; a row added in the portal can be deleted; "Restore the
shipped table" drops everything.

### What is deliberately not in the table

- **Internet Explorer 11.** Its CPE is on 470 machines here and every one is a
  disabled OS component, not a browser anybody runs. Its retirement is also
  conditional — IE mode in Edge is supported to 2029, and IE on an LTSC build
  follows that build. Listing it would produce 470 false alarms.
- **.NET Framework 3.5, 4.7 and 4.8.** Windows components, supported as long as
  the Windows underneath them is, so they have no date of their own. The
  genuinely retired 4.5.2 / 4.6 / 4.6.1 *are* listed.
- **Anything the vendor has not published.** Windows Server 23H2 is the live
  example: Microsoft's Annual Channel page still reads "In Support" with no
  date. It is in the table with a null date, so those machines are still
  counted — under "no published date" rather than under a number somebody
  invented.

### Matching

**Windows is keyed on the build number, never on the product name.** 21 assets
in this estate are labelled `Microsoft Windows 11 Enterprise` and are running
build 19045, which is Windows 10 22H2 — end of life since October 2025. The
label is somebody's typing; the build is the machine's. (`docs/CORE-API.md`
records the same disagreement from the import side.)

`Eol::windows_build()` handles the four shapes the inventory actually contains:

```
26100 (24H2)      Intune, feature-update style
10.0.26100.9106   Tenable, full NT version
6.3.9600.21620    Windows 8.1 / Server 2012 R2 — NT 6.3
26100             bare
```

Builds **9600** and **26100** each belong to a client release *and* a server
release. The tiebreaker is `asset_type`, not the OS string — half the Windows
Server rows here arrived truncated to `Microsoft`, and the classifier has
already decided what the machine is from far more evidence than its OS name.

Everything else matches on a version prefix against what `Os::parse()` pulls
out, longest prefix first so `9` cannot swallow a `9.3` that has its own row.

**Software** matches the CPE strings Tenable reports on the asset
(`cpe:/a:openssl:openssl:3.0.13`): `cpe` is the `vendor:product` half and
`version` is a prefix match on a dot boundary. Counted once per machine, so the
number is "machines to visit", not "installations".

### Three counts, kept apart

`Eol::estate()`, `Eol::software()` and `Eol::hardware()` are three separate
conversations with three different people, so they are never added together.
Hardware in particular comes from the CMDB's own `support_end_date`, which is a
**warranty** date — a machine out of warranty still gets security updates, and
a machine on a current OS can still be one nobody will repair.

Assets whose release cannot be established are **not dropped**. They group
under their family with an unknown status, because "48 Red Hat machines whose
release we do not know" is itself a finding, and omitting them would make the
chart add up to less than the estate.

### Drill-through

A release is not a column anybody can put in a `WHERE` clause, so
`Eol::asset_ids()` resolves the group and `Repo::assets( [ 'eol' => $key ] )`
takes the ids. Same matcher, one implementation, so the bar and the list cannot
disagree. `Repo::assets()` also accepts a plain `ids` array for the same reason.

---

## CSV export

`VulnHub_Dash_Export` streams any portal list as CSV, using **the same
repository call the screen was rendered with, minus the paging**. Somebody who
spent five minutes narrowing to "critical, past SLA, owned by Infrastructure"
wants those rows, not 228,000 others.

- Views: `assets`, `findings`, `coverage_gaps`, `patch_status`, `eol`.
- Capability-checked, nonce-checked, and written to the audit trail with the
  filters it ran under — "who downloaded the asset list" and "who downloaded
  every unpatchable critical" are different events.
- Streamed 500 rows at a time (the repository's own ceiling — asking for 1,000
  and advancing by 1,000 silently exports every other page), capped at 50,000
  rows, with a UTF-8 BOM so Excel does not read it as Windows-1252.
- `fputcsv( …, ',', '"', '' )`: the empty escape gives RFC 4180 doubled-quote
  escaping. PHP's backslash default is not RFC 4180 and Excel does not undo it.

### Choosing the columns

The export control is a `<details>` disclosure, not a link. Opening it shows
every column the view can emit, grouped the way the screen groups them
(Identity / Platform / Ownership / Coverage / Source identifiers / Exposure on
assets; Asset / Vulnerability / Severity and scoring / Remediation on findings),
with All and None shortcuts. Submitting posts `cols[]` to the same GET endpoint,
carrying the screen's current filters as hidden fields.

- `columns( $view )` is the single declaration: group, label, and the callable
  that produces the cell. Adding a column is one line there and nothing else.
- `chosen()` intersects that declared order against `cols[]`, so the file order
  is stable whatever order the boxes were ticked in, and an unknown key cannot
  reach the writer. An empty selection falls back to every default column, which
  is what an untouched picker submits and what a bare link would have produced —
  so old bookmarked export URLs keep working unchanged.
- `emit()` calls only the chosen callables. The CVE column is a `json_decode`
  per row; leaving it unticked on a 50,000-row export is not free.

The button sits on the assets list, the vulnerability list, and the **Affected
assets** panel of a single vulnerability — on that last one it carries the
`vuln` and `state` of the panel, so what downloads is the machines listed under
that CVE, not the whole estate.

Download lives in the panel's *header*, above the checkboxes rather than below
them. A 22-column list pushed a footer button past the bottom of the window,
where scrolling could not reach it: an absolutely positioned panel does not
lengthen the page it hangs from. At 640px and under the panel stops floating
and flows inline instead.

Widget-level CSV (`admin_post_vulnhub_widget_csv`) is separate and unchanged:
it exports the rows one widget was drawn from.

---

## New widgets and existing boards

A widget shipped after somebody arranged their dashboard used to be invisible
to them for ever. `VulnHub_Dash_Widgets` now keeps a second user meta,
`vulnhub_dashboard_seen`: anything in the default layout that is neither on
their board nor in that list is appended once, written back to their saved
layout, and recorded as seen. Take it off and it stays off — saving a layout
records everything on it as seen.

---

## Testing

```bash
node dev/lifecyclepass.js
```

29 assertions. The ones that matter: every patch segment and every EOL bar is
followed to its list and the counts are compared, and the CSV from a filtered
list is counted against the list itself. Screenshots land in `dev/shots/`.

`dev/browserpass.js` also covers `/assets/?eol=…`,
`/vulnerabilities/?…&patch_available=0` and the portal lifecycle screen at both
widths and in both themes.

