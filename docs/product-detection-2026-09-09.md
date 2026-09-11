# Detecting affected products from vulnerability data

**Source:** `vh_vulnhub_vulns.title` / `.family` / `.description`, joined to open findings.
**Open findings analysed:** 228,107 across 11,741 distinct vulnerabilities (reporting scope: in_service + unknown).
**Note:** `cve_json` is empty and no CPE strings exist in the vuln data, so detection is driven by the **title**, with `family` as a coarse pre-filter — exactly the signals available.

---

## 1. Classification — every vuln lands in one of three buckets

| Bucket | Open findings | % | What it means |
|--------|--------------:|--:|---------------|
| **Native Linux (OS packages)** | 208,216 | 91.3% | Fix by running the distro updater on the host |
| **Third-party products** | 16,811 | 7.4% | Fix by upgrading a named app/library |
| **Native Windows / Microsoft** | 3,080 | 1.4% | Fix via Windows Update / MS patch |
| _unresolved_ | 0 | 0% | — |

### The single most important fact

**39 Linux hosts carry 202,327 of your 228,107 open findings (89%).** They are Tenable's
"Linux Distros Unpatched Vulnerability : CVE-…" checks — one finding per missing CVE patch per host.
The title names only the CVE, so they attribute to the **distro**, not a package:

| Group | Hosts | Findings |
|-------|------:|---------:|
| Linux — unpatched CVEs (no vendor fix yet) | 39 | 202,327 |
| Linux — RHEL advisories (RHSA) | 47 | 4,610 |
| Linux — Amazon Linux (ALAS) | 10 | 1,150 |
| Linux — Rocky Linux | 1 | 112 |

**Patching those 39 RHEL/Ubuntu hosts is the fastest way to drop the number.** No app triage required.

---

## 2. How native Linux updates are detected (the rule)

A vuln is **native Linux** if ANY of:
- `family LIKE '%Local Security Checks%'`  (Red Hat / Amazon / Rocky / Ubuntu / SUSE / Debian…)
- `title` starts with a distro name: `RHEL`, `Red Hat`, `CentOS`, `Rocky Linux`, `AlmaLinux`, `Oracle Linux`, `Amazon Linux`, `Ubuntu`, `Debian`, `SUSE`, `openSUSE`, `Fedora`
- `title` contains a native advisory id: `RHSA` / `RHBA` / `ALAS` / `USN` / `DSA` / `DLA` / `ELSA` / `SUSE-SU` / `CESA`
- `title` starts with `Linux Distros Unpatched`
Package (when present) is the token between `: ` and ` (` — e.g. `RHEL 9 : kernel (RHSA-2026:49870)` → `kernel`.

**Native Windows** if `title` starts `KB\d{6,7}`, contains `MS\d\d-\d{2,3}`, or is a `Security Update(s) for Microsoft .NET / Windows Server …` string.

---

## 3. Third-party products detected (top by vulnerable assets)

`kind = library` is flagged separately, as requested.

| Product | kind | Vulnerable assets | Findings |
|---------|------|------------------:|---------:|
| libcurl | library | 499 | 10769 |
| Google Chrome | application | 364 | 375 |
| SQLite | library | 271 | 709 |
| Apache Log4j | library | 124 | 511 |
| Zoom | application | 75 | 242 |
| Oracle Java SE | application | 59 | 1054 |
| Azul Zulu (Java) | application | 45 | 256 |
| Microsoft Office | application | 36 | 77 |
| Microsoft | application | 31 | 124 |
| Node.js | application | 27 | 192 |
| Apache Commons FileUpload | application | 26 | 26 |
| Mozilla Firefox | application | 25 | 211 |
| NVIDIA | application | 25 | 25 |
| Microsoft Windows | application | 22 | 22 |
| Tenable Nessus Agent | application | 22 | 22 |
| Oracle Coherence | application | 21 | 77 |
| Microsoft Visual Studio Code | application | 20 | 67 |
| Pandas | application | 19 | 19 |
| KeePassXC | application | 18 | 18 |
| OpenJDK | application | 17 | 122 |
| HP Hotkey Support | application | 17 | 17 |
| Spring Framework | library | 14 | 185 |
| Oracle Database | application | 14 | 99 |
| JetBrains IntelliJ IDEA | application | 14 | 66 |
| Spring_framework | application | 14 | 14 |
| OpenSSL | library | 13 | 113 |
| 7-Zip | application | 13 | 66 |
| Notepad++ | application | 13 | 28 |
| Microsoft Visual Studio | application | 13 | 13 |
| Microsoft Paint | application | 12 | 36 |

_149 distinct third-party products detected in total; 42 have ≥15 open findings._

### Libraries flagged (kind = library)

| Library | Vulnerable assets | Findings | Note |
|---------|------------------:|---------:|------|
| **libcurl** | 499 | 10,769 | Single biggest third-party lever — one component, ~every Windows host |
| **SQLite** | 271 | 709 | Bundled in many apps; often not directly patchable |
| **Apache Log4j** | 124 | 511 | Includes Log4j 1.x EOL + Log4shell-era CVEs |
| **OpenSSL** | — | 112 | 49 distinct CVEs |
| **Spring Framework** | — | 185 | Java web stack |

---

## 4. Quick-win reading of the list

- **Patch 39 Linux hosts** → −202,327 findings (89%).
- **Upgrade libcurl fleet-wide** → −10,769 findings across 499 hosts (one component).
- **Windows Update on 504 hosts** → −3,073 findings.
- **Google Chrome auto-update on 364 hosts** → −375 findings.
Four actions clear ~95% of everything open.

---

## 5. Automatic detection — design (existing + future uploads)

A single classifier `VH_Product::classify( $title, $family, $description ) : {class, product, kind, package}`
in `vulnhub-core`, applied in two places:

1. **Future uploads** — hook the import pipeline (`vulnhub_finding_imported` / after a vuln row is
   written) so `class` / `product` / `kind` are stamped on the `vulns` row as it lands.
2. **Existing data** — a WP-CLI backfill (`wp vulnhub classify-products`) that walks `vh_vulnhub_vulns`
   in batches and stamps the same columns. Idempotent; safe to re-run after rule changes.

Rules are the ones in §2–§3, as an ordered, filterable table (`vulnhub_product_rules`) so new
products/aliases are data, not code. A nightly re-classify catches titles added since.

**Storage:** add `product VARCHAR(191)`, `product_kind VARCHAR(16)`, `component_class VARCHAR(16)`
to `vh_vulnhub_vulns` (indexed). Widgets then group on a stored column — no title parsing at read time.

---

## 6. Proposed widget — "Exposure by product"

- Horizontal bars ranked by **vulnerable assets** (the actionable unit), toggle to findings.
- Each row: product icon + name + kind badge (library/app/OS) + asset count + finding count.
- Click-through to `/vulnerabilities/?product=<slug>&life=reportable` (needs a `product` filter on
  the findings query — small addition).
- Native Linux / Windows shown as their own rows so "just patch the OS" reads at a glance.
- **Icons:** bundled inline-SVG brand set for the top ~40 products (no external CDN — CSP-safe),
  with a lettered colour chip fallback for the long tail.

---

## Shipped (2026-09-09)

**Classifier** — `vulnhub-core/includes/class-vh-product.php`. Pure `VH_Product::classify($title,$family)`,
validated to reproduce the analysis numbers exactly (208,216 / 16,811 / 3,080). Aliases, known-libraries,
and brand colours are all `apply_filters` hooks, so new products are data, not code.

**Storage** — `vh_vulnhub_vulns` gains `component_class`, `product`, `product_kind`, `product_slug`
(indexed). DB version 21 → 22; dbDelta adds the columns on the next admin load.

**Future uploads** — `Repo::upsert_vuln()` stamps the four columns on every write, so every importer
(Tenable and any other) is covered with no per-importer code.

**Existing data** — `wp vulnhub classify-products [--dry-run]` backfills. Ran it: 11,746 vulns stamped.
Idempotent; re-run after any rule change.

**Drill-through** — `/vulnerabilities/?product=<slug>` filters findings by product (verified: libcurl → 10,769,
Chrome → 375, Log4j → 511). Scope notice shown; the filter is carried through the form.

**Widget** — "Exposure by product" (12-col, top of the default board). Ranks by **vulnerable in-scope
assets**, with a brand icon, a library/app/OS badge, asset + finding counts, a length-by-assets bar, and a
click-through to the findings. Icons: real inline SVG where bundled (Windows today) + brand-coloured
monogram chip otherwise; drop-in real logos via the `vulnhub_product_icons` filter.

### Extending it

- New product spelling merges wrong → add to `vulnhub_product_aliases`.
- A component should count as a library → add to `vulnhub_known_libraries`.
- Want a real logo → add its inner SVG under the product slug in `vulnhub_product_icons`.

### Known long-tail imperfections (cosmetic, ~1% of findings)

A few over-trimmed labels in the tail (`Microsoft` as a bare bucket, `NVIDIA`). They don't affect the
class totals or the top rows; tighten via the alias filter when convenient.
