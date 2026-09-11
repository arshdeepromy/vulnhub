# VulnHub app — unauthenticated security scan

**Target:** VulnHub — Vulnerability & Asset Management (WordPress)
**Origin scanned:** http://localhost:8093 (also reachable at the deployment's public hostname via a Cloudflare tunnel)
**Date:** 2026-09-09
**Scope of this pass:** what a stranger with only the login-page URL can reach — no credentials.
**Method:** `curl` for the HTTP/API surface (faster and more precise than a browser for this),
Playwright headless Chromium to confirm the login page and the client-side gate visually.
**Authorisation:** owner-requested test of their own application.

---

## Headline

The application's own authorisation is sound. Every custom REST route
(`vulnhub/v1/*`, `vulnhub-mcp/v1/*`, `vulnhub-import/v1/*`) returns **401** without
credentials; the portal views redirect to `/sign-in/`; the public Estate page renders
only "Sign in". A headless browser hitting `/assets/` unauthenticated was bounced to
`/sign-in/` and leaked **zero** data markers.

The exposure is the **WordPress platform underneath it**, not the app. WordPress leaks
the administrator username (`admin`, id 1) three different ways, and the origin advertises
its software versions. On a login page reachable from the internet, a confirmed username
turns "guess two things" into "guess one" — it is the single change that most helps an
attacker, and the thing the "only the login page should be exposed" goal is really about.

---

## Findings

| # | Severity | Finding | Evidence |
|---|----------|---------|----------|
| 1 | High | **Admin username disclosed via REST** | `GET /wp-json/wp/v2/users` → `[{"id":1,"slug":"romy",...}]` |
| 2 | High | **Admin username disclosed via author scan** | `GET /?author=1` → 301 `Location: /author/romy/` |
| 3 | Medium | **Login form confirms valid usernames** | wrong pw for `admin` → "the password you entered for <username> is incorrect"; unknown user → "not registered on this site" |
| 4 | Medium | **`xmlrpc.php` enabled** (pingback + `system.multicall`) | `POST /xmlrpc.php system.listMethods` lists `pingback.ping`, `system.multicall` — brute-force amplification and pingback SSRF/reflection |
| 5 | Medium | **Debug log world-readable** | `GET /wp-content/debug.log` → 200; leaks absolute server paths and a real code warning (see #8) |
| 6 | Low | **Software version disclosure** | `Server: Apache/2.4.68 (Debian)`, `X-Powered-By: PHP/8.3.33`, `GET /readme.html` + `/license.txt` → 200 |
| 7 | Low | **Debug mode on in a public-facing config** | compose sets `WORDPRESS_DEBUG: 1`, `WP_DEBUG_LOG`, `SCRIPT_DEBUG` — display is off, so no direct leak, but posture is wrong for an app on the public internet |
| 8 | Low | **"Headers already sent" bug** | `debug.log`: output starts at `vulnhub-dashboard/templates/app.php:29` before a login-flow header call — real defect, currently only noisy |

### Verified safe (no action)

- All `vulnhub/v1/*`, `vulnhub-mcp/v1/*`, `vulnhub-import/v1/*` routes → **401** unauthenticated. No route uses `__return_true`; the "route/permission count mismatch" is *more* permission lines than routes (shared guard + comments).
- `vulnhub-mcp/v1/mcp` demands a bearer connector token.
- Portal views (`/assets/`, `/vulnerabilities/`, `/tickets/`, `/exceptions/`) → 302 to sign-in. Estate page gated to "Sign in". Browser confirms no data leak.
- `/wp-content/uploads/` directory listing → 403. Auth cookies are `HttpOnly`. `wp-login.php` carries `X-Frame-Options: SAMEORIGIN` and `Content-Security-Policy: frame-ancestors 'self'` (clickjacking-safe).

---

## "Every system or function that could be affected"

The four hardening findings (#1–#6) are **WordPress-platform**, not app-code, so the fix is
cross-cutting and belongs in one place rather than scattered through the plugins:

- **User enumeration (#1, #2)** — affects the REST users controller and the author-archive
  rewrite. Fix once at the platform level; no plugin touches these.
- **Login error text (#3)** — the `login_errors` filter; global.
- **xmlrpc (#4)** — `xmlrpc_enabled` / method filters; global.
- **Debug log + readme + versions (#5, #6)** — file-level (Apache) plus header filters.
- **Bug (#8)** — local to `vulnhub-dashboard/templates/app.php`.

Applied as a single mu-plugin (`vulnhub-hardening.php`) for the PHP-level controls and a
small `.htaccess` block for the file-level ones, so nothing depends on a plugin staying
active and the app plugins are left unchanged.

---

## Fixes applied & verified (2026-09-09)

Two files, both under the bind-mounted `./wp` so they survive container recreation:

- `wp/wp-content/mu-plugins/vulnhub-hardening.php` — PHP-level controls
- `wp/.htaccess` — file/banner controls (block above the WordPress marker block)

| # | Finding | Before | After |
|---|---------|--------|-------|
| 1 | REST user enumeration | `200`, exposes `slug:romy` | `404` for anonymous; `200` preserved for logged-in users |
| 2 | `?author=N` / author archive | `301 → /author/romy/` | `404` |
| 3 | Login username oracle | "…for **romy** is incorrect" vs "not registered" | identical "username or password is incorrect" |
| 4 | `xmlrpc.php` | enabled (pingback + multicall) | `403` (Apache) + `xmlrpc_enabled` false + methods dropped |
| 5 | `wp-content/debug.log` | `200` | `403` |
| 6 | `readme.html` / `license.txt` | `200` | `403` |
| 6 | `X-Powered-By: PHP/8.3.33` | present | removed; added `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options`; `X-Pingback` removed |

**No regressions:** `/sign-in/` 200, `wp-login.php` 200, `wp-admin` 302→login, all 40 custom
`vulnhub/*` routes still registered and still `401` anonymous / `200` authenticated.

### Residual (server-config, not closable from `.htaccess`/PHP) — Low

- **#6 `Server: Apache/2.4.68 (Debian)` banner.** Needs `ServerTokens Prod` + `ServerSignature Off`
  in Apache config; `mod_headers` is not loaded in the image. Belongs in the image/compose.
- **#7 `WORDPRESS_DEBUG: 1`.** The only leak it caused (the log file) is now blocked and display was
  already off. Recommend `WORDPRESS_DEBUG: 0` for the public deployment — one-line compose change,
  needs a container recreate.
- **#8 "headers already sent" at `vulnhub-dashboard/templates/app.php:29`.** A real bug, not a
  vulnerability (display off; only a log line). Left deliberately — the safe fix touches the login
  render path and wants its own change.

### Edge note

Scanned the origin (`localhost:8093`). At the public hostname, Cloudflare may already mask the
Server banner and enforce HTTPS/HSTS; confirm HSTS is set at the edge, since the origin is plain
HTTP inside the tunnel.
