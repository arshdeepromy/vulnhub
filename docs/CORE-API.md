# VulnHub Core — plugin developer contract

Read this before writing any VulnHub integration plugin. Core owns the data model,
the credential vault, scheduling, logging, ownership mapping and the admin portal.
Your plugin supplies **one connector class** and (optionally) its own admin screen.

Plugins live under `wp/wp-content/plugins/` in the repository.

WordPress 7.0.4, PHP 8.3, MariaDB 11. Table prefix `vh_`, so VulnHub tables are
`vh_vulnhub_*`. Use `vh_table('assets')` — never hardcode.

---

## 1. Plugin skeleton

```
vulnhub-<name>/
  vulnhub-<name>.php      bootstrap + header
  includes/
    class-vh-<name>-connector.php
    class-vh-<name>-client.php
  admin/ (optional)
```

Bootstrap:

```php
<?php
/**
 * Plugin Name: VulnHub <Name>
 * Description: <one line>
 * Version:     1.0.0
 * Requires PHP: 8.1
 * License:     GPL-2.0-or-later
 * Text Domain: vulnhub
 */
declare( strict_types = 1 );
if ( ! defined( 'ABSPATH' ) ) { exit; }

define( 'VULNHUB_XXX_DIR', plugin_dir_path( __FILE__ ) );

add_action( 'vulnhub_register_connectors', static function ( $connectors ): void {
    require_once VULNHUB_XXX_DIR . 'includes/class-vh-xxx-connector.php';
    $connectors->register( new VulnHub_Xxx_Connector() );
} );
```

**Do not** use core's `VulnHub\Core\` namespace or its `class-vh-*.php` naming inside
`vulnhub-core/includes` — core autoloads that namespace from its own directory only.
Integration plugins use plain prefixed class names (`VulnHub_Tenable_Connector`) and
`require_once` their own files.

Guard against core being inactive:

```php
add_action( 'admin_notices', static function (): void {
    if ( ! function_exists( 'vulnhub' ) ) {
        echo '<div class="notice notice-error"><p>VulnHub Tenable requires VulnHub Core.</p></div>';
    }
} );
```

---

## 2. The connector class

Extend `\VulnHub\Core\Connector`. Required methods:

```php
public function id(): string;                 // 'tenable' — lowercase, [a-z0-9_-]
public function label(): string;              // 'Tenable Vulnerability Management'
public function description(): string;        // one sentence for the portal card
public function fields(): array;              // settings field definitions
public function test_connection(): array;     // ['ok'=>bool,'message'=>string]
protected function do_sync( array $args = [] ): array;  // ['ok'=>bool,'message'=>string]
```

Optional overrides:

```php
public function icon(): string;               // dashicon slug, default dashicons-admin-plugins
public function category(): string;           // vulnerability|identity|cmdb|itsm|auth|other
public function supports_sync(): bool;        // false for auth-only connectors
public function default_interval(): string;   // vh_15min|vh_30min|vh_hourly|vh_4hours|vh_12hours|vh_daily|vh_weekly|manual
```

### Field definitions

```php
public function fields(): array {
    return array(
        array(
            'key'      => 'base_url',
            'label'    => __( 'API base URL', 'vulnhub' ),
            'type'     => 'url',            // text|url|email|number|textarea|select|checkbox
            'required' => true,
            'default'  => 'https://cloud.tenable.com',
            'help'     => __( 'Change only for regional or FedRAMP instances.', 'vulnhub' ),
        ),
        array(
            'key'      => 'secret_key',
            'label'    => __( 'Secret key', 'vulnhub' ),
            'type'     => 'text',
            'secret'   => true,             // encrypted at rest, masked in the UI
            'required' => true,
        ),
        array(
            'key'     => 'severity_floor',
            'label'   => __( 'Minimum severity to import', 'vulnhub' ),
            'type'    => 'select',
            'options' => array( 'info' => 'Info and above', 'low' => 'Low and above' ),
            'default' => 'low',
        ),
    );
}
```

`select` options are `value => label`. `checkbox` may add `checkbox_label`.
A blank secret field on submit means "keep the stored value" — never clear it.

### Reading configuration

```php
$this->get( 'base_url', 'https://cloud.tenable.com' );  // non-secret
$this->secret( 'secret_key' );                          // decrypted secret
$this->is_mock();                                       // honour this!
$this->settings->get_bool( $this->id(), 'some_flag' );
$this->settings->get_int( $this->id(), 'page_size', 500 );
```

### Inside `do_sync()`

```php
protected function do_sync( array $args = array() ): array {
    $this->log( 'Fetching assets…' );      // goes to the run log, visible in the UI
    $this->bump( 'processed' );            // processed|created|updated|skipped|failed
    return array( 'ok' => true, 'message' => 'Imported 120 assets, 840 findings.' );
}
```

Core wraps `do_sync()` with run bookkeeping, a 30-minute lock, exception capture and
the `vulnhub_sync_complete` action. Throwing is safe — it is caught and logged.

**Mock mode is mandatory.** Every connector must produce useful data with
`$this->is_mock() === true` and no credentials, using the shared fixtures in §5.

---

## 3. HTTP client

`$this->http` is a `\VulnHub\Core\Http` already wired to log into the current run.
It retries 429 and 5xx up to 5 times, always honouring `Retry-After` over its own
exponential backoff, with jitter.

```php
$response = $this->http->get( $url, $query, $headers );
$response = $this->http->post( $url, $body_array_or_string, $headers );
$response = $this->http->post_form( $url, array( 'grant_type' => 'client_credentials' ) );
$response = $this->http->request( 'PUT', $url, array( 'headers' => [], 'body' => [], 'timeout' => 60 ) );

$response->ok();              // bool: no transport error and 2xx
$response->status;            // int
$response->data();            // decoded JSON as array (never null)
$response->header( 'retry-after' );
$response->error_message();   // vendor error envelope decoded (Graph / Jira / Tenable)
```

Never hand-roll cURL. Never log a secret — use `Http::scrub( $url )` if you must
log a URL.

---

## 4. Writing data

All static, on `\VulnHub\Core\Repo`.

### People

```php
Repo::upsert_person( array(
    'source'          => 'intune',     // required, becomes half the unique key
    'source_uid'      => $graph_id,    // required
    'upn'             => 'a.b@x.com',  // lowercased automatically
    'email'           => '…',
    'display_name'    => '…',
    'given_name'      => '…',
    'surname'         => '…',
    'job_title'       => '…',
    'department'      => '…',
    'company'         => '…',
    'employee_id'     => '…',
    'manager_upn'     => '…',
    'office_location' => '…',
    'city'            => '…',
    'state'           => '…',
    'country'         => '…',
    'usage_location'  => 'NZ',
    'is_active'       => true,
    'groups'          => array( … ),   // json-encoded for you
    'raw'             => array( … ),   // json-encoded for you
) );
// returns ['id' => int, 'created' => bool]
```

Matching order: (source, source_uid) → upn → email.

### Assets

```php
Repo::upsert_asset( array(
    'primary_source'     => 'tenable',
    'tenable_uuid'       => '…',
    'intune_id'          => '…',
    'azure_ad_device_id' => '…',
    'cmdb_id'            => '…',
    'hostname'           => 'NZWS-001',    // lowercased automatically
    'fqdn'               => '…',
    'ipv4'               => '10.10.20.15',
    'ipv4s'              => array( … ),    // or comma string
    'mac_address'        => '…',
    'serial_number'      => '…',
    'asset_type'         => 'workstation', // workstation|server|mobile|network|cloud|appliance|unknown
    'operating_system'   => 'Windows',
    'os_version'         => '10.0.22631',
    'manufacturer'       => '…',
    'model'              => '…',
    'criticality'        => 'medium',      // critical|high|medium|low
    'environment'        => 'production',
    'business_service'   => '…',
    'compliance_state'   => 'compliant',
    'enrollment_type'    => '…',
    'join_type'          => '…',
    'has_agent'          => true,
    'is_managed'         => true,
    'first_seen'         => '…',           // any ISO8601 / epoch / MySQL string
    'last_seen'          => '…',
    'last_intune_sync'   => '…',
    'tags'               => array( array( 'key' => 'Team', 'value' => 'Infra' ) ),
    'software'           => array( … ),
    'raw'                => array( … ),
) );
// returns ['id' => int, 'created' => bool]
```

Matching order: tenable_uuid → intune_id → azure_ad_device_id → cmdb_id →
serial_number → hostname. **Never set `owner_person_id` / `team_id` / `location_id`
directly from a sync** — that is the mapping engine's job (§6). The one exception is
the Intune connector, which must write the primary user's UPN into
`raw['intune']['userPrincipalName']` so the `person_from_intune` rule can find it.

### Vulnerability definitions and findings

```php
$vuln_id = Repo::upsert_vuln( array(
    'source'            => 'tenable',
    'plugin_id'         => '182291',       // required, unique with source
    'title'             => '…',
    'family'            => '…',
    'severity'          => 'critical',     // critical|high|medium|low|info
    'cve'               => array( 'CVE-2026-21762' ),
    'cvss2_base'        => 9.8,
    'cvss3_base'        => 9.8,
    'vpr_score'         => 9.4,
    'exploit_available' => true,
    'description'       => '…',
    'solution'          => '…',
    'see_also'          => array( 'https://…' ),
    'patch_publication_date' => '2026-06-11',
) );

Repo::upsert_finding( array(
    'asset_id'    => $asset_id,   // required
    'vuln_id'     => $vuln_id,    // required
    'source'      => 'tenable',
    'severity'    => 'critical',
    'state'       => 'open',      // open|reopened|fixed
    'port'        => 445,
    'protocol'    => 'tcp',
    'service'     => 'cifs',
    'output'      => '…',
    'risk_score'  => vh_risk_score( 'critical', $asset_criticality, true, 9.4 ),
    'first_found' => '…',
    'last_found'  => '…',
    'last_fixed'  => '…',
    'due_at'      => '…',         // first_found + the team's SLA for that severity
    'scan_uuid'   => '…',
) );
// returns ['id' => int, 'created' => bool, 'reopened' => bool]
```

The finding fingerprint is (asset, vuln, port, protocol) — upserts are idempotent.
A finding that returns after being `fixed` is automatically flipped to `reopened`;
watch the `reopened` flag and log it, it is a meaningful security event.

After a bulk import, call `Repo::recalculate_asset_rollups()` once.

Recording a post-closure re-check on one finding:

```php
Repo::record_finding_verification( $finding_id, Tickets::VERIFY_STILL_OPEN, 'reopened' );
// third argument is optional; pass a finding state to change it at the same time
```

Asset cloud identifiers (v11+): `azure_vm_id`, `aws_instance_id`, `gcp_instance_id`
are real columns — use them rather than overloading `azure_ad_device_id`, which is
the Entra ID *device* object id and a match key.

### Tickets

```php
\VulnHub\Core\Tickets::upsert( array(
    'provider'        => 'jira',
    'external_key'    => 'SEC-142',   // unique with provider
    'external_id'     => '10432',
    'url'             => 'https://x.atlassian.net/browse/SEC-142',
    'project_key'     => 'SEC',
    'issue_type'      => 'Task',
    'summary'         => '…',
    'status'          => 'In Progress',
    'status_category' => 'indeterminate',  // new|indeterminate|done
    'resolution'      => '…',
    'assignee'        => '…',
    'team_id'         => 0,
    'asset_id'        => 0,
    'created_via'     => 'manual',    // manual|automation|api
    'payload'         => array( … ),
) );

Tickets::attach_findings( $ticket_id, array( 12, 13, 14 ) );
Tickets::mark_closed( $ticket_id, 'Done' );      // queues closure verification
Tickets::record_verification( $ticket_id, Tickets::VERIFY_CONFIRMED, 'note', $detail );
Tickets::awaiting_verification( 50 );            // tickets to re-check
Tickets::findings_for( $ticket_id );
```

Verification constants: `VERIFY_NOT_REQUIRED`, `VERIFY_PENDING`, `VERIFY_CONFIRMED`,
`VERIFY_STILL_OPEN`, `VERIFY_UNKNOWN`.

### Reading

```php
Repo::asset( $id ); Repo::person( $id ); Repo::vuln( $id ); Repo::finding( $id );
Repo::person_by_upn( 'a.b@x.com' );
Repo::teams(); Repo::team( $id ); Repo::team_id_by_slug( 'infrastructure' );
Repo::ensure_team( 'Network Operations', 'intune' );   // creates if missing
Repo::ensure_location( 'Auckland HQ', 'Auckland', 'New Zealand' );
Repo::assets( array( 'search'=>…, 'asset_type'=>…, 'team_id'=>…, 'limit'=>50, 'offset'=>0 ) );
Repo::findings( array( 'state'=>'open_any', 'severity'=>['critical','high'], 'asset_id'=>…, 'limit'=>50 ) );
Repo::summary(); Repo::breakdown( 'team' ); Repo::top_vulns( 10 );
```

---

## 5. Shared mock fixtures — use these, do not invent your own

`\VulnHub\Core\Mock` generates one deterministic fleet that **every** connector must
draw from, so Tenable and Intune describe the same machines and the ownership
mapping actually joins.

```php
Mock::people();    // ~56 records shaped like Microsoft Graph /users
Mock::devices();   // ~150 records: workstations, mobiles, servers, network gear
Mock::vulns();     // 25 vulnerability definitions shaped like Tenable plugin data
Mock::vulns_for_device( $device );          // the ones applicable to that OS
Mock::has_vuln( $hostname, $plugin_id, $severity );  // deterministic yes/no
```

A `Mock::people()` record has Graph field names: `id`, `displayName`, `givenName`,
`surname`, `userPrincipalName`, `mail`, `jobTitle`, `department`, `companyName`,
`officeLocation`, `city`, `state`, `country`, `usageLocation`, `employeeId`,
`accountEnabled`, `manager` (`['userPrincipalName'=>…]` or null), `isManager`.

A `Mock::devices()` record has neutral field names: `seq`, `hostname`, `fqdn`,
`asset_type`, `ipv4`, `mac`, `serial`, `operating_system`, `os_version`,
`manufacturer`, `model`, `tenable_uuid`, `intune_id`, `azure_ad_device_id`,
`cmdb_id`, `owner_upn`, `owner_name`, `owner_id`, `department`, `office_location`,
`team`, `environment`, `business_service`, `compliance_state`, `enrollment_type`,
`join_type`, `criticality`, `last_seen`, `first_seen`, `has_agent`.
Servers and network devices have an empty `owner_upn` and a populated `team` —
that is deliberate.

A `Mock::vulns()` record is a positional array:
`[0]` plugin_id, `[1]` title, `[2]` severity, `[3]` cvss2, `[4]` cvss3, `[5]` vpr,
`[6]` family, `[7]` cve array, `[8]` description, `[9]` solution,
`[10]` exploit_available bool, `[11]` array of OS strings it applies to.

**Your mock path must reshape these fixtures into your vendor's real payload
format and then run them through the exact same normalisation code as live data.**
That is the point — it proves the live path works.

---

## 6. Ownership mapping — do not do this yourself

Core runs `\VulnHub\Core\Mapping` automatically after any successful `tenable`,
`intune` or `cmdb` sync. Rules are administrator-editable in the portal. The
built-in rules express the business requirement:

- workstations and mobiles resolve to the **Intune primary user** (an individual);
- Tenable tag `Team` maps to a team;
- servers / network / cloud fall back to a default team;
- team and location are then inherited from the owner's Entra ID department and
  office if still unset.

Your job is only to populate the raw signals: asset type, tags, and — for Intune —
`raw['intune']['userPrincipalName']`.

---

## 7. Hooks you can use

```php
do_action( 'vulnhub_register_connectors', $connectors );   // register here
do_action( 'vulnhub_loaded', $core );
do_action( 'vulnhub_sync_complete', $connector_id, $status, $stats );
do_action( 'vulnhub_verify_closures' );    // hourly: re-check closed tickets
do_action( 'vulnhub_run_automations' );    // every 15 min
apply_filters( 'vulnhub_create_ticket', null, $finding_ids, $request );   // ITSM plugin answers
apply_filters( 'vulnhub_refresh_ticket', null, $ticket );
apply_filters( 'vulnhub_admin_pages', $pages );            // add an admin screen
do_action( 'vulnhub_render_admin_page', $slug );           // render it
apply_filters( 'vulnhub_user_bound_asset_types', array( 'workstation', 'mobile' ) );
apply_filters( 'vulnhub_asset_risk_score', 'COALESCE(x.rs, 0)', $assets, $findings );
```

`vulnhub_asset_risk_score` is an **SQL expression** filter, not a value filter.
`Repo::recalculate_asset_rollups()` is one set-based `UPDATE` across the whole
estate -- 25,112 assets against 425,289 findings in 0.9 s -- so returning a
number per asset would mean 25,112 round trips. What you return is spliced into
that statement, where `a` is the assets table and `x` the per-asset aggregate
over open, non-excepted findings (`x.rs` is the summed finding risk). As with
WordPress's own `posts_where`, the return value is SQL and keeping it safe is
the caller's job. The result is clamped to `[0, 999999.99]`, the range of the
`decimal(8,2)` column.

vulnhub-rules uses it to apply the priority weight its classification rules
set. The weight is a percentage of normal -- the editor takes 0-1000 and
suggests 200 -- so 200 doubles an asset's score, 50 halves it, and 0 (the
column default, meaning no rule has set one) leaves it alone:

```php
add_filter( 'vulnhub_asset_risk_score', static function ( string $expr ): string {
    $state = VulnHub_Rules_Repo::state_table();
    return "( {$expr} ) * ( COALESCE( NULLIF( ( SELECT w.priority_weight FROM {$state} w WHERE w.asset_id = a.id ), 0 ), 100 ) / 100 )";
} );
```

**Never name a WP-Cron event after the action it fires.** `Scheduler` listens on
its own cron events, so when `HOOK_VERIFY` was literally `vulnhub_verify_closures`
the callback re-entered itself through `do_action()` and recursed until PHP ran
out of memory -- a 9.6 GB worker the container OOM-killed once a minute, with
nothing in the UI to show for it. The two namespaces are now kept apart:

| Cron event (internal, do not hook) | Public action it fires (hook this) |
|---|---|
| `vulnhub_cron_verify_closures` | `vulnhub_verify_closures` |
| `vulnhub_cron_run_automations` | `vulnhub_run_automations` |

`Scheduler::dispatch()` additionally refuses to re-enter an action that is
already running and writes a `scheduler.reentered` audit line instead, so a
third-party listener cannot reintroduce the same failure.

`do_action( $hook )` with no payload still hands every callback an empty string,
so a listener whose method has a **typed** parameter (`run( int $limit = 200 )`)
raises a `TypeError` under `declare( strict_types = 1 )`. Register those with
zero accepted args:

```php
add_action( 'vulnhub_verify_closures', array( $this, 'run' ), 10, 0 );
```

To add an admin screen:

```php
add_filter( 'vulnhub_admin_pages', static function ( array $pages ): array {
    $pages['vulnhub-automation'] = array(
        'title' => __( 'Automation', 'vulnhub' ),
        'menu'  => __( 'Automation', 'vulnhub' ),
        'cap'   => 'vulnhub_manage',
        'view'  => 'automation',   // no core view file exists, so the action fires
    );
    return $pages;
} );
add_action( 'vulnhub_render_admin_page', static function ( string $slug ): void {
    if ( 'vulnhub-automation' === $slug ) { include __DIR__ . '/admin/views/automation.php'; }
} );
```

An admin screen registered this way is **automatically mirrored into the
front-end portal** — `VulnHub_Dash_Portal::mirrored_sections()` reads
`vulnhub_admin_pages` and draws each one under Administration. You do not
register twice. Two consequences:

* Your view is included on the front end, where `wp-admin/includes/*` is not
  loaded. `Admin::render_screen()` loads `screen.php`, `template.php`,
  `plugin.php` and `misc.php` before including a view, so `submit_button()`,
  `add_settings_error()` and friends work — but anything beyond those four
  files you must require yourself.
* Anything wider than about 700px needs to survive a phone. `.wp-list-table`
  and `.form-table` are handled for you in `app.css`; a bespoke wide layout is
  not.

To add a portal administration section that has no wp-admin equivalent, use
`vulnhub_portal_sections` (filter) and `vulnhub_render_portal_section`
(action). To add a destination to the portal's primary navigation, use
`vulnhub_portal_nav_extra`:

```php
add_filter( 'vulnhub_portal_nav_extra', static function ( array $links ): array {
    $links[] = array(
        'label'  => __( 'Runbooks', 'vulnhub' ),
        'url'    => home_url( '/runbooks/' ),
        'icon'   => 'M4 4h16v16H4z',  // an SVG path, drawn on a 24x24 viewBox
        'active' => is_page( 'runbooks' ),
    );
    return $links;
} );
```

### The dashboard board

Widgets are laid out on a 12-column grid the operator arranges. Two things are
worth knowing before touching it.

**Packing is done in JavaScript, on purpose.** `grid-auto-flow: dense` closes
horizontal holes on its own, but grid makes every item in a row as tall as the
tallest, so a short widget beside a tall one leaves a void. `app.js` measures
each card and writes `grid-row: span n` against an 8px row track — masonry,
until `grid-template-rows: masonry` actually ships. Two rules follow from that:

* **Clear the inline spans before measuring.** Measuring with the previous
  pass's `span 35` still applied, and no 8px row track to interpret it, made
  widgets report tens of thousands of pixels; the board once computed itself
  to eleven million pixels tall.
* **A stretch pass must not feed back.** The only gap that gets closed by
  stretching is the one above a *full-width* widget, whose top is already
  fixed by the tallest card above it — so growing its shorter neighbours down
  to meet it cannot move anything. Doing it for arbitrary neighbours does move
  things, which opens new gaps, which stretch further.

**Reordering is pointer events, not HTML5 drag and drop.** HTML5 dragging does
not exist on touch and only ever shows a ghost — the board does not move until
you let go. The pointer is tracked on the *document*, never captured on the
grip: reordering re-parents the carried widget, and re-parenting an element
releases its pointer capture, which silently broke the drop and the save.
Arrow keys on a focused grip do the same job for anyone not using a pointer.

The order saves itself to `POST vulnhub-dashboard/v1/layout` (capability
`vulnhub_view` — a layout is stored per person, so there is no one else's to
reach), debounced, and flushed on `pagehide` with `keepalive` so a nudge
followed immediately by a click away is not lost. The Customise form still
posts to `admin-post.php` and still works with JavaScript off.

The portal's own header and footer can be replaced wholesale — see
`docs/ELEMENTOR.md` for `vulnhub_portal_has_custom_header`,
`vulnhub_portal_header` and their footer equivalents.

Reuse core's CSS classes so screens look native: `vh-card`, `vh-grid vh-grid--2|3|4`,
`vh-table-wrap`, `vh-filters`, `vh-pill vh-sev-critical`, `vh-state vh-state--open`,
`vh-form`, `vh-tabs`, `vh-empty`, `vh-log`, `vh-detail`, `vh-mono`, `vh-muted`.

---

## 8. Capabilities

`vulnhub_view`, `vulnhub_triage`, `vulnhub_raise_ticket`, `vulnhub_request_exception`,
`vulnhub_approve_exception`, `vulnhub_run_sync`, `vulnhub_view_audit`,
`vulnhub_manage`. Every REST route needs a real `permission_callback`; never
`__return_true`.

---

## 9. Helper functions (global)

```php
vh_table( 'assets' );          vh_now();                  vh_to_mysql( $any );
vh_severities();               vh_severity_from_id( 3 );  vh_severity_label( 'high' );
vh_severity_color( 'high' );   vh_severity_pill( 'high' );
vh_asset_types();              vh_user_bound_asset_types();  vh_finding_states();
vh_risk_score( $sev, $crit, $exploitable, $vpr );
vh_json( $maybe_json );        vh_date( $mysql );         vh_ago( $mysql );
vh_fingerprint( ...$parts );   vh_trim( $text, 90 );      vh_admin_url( 'vulnhub-assets', [] );
vh_can_manage();
```

---

## 10. House rules

- `declare( strict_types = 1 );` at the top of every file; `if ( ! defined( 'ABSPATH' ) ) { exit; }`.
- WordPress coding standards: Yoda-free is fine, but escape **all** output
  (`esc_html`, `esc_attr`, `esc_url`, `wp_kses_post`), sanitise all input, and use
  `$wpdb->prepare()` for every query with a variable in it.
- `wp_nonce_field()` / `check_admin_referer()` on every admin form.
- `$this->log()` writes to the run log always, and mirrors to `debug.log` only when
  the connector has a `verbose_log` setting turned on. Add that field if you want it.
- Never `error_log()` a credential. Never echo a secret back into a form field —
  render the mask from `Settings::secret_hint()` as a placeholder instead.
- Translatable strings use the `vulnhub` text domain.
- Lint before you finish: `./lint.sh`
- Smoke-test pages: `./check-pages.sh "/wp-admin/admin.php?page=…"`



---

## 11. What real vendor exports actually look like

Lessons from live Tenable and CMDB exports. Every one of these caused a silent
failure before it was handled.

**Tenable tags are `{category, value}`, not `{key, value}`.** Reading only `key`
matched nothing at all. `Mapping::tag_map()` now accepts `category`,
`category_name` or `key`.

**A Tenable asset export may have no hostname.** One real 912-row export carried
only `id`, `ipv4_addresses`, scan times, `sources` and `tags` — so it shares *no
join key at all* with a CMDB export that has hostname, serial and MAC. Match on
as many identifiers as you can (`upsert_asset()` now also tries MAC, FQDN, and an
FQDN's short name against a bare hostname), and expect some assets to stay
unmatched rather than pretending otherwise.

**Asset type usually lives in the customer's tag taxonomy**, not in the OS
string: categories like `WORKSTATIONS` / `SERVERS`, values like
`Windows Workstations` / `AWS`. 911 of those 912 assets were typable *only* by
tag. Rollup tags (`Data_Rollup: All_Licensed_Assets`) classify nothing — skip them.

**CMDB IP columns are often not IP addresses.** 782 of 783 rows in a live export
held the literal string `DHCP`. Use `vh_clean_ip()`; it returns `''` for anything
that is not a real address.

**Custodian columns are `"Display Name - email@example.com"`.** Use
`vh_split_person()`. Rejecting anything that fails `is_email()` throws away the
address and the name together.

**Ownership needs a fallback chain.** Custodian was populated on 75.6% of rows,
last-logged-in-user on 92.3%; trying custodian then falling back reaches 93.0%.
Record which one fired in `owner_confidence` + `owner_rule` so the weaker signal
stays auditable.

**Lifecycle status decides whether an owner is even expected.** A live export was
34% not-in-service (spare, stock, quarantine, planned, retired, and one
misspelled `Decommsion`). Counting those as ownership gaps roughly doubles the
apparent gap list. Use `vh_normalise_lifecycle()` and `vh_in_service_sql()`.

**Duplicate OS-version columns disagree.** One export had `OS Version` = `19045
(22H2)` — a Windows 10 build — on rows whose `Operating System` said Windows 11,
while `OS Version (Cherwell)` correctly said `26100 (24H2)`; 560 of 783 rows
disagreed. Put the more accurate column first in the alias order.

**Header names alone do not identify a column.** That export had both `Asset Tag`
(0% populated) and `Key` / `Datacom CMDB ID` (100% / 99.7%). `detect_mapping()`
now takes sample rows and prefers a column that actually contains data.
