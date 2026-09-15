<?php
/**
 * Shared helper functions for the VulnHub platform.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Prefixed table name.
 */
function vh_table( string $name ): string {
	global $wpdb;
	return $wpdb->prefix . 'vulnhub_' . $name;
}

/**
 * Canonical severity ladder. Tenable severity ids map 1:1.
 *
 * @return array<string,array{id:int,label:string,color:string,weight:int}>
 */
function vh_severities(): array {
	return array(
		'critical' => array(
			'id'     => 4,
			'label'  => __( 'Critical', 'vulnhub' ),
			'color'  => '#b4232c',
			'weight' => 40,
		),
		'high'     => array(
			'id'     => 3,
			'label'  => __( 'High', 'vulnhub' ),
			'color'  => '#d97706',
			'weight' => 20,
		),
		'medium'   => array(
			'id'     => 2,
			'label'  => __( 'Medium', 'vulnhub' ),
			'color'  => '#ca8a04',
			'weight' => 8,
		),
		'low'      => array(
			'id'     => 1,
			'label'  => __( 'Low', 'vulnhub' ),
			'color'  => '#2563eb',
			'weight' => 3,
		),
		'info'     => array(
			'id'     => 0,
			'label'  => __( 'Info', 'vulnhub' ),
			'color'  => '#64748b',
			'weight' => 0,
		),
	);
}

function vh_severity_label( string $slug ): string {
	$all = vh_severities();
	return $all[ $slug ]['label'] ?? ucfirst( $slug );
}

function vh_severity_color( string $slug ): string {
	$all = vh_severities();
	return $all[ $slug ]['color'] ?? '#64748b';
}

/**
 * Map a numeric Tenable severity id to our slug.
 */
function vh_severity_from_id( int $id ): string {
	foreach ( vh_severities() as $slug => $meta ) {
		if ( $meta['id'] === $id ) {
			return $slug;
		}
	}
	return 'info';
}

/**
 * Asset type vocabulary. "workstation" is the type that REQUIRES an assigned user.
 *
 * @return array<string,string>
 */
function vh_asset_types(): array {
	return array(
		'workstation' => __( 'Workstation', 'vulnhub' ),
		'server'      => __( 'Server', 'vulnhub' ),
		'mobile'      => __( 'Mobile device', 'vulnhub' ),
		'network'     => __( 'Network device', 'vulnhub' ),
		'cloud'       => __( 'Cloud resource', 'vulnhub' ),
		'appliance'   => __( 'Appliance', 'vulnhub' ),
		'unknown'     => __( 'Unknown', 'vulnhub' ),
	);
}

/**
 * Asset types that must resolve to an individual human owner.
 *
 * @return string[]
 */
function vh_asset_type_label( string $type ): string {
	$types = vh_asset_types();

	return (string) ( $types[ $type ] ?? ( $types['unknown'] ?? $type ) );
}

/**
 * Asset types that must resolve to an individual rather than a team.
 */
function vh_user_bound_asset_types(): array {
	return (array) apply_filters( 'vulnhub_user_bound_asset_types', array( 'workstation', 'mobile' ) );
}

/**
 * Asset lifecycle status vocabulary.
 *
 * Real CMDB exports are full of devices that are deliberately unassigned —
 * spares, stock, quarantine, retired. Treating those as "workstation with no
 * owner" buries the handful of genuine gaps in a pile of false positives, so
 * ownership expectations only apply to assets that are actually in service.
 *
 * @return array<string,array{label:string,in_service:bool}>
 */
function vh_lifecycle_statuses(): array {
	return array(
		'in_service'   => array( 'label' => __( 'In service', 'vulnhub' ), 'in_service' => true ),
		'quarantine'   => array( 'label' => __( 'In quarantine', 'vulnhub' ), 'in_service' => true ),
		'maintenance'  => array( 'label' => __( 'In repair / maintenance', 'vulnhub' ), 'in_service' => true ),
		'spare'        => array( 'label' => __( 'Spare', 'vulnhub' ), 'in_service' => false ),
		'stock'        => array( 'label' => __( 'In stock', 'vulnhub' ), 'in_service' => false ),
		'planned'      => array( 'label' => __( 'Planned', 'vulnhub' ), 'in_service' => false ),
		'retired'      => array( 'label' => __( 'Retired / decommissioned', 'vulnhub' ), 'in_service' => false ),
		'missing'      => array( 'label' => __( 'Missing / lost', 'vulnhub' ), 'in_service' => false ),
		'unknown'      => array( 'label' => __( 'Unknown', 'vulnhub' ), 'in_service' => true ),
	);
}

/**
 * Lifecycle statuses that carry an ownership expectation.
 *
 * @return string[]
 */
function vh_in_service_statuses(): array {
	$out = array();
	foreach ( vh_lifecycle_statuses() as $slug => $meta ) {
		if ( $meta['in_service'] ) {
			$out[] = $slug;
		}
	}
	return (array) apply_filters( 'vulnhub_in_service_statuses', $out );
}

/**
 * How long to wait after Jira closes a ticket before re-checking the finding.
 *
 * Read through here rather than straight from the option because the stored
 * value can be nonsense. This estate had it saved as 0, which is outside the
 * range the settings screen allows (min 1) and outside what the handler can
 * write (max(1, ...)) -- so it was written by something else, and it meant the
 * verifier re-checked the scanner the instant a ticket closed. Tenable had not
 * rescanned in between, so every closure came back "still detected" and every
 * Jira issue got reopened. That is precisely the failure the help text on the
 * settings screen warns about.
 *
 * Zero is therefore treated as "nobody chose this" and falls back to the
 * documented 24 hours, rather than being honoured as "verify immediately".
 */
function vh_verification_delay_hours(): int {
	$raw = (int) vulnhub()->settings->platform( 'auto_verify_hours', 24 );

	return $raw > 0 ? min( 720, $raw ) : 24;
}

/**
 * Lifecycle statuses that are expected to carry a Tenable scan.
 *
 * Deliberately NOT the same list as vh_in_service_statuses(). That one answers
 * "should this asset resolve to an owner", and a machine sitting in a repair
 * bay or isolated in quarantine still has an owner -- so it belongs there. It
 * does not belong here, because nothing on the network can scan it, and
 * counting it as a scanning gap buries the machines somebody could actually
 * do something about.
 *
 * On the estate this was written against, sharing one list put 90 quarantined
 * and 7 in-repair machines into a 196-strong "not scanned" list, so 49% of the
 * work queue was machines that are not on the network by definition.
 *
 * `unknown` is included on purpose and against the obvious instinct. It is not
 * a status anybody chose -- it is the absence of one -- and an unclassified
 * device is exactly the kind that goes unscanned. Excluding it would hide the
 * gap this whole feature exists to surface.
 *
 * Administrator-editable at VulnHub -> Settings -> Coverage scope.
 *
 * @return string[]
 */
function vh_scannable_statuses(): array {
	$stored = vulnhub()->settings->platform( 'coverage_scope', null );

	if ( is_array( $stored ) && $stored ) {
		$valid = array_keys( vh_lifecycle_statuses() );
		$out   = array_values( array_intersect( $stored, $valid ) );
	} else {
		$out = array( 'in_service', 'unknown' );
	}

	// An empty scope would make every asset out of scope and the coverage
	// figure meaningless, so the default reasserts itself.
	if ( ! $out ) {
		$out = array( 'in_service', 'unknown' );
	}

	return (array) apply_filters( 'vulnhub_scannable_statuses', $out );
}

/**
 * vh_scannable_statuses() as a quoted SQL list.
 */
function vh_scannable_sql(): string {
	return "'" . implode( "','", array_map( 'esc_sql', vh_scannable_statuses() ) ) . "'";
}

/**
 * Lifecycle statuses that dashboard widgets and their reports count.
 *
 * The third of three lifecycle questions, and the one that was missing. They
 * are deliberately separate lists because they are separate questions, and an
 * administrator who narrows one must not silently move the others:
 *
 * - vh_in_service_statuses()  "should this asset resolve to an owner?"
 *   Includes quarantine and maintenance: a machine in a repair bay still
 *   belongs to somebody, and its owner is who you ring about it.
 *
 * - vh_scannable_statuses()   "should Tenable have scanned this?"
 *   Excludes quarantine and maintenance: nothing on the network can reach a
 *   device that is off it, so counting one as a scanning gap buries the
 *   machines somebody could actually do something about.
 *
 * - vh_reportable_statuses()  "should this asset be in a reported number?"
 *   This one. Excludes quarantine and maintenance for the same reason the
 *   scanning list does -- an isolated machine is nobody's remediation queue
 *   -- and on the estate this was written against those 98 machines carried
 *   30 open findings between them while supplying 59 of the 78 rows in the
 *   ownership-gap list. Reporting on them built a work queue that was 94%
 *   things nobody could act on.
 *
 * `unknown` is included, as it is in the scanning list, and for a stronger
 * reason. It is not a status anybody chose -- it is the absence of one -- and
 * on this estate its 194 assets carry 213,200 of the 228,107 open findings.
 * Excluding it would have every widget report 6.5% of the real exposure and
 * call it the estate. An unclassified device is a reporting gap to close, not
 * a device to stop reporting on.
 *
 * Administrator-editable at VulnHub -> Settings -> Reporting scope.
 *
 * @return string[]
 */
function vh_reportable_statuses(): array {
	$stored = vulnhub()->settings->platform( 'reporting_scope', null );

	if ( is_array( $stored ) && $stored ) {
		$valid = array_keys( vh_lifecycle_statuses() );
		$out   = array_values( array_intersect( $stored, $valid ) );
	} else {
		$out = array( 'in_service', 'unknown' );
	}

	// An empty scope would put every asset out of scope and make every
	// reported number zero, so the default reasserts itself.
	if ( ! $out ) {
		$out = array( 'in_service', 'unknown' );
	}

	return (array) apply_filters( 'vulnhub_reportable_statuses', $out );
}

/**
 * vh_reportable_statuses() as a quoted SQL list.
 */
function vh_reportable_sql(): string {
	return "'" . implode( "','", array_map( 'esc_sql', vh_reportable_statuses() ) ) . "'";
}

/**
 * The systems an asset's data can come from, and what to call them.
 *
 * @return array<string,string> slug => label.
 */
function vh_asset_sources(): array {
	return (array) apply_filters(
		'vulnhub_asset_sources',
		array(
			'intune'  => __( 'Intune', 'vulnhub' ),
			'tenable' => __( 'Tenable', 'vulnhub' ),
			'defender' => __( 'Defender', 'vulnhub' ),
			'cmdb'    => __( 'CMDB', 'vulnhub' ),
			'manual'  => __( 'Entered by hand', 'vulnhub' ),
		)
	);
}

/**
 * Reduce a feed's own name for itself to one of ours.
 *
 * Every importer and connector spells its source slightly differently --
 * `intune-csv` from the device export, `intune` from the Graph connector,
 * `tenable-csv`, `cmdb-csv`, `servicenow` -- and a reader does not care
 * which file a fact arrived in, only which system knows it.
 *
 * @param string $raw Whatever the feed called itself.
 * @return string A key of vh_asset_sources(), or '' when unrecognised.
 */
function vh_normalise_source( string $raw ): string {
	$v = strtolower( trim( $raw ) );

	if ( '' === $v ) {
		return '';
	}

	if ( str_contains( $v, 'intune' ) || str_contains( $v, 'endpoint manager' ) ) {
		return 'intune';
	}
	if ( str_contains( $v, 'tenable' ) || str_contains( $v, 'nessus' ) ) {
		return 'tenable';
	}
	if ( str_contains( $v, 'defender' ) || str_contains( $v, 'mde' ) || str_contains( $v, 'mdatp' ) || str_contains( $v, 'security center' ) || str_contains( $v, 'atp' ) ) {
		return 'defender';
	}
	if ( str_contains( $v, 'cmdb' ) || str_contains( $v, 'servicenow' ) || str_contains( $v, 'cherwell' ) || str_contains( $v, 'jira asset' ) ) {
		return 'cmdb';
	}
	// Anything a person drove themselves -- the portal's own form, the MCP
	// connector -- is hand-entered as far as a reader is concerned.
	if ( str_contains( $v, 'manual' ) || str_contains( $v, 'hand' ) || str_contains( $v, 'portal' ) || 'mcp' === $v ) {
		return 'manual';
	}

	return '';
}

/**
 * Does this operating system belong to a general-purpose computer?
 *
 * The question a form factor cannot answer. A CMDB that classes a Surface Go
 * as a "Tablet" is not wrong about its shape, but the platform files it under
 * `mobile` on the strength of that word alone -- and mobile is excluded from
 * scanning coverage, so nine Windows 10 and 11 Enterprise machines quietly
 * left the figure while their owners carried them into the office every day.
 *
 * The operating system is the stronger evidence and it is the one that
 * decides here: a device running Windows Enterprise, macOS, a desktop Linux
 * or ChromeOS is patched like a computer and has to be scanned like one,
 * whatever the register calls its case.
 *
 * @param string $os Operating system string from any feed.
 * @return bool
 */
function vh_is_computer_os( string $os ): bool {
	$v = strtolower( trim( $os ) );

	if ( '' === $v ) {
		return false;
	}

	/*
	 * A true mobile OS wins outright. Tested first so that "Windows Phone"
	 * is never read as Windows, and so an Android tablet stays mobile.
	 */
	if ( preg_match( '/\b(android|ipados|iphone ?os|windows ?phone|watchos|tizen|harmonyos|kaios|blackberry)\b/', $v ) ) {
		return false;
	}
	if ( preg_match( '/\bios\b/', $v ) && ! preg_match( '/\b(ios-xe|ios xe)\b/', $v ) ) {
		return false;
	}

	return (bool) preg_match(
		'/\b(windows|macos|mac ?os ?x?|os x|chrome ?os|linux|ubuntu|debian|centos|red ?hat|rhel|suse|rocky|almalinux|fedora|oracle linux|freebsd|solaris|aix|esxi|hp-ux)\b/',
		$v
	);
}

/**
 * Device classes a coverage percentage is not a fair question about.
 *
 * Scanning and endpoint coverage are both statements about machines somebody
 * can patch. A Ricoh printer, a TP-Link switch and a Polycom video unit are
 * none of those: Defender cannot onboard them, nobody was ever going to put a
 * Tenable agent on them, and after a Defender import discovered a hundred and
 * nineteen of them they moved the estate's scanning figure from 73% to 54%
 * overnight without a single machine changing.
 *
 * They are excluded from the *percentage*, not from the platform. The
 * by-device-type charts still count them and still show them as uncovered,
 * because "we have 48 switches nobody is looking at" is a real finding -- it
 * is just not the same finding as "we have 129 servers nobody is scanning",
 * and averaging the two together hides both.
 *
 * Stated as what comes *out* rather than what stays in, and deliberately.
 * The list-in form was tried first and quietly dropped eighteen Red Hat
 * application servers the CMDB had never given a device type -- they were
 * `unknown`, `unknown` was not on the allow-list, and eighteen real servers
 * left the scanning figure without appearing anywhere. An asset nobody has
 * classified is exactly the kind that goes unscanned; the default has to be
 * that it counts.
 *
 * @return string[] Keys of vh_asset_types().
 */
function vh_unscannable_asset_types(): array {
	return (array) apply_filters( 'vulnhub_unscannable_asset_types', array( 'appliance', 'network', 'mobile' ) );
}

/**
 * The device classes a coverage percentage *is* about.
 *
 * @return string[]
 */
function vh_scannable_asset_types(): array {
	return array_values( array_diff( array_keys( vh_asset_types() ), vh_unscannable_asset_types() ) );
}

/**
 * SQL fragment listing the scannable device classes, quoted and escaped.
 */
function vh_scannable_types_sql(): string {
	return "'" . implode( "','", array_map( 'esc_sql', vh_scannable_asset_types() ) ) . "'";
}

/**
 * Lifecycle statuses meaning "nobody has this machine".
 *
 * Not the same question as `vh_in_service_statuses()`. A retired or missing
 * laptop is also out of service, but it once belonged to somebody and its
 * history is worth keeping. These three are kit that has never been issued
 * -- sitting in a cupboard, on a shelf, or still on order -- and an
 * inventory of live vulnerabilities has no use for them at all.
 *
 * @return string[]
 */
function vh_unissued_statuses(): array {
	return (array) apply_filters( 'vulnhub_unissued_statuses', array( 'spare', 'stock', 'planned' ) );
}

/**
 * SQL fragment listing the in-service statuses, quoted and escaped.
 */
function vh_in_service_sql(): string {
	return "'" . implode( "','", array_map( 'esc_sql', vh_in_service_statuses() ) ) . "'";
}

/**
 * Normalise a vendor lifecycle/install status on to our vocabulary.
 *
 * Deliberately forgiving: real exports contain "Decommsion", "In Stock",
 * "For Verification" and similar, and a typo must not silently become a
 * device the platform stops expecting an owner for.
 */
function vh_normalise_lifecycle( ?string $raw ): string {
	$v = strtolower( trim( (string) $raw ) );

	if ( '' === $v ) {
		return 'unknown';
	}

	$v = str_replace( array( '_', '-', '/' ), ' ', $v );
	$v = (string) preg_replace( '/\s+/', ' ', $v );

	$map = array(
		'in service'      => 'in_service',
		'installed'       => 'in_service',
		'active'          => 'in_service',
		'operational'     => 'in_service',
		'deployed'        => 'in_service',
		'production'      => 'in_service',
		'in use'          => 'in_service',
		'in quarantine'   => 'quarantine',
		'quarantine'      => 'quarantine',
		'quarantined'     => 'quarantine',
		'in repair maintenance' => 'maintenance',
		'in repair'       => 'maintenance',
		'maintenance'     => 'maintenance',
		'repair'          => 'maintenance',
		'spare'           => 'spare',
		'spares'          => 'spare',
		'in stock'        => 'stock',
		'stock'           => 'stock',
		'in storage'      => 'stock',
		'storage'         => 'stock',
		'available'       => 'stock',
		'planned'         => 'planned',
		'on order'        => 'planned',
		'ordered'         => 'planned',
		'pending install' => 'planned',
		'retired'         => 'retired',
		'decommissioned'  => 'retired',
		'decommission'    => 'retired',
		'decommsion'      => 'retired', // Seen misspelled in a live export.
		'disposed'        => 'retired',
		'end of life'     => 'retired',
		'absent'          => 'retired',
		'missing'         => 'missing',
		'lost'            => 'missing',
		'stolen'          => 'missing',
	);

	if ( isset( $map[ $v ] ) ) {
		return $map[ $v ];
	}

	// Substring fallbacks for phrases like "For Verification - In Service".
	foreach ( $map as $needle => $slug ) {
		if ( str_contains( $v, $needle ) ) {
			return $slug;
		}
	}

	return 'unknown';
}

/**
 * Is this a value we should store as an IP address?
 *
 * CMDB exports routinely carry "DHCP", "N/A" or "-" in the IP column — 782 of
 * 783 rows in one real export — and writing those into an address field makes
 * every downstream IP match and subnet lookup wrong.
 */
/**
 * Is this a value we should treat as a serial number?
 *
 * A serial is used as a match key, ahead of hostname, so a value that is not
 * unique to one machine merges machines. Live exports are full of them: every
 * AIX partition reports "LPAR", everything virtual reports "Not Applicable",
 * and unconfigured hardware reports whatever the board vendor left in the
 * BIOS. Seven distinct partitions collapsed into one asset before this
 * existed.
 */
function vh_clean_serial( ?string $raw ): string {
	$v = trim( (string) $raw );

	if ( '' === $v ) {
		return '';
	}

	$needle = strtolower( (string) preg_replace( '/[^a-z0-9]/i', '', $v ) );

	$placeholders = array(
		'lpar', 'notapplicable', 'na', 'n', 'none', 'null', 'nil', 'unknown',
		'notspecified', 'noserial', 'tbd', 'default', 'defaultstring',
		'tobefilledbyoem', 'systemserialnumber', 'serialnumber', 'invalid',
		'notavailable', 'notprovided', 'chassisserialnumber', '0', '00000000',
	);

	if ( '' === $needle || strlen( $needle ) < 3 || in_array( $needle, $placeholders, true ) ) {
		return '';
	}

	// A serial that is one repeated character carries no information either.
	if ( 1 === count( array_unique( str_split( $needle ) ) ) ) {
		return '';
	}

	return $v;
}

function vh_clean_ip( ?string $raw ): string {
	$v = trim( (string) $raw );

	if ( '' === $v ) {
		return '';
	}
	if ( ! filter_var( $v, FILTER_VALIDATE_IP ) ) {
		return '';
	}
	return $v;
}

/**
 * Normalise a MAC address to AA:BB:CC:DD:EE:FF, or '' when it is not one.
 */
function vh_clean_mac( ?string $raw ): string {
	$hex = strtoupper( (string) preg_replace( '/[^0-9A-Fa-f]/', '', (string) $raw ) );

	if ( 12 !== strlen( $hex ) ) {
		return '';
	}
	return implode( ':', str_split( $hex, 2 ) );
}

/**
 * Split a "Display Name - email@example.com" custodian string.
 *
 * @return array{name:string,email:string}
 */
function vh_split_person( ?string $raw ): array {
	$v = trim( (string) $raw );

	if ( '' === $v ) {
		return array( 'name' => '', 'email' => '' );
	}

	$email = '';
	if ( preg_match( '/[\w.+-]+@[\w-]+\.[\w.-]+/', $v, $m ) ) {
		$email = strtolower( $m[0] );
	}

	$name = trim( (string) preg_replace( '/[\w.+-]+@[\w-]+\.[\w.-]+/', '', $v ) );
	$name = trim( $name, " \t\n\r\0\x0B-–—<>(),;" );

	return array( 'name' => $name, 'email' => $email );
}

/**
 * Finding lifecycle states.
 *
 * @return array<string,string>
 */
function vh_finding_states(): array {
	return array(
		'open'       => __( 'Open', 'vulnhub' ),
		'reopened'   => __( 'Reopened', 'vulnhub' ),
		'fixed'      => __( 'Fixed', 'vulnhub' ),
		'archived'   => __( 'Archived', 'vulnhub' ),
		'suppressed' => __( 'Suppressed', 'vulnhub' ),
	);
}

/**
 * Severities the product does not report on.
 *
 * Informational findings are not vulnerabilities. Tenable's enumeration
 * plugins -- "User Download Folder Files", "Adobe Recent Files", "MUICache
 * Program Execution History" -- describe what is on a machine, not what is
 * wrong with it, and they are numerous enough to dominate any aggregate they
 * are allowed into: 82,383 of 323,595 findings here, and 93% of what the
 * download-folder widget first reported.
 *
 * Suppression is a reporting decision, not a deletion. Findings at these
 * severities are parked in the `suppressed` state, which is outside
 * vh_live_finding_states() and therefore outside every count in the product,
 * and `prev_state` keeps the way back. Empty this filter and re-run
 * `wp vulnhub suppress-severities --restore` to reverse it.
 *
 * @return string[]
 */
function vh_suppressed_severities(): array {
	return (array) apply_filters( 'vulnhub_suppressed_severities', array( 'info' ) );
}

/** Whether a severity is one the product currently declines to report on. */
function vh_severity_suppressed( string $severity ): bool {
	return in_array( strtolower( $severity ), vh_suppressed_severities(), true );
}

/** vh_live_finding_states() as a quoted SQL list. */
function vh_live_finding_sql(): string {
	return "'" . implode( "','", array_map( 'esc_sql', vh_live_finding_states() ) ) . "'";
}

/**
 * Finding states that count as live exposure.
 *
 * Every count in the product -- roll-ups, dashboards, Jira automation,
 * exception scoping -- is scoped to these two. `archived` is deliberately
 * outside them: a finding on a machine that has left the estate is history,
 * not a thing anybody can go and patch, and leaving it in the totals is how
 * a decommissioned estate keeps reporting risk it no longer carries.
 *
 * @return string[]
 */
function vh_live_finding_states(): array {
	return array( 'open', 'reopened' );
}

/**
 * Safe JSON decode to array.
 *
 * @return array<mixed>
 */
function vh_json( ?string $raw ): array {
	if ( empty( $raw ) ) {
		return array();
	}
	$out = json_decode( $raw, true );
	return is_array( $out ) ? $out : array();
}

/**
 * Format a MySQL datetime for display in the site timezone.
 */
function vh_date( ?string $mysql, string $format = 'j M Y, H:i' ): string {
	if ( empty( $mysql ) || '0000-00-00 00:00:00' === $mysql ) {
		return '—';
	}
	$ts = strtotime( $mysql . ' UTC' );
	if ( false === $ts ) {
		return '—';
	}
	return wp_date( $format, $ts );
}

/**
 * Human "time ago" wrapper that tolerates nulls.
 */
function vh_ago( ?string $mysql ): string {
	if ( empty( $mysql ) ) {
		return '—';
	}
	$ts = strtotime( $mysql . ' UTC' );
	if ( false === $ts ) {
		return '—';
	}
	if ( $ts > time() ) {
		/* translators: %s: human readable time difference. */
		return sprintf( __( 'in %s', 'vulnhub' ), human_time_diff( time(), $ts ) );
	}
	/* translators: %s: human readable time difference. */
	return sprintf( __( '%s ago', 'vulnhub' ), human_time_diff( $ts, time() ) );
}

/**
 * Current UTC timestamp in MySQL format.
 */
function vh_now(): string {
	return gmdate( 'Y-m-d H:i:s' );
}

/**
 * A duration in milliseconds as a short human string: "45s", "3m 42s",
 * "1h 5m". Zero or negative reads as an em dash, because "0s" on a card
 * looks like a real measurement of nothing rather than the absence of one.
 *
 * @param int $ms Duration in milliseconds.
 */
function vh_duration_human( int $ms ): string {
	if ( $ms <= 0 ) {
		return '—';
	}

	$seconds = (int) round( $ms / 1000 );

	if ( $seconds < 60 ) {
		return $seconds . 's';
	}

	$minutes = intdiv( $seconds, 60 );
	$seconds = $seconds % 60;

	if ( $minutes < 60 ) {
		return $seconds ? sprintf( '%dm %ds', $minutes, $seconds ) : sprintf( '%dm', $minutes );
	}

	$hours   = intdiv( $minutes, 60 );
	$minutes = $minutes % 60;

	return $minutes ? sprintf( '%dh %dm', $hours, $minutes ) : sprintf( '%dh', $hours );
}

/**
 * Normalise a vendor timestamp (ISO8601, epoch seconds, or MySQL) to UTC MySQL.
 */
function vh_to_mysql( mixed $value ): ?string {
	if ( empty( $value ) ) {
		return null;
	}
	if ( is_numeric( $value ) ) {
		$num = (float) $value;

		/*
		 * An Excel serial, not an epoch.
		 *
		 * Save a Defender or Intune export as CSV with the date columns
		 * still formatted as numbers and every timestamp arrives as
		 * `46274.105` -- days since 1899-12-30. Read as epoch seconds
		 * that is the 1st of January 1970, which then reads as "nothing
		 * has seen this machine in fifty years" on the coverage screen.
		 * The two ranges cannot overlap: a real epoch timestamp for any
		 * date after 1970 is at least eight digits, and a serial for any
		 * date between 1955 and 2064 is five.
		 */
		if ( $num >= 20000 && $num < 60000 ) {
			return gmdate( 'Y-m-d H:i:s', (int) round( ( $num - 25569 ) * 86400 ) );
		}

		$ts = (int) $value;
		// Milliseconds guard.
		if ( $ts > 100000000000 ) {
			$ts = (int) ( $ts / 1000 );
		}
		return gmdate( 'Y-m-d H:i:s', $ts );
	}

	$ts = strtotime( vh_disambiguate_date( (string) $value ) );

	return false === $ts ? null : gmdate( 'Y-m-d H:i:s', $ts );
}

/**
 * Which way round a slashed date is written here.
 *
 * 'dmy' or 'mdy'. Settable at VulnHub → Settings; 'auto' reads it off the
 * WordPress locale, which is right for the overwhelming majority of installs
 * and wrong only for a site left on en_US that imports British-format files.
 */
function vh_date_order(): string {
	$stored = (string) vulnhub()->settings->platform( 'import_date_order', 'auto' );

	if ( in_array( $stored, array( 'dmy', 'mdy' ), true ) ) {
		return $stored;
	}

	/*
	 * The site's timezone, not its admin language.
	 *
	 * Almost every WordPress install outside the United States is left on
	 * en_US -- this one is, and it is a New Zealand company -- so reading the
	 * locale would have told every non-American customer that their exports
	 * are American. The timezone is set during installation by somebody who
	 * knows where they are, and it maps to a country exactly.
	 *
	 * The United States and the Philippines write the month first. Everywhere
	 * else writes the day first.
	 */
	$tz = (string) wp_timezone_string();

	if ( '' !== $tz && ! str_contains( $tz, ':' ) ) {
		$month_first = array_merge(
			(array) DateTimeZone::listIdentifiers( DateTimeZone::PER_COUNTRY, 'US' ),
			(array) DateTimeZone::listIdentifiers( DateTimeZone::PER_COUNTRY, 'PH' )
		);

		return in_array( $tz, $month_first, true ) ? 'mdy' : 'dmy';
	}

	// A raw UTC offset says nothing about where anybody is; fall back to the
	// language, which at least someone chose.
	return 'en_US' === get_locale() ? 'mdy' : 'dmy';
}

/**
 * Rewrite an ambiguous slashed date so strtotime cannot misread it.
 *
 * `strtotime()` reads 07/09/2026 as the 9th of July, always, because a slashed
 * date is American to PHP. An Intune or CMDB export produced on a New Zealand
 * machine means the 7th of September, and taking it at face value moved a
 * device's last check-in two months -- straight into the window that decides
 * whether the platform reports it as live or as a record nobody retired.
 *
 * Where the day is unmistakable (a field above 12) that settles it whatever
 * the setting says, because a file is better evidence than a preference. Only
 * genuinely ambiguous dates fall back to vh_date_order().
 *
 * Anything already unambiguous -- ISO 8601, a dash-separated date, a written
 * month -- is returned untouched.
 */
function vh_disambiguate_date( string $value ): string {
	$value = trim( $value );

	if ( ! preg_match( '#^(\d{1,2})/(\d{1,2})/(\d{4})(\D.*)?$#', $value, $m ) ) {
		return $value;
	}

	$first  = (int) $m[1];
	$second = (int) $m[2];
	$rest   = (string) ( $m[4] ?? '' );

	if ( $first > 12 && $second <= 12 ) {
		$day   = $first;
		$month = $second;
	} elseif ( $second > 12 && $first <= 12 ) {
		$day   = $second;
		$month = $first;
	} elseif ( 'dmy' === vh_date_order() ) {
		$day   = $first;
		$month = $second;
	} else {
		return $value;
	}

	if ( $day < 1 || $day > 31 || $month < 1 || $month > 12 ) {
		return $value;
	}

	return sprintf( '%04d-%02d-%02d%s', (int) $m[3], $month, $day, $rest );
}

/**
 * Deterministic hash used to de-duplicate findings across syncs.
 */
function vh_fingerprint( string ...$parts ): string {
	return hash( 'sha256', implode( '|', array_map( 'strval', $parts ) ) );
}

/**
 * Risk score: severity weight amplified by asset criticality and exploit availability.
 */
function vh_risk_score( string $severity, string $criticality = 'medium', bool $exploitable = false, ?float $vpr = null ): float {
	$sev  = vh_severities()[ $severity ]['weight'] ?? 0;
	$crit = array(
		'critical' => 2.0,
		'high'     => 1.5,
		'medium'   => 1.0,
		'low'      => 0.6,
	)[ $criticality ] ?? 1.0;

	$score = $sev * $crit;
	if ( $exploitable ) {
		$score *= 1.4;
	}
	if ( null !== $vpr && $vpr > 0 ) {
		$score *= ( 1 + ( $vpr / 20 ) );
	}
	return round( min( $score, 100 ), 1 );
}

/**
 * Current user can manage the platform.
 */
function vh_can_manage(): bool {
	return current_user_can( 'vulnhub_manage' );
}

/**
 * Escaped admin URL for a VulnHub screen.
 *
 * @param array<string,string|int> $args Extra query args.
 */
function vh_admin_url( string $page, array $args = array() ): string {
	/**
	 * Filters the destination for a VulnHub admin screen.
	 *
	 * Every screen is reachable from two places: wp-admin, and the front-end
	 * portal that mirrors it. A form submitted from the portal posts to
	 * admin-post.php like any other, and the handler then redirects with this
	 * helper -- so without this filter the operator is silently dumped into
	 * wp-admin halfway through a task. The dashboard plugin answers it when
	 * the request came from the portal.
	 *
	 * @param string               $url  Default wp-admin URL.
	 * @param string               $page Screen slug.
	 * @param array<string,scalar> $args Query arguments.
	 */
	return (string) apply_filters(
		'vulnhub_admin_screen_url',
		add_query_arg( array_merge( array( 'page' => $page ), $args ), admin_url( 'admin.php' ) ),
		$page,
		$args
	);
}

/**
 * Render a severity pill.
 */
function vh_severity_pill( string $severity ): string {
	return sprintf(
		'<span class="vh-pill vh-sev-%1$s">%2$s</span>',
		esc_attr( $severity ),
		esc_html( vh_severity_label( $severity ) )
	);
}

/**
 * Truncate for table cells.
 */
function vh_trim( ?string $text, int $len = 90 ): string {
	$text = trim( (string) $text );
	if ( mb_strlen( $text ) <= $len ) {
		return $text;
	}
	return mb_substr( $text, 0, $len ) . '…';
}

