<?php
/**
 * Filter conformance audit.
 *
 *   ./wp.sh eval-file /var/www/html/wp-content/../../dev/filter-audit.php
 *   docker compose exec -T wpcli wp eval-file /tmp/filter-audit.php
 *
 * Two questions, both of which have been wrong here before:
 *
 *   1. Does every filter argument the repos accept actually filter? A filter
 *      that is read and never applied returns the unfiltered total, which is
 *      indistinguishable from "no matches excluded" unless you check.
 *
 *   2. Does every clickable number on the dashboard equal the list it opens?
 *      A number that changes when you click it is worse than no number.
 *
 * Exits non-zero if anything disagrees, so it can gate a deploy.
 *
 * @package VulnHub\Dev
 */

// No declare(strict_types) here: `wp eval-file` eval()s the body, and a
// declare must be the first statement in a *script*.
global $wpdb;

$repo = 'VulnHub\Core\Repo';
$A    = vh_table( 'assets' );
$F    = vh_table( 'findings' );

$all_assets   = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$A}" );
$all_findings = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$F}" );
$fails        = array();

$check = static function ( string $label, int $got, int $want, int $unfiltered ) use ( &$fails ): void {
	if ( $got === $want ) {
		return;
	}

	$fails[] = sprintf(
		'%-44s repo %-10s sql %-10s%s',
		$label,
		number_format_i18n( $got ),
		number_format_i18n( $want ),
		$got === $unfiltered ? '  <-- IGNORED: returned everything' : ''
	);
};

/* ============================================================== assets. */

$in_service = "'" . implode( "','", vh_in_service_statuses() ) . "'";
$gap        = "'" . implode( "','", \VulnHub\Core\Coverage::gap_states() ) . "'";

foreach ( array(
	array( 'asset_type=server',        array( 'asset_type' => 'server' ),        "asset_type='server'" ),
	array( 'criticality=high',         array( 'criticality' => 'high' ),         "criticality='high'" ),
	array( 'environment=production',   array( 'environment' => 'production' ),   "environment='production'" ),
	array( 'primary_source=tenable',   array( 'primary_source' => 'tenable' ),   "primary_source='tenable'" ),
	array( 'team_id=1',                array( 'team_id' => 1 ),                  'team_id=1' ),
	array( 'location_id=25',           array( 'location_id' => 25 ),             'location_id=25' ),
	array( 'unowned',                  array( 'unowned' => 1 ),                  'owner_person_id=0 AND team_id=0' ),
	array( 'needs_user',               array( 'needs_user' => 1 ),               "asset_type IN ('" . implode( "','", vh_user_bound_asset_types() ) . "') AND owner_person_id=0" ),
	array( 'coverage=gap',             array( 'coverage' => 'gap' ),             "coverage_state IN ({$gap})" ),
	array( 'coverage=covered',         array( 'coverage' => 'covered' ),         "coverage_state='covered'" ),
	array( 'coverage=out_of_scope',    array( 'coverage' => 'out_of_scope' ),    "coverage_state='out_of_scope'" ),
	array( 'has_vulns',                array( 'has_vulns' => 1 ),                '(open_critical+open_high+open_medium+open_low)>0' ),
	array( 'lifecycle_status=retired', array( 'lifecycle_status' => 'retired' ), "lifecycle_status='retired'" ),
	array( 'in_service_only',          array( 'in_service_only' => 1 ),          "lifecycle_status IN ({$in_service})" ),
	array( 'out_of_service_only',      array( 'out_of_service_only' => 1 ),      "lifecycle_status NOT IN ({$in_service})" ),
	array( 'source=intune',            array( 'source' => 'intune' ),            'sources_json LIKE \'%"intune"%\'' ),
	array( 'without_source=intune',    array( 'without_source' => 'intune' ),    '( sources_json = \'\' OR sources_json NOT LIKE \'%"intune"%\' )' ),
	array( 'sole_source',              array( 'sole_source' => 1 ),              "sources_json <> '' AND sources_json NOT LIKE '%,%'" ),
	array( 'search=nz',                array( 'search' => 'nz' ),                "(hostname LIKE '%nz%' OR fqdn LIKE '%nz%' OR ipv4 LIKE '%nz%' OR serial_number LIKE '%nz%' OR model LIKE '%nz%')" ),
	array( 'coverage=gap + in_service', array( 'coverage' => 'gap', 'in_service_only' => 1 ), "coverage_state IN ({$gap}) AND lifecycle_status IN ({$in_service})" ),
) as $c ) {
	$check(
		'assets: ' . $c[0],
		(int) $repo::assets( $c[1] + array( 'limit' => 1 ) )['total'],
		(int) $wpdb->get_var( "SELECT COUNT(*) FROM {$A} WHERE " . $c[2] ), // phpcs:ignore
		$all_assets
	);
}

/* ============================================================ findings. */

$open = "state IN ('open','reopened')";

foreach ( array(
	array( 'state=open_any',    array( 'state' => 'open_any' ),                          $open ),
	array( 'state=fixed',       array( 'state' => 'fixed' ),                             "state='fixed'" ),
	array( 'severity=critical', array( 'state' => 'open_any', 'severity' => 'critical' ), "{$open} AND severity='critical'" ),
	array( 'overdue',           array( 'state' => 'open_any', 'overdue' => 1 ),           "{$open} AND due_at IS NOT NULL AND due_at < UTC_TIMESTAMP()" ),
	array( 'has_ticket',        array( 'state' => 'open_any', 'has_ticket' => 1 ),        "{$open} AND ticket_id > 0" ),
	array( 'excepted=1',        array( 'state' => 'open_any', 'excepted' => 1 ),          "{$open} AND exception_id > 0" ),
	array( 'excepted=0',        array( 'state' => 'open_any', 'excepted' => '0' ),        "{$open} AND exception_id = 0" ),
) as $c ) {
	$check(
		'findings: ' . $c[0],
		(int) $repo::findings( $c[1] + array( 'limit' => 1 ) )['total'],
		(int) $wpdb->get_var( "SELECT COUNT(*) FROM {$F} WHERE " . $c[2] ), // phpcs:ignore
		$all_findings
	);
}

foreach ( array(
	array( 'asset_type=server', array( 'asset_type' => 'server' ), "a.asset_type='server'" ),
	array( 'team_id=1',         array( 'team_id' => 1 ),           'a.team_id=1' ),
	array( 'location_id=25',    array( 'location_id' => 25 ),      'a.location_id=25' ),
) as $c ) {
	$check(
		'findings: ' . $c[0],
		(int) $repo::findings( $c[1] + array( 'state' => 'open_any', 'limit' => 1 ) )['total'],
		(int) $wpdb->get_var( "SELECT COUNT(*) FROM {$F} f JOIN {$A} a ON a.id=f.asset_id WHERE f.state IN ('open','reopened') AND " . $c[2] ), // phpcs:ignore
		$all_findings
	);
}

printf( "%d filter arguments checked against hand-written SQL.\n", 30 );

/* ============================================ widget link vs its list. */

/*
 * `severity_age` is exempt and says so on its own face: the cell counts
 * vulnerabilities and the list counts the asset findings behind them, both
 * numbers are printed in the cell, and the link's label names the second.
 */
$exempt = array( 'severity_age' );

$claim = static function ( string $txt ): ?int {
	$t = trim( (string) preg_replace( '/\s+/', ' ', $txt ) );

	if ( preg_match( '/([\d,]+)\s*gaps?\b/i', $t, $m ) ) { return (int) str_replace( ',', '', $m[1] ); }
	if ( preg_match( '/^([\d,]+)$/', $t, $m ) )          { return (int) str_replace( ',', '', $m[1] ); }
	if ( preg_match( '/^([\d,]+)\s+(assets?|findings?|machines?)\b/i', $t, $m ) ) { return (int) str_replace( ',', '', $m[1] ); }

	return null;
};

$links = 0;

foreach ( array_keys( VulnHub_Dash_Widgets::all() ) as $id ) {
	if ( in_array( $id, $exempt, true ) ) {
		continue;
	}

	ob_start();
	VulnHub_Dash_Widgets::render( $id, 12 );
	$html = (string) ob_get_clean();

	if ( ! preg_match_all( '#<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>#s', $html, $m, PREG_SET_ORDER ) ) {
		continue;
	}

	foreach ( $m as $hit ) {
		$url = html_entity_decode( $hit[1] );

		if ( ! preg_match( '#/(vulnerabilities|assets)/#', $url, $screen ) ) { continue; }

		parse_str( (string) wp_parse_url( $url, PHP_URL_QUERY ), $a );

		// Entity links open one record, not a list.
		if ( isset( $a['asset'] ) || isset( $a['vuln'] ) || isset( $a['ticket'] ) ) { continue; }

		$claimed = $claim( wp_strip_all_tags( $hit[2] ) );

		if ( null === $claimed ) { continue; }

		unset( $a['page_id'] );
		$a['limit'] = 1;

		if ( 'vulnerabilities' === $screen[1] ) {
			$a['state'] = $a['state'] ?? 'open_any';
			$got        = (int) $repo::findings( $a )['total'];
		} else {
			$life = $a['life'] ?? null;
			unset( $a['life'] );

			if ( null === $life )              { $a['in_service_only'] = '1'; }
			elseif ( 'retired_all' === $life ) { $a['out_of_service_only'] = '1'; }
			elseif ( 'all' !== $life )         { $a['lifecycle_status'] = $life; }

			if ( isset( $a['known'] ) ) {
				$k = (string) $a['known'];
				unset( $a['known'] );
				if ( str_starts_with( $k, 'only:' ) )    { $a['source'] = substr( $k, 5 ); $a['sole_source'] = '1'; }
				elseif ( str_starts_with( $k, 'not:' ) ) { $a['without_source'] = substr( $k, 4 ); }
				elseif ( '' !== $k )                     { $a['source'] = $k; }
			}

			$got = (int) $repo::assets( $a )['total'];
		}

		++$links;

		if ( $claimed !== $got ) {
			$fails[] = sprintf(
				'%-22s claims %-9s opens %-9s  ?%s',
				$id,
				number_format_i18n( $claimed ),
				number_format_i18n( $got ),
				(string) wp_parse_url( $url, PHP_URL_QUERY )
			);
		}
	}
}

printf( "%d dashboard links followed and compared with the number on them.\n\n", $links );

if ( $fails ) {
	echo "FAILURES\n" . implode( "\n", $fails ) . "\n";
	exit( 1 );
}

echo "Every filter and every clickable number agrees.\n";
