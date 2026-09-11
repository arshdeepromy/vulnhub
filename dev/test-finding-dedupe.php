<?php
/**
 * Proves Repo::resolve_finding() collapses port/protocol drift without
 * collapsing genuinely distinct network services.
 *
 *     docker compose cp dev/test-finding-dedupe.php wpcli:/tmp/tfd.php
 *     docker compose exec -T wpcli wp eval-file /tmp/tfd.php
 *
 * Works on synthetic asset/vuln ids far above anything real and deletes every
 * row it wrote, so it is safe to run against the live estate.
 *
 * @package VulnHub
 */

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	exit( "Run this through wp-cli - see the header for the docker compose cp/exec pair.\n" );
}

global $wpdb;

$table    = vh_table( 'findings' );
$asset_id = 990000001;   // Synthetic: nothing real reaches this far.
$drift    = 990000001;
$service  = 990000002;

$vh_failures = 0;

/** Assert and report in one line. */
$check = static function ( string $label, bool $ok, string $detail = '' ) use ( &$vh_failures ): void {
	printf( "  [%s] %s%s\n", $ok ? ' ok ' : 'FAIL', $label, '' !== $detail ? "  ({$detail})" : '' );
	if ( ! $ok ) {
		++$vh_failures;
	}
};

$rows_for = static function ( int $vuln_id ) use ( $wpdb, $table, $asset_id ): array {
	return $wpdb->get_results(
		$wpdb->prepare( "SELECT id, port, protocol, output FROM {$table} WHERE asset_id = %d AND vuln_id = %d ORDER BY id", $asset_id, $vuln_id ), // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		ARRAY_A
	);
};

$cleanup = static function () use ( $wpdb, $table, $asset_id ): void {
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE asset_id = %d", $asset_id ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
};

$cleanup();

/* ---------------------------------------------------------------------------
 * 1. Port/protocol drift is the same finding.
 * ------------------------------------------------------------------------ */

echo "Port/protocol drift collapses onto one finding:\n";

$path = ' Path : C:\\Program Files\\Thing\\libthing.dll Installed version : 1.0';

$first = \VulnHub\Core\Repo::upsert_finding(
	array(
		'asset_id' => $asset_id,
		'vuln_id'  => $drift,
		'severity' => 'high',
		'state'    => 'open',
		'port'     => 0,
		'protocol' => '',
		'output'   => $path,
	)
);
$check( 'first sighting creates the finding', true === $first['created'] );

// The shape the next export reported: protocol filled in, output dropped.
$second = \VulnHub\Core\Repo::upsert_finding(
	array(
		'asset_id' => $asset_id,
		'vuln_id'  => $drift,
		'severity' => 'high',
		'state'    => 'open',
		'port'     => 0,
		'protocol' => 'tcp',
		'output'   => '',
	)
);
$check( "protocol '' -> 'tcp' updates, does not insert", false === $second['created'] && $second['id'] === $first['id'], 'id ' . $second['id'] );

// And the shape after that: the SMB port it scanned over.
$third = \VulnHub\Core\Repo::upsert_finding(
	array(
		'asset_id' => $asset_id,
		'vuln_id'  => $drift,
		'severity' => 'high',
		'state'    => 'open',
		'port'     => 445,
		'protocol' => 'tcp',
		'output'   => '',
	)
);
$check( 'port 0 -> 445 updates, does not insert', false === $third['created'] && $third['id'] === $first['id'], 'id ' . $third['id'] );

$rows = $rows_for( $drift );
$check( 'exactly one row survives', 1 === count( $rows ), count( $rows ) . ' row(s)' );
$check( 'the install path was not wiped by the empty exports', isset( $rows[0] ) && str_contains( (string) $rows[0]['output'], 'libthing.dll' ) );
$check( 'the current port/protocol won', isset( $rows[0] ) && 445 === (int) $rows[0]['port'] && 'tcp' === $rows[0]['protocol'] );

if ( isset( $rows[0] ) && class_exists( 'VH_Product' ) ) {
	$parsed = \VH_Product::install_path( (string) $rows[0]['output'] );
	$check( 'the dashboard would render an install path', '' !== $parsed, $parsed );
}

/* ---------------------------------------------------------------------------
 * 2. Two real services are still two findings.
 * ------------------------------------------------------------------------ */

echo "\nGenuinely distinct network services stay separate:\n";

foreach ( array( 80, 443 ) as $port ) {
	\VulnHub\Core\Repo::upsert_finding(
		array(
			'asset_id' => $asset_id,
			'vuln_id'  => $service,
			'severity' => 'medium',
			'state'    => 'open',
			'port'     => $port,
			'protocol' => 'tcp',
			'output'   => "port {$port} detail",
		)
	);
}

$rows = $rows_for( $service );
$check( 'ports 80 and 443 remain two findings', 2 === count( $rows ), count( $rows ) . ' row(s)' );

// Re-reporting port 443 must land on the port-443 row, not fork a third.
$again = \VulnHub\Core\Repo::upsert_finding(
	array(
		'asset_id' => $asset_id,
		'vuln_id'  => $service,
		'severity' => 'medium',
		'state'    => 'open',
		'port'     => 443,
		'protocol' => 'tcp',
		'output'   => 'port 443 detail',
	)
);
$check( 're-reporting port 443 updates in place', false === $again['created'] );
$check( 'still two findings', 2 === count( $rows_for( $service ) ) );

$cleanup();

printf( "\n%s\n", 0 === $vh_failures ? 'All checks passed.' : $vh_failures . ' check(s) FAILED.' );
