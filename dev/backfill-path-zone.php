<?php
/**
 * One-off: populate findings.path_zone / zone_path on rows that predate them.
 *
 *     docker compose cp dev/backfill-path-zone.php wpcli:/tmp/bpz.php
 *     docker compose exec -T wpcli wp eval-file /tmp/bpz.php            # dry run
 *     docker compose exec -T wpcli wp eval-file /tmp/bpz.php apply      # write
 *
 * upsert_finding() derives both columns from the plugin output, so every
 * finding imported from now on carries them. Rows already in the table were
 * written before the columns existed and have to be filled in once.
 *
 * Only rows whose output could possibly match are read. The only zone that
 * exists is 'downloads', so a `LIKE '%ownloads%'` prefilter (one ~2 second
 * scan) narrows 296,000 rows with output down to about 2,200 -- reading every
 * output blob instead would mean pulling several hundred megabytes of text
 * through PHP for an answer that is '' in 99% of cases. ADD A NEW ZONE TO
 * VH_Product::path_zone() AND THIS PREFILTER HAS TO GROW TO MATCH, or the
 * backfill will silently skip the rows that zone applies to.
 *
 * @package VulnHub
 */

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	exit( "Run this through wp-cli - see the header for the docker compose cp/exec pair.\n" );
}

global $wpdb;

/** @var array<int,string> $args */
$apply = in_array( 'apply', $args ?? array(), true );
$table = vh_table( 'findings' );

/** Substrings that can put a finding in a zone. See the header warning. */
$prefilter = array( 'ownloads' );

printf( "%s\n\n", $apply ? '=== APPLY ===' : '=== DRY RUN: nothing will be written ===' );

$like = array();
foreach ( $prefilter as $needle ) {
	$like[] = $wpdb->prepare( 'output LIKE %s', '%' . $wpdb->esc_like( $needle ) . '%' );
}
$where = '( ' . implode( ' OR ', $like ) . " ) AND output <> ''";

$total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE {$where}" ); // phpcs:ignore
printf( "candidate rows: %s\n", number_format( $total ) );

$cursor  = 0;
$read    = 0;
$zoned   = 0;
$written = 0;
$by_zone = array();
$samples = array();

while ( true ) {
	// id + output only, 500 at a time: the whole point is to never hold more
	// than a megabyte or so of scanner text at once.
	$rows = $wpdb->get_results(
		$wpdb->prepare(
			"SELECT id, output FROM {$table} WHERE {$where} AND id > %d ORDER BY id LIMIT 500", // phpcs:ignore
			$cursor
		),
		ARRAY_A
	);

	if ( ! $rows ) {
		break;
	}

	foreach ( $rows as $row ) {
		$cursor = (int) $row['id'];
		++$read;

		$zone = \VH_Product::path_zone( (string) $row['output'] );
		if ( '' === $zone['zone'] ) {
			continue;
		}

		++$zoned;
		$by_zone[ $zone['zone'] ] = ( $by_zone[ $zone['zone'] ] ?? 0 ) + 1;

		if ( count( $samples ) < 6 ) {
			$samples[] = sprintf( '#%d  %s  %s', $cursor, $zone['zone'], substr( $zone['path'], 0, 76 ) );
		}

		if ( $apply ) {
			$written += (int) $wpdb->update(
				$table,
				array(
					'path_zone' => $zone['zone'],
					'zone_path' => mb_substr( $zone['path'], 0, 512 ),
				),
				array( 'id' => $cursor )
			);
		}
	}

	unset( $rows );
	printf( "  ...%s / %s read\r", number_format( $read ), number_format( $total ) );
}

echo "\n\n";
if ( $samples ) {
	echo "sample:\n" . implode( "\n", $samples ) . "\n\n";
}

printf( "read           %s\n", number_format( $read ) );
printf( "in a zone      %s\n", number_format( $zoned ) );
foreach ( $by_zone as $zone => $n ) {
	printf( "  %-12s %s\n", $zone, number_format( $n ) );
}
printf( "rows written   %s\n", number_format( $written ) );

if ( ! $apply ) {
	echo "\nNothing was written. Re-run with 'apply' to fill the columns in.\n";
}
