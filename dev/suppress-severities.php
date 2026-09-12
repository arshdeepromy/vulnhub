<?php
/**
 * Park findings at a non-reported severity in the `suppressed` state, or let
 * them back out again.
 *
 *     docker compose cp dev/suppress-severities.php wpcli:/tmp/sup.php
 *     docker compose exec -T wpcli wp eval-file /tmp/sup.php            # dry run
 *     docker compose exec -T wpcli wp eval-file /tmp/sup.php apply      # suppress
 *     docker compose exec -T wpcli wp eval-file /tmp/sup.php restore    # undo
 *
 * Which severities count is vh_suppressed_severities() -- informational only,
 * today. upsert_finding() applies the same rule to everything arriving from a
 * connector, so this script is only for the rows that were already in the
 * table when the decision was made.
 *
 * Why a state rather than a WHERE clause: every count in the product filters
 * `state IN ('open','reopened')` -- 36 separate query sites, none of which
 * share a helper. Adding a severity clause to each one is 36 chances to miss
 * one and report a number that disagrees with the widget next to it. Moving
 * the rows outside the live states makes every one of those queries correct
 * without being touched.
 *
 * Why not delete: `prev_state` makes this a one-UPDATE reversal, and the
 * decision is explicitly a "for now". Deleting 82,000 rows would make the
 * only way back a full re-sync.
 *
 * `suppressed` is inert to the lifecycle sweep, which archives only findings
 * in a live state and restores only findings in `archived` -- so a suppressed
 * finding is neither swept away nor quietly resurrected.
 *
 * @package VulnHub
 */

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	exit( "Run this through wp-cli - see the header for the docker compose cp/exec pair.\n" );
}

global $wpdb;

/** @var array<int,string> $args */
$mode = in_array( 'restore', $args ?? array(), true ) ? 'restore'
	: ( in_array( 'apply', $args ?? array(), true ) ? 'apply' : 'dry' );

$table = vh_table( 'findings' );
$sevs  = vh_suppressed_severities();

if ( ! $sevs ) {
	echo "vh_suppressed_severities() is empty - nothing is being suppressed.\n";
	echo "Run with 'restore' to bring any already-suppressed findings back.\n\n";
}

$sev_sql = $sevs ? "'" . implode( "','", array_map( 'esc_sql', $sevs ) ) . "'" : "''";

printf( "mode: %s\n", strtoupper( $mode ) );
printf( "suppressed severities: %s\n\n", $sevs ? implode( ', ', $sevs ) : '(none)' );

if ( 'restore' === $mode ) {
	$pending = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE state = 'suppressed'" ); // phpcs:ignore
	printf( "suppressed findings to restore: %s\n", number_format( $pending ) );

	// prev_state is where the row came from; anything without one predates
	// the column and was open, which is what all but a handful were.
	$done = (int) $wpdb->query(
		$wpdb->prepare(
			"UPDATE {$table}
			    SET state      = IF( prev_state = '', 'open', prev_state ),
			        prev_state = '',
			        updated_at = %s
			  WHERE state = 'suppressed'", // phpcs:ignore
			vh_now()
		)
	);
	printf( "restored: %s\n", number_format( $done ) );

	VulnHub_Dash_Widgets::bust();
	\VulnHub\Core\Repo::recalculate_asset_rollups();
	echo "widget caches busted, asset roll-ups recalculated.\n";
	return;
}

$total = (int) $wpdb->get_var(
	"SELECT COUNT(*) FROM {$table}
	  WHERE severity IN ({$sev_sql}) AND state IN (" . vh_live_finding_sql() . ')' // phpcs:ignore
);

printf( "live findings at a suppressed severity: %s\n", number_format( $total ) );

$rows = (array) $wpdb->get_results(
	"SELECT severity, state, COUNT(*) n FROM {$table}
	  WHERE severity IN ({$sev_sql}) AND state IN (" . vh_live_finding_sql() . ')
	  GROUP BY severity, state ORDER BY n DESC', // phpcs:ignore
	ARRAY_A
);
foreach ( $rows as $row ) {
	printf( "  %-10s %-10s %s\n", $row['severity'], $row['state'], number_format( (int) $row['n'] ) );
}

if ( 'dry' === $mode ) {
	echo "\nNothing was written. Re-run with 'apply' to suppress, or 'restore' to undo.\n";
	return;
}

/*
 * Batched. A single UPDATE over 82,000 rows holds one transaction and one set
 * of row locks for its whole duration, and the cron container is running
 * syncs against this table the entire time.
 */
$moved = 0;
while ( true ) {
	$n = (int) $wpdb->query(
		$wpdb->prepare(
			"UPDATE {$table}
			    SET prev_state = IF( prev_state = '', state, prev_state ),
			        state      = 'suppressed',
			        updated_at = %s
			  WHERE severity IN ({$sev_sql}) AND state IN (" . vh_live_finding_sql() . ')
			  LIMIT 2000', // phpcs:ignore
			vh_now()
		)
	);

	if ( $n < 1 ) {
		break;
	}

	$moved += $n;
	printf( "  ...%s / %s\r", number_format( $moved ), number_format( $total ) );
}

printf( "\n\nsuppressed: %s findings\n", number_format( $moved ) );

VulnHub_Dash_Widgets::bust();
\VulnHub\Core\Repo::recalculate_asset_rollups();
echo "widget caches busted, asset roll-ups recalculated.\n";

printf(
	"\nlive findings remaining: %s\n",
	number_format( (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE state IN (" . vh_live_finding_sql() . ')' ) ) // phpcs:ignore
);
