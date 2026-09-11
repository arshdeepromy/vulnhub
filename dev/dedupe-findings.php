<?php
/**
 * One-off: collapse findings that were duplicated by port/protocol drift.
 *
 *     docker compose cp dev/dedupe-findings.php wpcli:/tmp/dd.php
 *     docker compose exec -T wpcli wp eval-file /tmp/dd.php            # dry run
 *     docker compose exec -T wpcli wp eval-file /tmp/dd.php apply      # merge
 *
 * The write path used to key a finding on its fingerprint alone, and the
 * fingerprint folds port and protocol in. Two Tenable exports of the same
 * estate disagree about both -- one reports port 0 with a blank protocol, the
 * next the SMB port it scanned over and "tcp" -- so the second export inserted
 * a fresh row for every finding that already existed, carrying none of the
 * plugin output (and so none of the install paths) the first had captured.
 * Repo::resolve_finding() stops it happening again; this cleans up what the
 * syncs before it left behind.
 *
 * A group is one (asset_id, vuln_id) pair. The lowest id survives and takes
 * the richest output in the group plus the newest scanner state; the rest are
 * deleted. Anything the merge cannot decide safely is left exactly as it is
 * and counted in the report -- this never guesses.
 *
 * Resumable: the work list lives in its own table, so an interrupted run
 * picks up where it stopped instead of starting over.
 *
 * @package VulnHub
 */

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	exit( "Run this through wp-cli - see the header for the docker compose cp/exec pair.\n" );
}

global $wpdb;

/** @var array<int,string> $args */
$vh_apply = in_array( 'apply', $args ?? array(), true );
$findings = vh_table( 'findings' );
$work     = $wpdb->prefix . 'vulnhub_dedupe_work';

/** Higher wins when two rows in a group disagree about state. */
$vh_state_rank = array(
	'reopened' => 3,
	'open'     => 2,
	'fixed'    => 1,
	'archived' => 0,
);

printf( "%s\n", $vh_apply ? '=== APPLY: rows will be merged and deleted ===' : '=== DRY RUN: nothing will be written ===' );

/* ---------------------------------------------------------------------------
 * Build the work list once, then walk it by primary key. Materialising the
 * duplicate pairs into a table rather than paging a GROUP BY keeps every
 * query bounded and lets an interrupted run resume.
 * ------------------------------------------------------------------------ */

$vh_resuming = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s', $work ) );

if ( ! $vh_resuming ) {
	echo "Building the work list…\n";
	$wpdb->query(
		"CREATE TABLE {$work} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
			asset_id BIGINT UNSIGNED NOT NULL,
			vuln_id BIGINT UNSIGNED NOT NULL
		) ENGINE=InnoDB"
	);
	$wpdb->query(
		"INSERT INTO {$work} (asset_id, vuln_id)
		 SELECT asset_id, vuln_id FROM {$findings}
		 GROUP BY asset_id, vuln_id HAVING COUNT(*) > 1"
	);
} else {
	echo "Work list already exists - resuming.\n";
}

$vh_pairs = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$work}" );
printf( "%s duplicated (asset, vuln) pairs to consider.\n\n", number_format( $vh_pairs ) );

$vh_stats = array(
	'groups_merged'   => 0,
	'rows_deleted'    => 0,
	'output_restored' => 0,
	'state_conflicts' => 0,
	'skip_ticketed'   => 0,
	'skip_archived'   => 0,
	'skip_multiport'  => 0,
);

$vh_cursor  = 0;
$vh_seen    = 0;
$vh_samples = array();

while ( true ) {
	$batch = $wpdb->get_results(
		$wpdb->prepare( "SELECT id, asset_id, vuln_id FROM {$work} WHERE id > %d ORDER BY id LIMIT 500", $vh_cursor ),
		ARRAY_A
	);

	if ( ! $batch ) {
		break;
	}

	foreach ( $batch as $pair ) {
		$vh_cursor = (int) $pair['id'];
		++$vh_seen;

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, fingerprint, state, port, protocol, service, severity, risk_score,
				        output, bundle_app, ticket_id, exception_id, verification_state, verified_at,
				        first_found, last_found, last_fixed, due_at, scan_uuid, last_synced_at
				 FROM {$findings} WHERE asset_id = %d AND vuln_id = %d ORDER BY id",
				(int) $pair['asset_id'],
				(int) $pair['vuln_id']
			),
			ARRAY_A
		);

		if ( count( $rows ) < 2 ) {
			continue;   // Already dealt with, or the duplicate went away.
		}

		/* ----- refuse anything the merge cannot decide safely ----- */

		foreach ( $rows as $row ) {
			if ( (int) $row['ticket_id'] > 0 || (int) $row['exception_id'] > 0 ) {
				++$vh_stats['skip_ticketed'];
				continue 2;
			}
			if ( 'archived' === (string) $row['state'] ) {
				++$vh_stats['skip_archived'];
				continue 2;
			}
		}

		$real_ports = array_unique(
			array_map( 'intval', array_column( array_filter( $rows, static fn( array $r ): bool => (int) $r['port'] > 0 ), 'port' ) )
		);
		if ( count( $real_ports ) > 1 ) {
			// Genuinely distinct network services on the same asset. Not a
			// duplicate at all -- leave both alone.
			++$vh_stats['skip_multiport'];
			continue;
		}

		/* ----- merge ----- */

		$keeper = $rows[0];
		$losers = array_slice( $rows, 1 );

		// Newest by scanner clock; the id is the tie-break so the choice is
		// stable across runs.
		$newest = $rows[0];
		foreach ( $rows as $row ) {
			if ( (string) $row['last_synced_at'] > (string) $newest['last_synced_at']
				|| ( (string) $row['last_synced_at'] === (string) $newest['last_synced_at'] && (int) $row['id'] > (int) $newest['id'] ) ) {
				$newest = $row;
			}
		}

		// The richest output in the group, whichever row happens to hold it.
		$output = '';
		foreach ( $rows as $row ) {
			if ( mb_strlen( (string) $row['output'] ) > mb_strlen( $output ) ) {
				$output = (string) $row['output'];
			}
		}
		if ( '' !== $output && '' === (string) $keeper['output'] ) {
			++$vh_stats['output_restored'];
		}

		// A finding still reported open by any view of it is open; only a
		// group that is fixed everywhere is fixed.
		$state = (string) $newest['state'];
		foreach ( $rows as $row ) {
			if ( ( $vh_state_rank[ (string) $row['state'] ] ?? 0 ) > ( $vh_state_rank[ $state ] ?? 0 ) ) {
				$state = (string) $row['state'];
			}
		}
		if ( $state !== (string) $newest['state'] ) {
			++$vh_stats['state_conflicts'];
		}

		$port     = (int) $newest['port'];
		$protocol = (string) $newest['protocol'];

		$merged = array(
			'fingerprint'    => vh_fingerprint( (string) $pair['asset_id'], (string) $pair['vuln_id'], (string) $port, $protocol ),
			'state'          => $state,
			'port'           => $port,
			'protocol'       => $protocol,
			'service'        => (string) $newest['service'],
			'severity'       => (string) $newest['severity'],
			'risk_score'     => (float) $newest['risk_score'],
			'scan_uuid'      => (string) $newest['scan_uuid'],
			'output'         => $output,
			'bundle_app'     => class_exists( 'VH_Product' ) ? \VH_Product::app_from_output( $output ) : (string) $keeper['bundle_app'],
			'last_found'     => $newest['last_found'],
			'due_at'         => $newest['due_at'],
			'last_synced_at' => $newest['last_synced_at'],
			'updated_at'     => vh_now(),
		);
		$merged['bundle_app_slug'] = class_exists( 'VH_Product' ) ? \VH_Product::slug( (string) $merged['bundle_app'] ) : '';

		// Oldest sighting and newest closure across the whole group.
		$firsts = array_filter( array_column( $rows, 'first_found' ) );
		$fixes  = array_filter( array_column( $rows, 'last_fixed' ) );
		if ( $firsts ) {
			$merged['first_found'] = min( $firsts );
		}
		if ( $fixes ) {
			$merged['last_fixed'] = max( $fixes );
		}

		// Verification detail lives on whichever row carries it.
		foreach ( $rows as $row ) {
			if ( ! empty( $row['verification_state'] ) ) {
				$merged['verification_state'] = (string) $row['verification_state'];
				$merged['verified_at']        = $row['verified_at'];
				break;
			}
		}

		if ( count( $vh_samples ) < 5 ) {
			$vh_samples[] = sprintf(
				'  asset %d / vuln %d: keep #%d, drop %s -> port %d/%s, state %s, output %s',
				(int) $pair['asset_id'],
				(int) $pair['vuln_id'],
				(int) $keeper['id'],
				implode( ',', array_map( static fn( array $r ): string => '#' . $r['id'], $losers ) ),
				$port,
				'' !== $protocol ? $protocol : '-',
				$state,
				'' !== $output ? mb_strlen( $output ) . ' chars' : 'none'
			);
		}

		++$vh_stats['groups_merged'];
		$vh_stats['rows_deleted'] += count( $losers );

		if ( $vh_apply ) {
			// Delete first: `fingerprint` is UNIQUE, and the keeper is about
			// to take the port/protocol -- and so the fingerprint -- that one
			// of the losers currently holds.
			$ids = implode( ',', array_map( static fn( array $r ): int => (int) $r['id'], $losers ) );
			$wpdb->query( "DELETE FROM {$findings} WHERE id IN ({$ids})" );
			$wpdb->update( $findings, $merged, array( 'id' => (int) $keeper['id'] ) );
		}
	}

	printf( "  …%s / %s pairs\r", number_format( $vh_seen ), number_format( $vh_pairs ) );

	if ( $vh_apply ) {
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$work} WHERE id <= %d", $vh_cursor ) );
		$vh_cursor = 0;
	}
}

echo "\n\n";
if ( $vh_samples ) {
	echo "Sample of what was merged:\n" . implode( "\n", $vh_samples ) . "\n\n";
}

printf( "Groups merged        %s\n", number_format( $vh_stats['groups_merged'] ) );
printf( "Rows deleted         %s\n", number_format( $vh_stats['rows_deleted'] ) );
printf( "Findings given back\n  their install path %s\n", number_format( $vh_stats['output_restored'] ) );
printf( "State conflicts      %s  (a view said fixed while another said open; open won)\n", number_format( $vh_stats['state_conflicts'] ) );
printf( "Skipped, ticketed    %s\n", number_format( $vh_stats['skip_ticketed'] ) );
printf( "Skipped, archived    %s\n", number_format( $vh_stats['skip_archived'] ) );
printf( "Skipped, real multi-service %s\n", number_format( $vh_stats['skip_multiport'] ) );

if ( $vh_apply ) {
	$wpdb->query( "DROP TABLE IF EXISTS {$work}" );

	/*
	 * assets.risk_score is a cached roll-up of each asset's open findings, so
	 * every asset that had a duplicate was carrying the same finding's risk
	 * twice. Nothing else derives from findings this way -- the threat
	 * plugin's asset_exposure is built from the assets table, not from these
	 * rows -- so this one pass is enough to make the estate consistent again.
	 */
	echo "\nRecalculating asset risk roll-ups…\n";
	\VulnHub\Core\Repo::recalculate_asset_rollups();

	printf( "\nFindings table now holds %s rows.\n", number_format( (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$findings}" ) ) );
} else {
	$wpdb->query( "DROP TABLE IF EXISTS {$work}" );
	echo "\nNothing was written. Re-run with --apply to merge.\n";
}
