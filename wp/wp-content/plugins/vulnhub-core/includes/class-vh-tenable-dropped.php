<?php
/**
 * Assets Tenable has dropped while the business still runs them.
 *
 * Tenable reclaims licences and deletes assets that have been quiet for long
 * enough. When it does, the findings we already hold stop being a picture of
 * anything: nothing is scanning that machine any more, so the numbers freeze at
 * whatever they were and go on looking current.
 *
 * **Absence from a sync is not evidence.** An incremental asset export returns
 * only recently-assessed hosts, so a machine missing from one has usually just
 * not been rescanned. Measured on this estate: of eight assets whose Tenable
 * date had fallen behind, all eight were still in Tenable. Inferring removal
 * from a sync would have condemned every one of them. So removal is *verified*,
 * one asset at a time, against `GET /assets/{uuid}`: 404 is the only thing this
 * class will accept as gone.
 *
 * **And gone is not the same as wrong.** An asset Tenable dropped that the CMDB
 * has since retired was dropped correctly, and putting it back would be the
 * mistake. What makes this actionable is the combination: the scanner has let
 * go of a machine the CMDB still reports, fresh, as in service -- a live host
 * that nothing is scanning, carrying findings nobody is refreshing.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Tenable_Dropped {

	/** Assets verified per run, so a daily job stays bounded and polite. */
	private const BATCH = 40;

	/** Don't re-ask about the same asset more often than this. */
	private const RECHECK_DAYS = 3;

	/** The CMDB's own reporting must be at least this fresh to be leaned on. */
	private const CMDB_FRESH_DAYS = 7;

	/**
	 * Assets worth asking Tenable about.
	 *
	 * Tenable knew them (they carry a uuid), the CMDB still reports them in
	 * service and reported recently, and Tenable's own last word on them is
	 * older than the connector's most recent asset import. Ordered oldest
	 * first so the worst are confirmed first.
	 *
	 * @return array<int,array{id:int,hostname:string,tenable_uuid:string,findings:int}>
	 */
	public static function candidates( int $limit = self::BATCH ): array {
		global $wpdb;

		$a       = vh_table( 'assets' );
		$fresh   = gmdate( 'Y-m-d', time() - self::CMDB_FRESH_DAYS * DAY_IN_SECONDS );
		$recheck = gmdate( 'Y-m-d H:i:s', time() - self::RECHECK_DAYS * DAY_IN_SECONDS );

		return (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, hostname, tenable_uuid,
					(open_critical + open_high + open_medium + open_low) AS findings
				 FROM {$a}
				 WHERE tenable_uuid <> ''
				   AND lifecycle_status IN (" . vh_scannable_sql() . ")
				   AND LOCATE('cmdb', sources_json) > 0
				   AND JSON_UNQUOTE(JSON_EXTRACT(sources_json, '$.cmdb')) >= %s
				   AND ( tenable_checked_at IS NULL OR tenable_checked_at < %s )
				 ORDER BY tenable_dropped_at IS NULL, tenable_checked_at IS NOT NULL, tenable_last_scan ASC
				 LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$fresh,
				$recheck,
				max( 1, min( 200, $limit ) )
			),
			ARRAY_A
		);
	}

	/**
	 * Ask Tenable about a batch, and record the answers.
	 *
	 * A 404 marks the asset dropped. Any successful read clears the mark --
	 * including for an asset that was marked before and has since been
	 * re-onboarded, which is how the flag heals itself without anyone
	 * remembering to clear it. Anything else (a 500, a timeout, a rate limit)
	 * changes nothing at all: an API having a bad minute must never be able to
	 * declare an estate missing.
	 *
	 * @return array{checked:int,dropped:int,restored:int,skipped:int}
	 */
	public static function verify( \VulnHub_Tenable_Connector $connector, int $limit = self::BATCH ): array {
		global $wpdb;

		$out = array( 'checked' => 0, 'dropped' => 0, 'restored' => 0, 'skipped' => 0 );

		if ( ! $connector->is_enabled() || $connector->is_mock() ) {
			return $out;
		}

		$a   = vh_table( 'assets' );
		$now = vh_now();

		foreach ( self::candidates( $limit ) as $row ) {
			$status = $connector->asset_http_status( (string) $row['tenable_uuid'] );

			// Unknown is unknown: leave the record exactly as it was.
			if ( 404 !== $status && ( $status < 200 || $status > 299 ) ) {
				++$out['skipped'];
				continue;
			}

			++$out['checked'];

			$was     = null !== $wpdb->get_var( $wpdb->prepare( "SELECT tenable_dropped_at FROM {$a} WHERE id = %d", (int) $row['id'] ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$dropped = 404 === $status;

			$wpdb->update(
				$a,
				array(
					'tenable_dropped_at' => $dropped ? ( $was ? null : $now ) : null,
					'tenable_checked_at' => $now,
					'updated_at'         => $now,
				),
				array( 'id' => (int) $row['id'] )
			);

			/*
			 * Keep the original drop date when it was already marked: "gone
			 * since" is only useful if it means the first time we could prove
			 * it, not the last time we asked.
			 */
			if ( $dropped && $was ) {
				$wpdb->query( $wpdb->prepare( "UPDATE {$a} SET tenable_dropped_at = COALESCE(tenable_dropped_at, %s) WHERE id = %d", $now, (int) $row['id'] ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			}

			if ( $dropped && ! $was ) {
				++$out['dropped'];
				$connector->log( sprintf( 'Tenable no longer holds %s (HTTP 404) and the CMDB still reports it in service.', (string) $row['hostname'] ) );
			} elseif ( ! $dropped && $was ) {
				++$out['restored'];
			}
		}

		update_option( 'vulnhub_tenable_dropped_checked_at', $now, false );

		return $out;
	}

	/** How many assets are currently confirmed dropped, and what they carry. */
	public static function summary(): array {
		global $wpdb;

		$row = (array) $wpdb->get_row(
			'SELECT COUNT(*) AS assets,
				COALESCE(SUM(open_critical + open_high + open_medium + open_low), 0) AS findings
			 FROM ' . vh_table( 'assets' ) . ' WHERE tenable_dropped_at IS NOT NULL',
			ARRAY_A
		);

		return array(
			'assets'   => (int) ( $row['assets'] ?? 0 ),
			'findings' => (int) ( $row['findings'] ?? 0 ),
			'checked'  => (string) get_option( 'vulnhub_tenable_dropped_checked_at', '' ),
		);
	}
}
