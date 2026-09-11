<?php
/**
 * Moving an asset in and out of service, and taking its findings with it.
 *
 * @package VulnHub
 */

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * One rule, applied in one place.
 *
 * An asset that is not in service is out of coverage scope -- `Coverage`
 * has always said so -- but its findings went on counting, so a
 * decommissioned machine left the estate in the coverage chart and stayed in
 * it in every severity total. The two answers disagreed, which is the worst
 * possible state for a number somebody reports upwards.
 *
 * So: not in service means out of scope means findings archived. The sweep
 * below is the whole rule, it is set-based, and it is re-run after every
 * import -- because a re-import reopens findings on machines that left
 * months ago, and a rule that has to be remembered is a rule that decays.
 *
 * Archiving is not deletion. `prev_state` remembers what a finding was
 * before it was put away, so returning an asset to service restores exactly
 * the state it had rather than a guess at one.
 */
final class Lifecycle {

	/**
	 * Put assets into a lifecycle status and reconcile everything that follows.
	 *
	 * @param array<int,int> $asset_ids Assets to move.
	 * @param string         $status    A key of vh_lifecycle_statuses().
	 * @return array{assets:int,archived:int,restored:int,status:string}
	 */
	public static function set( array $asset_ids, string $status ): array {
		global $wpdb;

		$ids    = array_values( array_unique( array_filter( array_map( 'intval', $asset_ids ) ) ) );
		$status = vh_normalise_lifecycle( $status );

		$empty = array(
			'assets'   => 0,
			'archived' => 0,
			'restored' => 0,
			'status'   => $status,
		);

		if ( ! $ids || ! isset( vh_lifecycle_statuses()[ $status ] ) ) {
			return $empty;
		}

		$assets = vh_table( 'assets' );
		$in     = implode( ',', array_fill( 0, count( $ids ), '%d' ) );

		$changed = (int) $wpdb->query(
			$wpdb->prepare(
				"UPDATE {$assets} SET lifecycle_status = %s, updated_at = %s WHERE id IN ({$in})", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				...array_merge( array( $status, vh_now() ), $ids )
			)
		);

		$moved = self::sweep( $ids );

		/*
		 * Roll-ups first, then coverage. The roll-up reads finding states, so
		 * running it before the sweep would bake in the numbers we just
		 * changed; coverage reads lifecycle, which is already written.
		 */
		Repo::recalculate_asset_rollups();
		Coverage::recalculate();

		vulnhub()->logger->audit(
			'asset.lifecycle',
			sprintf(
				/* translators: 1: number of assets, 2: lifecycle status label. */
				__( '%1$d asset(s) set to %2$s', 'vulnhub' ),
				count( $ids ),
				(string) ( vh_lifecycle_statuses()[ $status ]['label'] ?? $status )
			),
			'asset',
			1 === count( $ids ) ? (string) $ids[0] : implode( ',', array_slice( $ids, 0, 20 ) ),
			array(
				'status'   => $status,
				'assets'   => $ids,
				'archived' => $moved['archived'],
				'restored' => $moved['restored'],
			),
			'notice'
		);

		/**
		 * Fires after assets have been moved between lifecycle statuses.
		 *
		 * @param array<int,int>      $ids    Assets that moved.
		 * @param string              $status The status they moved to.
		 * @param array<string,int>   $moved  Findings archived and restored.
		 */
		do_action( 'vulnhub_lifecycle_changed', $ids, $status, $moved );

		return array(
			'assets'   => $changed,
			'archived' => $moved['archived'],
			'restored' => $moved['restored'],
			'status'   => $status,
		);
	}

	/**
	 * Bring findings back in line with the lifecycle of the asset they sit on.
	 *
	 * Safe to run at any time and as often as you like: it is two UPDATEs
	 * whose WHERE clauses match nothing once the estate agrees with itself.
	 *
	 * @param array<int,int> $asset_ids Limit to these assets; empty means all.
	 * @return array{archived:int,restored:int}
	 */
	public static function sweep( array $asset_ids = array() ): array {
		global $wpdb;

		$assets   = vh_table( 'assets' );
		$findings = vh_table( 'findings' );
		$in_scope = vh_in_service_sql();
		$live     = "'" . implode( "','", array_map( 'esc_sql', vh_live_finding_states() ) ) . "'";

		$scope  = '';
		$params = array();
		$ids    = array_values( array_unique( array_filter( array_map( 'intval', $asset_ids ) ) ) );

		if ( $ids ) {
			$scope  = ' AND a.id IN (' . implode( ',', array_fill( 0, count( $ids ), '%d' ) ) . ')';
			$params = $ids;
		}

		/*
		 * Out of service: put the live findings away, remembering what they
		 * were. `prev_state` is only written when it is still empty, so an
		 * asset swept twice does not overwrite the original state with
		 * 'archived' and lose the way back.
		 */
		$archived = (int) $wpdb->query(
			$wpdb->prepare(
				"UPDATE {$findings} f
				 JOIN {$assets} a ON a.id = f.asset_id
				 SET f.prev_state  = IF( f.prev_state = '', f.state, f.prev_state ),
				     f.state       = 'archived',
				     f.archived_at = %s,
				     f.updated_at  = %s
				 WHERE a.lifecycle_status NOT IN ({$in_scope})
				   AND f.state IN ({$live}){$scope}", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				...array_merge( array( vh_now(), vh_now() ), $params )
			)
		);

		/*
		 * Back in service: exactly what it was before, not a guess. A finding
		 * archived before `prev_state` existed falls back to 'open', which is
		 * the state all but a handful of them were in.
		 */
		$restored = (int) $wpdb->query(
			$wpdb->prepare(
				"UPDATE {$findings} f
				 JOIN {$assets} a ON a.id = f.asset_id
				 SET f.state       = IF( f.prev_state = '', 'open', f.prev_state ),
				     f.prev_state  = '',
				     f.archived_at = NULL,
				     f.updated_at  = %s
				 WHERE a.lifecycle_status IN ({$in_scope})
				   AND f.state = 'archived'{$scope}", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				...array_merge( array( vh_now() ), $params )
			)
		);

		return array(
			'archived' => $archived,
			'restored' => $restored,
		);
	}

	/**
	 * The same sweep, followed by the recounts, for use after an import.
	 *
	 * A Tenable export reports the machines it scanned last month, including
	 * ones retired since, and re-opens their findings. Without this the
	 * numbers silently drift back every sync.
	 */
	public static function sweep_and_recount(): array {
		$moved = self::sweep();

		if ( $moved['archived'] || $moved['restored'] ) {
			Repo::recalculate_asset_rollups();
		}

		return $moved;
	}

	/**
	 * How many live findings sit on these assets right now.
	 *
	 * Used to tell the operator what a decommission is about to put away,
	 * before they press the button rather than after.
	 *
	 * @param array<int,int> $asset_ids Assets to count across.
	 */
	public static function live_finding_count( array $asset_ids ): int {
		global $wpdb;

		$ids = array_values( array_unique( array_filter( array_map( 'intval', $asset_ids ) ) ) );

		if ( ! $ids ) {
			return 0;
		}

		$findings = vh_table( 'findings' );
		$live     = "'" . implode( "','", array_map( 'esc_sql', vh_live_finding_states() ) ) . "'";
		$in       = implode( ',', array_fill( 0, count( $ids ), '%d' ) );

		return (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$findings} WHERE state IN ({$live}) AND asset_id IN ({$in})", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				...$ids
			)
		);
	}

	/**
	 * How many archived findings an asset is holding.
	 */
	public static function archived_count( int $asset_id ): int {
		global $wpdb;

		if ( ! $asset_id ) {
			return 0;
		}

		return (int) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(*) FROM ' . vh_table( 'findings' ) . ' WHERE state = %s AND asset_id = %d',
				'archived',
				$asset_id
			)
		);
	}
}

