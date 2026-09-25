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
	 * Who can set an asset's lifecycle, in the order they win.
	 *
	 * @return array<string,string> slug => label.
	 */
	public static function sources(): array {
		return array(
			'manual'   => __( 'Set by hand', 'vulnhub' ),
			'cmdb'     => __( 'CMDB', 'vulnhub' ),
			'aws'      => __( 'AWS', 'vulnhub' ),
			'tenable'  => __( 'Tenable', 'vulnhub' ),
			'fleet'    => __( 'AppStream fleet', 'vulnhub' ),
			'merge'    => __( 'Duplicate merged', 'vulnhub' ),
			'restore'  => __( 'Restored', 'vulnhub' ),
			'rule'     => __( 'Not in CMDB: VulnHub rule', 'vulnhub' ),
			'system'   => __( 'VulnHub', 'vulnhub' ),
		);
	}

	/** The source to record for a change, naming a person when there is one. */
	private static function who( string $source ): string {
		$source = sanitize_key( $source );
		if ( '' !== $source ) {
			return $source;
		}

		$person = get_current_user_id() > 0 && ! wp_doing_cron() && ! ( defined( 'WP_CLI' ) && WP_CLI );

		return $person ? 'manual' : 'system';
	}

	/**
	 * Lifecycle for the servers and workstations the CMDB does not know.
	 *
	 * The CMDB owns lifecycle for everything it lists (its Status, applied
	 * on every CMDB sync). For the rest there was no rule: whichever feed
	 * created the record wrote a status once -- the Defender import called
	 * every new device in service, an AppStream fleet record was born in
	 * service -- and nothing ever revisited it. So:
	 *
	 *  - **Server, not in the CMDB:** in service while Tenable, Defender, AWS
	 *    or the posture inventory has seen it inside the contact window.
	 *  - **Workstation, not in the CMDB:** in service only with an owner from
	 *    Intune *and* a Tenable scan or Defender contact inside the window.
	 *    Otherwise Unknown -- not claimed in service, but still counted:
	 *    Unknown is in the reporting scope, so no finding is archived and no
	 *    number drops. The owner gap shows on the existing filters.
	 *
	 * Deliberately narrow, because every other status was set by newer
	 * evidence than a sighting: only records that are In service or Unknown
	 * move, and only between those two. Retired (AppStream clean-up, a
	 * merge, an instance that is gone), Missing (gone from Tenable's complete
	 * export), Spare (instance stopped) and anything set by hand or by the
	 * CMDB are left exactly as they are. A server this rule did not put in
	 * service is never taken out of it.
	 *
	 * @param bool $dry_run Count, change nothing.
	 * @return array{candidates:int,to_in_service:int,to_unknown:int,unchanged:int,examples:array<int,string>}
	 */
	public static function derive( bool $dry_run = false ): array {
		global $wpdb;

		$a    = vh_table( 'assets' );
		$days = max( 1, (int) vulnhub()->settings->platform( 'contact_window_days', 45 ) );
		$from = gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS );

		$rows = (array) $wpdb->get_results( // phpcs:ignore
			"SELECT id, hostname, asset_type, primary_source, lifecycle_status, lifecycle_source, lifecycle_reason,
					owner_person_id, owner_source, sources_json, tenable_last_scan, defender_last_seen, last_seen, aws_instance_id
			 FROM {$a}
			 WHERE ( duplicate_of IS NULL OR duplicate_of = 0 )
			   AND cmdb_id = '' AND sources_json NOT LIKE '%\"cmdb\"%'
			   AND asset_type IN ( 'server', 'workstation' )
			   AND lifecycle_status IN ( 'in_service', 'unknown' )
			   AND lifecycle_source NOT IN ( 'manual', 'cmdb' )", // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			ARRAY_A
		);

		$out  = array( 'candidates' => count( $rows ), 'to_in_service' => 0, 'to_unknown' => 0, 'unchanged' => 0, 'examples' => array() );
		$move = array( 'in_service' => array(), 'unknown' => array() );
		$why  = array();

		foreach ( $rows as $r ) {
			$src = (array) json_decode( (string) $r['sources_json'], true );
			$saw = array(
				'Tenable'  => max( (string) ( $r['tenable_last_scan'] ?? '' ), (string) ( $src['tenable'] ?? '' ) ),
				'Defender' => max( (string) ( $r['defender_last_seen'] ?? '' ), (string) ( $src['defender'] ?? '' ) ),
			);
			// AWS and the posture inventory do not stamp a per-source date;
			// a record they made, or an instance, is seen when last_seen is.
			if ( in_array( (string) $r['primary_source'], array( 'aws', 'plerion', 'fleet' ), true ) || '' !== (string) $r['aws_instance_id'] ) {
				$saw['AWS'] = (string) $r['last_seen'];
			}

			$recent = array_filter( $saw, static fn( string $d ): bool => '' !== $d && $d >= $from );
			arsort( $recent );

			if ( 'server' === $r['asset_type'] ) {
				if ( $recent ) {
					$by     = (string) array_key_first( $recent );
					$target = 'in_service';
					/* translators: 1: source, 2: date. */
					$reason = sprintf( __( 'Server not in CMDB; seen by %1$s on %2$s', 'vulnhub' ), $by, substr( (string) $recent[ $by ], 0, 10 ) );
				} elseif ( 'rule' === $r['lifecycle_source'] ) {
					$target = 'unknown';
					/* translators: %d: days. */
					$reason = sprintf( __( 'Server not in CMDB; no source has seen it in %d days', 'vulnhub' ), $days );
				} else {
					++$out['unchanged'];
					continue;
				}
			} else {
				$owner = (int) $r['owner_person_id'] > 0 && str_starts_with( (string) $r['owner_source'], 'intune' );
				$scan  = array_intersect_key( $recent, array( 'Tenable' => 1, 'Defender' => 1 ) );

				if ( $owner && $scan ) {
					$by     = (string) array_key_first( $scan );
					$target = 'in_service';
					/* translators: 1: source, 2: date. */
					$reason = sprintf( __( 'Workstation not in CMDB; Intune owner, seen by %1$s on %2$s', 'vulnhub' ), $by, substr( (string) $scan[ $by ], 0, 10 ) );
				} else {
					$target = 'unknown';
					$reason = ! $owner
						? __( 'Workstation not in CMDB and no owner from Intune', 'vulnhub' )
						/* translators: %d: days. */
						: sprintf( __( 'Workstation not in CMDB; no Tenable scan or Defender contact in %d days', 'vulnhub' ), $days );
				}
			}

			$why[ (int) $r['id'] ] = $reason;

			if ( $target === $r['lifecycle_status'] ) {
				++$out['unchanged'];
			} else {
				$move[ $target ][] = (int) $r['id'];
				++$out[ 'in_service' === $target ? 'to_in_service' : 'to_unknown' ];
				if ( count( $out['examples'] ) < 12 ) {
					$out['examples'][] = sprintf( '%s: %s -> %s (%s)', (string) $r['hostname'], (string) $r['lifecycle_status'], $target, $reason );
				}
			}
		}

		if ( $dry_run ) {
			return $out;
		}

		// Moves through set(), so findings, roll-ups and coverage follow
		// (between these two statuses nothing is archived).
		foreach ( $move as $status => $ids ) {
			if ( $ids ) {
				self::set( $ids, $status, 'rule', __( 'Not in CMDB', 'vulnhub' ) );
			}
		}

		// Every record the rule covers says why, moved or not.
		foreach ( $why as $id => $reason ) {
			$wpdb->query( // phpcs:ignore
				$wpdb->prepare(
					"UPDATE {$a} SET lifecycle_source = 'rule', lifecycle_reason = %s, lifecycle_set_at = COALESCE( lifecycle_set_at, %s ) WHERE id = %d AND ( lifecycle_source <> 'rule' OR lifecycle_reason <> %s )", // phpcs:ignore
					mb_substr( $reason, 0, 191 ),
					vh_now(),
					$id,
					mb_substr( $reason, 0, 191 )
				)
			);
		}

		return $out;
	}

	/**
	 * Put assets into a lifecycle status and reconcile everything that follows.
	 *
	 * @param array<int,int> $asset_ids Assets to move.
	 * @param string         $status    A key of vh_lifecycle_statuses().
	 * @param string         $source    Who decided (sources()). Empty: a
	 *                                  person when one is signed in and
	 *                                  this is not cron or wp-cli, else
	 *                                  `system`.
	 * @param string         $reason    One line saying why, for the asset page.
	 * @return array{assets:int,archived:int,restored:int,status:string}
	 */
	public static function set( array $asset_ids, string $status, string $source = '', string $reason = '' ): array {
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
				"UPDATE {$assets} SET lifecycle_status = %s, lifecycle_source = %s, lifecycle_reason = %s, lifecycle_set_at = %s, updated_at = %s WHERE id IN ({$in})", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				...array_merge( array( $status, self::who( $source ), mb_substr( $reason, 0, 191 ), vh_now(), vh_now() ), $ids )
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
				'source'   => self::who( $source ),
				'reason'   => $reason,
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

