<?php
/**
 * Endpoint (Defender) coverage.
 *
 * The sibling of `Coverage`, asking the same question of a different feed.
 * Where that class answers "has a scanner looked inside this machine", this
 * one answers "is the endpoint sensor actually running on it" -- and the two
 * gaps are not the same set. A server can be scanned weekly by Tenable and
 * still have no Defender sensor, in which case nothing is watching it between
 * scans; a laptop can be onboarded to Defender and never have been scanned,
 * in which case its unpatched software is invisible. Only reporting both says
 * which of the two somebody has to go and fix.
 *
 * The state machine deliberately mirrors the scanning one, including its
 * central rule: an asset Defender holds but has not heard from is *covered*
 * and separately flagged, not a coverage gap. Sending somebody to onboard a
 * machine that is already onboarded wastes the trip and buries the machines
 * that genuinely have no sensor.
 *
 * The scope is the same too: `vh_scannable_statuses()` decides what counts as
 * an in-service asset, so retired and in-stock kit never lands in a
 * denominator here either. On top of it Defender adds a scope rule of its
 * own -- a printer, a switch or a video-conference unit is discovered by
 * Defender and can never be onboarded to it, and counting those as gaps would
 * put sixty devices nobody can do anything about at the top of the list.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Defender_Coverage {

	/** Onboarded, and the sensor has reported inside the freshness window. */
	public const ONBOARDED = 'onboarded';

	/** Onboarded, but the sensor has not reported inside the window. */
	public const SILENT = 'silent';

	/** Onboarded, and the sensor has never reported at all. */
	public const NEVER_REPORTED = 'never_reported';

	/** Defender can see the device and could onboard it. Nobody has. */
	public const NOT_ONBOARDED = 'not_onboarded';

	/** Defender has no record of the asset at all. */
	public const NOT_IN_DEFENDER = 'not_in_defender';

	/** No Defender record, and nothing else has seen it lately either. */
	public const NO_CONTACT = 'no_contact';

	/** Retired, in stock, or a device Defender cannot onboard. */
	public const OUT_OF_SCOPE = 'out_of_scope';

	/** A live device of a class no endpoint agent was going onto. */
	public const OTHER_DEVICE = 'other_device';

	/** The onboarding values that mean Defender will never manage this device. */
	public const UNONBOARDABLE = array( 'unsupported', 'insufficient_info' );

	/**
	 * Every state, worst first, with how to describe it.
	 *
	 * @return array<string,array{label:string,tone:string,gap:bool}>
	 */
	public static function states(): array {
		return array(
			self::NOT_IN_DEFENDER => array(
				'label' => __( 'Not in Defender', 'vulnhub' ),
				'tone'  => 'bad',
				'gap'   => true,
			),
			self::NOT_ONBOARDED   => array(
				'label' => __( 'Seen, not onboarded', 'vulnhub' ),
				'tone'  => 'bad',
				'gap'   => true,
			),
			self::NEVER_REPORTED  => array(
				'label' => __( 'Never reported', 'vulnhub' ),
				'tone'  => 'warn',
				'gap'   => false,
			),
			self::NO_CONTACT      => array(
				'label' => __( 'No recent contact', 'vulnhub' ),
				'tone'  => 'warn',
				'gap'   => true,
			),
			self::SILENT          => array(
				'label' => __( 'Sensor silent', 'vulnhub' ),
				'tone'  => 'warn',
				'gap'   => false,
			),
			self::ONBOARDED       => array(
				'label' => __( 'Onboarded', 'vulnhub' ),
				'tone'  => 'good',
				'gap'   => false,
			),
			self::OTHER_DEVICE    => array(
				'label' => __( 'Not an endpoint target', 'vulnhub' ),
				'tone'  => 'muted',
				'gap'   => false,
			),
			self::OUT_OF_SCOPE    => array(
				'label' => __( 'Out of scope', 'vulnhub' ),
				'tone'  => 'muted',
				'gap'   => false,
			),
		);
	}

	public static function label( string $state ): string {
		$states = self::states();

		return (string) ( $states[ $state ]['label'] ?? $state );
	}

	public static function tone( string $state ): string {
		$states = self::states();

		return (string) ( $states[ $state ]['tone'] ?? 'muted' );
	}

	/** States that count as a gap somebody has to close. */
	public static function gap_states(): array {
		return array_keys( array_filter( self::states(), static fn( array $s ): bool => $s['gap'] ) );
	}

	/**
	 * States where Defender is managing the asset.
	 *
	 * The Defender equivalent of `Coverage::in_tenable_states()`, and for the
	 * same reason: onboarded-and-quiet is a sensor to chase, not an endpoint
	 * to onboard.
	 *
	 * @return array<int,string>
	 */
	public static function covered_states(): array {
		return array( self::ONBOARDED, self::SILENT, self::NEVER_REPORTED );
	}

	/**
	 * States where Defender holds the asset but has heard nothing current.
	 *
	 * @return array<int,string>
	 */
	public static function quiet_states(): array {
		return array( self::SILENT, self::NEVER_REPORTED );
	}

	/** covered_states() as a quoted SQL list. */
	public static function covered_sql(): string {
		return "'" . implode( "','", array_map( 'esc_sql', self::covered_states() ) ) . "'";
	}

	/**
	 * How long a sensor may stay quiet before it is worth flagging.
	 *
	 * Shares the scanning window's setting by default -- an estate that
	 * considers a 30-day-old scan current has no reason to consider a
	 * 30-day-old check-in stale -- but is separately filterable, because a
	 * sensor reports continuously and a scanner runs on a schedule.
	 */
	public static function window_days(): int {
		return max( 1, (int) apply_filters( 'vulnhub_defender_window_days', Coverage::window_days() ) );
	}

	/* =================================================================
	 * Write
	 * ============================================================== */

	/**
	 * Recompute `defender_coverage_state` for every asset.
	 *
	 * Runs off the back of `Coverage::recalculate()` so the two can never
	 * describe the estate as of different moments.
	 */
	public static function recalculate(): void {
		global $wpdb;

		$a        = vh_table( 'assets' );
		$cutoff   = gmdate( 'Y-m-d H:i:s', time() - self::window_days() * DAY_IN_SECONDS );
		$seen_by  = gmdate( 'Y-m-d H:i:s', time() - Coverage::contact_days() * DAY_IN_SECONDS );
		$contact  = Coverage::contact_sql();
		$in_scope = vh_scannable_sql();
		$cannot   = "'" . implode( "','", array_map( 'esc_sql', self::UNONBOARDABLE ) ) . "'";
		$types    = vh_scannable_types_sql();

		/*
		 * Two scope rules, in this order and not the other way round.
		 *
		 * The lifecycle test comes first because a retired printer should
		 * read as retired, not as a device Defender cannot support -- the
		 * reason an asset is excluded is what tells somebody whether to do
		 * anything about it.
		 */
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE {$a} a SET a.defender_coverage_state = CASE
					WHEN a.lifecycle_status NOT IN ({$in_scope}) THEN %s
					WHEN a.asset_type NOT IN ({$types}) THEN %s
					WHEN a.defender_onboarding IN ({$cannot}) THEN %s
					WHEN a.defender_onboarding = 'can_be_onboarded' THEN %s
					WHEN a.defender_onboarding = 'onboarded' AND a.defender_last_seen IS NULL THEN %s
					WHEN a.defender_onboarding = 'onboarded' AND a.defender_last_seen < %s THEN %s
					WHEN a.defender_onboarding = 'onboarded' THEN %s
					WHEN {$contact} > '1970-01-01' AND {$contact} < %s THEN %s
					ELSE %s
				END", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				self::OUT_OF_SCOPE,
				self::OTHER_DEVICE,
				self::OUT_OF_SCOPE,
				self::NOT_ONBOARDED,
				self::NEVER_REPORTED,
				$cutoff,
				self::SILENT,
				self::ONBOARDED,
				$seen_by,
				self::NO_CONTACT,
				self::NOT_IN_DEFENDER
			)
		);

		/** Fires once endpoint coverage has been recomputed for the estate. */
		do_action( 'vulnhub_defender_coverage_recalculated' );
	}

	/**
	 * What is being held back from the Defender denominator, and why.
	 *
	 * Two lists rather than one. Retired kit is excluded for the same reason
	 * it is excluded everywhere else; a switch is excluded because Defender
	 * cannot onboard a switch, which is a different fact and belongs under a
	 * different heading.
	 *
	 * @return array<int,array{status:string,label:string,count:int}>
	 */
	public static function excluded_by_scope(): array {
		global $wpdb;

		$a      = vh_table( 'assets' );
		$cannot = "'" . implode( "','", array_map( 'esc_sql', self::UNONBOARDABLE ) ) . "'";
		$labels = vh_lifecycle_statuses();
		$out    = array();

		$rows = (array) $wpdb->get_results(
			"SELECT lifecycle_status AS status, COUNT(*) AS n FROM {$a}
			 WHERE lifecycle_status NOT IN (" . vh_scannable_sql() . ')
			 GROUP BY lifecycle_status ORDER BY n DESC', // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			ARRAY_A
		);

		foreach ( $rows as $row ) {
			$slug  = (string) $row['status'];
			$out[] = array(
				'status' => $slug,
				'label'  => (string) ( $labels[ $slug ]['label'] ?? $slug ),
				'count'  => (int) $row['n'],
			);
		}

		$other = (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$a} WHERE defender_coverage_state = '" . esc_sql( self::OTHER_DEVICE ) . "'" // phpcs:ignore WordPress.DB.PreparedSQL
		);

		if ( $other > 0 ) {
			$out[] = array(
				'status' => self::OTHER_DEVICE,
				'label'  => __( 'printers, switches and other kit no agent runs on', 'vulnhub' ),
				'count'  => $other,
			);
		}

		/*
		 * What is left here is a *computer* Defender says it cannot onboard --
		 * an old server, an ESXi host, a box the sensor does not support. Very
		 * different from a printer, and worth its own line: nothing is
		 * watching those, and unlike a switch somebody could do something
		 * about it.
		 */
		$unsupportable = (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$a}
			 WHERE lifecycle_status IN (" . vh_scannable_sql() . ")
			   AND asset_type IN (" . vh_scannable_types_sql() . ")
			   AND defender_onboarding IN ({$cannot})" // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		);

		if ( $unsupportable > 0 ) {
			$out[] = array(
				'status' => 'unonboardable',
				'label'  => __( 'servers and workstations Defender cannot onboard', 'vulnhub' ),
				'count'  => $unsupportable,
			);
		}

		return $out;
	}

	/* =================================================================
	 * Read
	 * ============================================================== */

	/**
	 * Headline endpoint-coverage numbers, in-scope only.
	 *
	 * @return array<string,mixed>
	 */
	public static function summary(): array {
		global $wpdb;

		$a    = vh_table( 'assets' );
		$rows = (array) $wpdb->get_results(
			"SELECT defender_coverage_state AS state, COUNT(*) AS n FROM {$a} GROUP BY defender_coverage_state", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			ARRAY_A
		);

		$states = array_fill_keys( array_keys( self::states() ), 0 );

		foreach ( $rows as $row ) {
			$state = (string) $row['state'];

			if ( isset( $states[ $state ] ) ) {
				$states[ $state ] = (int) $row['n'];
			}
		}

		$in_scope = array_sum( $states ) - $states[ self::OUT_OF_SCOPE ] - $states[ self::OTHER_DEVICE ];
		$quiet    = $states[ self::SILENT ] + $states[ self::NEVER_REPORTED ];
		$covered  = $states[ self::ONBOARDED ] + $quiet;

		return array(
			'states'      => $states,
			'in_scope'    => $in_scope,
			'excluded'    => $states[ self::OUT_OF_SCOPE ] + $states[ self::OTHER_DEVICE ],
			'retired'     => $states[ self::OUT_OF_SCOPE ],
			'other_kit'   => $states[ self::OTHER_DEVICE ],
			'covered'     => $covered,
			'reporting'   => $states[ self::ONBOARDED ],
			'quiet'       => $quiet,
			'gaps'        => max( 0, $in_scope - $covered ),
			'percent'     => $in_scope > 0 ? round( 100 * $covered / $in_scope, 1 ) : 0.0,
			'window_days' => self::window_days(),
		);
	}

	/**
	 * Endpoint coverage broken down by one of `Coverage::dimensions()`.
	 *
	 * Same shape as `Coverage::by_dimension()` so a chart can render either
	 * without knowing which feed it is looking at.
	 *
	 * @param string $dimension One of Coverage::dimensions().
	 * @param int    $limit     Rows to return.
	 * @return array<int,array<string,mixed>>
	 */
	public static function by_dimension( string $dimension = 'asset_type', int $limit = 12 ): array {
		global $wpdb;

		$dims = Coverage::dimensions();
		$dim  = $dims[ $dimension ] ?? $dims['asset_type'];
		$a    = vh_table( 'assets' );

		$join = '';

		if ( 'teams' === $dim['join'] ) {
			$join = ' LEFT JOIN ' . vh_table( 'teams' ) . ' t ON t.id = a.team_id';
		} elseif ( 'locations' === $dim['join'] ) {
			$join = ' LEFT JOIN ' . vh_table( 'locations' ) . ' l ON l.id = a.location_id';
		}

		$col   = $dim['column'];
		$key   = (string) ( $dim['key'] ?? $col );
		$limit = max( 1, min( 50, $limit ) );

		$rows = (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT COALESCE({$col}, %s) AS label,
					MIN({$key}) AS slice_key,
					COUNT(*) AS total,
					SUM(a.defender_coverage_state = %s) AS onboarded,
					SUM(a.defender_coverage_state = %s) AS silent,
					SUM(a.defender_coverage_state = %s) AS never_reported,
					SUM(a.defender_coverage_state = %s) AS not_onboarded,
					SUM(a.defender_coverage_state = %s) AS not_in_defender,
					SUM(a.defender_coverage_state = %s) AS no_contact,
					SUM(a.defender_coverage_state = %s) AS other_device,
					SUM(a.defender_coverage_state = %s) AS out_of_scope
				 FROM {$a} a{$join}
				 GROUP BY label
				 ORDER BY total DESC
				 LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				__( 'Unclassified', 'vulnhub' ),
				self::ONBOARDED,
				self::SILENT,
				self::NEVER_REPORTED,
				self::NOT_ONBOARDED,
				self::NOT_IN_DEFENDER,
				self::NO_CONTACT,
				self::OTHER_DEVICE,
				self::OUT_OF_SCOPE,
				$limit
			),
			ARRAY_A
		);

		return array_map(
			static function ( array $row ) use ( $dim ): array {
				$total     = (int) $row['total'];
				$oos       = (int) $row['out_of_scope'];
				$in_scope  = max( 0, $total - $oos );
				$reporting = (int) $row['onboarded'];
				$quiet     = (int) $row['silent'] + (int) $row['never_reported'];
				$covered   = $reporting + $quiet;
				$key       = (string) ( $row['slice_key'] ?? '' );

				if ( ( '' === $key || '0' === $key ) && '' !== (string) ( $dim['empty'] ?? '' ) ) {
					$key = (string) $dim['empty'];
				}

				return array(
					'label'     => (string) $row['label'],
					'filter'    => (string) ( $dim['filter'] ?? '' ),
					'key'       => $key,
					'total'     => $in_scope,
					'known'     => $total,
					'covered'   => $covered,
					'scanned'   => $reporting,
					'unscanned' => $quiet,
					'oos'       => $oos,
					'gaps'      => max( 0, $in_scope - $covered ),
					'percent'   => $in_scope > 0 ? round( 100 * $covered / $in_scope, 1 ) : 0.0,
					'states'    => array(
						self::ONBOARDED       => $covered,
						self::SILENT          => (int) $row['silent'],
						self::NEVER_REPORTED  => (int) $row['never_reported'],
						self::NOT_ONBOARDED   => (int) $row['not_onboarded'],
						self::NOT_IN_DEFENDER => (int) $row['not_in_defender'],
						self::NO_CONTACT      => (int) $row['no_contact'],
						self::OTHER_DEVICE    => (int) $row['other_device'],
						self::OUT_OF_SCOPE    => $oos,
					),
				);
			},
			$rows
		);
	}

	/**
	 * Endpoint coverage per source system.
	 *
	 * The counterpart of `Coverage::by_source()`, and the row a reader
	 * actually wants: "of the machines the CMDB says exist, how many have a
	 * Defender sensor". Assets overlap between rows on purpose -- one machine
	 * three systems know is counted once under each of them.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function by_source(): array {
		global $wpdb;

		$a   = vh_table( 'assets' );
		$out = array();

		foreach ( vh_asset_sources() as $slug => $label ) {
			$like = '%' . $wpdb->esc_like( '"' . $slug . '"' ) . '%';

			$row = $wpdb->get_row(
				$wpdb->prepare(
					"SELECT COUNT(*) AS total,
						SUM(a.defender_coverage_state = %s) AS onboarded,
						SUM(a.defender_coverage_state = %s) AS silent,
						SUM(a.defender_coverage_state = %s) AS never_reported,
						SUM(a.defender_coverage_state IN (%s, %s)) AS out_of_scope,
						SUM(a.sources_json NOT LIKE %s) AS sole
					 FROM {$a} a
					 WHERE a.sources_json LIKE %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					self::ONBOARDED,
					self::SILENT,
					self::NEVER_REPORTED,
					self::OUT_OF_SCOPE,
					self::OTHER_DEVICE,
					'%,%',
					$like
				),
				ARRAY_A
			);

			$total = (int) ( $row['total'] ?? 0 );

			if ( ! $total ) {
				continue;
			}

			$oos       = (int) ( $row['out_of_scope'] ?? 0 );
			$reporting = (int) ( $row['onboarded'] ?? 0 );
			$quiet     = (int) ( $row['silent'] ?? 0 ) + (int) ( $row['never_reported'] ?? 0 );
			$covered   = $reporting + $quiet;
			$in_scope  = max( 0, $total - $oos );

			$out[] = array(
				'label'     => (string) $label,
				'slug'      => (string) $slug,
				'filter'    => 'known',
				'key'       => (string) $slug,
				'total'     => $in_scope,
				'known'     => $total,
				'covered'   => $covered,
				'scanned'   => $reporting,
				'unscanned' => $quiet,
				'oos'       => $oos,
				'sole'      => (int) ( $row['sole'] ?? 0 ),
				'gaps'      => max( 0, $in_scope - $covered ),
				'percent'   => $in_scope > 0 ? round( 100 * $covered / $in_scope, 1 ) : 0.0,
			);
		}

		return $out;
	}

	/**
	 * The endpoint gap list: in-scope assets with no Defender sensor.
	 *
	 * @param array<string,mixed> $args state, asset_type, team_id, search, limit, offset.
	 * @return array{rows:array<int,array<string,mixed>>,total:int}
	 */
	public static function gaps( array $args = array() ): array {
		global $wpdb;

		$a      = vh_table( 'assets' );
		$t      = vh_table( 'teams' );
		$p      = vh_table( 'people' );
		$where  = array();
		$params = array();

		$state = (string) ( $args['state'] ?? '' );

		if ( '' !== $state && array_key_exists( $state, self::states() ) ) {
			$where[]  = 'a.defender_coverage_state = %s';
			$params[] = $state;
		} else {
			$where[] = 'a.defender_coverage_state IN (' . implode(
				',',
				array_map( static fn( string $s ): string => "'" . esc_sql( $s ) . "'", self::gap_states() )
			) . ')';
		}

		if ( ! empty( $args['asset_type'] ) ) {
			$where[]  = 'a.asset_type = %s';
			$params[] = (string) $args['asset_type'];
		}
		if ( ! empty( $args['team_id'] ) ) {
			$where[]  = 'a.team_id = %d';
			$params[] = (int) $args['team_id'];
		}
		if ( ! empty( $args['search'] ) ) {
			$like     = '%' . $wpdb->esc_like( (string) $args['search'] ) . '%';
			$where[]  = '(a.hostname LIKE %s OR a.fqdn LIKE %s OR a.ipv4 LIKE %s)';
			array_push( $params, $like, $like, $like );
		}
		/*
		 * Restrict the population to the machines one system vouches for.
		 *
		 * The CMDB is the register of what is *supposed* to exist, so "of the
		 * assets the CMDB knows, which has no scan" is a question somebody
		 * can act on: every row has a CI, an owner and a service behind it.
		 * The unrestricted list mixes that with devices only a discovery
		 * sweep has ever seen, which is a different job for a different team.
		 */
		if ( ! empty( $args['source'] ) ) {
			$where[]  = 'a.sources_json LIKE %s';
			$params[] = '%' . $wpdb->esc_like( '"' . vh_normalise_source( (string) $args['source'] ) . '"' ) . '%';
		}

		$sql    = implode( ' AND ', $where );
		$limit  = max( 1, min( 200, (int) ( $args['limit'] ?? 50 ) ) );
		$offset = max( 0, (int) ( $args['offset'] ?? 0 ) );

		$count_sql = "SELECT COUNT(*) FROM {$a} a WHERE {$sql}";
		$total     = (int) ( $params
			? $wpdb->get_var( $wpdb->prepare( $count_sql, $params ) ) // phpcs:ignore WordPress.DB.PreparedSQL
			: $wpdb->get_var( $count_sql ) ); // phpcs:ignore WordPress.DB.PreparedSQL

		$rows_sql = "SELECT a.*, t.name AS team_name, p.display_name AS owner_name
			 FROM {$a} a
			 LEFT JOIN {$t} t ON t.id = a.team_id
			 LEFT JOIN {$p} p ON p.id = a.owner_person_id
			 WHERE {$sql}
			 ORDER BY FIELD(a.criticality,'critical','high','medium','low'), a.hostname
			 LIMIT %d OFFSET %d";

		$rows = (array) $wpdb->get_results(
			$wpdb->prepare( $rows_sql, array_merge( $params, array( $limit, $offset ) ) ), // phpcs:ignore WordPress.DB.PreparedSQL
			ARRAY_A
		);

		return array(
			'rows'  => $rows,
			'total' => $total,
		);
	}
}
