<?php
/**
 * Reading the programme: coverage, rows and summaries.
 *
 * The one question this answers is the one the widget asks: for these assets,
 * which have a funded project with a date that has not passed, and which do
 * not. Everything else here exists to make that answer explorable.
 *
 * Coverage is computed at READ time, not stored. A plan whose quarter passes
 * overnight becomes overdue overnight, without anyone re-importing the
 * workbook -- which is the whole point of showing it.
 *
 * @package VulnHub\EOS
 */

declare( strict_types = 1 );

use VulnHub\Core\Eol;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Queries over the EOS plan table.
 */
final class VH_EOS_Repo {

	/**
	 * First month of the financial year.
	 *
	 * FY26 runs 1 April 2025 to 31 March 2026, which is the New Zealand
	 * convention this programme's workbook uses: its "FY26 Q3" rows are dated
	 * against Oct-Dec 2025. If the organisation's FY ever moves, this constant
	 * and nothing else needs to change.
	 */
	public const FY_START_MONTH = 4;

	/** Coverage buckets. `overdue` is a red, kept separate so it can say why. */
	public const COVERED   = 'covered';
	public const OVERDUE   = 'overdue';
	public const UNCOVERED = 'uncovered';

	/*
	 * A filter value, not a state a row can hold: everything the dashboard's
	 * red band counts, which is the overdue together with the never-planned.
	 * The bar shows two colours, so the list behind red has to answer with
	 * both -- otherwise the page contradicts the number that opened it.
	 */
	public const NOT_COVERED = 'not_covered';

	/** Plan states, as stored. */
	public const STATES = array( 'in_support', 'remediated', 'planned', 'no_plan', 'visibility_gap' );

	/**
	 * Ceiling on how many rows a single page query will assemble in PHP.
	 *
	 * The EOL universe is small by nature (the assets running a release that
	 * has run out), but "small by nature" is not a guarantee, and this merges
	 * two result sets before paging them.
	 */
	private const MAX_ROWS = 5000;

	/* =================================================================
	 * Vocabulary
	 * ============================================================== */

	/**
	 * Human labels for the stored states.
	 *
	 * @return array<string,string>
	 */
	public static function state_labels(): array {
		return array(
			'in_support'     => __( 'In support', 'vulnhub' ),
			'remediated'     => __( 'Remediated', 'vulnhub' ),
			'planned'        => __( 'Planned', 'vulnhub' ),
			'no_plan'        => __( 'No plan', 'vulnhub' ),
			'visibility_gap' => __( 'Visibility gap', 'vulnhub' ),
		);
	}

	public static function state_label( string $state ): string {
		$labels = self::state_labels();

		return (string) ( $labels[ $state ] ?? __( 'Not in the programme', 'vulnhub' ) );
	}

	/**
	 * Human labels for the coverage buckets.
	 *
	 * @return array<string,string>
	 */
	public static function coverage_labels(): array {
		return array(
			self::COVERED   => __( 'Covered by a project', 'vulnhub' ),
			self::OVERDUE   => __( 'Past its planned date', 'vulnhub' ),
			self::UNCOVERED => __( 'Not covered', 'vulnhub' ),
		);
	}

	/**
	 * Filter values a caller may ask for: the three states a row can hold,
	 * plus the combined NOT_COVERED the dashboard's red band uses.
	 *
	 * @return array<string,string>
	 */
	public static function coverage_filters(): array {
		return self::coverage_labels() + array(
			self::NOT_COVERED => __( 'Not covered (including overdue)', 'vulnhub' ),
		);
	}

	/**
	 * Predicate for one coverage filter value.
	 *
	 * NOT_COVERED spans two row states; everything else is an exact match.
	 * An unknown value matches nothing rather than everything, so a typo in a
	 * URL shows an empty list instead of quietly dropping the filter.
	 *
	 * @param string $want Coverage filter value.
	 * @return callable(array<string,mixed>):bool
	 */
	public static function coverage_matcher( string $want ): callable {
		if ( self::NOT_COVERED === $want ) {
			return static fn( array $r ): bool => in_array(
				(string) $r['coverage'],
				array( self::OVERDUE, self::UNCOVERED ),
				true
			);
		}

		return static fn( array $r ): bool => (string) $r['coverage'] === $want;
	}

	public static function coverage_label( string $coverage ): string {
		$labels = self::coverage_labels();

		return (string) ( $labels[ $coverage ] ?? $labels[ self::UNCOVERED ] );
	}

	/* =================================================================
	 * Timeframes
	 * ============================================================== */

	/**
	 * The last day of the timeframe a plan row names, or null when it names
	 * none ("TBD", blank, or anything this cannot read).
	 *
	 * Accepts "FY27", "FY26 Q3", "FY26Q3" and "FY 26 Q3". A year alone means
	 * the end of that financial year, which is the most generous reading and
	 * therefore the one least likely to call something overdue unfairly.
	 */
	public static function deadline_for( string $timeframe ): ?string {
		$tf = strtoupper( trim( $timeframe ) );

		if ( '' === $tf || 'TBD' === $tf ) {
			return null;
		}

		if ( ! preg_match( '/^FY\s?(\d{2}|\d{4})(?:\s*Q([1-4]))?$/', $tf, $m ) ) {
			return null;
		}

		$year = (int) $m[1];
		$year = $year < 100 ? 2000 + $year : $year;

		// FY26 starts in the calendar year before it: April 2025.
		$start_year = $year - 1;

		if ( empty( $m[2] ) ) {
			// The FY ends the day before it started, a year on.
			$end = new DateTimeImmutable( sprintf( '%04d-%02d-01', $year, self::FY_START_MONTH ) );

			return $end->modify( '-1 day' )->format( 'Y-m-d' );
		}

		$quarter = (int) $m[2];

		// Quarter 1 begins at the FY start; each quarter is three months.
		$begins = ( new DateTimeImmutable( sprintf( '%04d-%02d-01', $start_year, self::FY_START_MONTH ) ) )
			->modify( sprintf( '+%d months', ( $quarter - 1 ) * 3 ) );

		return $begins->modify( '+3 months' )->modify( '-1 day' )->format( 'Y-m-d' );
	}

	/**
	 * The label a deadline belongs under on the forward-workload chart.
	 * Falls back to the raw timeframe so "TBD" stays "TBD".
	 */
	public static function quarter_label( string $timeframe, ?string $deadline ): string {
		$tf = strtoupper( trim( $timeframe ) );

		if ( '' === $tf ) {
			return __( 'No timeframe', 'vulnhub' );
		}

		if ( 'TBD' === $tf ) {
			return __( 'TBD', 'vulnhub' );
		}

		unset( $deadline );

		return $tf;
	}

	/* =================================================================
	 * End-of-life populations
	 * ============================================================== */

	/**
	 * The assets whose operating-system release is past end of life, or ends
	 * within six months -- the two populations the widget's headline tiles
	 * count, so that clicking a tile lands on exactly that many rows.
	 *
	 * `past` is core's own list, used rather than recomputed: if the two ever
	 * disagreed, the tile and this screen would disagree, which is the whole
	 * thing this method exists to prevent. There is no core equivalent for
	 * `soon`, so it is derived here with the same two calls core uses
	 * (match the release, read its status) in a single pass.
	 *
	 * Memoised per status: the tiles, the chart and the table all ask within
	 * one request, and the answer cannot change between them.
	 *
	 * @param string $status past|soon.
	 * @return array<int,int> Asset ids.
	 */
	private static function eol_status_ids( string $status ): array {
		static $cache = array();

		if ( isset( $cache[ $status ] ) ) {
			return $cache[ $status ];
		}

		if ( 'past' === $status ) {
			$cache[ $status ] = array_map( 'intval', Eol::eol_os_asset_ids() );

			return $cache[ $status ];
		}

		if ( 'soon' !== $status ) {
			$cache[ $status ] = array();

			return $cache[ $status ];
		}

		global $wpdb;

		$assets = (array) $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			'SELECT id, operating_system, os_version, asset_type FROM ' . vh_table( 'assets' )
			. ' WHERE lifecycle_status IN (' . vh_reportable_sql() . ')', // phpcs:ignore WordPress.DB.PreparedSQL
			ARRAY_A
		);

		$out = array();

		foreach ( $assets as $asset ) {
			$matched = Eol::match_os( $asset );

			if ( $matched && 'soon' === Eol::status( (string) $matched['eol'] )['status'] ) {
				$out[] = (int) $asset['id'];
			}
		}

		$cache[ $status ] = $out;

		return $out;
	}

	/* =================================================================
	 * Coverage
	 * ============================================================== */

	/**
	 * Which bucket one plan row falls in.
	 *
	 * @param array<string,mixed>|null $row  Plan row, or null when the asset
	 *                                       has none.
	 * @param string                   $today Y-m-d, injectable for tests.
	 */
	public static function coverage_for_row( ?array $row, string $today = '' ): string {
		if ( ! $row ) {
			return self::UNCOVERED;
		}

		$today = '' !== $today ? $today : current_time( 'Y-m-d' );
		$state = (string) ( $row['state'] ?? '' );

		/*
		 * `remediated` is done, and `in_support` never needed doing -- both are
		 * green. `in_support` on a machine the lifecycle table calls end of
		 * life is a contradiction between two sources rather than a risk state,
		 * and the plan screen shows the state itself beside the colour so that
		 * disagreement is visible rather than averaged away.
		 */
		if ( 'remediated' === $state || 'in_support' === $state ) {
			return self::COVERED;
		}

		if ( 'planned' !== $state ) {
			// no_plan, visibility_gap, or a state this does not know.
			return self::UNCOVERED;
		}

		$deadline = (string) ( $row['deadline'] ?? '' );

		if ( '' === $deadline || '0000-00-00' === $deadline ) {
			// Planned in name only: no date to hold anyone to.
			return self::UNCOVERED;
		}

		return $deadline >= $today ? self::COVERED : self::OVERDUE;
	}

	/* =================================================================
	 * The contract
	 * ============================================================== */

	/** Is there any programme data at all? */
	public static function has_data(): bool {
		global $wpdb;

		if ( ! VH_EOS_Schema::ready() ) {
			return false;
		}

		static $has = null;

		if ( null !== $has ) {
			return $has;
		}

		$has = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . VH_EOS_Schema::table() ) > 0; // phpcs:ignore WordPress.DB

		return $has;
	}

	/**
	 * Plan detail for the given assets, keyed by asset id.
	 *
	 * Only assets that HAVE a plan row appear. Callers that need "everything
	 * else is uncovered" should use coverage_counts(), which says so.
	 *
	 * @param array<int,int> $asset_ids Asset ids.
	 * @return array<int,array<string,mixed>>
	 */
	public static function coverage_for_assets( array $asset_ids ): array {
		global $wpdb;

		$ids = array_values( array_unique( array_filter( array_map( 'intval', $asset_ids ) ) ) );

		if ( ! $ids || ! VH_EOS_Schema::ready() ) {
			return array();
		}

		$table = VH_EOS_Schema::table();
		$in    = implode( ',', $ids );

		$rows = (array) $wpdb->get_results( // phpcs:ignore WordPress.DB
			"SELECT asset_id, hostname, state, project, timeframe, deadline, rag, env_tier, environment, purpose, notes
			 FROM {$table}
			 WHERE asset_id IN ( {$in} )", // phpcs:ignore WordPress.DB
			ARRAY_A
		);

		$out = array();

		foreach ( $rows as $row ) {
			$row['coverage']       = self::coverage_for_row( $row );
			$row['coverage_label'] = self::coverage_label( (string) $row['coverage'] );
			$row['state_label']    = self::state_label( (string) $row['state'] );

			$out[ (int) $row['asset_id'] ] = $row;
		}

		return $out;
	}

	/**
	 * Covered / overdue / uncovered across a set of assets.
	 *
	 * An asset with no plan row counts as uncovered -- that is the honest
	 * reading, and it is the number the widget's red segment exists to show.
	 * Counting only the assessed rows would flatter the estate by leaving the
	 * unknown out of the denominator entirely.
	 *
	 * @param array<int,int> $asset_ids Asset ids.
	 * @return array{covered:int,overdue:int,uncovered:int,total:int,planned_rows:int}
	 */
	public static function coverage_counts( array $asset_ids ): array {
		$ids = array_values( array_unique( array_filter( array_map( 'intval', $asset_ids ) ) ) );

		$out = array(
			'covered'      => 0,
			'overdue'      => 0,
			'uncovered'    => 0,
			'total'        => count( $ids ),
			'planned_rows' => 0,
		);

		if ( ! $ids ) {
			return $out;
		}

		$plans = self::coverage_for_assets( $ids );

		foreach ( $ids as $id ) {
			$plan = $plans[ $id ] ?? null;

			if ( $plan ) {
				++$out['planned_rows'];
			}

			++$out[ self::coverage_for_row( $plan ) ];
		}

		return $out;
	}

	/* =================================================================
	 * Rows for the plan screen
	 * ============================================================== */

	/**
	 * Plan rows joined to their asset, filtered and paged.
	 *
	 * With `include_unplanned` the result also carries the end-of-life assets
	 * that have NO plan row, as rows whose state is empty and whose coverage is
	 * `uncovered`. Those machines are the point of the screen: a plan you have
	 * not written is not visible anywhere else.
	 *
	 * @param array<string,mixed> $args coverage, state, timeframe, env_tier,
	 *                                  rag, project, release_key, search,
	 *                                  team_id, location_id, life,
	 *                                  include_unplanned, orderby, order,
	 *                                  limit, offset.
	 * @return array{rows:array<int,array<string,mixed>>,total:int,counts:array<string,int>}
	 */
	public static function rows( array $args = array() ): array {
		$args = wp_parse_args(
			$args,
			array(
				'coverage'          => '',
				'state'             => '',
				'timeframe'         => '',
				'env_tier'          => '',
				'rag'               => '',
				'project'           => '',
				'release_key'       => '',
				'eol_status'        => '',
				'search'            => '',
				'team_id'           => 0,
				'location_id'       => 0,
				'life'              => '',
				'include_unplanned' => true,
				'orderby'           => 'hostname',
				'order'             => 'ASC',
				'limit'             => 50,
				'offset'            => 0,
			)
		);

		$all = self::assemble( $args );

		$counts = array(
			self::COVERED   => 0,
			self::OVERDUE   => 0,
			self::UNCOVERED => 0,
		);

		foreach ( $all as $row ) {
			++$counts[ (string) $row['coverage'] ];
		}

		$all = self::sort_rows( $all, (string) $args['orderby'], (string) $args['order'] );

		$total  = count( $all );
		$limit  = max( 0, (int) $args['limit'] );
		$offset = max( 0, (int) $args['offset'] );
		$page   = $limit > 0 ? array_slice( $all, $offset, $limit ) : array_slice( $all, $offset );

		return array(
			'rows'   => array_values( $page ),
			'total'  => $total,
			'counts' => $counts,
		);
	}

	/**
	 * Every matching row, unsorted and unpaged: plan rows, plus the unplanned
	 * end-of-life assets when asked for.
	 *
	 * @param array<string,mixed> $args Normalised args from rows().
	 * @return array<int,array<string,mixed>>
	 */
	private static function assemble( array $args ): array {
		global $wpdb;

		if ( ! VH_EOS_Schema::ready() ) {
			return array();
		}

		$table  = VH_EOS_Schema::table();
		$a      = vh_table( 'assets' );
		$t      = vh_table( 'teams' );
		$l      = vh_table( 'locations' );
		$people = vh_table( 'people' );

		$where  = array( '1=1' );
		$params = array();

		/*
		 * A release key limits both halves of the screen to the assets behind
		 * one bar of the widget, which is what makes a segment clickable.
		 */
		$release_ids = null;

		if ( '' !== (string) $args['release_key'] ) {
			$release_ids = array_map( 'intval', Eol::asset_ids( (string) $args['release_key'] ) );
		}

		/*
		 * `eol_status` restricts the screen to assets whose RELEASE is past
		 * end of life (or ends within six months), which is what the widget's
		 * headline tiles count. It intersects with a release key rather than
		 * replacing it, so the two compose, and it is what makes the tile's
		 * number and this screen's row count the same number.
		 *
		 * Note what it excludes: a programme host with no asset in the
		 * inventory has no release to be past the end of, so it drops out.
		 * That is the point -- the tile counts machines VulnHub can see.
		 */
		if ( '' !== (string) $args['eol_status'] ) {
			$eol_ids = self::eol_status_ids( (string) $args['eol_status'] );

			$release_ids = null === $release_ids
				? $eol_ids
				: array_values( array_intersect( $release_ids, $eol_ids ) );
		}

		if ( null !== $release_ids ) {
			$where[] = $release_ids
				? 'p.asset_id IN ( ' . implode( ',', $release_ids ) . ' )'
				: '1=0';
		}

		foreach ( array( 'state' => 'state', 'env_tier' => 'env_tier', 'rag' => 'rag', 'timeframe' => 'timeframe', 'project' => 'project' ) as $arg => $column ) {
			if ( '' !== (string) $args[ $arg ] ) {
				$where[]  = "p.{$column} = %s";
				$params[] = (string) $args[ $arg ];
			}
		}

		if ( (int) $args['team_id'] > 0 ) {
			$where[]  = 'a.team_id = %d';
			$params[] = (int) $args['team_id'];
		}

		// The Owner filter: whether the asset has a named owner.
		$owner_filter = vh_owner_filter( $args['owner'] ?? '' );
		if ( '' !== $owner_filter ) {
			$where[] = 'has' === $owner_filter ? 'a.owner_person_id > 0' : 'a.owner_person_id = 0';
		}

		if ( (int) $args['location_id'] > 0 ) {
			$where[]  = 'a.location_id = %d';
			$params[] = (int) $args['location_id'];
		}

		if ( '' !== (string) $args['search'] ) {
			$like     = '%' . $wpdb->esc_like( (string) $args['search'] ) . '%';
			$where[]  = '( p.hostname LIKE %s OR p.project LIKE %s OR p.purpose LIKE %s OR p.os_text LIKE %s OR a.hostname LIKE %s )';
			$params[] = $like;
			$params[] = $like;
			$params[] = $like;
			$params[] = $like;
			$params[] = $like;
		}

		/*
		 * LEFT JOIN, not INNER: a third of the programme's hosts have no asset
		 * in VulnHub, and dropping them here would quietly shrink the
		 * programme to whatever the scanner happens to see.
		 */
		$sql = "SELECT p.*,
				a.id AS asset_id_join, a.hostname AS asset_hostname, a.operating_system, a.os_version,
				a.asset_type, a.lifecycle_status, a.coverage_state, a.criticality, a.environment AS asset_environment,
				a.tenable_last_scan, a.open_critical, a.open_high, a.open_medium, a.open_low, a.risk_score,
				a.team_id, a.location_id, a.owner_person_id,
				t.name AS team_name, l.name AS site_name,
				per.display_name AS owner_name, per.email AS owner_email
			FROM {$table} p
			LEFT JOIN {$a} a ON a.id = p.asset_id
			LEFT JOIN {$t} t ON t.id = a.team_id
			LEFT JOIN {$l} l ON l.id = a.location_id
			LEFT JOIN {$people} per ON per.id = a.owner_person_id
			WHERE " . implode( ' AND ', $where ) . '
			LIMIT ' . self::MAX_ROWS;

		$prepared = $params ? $wpdb->prepare( $sql, $params ) : $sql; // phpcs:ignore WordPress.DB
		$plan     = (array) $wpdb->get_results( $prepared, ARRAY_A ); // phpcs:ignore WordPress.DB

		$out   = array();
		$seen  = array();
		$today = current_time( 'Y-m-d' );

		foreach ( $plan as $row ) {
			$row['in_programme'] = true;
			$row['coverage']     = self::coverage_for_row( $row, $today );
			$row                 = self::decorate( $row );

			$seen[ strtolower( (string) $row['hostname'] ) ] = true;

			if ( (int) $row['asset_id'] > 0 ) {
				$seen[ 'id:' . (int) $row['asset_id'] ] = true;
			}

			$out[] = $row;
		}

		if ( ! empty( $args['include_unplanned'] ) ) {
			$out = array_merge( $out, self::unplanned_rows( $args, $seen, $release_ids ) );
		}

		// Coverage filter applies to both halves, so it runs after the merge.
		if ( '' !== (string) $args['coverage'] ) {
			$want  = (string) $args['coverage'];
			$match = self::coverage_matcher( $want );
			$out   = array_values( array_filter( $out, $match ) );
		}

		return $out;
	}

	/**
	 * End-of-life assets with no plan row at all.
	 *
	 * @param array<string,mixed>  $args        Normalised args.
	 * @param array<string,bool>   $seen        Hostnames/ids already returned.
	 * @param array<int,int>|null  $release_ids The assets the screen is limited to: one release, one
	 *                                          end-of-life population, or the intersection of both.
	 *                                          Null when neither filter is set.
	 * @return array<int,array<string,mixed>>
	 */
	private static function unplanned_rows( array $args, array $seen, ?array $release_ids ): array {
		global $wpdb;

		/*
		 * Anything that names a plan attribute cannot match a machine with no
		 * plan, so this half is skipped rather than searched.
		 */
		foreach ( array( 'state', 'env_tier', 'rag', 'timeframe', 'project' ) as $arg ) {
			if ( '' !== (string) $args[ $arg ] ) {
				return array();
			}
		}

		/*
		 * A machine with no plan row is `uncovered`, so it belongs in an
		 * `uncovered` list and in the combined `not_covered` one -- and in no
		 * other. NOT_COVERED is the value the dashboard's red band links to,
		 * and leaving it out here is what made that band open an empty list.
		 */
		if ( '' !== (string) $args['coverage']
			&& ! in_array( (string) $args['coverage'], array( self::UNCOVERED, self::NOT_COVERED ), true ) ) {
			return array();
		}

		$ids = null === $release_ids
			? array_map( 'intval', Eol::eol_os_asset_ids() )
			: $release_ids;

		$ids = array_values(
			array_filter(
				$ids,
				static fn( int $id ): bool => $id > 0 && empty( $seen[ 'id:' . $id ] )
			)
		);

		if ( ! $ids ) {
			return array();
		}

		$a      = vh_table( 'assets' );
		$t      = vh_table( 'teams' );
		$l      = vh_table( 'locations' );
		$people = vh_table( 'people' );

		$where  = array( 'a.id IN ( ' . implode( ',', array_slice( $ids, 0, self::MAX_ROWS ) ) . ' )' );
		$params = array();

		if ( (int) $args['team_id'] > 0 ) {
			$where[]  = 'a.team_id = %d';
			$params[] = (int) $args['team_id'];
		}

		// The Owner filter: whether the asset has a named owner.
		$owner_filter = vh_owner_filter( $args['owner'] ?? '' );
		if ( '' !== $owner_filter ) {
			$where[] = 'has' === $owner_filter ? 'a.owner_person_id > 0' : 'a.owner_person_id = 0';
		}

		if ( (int) $args['location_id'] > 0 ) {
			$where[]  = 'a.location_id = %d';
			$params[] = (int) $args['location_id'];
		}

		if ( '' !== (string) $args['search'] ) {
			$like     = '%' . $wpdb->esc_like( (string) $args['search'] ) . '%';
			$where[]  = '( a.hostname LIKE %s OR a.operating_system LIKE %s )';
			$params[] = $like;
			$params[] = $like;
		}

		$sql = "SELECT a.id AS asset_id, a.hostname, a.operating_system, a.os_version, a.asset_type,
				a.lifecycle_status, a.coverage_state, a.criticality, a.environment AS asset_environment,
				a.tenable_last_scan, a.open_critical, a.open_high, a.open_medium, a.open_low, a.risk_score,
				a.team_id, a.location_id, a.owner_person_id,
				t.name AS team_name, l.name AS site_name,
				per.display_name AS owner_name, per.email AS owner_email
			FROM {$a} a
			LEFT JOIN {$t} t ON t.id = a.team_id
			LEFT JOIN {$l} l ON l.id = a.location_id
			LEFT JOIN {$people} per ON per.id = a.owner_person_id
			WHERE " . implode( ' AND ', $where ) . '
			LIMIT ' . self::MAX_ROWS;

		$prepared = $params ? $wpdb->prepare( $sql, $params ) : $sql; // phpcs:ignore WordPress.DB
		$rows     = (array) $wpdb->get_results( $prepared, ARRAY_A ); // phpcs:ignore WordPress.DB

		$out = array();

		foreach ( $rows as $row ) {
			if ( ! empty( $seen[ strtolower( (string) $row['hostname'] ) ] ) ) {
				continue;
			}

			$row['in_programme'] = false;
			$row['state']        = '';
			$row['project']      = '';
			$row['timeframe']    = '';
			$row['deadline']     = null;
			$row['rag']          = '';
			$row['env_tier']     = '';
			$row['environment']  = (string) ( $row['asset_environment'] ?? '' );
			$row['purpose']      = '';
			$row['os_text']      = (string) ( $row['operating_system'] ?? '' );
			$row['notes']        = '';
			$row['coverage']     = self::UNCOVERED;

			$out[] = self::decorate( $row );
		}

		return $out;
	}

	/**
	 * Labels and derived fields every consumer would otherwise recompute.
	 *
	 * @param array<string,mixed> $row Row.
	 * @return array<string,mixed>
	 */
	private static function decorate( array $row ): array {
		$row['asset_id']       = (int) ( $row['asset_id'] ?? 0 );
		$row['hostname']       = (string) ( $row['hostname'] ?? '' );
		$row['coverage_label'] = self::coverage_label( (string) $row['coverage'] );
		$row['state_label']    = self::state_label( (string) ( $row['state'] ?? '' ) );
		$row['quarter']        = self::quarter_label( (string) ( $row['timeframe'] ?? '' ), $row['deadline'] ?? null );
		$row['has_asset']      = (int) $row['asset_id'] > 0;
		$row['open_total']     = (int) ( $row['open_critical'] ?? 0 ) + (int) ( $row['open_high'] ?? 0 )
			+ (int) ( $row['open_medium'] ?? 0 ) + (int) ( $row['open_low'] ?? 0 );

		$row['is_overdue'] = self::OVERDUE === (string) $row['coverage'];

		/*
		 * Days late is the number people act on -- "three quarters late" is a
		 * different conversation from "a fortnight late" -- and it is only
		 * meaningful once the date has actually passed.
		 */
		$row['days_late'] = 0;

		if ( $row['is_overdue'] && ! empty( $row['deadline'] ) ) {
			$deadline = strtotime( (string) $row['deadline'] . ' 00:00:00' );
			$today    = strtotime( current_time( 'Y-m-d' ) . ' 00:00:00' );

			if ( $deadline && $today ) {
				$row['days_late'] = max( 0, (int) floor( ( $today - $deadline ) / DAY_IN_SECONDS ) );
			}
		}

		return $row;
	}

	/**
	 * Sort the merged set.
	 *
	 * @param array<int,array<string,mixed>> $rows    Rows.
	 * @param string                         $orderby Column.
	 * @param string                         $order   ASC|DESC.
	 * @return array<int,array<string,mixed>>
	 */
	private static function sort_rows( array $rows, string $orderby, string $order ): array {
		$dir = 'DESC' === strtoupper( $order ) ? -1 : 1;

		/*
		 * Coverage sorts by severity of the answer, not alphabetically:
		 * uncovered first, then overdue, then covered. Alphabetical would put
		 * "covered" at the top of a list whose reason for existing is the
		 * things that are not.
		 */
		$rank = array(
			self::UNCOVERED => 0,
			self::OVERDUE   => 1,
			self::COVERED   => 2,
		);

		$key = static function ( array $r ) use ( $orderby, $rank ) {
			switch ( $orderby ) {
				case 'coverage':
					return array( $rank[ (string) $r['coverage'] ] ?? 9, strtolower( (string) $r['hostname'] ) );
				case 'deadline':
					// No date sorts last in either direction: it is not a date.
					return array( empty( $r['deadline'] ) ? 1 : 0, (string) ( $r['deadline'] ?? '' ), strtolower( (string) $r['hostname'] ) );
				case 'project':
					return array( strtolower( (string) ( $r['project'] ?? '' ) ), strtolower( (string) $r['hostname'] ) );
				case 'state':
					return array( strtolower( (string) ( $r['state'] ?? '' ) ), strtolower( (string) $r['hostname'] ) );
				case 'exposure':
					return array( -1 * (int) $r['open_total'], strtolower( (string) $r['hostname'] ) );
				case 'team':
					return array( strtolower( (string) ( $r['team_name'] ?? '' ) ), strtolower( (string) $r['hostname'] ) );
				case 'os':
					return array( strtolower( (string) ( $r['os_text'] ?? $r['operating_system'] ?? '' ) ), strtolower( (string) $r['hostname'] ) );
				default:
					return array( strtolower( (string) $r['hostname'] ) );
			}
		};

		usort(
			$rows,
			static function ( array $x, array $y ) use ( $key, $dir ): int {
				return $dir * ( $key( $x ) <=> $key( $y ) );
			}
		);

		return $rows;
	}

	/* =================================================================
	 * Summary
	 * ============================================================== */

	/**
	 * Headline figures for the plan screen and the programme section.
	 *
	 * @param array<string,mixed> $args Same filter args as rows().
	 * @return array<string,mixed>
	 */
	public static function summary( array $args = array() ): array {
		$args['limit']  = 0;
		$args['offset'] = 0;

		$res  = self::rows( $args );
		$rows = $res['rows'];

		$by_quarter = array();
		$by_state   = array();
		$by_rag     = array();
		$projects   = array();

		foreach ( $rows as $row ) {
			$quarter = (string) $row['quarter'];
			$state   = (string) ( $row['state'] ?? '' );
			$rag     = (string) ( $row['rag'] ?? '' );

			$by_quarter[ $quarter ] = ( $by_quarter[ $quarter ] ?? 0 ) + 1;
			$by_state[ $state ]     = ( $by_state[ $state ] ?? 0 ) + 1;

			if ( '' !== $rag ) {
				$by_rag[ $rag ] = ( $by_rag[ $rag ] ?? 0 ) + 1;
			}

			if ( '' !== (string) ( $row['project'] ?? '' ) ) {
				$projects[ (string) $row['project'] ] = ( $projects[ (string) $row['project'] ] ?? 0 ) + 1;
			}
		}

		/*
		 * Quarters sort chronologically, with the two non-dates last. Sorting
		 * "FY26 Q3" as a string puts FY26 before FY27 correctly by luck, but
		 * puts "FY27" after "FY27 Q1", which reads as though the whole year
		 * comes after its own first quarter.
		 */
		uksort(
			$by_quarter,
			static function ( string $x, string $y ): int {
				$dx = self::deadline_for( $x );
				$dy = self::deadline_for( $y );

				if ( null === $dx && null === $dy ) {
					return strcmp( $x, $y );
				}
				if ( null === $dx ) {
					return 1;
				}
				if ( null === $dy ) {
					return -1;
				}

				return strcmp( $dx, $dy );
			}
		);

		arsort( $projects );

		return array(
			'covered'     => (int) $res['counts'][ self::COVERED ],
			'overdue'     => (int) $res['counts'][ self::OVERDUE ],
			'uncovered'   => (int) $res['counts'][ self::UNCOVERED ],
			'total'       => (int) $res['total'],
			'in_estate'   => count( array_filter( $rows, static fn( array $r ): bool => ! empty( $r['has_asset'] ) ) ),
			'by_quarter'  => $by_quarter,
			'by_state'    => $by_state,
			'by_rag'      => $by_rag,
			'projects'    => $projects,
			'last_import' => self::last_import(),
		);
	}

	/**
	 * When the programme data was last loaded, and what it carried.
	 *
	 * @return array<string,mixed>
	 */
	public static function last_import(): array {
		return (array) get_option( VH_EOS_Import::OPT_LAST, array() );
	}

	/**
	 * Distinct values for the plan screen's filter controls.
	 *
	 * @return array<string,array<int,string>>
	 */
	public static function filter_options(): array {
		global $wpdb;

		if ( ! VH_EOS_Schema::ready() ) {
			return array(
				'timeframe' => array(),
				'project'   => array(),
			);
		}

		$table = VH_EOS_Schema::table();

		$timeframes = array_map( 'strval', (array) $wpdb->get_col( "SELECT DISTINCT timeframe FROM {$table} WHERE timeframe <> '' ORDER BY timeframe" ) ); // phpcs:ignore WordPress.DB
		$projects   = array_map( 'strval', (array) $wpdb->get_col( "SELECT DISTINCT project FROM {$table} WHERE project <> '' ORDER BY project" ) ); // phpcs:ignore WordPress.DB

		usort(
			$timeframes,
			static function ( string $x, string $y ): int {
				$dx = self::deadline_for( $x );
				$dy = self::deadline_for( $y );

				if ( null === $dx && null === $dy ) {
					return strcmp( $x, $y );
				}
				if ( null === $dx ) {
					return 1;
				}
				if ( null === $dy ) {
					return -1;
				}

				return strcmp( $dx, $dy );
			}
		);

		return array(
			'timeframe' => $timeframes,
			'project'   => $projects,
		);
	}
}
