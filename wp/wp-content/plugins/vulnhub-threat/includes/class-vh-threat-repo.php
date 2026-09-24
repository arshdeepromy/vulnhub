<?php
/**
 * Counting findings by the route an attacker would take.
 *
 * Everything here works from id lists rather than joins. The findings table
 * holds 228,000 rows and the two tables this plugin adds hold 13,000 and 848;
 * asking the optimiser to filter findings on a column that lives in a small
 * table makes it walk findings doing a primary-key lookup per row. Resolving
 * the small tables first and handing over a list of ids turns every count into
 * an index range scan on `vuln_state_exc`, which already carries asset_id as
 * its last column -- so the edge lane's asset filter is answered from the
 * index too.
 *
 * @package VulnHub\Threat
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Lane counts and the drill-down filter behind them.
 */
final class VulnHub_Threat_Repo {

	public static function init(): void {
		add_filter( 'vulnhub_findings_query', array( __CLASS__, 'findings_query' ), 10, 2 );
	}

	/** Is there anything to draw yet? */
	public static function has_data(): bool {
		global $wpdb;

		$paths = VulnHub_Threat_Install::table( 'vuln_paths' );

		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$paths} WHERE has_poc = 1" ) > 0; // phpcs:ignore
	}

	/**
	 * Vulnerability definition ids on a route.
	 *
	 * @param string $route 'edge', 'user', 'inside' or '' for any.
	 * @param bool   $poc   Only definitions with a working exploit.
	 * @return int[]
	 */
	public static function vuln_ids( string $route, bool $poc = true ): array {
		global $wpdb;

		$paths  = VulnHub_Threat_Install::table( 'vuln_paths' );
		$column = $poc ? 'poc_route' : 'route';
		$where  = $poc ? array( 'has_poc = 1' ) : array();

		if ( '' !== $route ) {
			$where[] = $wpdb->prepare( "{$column} = %s", $route ); // phpcs:ignore
		}

		$sql = "SELECT vuln_id FROM {$paths}" . ( $where ? ' WHERE ' . implode( ' AND ', $where ) : '' );

		return array_map( 'intval', (array) $wpdb->get_col( $sql ) ); // phpcs:ignore
	}

	/**
	 * Definition ids on the user route, narrowed to one delivery channel.
	 *
	 * The three doors on the widget -- email, website, download -- are the same
	 * user-route population as {@see delivery_split()}, sliced by how it reaches
	 * a person. 'web' is the catch-all, so it is every user-route definition
	 * whose delivery is neither mail nor file; that keeps these three lists
	 * summing to exactly the counts the doors drew, even if a future row lands
	 * on the user route with an unrecognised delivery.
	 *
	 * @param string $channel 'mail', 'web' or 'file'.
	 * @param bool   $poc     Only definitions with a working exploit.
	 * @return int[]
	 */
	public static function delivery_ids( string $channel, bool $poc = true ): array {
		global $wpdb;

		$paths  = VulnHub_Threat_Install::table( 'vuln_paths' );
		$column = $poc ? 'poc_route' : 'route';
		$where  = array( "{$column} = 'user'" );

		if ( $poc ) {
			$where[] = 'has_poc = 1';
		}

		if ( 'mail' === $channel || 'file' === $channel ) {
			$where[] = $wpdb->prepare( 'delivery = %s', $channel ); // phpcs:ignore
		} else {
			// 'web' is the catch-all, matching the fold in delivery_split().
			$where[] = "( delivery NOT IN ('mail','file') OR delivery IS NULL )";
		}

		$sql = "SELECT vuln_id FROM {$paths} WHERE " . implode( ' AND ', $where );

		return array_map( 'intval', (array) $wpdb->get_col( $sql ) ); // phpcs:ignore
	}

	/**
	 * The two sets the edge lane is cut by: finding ids on an open door, and
	 * the machines that only look published (judged reachable, but with no
	 * way in the cloud map or a public address can show).
	 *
	 * @return array{0:int[],1:int[]}
	 */
	public static function door_parts(): array {
		if ( ! class_exists( 'VulnHub_Threat_Exposure' ) ) {
			return array( array(), self::internet_asset_ids() );
		}

		$x = VulnHub_Threat_Exposure::data();

		return array(
			VulnHub_Threat_Exposure::finding_ids( 'all' ),
			array_values( array_diff( self::internet_asset_ids(), (array) $x['door_assets'] ) ),
		);
	}

	/** @param int[] $ids Finding ids. */
	private static function in_ids( array $ids ): string {
		return $ids ? 'f.id IN (' . implode( ',', $ids ) . ')' : '1=0';
	}

	/** @param int[] $ids Finding ids. */
	private static function not_in_ids( array $ids ): string {
		return $ids ? 'f.id NOT IN (' . implode( ',', $ids ) . ')' : '1=1';
	}

	/**
	 * Edge-route findings that are neither on an open door nor on a machine
	 * that looks published: the part the inside lane borrows.
	 *
	 * @param int[] $edge_ids     Definition ids.
	 * @param int[] $door         Finding ids on an open door.
	 * @param int[] $maybe_assets Machines that look published.
	 */
	private static function borrowed_sql( array $edge_ids, array $door, array $maybe_assets ): string {
		return 'f.vuln_id IN (' . implode( ',', $edge_ids ) . ') AND ' . self::not_in_ids( $door )
			. ( $maybe_assets ? ' AND f.asset_id NOT IN (' . implode( ',', $maybe_assets ) . ')' : '' );
	}

	/** Assets the exposure rule says the internet can reach. @return int[] */
	public static function internet_asset_ids(): array {
		global $wpdb;

		$expo = VulnHub_Threat_Install::table( 'asset_exposure' );

		return array_map( 'intval', (array) $wpdb->get_col( "SELECT asset_id FROM {$expo} WHERE internet_facing = 1" ) ); // phpcs:ignore
	}

	/**
	 * The numbers the widget draws.
	 *
	 * @return array<string,mixed>
	 */
	public static function lanes(): array {
		global $wpdb;

		$f      = vh_table( 'findings' );
		$paths  = VulnHub_Threat_Install::table( 'vuln_paths' );
		$intel  = VulnHub_Threat_Install::table( 'cve_intel' );
		$facing = self::internet_asset_ids();

		$edge_ids   = self::vuln_ids( 'edge' );
		$user_ids   = self::vuln_ids( 'user' );
		$inside_ids = self::vuln_ids( 'inside' );

		$open = "f.state IN ('open','reopened') AND f.exception_id = 0";

		/*
		 * The edge lane is findings on a door that is actually open: the
		 * internet can open the port, and the bug is in what answers on it
		 * (VulnHub_Threat_Exposure). It used to be every edge-route finding
		 * on any machine judged reachable, whatever port the bug was on -- a
		 * kernel or perl bug on a server with 443 open counted as "straight
		 * from the internet", and the lane read 296 against a true 12.
		 *
		 * Machines that only *look* published -- a web or mail service is
		 * listening, but nothing here can read the firewall in front -- are
		 * their own number, not folded into either side. Everything else
		 * moves to the inside lane, where it can be used.
		 */
		[ $door, $maybe_assets ] = self::door_parts();

		$edge_open   = self::count_findings( $edge_ids, null, false, array( self::in_ids( $door ) ) );
		$edge_maybe  = self::count_findings( $edge_ids, $maybe_assets, false, array( self::not_in_ids( $door ) ) );
		$edge_rest   = self::count_findings( $edge_ids, null, false, array( self::not_in_ids( $door ) ) );
		$edge_hidden = array( 'findings' => $edge_rest['findings'] - $edge_maybe['findings'] );
		$user        = self::count_findings( $user_ids, null, false );
		$inside      = self::count_findings( $inside_ids, null, false );

		$totals = array(
			'open'    => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$f} f WHERE {$open}" ), // phpcs:ignore
			'assets'  => (int) $wpdb->get_var( "SELECT COUNT(DISTINCT f.asset_id) FROM {$f} f WHERE {$open}" ), // phpcs:ignore
			'facing'  => count( $facing ),
			'unknown' => self::count_findings( self::vuln_ids( 'unknown', false ), null, false )['findings'],
		);

		return array(
			'edge'      => $edge_open + array(
				'vulns' => count( $edge_ids ),
				'maybe' => $edge_maybe,
			),
			'user'      => $user + array(
				'vulns'    => count( $user_ids ),
				'delivery' => self::delivery_split( $user_ids ),
			),
			'inside'    => array(
				'findings' => $inside['findings'] + $edge_hidden['findings'],
				/*
				 * A real distinct count over the union of both sets. This was
				 * max() of the two, which is only correct when one set of
				 * machines contains the other -- otherwise it silently reports
				 * the larger half and loses every machine that appears solely
				 * in the smaller one.
				 */
				'assets'   => self::union_assets( $inside_ids, $edge_ids, $door, $maybe_assets ),
				'vulns'    => count( array_unique( array_merge( $inside_ids, $edge_ids ) ) ),
				'borrowed' => $edge_hidden['findings'],
			),
			'exposure'  => self::exposure_split(),
			'totals'    => $totals,
			'evidence'  => array(
				'kev'         => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$intel} WHERE kev = 1" ), // phpcs:ignore
				'exploit_ref' => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$intel} WHERE exploit_refs > 0" ), // phpcs:ignore
				'epss'        => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$intel} WHERE epss >= %f", VulnHub_Threat_Classify::epss_threshold() ) ), // phpcs:ignore
				'kev_vulns'   => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$paths} WHERE kev = 1" ), // phpcs:ignore
			),
			'as_of'     => (string) ( VulnHub_Threat_Feeds::status()['last_run'] ?? '' ),
			'threshold' => VulnHub_Threat_Classify::epss_threshold(),
		);
	}

	/**
	 * Distinct assets across the inside lane's two halves.
	 *
	 * The lane is "definitions that only work once somebody is inside" plus
	 * "edge definitions on a machine the internet cannot reach", and those two
	 * sets of machines overlap without either containing the other.
	 *
	 * @param int[] $inside_ids Inside-route definitions.
	 * @param int[] $edge_ids   Edge-route definitions.
	 * @param int[] $facing     Assets the internet can reach.
	 */
	private static function union_assets( array $inside_ids, array $edge_ids, array $door, array $maybe_assets ): int {
		global $wpdb;

		$f    = vh_table( 'findings' );
		$open = "f.state IN ('open','reopened') AND f.exception_id = 0";
		$or   = array();

		if ( $inside_ids ) {
			$or[] = 'f.vuln_id IN (' . implode( ',', $inside_ids ) . ')';
		}

		if ( $edge_ids ) {
			$or[] = '(' . self::borrowed_sql( $edge_ids, $door, $maybe_assets ) . ')';
		}

		if ( ! $or ) {
			return 0;
		}

		return (int) $wpdb->get_var( // phpcs:ignore
			"SELECT COUNT(DISTINCT f.asset_id) FROM {$f} f WHERE {$open} AND ( " . implode( ' OR ', $or ) . ' )' // phpcs:ignore
		);
	}

	/**
	 * How the estate splits across the three things we can actually say about
	 * whether the internet can reach a machine.
	 *
	 * `unknown` is the number that matters and the one a boolean would hide:
	 * machines nothing has port-scanned, which are neither confirmed reachable
	 * nor confirmed safe. Reporting them alongside the other two is the
	 * difference between a dashboard that says "23 reachable" and one that
	 * says "23 reachable, and we have not looked at 687".
	 *
	 * @return array<string,int>
	 */
	private static function exposure_split(): array {
		global $wpdb;

		$expo = VulnHub_Threat_Install::table( 'asset_exposure' );
		$a    = vh_table( 'assets' );

		$out = array( 'confirmed' => 0, 'ruled_out' => 0, 'unknown' => 0, 'asserted' => 0, 'unknown_servers' => 0 );

		foreach ( (array) $wpdb->get_results( "SELECT basis, internet_facing, COUNT(*) c FROM {$expo} GROUP BY basis, internet_facing", ARRAY_A ) as $row ) { // phpcs:ignore
			$basis = (string) $row['basis'];
			$n     = (int) $row['c'];

			if ( 'evidence' === $basis || ( 'asserted' === $basis && (int) $row['internet_facing'] === 1 ) ) {
				$out[ 'evidence' === $basis ? 'confirmed' : 'asserted' ] += $n;
				continue;
			}

			if ( isset( $out[ $basis ] ) ) {
				$out[ $basis ] += $n;
			}
		}

		// Servers we have never looked at are the actionable half of `unknown`.
		$out['unknown_servers'] = (int) $wpdb->get_var( // phpcs:ignore
			"SELECT COUNT(*) FROM {$expo} e INNER JOIN {$a} s ON s.id = e.asset_id
			  WHERE e.basis = 'unknown' AND s.asset_type IN ('server','cloud')" // phpcs:ignore
		);

		return $out;
	}

	/**
	 * Count open findings for a set of definitions, optionally gated on assets.
	 *
	 * @param int[]      $vuln_ids  Definition ids.
	 * @param int[]|null $asset_ids Assets to gate on, or null for no gate.
	 * @param bool       $invert    Count the assets NOT in the list instead.
	 * @return array{findings:int,assets:int}
	 */
	private static function count_findings( array $vuln_ids, ?array $asset_ids, bool $invert, array $extra = array() ): array {
		global $wpdb;

		if ( ! $vuln_ids ) {
			return array( 'findings' => 0, 'assets' => 0 );
		}

		$f     = vh_table( 'findings' );
		$where = array_merge( array( "f.state IN ('open','reopened')", 'f.exception_id = 0', 'f.vuln_id IN (' . implode( ',', $vuln_ids ) . ')' ), $extra );

		/*
		 * null and an empty array are deliberately different. null is "do not
		 * gate on the asset at all"; an empty array is "gate on a set that
		 * happens to be empty", which matches nothing going forwards and
		 * everything inverted. Collapsing the two would silently report every
		 * finding as internet-reachable on an estate where nothing is.
		 */
		if ( null !== $asset_ids ) {
			if ( ! $asset_ids ) {
				if ( ! $invert ) {
					return array( 'findings' => 0, 'assets' => 0 );
				}
			} else {
				$where[] = 'f.asset_id ' . ( $invert ? 'NOT IN' : 'IN' ) . ' (' . implode( ',', $asset_ids ) . ')';
			}
		}

		$row = (array) $wpdb->get_row( // phpcs:ignore
			"SELECT COUNT(*) AS findings, COUNT(DISTINCT f.asset_id) AS assets FROM {$f} f WHERE " . implode( ' AND ', $where ), // phpcs:ignore
			ARRAY_A
		);

		return array(
			'findings' => (int) ( $row['findings'] ?? 0 ),
			'assets'   => (int) ( $row['assets'] ?? 0 ),
		);
	}

	/**
	 * How the user-delivered findings arrive: email, website or download.
	 *
	 * @param int[] $vuln_ids Definition ids already known to be user-delivered.
	 * @return array<string,int>
	 */
	private static function delivery_split( array $vuln_ids ): array {
		global $wpdb;

		$out = array( 'mail' => 0, 'web' => 0, 'file' => 0 );

		if ( ! $vuln_ids ) {
			return $out;
		}

		$f     = vh_table( 'findings' );
		$paths = VulnHub_Threat_Install::table( 'vuln_paths' );

		$rows = (array) $wpdb->get_results( // phpcs:ignore
			"SELECT p.delivery, COUNT(*) n
			 FROM {$f} f INNER JOIN {$paths} p ON p.vuln_id = f.vuln_id
			 WHERE f.state IN ('open','reopened') AND f.exception_id = 0
			   AND f.vuln_id IN (" . implode( ',', $vuln_ids ) . ')
			 GROUP BY p.delivery', // phpcs:ignore
			ARRAY_A
		);

		foreach ( $rows as $row ) {
			$key = (string) $row['delivery'];

			if ( isset( $out[ $key ] ) ) {
				$out[ $key ] += (int) $row['n'];
			} else {
				$out['web'] += (int) $row['n'];
			}
		}

		return $out;
	}

	/* =================================================================
	 * Drill-down
	 * ============================================================== */

	/**
	 * Teach core's findings query about `route` and `poc`.
	 *
	 * Without this the widget's numbers would not be clickable, and a number
	 * you cannot click is a number nobody can act on.
	 *
	 * @param array<string,mixed> $ext  Extension clauses.
	 * @param array<string,mixed> $args Query arguments.
	 * @return array<string,mixed>
	 */
	public static function findings_query( array $ext, array $args ): array {
		$route    = sanitize_key( (string) ( $args['route'] ?? '' ) );
		$delivery = sanitize_key( (string) ( $args['delivery'] ?? '' ) );
		$poc      = '' !== (string) ( $args['poc'] ?? '' ) && (bool) $args['poc'];
		$expo     = sanitize_key( (string) ( $args['expo'] ?? '' ) );

		/*
		 * Open to the internet and vulnerable on that port: exactly the
		 * findings the panel counted, by id, so the list and the number cannot
		 * disagree. Stacks with everything else.
		 */
		if ( in_array( $expo, array_merge( VulnHub_Threat_Exposure::TIERS, array( 'all', 'latent' ) ), true ) ) {
			$ids            = VulnHub_Threat_Exposure::finding_ids( $expo );
			$ext['where'][] = $ids ? 'f.id IN (' . implode( ',', $ids ) . ')' : '1=0';
		}

		if ( '' === $route && '' === $delivery && ! $poc ) {
			return $ext;
		}

		$only_poc = $poc || '' !== $route || '' !== $delivery;

		/*
		 * A delivery channel is a slice of the user route, so it is already
		 * user-scoped and self-contained: it wins over the coarser `route`
		 * filter rather than stacking with it. This is what makes each door
		 * -- email, website, download -- drill into exactly its own rows.
		 */
		if ( in_array( $delivery, array( 'mail', 'web', 'file' ), true ) ) {
			$ids            = self::delivery_ids( $delivery, $only_poc );
			$ext['where'][] = $ids ? 'f.vuln_id IN (' . implode( ',', $ids ) . ')' : '1=0';

			return $ext;
		}

		if ( '' === $route ) {
			$ids                = self::vuln_ids( '', true );
			$ext['where'][] = $ids ? 'f.vuln_id IN (' . implode( ',', $ids ) . ')' : '1=0';

			return $ext;
		}

		/*
		 * The machines that only look published: edge-route findings there,
		 * off any open door. Its own drill-down, because it is its own
		 * question -- "is the firewall in front publishing this?" -- and
		 * folding it into either lane would answer that without asking.
		 */
		if ( 'maybe' === $route ) {
			$edge                    = self::vuln_ids( 'edge', $only_poc );
			[ $door, $maybe_assets ] = self::door_parts();

			$ext['where'][] = $edge && $maybe_assets
				? 'f.vuln_id IN (' . implode( ',', $edge ) . ') AND f.asset_id IN (' . implode( ',', $maybe_assets ) . ') AND ' . self::not_in_ids( $door )
				: '1=0';

			return $ext;
		}

		if ( 'inside' === $route ) {
			/*
			 * The inside lane is two populations: things that only work from
			 * inside, plus things that would work from the internet if the
			 * machine were reachable and is not. Both are the same job for
			 * whoever picks this list up, so the filter returns both.
			 */
			$inside = self::vuln_ids( 'inside', $only_poc );
			$edge   = self::vuln_ids( 'edge', $only_poc );
			$parts  = array();

			[ $door, $maybe_assets ] = self::door_parts();

			if ( $inside ) {
				$parts[] = 'f.vuln_id IN (' . implode( ',', $inside ) . ')';
			}
			if ( $edge ) {
				$parts[] = '( ' . self::borrowed_sql( $edge, $door, $maybe_assets ) . ' )';
			}

			$ext['where'][] = $parts ? '( ' . implode( ' OR ', $parts ) . ' )' : '1=0';

			return $ext;
		}

		$ids = self::vuln_ids( $route, $only_poc );

		if ( ! $ids ) {
			$ext['where'][] = '1=0';

			return $ext;
		}

		$ext['where'][] = 'f.vuln_id IN (' . implode( ',', $ids ) . ')';

		// Same cuts as lanes(), so a lane and the list it opens are one set.
		if ( 'edge' === $route ) {
			$ext['where'][] = self::in_ids( self::door_parts()[0] );
		}

		return $ext;
	}

	/**
	 * Portal link to the findings behind one exposure tier, optionally on one
	 * machine.
	 *
	 * @param string $which A tier, 'all' or 'latent'.
	 */
	public static function expo_url( string $which, int $asset = 0 ): string {
		if ( ! class_exists( 'VulnHub_Dash_Portal' ) ) {
			return '';
		}

		return VulnHub_Dash_Portal::portal_url(
			'vulnerabilities',
			array_filter(
				array(
					'state'    => 'open_any',
					'excepted' => 'exclude',
					'expo'     => $which,
					'asset'    => $asset ?: null,
				)
			)
		);
	}

	/** Portal link to the findings behind one lane. */
	public static function lane_url( string $route ): string {
		if ( ! class_exists( 'VulnHub_Dash_Portal' ) ) {
			return '';
		}

		return VulnHub_Dash_Portal::portal_url(
			'vulnerabilities',
			array(
				'state' => 'open_any',
				'route' => $route,
				'poc'   => '1',
			)
		);
	}

	/**
	 * Portal link to the findings behind one delivery door.
	 *
	 * `route=user` rides along so the drill-down reads as "user route, this
	 * channel" wherever the filter surfaces to the reader, even though
	 * findings_query() resolves it from `delivery` alone.
	 *
	 * @param string $channel 'mail', 'web' or 'file'.
	 */
	public static function delivery_url( string $channel ): string {
		if ( ! class_exists( 'VulnHub_Dash_Portal' ) ) {
			return '';
		}

		return VulnHub_Dash_Portal::portal_url(
			'vulnerabilities',
			array(
				'state'    => 'open_any',
				'route'    => 'user',
				'delivery' => $channel,
				'poc'      => '1',
			)
		);
	}
}
