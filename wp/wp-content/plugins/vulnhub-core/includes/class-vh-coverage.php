<?php
/**
 * Scanning coverage.
 *
 * A vulnerability platform that only counts the vulnerabilities it was told
 * about answers the wrong question. The dangerous asset is not the one with
 * 300 findings -- somebody is already looking at that one -- it is the asset
 * the scanner has never seen, because it contributes zero to every chart and
 * therefore looks perfect.
 *
 * Coverage is the join between what the CMDB and Intune say exists and what
 * Tenable has actually scanned, and the gap between those two lists is the
 * output of this class.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Coverage {

	/** An asset Tenable has scanned inside the freshness window. */
	public const COVERED = 'covered';

	/** Tenable knows the asset, but has not scanned it inside the window. */
	public const STALE = 'stale';

	/** Tenable knows the asset and has never returned a finding for it. */
	public const NEVER_SCANNED = 'never_scanned';

	/** The asset exists in the CMDB or Intune and Tenable has no record at all. */
	public const NOT_IN_TENABLE = 'not_in_tenable';

	/**
	 * Tenable has no record, and nothing else has seen it lately either.
	 *
	 * Split out of NOT_IN_TENABLE because the two need different people. A
	 * machine Intune synced this morning that Tenable has never scanned is a
	 * scanner-coverage problem: chase the scan. A machine nothing has heard
	 * from in six months is an inventory problem: chase the CMDB, and the
	 * answer is usually that it was thrown away and nobody retired the row.
	 * Both used to appear on the same list, in the same red, indistinguishable.
	 */
	public const NO_CONTACT = 'no_contact';

	/** Retired, in stock, quarantined -- not expected to be scanned. */
	public const OUT_OF_SCOPE = 'out_of_scope';

	/**
	 * A live device, but not one a scanner was ever going to be pointed at.
	 *
	 * Printers, switches, video units and the rest of what a Defender discovery
	 * sweep turns up. Held out of the coverage *percentage* by
	 * `vh_scannable_asset_types()` and counted everywhere else, so the
	 * by-device-type chart still reports 48 switches with no scan while the
	 * headline figure stays a statement about machines somebody can patch.
	 */
	public const OTHER_DEVICE = 'other_device';

	/**
	 * Every state, worst first, with how to describe it.
	 *
	 * @return array<string,array{label:string,tone:string,gap:bool}>
	 */
	public static function states(): array {
		return array(
			self::NOT_IN_TENABLE => array(
				'label' => __( 'Not in Tenable', 'vulnhub' ),
				'tone'  => 'bad',
				'gap'   => true,
			),
			/*
			 * Not a gap, and the distinction is the whole point.
			 *
			 * Tenable holding an asset it has not scanned is a scan to chase,
			 * not an onboarding job, so `summary()` counts it as covered and
			 * flags it apart. This flag has to agree: while it said `true`
			 * the gap list carried two assets the coverage figure was
			 * simultaneously counting as covered, and the widget totals were
			 * out by exactly those two with nothing on screen to explain it.
			 */
			self::NEVER_SCANNED  => array(
				'label' => __( 'Never scanned', 'vulnhub' ),
				'tone'  => 'warn',
				'gap'   => false,
			),
			self::NO_CONTACT     => array(
				'label' => __( 'No recent contact', 'vulnhub' ),
				'tone'  => 'warn',
				'gap'   => true,
			),
			self::STALE          => array(
				'label' => __( 'Scan is stale', 'vulnhub' ),
				'tone'  => 'warn',
				'gap'   => false,
			),
			self::COVERED        => array(
				'label' => __( 'Covered', 'vulnhub' ),
				'tone'  => 'good',
				'gap'   => false,
			),
			self::OTHER_DEVICE   => array(
				'label' => __( 'Not a scanning target', 'vulnhub' ),
				'tone'  => 'muted',
				'gap'   => false,
			),
			self::OUT_OF_SCOPE   => array(
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

	/**
	 * Network vendors, by the name Defender reports for a device's network
	 * card maker. Matched as lowercase substrings.
	 */
	private const NETWORK_VENDORS = array(
		'mellanox', 'tp-link', 'cisco', 'juniper', 'aruba', 'arista', 'ubiquiti', 'netgear', 'meraki',
		'extreme networks', 'brocade', 'mikrotik', 'fortinet', 'palo alto', 'check point', 'sonicwall',
		'zyxel', 'd-link', 'huawei', 'ruckus', 'riverbed', 'f5 networks', 'barracuda', 'watchguard',
	);

	/**
	 * Server-hardware vendors. On a device discovered on the network with no
	 * operating system anybody could name, this vendor's card is almost
	 * always the out-of-band management controller -- iLO, iDRAC, XClarity,
	 * a BMC -- not the server's own OS.
	 */
	private const BMC_VENDORS = array(
		'hewlett packard', 'hpe', 'dell', 'supermicro', 'super micro', 'lenovo', 'fujitsu', 'quanta',
		'american megatrends', 'aspeed', 'inspur', 'cisco systems ucs',
	);

	/**
	 * Give a type to devices Defender found on the network and could not
	 * identify.
	 *
	 * Defender's device discovery reports machines it has no sensor on. When
	 * it cannot tell what one is -- onboarding status "insufficient info" or
	 * "unsupported", no name, no OS version -- its export still files many of
	 * them as servers, and they were counted as servers needing a Tenable
	 * agent: management interfaces of switches and storage, VMware appliances
	 * (vCenter, NSX edges, ESXi management), out-of-band controllers. Pure
	 * noise on the agent-coverage list, and none of them can take an agent.
	 *
	 * Only rows nothing else vouches for are touched: known to Defender alone
	 * (no Tenable, Intune or CMDB record), still typed server or unknown, and
	 * with no real name (empty, or Defender's 40-hex device id). The type then
	 * follows the network card's maker:
	 *
	 *   network vendor              -> network device
	 *   server-hardware vendor      -> appliance (a management controller)
	 *   VMware, no OS version       -> appliance (a VMware virtual appliance)
	 *   anything, no OS version     -> unknown   (not a server we can name)
	 *
	 * A VMware machine that does report an OS version (Ubuntu 20, say) is
	 * left a server: that may be a real Linux VM nobody scans, which is a gap,
	 * not noise.
	 *
	 * @return int Rows retyped.
	 */
	public static function type_discovered_devices(): int {
		global $wpdb;

		$a    = vh_table( 'assets' );
		$rows = (array) $wpdb->get_results( // phpcs:ignore
			"SELECT id, manufacturer, operating_system, os_version FROM {$a}
			 WHERE defender_onboarding IN ('insufficient_info','unsupported')
			   AND ( tenable_uuid = '' OR tenable_uuid IS NULL )
			   AND ( intune_id = '' OR intune_id IS NULL )
			   AND ( cmdb_id = '' OR cmdb_id IS NULL )
			   AND asset_type IN ('server','unknown','')
			   AND ( hostname = '' OR hostname REGEXP '^[0-9a-f]{40}$' )",
			ARRAY_A
		);
		$n    = 0;

		foreach ( $rows as $r ) {
			$maker   = strtolower( (string) $r['manufacturer'] );
			$version = strtolower( trim( (string) $r['os_version'] ) );
			$no_os   = '' === $version || 'other' === $version || 'unknown' === $version;
			$type    = '';

			foreach ( self::NETWORK_VENDORS as $v ) {
				if ( str_contains( $maker, $v ) ) {
					$type = 'network';
					break;
				}
			}

			if ( '' === $type && $no_os ) {
				foreach ( self::BMC_VENDORS as $v ) {
					if ( str_contains( $maker, $v ) ) {
						$type = 'appliance';
						break;
					}
				}
			}

			if ( '' === $type && $no_os ) {
				$type = str_contains( $maker, 'vmware' ) ? 'appliance' : 'unknown';
			}

			if ( '' !== $type ) {
				$n += (int) $wpdb->query( $wpdb->prepare( "UPDATE {$a} SET asset_type = %s, updated_at = %s WHERE id = %d AND asset_type <> %s", $type, vh_now(), (int) $r['id'], $type ) ); // phpcs:ignore
			}
		}

		return $n;
	}

	/** States that count as a gap somebody has to close. */
	public static function gap_states(): array {
		return array_keys( array_filter( self::states(), static fn( array $s ): bool => $s['gap'] ) );
	}

	/**
	 * States where Tenable has a record of the asset.
	 *
	 * Coverage answers "is this machine known to the scanner", not "was it
	 * scanned this month". An asset Tenable holds but has not scanned yet is
	 * covered, and flagged separately as unscanned. Counting it as a coverage
	 * gap sends somebody to onboard a machine that is already onboarded, and
	 * buries the machines Tenable genuinely has no record of -- which are the
	 * only ones that actually need onboarding.
	 *
	 * @return array<int,string>
	 */
	public static function in_tenable_states(): array {
		return array( self::COVERED, self::STALE, self::NEVER_SCANNED );
	}

	/**
	 * States where Tenable holds the asset but has no current scan for it.
	 *
	 * A subset of in_tenable_states(): counted as covered, flagged apart.
	 *
	 * @return array<int,string>
	 */
	public static function unscanned_states(): array {
		return array( self::STALE, self::NEVER_SCANNED );
	}

	/** in_tenable_states() as a quoted SQL list. */
	public static function in_tenable_sql(): string {
		return "'" . implode( "','", array_map( 'esc_sql', self::in_tenable_states() ) ) . "'";
	}

	/**
	 * How many days a Tenable scan stays fresh before the asset is stale.
	 */
	public static function window_days(): int {
		$days = (int) vulnhub()->settings->platform( 'coverage_window_days', 30 );

		return max( 1, min( 365, $days ) );
	}

	/**
	 * How long any system's word that an asset exists stays good for.
	 *
	 * Longer than the scan window on purpose. A scan going stale is a process
	 * slipping; nothing having seen a machine at all is a much stronger claim,
	 * and a laptop can easily sit in a drawer for a month between check-ins
	 * without being gone.
	 */
	public static function contact_days(): int {
		$days = (int) vulnhub()->settings->platform( 'contact_window_days', 45 );

		return max( 1, min( 730, $days ) );
	}

	/**
	 * SQL for "when did anything last see this asset".
	 *
	 * Every source's claim, newest wins. The epoch stands in for NULL because
	 * GREATEST() returns NULL if any argument is, and an asset no system has
	 * ever dated must be distinguishable from one dated long ago -- the first
	 * is unknown, the second is evidence of absence.
	 *
	 * @param string $alias Table alias.
	 */
	public static function contact_sql( string $alias = 'a' ): string {
		return "GREATEST("
			. "COALESCE({$alias}.last_intune_sync, '1970-01-01'), "
			. "COALESCE({$alias}.cmdb_last_scan, '1970-01-01'), "
			. "COALESCE({$alias}.last_seen, '1970-01-01')"
			. ')';
	}

	/** How many assets carry a contact date from any system at all. */
	public static function assets_with_contact(): int {
		global $wpdb;

		$a = vh_table( 'assets' );

		return (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$a} a WHERE " . self::contact_sql() . " > '1970-01-01'" // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		);
	}

	/* =================================================================
	 * Recompute
	 * ============================================================== */

	/**
	 * Recompute `tenable_last_scan` and `coverage_state` for every asset.
	 *
	 * Two set-based statements over the whole estate rather than a loop:
	 * against 25,112 assets and 425,289 findings the pair runs in about a
	 * second, and a per-asset version would not finish inside a cron slot.
	 */
	public static function recalculate(): void {
		global $wpdb;

		$a = vh_table( 'assets' );
		$f = vh_table( 'findings' );

		// Type first: every coverage answer below depends on it.
		self::type_discovered_devices();

		// 1. When did Tenable last actually see this asset? The freshest
		//    finding it reported is the only evidence we have of a scan.
		$wpdb->query(
			"UPDATE {$a} a
			 LEFT JOIN (
				SELECT asset_id, MAX(last_found) AS seen
				FROM {$f}
				WHERE source = 'tenable'
				GROUP BY asset_id
			 ) s ON s.asset_id = a.id
			 SET a.tenable_last_scan = s.seen" // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		);

		$cutoff    = gmdate( 'Y-m-d H:i:s', time() - self::window_days() * DAY_IN_SECONDS );
		$seen_by   = gmdate( 'Y-m-d H:i:s', time() - self::contact_days() * DAY_IN_SECONDS );
		$contact   = self::contact_sql();
		$in_scope  = vh_scannable_sql();
		$covered   = self::COVERED;
		$stale     = self::STALE;
		$never     = self::NEVER_SCANNED;
		$missing   = self::NOT_IN_TENABLE;
		$quiet     = self::NO_CONTACT;
		$oos       = self::OUT_OF_SCOPE;
		$other     = self::OTHER_DEVICE;
		$types     = vh_scannable_types_sql();

		/*
		 * Scope comes from vh_scannable_statuses(), not from the ownership
		 * list. A quarantined or in-repair machine still has an owner but is
		 * not on the network to be scanned, and counting it as a scanning gap
		 * pushes the machines somebody can actually fix off the first page.
		 *
		 * `unknown` is in the default scope, for a reason worth keeping: a
		 * device nobody has classified is exactly the kind that goes
		 * unscanned, and excluding it would hide the gap this table exists to
		 * surface. It used to be forced in scope by a hard-coded
		 * `lifecycle_status <> 'unknown'` here, which made the Unknown tick
		 * box on the settings screen do nothing at all -- a control that
		 * lies. It is now a default, not a rule, and unticking it works.
		 *
		 * "Not in Tenable" splits in two on the way past. An asset no scanner
		 * knows, that some other system saw recently, is live and unscanned:
		 * real work for whoever owns scanning. One that nothing has dated
		 * inside the contact window is almost always a record nobody retired,
		 * and belongs to whoever owns the inventory. An asset with no contact
		 * date from any system stays in the first group -- absence of evidence
		 * is not evidence of absence, and hiding it would be the same mistake
		 * as never surfacing it.
		 *
		 * "Not in Tenable" needs both tests. A UUID is what the API connector
		 * leaves behind, but a CSV export carries no asset id at all -- so
		 * keying off the UUID alone declared an estate with a quarter of a
		 * million imported Tenable findings to be entirely unscanned.
		 * Findings *from* Tenable are evidence Tenable knows the asset, and
		 * that is what `tenable_last_scan` above summarises.
		 */
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE {$a} a SET a.coverage_state = CASE
					WHEN a.lifecycle_status NOT IN ({$in_scope}) THEN %s
					WHEN a.asset_type NOT IN ({$types}) THEN %s
					WHEN a.tenable_uuid = '' AND a.tenable_last_scan IS NULL
						AND {$contact} > '1970-01-01' AND {$contact} < %s THEN %s
					WHEN a.tenable_uuid = '' AND a.tenable_last_scan IS NULL THEN %s
					WHEN a.tenable_last_scan IS NULL THEN %s
					WHEN a.tenable_last_scan < %s THEN %s
					ELSE %s
				END", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$oos,
				$other,
				$seen_by,
				$quiet,
				$missing,
				$never,
				$cutoff,
				$stale,
				$covered
			)
		);

		/** Fires once coverage has been recomputed for the whole estate. */
		do_action( 'vulnhub_coverage_recalculated' );
	}

	/**
	 * What the scope rule is currently holding back, and why.
	 *
	 * Shown next to the coverage figure so that "196 not scanned" can never
	 * quietly become "106 not scanned" without the reader being told which
	 * 90 machines moved and on what grounds.
	 *
	 * @return array<int,array{status:string,label:string,count:int}>
	 */
	public static function excluded_by_scope(): array {
		global $wpdb;

		$a    = vh_table( 'assets' );
		$rows = (array) $wpdb->get_results(
			"SELECT lifecycle_status AS status, COUNT(*) AS n FROM {$a}
			 WHERE lifecycle_status NOT IN (" . vh_scannable_sql() . ")
			 GROUP BY lifecycle_status ORDER BY n DESC", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			ARRAY_A
		);

		$labels = vh_lifecycle_statuses();
		$out    = array();

		foreach ( $rows as $row ) {
			$slug  = (string) $row['status'];
			$out[] = array(
				'status' => $slug,
				'label'  => (string) ( $labels[ $slug ]['label'] ?? $slug ),
				'count'  => (int) $row['n'],
			);
		}

		/*
		 * Named apart from the lifecycle reasons, and last, because it is a
		 * different claim. "130 retired" says those machines are gone; "112
		 * printers and switches" says they are very much here and simply not
		 * what this number is about. A reader who cannot tell the two apart
		 * cannot tell whether the figure improved or the definition did.
		 */
		$other = (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$a} WHERE coverage_state = '" . esc_sql( self::OTHER_DEVICE ) . "'" // phpcs:ignore WordPress.DB.PreparedSQL
		);

		if ( $other > 0 ) {
			$out[] = array(
				'status' => self::OTHER_DEVICE,
				'label'  => __( 'printers, switches and other kit nobody scans', 'vulnhub' ),
				'count'  => $other,
			);
		}

		return $out;
	}

	/* =================================================================
	 * Read
	 * ============================================================== */

	/**
	 * Headline coverage numbers.
	 *
	 * @return array{states:array<string,int>,in_scope:int,covered:int,gaps:int,percent:float,window_days:int}
	 */
	public static function summary(): array {
		global $wpdb;

		$a    = vh_table( 'assets' );
		$rows = (array) $wpdb->get_results(
			"SELECT coverage_state AS state, COUNT(*) AS n FROM {$a} GROUP BY coverage_state", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			ARRAY_A
		);

		$states = array_fill_keys( array_keys( self::states() ), 0 );

		foreach ( $rows as $row ) {
			$states[ (string) $row['state'] ] = (int) $row['n'];
		}

		$in_scope = array_sum( $states ) - $states[ self::OUT_OF_SCOPE ] - $states[ self::OTHER_DEVICE ];
		$unscanned = $states[ self::STALE ] + $states[ self::NEVER_SCANNED ];
		$covered   = $states[ self::COVERED ] + $unscanned;

		return array(
			'states'      => $states,
			'in_scope'    => $in_scope,
			'excluded'    => $states[ self::OUT_OF_SCOPE ] + $states[ self::OTHER_DEVICE ],
			'retired'     => $states[ self::OUT_OF_SCOPE ],
			'other_kit'   => $states[ self::OTHER_DEVICE ],
			'covered'     => $covered,
			'scanned'     => $states[ self::COVERED ],
			'unscanned'   => $unscanned,
			'gaps'        => max( 0, $in_scope - $covered ),
			'percent'     => $in_scope > 0 ? round( 100 * $covered / $in_scope, 1 ) : 0.0,
			'window_days' => self::window_days(),
		);
	}

	/**
	 * Dimensions coverage can be sliced by, and the column each one reads.
	 *
	 * @return array<string,array{label:string,column:string,join:string}>
	 */
	public static function dimensions(): array {
		/*
		 * `filter` is the asset-query argument that isolates one bar, and
		 * `key` the column holding the value to put in it. For most
		 * dimensions the label IS the value; for a team or a site the label
		 * is a name and the filter wants the foreign key, so the two are
		 * selected separately.
		 */
		return array(
			'asset_type'    => array(
				'label'  => __( 'Device type', 'vulnhub' ),
				'column' => 'a.asset_type',
				'join'   => '',
				'filter' => 'asset_type',
				'key'    => 'a.asset_type',
			),
			'environment'   => array(
				'label'  => __( 'Environment', 'vulnhub' ),
				'column' => "NULLIF(a.environment, '')",
				'join'   => '',
				'filter' => 'environment',
				'key'    => 'a.environment',
			),
			'criticality'   => array(
				'label'  => __( 'Business criticality', 'vulnhub' ),
				'column' => "NULLIF(a.criticality, '')",
				'join'   => '',
				'filter' => 'criticality',
				'key'    => 'a.criticality',
			),
			'primary_source' => array(
				'label'  => __( 'Discovered by', 'vulnhub' ),
				'column' => "NULLIF(a.primary_source, '')",
				'join'   => '',
				'filter' => 'primary_source',
				'key'    => 'a.primary_source',
			),
			'operating_system' => array(
				'label'  => __( 'Operating system', 'vulnhub' ),
				'column' => "NULLIF(a.operating_system, '')",
				'join'   => '',
				'filter' => 'operating_system',
				'key'    => 'a.operating_system',
			),
			'team'          => array(
				'label'  => __( 'Owning team', 'vulnhub' ),
				'column' => 't.name',
				'join'   => 'teams',
				'filter' => 'team_id',
				'key'    => 'a.team_id',
			),
			'location'      => array(
				'label'  => __( 'Site', 'vulnhub' ),
				'column' => 'l.name',
				'join'   => 'locations',
				/*
				 * What to put in the filter for the "Unclassified" row. Only
				 * the site dimension has one, because only the site filter
				 * can express "recorded as nothing" -- for a bare column an
				 * empty value is indistinguishable from "no filter", and a
				 * link that quietly means "everything" is worse than no link.
				 */
				'empty'  => 'none',
				'filter' => 'location_id',
				'key'    => 'a.location_id',
			),
		);
	}

	/**
	 * Coverage broken down by one dimension.
	 *
	 * @param string $dimension One of dimensions().
	 * @param int    $limit     Rows to return, worst coverage first.
	 * @return array<int,array{label:string,filter:string,key:string,total:int,covered:int,gaps:int,percent:float,states:array<string,int>}>
	 */
	public static function by_dimension( string $dimension = 'asset_type', int $limit = 12 ): array {
		global $wpdb;

		$dims = self::dimensions();
		$dim  = $dims[ $dimension ] ?? $dims['asset_type'];
		$a    = vh_table( 'assets' );

		$join = '';
		if ( 'teams' === $dim['join'] ) {
			$join = ' LEFT JOIN ' . vh_table( 'teams' ) . ' t ON t.id = a.team_id';
		} elseif ( 'locations' === $dim['join'] ) {
			$join = ' LEFT JOIN ' . vh_table( 'locations' ) . ' l ON l.id = a.location_id';
		}

		$col   = $dim['column'];
		$limit = max( 1, min( 50, $limit ) );

		$key = (string) ( $dim['key'] ?? $col );

		$rows = (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT COALESCE({$col}, %s) AS label,
					MIN({$key}) AS slice_key,
					COUNT(*) AS total,
					SUM(a.coverage_state = %s) AS covered,
					SUM(a.coverage_state = %s) AS not_in_tenable,
					SUM(a.coverage_state = %s) AS never_scanned,
					SUM(a.coverage_state = %s) AS stale,
					SUM(a.coverage_state = %s) AS other_device,
					SUM(a.coverage_state = %s) AS out_of_scope
				 FROM {$a} a{$join}
				 GROUP BY label
				 ORDER BY total DESC
				 LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				__( 'Unclassified', 'vulnhub' ),
				self::COVERED,
				self::NOT_IN_TENABLE,
				self::NEVER_SCANNED,
				self::STALE,
				self::OTHER_DEVICE,
				self::OUT_OF_SCOPE,
				$limit
			),
			ARRAY_A
		);

		$out = array();

		foreach ( $rows as $row ) {
			$total    = (int) $row['total'];
			$oos      = (int) $row['out_of_scope'];
			/*
			 * Only the lifecycle exclusion comes out of a per-type row. A
			 * printer is held out of the estate percentage, but the printer
			 * row itself is exactly where somebody goes to ask about
			 * printers, and showing it as 0 of 0 would answer nothing.
			 */
			$in_scope = max( 0, $total - $oos );
			$scanned   = (int) $row['covered'];
			$unscanned = (int) $row['never_scanned'] + (int) $row['stale'];
			$covered   = $scanned + $unscanned;

			$key = (string) ( $row['slice_key'] ?? '' );

			// An unplaced asset has location_id 0, which is a real value the
			// filter understands -- not an absent one.
			if ( ( '' === $key || '0' === $key ) && '' !== (string) ( $dim['empty'] ?? '' ) ) {
				$key = (string) $dim['empty'];
			}

			$out[] = array(
				'label'   => (string) $row['label'],
				'filter'  => (string) ( $dim['filter'] ?? '' ),
				'key'     => $key,
				/*
				 * `total` is the in-scope population, not everything the source
				 * knows about. A coverage figure is a statement about machines
				 * somebody is expected to scan, so retired and quarantined kit
				 * cannot sit in the denominator -- and it cannot sit in the
				 * total beside it either, or the row reads as though a third of
				 * the estate is unaccounted for. The full count stays available
				 * as `known`, and what was held back is named in the caption.
				 */
				'total'   => $in_scope,
				'known'   => $total,
				'covered'   => $covered,
				'scanned'   => $scanned,
				'unscanned' => $unscanned,
				'oos'       => $oos,
				'gaps'    => max( 0, $in_scope - $covered ),
				'percent' => $in_scope > 0 ? round( 100 * $covered / $in_scope, 1 ) : 0.0,
				'states'  => array(
					self::COVERED        => $covered,
					self::STALE          => (int) $row['stale'],
					self::NEVER_SCANNED  => (int) $row['never_scanned'],
					self::NOT_IN_TENABLE => (int) $row['not_in_tenable'],
					self::OTHER_DEVICE   => (int) $row['other_device'],
					self::OUT_OF_SCOPE   => $oos,
				),
			);
		}

		return $out;
	}

	/**
	 * Coverage per source system, counting every system that knows an asset.
	 *
	 * Deliberately not a `GROUP BY`, and deliberately not `primary_source`.
	 * A machine the CMDB, Intune and Tenable all know is one row in the
	 * table and three rows here, so the totals sum to more than the estate.
	 * That overlap is the point: the reader is asking "of the machines
	 * Tenable has never scanned, who says they exist", and a grouping that
	 * forced each asset into one bucket could not answer it.
	 *
	 * `sole` is the cleanup column -- assets one system claims and no other
	 * has ever confirmed. Either they left the network without anyone
	 * retiring the record, or nothing else can see them.
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
						SUM(a.coverage_state = %s) AS covered,
						SUM(a.coverage_state = %s) AS never_scanned,
						SUM(a.coverage_state = %s) AS stale,
						SUM(a.coverage_state IN (%s, %s)) AS out_of_scope,
						SUM(a.sources_json NOT LIKE %s) AS sole
					 FROM {$a} a
					 WHERE a.sources_json LIKE %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					self::COVERED,
					self::NEVER_SCANNED,
					self::STALE,
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

			$oos      = (int) ( $row['out_of_scope'] ?? 0 );
			$scanned   = (int) ( $row['covered'] ?? 0 );
			$unscanned = (int) ( $row['never_scanned'] ?? 0 ) + (int) ( $row['stale'] ?? 0 );
			$covered   = $scanned + $unscanned;
			$in_scope = max( 0, $total - $oos );

			$out[] = array(
				'label'   => (string) $label,
				'slug'    => (string) $slug,
				'filter'  => 'known',
				'key'     => (string) $slug,
				/*
				 * `total` is the in-scope population, not everything the source
				 * knows about. A coverage figure is a statement about machines
				 * somebody is expected to scan, so retired and quarantined kit
				 * cannot sit in the denominator -- and it cannot sit in the
				 * total beside it either, or the row reads as though a third of
				 * the estate is unaccounted for. The full count stays available
				 * as `known`, and what was held back is named in the caption.
				 */
				'total'   => $in_scope,
				'known'   => $total,
				'covered'   => $covered,
				'scanned'   => $scanned,
				'unscanned' => $unscanned,
				'oos'       => $oos,
				'sole'    => (int) ( $row['sole'] ?? 0 ),
				'gaps'    => max( 0, $in_scope - $covered ),
				'percent' => $in_scope > 0 ? round( 100 * $covered / $in_scope, 1 ) : 0.0,
			);
		}

		return $out;
	}

	/**
	 * The gap list itself: assets somebody has to get a scanner on to.
	 *
	 * @param array<string,mixed> $args state, asset_type, team_id, search, limit, offset.
	 * @return array{rows:array<int,array<string,mixed>>,total:int}
	 */
	public static function gaps( array $args = array() ): array {
		global $wpdb;

		$a  = vh_table( 'assets' );
		$t  = vh_table( 'teams' );
		$p  = vh_table( 'people' );

		$where  = array();
		$params = array();

		$state = (string) ( $args['state'] ?? '' );

		if ( $state && isset( self::states()[ $state ] ) ) {
			$where[]  = 'a.coverage_state = %s';
			$params[] = $state;
		} else {
			$gap     = self::gap_states();
			$where[] = "a.coverage_state IN ('" . implode( "','", array_map( 'esc_sql', $gap ) ) . "')";
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
			$where[]  = '(a.hostname LIKE %s OR a.fqdn LIKE %s OR a.ipv4 LIKE %s OR a.serial_number LIKE %s)';
			array_push( $params, $like, $like, $like, $like );
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

		$where_sql = $where ? implode( ' AND ', $where ) : '1=1';
		$limit     = max( 1, min( 500, (int) ( $args['limit'] ?? 25 ) ) );
		$offset    = max( 0, (int) ( $args['offset'] ?? 0 ) );

		$total = (int) ( $params
			? $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$a} a WHERE {$where_sql}", ...$params ) ) // phpcs:ignore
			: $wpdb->get_var( "SELECT COUNT(*) FROM {$a} a WHERE {$where_sql}" ) ); // phpcs:ignore

		$qp   = $params;
		$qp[] = $limit;
		$qp[] = $offset;

		$rows = (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT a.id, a.hostname, a.fqdn, a.ipv4, a.asset_type, a.operating_system,
					a.criticality, a.environment, a.primary_source, a.lifecycle_status,
					a.coverage_state, a.tenable_uuid, a.intune_id, a.cmdb_id, a.sources_json,
					a.tenable_last_scan, a.last_seen,
					t.name AS team_name, p.display_name AS owner_name
				 FROM {$a} a
				 LEFT JOIN {$t} t ON t.id = a.team_id
				 LEFT JOIN {$p} p ON p.id = a.owner_person_id
				 WHERE {$where_sql}
				 ORDER BY FIELD(a.coverage_state, %s, %s, %s), a.hostname ASC
				 LIMIT %d OFFSET %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				...array_merge(
					$params,
					array( self::NOT_IN_TENABLE, self::NEVER_SCANNED, self::STALE ),
					array( $limit, $offset )
				)
			),
			ARRAY_A
		);

		return array(
			'rows'  => $rows,
			'total' => $total,
		);
	}
}
