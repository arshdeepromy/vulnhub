<?php
/**
 * How each EC2 instance actually runs, and what that does to its online dot.
 *
 * The online dot used to know one thing: whether something that talks to the
 * machine had heard from it inside 24 hours. For an instance that the Instance
 * Scheduler switches off every evening and all weekend that is wrong twice a
 * day -- hollow on a Monday morning for a box that is exactly where it should
 * be. The AWS cost snapshot already holds what is needed to do better, for
 * every account the sign-in reaches: 14 days of hourly CloudWatch data per
 * instance (so the hours it really ran, as a weekday x hour grid), its tags
 * (auto-scaling group, Instance Scheduler's last action), and when it was
 * stopped. The network capture adds a fresher running/stopped reading.
 *
 * From those, one profile per instance:
 *
 * - `always_on`   ran at least 90% of the window.
 * - `scheduled`   ran part of the window on a repeating weekly pattern, or
 *                 carries a scheduler tag. Its scheduled hours are the grid
 *                 cells it ran in.
 * - `autoscaling` a member of an auto-scaling group (Elastic Beanstalk too):
 *                 part-time because it is replaced, not because it sleeps.
 * - `part_time`   ran part of the window with no pattern -- rebuilt, or
 *                 started by hand.
 * - `off`         did not run at all in the window.
 *
 * And the dot, through `vulnhub_online_state`:
 *
 * - **green** -- the ordinary rule; or, for a scheduled instance, something
 *   heard from it during its most recent scheduled window, so being dark out
 *   of hours is not held against it.
 * - **orange** -- AWS says it is stopped, and nothing heard from it during its
 *   last scheduled window (or, unscheduled, inside the ordinary window). It
 *   missed its hours, or it was stopped recently.
 * - **red** -- AWS says it is stopped and has been for more than a week, with
 *   nothing heard from it since it stopped.
 *
 * Nothing here contacts a machine. The only evidence is configuration and
 * metrics AWS already reports, and the check-ins other systems already hold.
 * Plerion's EC2 list carries no running state, so it can place an instance
 * but never confirm one stopped.
 *
 * See docs/COVERAGE.md, "Online dot and EC2 schedules".
 *
 * @package VulnHub
 */

defined( 'ABSPATH' ) || exit;

final class VulnHub_AWS_Run_Profile {

	/** Cached profiles, rebuilt whenever a newer cost snapshot or capture lands. */
	public const OPT = 'vulnhub_aws_run_profiles';

	/** Days stopped before an instance reads as off rather than paused. */
	public const OFF_DAYS = 7;

	/**
	 * A window that started less than this long ago is too new to judge: the
	 * agent may simply not have checked in yet. The previous window is used.
	 */
	private const GRACE_HOURS = 2;

	/** Ran at least this share of the window: always on. */
	private const ALWAYS_ON = 0.9;

	/** @var array<string,mixed>|null */
	private static ?array $cache = null;

	public static function init(): void {
		add_filter( 'vulnhub_online_state', array( __CLASS__, 'online_state' ), 10, 2 );
	}

	/* =================================================================
	 * Profiles
	 * ============================================================== */

	/**
	 * Every profile: instance id => profile. Built once per change of inputs.
	 *
	 * @return array<string,array<string,mixed>>
	 */
	public static function all(): array {
		if ( null !== self::$cache ) {
			return self::$cache['profiles'];
		}

		global $wpdb;

		$ct  = class_exists( 'VulnHub_AWS_Cost_Store' ) ? VulnHub_AWS_Cost_Store::table() : '';
		$nt  = VulnHub_AWS_Network::nodes_table();
		$sid = '' !== $ct ? (int) $wpdb->get_var( "SELECT MAX(id) FROM {$ct} WHERE status = 'ok'" ) : 0; // phpcs:ignore WordPress.DB
		$net = (string) $wpdb->get_var( "SELECT MAX(last_seen) FROM {$nt} WHERE node_type = 'instance' AND source = 'aws'" ); // phpcs:ignore WordPress.DB
		$key = 'v2|' . $sid . '|' . $net;

		$stored = get_option( self::OPT, array() );

		if ( is_array( $stored ) && ( $stored['key'] ?? '' ) === $key && is_array( $stored['profiles'] ?? null ) ) {
			self::$cache = $stored;

			return self::$cache['profiles'];
		}

		self::$cache = array(
			'key'      => $key,
			'built'    => vh_now(),
			'profiles' => self::build(),
		);

		update_option( self::OPT, self::$cache, false );

		return self::$cache['profiles'];
	}

	/** @return array<string,mixed>|null */
	public static function for_instance( string $iid ): ?array {
		$iid = trim( $iid );

		return '' === $iid ? null : ( self::all()[ $iid ] ?? null );
	}

	/**
	 * Build the profiles from the newest complete cost snapshot and the
	 * network capture.
	 *
	 * @return array<string,array<string,mixed>>
	 */
	private static function build(): array {
		global $wpdb;

		$out  = array();
		$snap = class_exists( 'VulnHub_AWS_Cost_Store' ) ? VulnHub_AWS_Cost_Store::latest() : null;

		if ( $snap ) {
			$d        = (array) $snap['data'];
			$tz       = (string) ( $d['timezone'] ?? 'UTC' );
			$possible = (int) ( $d['window']['possible']['all'] ?? 0 );
			$w_start  = self::utc( (string) ( $d['window']['start'] ?? '' ) );
			$read_at  = (string) $snap['started_at'];

			foreach ( (array) ( $d['instances'] ?? array() ) as $i ) {
				$iid = (string) ( $i['id'] ?? '' );

				if ( '' === $iid ) {
					continue;
				}

				$tags  = (array) ( $i['tags'] ?? array() );
				$m     = is_array( $i['metrics'] ?? null ) ? $i['metrics'] : null;
				$hours = null !== $m ? (int) ( $m['hours'] ?? 0 ) : null;
				$grid  = null !== $m ? (array) ( $m['grid'] ?? array() ) : array();
				$state = (string) ( $i['state'] ?? '' );
				$stop  = 'stopped' === $state ? self::utc( (string) ( $i['stopped_at'] ?? '' ) ) : '';
				$floor = false;

				// A stop with no timestamp in its reason, and no running hour in
				// the whole window: off since at least the window's start.
				if ( 'stopped' === $state && '' === $stop && 0 === $hours && '' !== $w_start ) {
					$stop  = $w_start;
					$floor = true;
				}

				$pattern = self::pattern( $hours, $possible, $grid, $tags );

				$out[ $iid ] = array(
					'pattern'       => $pattern,
					'hours'         => $hours,
					'possible'      => $possible,
					'tz'            => $tz,
					'mask'          => 'scheduled' === $pattern ? self::mask( self::core( $grid ) ) : array(),
					'label'         => 'scheduled' === $pattern ? self::label( self::core( $grid ) ) : '',
					'asg'           => (string) ( $tags['aws:autoscaling:groupName'] ?? '' ),
					'state'         => $state,
					'state_at'      => $read_at,
					'stopped_since' => $stop,
					'since_floor'   => $floor,
				);
			}
		}

		// The network capture's reading, where it is the newer of the two.
		$nt = VulnHub_AWS_Network::nodes_table();

		foreach ( (array) $wpdb->get_results( "SELECT resource_id, state, last_seen FROM {$nt} WHERE node_type = 'instance' AND source = 'aws'", ARRAY_A ) as $r ) { // phpcs:ignore WordPress.DB
			$iid   = (string) $r['resource_id'];
			$state = '' !== (string) $r['state'] ? (string) $r['state'] : 'running';
			$at    = (string) $r['last_seen'];

			if ( ! isset( $out[ $iid ] ) ) {
				$out[ $iid ] = array(
					'pattern'       => 'unknown',
					'hours'         => null,
					'possible'      => 0,
					'tz'            => 'UTC',
					'mask'          => array(),
					'label'         => '',
					'asg'           => '',
					'state'         => $state,
					'state_at'      => $at,
					'stopped_since' => '',
					'since_floor'   => false,
				);
				continue;
			}

			if ( strtotime( $at ) <= strtotime( (string) $out[ $iid ]['state_at'] ) ) {
				continue;
			}

			$prev = $out[ $iid ];

			$out[ $iid ]['state']    = $state;
			$out[ $iid ]['state_at'] = $at;

			// Still stopped since the snapshot read it stopped: the same stop,
			// so its start carries over. Running then and stopped now: it
			// stopped somewhere in between, so no start is claimed.
			if ( 'stopped' !== $state ) {
				$out[ $iid ]['stopped_since'] = '';
			} elseif ( 'stopped' !== $prev['state'] ) {
				$out[ $iid ]['stopped_since'] = '';
			}
		}

		return $out;
	}

	/**
	 * @param array<int,array<int,int>> $grid weekday (0 = Mon) x hour => hours ran.
	 * @param array<string,string>      $tags
	 */
	private static function pattern( ?int $hours, int $possible, array $grid, array $tags ): string {
		if ( '' !== (string) ( $tags['aws:autoscaling:groupName'] ?? '' ) ) {
			return 'autoscaling';
		}
		if ( null === $hours || $possible <= 0 ) {
			return 'unknown';
		}
		if ( 0 === $hours ) {
			return 'off';
		}
		if ( $hours >= self::ALWAYS_ON * $possible ) {
			return 'always_on';
		}

		$tagged = isset( $tags['InstanceScheduler-LastAction'] ) || isset( $tags['Schedule'] ) || isset( $tags['CustodianOffHours'] );

		// Repeating: most of its running hours fell in a slot it ran in on
		// more than one week. A rebuilt or hand-started box does not repeat.
		$repeat = 0;
		foreach ( $grid as $row ) {
			foreach ( (array) $row as $n ) {
				if ( (int) $n >= 2 ) {
					$repeat += (int) $n;
				}
			}
		}

		return ( $tagged || $repeat >= 0.7 * $hours ) ? 'scheduled' : 'part_time';
	}

	/**
	 * The slots it ran in on more than one week -- the schedule -- without the
	 * one-off evening it was left on. Falls back to every slot it ran in when
	 * nothing repeated (a window shorter than two weeks, say).
	 *
	 * @param array<int,array<int,int>> $grid
	 * @return array<int,array<int,int>>
	 */
	private static function core( array $grid ): array {
		$out = array();
		$any = false;

		foreach ( $grid as $d => $row ) {
			foreach ( (array) $row as $h => $n ) {
				$out[ $d ][ $h ] = (int) $n >= 2 ? (int) $n : 0;
				$any             = $any || (int) $n >= 2;
			}
		}

		return $any ? $out : $grid;
	}

	/**
	 * Scheduled hours as one 24-bit mask per weekday.
	 *
	 * @param array<int,array<int,int>> $grid
	 * @return int[]
	 */
	private static function mask( array $grid ): array {
		$out = array();

		for ( $d = 0; $d < 7; $d++ ) {
			$bits = 0;
			for ( $h = 0; $h < 24; $h++ ) {
				if ( (int) ( $grid[ $d ][ $h ] ?? 0 ) > 0 ) {
					$bits |= 1 << $h;
				}
			}
			$out[] = $bits;
		}

		return $out;
	}

	/**
	 * "Mon–Fri 07:00–18:00" -- the days it ran and the span of hours, which is
	 * a summary, not the schedule's own definition.
	 *
	 * @param array<int,array<int,int>> $grid
	 */
	private static function label( array $grid ): string {
		$names = array( 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun' );
		$days  = array();
		$lo    = 24;
		$hi    = -1;

		for ( $d = 0; $d < 7; $d++ ) {
			for ( $h = 0; $h < 24; $h++ ) {
				if ( (int) ( $grid[ $d ][ $h ] ?? 0 ) > 0 ) {
					$days[ $d ] = true;
					$lo         = min( $lo, $h );
					$hi         = max( $hi, $h );
				}
			}
		}

		if ( ! $days ) {
			return '';
		}

		$keys = array_keys( $days );
		sort( $keys );
		$run  = ( end( $keys ) - $keys[0] + 1 ) === count( $keys );
		$span = $run && count( $keys ) > 2 ? $names[ $keys[0] ] . '–' . $names[ end( $keys ) ] : implode( ', ', array_map( static fn( int $k ): string => $names[ $k ], $keys ) );

		if ( 7 === count( $keys ) ) {
			$span = __( 'every day', 'vulnhub' );
		}

		if ( 0 === $lo && 23 === $hi ) {
			/* translators: %s: the days, e.g. "Mon–Fri". */
			return sprintf( __( '%s, around the clock on those days', 'vulnhub' ), $span );
		}

		return sprintf( '%s %02d:00–%02d:00', $span, $lo, ( $hi + 1 ) % 24 );
	}

	/* =================================================================
	 * Windows
	 * ============================================================== */

	/**
	 * Start, as a Unix time, of the most recent scheduled window that began
	 * at least GRACE_HOURS ago. Null when the mask is empty.
	 *
	 * @param int[] $mask
	 */
	public static function last_window_start( array $mask, string $tz, int $now ): ?int {
		if ( ! array_filter( $mask ) ) {
			return null;
		}

		try {
			$zone = new \DateTimeZone( $tz );
		} catch ( \Exception $e ) {
			$zone = new \DateTimeZone( 'UTC' );
		}

		$on = static function ( int $ts ) use ( $mask, $zone ): bool {
			$dt = ( new \DateTimeImmutable( '@' . $ts ) )->setTimezone( $zone );

			return (bool) ( ( (int) ( $mask[ (int) $dt->format( 'N' ) - 1 ] ?? 0 ) ) & ( 1 << (int) $dt->format( 'G' ) ) );
		};

		// Walk back an hour at a time from the hour that began GRACE_HOURS
		// ago: find the latest scheduled hour, then the start of its block.
		$t     = (int) ( floor( ( $now - self::GRACE_HOURS * HOUR_IN_SECONDS ) / HOUR_IN_SECONDS ) * HOUR_IN_SECONDS );
		$limit = $t - 15 * DAY_IN_SECONDS;

		while ( $t > $limit && ! $on( $t ) ) {
			$t -= HOUR_IN_SECONDS;
		}

		if ( $t <= $limit ) {
			return null;
		}

		while ( $on( $t - HOUR_IN_SECONDS ) && $t > $limit ) {
			$t -= HOUR_IN_SECONDS;
		}

		return $t;
	}

	/* =================================================================
	 * The dot
	 * ============================================================== */

	/**
	 * Adjust the online state for an EC2 instance AWS has a profile for.
	 *
	 * @param array<string,mixed> $state From Repo::online_state().
	 * @param array<string,mixed> $asset Asset row.
	 * @return array<string,mixed>
	 */
	public static function online_state( array $state, array $asset ): array {
		$p = self::for_instance( (string) ( $asset['aws_instance_id'] ?? '' ) );

		if ( ! $p ) {
			return $state;
		}

		$now     = time();
		$heard   = '' !== (string) $state['at'] ? (int) strtotime( (string) $state['at'] . ' UTC' ) : 0;
		$stopped = 'stopped' === $p['state'];
		$read    = sprintf(
			/* translators: %s: how long ago AWS reported the state. */
			__( 'AWS reported it stopped %s', 'vulnhub' ),
			vh_ago( (string) $p['state_at'] )
		);

		$state['pattern'] = (string) $p['pattern'];

		// Red: stopped for more than a week, and not heard from since.
		if ( $stopped && '' !== (string) $p['stopped_since'] ) {
			$since = (int) strtotime( (string) $p['stopped_since'] . ' UTC' );

			if ( $since <= $now - self::OFF_DAYS * DAY_IN_SECONDS && $heard < $since ) {
				$state['online'] = false;
				$state['tone']   = 'down';
				$state['note']   = sprintf(
					/* translators: 1: date it stopped, 2: how long ago. */
					! empty( $p['since_floor'] )
						? __( 'Off: stopped in AWS since at least %1$s (%2$s), and nothing has heard from it since.', 'vulnhub' )
						: __( 'Off: stopped in AWS since %1$s (%2$s), and nothing has heard from it since.', 'vulnhub' ),
					get_date_from_gmt( (string) $p['stopped_since'], 'j M Y' ),
					vh_ago( (string) $p['stopped_since'] )
				);

				return $state;
			}
		}

		if ( 'scheduled' === $p['pattern'] && $p['mask'] ) {
			$start = self::last_window_start( (array) $p['mask'], (string) $p['tz'], $now );

			if ( null !== $start ) {
				$sched = sprintf(
					/* translators: %s: schedule summary such as "Mon–Fri 07:00–18:00". */
					__( 'Scheduled (runs %s)', 'vulnhub' ),
					(string) $p['label']
				);

				if ( $heard >= $start ) {
					$state['online'] = true;
					$state['tone']   = 'on';
					$state['note']   = sprintf(
						/* translators: 1: schedule sentence, 2: what heard it, 3: how long ago. */
						__( '%1$s: heard from by %2$s %3$s, during its most recent scheduled window.', 'vulnhub' ),
						$sched,
						(string) $state['via'],
						vh_ago( (string) $state['at'] )
					);

					return $state;
				}

				// Only a stopped reading taken after the window opened says the
				// machine missed it. One taken before -- last night's -- says only
				// that it was off out of hours, which is the schedule working.
				if ( $stopped && (int) strtotime( (string) $p['state_at'] . ' UTC' ) >= $start ) {
					$state['online'] = false;
					$state['tone']   = 'warn';
					$state['note']   = sprintf(
						/* translators: 1: schedule sentence, 2: AWS reading sentence. */
						__( '%1$s: nothing heard from it during its last scheduled window, and %2$s.', 'vulnhub' ),
						$sched,
						$read
					);

					return $state;
				}

				if ( 'off' === ( $state['tone'] ?? '' ) && (int) strtotime( (string) $p['state_at'] . ' UTC' ) >= $start ) {
					$state['note'] = sprintf(
						/* translators: 1: schedule sentence, 2: what heard it, 3: how long ago, 4: how long ago AWS read it. */
						__( '%1$s: last heard from by %2$s %3$s, not during its most recent window, though AWS read it running %4$s.', 'vulnhub' ),
						$sched,
						(string) $state['via'],
						vh_ago( (string) $state['at'] ),
						vh_ago( (string) $p['state_at'] )
					);
				} elseif ( 'off' === ( $state['tone'] ?? '' ) ) {
					$state['note'] = sprintf(
						/* translators: 1: schedule sentence, 2: what heard it, 3: how long ago, 4: how long ago AWS last read it. */
						__( '%1$s: last heard from by %2$s %3$s, not during its most recent window. AWS last read its state %4$s, before that window opened, so whether it started is not known.', 'vulnhub' ),
						$sched,
						(string) $state['via'],
						vh_ago( (string) $state['at'] ),
						vh_ago( (string) $p['state_at'] )
					);
				}

				return $state;
			}
		}

		// Unscheduled, stopped recently, and not online by the ordinary rule.
		if ( $stopped && empty( $state['online'] ) ) {
			$state['tone'] = 'warn';
			$state['note'] = sprintf(
				/* translators: %s: AWS reading sentence. */
				__( 'Not heard from inside its window, and %s.', 'vulnhub' ),
				$read
			);
		}

		return $state;
	}

	/** 'Y-m-d H:i:s' UTC from an ISO or SQL-shaped time, or '' if unreadable. */
	private static function utc( string $t ): string {
		$t = trim( $t );

		if ( '' === $t ) {
			return '';
		}

		$ts = strtotime( preg_match( '/[zZ]$|[+-]\d{2}:?\d{2}$/', $t ) ? $t : $t . ' UTC' );

		return $ts ? gmdate( 'Y-m-d H:i:s', $ts ) : '';
	}
}
