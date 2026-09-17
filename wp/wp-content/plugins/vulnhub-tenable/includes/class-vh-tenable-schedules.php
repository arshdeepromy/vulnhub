<?php
/**
 * Tenable's own scan schedules, and when a ticket should be checked after them.
 *
 * VulnHub does not rescan servers. A server's findings change when the
 * scheduled scan that covers it next runs, so the useful moment to check a
 * ticket is just after that run: the scan runs on a Tuesday, the ticket is
 * checked on Wednesday morning.
 *
 * Which schedule covers which machines is chosen per asset type on the Tenable
 * connector ("Servers are scanned by", "Workstations are scanned by"). It is
 * not detected: a machine's `last_schedule_id` names whatever scan touched it
 * last (inventory scans included), and agent scan histories use placeholder
 * run ids that findings never carry, so neither points reliably at the scan
 * that finds vulnerabilities.
 *
 * Run times come from the schedule's recurrence rule (`rrules`, `starttime`,
 * `timezone`). How long a run takes comes from its completed history, when the
 * history holds real runs.
 *
 * @package VulnHub\Tenable
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Scan schedules.
 */
final class VulnHub_Tenable_Schedules {

	/**
	 * The only asset types a scan may ever be launched against from VulnHub.
	 *
	 * Deliberately a constant and not a setting: servers are scanned by their
	 * own schedules and never by a button here.
	 */
	public const RESCAN_ASSET_TYPES = array( 'workstation' );

	/** Asset types that can be matched to a schedule. */
	public const TYPES = array( 'server', 'workstation' );

	/** Local hour a check runs on the morning after a scan. */
	public const CHECK_HOUR = 10;

	private const OPTION = 'vh_tenable_schedules';

	private const MAX_AGE = HOUR_IN_SECONDS;

	/** Assumed run length when history has no real runs to measure. */
	private const DEFAULT_DURATION = 3 * HOUR_IN_SECONDS;

	/* =================================================================
	 * Reading Tenable
	 * ============================================================== */

	/**
	 * The stored schedule list, refreshed from Tenable when older than an hour.
	 *
	 * @return array{fetched:int,scans:array<int,array<string,mixed>>}
	 */
	public static function data( ?VulnHub_Tenable_Connector $connector = null, bool $allow_fetch = false ): array {
		$data = get_option( self::OPTION, array() );
		$data = is_array( $data ) && isset( $data['scans'] ) ? $data : array( 'fetched' => 0, 'scans' => array() );

		if ( $allow_fetch && $connector && (int) $data['fetched'] < time() - self::MAX_AGE ) {
			$fresh = self::refresh( $connector );
			$data  = null !== $fresh ? $fresh : $data;
		}

		return $data;
	}

	/**
	 * Read every scan and its recent runs from Tenable and store them.
	 *
	 * A failed read keeps what was stored: a check planned from last hour's
	 * list is better than none.
	 *
	 * @return array{fetched:int,scans:array<int,array<string,mixed>>}|null
	 */
	public static function refresh( VulnHub_Tenable_Connector $connector ): ?array {
		if ( $connector->is_mock() || ! $connector->client()->has_credentials() ) {
			return null;
		}

		$list = $connector->client()->scans();

		if ( ! $list ) {
			return null;
		}

		$scans = array();

		foreach ( $list as $scan ) {
			if ( ! self::is_recurring( $scan ) ) {
				continue;
			}

			$runs = $connector->client()->scan_history( (int) $scan['id'], 20 );

			$scans[ (int) $scan['id'] ] = array(
				'id'        => (int) $scan['id'],
				'name'      => (string) $scan['name'],
				'type'      => (string) $scan['type'],
				'rrules'    => (string) $scan['rrules'],
				'starttime' => (string) $scan['starttime'],
				'timezone'  => (string) $scan['timezone'],
				'duration'  => self::typical_duration( (array) $runs ),
				'running'   => self::running_since( (array) $runs ),
			);
		}

		$data = array( 'fetched' => time(), 'scans' => $scans );
		update_option( self::OPTION, $data, false );

		return $data;
	}

	/**
	 * Enabled, with a recurrence rule this class can follow.
	 *
	 * @param array<string,mixed> $scan Scan from the client.
	 */
	private static function is_recurring( array $scan ): bool {
		if ( empty( $scan['enabled'] ) ) {
			return false;
		}

		$rule = self::parse_rule( (string) ( $scan['rrules'] ?? '' ) );

		return null !== $rule && '' !== self::start_of( $scan );
	}

	/**
	 * Median length of completed real runs, or the default.
	 *
	 * Agent scan histories list rolling windows under placeholder ids
	 * (`00000000-…`); those are not runs and are not measured.
	 *
	 * @param array<int,array<string,mixed>> $runs Runs.
	 */
	private static function typical_duration( array $runs ): int {
		$lengths = array();

		foreach ( $runs as $run ) {
			if ( 'completed' !== $run['status'] || str_starts_with( (string) $run['uuid'], '00000000-' ) ) {
				continue;
			}

			$length = (int) $run['end'] - (int) $run['start'];

			if ( $length > 0 && $length < 2 * DAY_IN_SECONDS ) {
				$lengths[] = $length;
			}
		}

		if ( ! $lengths ) {
			return self::DEFAULT_DURATION;
		}

		sort( $lengths );

		return (int) $lengths[ intdiv( count( $lengths ), 2 ) ];
	}

	/**
	 * Start time of a real run still in progress, or 0.
	 *
	 * @param array<int,array<string,mixed>> $runs Runs.
	 */
	private static function running_since( array $runs ): int {
		foreach ( $runs as $run ) {
			if ( str_starts_with( (string) $run['uuid'], '00000000-' ) ) {
				continue;
			}

			if ( in_array( (string) $run['status'], array( 'running', 'pending', 'processing', 'initializing', 'publishing', 'resuming', 'paused' ), true ) ) {
				return (int) $run['start'];
			}
		}

		return 0;
	}

	/* =================================================================
	 * Which schedule, and when
	 * ============================================================== */

	/**
	 * Picker options: recurring scans by id.
	 *
	 * @return array<string,string>
	 */
	public static function options(): array {
		$out = array();

		foreach ( self::data()['scans'] as $scan ) {
			$out[ (string) $scan['id'] ] = sprintf( '%1$s (%2$s)', (string) $scan['name'], self::describe_rule( $scan ) );
		}

		return $out;
	}

	/**
	 * The schedule chosen for an asset type, or null.
	 *
	 * @return array<string,mixed>|null
	 */
	public static function for_type( VulnHub_Tenable_Connector $connector, string $type ): ?array {
		$id = $connector->schedule_for_type( $type );

		return $id ? ( self::data()['scans'][ $id ] ?? null ) : null;
	}

	/**
	 * When to check after this schedule's first run that starts at or after
	 * `$anchor`.
	 *
	 * @return array{at:int,start:int,due:bool}|null Null when no run is coming.
	 */
	public static function check_after( array $scan, int $anchor, int $now ): ?array {
		$start = self::next_start( $scan, $anchor );

		if ( ! $start ) {
			return null;
		}

		$at = self::morning_after( $start + (int) $scan['duration'] );

		// A run that is visibly still going waits, however long it takes.
		$running = (int) ( $scan['running'] ?? 0 );
		$busy    = $running && abs( $running - $start ) < 6 * HOUR_IN_SECONDS;

		return array(
			'at'    => $at,
			'start' => $start,
			'due'   => $now >= $at && ! $busy,
		);
	}

	/**
	 * 10:00 site time on the day after `$ts`.
	 */
	public static function morning_after( int $ts ): int {
		$day = ( new DateTimeImmutable( '@' . $ts ) )->setTimezone( wp_timezone() )->modify( '+1 day' );

		return $day->setTime( self::CHECK_HOUR, 0 )->getTimestamp();
	}

	/**
	 * 10:00 site time on a Y-m-d date.
	 */
	public static function morning_of( string $date ): int {
		$day = DateTimeImmutable::createFromFormat( 'Y-m-d H:i', $date . ' 00:00', wp_timezone() );

		return $day ? $day->setTime( self::CHECK_HOUR, 0 )->getTimestamp() : 0;
	}

	/* =================================================================
	 * Recurrence
	 * ============================================================== */

	/**
	 * First run start at or after `$from`, looking up to 400 days ahead.
	 */
	public static function next_start( array $scan, int $from ): int {
		$rule  = self::parse_rule( (string) $scan['rrules'] );
		$start = self::start_of( $scan );

		if ( null === $rule || '' === $start ) {
			return 0;
		}

		$tz    = self::zone( (string) $scan['timezone'] );
		$first = DateTimeImmutable::createFromFormat( 'Ymd\THis', $start, $tz );

		if ( ! $first ) {
			return 0;
		}

		$time = array( (int) $first->format( 'H' ), (int) $first->format( 'i' ), (int) $first->format( 's' ) );
		$day  = ( new DateTimeImmutable( '@' . max( $from, $first->getTimestamp() ) ) )->setTimezone( $tz )->setTime( 0, 0 );

		for ( $i = 0; $i < 400; $i++, $day = $day->modify( '+1 day' ) ) {
			if ( ! self::matches( $rule, $first, $day ) ) {
				continue;
			}

			$run = $day->setTime( $time[0], $time[1], $time[2] )->getTimestamp();

			if ( $run >= $from && $run >= $first->getTimestamp() ) {
				return $run;
			}
		}

		return 0;
	}

	/**
	 * @return array{freq:string,interval:int,byday:array<int,array{0:int,1:string}>,bymonthday:int[]}|null
	 */
	private static function parse_rule( string $rrules ): ?array {
		$parts = array();

		foreach ( explode( ';', strtoupper( $rrules ) ) as $pair ) {
			if ( str_contains( $pair, '=' ) ) {
				[ $k, $v ]   = explode( '=', $pair, 2 );
				$parts[ $k ] = $v;
			}
		}

		$freq = (string) ( $parts['FREQ'] ?? '' );

		if ( ! in_array( $freq, array( 'DAILY', 'WEEKLY', 'MONTHLY' ), true ) ) {
			return null;
		}

		$byday = array();

		foreach ( array_filter( explode( ',', (string) ( $parts['BYDAY'] ?? '' ) ) ) as $token ) {
			if ( preg_match( '/^([+-]?\d)?(MO|TU|WE|TH|FR|SA|SU)$/', $token, $m ) ) {
				$byday[] = array( (int) ( $m[1] ?? 0 ), $m[2] );
			}
		}

		return array(
			'freq'       => $freq,
			'interval'   => max( 1, (int) ( $parts['INTERVAL'] ?? 1 ) ),
			'byday'      => $byday,
			'bymonthday' => array_values( array_filter( array_map( 'intval', explode( ',', (string) ( $parts['BYMONTHDAY'] ?? '' ) ) ) ) ),
		);
	}

	/**
	 * Whether a run falls on `$day`.
	 *
	 * @param array<string,mixed> $rule Parsed rule.
	 */
	private static function matches( array $rule, DateTimeImmutable $first, DateTimeImmutable $day ): bool {
		$dow = strtoupper( substr( $day->format( 'D' ), 0, 2 ) );

		switch ( $rule['freq'] ) {
			case 'DAILY':
				$days = (int) floor( ( $day->getTimestamp() - $first->setTime( 0, 0 )->getTimestamp() + 7200 ) / DAY_IN_SECONDS );
				return 0 === $days % $rule['interval'];

			case 'WEEKLY':
				$weekdays = $rule['byday'] ? array_map( static fn( array $d ): string => $d[1], $rule['byday'] ) : array( strtoupper( substr( $first->format( 'D' ), 0, 2 ) ) );
				if ( ! in_array( $dow, $weekdays, true ) ) {
					return false;
				}
				$weeks = (int) floor( ( $day->modify( 'monday this week' )->getTimestamp() - $first->modify( 'monday this week' )->setTime( 0, 0 )->getTimestamp() + 7200 ) / WEEK_IN_SECONDS );
				return 0 === $weeks % $rule['interval'];

			case 'MONTHLY':
				$months = ( (int) $day->format( 'Y' ) - (int) $first->format( 'Y' ) ) * 12 + (int) $day->format( 'n' ) - (int) $first->format( 'n' );
				if ( 0 !== $months % $rule['interval'] ) {
					return false;
				}
				if ( $rule['bymonthday'] ) {
					return in_array( (int) $day->format( 'j' ), $rule['bymonthday'], true );
				}
				foreach ( $rule['byday'] as [ $nth, $weekday ] ) {
					if ( $weekday !== $dow ) {
						continue;
					}
					$from_start = intdiv( (int) $day->format( 'j' ) - 1, 7 ) + 1;
					$from_end   = -( intdiv( (int) $day->format( 't' ) - (int) $day->format( 'j' ), 7 ) + 1 );
					if ( 0 === $nth || $nth === $from_start || $nth === $from_end ) {
						return true;
					}
				}
				return ! $rule['byday'] && (int) $day->format( 'j' ) === (int) $first->format( 'j' );
		}

		return false;
	}

	/**
	 * @param array<string,mixed> $scan Scan.
	 */
	private static function start_of( array $scan ): string {
		$start = (string) ( $scan['starttime'] ?? '' );

		return preg_match( '/^\d{8}T\d{6}$/', $start ) ? $start : '';
	}

	private static function zone( string $name ): DateTimeZone {
		try {
			return '' !== $name ? new DateTimeZone( $name ) : wp_timezone();
		} catch ( \Exception $e ) {
			return wp_timezone();
		}
	}

	/**
	 * "weekly on Sun at 01:00", for pickers.
	 *
	 * @param array<string,mixed> $scan Scan.
	 */
	public static function describe_rule( array $scan ): string {
		$rule  = self::parse_rule( (string) $scan['rrules'] );
		$first = DateTimeImmutable::createFromFormat( 'Ymd\THis', self::start_of( $scan ), self::zone( (string) $scan['timezone'] ) );

		if ( null === $rule || ! $first ) {
			return __( 'no repeating schedule', 'vulnhub' );
		}

		$names = array( 'MO' => 'Mon', 'TU' => 'Tue', 'WE' => 'Wed', 'TH' => 'Thu', 'FR' => 'Fri', 'SA' => 'Sat', 'SU' => 'Sun' );
		$days  = implode( ', ', array_map( static fn( array $d ): string => ( $d[0] ? $d[0] . ' ' : '' ) . $names[ $d[1] ], $rule['byday'] ) );
		$every = 1 === $rule['interval'] ? strtolower( $rule['freq'] ) : sprintf( 'every %d %s', $rule['interval'], array( 'DAILY' => 'days', 'WEEKLY' => 'weeks', 'MONTHLY' => 'months' )[ $rule['freq'] ] );

		return trim( sprintf( '%1$s%2$s at %3$s %4$s', $every, '' !== $days ? ' on ' . $days : '', $first->format( 'H:i' ), $first->getTimezone()->getName() ) );
	}
}
