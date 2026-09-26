<?php
/**
 * Reads what the AWS estate costs and how hard it is actually used.
 *
 * Read-only, through the same SSO session the network sync uses. Per account:
 *
 *  - Cost Explorer: spend by service and usage type (last full month and the
 *    month so far), by record type (what the Savings Plan covered), and a
 *    45-day daily series by service for trends and spikes. Each query is
 *    filtered to the account being read, so an account that can see others
 *    (a payer) is never counted twice.
 *  - EC2: every instance (running and stopped), every volume, every Elastic IP.
 *  - CloudWatch: 14 days of hourly CPU and network for every instance, and
 *    5-minute IOPS / throughput for provisioned-IOPS volumes.
 *  - What schedules instances: Instance Scheduler stacks, EventBridge rules
 *    and EventBridge Scheduler schedules that start or stop things.
 *
 * Then the AWS Price List for exactly the instance types, volume types and
 * addresses it found. Every saving the recommendation engine shows is
 * arithmetic on these numbers; nothing is assumed.
 *
 * Cost Explorer bills $0.01 per request. This reader makes four per account,
 * so a refresh of a 60-account estate costs about $2.40. It runs on demand,
 * never on every sync.
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_AWS_Cost_Collector {

	public const HOOK = 'vulnhub_aws_cost_refresh';

	private const WINDOW_DAYS = 14;
	private const DAILY_DAYS  = 45;

	/** Smallest instance size a "one size down" suggestion will target. */
	private const SIZES = array( 'nano', 'micro', 'small', 'medium', 'large', 'xlarge', '2xlarge', '4xlarge', '8xlarge', '12xlarge', '16xlarge', '24xlarge' );

	/** Previous-generation family => its current-generation equivalent at the same size. */
	public const CURRENT_GEN = array(
		't2' => 't3',
		'm3' => 'm6i',
		'm4' => 'm6i',
		'c3' => 'c6i',
		'c4' => 'c6i',
		'r3' => 'r6i',
		'r4' => 'r6i',
	);

	/** platformDetails => Price List `operation`, the one key that separates OS pricing cleanly. */
	private const OPERATION = array(
		'Linux/UNIX'               => 'RunInstances',
		'Windows'                  => 'RunInstances:0002',
		'Red Hat Enterprise Linux' => 'RunInstances:0010',
		'SUSE Linux'               => 'RunInstances:000g',
		'Ubuntu Pro'               => 'RunInstances:0g00',
	);

	/** @var string[] */
	private array $errors = array();
	private int $ce_calls = 0;
	/** @var array<string,array<string,string>> Credentials already issued this run, per account. */
	private array $creds = array();
	private string $last_error = '';

	public const OPT_AUTO      = 'vulnhub_aws_cost_auto';
	public const OPT_AUTO_LAST = 'vulnhub_aws_cost_auto_last';

	/** Auto-refresh choices: mode => [label, minimum hours between reads]. */
	public const AUTO_MODES = array(
		'daily'  => array( 'After each AWS sync, at most daily', 20 ),
		'weekly' => array( 'After each AWS sync, at most weekly', 160 ),
		'off'    => array( 'Off — refresh by hand', 0 ),
	);

	public static function init(): void {
		add_action( self::HOOK, array( __CLASS__, 'run_job' ) );
		// A successful AWS sync is the one moment the SSO session is known to be
		// good, so that is when a cost read is queued -- rate-limited, because
		// every read costs Cost Explorer requests.
		add_action( 'vulnhub_sync_complete', array( __CLASS__, 'after_sync' ), 20, 2 );
	}

	public static function auto_mode(): string {
		$m = (string) get_option( self::OPT_AUTO, 'daily' );
		return isset( self::AUTO_MODES[ $m ] ) ? $m : 'daily';
	}

	/**
	 * Queue a cost read after a successful AWS sync, unless auto-refresh is
	 * off, a read is already running, or the newest snapshot is still fresh.
	 *
	 * @return string What happened, for the log and the dashboard.
	 */
	public static function after_sync( $connector, $status = '' ): string {
		if ( 'aws' !== (string) $connector ) {
			return 'not aws';
		}
		$why = self::decide_auto( (string) $status );
		update_option( self::OPT_AUTO_LAST, array( 'at' => vh_now(), 'result' => $why ), false );
		return $why;
	}

	private static function decide_auto( string $status ): string {
		if ( 'success' !== $status ) {
			return 'skipped: the AWS sync did not succeed';
		}
		$mode = self::auto_mode();
		if ( 'off' === $mode ) {
			return 'skipped: auto-refresh is off';
		}
		if ( self::is_running() ) {
			return 'skipped: a cost read is already running';
		}
		$last = VulnHub_AWS_Cost_Store::latest();
		$min  = (int) self::AUTO_MODES[ $mode ][1];
		if ( $last && ( time() - (int) strtotime( $last['finished_at'] . ' UTC' ) ) < $min * HOUR_IN_SECONDS ) {
			return sprintf( 'skipped: the last cost read is under %d hours old', $min );
		}
		return self::queue() ? 'queued a cost read' : 'skipped: could not queue';
	}

	/** Is a refresh in flight right now (heartbeat within ten minutes)? */
	public static function is_running(): bool {
		$p = VulnHub_AWS_Cost_Store::progress();
		if ( ! in_array( (string) ( $p['state'] ?? '' ), array( 'queued', 'running' ), true ) ) {
			return false;
		}
		// Queued behind a long sync on the single-flight runner: still pending
		// for as long as the event is on the schedule, however long that is.
		if ( 'queued' === $p['state'] && wp_next_scheduled( self::HOOK ) ) {
			return true;
		}
		$beat = strtotime( (string) ( $p['heartbeat'] ?? '' ) . ' UTC' );
		return $beat && ( time() - $beat ) < 600;
	}

	/** Queue a refresh on the cron runner. False when one is already going. */
	public static function queue(): bool {
		if ( self::is_running() ) {
			return false;
		}
		VulnHub_AWS_Cost_Store::set_progress( array( 'state' => 'queued', 'stage' => __( 'Waiting for the background runner…', 'vulnhub' ), 'done' => 0, 'total' => 0 ) );
		wp_schedule_single_event( time(), self::HOOK );
		return true;
	}

	public static function run_job(): void {
		( new self() )->run();
	}

	/* ================================================================== run */

	/** @return array{ok:bool,message:string} */
	public function run(): array {
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 0 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		}

		$started = vh_now();
		$this->progress( 'running', __( 'Signing in to AWS…', 'vulnhub' ), 0, 0 );

		if ( ! class_exists( 'VulnHub_AWS_Connector' ) ) {
			return $this->fail( $started, __( 'The AWS integration is not loaded.', 'vulnhub' ) );
		}

		$session = ( new VulnHub_AWS_Connector() )->read_session();
		$token   = (array) $session['token'];
		$regions = (array) $session['regions'];

		if ( empty( $token['accessToken'] ) ) {
			return $this->fail( $started, __( 'The AWS SSO session has expired — sign in again on the AWS integration, then refresh.', 'vulnhub' ) );
		}

		$sso      = new VulnHub_AWS_SSO( (string) $token['region'] );
		$accounts = $sso->list_accounts( (string) $token['accessToken'] );

		if ( ! $accounts ) {
			return $this->fail( $started, __( 'The AWS SSO login returned no accounts.', 'vulnhub' ) );
		}

		$tz   = wp_timezone();
		$end  = gmdate( 'Y-m-d\TH:00:00\Z' );
		$beg  = gmdate( 'Y-m-d\TH:00:00\Z', strtotime( $end ) - self::WINDOW_DAYS * DAY_IN_SECONDS );
		$lm0  = gmdate( 'Y-m-01', strtotime( 'first day of last month' ) );
		$m0   = gmdate( 'Y-m-01' );
		$day  = gmdate( 'Y-m-d' );
		$dim  = (int) gmdate( 't' );

		$data = array(
			'version'     => 1,
			'generated'   => vh_now(),
			'timezone'    => $tz->getName(),
			'regions'     => $regions,
			'window'      => array( 'start' => $beg, 'end' => $end, 'possible' => $this->possible_hours( $beg, $end, $tz ) ),
			'periods'     => array(
				'last_month' => array( 'start' => $lm0, 'end' => $m0 ),
				'mtd'        => array( 'start' => $m0, 'end' => $day, 'days_elapsed' => max( 0, (int) gmdate( 'j' ) - 1 ), 'days_in_month' => $dim ),
			),
			'accounts'    => array(),
			'services'    => array(),
			'usage'       => array(),
			'records'     => array(),
			'daily'       => array(),
			'instances'   => array(),
			'volumes'     => array(),
			'eips'        => array(),
			'scheduler'   => array( 'stacks' => array(), 'rules' => array(), 'schedules' => array() ),
			'prices'      => array(),
			'errors'      => array(),
		);

		$total = count( $accounts );
		$i     = 0;

		foreach ( $accounts as $a ) {
			$acct = (string) ( $a['accountId'] ?? '' );
			if ( '' === $acct ) {
				continue;
			}
			++$i;
			$name = (string) ( $a['accountName'] ?? '' );
			/* translators: 1: current, 2: total, 3: account name. */
			$this->progress( 'running', sprintf( __( 'Reading account %1$d of %2$d — %3$s', 'vulnhub' ), $i, $total, $name ?: $acct ), $i - 1, $total );

			$data['accounts'][ $acct ] = array( 'name' => $name, 'cost_ok' => false, 'ec2_ok' => false );

			$cr = $this->credentials( $sso, (string) $token['accessToken'], $acct );
			if ( ! $cr ) {
				$this->err( $acct, 'credentials', $this->last_error ?: 'no readable role' );
				continue;
			}

			$data['accounts'][ $acct ]['cost_ok'] = $this->read_costs( $cr, $acct, $data, $lm0, $m0, $day );

			$client = new VulnHub_AWS_Client( (string) $cr['accessKeyId'], (string) $cr['secretAccessKey'], (string) $cr['sessionToken'], 60 );
			$ec2_ok = true;

			foreach ( $regions as $rg ) {
				$ec2_ok = $this->read_ec2( $client, $cr, $acct, $name, (string) $rg, $data, $beg, $end, $tz ) && $ec2_ok;
				$this->read_schedulers( $client, $cr, $acct, $name, (string) $rg, $data );
			}

			$data['accounts'][ $acct ]['ec2_ok'] = $ec2_ok;
		}

		$this->progress( 'running', __( 'Reading the AWS price list…', 'vulnhub' ), $total, $total );
		// Any account's credentials can read the global price list; reuse one.
		$pricing_cr = $this->creds ? reset( $this->creds ) : null;
		if ( $pricing_cr ) {
			$data['prices'] = $this->read_prices( $pricing_cr, $data, $regions );
		} else {
			$this->err( '', 'pricing', 'no credentials to read the price list' );
		}

		$data['errors']   = $this->errors;
		$data['ce_calls'] = $this->ce_calls;

		$read = count( array_filter( $data['accounts'], static fn( $x ) => ! empty( $x['cost_ok'] ) ) );
		if ( 0 === $read ) {
			return $this->fail( $started, __( 'No account returned Cost Explorer data.', 'vulnhub' ) . ' ' . implode( ' · ', array_slice( $this->errors, 0, 3 ) ) );
		}

		/* translators: 1: accounts with costs, 2: accounts listed, 3: instances. */
		$msg = sprintf( __( 'Read costs for %1$d of %2$d accounts and %3$d instances.', 'vulnhub' ), $read, count( $data['accounts'] ), count( $data['instances'] ) );

		// A partial read must never replace a complete one: to the screens a
		// skipped account looks like an account whose costs vanished, and its
		// suggestions like work that got done. It is kept, labelled, and the
		// last complete read stays current until a full one arrives.
		$gaps = array();
		$bad  = array_filter( $data['accounts'], static fn( $x ) => empty( $x['cost_ok'] ) || empty( $x['ec2_ok'] ) );
		if ( $bad ) {
			/* translators: 1: count, 2: account names. */
			$gaps[] = sprintf( __( '%1$d accounts not fully read (%2$s)', 'vulnhub' ), count( $bad ), implode( ', ', array_slice( array_map( static fn( $x ) => $x['name'], $bad ), 0, 8 ) ) . ( count( $bad ) > 8 ? '…' : '' ) );
		}
		if ( empty( $data['prices']['ec2'] ) || empty( $data['prices']['ebs'] ) ) {
			$gaps[] = __( 'the AWS price list could not be read', 'vulnhub' );
		}
		$prev = VulnHub_AWS_Cost_Store::latest();
		$prev_n = $prev ? count( (array) ( $prev['data']['accounts'] ?? array() ) ) : 0;
		if ( count( $data['accounts'] ) < $prev_n ) {
			/* translators: 1: accounts now, 2: accounts before. */
			$gaps[] = sprintf( __( 'the SSO login listed %1$d accounts, the last complete read had %2$d', 'vulnhub' ), count( $data['accounts'] ), $prev_n );
		}

		if ( $gaps && $prev ) {
			$msg .= ' ' . __( 'Incomplete — kept aside, the last complete read is still shown:', 'vulnhub' ) . ' ' . implode( '; ', $gaps ) . '.';
			VulnHub_AWS_Cost_Store::save( $data, $started, 'partial', $msg );
			VulnHub_AWS_Cost_Store::set_progress( array( 'state' => 'partial', 'stage' => $msg, 'done' => $total, 'total' => $total, 'finished' => vh_now() ) );
			return array( 'ok' => false, 'message' => $msg );
		}
		if ( $gaps ) {
			// The very first read: better shown, clearly flagged, than nothing.
			$msg .= ' ' . implode( '; ', $gaps ) . '.';
		}

		VulnHub_AWS_Cost_Store::save( $data, $started, 'ok', $msg );
		VulnHub_AWS_Cost_Store::set_progress( array( 'state' => 'done', 'stage' => $msg, 'done' => $total, 'total' => $total, 'finished' => vh_now() ) );

		return array( 'ok' => true, 'message' => $msg );
	}

	/* ============================================================ plumbing */

	private function progress( string $state, string $stage, int $done, int $total ): void {
		VulnHub_AWS_Cost_Store::set_progress( array( 'state' => $state, 'stage' => $stage, 'done' => $done, 'total' => $total ) );
	}

	/** @return array{ok:bool,message:string} */
	private function fail( string $started, string $msg ): array {
		VulnHub_AWS_Cost_Store::save( array( 'errors' => $this->errors ), $started, 'failed', $msg );
		VulnHub_AWS_Cost_Store::set_progress( array( 'state' => 'failed', 'stage' => $msg, 'finished' => vh_now() ) );
		return array( 'ok' => false, 'message' => $msg );
	}

	private function err( string $acct, string $what, string $msg ): void {
		$this->errors[] = trim( $acct . ' ' . $what . ': ' . mb_substr( $msg, 0, 200 ) );
	}

	/** @return array<string,string>|null */
	private function credentials( VulnHub_AWS_SSO $sso, string $token, string $acct ): ?array {
		if ( '' === $acct ) {
			return null;
		}
		if ( isset( $this->creds[ $acct ] ) ) {
			return $this->creds[ $acct ];
		}
		// The SSO portal throttles, and a throttled call looks exactly like an
		// account with no roles. Back off and ask again before believing it.
		$roles = array();
		for ( $try = 0; $try < 5 && ! $roles; $try++ ) {
			if ( $try ) {
				sleep( min( 16, 2 ** $try ) );
			}
			$roles = $sso->list_roles( $token, $acct );
		}
		$role  = '';
		foreach ( array( 'ReadOnlyAccess', 'ViewOnlyAccess', 'SecurityAudit' ) as $pref ) {
			if ( in_array( $pref, $roles, true ) ) {
				$role = $pref;
				break;
			}
		}
		$role = $role ?: (string) ( $roles[0] ?? '' );
		if ( '' === $role ) {
			$this->last_error = 'no role assigned';
			return null;
		}
		$cr = array();
		for ( $try = 0; $try < 4 && empty( $cr['accessKeyId'] ); $try++ ) {
			if ( $try ) {
				sleep( min( 16, 2 ** $try ) );
			}
			$cr = $sso->role_credentials( $token, $acct, $role );
		}
		if ( empty( $cr['accessKeyId'] ) ) {
			$this->last_error = (string) ( $cr['_error'] ?? 'no credentials' );
			return null;
		}
		return $this->creds[ $acct ] = array(
			'accessKeyId'     => (string) $cr['accessKeyId'],
			'secretAccessKey' => (string) $cr['secretAccessKey'],
			'sessionToken'    => (string) $cr['sessionToken'],
			'role'            => $role,
		);
	}

	/**
	 * A signed JSON-protocol call (Cost Explorer, Price List, EventBridge).
	 *
	 * @param array<string,string> $cr
	 * @param array<string,mixed>  $body
	 * @return array{ok:bool,status:int,data:array<string,mixed>,error:string}
	 */
	private function jcall( array $cr, string $service, string $region, string $host, string $target, array $body ): array {
		$url  = 'https://' . $host . '/';
		$json = (string) wp_json_encode( $body );
		$h    = VulnHub_AWS_SigV4::headers( 'POST', $url, $json, array( 'content-type' => 'application/x-amz-json-1.1', 'x-amz-target' => $target ), $region, $service, $cr['accessKeyId'], $cr['secretAccessKey'], $cr['sessionToken'] );
		$r    = wp_remote_post( $url, array( 'headers' => $h, 'body' => $json, 'timeout' => 60 ) );
		return $this->decode( $r );
	}

	/** @param array<string,string> $cr @return array{ok:bool,status:int,data:array<string,mixed>,error:string} */
	private function rest_get( array $cr, string $service, string $region, string $url ): array {
		$h = VulnHub_AWS_SigV4::headers( 'GET', $url, '', array(), $region, $service, $cr['accessKeyId'], $cr['secretAccessKey'], $cr['sessionToken'] );
		$r = wp_remote_get( $url, array( 'headers' => $h, 'timeout' => 60 ) );
		return $this->decode( $r );
	}

	/** @param array|\WP_Error $r @return array{ok:bool,status:int,data:array<string,mixed>,error:string} */
	private function decode( $r ): array {
		if ( is_wp_error( $r ) ) {
			return array( 'ok' => false, 'status' => 0, 'data' => array(), 'error' => $r->get_error_message() );
		}
		$s = (int) wp_remote_retrieve_response_code( $r );
		$d = json_decode( (string) wp_remote_retrieve_body( $r ), true );
		$d = is_array( $d ) ? $d : array();
		if ( $s >= 200 && $s < 300 ) {
			return array( 'ok' => true, 'status' => $s, 'data' => $d, 'error' => '' );
		}
		$type = explode( ':', (string) wp_remote_retrieve_header( $r, 'x-amzn-errortype' ) )[0];
		return array( 'ok' => false, 'status' => $s, 'data' => $d, 'error' => trim( $type . ' ' . (string) ( $d['message'] ?? $d['Message'] ?? '' ) ) );
	}

	/**
	 * Cost Explorer with back-off on throttling, following every page.
	 * Returns null (never a partial list) when any page fails.
	 *
	 * @param array<string,string> $cr
	 * @param array<string,mixed>  $body
	 * @return array<int,array<string,mixed>>|null ResultsByTime entries.
	 */
	private function ce( array $cr, array $body ): ?array {
		$out = array();
		$tok = null;
		do {
			if ( $tok ) {
				$body['NextPageToken'] = $tok;
			}
			$page = null;
			for ( $try = 0; $try < 6; $try++ ) {
				++$this->ce_calls;
				$r = $this->jcall( $cr, 'ce', 'us-east-1', 'ce.us-east-1.amazonaws.com', 'AWSInsightsIndexService.GetCostAndUsage', $body );
				if ( $r['ok'] ) {
					$page = $r['data'];
					break;
				}
				$this->last_error = $r['error'];
				if ( 0 === $r['status'] || $r['status'] >= 500 || preg_match( '/Throttl|LimitExceeded|TooManyRequests|RequestLimit/i', $r['error'] ) ) {
					sleep( min( 30, 2 ** ( $try + 1 ) ) );
					continue;
				}
				return null;
			}
			if ( null === $page ) {
				return null;
			}
			foreach ( (array) ( $page['ResultsByTime'] ?? array() ) as $rt ) {
				$out[] = (array) $rt;
			}
			$tok = $page['NextPageToken'] ?? null;
		} while ( $tok );

		return $out;
	}

	/* ================================================================ costs */

	/** @param array<string,string> $cr @param array<string,mixed> $data */
	private function read_costs( array $cr, string $acct, array &$data, string $lm0, string $m0, string $day ): bool {
		$filter = array( 'Dimensions' => array( 'Key' => 'LINKED_ACCOUNT', 'Values' => array( $acct ) ) );
		$ok     = true;

		foreach ( array( 'last_month' => array( $lm0, $m0 ), 'mtd' => array( $m0, $day ) ) as $per => $p ) {
			if ( $p[0] >= $p[1] ) {
				$data['services'][ $per ][ $acct ] = array();
				continue;
			}
			$res = $this->ce(
				$cr,
				array(
					'TimePeriod'  => array( 'Start' => $p[0], 'End' => $p[1] ),
					'Granularity' => 'MONTHLY',
					'Metrics'     => array( 'UnblendedCost', 'UsageQuantity' ),
					'Filter'      => $filter,
					'GroupBy'     => array( array( 'Type' => 'DIMENSION', 'Key' => 'SERVICE' ), array( 'Type' => 'DIMENSION', 'Key' => 'USAGE_TYPE' ) ),
				)
			);
			if ( null === $res ) {
				$this->err( $acct, 'cost ' . $per, $this->last_error );
				$ok = false;
				continue;
			}
			$svc  = array();
			$rows = array();
			foreach ( $res as $rt ) {
				foreach ( (array) ( $rt['Groups'] ?? array() ) as $g ) {
					$c = (float) ( $g['Metrics']['UnblendedCost']['Amount'] ?? 0 );
					$s = (string) $g['Keys'][0];
					$svc[ $s ] = ( $svc[ $s ] ?? 0 ) + $c;
					// Totals above keep every cent; the detail keeps the rows worth reading.
					if ( abs( $c ) >= 1 ) {
						$rows[] = array( $s, (string) $g['Keys'][1], round( $c, 2 ), round( (float) ( $g['Metrics']['UsageQuantity']['Amount'] ?? 0 ), 2 ), (string) ( $g['Metrics']['UsageQuantity']['Unit'] ?? '' ) );
					}
				}
			}
			$data['services'][ $per ][ $acct ] = array_map( static fn( $v ) => round( $v, 2 ), $svc );
			$data['usage'][ $per ][ $acct ]    = $rows;
		}

		// What the Savings Plan covered versus what was billed on demand.
		$res = $this->ce(
			$cr,
			array(
				'TimePeriod'  => array( 'Start' => $lm0, 'End' => $m0 ),
				'Granularity' => 'MONTHLY',
				'Metrics'     => array( 'UnblendedCost' ),
				'Filter'      => $filter,
				'GroupBy'     => array( array( 'Type' => 'DIMENSION', 'Key' => 'RECORD_TYPE' ), array( 'Type' => 'DIMENSION', 'Key' => 'SERVICE' ) ),
			)
		);
		if ( null === $res ) {
			$this->err( $acct, 'record types', $this->last_error );
			$ok = false;
		} else {
			$rec = array();
			foreach ( $res as $rt ) {
				foreach ( (array) ( $rt['Groups'] ?? array() ) as $g ) {
					$c = (float) ( $g['Metrics']['UnblendedCost']['Amount'] ?? 0 );
					if ( abs( $c ) >= 0.01 ) {
						$rec[] = array( (string) $g['Keys'][0], (string) $g['Keys'][1], round( $c, 2 ) );
					}
				}
			}
			$data['records'][ $acct ] = $rec;
		}

		// Daily by service, for the trend and for spikes.
		$res = $this->ce(
			$cr,
			array(
				'TimePeriod'  => array( 'Start' => gmdate( 'Y-m-d', time() - self::DAILY_DAYS * DAY_IN_SECONDS ), 'End' => $day ),
				'Granularity' => 'DAILY',
				'Metrics'     => array( 'UnblendedCost' ),
				'Filter'      => $filter,
				'GroupBy'     => array( array( 'Type' => 'DIMENSION', 'Key' => 'SERVICE' ) ),
			)
		);
		if ( null === $res ) {
			$this->err( $acct, 'daily', $this->last_error );
			$ok = false;
		} else {
			$daily = array();
			foreach ( $res as $rt ) {
				$d = (string) ( $rt['TimePeriod']['Start'] ?? '' );
				foreach ( (array) ( $rt['Groups'] ?? array() ) as $g ) {
					$c = (float) ( $g['Metrics']['UnblendedCost']['Amount'] ?? 0 );
					if ( abs( $c ) >= 0.05 ) {
						$daily[ $d ][ (string) $g['Keys'][0] ] = round( ( $daily[ $d ][ (string) $g['Keys'][0] ] ?? 0 ) + $c, 2 );
					}
				}
			}
			$data['daily'][ $acct ] = $daily;
		}

		return $ok;
	}

	/* ================================================================== EC2 */

	/**
	 * @param array<string,string> $cr
	 * @param array<string,mixed>  $data
	 */
	private function read_ec2( VulnHub_AWS_Client $client, array $cr, string $acct, string $name, string $rg, array &$data, string $beg, string $end, \DateTimeZone $tz ): bool {
		$ok  = true;
		$ids = array();

		// Instances, every state, every page -- or none at all.
		$found = array();
		$tok   = '';
		do {
			$p = array( 'Action' => 'DescribeInstances', 'Version' => '2016-11-15', 'MaxResults' => '1000' );
			if ( '' !== $tok ) {
				$p['NextToken'] = $tok;
			}
			$r = $client->query( 'ec2', $rg, $p );
			if ( ! $r['ok'] ) {
				$this->err( $acct, 'instances ' . $rg, (string) $r['error'] );
				return false;
			}
			foreach ( $r['xml']->reservationSet->item as $res ) {
				foreach ( $res->instancesSet->item as $in ) {
					$iid  = (string) $in->instanceId;
					$tags = self::tags( $in );
					$why  = (string) $in->stateReason->message . ' ' . (string) $in->reason;
					$stop = '';
					if ( preg_match( '/\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) GMT\)/', (string) $in->reason, $m ) ) {
						$stop = $m[1];
					}
					$found[ $iid ] = array(
						'id'           => $iid,
						'account'      => $acct,
						'account_name' => $name,
						'region'       => $rg,
						'name'         => (string) ( $tags['Name'] ?? '' ),
						'type'         => (string) $in->instanceType,
						'state'        => (string) $in->instanceState->name,
						'platform'     => (string) $in->platformDetails,
						'launch'       => (string) $in->launchTime,
						'stopped_at'   => 'stopped' === (string) $in->instanceState->name ? $stop : '',
						'reason'       => trim( $why ),
						'lifecycle'    => (string) $in->instanceLifecycle,
						'tags'         => array_map( static fn( $v ) => mb_substr( (string) $v, 0, 200 ), $tags ),
						'ebs'          => array(),
						'metrics'      => null,
					);
					$ids[] = $iid;
				}
			}
			$tok = (string) ( $r['xml']->nextToken ?? '' );
		} while ( '' !== $tok );

		// Volumes, every state.
		$vols = array();
		$tok  = '';
		do {
			$p = array( 'Action' => 'DescribeVolumes', 'Version' => '2016-11-15', 'MaxResults' => '500' );
			if ( '' !== $tok ) {
				$p['NextToken'] = $tok;
			}
			$r = $client->query( 'ec2', $rg, $p );
			if ( ! $r['ok'] ) {
				$this->err( $acct, 'volumes ' . $rg, (string) $r['error'] );
				$ok = false;
				break;
			}
			foreach ( $r['xml']->volumeSet->item as $v ) {
				$vid        = (string) $v->volumeId;
				$att        = (string) ( $v->attachmentSet->item->instanceId ?? '' );
				$vols[ $vid ] = array(
					'id'         => $vid,
					'account'    => $acct,
					'account_name' => $name,
					'region'     => $rg,
					'gb'         => (int) $v->size,
					'type'       => (string) $v->volumeType,
					'iops'       => (int) $v->iops,
					'throughput' => (int) $v->throughput,
					'state'      => (string) $v->status,
					'instance'   => $att,
					'created'    => (string) $v->createTime,
					'name'       => (string) ( self::tags( $v )['Name'] ?? '' ),
				);
				if ( '' !== $att && isset( $found[ $att ] ) ) {
					$found[ $att ]['ebs'][] = $vid;
				}
			}
			$tok = (string) ( $r['xml']->nextToken ?? '' );
		} while ( '' !== $tok );

		// Elastic IPs.
		$r = $client->query( 'ec2', $rg, array( 'Action' => 'DescribeAddresses', 'Version' => '2016-11-15' ) );
		if ( $r['ok'] ) {
			foreach ( $r['xml']->addressesSet->item as $e ) {
				$data['eips'][] = array(
					'account'      => $acct,
					'account_name' => $name,
					'region'       => $rg,
					'ip'           => (string) $e->publicIp,
					'alloc'        => (string) $e->allocationId,
					'association'  => (string) $e->associationId,
					'instance'     => (string) $e->instanceId,
					'eni'          => (string) $e->networkInterfaceId,
					'name'         => (string) ( self::tags( $e )['Name'] ?? '' ),
				);
			}
		} else {
			$this->err( $acct, 'addresses ' . $rg, (string) $r['error'] );
			$ok = false;
		}

		// Instance usage, 14 days hourly.
		$metrics = $this->instance_metrics( $client, $acct, $rg, $ids, $beg, $end, $tz );
		if ( null === $metrics ) {
			$ok = false;
		} else {
			foreach ( $metrics as $iid => $m ) {
				if ( isset( $found[ $iid ] ) ) {
					$found[ $iid ]['metrics'] = $m;
				}
			}
		}

		// Provisioned-IOPS volumes: what they actually do.
		$pio = array_keys( array_filter( $vols, static fn( $v ) => in_array( $v['type'], array( 'io1', 'io2' ), true ) ) );
		if ( $pio ) {
			$io = $this->volume_metrics( $client, $acct, $rg, $pio, $beg, $end );
			foreach ( (array) $io as $vid => $m ) {
				$vols[ $vid ]['measured'] = $m;
			}
		}

		$data['instances'] += $found;
		$data['volumes']   += $vols;

		return $ok;
	}

	/** @return array<string,string> */
	private static function tags( \SimpleXMLElement $node ): array {
		$out = array();
		if ( isset( $node->tagSet->item ) ) {
			foreach ( $node->tagSet->item as $t ) {
				$out[ trim( (string) $t->key ) ] = (string) $t->value;
			}
		}
		return $out;
	}

	/**
	 * GetMetricData, all pages, as [query id => [timestamp => value]].
	 *
	 * @param array<string,string> $params
	 * @return array<string,array<string,float>>|null
	 */
	private function metric_data( VulnHub_AWS_Client $client, string $acct, string $rg, array $params ): ?array {
		$out = array();
		$tok = '';
		do {
			$p = $params;
			if ( '' !== $tok ) {
				$p['NextToken'] = $tok;
			}
			$r = $client->query( 'monitoring', $rg, $p );
			if ( ! $r['ok'] ) {
				$this->err( $acct, 'cloudwatch ' . $rg, (string) $r['error'] );
				return null;
			}
			$res = $r['xml']->GetMetricDataResult;
			foreach ( $res->MetricDataResults->member as $mm ) {
				$id = (string) $mm->Id;
				$ts = array();
				foreach ( $mm->Timestamps->member as $x ) {
					$ts[] = (string) $x;
				}
				$j = 0;
				foreach ( $mm->Values->member as $x ) {
					if ( isset( $ts[ $j ] ) ) {
						$out[ $id ][ $ts[ $j ] ] = (float) $x;
					}
					++$j;
				}
			}
			$tok = (string) ( $res->NextToken ?? '' );
		} while ( '' !== $tok );

		return $out;
	}

	/**
	 * Hourly CPU (average and maximum) and network (in + out) per instance,
	 * summarised: when it ran (a weekday x hour grid in the site timezone),
	 * how busy it was, and how much it talked.
	 *
	 * @param string[] $ids
	 * @return array<string,array<string,mixed>>|null
	 */
	private function instance_metrics( VulnHub_AWS_Client $client, string $acct, string $rg, array $ids, string $beg, string $end, \DateTimeZone $tz ): ?array {
		$out = array();
		foreach ( array_chunk( $ids, 100 ) as $chunk ) {
			$p   = array( 'Action' => 'GetMetricData', 'Version' => '2010-08-01', 'StartTime' => $beg, 'EndTime' => $end, 'ScanBy' => 'TimestampAscending' );
			$q   = 0;
			$map = array();
			foreach ( $chunk as $ix => $iid ) {
				foreach ( array( array( 'CPUUtilization', 'Average', 'a' ), array( 'CPUUtilization', 'Maximum', 'x' ), array( 'NetworkIn', 'Sum', 'i' ), array( 'NetworkOut', 'Sum', 'o' ) ) as $m ) {
					++$q;
					$qid         = $m[2] . $ix;
					$map[ $qid ] = array( $iid, $m[2] );
					$b           = "MetricDataQueries.member.$q.";
					$p[ $b . 'Id' ]                                        = $qid;
					$p[ $b . 'MetricStat.Metric.Namespace' ]               = 'AWS/EC2';
					$p[ $b . 'MetricStat.Metric.MetricName' ]              = $m[0];
					$p[ $b . 'MetricStat.Metric.Dimensions.member.1.Name' ]  = 'InstanceId';
					$p[ $b . 'MetricStat.Metric.Dimensions.member.1.Value' ] = $iid;
					$p[ $b . 'MetricStat.Period' ]                         = '3600';
					$p[ $b . 'MetricStat.Stat' ]                           = $m[1];
					$p[ $b . 'ReturnData' ]                                = 'true';
				}
			}
			$raw = $this->metric_data( $client, $acct, $rg, $p );
			if ( null === $raw ) {
				return null;
			}
			$series = array();
			foreach ( $raw as $qid => $vals ) {
				if ( isset( $map[ $qid ] ) ) {
					$series[ $map[ $qid ][0] ][ $map[ $qid ][1] ] = $vals;
				}
			}
			foreach ( $chunk as $iid ) {
				$out[ $iid ] = $this->summarise( $series[ $iid ] ?? array(), $tz );
			}
		}
		return $out;
	}

	/**
	 * @param array<string,array<string,float>> $s Series a (cpu avg), x (cpu max), i, o (bytes).
	 * @return array<string,mixed>
	 */
	private function summarise( array $s, \DateTimeZone $tz ): array {
		$a    = (array) ( $s['a'] ?? array() );
		$grid = array_fill( 0, 7, array_fill( 0, 24, 0 ) );
		$b    = array( 'weekend' => array( 0, 0.0, 0.0 ), 'business' => array( 0, 0.0, 0.0 ), 'night' => array( 0, 0.0, 0.0 ) );
		$max  = array();
		$net  = 0.0;
		$cpu  = 0.0;

		foreach ( $a as $ts => $v ) {
			$dt = ( new \DateTimeImmutable( $ts ) )->setTimezone( $tz );
			$wd = (int) $dt->format( 'N' ) - 1;
			$hr = (int) $dt->format( 'G' );
			++$grid[ $wd ][ $hr ];
			$k  = $wd >= 5 ? 'weekend' : ( $hr >= 7 && $hr < 19 ? 'business' : 'night' );
			$n  = (float) ( $s['i'][ $ts ] ?? 0 ) + (float) ( $s['o'][ $ts ] ?? 0 );
			++$b[ $k ][0];
			$b[ $k ][1] += $v;
			$b[ $k ][2] += $n;
			$max[]       = (float) ( $s['x'][ $ts ] ?? $v );
			$net        += $n;
			$cpu        += $v;
		}

		$hours = count( $a );
		sort( $max );
		$buckets = array();
		foreach ( $b as $k => $x ) {
			$buckets[ $k ] = array(
				'hours'     => $x[0],
				'cpu_avg'   => $x[0] ? round( $x[1] / $x[0], 2 ) : null,
				'net_mb_hr' => $x[0] ? round( $x[2] / $x[0] / 1048576, 3 ) : null,
			);
		}

		return array(
			'hours'     => $hours,
			'grid'      => $grid,
			'cpu_avg'   => $hours ? round( $cpu / $hours, 2 ) : null,
			'cpu_p95'   => $hours ? round( $max[ max( 0, (int) ceil( 0.95 * $hours ) - 1 ) ], 1 ) : null,
			'cpu_peak'  => $hours ? round( end( $max ), 1 ) : null,
			'net_mb_hr' => $hours ? round( $net / $hours / 1048576, 3 ) : null,
			'buckets'   => $buckets,
		);
	}

	/**
	 * Measured IOPS and throughput for provisioned-IOPS volumes, as the peak
	 * and 99th percentile of 5-minute averages (short bursts inside a 5-minute
	 * window are averaged away, and the view says so).
	 *
	 * @param string[] $vids
	 * @return array<string,array<string,float|int>>|null
	 */
	private function volume_metrics( VulnHub_AWS_Client $client, string $acct, string $rg, array $vids, string $beg, string $end ): ?array {
		$out = array();
		foreach ( array_chunk( $vids, 25 ) as $chunk ) {
			$p   = array( 'Action' => 'GetMetricData', 'Version' => '2010-08-01', 'StartTime' => $beg, 'EndTime' => $end, 'ScanBy' => 'TimestampAscending' );
			$q   = 0;
			$map = array();
			foreach ( $chunk as $ix => $vid ) {
				foreach ( array( 'VolumeReadOps' => 'r', 'VolumeWriteOps' => 'w', 'VolumeReadBytes' => 'rb', 'VolumeWriteBytes' => 'wb' ) as $metric => $k ) {
					++$q;
					$qid         = $k . $ix;
					$map[ $qid ] = array( $vid, $k );
					$b           = "MetricDataQueries.member.$q.";
					$p[ $b . 'Id' ]                                        = $qid;
					$p[ $b . 'MetricStat.Metric.Namespace' ]               = 'AWS/EBS';
					$p[ $b . 'MetricStat.Metric.MetricName' ]              = $metric;
					$p[ $b . 'MetricStat.Metric.Dimensions.member.1.Name' ]  = 'VolumeId';
					$p[ $b . 'MetricStat.Metric.Dimensions.member.1.Value' ] = $vid;
					$p[ $b . 'MetricStat.Period' ]                         = '300';
					$p[ $b . 'MetricStat.Stat' ]                           = 'Sum';
					$p[ $b . 'ReturnData' ]                                = 'true';
				}
			}
			$raw = $this->metric_data( $client, $acct, $rg, $p );
			if ( null === $raw ) {
				return null;
			}
			$s = array();
			foreach ( $raw as $qid => $vals ) {
				if ( isset( $map[ $qid ] ) ) {
					$s[ $map[ $qid ][0] ][ $map[ $qid ][1] ] = $vals;
				}
			}
			foreach ( $chunk as $vid ) {
				$iops = array();
				$mibs = array();
				$x    = $s[ $vid ] ?? array();
				foreach ( array_keys( (array) ( $x['r'] ?? array() ) + (array) ( $x['w'] ?? array() ) ) as $ts ) {
					$iops[] = ( (float) ( $x['r'][ $ts ] ?? 0 ) + (float) ( $x['w'][ $ts ] ?? 0 ) ) / 300;
					$mibs[] = ( (float) ( $x['rb'][ $ts ] ?? 0 ) + (float) ( $x['wb'][ $ts ] ?? 0 ) ) / 300 / 1048576;
				}
				sort( $iops );
				sort( $mibs );
				$n           = count( $iops );
				$out[ $vid ] = array(
					'points'    => $n,
					'iops_peak' => $n ? (int) ceil( end( $iops ) ) : 0,
					'iops_p99'  => $n ? (int) ceil( $iops[ max( 0, (int) ceil( 0.99 * $n ) - 1 ) ] ) : 0,
					'mibs_peak' => $n ? round( end( $mibs ), 1 ) : 0,
					'mibs_p99'  => $n ? round( $mibs[ max( 0, (int) ceil( 0.99 * $n ) - 1 ) ], 1 ) : 0,
				);
			}
		}
		return $out;
	}

	/** Hours of each kind in the window, so "ran 100% of weekend hours" has a denominator. @return array<string,int> */
	private function possible_hours( string $beg, string $end, \DateTimeZone $tz ): array {
		$out = array( 'weekend' => 0, 'business' => 0, 'night' => 0, 'all' => 0 );
		for ( $t = strtotime( $beg ); $t < strtotime( $end ); $t += HOUR_IN_SECONDS ) {
			$dt = ( new \DateTimeImmutable( '@' . $t ) )->setTimezone( $tz );
			$wd = (int) $dt->format( 'N' );
			$hr = (int) $dt->format( 'G' );
			++$out[ $wd >= 6 ? 'weekend' : ( $hr >= 7 && $hr < 19 ? 'business' : 'night' ) ];
			++$out['all'];
		}
		return $out;
	}

	/* ============================================================ schedulers */

	/** @param array<string,string> $cr @param array<string,mixed> $data */
	private function read_schedulers( VulnHub_AWS_Client $client, array $cr, string $acct, string $name, string $rg, array &$data ): void {
		// Instance Scheduler (the AWS solution) hub and spoke stacks.
		$tok = '';
		do {
			$p = array( 'Action' => 'DescribeStacks', 'Version' => '2010-05-15' );
			if ( '' !== $tok ) {
				$p['NextToken'] = $tok;
			}
			$r = $client->query( 'cloudformation', $rg, $p );
			if ( ! $r['ok'] ) {
				break;
			}
			foreach ( $r['xml']->DescribeStacksResult->Stacks->member as $st ) {
				$desc = (string) $st->Description;
				if ( ! preg_match( '/instance[- ]scheduler|SO0030/i', $desc . ' ' . (string) $st->StackName ) ) {
					continue;
				}
				$params = array();
				foreach ( $st->Parameters->member as $pm ) {
					$params[ (string) $pm->ParameterKey ] = (string) $pm->ParameterValue;
				}
				$ver = preg_match( '/v(\d+\.\d+\.\d+)/', $desc, $m ) ? $m[1] : '';
				$data['scheduler']['stacks'][] = array(
					'account'      => $acct,
					'account_name' => $name,
					'region'       => $rg,
					'stack'        => (string) $st->StackName,
					'status'       => (string) $st->StackStatus,
					'version'      => $ver,
					'role'         => preg_match( '/remote|spoke|cross account/i', $desc ) ? 'spoke' : 'hub',
					'params'       => array_intersect_key( $params, array_flip( array( 'TagName', 'DefaultTimezone', 'SchedulingActive', 'ScheduleEC2', 'ScheduleRds', 'SchedulerFrequency', 'Regions', 'Namespace' ) ) ),
				);
			}
			$tok = (string) ( $r['xml']->DescribeStacksResult->NextToken ?? '' );
		} while ( '' !== $tok );

		// EventBridge rules on a schedule that start or stop things.
		$next = null;
		do {
			$body = array( 'Limit' => 100 );
			if ( $next ) {
				$body['NextToken'] = $next;
			}
			$r = $this->jcall( $cr, 'events', $rg, "events.$rg.amazonaws.com", 'AWSEvents.ListRules', $body );
			if ( ! $r['ok'] ) {
				break;
			}
			foreach ( (array) ( $r['data']['Rules'] ?? array() ) as $ru ) {
				if ( empty( $ru['ScheduleExpression'] ) ) {
					continue;
				}
				$t       = $this->jcall( $cr, 'events', $rg, "events.$rg.amazonaws.com", 'AWSEvents.ListTargetsByRule', array( 'Rule' => $ru['Name'] ) );
				$targets = array();
				foreach ( (array) ( $t['data']['Targets'] ?? array() ) as $x ) {
					$targets[] = (string) $x['Arn'];
				}
				if ( ! self::is_start_stop( (string) $ru['Name'] . ' ' . (string) ( $ru['Description'] ?? '' ) . ' ' . implode( ' ', $targets ) ) ) {
					continue;
				}
				$data['scheduler']['rules'][] = array(
					'account'      => $acct,
					'account_name' => $name,
					'region'       => $rg,
					'name'         => (string) $ru['Name'],
					'expression'   => (string) $ru['ScheduleExpression'],
					'state'        => (string) ( $ru['State'] ?? '' ),
					'description'  => mb_substr( (string) ( $ru['Description'] ?? '' ), 0, 240 ),
					'targets'      => $targets,
				);
			}
			$next = $r['data']['NextToken'] ?? null;
		} while ( $next );

		// EventBridge Scheduler schedules that start or stop instances.
		$url  = "https://scheduler.$rg.amazonaws.com/schedules?MaxResults=100";
		$r    = $this->rest_get( $cr, 'scheduler', $rg, $url );
		$seen = 0;
		while ( $r['ok'] && $seen < 20 ) {
			++$seen;
			foreach ( (array) ( $r['data']['Schedules'] ?? array() ) as $s ) {
				$arn = (string) ( $s['Target']['Arn'] ?? '' );
				if ( ! self::is_start_stop( $arn . ' ' . (string) $s['Name'] ) ) {
					continue;
				}
				$d = $this->rest_get( $cr, 'scheduler', $rg, "https://scheduler.$rg.amazonaws.com/schedules/" . rawurlencode( (string) $s['Name'] ) . '?groupName=' . rawurlencode( (string) ( $s['GroupName'] ?? 'default' ) ) );
				$data['scheduler']['schedules'][] = array(
					'account'      => $acct,
					'account_name' => $name,
					'region'       => $rg,
					'name'         => (string) $s['Name'],
					'state'        => (string) ( $s['State'] ?? '' ),
					'expression'   => (string) ( $d['data']['ScheduleExpression'] ?? '' ),
					'timezone'     => (string) ( $d['data']['ScheduleExpressionTimezone'] ?? '' ),
					'target'       => (string) ( $d['data']['Target']['Arn'] ?? $arn ),
				);
			}
			if ( empty( $r['data']['NextToken'] ) ) {
				break;
			}
			$r = $this->rest_get( $cr, 'scheduler', $rg, $url . '&NextToken=' . rawurlencode( (string) $r['data']['NextToken'] ) );
		}
	}

	/* ================================================================ prices */

	/**
	 * The AWS Price List for what was found. A price that comes back
	 * ambiguous (two different on-demand rates for one key) is stored as null
	 * and every suggestion that would need it is simply not made.
	 *
	 * @param array<string,string> $cr
	 * @param array<string,mixed>  $data
	 * @param string[]             $regions
	 * @return array<string,mixed>
	 */
	private function read_prices( array $cr, array $data, array $regions ): array {
		$out = array( 'ec2' => array(), 'ebs' => array(), 'ipv4_idle_hr' => array(), 'snapshot_gb' => array() );

		// Every instance type seen, plus the one-size-down and current-generation
		// targets a suggestion could name.
		$want = array();
		foreach ( (array) $data['instances'] as $i ) {
			$op = self::OPERATION[ (string) $i['platform'] ] ?? '';
			if ( '' === $op ) {
				continue;
			}
			foreach ( array_filter( array( $i['type'], self::one_size_down( (string) $i['type'] ), self::current_gen( (string) $i['type'] ), self::one_size_down( (string) self::current_gen( (string) $i['type'] ) ) ) ) as $ty ) {
				$want[ $ty . '|' . $op . '|' . $i['region'] ] = array( $ty, $op, $i['region'] );
			}
		}

		foreach ( $want as $key => $w ) {
			$vals = $this->price_values(
				$cr,
				'AmazonEC2',
				array(
					'instanceType'    => $w[0],
					'regionCode'      => $w[2],
					'operation'       => $w[1],
					'tenancy'         => 'Shared',
					'capacitystatus'  => 'Used',
					'preInstalledSw'  => 'NA',
				)
			);
			$vals              = array_values( array_unique( array_map( static fn( $x ) => $x['usd'], $vals ) ) );
			$out['ec2'][ $key ] = 1 === count( $vals ) ? $vals[0] : null;
		}

		foreach ( $regions as $rg ) {
			$rg  = (string) $rg;
			$ebs = array();
			foreach ( array( 'Storage', 'System Operation', 'Provisioned Throughput', 'Storage Snapshot' ) as $fam ) {
				foreach ( $this->price_values( $cr, 'AmazonEC2', array( 'regionCode' => $rg, 'productFamily' => $fam ) ) as $x ) {
					$ut = (string) $x['usagetype'];
					$map = array(
						'EBS:VolumeUsage.gp2'             => 'gp2_gb',
						'EBS:VolumeUsage.gp3'             => 'gp3_gb',
						'EBS:VolumeUsage.piops'           => 'io1_gb',
						'EBS:VolumeUsage.io2'             => 'io2_gb',
						'EBS:VolumeUsage.st1'             => 'st1_gb',
						'EBS:VolumeUsage.sc1'             => 'sc1_gb',
						'EBS:VolumeUsage'                 => 'standard_gb',
						'EBS:VolumeP-IOPS.gp3'            => 'gp3_iops',
						'EBS:VolumeP-IOPS.piops'          => 'io1_iops',
						'EBS:VolumeP-IOPS.io2'            => 'io2_iops',
						'EBS:VolumeP-IOPS.io2.tier2'      => 'io2_iops_t2',
						'EBS:VolumeP-IOPS.io2.tier3'      => 'io2_iops_t3',
						'EBS:VolumeP-Throughput.gp3'      => 'gp3_gibps',
						'EBS:SnapshotUsage'               => 'snapshot_gb',
						'EBS:SnapshotArchiveStorage'      => 'snapshot_archive_gb',
					);
					$suffix = preg_replace( '/^[A-Z0-9]+-/', '', $ut );
					if ( isset( $map[ $suffix ] ) ) {
						$ebs[ $map[ $suffix ] ] = $x['usd'];
					}
				}
			}
			if ( isset( $ebs['gp3_gibps'] ) ) {
				$ebs['gp3_mibps'] = round( $ebs['gp3_gibps'] / 1024, 6 );
			}
			$out['ebs'][ $rg ] = $ebs;

			foreach ( $this->price_values( $cr, 'AmazonVPC', array( 'regionCode' => $rg ) ) as $x ) {
				if ( str_ends_with( (string) $x['usagetype'], 'PublicIPv4:IdleAddress' ) ) {
					$out['ipv4_idle_hr'][ $rg ] = $x['usd'];
				}
			}
		}

		return $out;
	}

	/**
	 * GetProducts, all pages, flattened to on-demand price dimensions.
	 *
	 * @param array<string,string> $cr
	 * @param array<string,string> $filters
	 * @return array<int,array{usagetype:string,usd:float,unit:string}>
	 */
	private function price_values( array $cr, string $svc, array $filters ): array {
		$f = array();
		foreach ( $filters as $k => $v ) {
			$f[] = array( 'Type' => 'TERM_MATCH', 'Field' => $k, 'Value' => $v );
		}
		$out  = array();
		$next = null;
		$page = 0;
		do {
			$body = array( 'ServiceCode' => $svc, 'Filters' => $f, 'MaxResults' => 100 );
			if ( $next ) {
				$body['NextToken'] = $next;
			}
			$r = $this->jcall( $cr, 'pricing', 'us-east-1', 'api.pricing.us-east-1.amazonaws.com', 'AWSPriceListService.GetProducts', $body );
			if ( ! $r['ok'] ) {
				$this->err( '', 'price list ' . $svc, $r['error'] );
				break;
			}
			foreach ( (array) ( $r['data']['PriceList'] ?? array() ) as $pl ) {
				$pj = is_string( $pl ) ? json_decode( $pl, true ) : $pl;
				$ut = (string) ( $pj['product']['attributes']['usagetype'] ?? '' );
				foreach ( (array) ( $pj['terms']['OnDemand'] ?? array() ) as $term ) {
					foreach ( (array) ( $term['priceDimensions'] ?? array() ) as $pd ) {
						$usd = (float) ( $pd['pricePerUnit']['USD'] ?? 0 );
						if ( $usd > 0 ) {
							$out[] = array( 'usagetype' => $ut, 'usd' => $usd, 'unit' => (string) ( $pd['unit'] ?? '' ) );
						}
					}
				}
			}
			$next = $r['data']['NextToken'] ?? null;
		} while ( $next && ++$page < 20 );

		return $out;
	}

	/* =============================================================== helpers */

	public static function one_size_down( string $type ): string {
		if ( ! preg_match( '/^([a-z0-9-]+)\.([a-z0-9]+)$/', $type, $m ) ) {
			return '';
		}
		$ix = array_search( $m[2], self::SIZES, true );
		// Never below "small": the smallest sizes are burst-credit machines whose behaviour changes, not just their price.
		if ( false === $ix || $ix <= 2 ) {
			return '';
		}
		return $m[1] . '.' . self::SIZES[ $ix - 1 ];
	}

	public static function current_gen( string $type ): string {
		if ( ! preg_match( '/^([a-z0-9]+)\.([a-z0-9]+)$/', $type, $m ) ) {
			return '';
		}
		return isset( self::CURRENT_GEN[ $m[1] ] ) ? self::CURRENT_GEN[ $m[1] ] . '.' . $m[2] : '';
	}

	/**
	 * Does this rule or schedule start or stop instances? Matched on its
	 * name, description and target: an EC2/RDS start or stop call, a resource
	 * or instance scheduler, or an office-hours rule. A batch job that merely
	 * runs "on a schedule" is not one.
	 */
	public static function is_start_stop( string $text ): bool {
		return (bool) preg_match( '/(start|stop)[-_ ]?(ec2|instances?|rds|db|servers?|vms?)\\b|\\b(ec2|instances?|rds)[-_ ]?(start|stop)|resource[-_ ]?scheduler|instance[-_ ]?scheduler|(off|on)[-_ ]?hours|(start|stop)(Instances|DBInstance)|AWS-(Start|Stop)EC2/i', $text );
	}

	public static function operation( string $platform ): string {
		return self::OPERATION[ $platform ] ?? '';
	}
}

