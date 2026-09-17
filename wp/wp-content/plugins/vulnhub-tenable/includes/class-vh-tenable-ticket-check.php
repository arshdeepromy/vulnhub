<?php
/**
 * Verify tickets on demand, and on their due date.
 *
 * A check is a background job, because the slow parts are Tenable's:
 *
 *   1. refresh   each ticket's status from its ticketing system
 *                (`vulnhub_refresh_ticket`), so a ticket resolved in Jira a
 *                minute ago is judged as resolved
 *   2. scan      Verify only: launch the configured network scan with the
 *                tickets' network-scanned hosts as its only targets, and wait
 *                for it to finish. Agent-based machines are never scanned this
 *                way -- an agent scan cannot be narrowed to single machines --
 *                they are judged on their latest agent results.
 *   3. verify    VulnHub_Tenable_Verifier::check_ticket() for every ticket that
 *                covers findings; asset-list tickets are judged live anyway,
 *                so their check is the status refresh.
 *
 * Jobs advance one step per cron event (the stack's cron loop runs every
 * minute) and store their progress in an option the Tickets page polls. On a
 * ticket's due date an automatic job checks it -- no scan, nothing launched.
 *
 * Nothing here writes to Jira: the status refresh only reads, and whether a
 * check comments on or reopens a ticket is the Jira connector's own setting.
 *
 * @package VulnHub\Tenable
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Ticket check jobs.
 */
final class VulnHub_Tenable_Ticket_Check {

	public const STEP_HOOK = 'vulnhub_ticket_check_step';
	public const DUE_HOOK  = 'vulnhub_ticket_check_due';

	private const OPTION_PREFIX = 'vh_ticket_check_';

	/** A launched scan still running after this long is given up on. */
	private const SCAN_TIMEOUT = 4 * HOUR_IN_SECONDS;

	/** How often a job looks at a running scan. */
	private const SCAN_POLL = 2 * MINUTE_IN_SECONDS;

	/** Most tickets one job takes on. */
	private const MAX_TICKETS = 200;

	public function hooks(): void {
		add_filter( 'vulnhub_start_ticket_check', array( $this, 'start_filter' ), 10, 3 );
		add_filter( 'vulnhub_ticket_check_status', array( $this, 'status_filter' ), 10, 2 );
		add_action( self::STEP_HOOK, array( $this, 'step' ), 10, 1 );
		add_action( self::DUE_HOOK, array( $this, 'run_due' ), 10, 0 );

		add_action(
			'init',
			static function (): void {
				if ( ! wp_next_scheduled( self::DUE_HOOK ) ) {
					wp_schedule_event( time() + 300, 'hourly', self::DUE_HOOK );
				}
			}
		);
	}

	/* =================================================================
	 * Starting and reading jobs
	 * ============================================================== */

	/**
	 * Answer `vulnhub_start_ticket_check`.
	 *
	 * @param array<string,mixed>|null $result     Result so far.
	 * @param int[]                    $ticket_ids Tickets; empty means every ticket still worth checking.
	 * @param bool                     $rescan     Launch the network rescan (Verify) or not (automatic).
	 * @return array<string,mixed>|null
	 */
	public function start_filter( ?array $result, array $ticket_ids, bool $rescan ): ?array {
		return null !== $result ? $result : $this->start( $ticket_ids, $rescan, 'manual' );
	}

	/**
	 * @param array<string,mixed>|null $result Result so far.
	 * @return array<string,mixed>|null
	 */
	public function status_filter( ?array $result, string $job_id ): ?array {
		return null !== $result ? $result : $this->public_view( $this->load( $job_id ) );
	}

	/**
	 * Queue a check.
	 *
	 * @param int[] $ticket_ids Tickets; empty means every ticket still worth checking.
	 * @return array<string,mixed>
	 */
	public function start( array $ticket_ids, bool $rescan, string $trigger ): array {
		$ids = array_values( array_unique( array_filter( array_map( 'intval', $ticket_ids ) ) ) );
		$ids = $ids ? $ids : $this->worth_checking();
		$ids = array_slice( $ids, 0, self::MAX_TICKETS );

		if ( ! $ids ) {
			return array( 'ok' => false, 'message' => __( 'There are no tickets to check.', 'vulnhub' ) );
		}

		$tickets = array();

		foreach ( $ids as $id ) {
			$row = \VulnHub\Core\Tickets::get( $id );

			if ( $row ) {
				$tickets[ $id ] = array(
					'key'     => (string) $row['external_key'],
					'state'   => 'queued',
					'message' => __( 'Waiting to start…', 'vulnhub' ),
				);
			}
		}

		if ( ! $tickets ) {
			return array( 'ok' => false, 'message' => __( 'Those tickets no longer exist.', 'vulnhub' ) );
		}

		$job = array(
			'id'       => strtolower( wp_generate_password( 16, false, false ) ),
			'trigger'  => $trigger,
			'rescan'   => $rescan,
			'user'     => get_current_user_id(),
			'created'  => time(),
			'phase'    => 'refresh',
			'message'  => __( 'Queued. Checks start within a minute.', 'vulnhub' ),
			'scan'     => null,
			'tickets'  => $tickets,
			'finished' => 0,
		);

		$this->save( $job );
		wp_schedule_single_event( time(), self::STEP_HOOK, array( $job['id'] ) );

		vulnhub()->logger->audit(
			'ticket.check_started',
			sprintf( 'Ticket check started for %d ticket(s)%s', count( $tickets ), $rescan ? ' with a rescan' : '' ),
			'ticket',
			0,
			array( 'job' => $job['id'], 'trigger' => $trigger, 'tickets' => array_keys( $tickets ), 'rescan' => $rescan )
		);

		return array_merge( array( 'ok' => true ), $this->public_view( $job ) );
	}

	/**
	 * Tickets still worth checking: not verified fixed yet, with a key.
	 *
	 * @return int[]
	 */
	private function worth_checking(): array {
		global $wpdb;

		return array_map(
			'intval',
			(array) $wpdb->get_col(
				$wpdb->prepare(
					'SELECT id FROM ' . vh_table( 'tickets' ) . " WHERE external_key <> '' AND verification_state <> %s ORDER BY updated_at ASC LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL
					\VulnHub\Core\Tickets::VERIFY_CONFIRMED,
					self::MAX_TICKETS
				)
			)
		);
	}

	/**
	 * @param array<string,mixed>|null $job Stored job.
	 * @return array<string,mixed>|null
	 */
	private function public_view( ?array $job ): ?array {
		if ( ! $job ) {
			return array( 'ok' => false, 'message' => __( 'That check has expired.', 'vulnhub' ) );
		}

		return array(
			'ok'       => true,
			'job'      => (string) $job['id'],
			'phase'    => (string) $job['phase'],
			'done'     => 'done' === $job['phase'],
			'message'  => (string) $job['message'],
			'tickets'  => $job['tickets'],
			'scan'     => $job['scan'],
		);
	}

	private function load( string $job_id ): ?array {
		$job = get_option( self::OPTION_PREFIX . sanitize_key( $job_id ), null );

		return is_array( $job ) ? $job : null;
	}

	/**
	 * @param array<string,mixed> $job Job.
	 */
	private function save( array $job ): void {
		update_option( self::OPTION_PREFIX . $job['id'], $job, false );
	}

	/* =================================================================
	 * Running a job
	 * ============================================================== */

	public function step( string $job_id = '' ): void {
		$job = $this->load( $job_id );

		if ( ! $job || 'done' === $job['phase'] ) {
			return;
		}

		// One worker per job: the cron loop and a manual run must not both
		// launch the scan.
		$lock = self::OPTION_PREFIX . 'lock_' . $job['id'];

		if ( ! add_option( $lock, (string) time(), '', false ) ) {
			if ( (int) get_option( $lock, 0 ) > time() - 15 * MINUTE_IN_SECONDS ) {
				return;
			}
			update_option( $lock, (string) time(), false );
		}

		try {
			$job = match ( (string) $job['phase'] ) {
				'refresh' => $this->phase_refresh( $job ),
				'scan'    => $this->phase_scan( $job ),
				'verify'  => $this->phase_verify( $job ),
				default   => $job,
			};

			$this->save( $job );

			if ( 'done' !== $job['phase'] ) {
				$delay = 'scan' === $job['phase'] && ! empty( $job['scan']['launched_at'] ) ? self::SCAN_POLL : 0;
				wp_schedule_single_event( time() + $delay, self::STEP_HOOK, array( $job['id'] ) );
			} else {
				$job['finished'] = time();
				$this->save( $job );
				$this->forget_old();
			}
		} catch ( \Throwable $e ) {
			$job['phase']   = 'done';
			/* translators: %s: error. */
			$job['message'] = sprintf( __( 'The check stopped: %s', 'vulnhub' ), $e->getMessage() );
			$this->save( $job );
		} finally {
			delete_option( $lock );
		}
	}

	/**
	 * @param array<string,mixed> $job Job.
	 * @return array<string,mixed>
	 */
	private function phase_refresh( array $job ): array {
		foreach ( array_keys( $job['tickets'] ) as $id ) {
			$ticket = \VulnHub\Core\Tickets::get( (int) $id );

			if ( ! $ticket ) {
				$job['tickets'][ $id ] = array_merge( $job['tickets'][ $id ], array( 'state' => 'error', 'message' => __( 'The ticket no longer exists.', 'vulnhub' ) ) );
				continue;
			}

			/** This filter is documented in vulnhub-core/includes/class-vh-rest.php */
			$refreshed = apply_filters( 'vulnhub_refresh_ticket', null, $ticket );
			$ticket    = (array) \VulnHub\Core\Tickets::get( (int) $id );

			$job['tickets'][ $id ]['state']   = 'refreshed';
			$job['tickets'][ $id ]['status']  = (string) $ticket['status'];
			if ( null === $refreshed ) {
				/* translators: %s: status name. */
				$message = sprintf( __( 'Status recorded here: %s.', 'vulnhub' ), (string) $ticket['status'] );
			} elseif ( empty( $refreshed['ok'] ) ) {
				/* translators: %s: error. */
				$message = sprintf( __( 'Could not read the status from Jira (%s); checking with the status already recorded.', 'vulnhub' ), vh_trim( (string) ( $refreshed['message'] ?? '' ), 120 ) );
			} else {
				/* translators: %s: status name. */
				$message = sprintf( __( 'Status in Jira: %s.', 'vulnhub' ), (string) $ticket['status'] );
			}

			$job['tickets'][ $id ]['message'] = $message;
		}

		$targets = $job['rescan'] ? $this->network_targets( array_keys( $job['tickets'] ) ) : array();
		$scan_id = $this->connector() ? $this->connector()->rescan_scan_id() : 0;

		if ( $job['rescan'] && $targets && $scan_id ) {
			$job['phase']   = 'scan';
			$job['scan']    = array( 'id' => $scan_id, 'targets' => $targets, 'launched_at' => 0, 'status' => 'launching' );
			/* translators: %d: number of hosts. */
			$job['message'] = sprintf( _n( 'Launching a Tenable rescan of %d network host…', 'Launching a Tenable rescan of %d network hosts…', count( $targets ), 'vulnhub' ), count( $targets ) );
		} else {
			$job['phase']   = 'verify';
			$job['message'] = $job['rescan'] && $targets && ! $scan_id
				? __( 'No rescan scan is chosen in the Tenable settings, so network hosts are checked on their latest scan. Checking…', 'vulnhub' )
				: __( 'Checking findings against Tenable…', 'vulnhub' );
		}

		return $job;
	}

	/**
	 * @param array<string,mixed> $job Job.
	 * @return array<string,mixed>
	 */
	private function phase_scan( array $job ): array {
		$connector = $this->connector();

		if ( ! $connector ) {
			$job['phase'] = 'verify';
			return $job;
		}

		$scan = (array) $job['scan'];

		if ( empty( $scan['launched_at'] ) ) {
			$response = $connector->client()->launch_scan( (int) $scan['id'], (array) $scan['targets'] );

			if ( ! $response->ok() ) {
				$scan['status']  = 'not launched';
				$job['scan']     = $scan;
				$job['phase']    = 'verify';
				$job['message']  = 409 === $response->status
					? __( 'That Tenable scan is already running, so no rescan was started; checking on the latest results.', 'vulnhub' )
					/* translators: 1: HTTP status, 2: error. */
					: sprintf( __( 'Tenable did not start the rescan (HTTP %1$d: %2$s); checking on the latest results.', 'vulnhub' ), $response->status, vh_trim( $response->error_message(), 120 ) );

				return $job;
			}

			$scan['launched_at'] = time();
			$scan['status']      = 'pending';
			$job['scan']         = $scan;
			/* translators: %d: number of hosts. */
			$job['message']      = sprintf( _n( 'Tenable is rescanning %d network host. Results are checked when it finishes.', 'Tenable is rescanning %d network hosts. Results are checked when it finishes.', count( (array) $scan['targets'] ), 'vulnhub' ), count( (array) $scan['targets'] ) );

			vulnhub()->logger->audit( 'ticket.rescan_launched', sprintf( 'Launched Tenable scan %d against %d host(s) to verify tickets', (int) $scan['id'], count( (array) $scan['targets'] ) ), 'ticket', 0, array( 'job' => $job['id'], 'scan' => (int) $scan['id'], 'targets' => $scan['targets'] ) );

			return $job;
		}

		$status         = $connector->client()->scan_latest_status( (int) $scan['id'] );
		$scan['status'] = '' !== $status ? $status : (string) $scan['status'];
		$job['scan']    = $scan;

		$finished = in_array( $status, array( 'completed', 'imported', 'canceled', 'cancelled', 'aborted', 'stopped' ), true );
		$too_long = time() - (int) $scan['launched_at'] > self::SCAN_TIMEOUT;

		if ( $finished || $too_long ) {
			$job['phase']   = 'verify';
			$job['message'] = $too_long && ! $finished
				? __( 'The rescan is taking longer than four hours; checking on the results Tenable has so far.', 'vulnhub' )
				/* translators: %s: scan status. */
				: sprintf( __( 'Rescan %s. Checking findings against Tenable…', 'vulnhub' ), $status );
		} else {
			/* translators: 1: scan status, 2: minutes. */
			$job['message'] = sprintf( __( 'Rescan %1$s (%2$d min so far). Results are checked when it finishes.', 'vulnhub' ), '' !== $status ? $status : __( 'running', 'vulnhub' ), (int) floor( ( time() - (int) $scan['launched_at'] ) / 60 ) );
		}

		return $job;
	}

	/**
	 * @param array<string,mixed> $job Job.
	 * @return array<string,mixed>
	 */
	private function phase_verify( array $job ): array {
		$connector = $this->connector();
		$verifier  = new VulnHub_Tenable_Verifier();

		foreach ( array_keys( $job['tickets'] ) as $id ) {
			if ( 'error' === $job['tickets'][ $id ]['state'] ) {
				continue;
			}

			$ticket = \VulnHub\Core\Tickets::get( (int) $id );

			if ( ! $ticket ) {
				continue;
			}

			// Asset-list tickets are judged against live asset data whenever
			// they are shown; refreshing the status was their check.
			if ( (int) $ticket['asset_count'] > 0 ) {
				$counts = \VulnHub\Core\Tickets::asset_outcomes( $ticket );
				$summary = array(
					'state'    => 'assets',
					'resolved' => 'done' === (string) $ticket['status_category'],
					'fixed'    => (int) $counts['resolved'],
					'open'     => (int) $counts['open'],
					'unknown'  => 0,
					'headline' => sprintf(
						/* translators: 1: done, 2: total, 3: outstanding, 4: no longer relevant. */
						__( '%1$d of %2$d assets done, %3$d still outstanding, %4$d no longer relevant.', 'vulnhub' ),
						$counts['resolved'],
						$counts['total'],
						$counts['open'],
						$counts['retired'] + $counts['removed']
					),
				);
				\VulnHub\Core\Tickets::set_last_check( (int) $id, $summary );
			} elseif ( $connector && $connector->is_enabled() ) {
				$summary = $verifier->check_ticket( $connector, $ticket );
			} else {
				$summary = array( 'state' => 'unavailable', 'headline' => __( 'Tenable is not enabled, so findings could not be checked.', 'vulnhub' ) );
			}

			$job['tickets'][ $id ]['state']   = 'checked';
			$job['tickets'][ $id ]['result']  = (string) $summary['state'];
			$job['tickets'][ $id ]['message'] = (string) $summary['headline'];
		}

		$job['phase']   = 'done';
		/* translators: %d: tickets. */
		$job['message'] = sprintf( _n( 'Checked %d ticket.', 'Checked %d tickets.', count( $job['tickets'] ), 'vulnhub' ), count( $job['tickets'] ) );

		return $job;
	}

	/* =================================================================
	 * Due dates
	 * ============================================================== */

	/**
	 * Hourly: check every ticket whose due date has arrived and has not been
	 * checked since. No scan is launched.
	 */
	public function run_due(): void {
		global $wpdb;

		$today = wp_date( 'Y-m-d' );
		$rows  = (array) $wpdb->get_results(
			$wpdb->prepare(
				'SELECT * FROM ' . vh_table( 'tickets' ) . " WHERE external_key <> '' AND verification_state <> %s", // phpcs:ignore WordPress.DB.PreparedSQL
				\VulnHub\Core\Tickets::VERIFY_CONFIRMED
			),
			ARRAY_A
		);

		$due = array();

		foreach ( $rows as $row ) {
			$date = \VulnHub\Core\Tickets::due_date( $row );

			if ( '' === $date || $date > $today ) {
				continue;
			}

			$last = \VulnHub\Core\Tickets::last_check( $row );

			// Already checked on or after its due date: once is the promise.
			if ( $last && ! empty( $last['checked_at'] ) && wp_date( 'Y-m-d', (int) strtotime( (string) $last['checked_at'] . ' UTC' ) ) >= $date ) {
				continue;
			}

			$due[] = (int) $row['id'];
		}

		if ( $due ) {
			$this->start( $due, false, 'due' );
		}
	}

	/* =================================================================
	 * Helpers
	 * ============================================================== */

	private function connector(): ?VulnHub_Tenable_Connector {
		$connector = vulnhub()->connectors->get( 'tenable' );

		return $connector instanceof VulnHub_Tenable_Connector ? $connector : null;
	}

	/**
	 * Network-scanned hosts behind the tickets' findings: not agent-based,
	 * known to Tenable, with an address to aim a scan at.
	 *
	 * @param int[] $ticket_ids Tickets.
	 * @return string[]
	 */
	private function network_targets( array $ticket_ids ): array {
		global $wpdb;

		$ids = array_values( array_filter( array_map( 'intval', $ticket_ids ) ) );

		if ( ! $ids ) {
			return array();
		}

		$rows = (array) $wpdb->get_results(
			'SELECT DISTINCT a.ipv4, a.fqdn, a.hostname
			 FROM ' . vh_table( 'ticket_findings' ) . ' tf
			 JOIN ' . vh_table( 'findings' ) . ' f ON f.id = tf.finding_id
			 JOIN ' . vh_table( 'assets' ) . " a ON a.id = f.asset_id
			 WHERE tf.ticket_id IN (" . implode( ',', $ids ) . ") AND a.has_agent = 0 AND a.tenable_uuid <> ''", // phpcs:ignore WordPress.DB.PreparedSQL
			ARRAY_A
		);

		$targets = array();

		foreach ( $rows as $row ) {
			$target = '' !== (string) $row['ipv4'] ? (string) $row['ipv4'] : ( '' !== (string) $row['fqdn'] ? (string) $row['fqdn'] : '' );

			if ( '' !== $target ) {
				$targets[ $target ] = true;
			}
		}

		return array_keys( $targets );
	}

	/**
	 * Drop finished jobs older than a day.
	 */
	private function forget_old(): void {
		global $wpdb;

		foreach ( (array) $wpdb->get_col( $wpdb->prepare( "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s", $wpdb->esc_like( self::OPTION_PREFIX ) . '%' ) ) as $name ) {
			$job = get_option( $name );

			if ( is_array( $job ) && 'done' === ( $job['phase'] ?? '' ) && (int) ( $job['finished'] ?? 0 ) < time() - DAY_IN_SECONDS ) {
				delete_option( $name );
			}
		}
	}
}
