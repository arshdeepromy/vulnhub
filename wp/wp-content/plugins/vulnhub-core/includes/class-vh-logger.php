<?php
/**
 * Audit trail and sync-run logging.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Logger {

	/**
	 * Record an auditable action.
	 *
	 * @param array<string,mixed> $detail Structured context.
	 */
	public function audit(
		string $action,
		string $summary,
		string $object_type = '',
		string|int $object_id = '',
		array $detail = array(),
		string $severity = 'info'
	): int {
		global $wpdb;

		$user  = wp_get_current_user();
		$actor = $user && $user->ID ? $user->user_login : ( wp_doing_cron() ? 'system:cron' : 'system' );

		$wpdb->insert(
			vh_table( 'audit' ),
			array(
				'logged_at'   => vh_now(),
				'user_id'     => $user ? (int) $user->ID : 0,
				'actor'       => $actor,
				'action'      => substr( $action, 0, 64 ),
				'object_type' => substr( $object_type, 0, 48 ),
				'object_id'   => substr( (string) $object_id, 0, 64 ),
				'summary'     => substr( $summary, 0, 255 ),
				'detail_json' => $detail ? wp_json_encode( $detail ) : null,
				'ip'          => self::client_ip(),
				'severity'    => $severity,
			)
		);

		return (int) $wpdb->insert_id;
	}

	public static function client_ip(): string {
		$ip = $_SERVER['REMOTE_ADDR'] ?? '';
		return substr( (string) filter_var( $ip, FILTER_VALIDATE_IP ) ?: '', 0, 45 );
	}

	/* -----------------------------------------------------------------
	 * Sync runs
	 * --------------------------------------------------------------- */

	/**
	 * Open a sync run and return its id.
	 */
	public function start_run( string $connector, string $mode = 'scheduled' ): int {
		global $wpdb;

		$wpdb->insert(
			vh_table( 'sync_runs' ),
			array(
				'connector'    => $connector,
				'mode'         => $mode,
				'status'       => 'running',
				'started_at'   => vh_now(),
				'created_at'   => vh_now(),
				'triggered_by' => get_current_user_id(),
				'log_text'     => '',
			)
		);

		return (int) $wpdb->insert_id;
	}

	/**
	 * Append a line to a run's log.
	 */
	public function log_line( int $run_id, string $line ): void {
		global $wpdb;

		if ( ! $run_id ) {
			return;
		}
		$stamp = gmdate( 'H:i:s' );
		$wpdb->query(
			$wpdb->prepare(
				'UPDATE ' . vh_table( 'sync_runs' ) . ' SET log_text = CONCAT(COALESCE(log_text, ""), %s) WHERE id = %d',
				"[{$stamp}] {$line}\n",
				$run_id
			)
		);
	}

	/**
	 * Record live progress on an in-flight run, so a poller can draw a moving
	 * bar and spot a stall. `processed` carries the running count; the stage
	 * and a heartbeat go into stats_json (no schema change), and finish_run
	 * overwrites stats_json with the final tally at the end. The heartbeat is
	 * what tells "still working" from "stopped without saying so": a run whose
	 * heartbeat has gone quiet for too long is reaped as failed.
	 *
	 * @param int    $run_id Run id.
	 * @param int    $done   Records processed so far.
	 * @param string $stage  Human label for the current phase.
	 */
	public function progress( int $run_id, int $done, string $stage = '' ): void {
		global $wpdb;

		if ( ! $run_id ) {
			return;
		}

		$wpdb->update(
			vh_table( 'sync_runs' ),
			array(
				'processed'  => $done,
				'stats_json' => (string) wp_json_encode(
					array(
						'stage'     => $stage,
						'done'      => $done,
						'heartbeat' => vh_now(),
					)
				),
			),
			array( 'id' => $run_id )
		);
	}

	/**
	 * Record two-phase progress for a staged sync (download, then process),
	 * so the card can draw both bars. Same heartbeat contract as progress():
	 * a stall past STALL_SECONDS is reaped as failed.
	 *
	 * @param int                 $run_id Run id.
	 * @param array<string,mixed> $stage  { phase, download{...}, process{...} }.
	 */
	public function stage_progress( int $run_id, array $stage ): void {
		global $wpdb;

		if ( ! $run_id ) {
			return;
		}

		$done              = (int) ( $stage['process']['records_done'] ?? 0 );
		$stage['heartbeat'] = vh_now();

		$wpdb->update(
			vh_table( 'sync_runs' ),
			array(
				'processed'  => $done,
				'stats_json' => (string) wp_json_encode( $stage ),
			),
			array( 'id' => $run_id )
		);
	}

	/**
	 * Close a sync run.
	 *
	 * @param array<string,int|string|array<mixed>> $stats Counters.
	 */
	public function finish_run( int $run_id, string $status, array $stats = array(), string $message = '' ): void {
		global $wpdb;

		if ( ! $run_id ) {
			return;
		}

		$row     = $wpdb->get_row( $wpdb->prepare( 'SELECT started_at FROM ' . vh_table( 'sync_runs' ) . ' WHERE id = %d', $run_id ), ARRAY_A );
		$started = $row['started_at'] ?? vh_now();
		$ms      = max( 0, ( strtotime( vh_now() . ' UTC' ) - strtotime( $started . ' UTC' ) ) * 1000 );

		$wpdb->update(
			vh_table( 'sync_runs' ),
			array(
				'status'      => $status,
				'finished_at' => vh_now(),
				'duration_ms' => $ms,
				'processed'   => (int) ( $stats['processed'] ?? 0 ),
				'created'     => (int) ( $stats['created'] ?? 0 ),
				'updated'     => (int) ( $stats['updated'] ?? 0 ),
				'skipped'     => (int) ( $stats['skipped'] ?? 0 ),
				'failed'      => (int) ( $stats['failed'] ?? 0 ),
				'message'     => substr( $message, 0, 1000 ),
				'stats_json'  => wp_json_encode( $stats ),
			),
			array( 'id' => $run_id )
		);

		$this->audit(
			'sync.' . $status,
			sprintf( '%s sync %s', ucfirst( (string) $wpdb->get_var( $wpdb->prepare( 'SELECT connector FROM ' . vh_table( 'sync_runs' ) . ' WHERE id = %d', $run_id ) ) ), $status ),
			'sync_run',
			$run_id,
			$stats,
			'failed' === $status ? 'error' : 'info'
		);
	}

	/**
	 * Most recent run for a connector.
	 *
	 * @return array<string,mixed>|null
	 */
	public function last_run( string $connector ): ?array {
		global $wpdb;

		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT * FROM ' . vh_table( 'sync_runs' ) . ' WHERE connector = %s ORDER BY id DESC LIMIT 1',
				$connector
			),
			ARRAY_A
		);
		return $row ?: null;
	}

	/**
	 * The most recent run that actually finished -- success or failure -- as
	 * opposed to last_run(), which returns whatever started most recently and
	 * so can hand back a row still 'running' (or one left stranded 'running'
	 * because the process was killed mid-sync before it could write its
	 * finish time). "When did the last sync complete, and how long did it
	 * take?" can only be answered by a row that has a finished_at, which is
	 * exactly what this selects.
	 *
	 * @param string $connector Connector id.
	 * @return array<string,mixed>|null
	 */
	public function last_completed_run( string $connector ): ?array {
		global $wpdb;

		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT * FROM ' . vh_table( 'sync_runs' )
				. " WHERE connector = %s AND finished_at IS NOT NULL AND finished_at <> '0000-00-00 00:00:00'"
				. ' ORDER BY finished_at DESC, id DESC LIMIT 1',
				$connector
			),
			ARRAY_A
		);
		return $row ?: null;
	}

	/** A run with no heartbeat for this long is treated as stalled. */
	private const STALL_SECONDS = 600;

	/**
	 * Live status for a connector's most recent run, for the progress poller.
	 *
	 * When a run is in flight this returns where it is, how fast it is going,
	 * and a rough ETA drawn from the last run that actually finished; when it
	 * has stopped it returns success or failure. A run still marked 'running'
	 * whose heartbeat has been silent past STALL_SECONDS is reaped here: the
	 * PHP process was killed (an OOM on a large export, a container restart)
	 * without ever reaching finish_run, so the row would otherwise sit at
	 * "running" for ever. It is flipped to failed so the truth is visible.
	 *
	 * @param string $connector Connector id.
	 * @return array<string,mixed>
	 */
	public function sync_status( string $connector ): array {
		global $wpdb;

		$run = $this->last_run( $connector );

		if ( ! $run ) {
			return array( 'state' => 'idle' );
		}

		if ( 'running' !== (string) $run['status'] ) {
			return array(
				'state'       => 'success' === (string) $run['status'] ? 'ok' : (string) $run['status'],
				'message'     => (string) ( $run['message'] ?? '' ),
				'finished_at' => (string) ( $run['finished_at'] ?? '' ),
				'duration_ms' => (int) ( $run['duration_ms'] ?? 0 ),
				'processed'   => (int) ( $run['processed'] ?? 0 ),
			);
		}

		$now       = strtotime( vh_now() . ' UTC' );
		$started   = strtotime( (string) $run['started_at'] . ' UTC' ) ?: $now;
		$stats     = json_decode( (string) ( $run['stats_json'] ?? '' ), true );
		$heartbeat = is_array( $stats ) && ! empty( $stats['heartbeat'] )
			? ( strtotime( (string) $stats['heartbeat'] . ' UTC' ) ?: $started )
			: $started;
		$done      = (int) ( $run['processed'] ?? 0 );
		$stage     = is_array( $stats ) ? (string) ( $stats['stage'] ?? '' ) : '';
		$elapsed   = max( 1, $now - $started );
		$hb_age    = max( 0, $now - $heartbeat );

		// Stalled: reap it so it stops claiming to run, and report the truth.
		if ( $hb_age > self::STALL_SECONDS ) {
			// Release the run lock the dead process never got to, so the next
			// "Sync now" is not refused as "already running" for up to 30
			// minutes after the process that held it has gone.
			delete_transient( 'vulnhub_sync_lock_' . $connector );

			$this->finish_run(
				(int) $run['id'],
				'failed',
				array( 'processed' => $done ),
				sprintf(
					/* translators: 1: records imported, 2: minutes idle. */
					__( 'Sync stopped after importing %1$d records (no progress for %2$d minutes) — the process was interrupted. Its progress is checkpointed on disk, so the next sync resumes from where it left off rather than starting over.', 'vulnhub' ),
					$done,
					(int) round( $hb_age / 60 )
				)
			);

			$reaped = $this->last_run( $connector );

			return array(
				'state'       => 'failed',
				'message'     => (string) ( $reaped['message'] ?? '' ),
				'finished_at' => (string) ( $reaped['finished_at'] ?? '' ),
				'duration_ms' => (int) ( $reaped['duration_ms'] ?? 0 ),
				'processed'   => $done,
				'stalled'     => true,
			);
		}

		// Rough total for the bar's scale: the largest import any recent run
		// managed, not merely the last one to finish -- a run reaped at zero
		// records must not flatten the estimate and wipe out the ETA.
		$biggest  = (int) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT MAX(processed) FROM ' . vh_table( 'sync_runs' )
				. " WHERE connector = %s AND finished_at IS NOT NULL",
				$connector
			)
		);
		// Staged sync: prefer the total the download actually measured, and
		// scale the ETA to the processing phase only (download is quick).
		$is_staged = is_array( $stats ) && isset( $stats['phase'] );
		$phase     = $is_staged ? (string) $stats['phase'] : '';
		$rec_total = $is_staged ? (int) ( $stats['process']['records_total'] ?? 0 ) : 0;

		$estimate = $rec_total > 0 ? $rec_total : max( $done, $biggest );
		$rate     = $done / $elapsed;
		$eta      = ( $estimate > $done && $rate > 0 && 'process' === ( $phase ?: 'process' ) ) ? (int) round( ( $estimate - $done ) / $rate ) : null;

		$out = array(
			'state'          => 'running',
			'stage'          => $stage,
			'done'           => $done,
			'estimate'       => $estimate,
			'elapsed'        => $elapsed,
			'rate'           => round( $rate, 1 ),
			'eta'            => $eta,
			'heartbeat_age'  => $hb_age,
			'run_id'         => (int) $run['id'],
			'mode'           => (string) ( $run['mode'] ?? '' ),
		);

		if ( $is_staged ) {
			$out['phase']    = $phase;
			$out['download'] = (array) ( $stats['download'] ?? array() );
			$out['process']  = (array) ( $stats['process'] ?? array() );

			// Give the download bar a rate and, from a comparable past run, a
			// size estimate and ETA -- so "3 GB downloaded at 45 MB/s, ~40%,
			// 2 min left" instead of a bar with no numbers behind it.
			if ( 'download' === $phase ) {
				$dl_bytes = (int) ( $out['download']['bytes'] ?? 0 );
				$is_full  = ! empty( $stats['is_full'] ) || ! empty( $out['download']['is_full'] );
				$est_key  = 'vulnhub_' . ( $is_full ? 'dl_est_full_' : 'dl_est_incr_' ) . $connector;
				$dl_est   = (int) get_option( $est_key, 0 );
				$dl_rate  = $dl_bytes / $elapsed; // bytes/sec

				$out['download']['rate_bps']  = (int) round( $dl_rate );
				$out['download']['est_bytes'] = $dl_est;
				$out['download']['eta']       = ( $dl_est > $dl_bytes && $dl_rate > 0 ) ? (int) round( ( $dl_est - $dl_bytes ) / $dl_rate ) : null;
			}
		}

		return $out;
	}

	/**
	 * Recent runs across all connectors.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public function recent_runs( int $limit = 20, string $connector = '' ): array {
		global $wpdb;

		if ( $connector ) {
			return (array) $wpdb->get_results(
				$wpdb->prepare(
					'SELECT * FROM ' . vh_table( 'sync_runs' ) . ' WHERE connector = %s ORDER BY id DESC LIMIT %d',
					$connector,
					$limit
				),
				ARRAY_A
			);
		}

		return (array) $wpdb->get_results(
			$wpdb->prepare( 'SELECT * FROM ' . vh_table( 'sync_runs' ) . ' ORDER BY id DESC LIMIT %d', $limit ),
			ARRAY_A
		);
	}

	/**
	 * Recent audit entries.
	 *
	 * @param array<string,string|int> $args Filters: action, object_type, user_id, limit, offset.
	 * @return array<int,array<string,mixed>>
	 */
	public function audit_log( array $args = array() ): array {
		global $wpdb;

		$where  = array( '1=1' );
		$params = array();

		if ( ! empty( $args['action'] ) ) {
			$where[]  = 'action LIKE %s';
			$params[] = $wpdb->esc_like( (string) $args['action'] ) . '%';
		}
		if ( ! empty( $args['object_type'] ) ) {
			$where[]  = 'object_type = %s';
			$params[] = $args['object_type'];
		}
		if ( ! empty( $args['search'] ) ) {
			$where[]  = '(summary LIKE %s OR actor LIKE %s)';
			$like     = '%' . $wpdb->esc_like( (string) $args['search'] ) . '%';
			$params[] = $like;
			$params[] = $like;
		}

		$limit  = (int) ( $args['limit'] ?? 50 );
		$offset = (int) ( $args['offset'] ?? 0 );

		$sql      = 'SELECT * FROM ' . vh_table( 'audit' ) . ' WHERE ' . implode( ' AND ', $where ) . ' ORDER BY id DESC LIMIT %d OFFSET %d';
		$params[] = $limit;
		$params[] = $offset;

		return (array) $wpdb->get_results( $wpdb->prepare( $sql, ...$params ), ARRAY_A );
	}

	public function audit_count( array $args = array() ): int {
		global $wpdb;
		unset( $args );
		return (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . vh_table( 'audit' ) );
	}
}

