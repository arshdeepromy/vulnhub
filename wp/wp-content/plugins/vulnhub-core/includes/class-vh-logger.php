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

