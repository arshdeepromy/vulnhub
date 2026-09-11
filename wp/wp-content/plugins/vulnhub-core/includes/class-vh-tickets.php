<?php
/**
 * Ticket repository — provider-agnostic, but Jira is the first implementation.
 *
 * A ticket may cover many findings (grouped by asset or by vulnerability),
 * which is why the join table exists.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Tickets {

	public const VERIFY_NOT_REQUIRED = 'not_required';
	public const VERIFY_PENDING      = 'pending';
	public const VERIFY_CONFIRMED    = 'confirmed_fixed';
	public const VERIFY_STILL_OPEN   = 'still_open';
	public const VERIFY_UNKNOWN      = 'unknown';

	/**
	 * @return array<string,string>
	 */
	public static function verification_labels(): array {
		return array(
			self::VERIFY_NOT_REQUIRED => __( 'Not required', 'vulnhub' ),
			self::VERIFY_PENDING      => __( 'Awaiting verification', 'vulnhub' ),
			self::VERIFY_CONFIRMED    => __( 'Verified fixed', 'vulnhub' ),
			self::VERIFY_STILL_OPEN   => __( 'Still detected', 'vulnhub' ),
			self::VERIFY_UNKNOWN      => __( 'Cannot verify', 'vulnhub' ),
		);
	}

	/**
	 * Create or update a ticket row.
	 *
	 * @param array<string,mixed> $data Ticket fields.
	 * @return array{id:int,created:bool}
	 */
	public static function upsert( array $data ): array {
		global $wpdb;

		$table    = vh_table( 'tickets' );
		$provider = (string) ( $data['provider'] ?? 'jira' );
		$key      = (string) ( $data['external_key'] ?? '' );

		$existing = $key
			? $wpdb->get_row( $wpdb->prepare( "SELECT id FROM {$table} WHERE provider = %s AND external_key = %s", $provider, $key ), ARRAY_A )
			: null;

		$row = array( 'provider' => $provider );
		foreach ( array(
			'external_id', 'external_key', 'url', 'project_key', 'issue_type', 'summary',
			'status', 'status_category', 'resolution', 'priority', 'assignee', 'assignee_id',
			'reporter', 'grouping_key', 'created_via', 'verification_state', 'verification_note',
		) as $col ) {
			if ( isset( $data[ $col ] ) ) {
				$row[ $col ] = (string) $data[ $col ];
			}
		}
		foreach ( array( 'team_id', 'asset_id', 'finding_count', 'created_by', 'automation_id' ) as $col ) {
			if ( isset( $data[ $col ] ) ) {
				$row[ $col ] = (int) $data[ $col ];
			}
		}
		foreach ( array( 'verified_at', 'remote_closed_at' ) as $col ) {
			if ( ! empty( $data[ $col ] ) ) {
				$row[ $col ] = vh_to_mysql( $data[ $col ] );
			}
		}
		if ( isset( $data['payload'] ) ) {
			$row['payload_json'] = (string) wp_json_encode( $data['payload'] );
		}

		$row['last_synced_at'] = vh_now();
		$row['updated_at']     = vh_now();

		if ( $existing ) {
			$wpdb->update( $table, $row, array( 'id' => (int) $existing['id'] ) );
			return array(
				'id'      => (int) $existing['id'],
				'created' => false,
			);
		}

		$row['created_at'] = vh_now();
		$wpdb->insert( $table, $row );

		return array(
			'id'      => (int) $wpdb->insert_id,
			'created' => true,
		);
	}

	/**
	 * @return array<string,mixed>|null
	 */
	public static function get( int $id ): ?array {
		global $wpdb;
		if ( ! $id ) {
			return null;
		}
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . vh_table( 'tickets' ) . ' WHERE id = %d', $id ), ARRAY_A );
		return $row ?: null;
	}

	/**
	 * @return array<string,mixed>|null
	 */
	public static function by_key( string $key, string $provider = 'jira' ): ?array {
		global $wpdb;
		$row = $wpdb->get_row(
			$wpdb->prepare( 'SELECT * FROM ' . vh_table( 'tickets' ) . ' WHERE provider = %s AND external_key = %s', $provider, $key ),
			ARRAY_A
		);
		return $row ?: null;
	}

	/**
	 * Attach findings to a ticket and stamp the ticket id onto them.
	 *
	 * @param int[] $finding_ids Finding ids.
	 */
	public static function attach_findings( int $ticket_id, array $finding_ids ): int {
		global $wpdb;

		$attached = 0;
		foreach ( array_unique( array_map( 'intval', $finding_ids ) ) as $fid ) {
			if ( ! $fid ) {
				continue;
			}
			$wpdb->query(
				$wpdb->prepare(
					'INSERT IGNORE INTO ' . vh_table( 'ticket_findings' ) . ' (ticket_id, finding_id, created_at) VALUES (%d, %d, %s)',
					$ticket_id,
					$fid,
					vh_now()
				)
			);
			$wpdb->update(
				vh_table( 'findings' ),
				array(
					'ticket_id'  => $ticket_id,
					'updated_at' => vh_now(),
				),
				array( 'id' => $fid )
			);
			++$attached;
		}

		$wpdb->update(
			vh_table( 'tickets' ),
			array(
				'finding_count' => (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . vh_table( 'ticket_findings' ) . ' WHERE ticket_id = %d', $ticket_id ) ),
				'updated_at'    => vh_now(),
			),
			array( 'id' => $ticket_id )
		);

		return $attached;
	}

	/**
	 * Findings covered by a ticket.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function findings_for( int $ticket_id ): array {
		global $wpdb;

		return (array) $wpdb->get_results(
			$wpdb->prepare(
				'SELECT f.*, a.hostname, a.asset_type, v.title AS vuln_title, v.plugin_id
				 FROM ' . vh_table( 'ticket_findings' ) . ' tf
				 INNER JOIN ' . vh_table( 'findings' ) . ' f ON f.id = tf.finding_id
				 INNER JOIN ' . vh_table( 'assets' ) . ' a ON a.id = f.asset_id
				 INNER JOIN ' . vh_table( 'vulns' ) . ' v ON v.id = f.vuln_id
				 WHERE tf.ticket_id = %d
				 ORDER BY f.severity DESC, a.hostname ASC',
				$ticket_id
			),
			ARRAY_A
		);
	}

	/**
	 * Query tickets.
	 *
	 * @param array<string,mixed> $args Filters.
	 * @return array{rows:array<int,array<string,mixed>>,total:int}
	 */
	public static function query( array $args = array() ): array {
		global $wpdb;

		$t      = vh_table( 'tickets' );
		$where  = array( '1=1' );
		$params = array();

		if ( ! empty( $args['status_category'] ) ) {
			$where[]  = 'status_category = %s';
			$params[] = (string) $args['status_category'];
		}
		if ( ! empty( $args['verification_state'] ) ) {
			$where[]  = 'verification_state = %s';
			$params[] = (string) $args['verification_state'];
		}
		if ( ! empty( $args['team_id'] ) ) {
			$where[]  = 'team_id = %d';
			$params[] = (int) $args['team_id'];
		}
		if ( ! empty( $args['project_key'] ) ) {
			$where[]  = 'project_key = %s';
			$params[] = (string) $args['project_key'];
		}
		if ( ! empty( $args['search'] ) ) {
			$like    = '%' . $wpdb->esc_like( (string) $args['search'] ) . '%';
			$where[] = '(external_key LIKE %s OR summary LIKE %s OR assignee LIKE %s)';
			array_push( $params, $like, $like, $like );
		}
		if ( isset( $args['open'] ) && $args['open'] ) {
			$where[] = "status_category <> 'done'";
		}

		$where_sql = implode( ' AND ', $where );

		$total = (int) ( $params
			? $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$t} WHERE {$where_sql}", ...$params ) ) // phpcs:ignore
			: $wpdb->get_var( "SELECT COUNT(*) FROM {$t} WHERE {$where_sql}" ) ); // phpcs:ignore

		$allowed = array( 'created_at', 'updated_at', 'external_key', 'status', 'finding_count' );
		$orderby = in_array( (string) ( $args['orderby'] ?? '' ), $allowed, true ) ? (string) $args['orderby'] : 'created_at';
		$order   = 'ASC' === strtoupper( (string) ( $args['order'] ?? 'DESC' ) ) ? 'ASC' : 'DESC';
		$limit   = max( 1, min( 300, (int) ( $args['limit'] ?? 50 ) ) );
		$offset  = max( 0, (int) ( $args['offset'] ?? 0 ) );

		$qp   = $params;
		$qp[] = $limit;
		$qp[] = $offset;

		$rows = (array) $wpdb->get_results(
			$wpdb->prepare( "SELECT * FROM {$t} WHERE {$where_sql} ORDER BY {$orderby} {$order} LIMIT %d OFFSET %d", ...$qp ), // phpcs:ignore
			ARRAY_A
		);

		return array(
			'rows'  => $rows,
			'total' => $total,
		);
	}

	/**
	 * Mark a ticket closed remotely and queue it for verification against
	 * the authoritative vulnerability source.
	 */
	public static function mark_closed( int $ticket_id, string $resolution = '' ): void {
		global $wpdb;

		$wpdb->update(
			vh_table( 'tickets' ),
			array(
				'status_category'    => 'done',
				'resolution'         => $resolution,
				'remote_closed_at'   => vh_now(),
				'verification_state' => self::VERIFY_PENDING,
				'updated_at'         => vh_now(),
			),
			array( 'id' => $ticket_id )
		);

		$wpdb->query(
			$wpdb->prepare(
				'UPDATE ' . vh_table( 'findings' ) . " f
				 INNER JOIN " . vh_table( 'ticket_findings' ) . ' tf ON tf.finding_id = f.id
				 SET f.verification_state = %s, f.updated_at = %s
				 WHERE tf.ticket_id = %d',
				self::VERIFY_PENDING,
				vh_now(),
				$ticket_id
			)
		);
	}

	/**
	 * Record the outcome of a verification pass.
	 *
	 * @param array<string,mixed> $detail Extra context for the audit log.
	 */
	public static function record_verification( int $ticket_id, string $state, string $note = '', array $detail = array() ): void {
		global $wpdb;

		$wpdb->update(
			vh_table( 'tickets' ),
			array(
				'verification_state' => $state,
				'verification_note'  => vh_trim( $note, 900 ),
				'verified_at'        => vh_now(),
				'updated_at'         => vh_now(),
			),
			array( 'id' => $ticket_id )
		);

		$ticket = self::get( $ticket_id );

		vulnhub()->logger->audit(
			'ticket.verified.' . $state,
			sprintf(
				/* translators: 1: ticket key, 2: verification outcome. */
				__( 'Ticket %1$s verification: %2$s', 'vulnhub' ),
				$ticket['external_key'] ?? (string) $ticket_id,
				self::verification_labels()[ $state ] ?? $state
			),
			'ticket',
			$ticket_id,
			$detail,
			self::VERIFY_STILL_OPEN === $state ? 'warning' : 'info'
		);
	}

	/**
	 * Tickets closed in Jira and waiting on a Tenable re-check.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function awaiting_verification( int $limit = 50 ): array {
		global $wpdb;

		return (array) $wpdb->get_results(
			$wpdb->prepare(
				'SELECT * FROM ' . vh_table( 'tickets' ) . ' WHERE verification_state = %s ORDER BY remote_closed_at ASC LIMIT %d',
				self::VERIFY_PENDING,
				$limit
			),
			ARRAY_A
		);
	}
}

