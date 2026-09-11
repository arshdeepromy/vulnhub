<?php
/**
 * Vulnerability exception / risk acceptance register.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Exceptions {

	/**
	 * @return array<string,string>
	 */
	public static function statuses(): array {
		return array(
			'draft'    => __( 'Draft', 'vulnhub' ),
			'pending'  => __( 'Pending approval', 'vulnhub' ),
			'approved' => __( 'Approved', 'vulnhub' ),
			'rejected' => __( 'Rejected', 'vulnhub' ),
			'expired'  => __( 'Expired', 'vulnhub' ),
			'revoked'  => __( 'Revoked', 'vulnhub' ),
		);
	}

	/**
	 * @return array<string,string>
	 */
	public static function reasons(): array {
		return array(
			'false_positive'       => __( 'False positive', 'vulnhub' ),
			'compensating_control' => __( 'Compensating control in place', 'vulnhub' ),
			'no_fix_available'     => __( 'No vendor fix available', 'vulnhub' ),
			'business_impact'      => __( 'Fix would break a business process', 'vulnhub' ),
			'end_of_life'          => __( 'Asset is end-of-life / scheduled for decommission', 'vulnhub' ),
			'not_exploitable'      => __( 'Not exploitable in this environment', 'vulnhub' ),
			'accepted_risk'        => __( 'Risk formally accepted', 'vulnhub' ),
			'other'                => __( 'Other', 'vulnhub' ),
		);
	}

	/**
	 * @return array<string,string>
	 */
	public static function scope_types(): array {
		return array(
			'finding' => __( 'A single finding on one asset', 'vulnhub' ),
			'asset'   => __( 'Every finding on one asset', 'vulnhub' ),
			'vuln'    => __( 'One vulnerability across all assets', 'vulnhub' ),
			'team'    => __( 'One vulnerability across a team', 'vulnhub' ),
		);
	}

	private static function next_reference(): string {
		global $wpdb;
		$n = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . vh_table( 'exceptions' ) ) + 1;
		return sprintf( 'EXC-%04d', $n );
	}

	/**
	 * Create an exception request.
	 *
	 * @param array<string,mixed> $data Fields.
	 * @return array{ok:bool,id:int,message:string}
	 */
	public static function create( array $data ): array {
		global $wpdb;

		$scope_type = (string) ( $data['scope_type'] ?? 'finding' );
		if ( ! array_key_exists( $scope_type, self::scope_types() ) ) {
			return array(
				'ok'      => false,
				'id'      => 0,
				'message' => __( 'Unknown exception scope.', 'vulnhub' ),
			);
		}

		$reason = (string) ( $data['reason'] ?? 'other' );
		if ( ! array_key_exists( $reason, self::reasons() ) ) {
			$reason = 'other';
		}

		$justification = trim( (string) ( $data['justification'] ?? '' ) );
		if ( mb_strlen( $justification ) < 20 ) {
			return array(
				'ok'      => false,
				'id'      => 0,
				'message' => __( 'Please give a justification of at least 20 characters — this is the record an auditor will read.', 'vulnhub' ),
			);
		}

		$expires = ! empty( $data['expires_at'] ) ? vh_to_mysql( $data['expires_at'] ) : null;
		if ( $expires && strtotime( $expires . ' UTC' ) < time() ) {
			return array(
				'ok'      => false,
				'id'      => 0,
				'message' => __( 'The expiry date must be in the future.', 'vulnhub' ),
			);
		}

		$user   = wp_get_current_user();
		$status = ! empty( $data['submit'] ) ? 'pending' : 'draft';

		$scope_ref = (string) ( $data['scope_ref'] ?? '' );
		$label     = self::describe_scope( $scope_type, $scope_ref );

		$row = array(
			'reference'             => self::next_reference(),
			'title'                 => vh_trim( (string) ( $data['title'] ?? $label ), 250 ),
			'scope_type'            => $scope_type,
			'scope_ref'             => $scope_ref,
			'scope_label'           => vh_trim( $label, 250 ),
			'asset_id'              => (int) ( $data['asset_id'] ?? 0 ),
			'vuln_id'               => (int) ( $data['vuln_id'] ?? 0 ),
			'team_id'               => (int) ( $data['team_id'] ?? 0 ),
			'severity'              => (string) ( $data['severity'] ?? '' ),
			'reason'                => $reason,
			'justification'         => $justification,
			'compensating_controls' => (string) ( $data['compensating_controls'] ?? '' ),
			'business_impact'       => (string) ( $data['business_impact'] ?? '' ),
			'status'                => $status,
			'requested_by'          => (int) $user->ID,
			'requested_by_name'     => $user->display_name ?: $user->user_login,
			'expires_at'            => $expires,
			'review_at'             => ! empty( $data['review_at'] ) ? vh_to_mysql( $data['review_at'] ) : null,
			'requested_at'          => vh_now(),
			'created_at'            => vh_now(),
			'updated_at'            => vh_now(),
		);

		$wpdb->insert( vh_table( 'exceptions' ), $row );
		$id = (int) $wpdb->insert_id;

		if ( ! $id ) {
			return array(
				'ok'      => false,
				'id'      => 0,
				'message' => __( 'Could not save the exception.', 'vulnhub' ),
			);
		}

		self::refresh_affected( $id );

		vulnhub()->logger->audit(
			'exception.created',
			sprintf(
				/* translators: 1: reference, 2: scope description. */
				__( 'Exception %1$s requested for %2$s', 'vulnhub' ),
				$row['reference'],
				$label
			),
			'exception',
			$id,
			array(
				'scope_type' => $scope_type,
				'scope_ref'  => $scope_ref,
				'reason'     => $reason,
				'status'     => $status,
			)
		);

		return array(
			'ok'      => true,
			'id'      => $id,
			'message' => 'pending' === $status
				? __( 'Exception submitted for approval.', 'vulnhub' )
				: __( 'Exception saved as a draft.', 'vulnhub' ),
		);
	}

	/**
	 * Approve or reject.
	 *
	 * @return array{ok:bool,message:string}
	 */
	public static function decide( int $id, string $decision, string $note = '' ): array {
		global $wpdb;

		$exception = self::get( $id );
		if ( ! $exception ) {
			return array(
				'ok'      => false,
				'message' => __( 'Exception not found.', 'vulnhub' ),
			);
		}
		if ( ! in_array( $decision, array( 'approved', 'rejected' ), true ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'Invalid decision.', 'vulnhub' ),
			);
		}
		if ( ! in_array( $exception['status'], array( 'pending', 'draft' ), true ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'Only a pending exception can be decided.', 'vulnhub' ),
			);
		}

		$user = wp_get_current_user();

		$wpdb->update(
			vh_table( 'exceptions' ),
			array(
				'status'        => $decision,
				'approver_id'   => (int) $user->ID,
				'approver_name' => $user->display_name ?: $user->user_login,
				'decision_note' => vh_trim( $note, 900 ),
				'decided_at'    => vh_now(),
				'updated_at'    => vh_now(),
			),
			array( 'id' => $id )
		);

		self::apply( $id );

		vulnhub()->logger->audit(
			'exception.' . $decision,
			sprintf(
				/* translators: 1: reference, 2: decision. */
				__( 'Exception %1$s %2$s', 'vulnhub' ),
				$exception['reference'],
				$decision
			),
			'exception',
			$id,
			array(
				'note'     => $note,
				'approver' => $user->user_login,
			),
			'approved' === $decision ? 'warning' : 'info'
		);

		return array(
			'ok'      => true,
			'message' => 'approved' === $decision
				? __( 'Exception approved. Matching findings are now suppressed from open counts.', 'vulnhub' )
				: __( 'Exception rejected.', 'vulnhub' ),
		);
	}

	/**
	 * Revoke an approved exception.
	 *
	 * @return array{ok:bool,message:string}
	 */
	public static function revoke( int $id, string $note = '' ): array {
		global $wpdb;

		$exception = self::get( $id );
		if ( ! $exception || 'approved' !== $exception['status'] ) {
			return array(
				'ok'      => false,
				'message' => __( 'Only an approved exception can be revoked.', 'vulnhub' ),
			);
		}

		$wpdb->update(
			vh_table( 'exceptions' ),
			array(
				'status'        => 'revoked',
				'revoked_at'    => vh_now(),
				'decision_note' => vh_trim( $note, 900 ),
				'updated_at'    => vh_now(),
			),
			array( 'id' => $id )
		);

		$wpdb->update(
			vh_table( 'findings' ),
			array(
				'exception_id' => 0,
				'updated_at'   => vh_now(),
			),
			array( 'exception_id' => $id )
		);

		Repo::recalculate_asset_rollups();

		vulnhub()->logger->audit(
			'exception.revoked',
			sprintf(
				/* translators: %s: reference. */
				__( 'Exception %s revoked', 'vulnhub' ),
				$exception['reference']
			),
			'exception',
			$id,
			array( 'note' => $note ),
			'warning'
		);

		return array(
			'ok'      => true,
			'message' => __( 'Exception revoked. Affected findings are back in the open counts.', 'vulnhub' ),
		);
	}

	/**
	 * Stamp exception_id onto every matching finding (approved) or clear it.
	 */
	public static function apply( int $id ): int {
		global $wpdb;

		$exception = self::get( $id );
		if ( ! $exception ) {
			return 0;
		}

		// Always clear first so a scope change does not leave orphans.
		$wpdb->update( vh_table( 'findings' ), array( 'exception_id' => 0 ), array( 'exception_id' => $id ) );

		if ( 'approved' !== $exception['status'] ) {
			Repo::recalculate_asset_rollups();
			return 0;
		}

		$where  = self::scope_where( $exception );
		$count  = 0;
		if ( $where ) {
			$count = (int) $wpdb->query(
				$wpdb->prepare(
					'UPDATE ' . vh_table( 'findings' ) . ' f
					 INNER JOIN ' . vh_table( 'assets' ) . " a ON a.id = f.asset_id
					 SET f.exception_id = %d, f.updated_at = %s
					 WHERE f.state IN ('open','reopened') AND {$where['sql']}", // phpcs:ignore
					$id,
					vh_now(),
					...$where['params']
				)
			);
		}

		$wpdb->update(
			vh_table( 'exceptions' ),
			array(
				'affected_count' => $count,
				'updated_at'     => vh_now(),
			),
			array( 'id' => $id )
		);

		Repo::recalculate_asset_rollups();

		return $count;
	}

	/**
	 * Count what an exception would affect, without applying it.
	 */
	public static function refresh_affected( int $id ): int {
		global $wpdb;

		$exception = self::get( $id );
		if ( ! $exception ) {
			return 0;
		}
		$where = self::scope_where( $exception );
		if ( ! $where ) {
			return 0;
		}

		$count = (int) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(*) FROM ' . vh_table( 'findings' ) . ' f
				 INNER JOIN ' . vh_table( 'assets' ) . " a ON a.id = f.asset_id
				 WHERE f.state IN ('open','reopened') AND {$where['sql']}", // phpcs:ignore
				...$where['params']
			)
		);

		$wpdb->update( vh_table( 'exceptions' ), array( 'affected_count' => $count ), array( 'id' => $id ) );

		return $count;
	}

	/**
	 * Build the WHERE fragment for an exception's scope.
	 *
	 * @param array<string,mixed> $exception Exception row.
	 * @return array{sql:string,params:array<int,int|string>}|null
	 */
	private static function scope_where( array $exception ): ?array {
		switch ( (string) $exception['scope_type'] ) {
			case 'finding':
				return array(
					'sql'    => 'f.id = %d',
					'params' => array( (int) $exception['scope_ref'] ),
				);
			case 'asset':
				return array(
					'sql'    => 'f.asset_id = %d',
					'params' => array( (int) ( $exception['asset_id'] ?: $exception['scope_ref'] ) ),
				);
			case 'vuln':
				return array(
					'sql'    => 'f.vuln_id = %d',
					'params' => array( (int) ( $exception['vuln_id'] ?: $exception['scope_ref'] ) ),
				);
			case 'team':
				return array(
					'sql'    => 'f.vuln_id = %d AND a.team_id = %d',
					'params' => array( (int) $exception['vuln_id'], (int) $exception['team_id'] ),
				);
		}
		return null;
	}

	private static function describe_scope( string $type, string $ref ): string {
		switch ( $type ) {
			case 'finding':
				$f = Repo::finding( (int) $ref );
				if ( ! $f ) {
					return __( 'Unknown finding', 'vulnhub' );
				}
				$a = Repo::asset( (int) $f['asset_id'] );
				$v = Repo::vuln( (int) $f['vuln_id'] );
				return sprintf( '%s on %s', $v['title'] ?? '?', $a['hostname'] ?? '?' );
			case 'asset':
				$a = Repo::asset( (int) $ref );
				return sprintf(
					/* translators: %s: hostname. */
					__( 'All findings on %s', 'vulnhub' ),
					$a['hostname'] ?? '?'
				);
			case 'vuln':
				$v = Repo::vuln( (int) $ref );
				return sprintf(
					/* translators: %s: vulnerability title. */
					__( '%s across all assets', 'vulnhub' ),
					$v['title'] ?? '?'
				);
			case 'team':
				return __( 'Vulnerability scoped to a team', 'vulnhub' );
		}
		return $type;
	}

	/**
	 * @return array<string,mixed>|null
	 */
	public static function get( int $id ): ?array {
		global $wpdb;
		if ( ! $id ) {
			return null;
		}
		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . vh_table( 'exceptions' ) . ' WHERE id = %d', $id ), ARRAY_A );
		return $row ?: null;
	}

	/**
	 * @param array<string,mixed> $args Filters.
	 * @return array{rows:array<int,array<string,mixed>>,total:int}
	 */
	public static function query( array $args = array() ): array {
		global $wpdb;

		$t      = vh_table( 'exceptions' );
		$where  = array( '1=1' );
		$params = array();

		if ( ! empty( $args['status'] ) ) {
			$where[]  = 'status = %s';
			$params[] = (string) $args['status'];
		}
		if ( ! empty( $args['reason'] ) ) {
			$where[]  = 'reason = %s';
			$params[] = (string) $args['reason'];
		}
		if ( ! empty( $args['team_id'] ) ) {
			$where[]  = 'team_id = %d';
			$params[] = (int) $args['team_id'];
		}
		if ( ! empty( $args['requested_by'] ) ) {
			$where[]  = 'requested_by = %d';
			$params[] = (int) $args['requested_by'];
		}
		if ( ! empty( $args['expiring_days'] ) ) {
			$where[]  = "status = 'approved' AND expires_at IS NOT NULL AND expires_at <= %s";
			$params[] = gmdate( 'Y-m-d H:i:s', time() + (int) $args['expiring_days'] * DAY_IN_SECONDS );
		}
		if ( ! empty( $args['search'] ) ) {
			$like    = '%' . $wpdb->esc_like( (string) $args['search'] ) . '%';
			$where[] = '(reference LIKE %s OR title LIKE %s OR justification LIKE %s OR scope_label LIKE %s)';
			array_push( $params, $like, $like, $like, $like );
		}

		$where_sql = implode( ' AND ', $where );

		$total = (int) ( $params
			? $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$t} WHERE {$where_sql}", ...$params ) ) // phpcs:ignore
			: $wpdb->get_var( "SELECT COUNT(*) FROM {$t} WHERE {$where_sql}" ) ); // phpcs:ignore

		$limit  = max( 1, min( 300, (int) ( $args['limit'] ?? 50 ) ) );
		$offset = max( 0, (int) ( $args['offset'] ?? 0 ) );

		$qp   = $params;
		$qp[] = $limit;
		$qp[] = $offset;

		$rows = (array) $wpdb->get_results(
			$wpdb->prepare( "SELECT * FROM {$t} WHERE {$where_sql} ORDER BY FIELD(status,'pending','approved','draft','rejected','expired','revoked'), id DESC LIMIT %d OFFSET %d", ...$qp ), // phpcs:ignore
			ARRAY_A
		);

		return array(
			'rows'  => $rows,
			'total' => $total,
		);
	}
}

