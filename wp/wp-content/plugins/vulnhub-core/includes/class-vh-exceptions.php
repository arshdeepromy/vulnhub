<?php
/**
 * Vulnerability exception / risk acceptance register.
 *
 * Two kinds of row share it. Finding exceptions (scope finding, asset, vuln,
 * team, bundled) stamp exception_id onto findings and take them out of the
 * open counts. Security exceptions (scope `policy`) are decisions about a
 * control or a policy -- a firewall allow-list, offshore working, a legacy
 * cipher -- that have no finding behind them: they never touch a finding,
 * and are usually decided in a Jira service request and recorded here with
 * record().
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
			'withdrawn' => __( 'Withdrawn', 'vulnhub' ),
			'closed'    => __( 'Closed, no decision recorded', 'vulnhub' ),
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
			'bundled' => __( 'Every bundled library or file in one application, now and as found', 'vulnhub' ),
			'policy'  => __( 'A security policy or control (no findings)', 'vulnhub' ),
		);
	}

	/**
	 * Scopes that suppress findings. A `policy` exception never does.
	 */
	public static function is_finding_scope( string $scope_type ): bool {
		return 'policy' !== $scope_type;
	}

	/**
	 * Where a human opens the exception's Jira ticket: the site the Jira
	 * connector is configured for. No connector, no link -- never a guess.
	 */
	public static function jira_url( string $key ): string {
		$key = strtoupper( trim( $key ) );
		if ( ! preg_match( '/^[A-Z][A-Z0-9_]{0,30}-\d{1,9}$/', $key ) || ! function_exists( 'vulnhub' ) ) {
			return '';
		}

		$jira = vulnhub()->connectors->get( 'jira' );
		if ( ! $jira || ! method_exists( $jira, 'client' ) || ( method_exists( $jira, 'is_mock' ) && $jira->is_mock() ) ) {
			return '';
		}

		try {
			$site = (string) $jira->client()->site_url();
		} catch ( \Throwable $e ) {
			return '';
		}

		return '' !== $site ? $site . '/browse/' . rawurlencode( $key ) : '';
	}

	/**
	 * Record a security exception decided outside the portal, or correct one.
	 *
	 * The approval for these is given in a Jira service request, by people
	 * who may never sign in here, so the approver, the dates and the
	 * decision are taken as given rather than stamped from the current
	 * user -- that is the difference from create() + decide(). Only the
	 * `policy` scope can be recorded this way, so nothing written here can
	 * ever take a finding out of the open counts.
	 *
	 * @param array<string,mixed> $data Fields.
	 * @param int                 $id   Existing policy exception to update, or 0.
	 * @return array{ok:bool,id:int,message:string}
	 */
	public static function record( array $data, int $id = 0 ): array {
		global $wpdb;

		$fail = static fn( string $m ): array => array( 'ok' => false, 'id' => 0, 'message' => $m );

		if ( $id ) {
			$existing = self::get( $id );
			if ( ! $existing ) {
				return $fail( __( 'Exception not found.', 'vulnhub' ) );
			}
			if ( 'policy' !== (string) $existing['scope_type'] ) {
				return $fail( __( 'Only a security exception can be edited here. Finding exceptions are decided on their own screen.', 'vulnhub' ) );
			}
		}

		$title = trim( sanitize_text_field( (string) ( $data['title'] ?? '' ) ) );
		if ( '' === $title ) {
			return $fail( __( 'Give the exception a title.', 'vulnhub' ) );
		}

		$justification = trim( sanitize_textarea_field( (string) ( $data['justification'] ?? '' ) ) );
		if ( mb_strlen( $justification ) < 20 ) {
			return $fail( __( 'Please give a justification of at least 20 characters — this is the record an auditor will read.', 'vulnhub' ) );
		}

		$status = (string) ( $data['status'] ?? 'pending' );
		if ( ! array_key_exists( $status, self::statuses() ) ) {
			$status = 'pending';
		}

		$reason = (string) ( $data['reason'] ?? 'accepted_risk' );
		if ( ! array_key_exists( $reason, self::reasons() ) ) {
			$reason = 'other';
		}

		$date = static function ( $v ): ?string {
			$v = trim( (string) $v );
			if ( '' === $v ) {
				return null;
			}
			$ts = strtotime( ( preg_match( '/^\d{4}-\d{2}-\d{2}$/', $v ) ? $v . ' 00:00:00' : $v ) . ' UTC' );
			return $ts ? gmdate( 'Y-m-d H:i:s', $ts ) : null;
		};
		$text = static fn( string $k, int $max ): string => mb_substr( sanitize_textarea_field( (string) ( $data[ $k ] ?? '' ) ), 0, $max );
		$name = static fn( string $k ): string => mb_substr( sanitize_text_field( (string) ( $data[ $k ] ?? '' ) ), 0, 190 );

		$keys = array();
		foreach ( preg_split( '/[\s,;]+/', strtoupper( (string) ( $data['jira_key'] ?? '' ) ) ) ?: array() as $k ) {
			if ( preg_match( '/^[A-Z][A-Z0-9_]{0,30}-\d{1,9}$/', $k ) ) {
				$keys[ $k ] = $k;
			}
		}

		$row = array(
			'title'                 => vh_trim( $title, 250 ),
			'scope_type'            => 'policy',
			'scope_ref'             => '',
			'scope_label'           => __( 'Security policy exception', 'vulnhub' ),
			'reason'                => $reason,
			'justification'         => mb_substr( $justification, 0, 8000 ),
			'compensating_controls' => $text( 'compensating_controls', 8000 ),
			'business_impact'       => $text( 'business_impact', 4000 ),
			'status'                => $status,
			'requested_by_name'     => $name( 'requested_by_name' ),
			'approver_name'         => in_array( $status, array( 'pending', 'draft' ), true ) ? '' : $name( 'approver_name' ),
			'decision_note'         => $text( 'decision_note', 900 ),
			'jira_key'              => mb_substr( implode( ', ', $keys ), 0, 64 ),
			'expires_at'            => $date( $data['expires_at'] ?? '' ),
			'review_at'             => $date( $data['review_at'] ?? '' ),
			'requested_at'          => $date( $data['requested_at'] ?? '' ) ?? ( $id ? $existing['requested_at'] : vh_now() ),
			'decided_at'            => in_array( $status, array( 'pending', 'draft' ), true ) ? null : $date( $data['decided_at'] ?? '' ),
			'revoked_at'            => in_array( $status, array( 'revoked', 'withdrawn' ), true ) ? $date( $data['revoked_at'] ?? '' ) : null,
			'affected_count'        => 0,
			'updated_at'            => vh_now(),
		);

		if ( $id ) {
			$ok = false !== $wpdb->update( vh_table( 'exceptions' ), $row, array( 'id' => $id ) );
		} else {
			$row['reference']  = self::next_reference();
			$row['created_at'] = vh_now();
			$ok                = (bool) $wpdb->insert( vh_table( 'exceptions' ), $row );
			$id                = $ok ? (int) $wpdb->insert_id : 0;
		}

		if ( ! $ok || ! $id ) {
			return $fail( __( 'Could not save the exception.', 'vulnhub' ) );
		}

		$saved = self::get( $id );

		vulnhub()->logger->audit(
			isset( $existing ) ? 'exception.record_updated' : 'exception.recorded',
			sprintf(
				/* translators: 1: reference, 2: title, 3: status. */
				__( 'Security exception %1$s recorded: %2$s (%3$s)', 'vulnhub' ),
				(string) ( $saved['reference'] ?? '' ),
				$row['title'],
				self::statuses()[ $status ] ?? $status
			),
			'exception',
			$id,
			array(
				'status'   => $status,
				'approver' => $row['approver_name'],
				'jira'     => $row['jira_key'],
				'before'   => isset( $existing ) ? (string) $existing['status'] : '',
			)
		);

		self::changed();

		return array(
			'ok'      => true,
			'id'      => $id,
			'message' => __( 'Security exception saved.', 'vulnhub' ),
		);
	}

	/**
	 * The application a `bundled` exception is keyed on, as its slug.
	 *
	 * The request form is launched from a finding, so the reference may be a
	 * finding id: the exception then covers the application that finding's
	 * component ships in, and only if it is a component at all. A slug is
	 * taken as given (the By-product row links with one).
	 */
	private static function bundled_slug( string $ref ): string {
		global $wpdb;

		if ( ctype_digit( $ref ) ) {
			return (string) $wpdb->get_var(
				$wpdb->prepare(
					'SELECT ' . Repo::product_group_slug_sql( 'f', 'v' ) . ' FROM ' . vh_table( 'findings' ) . ' f
					 INNER JOIN ' . vh_table( 'vulns' ) . ' v ON v.id = f.vuln_id
					 WHERE f.id = %d AND ' . Repo::bundled_sql( 'f', 'v' ), // phpcs:ignore
					(int) $ref
				)
			);
		}

		return sanitize_title( $ref );
	}

	private static function next_reference(): string {
		global $wpdb;
		// The highest number in use, not the row count: a deleted row would
		// otherwise hand out a reference that already exists.
		$n = (int) $wpdb->get_var( 'SELECT COALESCE( MAX( CAST( SUBSTRING( reference, 5 ) AS UNSIGNED ) ), 0 ) FROM ' . vh_table( 'exceptions' ) . " WHERE LEFT( reference, 4 ) = 'EXC-'" ) + 1;
		return sprintf( 'EXC-%04d', $n );
	}

	/**
	 * Create an exception request.
	 *
	 * @param array<string,mixed> $data Fields.
	 * @return array{ok:bool,id:int,message:string}
	 */
	/**
	 * An exception was created, decided or revoked.
	 *
	 * Every one of those can change which findings count as open -- that is
	 * what `exception_id = 0` in every headline count means -- and none of
	 * them told the caches: the dashboard kept showing the finding as open
	 * until some unrelated sync happened to move the stamp. Busting
	 * 'findings' moves the global stamp too, so the exception widgets and
	 * the cached summary and grouped pages all follow; the warm then
	 * re-renders on cron instead of in front of the next reader.
	 */
	private static function changed(): void {
		if ( class_exists( '\\VulnHub_Dash_Widgets' ) ) {
			\VulnHub_Dash_Widgets::bust( 'findings' );
			\VulnHub_Dash_Widgets::queue_warm();
		}
	}

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
		if ( 'bundled' === $scope_type ) {
			$scope_ref = self::bundled_slug( $scope_ref );
			if ( '' === $scope_ref ) {
				return array(
					'ok'      => false,
					'id'      => 0,
					'message' => __( 'That finding is not a library or file bundled inside another application, so there is no application to scope this exception to.', 'vulnhub' ),
				);
			}
		}
		$label = self::describe_scope( $scope_type, $scope_ref );

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

		self::changed();

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

		self::changed();

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

		self::changed();

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
	 * Extend every active exception to findings that arrived after it was
	 * approved.
	 *
	 * apply() runs once, at approval, so a scope that reads as "this
	 * vulnerability everywhere" or "every bundled library in Zoom" stopped at
	 * the findings that existed that day: the next scan's new copy came in
	 * open. Additive only -- it never detaches or moves a finding from one
	 * exception to another; revocation and expiry still go through apply()
	 * and the nightly sweep.
	 *
	 * @return int Findings newly covered.
	 */
	public static function reapply_active(): int {
		global $wpdb;

		$rows = (array) $wpdb->get_results(
			$wpdb->prepare(
				'SELECT * FROM ' . vh_table( 'exceptions' ) . " WHERE status = 'approved' AND ( expires_at IS NULL OR expires_at > %s ) ORDER BY id ASC",
				vh_now()
			),
			ARRAY_A
		);

		$total = 0;
		foreach ( $rows as $exception ) {
			$where = self::scope_where( $exception );
			if ( ! $where ) {
				continue;
			}

			$added = (int) $wpdb->query(
				$wpdb->prepare(
					'UPDATE ' . vh_table( 'findings' ) . ' f
					 INNER JOIN ' . vh_table( 'assets' ) . " a ON a.id = f.asset_id
					 SET f.exception_id = %d, f.updated_at = %s
					 WHERE f.state IN ('open','reopened') AND f.exception_id = 0 AND {$where['sql']}", // phpcs:ignore
					(int) $exception['id'],
					vh_now(),
					...$where['params']
				)
			);

			if ( $added > 0 ) {
				$total += $added;
				self::refresh_affected( (int) $exception['id'] );
			}
		}

		if ( $total > 0 ) {
			Repo::recalculate_asset_rollups();
			vulnhub()->logger->audit(
				'exception.extended',
				sprintf(
					/* translators: %d: number of findings. */
					_n( '%d new finding covered by an existing exception', '%d new findings covered by existing exceptions', $total, 'vulnhub' ),
					$total
				),
				'exception',
				'',
				array( 'count' => $total )
			);
		}

		return $total;
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
			case 'bundled':
				// Exactly the orange segment of one By-product row: attributed
				// to that product (the row's own grouping) and a component
				// (bundled_sql(), the rule `comp=bundled` filters by). Correlated rather than
				// joined: apply() and refresh_affected() join only assets.
				if ( '' === (string) $exception['scope_ref'] ) {
					return null;
				}
				return array(
					'sql'    => 'EXISTS ( SELECT 1 FROM ' . vh_table( 'vulns' ) . ' v WHERE v.id = f.vuln_id AND ' . Repo::product_group_slug_sql( 'f', 'v' ) . ' = %s AND ' . Repo::bundled_sql( 'f', 'v' ) . ' )',
					'params' => array( (string) $exception['scope_ref'] ),
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
			case 'bundled':
				global $wpdb;
				$app = (string) $wpdb->get_var( $wpdb->prepare( 'SELECT ' . Repo::product_group_name_sql( 'f', 'v' ) . ' FROM ' . vh_table( 'findings' ) . ' f INNER JOIN ' . vh_table( 'vulns' ) . ' v ON v.id = f.vuln_id WHERE ' . Repo::product_group_slug_sql( 'f', 'v' ) . ' = %s LIMIT 1', $ref ) ); // phpcs:ignore
				return sprintf(
					/* translators: %s: application name. */
					__( 'Bundled libraries and files in %s', 'vulnhub' ),
					'' !== $app ? $app : $ref
				);
			case 'policy':
				return __( 'Security policy exception', 'vulnhub' );
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
		if ( ! empty( $args['scope'] ) ) {
			// 'policy' = security exceptions; 'findings' = everything else.
			$where[] = 'policy' === $args['scope'] ? "scope_type = 'policy'" : "scope_type <> 'policy'";
		}
		if ( ! empty( $args['jira_key'] ) ) {
			$where[]  = 'LOCATE( %s, jira_key ) > 0';
			$params[] = strtoupper( (string) $args['jira_key'] );
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
			$wpdb->prepare( "SELECT * FROM {$t} WHERE {$where_sql} ORDER BY FIELD(status,'pending','approved','draft','rejected','expired','revoked','withdrawn','closed'), COALESCE(decided_at, requested_at) DESC, id DESC LIMIT %d OFFSET %d", ...$qp ), // phpcs:ignore
			ARRAY_A
		);

		return array(
			'rows'  => $rows,
			'total' => $total,
		);
	}
}

