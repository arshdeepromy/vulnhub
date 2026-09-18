<?php
/**
 * Ticket repository — provider-agnostic, but Jira is the first implementation.
 *
 * Two shapes of ticket share this table. A vulnerability ticket covers
 * findings (grouped by asset or by vulnerability), through ticket_findings.
 * A scope ticket -- "onboard these 74 machines to Tenable", "clean these
 * CMDB rows up" -- covers assets, through ticket_assets, and remembers the
 * filter it was raised from so the list can be asked again later.
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

	/** The provider for tickets tracked by hand against Jira Service Management. */
	public const PROVIDER_JSM = 'jsm';

	public const KIND_VULNERABILITY = 'vulnerability';

	/**
	 * What a ticket is asking somebody to do.
	 *
	 * `resolved` names the test that decides, per asset, that the ask has
	 * been met -- see outcome_sql(). A kind with no test (`other`) can still
	 * be tracked; its assets simply never turn green on their own.
	 *
	 * @return array<string,array{label:string,help:string,resolved:string,scope:bool}>
	 */
	public static function kinds(): array {
		return (array) apply_filters(
			'vulnhub_ticket_kinds',
			array(
				self::KIND_VULNERABILITY => array(
					'label'    => __( 'Vulnerability remediation', 'vulnhub' ),
					'help'     => __( 'Findings to fix, verified against the scanner.', 'vulnhub' ),
					'resolved' => '',
					'scope'    => false,
				),
				'tenable_coverage'       => array(
					'label'    => __( 'Tenable coverage', 'vulnhub' ),
					'help'     => __( 'Get these assets scanned. Met once Tenable holds a record of the asset.', 'vulnhub' ),
					'resolved' => 'tenable',
					'scope'    => true,
				),
				'defender_coverage'      => array(
					'label'    => __( 'Defender onboarding', 'vulnhub' ),
					'help'     => __( 'Get the Defender sensor onto these assets. Met once Defender reports the asset onboarded.', 'vulnhub' ),
					'resolved' => 'defender',
					'scope'    => true,
				),
				'cmdb_gap'               => array(
					'label'    => __( 'CMDB gap', 'vulnhub' ),
					'help'     => __( 'Add these assets to the CMDB. Met once the CMDB reports the asset.', 'vulnhub' ),
					'resolved' => 'cmdb',
					'scope'    => true,
				),
				'intune_gap'             => array(
					'label'    => __( 'Intune gap', 'vulnhub' ),
					'help'     => __( 'Enrol these assets in Intune. Met once Intune reports the asset.', 'vulnhub' ),
					'resolved' => 'intune',
					'scope'    => true,
				),
				'cleanup'                => array(
					'label'    => __( 'Clean-up', 'vulnhub' ),
					'help'     => __( 'Retire or remove stale records. Met once the asset is out of service or gone from the inventory.', 'vulnhub' ),
					'resolved' => 'cleanup',
					'scope'    => true,
				),
				'other'                  => array(
					'label'    => __( 'Other request', 'vulnhub' ),
					'help'     => __( 'Anything else. Tracked, but never marked met automatically.', 'vulnhub' ),
					'resolved' => '',
					'scope'    => true,
				),
			)
		);
	}

	public static function kind_label( string $kind ): string {
		return (string) ( self::kinds()[ $kind ]['label'] ?? $kind );
	}

	/**
	 * The statuses a hand-tracked ticket can be moved through, keyed by the
	 * Jira status category they map to -- the same three the poller writes,
	 * so a JSM sync can take these rows over without translating anything.
	 *
	 * @return array<string,string>
	 */
	public static function manual_statuses(): array {
		return array(
			'new'           => __( 'Open', 'vulnhub' ),
			'indeterminate' => __( 'In progress', 'vulnhub' ),
			'done'          => __( 'Done', 'vulnhub' ),
		);
	}

	/**
	 * Per-asset outcomes on a scope ticket, in the order they are shown.
	 *
	 * @return array<string,array{label:string,tone:string}>
	 */
	public static function outcomes(): array {
		return array(
			'open'     => array( 'label' => __( 'Still outstanding', 'vulnhub' ), 'tone' => 'bad' ),
			'resolved' => array( 'label' => __( 'Done', 'vulnhub' ), 'tone' => 'good' ),
			'retired'  => array( 'label' => __( 'No longer matters', 'vulnhub' ), 'tone' => 'neutral' ),
			'removed'  => array( 'label' => __( 'Gone from inventory', 'vulnhub' ), 'tone' => 'neutral' ),
		);
	}

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
			? $wpdb->get_row( $wpdb->prepare( "SELECT id, payload_json FROM {$table} WHERE provider = %s AND external_key = %s", $provider, $key ), ARRAY_A )
			: null;

		$row = array( 'provider' => $provider );
		foreach ( array(
			'external_id', 'external_key', 'url', 'project_key', 'issue_type', 'summary',
			'status', 'status_category', 'resolution', 'priority', 'assignee', 'assignee_id',
			'reporter', 'grouping_key', 'created_via', 'verification_state', 'verification_note',
			'kind', 'source_view', 'notes',
		) as $col ) {
			if ( isset( $data[ $col ] ) ) {
				$row[ $col ] = (string) $data[ $col ];
			}
		}
		foreach ( array( 'team_id', 'asset_id', 'finding_count', 'created_by', 'automation_id', 'asset_count' ) as $col ) {
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
			$payload = (array) $data['payload'];

			// A sync replaces the provider's fields, not the record of the last
			// check, which only this site knows.
			$kept = $existing ? json_decode( (string) $existing['payload_json'], true ) : null;
			foreach ( array( 'last_check', 'next_check', 'last_comment' ) as $own ) {
				if ( is_array( $kept ) && is_array( $kept[ $own ] ?? null ) && ! isset( $payload[ $own ] ) ) {
					$payload[ $own ] = $kept[ $own ];
				}
			}

			$row['payload_json'] = (string) wp_json_encode( $payload );
		}
		if ( isset( $data['scope'] ) ) {
			$row['scope_json'] = (string) wp_json_encode( $data['scope'] );
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

	/** Findings linked per statement. Two statements per finding is a stalled Send. */
	private const ATTACH_BATCH = 500;

	/**
	 * Attach findings to a ticket and stamp the ticket id onto them.
	 *
	 * In batches, because one ticket can legitimately cover thousands of
	 * findings: a statement per finding turns a raise into a browser that
	 * looks hung, and the row count is the same either way.
	 *
	 * @param int[] $finding_ids Finding ids.
	 */
	public static function attach_findings( int $ticket_id, array $finding_ids ): int {
		global $wpdb;

		$ids = array_values( array_filter( array_unique( array_map( 'intval', $finding_ids ) ) ) );

		if ( ! $ids ) {
			return 0;
		}

		$now      = vh_now();
		$attached = 0;

		foreach ( array_chunk( $ids, self::ATTACH_BATCH ) as $chunk ) {
			$values = array();
			$args   = array();

			foreach ( $chunk as $fid ) {
				$values[] = '(%d, %d, %s)';
				$args[]   = $ticket_id;
				$args[]   = $fid;
				$args[]   = $now;
			}

			$wpdb->query(
				$wpdb->prepare(
					'INSERT IGNORE INTO ' . vh_table( 'ticket_findings' ) . ' (ticket_id, finding_id, created_at) VALUES ' . implode( ', ', $values ), // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					...$args
				)
			);

			$wpdb->query(
				$wpdb->prepare(
					'UPDATE ' . vh_table( 'findings' ) . ' SET ticket_id = %d, updated_at = %s WHERE id IN (' . implode( ', ', array_fill( 0, count( $chunk ), '%d' ) ) . ')', // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					$ticket_id,
					$now,
					...$chunk
				)
			);

			$attached += count( $chunk );
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
				'SELECT f.*, a.hostname, a.asset_type, a.operating_system, v.title AS vuln_title, v.plugin_id,
					v.product, v.product_slug, v.product_kind, v.component_class, v.solution, v.patch_publication_date
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
		if ( ! empty( $args['kind'] ) ) {
			$where[]  = 'kind = %s';
			$params[] = (string) $args['kind'];
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
		if ( isset( $args['ids'] ) && is_array( $args['ids'] ) ) {
			$ids     = array_values( array_filter( array_map( 'intval', $args['ids'] ) ) );
			$where[] = $ids ? 'id IN (' . implode( ',', $ids ) . ')' : '1=0';
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

	/* =================================================================
	 * Scope tickets: the assets a ticket was raised about
	 * ============================================================== */

	/**
	 * Record the assets a ticket covers, as they are right now.
	 *
	 * @param array<int,array<string,mixed>> $assets Asset rows from Repo::assets().
	 * @return int Rows written.
	 */
	public static function attach_assets( int $ticket_id, array $assets ): int {
		global $wpdb;

		$table   = vh_table( 'ticket_assets' );
		$written = 0;
		$now     = vh_now();

		foreach ( array_chunk( $assets, 200 ) as $chunk ) {
			$values = array();
			$params = array();

			foreach ( $chunk as $a ) {
				$values[] = '(%d, %d, %s, %s, %s, %s, %s, %s, %s)';
				array_push(
					$params,
					$ticket_id,
					(int) $a['id'],
					(string) ( $a['hostname'] ?? '' ),
					(string) ( $a['asset_type'] ?? '' ),
					(string) ( $a['coverage_state'] ?? '' ),
					(string) ( $a['defender_coverage_state'] ?? '' ),
					(string) ( $a['lifecycle_status'] ?? '' ),
					(string) ( $a['sources_json'] ?? '' ),
					$now
				);
			}

			$written += (int) $wpdb->query(
				$wpdb->prepare(
					"INSERT IGNORE INTO {$table} (ticket_id, asset_id, hostname, asset_type, coverage_state, defender_coverage_state, lifecycle_status, sources_json, created_at) VALUES " . implode( ',', $values ), // phpcs:ignore WordPress.DB.PreparedSQL
					...$params
				)
			);
		}

		$wpdb->update(
			vh_table( 'tickets' ),
			array(
				'asset_count' => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE ticket_id = %d", $ticket_id ) ), // phpcs:ignore WordPress.DB.PreparedSQL
				'updated_at'  => $now,
			),
			array( 'id' => $ticket_id )
		);

		return $written;
	}

	/**
	 * The SQL expression that classifies one ticket asset, as `outcome`.
	 *
	 * Built from constants and escaped state lists only -- no user input and
	 * no `%`, so it is safe to splice into a prepared statement.
	 *
	 * Order matters. Gone-from-inventory first, because there is no asset to
	 * ask anything else of. Then out of service: a decommissioned machine is
	 * not a Tenable gap any more, it is a machine that no longer matters --
	 * except on a clean-up ticket, where leaving service is the whole ask.
	 */
	public static function outcome_sql( string $kind, string $ta = 'ta', string $a = 'a' ): string {
		$in_service = "'" . implode( "','", array_map( 'esc_sql', vh_in_service_statuses() ) ) . "'";
		$test       = (string) ( self::kinds()[ $kind ]['resolved'] ?? '' );

		if ( 'cleanup' === $test ) {
			return "CASE WHEN {$a}.id IS NULL THEN 'resolved'
				WHEN {$a}.lifecycle_status NOT IN ({$in_service}) THEN 'resolved'
				ELSE 'open' END";
		}

		$irrelevant = "{$a}.lifecycle_status NOT IN ({$in_service})";
		$met        = '0';

		switch ( $test ) {
			case 'tenable':
				$irrelevant .= " OR {$a}.coverage_state IN ('" . esc_sql( Coverage::OUT_OF_SCOPE ) . "','" . esc_sql( Coverage::OTHER_DEVICE ) . "')";
				$met         = "{$a}.coverage_state IN (" . Coverage::in_tenable_sql() . ')';
				break;
			case 'defender':
				$irrelevant .= " OR {$a}.defender_coverage_state IN ('" . esc_sql( Defender_Coverage::OUT_OF_SCOPE ) . "','" . esc_sql( Defender_Coverage::OTHER_DEVICE ) . "')";
				$met         = "{$a}.defender_coverage_state IN (" . Defender_Coverage::covered_sql() . ')';
				break;
			case 'cmdb':
			case 'intune':
				// LOCATE, not LIKE: a literal % here is a wpdb placeholder.
				$met = "LOCATE('" . esc_sql( $test ) . "', {$a}.sources_json) > 0";
				break;
		}

		return "CASE WHEN {$a}.id IS NULL THEN 'removed'
			WHEN {$irrelevant} THEN 'retired'
			WHEN {$met} THEN 'resolved'
			ELSE 'open' END";
	}

	/**
	 * How many of a ticket's assets sit in each outcome.
	 *
	 * @return array<string,int> Every key of outcomes(), plus `total`.
	 */
	public static function asset_outcomes( array $ticket ): array {
		global $wpdb;

		$out = array_fill_keys( array_keys( self::outcomes() ), 0 );
		$sql = self::outcome_sql( (string) $ticket['kind'] );

		$rows = (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT {$sql} AS outcome, COUNT(*) AS n
				 FROM " . vh_table( 'ticket_assets' ) . ' ta
				 LEFT JOIN ' . vh_table( 'assets' ) . ' a ON a.id = ta.asset_id
				 WHERE ta.ticket_id = %d
				 GROUP BY outcome', // phpcs:ignore WordPress.DB.PreparedSQL
				(int) $ticket['id']
			),
			ARRAY_A
		);

		foreach ( $rows as $r ) {
			$out[ (string) $r['outcome'] ] = (int) $r['n'];
		}

		$out['total'] = array_sum( $out );

		return $out;
	}

	/**
	 * A page of a ticket's assets: the snapshot beside the asset as it is now.
	 *
	 * @param array<string,mixed> $args outcome, limit, offset.
	 * @return array{rows:array<int,array<string,mixed>>,total:int}
	 */
	public static function assets_for( array $ticket, array $args = array() ): array {
		global $wpdb;

		$sql    = self::outcome_sql( (string) $ticket['kind'] );
		$from   = ' FROM ' . vh_table( 'ticket_assets' ) . ' ta LEFT JOIN ' . vh_table( 'assets' ) . ' a ON a.id = ta.asset_id WHERE ta.ticket_id = %d';
		$params = array( (int) $ticket['id'] );

		$outcome = (string) ( $args['outcome'] ?? '' );

		if ( isset( self::outcomes()[ $outcome ] ) ) {
			$from    .= " AND ({$sql}) = %s";
			$params[] = $outcome;
		}

		$total = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*)' . $from, ...$params ) ); // phpcs:ignore WordPress.DB.PreparedSQL

		$limit  = max( 1, min( 500, (int) ( $args['limit'] ?? 50 ) ) );
		$offset = max( 0, (int) ( $args['offset'] ?? 0 ) );

		$rows = (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ta.*, ta.coverage_state AS was_coverage, ta.defender_coverage_state AS was_defender,
					ta.lifecycle_status AS was_lifecycle, ta.sources_json AS was_sources,
					a.id AS live_id, a.coverage_state AS now_coverage, a.defender_coverage_state AS now_defender,
					a.lifecycle_status AS now_lifecycle, a.sources_json AS now_sources,
					a.tenable_last_scan, a.defender_last_seen, a.ipv4,
					{$sql} AS outcome" . $from . '
				 ORDER BY FIELD(outcome, \'open\', \'resolved\', \'retired\', \'removed\'), ta.hostname ASC
				 LIMIT %d OFFSET %d', // phpcs:ignore WordPress.DB.PreparedSQL
				...array_merge( $params, array( $limit, $offset ) )
			),
			ARRAY_A
		);

		return array(
			'rows'  => $rows,
			'total' => $total,
		);
	}

	/**
	 * Move a hand-tracked ticket between statuses.
	 *
	 * Only for rows nothing else owns: a ticket the Jira poller refreshes
	 * would have its status put straight back on the next run.
	 */
	public static function set_manual_status( int $ticket_id, string $category, string $notes ): bool {
		global $wpdb;

		$ticket   = self::get( $ticket_id );
		$statuses = self::manual_statuses();

		if ( ! $ticket || self::PROVIDER_JSM !== (string) $ticket['provider'] || ! isset( $statuses[ $category ] ) ) {
			return false;
		}

		$row = array(
			'status'          => $statuses[ $category ],
			'status_category' => $category,
			'notes'           => $notes,
			'updated_at'      => vh_now(),
		);

		if ( 'done' === $category && 'done' !== (string) $ticket['status_category'] ) {
			$row['remote_closed_at'] = vh_now();
		} elseif ( 'done' !== $category ) {
			$row['remote_closed_at'] = null;
		}

		return false !== $wpdb->update( vh_table( 'tickets' ), $row, array( 'id' => $ticket_id ) );
	}

	/* =================================================================
	 * Checks
	 * ============================================================== */

	/**
	 * The due date a ticket was raised with (Y-m-d), or ''.
	 *
	 * @param array<string,mixed> $ticket Ticket row.
	 */
	public static function due_date( array $ticket ): string {
		$payload = json_decode( (string) ( $ticket['payload_json'] ?? '' ), true );
		$due     = is_array( $payload ) ? (string) ( $payload['duedate'] ?? '' ) : '';

		return preg_match( '/^\d{4}-\d{2}-\d{2}$/', $due ) ? $due : '';
	}

	/**
	 * The last check a ticket had, or null.
	 *
	 * @param array<string,mixed> $ticket Ticket row.
	 * @return array<string,mixed>|null
	 */
	public static function last_check( array $ticket ): ?array {
		$payload = json_decode( (string) ( $ticket['payload_json'] ?? '' ), true );

		return is_array( $payload ) && is_array( $payload['last_check'] ?? null ) ? $payload['last_check'] : null;
	}

	/**
	 * Record the outcome of a check on the ticket, without touching anything
	 * else in its payload.
	 *
	 * @param array<string,mixed> $summary state, fixed, open, unknown, headline…
	 */
	public static function set_last_check( int $ticket_id, array $summary ): void {
		unset( $summary['findings'] );
		$summary['checked_at'] = vh_now();

		self::set_payload_value( $ticket_id, 'last_check', $summary );
	}

	/**
	 * The latest comment seen on the ticket at the far end, or null.
	 *
	 * Kept on the ticket so the list can say what is happening without a call
	 * to Jira per row. It is a cache of someone else's system, refreshed every
	 * time the ticket is verified or refreshed -- so it is shown with its own
	 * timestamp, never as though it were live.
	 *
	 * @param array<string,mixed> $ticket Ticket row.
	 * @return array<string,mixed>|null author, author_id, body, created, public, seen_at.
	 */
	public static function last_comment( array $ticket ): ?array {
		$payload = json_decode( (string) ( $ticket['payload_json'] ?? '' ), true );

		return is_array( $payload ) && is_array( $payload['last_comment'] ?? null ) ? $payload['last_comment'] : null;
	}

	/**
	 * Record the latest comment, or clear it with null.
	 *
	 * @param array<string,mixed>|null $comment Normalised comment.
	 */
	public static function set_last_comment( int $ticket_id, ?array $comment ): void {
		if ( is_array( $comment ) ) {
			$comment['seen_at'] = vh_now();
		}

		self::set_payload_value( $ticket_id, 'last_comment', $comment );
	}

	/**
	 * The next automatic check planned for a ticket, or null.
	 *
	 * @param array<string,mixed> $ticket Ticket row.
	 * @return array{at:string,reason:string}|null `at` is UTC.
	 */
	public static function next_check( array $ticket ): ?array {
		$payload = json_decode( (string) ( $ticket['payload_json'] ?? '' ), true );

		return is_array( $payload ) && is_array( $payload['next_check'] ?? null ) ? $payload['next_check'] : null;
	}

	/**
	 * Record (or clear, with null) the next automatic check.
	 *
	 * @param array{at:string,reason:string}|null $next Plan.
	 */
	public static function set_next_check( int $ticket_id, ?array $next ): void {
		self::set_payload_value( $ticket_id, 'next_check', $next );
	}

	/**
	 * Set one key of a ticket's payload without touching the rest.
	 */
	private static function set_payload_value( int $ticket_id, string $key, mixed $value ): void {
		global $wpdb;

		$table   = vh_table( 'tickets' );
		$raw     = (string) $wpdb->get_var( $wpdb->prepare( "SELECT payload_json FROM {$table} WHERE id = %d", $ticket_id ) ); // phpcs:ignore WordPress.DB.PreparedSQL
		$payload = json_decode( $raw, true );
		$payload = is_array( $payload ) ? $payload : array();

		if ( null === $value ) {
			unset( $payload[ $key ] );
		} else {
			$payload[ $key ] = $value;
		}

		$wpdb->update( $table, array( 'payload_json' => (string) wp_json_encode( $payload ) ), array( 'id' => $ticket_id ) );
	}
}

