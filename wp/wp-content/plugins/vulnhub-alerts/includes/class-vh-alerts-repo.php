<?php
/**
 * Reads for the alerts page.
 *
 * @package VulnHub\Alerts
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Alerts_Repo {

	/** @return array<string,array{label:string,tone:string}> */
	public static function states(): array {
		return array(
			'new'          => array( 'label' => __( 'New', 'vulnhub' ),           'tone' => 'critical' ),
			'acknowledged' => array( 'label' => __( 'Acknowledged', 'vulnhub' ),  'tone' => 'warn' ),
			'affected'     => array( 'label' => __( 'Affected', 'vulnhub' ),      'tone' => 'critical' ),
			'not_affected' => array( 'label' => __( 'Not affected', 'vulnhub' ),  'tone' => 'good' ),
			'mitigated'    => array( 'label' => __( 'Mitigated', 'vulnhub' ),     'tone' => 'good' ),
		);
	}

	public static function state_label( string $state ): string {
		return (string) ( self::states()[ $state ]['label'] ?? $state );
	}

	public static function state_tone( string $state ): string {
		return (string) ( self::states()[ $state ]['tone'] ?? 'muted' );
	}

	/** States that still want somebody's attention. */
	public static function open_states(): array {
		return array( 'new', 'acknowledged', 'affected' );
	}

	/**
	 * Headline numbers for the page and the nav badge.
	 *
	 * @return array<string,int>
	 */
	public static function summary(): array {
		global $wpdb;

		$a = $wpdb->prefix . 'vulnhub_alerts';

		$row = $wpdb->get_row(
			"SELECT
				COUNT(*) AS total,
				SUM(matched = 1) AS matched,
				SUM(matched = 1 AND best_confidence = 'exact') AS exact,
				SUM(matched = 1 AND best_confidence = 'probable') AS probable,
				SUM(matched = 1 AND best_confidence = 'possible') AS possible,
				SUM(matched = 1 AND state = 'new') AS untriaged,
				SUM(matched = 1 AND kev = 1 AND state IN ('new','acknowledged','affected')) AS exploited,
				SUM(matched = 0) AS not_relevant
			   FROM {$a}",
			ARRAY_A
		);

		$out = array();
		foreach ( (array) $row as $key => $value ) {
			$out[ $key ] = (int) $value;
		}

		// The number worth interrupting somebody for: exact match, still
		// untriaged, and either exploited or critical.
		$out['urgent'] = (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM {$a}
			  WHERE matched = 1
			    AND best_confidence = 'exact'
			    AND state IN ('new','acknowledged','affected')
			    AND (kev = 1 OR severity = 'critical')"
		);

		return $out;
	}

	/**
	 * The alert list.
	 *
	 * @param array<string,mixed> $args Filters.
	 * @return array{rows:array<int,array<string,mixed>>,total:int}
	 */
	public static function alerts( array $args = array() ): array {
		global $wpdb;

		$a = $wpdb->prefix . 'vulnhub_alerts';

		$args = wp_parse_args(
			$args,
			array(
				'confidence' => '',
				'state'      => '',
				'severity'   => '',
				'source'     => '',
				'kev'        => '',
				'search'     => '',
				'matched'    => '1',
				'orderby'    => 'priority',
				'limit'      => 50,
				'offset'     => 0,
			)
		);

		$where = array( '1=1' );
		$vals  = array();

		if ( '' !== $args['matched'] ) {
			$where[] = 'matched = %d';
			$vals[]  = (int) $args['matched'];
		}

		if ( '' !== $args['confidence'] && isset( VulnHub_Alerts_Matcher::confidences()[ $args['confidence'] ] ) ) {
			$where[] = 'best_confidence = %s';
			$vals[]  = (string) $args['confidence'];
		}

		if ( 'open' === $args['state'] ) {
			$where[] = "state IN ('new','acknowledged','affected')";
		} elseif ( '' !== $args['state'] && isset( self::states()[ $args['state'] ] ) ) {
			$where[] = 'state = %s';
			$vals[]  = (string) $args['state'];
		}

		if ( '' !== $args['severity'] ) {
			$where[] = 'severity = %s';
			$vals[]  = (string) $args['severity'];
		}

		if ( '' !== $args['source'] ) {
			$where[] = 'source = %s';
			$vals[]  = (string) $args['source'];
		}

		if ( '' !== $args['kev'] ) {
			$where[] = 'kev = %d';
			$vals[]  = (int) $args['kev'];
		}

		if ( '' !== trim( (string) $args['search'] ) ) {
			$like    = '%' . $wpdb->esc_like( trim( (string) $args['search'] ) ) . '%';
			$where[] = '(title LIKE %s OR summary LIKE %s OR cve_json LIKE %s OR external_id LIKE %s)';
			array_push( $vals, $like, $like, $like, $like );
		}

		$sql_where = implode( ' AND ', $where );

		/*
		 * Default order is the one a person actually wants: how sure we are
		 * first, then whether it is being exploited, then severity, then how
		 * fresh it is. Sorting by date alone buries an exploited exact match
		 * under a week of unrated noise.
		 */
		$order = match ( (string) $args['orderby'] ) {
			'newest'   => 'published_at DESC, id DESC',
			'severity' => "FIELD(severity,'critical','high','medium','low','unknown'), cvss DESC",
			'assets'   => 'asset_count DESC, cvss DESC',
			default    => "FIELD(best_confidence,'exact','probable','possible') ASC, kev DESC,
			               FIELD(severity,'critical','high','medium','low','unknown') ASC,
			               published_at DESC",
		};

		$total_sql = "SELECT COUNT(*) FROM {$a} WHERE {$sql_where}";
		$total     = (int) ( $vals
			? $wpdb->get_var( $wpdb->prepare( $total_sql, $vals ) ) // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			: $wpdb->get_var( $total_sql ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared

		$limit  = max( 1, min( 200, (int) $args['limit'] ) );
		$offset = max( 0, (int) $args['offset'] );

		$rows_sql = "SELECT * FROM {$a} WHERE {$sql_where} ORDER BY {$order} LIMIT %d OFFSET %d";
		$rows     = $wpdb->get_results(
			$wpdb->prepare( $rows_sql, array_merge( $vals, array( $limit, $offset ) ) ), // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			ARRAY_A
		);

		return array( 'rows' => (array) $rows, 'total' => $total );
	}

	/** @return array<string,mixed>|null */
	public static function alert( int $id ): ?array {
		global $wpdb;

		$a   = $wpdb->prefix . 'vulnhub_alerts';
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$a} WHERE id = %d", $id ), ARRAY_A );

		return $row ?: null;
	}

	/**
	 * The assets an alert touches, worst confidence first, with enough asset
	 * detail to act without a second query per row.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function matches( int $alert_id, int $limit = 200 ): array {
		global $wpdb;

		$m      = $wpdb->prefix . 'vulnhub_alert_matches';
		$assets = $wpdb->prefix . 'vulnhub_assets';

		return (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT m.*, a.hostname, a.fqdn, a.ipv4, a.asset_type, a.operating_system,
				        a.criticality, a.lifecycle_status, a.team_id, a.owner_person_id
				   FROM {$m} m
				   LEFT JOIN {$assets} a ON a.id = m.asset_id
				  WHERE m.alert_id = %d
				  ORDER BY FIELD(m.confidence,'exact','probable','possible') ASC,
				           a.criticality DESC, a.hostname ASC
				  LIMIT %d",
				$alert_id,
				max( 1, min( 500, $limit ) )
			),
			ARRAY_A
		);
	}

	/** @return array<int,array<string,mixed>> */
	public static function events( int $alert_id ): array {
		global $wpdb;

		$e = $wpdb->prefix . 'vulnhub_alert_events';

		return (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$e} WHERE alert_id = %d ORDER BY created_at DESC, id DESC LIMIT 50",
				$alert_id
			),
			ARRAY_A
		);
	}

	/** @return array<int,array<string,mixed>> */
	public static function feeds( bool $enabled_only = false ): array {
		global $wpdb;

		$f   = $wpdb->prefix . 'vulnhub_alert_feeds';
		$sql = "SELECT * FROM {$f}";

		if ( $enabled_only ) {
			$sql .= ' WHERE enabled = 1';
		}

		$sql .= ' ORDER BY builtin DESC, label ASC';

		return (array) $wpdb->get_results( $sql, ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
	}

	/** @return array<string,mixed>|null */
	public static function feed( int $id ): ?array {
		global $wpdb;

		$f   = $wpdb->prefix . 'vulnhub_alert_feeds';
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$f} WHERE id = %d", $id ), ARRAY_A );

		return $row ?: null;
	}

	/**
	 * How many matched alerts each feed is contributing. The number that
	 * answers "is this source earning its place?".
	 *
	 * @return array<string,array{total:int,matched:int}>
	 */
	public static function per_source(): array {
		global $wpdb;

		$a = $wpdb->prefix . 'vulnhub_alerts';

		$rows = $wpdb->get_results(
			"SELECT source, COUNT(*) AS total, SUM(matched = 1) AS matched
			   FROM {$a} GROUP BY source",
			ARRAY_A
		);

		$out = array();

		foreach ( (array) $rows as $row ) {
			$out[ (string) $row['source'] ] = array(
				'total'   => (int) $row['total'],
				'matched' => (int) $row['matched'],
			);
		}

		return $out;
	}

	/**
	 * Change an alert's triage state and record who did it.
	 */
	public static function set_state( int $alert_id, string $state, string $note = '', int $user_id = 0 ): bool {
		global $wpdb;

		if ( ! isset( self::states()[ $state ] ) ) {
			return false;
		}

		$alert = self::alert( $alert_id );

		if ( ! $alert ) {
			return false;
		}

		$user_id = $user_id ?: get_current_user_id();
		$now     = current_time( 'mysql', true );

		$wpdb->update(
			$wpdb->prefix . 'vulnhub_alerts',
			array(
				'state'      => $state,
				'state_by'   => $user_id,
				'state_at'   => $now,
				'state_note' => $note,
			),
			array( 'id' => $alert_id )
		);

		$wpdb->insert(
			$wpdb->prefix . 'vulnhub_alert_events',
			array(
				'alert_id'   => $alert_id,
				'user_id'    => $user_id,
				'action'     => 'state',
				'from_state' => (string) $alert['state'],
				'to_state'   => $state,
				'note'       => $note,
				'created_at' => $now,
			)
		);

		// The nav badge is cached for five minutes; triaging something and
		// watching the count sit still makes the tool feel broken.
		delete_transient( 'vulnhub_alerts_badge' );

		do_action( 'vulnhub_alert_state_changed', $alert_id, $state, (string) $alert['state'], $user_id );

		return true;
	}

	/** @return string[] */
	public static function cves( array $alert ): array {
		$cves = json_decode( (string) ( $alert['cve_json'] ?? '[]' ), true );

		return is_array( $cves ) ? array_map( 'strval', $cves ) : array();
	}

	/** @return array<int,array<string,string>> */
	public static function products( array $alert ): array {
		$products = json_decode( (string) ( $alert['products_json'] ?? '[]' ), true );

		return is_array( $products ) ? $products : array();
	}
}
