<?php
/**
 * The Plerion CSPM findings store — deliberately separate from core findings.
 *
 * These are posture/misconfiguration and access findings (CSPM/CIEM), not the
 * scanner vulnerabilities the rest of the platform raises tickets from. They
 * are kept in their own table ON PURPOSE: the Vulnerabilities list, the ticket
 * report and every raise/JSM path read `vh_vulnhub_findings`, so a row that is
 * never written there can never be selected into a ticket, drafted, or counted
 * as remediation work. Isolation by construction, not by a flag someone has to
 * remember to check.
 *
 * @package VulnHub\Plerion
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Stored Plerion CSPM findings.
 */
final class VulnHub_Plerion_Findings {

	public static function table(): string {
		global $wpdb;

		return $wpdb->prefix . 'vulnhub_plerion_findings';
	}

	public static function install(): void {
		global $wpdb;

		$t       = self::table();
		$charset = $wpdb->get_charset_collate();

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		dbDelta(
			"CREATE TABLE {$t} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				finding_prn varchar(512) NOT NULL DEFAULT '',
				detection_id varchar(64) NOT NULL DEFAULT '',
				severity varchar(16) NOT NULL DEFAULT '',
				status varchar(16) NOT NULL DEFAULT '',
				source varchar(32) NOT NULL DEFAULT '',
				message text NULL,
				resource_type varchar(96) NOT NULL DEFAULT '',
				asset_prn varchar(512) NOT NULL DEFAULT '',
				account_id varchar(24) NOT NULL DEFAULT '',
				region varchar(32) NOT NULL DEFAULT '',
				resource_name varchar(255) NOT NULL DEFAULT '',
				resource_url varchar(512) NOT NULL DEFAULT '',
				first_observed varchar(40) NOT NULL DEFAULT '',
				last_observed varchar(40) NOT NULL DEFAULT '',
				sla_due varchar(40) NOT NULL DEFAULT '',
				is_exempted tinyint(1) NOT NULL DEFAULT 0,
				raw_json longtext NULL,
				first_seen datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				last_seen datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				PRIMARY KEY  (id),
				UNIQUE KEY finding_prn (finding_prn(191)),
				KEY severity (severity),
				KEY account_id (account_id),
				KEY detection_id (detection_id),
				KEY resource_type (resource_type)
			) {$charset};"
		);
	}

	/**
	 * @param array<string,mixed> $r   Normalised finding.
	 * @param string              $now UTC 'Y-m-d H:i:s'.
	 */
	public static function upsert( array $r, string $now ): void {
		global $wpdb;

		$prn = (string) ( $r['finding_prn'] ?? '' );

		if ( '' === $prn ) {
			return;
		}

		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$wpdb->prepare(
				"INSERT INTO " . self::table() . " (finding_prn, detection_id, severity, status, source, message, resource_type, asset_prn, account_id, region, resource_name, resource_url, first_observed, last_observed, sla_due, is_exempted, raw_json, first_seen, last_seen)
				 VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%d,%s,%s,%s)
				 ON DUPLICATE KEY UPDATE
					detection_id=VALUES(detection_id), severity=VALUES(severity), status=VALUES(status),
					source=VALUES(source), message=VALUES(message), resource_type=VALUES(resource_type),
					asset_prn=VALUES(asset_prn), account_id=VALUES(account_id), region=VALUES(region),
					resource_name=VALUES(resource_name), resource_url=VALUES(resource_url),
					first_observed=VALUES(first_observed), last_observed=VALUES(last_observed),
					sla_due=VALUES(sla_due), is_exempted=VALUES(is_exempted), raw_json=VALUES(raw_json),
					last_seen=VALUES(last_seen)",
				$prn,
				(string) ( $r['detection_id'] ?? '' ),
				(string) ( $r['severity'] ?? '' ),
				(string) ( $r['status'] ?? '' ),
				(string) ( $r['source'] ?? '' ),
				(string) ( $r['message'] ?? '' ),
				(string) ( $r['resource_type'] ?? '' ),
				(string) ( $r['asset_prn'] ?? '' ),
				(string) ( $r['account_id'] ?? '' ),
				(string) ( $r['region'] ?? '' ),
				(string) ( $r['resource_name'] ?? '' ),
				(string) ( $r['resource_url'] ?? '' ),
				(string) ( $r['first_observed'] ?? '' ),
				(string) ( $r['last_observed'] ?? '' ),
				(string) ( $r['sla_due'] ?? '' ),
				! empty( $r['is_exempted'] ) ? 1 : 0,
				(string) ( $r['raw_json'] ?? '' ),
				$now,
				$now
			)
		);
	}

	public static function prune( string $before ): int {
		global $wpdb;

		return (int) $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$wpdb->prepare( "DELETE FROM " . self::table() . " WHERE last_seen < %s", $before )
		);
	}

	/**
	 * @return array{total:int,by_severity:array<int,array<string,mixed>>,by_account:array<int,array<string,mixed>>}
	 */
	public static function summary(): array {
		global $wpdb;

		$t = self::table();

		return array(
			'total'       => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$t} WHERE is_exempted = 0" ), // phpcs:ignore
			'by_severity' => (array) $wpdb->get_results( "SELECT severity, COUNT(*) AS c FROM {$t} WHERE is_exempted = 0 GROUP BY severity", ARRAY_A ), // phpcs:ignore
			'by_account'  => (array) $wpdb->get_results( "SELECT account_id, COUNT(*) AS c FROM {$t} WHERE is_exempted = 0 GROUP BY account_id ORDER BY c DESC", ARRAY_A ), // phpcs:ignore
		);
	}

	/**
	 * A filtered page of findings.
	 *
	 * @param array<string,mixed> $a Filters: severity, account, resource_type, detection, search, limit, offset.
	 * @return array{rows:array<int,array<string,mixed>>,total:int}
	 */
	public static function query( array $a ): array {
		global $wpdb;
		$t = self::table();

		$where  = array( 'is_exempted = 0' );
		$params = array();

		if ( ! empty( $a['severity'] ) ) { $where[] = 'severity = %s'; $params[] = strtoupper( (string) $a['severity'] ); }
		if ( ! empty( $a['account'] ) ) { $where[] = 'account_id = %s'; $params[] = (string) $a['account']; }
		if ( ! empty( $a['resource_type'] ) ) { $where[] = 'resource_type = %s'; $params[] = (string) $a['resource_type']; }
		if ( ! empty( $a['detection'] ) ) { $where[] = 'detection_id = %s'; $params[] = (string) $a['detection']; }

		if ( ! empty( $a['search'] ) ) {
			$where[] = '( message LIKE %s OR resource_name LIKE %s OR detection_id LIKE %s )';
			$like    = '%' . $wpdb->esc_like( (string) $a['search'] ) . '%';
			$params[] = $like; $params[] = $like; $params[] = $like;
		}

		$w      = 'WHERE ' . implode( ' AND ', $where );
		$limit  = max( 1, min( 200, (int) ( $a['limit'] ?? 50 ) ) );
		$offset = max( 0, (int) ( $a['offset'] ?? 0 ) );
		$order  = "FIELD(severity,'CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'), last_observed DESC";

		$total = (int) ( $params
			? $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$t} {$w}", ...$params ) ) // phpcs:ignore
			: $wpdb->get_var( "SELECT COUNT(*) FROM {$t} {$w}" ) ); // phpcs:ignore

		$rows = (array) $wpdb->get_results( // phpcs:ignore
			$wpdb->prepare( "SELECT * FROM {$t} {$w} ORDER BY {$order} LIMIT %d OFFSET %d", ...array_merge( $params, array( $limit, $offset ) ) ),
			ARRAY_A
		);

		return array( 'rows' => $rows, 'total' => $total );
	}

	/** @return string[] */
	public static function accounts(): array {
		global $wpdb;
		return array_map( 'strval', (array) $wpdb->get_col( 'SELECT DISTINCT account_id FROM ' . self::table() . " WHERE account_id <> '' ORDER BY account_id" ) ); // phpcs:ignore
	}

	/** @return string[] */
	public static function resource_types(): array {
		global $wpdb;
		return array_map( 'strval', (array) $wpdb->get_col( 'SELECT DISTINCT resource_type FROM ' . self::table() . " WHERE resource_type <> '' ORDER BY resource_type" ) ); // phpcs:ignore
	}
}
