<?php
/**
 * The org-wide resource inventory read from AWS Resource Explorer.
 *
 * A different question from the per-account role path: not "what can reach this
 * instance", but "what exists, and in which account" -- across the whole
 * organisation, from one identity in the central account, with no role to
 * assume in each member. Resource Explorer returns the index, not the
 * configuration: an ARN, its type, region, owning account and tags. That is
 * enough to inventory every asset and every security group in the estate; it
 * is not enough to know a security group's rules, which stay on the role path.
 *
 * Kept in its own table for the same reason the accounts list is: this is AWS's
 * own view of the estate, keyed by ARN, and folding it into the shared asset
 * table would force the dedup and schema decisions the reachability path
 * deliberately leaves to the CMDB.
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The AWS Resource Explorer inventory store.
 */
final class VulnHub_AWS_Inventory {

	public static function table(): string {
		global $wpdb;

		return $wpdb->prefix . 'vulnhub_aws_inventory';
	}

	public static function install(): void {
		global $wpdb;

		$t       = self::table();
		$charset = $wpdb->get_charset_collate();

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		dbDelta(
			"CREATE TABLE {$t} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				arn varchar(512) NOT NULL DEFAULT '',
				account_id varchar(24) NOT NULL DEFAULT '',
				region varchar(32) NOT NULL DEFAULT '',
				service varchar(32) NOT NULL DEFAULT '',
				resource_type varchar(64) NOT NULL DEFAULT '',
				name varchar(255) NOT NULL DEFAULT '',
				tags_json longtext NULL,
				last_reported_at varchar(40) NOT NULL DEFAULT '',
				first_seen datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				last_seen datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				PRIMARY KEY  (id),
				UNIQUE KEY arn (arn(191)),
				KEY account_id (account_id),
				KEY resource_type (resource_type),
				KEY service (service)
			) {$charset};"
		);
	}

	/**
	 * Insert or refresh one resource, stamping first/last seen.
	 *
	 * @param array<string,mixed> $r   Normalised resource.
	 * @param string              $now Sync timestamp (UTC, 'Y-m-d H:i:s').
	 */
	public static function upsert( array $r, string $now ): void {
		global $wpdb;

		$arn = (string) ( $r['arn'] ?? '' );

		if ( '' === $arn ) {
			return;
		}

		$tags = wp_json_encode( $r['tags'] ?? array() );

		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$wpdb->prepare(
				"INSERT INTO " . self::table() . " (arn, account_id, region, service, resource_type, name, tags_json, last_reported_at, first_seen, last_seen)
				 VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
				 ON DUPLICATE KEY UPDATE
					account_id = VALUES(account_id),
					region = VALUES(region),
					service = VALUES(service),
					resource_type = VALUES(resource_type),
					name = VALUES(name),
					tags_json = VALUES(tags_json),
					last_reported_at = VALUES(last_reported_at),
					last_seen = VALUES(last_seen)",
				$arn,
				(string) ( $r['account_id'] ?? '' ),
				(string) ( $r['region'] ?? '' ),
				(string) ( $r['service'] ?? '' ),
				(string) ( $r['resource_type'] ?? '' ),
				(string) ( $r['name'] ?? '' ),
				is_string( $tags ) ? $tags : '[]',
				(string) ( $r['last_reported_at'] ?? '' ),
				$now,
				$now
			)
		);
	}

	/**
	 * Drop rows this sync did not touch -- resources gone from AWS.
	 *
	 * @param string $before Anything last_seen before this is stale.
	 */
	public static function prune( string $before ): int {
		global $wpdb;

		return (int) $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$wpdb->prepare( "DELETE FROM " . self::table() . " WHERE last_seen < %s", $before )
		);
	}

	/**
	 * Counts for the health panel and sync message.
	 *
	 * @return array{total:int,accounts:int,by_type:array<int,array<string,mixed>>}
	 */
	public static function summary(): array {
		global $wpdb;

		$t = self::table();

		return array(
			'total'    => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$t}" ), // phpcs:ignore
			'accounts' => (int) $wpdb->get_var( "SELECT COUNT(DISTINCT account_id) FROM {$t}" ), // phpcs:ignore
			'by_type'  => (array) $wpdb->get_results( // phpcs:ignore
				"SELECT resource_type, COUNT(*) AS c, COUNT(DISTINCT account_id) AS accounts
				 FROM {$t} GROUP BY resource_type ORDER BY c DESC",
				ARRAY_A
			),
		);
	}

	/**
	 * A page of rows, newest first, optionally filtered by type.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function all( string $resource_type = '', int $limit = 200 ): array {
		global $wpdb;

		$t     = self::table();
		$limit = max( 1, min( 1000, $limit ) );

		if ( '' !== $resource_type ) {
			return (array) $wpdb->get_results( // phpcs:ignore
				$wpdb->prepare( "SELECT * FROM {$t} WHERE resource_type = %s ORDER BY account_id, name LIMIT %d", $resource_type, $limit ),
				ARRAY_A
			);
		}

		return (array) $wpdb->get_results( // phpcs:ignore
			$wpdb->prepare( "SELECT * FROM {$t} ORDER BY account_id, resource_type, name LIMIT %d", $limit ),
			ARRAY_A
		);
	}
}
