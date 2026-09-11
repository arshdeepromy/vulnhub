<?php
/**
 * Schema for the threat-context tables.
 *
 * Three tables, all owned by this plugin. Nothing here writes to core's
 * `vulns`, `assets` or `findings` schema, so the plugin can be deactivated and
 * the estate data is exactly as it was.
 *
 *   vulnhub_cve_intel       one row per CVE id, as NVD/KEV/EPSS describe it
 *   vulnhub_vuln_paths      one row per scanner vulnerability definition
 *   vulnhub_asset_exposure  one row per asset: can the internet reach it
 *
 * The middle table exists because a scanner definition is not a CVE. A single
 * "RHEL 8 : kernel (RHSA-2025:23947)" row carries thirty CVEs, and the honest
 * answer for the definition is the most reachable route any one of them opens.
 * Working that out per page-load over 228,000 findings is not affordable, so it
 * is worked out once per sync and stored.
 *
 * @package VulnHub\Threat
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Creates and migrates this plugin's tables via dbDelta.
 */
final class VulnHub_Threat_Install {

	public const DB_VERSION = '1.0.0';
	public const DB_OPTION  = 'vulnhub_threat_db_version';

	/** Fully qualified name of one of this plugin's tables. */
	public static function table( string $name ): string {
		global $wpdb;

		return $wpdb->prefix . 'vulnhub_' . $name;
	}

	public static function activate(): void {
		self::install();
		VulnHub_Threat_Feeds::schedule();
	}

	public static function deactivate(): void {
		VulnHub_Threat_Feeds::unschedule();
	}

	public static function maybe_upgrade(): void {
		if ( (string) get_option( self::DB_OPTION, '' ) === self::DB_VERSION ) {
			return;
		}

		self::install();
		VulnHub_Threat_Feeds::schedule();
	}

	public static function install(): void {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset = $wpdb->get_charset_collate();
		$intel   = self::table( 'cve_intel' );
		$paths   = self::table( 'vuln_paths' );
		$expo    = self::table( 'asset_exposure' );

		/*
		 * `route` and `has_poc` are indexed together because every question the
		 * widget asks is some form of "which definitions are on route X and
		 * already have an exploit", and that is 13,000 rows resolved from the
		 * index rather than a table scan per lane.
		 */
		dbDelta(
			"CREATE TABLE {$intel} (
				cve_id varchar(24) NOT NULL,
				attack_vector varchar(16) NOT NULL DEFAULT '',
				attack_complexity varchar(8) NOT NULL DEFAULT '',
				privileges_required varchar(8) NOT NULL DEFAULT '',
				user_interaction varchar(12) NOT NULL DEFAULT '',
				scope varchar(12) NOT NULL DEFAULT '',
				base_score decimal(3,1) NOT NULL DEFAULT 0.0,
				cvss_version varchar(8) NOT NULL DEFAULT '',
				epss decimal(7,6) NOT NULL DEFAULT 0.000000,
				epss_percentile decimal(7,6) NOT NULL DEFAULT 0.000000,
				kev tinyint(1) NOT NULL DEFAULT 0,
				kev_added date DEFAULT NULL,
				kev_ransomware tinyint(1) NOT NULL DEFAULT 0,
				exploit_refs smallint(5) unsigned NOT NULL DEFAULT 0,
				has_poc tinyint(1) NOT NULL DEFAULT 0,
				route varchar(12) NOT NULL DEFAULT 'unknown',
				delivery varchar(12) NOT NULL DEFAULT '',
				nvd_published date DEFAULT NULL,
				nvd_modified datetime DEFAULT NULL,
				fetched_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				PRIMARY KEY  (cve_id),
				KEY route_poc (route,has_poc),
				KEY kev (kev),
				KEY epss (epss)
			) {$charset};"
		);

		dbDelta(
			"CREATE TABLE {$paths} (
				vuln_id bigint(20) unsigned NOT NULL,
				cve_count smallint(5) unsigned NOT NULL DEFAULT 0,
				known_count smallint(5) unsigned NOT NULL DEFAULT 0,
				route varchar(12) NOT NULL DEFAULT 'unknown',
				poc_route varchar(12) NOT NULL DEFAULT '',
				delivery varchar(12) NOT NULL DEFAULT '',
				has_poc tinyint(1) NOT NULL DEFAULT 0,
				kev tinyint(1) NOT NULL DEFAULT 0,
				top_epss decimal(7,6) NOT NULL DEFAULT 0.000000,
				top_cve varchar(24) NOT NULL DEFAULT '',
				evidence varchar(32) NOT NULL DEFAULT '',
				updated_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				PRIMARY KEY  (vuln_id),
				KEY poc_route (has_poc,poc_route),
				KEY route (route)
			) {$charset};"
		);

		/*
		 * Exposure is its own table rather than a column on core's assets
		 * table for one reason: it is a derived opinion, not inventory. A
		 * connector sync must never overwrite it, and dropping this plugin
		 * must not leave a stale column behind claiming a laptop faces the
		 * internet. `source` records whether a rule decided it or a person did,
		 * so a rule pass can rewrite its own decisions without touching the
		 * ones somebody set by hand.
		 */
		dbDelta(
			"CREATE TABLE {$expo} (
				asset_id bigint(20) unsigned NOT NULL,
				internet_facing tinyint(1) NOT NULL DEFAULT 0,
				source varchar(16) NOT NULL DEFAULT 'rule',
				reason varchar(191) NOT NULL DEFAULT '',
				updated_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				PRIMARY KEY  (asset_id),
				KEY facing (internet_facing)
			) {$charset};"
		);

		update_option( self::DB_OPTION, self::DB_VERSION, false );
	}
}
