<?php
/**
 * Schema for the advisory alerting subsystem.
 *
 * Four tables, and the split between them is the whole design:
 *
 *   alert_feeds    where advisories come from. Rows, not code, so a new free
 *                  feed is a form submission rather than a deployment.
 *   alerts         one normalised advisory, whatever shape it arrived in.
 *   alert_matches  the join to our estate. An advisory with no matches is
 *                  still stored -- "we looked and it does not affect us" is
 *                  an answer somebody will ask for six months from now.
 *   alert_events   who decided what, and why.
 *
 * @package VulnHub\Alerts
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Alerts_Install {

	public const DB_VERSION = '3';
	public const OPT_DB     = 'vulnhub_alerts_db_version';

	public static function activate(): void {
		self::run();
		self::seed_feeds();
		VulnHub_Alerts_Cron::schedule();
	}

	public static function deactivate(): void {
		VulnHub_Alerts_Cron::unschedule();
	}

	public static function maybe_upgrade(): void {
		if ( (string) get_option( self::OPT_DB, '' ) !== self::DB_VERSION ) {
			self::run();
			self::seed_feeds();
		}
	}

	/**
	 * dbDelta is picky: two spaces after PRIMARY KEY, lowercase types,
	 * KEY not INDEX, no backticks on index names, one column per line.
	 */
	public static function run(): void {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset = $wpdb->get_charset_collate();
		$p       = $wpdb->prefix . 'vulnhub_';
		$sql     = array();

		$sql[] = "CREATE TABLE {$p}alert_feeds (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			slug varchar(64) NOT NULL DEFAULT '',
			label varchar(191) NOT NULL DEFAULT '',
			adapter varchar(32) NOT NULL DEFAULT 'rss',
			url text NULL,
			config_json longtext NULL,
			enabled tinyint(1) NOT NULL DEFAULT 1,
			builtin tinyint(1) NOT NULL DEFAULT 0,
			interval_minutes int(10) unsigned NOT NULL DEFAULT 360,
			auth_key varchar(255) NOT NULL DEFAULT '',
			http_etag varchar(255) NOT NULL DEFAULT '',
			http_modified varchar(64) NOT NULL DEFAULT '',
			last_run_at datetime NULL,
			last_ok_at datetime NULL,
			last_status varchar(16) NOT NULL DEFAULT '',
			last_error text NULL,
			last_count int(10) unsigned NOT NULL DEFAULT 0,
			total_seen int(10) unsigned NOT NULL DEFAULT 0,
			created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			updated_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			PRIMARY KEY  (id),
			UNIQUE KEY slug (slug),
			KEY enabled_run (enabled,last_run_at)
		) {$charset};";

		$sql[] = "CREATE TABLE {$p}alerts (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			feed_id bigint(20) unsigned NOT NULL DEFAULT 0,
			source varchar(32) NOT NULL DEFAULT '',
			external_id varchar(191) NOT NULL DEFAULT '',
			fingerprint char(64) NOT NULL DEFAULT '',
			title varchar(500) NOT NULL DEFAULT '',
			summary longtext NULL,
			url text NULL,
			severity varchar(16) NOT NULL DEFAULT 'unknown',
			cvss decimal(4,1) NOT NULL DEFAULT 0.0,
			epss decimal(7,6) NOT NULL DEFAULT 0.000000,
			kev tinyint(1) NOT NULL DEFAULT 0,
			cve_json text NULL,
			products_json longtext NULL,
			raw_json longtext NULL,
			published_at datetime NULL,
			updated_at datetime NULL,
			first_seen datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			last_seen datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			matched tinyint(1) NOT NULL DEFAULT 0,
			best_confidence varchar(12) NOT NULL DEFAULT '',
			match_count int(10) unsigned NOT NULL DEFAULT 0,
			asset_count int(10) unsigned NOT NULL DEFAULT 0,
			state varchar(16) NOT NULL DEFAULT 'new',
			state_by bigint(20) unsigned NOT NULL DEFAULT 0,
			state_at datetime NULL,
			state_note text NULL,
			ticket_id bigint(20) unsigned NOT NULL DEFAULT 0,
			notified_at datetime NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY fingerprint (fingerprint),
			KEY feed_id (feed_id),
			KEY triage (matched,state,published_at),
			KEY rank_order (matched,best_confidence,cvss),
			KEY published_at (published_at),
			KEY kev (kev),
			KEY state (state)
		) {$charset};";

		$sql[] = "CREATE TABLE {$p}alert_matches (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			alert_id bigint(20) unsigned NOT NULL DEFAULT 0,
			asset_id bigint(20) unsigned NOT NULL DEFAULT 0,
			confidence varchar(12) NOT NULL DEFAULT 'possible',
			matched_on varchar(16) NOT NULL DEFAULT '',
			vendor varchar(191) NOT NULL DEFAULT '',
			product varchar(191) NOT NULL DEFAULT '',
			installed_version varchar(96) NOT NULL DEFAULT '',
			affected_range varchar(191) NOT NULL DEFAULT '',
			evidence text NULL,
			created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			PRIMARY KEY  (id),
			UNIQUE KEY alert_asset_product (alert_id,asset_id,product),
			KEY asset_id (asset_id),
			KEY confidence (confidence),
			KEY alert_conf (alert_id,confidence)
		) {$charset};";

		$sql[] = "CREATE TABLE {$p}alert_events (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			alert_id bigint(20) unsigned NOT NULL DEFAULT 0,
			user_id bigint(20) unsigned NOT NULL DEFAULT 0,
			action varchar(32) NOT NULL DEFAULT '',
			from_state varchar(16) NOT NULL DEFAULT '',
			to_state varchar(16) NOT NULL DEFAULT '',
			note text NULL,
			created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			PRIMARY KEY  (id),
			KEY alert_id (alert_id),
			KEY created_at (created_at)
		) {$charset};";

		foreach ( $sql as $statement ) {
			dbDelta( $statement );
		}

		update_option( self::OPT_DB, self::DB_VERSION, false );
	}

	/**
	 * Install the built-in feeds, but never overwrite one the operator has
	 * since edited or switched off -- a plugin upgrade quietly re-enabling a
	 * feed somebody deliberately disabled is exactly the kind of surprise
	 * that makes people stop trusting the tool.
	 */
	public static function seed_feeds(): void {
		global $wpdb;

		$table = $wpdb->prefix . 'vulnhub_alert_feeds';
		$now   = current_time( 'mysql', true );

		foreach ( VulnHub_Alerts_Registry::builtin_feeds() as $feed ) {
			$exists = (int) $wpdb->get_var(
				$wpdb->prepare( "SELECT id FROM {$table} WHERE slug = %s", $feed['slug'] )
			);

			if ( $exists ) {
				continue;
			}

			$wpdb->insert(
				$table,
				array(
					'slug'             => $feed['slug'],
					'label'            => $feed['label'],
					'adapter'          => $feed['adapter'],
					'url'              => $feed['url'] ?? '',
					'config_json'      => wp_json_encode( $feed['config'] ?? array() ),
					'enabled'          => (int) ( $feed['enabled'] ?? 1 ),
					'builtin'          => 1,
					'interval_minutes' => (int) ( $feed['interval'] ?? 360 ),
					'created_at'       => $now,
					'updated_at'       => $now,
				)
			);
		}
	}
}
