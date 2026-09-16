<?php
/**
 * The programme's own table, created and migrated by this plugin.
 *
 * Deliberately not added to vulnhub-core's installer: this is one programme's
 * planning data, not part of the platform's data model, and a site that never
 * activates this plugin should not carry the table.
 *
 * @package VulnHub\EOS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Install and migrate `vh_vulnhub_eos_plan`.
 */
final class VH_EOS_Schema {

	/** Bump when the CREATE TABLE below changes. */
	public const VERSION = 1;

	public const OPT_VERSION = 'vulnhub_eos_db_version';

	public static function init(): void {
		/*
		 * Cheap: one option read per request, and the option is autoloaded.
		 * An upgrade does not fire the activation hook, so without this a
		 * schema change would only land for sites that happened to deactivate
		 * and reactivate the plugin.
		 */
		if ( (int) get_option( self::OPT_VERSION, 0 ) !== self::VERSION ) {
			self::install();
		}
	}

	/**
	 * The table name, so nothing else has to remember the prefix rule.
	 */
	public static function table(): string {
		return vh_table( 'eos_plan' );
	}

	/**
	 * Create or migrate the table.
	 *
	 * dbDelta is particular: two spaces after PRIMARY KEY, lower-case column
	 * types, one column per line, no inline comments.
	 */
	public static function install(): void {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset = $wpdb->get_charset_collate();
		$table   = self::table();

		/*
		 * `hostname` is the natural key and is UNIQUE: the workbook is a
		 * reconciled list, one row per server, and re-importing it must update
		 * rows rather than stack duplicates.
		 *
		 * `asset_id` is 0 rather than NULL when nothing matched. A third of
		 * the programme's hosts have no asset in VulnHub -- retired, never
		 * scanned, or simply not there yet -- and they still have to import
		 * and still have to be visible, so "no asset" is an ordinary state
		 * here, not a failure.
		 */
		$sql = "CREATE TABLE {$table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			hostname varchar(191) NOT NULL DEFAULT '',
			asset_id bigint(20) unsigned NOT NULL DEFAULT 0,
			environment varchar(64) NOT NULL DEFAULT '',
			purpose varchar(191) NOT NULL DEFAULT '',
			os_text varchar(191) NOT NULL DEFAULT '',
			project varchar(191) NOT NULL DEFAULT '',
			timeframe varchar(32) NOT NULL DEFAULT '',
			deadline date NULL,
			state varchar(24) NOT NULL DEFAULT '',
			env_tier varchar(16) NOT NULL DEFAULT '',
			rag varchar(8) NOT NULL DEFAULT '',
			controls varchar(191) NOT NULL DEFAULT '',
			inherent_risk varchar(32) NOT NULL DEFAULT '',
			residual_risk varchar(32) NOT NULL DEFAULT '',
			jsm_status varchar(64) NOT NULL DEFAULT '',
			jsm_location varchar(128) NOT NULL DEFAULT '',
			notes text NULL,
			batch_id varchar(32) NOT NULL DEFAULT '',
			imported_at datetime NULL,
			updated_at datetime NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY hostname (hostname),
			KEY asset_id (asset_id),
			KEY state (state),
			KEY deadline (deadline),
			KEY batch_id (batch_id)
		) {$charset};";

		dbDelta( $sql );

		update_option( self::OPT_VERSION, self::VERSION, false );
	}

	/**
	 * Does the table exist? Used by the screens so a half-installed plugin
	 * reports "nothing imported yet" instead of a database error.
	 */
	public static function ready(): bool {
		global $wpdb;

		static $ready = null;

		if ( null !== $ready ) {
			return $ready;
		}

		$table = self::table();
		$found = (string) $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ); // phpcs:ignore WordPress.DB

		$ready = ( $found === $table );

		return $ready;
	}
}
