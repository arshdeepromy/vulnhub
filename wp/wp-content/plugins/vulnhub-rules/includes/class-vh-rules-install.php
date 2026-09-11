<?php
/**
 * Schema installer and default-rule seeder for the classification engine.
 *
 * Three tables, all owned by this plugin so core's `mapping_rules` (ownership)
 * is never touched:
 *
 *   vulnhub_class_rules            one row per classification rule
 *   vulnhub_class_rule_conditions  one row per condition inside a rule
 *   vulnhub_class_asset_state      what the engine last decided per asset
 *
 * @package VulnHub\Rules
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Creates and migrates the classification tables via dbDelta.
 */
final class VulnHub_Rules_Install {

	/**
	 * Schema version; bump to force a dbDelta pass.
	 */
	public const DB_VERSION = '1.0.0';

	/**
	 * Option holding the installed schema version.
	 */
	public const DB_OPTION = 'vulnhub_rules_db_version';

	/**
	 * Option that records the shipped defaults having been created.
	 */
	public const SEED_OPTION = 'vulnhub_rules_seeded';

	/**
	 * Fully qualified name of one of this plugin's tables.
	 *
	 * @param string $name Bare table name, e.g. 'class_rules'.
	 * @return string Prefixed table name.
	 */
	public static function table( string $name ): string {
		global $wpdb;

		return $wpdb->prefix . 'vulnhub_' . $name;
	}

	/**
	 * Activation: install the schema then seed the customer's rules.
	 */
	public static function activate(): void {
		self::install();
		self::seed_defaults();
	}

	/**
	 * Install the schema when the stored version is behind the code.
	 */
	public static function maybe_upgrade(): void {
		if ( (string) get_option( self::DB_OPTION, '' ) === self::DB_VERSION ) {
			return;
		}

		self::install();
		self::seed_defaults();
	}

	/**
	 * Create or migrate every table this plugin owns.
	 *
	 * dbDelta is picky: two spaces after PRIMARY KEY, lowercase column types,
	 * KEY rather than INDEX, and no backticks around index names.
	 */
	public static function install(): void {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset = $wpdb->get_charset_collate();
		$p       = $wpdb->prefix . 'vulnhub_';
		$sql     = array();

		$sql[] = "CREATE TABLE {$p}class_rules (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			name varchar(191) NOT NULL DEFAULT '',
			description varchar(255) NOT NULL DEFAULT '',
			enabled tinyint(1) NOT NULL DEFAULT 1,
			priority int(10) NOT NULL DEFAULT 100,
			match_type varchar(8) NOT NULL DEFAULT 'all',
			stop_processing tinyint(1) NOT NULL DEFAULT 0,
			set_environment varchar(32) NOT NULL DEFAULT '',
			set_criticality varchar(16) NOT NULL DEFAULT '',
			set_asset_type varchar(32) NOT NULL DEFAULT '',
			set_business_service varchar(191) NOT NULL DEFAULT '',
			set_priority_weight int(10) NULL DEFAULT NULL,
			match_count bigint(20) unsigned NOT NULL DEFAULT 0,
			last_matched_at datetime NULL,
			created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			updated_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			PRIMARY KEY  (id),
			KEY enabled_priority (enabled,priority)
		) {$charset};";

		$sql[] = "CREATE TABLE {$p}class_rule_conditions (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			rule_id bigint(20) unsigned NOT NULL DEFAULT 0,
			position int(10) NOT NULL DEFAULT 0,
			match_field varchar(64) NOT NULL DEFAULT 'hostname',
			field_key varchar(191) NOT NULL DEFAULT '',
			match_operator varchar(24) NOT NULL DEFAULT 'contains',
			match_value varchar(255) NOT NULL DEFAULT '',
			PRIMARY KEY  (id),
			KEY rule_position (rule_id,position)
		) {$charset};";

		$sql[] = "CREATE TABLE {$p}class_asset_state (
			asset_id bigint(20) unsigned NOT NULL,
			priority_weight int(10) NOT NULL DEFAULT 0,
			rules_applied varchar(255) NOT NULL DEFAULT '',
			classified_at datetime NULL,
			PRIMARY KEY  (asset_id),
			KEY priority_weight (priority_weight)
		) {$charset};";

		dbDelta( $sql );

		update_option( self::DB_OPTION, self::DB_VERSION, false );
	}

	/**
	 * Seed the rules the customer asked for, as real editable rows.
	 *
	 * "Any server that has akl or pod in the hostname is prod and any asset
	 * that has wlg or test is test." Both ship enabled; both are ordinary
	 * rows, so an administrator can reorder, edit or delete them.
	 */
	public static function seed_defaults(): void {
		global $wpdb;

		if ( (int) get_option( self::SEED_OPTION, 0 ) ) {
			return;
		}

		$table = self::table( 'class_rules' );
		$count = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . $table ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared

		if ( $count > 0 ) {
			update_option( self::SEED_OPTION, 1, false );
			return;
		}

		$defaults = array(
			array(
				'name'            => __( 'Auckland and POD hosts are production', 'vulnhub' ),
				'description'     => __( 'Hostnames carrying the akl or pod site code run production workloads.', 'vulnhub' ),
				'priority'        => 100,
				'match_type'      => 'any',
				'set_environment' => 'production',
				'conditions'      => array(
					array( 'hostname', '', 'contains', 'akl' ),
					array( 'hostname', '', 'contains', 'pod' ),
				),
			),
			array(
				'name'            => __( 'Wellington and test hosts are test', 'vulnhub' ),
				'description'     => __( 'Hostnames carrying wlg or test are non-production.', 'vulnhub' ),
				'priority'        => 110,
				'match_type'      => 'any',
				'set_environment' => 'test',
				'conditions'      => array(
					array( 'hostname', '', 'contains', 'wlg' ),
					array( 'hostname', '', 'contains', 'test' ),
				),
			),
		);

		$now = gmdate( 'Y-m-d H:i:s' );

		foreach ( $defaults as $rule ) {
			$wpdb->insert(
				$table,
				array(
					'name'            => (string) $rule['name'],
					'description'     => (string) $rule['description'],
					'enabled'         => 1,
					'priority'        => (int) $rule['priority'],
					'match_type'      => (string) $rule['match_type'],
					'stop_processing' => 0,
					'set_environment' => (string) $rule['set_environment'],
					'created_at'      => $now,
					'updated_at'      => $now,
				)
			);

			$rule_id = (int) $wpdb->insert_id;
			if ( ! $rule_id ) {
				continue;
			}

			$position = 0;
			foreach ( (array) $rule['conditions'] as $condition ) {
				$wpdb->insert(
					self::table( 'class_rule_conditions' ),
					array(
						'rule_id'        => $rule_id,
						'position'       => $position++,
						'match_field'    => (string) $condition[0],
						'field_key'      => (string) $condition[1],
						'match_operator' => (string) $condition[2],
						'match_value'    => (string) $condition[3],
					)
				);
			}
		}

		update_option( self::SEED_OPTION, 1, false );
	}
}

