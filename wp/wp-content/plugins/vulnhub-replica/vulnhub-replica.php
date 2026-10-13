<?php
/**
 * Plugin Name:       VulnHub Instance Sync
 * Description:       Keep one instance a one-way copy of another: a sync key from the source, a frequency on the copy, and the data arrives as zipped, chunked, checksummed packages of only what changed. A copy never acts on a real system.
 * Version:           1.0.0
 * Requires at least: 6.4
 * Requires PHP:      8.1
 * Author:            VulnHub
 * License:           GPL-2.0-or-later
 * Text Domain:       vulnhub
 *
 * Both halves live here, so any instance can be a source, a copy, or (rarely)
 * both in a chain. See docs/REPLICATION.md.
 *
 * @package VulnHub\Replica
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_REPLICA_DIR', plugin_dir_path( __FILE__ ) );
define( 'VULNHUB_REPLICA_VERSION', '1.0.0' );

require_once VULNHUB_REPLICA_DIR . 'includes/class-vh-replica-schema.php';
require_once VULNHUB_REPLICA_DIR . 'includes/class-vh-replica-tokens.php';
require_once VULNHUB_REPLICA_DIR . 'includes/class-vh-replica-job.php';
require_once VULNHUB_REPLICA_DIR . 'includes/class-vh-replica-source.php';
require_once VULNHUB_REPLICA_DIR . 'includes/class-vh-replica-guard.php';
require_once VULNHUB_REPLICA_DIR . 'includes/class-vh-replica-admin.php';

/*
 * The guard goes on as early as possible: before any other plugin's
 * plugins_loaded callback can schedule or send anything.
 */
VulnHub_Replica_Guard::init();

add_action(
	'plugins_loaded',
	static function (): void {
		if ( ! function_exists( 'vulnhub' ) ) {
			return;
		}

		VulnHub_Replica_Tokens::maybe_install();
		VulnHub_Replica_Source::init();
		VulnHub_Replica_Admin::init();

		add_filter( 'vulnhub_sync_disk_progress_at', array( 'VulnHub_Replica_Connector', 'disk_heartbeat' ), 10, 2 );

		// Packages a copy started and never collected.
		add_action( 'vulnhub_replica_sweep', array( 'VulnHub_Replica_Job', 'sweep' ) );
		if ( ! wp_next_scheduled( 'vulnhub_replica_sweep' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'vulnhub_replica_sweep' );
		}

		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			require_once VULNHUB_REPLICA_DIR . 'includes/class-vh-replica-cli.php';
			\WP_CLI::add_command( 'vulnhub-replica', 'VulnHub_Replica_CLI' );
		}
	},
	20
);

add_action(
	'vulnhub_register_connectors',
	static function ( $connectors ): void {
		// Core fires this at plugins_loaded:5, before our own callback above.
		require_once VULNHUB_REPLICA_DIR . 'includes/class-vh-replica-connector.php';
		$connectors->register( new VulnHub_Replica_Connector() );
	}
);

register_deactivation_hook(
	__FILE__,
	static function (): void {
		wp_clear_scheduled_hook( 'vulnhub_replica_sweep' );
	}
);

