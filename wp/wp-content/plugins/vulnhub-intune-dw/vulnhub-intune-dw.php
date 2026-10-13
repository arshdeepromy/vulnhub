<?php
/**
 * Plugin Name: VulnHub Intune Data Warehouse
 * Description: Reads the Intune Data Warehouse OData feed — the reporting model behind Intune, as facts and dimensions. Read-only.
 * Version: 0.1.0
 * Requires PHP: 8.1
 *
 * A separate connector from the Graph one on purpose. They read different
 * APIs, hold different credentials, and answer different questions: Graph is
 * the live object, the warehouse is yesterday's snapshot with a little
 * history behind it. Nothing forces you to run both.
 *
 * @package VulnHub\IntuneDW
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_INTUNE_DW_DIR', plugin_dir_path( __FILE__ ) );
define( 'VULNHUB_INTUNE_DW_VERSION', '0.1.0' );

add_action(
	'vulnhub_register_connectors',
	/**
	 * @param object $connectors The registry.
	 */
	static function ( $connectors ): void {
		require_once VULNHUB_INTUNE_DW_DIR . 'includes/class-vh-intune-dw-client.php';
		require_once VULNHUB_INTUNE_DW_DIR . 'includes/class-vh-intune-dw-connector.php';

		$connectors->register( new VulnHub_Intune_DW_Connector() );
	}
);
