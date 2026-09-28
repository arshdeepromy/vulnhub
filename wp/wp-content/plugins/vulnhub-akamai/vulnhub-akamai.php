<?php
/**
 * Plugin Name: VulnHub Akamai
 * Description: Reads the public edge from Akamai — properties, the hostnames they serve, the origin behind each one, and which hostnames a WAF policy covers. Read-only.
 * Version: 0.1.0
 * Requires PHP: 8.1
 *
 * The domain store this writes into lives in the AWS plugin, which is where
 * it grew up; the name is historical and the store is shared on purpose, so
 * one question -- what is this called and what stands in front of it -- has
 * one answer whichever system happens to know it.
 *
 * @package VulnHub\Akamai
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_AKAMAI_DIR', plugin_dir_path( __FILE__ ) );
define( 'VULNHUB_AKAMAI_URL', plugin_dir_url( __FILE__ ) );
define( 'VULNHUB_AKAMAI_VERSION', '0.1.0' );

add_action(
	'vulnhub_register_connectors',
	/**
	 * @param object $connectors The registry.
	 */
	static function ( $connectors ): void {
		require_once VULNHUB_AKAMAI_DIR . 'includes/class-vh-akamai-client.php';
		require_once VULNHUB_AKAMAI_DIR . 'includes/class-vh-akamai-connector.php';

		$connectors->register( new VulnHub_Akamai_Connector() );
	}
);

