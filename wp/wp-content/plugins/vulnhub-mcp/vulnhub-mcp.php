<?php
/**
 * Plugin Name:  VulnHub MCP
 * Description:  A machine-facing surface for VulnHub, so an agent can read the estate, correct the CMDB, map assets on to Tenable and work the scanning-coverage gap list.
 * Version:      1.1.0
 * Requires PHP: 8.1
 * Author:       VulnHub
 * Text Domain:  vulnhub
 *
 * Every other integration in this platform is VulnHub talking to a vendor.
 * This one is the other direction: a vendor -- an agent -- talking to VulnHub.
 * It is deliberately a separate plugin so it can be switched off on its own,
 * and it writes through the same `Repo::upsert_asset()` the connectors use, so
 * an agent cannot invent a shape of record the rest of the platform has never
 * seen.
 *
 * @package VulnHub\MCP
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_MCP_VERSION', '1.1.0' );
define( 'VULNHUB_MCP_DIR', plugin_dir_path( __FILE__ ) );
define( 'VULNHUB_MCP_NS', 'vulnhub-mcp/v1' );

require_once VULNHUB_MCP_DIR . 'includes/class-vh-mcp-rest.php';
require_once VULNHUB_MCP_DIR . 'includes/class-vh-mcp-tokens.php';
require_once VULNHUB_MCP_DIR . 'includes/class-vh-mcp-tools.php';
require_once VULNHUB_MCP_DIR . 'includes/class-vh-mcp-server.php';
require_once VULNHUB_MCP_DIR . 'includes/class-vh-mcp-admin.php';

/**
 * Plugins load alphabetically, so core is already here -- but a rename would
 * change that silently, and the failure mode is an unrelated "class not
 * found" from wp-cli. Check on `plugins_loaded` and never at file scope.
 */
add_action(
	'plugins_loaded',
	static function (): void {
		if ( ! function_exists( 'vulnhub' ) ) {
			return;
		}

		add_action( 'rest_api_init', array( new VulnHub_MCP_Rest(), 'register_routes' ) );

		VulnHub_MCP_Tokens::maybe_install();
		VulnHub_MCP_Server::init();
		VulnHub_MCP_Admin::init();
	},
	20
);
