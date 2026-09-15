<?php
/**
 * Plugin Name:       VulnHub CMDB
 * Plugin URI:        https://vulnhub.example.com
 * Description:       Configuration management database integration for VulnHub — resolves the owning team, business service and site for assets that are not bound to a person, from ServiceNow, a Confluence page, or an uploaded CSV.
 * Version:           1.0.0
 * Requires at least: 6.5
 * Requires PHP:      8.1
 * Author:            Romy Sidhu
 * License:           GPL-2.0-or-later
 * Text Domain:       vulnhub
 *
 * @package VulnHub\Cmdb
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_CMDB_VERSION', '1.0.0' );
define( 'VULNHUB_CMDB_FILE', __FILE__ );
define( 'VULNHUB_CMDB_DIR', plugin_dir_path( __FILE__ ) );

/**
 * Load every class this plugin owns. Idempotent.
 */
function vulnhub_cmdb_load(): void {
	require_once VULNHUB_CMDB_DIR . 'includes/class-vh-cmdb-schema.php';
	require_once VULNHUB_CMDB_DIR . 'includes/class-vh-cmdb-html.php';
	require_once VULNHUB_CMDB_DIR . 'includes/class-vh-cmdb-csv.php';
	require_once VULNHUB_CMDB_DIR . 'includes/class-vh-cmdb-servicenow-client.php';
	require_once VULNHUB_CMDB_DIR . 'includes/class-vh-cmdb-confluence-client.php';
	require_once VULNHUB_CMDB_DIR . 'includes/class-vh-cmdb-mock.php';
	require_once VULNHUB_CMDB_DIR . 'includes/class-vh-cmdb-connector.php';
}

/**
 * Register the connector.
 *
 * Core fires this on `plugins_loaded`, once its own subsystems exist — which is
 * also the earliest point at which `vulnhub()` is safe to call.
 *
 * @param \VulnHub\Core\Connectors $connectors Connector registry.
 */
add_action(
	'vulnhub_register_connectors',
	static function ( $connectors ): void {
		vulnhub_cmdb_load();

		$connectors->register( new VulnHub_Cmdb_Connector() );
	}
);

/**
 * Register the admin screen handlers.
 *
 * These live outside `vulnhub_register_connectors` because `admin_post_*` has
 * to be hooked on every admin request, not just when connectors are built.
 */
add_action(
	'plugins_loaded',
	static function (): void {
		if ( ! is_admin() || ! function_exists( 'vulnhub' ) ) {
			return;
		}

		vulnhub_cmdb_load();
		require_once VULNHUB_CMDB_DIR . 'includes/class-vh-cmdb-admin.php';

		( new VulnHub_Cmdb_Admin() )->hooks();
	},
	20
);

/**
 * Add the CMDB screen to the VulnHub portal.
 *
 * Core has no view file by this name, so rendering falls through to the
 * `vulnhub_render_admin_page` action below.
 *
 * @param array<string,array<string,mixed>> $pages Registered screens.
 * @return array<string,array<string,mixed>>
 */
add_filter(
	'vulnhub_admin_pages',
	static function ( array $pages ): array {
		$pages['vulnhub-cmdb'] = array(
			'title' => __( 'CMDB', 'vulnhub' ),
			'menu'  => __( 'CMDB', 'vulnhub' ),
			'cap'   => 'vulnhub_view',
			'view'  => 'cmdb',
		);

		return $pages;
	}
);

/**
 * Render the CMDB screen.
 *
 * @param string $slug Screen slug being rendered.
 */
add_action(
	'vulnhub_render_admin_page',
	static function ( string $slug ): void {
		if ( 'vulnhub-cmdb' === $slug ) {
			include VULNHUB_CMDB_DIR . 'admin/views/cmdb.php';
		}
	}
);

/**
 * Fail loudly, but only in the admin, if core is not active.
 */
add_action(
	'admin_notices',
	static function (): void {
		if ( function_exists( 'vulnhub' ) ) {
			return;
		}

		printf(
			'<div class="notice notice-error"><p>%s</p></div>',
			esc_html__( 'VulnHub CMDB requires the VulnHub Core plugin to be active.', 'vulnhub' )
		);
	}
);

