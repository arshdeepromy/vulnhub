<?php
/**
 * Plugin Name:       VulnHub Tenable
 * Plugin URI:        https://github.com/arshdeepromy/vulnhub
 * Description:       Tenable Vulnerability Management integration for VulnHub — imports assets and findings via the export APIs, classifies asset types for the ownership engine, computes SLA due dates, and verifies closed tickets against fresh scan data.
 * Version:           1.0.0
 * Requires at least: 6.5
 * Requires PHP:      8.1
 * Author:            Romy Sidhu
 * License:           GPL-2.0-or-later
 * Text Domain:       vulnhub
 *
 * @package VulnHub\Tenable
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_TENABLE_VERSION', '1.0.0' );
define( 'VULNHUB_TENABLE_FILE', __FILE__ );
define( 'VULNHUB_TENABLE_DIR', plugin_dir_path( __FILE__ ) );

/**
 * Register the connector and the closure-verification responder.
 *
 * Core fires this on `plugins_loaded` once its own subsystems exist, which is
 * also the earliest point at which `vulnhub()` is safe to call.
 *
 * @param \VulnHub\Core\Connectors $connectors Connector registry.
 */
add_action(
	'vulnhub_register_connectors',
	static function ( $connectors ): void {
		require_once VULNHUB_TENABLE_DIR . 'includes/class-vh-tenable-client.php';
		require_once VULNHUB_TENABLE_DIR . 'includes/class-vh-tenable-mock.php';
		require_once VULNHUB_TENABLE_DIR . 'includes/class-vh-tenable-connector.php';
		require_once VULNHUB_TENABLE_DIR . 'includes/class-vh-tenable-verifier.php';

		$connectors->register( new VulnHub_Tenable_Connector() );

		( new VulnHub_Tenable_Verifier() )->hooks();
	}
);

/**
 * Add the Tenable screen to the VulnHub portal.
 *
 * Core has no view file by this name, so it falls through to the
 * `vulnhub_render_admin_page` action below.
 *
 * @param array<string,array<string,mixed>> $pages Registered screens.
 * @return array<string,array<string,mixed>>
 */
add_filter(
	'vulnhub_admin_pages',
	static function ( array $pages ): array {
		$pages['vulnhub-tenable'] = array(
			'title' => __( 'Tenable', 'vulnhub' ),
			'menu'  => __( 'Tenable', 'vulnhub' ),
			'cap'   => 'vulnhub_view',
			'view'  => 'tenable',
		);

		return $pages;
	}
);

/**
 * Render the Tenable screen.
 *
 * @param string $slug Screen slug being rendered.
 */
add_action(
	'vulnhub_render_admin_page',
	static function ( string $slug ): void {
		if ( 'vulnhub-tenable' === $slug ) {
			include VULNHUB_TENABLE_DIR . 'admin/views/tenable.php';
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
			esc_html__( 'VulnHub Tenable requires the VulnHub Core plugin to be active.', 'vulnhub' )
		);
	}
);

