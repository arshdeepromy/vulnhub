<?php
/**
 * Plugin Name:       VulnHub Docs
 * Plugin URI:        https://vulnhub.example.com
 * Description:       The built-in handbook and developer wiki for VulnHub. Adds a "Docs" section to the portal — a browsable set of guide and reference pages that explain every widget, every number and how the data is filtered, for new users and new developers alike — and links it from the primary navigation and the admin area.
 * Version:           1.0.0
 * Requires at least: 6.5
 * Requires PHP:      8.1
 * Author:            Romy Sidhu
 * License:           GPL-2.0-or-later
 * Text Domain:       vulnhub
 *
 * @package VulnHub\Docs
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_DOCS_VERSION', '1.0.0' );
define( 'VULNHUB_DOCS_DIR', plugin_dir_path( __FILE__ ) );
define( 'VULNHUB_DOCS_URL', plugin_dir_url( __FILE__ ) );

require_once VULNHUB_DOCS_DIR . 'includes/class-vh-docs-content.php';
require_once VULNHUB_DOCS_DIR . 'includes/class-vh-docs.php';

/*
 * The portal page that hosts the wiki is created on activation, the same way
 * every other view's page is. It carries the `[vulnhub_app view="docs"]`
 * shortcode, so the portal chrome (nav, theme, auth) wraps the wiki exactly as
 * it wraps the dashboard, and its id is remembered in `vulnhub_dash_pages` so
 * the navigation can build a link to it.
 */
register_activation_hook( __FILE__, array( 'VulnHub_Docs', 'activate' ) );

/*
 * Boot after core and the dashboard. Plugins load alphabetically, so
 * `vulnhub-docs` already loads after `vulnhub-core` and `vulnhub-dashboard`;
 * the guard on `vulnhub()` makes that explicit rather than incidental, and the
 * priority 20 matches the other satellite plugins.
 */
add_action(
	'plugins_loaded',
	static function (): void {
		if ( ! function_exists( 'vulnhub' ) ) {
			add_action(
				'admin_notices',
				static function (): void {
					if ( current_user_can( 'activate_plugins' ) ) {
						printf(
							'<div class="notice notice-error"><p><strong>%s</strong> %s</p></div>',
							esc_html__( 'VulnHub Docs:', 'vulnhub' ),
							esc_html__( 'VulnHub Core and Dashboard must be active — the docs live inside the portal they build.', 'vulnhub' )
						);
					}
				}
			);

			return;
		}

		VulnHub_Docs::init();
	},
	20
);
