<?php
/**
 * Plugin Name:       VulnHub Advisory Alerts
 * Plugin URI:        https://github.com/arshdeepromy/vulnhub
 * Description:       Watches free advisory and zero-day feeds — EUVD, Microsoft MSRC, CISA, GitHub, Red Hat, Ubuntu, or any RSS or JSON source you add — and tells you which of them can actually reach your estate, matched against the software and operating systems the inventory says you run.
 * Version:           1.0.0
 * Requires at least: 6.5
 * Requires PHP:      8.1
 * Author:            Romy Sidhu
 * License:           GPL-2.0-or-later
 * Text Domain:       vulnhub
 *
 * @package VulnHub\Alerts
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_ALERTS_VERSION', '1.0.0' );
define( 'VULNHUB_ALERTS_DIR', plugin_dir_path( __FILE__ ) );
define( 'VULNHUB_ALERTS_URL', plugin_dir_url( __FILE__ ) );

require_once VULNHUB_ALERTS_DIR . 'includes/class-vh-alerts-registry.php';
require_once VULNHUB_ALERTS_DIR . 'includes/class-vh-alerts-install.php';
require_once VULNHUB_ALERTS_DIR . 'includes/class-vh-alerts-inventory.php';
require_once VULNHUB_ALERTS_DIR . 'includes/class-vh-alerts-matcher.php';
require_once VULNHUB_ALERTS_DIR . 'includes/class-vh-alerts-adapter.php';
require_once VULNHUB_ALERTS_DIR . 'includes/class-vh-alerts-runner.php';
require_once VULNHUB_ALERTS_DIR . 'includes/class-vh-alerts-repo.php';
require_once VULNHUB_ALERTS_DIR . 'includes/class-vh-alerts-cron.php';
require_once VULNHUB_ALERTS_DIR . 'includes/class-vh-alerts-notify.php';
require_once VULNHUB_ALERTS_DIR . 'includes/class-vh-alerts-page.php';
require_once VULNHUB_ALERTS_DIR . 'includes/class-vh-alerts-admin.php';

/*
 * The generic RSS adapter first: glob() returns files alphabetically, so
 * `cisa` loaded before `rss` and fataled on extending a class that did not
 * exist yet. Anything else that subclasses an adapter needs the same
 * treatment, which is why this is a named list rather than a lucky sort.
 */
require_once VULNHUB_ALERTS_DIR . 'includes/adapters/class-vh-alerts-adapter-rss.php';

foreach ( glob( VULNHUB_ALERTS_DIR . 'includes/adapters/*.php' ) ?: array() as $adapter ) {
	require_once $adapter;
}

register_activation_hook( __FILE__, array( 'VulnHub_Alerts_Install', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'VulnHub_Alerts_Install', 'deactivate' ) );

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
							esc_html__( 'VulnHub Advisory Alerts:', 'vulnhub' ),
							esc_html__( 'VulnHub Core must be active — there is no inventory to match advisories against without it.', 'vulnhub' )
						);
					}
				}
			);

			return;
		}

		VulnHub_Alerts_Install::maybe_upgrade();
		VulnHub_Alerts_Inventory::init();
		VulnHub_Alerts_Cron::init();
		VulnHub_Alerts_Notify::init();
		VulnHub_Alerts_Page::init();
		VulnHub_Alerts_Admin::init();
	},
	20
);
