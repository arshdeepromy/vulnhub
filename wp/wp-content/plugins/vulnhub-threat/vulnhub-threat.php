<?php
/**
 * Plugin Name:       VulnHub Threat Context
 * Plugin URI:        https://github.com/arshdeepromy/vulnhub
 * Description:       Answers "how would somebody actually reach this?" — extracts CVE ids from scanner titles and descriptions, enriches them from NVD, CISA KEV and FIRST EPSS, and sorts every open finding into the route an attacker would have to take: delivered to a person, reachable from the internet, or only usable once they are already inside.
 * Version:           1.0.0
 * Requires at least: 6.5
 * Requires PHP:      8.1
 * Author:            Romy Sidhu
 * License:           GPL-2.0-or-later
 * Text Domain:       vulnhub
 *
 * @package VulnHub\Threat
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_THREAT_VERSION', '1.0.0' );
define( 'VULNHUB_THREAT_DIR', plugin_dir_path( __FILE__ ) );
define( 'VULNHUB_THREAT_URL', plugin_dir_url( __FILE__ ) );

require_once VULNHUB_THREAT_DIR . 'includes/class-vh-threat-install.php';
require_once VULNHUB_THREAT_DIR . 'includes/class-vh-threat-feeds.php';
require_once VULNHUB_THREAT_DIR . 'includes/class-vh-threat-ports.php';
require_once VULNHUB_THREAT_DIR . 'includes/class-vh-threat-classify.php';
require_once VULNHUB_THREAT_DIR . 'includes/class-vh-threat-repo.php';
require_once VULNHUB_THREAT_DIR . 'includes/class-vh-threat-widget.php';
require_once VULNHUB_THREAT_DIR . 'includes/class-vh-threat-admin.php';

register_activation_hook( __FILE__, array( 'VulnHub_Threat_Install', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'VulnHub_Threat_Install', 'deactivate' ) );

/*
 * Boot after everything else.
 *
 * Plugins load alphabetically, so `vulnhub-threat` already loads after
 * `vulnhub-core` and `vulnhub-dashboard`. That is luck rather than design, and
 * a rename would silently break it, so the check is on `plugins_loaded` like
 * every other plugin here rather than at file scope.
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
							esc_html__( 'VulnHub Threat Context:', 'vulnhub' ),
							esc_html__( 'VulnHub Core must be active — there are no vulnerabilities to place without it.', 'vulnhub' )
						);
					}
				}
			);

			return;
		}

		VulnHub_Threat_Install::maybe_upgrade();
		VulnHub_Threat_Ports::init();
		VulnHub_Threat_Feeds::init();
		VulnHub_Threat_Repo::init();
		VulnHub_Threat_Widget::init();
		VulnHub_Threat_Admin::init();
	},
	20
);

/*
 * The heavy refresh is a WP-CLI command as well as a cron event.
 *
 * The cron container runs `wp cron event run --due-now` every 60s in the
 * wordpress:cli image, so the scheduled event and the command execute in the
 * same place — which is the only place with a decompressor for the NVD year
 * files and no request timeout over it.
 */
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	WP_CLI::add_command(
		'vulnhub threat',
		static function ( array $args, array $assoc ): void {
			$sub = (string) ( $args[0] ?? 'refresh' );

			switch ( $sub ) {
				case 'refresh':
					$report = VulnHub_Threat_Feeds::refresh_all( ! empty( $assoc['force'] ) );
					foreach ( $report as $line ) {
						WP_CLI::log( $line );
					}
					WP_CLI::success( 'Threat context refreshed.' );
					break;

				case 'classify':
					$n = VulnHub_Threat_Classify::rebuild_all();
					WP_CLI::success( sprintf( '%d vulnerability definitions placed.', $n ) );
					break;

				case 'status':
					foreach ( VulnHub_Threat_Feeds::status() as $k => $v ) {
						WP_CLI::log( str_pad( (string) $k, 22 ) . ( is_scalar( $v ) ? (string) $v : wp_json_encode( $v ) ) );
					}
					break;

				default:
					WP_CLI::error( 'Unknown subcommand. Try: refresh | classify | status' );
			}
		}
	);
}
