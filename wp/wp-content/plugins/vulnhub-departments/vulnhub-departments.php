<?php
/**
 * Plugin Name:       VulnHub Departments
 * Plugin URI:        https://github.com/arshdeepromy/vulnhub
 * Description:       Enriches existing people with the department they belong to from an Entra/Azure AD user export, and exposes department as a first-class dimension — a filter on the vulnerability list, a "Vulnerabilities by department" widget, and an export. It never creates users: a row that does not match an existing person is skipped.
 * Version:           1.0.0
 * Requires at least: 6.5
 * Requires PHP:      8.1
 * Author:            Romy Sidhu
 * License:           GPL-2.0-or-later
 * Text Domain:       vulnhub
 *
 * @package VulnHub\Departments
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_DEPT_VERSION', '1.0.0' );
define( 'VULNHUB_DEPT_DIR', plugin_dir_path( __FILE__ ) );
define( 'VULNHUB_DEPT_URL', plugin_dir_url( __FILE__ ) );

require_once VULNHUB_DEPT_DIR . 'includes/class-vh-departments.php';

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
							esc_html__( 'VulnHub Departments:', 'vulnhub' ),
							esc_html__( 'VulnHub Core must be active.', 'vulnhub' )
						);
					}
				}
			);

			return;
		}

		VulnHub_Departments::init();
	},
	20
);
