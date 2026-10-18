<?php
/**
 * Plugin Name:       VulnHub Supplier Assessments
 * Plugin URI:        https://github.com/arshdeepromy/vulnhub
 * Description:       A register of third-party (supplier) information security assessments and security exceptions: rows inherited from a previous team's register and rows assessed here since, with reviewer, decision maker, conditions and review dates, each linked to its Jira tickets. Lists assessment requests from the Jira inbox that are not in the register yet, with the newest comment that reads as a decision.
 * Version:           1.0.0
 * Requires at least: 6.5
 * Requires PHP:      8.1
 * Author:            Romy Sidhu
 * License:           GPL-2.0-or-later
 * Text Domain:       vulnhub
 *
 * @package VulnHub\Assessments
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_ASSESS_VERSION', '1.0.0' );
define( 'VULNHUB_ASSESS_DIR', plugin_dir_path( __FILE__ ) );
define( 'VULNHUB_ASSESS_URL', plugin_dir_url( __FILE__ ) );

require_once VULNHUB_ASSESS_DIR . 'includes/class-vh-assess-repo.php';
require_once VULNHUB_ASSESS_DIR . 'includes/class-vh-assess-jira.php';
require_once VULNHUB_ASSESS_DIR . 'includes/class-vh-assess-view.php';

register_activation_hook(
	__FILE__,
	static function (): void {
		VH_Assess_Repo::install();
	}
);

add_action(
	'plugins_loaded',
	static function (): void {
		if ( ! function_exists( 'vulnhub' ) ) {
			return;
		}

		VH_Assess_Repo::init();
		VH_Assess_View::init();
	},
	20
);

if ( defined( 'WP_CLI' ) && WP_CLI ) {
	require_once VULNHUB_ASSESS_DIR . 'includes/class-vh-assess-cli.php';
	WP_CLI::add_command( 'vulnhub assessments', 'VH_Assess_CLI' );
}

