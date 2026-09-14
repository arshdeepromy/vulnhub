<?php
/**
 * Plugin Name:       VulnHub Hosting
 * Plugin URI:        https://github.com/arshdeepromy/vulnhub
 * Description:       Classifies servers by their hosting environment — cloud (AWS / Azure / GCP) versus on-prem (Datacom data centres and offices) — from cloud instance ids, the location register and hostname naming, and adds a dashboard widget showing the server count, the Linux-vs-Windows split and the open-finding exposure of each environment.
 * Version:           1.0.0
 * Requires at least: 6.5
 * Requires PHP:      8.1
 * Author:            Romy Sidhu
 * License:           GPL-2.0-or-later
 * Text Domain:       vulnhub
 *
 * @package VulnHub\Hosting
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_HOSTING_VERSION', '1.0.0' );
define( 'VULNHUB_HOSTING_DIR', plugin_dir_path( __FILE__ ) );

require_once VULNHUB_HOSTING_DIR . 'includes/class-vh-hosting.php';

add_action(
	'plugins_loaded',
	static function (): void {
		if ( ! function_exists( 'vulnhub' ) ) {
			return;
		}

		VulnHub_Hosting::init();
	},
	20
);
