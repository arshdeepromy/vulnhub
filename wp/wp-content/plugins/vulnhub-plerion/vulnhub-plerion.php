<?php
/**
 * Plugin Name:       VulnHub Plerion
 * Description:       Reads cloud asset inventory and public-exposure from Plerion (CSPM/CIEM) across every connected AWS/Azure/GCP account through one read-only API key — no per-account roles.
 * Version:           0.1.0
 * Requires at least: 6.4
 * Requires PHP:      8.1
 * Author:            VulnHub
 * License:           GPL-2.0-or-later
 * Text Domain:       vulnhub
 *
 * Plerion already onboards the cloud accounts and aggregates their inventory,
 * vulnerabilities, misconfigurations and access grants centrally. So where the
 * AWS connector assumes a role in each member account, this one authenticates
 * once and reads the whole estate over REST -- which is why it works where the
 * per-account trust does not.
 *
 * @package VulnHub\Plerion
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_PLERION_DIR', plugin_dir_path( __FILE__ ) );
define( 'VULNHUB_PLERION_VERSION', '0.1.0' );
define( 'VULNHUB_PLERION_URL', plugin_dir_url( __FILE__ ) );

add_action(
	'vulnhub_register_connectors',
	/**
	 * @param \VulnHub\Core\Connectors $connectors Core connector registry.
	 */
	static function ( $connectors ): void {
		require_once VULNHUB_PLERION_DIR . 'includes/class-vh-plerion-client.php';
		require_once VULNHUB_PLERION_DIR . 'includes/class-vh-plerion-findings.php';
		require_once VULNHUB_PLERION_DIR . 'includes/class-vh-plerion-connector.php';

		VulnHub_Plerion_Findings::install();

		$connectors->register( new VulnHub_Plerion_Connector() );
	}
);

/**
 * Portal pages (Cloud Posture + Exposure map) register on their own hooks and
 * are independent of the connector registry.
 */
require_once VULNHUB_PLERION_DIR . 'includes/class-vh-plerion-findings.php';
require_once VULNHUB_PLERION_DIR . 'includes/class-vh-plerion-findings-page.php';
require_once VULNHUB_PLERION_DIR . 'includes/class-vh-plerion-exposure-page.php';

VulnHub_Plerion_Findings_Page::init();
VulnHub_Plerion_Exposure_Page::init();
