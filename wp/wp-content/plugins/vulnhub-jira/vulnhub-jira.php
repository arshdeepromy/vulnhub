<?php
/**
 * Plugin Name:       VulnHub Jira
 * Plugin URI:        https://vul.romynz.com
 * Description:       Jira Cloud integration for VulnHub — raises remediation tickets from findings with a genuine Atlassian Document Format description, keeps their status in sync in batched JQL queries, reopens issues the scanner still detects, and drives a configurable automation engine that flows tickets to the right team.
 * Version:           1.0.0
 * Requires at least: 6.5
 * Requires PHP:      8.1
 * Author:            Romy Sidhu
 * License:           GPL-2.0-or-later
 * Text Domain:       vulnhub
 *
 * @package VulnHub\Jira
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_JIRA_VERSION', '1.0.0' );
define( 'VULNHUB_JIRA_FILE', __FILE__ );
define( 'VULNHUB_JIRA_DIR', plugin_dir_path( __FILE__ ) );

/**
 * Load every class this plugin owns.
 *
 * Integration plugins do not share core's autoloader, so each file is required
 * explicitly (see docs/CORE-API.md §1).
 */
function vulnhub_jira_load(): void {
	static $loaded = false;

	if ( $loaded ) {
		return;
	}
	$loaded = true;

	require_once VULNHUB_JIRA_DIR . 'includes/class-vh-jira-adf.php';
	require_once VULNHUB_JIRA_DIR . 'includes/class-vh-jira-mock.php';
	require_once VULNHUB_JIRA_DIR . 'includes/class-vh-jira-client.php';
	require_once VULNHUB_JIRA_DIR . 'includes/class-vh-jira-connector.php';
	require_once VULNHUB_JIRA_DIR . 'includes/class-vh-jira-directory.php';
	require_once VULNHUB_JIRA_DIR . 'includes/class-vh-jira-ticketer.php';
	require_once VULNHUB_JIRA_DIR . 'includes/class-vh-jira-reopener.php';
	require_once VULNHUB_JIRA_DIR . 'includes/class-vh-jira-automation.php';
	require_once VULNHUB_JIRA_DIR . 'includes/class-vh-jira-automation-admin.php';
	require_once VULNHUB_JIRA_DIR . 'includes/class-vh-jira-routing-admin.php';
}

/**
 * The registered Jira connector, or null when core has not booted it yet.
 */
function vulnhub_jira_connector(): ?VulnHub_Jira_Connector {
	if ( ! function_exists( 'vulnhub' ) ) {
		return null;
	}

	$connector = vulnhub()->connectors->get( 'jira' );

	return $connector instanceof VulnHub_Jira_Connector ? $connector : null;
}

/**
 * Shared ticket writer (grouping, ADF bodies, persistence).
 */
function vulnhub_jira_ticketer(): VulnHub_Jira_Ticketer {
	static $instance = null;

	if ( null === $instance ) {
		vulnhub_jira_load();
		$instance = new VulnHub_Jira_Ticketer();
	}

	return $instance;
}

/**
 * Shared routing directory (service desks, request types, Team field).
 */
function vulnhub_jira_directory(): ?VulnHub_Jira_Directory {
	vulnhub_jira_load();

	return VulnHub_Jira_Directory::instance();
}

/**
 * Shared automation engine.
 */
function vulnhub_jira_automation(): VulnHub_Jira_Automation {
	static $instance = null;

	if ( null === $instance ) {
		vulnhub_jira_load();
		$instance = new VulnHub_Jira_Automation();
	}

	return $instance;
}

/**
 * Register the connector and everything that hangs off it.
 *
 * Core fires this on `plugins_loaded` once its own subsystems exist, which is
 * the earliest point at which `vulnhub()` is safe to call.
 *
 * @param \VulnHub\Core\Connectors $connectors Connector registry.
 */
add_action(
	'vulnhub_register_connectors',
	static function ( $connectors ): void {
		vulnhub_jira_load();

		$connectors->register( new VulnHub_Jira_Connector() );

		vulnhub_jira_ticketer()->hooks();
		vulnhub_jira_automation()->hooks();

		( new VulnHub_Jira_Reopener() )->hooks();
		( new VulnHub_Jira_Automation_Admin() )->hooks();
		( new VulnHub_Jira_Routing_Admin() )->hooks();
	}
);

/**
 * Seed the two example automation rules on activation.
 *
 * They are created disabled so nothing reaches Jira until an administrator
 * has read them and turned them on deliberately.
 */
register_activation_hook(
	VULNHUB_JIRA_FILE,
	static function (): void {
		if ( ! function_exists( 'vulnhub' ) ) {
			return;
		}

		vulnhub_jira_load();
		VulnHub_Jira_Automation::seed_examples();
	}
);

/**
 * Register the Automation and Jira screens on the VulnHub menu.
 *
 * Core has no view files by these names, so rendering falls through to the
 * `vulnhub_render_admin_page` action below.
 *
 * @param array<string,array<string,mixed>> $pages Registered screens.
 * @return array<string,array<string,mixed>>
 */
add_filter(
	'vulnhub_admin_pages',
	static function ( array $pages ): array {
		$pages['vulnhub-jira'] = array(
			'title' => __( 'Jira', 'vulnhub' ),
			'menu'  => __( 'Jira', 'vulnhub' ),
			'cap'   => 'vulnhub_view',
			'view'  => 'jira',
		);

		$pages['vulnhub-automation'] = array(
			'title' => __( 'Automation', 'vulnhub' ),
			'menu'  => __( 'Automation', 'vulnhub' ),
			'cap'   => 'vulnhub_view',
			'view'  => 'automation',
		);

		return $pages;
	}
);

/**
 * Render one of our screens.
 *
 * @param string $slug Screen slug being rendered.
 */
add_action(
	'vulnhub_render_admin_page',
	static function ( string $slug ): void {
		if ( 'vulnhub-jira' === $slug ) {
			vulnhub_jira_load();
			include VULNHUB_JIRA_DIR . 'admin/views/jira.php';
			return;
		}

		if ( 'vulnhub-automation' === $slug ) {
			vulnhub_jira_load();
			include VULNHUB_JIRA_DIR . 'admin/views/automation.php';
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
			esc_html__( 'VulnHub Jira requires the VulnHub Core plugin to be active.', 'vulnhub' )
		);
	}
);

