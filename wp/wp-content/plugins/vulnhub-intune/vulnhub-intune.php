<?php
/**
 * Plugin Name: VulnHub Intune &amp; Entra ID
 * Description: Syncs Microsoft Entra ID people and Intune managed devices into VulnHub, and feeds the primary-user signal the ownership engine needs to resolve workstations.
 * Version:     1.0.0
 * Requires PHP: 8.1
 * License:     GPL-2.0-or-later
 * Text Domain: vulnhub
 *
 * @package VulnHub\Intune
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_INTUNE_DIR', plugin_dir_path( __FILE__ ) );
define( 'VULNHUB_INTUNE_VERSION', '1.0.0' );
define( 'VULNHUB_INTUNE_PAGE', 'vulnhub-intune' );

/**
 * Register the connector with core.
 *
 * Core fires this on plugins_loaded:5, so everything below can assume the
 * `vulnhub()` singleton and the \VulnHub\Core\ namespace exist.
 *
 * @param \VulnHub\Core\Connectors $connectors Core connector registry.
 * @return void
 */
add_action(
	'vulnhub_register_connectors',
	static function ( $connectors ): void {
		require_once VULNHUB_INTUNE_DIR . 'includes/class-vh-intune-mock-graph.php';
		require_once VULNHUB_INTUNE_DIR . 'includes/class-vh-intune-client.php';
		require_once VULNHUB_INTUNE_DIR . 'includes/class-vh-intune-connector.php';

		$connectors->register( new VulnHub_Intune_Connector() );
	}
);

/**
 * Warn loudly when core is missing — the connector cannot load without it.
 *
 * @return void
 */
add_action(
	'admin_notices',
	static function (): void {
		if ( function_exists( 'vulnhub' ) ) {
			return;
		}
		echo '<div class="notice notice-error"><p>'
			. esc_html__( 'VulnHub Intune & Entra ID requires the VulnHub Core plugin to be active.', 'vulnhub' )
			. '</p></div>';
	}
);

/**
 * Register the Intune admin screen.
 *
 * The `view` key names a template that core does not ship, so core falls
 * through to the `vulnhub_render_admin_page` action below.
 *
 * @param array<string,array<string,mixed>> $pages Registered screens.
 * @return array<string,array<string,mixed>>
 */
add_filter(
	'vulnhub_admin_pages',
	static function ( array $pages ): array {
		$pages[ VULNHUB_INTUNE_PAGE ] = array(
			'title' => __( 'Intune &amp; Entra ID', 'vulnhub' ),
			'menu'  => __( 'Intune', 'vulnhub' ),
			'cap'   => 'vulnhub_view',
			'view'  => 'intune-entra',
		);
		return $pages;
	}
);

/**
 * Render the Intune admin screen.
 *
 * @param string $slug Screen slug core is rendering.
 * @return void
 */
add_action(
	'vulnhub_render_admin_page',
	static function ( string $slug ): void {
		if ( VULNHUB_INTUNE_PAGE !== $slug ) {
			return;
		}
		require VULNHUB_INTUNE_DIR . 'admin/views/intune.php';
	}
);

/**
 * Handle the "Sync now" button on the Intune screen.
 *
 * @return void
 */
add_action(
	'admin_post_vulnhub_intune_sync',
	static function (): void {
		if ( ! current_user_can( 'vulnhub_run_sync' ) ) {
			wp_die( esc_html__( 'You do not have permission to run a sync.', 'vulnhub' ) );
		}
		check_admin_referer( 'vulnhub_intune_sync' );

		$connector = function_exists( 'vulnhub' ) ? vulnhub()->connectors->get( 'intune' ) : null;
		$notice    = 'missing';

		if ( $connector ) {
			$result = $connector->sync(
				array(
					'force' => true,
					'mode'  => 'manual',
				)
			);
			$notice = ! empty( $result['ok'] ) ? 'synced' : 'failed';
		}

		wp_safe_redirect(
			add_query_arg(
				array(
					'page'        => VULNHUB_INTUNE_PAGE,
					'vh_intune'   => $notice,
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}
);

