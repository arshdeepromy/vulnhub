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
		require_once VULNHUB_TENABLE_DIR . 'includes/class-vh-tenable-store.php';
		require_once VULNHUB_TENABLE_DIR . 'includes/class-vh-tenable-mock.php';
		require_once VULNHUB_TENABLE_DIR . 'includes/class-vh-tenable-connector.php';
		require_once VULNHUB_TENABLE_DIR . 'includes/class-vh-tenable-verifier.php';
		require_once VULNHUB_TENABLE_DIR . 'includes/class-vh-tenable-schedules.php';
		require_once VULNHUB_TENABLE_DIR . 'includes/class-vh-tenable-ticket-check.php';

		$connectors->register( new VulnHub_Tenable_Connector() );

		( new VulnHub_Tenable_Verifier() )->hooks();
		( new VulnHub_Tenable_Ticket_Check() )->hooks();

		// A person deciding an asset's lifecycle overrides the full-resync
		// prune's decision, so the prune must not later undo theirs.
		add_action( 'vulnhub_lifecycle_changed', array( \VulnHub\Core\Repo::class, 'forget_pruned_tenable' ), 10, 1 );

		/*
		 * A staged sync writes chunk files for minutes at a time without
		 * finishing one, so the newest mtime under its staging directory is
		 * the truest sign it is alive. Answered here because only this plugin
		 * knows where it stages.
		 */
		add_filter(
			'vulnhub_sync_disk_progress_at',
			static function ( $latest, string $connector ) {
				if ( 'tenable' !== $connector ) {
					return $latest;
				}

				$dir = trailingslashit( (string) wp_upload_dir()['basedir'] ) . 'vulnhub-sync/tenable/';

				if ( ! is_dir( $dir ) ) {
					return $latest;
				}

				$newest = (int) $latest;

				foreach ( (array) glob( $dir . '*' ) as $file ) {
					$when = (int) @filemtime( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors

					if ( $when > $newest ) {
						$newest = $when;
					}
				}

				return $newest;
			},
			10,
			2
		);

		/*
		 * The hourly agent reading. Answered here rather than in core because
		 * only this connector can reach the endpoint -- core owns the history
		 * table, the connector owns the API.
		 */
		/*
		 * Confirm, a batch a day, which assets Tenable has actually dropped.
		 * On housekeeping rather than the sync: it is a small number of
		 * single-asset reads and must never lengthen an import.
		 */
		add_action(
			\VulnHub\Core\Scheduler::HOOK_HOUSEKEEP,
			static function (): void {
				$tenable = vulnhub()->connectors->get( 'tenable' );

				if ( $tenable instanceof VulnHub_Tenable_Connector ) {
					\VulnHub\Core\Tenable_Dropped::verify( $tenable );
				}
			}
		);



		/*
		 * The hourly agent reading. Answered here rather than in core because
		 * only this connector can reach the endpoint -- core owns the history
		 * table, the connector owns the API.
		 */
		add_action(
			\VulnHub\Core\Scheduler::HOOK_AGENT_STATUS,
			static function (): void {
				$tenable = vulnhub()->connectors->get( 'tenable' );

				if ( $tenable instanceof VulnHub_Tenable_Connector ) {
					\VulnHub\Core\Agent_Status::poll( $tenable );
				}
			}
		);
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


/*
 * AppStream cleanup is a front-end tool, not a connector, so it boots at file
 * load like the other page modules and registers its own REST, view and the
 * topbar-bell notice.
 */
require_once VULNHUB_TENABLE_DIR . 'includes/class-vh-tenable-appstream.php';
VulnHub_Tenable_AppStream::init();
