<?php
/**
 * Plugin Name:       VulnHub Import
 * Plugin URI:        https://vulnhub.example.com
 * Description:       Streaming, resumable, de-duplicating CSV import for VulnHub — chunked browser uploads, byte-offset checkpointing and cron-driven continuation, so a 300 MB Tenable or CMDB export imports without ever being held in memory.
 * Version:           1.0.0
 * Requires at least: 6.5
 * Requires PHP:      8.1
 * Author:            Romy Sidhu
 * License:           GPL-2.0-or-later
 * Text Domain:       vulnhub
 *
 * @package VulnHub\Import
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_IMPORT_VERSION', '1.0.5' );
define( 'VULNHUB_IMPORT_FILE', __FILE__ );
define( 'VULNHUB_IMPORT_DIR', plugin_dir_path( __FILE__ ) );
define( 'VULNHUB_IMPORT_URL', plugin_dir_url( __FILE__ ) );

/**
 * Load every class this plugin owns. Idempotent, and safe to call before core
 * has booted — nothing here runs at file scope.
 *
 * @return void
 */
function vulnhub_import_load(): void {
	require_once VULNHUB_IMPORT_DIR . 'includes/class-vh-import-jobs.php';
	require_once VULNHUB_IMPORT_DIR . 'includes/class-vh-import-storage.php';
	require_once VULNHUB_IMPORT_DIR . 'includes/class-vh-import-reader.php';
	require_once VULNHUB_IMPORT_DIR . 'includes/class-vh-import-schema.php';
	require_once VULNHUB_IMPORT_DIR . 'includes/class-vh-import-cmdb.php';
require_once VULNHUB_IMPORT_DIR . 'includes/class-vh-import-intune.php';
require_once VULNHUB_IMPORT_DIR . 'includes/class-vh-import-defender.php';
	require_once VULNHUB_IMPORT_DIR . 'includes/class-vh-import-tenable.php';
	require_once VULNHUB_IMPORT_DIR . 'includes/class-vh-import-runner.php';
	require_once VULNHUB_IMPORT_DIR . 'includes/class-vh-import-rest.php';
}

/**
 * Create the jobs table and the protected upload directory on activation.
 *
 * @return void
 */
function vulnhub_import_activate(): void {
	vulnhub_import_load();

	VulnHub_Import_Jobs::install();
	VulnHub_Import_Storage::ensure_dir();

	if ( ! wp_next_scheduled( VulnHub_Import_Runner::SWEEP_HOOK ) ) {
		wp_schedule_event( time() + 60, 'vh_5min', VulnHub_Import_Runner::SWEEP_HOOK );
	}
}
register_activation_hook( __FILE__, 'vulnhub_import_activate' );

/**
 * Tear down our own schedules. The jobs table and any uploaded temporary file
 * are deliberately left alone so a deactivate/reactivate cycle does not lose
 * an operator's import history mid-run.
 *
 * @return void
 */
function vulnhub_import_deactivate(): void {
	vulnhub_import_load();
	wp_clear_scheduled_hook( VulnHub_Import_Runner::SWEEP_HOOK );
}
register_deactivation_hook( __FILE__, 'vulnhub_import_deactivate' );

/**
 * Boot. Core loads on `plugins_loaded` priority 5, so priority 20 is the
 * earliest point at which `vulnhub()` is guaranteed to exist.
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
							esc_html__( 'VulnHub Import:', 'vulnhub' ),
							esc_html__( 'VulnHub Core must be active before CSV imports can run.', 'vulnhub' )
						);
					}
				}
			);
			return;
		}

		vulnhub_import_load();

		VulnHub_Import_Jobs::maybe_install();
		VulnHub_Import_Runner::hooks();

		add_action(
			'rest_api_init',
			static function (): void {
				( new VulnHub_Import_Rest() )->register_routes();
			}
		);
	},
	20
);

/**
 * Add the Imports screen to the VulnHub portal.
 *
 * Core's dashboard plugin already declares an `imports` slug with no view file
 * of its own, so this filter only refreshes the description; the render action
 * below is what actually fills the screen.
 */
add_filter(
	'vulnhub_portal_sections',
	static function ( array $sections ): array {
		$sections['imports'] = array(
			'label'   => __( 'Imports', 'vulnhub' ),
			'cap'     => 'vulnhub_manage',
			'group'   => 'data',
			'order'   => 20,
			'summary' => __( 'Upload CMDB and Tenable CSV exports — streamed, resumable and de-duplicated, whatever the file size.', 'vulnhub' ),
		);

		return $sections;
	}
);

add_action(
	'vulnhub_render_portal_section',
	static function ( string $section ): void {
		if ( 'imports' !== $section ) {
			return;
		}
		if ( ! function_exists( 'vulnhub' ) || ! current_user_can( 'vulnhub_manage' ) ) {
			return;
		}

		vulnhub_import_load();
		include VULNHUB_IMPORT_DIR . 'admin/views/imports.php';
	}
);

/**
 * Is the current request the portal's Imports screen?
 *
 * @return bool
 */
function vulnhub_import_is_screen(): bool {
	if ( is_admin() || ! class_exists( 'VulnHub_Dash_App' ) || ! class_exists( 'VulnHub_Dash_Portal' ) ) {
		return false;
	}
	if ( VulnHub_Dash_App::view_for_post( get_post() ) !== VulnHub_Dash_Portal::ADMIN_VIEW ) {
		return false;
	}

	return 'imports' === VulnHub_Dash_Portal::current_section();
}

/**
 * Enqueue the importer's own stylesheet and script, only on its own screen.
 */
add_action(
	'wp_enqueue_scripts',
	static function (): void {
		if ( ! vulnhub_import_is_screen() || ! current_user_can( 'vulnhub_manage' ) ) {
			return;
		}

		wp_enqueue_style(
			'vulnhub-import',
			VULNHUB_IMPORT_URL . 'assets/import.css',
			array( 'vulnhub-app' ),
			VULNHUB_IMPORT_VERSION
		);

		wp_enqueue_script(
			'vulnhub-import',
			VULNHUB_IMPORT_URL . 'assets/import.js',
			array(),
			VULNHUB_IMPORT_VERSION,
			true
		);

		vulnhub_import_load();

		wp_localize_script(
			'vulnhub-import',
			'VulnHubImport',
			array(
				'root'      => esc_url_raw( rest_url( VulnHub_Import_Rest::NS . '/' ) ),
				'restNonce' => wp_create_nonce( 'wp_rest' ),
				'nonce'     => wp_create_nonce( VulnHub_Import_Rest::NONCE ),
				'chunkSize' => VulnHub_Import_Storage::chunk_size(),
				'maxChunk'  => VulnHub_Import_Storage::chunk_max(),
				'maxBytes'  => VulnHub_Import_Storage::max_bytes(),
				'i18n'      => array(
					'uploading'   => __( 'Uploading', 'vulnhub' ),
					'analysing'   => __( 'Analysing the file…', 'vulnhub' ),
					'failed'      => __( 'Something went wrong.', 'vulnhub' ),
					'tooBig'      => sprintf(
						/* translators: %s: the largest file the importer accepts. */
						__( 'That file is larger than the %s this importer accepts.', 'vulnhub' ),
						size_format( VulnHub_Import_Storage::max_bytes() )
					),
					'retrying'    => __( 'Connection hiccup — retrying that slice', 'vulnhub' ),
					'badType'     => __( 'Only .csv, .tsv and .txt files are accepted.', 'vulnhub' ),
					'confirmRun'  => __( 'Start importing this file?', 'vulnhub' ),
					'confirmStop' => __( 'Cancel this job? Rows already imported are kept.', 'vulnhub' ),
					'duplicate'   => __( 'You have already imported this exact file.', 'vulnhub' ),
					'done'        => __( 'Import finished.', 'vulnhub' ),
					'perSecond'   => __( 'rows/sec', 'vulnhub' ),
					'eta'         => __( 'ETA', 'vulnhub' ),
				),
			)
		);
	},
	20
);

