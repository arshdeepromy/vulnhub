<?php
/**
 * Plugin Name:       VulnHub Backup
 * Plugin URI:        https://github.com/arshdeepromy/vulnhub
 * Description:       Full-fidelity backup and restore for VulnHub — batched, resumable DB export and wp-content archiving, optional scheduled push to S3 with count-based retention, and a chunked-upload restore path for standing the site up again on a fresh stack.
 * Version:           1.0.0
 * Requires at least: 6.5
 * Requires PHP:      8.1
 * Author:            Romy Sidhu
 * License:           GPL-2.0-or-later
 * Text Domain:       vulnhub
 *
 * @package VulnHub\Backup
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_BACKUP_VERSION', '1.0.0' );
define( 'VULNHUB_BACKUP_FILE', __FILE__ );
define( 'VULNHUB_BACKUP_DIR', plugin_dir_path( __FILE__ ) );
define( 'VULNHUB_BACKUP_URL', plugin_dir_url( __FILE__ ) );

/**
 * Load every class this plugin owns. Idempotent, and safe to call before core
 * has booted — nothing here runs at file scope.
 *
 * @return void
 */
function vulnhub_backup_load(): void {
	require_once VULNHUB_BACKUP_DIR . 'includes/class-vh-backup-jobs.php';
	require_once VULNHUB_BACKUP_DIR . 'includes/class-vh-backup-storage.php';
	require_once VULNHUB_BACKUP_DIR . 'includes/class-vh-backup-s3.php';
	require_once VULNHUB_BACKUP_DIR . 'includes/class-vh-backup-runner.php';
	require_once VULNHUB_BACKUP_DIR . 'includes/class-vh-backup-restore-runner.php';
	require_once VULNHUB_BACKUP_DIR . 'includes/class-vh-backup-scheduler.php';
	require_once VULNHUB_BACKUP_DIR . 'includes/class-vh-backup-rest.php';
}

/**
 * Create the jobs table and the protected storage directory on activation.
 *
 * @return void
 */
function vulnhub_backup_activate(): void {
	vulnhub_backup_load();

	VulnHub_Backup_Jobs::install();
	VulnHub_Backup_Storage::ensure_dir();

	if ( ! wp_next_scheduled( VulnHub_Backup_Runner::SWEEP_HOOK ) ) {
		wp_schedule_event( time() + 60, 'vh_5min', VulnHub_Backup_Runner::SWEEP_HOOK );
	}
}
register_activation_hook( __FILE__, 'vulnhub_backup_activate' );

/**
 * Tear down our own schedules. The jobs table and any local archives are
 * deliberately left alone — a deactivate/reactivate cycle should not lose
 * backup history or force a re-download of anything already staged.
 *
 * @return void
 */
function vulnhub_backup_deactivate(): void {
	vulnhub_backup_load();
	wp_clear_scheduled_hook( VulnHub_Backup_Runner::SWEEP_HOOK );
	wp_clear_scheduled_hook( VulnHub_Backup_Scheduler::HOOK_RUN );
}
register_deactivation_hook( __FILE__, 'vulnhub_backup_deactivate' );

/**
 * Boot. Core loads on `plugins_loaded` priority 5, so priority 20 is the
 * earliest point at which `vulnhub()` is guaranteed to exist. Plugins load
 * alphabetically, so this file itself must never call vulnhub() outside a
 * hook callback.
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
							esc_html__( 'VulnHub Backup:', 'vulnhub' ),
							esc_html__( 'VulnHub Core must be active before backups can run.', 'vulnhub' )
						);
					}
				}
			);
			return;
		}

		vulnhub_backup_load();

		VulnHub_Backup_Jobs::maybe_install();
		VulnHub_Backup_Runner::hooks();
		VulnHub_Backup_Restore_Runner::hooks();
		VulnHub_Backup_Scheduler::hooks();

		add_action(
			'rest_api_init',
			static function (): void {
				( new VulnHub_Backup_Rest() )->register_routes();
			}
		);
	},
	20
);

/**
 * Add the Backup & Restore screen to the VulnHub admin menu.
 *
 * The `view` key deliberately names a file that does not exist under core's
 * own admin/views/ directory, so Admin::render_screen() falls through to the
 * `vulnhub_render_admin_page` action below rather than trying to include one
 * of core's templates.
 */
add_filter(
	'vulnhub_admin_pages',
	static function ( array $pages ): array {
		$pages['vulnhub-backup'] = array(
			'title' => __( 'Backup & Restore', 'vulnhub' ),
			'menu'  => __( 'Backup', 'vulnhub' ),
			'cap'   => \VulnHub\Core\Caps::MANAGE,
			'view'  => 'backup',
		);

		return $pages;
	}
);

add_action(
	'vulnhub_render_admin_page',
	static function ( string $slug ): void {
		if ( 'vulnhub-backup' !== $slug ) {
			return;
		}
		if ( ! function_exists( 'vulnhub' ) || ! current_user_can( \VulnHub\Core\Caps::MANAGE ) ) {
			return;
		}

		vulnhub_backup_load();
		include VULNHUB_BACKUP_DIR . 'admin/views/backup.php';
	}
);

/**
 * Cache-busting version for one bundled asset: the plugin version plus the
 * file's own mtime.
 *
 * The plugin version alone moves only on release, so a CDN in front of the
 * portal serves the old file to anyone who loaded the page recently -- new
 * markup styled by old rules. The mtime changes exactly when the bytes do.
 * Mirrors VulnHub_Dash_App::asset_ver().
 *
 * @param string $rel Path relative to the plugin directory.
 */
function vulnhub_backup_asset_ver( string $rel ): string {
	$mtime = @filemtime( VULNHUB_BACKUP_DIR . $rel ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

	return $mtime ? VULNHUB_BACKUP_VERSION . '.' . $mtime : VULNHUB_BACKUP_VERSION;
}

/**
 * Enqueue this screen's own script/style, on top of the shared vulnhub-app
 * bundle every other integration screen depends on for visual consistency.
 *
 * Split out of the hook so the portal can enqueue exactly the same script with
 * exactly the same REST root and nonces — see vulnhub_backup_portal_assets().
 *
 * @return void
 */
function vulnhub_backup_enqueue(): void {
	vulnhub_backup_load();

	wp_enqueue_style( 'vulnhub-backup', VULNHUB_BACKUP_URL . 'assets/backup.css', array( 'vulnhub-app' ), vulnhub_backup_asset_ver( 'assets/backup.css' ) );
	wp_enqueue_script( 'vulnhub-backup', VULNHUB_BACKUP_URL . 'assets/backup.js', array(), vulnhub_backup_asset_ver( 'assets/backup.js' ), true );

	wp_localize_script(
		'vulnhub-backup',
		'VulnHubBackup',
		array(
			'root'      => esc_url_raw( rest_url( VulnHub_Backup_Rest::NS . '/' ) ),
			'restNonce' => wp_create_nonce( 'wp_rest' ),
			'nonce'     => wp_create_nonce( VulnHub_Backup_Rest::NONCE ),
			'chunkSize' => VulnHub_Backup_Storage::chunk_size(),
			'maxChunk'  => VulnHub_Backup_Storage::chunk_max(),
			'siteHost'  => wp_parse_url( home_url(), PHP_URL_HOST ),
			'i18n'      => array(
				'confirmRestore' => __( 'This will permanently replace every table and every plugin/theme/upload file on this site. Type the site domain above to confirm.', 'vulnhub' ),
				'wrongDomain'    => __( 'That does not match this site\'s domain.', 'vulnhub' ),
				'uploading'      => __( 'Uploading…', 'vulnhub' ),
				'failed'         => __( 'Something went wrong.', 'vulnhub' ),
				'finished'       => __( 'Backup finished.', 'vulnhub' ),
				'failedJob'      => __( 'The backup failed.', 'vulnhub' ),
				'cancelled'      => __( 'Backup cancelled.', 'vulnhub' ),
				'working'        => __( 'Working…', 'vulnhub' ),
			),
		)
	);
}

add_action(
	'admin_enqueue_scripts',
	static function ( string $hook ): void {
		unset( $hook );

		if ( ! isset( $_GET['page'] ) || 'vulnhub-backup' !== sanitize_key( wp_unslash( $_GET['page'] ) ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			return;
		}
		if ( ! current_user_can( \VulnHub\Core\Caps::MANAGE ) ) {
			return;
		}

		vulnhub_backup_enqueue();
	}
);

/**
 * The same assets, on the portal's copy of this screen.
 *
 * `/portal-admin/?section=screen-vulnhub-backup` renders this very view
 * through core's render_screen(), but it is a front-end page: nothing here was
 * ever enqueued, so the screen had no progress polling and no uploader at all.
 * Pressing "Backup now" appeared to do nothing but move you somewhere else.
 *
 * Mirrors VulnHub_Admin::portal_assets(), which had to solve this for the
 * connector cards.
 *
 * @return void
 */
function vulnhub_backup_portal_assets(): void {
	if ( ! class_exists( 'VulnHub_Dash_Portal' ) || ! class_exists( 'VulnHub_Dash_App' ) ) {
		return;
	}
	if ( ! current_user_can( \VulnHub\Core\Caps::MANAGE ) ) {
		return;
	}
	if ( VulnHub_Dash_App::view_for_post( get_post() ) !== VulnHub_Dash_Portal::ADMIN_VIEW ) {
		return;
	}

	vulnhub_backup_load();

	// Only on this section: the portal's admin area is one page, so without
	// this every admin screen would carry the uploader's script.
	if ( VulnHub_Dash_Portal::current_section() !== VulnHub_Dash_Portal::MIRROR_PREFIX . 'vulnhub-backup' ) {
		return;
	}

	vulnhub_backup_enqueue();
}
add_action( 'wp_enqueue_scripts', 'vulnhub_backup_portal_assets' );

/**
 * Form handlers: manual backup trigger, settings save, local delete.
 * Each mirrors Admin::guard() inline since that method is private to core's
 * own Admin class.
 */
add_action(
	'admin_post_vulnhub_backup_now',
	static function (): void {
		if ( ! current_user_can( \VulnHub\Core\Caps::MANAGE ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'vulnhub_backup_now' );

		vulnhub_backup_load();

		$job_id = VulnHub_Backup_Runner::start_new( 'manual' );

		/*
		 * vh_admin_url(), never admin_url(). The portal mirrors this screen and
		 * posts to admin-post.php exactly as wp-admin does; a hardcoded
		 * admin_url() redirect walks the operator out of the portal mid-task,
		 * and a portal-only account is then bounced from wp-admin to the
		 * dashboard -- which looks like the button threw the backup away.
		 */
		wp_safe_redirect(
			vh_admin_url(
				'vulnhub-backup',
				array(
					'vh_msg'  => $job_id ? __( 'Backup started. It runs in the background — this page follows it.', 'vulnhub' ) : __( 'Could not start the backup.', 'vulnhub' ),
					'vh_type' => $job_id ? 'success' : 'error',
					'vh_job'  => $job_id,
				)
			)
		);
		exit;
	}
);

add_action(
	'admin_post_vulnhub_backup_save_settings',
	static function (): void {
		if ( ! current_user_can( \VulnHub\Core\Caps::MANAGE ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'vulnhub_backup_save_settings' );

		vulnhub_backup_load();

		$settings = vulnhub()->settings;
		$id       = 'backup_s3';

		if ( isset( $_POST['clear_access_key_id'] ) ) {
			$settings->set_secret( $id, 'access_key_id', null );
		} elseif ( isset( $_POST['vh_access_key_id'] ) ) {
			$settings->set_secret( $id, 'access_key_id', (string) wp_unslash( $_POST['vh_access_key_id'] ) );
		}

		if ( isset( $_POST['clear_secret_access_key'] ) ) {
			$settings->set_secret( $id, 'secret_access_key', null );
		} elseif ( isset( $_POST['vh_secret_access_key'] ) ) {
			$settings->set_secret( $id, 'secret_access_key', (string) wp_unslash( $_POST['vh_secret_access_key'] ) );
		}

		$values = array(
			'enabled'         => isset( $_POST['enabled'] ) ? 1 : 0,
			'bucket'          => isset( $_POST['bucket'] ) ? sanitize_text_field( wp_unslash( $_POST['bucket'] ) ) : '',
			'region'          => isset( $_POST['region'] ) ? sanitize_text_field( wp_unslash( $_POST['region'] ) ) : 'us-east-1',
			'prefix'          => isset( $_POST['prefix'] ) ? trim( sanitize_text_field( wp_unslash( $_POST['prefix'] ) ), '/' ) : 'vulnhub-backups',
			'interval'        => isset( $_POST['interval'] ) ? sanitize_key( wp_unslash( $_POST['interval'] ) ) : 'manual',
			'retention_count' => isset( $_POST['retention_count'] ) ? max( 1, min( 365, (int) $_POST['retention_count'] ) ) : 10,
		);

		$settings->update( $id, $values );

		VulnHub_Backup_Scheduler::ensure_schedule();

		vulnhub()->logger->audit( 'backup.settings_saved', __( 'Backup settings updated', 'vulnhub' ), 'backup', '', array( 'enabled' => $values['enabled'], 'interval' => $values['interval'] ) );

		wp_safe_redirect(
			vh_admin_url(
				'vulnhub-backup',
				array(
					'vh_msg'  => __( 'Backup settings saved.', 'vulnhub' ),
					'vh_type' => 'success',
				)
			)
		);
		exit;
	}
);

add_action(
	'admin_post_vulnhub_backup_delete',
	static function (): void {
		if ( ! current_user_can( \VulnHub\Core\Caps::MANAGE ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'vulnhub_backup_delete' );

		vulnhub_backup_load();

		$folder = isset( $_POST['folder'] ) ? sanitize_file_name( wp_unslash( $_POST['folder'] ) ) : '';

		if ( '' !== $folder ) {
			VulnHub_Backup_Storage::delete_local_set( $folder );
		}

		wp_safe_redirect(
			vh_admin_url(
				'vulnhub-backup',
				array(
					'vh_msg'  => __( 'Local backup deleted.', 'vulnhub' ),
					'vh_type' => 'success',
				)
			)
		);
		exit;
	}
);

