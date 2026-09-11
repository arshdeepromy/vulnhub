<?php
/**
 * Cron scheduling for automatic backups.
 *
 * Parallel to core's \VulnHub\Core\Scheduler, not an extension of it — core's
 * ensure_schedules() is hard-wired to registered sync connectors plus a fixed
 * standing-jobs array, not an open extension point. vulnhub-import already
 * sets the precedent of an integration plugin owning its own wp_schedule_event()
 * independently, so this follows that rather than core's.
 *
 * Reuses core's already-registered vh_* interval names (vh_hourly, vh_daily,
 * etc.) rather than registering new ones.
 *
 * @package VulnHub\Backup
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Reconciles the configured backup frequency with WP-Cron.
 */
final class VulnHub_Backup_Scheduler {

	public const HOOK_RUN = 'vulnhub_backup_run_cron';

	/**
	 * @return void
	 */
	public static function hooks(): void {
		add_action( self::HOOK_RUN, array( __CLASS__, 'run' ) );
		add_action( 'vulnhub_loaded', array( __CLASS__, 'ensure_schedule' ), 25 );
	}

	/**
	 * Reconcile the scheduled event with the configured interval. Called on
	 * boot and whenever the backup settings are saved.
	 *
	 * @return void
	 */
	public static function ensure_schedule(): void {
		if ( ! function_exists( 'vulnhub' ) ) {
			return;
		}

		$interval  = (string) vulnhub()->settings->get( 'backup_s3', 'interval', 'manual' );
		$enabled   = vulnhub()->settings->get_bool( 'backup_s3', 'enabled', false );
		$scheduled = wp_next_scheduled( self::HOOK_RUN );

		if ( ! $enabled || 'manual' === $interval ) {
			if ( $scheduled ) {
				wp_unschedule_event( $scheduled, self::HOOK_RUN );
			}
			return;
		}

		$current = wp_get_schedule( self::HOOK_RUN );

		if ( $current === $interval ) {
			return;
		}

		if ( $scheduled ) {
			wp_unschedule_event( $scheduled, self::HOOK_RUN );
		}

		wp_schedule_event( time() + wp_rand( 30, 300 ), $interval, self::HOOK_RUN );
	}

	/**
	 * Cron callback: start a scheduled backup, unless one is already running.
	 *
	 * @return void
	 */
	public static function run(): void {
		$resumable = VulnHub_Backup_Jobs::resumable( 1 );

		if ( $resumable ) {
			// A backup is already in flight; let it finish rather than
			// starting a second one on top of it.
			return;
		}

		VulnHub_Backup_Runner::start_new( 'scheduled' );
	}
}

