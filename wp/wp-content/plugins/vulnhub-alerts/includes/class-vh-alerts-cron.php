<?php
/**
 * Scheduling. One hourly tick asks which feeds are due; each feed keeps its
 * own interval, so the Microsoft document is not re-downloaded hourly just
 * because the CISA feed wants to be.
 *
 * @package VulnHub\Alerts
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Alerts_Cron {

	public const HOOK        = 'vulnhub_alerts_poll';
	public const DIGEST_HOOK = 'vulnhub_alerts_digest';

	public static function init(): void {
		add_action( self::HOOK, array( __CLASS__, 'poll' ) );
		add_action( self::DIGEST_HOOK, array( 'VulnHub_Alerts_Notify', 'send_digest' ) );
	}

	public static function schedule(): void {
		if ( ! wp_next_scheduled( self::HOOK ) ) {
			wp_schedule_event( time() + 300, 'hourly', self::HOOK );
		}

		if ( ! wp_next_scheduled( self::DIGEST_HOOK ) ) {
			wp_schedule_event( self::next_digest_time(), 'daily', self::DIGEST_HOOK );
		}
	}

	public static function unschedule(): void {
		foreach ( array( self::HOOK, self::DIGEST_HOOK ) as $hook ) {
			$timestamp = wp_next_scheduled( $hook );

			while ( $timestamp ) {
				wp_unschedule_event( $timestamp, $hook );
				$timestamp = wp_next_scheduled( $hook );
			}
		}
	}

	/**
	 * 08:00 in the site's timezone, which is when somebody is actually going
	 * to read it, rather than 08:00 UTC.
	 */
	private static function next_digest_time(): int {
		$tz  = wp_timezone();
		$now = new DateTimeImmutable( 'now', $tz );
		$at  = $now->setTime( 8, 0 );

		if ( $at <= $now ) {
			$at = $at->modify( '+1 day' );
		}

		return $at->getTimestamp();
	}

	public static function poll(): void {
		VulnHub_Alerts_Runner::run_due();
	}
}
