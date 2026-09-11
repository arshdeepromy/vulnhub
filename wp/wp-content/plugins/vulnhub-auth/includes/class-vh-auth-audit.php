<?php
/**
 * Audit trail helper and login throttle.
 *
 * Everything authentication-related is written to the VulnHub audit trail with
 * an `auth.` action prefix so the Audit screen can filter on it, and so an
 * analyst reviewing an incident sees sign-ins, MFA challenges, lockouts and
 * SSO provisioning in the same timeline as vulnerability activity.
 *
 * @package VulnHub\Auth
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Writes `auth.*` entries to the core audit log.
 */
final class VulnHub_Auth_Audit {

	/**
	 * Record an authentication event.
	 *
	 * The $detail array is JSON-encoded into the audit row, so it must never
	 * carry a password, a TOTP secret, a recovery code, an access token or an
	 * ID token. Callers pass identifiers and outcomes only.
	 *
	 * @param string              $action   Action suffix, e.g. 'mfa.success'.
	 * @param string              $summary  Human-readable one-liner.
	 * @param int                 $user_id  Subject user id, 0 when unknown.
	 * @param array<string,mixed> $detail   Structured context (never secret).
	 * @param string              $severity info|warning|error|critical.
	 * @return void
	 */
	public static function log( string $action, string $summary, int $user_id = 0, array $detail = array(), string $severity = 'info' ): void {
		if ( ! function_exists( 'vulnhub' ) ) {
			return;
		}

		$core = vulnhub();
		if ( ! isset( $core->logger ) ) {
			return;
		}

		$detail['ip'] = self::client_ip();

		try {
			$core->logger->audit(
				'auth.' . $action,
				$summary,
				'user',
				$user_id > 0 ? $user_id : '',
				$detail,
				$severity
			);
		} catch ( \Throwable $e ) {
			// The audit table may not exist yet during activation. Never let
			// logging break a login.
			unset( $e );
		}
	}

	/**
	 * Best-effort client IP.
	 *
	 * Deliberately does NOT trust X-Forwarded-For: on this deployment the value
	 * is attacker-controlled, and a spoofable IP in a lockout key would let an
	 * attacker evade the throttle by rotating the header.
	 *
	 * @return string IP address or ''.
	 */
	public static function client_ip(): string {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$ip = filter_var( $ip, FILTER_VALIDATE_IP );
		return is_string( $ip ) ? $ip : '';
	}
}

/**
 * Failed-attempt throttle for the second-factor challenge.
 *
 * Counters are keyed on (user, IP) so that one user's mistakes cannot lock out
 * the same user signing in from somewhere else, and one IP hammering many
 * accounts is stopped per account.
 */
final class VulnHub_Auth_Throttle {

	/**
	 * Transient key for a user/IP pair.
	 *
	 * @param int    $user_id User id.
	 * @param string $bucket  Counter name.
	 * @return string Transient key.
	 */
	private static function key( int $user_id, string $bucket ): string {
		return 'vh_auth_' . $bucket . '_' . md5( $user_id . '|' . VulnHub_Auth_Audit::client_ip() );
	}

	/**
	 * Is this user/IP currently locked out?
	 *
	 * @param int $user_id User id.
	 * @return int Seconds remaining, 0 when not locked.
	 */
	public static function locked_for( int $user_id ): int {
		$until = (int) get_transient( self::key( $user_id, 'lock' ) );
		return $until > time() ? $until - time() : 0;
	}

	/**
	 * Record a failure and lock out once the threshold is reached.
	 *
	 * @param int $user_id   User id.
	 * @param int $threshold Failures allowed before lockout.
	 * @param int $minutes   Lockout duration.
	 * @return bool True when this failure triggered a lockout.
	 */
	public static function fail( int $user_id, int $threshold = 5, int $minutes = 15 ): bool {
		$threshold = max( 1, $threshold );
		$minutes   = max( 1, $minutes );

		$key   = self::key( $user_id, 'fail' );
		$count = (int) get_transient( $key ) + 1;
		set_transient( $key, $count, $minutes * MINUTE_IN_SECONDS );

		if ( $count >= $threshold ) {
			set_transient( self::key( $user_id, 'lock' ), time() + $minutes * MINUTE_IN_SECONDS, $minutes * MINUTE_IN_SECONDS );
			delete_transient( $key );
			return true;
		}

		return false;
	}

	/**
	 * How many failures have been recorded in the current window.
	 *
	 * @param int $user_id User id.
	 * @return int Count.
	 */
	public static function failures( int $user_id ): int {
		return (int) get_transient( self::key( $user_id, 'fail' ) );
	}

	/**
	 * Clear counters after a successful authentication.
	 *
	 * @param int $user_id User id.
	 * @return void
	 */
	public static function clear( int $user_id ): void {
		delete_transient( self::key( $user_id, 'fail' ) );
		delete_transient( self::key( $user_id, 'lock' ) );
	}
}

