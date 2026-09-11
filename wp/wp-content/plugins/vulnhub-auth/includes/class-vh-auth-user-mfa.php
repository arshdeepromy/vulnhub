<?php
/**
 * Per-user MFA state: the encrypted TOTP secret, recovery codes, replay
 * bookkeeping and trusted devices.
 *
 * Storage rules this class enforces:
 *
 *  - The TOTP shared secret is written through \VulnHub\Core\Crypto::encrypt()
 *    (libsodium XChaCha20-Poly1305 with the key from wp-config.php), so a
 *    database dump alone does not hand over everyone's second factor.
 *  - The secret is returned to the browser exactly once, during enrolment, and
 *    never again — there is no "show my secret" path.
 *  - Recovery codes are stored only as password hashes and are single use.
 *  - The counter of the last accepted code is remembered so the same code
 *    cannot be replayed inside its 30-second step (RFC 6238 §5.2).
 *
 * @package VulnHub\Auth
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Reads and writes one user's MFA enrolment.
 */
final class VulnHub_Auth_User_MFA {

	public const META_SECRET       = '_vh_auth_totp_secret';
	public const META_PENDING      = '_vh_auth_pending_secret';
	public const META_ENABLED      = '_vh_auth_mfa_enabled';
	public const META_ENROLLED_AT  = '_vh_auth_enrolled_at';
	public const META_LAST_COUNTER = '_vh_auth_last_counter';
	public const META_LAST_USED    = '_vh_auth_last_used';
	public const META_RECOVERY     = '_vh_auth_recovery_codes';
	public const META_TRUSTED      = '_vh_auth_trusted_devices';
	public const META_CHALLENGE    = '_vh_auth_challenge';

	/** How many recovery codes are issued at enrolment. */
	public const RECOVERY_COUNT = 10;

	/* -----------------------------------------------------------------
	 * Secret storage
	 * --------------------------------------------------------------- */

	/**
	 * Encrypt a value for storage, falling back to plaintext only when core's
	 * crypto is genuinely unavailable (which cannot happen while the plugin is
	 * active, since it requires core).
	 *
	 * @param string $plaintext Value.
	 * @return string Stored blob.
	 */
	private static function seal( string $plaintext ): string {
		if ( class_exists( '\VulnHub\Core\Crypto' ) ) {
			return \VulnHub\Core\Crypto::encrypt( $plaintext );
		}
		return $plaintext;
	}

	/**
	 * Reverse of seal().
	 *
	 * @param string $blob Stored blob.
	 * @return string Plaintext.
	 */
	private static function unseal( string $blob ): string {
		if ( '' === $blob ) {
			return '';
		}
		if ( class_exists( '\VulnHub\Core\Crypto' ) ) {
			return \VulnHub\Core\Crypto::decrypt( $blob );
		}
		return $blob;
	}

	/**
	 * The user's active base32 TOTP secret.
	 *
	 * Internal use only — never render this after enrolment.
	 *
	 * @param int $user_id User id.
	 * @return string Base32 secret or ''.
	 */
	public static function secret( int $user_id ): string {
		return self::unseal( (string) get_user_meta( $user_id, self::META_SECRET, true ) );
	}

	/**
	 * Is MFA switched on for this user?
	 *
	 * @param int $user_id User id.
	 * @return bool
	 */
	public static function is_enabled( int $user_id ): bool {
		return '1' === (string) get_user_meta( $user_id, self::META_ENABLED, true )
			&& '' !== self::secret( $user_id );
	}

	/* -----------------------------------------------------------------
	 * Enrolment
	 * --------------------------------------------------------------- */

	/**
	 * Start enrolment: mint a secret and park it as "pending" until the user
	 * proves they can produce a code from it.
	 *
	 * @param int $user_id User id.
	 * @return string The new base32 secret (shown once, to this user only).
	 * @throws \Random\RandomException When the CSPRNG is unavailable.
	 */
	public static function begin_enrolment( int $user_id ): string {
		$secret = VulnHub_Auth_TOTP::generate_secret();
		update_user_meta( $user_id, self::META_PENDING, self::seal( $secret ) );
		return $secret;
	}

	/**
	 * The pending (unconfirmed) secret, if enrolment is in progress.
	 *
	 * @param int $user_id User id.
	 * @return string Base32 secret or ''.
	 */
	public static function pending_secret( int $user_id ): string {
		return self::unseal( (string) get_user_meta( $user_id, self::META_PENDING, true ) );
	}

	/**
	 * Abandon an in-progress enrolment.
	 *
	 * @param int $user_id User id.
	 * @return void
	 */
	public static function cancel_enrolment( int $user_id ): void {
		delete_user_meta( $user_id, self::META_PENDING );
	}

	/**
	 * Confirm enrolment with a code generated from the pending secret.
	 *
	 * Requiring a valid code before switching MFA on is the whole point of the
	 * two-step enrolment: it proves the authenticator really holds the secret,
	 * so nobody locks themselves out of their own account.
	 *
	 * @param int    $user_id User id.
	 * @param string $code    Submitted code.
	 * @return bool True when MFA is now on.
	 */
	public static function confirm_enrolment( int $user_id, string $code ): bool {
		$secret = self::pending_secret( $user_id );
		if ( '' === $secret ) {
			return false;
		}

		$counter = null;
		if ( ! VulnHub_Auth_TOTP::verify( $secret, $code, $counter ) ) {
			return false;
		}

		update_user_meta( $user_id, self::META_SECRET, self::seal( $secret ) );
		update_user_meta( $user_id, self::META_ENABLED, '1' );
		update_user_meta( $user_id, self::META_ENROLLED_AT, gmdate( 'Y-m-d H:i:s' ) );
		update_user_meta( $user_id, self::META_LAST_COUNTER, (int) $counter );
		delete_user_meta( $user_id, self::META_PENDING );

		return true;
	}

	/**
	 * Turn MFA off and destroy every associated secret.
	 *
	 * @param int $user_id User id.
	 * @return void
	 */
	public static function disable( int $user_id ): void {
		foreach (
			array(
				self::META_SECRET,
				self::META_PENDING,
				self::META_ENABLED,
				self::META_ENROLLED_AT,
				self::META_LAST_COUNTER,
				self::META_RECOVERY,
				self::META_TRUSTED,
				self::META_CHALLENGE,
			) as $meta
		) {
			delete_user_meta( $user_id, $meta );
		}
	}

	/* -----------------------------------------------------------------
	 * Verification
	 * --------------------------------------------------------------- */

	/**
	 * Verify a submitted code, honouring drift and refusing replays.
	 *
	 * @param int    $user_id User id.
	 * @param string $code    Submitted code.
	 * @param string $reason  Out: 'ok'|'replay'|'invalid'|'not_enrolled'.
	 * @return bool
	 */
	public static function verify_code( int $user_id, string $code, string &$reason = '' ): bool {
		$secret = self::secret( $user_id );
		if ( '' === $secret ) {
			$reason = 'not_enrolled';
			return false;
		}

		$counter = null;
		if ( ! VulnHub_Auth_TOTP::verify( $secret, $code, $counter ) ) {
			$reason = 'invalid';
			return false;
		}

		// RFC 6238 §5.2: a code that has already been accepted must not be
		// accepted again. Anything at or below the high-water mark is a replay.
		$last = (int) get_user_meta( $user_id, self::META_LAST_COUNTER, true );
		if ( $last > 0 && (int) $counter <= $last ) {
			$reason = 'replay';
			return false;
		}

		update_user_meta( $user_id, self::META_LAST_COUNTER, (int) $counter );
		update_user_meta( $user_id, self::META_LAST_USED, gmdate( 'Y-m-d H:i:s' ) );

		$reason = 'ok';
		return true;
	}

	/* -----------------------------------------------------------------
	 * Recovery codes
	 * --------------------------------------------------------------- */

	/**
	 * Issue a fresh set of recovery codes.
	 *
	 * Returns the plaintext codes for a single display; only hashes are kept.
	 *
	 * @param int $user_id User id.
	 * @return array<int,string> Plaintext codes.
	 * @throws \Random\RandomException When the CSPRNG is unavailable.
	 */
	public static function generate_recovery_codes( int $user_id ): array {
		$alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // No I/O/0/1 — these get read aloud.
		$codes    = array();
		$hashes   = array();

		for ( $i = 0; $i < self::RECOVERY_COUNT; $i++ ) {
			$groups = array();
			for ( $g = 0; $g < 3; $g++ ) {
				$chunk = '';
				for ( $c = 0; $c < 4; $c++ ) {
					$chunk .= $alphabet[ random_int( 0, strlen( $alphabet ) - 1 ) ];
				}
				$groups[] = $chunk;
			}
			$code     = implode( '-', $groups );
			$codes[]  = $code;
			$hashes[] = wp_hash_password( $code );
		}

		update_user_meta( $user_id, self::META_RECOVERY, $hashes );

		return $codes;
	}

	/**
	 * How many recovery codes remain unused.
	 *
	 * @param int $user_id User id.
	 * @return int
	 */
	public static function recovery_remaining( int $user_id ): int {
		$hashes = get_user_meta( $user_id, self::META_RECOVERY, true );
		return is_array( $hashes ) ? count( $hashes ) : 0;
	}

	/**
	 * Consume a recovery code.
	 *
	 * Every stored hash is checked so the work does not depend on which code
	 * was supplied, and a matching code is deleted immediately: recovery codes
	 * are strictly single use.
	 *
	 * @param int    $user_id User id.
	 * @param string $code    Submitted code.
	 * @return bool True when a code was consumed.
	 */
	public static function consume_recovery_code( int $user_id, string $code ): bool {
		$hashes = get_user_meta( $user_id, self::META_RECOVERY, true );
		if ( ! is_array( $hashes ) || ! $hashes ) {
			return false;
		}

		// Normalise the shape people actually type: spaces, lower case, and
		// with or without the separating dashes.
		$candidate = strtoupper( preg_replace( '/[^A-Za-z0-9]/', '', $code ) ?? '' );
		if ( 12 !== strlen( $candidate ) ) {
			return false;
		}
		$candidate = substr( $candidate, 0, 4 ) . '-' . substr( $candidate, 4, 4 ) . '-' . substr( $candidate, 8, 4 );

		$matched = -1;
		foreach ( $hashes as $index => $hash ) {
			if ( wp_check_password( $candidate, (string) $hash ) && $matched < 0 ) {
				$matched = (int) $index;
			}
		}

		if ( $matched < 0 ) {
			return false;
		}

		unset( $hashes[ $matched ] );
		update_user_meta( $user_id, self::META_RECOVERY, array_values( $hashes ) );
		update_user_meta( $user_id, self::META_LAST_USED, gmdate( 'Y-m-d H:i:s' ) );

		return true;
	}

	/* -----------------------------------------------------------------
	 * Pending-login challenge token
	 * --------------------------------------------------------------- */

	/**
	 * Mint a short-lived, single-use, HMAC-signed token that carries the
	 * pending login across the second-factor form.
	 *
	 * The form field is `<payload>.<signature>` where the payload is
	 * base64url(user_id|expiry|jti). The user id is signed rather than simply
	 * posted, so it cannot be edited to challenge-and-then-become somebody
	 * else, and the `jti` is also written to user meta so that replaying a
	 * captured token after it has been used does nothing.
	 *
	 * @param int $user_id     User id.
	 * @param int $ttl_seconds Lifetime.
	 * @return string Token.
	 * @throws \Random\RandomException When the CSPRNG is unavailable.
	 */
	public static function issue_challenge_token( int $user_id, int $ttl_seconds = 600 ): string {
		$jti     = bin2hex( random_bytes( 16 ) );
		$expires = time() + max( 60, $ttl_seconds );

		update_user_meta(
			$user_id,
			self::META_CHALLENGE,
			array(
				'jti'     => $jti,
				'expires' => $expires,
			)
		);

		$payload   = VulnHub_Auth_JWT::b64url_encode( $user_id . '|' . $expires . '|' . $jti );
		$signature = VulnHub_Auth_JWT::b64url_encode( self::sign( $payload ) );

		return $payload . '.' . $signature;
	}

	/**
	 * Validate and consume a challenge token.
	 *
	 * @param string $token    Token from the form.
	 * @param bool   $consume  Delete the stored jti on success.
	 * @return int User id, or 0 when the token is not valid.
	 */
	public static function redeem_challenge_token( string $token, bool $consume = true ): int {
		$parts = explode( '.', $token );
		if ( 2 !== count( $parts ) ) {
			return 0;
		}

		// Signature first: nothing inside the payload is looked at until the
		// HMAC proves we minted it.
		$expected = VulnHub_Auth_JWT::b64url_encode( self::sign( $parts[0] ) );
		if ( ! hash_equals( $expected, $parts[1] ) ) {
			return 0;
		}

		try {
			$payload = VulnHub_Auth_JWT::b64url_decode( $parts[0] );
		} catch ( \Throwable $e ) {
			return 0;
		}

		$fields = explode( '|', $payload );
		if ( 3 !== count( $fields ) ) {
			return 0;
		}

		list( $user_id, $expires, $jti ) = $fields;
		$user_id = (int) $user_id;
		$expires = (int) $expires;

		if ( $user_id <= 0 || $expires < time() ) {
			return 0;
		}

		$stored = get_user_meta( $user_id, self::META_CHALLENGE, true );
		if ( ! is_array( $stored ) || empty( $stored['jti'] ) ) {
			return 0;
		}
		if ( ! hash_equals( (string) $stored['jti'], (string) $jti ) ) {
			return 0;
		}
		if ( (int) ( $stored['expires'] ?? 0 ) < time() ) {
			delete_user_meta( $user_id, self::META_CHALLENGE );
			return 0;
		}

		if ( $consume ) {
			delete_user_meta( $user_id, self::META_CHALLENGE );
		}

		return $user_id;
	}

	/**
	 * HMAC used to sign challenge tokens.
	 *
	 * Keyed on WordPress' own auth salt, so rotating the salts invalidates
	 * every in-flight challenge.
	 *
	 * @param string $payload Payload to sign.
	 * @return string Raw HMAC.
	 */
	private static function sign( string $payload ): string {
		return hash_hmac( 'sha256', 'vh-auth-challenge|' . $payload, wp_salt( 'auth' ), true );
	}

	/* -----------------------------------------------------------------
	 * Trusted devices
	 * --------------------------------------------------------------- */

	/**
	 * Name of the trusted-device cookie.
	 *
	 * @return string
	 */
	public static function trusted_cookie_name(): string {
		return 'vh_auth_trusted_' . COOKIEHASH;
	}

	/**
	 * Remember this browser so it is not challenged again for a while.
	 *
	 * The cookie holds a random token; only a hash of it is stored server-side,
	 * so a database read does not yield a usable device cookie.
	 *
	 * @param int $user_id User id.
	 * @param int $days    Lifetime in days.
	 * @return void
	 * @throws \Random\RandomException When the CSPRNG is unavailable.
	 */
	public static function trust_device( int $user_id, int $days ): void {
		$token   = bin2hex( random_bytes( 32 ) );
		$expires = time() + max( 1, $days ) * DAY_IN_SECONDS;

		$devices = self::trusted_devices( $user_id );
		$devices[] = array(
			'hash'    => hash_hmac( 'sha256', $token, wp_salt( 'auth' ) ),
			'expires' => $expires,
			'created' => time(),
			'agent'   => substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ?? '' ) ), 0, 120 ),
			'ip'      => VulnHub_Auth_Audit::client_ip(),
		);

		// Keep the list bounded.
		if ( count( $devices ) > 20 ) {
			$devices = array_slice( $devices, -20 );
		}

		update_user_meta( $user_id, self::META_TRUSTED, $devices );

		setcookie(
			self::trusted_cookie_name(),
			$user_id . '|' . $token,
			array(
				'expires'  => $expires,
				'path'     => COOKIEPATH ? COOKIEPATH : '/',
				'domain'   => COOKIE_DOMAIN,
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
	}

	/**
	 * Non-expired trusted devices for a user.
	 *
	 * @param int $user_id User id.
	 * @return array<int,array<string,mixed>>
	 */
	public static function trusted_devices( int $user_id ): array {
		$devices = get_user_meta( $user_id, self::META_TRUSTED, true );
		if ( ! is_array( $devices ) ) {
			return array();
		}

		$now  = time();
		$live = array();
		foreach ( $devices as $device ) {
			if ( is_array( $device ) && (int) ( $device['expires'] ?? 0 ) > $now ) {
				$live[] = $device;
			}
		}

		return $live;
	}

	/**
	 * Is the current browser a trusted device for this user?
	 *
	 * @param int $user_id User id.
	 * @return bool
	 */
	public static function is_trusted_device( int $user_id ): bool {
		if ( ! VulnHub_Auth_Policy::get( 'remember_enabled' ) ) {
			return false;
		}

		$name = self::trusted_cookie_name();
		if ( empty( $_COOKIE[ $name ] ) ) {
			return false;
		}

		$raw   = sanitize_text_field( wp_unslash( $_COOKIE[ $name ] ) );
		$parts = explode( '|', $raw, 2 );
		if ( 2 !== count( $parts ) || (int) $parts[0] !== $user_id ) {
			return false;
		}

		$offered = hash_hmac( 'sha256', $parts[1], wp_salt( 'auth' ) );
		foreach ( self::trusted_devices( $user_id ) as $device ) {
			if ( hash_equals( (string) $device['hash'], $offered ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Forget every trusted device for a user and clear the local cookie.
	 *
	 * @param int $user_id User id.
	 * @return void
	 */
	public static function forget_devices( int $user_id ): void {
		delete_user_meta( $user_id, self::META_TRUSTED );

		if ( ! headers_sent() ) {
			setcookie(
				self::trusted_cookie_name(),
				'',
				array(
					'expires'  => time() - DAY_IN_SECONDS,
					'path'     => COOKIEPATH ? COOKIEPATH : '/',
					'domain'   => COOKIE_DOMAIN,
					'secure'   => is_ssl(),
					'httponly' => true,
					'samesite' => 'Lax',
				)
			);
		}
	}

	/* -----------------------------------------------------------------
	 * Reporting
	 * --------------------------------------------------------------- */

	/**
	 * Summary row for the admin MFA status screen.
	 *
	 * @param int $user_id User id.
	 * @return array{enabled:bool,enrolled_at:string,last_used:string,recovery:int,devices:int}
	 */
	public static function status( int $user_id ): array {
		return array(
			'enabled'     => self::is_enabled( $user_id ),
			'enrolled_at' => (string) get_user_meta( $user_id, self::META_ENROLLED_AT, true ),
			'last_used'   => (string) get_user_meta( $user_id, self::META_LAST_USED, true ),
			'recovery'    => self::recovery_remaining( $user_id ),
			'devices'     => count( self::trusted_devices( $user_id ) ),
		);
	}
}

