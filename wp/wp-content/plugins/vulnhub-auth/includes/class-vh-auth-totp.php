<?php
/**
 * RFC 4226 (HOTP) and RFC 6238 (TOTP) implemented from the specification.
 *
 * Deliberately dependency-free: no Composer, no external service. The whole
 * algorithm is fifteen lines of arithmetic and the security of the feature
 * depends on getting those fifteen lines exactly right, so the reasoning is
 * spelled out inline and `self::rfc6238_test_vectors()` checks the published
 * vectors from RFC 6238 Appendix B on demand.
 *
 * Specification notes that shaped this implementation:
 *
 *  - RFC 4226 §5.3: HOTP(K,C) = Truncate(HMAC-SHA-1(K,C)). The counter C is an
 *    8-byte big-endian value. Dynamic truncation takes the low-order 4 bits of
 *    the LAST byte of the HMAC as an offset, reads the 4 bytes at that offset,
 *    masks the most significant bit (0x7f) to get a 31-bit integer, then takes
 *    that modulo 10^digits.
 *  - RFC 6238 §4.2: T = floor((unix_time - T0) / X) with T0 = 0 and X = 30 by
 *    default; T is used as the HOTP counter.
 *  - RFC 6238 §5.2: a validator MAY accept a small number of steps either side
 *    to absorb clock drift and network delay.
 *  - RFC 6238 §5.2 (last paragraph): "The verifier MUST NOT accept the second
 *    attempt of the OTP after the successful validation has been issued for the
 *    first OTP" — hence the last-accepted-counter bookkeeping in
 *    VulnHub_Auth_User_MFA, which this class exposes through $matched_counter.
 *
 * @package VulnHub\Auth
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Time-based one-time password generation and verification.
 */
final class VulnHub_Auth_TOTP {

	/** Default time step in seconds (RFC 6238 X). */
	public const PERIOD = 30;

	/** Default number of digits in a code. */
	public const DIGITS = 6;

	/** Default HMAC algorithm. */
	public const ALGO = 'sha1';

	/** RFC 4648 base32 alphabet. */
	private const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/* -----------------------------------------------------------------
	 * Base32 (RFC 4648)
	 * --------------------------------------------------------------- */

	/**
	 * Encode raw bytes as unpadded uppercase base32.
	 *
	 * The provisioning URI format explicitly says the RFC 3548 padding "is not
	 * required and should be omitted", so no '=' is emitted.
	 *
	 * @param string $binary Raw bytes.
	 * @return string Base32 text.
	 */
	public static function base32_encode( string $binary ): string {
		if ( '' === $binary ) {
			return '';
		}

		$bits = '';
		$len  = strlen( $binary );
		for ( $i = 0; $i < $len; $i++ ) {
			$bits .= str_pad( decbin( ord( $binary[ $i ] ) ), 8, '0', STR_PAD_LEFT );
		}

		$out    = '';
		$chunks = str_split( $bits, 5 );
		foreach ( $chunks as $chunk ) {
			$chunk = str_pad( $chunk, 5, '0', STR_PAD_RIGHT );
			$out  .= self::B32_ALPHABET[ (int) bindec( $chunk ) ];
		}

		return $out;
	}

	/**
	 * Decode base32 text to raw bytes. Tolerant of padding, spaces and case.
	 *
	 * @param string $base32 Base32 text.
	 * @return string Raw bytes ('' when the input is not valid base32).
	 */
	public static function base32_decode( string $base32 ): string {
		$clean = strtoupper( preg_replace( '/[^A-Za-z2-7]/', '', $base32 ) ?? '' );
		if ( '' === $clean ) {
			return '';
		}

		$bits = '';
		$len  = strlen( $clean );
		for ( $i = 0; $i < $len; $i++ ) {
			$index = strpos( self::B32_ALPHABET, $clean[ $i ] );
			if ( false === $index ) {
				return '';
			}
			$bits .= str_pad( decbin( $index ), 5, '0', STR_PAD_LEFT );
		}

		$out    = '';
		$octets = str_split( $bits, 8 );
		foreach ( $octets as $octet ) {
			// A trailing partial group is padding introduced by the 5->8 bit
			// mismatch and is discarded, per RFC 4648.
			if ( 8 !== strlen( $octet ) ) {
				break;
			}
			$out .= chr( (int) bindec( $octet ) );
		}

		return $out;
	}

	/* -----------------------------------------------------------------
	 * Secrets
	 * --------------------------------------------------------------- */

	/**
	 * Generate a fresh shared secret.
	 *
	 * 20 bytes (160 bits) matches the HMAC-SHA-1 block recommendation in
	 * RFC 4226 §4 R6 ("The algorithm MUST use a strong shared secret. The
	 * length of the shared secret MUST be at least 128 bits... 160 bits
	 * recommended") and encodes to 32 base32 characters.
	 *
	 * @param int $bytes Secret length in bytes.
	 * @return string Base32-encoded secret.
	 * @throws \Random\RandomException When the CSPRNG is unavailable.
	 */
	public static function generate_secret( int $bytes = 20 ): string {
		$bytes = max( 16, min( 64, $bytes ) );
		return self::base32_encode( random_bytes( $bytes ) );
	}

	/**
	 * Is this string a usable base32 secret?
	 *
	 * @param string $secret Candidate secret.
	 * @return bool
	 */
	public static function is_valid_secret( string $secret ): bool {
		return strlen( self::base32_decode( $secret ) ) >= 10;
	}

	/* -----------------------------------------------------------------
	 * Code generation
	 * --------------------------------------------------------------- */

	/**
	 * The RFC 6238 time counter T for a given moment.
	 *
	 * T = floor( (unix_time - T0) / X ), with T0 = 0.
	 *
	 * @param int|null $timestamp Unix time, or null for now.
	 * @param int      $period    Time step X in seconds.
	 * @return int Counter value.
	 */
	public static function counter( ?int $timestamp = null, int $period = self::PERIOD ): int {
		$timestamp = null === $timestamp ? time() : $timestamp;
		$period    = max( 1, $period );
		return (int) floor( $timestamp / $period );
	}

	/**
	 * RFC 4226 HOTP over a raw binary key.
	 *
	 * @param string $key     Raw (already base32-decoded) shared secret.
	 * @param int    $counter Moving factor C.
	 * @param int    $digits  Number of digits to emit.
	 * @param string $algo    HMAC algorithm (sha1|sha256|sha512).
	 * @return string Zero-padded code.
	 */
	public static function hotp( string $key, int $counter, int $digits = self::DIGITS, string $algo = self::ALGO ): string {
		// C is an 8-byte big-endian counter. 'J' is unsigned 64-bit big-endian.
		$message = pack( 'J', $counter );
		$hash    = hash_hmac( $algo, $message, $key, true );

		// Dynamic truncation (RFC 4226 §5.3):
		//   offset = low-order 4 bits of the last byte of the HMAC.
		$offset = ord( $hash[ strlen( $hash ) - 1 ] ) & 0x0f;

		//   P = the 4 bytes at that offset; keep the low 31 bits (mask 0x7f on
		//   the first byte) so the value is positive on every platform.
		$binary = ( ( ord( $hash[ $offset ] ) & 0x7f ) << 24 )
			| ( ( ord( $hash[ $offset + 1 ] ) & 0xff ) << 16 )
			| ( ( ord( $hash[ $offset + 2 ] ) & 0xff ) << 8 )
			| ( ord( $hash[ $offset + 3 ] ) & 0xff );

		$modulo = 10 ** $digits;

		return str_pad( (string) ( $binary % $modulo ), $digits, '0', STR_PAD_LEFT );
	}

	/**
	 * TOTP for a base32 secret at a given counter.
	 *
	 * @param string $secret_b32 Base32 secret.
	 * @param int    $counter    Time counter T.
	 * @param int    $digits     Digits.
	 * @param string $algo       HMAC algorithm.
	 * @return string Code, or '' when the secret is unusable.
	 */
	public static function code_at( string $secret_b32, int $counter, int $digits = self::DIGITS, string $algo = self::ALGO ): string {
		$key = self::base32_decode( $secret_b32 );
		if ( '' === $key ) {
			return '';
		}
		return self::hotp( $key, $counter, $digits, $algo );
	}

	/**
	 * TOTP for a base32 secret at a moment in time.
	 *
	 * @param string   $secret_b32 Base32 secret.
	 * @param int|null $timestamp  Unix time, or null for now.
	 * @param int      $digits     Digits.
	 * @param int      $period     Time step.
	 * @param string   $algo       HMAC algorithm.
	 * @return string Code.
	 */
	public static function code(
		string $secret_b32,
		?int $timestamp = null,
		int $digits = self::DIGITS,
		int $period = self::PERIOD,
		string $algo = self::ALGO
	): string {
		return self::code_at( $secret_b32, self::counter( $timestamp, $period ), $digits, $algo );
	}

	/* -----------------------------------------------------------------
	 * Verification
	 * --------------------------------------------------------------- */

	/**
	 * Verify a submitted code against a secret, tolerating clock drift.
	 *
	 * Checks the counters [T - window, T + window] inclusive; with the default
	 * window of 1 that is the previous, current and next 30-second step, the
	 * drift allowance RFC 6238 §5.2 describes.
	 *
	 * Every comparison uses hash_equals() so that the number of matching
	 * leading digits cannot be recovered from response timing.
	 *
	 * The caller receives the counter that matched so it can refuse to accept
	 * the same counter twice (RFC 6238 §5.2 replay rule).
	 *
	 * @param string   $secret_b32     Base32 secret.
	 * @param string   $code           Submitted code.
	 * @param int|null $matched_counter Out: the counter that matched.
	 * @param int      $window         Steps either side to accept.
	 * @param int|null $timestamp      Unix time, or null for now.
	 * @param int      $digits         Digits.
	 * @param int      $period         Time step.
	 * @param string   $algo           HMAC algorithm.
	 * @return bool True when the code is valid for some counter in the window.
	 */
	public static function verify(
		string $secret_b32,
		string $code,
		?int &$matched_counter = null,
		int $window = 1,
		?int $timestamp = null,
		int $digits = self::DIGITS,
		int $period = self::PERIOD,
		string $algo = self::ALGO
	): bool {
		$matched_counter = null;

		$code = preg_replace( '/\D/', '', $code ) ?? '';
		if ( strlen( $code ) !== $digits ) {
			return false;
		}
		if ( ! self::is_valid_secret( $secret_b32 ) ) {
			return false;
		}

		$now    = self::counter( $timestamp, $period );
		$window = max( 0, min( 10, $window ) );
		$found  = false;

		for ( $offset = -$window; $offset <= $window; $offset++ ) {
			$counter  = $now + $offset;
			$expected = self::code_at( $secret_b32, $counter, $digits, $algo );

			// Do not break early: keep the loop's work constant across the
			// whole window so a match near the start is not distinguishable
			// from a match near the end by timing.
			if ( '' !== $expected && hash_equals( $expected, $code ) && ! $found ) {
				$found           = true;
				$matched_counter = $counter;
			}
		}

		return $found;
	}

	/* -----------------------------------------------------------------
	 * Provisioning URI
	 * --------------------------------------------------------------- */

	/**
	 * Build the otpauth:// provisioning URI an authenticator app scans.
	 *
	 * Format (Key Uri Format specification):
	 *   otpauth://totp/ISSUER:ACCOUNT?secret=...&issuer=...&algorithm=...&digits=...&period=...
	 *
	 * The issuer is written both as the label prefix and as a query parameter,
	 * which the specification explicitly recommends for compatibility with
	 * older and newer authenticator apps. Neither the issuer nor the account
	 * name may contain a colon, so colons are stripped before encoding.
	 *
	 * @param string $secret_b32 Base32 secret.
	 * @param string $account    Account name, usually an email address.
	 * @param string $issuer     Issuer / service name.
	 * @param int    $digits     Digits.
	 * @param int    $period     Time step.
	 * @param string $algo       Algorithm label (SHA1|SHA256|SHA512).
	 * @return string otpauth URI.
	 */
	public static function provisioning_uri(
		string $secret_b32,
		string $account,
		string $issuer,
		int $digits = self::DIGITS,
		int $period = self::PERIOD,
		string $algo = 'SHA1'
	): string {
		$issuer  = str_replace( ':', '', $issuer );
		$account = str_replace( ':', '', $account );

		$label = rawurlencode( $issuer ) . ':' . rawurlencode( $account );

		$query = http_build_query(
			array(
				'secret'    => $secret_b32,
				'issuer'    => $issuer,
				'algorithm' => strtoupper( $algo ),
				'digits'    => $digits,
				'period'    => $period,
			),
			'',
			'&',
			PHP_QUERY_RFC3986
		);

		return 'otpauth://totp/' . $label . '?' . $query;
	}

	/* -----------------------------------------------------------------
	 * Self-test
	 * --------------------------------------------------------------- */

	/**
	 * Run the published RFC 6238 Appendix B test vectors.
	 *
	 * The vectors use the ASCII seed "12345678901234567890", 8 digits, T0 = 0
	 * and X = 30. The SHA-256 and SHA-512 rows in the RFC use longer seeds
	 * (the 20-byte seed repeated and truncated to the hash block size), which
	 * is reproduced here so all three modes can be checked.
	 *
	 * @return array<int,array{time:int,algo:string,expected:string,actual:string,pass:bool}>
	 */
	public static function rfc6238_test_vectors(): array {
		$seed_sha1   = '12345678901234567890';                                     // 20 bytes.
		$seed_sha256 = substr( str_repeat( '12345678901234567890', 2 ), 0, 32 );   // 32 bytes.
		$seed_sha512 = substr( str_repeat( '12345678901234567890', 4 ), 0, 64 );   // 64 bytes.

		$vectors = array(
			array( 59, 'sha1', '94287082' ),
			array( 59, 'sha256', '46119246' ),
			array( 59, 'sha512', '90693936' ),
			array( 1111111109, 'sha1', '07081804' ),
			array( 1111111109, 'sha256', '68084774' ),
			array( 1111111109, 'sha512', '25091201' ),
			array( 1111111111, 'sha1', '14050471' ),
			array( 1111111111, 'sha256', '67062674' ),
			array( 1111111111, 'sha512', '99943326' ),
			array( 1234567890, 'sha1', '89005924' ),
			array( 1234567890, 'sha256', '91819424' ),
			array( 1234567890, 'sha512', '93441116' ),
			array( 2000000000, 'sha1', '69279037' ),
			array( 2000000000, 'sha256', '90698825' ),
			array( 2000000000, 'sha512', '38618901' ),
			array( 20000000000, 'sha1', '65353130' ),
			array( 20000000000, 'sha256', '77737706' ),
			array( 20000000000, 'sha512', '47863826' ),
		);

		$seeds = array(
			'sha1'   => $seed_sha1,
			'sha256' => $seed_sha256,
			'sha512' => $seed_sha512,
		);

		$results = array();
		foreach ( $vectors as $vector ) {
			list( $time, $algo, $expected ) = $vector;

			$actual    = self::hotp( $seeds[ $algo ], self::counter( $time, self::PERIOD ), 8, $algo );
			$results[] = array(
				'time'     => $time,
				'algo'     => $algo,
				'expected' => $expected,
				'actual'   => $actual,
				'pass'     => hash_equals( $expected, $actual ),
			);
		}

		return $results;
	}
}

