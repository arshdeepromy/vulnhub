<?php
/**
 * Compact JWT verification and RSA JWK -> PEM conversion.
 *
 * WHY THIS IS WRITTEN OUT LONGHAND: an OIDC integration that base64-decodes an
 * ID token and trusts the claims is worse than having no SSO at all, because it
 * turns "anyone who can reach /wp-login.php" into "anyone who can forge a JSON
 * blob". Everything below exists so that the only claims this plugin ever acts
 * on came inside a token whose RS256 signature verified against a key the
 * identity provider published at its JWKS endpoint.
 *
 * The three classic ways to get this wrong, and how each is closed here:
 *
 *  1. alg: "none"           -> the algorithm allow-list is checked before any
 *                              key lookup, and "none" is not on it.
 *  2. algorithm confusion   -> only RSA keys are accepted, and only RS256/384/
 *     (RS256 -> HS256)         512 header algorithms. An HMAC family header is
 *                              rejected outright, so a public key can never be
 *                              used as a shared secret.
 *  3. attacker-chosen key   -> keys come only from the provider's JWKS URI
 *     (embedded jwk/jku)       taken from its discovery document. Any "jwk",
 *                              "jku" or "x5u" header member is ignored.
 *
 * Signature verification happens BEFORE any claim is read for authorisation.
 *
 * @package VulnHub\Auth
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Raised when a token fails verification. The message is safe to show an admin
 * but is never allowed to contain the token or any key material.
 */
class VulnHub_Auth_JWT_Exception extends \RuntimeException {}

/**
 * JSON Web Token verification restricted to the RSA-SHA2 family.
 */
final class VulnHub_Auth_JWT {

	/**
	 * Header `alg` values this plugin will verify, mapped to OpenSSL constants.
	 *
	 * Note what is absent: "none", every HS* value and every EC/EdDSA value.
	 * An identity provider that only offers ES256 will fail closed with a clear
	 * message rather than being waved through.
	 *
	 * @var array<string,int>
	 */
	private const ALLOWED_ALGS = array(
		'RS256' => OPENSSL_ALGO_SHA256,
		'RS384' => OPENSSL_ALGO_SHA384,
		'RS512' => OPENSSL_ALGO_SHA512,
	);

	/* -----------------------------------------------------------------
	 * base64url
	 * --------------------------------------------------------------- */

	/**
	 * Decode base64url (RFC 7515 Appendix C) strictly.
	 *
	 * @param string $input Encoded text.
	 * @return string Raw bytes.
	 * @throws VulnHub_Auth_JWT_Exception When the input is not base64url.
	 */
	public static function b64url_decode( string $input ): string {
		$remainder = strlen( $input ) % 4;
		if ( $remainder ) {
			$input .= str_repeat( '=', 4 - $remainder );
		}
		$decoded = base64_decode( strtr( $input, '-_', '+/' ), true );
		if ( false === $decoded ) {
			throw new VulnHub_Auth_JWT_Exception( __( 'Token segment is not valid base64url.', 'vulnhub' ) );
		}
		return $decoded;
	}

	/**
	 * Encode raw bytes as base64url without padding.
	 *
	 * @param string $input Raw bytes.
	 * @return string Encoded text.
	 */
	public static function b64url_encode( string $input ): string {
		return rtrim( strtr( base64_encode( $input ), '+/', '-_' ), '=' );
	}

	/* -----------------------------------------------------------------
	 * Parsing
	 * --------------------------------------------------------------- */

	/**
	 * Split a compact JWS and decode its header and payload WITHOUT verifying.
	 *
	 * Only ever used to read the `kid`/`alg` needed to pick a key. Nothing that
	 * comes out of here may be trusted until verify() has returned.
	 *
	 * @param string $jwt Compact serialisation.
	 * @return array{header:array<string,mixed>,payload:array<string,mixed>,signing_input:string,signature:string}
	 * @throws VulnHub_Auth_JWT_Exception On malformed input.
	 */
	public static function parse( string $jwt ): array {
		$parts = explode( '.', $jwt );
		if ( 3 !== count( $parts ) ) {
			throw new VulnHub_Auth_JWT_Exception( __( 'ID token is not a compact JWS with three segments.', 'vulnhub' ) );
		}

		$header  = json_decode( self::b64url_decode( $parts[0] ), true );
		$payload = json_decode( self::b64url_decode( $parts[1] ), true );

		if ( ! is_array( $header ) || ! is_array( $payload ) ) {
			throw new VulnHub_Auth_JWT_Exception( __( 'ID token header or payload is not a JSON object.', 'vulnhub' ) );
		}

		return array(
			'header'        => $header,
			'payload'       => $payload,
			'signing_input' => $parts[0] . '.' . $parts[1],
			'signature'     => self::b64url_decode( $parts[2] ),
		);
	}

	/* -----------------------------------------------------------------
	 * JWK -> PEM
	 * --------------------------------------------------------------- */

	/**
	 * Convert an RSA JSON Web Key into a PEM public key.
	 *
	 * A JWK gives the modulus `n` and exponent `e` as base64url big-endian
	 * integers. OpenSSL wants a DER SubjectPublicKeyInfo:
	 *
	 *   SEQUENCE {
	 *     SEQUENCE { OID 1.2.840.113549.1.1.1 (rsaEncryption), NULL }
	 *     BIT STRING { SEQUENCE { INTEGER n, INTEGER e } }
	 *   }
	 *
	 * so the ASN.1 is assembled by hand below. DER INTEGERs are signed, hence
	 * the leading 0x00 whenever the high bit of the first byte is set.
	 *
	 * @param array<string,mixed> $jwk JWK with kty=RSA, n and e.
	 * @return string PEM public key.
	 * @throws VulnHub_Auth_JWT_Exception When the key is not a usable RSA key.
	 */
	public static function jwk_to_pem( array $jwk ): string {
		if ( 'RSA' !== ( $jwk['kty'] ?? '' ) ) {
			throw new VulnHub_Auth_JWT_Exception( __( 'Signing key is not an RSA key.', 'vulnhub' ) );
		}
		if ( empty( $jwk['n'] ) || empty( $jwk['e'] ) ) {
			throw new VulnHub_Auth_JWT_Exception( __( 'RSA signing key is missing its modulus or exponent.', 'vulnhub' ) );
		}

		$modulus  = self::b64url_decode( (string) $jwk['n'] );
		$exponent = self::b64url_decode( (string) $jwk['e'] );

		// A 1024-bit modulus is 128 bytes; anything shorter is not a key we
		// should be trusting for authentication.
		if ( strlen( $modulus ) < 128 ) {
			throw new VulnHub_Auth_JWT_Exception( __( 'RSA signing key is too small to be trusted.', 'vulnhub' ) );
		}

		$rsa_public_key = self::der_sequence(
			self::der_integer( $modulus ) . self::der_integer( $exponent )
		);

		// AlgorithmIdentifier for rsaEncryption with the required NULL params.
		$algorithm = self::der_sequence(
			"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" . "\x05\x00"
		);

		// The BIT STRING wraps the key with a zero "unused bits" prefix.
		$bit_string = self::der_tlv( 0x03, "\x00" . $rsa_public_key );

		$der = self::der_sequence( $algorithm . $bit_string );

		return "-----BEGIN PUBLIC KEY-----\n"
			. chunk_split( base64_encode( $der ), 64, "\n" )
			. "-----END PUBLIC KEY-----\n";
	}

	/**
	 * Wrap content in a DER SEQUENCE.
	 *
	 * @param string $content DER content.
	 * @return string DER element.
	 */
	private static function der_sequence( string $content ): string {
		return self::der_tlv( 0x30, $content );
	}

	/**
	 * Encode a big-endian unsigned integer as a DER INTEGER.
	 *
	 * @param string $bytes Big-endian magnitude.
	 * @return string DER element.
	 */
	private static function der_integer( string $bytes ): string {
		$bytes = ltrim( $bytes, "\x00" );
		if ( '' === $bytes ) {
			$bytes = "\x00";
		}
		// DER INTEGERs are two's complement; prefix 0x00 so a high bit is not
		// read as a negative number.
		if ( ord( $bytes[0] ) & 0x80 ) {
			$bytes = "\x00" . $bytes;
		}
		return self::der_tlv( 0x02, $bytes );
	}

	/**
	 * Build a DER tag-length-value element with definite long-form lengths.
	 *
	 * @param int    $tag     ASN.1 tag byte.
	 * @param string $content Content octets.
	 * @return string DER element.
	 */
	private static function der_tlv( int $tag, string $content ): string {
		$length = strlen( $content );

		if ( $length < 0x80 ) {
			$header = chr( $length );
		} else {
			$encoded = '';
			$value   = $length;
			while ( $value > 0 ) {
				$encoded = chr( $value & 0xff ) . $encoded;
				$value >>= 8;
			}
			$header = chr( 0x80 | strlen( $encoded ) ) . $encoded;
		}

		return chr( $tag ) . $header . $content;
	}

	/* -----------------------------------------------------------------
	 * Verification
	 * --------------------------------------------------------------- */

	/**
	 * Select the signing key for a token header from a JWK Set.
	 *
	 * Selection is by `kid` when the header carries one. When it does not (some
	 * providers omit it on single-key sets) the only RSA signing key is used,
	 * and an ambiguous set is rejected rather than guessed at.
	 *
	 * @param array<string,mixed> $header Token header.
	 * @param array<string,mixed> $jwks   Decoded JWK Set.
	 * @return array<string,mixed>|null Matching JWK, or null when absent.
	 */
	public static function select_key( array $header, array $jwks ): ?array {
		$keys = array();
		foreach ( (array) ( $jwks['keys'] ?? array() ) as $key ) {
			if ( ! is_array( $key ) || 'RSA' !== ( $key['kty'] ?? '' ) ) {
				continue;
			}
			// "use" is optional; when present it must say signature.
			if ( isset( $key['use'] ) && 'sig' !== $key['use'] ) {
				continue;
			}
			$keys[] = $key;
		}

		$kid = isset( $header['kid'] ) ? (string) $header['kid'] : '';
		if ( '' !== $kid ) {
			foreach ( $keys as $key ) {
				if ( isset( $key['kid'] ) && hash_equals( (string) $key['kid'], $kid ) ) {
					return $key;
				}
			}
			return null;
		}

		return 1 === count( $keys ) ? $keys[0] : null;
	}

	/**
	 * Verify a token's signature against a specific JWK.
	 *
	 * @param string              $jwt Compact serialisation.
	 * @param array<string,mixed> $jwk Signing key.
	 * @return bool True only when OpenSSL reports a good signature.
	 * @throws VulnHub_Auth_JWT_Exception When the header algorithm is not allowed.
	 */
	public static function verify_signature( string $jwt, array $jwk ): bool {
		$parsed = self::parse( $jwt );
		$alg    = isset( $parsed['header']['alg'] ) ? (string) $parsed['header']['alg'] : '';

		if ( ! isset( self::ALLOWED_ALGS[ $alg ] ) ) {
			/* translators: %s: JWS algorithm name from the token header. */
			throw new VulnHub_Auth_JWT_Exception( sprintf( __( 'ID token is signed with an unsupported algorithm (%s). Only RS256, RS384 and RS512 are accepted.', 'vulnhub' ), preg_replace( '/[^A-Za-z0-9]/', '', $alg ) ?: 'unknown' ) );
		}

		// If the key itself declares an algorithm it must agree with the header,
		// which stops a key published for one algorithm being used with another.
		if ( isset( $jwk['alg'] ) && ! hash_equals( (string) $jwk['alg'], $alg ) ) {
			throw new VulnHub_Auth_JWT_Exception( __( 'ID token algorithm does not match the published signing key.', 'vulnhub' ) );
		}

		$pem = self::jwk_to_pem( $jwk );

		// openssl_verify returns 1 (good), 0 (bad) or -1 (error). Only 1 passes.
		$result = openssl_verify(
			$parsed['signing_input'],
			$parsed['signature'],
			$pem,
			self::ALLOWED_ALGS[ $alg ]
		);

		return 1 === $result;
	}

	/**
	 * Validate the registered claims of an already signature-verified token.
	 *
	 * @param array<string,mixed> $claims  Token payload.
	 * @param array{issuer:string,client_id:string,nonce?:string,leeway?:int,max_age?:int} $expect Expectations.
	 * @throws VulnHub_Auth_JWT_Exception When any check fails.
	 */
	public static function validate_claims( array $claims, array $expect ): void {
		$leeway = (int) ( $expect['leeway'] ?? 120 );
		$now    = time();

		// --- iss -----------------------------------------------------------
		// Compared byte-for-byte against the issuer the discovery document
		// advertised, which is itself pinned to the configured domain.
		$issuer = isset( $claims['iss'] ) ? (string) $claims['iss'] : '';
		if ( '' === $issuer || ! hash_equals( $expect['issuer'], $issuer ) ) {
			throw new VulnHub_Auth_JWT_Exception( __( 'ID token issuer does not match the configured identity provider.', 'vulnhub' ) );
		}

		// --- aud -----------------------------------------------------------
		// May be a string or an array; our client id must be present.
		$audience = $claims['aud'] ?? '';
		$audience = is_array( $audience ) ? array_map( 'strval', $audience ) : array( (string) $audience );
		$matched  = false;
		foreach ( $audience as $entry ) {
			if ( hash_equals( $expect['client_id'], $entry ) ) {
				$matched = true;
			}
		}
		if ( ! $matched ) {
			throw new VulnHub_Auth_JWT_Exception( __( 'ID token audience does not contain this application.', 'vulnhub' ) );
		}

		// When several audiences are present, azp must name us (OIDC Core 3.1.3.7).
		if ( count( $audience ) > 1 || isset( $claims['azp'] ) ) {
			$azp = isset( $claims['azp'] ) ? (string) $claims['azp'] : '';
			if ( '' === $azp || ! hash_equals( $expect['client_id'], $azp ) ) {
				throw new VulnHub_Auth_JWT_Exception( __( 'ID token authorised party is not this application.', 'vulnhub' ) );
			}
		}

		// --- exp / nbf / iat ------------------------------------------------
		$exp = isset( $claims['exp'] ) ? (int) $claims['exp'] : 0;
		if ( $exp <= 0 || $now > $exp + $leeway ) {
			throw new VulnHub_Auth_JWT_Exception( __( 'ID token has expired.', 'vulnhub' ) );
		}
		if ( isset( $claims['nbf'] ) && $now + $leeway < (int) $claims['nbf'] ) {
			throw new VulnHub_Auth_JWT_Exception( __( 'ID token is not valid yet.', 'vulnhub' ) );
		}
		$iat = isset( $claims['iat'] ) ? (int) $claims['iat'] : 0;
		if ( $iat <= 0 ) {
			throw new VulnHub_Auth_JWT_Exception( __( 'ID token has no issued-at time.', 'vulnhub' ) );
		}
		if ( $iat > $now + $leeway ) {
			throw new VulnHub_Auth_JWT_Exception( __( 'ID token was issued in the future; check the server clock.', 'vulnhub' ) );
		}
		// A token minted long ago replayed at us is not acceptable even if it
		// has a generous exp.
		$max_age = (int) ( $expect['max_age'] ?? 0 );
		if ( $max_age > 0 && $iat < $now - $max_age - $leeway ) {
			throw new VulnHub_Auth_JWT_Exception( __( 'ID token is older than the permitted authentication age.', 'vulnhub' ) );
		}

		// --- nonce ----------------------------------------------------------
		// Binds the token to the authorisation request this browser started,
		// which is what stops a token obtained elsewhere being replayed here.
		if ( isset( $expect['nonce'] ) && '' !== $expect['nonce'] ) {
			$nonce = isset( $claims['nonce'] ) ? (string) $claims['nonce'] : '';
			if ( '' === $nonce || ! hash_equals( $expect['nonce'], $nonce ) ) {
				throw new VulnHub_Auth_JWT_Exception( __( 'ID token nonce does not match this sign-in attempt.', 'vulnhub' ) );
			}
		}

		// --- sub ------------------------------------------------------------
		if ( '' === (string) ( $claims['sub'] ?? '' ) ) {
			throw new VulnHub_Auth_JWT_Exception( __( 'ID token has no subject claim.', 'vulnhub' ) );
		}
	}
}

