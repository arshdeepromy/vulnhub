<?php
/**
 * Credential encryption at rest.
 *
 * Uses libsodium's XChaCha20-Poly1305 secretbox with a key supplied via the
 * VULNHUB_ENCRYPTION_KEY constant in wp-config.php. Falls back to an
 * options-table key only if the constant is missing (and warns loudly in the
 * admin, because a key in the database is a much weaker posture).
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Crypto {

	private const PREFIX = 'vhenc1:';

	/**
	 * Resolve the 32-byte binary key.
	 */
	private static function key(): string {
		if ( defined( 'VULNHUB_ENCRYPTION_KEY' ) && '' !== (string) VULNHUB_ENCRYPTION_KEY ) {
			$raw = (string) VULNHUB_ENCRYPTION_KEY;
			// Accept hex (64 chars), base64, or raw.
			if ( 64 === strlen( $raw ) && ctype_xdigit( $raw ) ) {
				return (string) hex2bin( $raw );
			}
			return substr( hash( 'sha256', $raw, true ), 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES );
		}

		$fallback = get_option( 'vulnhub_fallback_key' );
		if ( ! $fallback ) {
			$fallback = base64_encode( random_bytes( 32 ) );
			update_option( 'vulnhub_fallback_key', $fallback, false );
		}
		return substr( (string) base64_decode( (string) $fallback, true ), 0, SODIUM_CRYPTO_SECRETBOX_KEYBYTES );
	}

	public static function using_config_key(): bool {
		return defined( 'VULNHUB_ENCRYPTION_KEY' ) && '' !== (string) VULNHUB_ENCRYPTION_KEY;
	}

	/**
	 * Encrypt a plaintext secret. Returns a prefixed base64 blob.
	 */
	public static function encrypt( string $plaintext ): string {
		if ( '' === $plaintext ) {
			return '';
		}
		$nonce  = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$cipher = sodium_crypto_secretbox( $plaintext, $nonce, self::key() );
		$blob   = self::PREFIX . base64_encode( $nonce . $cipher );

		sodium_memzero( $plaintext );
		return $blob;
	}

	/**
	 * Decrypt. Returns '' when the blob is empty, malformed, or the key changed.
	 */
	public static function decrypt( string $blob ): string {
		if ( '' === $blob ) {
			return '';
		}
		if ( ! str_starts_with( $blob, self::PREFIX ) ) {
			// Legacy/plaintext value — return as-is so nothing breaks on upgrade.
			return $blob;
		}
		$raw = base64_decode( substr( $blob, strlen( self::PREFIX ) ), true );
		if ( false === $raw || strlen( $raw ) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) {
			return '';
		}
		$nonce  = substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$cipher = substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );

		$plain = sodium_crypto_secretbox_open( $cipher, $nonce, self::key() );
		return false === $plain ? '' : $plain;
	}

	/**
	 * Mask a secret for display: keeps first 4 and last 4 characters.
	 */
	public static function mask( string $secret ): string {
		$len = strlen( $secret );
		if ( 0 === $len ) {
			return '';
		}
		if ( $len <= 10 ) {
			return str_repeat( '•', $len );
		}
		return substr( $secret, 0, 4 ) . str_repeat( '•', 12 ) . substr( $secret, -4 );
	}

	/**
	 * Constant-time comparison helper.
	 */
	public static function equals( string $a, string $b ): bool {
		return hash_equals( $a, $b );
	}
}

