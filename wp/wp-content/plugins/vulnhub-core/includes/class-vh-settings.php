<?php
/**
 * Settings + encrypted credential store.
 *
 * Non-secret settings live in a single autoloaded option per connector.
 * Secrets live in a separate, NON-autoloaded option, encrypted at rest.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Settings {

	private const OPT_PREFIX    = 'vulnhub_cfg_';
	private const SECRET_PREFIX = 'vulnhub_sec_';

	/** @var array<string,array<string,mixed>> */
	private array $cache = array();

	/**
	 * Read the full config for a connector (secrets decrypted on demand).
	 *
	 * @return array<string,mixed>
	 */
	public function all( string $connector ): array {
		if ( ! isset( $this->cache[ $connector ] ) ) {
			$this->cache[ $connector ] = (array) get_option( self::OPT_PREFIX . $connector, array() );
		}
		return $this->cache[ $connector ];
	}

	public function get( string $connector, string $key, mixed $default = '' ): mixed {
		$all = $this->all( $connector );
		return array_key_exists( $key, $all ) ? $all[ $key ] : $default;
	}

	public function get_bool( string $connector, string $key, bool $default = false ): bool {
		$v = $this->get( $connector, $key, $default ? '1' : '0' );
		return in_array( $v, array( 1, '1', true, 'true', 'yes', 'on' ), true );
	}

	public function get_int( string $connector, string $key, int $default = 0 ): int {
		$v = $this->get( $connector, $key, $default );
		return is_numeric( $v ) ? (int) $v : $default;
	}

	/**
	 * Merge and persist non-secret settings.
	 *
	 * @param array<string,mixed> $values Values to merge.
	 */
	public function update( string $connector, array $values ): void {
		$current = $this->all( $connector );
		$merged  = array_merge( $current, $values );
		update_option( self::OPT_PREFIX . $connector, $merged, false );
		$this->cache[ $connector ] = $merged;
	}

	public function set( string $connector, string $key, mixed $value ): void {
		$this->update( $connector, array( $key => $value ) );
	}

	public function delete( string $connector ): void {
		delete_option( self::OPT_PREFIX . $connector );
		delete_option( self::SECRET_PREFIX . $connector );
		unset( $this->cache[ $connector ] );
	}

	/* -----------------------------------------------------------------
	 * Secrets
	 * --------------------------------------------------------------- */

	/**
	 * @return array<string,string> Decrypted secrets keyed by field name.
	 */
	public function secrets( string $connector ): array {
		$stored = (array) get_option( self::SECRET_PREFIX . $connector, array() );
		$out    = array();
		foreach ( $stored as $key => $blob ) {
			$out[ $key ] = Crypto::decrypt( (string) $blob );
		}
		return $out;
	}

	public function secret( string $connector, string $key ): string {
		$stored = (array) get_option( self::SECRET_PREFIX . $connector, array() );
		if ( ! isset( $stored[ $key ] ) ) {
			return '';
		}
		return Crypto::decrypt( (string) $stored[ $key ] );
	}

	public function has_secret( string $connector, string $key ): bool {
		$stored = (array) get_option( self::SECRET_PREFIX . $connector, array() );
		return ! empty( $stored[ $key ] );
	}

	/**
	 * Store a secret. An empty value is IGNORED (so a blank form field means
	 * "leave the existing secret alone"); pass null to explicitly clear it.
	 */
	public function set_secret( string $connector, string $key, ?string $value ): void {
		$stored = (array) get_option( self::SECRET_PREFIX . $connector, array() );

		if ( null === $value ) {
			unset( $stored[ $key ] );
		} elseif ( '' === trim( $value ) ) {
			return; // Blank submit: keep what we have.
		} else {
			$stored[ $key ] = Crypto::encrypt( trim( $value ) );
		}

		update_option( self::SECRET_PREFIX . $connector, $stored, false );
	}

	/**
	 * Masked preview for the settings screen.
	 */
	public function secret_hint( string $connector, string $key ): string {
		$value = $this->secret( $connector, $key );
		return '' === $value ? '' : Crypto::mask( $value );
	}

	/* -----------------------------------------------------------------
	 * Platform-wide settings (single option)
	 * --------------------------------------------------------------- */

	public function platform( string $key, mixed $default = '' ): mixed {
		$all = (array) get_option( 'vulnhub_platform', array() );
		return array_key_exists( $key, $all ) ? $all[ $key ] : $default;
	}

	/**
	 * @param array<string,mixed> $values Values to merge.
	 */
	public function update_platform( array $values ): void {
		$all = (array) get_option( 'vulnhub_platform', array() );
		update_option( 'vulnhub_platform', array_merge( $all, $values ), true );
	}

	/**
	 * Is the whole platform running against mock data?
	 */
	public function mock_mode(): bool {
		return (bool) $this->platform( 'mock_mode', 1 );
	}
}

