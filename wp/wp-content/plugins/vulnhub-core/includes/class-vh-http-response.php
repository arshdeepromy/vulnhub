<?php
/**
 * Value object returned by every Http request.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Http_Response {

	/**
	 * @param array<string,mixed> $headers Response headers.
	 * @param array<mixed>|null   $json    Decoded JSON body when available.
	 */
	public function __construct(
		public readonly int $status,
		public readonly array $headers,
		public readonly string $body,
		public readonly ?array $json,
		public readonly ?string $error = null,
		public readonly int $attempts = 1,
		public readonly float $duration = 0.0
	) {}

	public function ok(): bool {
		return null === $this->error && $this->status >= 200 && $this->status < 300;
	}

	/**
	 * @return array<mixed>
	 */
	public function data(): array {
		return $this->json ?? array();
	}

	public function header( string $name ): string {
		$name = strtolower( $name );
		foreach ( $this->headers as $key => $value ) {
			if ( strtolower( (string) $key ) === $name ) {
				return is_array( $value ) ? (string) reset( $value ) : (string) $value;
			}
		}
		return '';
	}

	/**
	 * Best-effort error message from whichever vendor error envelope we got.
	 */
	public function error_message(): string {
		if ( $this->error ) {
			return $this->error;
		}
		$j = $this->json ?? array();

		// Microsoft Graph / Entra ID.
		if ( isset( $j['error']['message'] ) ) {
			$msg = (string) $j['error']['message'];
			if ( isset( $j['error']['code'] ) ) {
				$msg = $j['error']['code'] . ': ' . $msg;
			}
			return $msg;
		}
		if ( isset( $j['error_description'] ) ) {
			return (string) $j['error_description'];
		}

		// Jira / Confluence.
		if ( ! empty( $j['errorMessages'] ) && is_array( $j['errorMessages'] ) ) {
			return implode( '; ', array_map( 'strval', $j['errorMessages'] ) );
		}
		if ( ! empty( $j['errors'] ) && is_array( $j['errors'] ) ) {
			$parts = array();
			foreach ( $j['errors'] as $k => $v ) {
				$parts[] = $k . ': ' . ( is_scalar( $v ) ? (string) $v : (string) wp_json_encode( $v ) );
			}
			return implode( '; ', $parts );
		}

		// Tenable.
		if ( isset( $j['message'] ) && is_string( $j['message'] ) ) {
			return $j['message'];
		}
		if ( isset( $j['error'] ) && is_string( $j['error'] ) ) {
			return $j['error'];
		}

		if ( 0 === $this->status ) {
			return __( 'No response from the remote service.', 'vulnhub' );
		}

		/* translators: %d: HTTP status code. */
		return sprintf( __( 'HTTP %d', 'vulnhub' ), $this->status );
	}
}

