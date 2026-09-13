<?php
/**
 * AWS Signature Version 4.
 *
 * Written out rather than pulled in with the AWS SDK, which would mean adding
 * Composer and several thousand files to a stack that currently has neither,
 * for four read-only API calls. SigV4 is a well-specified HMAC chain and the
 * container already has `hash_hmac`, `openssl` and `simplexml`.
 *
 * The risk in hand-rolling a signer is that you cannot tell a correct one from
 * a broken one without credentials -- every failure looks like
 * "SignatureDoesNotMatch". So this is verified against the test vector AWS
 * publishes with the specification, which pins the canonical request, the
 * string to sign and the final signature to known-good values. See
 * dev/test-aws-sigv4.php: if that passes, a signing failure against the live
 * API is a credential or permission problem, not this code.
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Signs a request the way AWS expects.
 */
final class VulnHub_AWS_SigV4 {

	private const ALGO = 'AWS4-HMAC-SHA256';

	/**
	 * Build the headers a signed request needs.
	 *
	 * @param string                $method  HTTP verb.
	 * @param string                $url     Full request URL.
	 * @param string                $body    Raw request body ('' for GET).
	 * @param array<string,string>  $headers Headers to sign, host excluded.
	 * @param string                $region  AWS region.
	 * @param string                $service Service name, e.g. 'inspector2'.
	 * @param string                $key     Access key id.
	 * @param string                $secret  Secret access key.
	 * @param string                $token   Session token, when assuming a role.
	 * @param string                $now     Override the clock, for tests only.
	 * @return array<string,string> Headers including Authorization.
	 */
	public static function headers(
		string $method,
		string $url,
		string $body,
		array $headers,
		string $region,
		string $service,
		string $key,
		string $secret,
		string $token = '',
		string $now = ''
	): array {
		$parts = wp_parse_url( $url );
		$host  = (string) ( $parts['host'] ?? '' );
		$path  = (string) ( $parts['path'] ?? '/' );
		$query = (string) ( $parts['query'] ?? '' );

		if ( '' === $path ) {
			$path = '/';
		}

		$stamp = '' !== $now ? $now : gmdate( 'Ymd\THis\Z' );
		$date  = substr( $stamp, 0, 8 );

		$headers['host']       = $host;
		$headers['x-amz-date'] = $stamp;

		if ( '' !== $token ) {
			$headers['x-amz-security-token'] = $token;
		}

		$payload_hash = hash( 'sha256', $body );

		/*
		 * x-amz-content-sha256 is deliberately NOT added here. It is an S3
		 * requirement, not a general one, and adding it changes the signed
		 * header set -- which would make this signer disagree with the
		 * reference vector AWS publishes and leave nothing to verify against.
		 * A caller that needs it passes it in $headers and it gets signed like
		 * any other header.
		 */

		// Canonical headers: lowercase names, trimmed values, sorted by name.
		$canon = array();

		foreach ( $headers as $name => $value ) {
			$canon[ strtolower( trim( $name ) ) ] = preg_replace( '/\s+/', ' ', trim( (string) $value ) );
		}

		ksort( $canon );

		$canon_headers = '';

		foreach ( $canon as $name => $value ) {
			$canon_headers .= $name . ':' . $value . "\n";
		}

		$signed_headers = implode( ';', array_keys( $canon ) );

		$canonical_request = implode(
			"\n",
			array(
				strtoupper( $method ),
				self::canonical_path( $path ),
				self::canonical_query( $query ),
				$canon_headers,
				$signed_headers,
				$payload_hash,
			)
		);

		$scope = $date . '/' . $region . '/' . $service . '/aws4_request';

		$string_to_sign = implode(
			"\n",
			array(
				self::ALGO,
				$stamp,
				$scope,
				hash( 'sha256', $canonical_request ),
			)
		);

		$signature = hash_hmac( 'sha256', $string_to_sign, self::signing_key( $secret, $date, $region, $service ) );

		$headers['Authorization'] = sprintf(
			'%s Credential=%s/%s, SignedHeaders=%s, Signature=%s',
			self::ALGO,
			$key,
			$scope,
			$signed_headers,
			$signature
		);

		return $headers;
	}

	/**
	 * The four-step HMAC chain that derives the signing key.
	 *
	 * Each round keys the next, so the resulting key is bound to the day, the
	 * region and the service -- which is why a signature cannot be replayed
	 * against a different region even with the same secret.
	 */
	private static function signing_key( string $secret, string $date, string $region, string $service ): string {
		$k = hash_hmac( 'sha256', $date, 'AWS4' . $secret, true );
		$k = hash_hmac( 'sha256', $region, $k, true );
		$k = hash_hmac( 'sha256', $service, $k, true );

		return hash_hmac( 'sha256', 'aws4_request', $k, true );
	}

	/**
	 * URI-encode each path segment, leaving the separators alone.
	 *
	 * S3 is the exception that does not want this double-encoding, but none of
	 * the services here are S3.
	 */
	private static function canonical_path( string $path ): string {
		$out = array();

		foreach ( explode( '/', $path ) as $segment ) {
			$out[] = rawurlencode( rawurldecode( $segment ) );
		}

		return implode( '/', $out );
	}

	/**
	 * Sort query parameters by name, then by value, and re-encode them.
	 */
	private static function canonical_query( string $query ): string {
		if ( '' === $query ) {
			return '';
		}

		$pairs = array();

		foreach ( explode( '&', $query ) as $pair ) {
			if ( '' === $pair ) {
				continue;
			}

			$bits  = explode( '=', $pair, 2 );
			$name  = rawurlencode( rawurldecode( $bits[0] ) );
			$value = rawurlencode( rawurldecode( $bits[1] ?? '' ) );

			$pairs[] = array( $name, $value );
		}

		usort(
			$pairs,
			static fn( array $a, array $b ): int => $a[0] === $b[0] ? strcmp( $a[1], $b[1] ) : strcmp( $a[0], $b[0] )
		);

		return implode( '&', array_map( static fn( array $p ): string => $p[0] . '=' . $p[1], $pairs ) );
	}
}
