<?php
/**
 * Shared HTTP client for every connector.
 *
 * Implements the retry semantics every vendor asks for:
 *  - Microsoft Graph: honour Retry-After above your own backoff, add jitter,
 *    never retry immediately (learn.microsoft.com/graph/throttling).
 *  - Tenable: 429 with Retry-After, plus export job polling.
 *  - Atlassian: 429 with Retry-After, cost-based limits.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Http {

	private const MAX_ATTEMPTS  = 5;
	private const BASE_BACKOFF  = 1.0;
	private const MAX_BACKOFF   = 60.0;

	private string $user_agent;

	/** @var callable|null */
	private $log;

	public function __construct( string $user_agent = '', ?callable $log = null ) {
		$this->user_agent = $user_agent ?: self::default_user_agent();
		$this->log        = $log;
	}

	/**
	 * Tenable asks integrations to identify themselves in this exact shape.
	 */
	public static function default_user_agent(): string {
		return sprintf( 'Integration/1.0 (Romy Sidhu; VulnHub; Build/%s)', VULNHUB_VERSION );
	}

	private function trace( string $message ): void {
		if ( is_callable( $this->log ) ) {
			call_user_func( $this->log, $message );
		}
	}

	/**
	 * Perform a request with retry on 429/5xx.
	 *
	 * @param array{
	 *   headers?:array<string,string>,
	 *   body?:string|array<mixed>|null,
	 *   timeout?:int,
	 *   json?:bool,
	 *   retries?:int,
	 *   expect_json?:bool
	 * } $args Options.
	 */
	public function request( string $method, string $url, array $args = array() ): Http_Response {
		$headers = $args['headers'] ?? array();
		$timeout = (int) ( $args['timeout'] ?? 45 );
		$retries = (int) ( $args['retries'] ?? self::MAX_ATTEMPTS );
		$body    = $args['body'] ?? null;
		$as_json = $args['json'] ?? true;

		$headers['User-Agent'] = $headers['User-Agent'] ?? $this->user_agent;
		$headers['Accept']     = $headers['Accept'] ?? 'application/json';

		if ( is_array( $body ) ) {
			$body                       = (string) wp_json_encode( $body );
			$headers['Content-Type']    = $headers['Content-Type'] ?? 'application/json';
		}

		$attempt = 0;
		$start   = microtime( true );
		$last    = null;

		while ( $attempt < max( 1, $retries ) ) {
			++$attempt;

			$response = wp_remote_request(
				$url,
				array(
					'method'      => strtoupper( $method ),
					'headers'     => $headers,
					'body'        => $body,
					'timeout'     => $timeout,
					'redirection' => 5,
					'sslverify'   => true,
				)
			);

			if ( is_wp_error( $response ) ) {
				$last = new Http_Response(
					0,
					array(),
					'',
					null,
					$response->get_error_message(),
					$attempt,
					microtime( true ) - $start
				);
				$this->trace( sprintf( 'HTTP %s %s -> transport error: %s (attempt %d)', $method, self::scrub( $url ), $response->get_error_message(), $attempt ) );

				if ( $attempt < $retries ) {
					$this->sleep( $this->backoff( $attempt ) );
					continue;
				}
				break;
			}

			$status      = (int) wp_remote_retrieve_response_code( $response );
			$raw_headers = wp_remote_retrieve_headers( $response );
			$hdrs        = is_object( $raw_headers ) && method_exists( $raw_headers, 'getAll' )
				? $raw_headers->getAll()
				: (array) $raw_headers;
			$raw_body    = (string) wp_remote_retrieve_body( $response );
			$json        = $as_json ? json_decode( $raw_body, true ) : null;
			$json        = is_array( $json ) ? $json : null;

			$last = new Http_Response( $status, $hdrs, $raw_body, $json, null, $attempt, microtime( true ) - $start );

			// Retryable?
			$retryable = 429 === $status || in_array( $status, array( 500, 502, 503, 504 ), true );

			if ( ! $retryable || $attempt >= $retries ) {
				if ( $status >= 400 ) {
					$this->trace( sprintf( 'HTTP %s %s -> %d %s', $method, self::scrub( $url ), $status, vh_trim( $last->error_message(), 160 ) ) );
				}
				return $last;
			}

			// Retry-After always wins over our own backoff.
			$retry_after = $last->header( 'retry-after' );
			$wait        = '' !== $retry_after && is_numeric( $retry_after )
				? min( (float) $retry_after, self::MAX_BACKOFF )
				: $this->backoff( $attempt );

			$this->trace( sprintf( 'HTTP %s %s -> %d, backing off %.1fs (attempt %d/%d)', $method, self::scrub( $url ), $status, $wait, $attempt, $retries ) );
			$this->sleep( $wait );
		}

		return $last ?? new Http_Response( 0, array(), '', null, 'no response', $attempt, microtime( true ) - $start );
	}

	/**
	 * Exponential backoff with jitter, so parallel workers do not resynchronise.
	 */
	private function backoff( int $attempt ): float {
		$base   = self::BASE_BACKOFF * ( 2 ** ( $attempt - 1 ) );
		$jitter = wp_rand( 0, 1000 ) / 1000;
		return min( $base + $jitter, self::MAX_BACKOFF );
	}

	private function sleep( float $seconds ): void {
		usleep( (int) round( $seconds * 1000000 ) );
	}

	/**
	 * Remove obvious secrets from a URL before logging it.
	 */
	public static function scrub( string $url ): string {
		$url = (string) preg_replace( '/(client_secret|secretKey|api_token|password|access_token|code)=[^&]+/i', '$1=***', $url );
		return vh_trim( $url, 180 );
	}

	/* -----------------------------------------------------------------
	 * Convenience verbs
	 * --------------------------------------------------------------- */

	/**
	 * @param array<string,string|int|bool> $query Query args.
	 * @param array<string,string>          $headers Headers.
	 */
	public function get( string $url, array $query = array(), array $headers = array(), array $args = array() ): Http_Response {
		if ( $query ) {
			$url = add_query_arg( $query, $url );
		}
		return $this->request( 'GET', $url, array_merge( $args, array( 'headers' => $headers ) ) );
	}

	/**
	 * @param array<mixed>|string|null $body Body.
	 * @param array<string,string>     $headers Headers.
	 */
	public function post( string $url, array|string|null $body = null, array $headers = array(), array $args = array() ): Http_Response {
		return $this->request( 'POST', $url, array_merge( $args, array( 'headers' => $headers, 'body' => $body ) ) );
	}

	/**
	 * @param array<mixed>|string|null $body Body.
	 * @param array<string,string>     $headers Headers.
	 */
	public function put( string $url, array|string|null $body = null, array $headers = array(), array $args = array() ): Http_Response {
		return $this->request( 'PUT', $url, array_merge( $args, array( 'headers' => $headers, 'body' => $body ) ) );
	}

	/**
	 * Form-encoded POST (OAuth token endpoints).
	 *
	 * @param array<string,string> $fields Form fields.
	 */
	public function post_form( string $url, array $fields, array $headers = array() ): Http_Response {
		$headers['Content-Type'] = 'application/x-www-form-urlencoded';
		return $this->request(
			'POST',
			$url,
			array(
				'headers' => $headers,
				'body'    => http_build_query( $fields, '', '&', PHP_QUERY_RFC3986 ),
			)
		);
	}
}

