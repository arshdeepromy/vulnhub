<?php
/**
 * A signed client for Akamai's OPEN APIs.
 *
 * Akamai does not take a bearer token. Every request carries an
 * `EG1-HMAC-SHA256` Authorization header whose signature covers the method,
 * host, path, query and body, so the credential never travels and a captured
 * request cannot be replayed against another path. Getting any part of the
 * string wrong yields a 401 that says nothing useful, which is why the
 * construction below follows Akamai's own reference implementation field for
 * field, and why `self_test()` exists.
 *
 * The scheme, in order:
 *
 *   signing key   = base64( HMAC-SHA256( timestamp, client_secret ) )
 *   content hash  = base64( SHA-256( body ) ), POST only, first 128 KB
 *   data to sign  = method \t https \t host \t path?query \t canonical headers
 *                   \t content hash \t auth header (no signature yet)
 *   signature     = base64( HMAC-SHA256( data to sign, signing key ) )
 *
 * The auth header inside the signed data ends with a trailing semicolon and
 * carries no signature; the signature is appended afterwards. Timestamps are
 * UTC `Ymd\THis+0000` and must be within 30 seconds of real time, so a Pi
 * with a drifting clock will fail authentication rather than authorisation --
 * worth knowing before anyone goes looking for a permissions problem.
 *
 * Credentials come from an API client created in Control Center
 * (ACCOUNT ADMIN -> Identity & access). Read-only grants on Property Manager
 * and Application Security are all this needs; it never writes.
 *
 * @package VulnHub\Akamai
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Akamai_Client {

	/** Akamai signs at most the first 128 KB of a body. */
	private const MAX_BODY = 131072;

	private string $host;
	private string $client_token;
	private string $client_secret;
	private string $access_token;
	private string $account_key;
	private int $timeout;
	private int $calls = 0;

	public function __construct(
		string $host,
		string $client_token,
		string $client_secret,
		string $access_token,
		string $account_key = '',
		int $timeout = 60
	) {
		// The credential file gives the host bare; tolerate a pasted scheme
		// or trailing slash rather than failing to sign for a typo.
		$host = (string) preg_replace( '#^https?://#', '', trim( $host ) );

		$this->host          = rtrim( $host, '/' );
		$this->client_token  = trim( $client_token );
		$this->client_secret = trim( $client_secret );
		$this->access_token  = trim( $access_token );
		$this->account_key   = trim( $account_key );
		$this->timeout       = $timeout;
	}

	public function calls(): int {
		return $this->calls;
	}

	public function configured(): bool {
		return '' !== $this->host
			&& '' !== $this->client_token
			&& '' !== $this->client_secret
			&& '' !== $this->access_token;
	}

	/* =================================================================
	 * Requests
	 * ============================================================== */

	/**
	 * GET one path.
	 *
	 * @param array<string,string> $query   Query parameters, unencoded.
	 * @param array<string,string> $headers Extra request headers.
	 * @return array{ok:bool,status:int,data:array<string,mixed>,error:string}
	 */
	public function get( string $path, array $query = array(), array $headers = array() ): array {
		if ( '' !== $this->account_key ) {
			$query['accountSwitchKey'] = $this->account_key;
		}

		$qs  = $query ? '?' . http_build_query( $query, '', '&', PHP_QUERY_RFC3986 ) : '';
		$url = 'https://' . $this->host . $path . $qs;

		$headers['Authorization'] = $this->auth_header( 'GET', $path . $qs, '' );
		$headers['Accept']        = 'application/json';

		++$this->calls;

		$res = wp_remote_get(
			$url,
			array(
				'headers' => $headers,
				'timeout' => $this->timeout,
			)
		);

		return $this->decode( $res );
	}

	/**
	 * @param array<string,mixed>|WP_Error $res Response from wp_remote_*.
	 * @return array{ok:bool,status:int,data:array<string,mixed>,error:string}
	 */
	private function decode( $res ): array {
		if ( is_wp_error( $res ) ) {
			return self::fail( 0, $res->get_error_message() );
		}

		$status = (int) wp_remote_retrieve_response_code( $res );
		$raw    = (string) wp_remote_retrieve_body( $res );
		$data   = json_decode( $raw, true );
		$data   = is_array( $data ) ? $data : array();

		if ( $status >= 200 && $status < 300 ) {
			return array(
				'ok'     => true,
				'status' => $status,
				'data'   => $data,
				'error'  => '',
			);
		}

		/*
		 * Akamai answers errors as RFC 7807 problem documents. `detail` is
		 * the sentence worth showing; `title` alone is usually too vague to
		 * act on, and a 401 here means the signature or the clock, while a
		 * 403 means the API client lacks the grant.
		 */
		$msg = trim(
			(string) ( $data['detail'] ?? '' ) ?: (string) ( $data['title'] ?? '' )
		);

		if ( '' === $msg ) {
			$msg = substr( $raw, 0, 300 );
		}

		if ( 401 === $status ) {
			$msg = __( 'Akamai rejected the signature. Check the credentials, and check this machine\'s clock is within 30 seconds of real time.', 'vulnhub' ) . ' ' . $msg;
		}

		return self::fail( $status, $msg );
	}

	/**
	 * @return array{ok:bool,status:int,data:array<string,mixed>,error:string}
	 */
	private static function fail( int $status, string $error ): array {
		return array(
			'ok'     => false,
			'status' => $status,
			'data'   => array(),
			'error'  => $error,
		);
	}

	/* =================================================================
	 * Signing
	 * ============================================================== */

	/**
	 * The Authorization header for one request.
	 *
	 * @param string $target Path with query string, exactly as sent.
	 */
	private function auth_header( string $method, string $target, string $body, string $timestamp = '', string $nonce = '' ): string {
		$timestamp = '' !== $timestamp ? $timestamp : gmdate( 'Ymd\THis+0000' );
		$nonce     = '' !== $nonce ? $nonce : self::nonce();

		$auth = sprintf(
			'EG1-HMAC-SHA256 client_token=%s;access_token=%s;timestamp=%s;nonce=%s;',
			$this->client_token,
			$this->access_token,
			$timestamp,
			$nonce
		);

		$signature = self::base64_hmac(
			$this->data_to_sign( $method, $target, $body, $auth ),
			self::base64_hmac( $timestamp, $this->client_secret )
		);

		return $auth . 'signature=' . $signature;
	}

	/**
	 * The tab-separated string the signature covers.
	 *
	 * The empty fifth field is the canonical header list. Nothing here signs
	 * extra headers, and an empty field is correct -- not an omission: drop
	 * the field and every signature is wrong.
	 */
	private function data_to_sign( string $method, string $target, string $body, string $auth ): string {
		$method = strtoupper( $method );

		return implode(
			"\t",
			array(
				$method,
				'https',
				$this->host,
				$target,
				'',
				'POST' === $method && '' !== $body ? self::base64_sha256( substr( $body, 0, self::MAX_BODY ) ) : '',
				$auth,
			)
		);
	}

	private static function base64_hmac( string $data, string $key ): string {
		return base64_encode( hash_hmac( 'sha256', $data, $key, true ) );
	}

	private static function base64_sha256( string $data ): string {
		return base64_encode( hash( 'sha256', $data, true ) );
	}

	/** A throwaway value that makes a captured request unrepeatable. */
	private static function nonce(): string {
		return function_exists( 'wp_generate_uuid4' ) ? wp_generate_uuid4() : bin2hex( random_bytes( 16 ) );
	}

	/* =================================================================
	 * Proving the signer, without a credential
	 * ============================================================== */

	/**
	 * Check the signing maths against Akamai's own published test vector.
	 *
	 * A signing implementation that is subtly wrong fails with 401, which
	 * looks exactly like a bad credential or a wrong grant -- so the first
	 * live run would send somebody hunting through Control Center for a
	 * permissions problem that does not exist. This settles that question
	 * before any credential is involved: the vector and its expected key
	 * come from Akamai's reference test data.
	 *
	 * @return array{ok:bool,message:string}
	 */
	public static function self_test(): array {
		$timestamp = '20140321T19:34:21+0000';
		$secret    = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=';
		$expected  = 'znsRMDBRqTXGJ7Ojip3/h2FGPu3LuoMYWgv9PKEnE/o=';
		$got       = self::base64_hmac( $timestamp, $secret );

		if ( $got !== $expected ) {
			return array(
				'ok'      => false,
				'message' => __( 'The EdgeGrid signing key does not match Akamai\'s published test vector -- the signer is wrong, not the credentials.', 'vulnhub' ),
			);
		}

		// The shape of the signed string matters as much as the maths: seven
		// tab-separated fields, the fifth empty, the last ending in ";".
		$probe  = new self( 'example.akamaiapis.net', 'ct', 'cs', 'at' );
		$fields = explode( "\t", $probe->data_to_sign( 'GET', '/papi/v1/groups', '', 'EG1-HMAC-SHA256 client_token=ct;' ) );

		if ( 7 !== count( $fields ) || '' !== $fields[4] || '' !== $fields[5] ) {
			return array(
				'ok'      => false,
				'message' => __( 'The EdgeGrid data-to-sign string is not the shape Akamai expects.', 'vulnhub' ),
			);
		}

		return array(
			'ok'      => true,
			'message' => __( 'EdgeGrid signing matches Akamai\'s published test vector.', 'vulnhub' ),
		);
	}
}

