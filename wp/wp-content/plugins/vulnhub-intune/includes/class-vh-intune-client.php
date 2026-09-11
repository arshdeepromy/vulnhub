<?php
/**
 * Microsoft Graph client for the Intune / Entra ID connector.
 *
 * Everything vendor-specific about talking to Graph lives here: the app-only
 * (client credentials) token, opaque `@odata.nextLink` paging, and JSON
 * batching. The connector itself only ever deals in decoded Graph objects.
 *
 * Behaviour is sourced from Microsoft's own documentation:
 *  - Token:     learn.microsoft.com/entra/identity-platform/v2-oauth2-client-creds-grant-flow
 *               POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
 *               with grant_type=client_credentials and
 *               scope=https://graph.microsoft.com/.default. The docs state the
 *               client secret must be URL-encoded before being sent.
 *  - Paging:    learn.microsoft.com/graph/paging — "Use the entire URL in the
 *               @odata.nextLink property"; "Don't try to extract the $skiptoken
 *               or $skip value and use it in a different request." Custom
 *               headers such as ConsistencyLevel are NOT carried into the
 *               nextLink request and must be re-sent explicitly.
 *  - Batching:  learn.microsoft.com/graph/json-batching — 20 requests maximum,
 *               responses may come back in a different order than the requests,
 *               correlate them with the `id` property, and each entry carries
 *               its own status code.
 *  - Throttling learn.microsoft.com/graph/throttling — 429 plus a Retry-After
 *               header; wait that long and retry. Core's Http already honours
 *               Retry-After above its own backoff, so single requests are
 *               covered; entries throttled *inside* a batch are not retried
 *               automatically, so this class retries those itself.
 *
 * @package VulnHub\Intune
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Thin, well-behaved Microsoft Graph client.
 */
final class VulnHub_Intune_Client {

	/**
	 * Transient prefix for cached app-only access tokens.
	 */
	private const TOKEN_PREFIX = 'vh_intune_tok_';

	/**
	 * Expire the cached token this many seconds before Graph does, so a token
	 * can never go stale mid-page. We never parse the JWT — `expires_in` from
	 * the token response is the only lifetime signal we trust.
	 */
	private const TOKEN_SAFETY_WINDOW = 300;

	/**
	 * Hard ceiling on pages per collection. A malformed or looping nextLink
	 * must never be able to spin this connector forever.
	 */
	private const MAX_PAGES = 500;

	/**
	 * Graph's documented JSON batch limit.
	 */
	private const BATCH_LIMIT = 20;

	/**
	 * Core HTTP client (retries 429/5xx, honours Retry-After).
	 *
	 * @var \VulnHub\Core\Http
	 */
	private \VulnHub\Core\Http $http;

	/**
	 * Directory (tenant) id or verified domain.
	 *
	 * @var string
	 */
	private string $tenant_id;

	/**
	 * Application (client) id of the Entra app registration.
	 *
	 * @var string
	 */
	private string $client_id;

	/**
	 * Client secret. Never logged, never echoed, never stored by this class
	 * beyond the lifetime of the request.
	 *
	 * @var string
	 */
	private string $client_secret;

	/**
	 * Graph base URL, e.g. https://graph.microsoft.com/v1.0.
	 *
	 * @var string
	 */
	private string $base_url;

	/**
	 * Mock transport. When set, no network calls are made at all and Graph
	 * shaped payloads are served locally — but through the same paging,
	 * batching and normalisation code as the live path.
	 *
	 * @var VulnHub_Intune_Mock_Graph|null
	 */
	private ?VulnHub_Intune_Mock_Graph $mock;

	/**
	 * Run logger.
	 *
	 * @var callable|null
	 */
	private $log;

	/**
	 * Number of Graph requests issued during this client's lifetime.
	 *
	 * @var int
	 */
	private int $requests = 0;

	/**
	 * Constructor.
	 *
	 * @param \VulnHub\Core\Http             $http   Core HTTP client.
	 * @param array<string,mixed>            $config tenant_id, client_id, client_secret, base_url.
	 * @param callable|null                  $log    Logger callable.
	 * @param VulnHub_Intune_Mock_Graph|null $mock   Mock transport, or null for live Graph.
	 */
	public function __construct( \VulnHub\Core\Http $http, array $config, ?callable $log = null, ?VulnHub_Intune_Mock_Graph $mock = null ) {
		$this->http          = $http;
		$this->tenant_id     = trim( (string) ( $config['tenant_id'] ?? '' ) );
		$this->client_id     = trim( (string) ( $config['client_id'] ?? '' ) );
		$this->client_secret = (string) ( $config['client_secret'] ?? '' );
		$this->base_url      = rtrim( (string) ( $config['base_url'] ?? 'https://graph.microsoft.com/v1.0' ), '/' );
		$this->log           = $log;
		$this->mock          = $mock;
	}

	/**
	 * Write a line to the run log.
	 *
	 * @param string $message Message.
	 * @return void
	 */
	private function trace( string $message ): void {
		if ( is_callable( $this->log ) ) {
			call_user_func( $this->log, $message );
		}
	}

	/**
	 * How many Graph requests have been issued.
	 *
	 * @return int
	 */
	public function request_count(): int {
		return $this->requests;
	}

	/**
	 * Is this client serving generated data rather than live Graph?
	 *
	 * @return bool
	 */
	public function is_mock(): bool {
		return null !== $this->mock;
	}

	/**
	 * Graph base URL.
	 *
	 * @return string
	 */
	public function base_url(): string {
		return $this->base_url;
	}

	/* -----------------------------------------------------------------
	 * Authentication
	 * --------------------------------------------------------------- */

	/**
	 * Transient key for the cached token, scoped to tenant + client id so two
	 * app registrations (or two tenants) can never share a token.
	 *
	 * @return string
	 */
	private function token_key(): string {
		return self::TOKEN_PREFIX . md5( $this->tenant_id . '|' . $this->client_id . '|' . $this->base_url );
	}

	/**
	 * Drop the cached token (used after a 401, and by the settings screen when
	 * credentials change).
	 *
	 * @return void
	 */
	public function forget_token(): void {
		delete_transient( $this->token_key() );
	}

	/**
	 * Acquire an app-only access token via the client credentials grant.
	 *
	 * @throws RuntimeException When credentials are incomplete or Entra ID refuses the request.
	 * @return string Bearer token.
	 */
	public function token(): string {
		if ( $this->mock ) {
			return 'mock-access-token';
		}

		if ( '' === $this->tenant_id || '' === $this->client_id || '' === $this->client_secret ) {
			throw new RuntimeException( esc_html__( 'Tenant id, client id and client secret are all required.', 'vulnhub' ) );
		}

		$cached = get_transient( $this->token_key() );
		if ( is_string( $cached ) && '' !== $cached ) {
			return $cached;
		}

		$url = sprintf( 'https://login.microsoftonline.com/%s/oauth2/v2.0/token', rawurlencode( $this->tenant_id ) );

		// post_form() encodes the body with PHP_QUERY_RFC3986, which satisfies
		// the documented requirement that the client secret be URL-encoded.
		$response = $this->http->post_form(
			$url,
			array(
				'client_id'     => $this->client_id,
				'scope'         => 'https://graph.microsoft.com/.default',
				'client_secret' => $this->client_secret,
				'grant_type'    => 'client_credentials',
			)
		);
		++$this->requests;

		if ( ! $response->ok() ) {
			// Log the tenant, never the secret.
			$this->trace( sprintf( 'Token request for tenant %s failed: HTTP %d %s', $this->tenant_id, $response->status, $response->error_message() ) );
			throw new RuntimeException(
				sprintf(
					/* translators: 1: HTTP status, 2: error message. */
					esc_html__( 'Could not get an access token (HTTP %1$d): %2$s', 'vulnhub' ),
					(int) $response->status,
					esc_html( $response->error_message() )
				)
			);
		}

		$data  = $response->data();
		$token = (string) ( $data['access_token'] ?? '' );
		if ( '' === $token ) {
			throw new RuntimeException( esc_html__( 'Entra ID returned no access token.', 'vulnhub' ) );
		}

		// expires_in is seconds. Cache it minus the safety window; we deliberately
		// do NOT decode the JWT to read its exp claim — the token is opaque to us.
		$expires_in = (int) ( $data['expires_in'] ?? 3600 );
		$ttl        = max( 60, $expires_in - self::TOKEN_SAFETY_WINDOW );
		set_transient( $this->token_key(), $token, $ttl );

		$this->trace( sprintf( 'Acquired app-only token for tenant %s (cached for %d seconds).', $this->tenant_id, $ttl ) );

		return $token;
	}

	/* -----------------------------------------------------------------
	 * URL building
	 * --------------------------------------------------------------- */

	/**
	 * Build an absolute Graph URL from a relative path and OData query args.
	 *
	 * OData punctuation ($ , ( ) ') is left intact so URLs stay readable in the
	 * run log and byte-identical to the examples in Microsoft's docs.
	 *
	 * @param string                     $path  Relative path, e.g. 'users'.
	 * @param array<string,string|int>   $query OData query args.
	 * @return string
	 */
	public function build_url( string $path, array $query = array() ): string {
		$url = str_starts_with( $path, 'http' ) ? $path : $this->base_url . '/' . ltrim( $path, '/' );

		if ( ! $query ) {
			return $url;
		}

		$parts = array();
		foreach ( $query as $key => $value ) {
			$parts[] = self::encode_odata( (string) $key ) . '=' . self::encode_odata( (string) $value );
		}

		return $url . ( str_contains( $url, '?' ) ? '&' : '?' ) . implode( '&', $parts );
	}

	/**
	 * Percent-encode an OData query value, keeping the punctuation Graph's own
	 * examples use unescaped.
	 *
	 * @param string $value Raw value.
	 * @return string
	 */
	private static function encode_odata( string $value ): string {
		return strtr(
			rawurlencode( $value ),
			array(
				'%24' => '$',
				'%2C' => ',',
				'%28' => '(',
				'%29' => ')',
				'%27' => "'",
				'%3A' => ':',
			)
		);
	}

	/**
	 * Is this URL one we are willing to follow?
	 *
	 * A nextLink is opaque, but it must still point at the same Graph host we
	 * started from — otherwise a poisoned response could redirect the sync (and
	 * its bearer token) somewhere else entirely.
	 *
	 * @param string $url Candidate URL.
	 * @return bool
	 */
	private function is_trusted_url( string $url ): bool {
		$want = wp_parse_url( $this->base_url, PHP_URL_HOST );
		$got  = wp_parse_url( $url, PHP_URL_HOST );

		return is_string( $want ) && is_string( $got )
			&& 0 === strcasecmp( $want, $got )
			&& 'https' === strtolower( (string) wp_parse_url( $url, PHP_URL_SCHEME ) );
	}

	/* -----------------------------------------------------------------
	 * Requests
	 * --------------------------------------------------------------- */

	/**
	 * GET an absolute URL and return the decoded payload.
	 *
	 * @param string               $url     Absolute URL.
	 * @param array<string,string> $headers Extra headers (e.g. ConsistencyLevel).
	 *
	 * @throws RuntimeException On any non-2xx response.
	 * @return array<string,mixed>
	 */
	public function fetch( string $url, array $headers = array() ): array {
		++$this->requests;

		if ( $this->mock ) {
			return $this->mock->respond( $url );
		}

		$headers['Authorization'] = 'Bearer ' . $this->token();
		$response                 = $this->http->get( $url, array(), $headers );

		// A 401 mid-sync almost always means the cached token was revoked or
		// rotated. Drop it and try exactly once more.
		if ( 401 === $response->status ) {
			$this->trace( 'Graph returned 401; discarding the cached token and retrying once.' );
			$this->forget_token();
			$headers['Authorization'] = 'Bearer ' . $this->token();
			$response                 = $this->http->get( $url, array(), $headers );
			++$this->requests;
		}

		if ( ! $response->ok() ) {
			throw new RuntimeException(
				sprintf(
					/* translators: 1: URL, 2: HTTP status, 3: error message. */
					esc_html__( 'Graph request %1$s failed (HTTP %2$d): %3$s', 'vulnhub' ),
					esc_html( \VulnHub\Core\Http::scrub( $url ) ),
					(int) $response->status,
					esc_html( $response->error_message() )
				)
			);
		}

		return $response->data();
	}

	/**
	 * GET a relative Graph path with query args.
	 *
	 * @param string                   $path    Relative path.
	 * @param array<string,string|int> $query   Query args.
	 * @param array<string,string>     $headers Extra headers.
	 *
	 * @return array<string,mixed>
	 */
	public function get( string $path, array $query = array(), array $headers = array() ): array {
		return $this->fetch( $this->build_url( $path, $query ), $headers );
	}

	/**
	 * Probe an endpoint and report success/failure without throwing — used by
	 * test_connection() to tell "no permission" apart from "no connectivity".
	 *
	 * @param string                   $path  Relative path.
	 * @param array<string,string|int> $query Query args.
	 * @return array{ok:bool,status:int,message:string,count:int}
	 */
	public function probe( string $path, array $query = array() ): array {
		$url = $this->build_url( $path, $query );

		if ( $this->mock ) {
			$data = $this->mock->respond( $url );
			return array(
				'ok'      => true,
				'status'  => 200,
				'message' => 'mock',
				'count'   => count( (array) ( $data['value'] ?? array() ) ),
			);
		}

		try {
			$token = $this->token();
		} catch ( Throwable $e ) {
			return array(
				'ok'      => false,
				'status'  => 0,
				'message' => $e->getMessage(),
				'count'   => 0,
			);
		}

		++$this->requests;
		$response = $this->http->get( $url, array(), array( 'Authorization' => 'Bearer ' . $token ) );

		return array(
			'ok'      => $response->ok(),
			'status'  => (int) $response->status,
			'message' => $response->ok() ? 'ok' : $response->error_message(),
			'count'   => count( (array) ( $response->data()['value'] ?? array() ) ),
		);
	}

	/* -----------------------------------------------------------------
	 * Paging
	 * --------------------------------------------------------------- */

	/**
	 * Walk a Graph collection, handing each page to a callback.
	 *
	 * The `@odata.nextLink` is passed through verbatim and unmodified, exactly
	 * as the documentation requires. Two guards keep the loop bounded: a hard
	 * page ceiling, and a set of URLs already fetched — a nextLink that repeats
	 * an earlier URL is a malformed response, not a page, and we stop.
	 *
	 * @param string                   $path    Relative path, e.g. 'users'.
	 * @param array<string,string|int> $query   Initial query args (later pages inherit them via the nextLink).
	 * @param array<string,string>     $headers Headers to send on EVERY page — Graph does not carry custom
	 *                                          headers such as ConsistencyLevel into nextLink requests.
	 * @param callable                 $on_page function(array $items, int $page): void.
	 *
	 * @return array{pages:int,items:int}
	 */
	public function paginate( string $path, array $query, array $headers, callable $on_page ): array {
		$url   = $this->build_url( $path, $query );
		$seen  = array();
		$pages = 0;
		$items = 0;

		while ( '' !== $url ) {
			$fingerprint = md5( $url );
			if ( isset( $seen[ $fingerprint ] ) ) {
				$this->trace( 'Paging stopped: @odata.nextLink pointed back at a page already fetched (malformed response).' );
				break;
			}
			$seen[ $fingerprint ] = true;

			++$pages;
			if ( $pages > self::MAX_PAGES ) {
				$this->trace( sprintf( 'Paging stopped: hit the %d page ceiling for %s.', self::MAX_PAGES, $path ) );
				break;
			}

			$payload = $this->fetch( $url, $headers );
			$batch   = isset( $payload['value'] ) && is_array( $payload['value'] ) ? $payload['value'] : array();
			$items  += count( $batch );

			$on_page( $batch, $pages );

			$next = trim( (string) ( $payload['@odata.nextLink'] ?? '' ) );
			if ( '' === $next ) {
				break;
			}
			if ( ! $this->is_trusted_url( $next ) ) {
				$this->trace( 'Paging stopped: @odata.nextLink pointed at an unexpected host.' );
				break;
			}

			$url = $next;
		}

		$this->trace( sprintf( 'Fetched %d %s across %d page(s).', $items, $path, $pages ) );

		return array(
			'pages' => $pages,
			'items' => $items,
		);
	}

	/* -----------------------------------------------------------------
	 * JSON batching
	 * --------------------------------------------------------------- */

	/**
	 * Run a set of GET requests through POST /$batch.
	 *
	 * @param array<string,string> $requests Map of correlation id => relative Graph URL.
	 * @param array<string,string> $headers  Per-request headers applied to every entry.
	 *
	 * @return array<string,array{status:int,body:array<mixed>}> Keyed by the SAME ids that were passed in.
	 */
	public function batch( array $requests, array $headers = array() ): array {
		$out = array();

		foreach ( array_chunk( $requests, self::BATCH_LIMIT, true ) as $chunk ) {
			$out += $this->batch_chunk( $chunk, $headers, true );
		}

		return $out;
	}

	/**
	 * Execute one batch of at most 20 requests.
	 *
	 * @param array<string,string> $chunk      Map of id => relative URL.
	 * @param array<string,string> $headers    Per-entry headers.
	 * @param bool                 $retry_429  Retry entries throttled inside the batch once.
	 *
	 * @return array<string,array{status:int,body:array<mixed>}>
	 */
	private function batch_chunk( array $chunk, array $headers, bool $retry_429 ): array {
		$entries = array();
		foreach ( $chunk as $id => $relative ) {
			$entry = array(
				'id'     => (string) $id,
				'method' => 'GET',
				'url'    => '/' . ltrim( (string) $relative, '/' ),
			);
			if ( $headers ) {
				$entry['headers'] = $headers;
			}
			$entries[] = $entry;
		}

		++$this->requests;

		if ( $this->mock ) {
			$payload = $this->mock->batch( $entries );
		} else {
			$response = $this->http->post(
				$this->build_url( '$batch' ),
				array( 'requests' => $entries ),
				array(
					'Authorization' => 'Bearer ' . $this->token(),
					'Content-Type'  => 'application/json',
				)
			);
			if ( ! $response->ok() ) {
				$this->trace( sprintf( 'Batch request failed (HTTP %d): %s', $response->status, $response->error_message() ) );
				return array();
			}
			$payload = $response->data();
		}

		$out       = array();
		$throttled = array();
		$wait      = 0;

		// Responses may arrive in a different order than the requests, so we
		// correlate strictly by `id` and never by position.
		foreach ( (array) ( $payload['responses'] ?? array() ) as $item ) {
			$id     = (string) ( $item['id'] ?? '' );
			$status = (int) ( $item['status'] ?? 0 );
			if ( '' === $id || ! isset( $chunk[ $id ] ) ) {
				continue;
			}

			if ( 429 === $status && $retry_429 ) {
				// Throttled entries inside a batch are NOT retried for us.
				$throttled[ $id ] = $chunk[ $id ];
				$retry_after      = (int) ( $item['headers']['Retry-After'] ?? $item['headers']['retry-after'] ?? 5 );
				$wait             = max( $wait, min( $retry_after, 60 ) );
				continue;
			}

			$out[ $id ] = array(
				'status' => $status,
				'body'   => is_array( $item['body'] ?? null ) ? (array) $item['body'] : array(),
			);
		}

		if ( $throttled ) {
			$this->trace( sprintf( '%d batched request(s) were throttled; waiting %ds before a single retry.', count( $throttled ), $wait ) );
			sleep( max( 1, $wait ) );
			$out += $this->batch_chunk( $throttled, $headers, false );
		}

		return $out;
	}
}

