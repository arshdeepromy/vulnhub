<?php
/**
 * Tenable Vulnerability Management REST client.
 *
 * Everything here follows the vendor contract published on
 * developer.tenable.com (verified 2026-09):
 *
 *  - Authentication is a single header:
 *      `X-ApiKeys: accessKey=<ACCESS_KEY>;secretKey=<SECRET_KEY>;`
 *    (developer.tenable.com/docs/authorization). There is no OAuth dance and
 *    the deprecated POST /session token flow is deliberately not used.
 *  - Integrations must identify themselves with
 *      `User-Agent: Integration/1.0 (VENDOR; PRODUCT; Build/VERSION)`
 *    (developer.tenable.com/docs/user-agent-header). Core's Http client
 *    already emits exactly that shape; we set it explicitly so the
 *    requirement is visible at the call site.
 *  - Bulk data comes from the export APIs, never the workbench endpoints —
 *    Tenable's own rate-limiting guidance says exports are the supported way
 *    to pull volume, and that requests should be sequential, not threaded
 *    (developer.tenable.com/docs/rate-limiting). 429 responses carry a
 *    `retry-after` header; core's Http honours it above its own backoff, so
 *    this class never implements throttling of its own.
 *
 * The export lifecycle for both assets and vulns is identical:
 *
 *   POST /{kind}/export                       -> { "export_uuid": "..." }
 *   GET  /{kind}/export/{uuid}/status         -> { status, chunks_available[] }
 *   GET  /{kind}/export/{uuid}/chunks/{id}    -> [ record, record, ... ]
 *
 * Job status values are QUEUED, PROCESSING, FINISHED, CANCELLED and ERROR.
 * Chunks are produced in parallel and therefore appear out of order, so we
 * download each chunk the moment it shows up in `chunks_available` rather
 * than waiting for the whole job. Chunks stay downloadable for 24 hours.
 *
 * @package VulnHub\Tenable
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Stateless wrapper around the Tenable VM export and metadata endpoints.
 */
final class VulnHub_Tenable_Client {

	/** Export kind: assets. */
	public const KIND_ASSETS = 'assets';

	/** Export kind: vulnerabilities. */
	public const KIND_VULNS = 'vulns';

	/** Job states that mean "stop polling". */
	private const TERMINAL_STATES = array( 'FINISHED', 'ERROR', 'CANCELLED' );

	/** Hard wall-clock ceiling for a single export job, in seconds. */
	private const POLL_TIMEOUT_SECONDS = 480;

	/** Hard ceiling on status requests for a single export job. */
	private const POLL_MAX_ATTEMPTS = 200;

	/** First and largest sleep between status polls, in seconds. */
	private const POLL_FIRST_WAIT = 2.0;
	private const POLL_MAX_WAIT   = 15.0;

	/**
	 * API base, e.g. https://cloud.tenable.com — no trailing slash.
	 */
	private string $base_url;

	/**
	 * Tenable access key. Never logged.
	 */
	private string $access_key;

	/**
	 * Tenable secret key. Never logged.
	 */
	private string $secret_key;

	/**
	 * Shared HTTP client (retries, Retry-After handling, jitter).
	 */
	private \VulnHub\Core\Http $http;

	/**
	 * Run-log sink.
	 *
	 * @var callable(string):void
	 */
	private $log;

	/**
	 * @param string                $base_url   API base URL.
	 * @param string                $access_key Tenable access key.
	 * @param string                $secret_key Tenable secret key.
	 * @param \VulnHub\Core\Http    $http       Shared HTTP client.
	 * @param callable(string):void $log        Optional run-log callback.
	 */
	public function __construct(
		string $base_url,
		string $access_key,
		string $secret_key,
		\VulnHub\Core\Http $http,
		?callable $log = null
	) {
		$this->base_url   = untrailingslashit( trim( $base_url ) ?: 'https://cloud.tenable.com' );
		$this->access_key = trim( $access_key );
		$this->secret_key = trim( $secret_key );
		$this->http       = $http;
		$this->log        = $log ?? static function ( string $message ): void {
			unset( $message );
		};
	}

	/**
	 * Absolute URL for an API path.
	 */
	private function url( string $path ): string {
		return $this->base_url . '/' . ltrim( $path, '/' );
	}

	/**
	 * Authentication headers.
	 *
	 * The key material only ever exists inside this array — it is never passed
	 * through a query string and never reaches the run log.
	 *
	 * @return array<string,string>
	 */
	private function headers(): array {
		return array(
			'X-ApiKeys'    => sprintf( 'accessKey=%s;secretKey=%s;', $this->access_key, $this->secret_key ),
			'Accept'       => 'application/json',
			'Content-Type' => 'application/json',
			'User-Agent'   => \VulnHub\Core\Http::default_user_agent(),
		);
	}

	/**
	 * Append a line to the run log.
	 */
	private function trace( string $message ): void {
		call_user_func( $this->log, $message );
	}

	/**
	 * Do we have both halves of the key pair?
	 */
	public function has_credentials(): bool {
		return '' !== $this->access_key && '' !== $this->secret_key;
	}

	/* -----------------------------------------------------------------
	 * Cheap authenticated calls
	 * --------------------------------------------------------------- */

	/**
	 * Identify the authenticated principal and its container (tenant).
	 *
	 * GET /session is the cheapest identity call and still returns
	 * `container_name`, which is what an operator wants to see. Tenable
	 * deprecated the *session token* endpoints in 2020 in favour of API keys,
	 * so if the read is rejected we fall back to GET /users, which is fully
	 * documented and only needs the Basic [16] role.
	 *
	 * @return array{ok:bool,message:string,detail:array<string,mixed>}
	 */
	public function whoami(): array {
		$response = $this->http->get( $this->url( '/session' ), array(), $this->headers(), array( 'retries' => 2 ) );

		if ( $response->ok() ) {
			$data = $response->data();

			return array(
				'ok'      => true,
				'message' => $this->describe_identity( $data ),
				'detail'  => array(
					'endpoint'       => 'GET /session',
					'username'       => (string) ( $data['username'] ?? '' ),
					'container_name' => (string) ( $data['container_name'] ?? '' ),
					'container_uuid' => (string) ( $data['container_uuid'] ?? '' ),
					'status'         => $response->status,
				),
			);
		}

		$fallback = $this->http->get( $this->url( '/users' ), array(), $this->headers(), array( 'retries' => 2 ) );

		if ( $fallback->ok() ) {
			$users = (array) ( $fallback->data()['users'] ?? array() );
			$first = is_array( $users[0] ?? null ) ? $users[0] : array();

			return array(
				'ok'      => true,
				'message' => sprintf(
					/* translators: 1: number of users, 2: container uuid. */
					__( 'Authenticated to Tenable. GET /users returned %1$d user account(s) in container %2$s.', 'vulnhub' ),
					count( $users ),
					(string) ( $first['container_uuid'] ?? __( 'unknown', 'vulnhub' ) )
				),
				'detail'  => array(
					'endpoint'       => 'GET /users',
					'user_count'     => count( $users ),
					'container_uuid' => (string) ( $first['container_uuid'] ?? '' ),
					'status'         => $fallback->status,
				),
			);
		}

		return array(
			'ok'      => false,
			'message' => sprintf(
				/* translators: 1: HTTP status, 2: error message. */
				__( 'Tenable rejected the credentials (HTTP %1$d): %2$s', 'vulnhub' ),
				$fallback->status ?: $response->status,
				vh_trim( $fallback->error_message(), 180 )
			),
			'detail'  => array(
				'session_status' => $response->status,
				'users_status'   => $fallback->status,
			),
		);
	}

	/**
	 * Human sentence describing a /session payload.
	 *
	 * @param array<string,mixed> $data Session payload.
	 */
	private function describe_identity( array $data ): string {
		$who       = (string) ( $data['username'] ?? $data['name'] ?? __( 'unknown user', 'vulnhub' ) );
		$container = (string) ( $data['container_name'] ?? $data['container_uuid'] ?? __( 'unknown container', 'vulnhub' ) );

		return sprintf(
			/* translators: 1: username, 2: Tenable container/tenant name. */
			__( 'Authenticated to Tenable as %1$s in container "%2$s".', 'vulnhub' ),
			$who,
			$container
		);
	}

	/**
	 * List tag values so an operator can see which tag categories exist.
	 *
	 * GET /tags/values returns `{ values: [ {uuid, category_name, value, ...} ], pagination: {...} }`.
	 *
	 * @param int $limit Maximum tag values to return (Tenable default 5000).
	 * @return array<int,array<string,mixed>>
	 */
	public function tag_values( int $limit = 500 ): array {
		$response = $this->http->get(
			$this->url( '/tags/values' ),
			array( 'limit' => max( 1, min( 5000, $limit ) ) ),
			$this->headers()
		);

		if ( ! $response->ok() ) {
			$this->trace( sprintf( 'Tag value lookup failed: %s', vh_trim( $response->error_message(), 160 ) ) );
			return array();
		}

		$values = $response->data()['values'] ?? array();

		return is_array( $values ) ? $values : array();
	}

	/* -----------------------------------------------------------------
	 * Export lifecycle
	 * --------------------------------------------------------------- */

	/**
	 * Queue an export job and return its uuid.
	 *
	 * @param string              $kind Self::KIND_ASSETS or Self::KIND_VULNS.
	 * @param array<string,mixed> $body Request body (chunk_size / num_assets / filters).
	 *
	 * @throws RuntimeException When Tenable refuses to queue the job.
	 */
	public function request_export( string $kind, array $body ): string {
		$response = $this->http->post( $this->url( '/' . $kind . '/export' ), $body, $this->headers() );

		if ( ! $response->ok() ) {
			throw new RuntimeException(
				sprintf(
					/* translators: 1: export kind, 2: HTTP status, 3: error message. */
					esc_html__( 'Could not queue the %1$s export (HTTP %2$d): %3$s', 'vulnhub' ),
					esc_html( $kind ),
					(int) $response->status,
					esc_html( vh_trim( $response->error_message(), 200 ) )
				)
			);
		}

		$uuid = (string) ( $response->data()['export_uuid'] ?? '' );

		if ( '' === $uuid ) {
			throw new RuntimeException(
				sprintf(
					/* translators: %s: export kind. */
					esc_html__( 'Tenable accepted the %s export but returned no export_uuid.', 'vulnhub' ),
					esc_html( $kind )
				)
			);
		}

		return $uuid;
	}

	/**
	 * Poll an export job's status.
	 *
	 * @param string $kind Export kind.
	 * @param string $uuid Export uuid.
	 * @return array<string,mixed> Decoded status payload.
	 */
	public function export_status( string $kind, string $uuid ): array {
		$response = $this->http->get(
			$this->url( sprintf( '/%s/export/%s/status', $kind, rawurlencode( $uuid ) ) ),
			array(),
			$this->headers()
		);

		if ( ! $response->ok() ) {
			$this->trace(
				sprintf(
					'Status poll for %s export %s failed (HTTP %d): %s',
					$kind,
					$uuid,
					$response->status,
					vh_trim( $response->error_message(), 160 )
				)
			);
			return array( 'status' => '' );
		}

		return $response->data();
	}

	/**
	 * Download one export chunk.
	 *
	 * The response is served as application/octet-stream but the payload is a
	 * JSON array of records.
	 *
	 * @param string $kind     Export kind.
	 * @param string $uuid     Export uuid.
	 * @param int    $chunk_id Chunk id from `chunks_available`.
	 * @return array<int,array<string,mixed>>
	 */
	public function download_chunk( string $kind, string $uuid, int $chunk_id ): array {
		$response = $this->http->get(
			$this->url( sprintf( '/%s/export/%s/chunks/%d', $kind, rawurlencode( $uuid ), $chunk_id ) ),
			array(),
			$this->headers(),
			array( 'timeout' => 120 )
		);

		if ( ! $response->ok() ) {
			$this->trace(
				sprintf(
					'Chunk %d of %s export %s failed (HTTP %d): %s',
					$chunk_id,
					$kind,
					$uuid,
					$response->status,
					vh_trim( $response->error_message(), 160 )
				)
			);
			return array();
		}

		$records = $response->data();

		// Defensive: a chunk is a JSON list; anything else is not usable.
		return array_values( array_filter( $records, 'is_array' ) );
	}

	/**
	 * Run a complete export: queue, poll, and stream each chunk to a callback.
	 *
	 * The polling loop is bounded twice over — by attempt count and by
	 * wall-clock time — so a stuck Tenable job can never hang a WP cron run.
	 *
	 * @param string                                        $kind     Export kind.
	 * @param array<string,mixed>                           $body     Request body.
	 * @param callable(array<int,array<string,mixed>>,int):void $on_chunk Chunk handler.
	 * @return array{uuid:string,status:string,chunks:int,records:int,seconds:float}
	 */
	public function run_export( string $kind, array $body, callable $on_chunk ): array {
		$started = microtime( true );
		$uuid    = $this->request_export( $kind, $body );

		$this->trace( sprintf( 'Queued %s export %s', $kind, $uuid ) );

		$seen     = array();
		$records  = 0;
		$attempts = 0;
		$wait     = self::POLL_FIRST_WAIT;
		$status   = 'QUEUED';

		while ( true ) {
			++$attempts;

			$state  = $this->export_status( $kind, $uuid );
			$status = strtoupper( (string) ( $state['status'] ?? '' ) );

			// Download every chunk that has appeared since the last poll.
			foreach ( (array) ( $state['chunks_available'] ?? array() ) as $chunk_id ) {
				$chunk_id = (int) $chunk_id;
				if ( isset( $seen[ $chunk_id ] ) ) {
					continue;
				}
				$seen[ $chunk_id ] = true;

				$chunk    = $this->download_chunk( $kind, $uuid, $chunk_id );
				$records += count( $chunk );

				$on_chunk( $chunk, $chunk_id );
			}

			if ( in_array( $status, self::TERMINAL_STATES, true ) ) {
				break;
			}

			$elapsed = microtime( true ) - $started;

			if ( $attempts >= self::POLL_MAX_ATTEMPTS || $elapsed >= self::POLL_TIMEOUT_SECONDS ) {
				$status = 'TIMEOUT';
				$this->trace(
					sprintf(
						'Gave up polling %s export %s after %d attempts / %.0fs (last state: %s)',
						$kind,
						$uuid,
						$attempts,
						$elapsed,
						(string) ( $state['status'] ?? 'unknown' )
					)
				);
				break;
			}

			usleep( (int) round( $wait * 1000000 ) );
			$wait = min( self::POLL_MAX_WAIT, $wait * 1.5 );
		}

		$seconds = round( microtime( true ) - $started, 2 );

		$this->trace(
			sprintf(
				'%s export %s finished as %s — %d chunk(s), %d record(s) in %.2fs',
				ucfirst( $kind ),
				$uuid,
				$status,
				count( $seen ),
				$records,
				$seconds
			)
		);

		if ( 'FINISHED' !== $status ) {
			$this->trace( sprintf( 'WARNING: %s export did not reach FINISHED; imported data may be partial.', $kind ) );
		}

		return array(
			'uuid'    => $uuid,
			'status'  => $status,
			'chunks'  => count( $seen ),
			'records' => $records,
			'seconds' => (float) $seconds,
		);
	}
}

