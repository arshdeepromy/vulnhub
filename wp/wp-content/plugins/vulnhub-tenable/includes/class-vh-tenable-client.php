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

	/**
	 * Hard wall-clock ceiling for a single export job, in seconds.
	 *
	 * 480s (8 min) was too short for a live vulnerability export on any
	 * account with meaningful data — confirmed in production: a 644-asset
	 * account's vuln export was still PROCESSING at 8 minutes and got
	 * abandoned as TIMEOUT, silently importing zero findings. Assets
	 * exports are cheap (the same account finished in ~4s); vuln exports
	 * are the expensive one and need real headroom. A WP-Cron-driven
	 * scheduled sync has no PHP execution ceiling to worry about; an
	 * interactive "Sync now" gets its own set_time_limit() call in
	 * VulnHub_Tenable_Connector::do_sync() to match.
	 */
	 // Raised to 1h: the staged sync only DOWNLOADS in this phase (no per-row
	 // database work), so the ceiling now bounds a network transfer of a
	 // multi-gigabyte full export rather than a download-and-import, and a
	 // first full pull of a large account can legitimately stream for a while.
	private const POLL_TIMEOUT_SECONDS = 3600;

	/** Hard ceiling on status requests for a single export job. */
	private const POLL_MAX_ATTEMPTS = 1200;

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
	 * Scans and single assets (ticket verification)
	 * --------------------------------------------------------------- */

	/**
	 * GET /scans — the scans this key can see, reduced to what a picker and
	 * a launch need.
	 *
	 * @return array<int,array{id:int,name:string,type:string,status:string,can_launch:bool}>
	 */
	public function scans(): array {
		$response = $this->http->get( $this->url( '/scans' ), array(), $this->headers(), array( 'retries' => 2 ) );

		if ( ! $response->ok() ) {
			$this->trace( sprintf( 'Scan list failed (HTTP %d): %s', $response->status, vh_trim( $response->error_message(), 160 ) ) );
			return array();
		}

		$out = array();

		foreach ( (array) ( $response->data()['scans'] ?? array() ) as $scan ) {
			if ( ! is_array( $scan ) || empty( $scan['id'] ) ) {
				continue;
			}

			$out[] = array(
				'id'         => (int) $scan['id'],
				'name'       => (string) ( $scan['name'] ?? '' ),
				'type'       => (string) ( $scan['type'] ?? '' ),
				'status'     => (string) ( $scan['status'] ?? '' ),
				'can_launch' => ! empty( $scan['control'] ),
			);
		}

		return $out;
	}

	/**
	 * POST /scans/{scan_id}/launch with `alt_targets` — run an existing scan
	 * against these hosts only, instead of its configured targets.
	 *
	 * One attempt: a retried launch after a slow answer would queue the scan
	 * twice, and Tenable answers a second launch of a running scan with 409.
	 *
	 * @param string[] $targets IP addresses or host names.
	 */
	public function launch_scan( int $scan_id, array $targets ): \VulnHub\Core\Http_Response {
		return $this->http->request(
			'POST',
			$this->url( '/scans/' . $scan_id . '/launch' ),
			array(
				'headers' => $this->headers(),
				'body'    => array( 'alt_targets' => array_values( array_unique( array_filter( array_map( 'strval', $targets ) ) ) ) ),
				'retries' => 1,
			)
		);
	}

	/**
	 * GET /scans/{scan_id}/latest-status — pending, running, completed,
	 * canceled, aborted… or '' when it cannot be read.
	 */
	public function scan_latest_status( int $scan_id ): string {
		$response = $this->http->get( $this->url( '/scans/' . $scan_id . '/latest-status' ), array(), $this->headers(), array( 'retries' => 2 ) );

		return $response->ok() ? strtolower( (string) ( $response->data()['status'] ?? '' ) ) : '';
	}

	/**
	 * GET /assets/{asset_uuid} — one asset as Tenable holds it now, including
	 * when it was last seen and last scanned.
	 *
	 * @return array<string,mixed> Empty when the asset cannot be read.
	 */
	public function asset( string $uuid ): array {
		$response = $this->http->get( $this->url( '/assets/' . rawurlencode( $uuid ) ), array(), $this->headers(), array( 'retries' => 2 ) );

		return $response->ok() ? (array) ( $response->data()['info'] ?? $response->data() ) : array();
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

		/*
		 * Release the response before touching the records. Http_Response holds
		 * the raw JSON body *and* the decoded array at the same time, and a
		 * single vuln chunk here runs to 20k-40k nested records -- the raw body
		 * alone is worth hundreds of MB. Nothing below needs the response.
		 */
		unset( $response );

		/*
		 * Defensive: a chunk is a JSON list; anything else is not usable.
		 *
		 * This filters in place rather than via array_values( array_filter() ),
		 * which built two further complete copies of the chunk. Holding three
		 * copies of a 40k-record chunk at once is what actually exhausted the
		 * container: measured peaks climbed 859MB -> 2.1GB -> 2.6GB -> 3.3GB,
		 * one step per chunk, until the cgroup OOM-killed the process. The
		 * import path itself is flat (40k upsert_finding() calls measured at
		 * zero net growth), so the copies were the whole problem.
		 *
		 * Callers only foreach/count the result, so the non-sequential keys
		 * left behind by unset() are fine and not worth a reindex copy.
		 */
		foreach ( $records as $index => $record ) {
			if ( ! is_array( $record ) ) {
				unset( $records[ $index ] );
			}
		}

		return $records;
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
	public function run_export( string $kind, array $body, callable $on_chunk, ?callable $on_poll = null ): array {
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

			// A liveness beat every poll, before any chunk downloads. A large
			// export can sit in QUEUED/PROCESSING for minutes between chunks
			// while Tenable prepares the next batch; without a beat here the
			// stall-reaper mistakes that legitimate wait for a dead process
			// and kills a download that is working fine.
			if ( $on_poll ) {
				$on_poll();
			}

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

	/**
	 * Stream one chunk straight to a file, without ever holding it in memory.
	 *
	 * A chunk can be hundreds of megabytes; the normal path buffers the whole
	 * body and json_decode()s it, which builds a multi-gigabyte array and
	 * OOM-kills the worker. Here WordPress writes the response body directly to
	 * disk (the `stream`/`filename` request options), so peak memory is a
	 * socket buffer no matter how large the chunk is. Written to a temp file and
	 * renamed, so a half-written chunk from a failure is never seen as complete.
	 *
	 * @param string $kind     Export kind.
	 * @param string $uuid     Export uuid.
	 * @param int    $chunk_id 1-based chunk number.
	 * @param string $dest     Final destination path for the chunk.
	 * @return int Bytes written, or 0 on failure.
	 */
	public function download_chunk_to_file( string $kind, string $uuid, int $chunk_id, string $dest ): int {
		$url = $this->url( sprintf( '/%s/export/%s/chunks/%d', $kind, rawurlencode( $uuid ), $chunk_id ) );
		$tmp = $dest . '.part';

		$attempts = 0;

		while ( true ) {
			++$attempts;

			if ( file_exists( $tmp ) ) {
				wp_delete_file( $tmp );
			}

			$response = wp_remote_get( // phpcs:ignore WordPress.WP.AlternativeFunctions
				$url,
				array(
					'headers'  => $this->headers(),
					'timeout'  => 600,
					'stream'   => true,
					'filename' => $tmp,
				)
			);

			if ( is_wp_error( $response ) ) {
				if ( $attempts < 5 ) {
					usleep( (int) round( min( 30.0, 2.0 * $attempts ) * 1000000 ) );
					continue;
				}
				$this->trace( sprintf( 'Chunk %d of %s export %s stream failed: %s', $chunk_id, $kind, $uuid, $response->get_error_message() ) );
				if ( file_exists( $tmp ) ) {
					wp_delete_file( $tmp );
				}
				return 0;
			}

			$status = (int) wp_remote_retrieve_response_code( $response );

			if ( ( 429 === $status || in_array( $status, array( 500, 502, 503, 504 ), true ) ) && $attempts < 5 ) {
				$retry_after = (int) wp_remote_retrieve_header( $response, 'retry-after' );
				$wait        = $retry_after > 0 ? min( 60, $retry_after ) : min( 30.0, 2.0 * $attempts );
				usleep( (int) round( $wait * 1000000 ) );
				continue;
			}

			if ( $status < 200 || $status >= 300 ) {
				$this->trace( sprintf( 'Chunk %d of %s export %s failed (HTTP %d)', $chunk_id, $kind, $uuid, $status ) );
				if ( file_exists( $tmp ) ) {
					wp_delete_file( $tmp );
				}
				return 0;
			}

			break;
		}

		$bytes = (int) ( file_exists( $tmp ) ? filesize( $tmp ) : 0 );

		if ( ! rename( $tmp, $dest ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
			if ( file_exists( $tmp ) ) {
				wp_delete_file( $tmp );
			}
			return 0;
		}

		return $bytes;
	}

	/**
	 * Run a complete export, streaming each chunk to disk instead of decoding
	 * it in memory. Same queue/poll loop as run_export(), but chunks are written
	 * straight to files the caller names, so a quarter-million-row export never
	 * has to be held decoded. Completion is the same: the loop ends when Tenable
	 * reports a terminal status, having first pulled every chunk it listed.
	 *
	 * @param string                     $kind      Export kind.
	 * @param array<string,mixed>        $body      Request body.
	 * @param callable(int):string       $dest_for  Returns the destination path for a chunk id.
	 * @param callable(int,int):void     $on_saved  Called after each chunk saves (chunk id, bytes).
	 * @param callable():void|null       $on_poll   Liveness beat every poll.
	 * @return array{uuid:string,status:string,chunks:int,bytes:int,seconds:float}
	 */
	public function run_export_streamed( string $kind, array $body, callable $dest_for, callable $on_saved, ?callable $on_poll = null ): array {
		$started = microtime( true );
		$uuid    = $this->request_export( $kind, $body );

		$this->trace( sprintf( 'Queued %s export %s (streamed)', $kind, $uuid ) );

		$seen        = array();
		$bytes_total = 0;
		$attempts    = 0;
		$wait        = self::POLL_FIRST_WAIT;
		$status      = 'QUEUED';

		while ( true ) {
			++$attempts;

			$state  = $this->export_status( $kind, $uuid );
			$status = strtoupper( (string) ( $state['status'] ?? '' ) );

			if ( $on_poll ) {
				$on_poll();
			}

			foreach ( (array) ( $state['chunks_available'] ?? array() ) as $chunk_id ) {
				$chunk_id = (int) $chunk_id;
				if ( isset( $seen[ $chunk_id ] ) ) {
					continue;
				}
				$seen[ $chunk_id ] = true;

				$bytes        = $this->download_chunk_to_file( $kind, $uuid, $chunk_id, (string) $dest_for( $chunk_id ) );
				$bytes_total += $bytes;

				$on_saved( $chunk_id, $bytes );
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
				'%s export %s finished as %s — %d chunk(s), %d bytes streamed in %.2fs',
				ucfirst( $kind ),
				$uuid,
				$status,
				count( $seen ),
				$bytes_total,
				$seconds
			)
		);

		if ( 'FINISHED' !== $status ) {
			$this->trace( sprintf( 'WARNING: %s export did not reach FINISHED; downloaded data may be partial.', $kind ) );
		}

		return array(
			'uuid'    => $uuid,
			'status'  => $status,
			'chunks'  => count( $seen ),
			'bytes'   => $bytes_total,
			'seconds' => (float) $seconds,
		);
	}
}

