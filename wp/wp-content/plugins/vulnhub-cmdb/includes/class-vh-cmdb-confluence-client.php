<?php
/**
 * Confluence Cloud REST API v2 client.
 *
 * Verified against Atlassian's published OpenAPI description of the v2 API
 * (`The Confluence Cloud REST API v2`, server `https://{your-domain}/wiki/api/v2`):
 *
 *   GET /wiki/api/v2/pages/{id}?body-format=storage
 *       body-format is an enum of `storage` | `atlas_doc_format`; the body
 *       arrives at `body.storage.value` with `body.storage.representation`.
 *   GET /wiki/api/v2/pages?space-id=&title=&body-format=&limit=&cursor=
 *   GET /wiki/api/v2/spaces?keys=&limit=&cursor=
 *       Both list endpoints return `{ "results": [...], "_links": { "next": ... } }`
 *       where `_links.next` is a RELATIVE url already carrying the opaque
 *       `cursor` query parameter, and is simply absent on the last page. This
 *       client follows that link rather than constructing cursors itself,
 *       which is what Atlassian asks integrations to do.
 *
 * Search still lives on the v1 API:
 *
 *   GET /wiki/rest/api/search?cql=...&limit=25
 *       Also paginated through `_links.next`; the older `start` parameter is
 *       deprecated in favour of `cursor`.
 *
 * Authentication is HTTP Basic with an Atlassian account email as the user
 * name and an API token as the password (the v2 description declares a
 * `basicAuth` security scheme). The token is never logged.
 *
 * @package VulnHub\Cmdb
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Read-only Confluence client: enough to fetch page bodies in storage format.
 */
final class VulnHub_Cmdb_Confluence_Client {

	/** Hard ceiling on pages followed through `_links.next`. */
	private const MAX_PAGES = 25;

	/**
	 * Site base URL, without a trailing slash, e.g. https://acme.atlassian.net.
	 */
	private string $base_url;

	/**
	 * Atlassian account email.
	 */
	private string $email;

	/**
	 * API token.
	 */
	private string $token;

	/**
	 * Shared HTTP client.
	 */
	private \VulnHub\Core\Http $http;

	/**
	 * Run logger.
	 *
	 * @var callable
	 */
	private $log;

	/**
	 * @param string             $base_url Site URL.
	 * @param string             $email    Atlassian account email.
	 * @param string             $token    API token.
	 * @param \VulnHub\Core\Http $http     Shared HTTP client.
	 * @param callable|null      $log      Logger callback.
	 */
	public function __construct( string $base_url, string $email, string $token, \VulnHub\Core\Http $http, ?callable $log = null ) {
		$this->base_url = untrailingslashit( trim( $base_url ) );
		$this->email    = trim( $email );
		$this->token    = $token;
		$this->http     = $http;
		$this->log      = $log ?? static function ( string $message ): void {};
	}

	/**
	 * Do we have enough to talk to the site?
	 */
	public function has_credentials(): bool {
		return '' !== $this->base_url && '' !== $this->email && '' !== $this->token;
	}

	/**
	 * Basic auth header, built from email:api_token. Never logged.
	 *
	 * @return array<string,string>
	 */
	private function headers(): array {
		return array(
			'Authorization' => 'Basic ' . base64_encode( $this->email . ':' . $this->token ),
			'Accept'        => 'application/json',
		);
	}

	/**
	 * Fetch one page, body included, in storage format.
	 *
	 * @param string $page_id Numeric page id.
	 * @return array{ok:bool,message:string,page:array<string,mixed>}
	 */
	public function page( string $page_id ): array {
		$page_id = preg_replace( '/[^0-9]/', '', $page_id ) ?? '';

		if ( '' === $page_id ) {
			return array(
				'ok'      => false,
				'message' => __( 'A Confluence page id must be numeric.', 'vulnhub' ),
				'page'    => array(),
			);
		}

		$response = $this->http->get(
			$this->base_url . '/wiki/api/v2/pages/' . $page_id,
			array( 'body-format' => 'storage' ),
			$this->headers()
		);

		if ( ! $response->ok() ) {
			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: 1: page id, 2: HTTP status, 3: error text. */
					__( 'Confluence returned %2$d for page %1$s: %3$s', 'vulnhub' ),
					$page_id,
					$response->status,
					vh_trim( $response->error_message(), 160 )
				),
				'page'    => array(),
			);
		}

		return array(
			'ok'      => true,
			'message' => '',
			'page'    => (array) $response->data(),
		);
	}

	/**
	 * Storage-format body of a page payload.
	 *
	 * @param array<string,mixed> $page Page payload from `page()`.
	 */
	public static function storage_body( array $page ): string {
		$body = $page['body'] ?? array();

		if ( ! is_array( $body ) ) {
			return '';
		}

		$storage = $body['storage'] ?? array();

		return is_array( $storage ) ? (string) ( $storage['value'] ?? '' ) : '';
	}

	/**
	 * Every page in a space, with bodies, following `_links.next`.
	 *
	 * @param string $space_key Space key, e.g. "IT".
	 * @param int    $limit     Page size (Atlassian defaults to 25).
	 * @return array{ok:bool,message:string,pages:array<int,array<string,mixed>>}
	 */
	public function pages_in_space( string $space_key, int $limit = 25 ): array {
		$space = $this->space_by_key( $space_key );

		if ( ! $space['ok'] ) {
			return array(
				'ok'      => false,
				'message' => $space['message'],
				'pages'   => array(),
			);
		}

		return $this->collect(
			'/wiki/api/v2/spaces/' . rawurlencode( (string) $space['id'] ) . '/pages',
			array(
				'body-format' => 'storage',
				'limit'       => max( 1, min( 250, $limit ) ),
			)
		);
	}

	/**
	 * Resolve a space key to its numeric id.
	 *
	 * @return array{ok:bool,id:string,message:string}
	 */
	public function space_by_key( string $space_key ): array {
		$space_key = trim( $space_key );

		if ( '' === $space_key ) {
			return array(
				'ok'      => false,
				'id'      => '',
				'message' => __( 'No Confluence space key was configured.', 'vulnhub' ),
			);
		}

		$response = $this->http->get(
			$this->base_url . '/wiki/api/v2/spaces',
			array(
				'keys'  => $space_key,
				'limit' => 1,
			),
			$this->headers()
		);

		if ( ! $response->ok() ) {
			return array(
				'ok'      => false,
				'id'      => '',
				'message' => sprintf(
					/* translators: 1: HTTP status, 2: error text. */
					__( 'Confluence returned %1$d looking up the space: %2$s', 'vulnhub' ),
					$response->status,
					vh_trim( $response->error_message(), 160 )
				),
			);
		}

		$results = (array) ( $response->data()['results'] ?? array() );
		$first   = is_array( $results[0] ?? null ) ? $results[0] : array();
		$id      = (string) ( $first['id'] ?? '' );

		if ( '' === $id ) {
			return array(
				'ok'      => false,
				'id'      => '',
				'message' => sprintf(
					/* translators: %s: space key. */
					__( 'No Confluence space with the key %s is visible to this account.', 'vulnhub' ),
					$space_key
				),
			);
		}

		return array(
			'ok'      => true,
			'id'      => $id,
			'message' => '',
		);
	}

	/**
	 * Run a CQL search and fetch the storage body of every page it returns.
	 *
	 * Search is a v1 endpoint; its results carry a nested `content` object
	 * rather than a page object, so the ids are re-fetched through v2 to get
	 * bodies in a consistent shape.
	 *
	 * @param string $cql   CQL expression.
	 * @param int    $limit Maximum pages to resolve.
	 * @return array{ok:bool,message:string,pages:array<int,array<string,mixed>>}
	 */
	public function search( string $cql, int $limit = 25 ): array {
		$cql = trim( $cql );

		if ( '' === $cql ) {
			return array(
				'ok'      => false,
				'message' => __( 'No CQL expression was configured.', 'vulnhub' ),
				'pages'   => array(),
			);
		}

		$found = $this->collect(
			'/wiki/rest/api/search',
			array(
				'cql'   => $cql,
				'limit' => max( 1, min( 100, $limit ) ),
			)
		);

		if ( ! $found['ok'] ) {
			return $found;
		}

		$pages = array();

		foreach ( $found['pages'] as $result ) {
			$content = is_array( $result['content'] ?? null ) ? $result['content'] : array();
			$id      = (string) ( $content['id'] ?? '' );
			$type    = (string) ( $content['type'] ?? 'page' );

			if ( '' === $id || 'page' !== $type ) {
				continue;
			}
			if ( count( $pages ) >= $limit ) {
				break;
			}

			$page = $this->page( $id );

			if ( $page['ok'] ) {
				$pages[] = $page['page'];
			} else {
				call_user_func( $this->log, $page['message'] );
			}
		}

		return array(
			'ok'      => true,
			'message' => '',
			'pages'   => $pages,
		);
	}

	/**
	 * Follow a paginated endpoint to the end, accumulating `results`.
	 *
	 * `_links.next` is a relative URL that already carries the cursor, so it is
	 * appended to the site base rather than rebuilt.
	 *
	 * @param string                        $path  Path beneath the site root.
	 * @param array<string,string|int|bool> $query First-page query arguments.
	 * @return array{ok:bool,message:string,pages:array<int,array<string,mixed>>}
	 */
	private function collect( string $path, array $query ): array {
		$url     = $this->base_url . $path;
		$results = array();
		$page    = 0;

		while ( $page < self::MAX_PAGES ) {
			$response = 0 === $page
				? $this->http->get( $url, $query, $this->headers() )
				: $this->http->get( $url, array(), $this->headers() );
			++$page;

			if ( ! $response->ok() ) {
				return array(
					'ok'      => false,
					'message' => sprintf(
						/* translators: 1: HTTP status, 2: error text. */
						__( 'Confluence returned %1$d: %2$s', 'vulnhub' ),
						$response->status,
						vh_trim( $response->error_message(), 160 )
					),
					'pages'   => $results,
				);
			}

			$data  = $response->data();
			$batch = isset( $data['results'] ) && is_array( $data['results'] ) ? $data['results'] : array();

			foreach ( $batch as $item ) {
				if ( is_array( $item ) ) {
					$results[] = $item;
				}
			}

			$links = is_array( $data['_links'] ?? null ) ? $data['_links'] : array();
			$next  = (string) ( $links['next'] ?? '' );

			if ( '' === $next ) {
				break;
			}

			// Relative on both APIs, but tolerate an absolute link.
			$url = str_starts_with( $next, 'http' ) ? $next : $this->base_url . '/' . ltrim( $next, '/' );
		}

		return array(
			'ok'      => true,
			'message' => '',
			'pages'   => $results,
		);
	}

	/**
	 * Cheap authenticated call used by the connection test.
	 *
	 * @return array{ok:bool,message:string,detail:array<string,mixed>}
	 */
	public function ping(): array {
		$response = $this->http->get(
			$this->base_url . '/wiki/api/v2/spaces',
			array( 'limit' => 1 ),
			$this->headers()
		);

		if ( 401 === $response->status || 403 === $response->status ) {
			return array(
				'ok'      => false,
				'message' => __( 'Confluence rejected the credentials. Check the account email and that the API token has not been revoked.', 'vulnhub' ),
				'detail'  => array( 'status' => $response->status ),
			);
		}

		if ( ! $response->ok() ) {
			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: 1: HTTP status, 2: error text. */
					__( 'Confluence returned %1$d: %2$s', 'vulnhub' ),
					$response->status,
					vh_trim( $response->error_message(), 200 )
				),
				'detail'  => array( 'status' => $response->status ),
			);
		}

		return array(
			'ok'      => true,
			'message' => __( 'Connected to Confluence.', 'vulnhub' ),
			'detail'  => array( 'status' => $response->status ),
		);
	}
}

