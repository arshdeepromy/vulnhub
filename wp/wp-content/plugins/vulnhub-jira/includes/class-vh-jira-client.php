<?php
/**
 * Jira Cloud REST API v3 client.
 *
 * Everything here follows the vendor contract published on
 * developer.atlassian.com and the machine-readable OpenAPI description
 * (swagger-v3.v3.json), both verified in September 2026:
 *
 *  - Authentication is HTTP Basic with an Atlassian account email and an API
 *    token: `Authorization: Basic base64(email:api_token)`
 *    (developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis).
 *    The vendor's own example uses `echo -n … | base64` — the `-n` matters,
 *    a trailing newline corrupts the credential. PHP's base64_encode() adds
 *    no newline and no line wrapping, so it is used directly; chunk_split()
 *    would break the header and is deliberately not used.
 *
 *  - JQL search goes to `POST /rest/api/3/search/jql`. The old
 *    `GET|POST /rest/api/3/search` is flagged `deprecated: true` in the
 *    OpenAPI description with the summary "Currently being removed"
 *    (changelog CHANGE-2046) and is not used here. The replacement pages with
 *    an opaque `nextPageToken` cursor instead of `startAt`, returns `isLast`,
 *    no longer returns `total`, caps `maxResults` at 5000, and requires a
 *    *bounded* query — `key in (…)` qualifies.
 *
 *  - Rich text fields are Atlassian Document Format, never plain text. See
 *    VulnHub_Jira_Adf.
 *
 *  - Field discovery uses
 *    `GET /rest/api/3/issue/createmeta/{projectIdOrKey}/issuetypes/{issueTypeId}`,
 *    which is current; the parent `GET /rest/api/3/issue/createmeta` is
 *    deprecated (CHANGE-1304).
 *
 *  - Priorities come from `GET /rest/api/3/priority/search`; plain
 *    `GET /rest/api/3/priority` is deprecated.
 *
 *  - 429 responses carry `Retry-After` in seconds. Core's Http client already
 *    honours Retry-After above its own exponential backoff and adds jitter,
 *    exactly as Atlassian's rate-limiting guidance asks, so this class does no
 *    throttling of its own.
 *
 * In mock mode the same call sites run, but the request is answered by
 * VulnHub_Jira_Mock instead of the network — so normalisation is shared.
 *
 * @package VulnHub\Jira
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Stateless wrapper around the Jira Cloud REST endpoints VulnHub needs.
 */
final class VulnHub_Jira_Client {

	/** API root shared by every call. */
	public const API = '/rest/api/3';

	/**
	 * Jira Service Management API root.
	 *
	 * JSM is a separate REST surface on the same host with its own paging
	 * envelope (`values` / `size` / `start` / `limit` / `isLastPage`). On a site
	 * without Jira Service Management every path under it answers 404, which is
	 * information, not a failure.
	 */
	public const SD_API = '/rest/servicedeskapi';

	/** Jira caps enhanced search at 5000 issues per page. */
	public const MAX_PAGE = 5000;

	/**
	 * Site base URL, e.g. https://yoursite.atlassian.net — no trailing slash.
	 */
	private string $base_url;

	/**
	 * Atlassian account email. Half of the Basic credential.
	 */
	private string $email;

	/**
	 * API token. Never logged, never echoed back into a form.
	 */
	private string $token;

	/**
	 * Shared HTTP client (retries, Retry-After handling, jitter).
	 */
	private \VulnHub\Core\Http $http;

	/**
	 * Simulated site, or null when running live.
	 */
	private ?VulnHub_Jira_Mock $mock;

	/**
	 * Run-log sink.
	 *
	 * @var callable(string):void
	 */
	private $log;

	/**
	 * @param string                $base_url Site URL.
	 * @param string                $email    Account email.
	 * @param string                $token    API token.
	 * @param \VulnHub\Core\Http    $http     Shared HTTP client.
	 * @param VulnHub_Jira_Mock|null $mock    Simulated site when in mock mode.
	 * @param callable(string):void|null $log Run-log callback.
	 */
	public function __construct(
		string $base_url,
		string $email,
		string $token,
		\VulnHub\Core\Http $http,
		?VulnHub_Jira_Mock $mock = null,
		?callable $log = null
	) {
		$this->base_url = self::normalise_base_url( $base_url );
		$this->email    = trim( $email );
		$this->token    = trim( $token );
		$this->http     = $http;
		$this->mock     = $mock;
		$this->log      = $log ?? static function ( string $message ): void {
			unset( $message );
		};
	}

	/**
	 * Accept `yoursite.atlassian.net`, `https://yoursite.atlassian.net/` and
	 * anything in between, and return a clean origin.
	 */
	public static function normalise_base_url( string $url ): string {
		$url = trim( $url );

		if ( '' === $url ) {
			return '';
		}
		if ( ! preg_match( '#^https?://#i', $url ) ) {
			$url = 'https://' . ltrim( $url, '/' );
		}

		$parts  = (array) wp_parse_url( $url );
		$scheme = 'http' === ( $parts['scheme'] ?? 'https' ) ? 'http' : 'https';
		$host   = (string) ( $parts['host'] ?? '' );

		if ( '' === $host ) {
			return '';
		}

		return $scheme . '://' . $host . ( isset( $parts['port'] ) ? ':' . (int) $parts['port'] : '' );
	}

	/**
	 * Site URL as configured.
	 */
	public function site_url(): string {
		return $this->mock ? $this->mock->site_url() : $this->base_url;
	}

	/**
	 * The browse URL a human clicks to open an issue.
	 */
	public function browse_url( string $key ): string {
		return $this->site_url() . '/browse/' . rawurlencode( $key );
	}

	/**
	 * Do we have everything needed to authenticate?
	 */
	public function has_credentials(): bool {
		return '' !== $this->base_url && '' !== $this->email && '' !== $this->token;
	}

	/**
	 * Append a line to the run log.
	 */
	private function trace( string $message ): void {
		call_user_func( $this->log, $message );
	}

	/**
	 * Basic auth + JSON headers.
	 *
	 * The credential exists only inside this array. base64_encode() emits a
	 * single unwrapped line with no trailing newline, which is what Atlassian
	 * requires; never pass it through chunk_split().
	 *
	 * @return array<string,string>
	 */
	private function headers(): array {
		return array(
			'Authorization' => 'Basic ' . base64_encode( $this->email . ':' . $this->token ),
			'Accept'        => 'application/json',
			'Content-Type'  => 'application/json',
			'User-Agent'    => \VulnHub\Core\Http::default_user_agent(),
			// Atlassian asks integrations not to be treated as a browser.
			'X-Atlassian-Token' => 'no-check',
		);
	}

	/**
	 * Issue one request — over the wire, or against the simulated site.
	 *
	 * @param string                   $method HTTP verb.
	 * @param string                   $path   API path beginning with /rest/api/3.
	 * @param array<string,mixed>      $query  Query arguments.
	 * @param array<string,mixed>|null $body   JSON body.
	 * @param array<string,string>     $extra  Additional request headers, e.g.
	 *                                         `X-ExperimentalApi: opt-in`.
	 */
	private function call( string $method, string $path, array $query = array(), ?array $body = null, array $extra = array() ): \VulnHub\Core\Http_Response {
		if ( $this->mock ) {
			$response = $this->mock->respond( $method, $path, $query, $body, $extra );

			$this->trace( sprintf( 'MOCK %s %s -> %d', strtoupper( $method ), $path, $response->status ) );

			return $response;
		}

		$url = $this->base_url . $path;

		if ( $query ) {
			$url = add_query_arg( array_map( 'strval', $query ), $url );
		}

		$response = $this->http->request(
			$method,
			$url,
			array(
				'headers' => array_merge( $this->headers(), $extra ),
				'body'    => $body,
				'timeout' => 45,
			)
		);

		if ( ! $response->ok() ) {
			$this->trace(
				sprintf(
					'%s %s -> HTTP %d: %s',
					strtoupper( $method ),
					\VulnHub\Core\Http::scrub( $path ),
					$response->status,
					vh_trim( $response->error_message(), 180 )
				)
			);
		}

		return $response;
	}

	/* =================================================================
	 * Identity and reference data
	 * ============================================================== */

	/**
	 * GET /rest/api/3/myself — the cheapest authenticated call there is.
	 */
	public function myself(): \VulnHub\Core\Http_Response {
		return $this->call( 'GET', self::API . '/myself' );
	}

	/**
	 * GET /rest/api/3/project/{projectIdOrKey}.
	 */
	public function project( string $key ): \VulnHub\Core\Http_Response {
		return $this->call( 'GET', self::API . '/project/' . rawurlencode( $key ) );
	}

	/**
	 * GET /rest/api/3/project/search — paginated, `values` holds the projects.
	 */
	public function projects( string $search = '', int $limit = 50 ): \VulnHub\Core\Http_Response {
		$query = array( 'maxResults' => max( 1, min( 100, $limit ) ) );

		if ( '' !== $search ) {
			$query['query'] = $search;
		}

		return $this->call( 'GET', self::API . '/project/search', $query );
	}

	/**
	 * GET /rest/api/3/issuetype.
	 */
	public function issue_types(): \VulnHub\Core\Http_Response {
		return $this->call( 'GET', self::API . '/issuetype' );
	}

	/**
	 * GET /rest/api/3/field.
	 */
	public function fields(): \VulnHub\Core\Http_Response {
		return $this->call( 'GET', self::API . '/field' );
	}

	/**
	 * GET /rest/api/3/priority/search (the non-deprecated priority listing).
	 */
	public function priorities(): \VulnHub\Core\Http_Response {
		return $this->call( 'GET', self::API . '/priority/search', array( 'maxResults' => 100 ) );
	}

	/**
	 * GET /rest/api/3/issue/createmeta/{projectIdOrKey}/issuetypes/{issueTypeId}
	 *
	 * Field discovery for one project + issue type. Used to warn an operator
	 * when a project demands a required field VulnHub does not populate.
	 */
	public function create_field_meta( string $project_key, string $issue_type_id ): \VulnHub\Core\Http_Response {
		return $this->call(
			'GET',
			sprintf(
				'%s/issue/createmeta/%s/issuetypes/%s',
				self::API,
				rawurlencode( $project_key ),
				rawurlencode( $issue_type_id )
			),
			array( 'maxResults' => 100 )
		);
	}

	/**
	 * GET /rest/api/3/user/search — resolve an email address to an account id.
	 *
	 * Jira has not accepted usernames since the GDPR API changes; assignment
	 * requires `accountId`.
	 */
	public function user_search( string $query ): \VulnHub\Core\Http_Response {
		return $this->call( 'GET', self::API . '/user/search', array( 'query' => $query, 'maxResults' => 5 ) );
	}

	/* =================================================================
	 * Routing directory — service desks, request types, fields, people
	 * ============================================================== */

	/**
	 * GET /rest/servicedeskapi/servicedesk — every service desk this account
	 * can see.
	 *
	 * Documented as "returns all the service desks in the Jira Service
	 * Management instance that the user has permission to access", paged with
	 * `start` and `limit`. The operation is not flagged experimental in the JSM
	 * OpenAPI description, so it deliberately sends no `X-ExperimentalApi`
	 * header. Plain Jira answers 404 — the caller reads that as "no JSM here".
	 *
	 * @param int $start Zero-based index of the first item.
	 * @param int $limit Page size (Atlassian defaults to 50).
	 */
	public function service_desks( int $start = 0, int $limit = 50 ): \VulnHub\Core\Http_Response {
		return $this->call(
			'GET',
			self::SD_API . '/servicedesk',
			array(
				'start' => max( 0, $start ),
				'limit' => max( 1, min( 100, $limit ) ),
			)
		);
	}

	/**
	 * GET /rest/servicedeskapi/servicedesk/{serviceDeskId}/requesttype.
	 *
	 * Each `RequestTypeDTO` carries `issueTypeId` — "ID of the issue type the
	 * request type is based upon" — which is how a JSM request type is turned
	 * into something the platform issue API understands. Also not experimental.
	 *
	 * @param string $desk_id Service desk id (a project key is also accepted).
	 * @param int    $start   Zero-based index of the first item.
	 * @param int    $limit   Page size.
	 */
	public function request_types( string $desk_id, int $start = 0, int $limit = 50 ): \VulnHub\Core\Http_Response {
		return $this->call(
			'GET',
			self::SD_API . '/servicedesk/' . rawurlencode( $desk_id ) . '/requesttype',
			array(
				'start' => max( 0, $start ),
				'limit' => max( 1, min( 100, $limit ) ),
			)
		);
	}

	/**
	 * GET /rest/servicedeskapi/requesttype — every request type on the site.
	 *
	 * This one IS flagged `x-experimental: true`, so it must carry
	 * `X-ExperimentalApi: opt-in`; without the header Jira answers 412. Used
	 * only to collapse a fan-out on instances with many desks.
	 *
	 * @param int $start Zero-based index of the first item.
	 * @param int $limit Page size.
	 */
	public function all_request_types( int $start = 0, int $limit = 50 ): \VulnHub\Core\Http_Response {
		return $this->call(
			'GET',
			self::SD_API . '/requesttype',
			array(
				'start' => max( 0, $start ),
				'limit' => max( 1, min( 200, $limit ) ),
			),
			null,
			array( 'X-ExperimentalApi' => 'opt-in' )
		);
	}

	/**
	 * GET /rest/api/3/groups/picker — group names matching a query.
	 *
	 * Jira Cloud has no team listing, so groups are one of the few real
	 * directories the platform API does expose.
	 *
	 * @param string $query Substring to match, or '' for the first page of all.
	 * @param int    $limit Maximum groups returned.
	 */
	public function groups( string $query = '', int $limit = 50 ): \VulnHub\Core\Http_Response {
		$args = array( 'maxResults' => max( 1, min( 200, $limit ) ) );

		if ( '' !== trim( $query ) ) {
			$args['query'] = trim( $query );
		}

		return $this->call( 'GET', self::API . '/groups/picker', $args );
	}

	/**
	 * GET /rest/api/3/project/{projectIdOrKey}/role — role name => role URL.
	 *
	 * Project roles are shared across every project in Jira Cloud, so one call
	 * describes the whole site.
	 *
	 * @param string $key Project key or id.
	 */
	public function project_roles( string $key ): \VulnHub\Core\Http_Response {
		return $this->call( 'GET', self::API . '/project/' . rawurlencode( $key ) . '/role' );
	}

	/**
	 * GET /rest/api/3/user/assignable/search — users assignable in a project.
	 *
	 * @param string $project_key Project key.
	 * @param string $query       Optional name or email fragment.
	 * @param int    $limit       Maximum users returned.
	 */
	public function assignable_users( string $project_key, string $query = '', int $limit = 50 ): \VulnHub\Core\Http_Response {
		$args = array(
			'project'    => strtoupper( trim( $project_key ) ),
			'maxResults' => max( 1, min( 200, $limit ) ),
		);

		if ( '' !== trim( $query ) ) {
			$args['query'] = trim( $query );
		}

		return $this->call( 'GET', self::API . '/user/assignable/search', $args );
	}

	/**
	 * GET /rest/api/3/field/{fieldId}/context — contexts of a custom field.
	 *
	 * @param string $field_id Custom field id, e.g. customfield_10001.
	 */
	public function field_contexts( string $field_id ): \VulnHub\Core\Http_Response {
		return $this->call(
			'GET',
			self::API . '/field/' . rawurlencode( $field_id ) . '/context',
			array( 'maxResults' => 50 )
		);
	}

	/**
	 * GET /rest/api/3/field/{fieldId}/context/{contextId}/option.
	 *
	 * The only public way to enumerate the selectable values of an
	 * option-backed custom field.
	 *
	 * @param string $field_id   Custom field id.
	 * @param string $context_id Context id.
	 */
	public function field_context_options( string $field_id, string $context_id ): \VulnHub\Core\Http_Response {
		return $this->call(
			'GET',
			self::API . '/field/' . rawurlencode( $field_id ) . '/context/' . rawurlencode( $context_id ) . '/option',
			array(
				'maxResults'  => 100,
				'onlyOptions' => 'false',
			)
		);
	}

	/* =================================================================
	 * Issues
	 * ============================================================== */

	/**
	 * POST /rest/api/3/issue.
	 *
	 * @param array<string,mixed> $fields The `fields` object (project, summary,
	 *                                    description as ADF, issuetype, …).
	 */
	public function create_issue( array $fields ): \VulnHub\Core\Http_Response {
		return $this->call( 'POST', self::API . '/issue', array(), array( 'fields' => $fields ) );
	}

	/**
	 * GET /rest/api/3/issue/{issueIdOrKey}.
	 *
	 * @param string[] $fields Field ids to return.
	 */
	public function get_issue( string $key, array $fields = array() ): \VulnHub\Core\Http_Response {
		$query = array();

		if ( $fields ) {
			$query['fields'] = implode( ',', $fields );
		}

		return $this->call( 'GET', self::API . '/issue/' . rawurlencode( $key ), $query );
	}

	/**
	 * POST /rest/api/3/search/jql — enhanced (cursor-paged) JQL search.
	 *
	 * @param string   $jql    A bounded JQL expression.
	 * @param string[] $fields Field ids to return.
	 * @param int      $max    Page size, capped at 5000 by the platform.
	 * @param string   $token  `nextPageToken` from the previous page, or ''.
	 */
	public function search_jql( string $jql, array $fields, int $max = 100, string $token = '' ): \VulnHub\Core\Http_Response {
		$body = array(
			'jql'        => $jql,
			'maxResults' => max( 1, min( self::MAX_PAGE, $max ) ),
		);

		if ( $fields ) {
			$body['fields'] = array_values( $fields );
		}
		if ( '' !== $token ) {
			$body['nextPageToken'] = $token;
		}

		return $this->call( 'POST', self::API . '/search/jql', array(), $body );
	}

	/**
	 * GET /rest/api/3/issue/{issueIdOrKey}/transitions.
	 */
	public function transitions( string $key ): \VulnHub\Core\Http_Response {
		return $this->call( 'GET', self::API . '/issue/' . rawurlencode( $key ) . '/transitions' );
	}

	/**
	 * POST /rest/api/3/issue/{issueIdOrKey}/transitions.
	 *
	 * @param string                   $key           Issue key.
	 * @param string                   $transition_id Transition id from transitions().
	 * @param array<string,mixed>|null $comment_adf   Optional ADF comment posted with the move.
	 */
	public function transition( string $key, string $transition_id, ?array $comment_adf = null ): \VulnHub\Core\Http_Response {
		$body = array( 'transition' => array( 'id' => $transition_id ) );

		if ( $comment_adf ) {
			$body['update'] = array(
				'comment' => array(
					array( 'add' => array( 'body' => $comment_adf ) ),
				),
			);
		}

		return $this->call( 'POST', self::API . '/issue/' . rawurlencode( $key ) . '/transitions', array(), $body );
	}

	/**
	 * POST /rest/api/3/issue/{issueIdOrKey}/comment.
	 *
	 * @param array<string,mixed> $adf Comment body as an ADF document.
	 */
	public function comment( string $key, array $adf ): \VulnHub\Core\Http_Response {
		return $this->call(
			'POST',
			self::API . '/issue/' . rawurlencode( $key ) . '/comment',
			array(),
			array( 'body' => $adf )
		);
	}

	/**
	 * PUT /rest/api/3/issue/{issueIdOrKey} — field edit (used to set priority).
	 *
	 * @param array<string,mixed> $fields Fields to set.
	 */
	public function update_issue( string $key, array $fields ): \VulnHub\Core\Http_Response {
		return $this->call(
			'PUT',
			self::API . '/issue/' . rawurlencode( $key ),
			array(),
			array( 'fields' => $fields )
		);
	}

	/**
	 * POST /rest/api/3/issue/{issueIdOrKey}/remotelink.
	 *
	 * `globalId` makes the call idempotent: repeating it updates the existing
	 * link rather than adding a duplicate.
	 *
	 * @param string $key      Issue key.
	 * @param string $url      Target URL in VulnHub.
	 * @param string $title    Link title.
	 * @param string $summary  Link summary.
	 * @param string $global_id Stable identity for the link.
	 */
	public function remote_link( string $key, string $url, string $title, string $summary, string $global_id ): \VulnHub\Core\Http_Response {
		$body = array(
			'globalId'     => $global_id,
			'application'  => array(
				'type' => 'com.vulnhub.app',
				'name' => 'VulnHub',
			),
			'relationship' => 'tracked in VulnHub',
			'object'       => array(
				'url'     => $url,
				'title'   => $title,
				'summary' => vh_trim( $summary, 240 ),
				'icon'    => array(
					'url16x16' => admin_url( 'images/wordpress-logo.svg' ),
					'title'    => 'VulnHub',
				),
			),
		);

		return $this->call( 'POST', self::API . '/issue/' . rawurlencode( $key ) . '/remotelink', array(), $body );
	}
}

