<?php
/**
 * Jira Cloud REST API v3 client.
 *
 * Everything here follows the vendor contract published on
 * developer.atlassian.com and the machine-readable OpenAPI description
 * (swagger-v3.v3.json), both verified in September 2026:
 *
 *  - Authentication is either OAuth 2.0 (3LO) -- `Authorization: Bearer`,
 *    sent to the Atlassian gateway `https://api.atlassian.com/ex/jira/<cloudId>`
 *    rather than the site host (see VulnHub_Jira_OAuth) -- or HTTP Basic with
 *    an Atlassian account email and an API
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

	/**
	 * The User-Agent sent to Atlassian. Deliberately generic: core's default
	 * names the product and its maintainer, and nothing sent to Jira should.
	 */
	public const USER_AGENT = 'Integration/1.0';

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

	/**
	 * Anything that adds something to Jira is attempted exactly once: creating
	 * an issue or a request, commenting, and uploading an attachment.
	 *
	 * Core's Http retries timeouts and 5xx responses, which is right for a
	 * read and wrong for an add: Jira can make the issue, post the comment or
	 * store the file and then fail to answer, and the retry makes a second
	 * one. A failed add is reported and left for a person to repeat. Edits
	 * (summary, status transition) and the idempotent remote link keep
	 * retrying, since repeating them changes nothing. The one retry kept for
	 * adds is the OAuth refresh after a 401 in call(): a 401 means Jira did
	 * nothing.
	 */
	public const CREATE_ATTEMPTS = 1;

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

	/** `basic` or `oauth`. */
	private string $auth_mode = 'basic';

	/** The Atlassian cloudId the OAuth grant resolved to. */
	private string $cloud_id = '';

	/**
	 * Supplies a Bearer token; called with true to force a refresh.
	 *
	 * @var callable(bool):string|null
	 */
	private $token_source = null;

	/**
	 * Project keys writes are allowed to touch. Empty means unrestricted.
	 *
	 * @var string[]
	 */
	private array $allowed_projects = array();

	/**
	 * Service desk id => project key, learned while checking the allowlist.
	 *
	 * @var array<string,string>
	 */
	private array $desk_projects = array();

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
	 * Switch to OAuth: Bearer tokens through the Atlassian gateway.
	 *
	 * @param string              $cloud_id Atlassian cloudId.
	 * @param callable(bool):string $token  Token source; true forces a refresh.
	 * @param string              $site     The site's own URL, for browse links
	 *                                      when no site URL is configured.
	 */
	public function use_oauth( string $cloud_id, callable $token, string $site = '' ): void {
		$this->auth_mode    = 'oauth';
		$this->cloud_id     = trim( $cloud_id );
		$this->token_source = $token;

		if ( '' === $this->base_url || str_contains( $this->base_url, 'yoursite.atlassian.net' ) ) {
			$this->base_url = self::normalise_base_url( $site );
		}
	}

	public function auth_mode(): string {
		return $this->auth_mode;
	}

	/**
	 * Refuse writes outside these projects.
	 *
	 * Enforced here, in the one method every request goes through, so no
	 * caller -- ticketer, reopener, automation, or anything added later -- can
	 * act on a project it was not meant to. OAuth scopes cannot express this:
	 * they are product-wide, so a token that can write one project can write
	 * all of them.
	 *
	 * @param string[] $keys Project keys.
	 */
	public function restrict_projects( array $keys ): void {
		$this->allowed_projects = array_values( array_unique( array_filter( array_map( static fn( $k ): string => strtoupper( trim( (string) $k ) ), $keys ) ) ) );
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
		if ( 'oauth' === $this->auth_mode ) {
			return '' !== $this->cloud_id && null !== $this->token_source;
		}

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
	private function headers( string $bearer = '' ): array {
		return array(
			'Authorization' => 'oauth' === $this->auth_mode
				? 'Bearer ' . $bearer
				: 'Basic ' . base64_encode( $this->email . ':' . $this->token ),
			'Accept'        => 'application/json',
			'Content-Type'  => 'application/json',
			'User-Agent'    => self::USER_AGENT,
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
	private function call( string $method, string $path, array $query = array(), ?array $body = null, array $extra = array(), ?string $raw = null, ?int $attempts = null ): \VulnHub\Core\Http_Response {
		$refused = $this->refuse_outside_allowlist( $method, $path, $body );

		if ( $refused ) {
			return $refused;
		}

		if ( $this->mock ) {
			$response = $this->mock->respond( $method, $path, $query, $body, $extra );

			$this->trace( sprintf( 'MOCK %s %s -> %d', strtoupper( $method ), $path, $response->status ) );

			return $response;
		}

		$bearer = '';

		if ( 'oauth' === $this->auth_mode ) {
			$bearer = null !== $this->token_source ? (string) call_user_func( $this->token_source, false ) : '';

			if ( '' === $bearer || '' === $this->cloud_id ) {
				return new \VulnHub\Core\Http_Response( 401, array(), '', null, 'Jira is not connected: connect it again from the Jira integration settings.' );
			}
		}

		// Under OAuth every call goes to the gateway, never the site host.
		// The path is the same either way.
		$root = 'oauth' === $this->auth_mode
			? 'https://api.atlassian.com/ex/jira/' . rawurlencode( $this->cloud_id )
			: $this->base_url;
		$url  = $root . $path;

		if ( $query ) {
			$url = add_query_arg( array_map( 'strval', $query ), $url );
		}

		$send = function ( string $token ) use ( $method, $url, $extra, $body, $raw, $attempts ): \VulnHub\Core\Http_Response {
			$args = array(
				'headers' => array_merge( $this->headers( $token ), $extra ),
				'body'    => null !== $raw ? $raw : $body,
				'timeout' => null !== $raw ? 120 : 45,
			);

			if ( null !== $attempts ) {
				$args['retries'] = max( 1, $attempts );
			}

			return $this->http->request( $method, $url, $args );
		};

		$response = $send( $bearer );

		// An access token can be revoked or expire early. Refresh once and
		// retry once; a second 401 is a real answer.
		if ( 401 === $response->status && 'oauth' === $this->auth_mode && null !== $this->token_source ) {
			$fresh = (string) call_user_func( $this->token_source, true );

			if ( '' !== $fresh && $fresh !== $bearer ) {
				$this->trace( sprintf( '%s %s -> HTTP 401; refreshed the OAuth token and retried', strtoupper( $method ), \VulnHub\Core\Http::scrub( $path ) ) );
				$response = $send( $fresh );
			}
		}

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
	 * GET /rest/api/3/issue/createmeta/{projectIdOrKey}/issuetypes — the issue
	 * types a project allows creating, with their ids.
	 */
	public function create_issue_types( string $project_key ): \VulnHub\Core\Http_Response {
		return $this->call(
			'GET',
			sprintf( '%s/issue/createmeta/%s/issuetypes', self::API, rawurlencode( $project_key ) ),
			array( 'maxResults' => 100 )
		);
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
		return $this->call( 'POST', self::API . '/issue', array(), array( 'fields' => $fields ), array(), null, self::CREATE_ATTEMPTS );
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
			array( 'body' => $adf ),
			array(),
			null,
			self::CREATE_ATTEMPTS
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
				'type' => 'remediation-tracking',
				'name' => 'Remediation tracking',
			),
			'relationship' => 'tracked in',
			'object'       => array(
				'url'     => $url,
				'title'   => $title,
				'summary' => vh_trim( $summary, 240 ),
				'icon'    => array(
					'url16x16' => admin_url( 'images/wordpress-logo.svg' ),
					'title'    => 'Remediation tracking',
				),
			),
		);

		return $this->call( 'POST', self::API . '/issue/' . rawurlencode( $key ) . '/remotelink', array(), $body );
	}

	/* =================================================================
	 * Project allowlist
	 * ============================================================== */

	/**
	 * A refusal response when a write would leave the allowed projects.
	 *
	 * Reads are never refused: listing desks and request types across the
	 * site is what the routing screen is for. Anything that creates, edits,
	 * comments, transitions or attaches is checked. A write whose project
	 * cannot be worked out is refused too -- failing closed is the point.
	 *
	 * @param array<string,mixed>|null $body Request body.
	 */
	private function refuse_outside_allowlist( string $method, string $path, ?array $body ): ?\VulnHub\Core\Http_Response {
		if ( ! $this->allowed_projects || 'GET' === strtoupper( $method ) ) {
			return null;
		}

		$project = $this->project_for_write( $path, $body );

		if ( null !== $project && in_array( $project, $this->allowed_projects, true ) ) {
			return null;
		}

		$message = sprintf(
			'Refusing to %s %s: project %s is outside the allowed set (%s).',
			strtoupper( $method ),
			$path,
			null === $project ? '(could not be determined)' : $project,
			implode( ', ', $this->allowed_projects )
		);

		$this->trace( $message );

		return new \VulnHub\Core\Http_Response( 403, array(), '', array( 'errorMessages' => array( $message ) ), $message );
	}

	/**
	 * The project key a write targets, or null when it cannot be determined.
	 *
	 * @param array<string,mixed>|null $body Request body.
	 */
	private function project_for_write( string $path, ?array $body ): ?string {
		// POST /rest/api/3/issue: the project is in the fields.
		if ( self::API . '/issue' === $path ) {
			$ref = (array) ( $body['fields']['project'] ?? array() );

			if ( ! empty( $ref['key'] ) ) {
				return strtoupper( (string) $ref['key'] );
			}

			return ! empty( $ref['id'] ) ? $this->project_key_for_id( (string) $ref['id'] ) : null;
		}

		// POST /rest/servicedeskapi/request: the desk decides the project.
		if ( self::SD_API . '/request' === $path ) {
			return $this->desk_project( (string) ( $body['serviceDeskId'] ?? '' ) );
		}

		if ( preg_match( '#^' . preg_quote( self::SD_API, '#' ) . '/servicedesk/([^/]+)/#', $path, $m ) ) {
			return $this->desk_project( rawurldecode( $m[1] ) );
		}

		// Anything on an existing issue or request: the key carries the project.
		if ( preg_match( '#^(?:' . preg_quote( self::API, '#' ) . '/issue|' . preg_quote( self::SD_API, '#' ) . '/request)/([^/]+)#', $path, $m ) ) {
			$ref = rawurldecode( $m[1] );

			if ( preg_match( '/^([A-Za-z][A-Za-z0-9_]*)-\d+$/', $ref, $k ) ) {
				return strtoupper( $k[1] );
			}

			// A numeric issue id: ask Jira which project it is in.
			$issue = $this->get_issue( $ref, array( 'project' ) );

			return $issue->ok() ? strtoupper( (string) ( $issue->data()['fields']['project']['key'] ?? '' ) ) ?: null : null;
		}

		return null;
	}

	private function desk_project( string $desk_id ): ?string {
		if ( '' === $desk_id ) {
			return null;
		}

		if ( ! isset( $this->desk_projects[ $desk_id ] ) ) {
			$desk = $this->call( 'GET', self::SD_API . '/servicedesk/' . rawurlencode( $desk_id ) );

			$this->desk_projects[ $desk_id ] = $desk->ok() ? strtoupper( (string) ( $desk->data()['projectKey'] ?? '' ) ) : '';
		}

		return '' !== $this->desk_projects[ $desk_id ] ? $this->desk_projects[ $desk_id ] : null;
	}

	private function project_key_for_id( string $id ): ?string {
		$project = $this->call( 'GET', self::API . '/project/' . rawurlencode( $id ) );

		return $project->ok() ? strtoupper( (string) ( $project->data()['key'] ?? '' ) ) ?: null : null;
	}

	/* =================================================================
	 * Comments, requests and attachments
	 * ============================================================== */

	/**
	 * GET /rest/api/3/issue/{issueIdOrKey}/comment — newest first.
	 */
	public function issue_comments( string $key, int $max = 50 ): \VulnHub\Core\Http_Response {
		return $this->call(
			'GET',
			self::API . '/issue/' . rawurlencode( $key ) . '/comment',
			array(
				'maxResults' => max( 1, min( 100, $max ) ),
				'orderBy'    => '-created',
			)
		);
	}

	/**
	 * GET /rest/servicedeskapi/request/{issueIdOrKey} — the customer-facing
	 * view of a request: its request type, current status and SLA.
	 */
	public function get_request( string $key ): \VulnHub\Core\Http_Response {
		return $this->call( 'GET', self::SD_API . '/request/' . rawurlencode( $key ), array( 'expand' => 'status,requestType' ) );
	}

	/**
	 * POST /rest/servicedeskapi/request — raise a JSM customer request.
	 *
	 * Unlike POST /rest/api/3/issue this keeps the portal, the request type
	 * and its SLAs. `requestFieldValues` takes field ids as keys; summary and
	 * description are plain text.
	 *
	 * @param array<string,mixed> $fields Request field values.
	 */
	public function create_request( string $desk_id, string $request_type_id, array $fields ): \VulnHub\Core\Http_Response {
		return $this->call(
			'POST',
			self::SD_API . '/request',
			array(),
			array(
				'serviceDeskId'      => $desk_id,
				'requestTypeId'      => $request_type_id,
				'requestFieldValues' => $fields,
			),
			array(),
			null,
			self::CREATE_ATTEMPTS
		);
	}

	/**
	 * POST /rest/servicedeskapi/request/{issueIdOrKey}/comment.
	 *
	 * @param bool $public True for a reply the customer sees; false for an
	 *                     internal note.
	 */
	public function request_comment( string $key, string $body, bool $public = true ): \VulnHub\Core\Http_Response {
		return $this->call(
			'POST',
			self::SD_API . '/request/' . rawurlencode( $key ) . '/comment',
			array(),
			array(
				'body'   => $body,
				'public' => $public,
			),
			array(),
			null,
			self::CREATE_ATTEMPTS
		);
	}

	/**
	 * POST /rest/api/3/issue/{issueIdOrKey}/attachments — multipart, field `file`.
	 */
	public function attach( string $key, string $filename, string $bytes, string $mime = 'application/octet-stream' ): \VulnHub\Core\Http_Response {
		return $this->upload( self::API . '/issue/' . rawurlencode( $key ) . '/attachments', $filename, $bytes, $mime );
	}

	/**
	 * Attach a file to a JSM request: upload it to the desk as a temporary
	 * file, then attach that to the request. Two calls, because that is the
	 * only way the JSM request API accepts files.
	 *
	 * @param bool $public Whether the customer can see the attachment.
	 */
	public function request_attach( string $desk_id, string $key, string $filename, string $bytes, string $mime = 'application/octet-stream', bool $public = true, string $comment = '' ): \VulnHub\Core\Http_Response {
		$temp = $this->upload( self::SD_API . '/servicedesk/' . rawurlencode( $desk_id ) . '/attachTemporaryFile', $filename, $bytes, $mime );

		if ( ! $temp->ok() ) {
			return $temp;
		}

		$ids = array_values(
			array_filter(
				array_map(
					static fn( $t ): string => is_array( $t ) ? (string) ( $t['temporaryAttachmentId'] ?? '' ) : '',
					(array) ( $temp->data()['temporaryAttachments'] ?? array() )
				)
			)
		);

		if ( ! $ids ) {
			return new \VulnHub\Core\Http_Response( 502, array(), '', null, 'JSM accepted the upload but returned no temporary attachment id.' );
		}

		$body = array(
			'temporaryAttachmentIds' => $ids,
			'public'                 => $public,
		);

		if ( '' !== trim( $comment ) ) {
			$body['additionalComment'] = array( 'body' => $comment );
		}

		return $this->call( 'POST', self::SD_API . '/request/' . rawurlencode( $key ) . '/attachment', array(), $body, array(), null, self::CREATE_ATTEMPTS );
	}

	/**
	 * One multipart/form-data POST with a single `file` part.
	 *
	 * Core's Http JSON-encodes array bodies, so the body is assembled here
	 * and passed as a string, which Http sends untouched. Jira requires
	 * `X-Atlassian-Token: no-check` on uploads; headers() always sends it.
	 */
	private function upload( string $path, string $filename, string $bytes, string $mime ): \VulnHub\Core\Http_Response {
		$filename = sanitize_file_name( $filename ) ?: 'attachment.bin';
		$mime     = preg_match( '#^[\w.+-]+/[\w.+-]+$#', $mime ) ? $mime : 'application/octet-stream';

		if ( $this->mock ) {
			$refused = $this->refuse_outside_allowlist( 'POST', $path, null );

			return $refused ?? $this->mock->respond(
				'POST',
				$path,
				array(),
				array(
					'filename' => $filename,
					'mimeType' => $mime,
					'size'     => strlen( $bytes ),
				)
			);
		}

		$boundary = 'boundary-' . bin2hex( random_bytes( 12 ) );
		$body     = '--' . $boundary . "\r\n"
			. 'Content-Disposition: form-data; name="file"; filename="' . str_replace( '"', '', $filename ) . "\"\r\n"
			. 'Content-Type: ' . $mime . "\r\n\r\n"
			. $bytes . "\r\n"
			. '--' . $boundary . "--\r\n";

		return $this->call(
			'POST',
			$path,
			array(),
			null,
			array( 'Content-Type' => 'multipart/form-data; boundary=' . $boundary ),
			$body,
			self::CREATE_ATTEMPTS
		);
	}
}

