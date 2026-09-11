<?php
/**
 * A simulated Jira Cloud site.
 *
 * This is deliberately NOT a set of canned return values for the connector's
 * methods. It is a fake *transport*: `respond()` takes the same method, path,
 * query and body the live client would have put on the wire and hands back a
 * `\VulnHub\Core\Http_Response` carrying a payload shaped exactly like Jira
 * Cloud REST API v3 emits. Everything above the transport — normalisation,
 * status-category mapping, persistence through `Tickets::upsert()`, the ADF
 * description, remote issue links — therefore runs identically in mock mode
 * and live mode, which is the only way mock mode proves anything.
 *
 * The simulated site keeps real state in the connector's settings blob:
 * issue keys are allocated per project (`SEC-1001`, `SEC-1002`, …), issues
 * progress To Do → In Progress → Done over time on a deterministic per-issue
 * pace, assignees are drawn from `\VulnHub\Core\Mock::people()` so they are the
 * same humans every other connector sees, and comments, remote links and
 * workflow transitions are all recorded.
 *
 * @package VulnHub\Jira
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * In-memory (option-backed) Jira Cloud simulator.
 */
final class VulnHub_Jira_Mock {

	/** Connector id whose settings blob stores the simulated site. */
	private const NS = 'jira';

	/** Settings key holding the simulated site state. */
	private const STATE_KEY = 'mock_state';

	/** Newest issues retained; keeps the option a sane size. */
	private const MAX_ISSUES = 400;

	/** First issue number allocated in every project. */
	private const FIRST_NUMBER = 1001;

	/**
	 * The workflow every simulated project uses.
	 *
	 * Jira's status *category* is the machine-readable half — `new`,
	 * `indeterminate` and `done` (plus `undefined`) are the only four keys the
	 * platform defines, so those are what the connector keys its logic off.
	 *
	 * @var array<string,array{name:string,category:string,category_name:string,colour:string,id:string}>
	 */
	private const WORKFLOW = array(
		'todo'        => array(
			'name'          => 'To Do',
			'category'      => 'new',
			'category_name' => 'To Do',
			'colour'        => 'blue-gray',
			'id'            => '10000',
		),
		'in_progress' => array(
			'name'          => 'In Progress',
			'category'      => 'indeterminate',
			'category_name' => 'In Progress',
			'colour'        => 'yellow',
			'id'            => '10001',
		),
		'in_review'   => array(
			'name'          => 'In Review',
			'category'      => 'indeterminate',
			'category_name' => 'In Progress',
			'colour'        => 'yellow',
			'id'            => '10002',
		),
		'done'        => array(
			'name'          => 'Done',
			'category'      => 'done',
			'category_name' => 'Done',
			'colour'        => 'green',
			'id'            => '10003',
		),
	);

	/**
	 * Simulated site hostname, without a scheme.
	 */
	private string $host;

	/**
	 * Cached state: seq + issues.
	 *
	 * @var array{seq:array<string,int>,issues:array<string,array<string,mixed>>}|null
	 */
	private ?array $state = null;

	/**
	 * @param string $base_url Configured site URL; only its host is used.
	 */
	public function __construct( string $base_url = '' ) {
		$host = (string) wp_parse_url( $base_url ?: 'https://vulnhub-demo.atlassian.net', PHP_URL_HOST );

		$this->host = $host ?: 'vulnhub-demo.atlassian.net';
	}

	/**
	 * Public site URL, e.g. https://vulnhub-demo.atlassian.net.
	 */
	public function site_url(): string {
		return 'https://' . $this->host;
	}

	/* =================================================================
	 * Transport
	 * ============================================================== */

	/**
	 * Answer a request as the simulated Jira site would.
	 *
	 * @param string                   $method  HTTP verb.
	 * @param string                   $path    API path, e.g. /rest/api/3/issue.
	 * @param array<string,mixed>      $query   Query arguments.
	 * @param array<string,mixed>|null $body    Decoded JSON request body.
	 * @param array<string,string>     $headers Extra request headers the client
	 *                                          set, so experimental endpoints
	 *                                          can insist on X-ExperimentalApi
	 *                                          exactly as Jira does.
	 */
	public function respond( string $method, string $path, array $query = array(), ?array $body = null, array $headers = array() ): \VulnHub\Core\Http_Response {
		$method = strtoupper( $method );
		$path   = '/' . trim( (string) wp_parse_url( $path, PHP_URL_PATH ), '/' );

		$route = static function ( string $pattern ) use ( $path ): array|false {
			$regex = '#^' . str_replace( array( '{key}', '{id}' ), array( '([^/]+)', '([^/]+)' ), $pattern ) . '$#';

			return preg_match( $regex, $path, $m ) ? array_slice( $m, 1 ) : false;
		};

		// --- identity ---------------------------------------------------
		if ( 'GET' === $method && '/rest/api/3/myself' === $path ) {
			return $this->ok( $this->myself() );
		}

		// --- Jira Service Management ------------------------------------
		// Routed at the real vendor paths so live and mock run one code path.
		if ( 'GET' === $method && '/rest/servicedeskapi/servicedesk' === $path ) {
			return $this->ok( $this->paged( $this->service_desks(), $query ) );
		}
		if ( 'GET' === $method && preg_match( '#^/rest/servicedeskapi/servicedesk/([^/]+)$#', $path, $m ) ) {
			$desk = $this->service_desk( rawurldecode( $m[1] ) );

			return $desk
				? $this->ok( $desk )
				: $this->error( 404, array( 'No service desk found for the given id.' ) );
		}
		if ( 'GET' === $method && preg_match( '#^/rest/servicedeskapi/servicedesk/([^/]+)/requesttype$#', $path, $m ) ) {
			$desk = $this->service_desk( rawurldecode( $m[1] ) );

			if ( ! $desk ) {
				return $this->error( 404, array( 'No service desk found for the given id.' ) );
			}

			return $this->ok( $this->paged( $this->request_types( (string) $desk['id'] ), $query ) );
		}
		if ( 'GET' === $method && '/rest/servicedeskapi/requesttype' === $path ) {
			// This one is flagged x-experimental in Atlassian's own OpenAPI
			// description, and Jira answers 412 without the opt-in header.
			if ( '' === $this->header( $headers, 'X-ExperimentalApi' ) ) {
				return $this->error(
					412,
					array( 'The requested API is experimental; opt in with the X-ExperimentalApi header.' )
				);
			}

			return $this->ok( $this->paged( $this->request_types( '' ), $query ) );
		}

		// --- reference data ---------------------------------------------
		if ( 'GET' === $method && '/rest/api/3/project/search' === $path ) {
			return $this->ok( $this->project_page( (string) ( $query['query'] ?? '' ) ) );
		}
		if ( 'GET' === $method && $route( '/rest/api/3/project/{key}' ) ) {
			$args    = (array) $route( '/rest/api/3/project/{key}' );
			$project = $this->project( strtoupper( rawurldecode( (string) $args[0] ) ) );

			return $project
				? $this->ok( $project )
				: $this->error( 404, array( 'No project could be found with key.' ) );
		}
		if ( 'GET' === $method && '/rest/api/3/issuetype' === $path ) {
			return $this->ok( $this->issue_types() );
		}
		if ( 'GET' === $method && '/rest/api/3/priority/search' === $path ) {
			$values = $this->priorities();

			return $this->ok(
				array(
					'startAt'    => 0,
					'maxResults' => 50,
					'total'      => count( $values ),
					'isLast'     => true,
					'values'     => $values,
				)
			);
		}
		if ( 'GET' === $method && '/rest/api/3/field' === $path ) {
			return $this->ok( $this->fields() );
		}
		if ( 'GET' === $method && preg_match( '#^/rest/api/3/issue/createmeta/([^/]+)/issuetypes/([^/]+)$#', $path, $m ) ) {
			return $this->ok( $this->create_meta( strtoupper( rawurldecode( $m[1] ) ), rawurldecode( $m[2] ) ) );
		}
		if ( 'GET' === $method && '/rest/api/3/user/search' === $path ) {
			return $this->ok( $this->user_search( (string) ( $query['query'] ?? '' ) ) );
		}
		if ( 'GET' === $method && '/rest/api/3/user/assignable/search' === $path ) {
			return $this->ok( $this->assignable_users( (string) ( $query['query'] ?? '' ) ) );
		}
		if ( 'GET' === $method && '/rest/api/3/groups/picker' === $path ) {
			return $this->ok( $this->groups_picker( (string) ( $query['query'] ?? '' ) ) );
		}
		if ( 'GET' === $method && preg_match( '#^/rest/api/3/project/([^/]+)/role$#', $path, $m ) ) {
			$project = $this->project( strtoupper( rawurldecode( $m[1] ) ) );

			return $project
				? $this->ok( $this->project_roles() )
				: $this->error( 404, array( 'No project could be found with key.' ) );
		}
		if ( 'GET' === $method && preg_match( '#^/rest/api/3/field/([^/]+)/context$#', $path, $m ) ) {
			return $this->ok( $this->field_contexts( rawurldecode( $m[1] ) ) );
		}
		if ( 'GET' === $method && preg_match( '#^/rest/api/3/field/([^/]+)/context/([^/]+)/option$#', $path, $m ) ) {
			return $this->ok( $this->field_options( rawurldecode( $m[1] ), rawurldecode( $m[2] ) ) );
		}

		// --- issues ------------------------------------------------------
		if ( 'POST' === $method && '/rest/api/3/issue' === $path ) {
			return $this->create_issue( (array) ( $body['fields'] ?? array() ) );
		}
		if ( 'POST' === $method && '/rest/api/3/search/jql' === $path ) {
			return $this->ok( $this->search( (array) $body ) );
		}
		if ( 'GET' === $method && '/rest/api/3/search/jql' === $path ) {
			return $this->ok( $this->search( $query ) );
		}
		if ( 'GET' === $method && preg_match( '#^/rest/api/3/issue/([^/]+)$#', $path, $m ) ) {
			$issue = $this->issue( rawurldecode( $m[1] ) );

			return $issue
				? $this->ok( $issue )
				: $this->error( 404, array( 'Issue does not exist or you do not have permission to see it.' ) );
		}
		if ( preg_match( '#^/rest/api/3/issue/([^/]+)/transitions$#', $path, $m ) ) {
			$key = rawurldecode( $m[1] );

			return 'GET' === $method
				? $this->list_transitions( $key )
				: $this->apply_transition( $key, (array) $body );
		}
		if ( 'PUT' === $method && preg_match( '#^/rest/api/3/issue/([^/]+)$#', $path, $m ) ) {
			return $this->update_issue( rawurldecode( $m[1] ), (array) ( $body['fields'] ?? array() ) );
		}
		if ( 'POST' === $method && preg_match( '#^/rest/api/3/issue/([^/]+)/comment$#', $path, $m ) ) {
			return $this->add_comment( rawurldecode( $m[1] ), (array) ( $body['body'] ?? array() ) );
		}
		if ( 'POST' === $method && preg_match( '#^/rest/api/3/issue/([^/]+)/remotelink$#', $path, $m ) ) {
			return $this->add_remote_link( rawurldecode( $m[1] ), (array) $body );
		}

		return $this->error( 404, array( sprintf( 'The simulated Jira site has no route for %s %s.', $method, $path ) ) );
	}

	/* =================================================================
	 * Payload builders — shaped like the real vendor responses
	 * ============================================================== */

	/**
	 * GET /rest/api/3/myself.
	 *
	 * @return array<string,mixed>
	 */
	private function myself(): array {
		return array(
			'self'         => $this->site_url() . '/rest/api/3/user?accountId=5f8a1c2d4e6b7a0012345678',
			'accountId'    => '5f8a1c2d4e6b7a0012345678',
			'accountType'  => 'atlassian',
			'emailAddress' => 'vulnhub-automation@example.com',
			'displayName'  => 'VulnHub Automation',
			'active'       => true,
			'timeZone'     => 'Pacific/Auckland',
			'locale'       => 'en_NZ',
		);
	}

	/**
	 * Every project the simulated site knows about: the default project plus
	 * whatever project keys the teams carry.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	private function projects(): array {
		$keys = array();

		$default = strtoupper( trim( (string) vulnhub()->settings->get( self::NS, 'project_key', 'SEC' ) ) );
		if ( '' !== $default ) {
			$keys[ $default ] = __( 'Security Remediation', 'vulnhub' );
		}

		foreach ( \VulnHub\Core\Repo::teams() as $team ) {
			$key = strtoupper( trim( (string) ( $team['jira_project_key'] ?? '' ) ) );
			if ( '' !== $key && ! isset( $keys[ $key ] ) ) {
				$keys[ $key ] = (string) $team['name'];
			}
		}

		if ( ! $keys ) {
			$keys['SEC'] = __( 'Security Remediation', 'vulnhub' );
		}

		// The two service desks always exist as projects too: a JSM service
		// desk is a project with a peer desk, and both APIs must agree.
		$desks = array();

		foreach ( self::DESKS as $desk ) {
			$desks[ $desk['key'] ] = $desk;
			unset( $keys[ $desk['key'] ] );
		}

		$out = array();
		$id  = 10000;

		foreach ( $desks as $desk ) {
			$out[] = array(
				'self'           => $this->site_url() . '/rest/api/3/project/' . rawurlencode( $desk['key'] ),
				'id'             => $desk['project'],
				'key'            => $desk['key'],
				'name'           => $desk['name'],
				'projectTypeKey' => 'service_desk',
				'simplified'     => false,
				'style'          => 'next-gen',
				'isPrivate'      => false,
				'lead'           => array(
					'accountId'   => '5f8a1c2d4e6b7a0012345678',
					'displayName' => 'VulnHub Automation',
				),
			);
		}

		foreach ( $keys as $key => $name ) {
			$out[] = array(
				'self'           => $this->site_url() . '/rest/api/3/project/' . rawurlencode( $key ),
				'id'             => (string) $id,
				'key'            => $key,
				'name'           => $name,
				'projectTypeKey' => 'software',
				'simplified'     => false,
				'style'          => 'classic',
				'isPrivate'      => false,
				'lead'           => array(
					'accountId'   => '5f8a1c2d4e6b7a0012345678',
					'displayName' => 'VulnHub Automation',
				),
			);
			++$id;
		}

		return $out;
	}

	/**
	 * One project by key.
	 *
	 * @return array<string,mixed>|null
	 */
	private function project( string $key ): ?array {
		foreach ( $this->projects() as $project ) {
			if ( strtoupper( (string) $project['key'] ) === strtoupper( $key ) ) {
				return $project;
			}
		}

		return null;
	}

	/**
	 * GET /rest/api/3/project/search — a paginated envelope.
	 *
	 * @return array<string,mixed>
	 */
	private function project_page( string $search ): array {
		$values = $this->projects();

		if ( '' !== $search ) {
			$values = array_values(
				array_filter(
					$values,
					static fn( array $p ): bool => false !== stripos( $p['key'] . ' ' . $p['name'], $search )
				)
			);
		}

		return array(
			'self'       => $this->site_url() . '/rest/api/3/project/search',
			'maxResults' => 50,
			'startAt'    => 0,
			'total'      => count( $values ),
			'isLast'     => true,
			'values'     => $values,
		);
	}

	/**
	 * The Team custom field id this simulated site uses.
	 *
	 * A real Atlassian-Teams-backed Team field cannot be enumerated through the
	 * Jira REST API at all (there is no team listing endpoint — see
	 * VulnHub_Jira_Directory). Modelling that here would give a demo with no
	 * team values in it, so the simulated site uses the other shape sites
	 * really do run: an option-backed custom field called Team, whose values
	 * are listable through the genuine, public custom field context option
	 * endpoints. Both write shapes are exercised — the directory decides which
	 * from schema.custom, exactly as it does live.
	 */
	private const TEAM_FIELD = 'customfield_10001';

	/** The Team field's single global context. */
	private const TEAM_CONTEXT = '10100';

	/**
	 * The two simulated service desks and their peer projects.
	 *
	 * @var array<int,array<string,string>>
	 */
	private const DESKS = array(
		array(
			'id'      => '1',
			'key'     => 'ITSD',
			'name'    => 'IT Service Desk',
			'project' => '10100',
		),
		array(
			'id'      => '2',
			'key'     => 'SECOPS',
			'name'    => 'Security Operations Desk',
			'project' => '10101',
		),
	);

	/**
	 * Request types, in the shape RequestTypeDTO defines.
	 *
	 * `issueTypeId` is the documented bridge to a Jira issue type, so each one
	 * points at an issue type this simulated site really has.
	 *
	 * @var array<int,array<string,mixed>>
	 */
	private const REQUEST_TYPES = array(
		array( '10', '1', 'Get IT help', 'Something is broken or you need a hand.', '10006', array( '1' ) ),
		array( '11', '1', 'Request new software', 'Ask for software to be installed or licensed.', '10006', array( '1' ) ),
		array( '12', '1', 'Report a security vulnerability', 'Raise a weakness found on a system you use.', '10007', array( '2' ) ),
		array( '20', '2', 'Vulnerability remediation', 'Patch or mitigate a vulnerability the scanner found.', '10005', array( '3' ) ),
		array( '21', '2', 'Security incident', 'Something is actively going wrong right now.', '10007', array( '3' ) ),
		array( '22', '2', 'Patch request', 'Schedule a patch into the next maintenance window.', '10006', array( '3' ) ),
	);

	/**
	 * The Team field's selectable values.
	 *
	 * @var array<int,array<string,string>>
	 */
	private const TEAM_OPTIONS = array(
		array( '10101', 'Security Operations' ),
		array( '10102', 'Platform Engineering' ),
		array( '10103', 'End User Computing' ),
		array( '10104', 'Network Operations' ),
		array( '10105', 'Application Support' ),
	);

	/**
	 * Groups the simulated site knows, for GET /rest/api/3/groups/picker.
	 *
	 * @var array<int,string>
	 */
	private const GROUPS = array(
		'jira-administrators',
		'jira-servicedesk-users',
		'security-operations',
		'platform-engineering',
		'end-user-computing',
		'network-operations',
		'application-support',
	);

	/**
	 * Read one header case-insensitively.
	 *
	 * @param array<string,string> $headers Request headers.
	 * @param string               $name    Header name.
	 */
	private function header( array $headers, string $name ): string {
		foreach ( $headers as $key => $value ) {
			if ( 0 === strcasecmp( (string) $key, $name ) ) {
				return (string) $value;
			}
		}

		return '';
	}

	/**
	 * Wrap values in the JSM paged envelope: values / size / start / limit /
	 * isLastPage / _links.
	 *
	 * @param array<int,array<string,mixed>> $values All values.
	 * @param array<string,mixed>            $query  Request query args.
	 * @return array<string,mixed>
	 */
	private function paged( array $values, array $query ): array {
		$start = max( 0, (int) ( $query['start'] ?? 0 ) );
		$limit = max( 1, min( 100, (int) ( $query['limit'] ?? 50 ) ) );
		$page  = array_slice( $values, $start, $limit );

		return array(
			'_expands'   => array(),
			'size'       => count( $page ),
			'start'      => $start,
			'limit'      => $limit,
			'isLastPage' => ( $start + count( $page ) ) >= count( $values ),
			'_links'     => array( 'base' => $this->site_url() . '/rest/servicedeskapi' ),
			'values'     => $page,
		);
	}

	/**
	 * GET /rest/servicedeskapi/servicedesk values — ServiceDeskDTO objects.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	private function service_desks(): array {
		$out = array();

		foreach ( self::DESKS as $desk ) {
			$out[] = array(
				'id'             => $desk['id'],
				'projectId'      => $desk['project'],
				'projectKey'     => $desk['key'],
				'projectName'    => $desk['name'],
				'projectTypeKey' => 'service_desk',
				'_links'         => array(
					'self' => $this->site_url() . '/rest/servicedeskapi/servicedesk/' . $desk['id'],
				),
			);
		}

		return $out;
	}

	/**
	 * One service desk by id or by peer project key.
	 *
	 * @return array<string,mixed>|null
	 */
	private function service_desk( string $id ): ?array {
		$id = strtoupper( trim( $id ) );

		foreach ( $this->service_desks() as $desk ) {
			if ( strtoupper( (string) $desk['id'] ) === $id || strtoupper( (string) $desk['projectKey'] ) === $id ) {
				return $desk;
			}
		}

		return null;
	}

	/**
	 * Request types, optionally limited to one desk.
	 *
	 * @param string $desk_id Service desk id, or '' for every desk.
	 * @return array<int,array<string,mixed>>
	 */
	private function request_types( string $desk_id ): array {
		$out = array();

		foreach ( self::REQUEST_TYPES as $type ) {
			if ( '' !== $desk_id && $type[1] !== $desk_id ) {
				continue;
			}

			$out[] = array(
				'id'            => $type[0],
				'_links'        => array(
					'self' => $this->site_url() . '/rest/servicedeskapi/servicedesk/' . $type[1] . '/requesttype/' . $type[0],
				),
				'name'          => $type[2],
				'description'   => $type[3],
				'helpText'      => $type[3],
				'issueTypeId'   => $type[4],
				'serviceDeskId' => $type[1],
				'portalId'      => $type[1],
				'groupIds'      => $type[5],
				'practice'      => '10005' === $type[4] ? 'SERVICE_REQUEST' : 'INCIDENT',
			);
		}

		return $out;
	}

	/**
	 * GET /rest/api/3/field/{fieldId}/context.
	 *
	 * @return array<string,mixed>
	 */
	private function field_contexts( string $field_id ): array {
		$values = array();

		if ( self::TEAM_FIELD === $field_id ) {
			$values[] = array(
				'id'              => self::TEAM_CONTEXT,
				'name'            => 'Default Configuration Scheme for Team',
				'description'     => 'Applies to every project and issue type.',
				'isGlobalContext' => true,
				'isAnyIssueType'  => true,
			);
		}

		return array(
			'startAt'    => 0,
			'maxResults' => 50,
			'total'      => count( $values ),
			'isLast'     => true,
			'values'     => $values,
		);
	}

	/**
	 * GET /rest/api/3/field/{fieldId}/context/{contextId}/option.
	 *
	 * @return array<string,mixed>
	 */
	private function field_options( string $field_id, string $context_id ): array {
		$values = array();

		if ( self::TEAM_FIELD === $field_id && self::TEAM_CONTEXT === $context_id ) {
			foreach ( self::TEAM_OPTIONS as $option ) {
				$values[] = array(
					'id'       => $option[0],
					'value'    => $option[1],
					'disabled' => false,
				);
			}
		}

		return array(
			'startAt'    => 0,
			'maxResults' => 100,
			'total'      => count( $values ),
			'isLast'     => true,
			'values'     => $values,
		);
	}

	/**
	 * GET /rest/api/3/groups/picker.
	 *
	 * @return array<string,mixed>
	 */
	private function groups_picker( string $query ): array {
		$query  = strtolower( trim( $query ) );
		$groups = array();

		foreach ( self::GROUPS as $name ) {
			if ( '' !== $query && ! str_contains( $name, $query ) ) {
				continue;
			}

			$groups[] = array(
				'name'    => $name,
				'html'    => esc_html( $name ),
				'groupId' => substr( md5( 'group:' . $name ), 0, 8 ) . '-mock-group',
			);
		}

		return array(
			'header' => sprintf( 'Showing %d of %d matching groups', count( $groups ), count( self::GROUPS ) ),
			'total'  => count( $groups ),
			'groups' => $groups,
		);
	}

	/**
	 * GET /rest/api/3/project/{key}/role — role name => role URL.
	 *
	 * @return array<string,string>
	 */
	private function project_roles(): array {
		$roles = array(
			'Administrators'    => '10002',
			'Developers'        => '10001',
			'Service Desk Team' => '10003',
			'Viewers'           => '10004',
		);

		$out = array();

		foreach ( $roles as $name => $id ) {
			$out[ $name ] = $this->site_url() . '/rest/api/3/project/10000/role/' . $id;
		}

		return $out;
	}

	/**
	 * GET /rest/api/3/user/assignable/search — the shared mock people.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	private function assignable_users( string $query ): array {
		$query = strtolower( trim( $query ) );
		$out   = array();

		foreach ( \VulnHub\Core\Mock::people() as $person ) {
			$haystack = strtolower(
				(string) ( $person['displayName'] ?? '' ) . ' ' .
				(string) ( $person['mail'] ?? '' ) . ' ' .
				(string) ( $person['userPrincipalName'] ?? '' )
			);

			if ( '' !== $query && ! str_contains( $haystack, $query ) ) {
				continue;
			}

			$out[] = $this->user_node( $person );

			if ( count( $out ) >= 50 ) {
				break;
			}
		}

		return $out;
	}

	/**
	 * GET /rest/api/3/issuetype.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	private function issue_types(): array {
		$types = array(
			array( '10001', 'Task', 'A small, distinct piece of work.', false ),
			array( '10002', 'Bug', 'A problem which impairs product function.', false ),
			array( '10003', 'Story', 'A user story.', false ),
			array( '10004', 'Sub-task', 'A small piece of work within a larger task.', true ),
			array( '10005', 'Vulnerability', 'A security weakness requiring remediation.', false ),
			// The issue types the simulated request types are based upon.
			array( '10006', '[System] Service request', 'Created by Jira Service Management.', false ),
			array( '10007', '[System] Incident', 'Created by Jira Service Management.', false ),
		);

		return array_map(
			fn( array $t ): array => array(
				'self'           => $this->site_url() . '/rest/api/3/issuetype/' . $t[0],
				'id'             => $t[0],
				'name'           => $t[1],
				'description'    => $t[2],
				'subtask'        => $t[3],
				'hierarchyLevel' => $t[3] ? -1 : 0,
			),
			$types
		);
	}

	/**
	 * GET /rest/api/3/priority/search values.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	private function priorities(): array {
		$names = array( 'Highest', 'High', 'Medium', 'Low', 'Lowest' );
		$out   = array();

		foreach ( $names as $i => $name ) {
			$out[] = array(
				'self'        => $this->site_url() . '/rest/api/3/priority/' . ( $i + 1 ),
				'id'          => (string) ( $i + 1 ),
				'name'        => $name,
				'description' => sprintf( '%s priority.', $name ),
				'isDefault'   => 'Medium' === $name,
			);
		}

		return $out;
	}

	/**
	 * GET /rest/api/3/field.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	private function fields(): array {
		$fields = array(
			array( 'summary', 'Summary', 'string' ),
			array( 'description', 'Description', 'doc' ),
			array( 'issuetype', 'Issue Type', 'issuetype' ),
			array( 'priority', 'Priority', 'priority' ),
			array( 'assignee', 'Assignee', 'user' ),
			array( 'labels', 'Labels', 'array' ),
			array( 'duedate', 'Due date', 'date' ),
			array( 'status', 'Status', 'status' ),
			array( 'resolution', 'Resolution', 'resolution' ),
		);

		$out = array_map(
			static fn( array $f ): array => array(
				'id'           => $f[0],
				'key'          => $f[0],
				'name'         => $f[1],
				'custom'       => false,
				'navigable'    => true,
				'searchable'   => true,
				'orderable'    => true,
				'clauseNames'  => array( $f[0] ),
				'schema'       => array(
					'type'   => $f[2],
					'system' => $f[0],
				),
			),
			$fields
		);

		// The Team field. See the TEAM_FIELD note: this is the option-backed
		// shape, which is the one the public REST API can actually enumerate.
		$out[] = array(
			'id'          => self::TEAM_FIELD,
			'key'         => self::TEAM_FIELD,
			'name'        => 'Team',
			'custom'      => true,
			'navigable'   => true,
			'searchable'  => true,
			'orderable'   => true,
			'clauseNames' => array( 'Team', 'cf[10001]' ),
			'schema'      => array(
				'type'     => 'option',
				'custom'   => 'com.atlassian.jira.plugin.system.customfieldtypes:select',
				'customId' => 10001,
			),
		);

		return $out;
	}

	/**
	 * GET /rest/api/3/issue/createmeta/{projectIdOrKey}/issuetypes/{issueTypeId}.
	 *
	 * @return array<string,mixed>
	 */
	private function create_meta( string $project_key, string $issue_type_id ): array {
		unset( $project_key, $issue_type_id );

		$values = array();

		foreach ( $this->fields() as $field ) {
			$values[] = array(
				'required'        => in_array( $field['id'], array( 'summary', 'issuetype' ), true ),
				'schema'          => $field['schema'],
				'name'            => $field['name'],
				'fieldId'         => $field['id'],
				'hasDefaultValue' => false,
				'operations'      => array( 'set' ),
			);
		}

		return array(
			'maxResults' => 50,
			'startAt'    => 0,
			'total'      => count( $values ),
			'fields'     => $values,
		);
	}

	/**
	 * GET /rest/api/3/user/search — resolves an email to an account id.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	private function user_search( string $query ): array {
		$query = strtolower( trim( $query ) );

		if ( '' === $query ) {
			return array();
		}

		$out = array();

		foreach ( \VulnHub\Core\Mock::people() as $person ) {
			$upn  = strtolower( (string) ( $person['userPrincipalName'] ?? '' ) );
			$mail = strtolower( (string) ( $person['mail'] ?? '' ) );
			$name = strtolower( (string) ( $person['displayName'] ?? '' ) );

			if ( $upn === $query || $mail === $query || str_contains( $name, $query ) ) {
				$out[] = $this->user_node( $person );
			}

			if ( count( $out ) >= 10 ) {
				break;
			}
		}

		return $out;
	}

	/**
	 * A Jira user object built from a shared mock person.
	 *
	 * @param array<string,mixed> $person Mock::people() record.
	 * @return array<string,mixed>
	 */
	private function user_node( array $person ): array {
		$account = 'mock:' . substr( md5( (string) ( $person['id'] ?? $person['userPrincipalName'] ?? '' ) ), 0, 24 );

		return array(
			'self'         => $this->site_url() . '/rest/api/3/user?accountId=' . rawurlencode( $account ),
			'accountId'    => $account,
			'accountType'  => 'atlassian',
			'displayName'  => (string) ( $person['displayName'] ?? '' ),
			'emailAddress' => (string) ( $person['mail'] ?? $person['userPrincipalName'] ?? '' ),
			'active'       => true,
		);
	}

	/* =================================================================
	 * Issue lifecycle
	 * ============================================================== */

	/**
	 * POST /rest/api/3/issue.
	 *
	 * @param array<string,mixed> $fields The `fields` object from the request body.
	 */
	private function create_issue( array $fields ): \VulnHub\Core\Http_Response {
		$project_key = strtoupper( (string) ( $fields['project']['key'] ?? '' ) );
		$summary     = trim( (string) ( $fields['summary'] ?? '' ) );

		if ( '' === $project_key || null === $this->project( $project_key ) ) {
			return $this->error( 400, array(), array( 'project' => 'Specify a valid project key.' ) );
		}
		if ( '' === $summary ) {
			return $this->error( 400, array(), array( 'summary' => 'You must specify a summary of the issue.' ) );
		}

		$state = $this->state();
		$next  = max( self::FIRST_NUMBER, (int) ( $state['seq'][ $project_key ] ?? self::FIRST_NUMBER - 1 ) + 1 );
		$key   = $project_key . '-' . $next;

		$state['seq'][ $project_key ] = $next;

		$assignee = $this->resolve_assignee( (string) ( $fields['assignee']['id'] ?? $fields['assignee']['accountId'] ?? '' ), $key );

		$state['issues'][ $key ] = array(
			'id'          => (string) ( 100000 + crc32( $key ) % 800000 ),
			'key'         => $key,
			'project'     => $project_key,
			'issuetype'   => $this->issue_type_name( (array) ( $fields['issuetype'] ?? array() ) ),
			'summary'     => vh_trim( $summary, 250 ),
			'priority'    => (string) ( $fields['priority']['name'] ?? 'Medium' ),
			'labels'      => array_values( array_map( 'strval', (array) ( $fields['labels'] ?? array() ) ) ),
			'duedate'     => (string) ( $fields['duedate'] ?? '' ),
			'description' => vh_trim( VulnHub_Jira_Adf::to_text( (array) ( $fields['description'] ?? array() ) ), 4000 ),
			'assignee'    => $assignee,
			'created'     => vh_now(),
			'updated'     => vh_now(),
			// Deterministic remediation pace so the fleet shows a realistic
			// spread of To Do / In Progress / Done rather than one flat state.
			'pace'        => (int) ( crc32( 'pace:' . $key ) % 100 ),
			'forced'      => null,
			'comments'    => array(),
			'links'       => array(),
			// Whatever custom fields the caller set — the Team field included.
			'custom'      => $this->custom_fields( $fields ),
		);

		$this->save( $state );

		return new \VulnHub\Core\Http_Response(
			201,
			array( 'content-type' => 'application/json' ),
			'',
			array(
				'id'   => $state['issues'][ $key ]['id'],
				'key'  => $key,
				'self' => $this->site_url() . '/rest/api/3/issue/' . $key,
			)
		);
	}

	/**
	 * Resolve an `issuetype` reference to a name.
	 *
	 * The ticketer sends `{"id": …}` when a JSM request type decided the issue
	 * type (RequestTypeDTO.issueTypeId) and `{"name": …}` otherwise, so both
	 * have to work here exactly as they do in Jira.
	 *
	 * @param array<string,mixed> $ref Issue type reference from the request.
	 */
	private function issue_type_name( array $ref ): string {
		$id = trim( (string) ( $ref['id'] ?? '' ) );

		if ( '' !== $id ) {
			foreach ( $this->issue_types() as $type ) {
				if ( (string) $type['id'] === $id ) {
					return (string) $type['name'];
				}
			}
		}

		return trim( (string) ( $ref['name'] ?? '' ) ) ?: 'Task';
	}

	/**
	 * Every customfield_* value in a create or update request.
	 *
	 * @param array<string,mixed> $fields The `fields` object.
	 * @return array<string,mixed>
	 */
	private function custom_fields( array $fields ): array {
		$out = array();

		foreach ( $fields as $id => $value ) {
			if ( str_starts_with( (string) $id, 'customfield_' ) ) {
				$out[ (string) $id ] = $value;
			}
		}

		return $out;
	}

	/**
	 * Render a stored custom field value the way Jira renders it.
	 *
	 * An option-backed field comes back as `{id, value, self}`; anything else
	 * comes back as it went in.
	 *
	 * @param string $id    Custom field id.
	 * @param mixed  $value Stored value.
	 * @return mixed
	 */
	private function render_custom_field( string $id, mixed $value ): mixed {
		if ( self::TEAM_FIELD !== $id ) {
			return $value;
		}

		$wanted_id    = is_array( $value ) ? (string) ( $value['id'] ?? '' ) : '';
		$wanted_value = is_array( $value ) ? (string) ( $value['value'] ?? '' ) : (string) $value;

		foreach ( self::TEAM_OPTIONS as $option ) {
			if ( $option[0] === $wanted_id || $option[1] === $wanted_value ) {
				return array(
					'self'  => $this->site_url() . '/rest/api/3/customFieldOption/' . $option[0],
					'id'    => $option[0],
					'value' => $option[1],
				);
			}
		}

		return $value;
	}

	/**
	 * Pick the assignee for a new issue.
	 *
	 * An explicit account id wins; otherwise the simulated site round-robins
	 * across the shared mock people so tickets look owned by real humans.
	 *
	 * @param string $requested Requested account id, may be empty.
	 * @param string $key       Issue key, used as the deterministic seed.
	 * @return array<string,mixed>|null
	 */
	private function resolve_assignee( string $requested, string $key ): ?array {
		$people = \VulnHub\Core\Mock::people();

		if ( ! $people ) {
			return null;
		}

		if ( '' !== $requested ) {
			foreach ( $people as $person ) {
				$node = $this->user_node( $person );
				if ( $node['accountId'] === $requested ) {
					return $node;
				}
			}
		}

		// ~15% of issues sit unassigned in a triage queue, as they would in life.
		$seed = crc32( 'assign:' . $key );

		if ( $seed % 100 < 15 ) {
			return null;
		}

		return $this->user_node( $people[ $seed % count( $people ) ] );
	}

	/**
	 * The workflow state an issue is in right now.
	 *
	 * A forced state (set by an explicit transition) always wins. Otherwise the
	 * issue moves along the workflow on its own deterministic pace, so a site
	 * left alone for a week looks like a site people worked in for a week.
	 *
	 * @param array<string,mixed> $issue Stored issue record.
	 * @return array{name:string,category:string,category_name:string,colour:string,id:string}
	 */
	private function workflow_state( array $issue ): array {
		if ( is_array( $issue['forced'] ?? null ) && ! empty( $issue['forced']['slug'] ) ) {
			return self::WORKFLOW[ (string) $issue['forced']['slug'] ] ?? self::WORKFLOW['todo'];
		}

		$created = strtotime( ( (string) $issue['created'] ) . ' UTC' );
		$age     = false === $created ? 0 : max( 0, time() - $created );
		$pace    = (int) ( $issue['pace'] ?? 50 );

		if ( $pace < 18 ) {
			// Fast movers: already closed by the time we first poll.
			return self::WORKFLOW['done'];
		}

		if ( $pace < 55 ) {
			// Picked up immediately, closed within a few days.
			return $age >= 3 * DAY_IN_SECONDS ? self::WORKFLOW['done'] : self::WORKFLOW['in_progress'];
		}

		if ( $pace < 80 ) {
			if ( $age >= 7 * DAY_IN_SECONDS ) {
				return self::WORKFLOW['done'];
			}

			return $age >= DAY_IN_SECONDS ? self::WORKFLOW['in_review'] : self::WORKFLOW['todo'];
		}

		// Slow movers: sit in the backlog and only start after a couple of days.
		return $age >= 2 * DAY_IN_SECONDS ? self::WORKFLOW['in_progress'] : self::WORKFLOW['todo'];
	}

	/**
	 * Render a stored issue as the Jira REST API renders it.
	 *
	 * @return array<string,mixed>|null
	 */
	private function issue( string $key ): ?array {
		$state = $this->state();
		$key   = strtoupper( trim( $key ) );

		if ( ! isset( $state['issues'][ $key ] ) ) {
			return null;
		}

		return $this->render_issue( $state['issues'][ $key ] );
	}

	/**
	 * @param array<string,mixed> $issue Stored record.
	 * @return array<string,mixed>
	 */
	private function render_issue( array $issue ): array {
		$status  = $this->workflow_state( $issue );
		$project = $this->project( (string) $issue['project'] ) ?? array(
			'id'   => '10000',
			'key'  => (string) $issue['project'],
			'name' => (string) $issue['project'],
		);

		$resolution = null;

		if ( 'done' === $status['category'] ) {
			$name       = (string) ( $issue['forced']['resolution'] ?? 'Done' );
			$resolution = array(
				'self'        => $this->site_url() . '/rest/api/3/resolution/10000',
				'id'          => '10000',
				'name'        => $name,
				'description' => 'Work has been completed on this issue.',
			);
		}

		$issue_type_id = '10001';

		foreach ( $this->issue_types() as $type ) {
			if ( strcasecmp( (string) $type['name'], (string) $issue['issuetype'] ) === 0 ) {
				$issue_type_id = (string) $type['id'];
				break;
			}
		}

		$custom = array();

		foreach ( (array) ( $issue['custom'] ?? array() ) as $field_id => $value ) {
			$custom[ (string) $field_id ] = $this->render_custom_field( (string) $field_id, $value );
		}

		return array(
			'expand' => 'names,schema',
			'id'     => (string) $issue['id'],
			'self'   => $this->site_url() . '/rest/api/3/issue/' . $issue['key'],
			'key'    => (string) $issue['key'],
			'fields' => array(
				'summary'     => (string) $issue['summary'],
				'project'     => array(
					'id'   => (string) $project['id'],
					'key'  => (string) $project['key'],
					'name' => (string) $project['name'],
					'self' => $this->site_url() . '/rest/api/3/project/' . $project['key'],
				),
				'issuetype'   => array(
					'id'      => $issue_type_id,
					'name'    => (string) $issue['issuetype'],
					'subtask' => false,
					'self'    => $this->site_url() . '/rest/api/3/issuetype/' . $issue_type_id,
				),
				'status'      => array(
					'self'           => $this->site_url() . '/rest/api/3/status/' . $status['id'],
					'id'             => $status['id'],
					'name'           => $status['name'],
					'description'    => '',
					'statusCategory' => array(
						'self'      => $this->site_url() . '/rest/api/3/statuscategory/' . $status['id'],
						'id'        => 'done' === $status['category'] ? 3 : ( 'new' === $status['category'] ? 2 : 4 ),
						'key'       => $status['category'],
						'colorName' => $status['colour'],
						'name'      => $status['category_name'],
					),
				),
				'resolution'  => $resolution,
				'priority'    => array(
					'self' => $this->site_url() . '/rest/api/3/priority/3',
					'id'   => '3',
					'name' => (string) $issue['priority'],
				),
				'assignee'    => is_array( $issue['assignee'] ?? null ) ? $issue['assignee'] : null,
				'reporter'    => $this->myself(),
				'labels'      => array_values( (array) ( $issue['labels'] ?? array() ) ),
				'duedate'     => ( (string) ( $issue['duedate'] ?? '' ) ) ?: null,
				'created'     => $this->iso( (string) $issue['created'] ),
				'updated'     => $this->iso( (string) ( $issue['updated'] ?? $issue['created'] ) ),
				'resolutiondate' => 'done' === $status['category'] ? $this->iso( (string) ( $issue['updated'] ?? $issue['created'] ) ) : null,
				'description' => array(
					'type'    => 'doc',
					'version' => 1,
					'content' => array(
						array(
							'type'    => 'paragraph',
							'content' => array(
								array(
									'type' => 'text',
									'text' => (string) ( $issue['description'] ?: $issue['summary'] ),
								),
							),
						),
					),
				),
				'comment'     => array(
					'comments'   => array_values( (array) ( $issue['comments'] ?? array() ) ),
					'total'      => count( (array) ( $issue['comments'] ?? array() ) ),
					'maxResults' => 100,
					'startAt'    => 0,
				),
			) + $custom,
		);
	}

	/**
	 * POST /rest/api/3/search/jql.
	 *
	 * Only the query shapes the connector actually issues are honoured:
	 * `key in (…)` (batched status sync) and `project = X` (browsing).
	 *
	 * @param array<string,mixed> $body Request body or query args.
	 * @return array<string,mixed>
	 */
	private function search( array $body ): array {
		$jql   = (string) ( $body['jql'] ?? '' );
		$max   = max( 1, min( 5000, (int) ( $body['maxResults'] ?? 100 ) ) );
		$token = (string) ( $body['nextPageToken'] ?? '' );
		$state = $this->state();

		$matched = array();

		if ( preg_match_all( '/\b([A-Z][A-Z0-9_]+-\d+)\b/', strtoupper( $jql ), $m ) ) {
			foreach ( array_unique( $m[1] ) as $key ) {
				if ( isset( $state['issues'][ $key ] ) ) {
					$matched[] = $state['issues'][ $key ];
				}
			}
		} elseif ( preg_match( '/project\s*=\s*"?([A-Z][A-Z0-9_]*)"?/i', $jql, $m ) ) {
			$project = strtoupper( $m[1] );

			foreach ( $state['issues'] as $issue ) {
				if ( strtoupper( (string) $issue['project'] ) === $project ) {
					$matched[] = $issue;
				}
			}
		} else {
			$matched = array_values( $state['issues'] );
		}

		$offset = ctype_digit( $token ) ? (int) $token : 0;
		$page   = array_slice( $matched, $offset, $max );
		$next   = ( $offset + $max ) < count( $matched ) ? (string) ( $offset + $max ) : null;

		$out = array(
			'issues' => array_values( array_map( fn( array $i ): array => $this->render_issue( $i ), $page ) ),
			'isLast' => null === $next,
		);

		if ( null !== $next ) {
			$out['nextPageToken'] = $next;
		}

		return $out;
	}

	/**
	 * GET /rest/api/3/issue/{key}/transitions.
	 */
	private function list_transitions( string $key ): \VulnHub\Core\Http_Response {
		$state = $this->state();
		$key   = strtoupper( trim( $key ) );

		if ( ! isset( $state['issues'][ $key ] ) ) {
			return $this->error( 404, array( 'Issue does not exist or you do not have permission to see it.' ) );
		}

		$current = $this->workflow_state( $state['issues'][ $key ] );
		$out     = array();
		$id      = 11;

		foreach ( self::WORKFLOW as $slug => $target ) {
			if ( $target['name'] === $current['name'] ) {
				++$id;
				continue;
			}

			$out[] = array(
				'id'            => (string) $id,
				'name'          => $target['name'],
				'hasScreen'     => false,
				'isGlobal'      => true,
				'isInitial'     => 'todo' === $slug,
				'isAvailable'   => true,
				'isConditional' => false,
				'to'            => array(
					'self'           => $this->site_url() . '/rest/api/3/status/' . $target['id'],
					'id'             => $target['id'],
					'name'           => $target['name'],
					'statusCategory' => array(
						'id'        => 'done' === $target['category'] ? 3 : ( 'new' === $target['category'] ? 2 : 4 ),
						'key'       => $target['category'],
						'colorName' => $target['colour'],
						'name'      => $target['category_name'],
					),
				),
			);
			++$id;
		}

		return $this->ok( array( 'transitions' => $out ) );
	}

	/**
	 * POST /rest/api/3/issue/{key}/transitions.
	 *
	 * @param array<string,mixed> $body Transition payload.
	 */
	private function apply_transition( string $key, array $body ): \VulnHub\Core\Http_Response {
		$state = $this->state();
		$key   = strtoupper( trim( $key ) );

		if ( ! isset( $state['issues'][ $key ] ) ) {
			return $this->error( 404, array( 'Issue does not exist or you do not have permission to see it.' ) );
		}

		$transition_id = (string) ( $body['transition']['id'] ?? '' );
		$target        = null;
		$slug          = '';

		$id = 11;
		foreach ( self::WORKFLOW as $candidate_slug => $candidate ) {
			$current = $this->workflow_state( $state['issues'][ $key ] );

			if ( $candidate['name'] !== $current['name'] && (string) $id === $transition_id ) {
				$target = $candidate;
				$slug   = $candidate_slug;
				break;
			}
			++$id;
		}

		if ( null === $target ) {
			return $this->error( 400, array(), array( 'transition' => 'The transition is not valid for the issue in its current state.' ) );
		}

		$state['issues'][ $key ]['forced']  = array(
			'slug'       => $slug,
			'at'         => vh_now(),
			'resolution' => (string) ( $body['fields']['resolution']['name'] ?? 'Done' ),
		);
		$state['issues'][ $key ]['updated'] = vh_now();

		foreach ( (array) ( $body['update']['comment'] ?? array() ) as $entry ) {
			$adf = (array) ( $entry['add']['body'] ?? array() );
			if ( $adf ) {
				$state['issues'][ $key ]['comments'][] = $this->comment_node( $adf, count( $state['issues'][ $key ]['comments'] ) );
			}
		}

		$this->save( $state );

		return new \VulnHub\Core\Http_Response( 204, array(), '', array() );
	}

	/**
	 * POST /rest/api/3/issue/{key}/comment.
	 *
	 * @param array<string,mixed> $adf Comment body as ADF.
	 */
	/**
	 * PUT /rest/api/3/issue/{key} — edit an issue's fields.
	 *
	 * Jira answers a successful edit with 204 No Content, so this returns an
	 * empty body deliberately; callers must not expect the updated issue back.
	 *
	 * @param array<string,mixed> $fields Fields to change.
	 */
	private function update_issue( string $key, array $fields ): \VulnHub\Core\Http_Response {
		$state = $this->state();
		$key   = strtoupper( trim( $key ) );

		if ( ! isset( $state['issues'][ $key ] ) ) {
			return $this->error( 404, array( 'Issue does not exist or you do not have permission to see it.' ) );
		}
		if ( ! $fields ) {
			return $this->error( 400, array(), array( 'fields' => 'No fields were provided to update.' ) );
		}

		$issue = $state['issues'][ $key ];

		foreach ( $fields as $field => $value ) {
			switch ( $field ) {
				case 'summary':
					$issue['summary'] = vh_trim( (string) $value, 250 );
					break;
				case 'description':
					$issue['description'] = is_array( $value ) ? $value : array();
					break;
				case 'labels':
					$issue['labels'] = array_values( array_map( 'strval', (array) $value ) );
					break;
				case 'duedate':
					$issue['duedate'] = (string) $value;
					break;
				case 'priority':
					$issue['priority'] = (string) ( is_array( $value ) ? ( $value['name'] ?? '' ) : $value );
					break;
				case 'assignee':
					$issue['assignee'] = (string) ( is_array( $value ) ? ( $value['accountId'] ?? '' ) : $value );
					break;
				default:
					// Custom and unknown fields are stored verbatim, the way a
					// real site would accept anything on the screen.
					$issue['fields'][ $field ] = $value;
			}
		}

		$issue['updated']            = vh_now();
		$state['issues'][ $key ]     = $issue;

		$this->save( $state );

		return new \VulnHub\Core\Http_Response( 204, array(), '', array() );
	}

	private function add_comment( string $key, array $adf ): \VulnHub\Core\Http_Response {
		$state = $this->state();
		$key   = strtoupper( trim( $key ) );

		if ( ! isset( $state['issues'][ $key ] ) ) {
			return $this->error( 404, array( 'Issue does not exist or you do not have permission to see it.' ) );
		}
		if ( ! $adf ) {
			return $this->error( 400, array(), array( 'body' => 'The comment body is required and must be an Atlassian Document Format document.' ) );
		}

		$node = $this->comment_node( $adf, count( (array) $state['issues'][ $key ]['comments'] ) );

		$state['issues'][ $key ]['comments'][] = $node;
		$state['issues'][ $key ]['updated']    = vh_now();

		$this->save( $state );

		return new \VulnHub\Core\Http_Response( 201, array(), '', $node );
	}

	/**
	 * Build a Jira comment object.
	 *
	 * @param array<string,mixed> $adf   ADF body.
	 * @param int                 $index Sequence within the issue.
	 * @return array<string,mixed>
	 */
	private function comment_node( array $adf, int $index ): array {
		return array(
			'id'      => (string) ( 20000 + $index ),
			'self'    => $this->site_url() . '/rest/api/3/comment/' . ( 20000 + $index ),
			'author'  => $this->myself(),
			'body'    => $adf,
			'created' => $this->iso( vh_now() ),
			'updated' => $this->iso( vh_now() ),
		);
	}

	/**
	 * POST /rest/api/3/issue/{key}/remotelink.
	 *
	 * @param array<string,mixed> $body Remote link payload.
	 */
	private function add_remote_link( string $key, array $body ): \VulnHub\Core\Http_Response {
		$state = $this->state();
		$key   = strtoupper( trim( $key ) );

		if ( ! isset( $state['issues'][ $key ] ) ) {
			return $this->error( 404, array( 'Issue does not exist or you do not have permission to see it.' ) );
		}
		if ( empty( $body['object']['url'] ) ) {
			return $this->error( 400, array(), array( 'object' => 'The remote link object requires a url.' ) );
		}

		$id = 30000 + count( (array) $state['issues'][ $key ]['links'] );

		$state['issues'][ $key ]['links'][] = array(
			'id'          => $id,
			'globalId'    => (string) ( $body['globalId'] ?? '' ),
			'application' => (array) ( $body['application'] ?? array() ),
			'object'      => (array) $body['object'],
		);

		$this->save( $state );

		return new \VulnHub\Core\Http_Response(
			201,
			array(),
			'',
			array(
				'id'   => $id,
				'self' => $this->site_url() . '/rest/api/issue/' . $key . '/remotelink/' . $id,
			)
		);
	}

	/* =================================================================
	 * State + helpers
	 * ============================================================== */

	/**
	 * Load the simulated site.
	 *
	 * @return array{seq:array<string,int>,issues:array<string,array<string,mixed>>}
	 */
	private function state(): array {
		if ( null === $this->state ) {
			$stored = vulnhub()->settings->get( self::NS, self::STATE_KEY, array() );
			$stored = is_array( $stored ) ? $stored : array();

			$this->state = array(
				'seq'    => is_array( $stored['seq'] ?? null ) ? $stored['seq'] : array(),
				'issues' => is_array( $stored['issues'] ?? null ) ? $stored['issues'] : array(),
			);
		}

		return $this->state;
	}

	/**
	 * Persist the simulated site, keeping only the newest issues.
	 *
	 * @param array{seq:array<string,int>,issues:array<string,array<string,mixed>>} $state State.
	 */
	private function save( array $state ): void {
		if ( count( $state['issues'] ) > self::MAX_ISSUES ) {
			$state['issues'] = array_slice( $state['issues'], -self::MAX_ISSUES, null, true );
		}

		$this->state = $state;

		vulnhub()->settings->set( self::NS, self::STATE_KEY, $state );
	}

	/**
	 * How many issues the simulated site holds, for the admin screen.
	 */
	public function issue_count(): int {
		return count( $this->state()['issues'] );
	}

	/**
	 * Reset the simulated site.
	 */
	public function reset(): void {
		$this->save(
			array(
				'seq'    => array(),
				'issues' => array(),
			)
		);
	}

	/**
	 * Jira renders timestamps as ISO8601 with a numeric offset.
	 */
	private function iso( string $mysql ): string {
		$ts = strtotime( $mysql . ' UTC' );

		return gmdate( 'Y-m-d\TH:i:s.000O', false === $ts ? time() : $ts );
	}

	/**
	 * A 200 response carrying a decoded payload.
	 *
	 * @param array<string,mixed>|array<int,mixed> $payload Body.
	 */
	private function ok( array $payload ): \VulnHub\Core\Http_Response {
		return new \VulnHub\Core\Http_Response(
			200,
			array( 'content-type' => 'application/json' ),
			'',
			$payload
		);
	}

	/**
	 * A Jira-shaped error envelope.
	 *
	 * @param int                  $status   HTTP status.
	 * @param array<int,string>    $messages errorMessages entries.
	 * @param array<string,string> $errors   Field errors.
	 */
	private function error( int $status, array $messages = array(), array $errors = array() ): \VulnHub\Core\Http_Response {
		return new \VulnHub\Core\Http_Response(
			$status,
			array( 'content-type' => 'application/json' ),
			'',
			array(
				'errorMessages' => array_values( $messages ),
				'errors'        => $errors,
			)
		);
	}
}

