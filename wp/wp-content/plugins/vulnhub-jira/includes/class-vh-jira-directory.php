<?php
/**
 * Discovery of everything a ticket can be routed *to*: service desks, request
 * types, projects, the Team custom field, groups and project roles.
 *
 * Verified against developer.atlassian.com and both machine-readable OpenAPI
 * descriptions (platform `swagger-v3.v3.json`, Jira Service Management
 * `swagger.v3.json`), September 2026:
 *
 *  - `GET /rest/servicedeskapi/servicedesk` — "returns all the service desks in
 *    the Jira Service Management instance that the user has permission to
 *    access". Paged with `start` / `limit`; the envelope carries `values`,
 *    `size`, `start`, `limit`, `isLastPage` and `_links`. A `ServiceDeskDTO`
 *    is `{id, projectId, projectKey, projectName, projectTypeKey, _links}` —
 *    note it exposes the *peer project* key, which is the join back to the
 *    platform API. The operation is NOT flagged `x-experimental`, so it needs
 *    no `X-ExperimentalApi` header.
 *
 *  - `GET /rest/servicedeskapi/servicedesk/{serviceDeskId}/requesttype` —
 *    "returns all customer request types from a service desk", same paged
 *    envelope, also NOT experimental. A `RequestTypeDTO` is
 *    `{id, name, description, helpText, issueTypeId, serviceDeskId, groupIds,
 *    portalId, practice, …}`. **`issueTypeId` is the documented mapping from a
 *    JSM request type to a Jira issue type** — "ID of the issue type the
 *    request type is based upon" — which is exactly how this plugin turns a
 *    chosen request type into something `POST /rest/api/3/issue` understands.
 *
 *  - `GET /rest/servicedeskapi/requesttype` (every request type on the site in
 *    one call) IS flagged `x-experimental: true`, so it must carry
 *    `X-ExperimentalApi: opt-in` or Jira answers 412. It is used here only as
 *    an optimisation on instances with many desks.
 *
 *  - Plain Jira answers 404 on `/rest/servicedeskapi/*`. That means "this site
 *    has no Jira Service Management", not "the integration is broken", and is
 *    recorded as a note rather than an error.
 *
 *  - Teams. **The Jira Cloud platform REST API cannot list teams.** There is no
 *    `/rest/api/3/team` resource of any kind; the only team-shaped endpoints in
 *    the platform OpenAPI description are Advanced Roadmaps plan scoped
 *    (`GET /rest/api/3/plans/plan/{planId}/team`), which need Jira Premium, a
 *    plan id and *Administer Jira*, and only ever return the teams already
 *    added to that one plan. Atlassian Teams live on a different service
 *    entirely — `https://api.atlassian.com/public/teams/v1/org/{orgId}/teams`
 *    — which needs an organisation id (and a `siteId` for site-scoped teams),
 *    neither of which a Jira site URL and API token give you. So this class
 *    does not invent an endpoint: it enumerates the Team *custom field* and
 *    its selectable values when the field is option-backed (that is real,
 *    public and paged: `GET /rest/api/3/field/{fieldId}/context` then
 *    `GET /rest/api/3/field/{fieldId}/context/{contextId}/option`), and where
 *    the field is the Atlassian-Teams-backed one it says plainly that the
 *    values cannot be listed and falls back to what *is* listable — service
 *    desks, projects, groups (`GET /rest/api/3/groups/picker`) and project
 *    roles (`GET /rest/api/3/project/{key}/role`).
 *
 * Everything is cached in one transient for an hour, refreshable by hand from
 * the Jira routing screen, because this is reference data an operator reads
 * while filling in a form — not something to re-fetch on every page view.
 *
 * @package VulnHub\Jira
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Fetches and caches the Jira routing directory.
 */
final class VulnHub_Jira_Directory {

	/** Transient holding the whole snapshot. */
	private const TRANSIENT = 'vulnhub_jira_directory';

	/** Transient holding one project's assignable users. */
	private const USERS_TRANSIENT = 'vulnhub_jira_assignable_';

	/** How long a snapshot stays fresh. */
	private const TTL = HOUR_IN_SECONDS;

	/** Desks fetched individually before switching to the site-wide call. */
	private const DESK_FANOUT_LIMIT = 8;

	/** Page size for every paged call. */
	private const PAGE = 50;

	/** Hard ceiling on pages followed, so a broken cursor cannot loop. */
	private const MAX_PAGES = 20;

	/**
	 * The connector we borrow the client and the mode from.
	 */
	private VulnHub_Jira_Connector $connector;

	/**
	 * In-request memo so one page render costs at most one transient read.
	 *
	 * @var array<string,mixed>|null
	 */
	private ?array $memo = null;

	/**
	 * @param VulnHub_Jira_Connector $connector Registered Jira connector.
	 */
	public function __construct( VulnHub_Jira_Connector $connector ) {
		$this->connector = $connector;
	}

	/**
	 * The directory for the shared connector, or null when Jira is not registered.
	 */
	public static function instance(): ?self {
		$connector = vulnhub_jira_connector();

		return $connector ? new self( $connector ) : null;
	}

	/* =================================================================
	 * Cache
	 * ============================================================== */

	/**
	 * Cache key. Mock and live snapshots are kept apart so flipping the mode
	 * never serves the other one's data.
	 */
	private function cache_key(): string {
		return self::TRANSIENT . '_' . ( $this->connector->is_mock() ? 'mock' : 'live' );
	}

	/**
	 * The cached directory, fetching it if it is missing or stale.
	 *
	 * @param bool $refresh Force a re-fetch.
	 * @return array<string,mixed>
	 */
	public function snapshot( bool $refresh = false ): array {
		if ( ! $refresh && is_array( $this->memo ) ) {
			return $this->memo;
		}

		if ( ! $refresh ) {
			$cached = get_transient( $this->cache_key() );

			if ( is_array( $cached ) && ! empty( $cached['generated_at'] ) ) {
				$this->memo = $cached;

				return $cached;
			}
		}

		$snapshot   = $this->fetch();
		$this->memo = $snapshot;

		set_transient( $this->cache_key(), $snapshot, self::TTL );

		return $snapshot;
	}

	/**
	 * The cached directory without ever going to the network.
	 *
	 * @return array<string,mixed>|null
	 */
	public function cached(): ?array {
		if ( is_array( $this->memo ) ) {
			return $this->memo;
		}

		$cached = get_transient( $this->cache_key() );

		return is_array( $cached ) && ! empty( $cached['generated_at'] ) ? $cached : null;
	}

	/**
	 * Drop both cached snapshots.
	 */
	public function forget(): void {
		$this->memo = null;

		delete_transient( self::TRANSIENT . '_mock' );
		delete_transient( self::TRANSIENT . '_live' );
	}

	/* =================================================================
	 * Fetch
	 * ============================================================== */

	/**
	 * Build a fresh snapshot. Every leg degrades on its own: a site with no
	 * JSM, no Team field or no permission to browse groups still produces a
	 * usable directory of whatever it does expose.
	 *
	 * @return array<string,mixed>
	 */
	private function fetch(): array {
		$snapshot = array(
			'generated_at'  => vh_now(),
			'mode'          => $this->connector->is_mock() ? 'mock' : 'live',
			'ok'            => false,
			'jsm'           => false,
			'jsm_note'      => '',
			'service_desks' => array(),
			'projects'      => array(),
			'request_types' => array(),
			'team_field'    => $this->empty_team_field(),
			'groups'        => array(),
			'roles'         => array(),
			'notes'         => array(),
			'errors'        => array(),
		);

		if ( ! $this->connector->is_mock() && ! $this->connector->client()->has_credentials() ) {
			$snapshot['errors'][] = __( 'Jira has no site URL, account email or API token yet, so nothing can be discovered.', 'vulnhub' );

			return $snapshot;
		}

		$snapshot['projects']   = $this->fetch_projects( $snapshot );
		$desks                  = $this->fetch_service_desks( $snapshot );
		$snapshot['service_desks'] = $desks;

		if ( $desks ) {
			$snapshot['jsm']           = true;
			$snapshot['request_types'] = $this->fetch_request_types( $desks, $snapshot );
		}

		$snapshot['team_field'] = $this->fetch_team_field( $snapshot );
		$snapshot['groups']     = $this->fetch_groups( $snapshot );
		$snapshot['roles']      = $this->fetch_roles( $snapshot );
		$snapshot['ok']         = empty( $snapshot['errors'] );

		// Mark the projects that are service desks, so the routing screen can
		// say which project a JSM request type is even legal in.
		$desk_keys = array();

		foreach ( $desks as $desk ) {
			$desk_keys[ strtoupper( (string) $desk['project_key'] ) ] = (string) $desk['id'];
		}

		foreach ( $snapshot['projects'] as $i => $project ) {
			$key = strtoupper( (string) $project['key'] );

			$snapshot['projects'][ $i ]['service_desk_id'] = $desk_keys[ $key ] ?? '';
		}

		return $snapshot;
	}

	/**
	 * GET /rest/api/3/project/search.
	 *
	 * @param array<string,mixed> $snapshot Snapshot being built (by reference for notes).
	 * @return array<int,array<string,string>>
	 */
	private function fetch_projects( array &$snapshot ): array {
		$response = $this->connector->client()->projects( '', 100 );

		if ( ! $response->ok() ) {
			$snapshot['errors'][] = sprintf(
				/* translators: 1: HTTP status, 2: error message. */
				__( 'Could not list projects (GET /rest/api/3/project/search, HTTP %1$d): %2$s', 'vulnhub' ),
				$response->status,
				vh_trim( $response->error_message(), 160 )
			);

			return array();
		}

		$out = array();

		foreach ( (array) ( $response->data()['values'] ?? array() ) as $project ) {
			if ( ! is_array( $project ) ) {
				continue;
			}

			$out[] = array(
				'id'              => (string) ( $project['id'] ?? '' ),
				'key'             => strtoupper( (string) ( $project['key'] ?? '' ) ),
				'name'            => (string) ( $project['name'] ?? '' ),
				'type'            => (string) ( $project['projectTypeKey'] ?? '' ),
				'service_desk_id' => '',
			);
		}

		usort( $out, static fn( array $a, array $b ): int => strcmp( $a['key'], $b['key'] ) );

		return $out;
	}

	/**
	 * GET /rest/servicedeskapi/servicedesk, following the paged envelope.
	 *
	 * A 404 here is the documented shape of "this is plain Jira, not Jira
	 * Service Management" — it is recorded as a note, never as a failure.
	 *
	 * @param array<string,mixed> $snapshot Snapshot being built.
	 * @return array<int,array<string,string>>
	 */
	private function fetch_service_desks( array &$snapshot ): array {
		$out   = array();
		$start = 0;

		for ( $page = 0; $page < self::MAX_PAGES; $page++ ) {
			$response = $this->connector->client()->service_desks( $start, self::PAGE );

			if ( ! $response->ok() ) {
				if ( in_array( $response->status, array( 400, 403, 404 ), true ) ) {
					$snapshot['jsm_note'] = __( 'This Jira site did not answer the Service Management API (/rest/servicedeskapi), so it is being treated as plain Jira: there are no service desks or request types to route to. Everything else on this screen still works.', 'vulnhub' );
				} else {
					$snapshot['errors'][] = sprintf(
						/* translators: 1: HTTP status, 2: error message. */
						__( 'Could not list service desks (GET /rest/servicedeskapi/servicedesk, HTTP %1$d): %2$s', 'vulnhub' ),
						$response->status,
						vh_trim( $response->error_message(), 160 )
					);
				}

				return $out;
			}

			$data = $response->data();

			foreach ( (array) ( $data['values'] ?? array() ) as $desk ) {
				if ( ! is_array( $desk ) ) {
					continue;
				}

				$out[] = array(
					'id'           => (string) ( $desk['id'] ?? '' ),
					'project_id'   => (string) ( $desk['projectId'] ?? '' ),
					'project_key'  => strtoupper( (string) ( $desk['projectKey'] ?? '' ) ),
					'project_name' => (string) ( $desk['projectName'] ?? '' ),
					'project_type' => (string) ( $desk['projectTypeKey'] ?? '' ),
				);
			}

			if ( ! empty( $data['isLastPage'] ) || ! isset( $data['values'] ) || ! $data['values'] ) {
				break;
			}

			$start += self::PAGE;
		}

		return $out;
	}

	/**
	 * Request types for every discovered desk, keyed by service desk id.
	 *
	 * Few desks: one call each, using the stable non-experimental endpoint.
	 * Many desks: one site-wide call to the experimental
	 * `GET /rest/servicedeskapi/requesttype`, which must carry
	 * `X-ExperimentalApi: opt-in`, and is bucketed by `serviceDeskId`.
	 *
	 * @param array<int,array<string,string>> $desks    Discovered desks.
	 * @param array<string,mixed>             $snapshot Snapshot being built.
	 * @return array<string,array<int,array<string,mixed>>>
	 */
	private function fetch_request_types( array $desks, array &$snapshot ): array {
		$types = array();

		foreach ( $desks as $desk ) {
			$types[ (string) $desk['id'] ] = array();
		}

		if ( count( $desks ) > self::DESK_FANOUT_LIMIT ) {
			$response = $this->connector->client()->all_request_types( 0, self::PAGE * 4 );

			if ( $response->ok() ) {
				foreach ( (array) ( $response->data()['values'] ?? array() ) as $type ) {
					if ( ! is_array( $type ) ) {
						continue;
					}

					$desk_id = (string) ( $type['serviceDeskId'] ?? '' );

					if ( isset( $types[ $desk_id ] ) ) {
						$types[ $desk_id ][] = $this->request_type_row( $type );
					}
				}

				return $types;
			}

			$snapshot['notes'][] = sprintf(
				/* translators: %d: HTTP status. */
				__( 'The site-wide request type listing was refused (HTTP %d); falling back to one call per service desk.', 'vulnhub' ),
				$response->status
			);
		}

		foreach ( $desks as $desk ) {
			$desk_id = (string) $desk['id'];
			$start   = 0;

			for ( $page = 0; $page < self::MAX_PAGES; $page++ ) {
				$response = $this->connector->client()->request_types( $desk_id, $start, self::PAGE );

				if ( ! $response->ok() ) {
					$snapshot['notes'][] = sprintf(
						/* translators: 1: service desk id, 2: HTTP status. */
						__( 'No request types could be read for service desk %1$s (HTTP %2$d) — the API token may not have access to that desk.', 'vulnhub' ),
						$desk_id,
						$response->status
					);
					break;
				}

				$data = $response->data();

				foreach ( (array) ( $data['values'] ?? array() ) as $type ) {
					if ( is_array( $type ) ) {
						$types[ $desk_id ][] = $this->request_type_row( $type );
					}
				}

				if ( ! empty( $data['isLastPage'] ) || empty( $data['values'] ) ) {
					break;
				}

				$start += self::PAGE;
			}
		}

		return $types;
	}

	/**
	 * Normalise one RequestTypeDTO.
	 *
	 * @param array<string,mixed> $type Raw request type.
	 * @return array<string,mixed>
	 */
	private function request_type_row( array $type ): array {
		return array(
			'id'            => (string) ( $type['id'] ?? '' ),
			'name'          => (string) ( $type['name'] ?? '' ),
			'description'   => (string) ( $type['description'] ?? '' ),
			'help_text'     => (string) ( $type['helpText'] ?? '' ),
			// The documented bridge from a JSM request type to a Jira issue type.
			'issue_type_id' => (string) ( $type['issueTypeId'] ?? '' ),
			'desk_id'       => (string) ( $type['serviceDeskId'] ?? '' ),
			'portal_id'     => (string) ( $type['portalId'] ?? '' ),
			'group_ids'     => array_values( array_map( 'strval', (array) ( $type['groupIds'] ?? array() ) ) ),
		);
	}

	/**
	 * The shape returned when there is no Team field to talk about.
	 *
	 * @return array<string,mixed>
	 */
	private function empty_team_field(): array {
		return array(
			'id'         => '',
			'name'       => '',
			'type'       => '',
			'write'      => '',
			'enumerable' => false,
			'options'    => array(),
			'note'       => '',
		);
	}

	/**
	 * Find the Team custom field and, where the API allows it, its values.
	 *
	 * `GET /rest/api/3/field` returns every field with a `schema.custom` URI.
	 * The Atlassian-Teams-backed Team field is
	 * `com.atlassian.teams:rm-teams-custom-field-team`, and its value on an
	 * issue is a bare team id string, e.g.
	 * `"customfield_10001": "36885b3c-1bf0-4f85-a357-c5b858c31de4"`.
	 * An option-backed field (a plain select called Team, which plenty of
	 * sites use instead) takes `{"value": "…"}` or `{"id": "…"}` and *can* be
	 * enumerated through the custom field context option endpoints.
	 *
	 * @param array<string,mixed> $snapshot Snapshot being built.
	 * @return array<string,mixed>
	 */
	private function fetch_team_field( array &$snapshot ): array {
		$field = $this->empty_team_field();

		$response = $this->connector->client()->fields();

		if ( ! $response->ok() ) {
			$snapshot['errors'][] = sprintf(
				/* translators: 1: HTTP status, 2: error message. */
				__( 'Could not list fields (GET /rest/api/3/field, HTTP %1$d): %2$s', 'vulnhub' ),
				$response->status,
				vh_trim( $response->error_message(), 160 )
			);

			return $field;
		}

		$configured = trim( (string) $this->connector->get( 'team_field', '' ) );
		$best       = null;

		foreach ( (array) $response->data() as $candidate ) {
			if ( ! is_array( $candidate ) ) {
				continue;
			}

			$id     = (string) ( $candidate['id'] ?? '' );
			$name   = (string) ( $candidate['name'] ?? '' );
			$custom = (string) ( $candidate['schema']['custom'] ?? '' );

			if ( '' !== $configured ) {
				if ( $id === $configured ) {
					$best = $candidate;
					break;
				}
				continue;
			}

			if ( str_contains( $custom, 'teams:rm-teams-custom-field-team' ) || str_contains( $custom, 'atlassian-team' ) ) {
				$best = $candidate;
				break;
			}

			if ( null === $best && ! empty( $candidate['custom'] ) && 0 === strcasecmp( $name, 'Team' ) ) {
				$best = $candidate;
			}
		}

		if ( ! is_array( $best ) ) {
			$field['note'] = '' !== $configured
				? sprintf(
					/* translators: %s: configured field id. */
					__( 'The configured Team field "%s" does not exist on this Jira site.', 'vulnhub' ),
					$configured
				)
				: __( 'This Jira site exposes no Team custom field, so tickets cannot carry a team value.', 'vulnhub' );

			return $field;
		}

		$field['id']   = (string) ( $best['id'] ?? '' );
		$field['name'] = (string) ( $best['name'] ?? '' );
		$field['type'] = (string) ( $best['schema']['custom'] ?? ( $best['schema']['type'] ?? '' ) );

		if ( str_contains( $field['type'], 'teams:rm-teams-custom-field-team' ) || str_contains( $field['type'], 'atlassian-team' ) ) {
			$field['write']      = 'id';
			$field['enumerable'] = false;
			$field['note']       = __( 'This is the Atlassian Teams field. Its value is a team id, and the Jira Cloud REST API has no endpoint that lists teams — Atlassian Teams are served by api.atlassian.com/public/teams/v1/org/{orgId}/teams, which needs an organisation id (and a site id for site-scoped teams) that a Jira site URL and API token do not provide. Paste the team id from the Team field on any issue, or from the team\'s URL in Atlassian Home.', 'vulnhub' );

			return $field;
		}

		$field['write']   = 'value';
		$field['options'] = $this->fetch_field_options( $field['id'], $snapshot );

		$field['enumerable'] = (bool) $field['options'];

		if ( ! $field['enumerable'] ) {
			$field['note'] = __( 'The Team field has no selectable options this token can read, so the team value has to be typed in.', 'vulnhub' );
		}

		return $field;
	}

	/**
	 * Options of an option-backed custom field, across all of its contexts.
	 *
	 * @param string              $field_id Custom field id.
	 * @param array<string,mixed> $snapshot Snapshot being built.
	 * @return array<int,array<string,string>>
	 */
	private function fetch_field_options( string $field_id, array &$snapshot ): array {
		if ( '' === $field_id ) {
			return array();
		}

		$contexts = $this->connector->client()->field_contexts( $field_id );

		if ( ! $contexts->ok() ) {
			$snapshot['notes'][] = sprintf(
				/* translators: 1: field id, 2: HTTP status. */
				__( 'The contexts of field %1$s could not be read (HTTP %2$d), so its values are not listed. Reading custom field contexts needs Administer Jira.', 'vulnhub' ),
				$field_id,
				$contexts->status
			);

			return array();
		}

		$out  = array();
		$seen = array();

		foreach ( (array) ( $contexts->data()['values'] ?? array() ) as $context ) {
			if ( ! is_array( $context ) ) {
				continue;
			}

			$context_id = (string) ( $context['id'] ?? '' );

			if ( '' === $context_id ) {
				continue;
			}

			$options = $this->connector->client()->field_context_options( $field_id, $context_id );

			if ( ! $options->ok() ) {
				continue;
			}

			foreach ( (array) ( $options->data()['values'] ?? array() ) as $option ) {
				if ( ! is_array( $option ) || ! empty( $option['disabled'] ) ) {
					continue;
				}

				$value = (string) ( $option['value'] ?? '' );

				if ( '' === $value || isset( $seen[ $value ] ) ) {
					continue;
				}

				$seen[ $value ] = true;

				$out[] = array(
					'id'    => (string) ( $option['id'] ?? '' ),
					'value' => $value,
				);
			}
		}

		return $out;
	}

	/**
	 * GET /rest/api/3/groups/picker — the listable stand-in for teams on a site
	 * that has no enumerable Team field.
	 *
	 * @param array<string,mixed> $snapshot Snapshot being built.
	 * @return array<int,array<string,string>>
	 */
	private function fetch_groups( array &$snapshot ): array {
		$response = $this->connector->client()->groups( '', self::PAGE );

		if ( ! $response->ok() ) {
			$snapshot['notes'][] = sprintf(
				/* translators: %d: HTTP status. */
				__( 'Groups could not be listed (HTTP %d) — browsing users and groups is a global permission this token may not hold.', 'vulnhub' ),
				$response->status
			);

			return array();
		}

		$out = array();

		foreach ( (array) ( $response->data()['groups'] ?? array() ) as $group ) {
			if ( ! is_array( $group ) ) {
				continue;
			}

			$out[] = array(
				'id'   => (string) ( $group['groupId'] ?? '' ),
				'name' => (string) ( $group['name'] ?? '' ),
			);
		}

		return $out;
	}

	/**
	 * GET /rest/api/3/project/{key}/role for the default project only — one
	 * call, because project roles are shared across every project in Jira Cloud.
	 *
	 * @param array<string,mixed> $snapshot Snapshot being built.
	 * @return array<string,string> Role name => role URL.
	 */
	private function fetch_roles( array &$snapshot ): array {
		$project = $this->connector->default_project();

		if ( '' === $project ) {
			return array();
		}

		$response = $this->connector->client()->project_roles( $project );

		if ( ! $response->ok() ) {
			$snapshot['notes'][] = sprintf(
				/* translators: 1: project key, 2: HTTP status. */
				__( 'Project roles for %1$s could not be read (HTTP %2$d).', 'vulnhub' ),
				$project,
				$response->status
			);

			return array();
		}

		$out = array();

		foreach ( (array) $response->data() as $name => $url ) {
			$out[ (string) $name ] = (string) $url;
		}

		ksort( $out );

		return $out;
	}

	/* =================================================================
	 * Reads used by the routing screen and the ticketer
	 * ============================================================== */

	/**
	 * Users assignable in a project. Cached separately for 15 minutes because
	 * it is per-project and much more volatile than the rest.
	 *
	 * @param string $project_key Project key.
	 * @param string $query       Optional search term.
	 * @return array<int,array<string,string>>
	 */
	public function assignable_users( string $project_key, string $query = '' ): array {
		$project_key = strtoupper( trim( $project_key ) );

		if ( '' === $project_key ) {
			return array();
		}

		$key    = self::USERS_TRANSIENT . md5( $this->cache_key() . '|' . $project_key . '|' . $query );
		$cached = get_transient( $key );

		if ( is_array( $cached ) ) {
			return $cached;
		}

		$response = $this->connector->client()->assignable_users( $project_key, $query, self::PAGE );
		$out      = array();

		if ( $response->ok() ) {
			foreach ( (array) $response->data() as $user ) {
				if ( ! is_array( $user ) || empty( $user['accountId'] ) ) {
					continue;
				}

				$out[] = array(
					'account_id'   => (string) $user['accountId'],
					'display_name' => (string) ( $user['displayName'] ?? '' ),
					'email'        => (string) ( $user['emailAddress'] ?? '' ),
				);
			}
		}

		set_transient( $key, $out, 15 * MINUTE_IN_SECONDS );

		return $out;
	}

	/**
	 * One service desk by id.
	 *
	 * @param string $desk_id Service desk id.
	 * @return array<string,string>|null
	 */
	public function service_desk( string $desk_id ): ?array {
		foreach ( (array) ( $this->snapshot()['service_desks'] ?? array() ) as $desk ) {
			if ( (string) $desk['id'] === trim( $desk_id ) ) {
				return $desk;
			}
		}

		return null;
	}

	/**
	 * The service desk whose peer project is this project key.
	 *
	 * @param string $project_key Project key.
	 * @return array<string,string>|null
	 */
	public function desk_for_project( string $project_key ): ?array {
		$project_key = strtoupper( trim( $project_key ) );

		if ( '' === $project_key ) {
			return null;
		}

		foreach ( (array) ( $this->snapshot()['service_desks'] ?? array() ) as $desk ) {
			if ( strtoupper( (string) $desk['project_key'] ) === $project_key ) {
				return $desk;
			}
		}

		return null;
	}

	/**
	 * Request types belonging to one desk.
	 *
	 * @param string $desk_id Service desk id.
	 * @return array<int,array<string,mixed>>
	 */
	public function request_types_for( string $desk_id ): array {
		$types = (array) ( $this->snapshot()['request_types'] ?? array() );

		return (array) ( $types[ trim( $desk_id ) ] ?? array() );
	}

	/**
	 * One request type, searched across every desk when no desk is given.
	 *
	 * @param string $request_type_id Request type id.
	 * @param string $desk_id         Optional desk to look in first.
	 * @return array<string,mixed>|null
	 */
	public function request_type( string $request_type_id, string $desk_id = '' ): ?array {
		$request_type_id = trim( $request_type_id );

		if ( '' === $request_type_id ) {
			return null;
		}

		$buckets = (array) ( $this->snapshot()['request_types'] ?? array() );

		if ( '' !== trim( $desk_id ) ) {
			$buckets = array( trim( $desk_id ) => (array) ( $buckets[ trim( $desk_id ) ] ?? array() ) );
		}

		foreach ( $buckets as $types ) {
			foreach ( (array) $types as $type ) {
				if ( is_array( $type ) && (string) $type['id'] === $request_type_id ) {
					return $type;
				}
			}
		}

		return null;
	}

	/**
	 * The discovered Team custom field.
	 *
	 * @return array<string,mixed>
	 */
	public function team_field(): array {
		$field = (array) ( $this->snapshot()['team_field'] ?? array() );

		return $field ?: $this->empty_team_field();
	}

	/**
	 * Every team value the directory could enumerate, for a picker.
	 *
	 * @return array<int,array<string,string>>
	 */
	public function team_values(): array {
		return (array) ( $this->team_field()['options'] ?? array() );
	}

	/**
	 * How stale the cached snapshot is, in seconds; -1 when there is none.
	 */
	public function age(): int {
		$cached = $this->cached();

		if ( ! $cached ) {
			return -1;
		}

		$ts = strtotime( ( (string) $cached['generated_at'] ) . ' UTC' );

		return false === $ts ? -1 : max( 0, time() - $ts );
	}
}
