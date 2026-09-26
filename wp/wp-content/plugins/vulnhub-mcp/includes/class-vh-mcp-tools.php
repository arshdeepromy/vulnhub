<?php
/**
 * The tool catalogue.
 *
 * Every tool declares the capability it needs, and that capability is checked
 * twice: once when the catalogue is listed, so an agent is never told about a
 * tool it cannot use, and again when the tool is called, because a client that
 * has cached an old list must not be able to reach past its role. The check is
 * `current_user_can()` against the token's owner -- the same function the
 * portal's own screens use, so there is exactly one definition of who may do
 * what, not two that can drift apart.
 *
 * Handlers delegate to the platform's own repositories and services rather
 * than touching the database, so an agent gets identity matching, ownership
 * rules, normalisation and audit logging for free, and cannot write a shape of
 * record the rest of the platform has never seen.
 *
 * @package VulnHub\MCP
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;
use VulnHub\Core\Coverage;
use VulnHub\Core\Exceptions;
use VulnHub\Core\Repo;
use VulnHub\Core\Tickets;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Tool definitions and their handlers.
 */
final class VulnHub_MCP_Tools {

	/**
	 * Every tool, keyed by name.
	 *
	 * Kept as one flat array rather than scattered registrations so that the
	 * complete surface an agent can reach is readable on one screen.
	 *
	 * @return array<string,array{title:string,description:string,cap:string,schema:array<string,mixed>,handler:callable}>
	 */
	public static function all(): array {
		$str  = array( 'type' => 'string' );
		$int  = array( 'type' => 'integer' );
		$bool = array( 'type' => 'boolean' );

		$tools = array(

			/* ---------------------------------------------------- reading */

			'vulnhub_summary' => array(
				'title'       => __( 'Estate summary', 'vulnhub' ),
				'description' => 'Headline counts for the whole estate: open findings by severity, findings past their SLA, assets, and coverage. Start here to size a problem before listing anything.',
				'cap'         => Caps::VIEW,
				'schema'      => array( 'type' => 'object', 'properties' => new stdClass() ),
				'handler'     => static fn( array $a ): array => array(
					'findings' => Repo::summary(),
					'coverage' => Coverage::summary(),
				),
			),

			'vulnhub_list_assets' => array(
				'title'       => __( 'List assets', 'vulnhub' ),
				'description' => 'Search and filter the asset inventory. Filters: search (hostname, IP, serial), coverage state, owner (has = a named owner, none = missing one), unowned, needs_user, has_vulns. Returns at most 100 at a time; page with offset.',
				'cap'         => Caps::VIEW,
				'schema'      => array(
					'type'       => 'object',
					'properties' => array(
						'search'     => $str,
						'coverage'   => $str,
						'owner'      => array( 'type' => 'string', 'enum' => array( 'has', 'none' ) ),
						'unowned'    => $bool,
						'needs_user' => $bool,
						'has_vulns'  => $bool,
						'orderby'    => $str,
						'order'      => $str,
						'limit'      => $int,
						'offset'     => $int,
					),
				),
				'handler'     => static fn( array $a ): array => Repo::assets( self::paged( $a ) ),
			),

			'vulnhub_get_asset' => array(
				'title'       => __( 'Get one asset', 'vulnhub' ),
				'description' => 'The full record for a single asset by its VulnHub id, including identifiers, ownership, classification and coverage state.',
				'cap'         => Caps::VIEW,
				'schema'      => array(
					'type'       => 'object',
					'properties' => array( 'id' => $int ),
					'required'   => array( 'id' ),
				),
				'handler'     => static fn( array $a ): array => array( 'asset' => Repo::asset( (int) ( $a['id'] ?? 0 ) ) ),
			),

			'vulnhub_list_findings' => array(
				'title'       => __( 'List findings', 'vulnhub' ),
				'description' => 'Search vulnerability findings. Filters: severity (critical|high|medium|low|info), state (open|reopened|fixed|open_any), overdue, has_ticket, excepted, team_id, owner_person_id, asset_type, search. Page with offset.',
				'cap'         => Caps::VIEW,
				'schema'      => array(
					'type'       => 'object',
					'properties' => array(
						'search'          => $str,
						'severity'        => $str,
						'state'           => $str,
						'asset_type'      => $str,
						'team_id'         => $int,
						'owner_person_id' => $int,
						'overdue'         => $bool,
						'has_ticket'      => $bool,
						'excepted'        => $bool,
						'orderby'         => $str,
						'order'           => $str,
						'limit'           => $int,
						'offset'          => $int,
					),
				),
				'handler'     => static fn( array $a ): array => Repo::findings( self::paged( $a ) ),
			),

			'vulnhub_breakdown' => array(
				'title'       => __( 'Break findings down', 'vulnhub' ),
				'description' => 'Open findings grouped by a dimension — team, asset_type, environment, criticality, location — with severity splits. Use this instead of listing thousands of findings to answer "who carries the most".',
				'cap'         => Caps::VIEW,
				'schema'      => array(
					'type'       => 'object',
					'properties' => array( 'dimension' => $str, 'limit' => $int ),
				),
				'handler'     => static fn( array $a ): array => Repo::breakdown(
					(string) ( $a['dimension'] ?? 'team' ),
					self::clamp( (int) ( $a['limit'] ?? 10 ), 1, 50 )
				),
			),

			'vulnhub_top_vulnerabilities' => array(
				'title'       => __( 'Most widespread vulnerabilities', 'vulnhub' ),
				'description' => 'The vulnerabilities present on the most assets, worst first. The shortlist for a patching campaign.',
				'cap'         => Caps::VIEW,
				'schema'      => array( 'type' => 'object', 'properties' => array( 'limit' => $int ) ),
				'handler'     => static fn( array $a ): array => Repo::top_vulns( self::clamp( (int) ( $a['limit'] ?? 10 ), 1, 50 ) ),
			),

			'vulnhub_coverage' => array(
				'title'       => __( 'Tenable coverage', 'vulnhub' ),
				'description' => 'How much of the estate Tenable actually reaches, overall and broken down by a dimension. Coverage gaps are the findings you do not have. This is the vulnerability scanner only; Defender sensor coverage is a separate number.',
				'cap'         => Caps::VIEW,
				'schema'      => array(
					'type'       => 'object',
					'properties' => array( 'dimension' => $str, 'limit' => $int ),
				),
				'handler'     => static fn( array $a ): array => array(
					'summary'     => Coverage::summary(),
					'by_dimension' => Coverage::by_dimension(
						(string) ( $a['dimension'] ?? 'asset_type' ),
						self::clamp( (int) ( $a['limit'] ?? 12 ), 1, 50 )
					),
				),
			),

			'vulnhub_coverage_gaps' => array(
				'title'       => __( 'Assets Tenable is missing', 'vulnhub' ),
				'description' => 'Assets in the CMDB that Tenable has never scanned or does not know about. The work list for closing coverage.',
				'cap'         => Caps::VIEW,
				'schema'      => array(
					'type'       => 'object',
					'properties' => array(
						'state'      => $str,
						'asset_type' => $str,
						'search'     => $str,
						'limit'      => $int,
						'offset'     => $int,
					),
				),
				'handler'     => static fn( array $a ): array => Coverage::gaps( self::paged( $a ) ),
			),

			'vulnhub_list_tickets' => array(
				'title'       => __( 'List remediation tickets', 'vulnhub' ),
				'description' => 'Jira tickets raised against findings, with their state and verification outcome.',
				'cap'         => Caps::VIEW,
				'schema'      => array(
					'type'       => 'object',
					'properties' => array( 'status' => $str, 'search' => $str, 'limit' => $int, 'offset' => $int ),
				),
				'handler'     => static fn( array $a ): array => Tickets::query( self::paged( $a ) ),
			),

			'vulnhub_list_exceptions' => array(
				'title'       => __( 'List risk exceptions', 'vulnhub' ),
				'description' => 'Accepted-risk exceptions, with scope, reason, expiry and who approved them.',
				'cap'         => Caps::VIEW,
				'schema'      => array(
					'type'       => 'object',
					'properties' => array( 'status' => $str, 'search' => $str, 'limit' => $int, 'offset' => $int ),
				),
				'handler'     => static fn( array $a ): array => Exceptions::query( self::paged( $a ) ),
			),

			'vulnhub_list_teams' => array(
				'title'       => __( 'List teams', 'vulnhub' ),
				'description' => 'Remediation teams, the unit ownership rules and Jira routing work in.',
				'cap'         => Caps::VIEW,
				'schema'      => array( 'type' => 'object', 'properties' => new stdClass() ),
				'handler'     => static fn( array $a ): array => array( 'teams' => Repo::teams() ),
			),

			'vulnhub_sync_activity' => array(
				'title'       => __( 'Recent connector runs', 'vulnhub' ),
				'description' => 'The last connector syncs with their outcome and record counts — the first place to look when data has gone stale.',
				'cap'         => Caps::VIEW,
				'schema'      => array( 'type' => 'object', 'properties' => array( 'limit' => $int, 'connector' => $str ) ),
				'handler'     => static fn( array $a ): array => array(
					'runs' => vulnhub()->logger->recent_runs(
						self::clamp( (int) ( $a['limit'] ?? 20 ), 1, 100 ),
						(string) ( $a['connector'] ?? '' )
					),
				),
			),

			'vulnhub_audit_trail' => array(
				'title'       => __( 'Audit trail', 'vulnhub' ),
				'description' => 'Who changed what, and when. Covers sign-ins, account changes, configuration edits and triage decisions.',
				'cap'         => Caps::VIEW_AUDIT,
				'schema'      => array(
					'type'       => 'object',
					'properties' => array( 'action' => $str, 'limit' => $int ),
				),
				'handler'     => array( __CLASS__, 'audit' ),
			),

			/* -------------------------------------------- writing: estate */

			'vulnhub_update_asset' => array(
				'title'       => __( 'Correct an asset', 'vulnhub' ),
				'description' => 'Update classification, ownership or identifiers on one asset. Writes through the same path the connectors use, so identity matching and the ownership engine behave normally. Fields: hostname, fqdn, ipv4, mac_address, serial_number, asset_type, operating_system, os_version, manufacturer, model, criticality, environment, business_service, lifecycle_status, cmdb_id, intune_id, tenable_uuid, azure_ad_device_id.',
				'cap'         => Caps::MANAGE,
				'schema'      => array(
					'type'       => 'object',
					'properties' => array(
						'id'     => $int,
						'fields' => array( 'type' => 'object' ),
					),
					'required'   => array( 'id', 'fields' ),
				),
				'handler'     => array( __CLASS__, 'update_asset' ),
			),

			'vulnhub_request_exception' => array(
				'title'       => __( 'Request a risk exception', 'vulnhub' ),
				'description' => 'Raise an accepted-risk request. It is created pending and still needs an approver — this tool cannot approve anything.',
				'cap'         => Caps::REQUEST_EXCEPTION,
				'schema'      => array(
					'type'       => 'object',
					'properties' => array(
						'scope_type'  => $str,
						'scope_value' => $str,
						'reason'      => $str,
						'note'        => $str,
						'expires_at'  => $str,
					),
					'required'   => array( 'scope_type', 'scope_value', 'reason' ),
				),
				'handler'     => static fn( array $a ): array => Exceptions::create( $a ),
			),

			'vulnhub_decide_exception' => array(
				'title'       => __( 'Approve or reject an exception', 'vulnhub' ),
				'description' => 'Decide a pending risk exception. The decision, the decider and the note are written to the audit trail.',
				'cap'         => Caps::APPROVE_EXCEPTION,
				'schema'      => array(
					'type'       => 'object',
					'properties' => array(
						'id'       => $int,
						'decision' => $str,
						'note'     => $str,
					),
					'required'   => array( 'id', 'decision' ),
				),
				'handler'     => static fn( array $a ): array => Exceptions::decide(
					(int) ( $a['id'] ?? 0 ),
					(string) ( $a['decision'] ?? '' ),
					(string) ( $a['note'] ?? '' )
				),
			),

			/* --------------------------------------- writing: platform config */

			'vulnhub_get_settings' => array(
				'title'       => __( 'Read platform settings', 'vulnhub' ),
				'description' => 'Platform-wide settings: organisation name, SLA windows, ownership policy, retention, mock mode.',
				'cap'         => Caps::MANAGE,
				'schema'      => array( 'type' => 'object', 'properties' => new stdClass() ),
				'handler'     => static fn( array $a ): array => array(
					'settings' => (array) get_option( 'vulnhub_platform', array() ),
				),
			),

			'vulnhub_update_settings' => array(
				'title'       => __( 'Change platform settings', 'vulnhub' ),
				'description' => 'Merge values into the platform settings. Only the keys you pass are changed.',
				'cap'         => Caps::MANAGE,
				'schema'      => array(
					'type'       => 'object',
					'properties' => array( 'values' => array( 'type' => 'object' ) ),
					'required'   => array( 'values' ),
				),
				'handler'     => array( __CLASS__, 'update_settings' ),
			),

			'vulnhub_list_connectors' => array(
				'title'       => __( 'List integrations', 'vulnhub' ),
				'description' => 'Every connector with its health, whether it is enabled, whether it is on mock data, and its schedule.',
				'cap'         => Caps::MANAGE,
				'schema'      => array( 'type' => 'object', 'properties' => new stdClass() ),
				'handler'     => array( __CLASS__, 'list_connectors' ),
			),

			'vulnhub_get_connector' => array(
				'title'       => __( 'Read one integration', 'vulnhub' ),
				'description' => 'A connector\'s settings and field definitions. Secrets are never returned — only whether each one is set.',
				'cap'         => Caps::MANAGE,
				'schema'      => array(
					'type'       => 'object',
					'properties' => array( 'id' => $str ),
					'required'   => array( 'id' ),
				),
				'handler'     => array( __CLASS__, 'get_connector' ),
			),

			'vulnhub_update_connector' => array(
				'title'       => __( 'Configure an integration', 'vulnhub' ),
				'description' => 'Change a connector\'s settings, including enabling it, turning mock mode off, and setting credentials. Secret fields are accepted and stored encrypted; they cannot be read back.',
				'cap'         => Caps::MANAGE,
				'schema'      => array(
					'type'       => 'object',
					'properties' => array(
						'id'      => $str,
						'values'  => array( 'type' => 'object' ),
						'secrets' => array( 'type' => 'object' ),
					),
					'required'   => array( 'id' ),
				),
				'handler'     => array( __CLASS__, 'update_connector' ),
			),

			'vulnhub_test_connector' => array(
				'title'       => __( 'Test an integration', 'vulnhub' ),
				'description' => 'Verify a connector\'s credentials against the vendor. Never writes platform data.',
				'cap'         => Caps::MANAGE,
				'schema'      => array(
					'type'       => 'object',
					'properties' => array( 'id' => $str ),
					'required'   => array( 'id' ),
				),
				'handler'     => array( __CLASS__, 'test_connector' ),
			),

			'vulnhub_sync_connector' => array(
				'title'       => __( 'Run a sync now', 'vulnhub' ),
				'description' => 'Trigger a connector sync immediately rather than waiting for its schedule. Can be long-running.',
				'cap'         => Caps::RUN_SYNC,
				'schema'      => array(
					'type'       => 'object',
					'properties' => array( 'id' => $str, 'full' => $bool ),
					'required'   => array( 'id' ),
				),
				'handler'     => array( __CLASS__, 'sync_connector' ),
			),

			/* ------------------------------------------- writing: people */

			'vulnhub_list_people' => array(
				'title'       => __( 'List portal accounts', 'vulnhub' ),
				'description' => 'Everyone with portal access, their role, status and MFA state. WordPress administrators are never listed.',
				'cap'         => Caps::MANAGE,
				'schema'      => array( 'type' => 'object', 'properties' => new stdClass() ),
				'handler'     => array( __CLASS__, 'list_people' ),
			),

			'vulnhub_create_person' => array(
				'title'       => __( 'Create a portal account', 'vulnhub' ),
				'description' => 'Create an account and email a one-time password link. Roles: vulnhub_admin, vulnhub_analyst, vulnhub_approver, vulnhub_viewer.',
				'cap'         => Caps::MANAGE,
				'schema'      => array(
					'type'       => 'object',
					'properties' => array(
						'email'        => $str,
						'display_name' => $str,
						'role'         => $str,
					),
					'required'   => array( 'email', 'role' ),
				),
				'handler'     => array( __CLASS__, 'create_person' ),
			),

			'vulnhub_update_person' => array(
				'title'       => __( 'Update a portal account', 'vulnhub' ),
				'description' => 'Change somebody\'s name, email, job title, phone, team or role.',
				'cap'         => Caps::MANAGE,
				'schema'      => array(
					'type'       => 'object',
					'properties' => array(
						'user_id'      => $int,
						'display_name' => $str,
						'email'        => $str,
						'job_title'    => $str,
						'phone'        => $str,
						'team_id'      => $int,
						'role'         => $str,
					),
					'required'   => array( 'user_id' ),
				),
				'handler'     => array( __CLASS__, 'update_person' ),
			),

			'vulnhub_set_person_access' => array(
				'title'       => __( 'Suspend or restore an account', 'vulnhub' ),
				'description' => 'Suspend somebody (ends every session and blocks sign-in, keeps their history) or restore them to the role they held.',
				'cap'         => Caps::MANAGE,
				'schema'      => array(
					'type'       => 'object',
					'properties' => array( 'user_id' => $int, 'suspended' => $bool ),
					'required'   => array( 'user_id', 'suspended' ),
				),
				'handler'     => array( __CLASS__, 'set_person_access' ),
			),
		);

		/**
		 * Lets another plugin add a tool to the agent surface.
		 *
		 * @param array<string,array<string,mixed>> $tools Tool definitions.
		 */
		return (array) apply_filters( 'vulnhub_mcp_tools', $tools );
	}

	/**
	 * The tools this user may actually call.
	 *
	 * @return array<string,array<string,mixed>>
	 */
	public static function available(): array {
		return array_filter(
			self::all(),
			static fn( array $tool ): bool => current_user_can( (string) $tool['cap'] )
		);
	}

	/* -----------------------------------------------------------------
	 * Shared argument handling
	 * --------------------------------------------------------------- */

	/**
	 * Clamp paging so one call cannot ask for the whole database.
	 *
	 * @param array<string,mixed> $args Tool arguments.
	 * @return array<string,mixed>
	 */
	private static function paged( array $args ): array {
		$args['limit']  = self::clamp( (int) ( $args['limit'] ?? 25 ), 1, 100 );
		$args['offset'] = max( 0, (int) ( $args['offset'] ?? 0 ) );

		return $args;
	}

	private static function clamp( int $value, int $min, int $max ): int {
		return max( $min, min( $max, $value ) );
	}

	/* -----------------------------------------------------------------
	 * Handlers that need more than a one-liner
	 * --------------------------------------------------------------- */

	/**
	 * @param array<string,mixed> $args Tool arguments.
	 * @return array<string,mixed>
	 */
	public static function audit( array $args ): array {
		return array(
			'entries' => vulnhub()->logger->audit_log(
				array(
					'action' => (string) ( $args['action'] ?? '' ),
					'limit'  => self::clamp( (int) ( $args['limit'] ?? 50 ), 1, 200 ),
				)
			),
		);
	}

	/**
	 * @param array<string,mixed> $args Tool arguments.
	 * @return array<string,mixed>
	 */
	public static function update_asset( array $args ): array {
		$writable = array(
			'hostname',
			'fqdn',
			'ipv4',
			'mac_address',
			'serial_number',
			'asset_type',
			'operating_system',
			'os_version',
			'manufacturer',
			'model',
			'criticality',
			'environment',
			'business_service',
			'lifecycle_status',
			'cmdb_id',
			'intune_id',
			'tenable_uuid',
			'azure_ad_device_id',
		);

		$id    = (int) ( $args['id'] ?? 0 );
		$asset = Repo::asset( $id );

		if ( ! $asset ) {
			throw new RuntimeException( 'No asset with that id.' );
		}

		$fields = (array) ( $args['fields'] ?? array() );
		$clean  = array_intersect_key( $fields, array_flip( $writable ) );

		if ( ! $clean ) {
			throw new RuntimeException( 'None of those fields can be written. Writable: ' . implode( ', ', $writable ) );
		}

		// Identity has to travel with the change or upsert_asset() will match
		// the wrong record -- it keys on the identifiers, not on our row id.
		$clean['cmdb_id']      = $clean['cmdb_id'] ?? (string) ( $asset['cmdb_id'] ?? '' );
		$clean['hostname']     = $clean['hostname'] ?? (string) ( $asset['hostname'] ?? '' );
		$clean['source']       = 'mcp';

		$result = Repo::upsert_asset( $clean );

		VulnHub_MCP_Server::audit(
			'asset.updated',
			sprintf( 'Asset "%s" corrected via the agent connector: %s', (string) ( $asset['hostname'] ?? $id ), implode( ', ', array_keys( array_intersect_key( $fields, array_flip( $writable ) ) ) ) ),
			array( 'asset_id' => $id, 'fields' => array_keys( $clean ) )
		);

		return array(
			'asset'   => Repo::asset( $id ),
			'changed' => array_keys( $clean ),
			'result'  => $result,
		);
	}

	/**
	 * @param array<string,mixed> $args Tool arguments.
	 * @return array<string,mixed>
	 */
	public static function update_settings( array $args ): array {
		$values = (array) ( $args['values'] ?? array() );

		if ( ! $values ) {
			throw new RuntimeException( 'Pass at least one setting in "values".' );
		}

		vulnhub()->settings->update_platform( $values );

		VulnHub_MCP_Server::audit(
			'settings.updated',
			'Platform settings changed via the agent connector: ' . implode( ', ', array_keys( $values ) ),
			array( 'keys' => array_keys( $values ) )
		);

		return array( 'settings' => (array) get_option( 'vulnhub_platform', array() ) );
	}

	/**
	 * @param array<string,mixed> $args Tool arguments.
	 * @return array<string,mixed>
	 */
	public static function list_connectors( array $args ): array {
		unset( $args );

		$out = array();

		foreach ( vulnhub()->connectors->all() as $id => $connector ) {
			$health = $connector->health();
			$last   = vulnhub()->logger->last_run( (string) $id );

			$out[] = array(
				'id'            => (string) $id,
				'label'         => $connector->label(),
				'category'      => $connector->category(),
				'enabled'       => $connector->is_enabled(),
				'mock'          => $connector->is_mock(),
				'configured'    => $connector->is_configured(),
				'supports_sync' => $connector->supports_sync(),
				'health'        => $health['label'],
				'detail'        => $health['detail'],
				'last_run'      => $last['finished_at'] ?? null,
			);
		}

		return array( 'connectors' => $out );
	}

	/**
	 * @param array<string,mixed> $args Tool arguments.
	 * @return array<string,mixed>
	 */
	public static function get_connector( array $args ): array {
		$id        = (string) ( $args['id'] ?? '' );
		$connector = vulnhub()->connectors->get( $id );

		if ( ! $connector ) {
			throw new RuntimeException( 'No connector with that id. Use vulnhub_list_connectors first.' );
		}

		$fields = array();

		foreach ( $connector->fields() as $field ) {
			$key      = (string) $field['key'];
			$is_secret = ! empty( $field['secret'] );

			$fields[] = array(
				'key'      => $key,
				'label'    => (string) $field['label'],
				'type'     => (string) ( $field['type'] ?? 'text' ),
				'secret'   => $is_secret,
				'required' => ! empty( $field['required'] ),
				'help'     => (string) ( $field['help'] ?? '' ),
				'options'  => $field['options'] ?? null,
				// A secret is reported as set or not set. It is never returned.
				'value'    => $is_secret
					? ( vulnhub()->settings->has_secret( $id, $key ) ? '(set)' : '' )
					: vulnhub()->settings->get( $id, $key, '' ),
			);
		}

		$health = $connector->health();

		return array(
			'id'      => $id,
			'label'   => $connector->label(),
			'enabled' => $connector->is_enabled(),
			'mock'    => $connector->is_mock(),
			'health'  => $health,
			'fields'  => $fields,
		);
	}

	/**
	 * @param array<string,mixed> $args Tool arguments.
	 * @return array<string,mixed>
	 */
	public static function update_connector( array $args ): array {
		$id        = (string) ( $args['id'] ?? '' );
		$connector = vulnhub()->connectors->get( $id );

		if ( ! $connector ) {
			throw new RuntimeException( 'No connector with that id.' );
		}

		$values  = (array) ( $args['values'] ?? array() );
		$secrets = (array) ( $args['secrets'] ?? array() );

		if ( $values ) {
			vulnhub()->settings->update( $id, $values );
		}

		foreach ( $secrets as $key => $value ) {
			vulnhub()->settings->set_secret( $id, (string) $key, (string) $value );
		}

		if ( isset( $values['interval'] ) || isset( $values['enabled'] ) ) {
			vulnhub()->scheduler->ensure_schedules();
		}

		VulnHub_MCP_Server::audit(
			'connector.updated',
			sprintf( '%s reconfigured via the agent connector', $connector->label() ),
			array(
				'connector' => $id,
				'keys'      => array_keys( $values ),
				'secrets'   => array_keys( $secrets ),
			)
		);

		return self::get_connector( array( 'id' => $id ) );
	}

	/**
	 * @param array<string,mixed> $args Tool arguments.
	 * @return array<string,mixed>
	 */
	public static function test_connector( array $args ): array {
		$connector = vulnhub()->connectors->get( (string) ( $args['id'] ?? '' ) );

		if ( ! $connector ) {
			throw new RuntimeException( 'No connector with that id.' );
		}

		return (array) $connector->test_connection();
	}

	/**
	 * @param array<string,mixed> $args Tool arguments.
	 * @return array<string,mixed>
	 */
	public static function sync_connector( array $args ): array {
		$id        = (string) ( $args['id'] ?? '' );
		$connector = vulnhub()->connectors->get( $id );

		if ( ! $connector ) {
			throw new RuntimeException( 'No connector with that id.' );
		}
		if ( ! $connector->supports_sync() ) {
			throw new RuntimeException( 'That connector does not import anything, so there is nothing to sync.' );
		}

		VulnHub_MCP_Server::audit(
			'connector.sync',
			sprintf( '%s sync started via the agent connector', $connector->label() ),
			array( 'connector' => $id )
		);

		$full = ! empty( $args['full'] );

		// Same routing as the REST endpoint: a long-running connector is queued
		// rather than run inside the agent's request, and a full resync is
		// recorded on the connector so the queued run picks it up.
		if ( $connector->async_sync() ) {
			if ( $full && $connector->supports_full_sync() ) {
				$connector->request_full_sync();
			}

			\VulnHub\Core\Scheduler::queue_sync( $id );

			return array(
				'ok'      => true,
				'queued'  => true,
				'full'    => $full && $connector->supports_full_sync(),
				'message' => 'Sync queued in the background. Poll the connector status or the sync activity log for progress.',
			);
		}

		return (array) $connector->sync( array( 'full' => $full ) );
	}

	/* ------------------------------------------------------------ people */

	private static function people(): string {
		if ( ! class_exists( 'VulnHub_Auth_People' ) ) {
			throw new RuntimeException( 'Account management is unavailable — VulnHub Authentication is not active.' );
		}

		return 'VulnHub_Auth_People';
	}

	/**
	 * @param array<string,mixed> $args Tool arguments.
	 * @return array<string,mixed>
	 */
	public static function list_people( array $args ): array {
		unset( $args );

		$people = self::people();
		$roles  = $people::roles();
		$teams  = $people::teams();
		$out    = array();

		foreach ( $people::manageable() as $user ) {
			$profile = $people::profile( $user );
			$mfa     = $people::mfa( $user );
			$role    = $people::role_of( $user );

			$out[] = array(
				'user_id'   => (int) $user->ID,
				'name'      => $user->display_name,
				'username'  => $user->user_login,
				'email'     => $user->user_email,
				'role'      => $role,
				'role_label' => $roles[ $role ] ?? '',
				'job_title' => $profile['title'],
				'phone'     => $profile['phone'],
				'team'      => $teams[ $profile['team_id'] ] ?? '',
				'suspended' => $people::is_suspended( $user ),
				'invited'   => $people::is_invited( $user ),
				'mfa'       => ! empty( $mfa['enabled'] ),
			);
		}

		return array( 'people' => $out );
	}

	/**
	 * @param array<string,mixed> $args Tool arguments.
	 * @return array<string,mixed>
	 */
	public static function create_person( array $args ): array {
		$people = self::people();
		$email  = sanitize_email( (string) ( $args['email'] ?? '' ) );
		$role   = (string) ( $args['role'] ?? '' );

		if ( ! is_email( $email ) ) {
			throw new RuntimeException( 'That is not a valid email address.' );
		}
		if ( ! isset( $people::roles()[ $role ] ) ) {
			throw new RuntimeException( 'Unknown role. Valid roles: ' . implode( ', ', array_keys( $people::roles() ) ) );
		}
		if ( email_exists( $email ) ) {
			throw new RuntimeException( 'Somebody already has that email address.' );
		}

		$login = sanitize_user( (string) strstr( $email, '@', true ), true ) ?: 'user';
		$try   = $login;
		$n     = 1;

		while ( username_exists( $try ) ) {
			++$n;
			$try = $login . $n;
		}

		$name    = (string) ( $args['display_name'] ?? '' );
		$user_id = wp_insert_user(
			array(
				'user_login'   => $try,
				'user_email'   => $email,
				'user_pass'    => wp_generate_password( 32, true, true ),
				'display_name' => '' !== $name ? $name : $try,
				'role'         => $role,
			)
		);

		if ( is_wp_error( $user_id ) ) {
			throw new RuntimeException( (string) $user_id->get_error_message() );
		}

		$user = get_userdata( (int) $user_id );
		update_user_meta( (int) $user_id, $people::INVITED_META, (string) time() );

		$link = $people::invite_link( $user );
		$sent = $people::send_invite( $user, $link, true );

		VulnHub_MCP_Server::audit(
			'user.created',
			sprintf( 'Portal account "%s" created via the agent connector as %s', $user->user_login, $people::roles()[ $role ] ),
			array( 'user_id' => (int) $user_id, 'role' => $role, 'invite_sent' => $sent ),
			'critical'
		);

		return array(
			'user_id'     => (int) $user_id,
			'username'    => $user->user_login,
			'invite_sent' => $sent,
			// Handed back only when the email did not get out, so the operator
			// has something to pass on.
			'invite_link' => $sent ? null : $link,
		);
	}

	/**
	 * @param array<string,mixed> $args Tool arguments.
	 * @return array<string,mixed>
	 */
	public static function update_person( array $args ): array {
		$people  = self::people();
		$user_id = (int) ( $args['user_id'] ?? 0 );

		if ( ! $people::is_manageable( $user_id ) ) {
			throw new RuntimeException( 'That account cannot be managed from here.' );
		}

		$user    = get_userdata( $user_id );
		$changed = array();
		$update  = array( 'ID' => $user_id );

		if ( ! empty( $args['display_name'] ) ) {
			$update['display_name'] = (string) $args['display_name'];
			$changed[]              = 'name';
		}

		if ( ! empty( $args['email'] ) ) {
			$email  = sanitize_email( (string) $args['email'] );
			$holder = $email ? (int) email_exists( $email ) : 0;

			if ( ! is_email( $email ) ) {
				throw new RuntimeException( 'That is not a valid email address.' );
			}
			if ( $holder && $holder !== $user_id ) {
				throw new RuntimeException( 'Somebody else already has that email address.' );
			}

			$update['user_email'] = $email;
			$changed[]            = 'email';
		}

		if ( count( $update ) > 1 ) {
			$result = wp_update_user( $update );

			if ( is_wp_error( $result ) ) {
				throw new RuntimeException( (string) $result->get_error_message() );
			}
		}

		foreach ( array( 'job_title' => $people::TITLE_META, 'phone' => $people::PHONE_META ) as $arg => $meta ) {
			if ( ! isset( $args[ $arg ] ) ) {
				continue;
			}
			$value = (string) $args[ $arg ];
			if ( '' === $value ) {
				delete_user_meta( $user_id, $meta );
			} else {
				update_user_meta( $user_id, $meta, $value );
			}
			$changed[] = $arg;
		}

		if ( isset( $args['team_id'] ) ) {
			$team = (int) $args['team_id'];
			if ( $team > 0 && isset( $people::teams()[ $team ] ) ) {
				update_user_meta( $user_id, $people::TEAM_META, $team );
			} else {
				delete_user_meta( $user_id, $people::TEAM_META );
			}
			$changed[] = 'team';
		}

		if ( ! empty( $args['role'] ) ) {
			$role = (string) $args['role'];

			if ( ! isset( $people::roles()[ $role ] ) ) {
				throw new RuntimeException( 'Unknown role.' );
			}
			if ( $user_id === get_current_user_id() ) {
				throw new RuntimeException( 'A connector cannot change the role of the account it authenticates as.' );
			}

			if ( $people::is_suspended( $user ) ) {
				update_user_meta( $user_id, $people::SUSPENDED_META, $role );
			} else {
				$user->set_role( $role );
			}

			$changed[] = 'role';
		}

		if ( ! $changed ) {
			return array( 'changed' => array(), 'message' => 'Nothing was different.' );
		}

		VulnHub_MCP_Server::audit(
			'user.updated',
			sprintf( '"%s" updated via the agent connector: %s', $user->user_login, implode( ', ', $changed ) ),
			array( 'user_id' => $user_id, 'fields' => $changed ),
			in_array( 'role', $changed, true ) || in_array( 'email', $changed, true ) ? 'critical' : 'warning'
		);

		return array( 'user_id' => $user_id, 'changed' => $changed );
	}

	/**
	 * @param array<string,mixed> $args Tool arguments.
	 * @return array<string,mixed>
	 */
	public static function set_person_access( array $args ): array {
		$people  = self::people();
		$user_id = (int) ( $args['user_id'] ?? 0 );
		$suspend = ! empty( $args['suspended'] );

		if ( ! $people::is_manageable( $user_id ) ) {
			throw new RuntimeException( 'That account cannot be managed from here.' );
		}
		if ( $suspend && $user_id === get_current_user_id() ) {
			throw new RuntimeException( 'A connector cannot suspend the account it authenticates as.' );
		}

		$user = get_userdata( $user_id );

		if ( $suspend ) {
			update_user_meta( $user_id, $people::SUSPENDED_META, $people::role_of( $user ) );
			$user->set_role( '' );
			WP_Session_Tokens::get_instance( $user_id )->destroy_all();
		} else {
			$role = (string) get_user_meta( $user_id, $people::SUSPENDED_META, true );
			$role = isset( $people::roles()[ $role ] ) ? $role : 'vulnhub_viewer';

			delete_user_meta( $user_id, $people::SUSPENDED_META );
			$user->set_role( $role );
		}

		VulnHub_MCP_Server::audit(
			$suspend ? 'user.suspended' : 'user.reactivated',
			sprintf(
				$suspend ? 'Access suspended for "%s" via the agent connector' : 'Access restored for "%s" via the agent connector',
				$user->user_login
			),
			array( 'user_id' => $user_id ),
			'critical'
		);

		return array( 'user_id' => $user_id, 'suspended' => $suspend );
	}
}

