<?php
/**
 * ServiceNow Table API client.
 *
 * Verified against the ServiceNow Table API reference:
 *
 *   GET {instance}/api/now/table/{tableName}
 *     ?sysparm_query=...                encoded query, GlideRecord syntax
 *     &sysparm_fields=a,b,c             comma separated field allow list
 *     &sysparm_limit=1000               page size
 *     &sysparm_offset=0                 pagination offset
 *     &sysparm_display_value=true       see the note below
 *     &sysparm_exclude_reference_link=false
 *
 * Responses are wrapped in a single `result` key holding an array of records.
 *
 * `sysparm_display_value` is the parameter that matters most here. With the
 * default (`false`) a reference field such as `assigned_to`, `location` or
 * `support_group` comes back as `{"value":"<sys_id>","link":"<api url>"}` —
 * a 32-character GUID that means nothing to a human and nothing to our
 * people/teams tables. With `true`, the same field comes back as
 * `{"display_value":"Aroha Whitiora","link":"<api url>"}`, which is the name
 * we can actually resolve. That is why this client always asks for display
 * values, and why the normaliser reads `display_value` first.
 *
 * @package VulnHub\Cmdb
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Thin, read-only wrapper over the ServiceNow Table API.
 */
final class VulnHub_Cmdb_Servicenow_Client {

	/** Hard ceiling on pages fetched per table, so a bad filter cannot loop forever. */
	private const MAX_PAGES = 50;

	/**
	 * Instance base URL, without a trailing slash.
	 */
	private string $base_url;

	/**
	 * Integration user name.
	 */
	private string $username;

	/**
	 * Integration user password or API token.
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
	 * @param string                $base_url Instance URL, e.g. https://acme.service-now.com.
	 * @param string                $username Integration account user name.
	 * @param string                $token    Password or API token.
	 * @param \VulnHub\Core\Http    $http     Shared HTTP client.
	 * @param callable|null         $log      Logger callback.
	 */
	public function __construct( string $base_url, string $username, string $token, \VulnHub\Core\Http $http, ?callable $log = null ) {
		$this->base_url = untrailingslashit( trim( $base_url ) );
		$this->username = trim( $username );
		$this->token    = $token;
		$this->http     = $http;
		$this->log      = $log ?? static function ( string $message ): void {};
	}

	/**
	 * Do we have enough to talk to the instance?
	 */
	public function has_credentials(): bool {
		return '' !== $this->base_url && '' !== $this->username && '' !== $this->token;
	}

	/**
	 * Basic auth header. Never logged.
	 *
	 * @return array<string,string>
	 */
	private function headers(): array {
		return array(
			'Authorization' => 'Basic ' . base64_encode( $this->username . ':' . $this->token ),
			'Accept'        => 'application/json',
		);
	}

	/**
	 * The CI fields this integration reads.
	 *
	 * `os` and `os_version` are Computer-class fields rather than base
	 * `cmdb_ci` columns, but ServiceNow simply omits a field a table does not
	 * have rather than erroring, so one field list is safe across all three
	 * tables. `u_environment` is a customer-defined column — most instances
	 * add one, and the connector treats it as optional.
	 *
	 * Dot-walked fields are requested alongside the reference fields
	 * themselves. `sysparm_fields` accepts dot notation to reach a field on a
	 * referenced record, and ServiceNow returns each one as a FLAT key using
	 * that same dot notation — `"assigned_to.email": "a.b@x.com"` sits beside
	 * `"assigned_to": {"display_value": "...", "link": "..."}` in the record.
	 * That is the only way to get an address out of `assigned_to`, whose
	 * display value is a person's name, and a name cannot be looked up in the
	 * people table.
	 *
	 * @return array<int,string>
	 */
	public static function default_fields(): array {
		return array(
			'sys_id',
			'sys_class_name',
			'name',
			'fqdn',
			'serial_number',
			'asset_tag',
			'ip_address',
			'os',
			'os_version',
			'manufacturer',
			'model_id',
			'assigned_to',
			'managed_by',
			'support_group',
			'location',
			'company',
			'department',
			'install_status',
			'operational_status',
			'business_criticality',
			'u_environment',
			'short_description',
			'sys_updated_on',
			// Dot-walked: resolvable identities and a usable location.
			'assigned_to.email',
			'assigned_to.user_name',
			'assigned_to.name',
			'managed_by.email',
			'support_group.name',
			'location.name',
			'location.city',
			'location.country',
			'model_id.display_name',
		);
	}

	/**
	 * Fetch every record of one table, paging with sysparm_offset.
	 *
	 * @param string $table Table name, e.g. cmdb_ci_server.
	 * @param string $query Encoded query for sysparm_query ('' for none).
	 * @param int    $limit Page size.
	 * @return array{ok:bool,records:array<int,array<string,mixed>>,message:string,pages:int}
	 */
	public function table( string $table, string $query = '', int $limit = 500 ): array {
		$table = preg_replace( '/[^a-z0-9_]/i', '', $table ) ?? '';

		if ( '' === $table ) {
			return array(
				'ok'      => false,
				'records' => array(),
				'message' => __( 'Invalid table name.', 'vulnhub' ),
				'pages'   => 0,
			);
		}

		$limit   = max( 1, min( 10000, $limit ) );
		$offset  = 0;
		$pages   = 0;
		$records = array();
		$url     = $this->base_url . '/api/now/table/' . $table;

		while ( $pages < self::MAX_PAGES ) {
			$args = array(
				'sysparm_limit'                  => $limit,
				'sysparm_offset'                 => $offset,
				'sysparm_fields'                 => implode( ',', self::default_fields() ),
				'sysparm_display_value'          => 'true',
				'sysparm_exclude_reference_link' => 'false',
			);

			if ( '' !== trim( $query ) ) {
				$args['sysparm_query'] = trim( $query );
			}

			$response = $this->http->get( $url, $args, $this->headers() );
			++$pages;

			if ( ! $response->ok() ) {
				return array(
					'ok'      => false,
					'records' => $records,
					'message' => sprintf(
						/* translators: 1: table name, 2: HTTP status, 3: error text. */
						__( 'ServiceNow returned %2$d for %1$s: %3$s', 'vulnhub' ),
						$table,
						$response->status,
						vh_trim( $response->error_message(), 160 )
					),
					'pages'   => $pages,
				);
			}

			$data  = $response->data();
			$batch = isset( $data['result'] ) && is_array( $data['result'] ) ? $data['result'] : array();

			foreach ( $batch as $record ) {
				if ( is_array( $record ) ) {
					$records[] = $record;
				}
			}

			call_user_func(
				$this->log,
				sprintf( 'ServiceNow %s: page %d returned %d record(s).', $table, $pages, count( $batch ) )
			);

			if ( count( $batch ) < $limit ) {
				break;
			}

			$offset += $limit;
		}

		return array(
			'ok'      => true,
			'records' => $records,
			'message' => '',
			'pages'   => $pages,
		);
	}

	/**
	 * Cheap authenticated call used by the connection test.
	 *
	 * @return array{ok:bool,message:string,detail:array<string,mixed>}
	 */
	public function ping(): array {
		$response = $this->http->get(
			$this->base_url . '/api/now/table/cmdb_ci',
			array(
				'sysparm_limit'                  => 1,
				'sysparm_fields'                 => 'sys_id,name,sys_class_name',
				'sysparm_display_value'          => 'true',
				'sysparm_exclude_reference_link' => 'true',
			),
			$this->headers()
		);

		if ( 401 === $response->status || 403 === $response->status ) {
			return array(
				'ok'      => false,
				'message' => __( 'ServiceNow rejected the credentials. The integration account needs the itil or snc_read_only role and read access to the CMDB tables.', 'vulnhub' ),
				'detail'  => array( 'status' => $response->status ),
			);
		}

		if ( ! $response->ok() ) {
			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: 1: HTTP status, 2: error text. */
					__( 'ServiceNow returned %1$d: %2$s', 'vulnhub' ),
					$response->status,
					vh_trim( $response->error_message(), 200 )
				),
				'detail'  => array( 'status' => $response->status ),
			);
		}

		$data = $response->data();

		return array(
			'ok'      => true,
			'message' => __( 'Connected to ServiceNow and read the CMDB.', 'vulnhub' ),
			'detail'  => array(
				'status'  => $response->status,
				'sampled' => count( (array) ( $data['result'] ?? array() ) ),
			),
		);
	}
}

