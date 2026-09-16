<?php
/**
 * CMDB connector.
 *
 * The problem this exists to solve: Intune knows who carries a laptop, and
 * Tenable knows what is wrong with a host, but neither can tell you which team
 * runs NZAKLDC01, what business service it carries, or which building it sits
 * in. Assets that are not bound to a person still have to reach an owner, and
 * that answer lives in a configuration management database — or, honestly, in
 * a Confluence page, or in a spreadsheet somebody maintains by hand.
 *
 * So this connector supports four interchangeable back ends — ServiceNow, Jira
 * Service Management Assets, a Confluence page and an uploaded CSV — and
 * normalises all of them into one record shape before a single row is written.
 *
 * Layering, per the core contract: the mapping engine owns ownership, and this
 * connector's first job is to emit clean signals — asset type, tags, business
 * service, environment. Where the CMDB is genuinely authoritative it also
 * writes `team_id` and `location_id` directly; see `build_payload()` for
 * exactly when, and why that never touches a person-level owner.
 *
 * @package VulnHub\Cmdb
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The `cmdb` connector.
 */
final class VulnHub_Cmdb_Connector extends \VulnHub\Core\Connector {

	/** Connector id, also the `primary_source` value for rows it creates. */
	public const SOURCE = 'cmdb';

	/** Settings key holding the rows staged by the CSV importer. */
	public const OPT_CSV_ROWS = 'csv_rows';

	/** Settings key holding the operator's column mapping. */
	public const OPT_COLUMN_MAP = 'column_map';

	/**
	 * Settings key holding the Jira Assets attribute mapping.
	 *
	 * Kept apart from OPT_COLUMN_MAP on purpose. Both are field => column, but
	 * the columns are drawn from different vocabularies — a spreadsheet's
	 * headings and a workspace's attribute names — and letting one overwrite
	 * the other would silently re-map the source the operator was not editing.
	 */
	public const OPT_ASSETS_MAP = 'assets_map';

	/** Largest number of CSV rows kept for replay on a scheduled sync. */
	public const MAX_STORED_ROWS = 2000;

	/**
	 * Team ids resolved this run: name => id.
	 *
	 * @var array<string,int>
	 */
	private array $team_cache = array();

	/**
	 * Location ids resolved this run: key => id.
	 *
	 * @var array<string,int>
	 */
	private array $location_cache = array();

	/**
	 * People resolved this run: upn => id (0 when not found).
	 *
	 * @var array<string,int>
	 */
	private array $person_cache = array();

	/**
	 * Per-run tallies surfaced on the CMDB admin screen.
	 *
	 * @var array<string,int>
	 */
	private array $counts = array();

	/**
	 * Human-readable notes collected during a run, shown after a dry run.
	 *
	 * @var array<int,string>
	 */
	private array $notes = array();

	/* =================================================================
	 * Identity
	 * ============================================================== */

	/**
	 * Machine id.
	 */
	public function id(): string {
		return self::SOURCE;
	}

	/**
	 * Human label.
	 */
	public function label(): string {
		return __( 'Configuration Management Database', 'vulnhub' );
	}

	/**
	 * One-line description for the Integrations card.
	 */
	public function description(): string {
		return __( 'Resolves the owning team, business service and site for servers, network devices and cloud resources, from ServiceNow, Jira Assets, a Confluence page, or an uploaded CSV.', 'vulnhub' );
	}

	/**
	 * Dashicon slug.
	 */
	public function icon(): string {
		return 'dashicons-database';
	}

	/**
	 * Connector category.
	 */
	public function category(): string {
		return 'cmdb';
	}

	/**
	 * A CMDB is edited by humans during working hours; nightly is plenty.
	 */
	public function default_interval(): string {
		return 'vh_daily';
	}

	/* =================================================================
	 * Settings
	 * ============================================================== */

	/**
	 * The configured back end.
	 */
	public function source(): string {
		$source = (string) $this->get( 'source', 'servicenow' );

		return in_array( $source, array( 'servicenow', 'assets', 'confluence', 'csv' ), true ) ? $source : 'csv';
	}

	/**
	 * Settings field definitions.
	 *
	 * Nothing is marked `required`, because what is required depends entirely
	 * on the selected source — marking ServiceNow credentials required would
	 * report a CSV-only deployment as misconfigured forever. `is_configured()`
	 * below applies the real, source-aware rule instead.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public function fields(): array {
		return array(
			array(
				'key'     => 'source',
				'label'   => __( 'Source system', 'vulnhub' ),
				'type'    => 'select',
				'default' => 'servicenow',
				'options' => array(
					'servicenow' => __( 'ServiceNow (Table API)', 'vulnhub' ),
					'assets'     => __( 'Jira Service Management Assets (AQL)', 'vulnhub' ),
					'confluence' => __( 'Confluence page (HTML table)', 'vulnhub' ),
					'csv'        => __( 'CSV upload', 'vulnhub' ),
				),
				'help'    => __( 'All four produce the same records and run through the same normalisation. Pick CSV when there is no API to talk to — it needs no credentials and no vendor, and it is usually the first one an organisation can actually use.', 'vulnhub' ),
			),

			/* --- ServiceNow ------------------------------------------- */
			array(
				'key'         => 'sn_url',
				'show_when' => array( 'source' => array( 'servicenow' ) ),
				'label'       => __( 'ServiceNow instance URL', 'vulnhub' ),
				'type'        => 'url',
				'placeholder' => 'https://acme.service-now.com',
				'help'        => __( 'The instance root, with no path. Used as the base for /api/now/table/.', 'vulnhub' ),
			),
			array(
				'key'   => 'sn_user',
				'show_when' => array( 'source' => array( 'servicenow' ) ),
				'label' => __( 'ServiceNow user name', 'vulnhub' ),
				'type'  => 'text',
				'help'  => __( 'Give the integration its own account with a read-only role (snc_read_only plus read access to the CMDB tables). It never needs to write.', 'vulnhub' ),
			),
			array(
				'key'    => 'sn_token',
				'show_when' => array( 'source' => array( 'servicenow' ) ),
				'label'  => __( 'ServiceNow password or API token', 'vulnhub' ),
				'type'   => 'text',
				'secret' => true,
				'help'   => __( 'Stored encrypted and sent as HTTP Basic auth. Leave blank when editing to keep the stored value.', 'vulnhub' ),
			),
			array(
				'key'     => 'sn_tables',
				'show_when' => array( 'source' => array( 'servicenow' ) ),
				'label'   => __( 'CI tables to read', 'vulnhub' ),
				'type'    => 'text',
				'default' => 'cmdb_ci_server,cmdb_ci_netgear',
				'help'    => __( 'Comma separated. cmdb_ci_computer is the superclass of cmdb_ci_server, so querying it returns servers as well; records are de-duplicated on sys_id.', 'vulnhub' ),
			),
			array(
				'key'         => 'sn_query',
				'show_when' => array( 'source' => array( 'servicenow' ) ),
				'label'       => __( 'Encoded query filter', 'vulnhub' ),
				'type'        => 'text',
				'placeholder' => 'install_status=1^operational_status=1',
				'help'        => __( 'Passed straight through as sysparm_query, in GlideRecord encoded-query syntax. Leave blank for every record in the table.', 'vulnhub' ),
			),
			array(
				'key'     => 'sn_page_size',
				'show_when' => array( 'source' => array( 'servicenow' ) ),
				'label'   => __( 'Records per request', 'vulnhub' ),
				'type'    => 'number',
				'default' => 500,
				'help'    => __( 'Sent as sysparm_limit, with sysparm_offset advancing each page. ServiceNow permits up to 10000, but large pages time out on busy instances.', 'vulnhub' ),
			),

			/* --- Jira Service Management Assets ------------------------- */
			array(
				'key'   => 'as_email',
				'show_when' => array( 'source' => array( 'assets' ) ),
				'label' => __( 'Atlassian account email', 'vulnhub' ),
				'type'  => 'email',
				'help'  => __( 'The account the API token belongs to. Basic auth uses email:token. A dedicated integration account with read-only Assets access is preferable to a person\'s login.', 'vulnhub' ),
			),
			array(
				'key'    => 'as_token',
				'show_when' => array( 'source' => array( 'assets' ) ),
				'label'  => __( 'Assets API token', 'vulnhub' ),
				'type'   => 'text',
				'secret' => true,
				'help'   => __( 'A scoped API token from id.atlassian.com → Security → API tokens, carrying exactly these five read scopes: read:cmdb-object:jira, read:cmdb-attribute:jira, read:cmdb-schema:jira, read:cmdb-type:jira, read:cmdb-icon:jira. Those scopes make writing physically impossible, which is the read-only guarantee. Stored encrypted; leave blank when editing to keep the stored value.', 'vulnhub' ),
			),
			array(
				'key'         => 'as_cloud_id',
				'show_when' => array( 'source' => array( 'assets' ) ),
				'label'       => __( 'Atlassian cloud id', 'vulnhub' ),
				'type'        => 'text',
				'placeholder' => '00000000-0000-0000-0000-000000000000',
				'help'        => __( 'The site\'s cloud id, from {site}/_edge/tenant_info. Addresses the site on api.atlassian.com.', 'vulnhub' ),
			),
			array(
				'key'         => 'as_workspace_id',
				'show_when' => array( 'source' => array( 'assets' ) ),
				'label'       => __( 'Assets workspace id', 'vulnhub' ),
				'type'        => 'text',
				'placeholder' => '00000000-0000-0000-0000-000000000000',
				'help'        => __( 'From {site}/rest/servicedeskapi/assets/workspace. Not the same value as the cloud id.', 'vulnhub' ),
			),
			array(
				'key'     => 'as_schema_id',
				'show_when' => array( 'source' => array( 'assets' ) ),
				'label'   => __( 'Object schema id', 'vulnhub' ),
				'type'    => 'number',
				'default' => 6,
				'help'    => __( 'The numeric id of the object schema holding the asset register, visible in the Assets URL when the schema is open.', 'vulnhub' ),
			),
			array(
				'key'     => 'as_types',
				'show_when' => array( 'source' => array( 'assets' ) ),
				'label'   => __( 'Object types to read', 'vulnhub' ),
				'type'    => 'text',
				'default' => 'Servers, Computing Devices',
				'help'    => __( 'Comma separated, exactly as they are spelled in Assets. Quote a type whose name contains a comma. Leave blank to read every object in the schema, which is rarely what you want.', 'vulnhub' ),
			),

			/* --- Confluence -------------------------------------------- */
			array(
				'key'         => 'cf_url',
				'show_when' => array( 'source' => array( 'confluence' ) ),
				'label'       => __( 'Confluence site URL', 'vulnhub' ),
				'type'        => 'url',
				'placeholder' => 'https://acme.atlassian.net',
				'help'        => __( 'The site root. The v2 REST API lives beneath /wiki/api/v2/.', 'vulnhub' ),
			),
			array(
				'key'   => 'cf_email',
				'show_when' => array( 'source' => array( 'confluence' ) ),
				'label' => __( 'Atlassian account email', 'vulnhub' ),
				'type'  => 'email',
				'help'  => __( 'The account the API token belongs to. Basic auth uses email:token.', 'vulnhub' ),
			),
			array(
				'key'    => 'cf_token',
				'show_when' => array( 'source' => array( 'confluence' ) ),
				'label'  => __( 'Confluence API token', 'vulnhub' ),
				'type'   => 'text',
				'secret' => true,
				'help'   => __( 'Created at id.atlassian.com under Security → API tokens. Stored encrypted.', 'vulnhub' ),
			),
			array(
				'key'         => 'cf_pages',
				'show_when' => array( 'source' => array( 'confluence' ) ),
				'label'       => __( 'Page ids', 'vulnhub' ),
				'type'        => 'text',
				'placeholder' => '196611, 229377',
				'help'        => __( 'Comma separated numeric page ids. Each page is fetched with body-format=storage and every HTML table in it is parsed.', 'vulnhub' ),
			),
			array(
				'key'         => 'cf_cql',
				'show_when' => array( 'source' => array( 'confluence' ) ),
				'label'       => __( 'CQL search (instead of page ids)', 'vulnhub' ),
				'type'        => 'text',
				'placeholder' => 'space = IT AND label = "asset-register"',
				'help'        => __( 'Used when no page ids are given. Runs against /wiki/rest/api/search and reads every page it returns.', 'vulnhub' ),
			),
			array(
				'key'         => 'cf_space',
				'show_when' => array( 'source' => array( 'confluence' ) ),
				'label'       => __( 'Space key (fallback)', 'vulnhub' ),
				'type'        => 'text',
				'placeholder' => 'IT',
				'help'        => __( 'Used when neither page ids nor CQL are given: every page in the space is read. Expensive on a large space — prefer ids or a label query.', 'vulnhub' ),
			),

			/* --- Shared behaviour --------------------------------------- */
			array(
				'key'            => 'create_teams',
				'label'          => __( 'Unknown teams', 'vulnhub' ),
				'type'           => 'checkbox',
				'default'        => 1,
				'checkbox_label' => __( 'Create teams that do not exist yet', 'vulnhub' ),
				'help'           => __( 'When off, a support group with no matching team leaves the asset unassigned and the run log names it, rather than filling the teams table with typos.', 'vulnhub' ),
			),
			array(
				'key'            => 'create_locations',
				'label'          => __( 'Unknown locations', 'vulnhub' ),
				'type'           => 'checkbox',
				'default'        => 1,
				'checkbox_label' => __( 'Create locations that do not exist yet', 'vulnhub' ),
			),
			array(
				'key'            => 'update_only',
				'label'          => __( 'New assets', 'vulnhub' ),
				'type'           => 'checkbox',
				'default'        => 0,
				'checkbox_label' => __( 'Only update assets that already exist — never create one', 'vulnhub' ),
				'help'           => __( 'Recommended once Tenable and Intune are the system of record for what exists. The CMDB then enriches the inventory instead of defining it, and a stale spreadsheet row cannot resurrect a decommissioned host.', 'vulnhub' ),
			),
			array(
				'key'            => 'verbose_log',
				'label'          => __( 'Verbose logging', 'vulnhub' ),
				'type'           => 'checkbox',
				'default'        => 0,
				'checkbox_label' => __( 'Mirror this connector\'s run log to the PHP error log', 'vulnhub' ),
				'help'           => __( 'Diagnostics only. Credentials are never written to either log.', 'vulnhub' ),
			),
		);
	}

	/**
	 * Source-aware configuration check.
	 */
	public function is_configured(): bool {
		if ( $this->is_mock() ) {
			return true;
		}

		return match ( $this->source() ) {
			'servicenow' => '' !== trim( (string) $this->get( 'sn_url', '' ) )
				&& '' !== trim( (string) $this->get( 'sn_user', '' ) )
				&& $this->settings->has_secret( $this->id(), 'sn_token' ),
			'assets'     => '' !== trim( (string) $this->get( 'as_email', '' ) )
				&& '' !== trim( (string) $this->get( 'as_cloud_id', '' ) )
				&& '' !== trim( (string) $this->get( 'as_workspace_id', '' ) )
				&& $this->settings->has_secret( $this->id(), 'as_token' ),
			'confluence' => '' !== trim( (string) $this->get( 'cf_url', '' ) )
				&& '' !== trim( (string) $this->get( 'cf_email', '' ) )
				&& $this->settings->has_secret( $this->id(), 'cf_token' ),
			default      => array() !== $this->stored_rows(),
		};
	}

	/**
	 * The operator's column mapping, falling back to auto-detection.
	 *
	 * @return array<string,string>
	 */
	public function column_map(): array {
		$map = $this->get( self::OPT_COLUMN_MAP, array() );

		if ( ! is_array( $map ) ) {
			return array();
		}

		$fields = VulnHub_Cmdb_Schema::fields();
		$clean  = array();

		foreach ( $map as $field => $header ) {
			if ( isset( $fields[ (string) $field ] ) && is_scalar( $header ) && '' !== trim( (string) $header ) ) {
				$clean[ (string) $field ] = trim( (string) $header );
			}
		}

		return $clean;
	}

	/**
	 * Canonical records staged by the CSV importer.
	 *
	 * @return array<int,array<string,string>>
	 */
	public function stored_rows(): array {
		$rows = $this->get( self::OPT_CSV_ROWS, array() );

		return is_array( $rows ) ? array_values( array_filter( $rows, 'is_array' ) ) : array();
	}

	/**
	 * Replace the staged CSV records.
	 *
	 * @param array<int,array<string,string>> $rows Canonical records.
	 * @param array<string,mixed>             $meta Provenance for the screen.
	 */
	public function store_rows( array $rows, array $meta = array() ): void {
		$this->settings->update(
			$this->id(),
			array(
				self::OPT_CSV_ROWS => array_slice( array_values( $rows ), 0, self::MAX_STORED_ROWS ),
				'csv_meta'         => array_merge(
					array(
						'rows' => count( $rows ),
						'at'   => vh_now(),
					),
					$meta
				),
			)
		);
	}

	/**
	 * Build a ServiceNow client from the stored credentials.
	 */
	public function servicenow(): VulnHub_Cmdb_Servicenow_Client {
		return new VulnHub_Cmdb_Servicenow_Client(
			(string) $this->get( 'sn_url', '' ),
			(string) $this->get( 'sn_user', '' ),
			$this->secret( 'sn_token' ),
			$this->http,
			array( $this, 'log' )
		);
	}

	/**
	 * Build a Jira Assets client from the stored credentials.
	 */
	public function assets(): VulnHub_Cmdb_Assets_Client {
		return new VulnHub_Cmdb_Assets_Client(
			(string) $this->get( 'as_email', '' ),
			$this->secret( 'as_token' ),
			(string) $this->get( 'as_cloud_id', '' ),
			(string) $this->get( 'as_workspace_id', '' ),
			$this->http,
			array( $this, 'log' )
		);
	}

	/**
	 * Object types the operator configured.
	 *
	 * @return array<int,string>
	 */
	public function assets_types(): array {
		return VulnHub_Cmdb_Assets_Client::parse_types( (string) $this->get( 'as_types', 'Servers, Computing Devices' ) );
	}

	/**
	 * The AQL the configured settings produce.
	 */
	public function assets_aql(): string {
		return VulnHub_Cmdb_Assets_Client::build_aql(
			$this->settings->get_int( $this->id(), 'as_schema_id', 6 ),
			$this->assets_types()
		);
	}

	/**
	 * The operator's Assets attribute mapping, if they have saved one.
	 *
	 * @return array<string,string>
	 */
	public function assets_map(): array {
		$map = $this->get( self::OPT_ASSETS_MAP, array() );

		if ( ! is_array( $map ) ) {
			return array();
		}

		$fields = VulnHub_Cmdb_Schema::fields();
		$clean  = array();

		foreach ( $map as $field => $attribute ) {
			if ( isset( $fields[ (string) $field ] ) && is_scalar( $attribute ) && '' !== trim( (string) $attribute ) ) {
				$clean[ (string) $field ] = trim( (string) $attribute );
			}
		}

		return $clean;
	}

	/**
	 * Build a Confluence client from the stored credentials.
	 */
	public function confluence(): VulnHub_Cmdb_Confluence_Client {
		return new VulnHub_Cmdb_Confluence_Client(
			(string) $this->get( 'cf_url', '' ),
			(string) $this->get( 'cf_email', '' ),
			$this->secret( 'cf_token' ),
			$this->http,
			array( $this, 'log' )
		);
	}

	/* =================================================================
	 * Connection test
	 * ============================================================== */

	/**
	 * Verify the selected back end without writing anything.
	 *
	 * @return array{ok:bool,message:string,detail?:array<string,mixed>}
	 */
	public function test_connection(): array {
		$source = $this->source();

		if ( $this->is_mock() ) {
			$devices = count( VulnHub_Cmdb_Mock::devices() );

			return array(
				'ok'      => true,
				'message' => sprintf(
					/* translators: 1: number of CIs, 2: source name. */
					__( 'Mock mode: no call was made. Syncs will replay %1$d configuration items from the shared sample fleet through the %2$s normaliser.', 'vulnhub' ),
					$devices,
					$source
				),
				'detail'  => array(
					'mode'   => 'mock',
					'source' => $source,
					'cis'    => $devices,
				),
			);
		}

		if ( 'servicenow' === $source ) {
			$client = $this->servicenow();

			if ( ! $client->has_credentials() ) {
				return array(
					'ok'      => false,
					'message' => __( 'Add the ServiceNow instance URL, user name and token first.', 'vulnhub' ),
				);
			}

			$result             = $client->ping();
			$result['detail']   = $result['detail'] ?? array();
			$result['detail']['tables'] = $this->servicenow_tables();

			return $result;
		}

		if ( 'assets' === $source ) {
			$client = $this->assets();
			$aql    = $this->assets_aql();
			$result = $client->test_connection( $aql );

			$result['detail']          = $result['detail'] ?? array();
			$result['detail']['types'] = $this->assets_types();

			return $result;
		}

		if ( 'confluence' === $source ) {
			$client = $this->confluence();

			if ( ! $client->has_credentials() ) {
				return array(
					'ok'      => false,
					'message' => __( 'Add the Confluence site URL, account email and API token first.', 'vulnhub' ),
				);
			}

			$result = $client->ping();

			if ( ! empty( $result['ok'] ) ) {
				$pages = $this->confluence_pages( $client );

				if ( ! $pages['ok'] ) {
					return array(
						'ok'      => false,
						'message' => $pages['message'],
						'detail'  => array( 'stage' => 'pages' ),
					);
				}

				$tables = 0;
				foreach ( $pages['pages'] as $page ) {
					$tables += count( VulnHub_Cmdb_Html::tables( VulnHub_Cmdb_Confluence_Client::storage_body( (array) $page ) ) );
				}

				$result['message'] .= ' ' . sprintf(
					/* translators: 1: number of pages, 2: number of tables. */
					__( 'Read %1$d page(s) containing %2$d table(s).', 'vulnhub' ),
					count( $pages['pages'] ),
					$tables
				);
				$result['detail']['pages']  = count( $pages['pages'] );
				$result['detail']['tables'] = $tables;
			}

			return $result;
		}

		$rows = $this->stored_rows();
		$meta = (array) $this->get( 'csv_meta', array() );

		if ( ! $rows ) {
			return array(
				'ok'      => false,
				'message' => __( 'No CSV has been imported yet. Upload one on the CMDB screen, under "CSV import".', 'vulnhub' ),
			);
		}

		return array(
			'ok'      => true,
			'message' => sprintf(
				/* translators: 1: number of rows, 2: file name, 3: relative time. */
				__( '%1$d row(s) staged from %2$s, uploaded %3$s.', 'vulnhub' ),
				count( $rows ),
				(string) ( $meta['file'] ?? __( 'an uploaded file', 'vulnhub' ) ),
				vh_ago( (string) ( $meta['at'] ?? '' ) )
			),
			'detail'  => array(
				'rows' => count( $rows ),
				'file' => (string) ( $meta['file'] ?? '' ),
			),
		);
	}

	/* =================================================================
	 * Sync
	 * ============================================================== */

	/**
	 * Fetch from the configured source and merge into the asset inventory.
	 *
	 * @param array<string,mixed> $args Sync options. `dry_run` reports without writing.
	 * @return array{ok:bool,message:string}
	 */
	protected function do_sync( array $args = array() ): array {
		$this->reset_counters();

		$source  = $this->source();
		$dry_run = ! empty( $args['dry_run'] );

		$this->log(
			sprintf(
				'Source: %s. Create teams: %s. Create locations: %s. Update-only: %s.',
				$source,
				$this->settings->get_bool( $this->id(), 'create_teams', true ) ? 'yes' : 'no',
				$this->settings->get_bool( $this->id(), 'create_locations', true ) ? 'yes' : 'no',
				$this->settings->get_bool( $this->id(), 'update_only', false ) ? 'yes' : 'no'
			)
		);

		$fetched = isset( $args['records'] ) && is_array( $args['records'] )
			? array(
				'ok'      => true,
				'message' => '',
				'records' => $args['records'],
			)
			: $this->fetch_records( $source );

		if ( ! $fetched['ok'] ) {
			return array(
				'ok'      => false,
				'message' => $fetched['message'],
			);
		}

		$records = $fetched['records'];

		$this->log( sprintf( 'Normalised %d configuration item(s).', count( $records ) ) );

		$this->import_records( $records, $dry_run );

		if ( ! $dry_run ) {
			$this->persist_run_summary( $source );
		}

		$message = sprintf(
			/* translators: 1: records read, 2: created, 3: updated, 4: teams, 5: locations. */
			__( 'Read %1$d CI(s): %2$d asset(s) created, %3$d updated. Resolved %4$d team(s) and %5$d location(s).', 'vulnhub' ),
			$this->counts['records'],
			$this->counts['created'],
			$this->counts['updated'],
			$this->counts['teams_set'],
			$this->counts['locations_set']
		);

		if ( $dry_run ) {
			$message = __( 'Dry run — nothing was written. ', 'vulnhub' ) . $message;
		}

		return array(
			'ok'      => true,
			'message' => $message,
		);
	}

	/**
	 * Clear the per-run caches and counters.
	 */
	private function reset_counters(): void {
		$this->team_cache     = array();
		$this->location_cache = array();
		$this->person_cache   = array();
		$this->notes          = array();
		$this->counts         = array(
			'records'        => 0,
			'created'        => 0,
			'updated'        => 0,
			'unchanged'      => 0,
			'skipped'        => 0,
			'unissued'       => 0,
			'invalid'        => 0,
			'teams_set'      => 0,
			'teams_made'     => 0,
			'locations_set'  => 0,
			'locations_made' => 0,
			'owners_set'     => 0,
			'services_set'   => 0,
			'type_conflicts' => 0,
			'team_conflicts' => 0,
		);
	}

	/**
	 * Dry-run a set of records: what would change, without writing anything.
	 *
	 * Used by the CSV import screen so an operator can see the effect of a
	 * spreadsheet before it touches the inventory.
	 *
	 * @param array<int,array<string,string>> $records Canonical records.
	 * @return array{outcomes:array<int,array<string,mixed>>,counts:array<string,int>,notes:array<int,string>}
	 */
	public function preview( array $records ): array {
		$this->reset_counters();

		$outcomes = $this->import_records( $records, true );

		return array(
			'outcomes' => $outcomes,
			'counts'   => $this->counts,
			'notes'    => $this->notes,
		);
	}

	/**
	 * Read the configured source and hand back canonical records.
	 *
	 * @param string $source Source key.
	 * @return array{ok:bool,message:string,records:array<int,array<string,string>>}
	 */
	public function fetch_records( string $source ): array {
		return match ( $source ) {
			'servicenow' => $this->fetch_servicenow(),
			'assets'     => $this->fetch_assets(),
			'confluence' => $this->fetch_confluence(),
			default      => $this->fetch_csv(),
		};
	}

	/**
	 * Tables the operator configured, de-duplicated.
	 *
	 * @return array<int,string>
	 */
	public function servicenow_tables(): array {
		$raw    = (string) $this->get( 'sn_tables', 'cmdb_ci_server,cmdb_ci_netgear' );
		$tables = array();

		foreach ( explode( ',', $raw ) as $table ) {
			$table = strtolower( trim( (string) preg_replace( '/[^a-z0-9_]/i', '', $table ) ) );

			if ( '' !== $table ) {
				$tables[] = $table;
			}
		}

		return $tables ? array_values( array_unique( $tables ) ) : array( 'cmdb_ci_server', 'cmdb_ci_netgear' );
	}

	/**
	 * ServiceNow: read every configured table and normalise.
	 *
	 * @return array{ok:bool,message:string,records:array<int,array<string,string>>}
	 */
	private function fetch_servicenow(): array {
		$tables  = $this->servicenow_tables();
		$query   = (string) $this->get( 'sn_query', '' );
		$limit   = max( 1, min( 10000, $this->settings->get_int( $this->id(), 'sn_page_size', 500 ) ) );
		$seen    = array();
		$records = array();

		if ( $this->is_mock() ) {
			$tables = VulnHub_Cmdb_Mock::resolve_tables( $tables );
		}

		foreach ( $tables as $table ) {
			if ( $this->is_mock() ) {
				/*
				 * Mock mode builds the real Table API envelope and hands it to
				 * the same reader the live path uses, so the normaliser below
				 * is exercised identically either way.
				 */
				$payload = VulnHub_Cmdb_Mock::table_response( $table );
				$rows    = (array) ( $payload['result'] ?? array() );
				$this->log( sprintf( 'ServiceNow %s: %d record(s) (mock).', $table, count( $rows ) ) );
			} else {
				$result = $this->servicenow()->table( $table, $query, $limit );

				if ( ! $result['ok'] ) {
					return array(
						'ok'      => false,
						'message' => $result['message'],
						'records' => array(),
					);
				}

				$rows = $result['records'];
			}

			foreach ( $rows as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}

				// cmdb_ci_computer returns its subclasses too, so the same CI
				// can arrive from two configured tables.
				$sys_id = VulnHub_Cmdb_Schema::clean( $row['sys_id'] ?? '' );
				if ( '' !== $sys_id ) {
					if ( isset( $seen[ $sys_id ] ) ) {
						continue;
					}
					$seen[ $sys_id ] = true;
				}

				$records[] = $this->normalise_servicenow( $row, $table );
			}
		}

		return array(
			'ok'      => true,
			'message' => '',
			'records' => $records,
		);
	}

	/**
	 * Map one ServiceNow CI record on to the canonical record shape.
	 *
	 * Reference fields are read display-value first (`sysparm_display_value=true`
	 * turns `{"value":"<sys_id>"}` into `{"display_value":"Infrastructure"}`),
	 * then dot-walked keys, then the bare column.
	 *
	 * @param array<string,mixed> $row   Table API record.
	 * @param string              $table Table it came from.
	 * @return array<string,string>
	 */
	public function normalise_servicenow( array $row, string $table = '' ): array {
		$reference = static function ( mixed $value ): string {
			if ( is_array( $value ) ) {
				return VulnHub_Cmdb_Schema::clean( $value['display_value'] ?? $value['value'] ?? '' );
			}
			return VulnHub_Cmdb_Schema::clean( $value );
		};

		$pick = static function ( array $keys ) use ( $row, $reference ): string {
			foreach ( $keys as $key ) {
				if ( array_key_exists( $key, $row ) ) {
					$value = $reference( $row[ $key ] );
					if ( '' !== $value ) {
						return $value;
					}
				}
			}
			return '';
		};

		$class    = $pick( array( 'sys_class_name' ) ) ?: $table;
		$hostname = $pick( array( 'name', 'host_name', 'fqdn' ) );
		$location = $pick( array( 'location.name', 'location' ) );
		$city     = $pick( array( 'location.city' ) );
		$country  = $pick( array( 'location.country' ) );

		if ( '' !== $city || '' !== $country ) {
			$location = implode( ', ', array_filter( array( $location, $city, $country ) ) );
		}

		$record = array(
			'cmdb_id'          => $pick( array( 'sys_id' ) ),
			'hostname'         => $hostname,
			'fqdn'             => $pick( array( 'fqdn', 'dns_domain' ) ),
			'serial_number'    => $pick( array( 'serial_number' ) ),
			'ipv4'             => $pick( array( 'ip_address' ) ),
			'operating_system' => $pick( array( 'os' ) ),
			'os_version'       => $pick( array( 'os_version' ) ),
			'asset_type'       => $class,
			'criticality'      => $pick( array( 'business_criticality', 'u_criticality' ) ),
			'environment'      => $pick( array( 'u_environment', 'environment', 'used_for' ) ),
			'business_service' => $pick( array( 'u_business_service', 'business_service', 'service', 'short_description' ) ),
			'team'             => $pick( array( 'support_group.name', 'support_group', 'assignment_group', 'managed_by_group', 'department' ) ),
			'location'         => $location,
			'assigned_to'      => $pick( array( 'assigned_to.email', 'assigned_to.user_name', 'managed_by.email' ) ),
			'install_status'   => $pick( array( 'install_status' ) ),
		);

		// `short_description` is a fallback for business service and is often
		// prose; do not let a sentence become a service name.
		if ( strlen( $record['business_service'] ) > 80 || str_contains( $record['business_service'], ' — ' ) ) {
			$record['business_service'] = '';
		}

		$record                = VulnHub_Cmdb_Schema::normalise( $record );
		$record['source_ref']  = $pick( array( 'sys_id' ) );
		$record['source_kind'] = 'servicenow:' . $table;

		return $record;
	}

	/* =================================================================
	 * Jira Service Management Assets
	 * ============================================================== */

	/**
	 * Assets: read every matching object and normalise it.
	 *
	 * The whole point of the flattening step is that once an Assets object is
	 * a name => value row, it is a spreadsheet row, and the CSV path's
	 * detection, mapping and normalisation apply to it unchanged. Attribute
	 * names are workspace-specific and nobody outside Acme knows what
	 * they are called, so nothing here hard-codes them: the mapping is
	 * detected, overridable, and logged.
	 *
	 * @return array{ok:bool,message:string,records:array<int,array<string,string>>}
	 */
	private function fetch_assets(): array {
		$fetched = $this->fetch_assets_rows();

		if ( ! $fetched['ok'] ) {
			return array(
				'ok'      => false,
				'message' => $fetched['message'],
				'records' => array(),
			);
		}

		$records = array();
		foreach ( $fetched['rows'] as $row ) {
			$records[] = $this->normalise_assets( $row, $fetched['map'] );
		}

		return array(
			'ok'      => true,
			'message' => '',
			'records' => $records,
		);
	}

	/**
	 * Read every matching Assets object and flatten it, without normalising.
	 *
	 * Split out so the CMDB screen can stage exactly what a sync would import
	 * and dry-run it first — the same "look before it lands" step the CSV
	 * importer has always had.
	 *
	 * @return array{ok:bool,message:string,rows:array<int,array<string,string>>,headers:array<int,string>,map:array<string,string>}
	 */
	public function fetch_assets_rows(): array {
		$fail = static fn( string $message ): array => array(
			'ok'      => false,
			'message' => $message,
			'rows'    => array(),
			'headers' => array(),
			'map'     => array(),
		);

		if ( $this->is_mock() ) {
			/*
			 * Mock mode builds the real AQL envelope and reads it back through
			 * the same flattener the live path uses — including the page-level
			 * attribute-name lookup, which is the part a live workspace will
			 * exercise and a hand-written fixture would otherwise skip.
			 */
			$page    = VulnHub_Cmdb_Mock::assets_page( 0, VulnHub_Cmdb_Assets_Client::PAGE_SIZE );
			$objects = VulnHub_Cmdb_Mock::assets_objects();
			$names   = VulnHub_Cmdb_Assets_Client::attribute_names( $page );

			$this->log( sprintf( 'Assets: %d object(s) (mock).', count( $objects ) ) );
		} else {
			$client = $this->assets();

			if ( ! $client->has_credentials() ) {
				return $fail(
					sprintf(
						/* translators: %s: comma separated list of missing settings. */
						__( 'Jira Assets is not configured yet — still missing: %s.', 'vulnhub' ),
						implode( ', ', $client->missing() )
					)
				);
			}

			$aql = $this->assets_aql();

			$this->log( sprintf( 'Assets: querying %s', $aql ) );

			$fetched = $client->fetch_all( $aql );

			if ( ! $fetched['ok'] ) {
				return $fail( $fetched['message'] );
			}

			$objects = $fetched['objects'];
			$names   = $fetched['attribute_names'];
		}

		$rows = array();
		foreach ( $objects as $object ) {
			if ( is_array( $object ) ) {
				$rows[] = VulnHub_Cmdb_Assets_Client::flatten( $object, $names );
			}
		}

		if ( ! $rows ) {
			return $fail( __( 'The query succeeded but matched no objects. Check the schema id and the object type names — they must be spelled exactly as they are in Assets.', 'vulnhub' ) );
		}

		$map = $this->assets_mapping( $rows );

		$this->log_assets_mapping( $rows, $map );

		return array(
			'ok'      => true,
			'message' => '',
			'rows'    => $rows,
			'headers' => self::assets_headers( $rows ),
			'map'     => $map,
		);
	}

	/**
	 * Every attribute name seen across a set of flattened rows, in first-seen
	 * order.
	 *
	 * @param array<int,array<string,string>> $rows Flattened objects.
	 * @return array<int,string>
	 */
	public static function assets_headers( array $rows ): array {
		$headers = array();

		foreach ( $rows as $row ) {
			foreach ( array_keys( (array) $row ) as $name ) {
				$headers[ (string) $name ] = true;
			}
		}

		return array_keys( $headers );
	}

	/**
	 * Decide which attribute feeds which canonical field.
	 *
	 * Three layers, most specific first: what the operator saved, what the
	 * shared detector recognises from the attribute names, and finally the
	 * object's own built-in fields. Each layer only fills what the one above
	 * it left empty, so correcting a single field on the screen never throws
	 * away the rest of the detection.
	 *
	 * @param array<int,array<string,string>> $rows Flattened objects.
	 * @return array<string,string> canonical field => attribute name.
	 */
	public function assets_mapping( array $rows ): array {
		$headers = self::assets_headers( $rows );
		$saved   = $this->assets_map();
		$map     = array();

		// The saved mapping only applies where the attribute still exists — a
		// renamed attribute should fall back to detection, not to nothing.
		foreach ( $saved as $field => $attribute ) {
			if ( in_array( $attribute, $headers, true ) ) {
				$map[ $field ] = $attribute;
			}
		}

		$detected = VulnHub_Cmdb_Schema::detect_mapping( $headers, array_slice( $rows, 0, 50 ) );

		foreach ( $detected as $field => $attribute ) {
			if ( ! isset( $map[ $field ] ) ) {
				$map[ $field ] = $attribute;
			}
		}

		foreach ( self::assets_builtin_map() as $field => $attribute ) {
			if ( ! isset( $map[ $field ] ) && in_array( $attribute, $headers, true ) ) {
				$map[ $field ] = $attribute;
			}
		}

		return $map;
	}

	/**
	 * The object's own fields, as a last-resort mapping.
	 *
	 * These are the columns `VulnHub_Cmdb_Assets_Client::flatten()` synthesises
	 * from the object itself rather than from its attributes, so they are the
	 * one part of an Assets workspace whose names are known in advance. They
	 * are applied last: a workspace that has a real "Name" or "Serial Number"
	 * attribute should always win over the object's generic label.
	 *
	 * @return array<string,string>
	 */
	public static function assets_builtin_map(): array {
		return array(
			'cmdb_id'    => 'Assets Object Id',
			'cmdb_key'   => 'Assets Object Key',
			'hostname'   => 'Assets Label',
			'asset_type' => 'Assets Object Type',
			'last_scan'  => 'Assets Updated',
		);
	}

	/**
	 * Write the attribute names and the resulting mapping to the run log.
	 *
	 * Nobody can review a mapping they cannot see. The workspace's attribute
	 * names are not knowable from here, so every run records what it actually
	 * found and what it could not place — which is what turns "ownership is
	 * still empty" into "the support group attribute is called Service Owner".
	 *
	 * @param array<int,array<string,string>> $rows Flattened objects.
	 * @param array<string,string>            $map  Resolved mapping.
	 */
	private function log_assets_mapping( array $rows, array $map ): void {
		$headers = self::assets_headers( $rows );

		$this->log(
			sprintf(
				'Assets: %d attribute name(s) seen: %s',
				count( $headers ),
				vh_trim( implode( ', ', $headers ), 600 )
			)
		);

		$bound = array();
		foreach ( $map as $field => $attribute ) {
			$bound[] = $field . ' ← ' . $attribute;
		}

		$this->log( sprintf( 'Assets: mapping in use: %s', $bound ? implode( '; ', $bound ) : 'none' ) );

		$unmapped = array_values( array_diff( array_keys( VulnHub_Cmdb_Schema::fields() ), array_keys( $map ) ) );

		if ( $unmapped ) {
			$this->note(
				sprintf(
					/* translators: %s: comma separated list of field names. */
					__( 'No Assets attribute matched these fields: %s. Map them on the CMDB screen if the workspace has them under another name.', 'vulnhub' ),
					implode( ', ', $unmapped )
				)
			);
		}
	}

	/**
	 * Map one flattened Assets object on to the canonical record shape.
	 *
	 * @param array<string,string> $row Flattened object.
	 * @param array<string,string> $map canonical field => attribute name.
	 * @return array<string,string>
	 */
	public function normalise_assets( array $row, array $map ): array {
		$record = VulnHub_Cmdb_Schema::apply_mapping( $row, $map );

		$object_type = (string) ( $row['Assets Object Type'] ?? '' );
		$type        = self::assets_asset_type( $object_type );

		/*
		 * The object type is a class a human chose in Assets, which is stronger
		 * evidence than anything inferred from an OS string — and stronger than
		 * what `Schema::asset_type()` can make of it, since "Computing Devices"
		 * matches none of its patterns. Marking it explicit is what lets
		 * `reconcile_asset_type()` treat it as authoritative.
		 */
		if ( '' !== $type ) {
			$record['asset_type']        = $type;
			$record['asset_type_source'] = 'explicit';
		}

		$record['source_ref']  = (string) ( $row['Assets Object Key'] ?? '' ) ?: (string) ( $row['Assets Object Id'] ?? '' );
		$record['source_kind'] = 'assets:' . ( '' !== $object_type ? $object_type : 'object' );

		return $record;
	}

	/**
	 * Translate an Assets object type name into core's asset type vocabulary.
	 *
	 * Returns an empty string when the type says nothing useful, so the record
	 * keeps whatever the operating system and hostname implied rather than
	 * being overwritten with "unknown".
	 */
	public static function assets_asset_type( string $object_type ): string {
		$needle = strtolower( trim( $object_type ) );

		if ( '' === $needle ) {
			return '';
		}

		if ( str_contains( $needle, 'server' ) ) {
			return 'server';
		}
		if ( preg_match( '/(computing device|computer|workstation|desktop|laptop|notebook|endpoint)/', $needle ) ) {
			return 'workstation';
		}

		$mapped = VulnHub_Cmdb_Schema::asset_type( $object_type );

		return 'unknown' === $mapped ? '' : $mapped;
	}

	/**
	 * Confluence: read the configured pages and parse their tables.
	 *
	 * @return array{ok:bool,message:string,records:array<int,array<string,string>>}
	 */
	private function fetch_confluence(): array {
		if ( $this->is_mock() ) {
			$pages = array( VulnHub_Cmdb_Mock::confluence_page() );
			$this->log( 'Confluence: 1 page (mock).' );
		} else {
			$client = $this->confluence();

			if ( ! $client->has_credentials() ) {
				return array(
					'ok'      => false,
					'message' => __( 'Confluence credentials are incomplete.', 'vulnhub' ),
					'records' => array(),
				);
			}

			$result = $this->confluence_pages( $client );

			if ( ! $result['ok'] ) {
				return array(
					'ok'      => false,
					'message' => $result['message'],
					'records' => array(),
				);
			}

			$pages = $result['pages'];
			$this->log( sprintf( 'Confluence: %d page(s) fetched.', count( $pages ) ) );
		}

		$records = array();
		$map     = $this->column_map();

		foreach ( $pages as $page ) {
			$page    = (array) $page;
			$title   = (string) ( $page['title'] ?? '' );
			$page_id = (string) ( $page['id'] ?? '' );
			$tables  = VulnHub_Cmdb_Html::tables( VulnHub_Cmdb_Confluence_Client::storage_body( $page ) );

			if ( ! $tables ) {
				$this->log( sprintf( 'Confluence page "%s" (%s) has no parsable table.', vh_trim( $title, 60 ), $page_id ) );
				continue;
			}

			foreach ( $tables as $index => $table ) {
				// An explicit operator mapping wins; otherwise the headings on
				// this particular table are auto-detected.
				$table_map = $map ?: VulnHub_Cmdb_Schema::detect_mapping( $table['headers'], array_slice( (array) ( $table['rows'] ?? array() ), 0, 50 ) );

				if ( ! isset( $table_map['hostname'] ) ) {
					$this->log(
						sprintf(
							'Confluence page "%s": table %d has no hostname column (headings: %s). Skipped.',
							vh_trim( $title, 60 ),
							(int) $index + 1,
							vh_trim( implode( ', ', $table['headers'] ), 120 )
						)
					);
					continue;
				}

				foreach ( $table['rows'] as $row ) {
					$record                = VulnHub_Cmdb_Schema::apply_mapping( $row, $table_map );
					$record['source_ref']   = $page_id;
					$record['source_kind']  = 'confluence:' . $page_id;
					$records[]              = $record;
				}

				$this->log(
					sprintf(
						'Confluence page "%s": table %d contributed %d row(s).',
						vh_trim( $title, 60 ),
						(int) $index + 1,
						count( $table['rows'] )
					)
				);
			}
		}

		return array(
			'ok'      => true,
			'message' => '',
			'records' => $records,
		);
	}

	/**
	 * Resolve the configured Confluence pages: ids, then CQL, then space.
	 *
	 * @param VulnHub_Cmdb_Confluence_Client $client Client.
	 * @return array{ok:bool,message:string,pages:array<int,array<string,mixed>>}
	 */
	private function confluence_pages( VulnHub_Cmdb_Confluence_Client $client ): array {
		$ids = array_values(
			array_filter(
				array_map(
					static fn( string $id ): string => (string) preg_replace( '/[^0-9]/', '', trim( $id ) ),
					explode( ',', (string) $this->get( 'cf_pages', '' ) )
				)
			)
		);

		if ( $ids ) {
			$pages = array();

			foreach ( $ids as $id ) {
				$page = $client->page( $id );

				if ( ! $page['ok'] ) {
					return array(
						'ok'      => false,
						'message' => $page['message'],
						'pages'   => array(),
					);
				}

				$pages[] = $page['page'];
			}

			return array(
				'ok'      => true,
				'message' => '',
				'pages'   => $pages,
			);
		}

		$cql = trim( (string) $this->get( 'cf_cql', '' ) );

		if ( '' !== $cql ) {
			return $client->search( $cql, 25 );
		}

		$space = trim( (string) $this->get( 'cf_space', '' ) );

		if ( '' !== $space ) {
			return $client->pages_in_space( $space, 100 );
		}

		return array(
			'ok'      => false,
			'message' => __( 'Configure page ids, a CQL query, or a space key.', 'vulnhub' ),
			'pages'   => array(),
		);
	}

	/**
	 * CSV: replay the rows staged by the importer.
	 *
	 * @return array{ok:bool,message:string,records:array<int,array<string,string>>}
	 */
	private function fetch_csv(): array {
		if ( $this->is_mock() && ! $this->stored_rows() ) {
			// Nothing uploaded yet: parse the sample file that ships with the
			// plugin, through the same reader a real upload uses.
			$path = VulnHub_Cmdb_Csv::sample_path();

			if ( is_readable( $path ) ) {
				$parsed  = VulnHub_Cmdb_Csv::parse( $path );
				$map     = $this->column_map() ?: VulnHub_Cmdb_Schema::detect_mapping( $parsed['headers'], array_slice( (array) ( $parsed['rows'] ?? array() ), 0, 50 ) );
				$records = array();

				foreach ( $parsed['rows'] as $row ) {
					$record               = VulnHub_Cmdb_Schema::apply_mapping( $row, $map );
					$record['source_ref'] = 'sample-cmdb.csv';
					$record['source_kind'] = 'csv:sample';
					$records[]            = $record;
				}

				$this->log( sprintf( 'CSV: %d row(s) from the bundled sample file (mock).', count( $records ) ) );

				return array(
					'ok'      => true,
					'message' => '',
					'records' => $records,
				);
			}
		}

		$rows = $this->stored_rows();

		if ( ! $rows ) {
			return array(
				'ok'      => false,
				'message' => __( 'No CSV rows are staged. Upload a file on the CMDB screen first.', 'vulnhub' ),
				'records' => array(),
			);
		}

		$this->log( sprintf( 'CSV: replaying %d staged row(s).', count( $rows ) ) );

		return array(
			'ok'      => true,
			'message' => '',
			'records' => $rows,
		);
	}

	/* =================================================================
	 * Import
	 * ============================================================== */

	/**
	 * Merge canonical records into the asset inventory.
	 *
	 * @param array<int,array<string,string>> $records Canonical records.
	 * @param bool                            $dry_run Report without writing.
	 * @return array<int,array<string,mixed>> Per-row outcomes, for the preview.
	 */
	public function import_records( array $records, bool $dry_run = false ): array {
		// Self-contained: do_sync() and preview() reset the counters for
		// themselves, but the CSV import screen calls this method directly, and
		// without a reset the per-field tallies land on an unset array key.
		$this->reset_counters();

		$outcomes = array();

		foreach ( $records as $index => $record ) {
			$this->bump( 'processed' );
			++$this->counts['records'];

			$problem = VulnHub_Cmdb_Schema::validate( $record );

			if ( '' !== $problem ) {
				++$this->counts['invalid'];
				$this->bump( 'failed' );
				$outcomes[] = array(
					'row'      => (int) $index + 1,
					'hostname' => (string) ( $record['hostname'] ?? '' ),
					'action'   => 'invalid',
					'detail'   => $problem,
					'changes'  => array(),
				);
				continue;
			}

			$existing = $this->find_existing( $record );

			if ( ! $existing && $this->settings->get_bool( $this->id(), 'update_only', false ) ) {
				++$this->counts['skipped'];
				$this->bump( 'skipped' );
				$outcomes[] = array(
					'row'      => (int) $index + 1,
					'hostname' => (string) $record['hostname'],
					'action'   => 'skipped',
					'detail'   => __( 'No matching asset, and "only update existing assets" is on.', 'vulnhub' ),
					'changes'  => array(),
				);
				continue;
			}

			/*
			 * Kit nobody has been issued does not belong in a live inventory.
			 * A spare in a cupboard cannot be scanned, cannot be owned and
			 * cannot be patched, so creating an asset for it adds a row that
			 * will sit unowned and unscanned forever -- in one real export
			 * that was 166 of 783 rows.
			 *
			 * Deliberately only a bar on *creating*. Where the platform
			 * already holds the asset -- because Tenable scanned it or Intune
			 * enrolled it before it went back on the shelf -- the row is
			 * still applied, and writing `lifecycle_status = spare` is
			 * precisely what stops it being counted as a missing owner.
			 */
			$vh_lifecycle = vh_normalise_lifecycle( (string) ( $record['install_status'] ?? '' ) );

			if ( ! $existing && in_array( $vh_lifecycle, vh_unissued_statuses(), true ) ) {
				++$this->counts['skipped'];
				++$this->counts['unissued'];
				$this->bump( 'skipped' );
				$outcomes[] = array(
					'row'      => (int) $index + 1,
					'hostname' => (string) $record['hostname'],
					'action'   => 'skipped',
					'reason'   => 'unissued',
					'detail'   => sprintf(
						/* translators: %s: the lifecycle status, e.g. "Spare". */
						__( 'Not created: %s kit has not been issued to anyone.', 'vulnhub' ),
						(string) ( vh_lifecycle_statuses()[ $vh_lifecycle ]['label'] ?? $vh_lifecycle )
					),
					'changes'  => array(),
				);
				continue;
			}

			$payload = $this->build_payload( $record, $existing, $dry_run );
			$changes = $this->diff( $payload, $existing );

			if ( $dry_run ) {
				$outcomes[] = array(
					'row'      => (int) $index + 1,
					'hostname' => (string) $record['hostname'],
					'action'   => $existing ? ( $changes ? 'update' : 'unchanged' ) : 'create',
					'detail'   => $existing
						? sprintf(
							/* translators: 1: asset id, 2: matched column. */
							__( 'Matches asset #%1$d on %2$s.', 'vulnhub' ),
							(int) $existing['id'],
							(string) $existing['vh_matched_on']
						)
						: __( 'Would be created.', 'vulnhub' ),
					'changes'  => $changes,
				);

				if ( $existing ) {
					if ( $changes ) {
						++$this->counts['updated'];
					} else {
						++$this->counts['unchanged'];
					}
				} else {
					++$this->counts['created'];
				}

				continue;
			}

			$result = \VulnHub\Core\Repo::upsert_asset( $payload );

			if ( ! $result['id'] ) {
				++$this->counts['invalid'];
				$this->bump( 'failed' );
				$outcomes[] = array(
					'row'      => (int) $index + 1,
					'hostname' => (string) $record['hostname'],
					'action'   => 'invalid',
					'detail'   => __( 'The asset row could not be written.', 'vulnhub' ),
					'changes'  => array(),
				);
				continue;
			}

			if ( $result['created'] ) {
				++$this->counts['created'];
				$this->bump( 'created' );
			} elseif ( $changes ) {
				++$this->counts['updated'];
				$this->bump( 'updated' );
			} else {
				++$this->counts['unchanged'];
				$this->bump( 'skipped' );
			}

			if ( isset( $payload['team_id'] ) && $payload['team_id'] ) {
				++$this->counts['teams_set'];
			}
			if ( isset( $payload['location_id'] ) && $payload['location_id'] ) {
				++$this->counts['locations_set'];
			}
			if ( isset( $payload['owner_person_id'] ) && $payload['owner_person_id'] ) {
				++$this->counts['owners_set'];
			}
			if ( '' !== (string) ( $payload['business_service'] ?? '' ) ) {
				++$this->counts['services_set'];
			}

			$outcomes[] = array(
				'row'      => (int) $index + 1,
				'hostname' => (string) $record['hostname'],
				'action'   => $result['created'] ? 'create' : ( $changes ? 'update' : 'unchanged' ),
				'detail'   => '',
				'changes'  => $changes,
			);
		}

		return $outcomes;
	}

	/**
	 * Find the asset a CMDB record refers to.
	 *
	 * Matching order is cmdb_id → serial_number → hostname, which mirrors
	 * `Repo::upsert_asset()`. Doing the lookup here as well is what makes the
	 * connector safe: it lets us tell "create" from "update" before writing,
	 * so the update-only switch works, so `primary_source` is not stolen from
	 * Tenable, and so an existing owner is never overwritten.
	 *
	 * @param array<string,string> $record Canonical record.
	 * @return array<string,mixed>|null Asset row plus `vh_matched_on`.
	 */
	public function find_existing( array $record ): ?array {
		global $wpdb;

		$table   = vh_table( 'assets' );
		$columns = array(
			'cmdb_id'       => (string) ( $record['cmdb_id'] ?? '' ),
			'serial_number' => (string) ( $record['serial_number'] ?? '' ),
			'hostname'      => strtolower( trim( (string) ( $record['hostname'] ?? '' ) ) ),
		);

		foreach ( $columns as $column => $value ) {
			if ( '' === $value ) {
				continue;
			}

			$sql = match ( $column ) {
				'cmdb_id'       => "SELECT * FROM {$table} WHERE cmdb_id = %s LIMIT 1",
				'serial_number' => "SELECT * FROM {$table} WHERE serial_number = %s LIMIT 1",
				default         => "SELECT * FROM {$table} WHERE hostname = %s LIMIT 1",
			};

			$row = $wpdb->get_row( $wpdb->prepare( $sql, $value ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared

			if ( $row ) {
				$row['vh_matched_on'] = $column;
				return $row;
			}
		}

		return null;
	}

	/**
	 * Build the `Repo::upsert_asset()` payload for one record.
	 *
	 * @param array<string,string>     $record   Canonical record.
	 * @param array<string,mixed>|null $existing Matched asset row, if any.
	 * @param bool                     $dry_run  Suppress team/location creation.
	 * @return array<string,mixed>
	 */
	/**
	 * Has a scanner seen this asset recently enough to contradict the CMDB?
	 *
	 * Deliberately the contact window rather than the scan window: the
	 * question is "is this machine still here", not "is the scan fresh".
	 *
	 * @param array<string,mixed> $existing Matched asset row.
	 */
	private static function scanner_still_sees( array $existing ): bool {
		$seen = (string) ( $existing['tenable_last_scan'] ?? '' );

		if ( '' === $seen || '0000-00-00 00:00:00' === $seen ) {
			return false;
		}

		$cutoff = gmdate( 'Y-m-d H:i:s', time() - ( \VulnHub\Core\Coverage::contact_days() * DAY_IN_SECONDS ) );

		return $seen >= $cutoff;
	}

	private function build_payload( array $record, ?array $existing, bool $dry_run = false ): array {
		$payload = array(
			'cmdb_id'  => (string) $record['cmdb_id'],
			'hostname' => (string) $record['hostname'],
			// Separate from `primary_source` below: this records that the CMDB
			// knows the host today, whoever first told us it existed.
			'source'   => self::SOURCE,
		);

		/*
		 * `primary_source` is only claimed for assets this connector creates.
		 * A host Tenable already knows about stays a Tenable asset; the CMDB
		 * is enriching it, not taking it over.
		 */
		if ( ! $existing ) {
			$payload['primary_source'] = self::SOURCE;
		}

		foreach ( array( 'fqdn', 'serial_number', 'ipv4', 'operating_system', 'os_version', 'business_service', 'environment', 'mac_address', 'manufacturer', 'model', 'cmdb_key' ) as $field ) {
			if ( '' !== (string) ( $record[ $field ] ?? '' ) ) {
				$payload[ $field ] = (string) $record[ $field ];
			}
		}

		/*
		 * Warranty expiry. Exports from Jira Assets and Cherwell write it as
		 * `18/Jun/27`, which strtotime() reads as neither a date nor an
		 * error -- it simply returns nothing -- so the value has to be
		 * pulled apart by hand before it can be stored.
		 */
		$support_end = self::parse_short_date( (string) ( $record['support_end_date'] ?? '' ) );

		if ( '' !== $support_end ) {
			$payload['support_end_date'] = $support_end;
		}

		/*
		 * Lifecycle status. This decides whether the platform expects the asset
		 * to have a human owner at all: a Spare or In Stock laptop is *meant*
		 * to be unassigned, and counting those as ownership gaps drowns the
		 * real ones. In one live export 269 of 783 rows were not in service.
		 */
		$lifecycle = vh_normalise_lifecycle( (string) ( $record['install_status'] ?? '' ) );

		/*
		 * A CMDB status only removes an asset from scope when nothing is
		 * arguing back.
		 *
		 * One live export still listed a Platinum production server as
		 * "Planned" months after it was built. Applied verbatim that took a
		 * machine Tenable had scanned the day before out of scope and archived
		 * 6,433 open findings on it -- the estate's risk went down because a
		 * record was stale, which is the one thing this platform must never
		 * do. A scanner that saw the machine this week is better evidence that
		 * it is running than a status field is that it is not, so the CMDB's
		 * answer is recorded as a disagreement rather than acted on.
		 */
		if ( 'unknown' !== $lifecycle ) {
			if ( $existing && ! in_array( $lifecycle, vh_scannable_statuses(), true ) && self::scanner_still_sees( $existing ) ) {
				$this->counts['lifecycle_conflicts'] = (int) ( $this->counts['lifecycle_conflicts'] ?? 0 ) + 1;
				$this->note(
					sprintf(
						/* translators: 1: hostname, 2: CMDB lifecycle status. */
						__( '%1$s: the CMDB calls this %2$s, but Tenable scanned it inside the contact window. Kept it in scope; the CMDB record looks stale.', 'vulnhub' ),
						(string) $record['hostname'],
						$lifecycle
					)
				);
			} else {
				$payload['lifecycle_status'] = $lifecycle;
			}
		}

		if ( '' !== (string) $record['criticality'] ) {
			$payload['criticality'] = (string) $record['criticality'];
		}

		$type = $this->reconcile_asset_type(
			(string) $record['asset_type'],
			$existing,
			(string) $record['hostname'],
			'explicit' === (string) ( $record['asset_type_source'] ?? 'inferred' )
		);

		if ( '' !== $type ) {
			$payload['asset_type'] = $type;
		}

		/*
		 * Ownership. Two rules, both from the core contract:
		 *
		 *  - The mapping engine owns ownership, so the CMDB's answers are
		 *    ALSO emitted as tags below, where an administrator-editable rule
		 *    can use, override or ignore them.
		 *  - Where the CMDB is genuinely authoritative we still write the
		 *    foreign key directly, because for a domain controller or a core
		 *    switch there is no other source of truth — Intune has no primary
		 *    user for them and Tenable only has whatever tag someone typed.
		 *
		 * That direct write is fenced twice. It is confined to assets that are
		 * NOT user-bound, so a workstation's person-level owner resolved from
		 * Intune can never be replaced by a support group. And it only ever
		 * FILLS an empty column, never replaces a value the mapping engine
		 * already decided — because core's seeded rules include an
		 * unconditional "servers default to Infrastructure", and a connector
		 * that overwrote that would simply be reverted on the mapping pass
		 * that runs immediately after this sync, every single run, for ever.
		 * A disagreement is recorded instead: it is a real finding about the
		 * estate, not something a sync should silently arm-wrestle over. To
		 * make the CMDB win outright, raise the priority of the "Team" tag
		 * rule above the default-team rules on the Ownership screen — the tag
		 * this connector writes below is what that rule reads.
		 */
		$effective_type = $type ?: (string) ( $existing['asset_type'] ?? 'unknown' );
		$user_bound     = in_array( $effective_type, vh_user_bound_asset_types(), true );
		$current_team   = (int) ( $existing['team_id'] ?? 0 );

		$team_id = $this->resolve_team( (string) $record['team'], $dry_run );

		if ( $team_id && ! $user_bound ) {
			if ( 0 === $current_team ) {
				$payload['team_id'] = $team_id;
			} elseif ( $current_team !== $team_id ) {
				++$this->counts['team_conflicts'];
				$this->note(
					sprintf(
						/* translators: 1: hostname, 2: CMDB team name, 3: current team name. */
						__( '%1$s: the CMDB says the owner is "%2$s" but the ownership rules resolved "%3$s". Left as resolved — raise the Team tag rule above the default-team rules to let the CMDB win.', 'vulnhub' ),
						(string) $record['hostname'],
						(string) $record['team'],
						(string) ( \VulnHub\Core\Repo::team( $current_team )['name'] ?? $current_team )
					)
				);
			}
		}

		$location_id = $this->resolve_location( (string) $record['location'], $dry_run );

		if ( $location_id && ( ! $user_bound || 0 === (int) ( $existing['location_id'] ?? 0 ) ) ) {
			$payload['location_id'] = $location_id;
		}

		/*
		 * When the CMDB last saw the CI. Kept in its own column rather than
		 * folded into `last_seen`, because coverage needs to know which
		 * system is making the claim: "ServiceNow discovered it last night
		 * and Tenable has never scanned it" is a scanner problem, and it
		 * reads identically to a dead record unless the two dates are
		 * separable.
		 */
		/*
		 * Through the same parser as the warranty date, and for the same
		 * reason: a live export writes `02/Aug/26`, which strtotime() reads as
		 * neither a date nor an error, so vh_to_mysql() quietly returned null
		 * and every row imported with no discovery date at all. Coverage then
		 * could not tell a machine the CMDB saw last week from a record nobody
		 * has touched since 2019, and filed both as simply unscanned.
		 */
		$last_scan = self::parse_short_date( (string) ( $record['last_scan'] ?? '' ) );

		/*
		 * `01/Jan/00` is how this CMDB spells "never" -- 32 rows of one export
		 * carried it. Stored as a real date it becomes evidence of contact in
		 * the year 2000, which reads as an abandoned record rather than an
		 * unknown one. An absent date is the honest answer.
		 */
		if ( '' !== $last_scan && $last_scan < '2001-01-01' ) {
			$last_scan = '';
		}

		if ( '' !== $last_scan ) {
			$payload['cmdb_last_scan'] = $last_scan;
		}

		/*
		 * Ownership fallback chain. The custodian column is authoritative but
		 * incomplete — 75.6% populated in a live export — while the last
		 * logged-in user is populated 92.3% of the time. Trying the custodian
		 * first and falling back takes ownership coverage to 93.0% without
		 * ever overriding a better answer, and the confidence and rule text
		 * record which one actually resolved so the weaker signal is auditable
		 * rather than invisible.
		 */
		$person_id  = $this->resolve_person( (string) $record['assigned_to'] );
		$confidence = 'medium';
		$via        = __( 'CMDB custodian', 'vulnhub' );

		if ( ! $person_id && '' !== (string) ( $record['assigned_to_fallback'] ?? '' ) ) {
			$person_id = $this->resolve_person( (string) $record['assigned_to_fallback'] );
			if ( $person_id ) {
				$confidence = 'low';
				$via        = __( 'CMDB last logged-in user', 'vulnhub' );
			}
		}

		if ( $person_id && 0 === (int) ( $existing['owner_person_id'] ?? 0 ) ) {
			$payload['owner_person_id']  = $person_id;
			$payload['owner_source']     = self::SOURCE;
			$payload['owner_confidence'] = $confidence;
			$payload['owner_rule']       = $via;
		}

		$payload['tags'] = $this->merge_tags( $record, $existing );
		$payload['raw']  = $this->merge_raw( $record, $existing );

		return $payload;
	}

	/**
	 * Decide whether the CMDB's asset type should be written.
	 *
	 * Asset type is the single most consequential column this connector can
	 * touch, because `workstation` and `mobile` are user-bound: the platform
	 * demands a named human owner for them and reports anything without one.
	 * Re-typing an asset in either direction therefore changes who gets chased
	 * for a vulnerability. Three guard rails:
	 *
	 *  - an INFERRED type never overrides a type another connector already
	 *    set. A CI class an administrator typed is evidence; a type guessed
	 *    from an OS string is not. This is what stops a Confluence table with
	 *    no class column and an "Operating System" cell reading
	 *    "Cisco IOS 15.2(7)E6" from re-filing a core switch as a phone;
	 *  - a device that is genuinely enrolled — it has an Intune id, or a
	 *    person-level owner — keeps the type its enrolment gave it, whatever
	 *    the CMDB thinks;
	 *  - a known type is never overwritten with `unknown`.
	 *
	 * An explicit CI class can still correct an unenrolled asset that was
	 * mis-classified, which is the case worth allowing: nothing else in the
	 * platform can fix it.
	 *
	 * @param string                   $type     Type derived from the record.
	 * @param array<string,mixed>|null $existing Matched asset row.
	 * @param string                   $hostname Hostname, for the note.
	 * @param bool                     $explicit The source named a class column.
	 * @return string Type to write, or '' to leave the column alone.
	 */
	private function reconcile_asset_type( string $type, ?array $existing, string $hostname, bool $explicit ): string {
		if ( ! $existing ) {
			return $type ?: 'unknown';
		}

		$current = (string) ( $existing['asset_type'] ?? '' );

		if ( $current === $type || '' === $type ) {
			return '';
		}

		$known = '' !== $current && 'unknown' !== $current;

		if ( $known && ! $explicit ) {
			return '';
		}

		if ( 'unknown' === $type && '' !== $current ) {
			return '';
		}

		/*
		 * "Enrolled" means another system vouched for this being a user
		 * device: an Intune id, or a person-level owner that did NOT come
		 * from this connector. The exclusion matters — without it a type this
		 * connector got wrong on an earlier run would set an owner, and that
		 * owner would then permanently block the connector from correcting
		 * its own mistake.
		 */
		$enrolled = '' !== (string) ( $existing['intune_id'] ?? '' )
			|| ( (int) ( $existing['owner_person_id'] ?? 0 ) > 0 && self::SOURCE !== (string) ( $existing['owner_source'] ?? '' ) );

		if ( $known && in_array( $current, vh_user_bound_asset_types(), true ) && $enrolled ) {
			++$this->counts['type_conflicts'];
			$this->note(
				sprintf(
					/* translators: 1: hostname, 2: CMDB type, 3: current type. */
					__( '%1$s: the CMDB calls this a %2$s but it is enrolled as a %3$s with a named user. Kept the enrolled type.', 'vulnhub' ),
					$hostname,
					$type,
					$current
				)
			);
			return '';
		}

		if ( $known ) {
			$this->note(
				sprintf(
					/* translators: 1: hostname, 2: current type, 3: CMDB type. */
					__( '%1$s: re-typed from %2$s to %3$s on the CMDB\'s explicit CI class.', 'vulnhub' ),
					$hostname,
					$current,
					$type
				)
			);
		}

		return $type;
	}

	/**
	 * Merge CMDB signals into the asset's tags without discarding Tenable's.
	 *
	 * `Repo::upsert_asset()` replaces `tags_json` wholesale, so the existing
	 * tags have to be read and carried forward or the Tenable tag categories
	 * the ownership rules depend on would vanish on the first CMDB sync.
	 *
	 * @param array<string,string>     $record   Canonical record.
	 * @param array<string,mixed>|null $existing Matched asset row.
	 * @return array<int,array{key:string,value:string}>
	 */
	private function merge_tags( array $record, ?array $existing ): array {
		$tags = array();

		foreach ( vh_json( $existing['tags_json'] ?? null ) as $tag ) {
			if ( is_array( $tag ) && isset( $tag['key'] ) ) {
				$tags[ (string) $tag['key'] ] = (string) ( $tag['value'] ?? '' );
			}
		}

		// Unambiguous, CMDB-owned categories: always refreshed.
		$owned = array(
			'CMDB Team'        => (string) $record['team'],
			'CMDB Service'     => (string) $record['business_service'],
			'CMDB Environment' => (string) $record['environment'],
			'CMDB Site'        => (string) $record['location'],
			'CMDB Status'      => (string) $record['install_status'],
		);

		foreach ( $owned as $key => $value ) {
			if ( '' !== $value ) {
				$tags[ $key ] = vh_trim( $value, 120 );
			}
		}

		// Shared categories the built-in mapping rules read: filled only when
		// nothing else has claimed them, so the scanner's own tags win.
		$shared = array(
			'Team'     => (string) $record['team'],
			'Location' => (string) $record['location'],
		);

		foreach ( $shared as $key => $value ) {
			if ( '' !== $value && '' === (string) ( $tags[ $key ] ?? '' ) ) {
				$tags[ $key ] = vh_trim( $value, 120 );
			}
		}

		$out = array();

		foreach ( $tags as $key => $value ) {
			$out[] = array(
				'key'   => (string) $key,
				'value' => (string) $value,
			);
		}

		return $out;
	}

	/**
	 * Merge the CMDB record into `raw_json` without destroying what is there.
	 *
	 * This one is load-bearing: the built-in `person_from_intune` rule reads
	 * `raw['intune']['userPrincipalName']`. `Repo::upsert_asset()` replaces
	 * `raw_json` wholesale, so writing a bare `['cmdb' => …]` here would erase
	 * the Intune key and every workstation in the estate would lose its owner
	 * on the next mapping pass.
	 *
	 * @param array<string,string>     $record   Canonical record.
	 * @param array<string,mixed>|null $existing Matched asset row.
	 * @return array<string,mixed>
	 */
	private function merge_raw( array $record, ?array $existing ): array {
		$raw = vh_json( $existing['raw_json'] ?? null );

		$raw['cmdb'] = array(
			'source'           => $this->source(),
			'reference'        => (string) ( $record['source_ref'] ?? '' ),
			'kind'             => (string) ( $record['source_kind'] ?? '' ),
			'team'             => (string) $record['team'],
			'business_service' => (string) $record['business_service'],
			'environment'      => (string) $record['environment'],
			'location'         => (string) $record['location'],
			'assigned_to'      => (string) $record['assigned_to'],
			'install_status'   => (string) $record['install_status'],
			'synced_at'        => vh_now(),
		);

		return $raw;
	}

	/**
	 * Which columns this payload would actually change.
	 *
	 * @param array<string,mixed>      $payload  Upsert payload.
	 * @param array<string,mixed>|null $existing Matched asset row.
	 * @return array<string,array{from:string,to:string}>
	 */
	private function diff( array $payload, ?array $existing ): array {
		if ( ! $existing ) {
			return array();
		}

		$changes  = array();
		$compare  = array(
			'cmdb_id', 'hostname', 'fqdn', 'serial_number', 'ipv4', 'operating_system',
			'os_version', 'asset_type', 'criticality', 'environment', 'business_service',
			'team_id', 'location_id', 'owner_person_id',
		);

		foreach ( $compare as $column ) {
			if ( ! array_key_exists( $column, $payload ) ) {
				continue;
			}

			$to   = (string) $payload[ $column ];
			$from = (string) ( $existing[ $column ] ?? '' );

			if ( $from === $to ) {
				continue;
			}

			$changes[ $column ] = array(
				'from' => $from,
				'to'   => $to,
			);
		}

		return $changes;
	}

	/* =================================================================
	 * Resolution helpers
	 * ============================================================== */

	/**
	 * Resolve a support group name to a team id, creating it if allowed.
	 *
	 * @param string $name    Group name from the CMDB.
	 * @param bool   $dry_run Look up only; never create.
	 */
	private function resolve_team( string $name, bool $dry_run = false ): int {
		$name = trim( $name );

		if ( '' === $name ) {
			return 0;
		}

		$key = strtolower( $name );

		if ( isset( $this->team_cache[ $key ] ) ) {
			return $this->team_cache[ $key ];
		}

		$id = \VulnHub\Core\Repo::team_id_by_name( $name );

		if ( ! $id && ! $dry_run ) {
			if ( $this->settings->get_bool( $this->id(), 'create_teams', true ) ) {
				$id = \VulnHub\Core\Repo::ensure_team( $name, self::SOURCE );

				if ( $id ) {
					++$this->counts['teams_made'];
					$this->log( sprintf( 'Created team "%s" from the CMDB.', $name ) );
				}
			} else {
				$this->note(
					sprintf(
						/* translators: %s: team name. */
						__( 'No team matches the support group "%s", and creating teams is switched off.', 'vulnhub' ),
						$name
					)
				);
			}
		}

		$this->team_cache[ $key ] = (int) $id;

		return (int) $id;
	}

	/**
	 * Resolve a location string to a location id, creating it if allowed.
	 *
	 * @param string $value   Raw location from the CMDB.
	 * @param bool   $dry_run Look up only; never create.
	 */
	private function resolve_location( string $value, bool $dry_run = false ): int {
		$value = trim( $value );

		if ( '' === $value ) {
			return 0;
		}

		$key = strtolower( $value );

		if ( isset( $this->location_cache[ $key ] ) ) {
			return $this->location_cache[ $key ];
		}

		$parts = VulnHub_Cmdb_Schema::location_parts( $value );

		if ( '' === $parts['name'] ) {
			$this->location_cache[ $key ] = 0;
			return 0;
		}

		$id = $this->location_id_by_name( $parts['name'] );

		if ( ! $id && ! $dry_run ) {
			if ( $this->settings->get_bool( $this->id(), 'create_locations', true ) ) {
				$id = \VulnHub\Core\Repo::ensure_location( $parts['name'], $parts['city'], $parts['country'] );

				if ( $id ) {
					++$this->counts['locations_made'];
					$this->log( sprintf( 'Created location "%s" from the CMDB.', $parts['name'] ) );
				}
			} else {
				$this->note(
					sprintf(
						/* translators: %s: location name. */
						__( 'No location matches "%s", and creating locations is switched off.', 'vulnhub' ),
						$parts['name']
					)
				);
			}
		}

		$this->location_cache[ $key ] = (int) $id;

		return (int) $id;
	}

	/**
	 * Existing location id by name or slug, without creating anything.
	 */
	private function location_id_by_name( string $name ): int {
		global $wpdb;

		return (int) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT id FROM ' . vh_table( 'locations' ) . ' WHERE slug = %s OR name = %s LIMIT 1',
				sanitize_title( $name ),
				$name
			)
		);
	}

	/**
	 * Find a person by display name, for CMDB rows that name a custodian
	 * without an email address.
	 *
	 * Deliberately refuses to guess when the name is ambiguous — attaching a
	 * vulnerability to the wrong person is worse than leaving it unassigned.
	 */
	private function person_by_display_name( string $name ): int {
		global $wpdb;

		$name = trim( $name );

		if ( mb_strlen( $name ) < 4 ) {
			return 0;
		}

		$matches = (array) $wpdb->get_col(
			$wpdb->prepare(
				'SELECT id FROM ' . vh_table( 'people' ) . ' WHERE display_name = %s LIMIT 2',
				$name
			)
		);

		if ( 1 !== count( $matches ) ) {
			if ( count( $matches ) > 1 ) {
				$this->note(
					sprintf(
						/* translators: %s: person name. */
						__( 'The CMDB names custodian "%s" without an email, and more than one person matches, so the asset was left unassigned.', 'vulnhub' ),
						$name
					)
				);
			}
			return 0;
		}

		return (int) $matches[0];
	}

	/**
	 * Resolve an `assigned_to` address to a person id.
	 */
	private function resolve_person( string $raw ): int {
		/*
		 * Live CMDBs store a custodian as "Jane Doe - jane.doe@example.com",
		 * not as a bare address, so pull the address out before looking anyone
		 * up. When there is no address at all (2 rows in a live export) we fall
		 * back to matching on display name.
		 */
		$parts = vh_split_person( $raw );
		$upn   = $parts['email'];

		if ( '' === $upn && '' !== $parts['name'] ) {
			$by_name = $this->person_by_display_name( $parts['name'] );
			if ( $by_name ) {
				return $by_name;
			}
		}

		if ( '' === $upn ) {
			return 0;
		}

		if ( isset( $this->person_cache[ $upn ] ) ) {
			return $this->person_cache[ $upn ];
		}

		$person = \VulnHub\Core\Repo::person_by_upn( $upn );
		$id     = $person ? (int) $person['id'] : 0;

		if ( ! $id ) {
			$this->note(
				sprintf(
					/* translators: %s: user principal name. */
					__( 'The CMDB assigns a CI to %s, who is not in the people directory yet.', 'vulnhub' ),
					$upn
				)
			);
		}

		$this->person_cache[ $upn ] = $id;

		return $id;
	}

	/**
	 * Record a note, de-duplicated, and mirror it to the run log.
	 */
	private function note( string $message ): void {
		if ( in_array( $message, $this->notes, true ) ) {
			return;
		}

		if ( count( $this->notes ) < 100 ) {
			$this->notes[] = $message;
			$this->log( $message );
		}
	}

	/**
	 * Notes collected during the last in-process run.
	 *
	 * @return array<int,string>
	 */
	public function notes(): array {
		return $this->notes;
	}

	/**
	 * Counters from the last in-process run.
	 *
	 * @return array<string,int>
	 */
	public function counts(): array {
		return $this->counts;
	}

	/* =================================================================
	 * Coverage reporting
	 * ============================================================== */

	/**
	 * How much of the estate has an owning team, a service and a site.
	 *
	 * This is the number the integration exists to move, so it is computed
	 * from the asset table rather than from what this connector happened to
	 * write — a CMDB that improves nothing should show that plainly.
	 *
	 * @return array{total:int,service:int,team:int,location:int,complete:int,by_type:array<int,array<string,mixed>>}
	 */
	public static function coverage(): array {
		global $wpdb;

		$table = vh_table( 'assets' );

		$row = (array) $wpdb->get_row(
			"SELECT COUNT(*) AS total,
				SUM(business_service <> '') AS service,
				SUM(team_id > 0) AS team,
				SUM(location_id > 0) AS location,
				SUM(business_service <> '' AND team_id > 0 AND location_id > 0) AS complete
			FROM {$table}", // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			ARRAY_A
		);

		$by_type = (array) $wpdb->get_results(
			"SELECT asset_type,
				COUNT(*) AS total,
				SUM(business_service <> '') AS service,
				SUM(team_id > 0) AS team,
				SUM(location_id > 0) AS location
			FROM {$table}
			GROUP BY asset_type
			ORDER BY total DESC", // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			ARRAY_A
		);

		return array(
			'total'    => (int) ( $row['total'] ?? 0 ),
			'service'  => (int) ( $row['service'] ?? 0 ),
			'team'     => (int) ( $row['team'] ?? 0 ),
			'location' => (int) ( $row['location'] ?? 0 ),
			'complete' => (int) ( $row['complete'] ?? 0 ),
			'by_type'  => $by_type,
		);
	}

	/**
	 * The assets still missing a team, a service or a site.
	 *
	 * @param string $gap   One of team|service|location|any.
	 * @param int    $limit Maximum rows.
	 * @return array<int,array<string,mixed>>
	 */
	public static function gaps( string $gap = 'any', int $limit = 100 ): array {
		global $wpdb;

		$where = match ( $gap ) {
			'team'     => 'team_id = 0',
			'service'  => "business_service = ''",
			'location' => 'location_id = 0',
			default    => "(team_id = 0 OR location_id = 0 OR business_service = '')",
		};

		$limit = max( 1, min( 500, $limit ) );

		return (array) $wpdb->get_results(
			$wpdb->prepare(
				'SELECT id, hostname, asset_type, primary_source, business_service, team_id, location_id, owner_person_id, open_critical, open_high
				FROM ' . vh_table( 'assets' ) . "
				WHERE {$where}
				ORDER BY (open_critical * 10 + open_high) DESC, hostname ASC
				LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$limit
			),
			ARRAY_A
		);
	}

	/**
	 * Persist run tallies, notes and a coverage snapshot for the CMDB screen.
	 *
	 * @param string $source Source used for the run.
	 */
	private function persist_run_summary( string $source ): void {
		$this->settings->update(
			$this->id(),
			array(
				'last_import'      => $this->counts,
				'last_import_at'   => vh_now(),
				'last_import_mode' => $this->is_mock() ? 'mock' : 'live',
				'last_source'      => $source,
				'last_notes'       => array_slice( $this->notes, 0, 25 ),
				'last_coverage'    => self::coverage(),
			)
		);
	}

	/**
	 * Parse a `dd/Mon/yy` date, with or without a trailing time.
	 *
	 * Jira Assets and Cherwell both export dates this way -- `18/Jun/27`,
	 * `04/Apr/25 12:02 AM` -- and PHP cannot read either: with slashes it
	 * assumes American m/d/y, and `Jun` in the middle makes the whole string
	 * unparseable, so `strtotime()` returns false and the date is silently
	 * lost. Two-digit years are windowed against the current century, which
	 * is safe here because a support date is never a century away.
	 *
	 * @param string $raw Raw cell.
	 * @return string `Y-m-d`, or empty when the cell is not this shape.
	 */
	private static function parse_short_date( string $raw ): string {
		$raw = trim( $raw );

		if ( '' === $raw ) {
			return '';
		}

		if ( 1 === preg_match( '#^(\d{1,2})/([A-Za-z]{3})/(\d{2}|\d{4})\b#', $raw, $m ) ) {
			$month = (int) gmdate( 'n', (int) strtotime( $m[2] . ' 1 2000' ) );

			if ( $month < 1 ) {
				return '';
			}

			$year = (int) $m[3];

			if ( $year < 100 ) {
				$year += 2000;
			}

			$day = (int) $m[1];

			if ( ! checkdate( $month, $day, $year ) ) {
				return '';
			}

			return sprintf( '%04d-%02d-%02d', $year, $month, $day );
		}

		// Anything already unambiguous is left to the core helper.
		$fallback = vh_to_mysql( $raw );

		return $fallback ? substr( (string) $fallback, 0, 10 ) : '';
	}
}

