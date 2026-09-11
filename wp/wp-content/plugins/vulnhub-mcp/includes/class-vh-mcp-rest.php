<?php
/**
 * The REST surface an agent drives VulnHub through.
 *
 * Three jobs, in the order they matter:
 *
 * 1. Read the estate -- assets, their identities and their coverage.
 * 2. Correct the CMDB. Ownership and classification data rots, and an agent
 *    reconciling it against a source of truth is exactly the kind of dull,
 *    high-volume work nobody does by hand.
 * 3. Map an asset on to its Tenable record, which is what turns a coverage
 *    gap into a covered asset.
 *
 * Writes go through `Repo::upsert_asset()`, the same path the connectors use,
 * so identity matching, normalisation and the ownership engine all behave the
 * way they do for a real sync. Every change is written to the audit log with
 * the acting user, because "an agent changed it" has to be answerable months
 * later.
 *
 * @package VulnHub\MCP
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;
use VulnHub\Core\Coverage;
use VulnHub\Core\Repo;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_MCP_Rest {

	/** Fields an agent is allowed to write on an asset. */
	private const WRITABLE = array(
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

	public function register_routes(): void {
		$read  = array( $this, 'can_read' );
		$write = array( $this, 'can_write' );

		register_rest_route(
			VULNHUB_MCP_NS,
			'/assets',
			array(
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => array( $this, 'list_assets' ),
					'permission_callback' => $read,
					'args'                => array(
						'search'     => array( 'type' => 'string' ),
						'asset_type' => array( 'type' => 'string' ),
						'coverage'   => array( 'type' => 'string' ),
						'limit'      => array( 'type' => 'integer', 'default' => 25 ),
						'offset'     => array( 'type' => 'integer', 'default' => 0 ),
					),
				),
				array(
					'methods'             => WP_REST_Server::CREATABLE,
					'callback'            => array( $this, 'upsert_asset' ),
					'permission_callback' => $write,
				),
			)
		);

		register_rest_route(
			VULNHUB_MCP_NS,
			'/assets/(?P<id>\d+)',
			array(
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => array( $this, 'get_asset' ),
					'permission_callback' => $read,
				),
				array(
					'methods'             => WP_REST_Server::EDITABLE,
					'callback'            => array( $this, 'update_asset' ),
					'permission_callback' => $write,
				),
			)
		);

		register_rest_route(
			VULNHUB_MCP_NS,
			'/assets/(?P<id>\d+)/tenable',
			array(
				'methods'             => WP_REST_Server::EDITABLE,
				'callback'            => array( $this, 'map_tenable' ),
				'permission_callback' => $write,
				'args'                => array(
					'tenable_uuid' => array( 'type' => 'string', 'required' => true ),
				),
			)
		);

		register_rest_route(
			VULNHUB_MCP_NS,
			'/coverage',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'coverage' ),
				'permission_callback' => $read,
				'args'                => array(
					'dimension' => array( 'type' => 'string', 'default' => 'asset_type' ),
				),
			)
		);

		register_rest_route(
			VULNHUB_MCP_NS,
			'/coverage/gaps',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'gaps' ),
				'permission_callback' => $read,
				'args'                => array(
					'state'      => array( 'type' => 'string' ),
					'asset_type' => array( 'type' => 'string' ),
					'search'     => array( 'type' => 'string' ),
					'limit'      => array( 'type' => 'integer', 'default' => 50 ),
					'offset'     => array( 'type' => 'integer', 'default' => 0 ),
				),
			)
		);

		register_rest_route(
			VULNHUB_MCP_NS,
			'/coverage/recalculate',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( $this, 'recalculate' ),
				'permission_callback' => $write,
			)
		);

		register_rest_route(
			VULNHUB_MCP_NS,
			'/teams',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => array( $this, 'teams' ),
				'permission_callback' => $read,
			)
		);
	}

	/* =================================================================
	 * Permission
	 * ============================================================== */

	public function can_read(): bool|WP_Error {
		if ( current_user_can( Caps::VIEW ) ) {
			return true;
		}

		return new WP_Error(
			'vulnhub_mcp_forbidden',
			__( 'This account cannot read VulnHub data.', 'vulnhub' ),
			array( 'status' => rest_authorization_required_code() )
		);
	}

	public function can_write(): bool|WP_Error {
		if ( current_user_can( Caps::MANAGE ) ) {
			return true;
		}

		return new WP_Error(
			'vulnhub_mcp_forbidden',
			__( 'This account cannot change VulnHub data.', 'vulnhub' ),
			array( 'status' => rest_authorization_required_code() )
		);
	}

	/* =================================================================
	 * Read
	 * ============================================================== */

	public function list_assets( WP_REST_Request $request ): WP_REST_Response {
		$q = Repo::assets(
			array(
				'search'     => (string) $request->get_param( 'search' ),
				'asset_type' => (string) $request->get_param( 'asset_type' ),
				'coverage'   => (string) $request->get_param( 'coverage' ),
				'limit'      => (int) $request->get_param( 'limit' ),
				'offset'     => (int) $request->get_param( 'offset' ),
			)
		);

		return new WP_REST_Response(
			array(
				'total'  => (int) $q['total'],
				'assets' => array_map( array( $this, 'shape' ), (array) $q['rows'] ),
			)
		);
	}

	public function get_asset( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$asset = Repo::asset( (int) $request['id'] );

		if ( ! $asset ) {
			return new WP_Error( 'vulnhub_mcp_not_found', __( 'No such asset.', 'vulnhub' ), array( 'status' => 404 ) );
		}

		return new WP_REST_Response( $this->shape( $asset ) );
	}

	public function coverage( WP_REST_Request $request ): WP_REST_Response {
		$dimension = (string) $request->get_param( 'dimension' );

		return new WP_REST_Response(
			array(
				'summary'    => Coverage::summary(),
				'dimension'  => $dimension,
				'dimensions' => array_keys( Coverage::dimensions() ),
				'breakdown'  => Coverage::by_dimension( $dimension, 25 ),
			)
		);
	}

	public function gaps( WP_REST_Request $request ): WP_REST_Response {
		$q = Coverage::gaps(
			array(
				'state'      => (string) $request->get_param( 'state' ),
				'asset_type' => (string) $request->get_param( 'asset_type' ),
				'search'     => (string) $request->get_param( 'search' ),
				'limit'      => (int) $request->get_param( 'limit' ),
				'offset'     => (int) $request->get_param( 'offset' ),
			)
		);

		return new WP_REST_Response(
			array(
				'total' => (int) $q['total'],
				'gaps'  => array_map( array( $this, 'shape' ), (array) $q['rows'] ),
			)
		);
	}

	public function teams(): WP_REST_Response {
		return new WP_REST_Response(
			array_map(
				static fn( array $t ): array => array(
					'id'   => (int) $t['id'],
					'name' => (string) $t['name'],
					'slug' => (string) ( $t['slug'] ?? '' ),
				),
				(array) Repo::teams()
			)
		);
	}

	/* =================================================================
	 * Write
	 * ============================================================== */

	public function upsert_asset( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$data = $this->clean( (array) $request->get_json_params() );

		if ( ! $data ) {
			return new WP_Error( 'vulnhub_mcp_empty', __( 'Nothing to write.', 'vulnhub' ), array( 'status' => 400 ) );
		}

		// Something has to identify the asset, or every call creates a new one.
		$identifiers = array_filter(
			array(
				$data['cmdb_id'] ?? '',
				$data['tenable_uuid'] ?? '',
				$data['intune_id'] ?? '',
				$data['serial_number'] ?? '',
				$data['hostname'] ?? '',
			)
		);

		if ( ! $identifiers ) {
			return new WP_Error(
				'vulnhub_mcp_no_identity',
				__( 'Give at least one of cmdb_id, tenable_uuid, intune_id, serial_number or hostname so the asset can be matched rather than duplicated.', 'vulnhub' ),
				array( 'status' => 400 )
			);
		}

		$data['primary_source'] = (string) ( $data['primary_source'] ?? 'mcp' );

		$result = Repo::upsert_asset( $data );
		$id     = (int) ( $result['id'] ?? 0 );

		$this->audit( $id, 'asset.upserted', $data );

		Coverage::recalculate();

		$asset = $id ? Repo::asset( $id ) : null;

		return new WP_REST_Response(
			array(
				'created' => ! empty( $result['created'] ),
				'asset'   => $asset ? $this->shape( $asset ) : null,
			)
		);
	}

	public function update_asset( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		$id    = (int) $request['id'];
		$asset = Repo::asset( $id );

		if ( ! $asset ) {
			return new WP_Error( 'vulnhub_mcp_not_found', __( 'No such asset.', 'vulnhub' ), array( 'status' => 404 ) );
		}

		$data = $this->clean( (array) $request->get_json_params() );

		if ( ! $data ) {
			return new WP_Error( 'vulnhub_mcp_empty', __( 'Nothing to write.', 'vulnhub' ), array( 'status' => 400 ) );
		}

		global $wpdb;

		$data['updated_at'] = vh_now();

		$wpdb->update( vh_table( 'assets' ), $data, array( 'id' => $id ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

		$this->audit( $id, 'asset.updated', $data );

		Coverage::recalculate();

		return new WP_REST_Response( $this->shape( (array) Repo::asset( $id ) ) );
	}

	/**
	 * Attach an asset to its Tenable record.
	 *
	 * This is the call that closes a coverage gap: an asset the CMDB knows
	 * about and Tenable does not is only a gap until somebody works out which
	 * Tenable record it really is.
	 */
	public function map_tenable( WP_REST_Request $request ): WP_REST_Response|WP_Error {
		global $wpdb;

		$id    = (int) $request['id'];
		$uuid  = trim( (string) $request->get_param( 'tenable_uuid' ) );
		$asset = Repo::asset( $id );

		if ( ! $asset ) {
			return new WP_Error( 'vulnhub_mcp_not_found', __( 'No such asset.', 'vulnhub' ), array( 'status' => 404 ) );
		}
		if ( '' === $uuid ) {
			return new WP_Error( 'vulnhub_mcp_no_uuid', __( 'A tenable_uuid is required.', 'vulnhub' ), array( 'status' => 400 ) );
		}

		// Refuse to point two assets at one Tenable record; that is a merge,
		// and a merge is not something to do silently on an agent's say-so.
		$taken = (int) $wpdb->get_var(
			$wpdb->prepare(
				'SELECT id FROM ' . vh_table( 'assets' ) . ' WHERE tenable_uuid = %s AND id <> %d LIMIT 1', // phpcs:ignore
				$uuid,
				$id
			)
		);

		if ( $taken ) {
			return new WP_Error(
				'vulnhub_mcp_uuid_taken',
				sprintf(
					/* translators: %d: asset id. */
					__( 'Asset %d already carries that Tenable UUID. Merging two asset records is a deliberate act, not a mapping.', 'vulnhub' ),
					$taken
				),
				array( 'status' => 409 )
			);
		}

		$wpdb->update( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			vh_table( 'assets' ),
			array(
				'tenable_uuid' => $uuid,
				'updated_at'   => vh_now(),
			),
			array( 'id' => $id )
		);

		$this->audit( $id, 'asset.tenable_mapped', array( 'tenable_uuid' => $uuid ) );

		Coverage::recalculate();

		return new WP_REST_Response( $this->shape( (array) Repo::asset( $id ) ) );
	}

	public function recalculate(): WP_REST_Response {
		Coverage::recalculate();

		return new WP_REST_Response( Coverage::summary() );
	}

	/* =================================================================
	 * Helpers
	 * ============================================================== */

	/**
	 * @param array<string,mixed> $in Raw request body.
	 * @return array<string,string>
	 */
	private function clean( array $in ): array {
		$out = array();

		foreach ( self::WRITABLE as $field ) {
			if ( ! array_key_exists( $field, $in ) ) {
				continue;
			}

			$value = is_scalar( $in[ $field ] ) ? (string) $in[ $field ] : '';

			if ( 'lifecycle_status' === $field ) {
				$value = vh_normalise_lifecycle( $value );
			}
			if ( 'ipv4' === $field ) {
				$value = vh_clean_ip( $value );
			}

			$out[ $field ] = sanitize_text_field( $value );
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $row Asset row.
	 * @return array<string,mixed>
	 */
	private function shape( array $row ): array {
		$state = (string) ( $row['coverage_state'] ?? '' );

		return array(
			'id'                => (int) ( $row['id'] ?? 0 ),
			'hostname'          => (string) ( $row['hostname'] ?? '' ),
			'fqdn'              => (string) ( $row['fqdn'] ?? '' ),
			'ipv4'              => (string) ( $row['ipv4'] ?? '' ),
			'asset_type'        => (string) ( $row['asset_type'] ?? '' ),
			'operating_system'  => (string) ( $row['operating_system'] ?? '' ),
			'criticality'       => (string) ( $row['criticality'] ?? '' ),
			'environment'       => (string) ( $row['environment'] ?? '' ),
			'lifecycle_status'  => (string) ( $row['lifecycle_status'] ?? '' ),
			'identities'        => array(
				'tenable_uuid'  => (string) ( $row['tenable_uuid'] ?? '' ),
				'intune_id'     => (string) ( $row['intune_id'] ?? '' ),
				'cmdb_id'       => (string) ( $row['cmdb_id'] ?? '' ),
				'serial_number' => (string) ( $row['serial_number'] ?? '' ),
			),
			'owner'             => array(
				'person' => (string) ( $row['owner_name'] ?? '' ),
				'team'   => (string) ( $row['team_name'] ?? '' ),
				'source' => (string) ( $row['owner_source'] ?? '' ),
			),
			'coverage'          => array(
				'state'     => $state,
				'label'     => $state ? Coverage::label( $state ) : '',
				'is_gap'    => $state ? in_array( $state, Coverage::gap_states(), true ) : false,
				'last_scan' => (string) ( $row['tenable_last_scan'] ?? '' ),
			),
			'open_findings'     => array(
				'critical' => (int) ( $row['open_critical'] ?? 0 ),
				'high'     => (int) ( $row['open_high'] ?? 0 ),
				'medium'   => (int) ( $row['open_medium'] ?? 0 ),
				'low'      => (int) ( $row['open_low'] ?? 0 ),
			),
			'risk_score'        => (float) ( $row['risk_score'] ?? 0 ),
		);
	}

	/**
	 * @param array<string,mixed> $data What changed.
	 */
	private function audit( int $asset_id, string $action, array $data ): void {
		vulnhub()->logger->audit(
			$action,
			sprintf(
				/* translators: 1: action, 2: asset id. */
				__( 'MCP client performed %1$s on asset %2$d.', 'vulnhub' ),
				$action,
				$asset_id
			),
			'asset',
			(string) $asset_id,
			array(
				'fields' => array_keys( $data ),
				'via'    => 'mcp',
			)
		);
	}
}
