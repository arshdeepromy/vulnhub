<?php
/**
 * The importer's REST surface.
 *
 * Every route is authenticated twice over: a real `permission_callback` that
 * demands `vulnhub_manage`, and a nonce of our own on top of the cookie
 * authentication WordPress already applies. None of these routes is public and
 * none of them uses `__return_true`.
 *
 * @package VulnHub\Import
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Upload, mapping, preview, progress and control endpoints.
 */
final class VulnHub_Import_Rest {

	/** REST namespace. */
	public const NS = 'vulnhub-import/v1';

	/** Nonce action for every call this plugin makes. */
	public const NONCE = 'vulnhub_import';

	/** How many rows the dry-run preview shows. */
	private const PREVIEW_ROWS = 20;

	/**
	 * Register every route.
	 *
	 * @return void
	 */
	public function register_routes(): void {
		$guard = array( $this, 'can_manage' );

		register_rest_route(
			self::NS,
			'/upload/begin',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'upload_begin' ),
				'permission_callback' => $guard,
				'args'                => array(
					'filename' => array(
						'type'     => 'string',
						'required' => true,
					),
					'size'     => array(
						'type'     => 'integer',
						'required' => true,
					),
				),
			)
		);

		register_rest_route(
			self::NS,
			'/upload/chunk',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'upload_chunk' ),
				'permission_callback' => $guard,
			)
		);

		register_rest_route(
			self::NS,
			'/upload/status',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'upload_status' ),
				'permission_callback' => $guard,
				'args'                => array(
					'key' => array(
						'type'     => 'string',
						'required' => true,
					),
				),
			)
		);

		register_rest_route(
			self::NS,
			'/upload/finish',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'upload_finish' ),
				'permission_callback' => $guard,
			)
		);

		register_rest_route(
			self::NS,
			'/jobs',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'list_jobs' ),
				'permission_callback' => $guard,
			)
		);

		register_rest_route(
			self::NS,
			'/jobs/(?P<id>\d+)',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'get_job' ),
				'permission_callback' => $guard,
			)
		);

		register_rest_route(
			self::NS,
			'/jobs/(?P<id>\d+)/remap',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'remap' ),
				'permission_callback' => $guard,
			)
		);

		register_rest_route(
			self::NS,
			'/jobs/(?P<id>\d+)/start',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'start' ),
				'permission_callback' => $guard,
			)
		);

		register_rest_route(
			self::NS,
			'/jobs/(?P<id>\d+)/pass',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'pass' ),
				'permission_callback' => $guard,
			)
		);

		register_rest_route(
			self::NS,
			'/jobs/(?P<id>\d+)/cancel',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'cancel' ),
				'permission_callback' => $guard,
			)
		);
	}

	/**
	 * Permission callback: a real capability check plus our own nonce.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return true|WP_Error
	 */
	public function can_manage( WP_REST_Request $request ) {
		if ( ! is_user_logged_in() || ! current_user_can( Caps::MANAGE ) ) {
			return new WP_Error(
				'vulnhub_import_forbidden',
				__( 'You do not have permission to import data.', 'vulnhub' ),
				array( 'status' => rest_authorization_required_code() )
			);
		}

		$nonce = (string) ( $request->get_header( 'x-vh-import-nonce' ) ?: $request->get_param( '_vh_nonce' ) );

		if ( ! wp_verify_nonce( $nonce, self::NONCE ) ) {
			return new WP_Error(
				'vulnhub_import_nonce',
				__( 'That request expired. Reload the page and try again.', 'vulnhub' ),
				array( 'status' => 403 )
			);
		}

		return true;
	}

	/* =================================================================
	 * Upload
	 * ============================================================== */

	/**
	 * Open a chunked upload session.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function upload_begin( WP_REST_Request $request ) {
		$name = VulnHub_Import_Storage::safe_name( (string) $request->get_param( 'filename' ) );
		$size = (int) $request->get_param( 'size' );

		if ( ! VulnHub_Import_Storage::allowed_extension( $name ) ) {
			return new WP_Error(
				'vulnhub_import_type',
				__( 'Only .csv, .tsv and .txt files are accepted.', 'vulnhub' ),
				array( 'status' => 400 )
			);
		}

		if ( $size <= 0 ) {
			return new WP_Error(
				'vulnhub_import_size',
				__( 'That file is empty.', 'vulnhub' ),
				array( 'status' => 400 )
			);
		}

		if ( $size > VulnHub_Import_Storage::max_bytes() ) {
			return new WP_Error(
				'vulnhub_import_size',
				sprintf(
					/* translators: 1: size of the chosen file, 2: the importer's limit. */
					__( 'That file is %1$s. This importer accepts up to %2$s.', 'vulnhub' ),
					size_format( $size ),
					size_format( VulnHub_Import_Storage::max_bytes() )
				),
				array( 'status' => 400 )
			);
		}

		/*
		 * Fail now, not two hundred slices in. A staged file is written whole
		 * to disk before a row of it is read, and finding that out at 94%
		 * wastes the operator's afternoon.
		 */
		$headroom = VulnHub_Import_Storage::disk_headroom();

		if ( $headroom > 0 && $size > $headroom ) {
			return new WP_Error(
				'vulnhub_import_disk',
				sprintf(
					/* translators: 1: size of the chosen file, 2: free space available to staging. */
					__( 'That file is %1$s and only %2$s of staging space is free. Free some disk, or import it in parts.', 'vulnhub' ),
					size_format( $size ),
					size_format( $headroom )
				),
				array( 'status' => 507 )
			);
		}

		$key = VulnHub_Import_Storage::begin();

		if ( '' === $key ) {
			return new WP_Error(
				'vulnhub_import_storage',
				__( 'The staging directory could not be created. Check the uploads folder is writable.', 'vulnhub' ),
				array( 'status' => 500 )
			);
		}

		return rest_ensure_response(
			array(
				'key'       => $key,
				'name'      => $name,
				'chunkSize' => VulnHub_Import_Storage::chunk_size(),
				'maxChunk'  => VulnHub_Import_Storage::chunk_max(),
				'maxBytes'  => VulnHub_Import_Storage::max_bytes(),
			)
		);
	}

	/**
	 * How much of a session has landed.
	 *
	 * The uploader calls this after a slice fails, so a dropped connection
	 * costs one slice rather than the whole file.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function upload_status( WP_REST_Request $request ) {
		$key = (string) $request->get_param( 'key' );

		if ( ! VulnHub_Import_Storage::valid_key( $key ) || ! VulnHub_Import_Storage::exists( $key ) ) {
			return new WP_Error(
				'vulnhub_import_key',
				__( 'That upload session is not valid.', 'vulnhub' ),
				array( 'status' => 404 )
			);
		}

		return rest_ensure_response(
			array( 'received' => VulnHub_Import_Storage::staged_size( $key ) )
		);
	}

	/**
	 * Append one slice to the staged file.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function upload_chunk( WP_REST_Request $request ) {
		$key    = (string) $request->get_param( 'key' );
		$offset = (int) $request->get_param( 'offset' );
		$files  = $request->get_file_params();
		$file   = (array) ( $files['chunk'] ?? array() );

		if ( ! VulnHub_Import_Storage::valid_key( $key ) ) {
			return new WP_Error(
				'vulnhub_import_key',
				__( 'That upload session is not valid.', 'vulnhub' ),
				array( 'status' => 400 )
			);
		}

		if ( ! $file ) {
			return new WP_Error(
				'vulnhub_import_chunk',
				__( 'No slice was attached to that request.', 'vulnhub' ),
				array( 'status' => 400 )
			);
		}

		$result = VulnHub_Import_Storage::append( $key, $offset, $file );

		if ( ! $result['ok'] ) {
			return new WP_Error(
				'vulnhub_import_chunk',
				$result['message'],
				array(
					'status'   => 400,
					// So a client that lost track can carry on rather than
					// starting a half-gigabyte upload again.
					'received' => VulnHub_Import_Storage::staged_size( $key ),
				)
			);
		}

		return rest_ensure_response(
			array(
				'received' => $result['size'],
			)
		);
	}

	/**
	 * Close the upload, analyse the file and create the pending job.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function upload_finish( WP_REST_Request $request ) {
		$key  = (string) $request->get_param( 'key' );
		$name = VulnHub_Import_Storage::safe_name( (string) $request->get_param( 'filename' ) );

		if ( ! VulnHub_Import_Storage::valid_key( $key ) || ! VulnHub_Import_Storage::exists( $key ) ) {
			return new WP_Error(
				'vulnhub_import_key',
				__( 'That upload session is not valid.', 'vulnhub' ),
				array( 'status' => 400 )
			);
		}

		$sniff = VulnHub_Import_Storage::sniff( $key );

		if ( ! $sniff['ok'] ) {
			VulnHub_Import_Storage::delete( $key );

			return new WP_Error( 'vulnhub_import_content', $sniff['message'], array( 'status' => 400 ) );
		}

		$path   = VulnHub_Import_Storage::path( $key );
		$size   = VulnHub_Import_Storage::size( $key );
		$header = VulnHub_Import_Reader::read_header( $path );

		if ( ! $header['ok'] ) {
			VulnHub_Import_Storage::delete( $key );

			return new WP_Error( 'vulnhub_import_header', $header['message'], array( 'status' => 400 ) );
		}

		$sample = VulnHub_Import_Reader::sample( $path, $header['delimiter'], $header['headers'], $header['offset'], self::PREVIEW_ROWS );
		$shape  = VulnHub_Import_Schema::detect_shape( $header['headers'] );
		$map    = VulnHub_Import_Schema::detect_mapping( $shape, $header['headers'], $sample['rows'] );

		$job_id = VulnHub_Import_Jobs::create(
			array(
				'type'                => VulnHub_Import_Schema::type_for_shape( $shape ),
				'shape'               => $shape,
				'filename'            => $name,
				'storage_key'         => $key,
				'size_bytes'          => $size,
				'content_hash'        => VulnHub_Import_Storage::hash( $key ),
				'status'              => VulnHub_Import_Jobs::PENDING,
				'rows_total_estimate' => VulnHub_Import_Reader::estimate_rows( $size, (int) $header['offset'], (int) $sample['bytes'], count( $sample['rows'] ) ),
				'column_map'          => array(
					'headers'       => $header['headers'],
					'delimiter'     => $header['delimiter'],
					'header_offset' => (int) $header['offset'],
					'map'           => $map,
				),
			)
		);

		if ( ! $job_id ) {
			VulnHub_Import_Storage::delete( $key );

			return new WP_Error(
				'vulnhub_import_job',
				__( 'The import job could not be created.', 'vulnhub' ),
				array( 'status' => 500 )
			);
		}

		return rest_ensure_response( $this->job_payload( $job_id, true ) );
	}

	/* =================================================================
	 * Mapping, preview and control
	 * ============================================================== */

	/**
	 * Change the shape or the column mapping of a pending job.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function remap( WP_REST_Request $request ) {
		$job = VulnHub_Import_Jobs::get( (int) $request->get_param( 'id' ) );

		if ( ! $job ) {
			return new WP_Error( 'vulnhub_import_missing', __( 'That import job no longer exists.', 'vulnhub' ), array( 'status' => 404 ) );
		}

		if ( VulnHub_Import_Jobs::PENDING !== (string) $job['status'] ) {
			return new WP_Error(
				'vulnhub_import_locked',
				__( 'The column mapping can only be changed before the job starts.', 'vulnhub' ),
				array( 'status' => 400 )
			);
		}

		$plan    = (array) $job['column_map_arr'];
		$headers = array_map( 'strval', (array) ( $plan['headers'] ?? array() ) );
		$shape   = sanitize_key( (string) $request->get_param( 'shape' ) );

		if ( ! array_key_exists( $shape, VulnHub_Import_Schema::shapes() ) ) {
			$shape = (string) $job['shape'];
		}

		$submitted = $request->get_param( 'map' );
		$submitted = is_array( $submitted ) ? $submitted : array();

		if ( $submitted ) {
			$map = VulnHub_Import_Schema::sanitise_mapping( $shape, $submitted, $headers );
		} else {
			$sample = VulnHub_Import_Reader::sample(
				VulnHub_Import_Storage::path( (string) $job['storage_key'] ),
				(string) ( $plan['delimiter'] ?? ',' ),
				$headers,
				(int) ( $plan['header_offset'] ?? 0 ),
				self::PREVIEW_ROWS
			);

			$map = VulnHub_Import_Schema::detect_mapping( $shape, $headers, $sample['rows'] );
		}

		$plan['map'] = $map;

		VulnHub_Import_Jobs::update(
			(int) $job['id'],
			array(
				'shape'      => $shape,
				'type'       => VulnHub_Import_Schema::type_for_shape( $shape ),
				'column_map' => (string) wp_json_encode( $plan ),
			)
		);

		return rest_ensure_response( $this->job_payload( (int) $job['id'], true ) );
	}

	/**
	 * Start a prepared job.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function start( WP_REST_Request $request ) {
		$id  = (int) $request->get_param( 'id' );
		$job = VulnHub_Import_Jobs::get( $id );

		if ( ! $job ) {
			return new WP_Error( 'vulnhub_import_missing', __( 'That import job no longer exists.', 'vulnhub' ), array( 'status' => 404 ) );
		}

		if ( 'cmdb' === (string) $job['type'] && ! VulnHub_Import_Cmdb::available() ) {
			return new WP_Error(
				'vulnhub_import_cmdb',
				VulnHub_Import_Cmdb::unavailable_message(),
				array( 'status' => 400 )
			);
		}

		$missing = array();

		foreach ( VulnHub_Import_Schema::required( (string) $job['shape'] ) as $field ) {
			if ( empty( $job['column_map_arr']['map'][ $field ] ) ) {
				$missing[] = $field;
			}
		}

		if ( $missing ) {
			return new WP_Error(
				'vulnhub_import_mapping',
				sprintf(
					/* translators: %s: comma-separated field names. */
					__( 'These fields must be mapped before the import can start: %s', 'vulnhub' ),
					implode( ', ', $missing )
				),
				array( 'status' => 400 )
			);
		}

		$result = VulnHub_Import_Runner::start( $id );

		if ( ! $result['ok'] ) {
			return new WP_Error( 'vulnhub_import_start', $result['message'], array( 'status' => 400 ) );
		}

		// Get the first batch moving immediately so the operator sees progress
		// rather than waiting on the next cron tick.
		VulnHub_Import_Runner::run( $id, VulnHub_Import_Runner::WEB_BUDGET );

		return rest_ensure_response( $this->job_payload( $id ) );
	}

	/**
	 * Run one short pass inline. This is what the progress poller calls, so a
	 * watched import advances promptly; cron does the same work unattended.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function pass( WP_REST_Request $request ) {
		$id = (int) $request->get_param( 'id' );

		VulnHub_Import_Runner::run( $id, VulnHub_Import_Runner::WEB_BUDGET );

		return rest_ensure_response( $this->job_payload( $id ) );
	}

	/**
	 * Cancel a running job.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function cancel( WP_REST_Request $request ) {
		$id     = (int) $request->get_param( 'id' );
		$result = VulnHub_Import_Runner::cancel( $id );

		if ( ! $result['ok'] ) {
			return new WP_Error( 'vulnhub_import_cancel', $result['message'], array( 'status' => 400 ) );
		}

		return rest_ensure_response( $this->job_payload( $id ) );
	}

	/**
	 * Progress for one job.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function get_job( WP_REST_Request $request ) {
		$id      = (int) $request->get_param( 'id' );
		$payload = $this->job_payload( $id, (bool) $request->get_param( 'preview' ) );

		if ( ! $payload ) {
			return new WP_Error( 'vulnhub_import_missing', __( 'That import job no longer exists.', 'vulnhub' ), array( 'status' => 404 ) );
		}

		return rest_ensure_response( $payload );
	}

	/**
	 * Recent job history.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response
	 */
	public function list_jobs( WP_REST_Request $request ) {
		$limit = (int) ( $request->get_param( 'limit' ) ?: 25 );
		$jobs  = array();

		foreach ( VulnHub_Import_Jobs::recent( $limit ) as $job ) {
			$jobs[] = self::summarise( $job );
		}

		return rest_ensure_response( array( 'jobs' => $jobs ) );
	}

	/* =================================================================
	 * Payload building
	 * ============================================================== */

	/**
	 * Everything the screen needs about one job.
	 *
	 * @param int  $id      Job id.
	 * @param bool $preview Include the mapping table and the dry-run rows.
	 * @return array<string,mixed>|null
	 */
	private function job_payload( int $id, bool $preview = false ): ?array {
		$job = VulnHub_Import_Jobs::get( $id );

		if ( ! $job ) {
			return null;
		}

		$payload = self::summarise( $job );

		if ( ! $preview ) {
			return $payload;
		}

		$plan    = (array) $job['column_map_arr'];
		$headers = array_map( 'strval', (array) ( $plan['headers'] ?? array() ) );
		$shape   = (string) $job['shape'];
		$map     = (array) ( $plan['map'] ?? array() );

		$rows = array();

		if ( VulnHub_Import_Storage::exists( (string) $job['storage_key'] ) ) {
			$sample = VulnHub_Import_Reader::sample(
				VulnHub_Import_Storage::path( (string) $job['storage_key'] ),
				(string) ( $plan['delimiter'] ?? ',' ),
				$headers,
				(int) ( $plan['header_offset'] ?? 0 ),
				self::PREVIEW_ROWS
			);

			$rows = $sample['rows'];
		}

		$payload['headers']    = $headers;
		$payload['fields']     = VulnHub_Import_Schema::fields( $shape );
		$payload['required']   = VulnHub_Import_Schema::required( $shape );
		$payload['map']        = $map;
		$payload['shapes']     = VulnHub_Import_Schema::shapes();
		$payload['preview']    = self::preview_rows( $shape, $map, $rows );
		$payload['samples']    = self::first_values( $headers, $rows );
		$payload['duplicate']  = self::duplicate_notice( $job );
		$payload['cmdbActive'] = VulnHub_Import_Cmdb::available();

		return $payload;
	}

	/**
	 * Turn a job row into the flat structure the screen and the poller use.
	 *
	 * @param array<string,mixed> $job Hydrated job row.
	 * @return array<string,mixed>
	 */
	public static function summarise( array $job ): array {
		$counters = (array) $job['counters_arr'];
		$total    = (int) $job['rows_total_estimate'];
		$done     = (int) $job['rows_done'];
		$size     = (int) $job['size_bytes'];
		$offset   = (int) $job['byte_offset'];

		$percent = $size > 0
			? min( 100.0, round( ( $offset / $size ) * 100, 1 ) )
			: ( $total > 0 ? min( 100.0, round( ( $done / $total ) * 100, 1 ) ) : 0.0 );

		if ( VulnHub_Import_Jobs::DONE === (string) $job['status'] ) {
			$percent = 100.0;
		}

		unset( $counters['failures'] );

		return array(
			'id'          => (int) $job['id'],
			'type'        => (string) $job['type'],
			'shape'       => (string) $job['shape'],
			'filename'    => (string) $job['filename'],
			'sizeBytes'   => $size,
			'sizeLabel'   => size_format( $size, 1 ),
			'hash'        => (string) $job['content_hash'],
			'status'      => (string) $job['status'],
			'statusLabel' => (string) ( VulnHub_Import_Jobs::statuses()[ (string) $job['status'] ] ?? $job['status'] ),
			'byteOffset'  => $offset,
			'rowsDone'    => $done,
			'rowsTotal'   => $total,
			'percent'     => $percent,
			'counters'    => $counters,
			'error'       => (string) $job['error'],
			'createdAt'   => (string) $job['created_at'],
			'startedAt'   => (string) $job['started_at'],
			'finishedAt'  => (string) $job['finished_at'],
			'seconds'     => (float) ( $job['counters_arr']['seconds'] ?? 0 ),
			'failures'    => array_slice( (array) ( $job['counters_arr']['failures'] ?? array() ), 0, 100 ),
		);
	}

	/**
	 * The first non-empty value seen in each column, so the mapping table can
	 * show the operator what a column actually holds rather than only its name.
	 *
	 * @param array<int,string>               $headers Column headers.
	 * @param array<int,array<string,string>> $rows    Sample rows.
	 * @return array<string,string>
	 */
	private static function first_values( array $headers, array $rows ): array {
		$values = array();

		foreach ( $headers as $header ) {
			$values[ $header ] = '';

			foreach ( $rows as $row ) {
				$value = trim( (string) ( $row[ $header ] ?? '' ) );

				if ( '' !== $value ) {
					$values[ $header ] = vh_trim( $value, 70 );
					break;
				}
			}
		}

		return $values;
	}

	/**
	 * Build the dry-run preview: what the first rows will actually become.
	 *
	 * @param string                          $shape Shape key.
	 * @param array<string,string>            $map   canonical field => header.
	 * @param array<int,array<string,string>> $rows  Raw rows.
	 * @return array{columns:array<int,string>,rows:array<int,array<int,string>>}
	 */
	private static function preview_rows( string $shape, array $map, array $rows ): array {
		if ( VulnHub_Import_Schema::SHAPE_VULN === $shape ) {
			$columns = array(
				__( 'Row', 'vulnhub' ),
				__( 'Asset', 'vulnhub' ),
				__( 'Plugin', 'vulnhub' ),
				__( 'Name', 'vulnhub' ),
				__( 'Severity', 'vulnhub' ),
				__( 'Port', 'vulnhub' ),
				__( 'State', 'vulnhub' ),
			);

			$out = array();

			foreach ( $rows as $index => $row ) {
				$record = VulnHub_Import_Schema::apply( $row, $map );
				$shown  = VulnHub_Import_Tenable::describe_vuln_row( $record );

				$out[] = array(
					(string) ( $index + 1 ),
					$shown['asset'],
					$shown['plugin'],
					$shown['name'],
					$shown['severity'],
					'0' === $shown['port'] ? '' : $shown['port'] . '/' . $shown['protocol'],
					$shown['state'],
				);
			}

			return array(
				'columns' => $columns,
				'rows'    => $out,
			);
		}

		if ( VulnHub_Import_Schema::SHAPE_ASSET === $shape ) {
			$columns = array(
				__( 'Row', 'vulnhub' ),
				__( 'Asset UUID', 'vulnhub' ),
				__( 'Hostname', 'vulnhub' ),
				__( 'IPv4', 'vulnhub' ),
				__( 'Type', 'vulnhub' ),
				__( 'Tags', 'vulnhub' ),
				__( 'Last seen', 'vulnhub' ),
			);

			$out = array();

			foreach ( $rows as $index => $row ) {
				$record = VulnHub_Import_Schema::apply( $row, $map );
				$tags   = VulnHub_Import_Tenable::parse_tags( (string) ( $record['tags'] ?? '' ) );
				$ips    = VulnHub_Import_Tenable::split_list( (string) ( $record['ipv4s'] ?? '' ) );
				$names  = VulnHub_Import_Tenable::split_list( (string) ( $record['hostname'] ?? '' ) );
				$fqdns  = VulnHub_Import_Tenable::split_list( (string) ( $record['fqdn'] ?? '' ) );

				$labels = array();
				foreach ( array_slice( $tags, 0, 3 ) as $tag ) {
					$labels[] = trim( ( $tag['category'] ?? '' ) . ': ' . ( $tag['value'] ?? '' ), ' :' );
				}

				$out[] = array(
					(string) ( $index + 1 ),
					vh_trim( (string) ( $record['asset_uuid'] ?? '' ), 38 ),
					(string) ( $names[0] ?? $fqdns[0] ?? '' ),
					(string) ( $ips[0] ?? '' ),
					VulnHub_Import_Tenable::asset_type( $tags, (string) ( $record['operating_system'] ?? '' ), (string) ( $names[0] ?? '' ), (string) ( $record['system_type'] ?? '' ) ),
					implode( ', ', $labels ),
					VulnHub_Import_Tenable::date( (string) ( $record['last_seen'] ?? '' ) ),
				);
			}

			return array(
				'columns' => $columns,
				'rows'    => $out,
			);
		}

		$columns = array(
			__( 'Row', 'vulnhub' ),
			__( 'Hostname', 'vulnhub' ),
			__( 'CI id', 'vulnhub' ),
			__( 'Type', 'vulnhub' ),
			__( 'Team', 'vulnhub' ),
			__( 'Custodian', 'vulnhub' ),
			__( 'Verdict', 'vulnhub' ),
		);

		$out = array();

		foreach ( $rows as $index => $row ) {
			$record  = VulnHub_Import_Cmdb::map_row( $row, $map );
			$problem = $record ? VulnHub_Import_Cmdb::validate( $record ) : VulnHub_Import_Cmdb::unavailable_message();

			$out[] = array(
				(string) ( $index + 1 ),
				(string) ( $record['hostname'] ?? '' ),
				(string) ( $record['cmdb_id'] ?? '' ),
				(string) ( $record['asset_type'] ?? '' ),
				(string) ( $record['team'] ?? '' ),
				(string) ( $record['assigned_to'] ?? '' ),
				'' === $problem ? __( 'OK', 'vulnhub' ) : $problem,
			);
		}

		return array(
			'columns' => $columns,
			'rows'    => $out,
		);
	}

	/**
	 * "You have already imported this exact file" — a warning, never a block.
	 *
	 * @param array<string,mixed> $job Hydrated job row.
	 * @return array<string,mixed> Empty when this content is new.
	 */
	private static function duplicate_notice( array $job ): array {
		$previous = VulnHub_Import_Jobs::previous_with_hash( (string) $job['content_hash'], (int) $job['id'] );

		if ( ! $previous ) {
			return array();
		}

		return array(
			'id'       => (int) $previous['id'],
			'filename' => (string) $previous['filename'],
			'when'     => vh_date( (string) ( $previous['finished_at'] ?: $previous['created_at'] ) ),
			'rows'     => (int) $previous['rows_done'],
		);
	}
}

