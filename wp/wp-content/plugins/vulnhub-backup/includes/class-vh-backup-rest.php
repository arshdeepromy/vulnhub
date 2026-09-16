<?php
/**
 * The backup plugin's REST surface — upload, jobs, progress and control.
 *
 * Every route demands a real capability (never __return_true), exactly as
 * VulnHub_Import_Rest does.
 *
 * @package VulnHub\Backup
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Upload, job control, progress and download endpoints.
 */
final class VulnHub_Backup_Rest {

	public const NS    = 'vulnhub-backup/v1';
	public const NONCE = 'vulnhub_backup';

	/**
	 * Register every route.
	 *
	 * @return void
	 */
	public function register_routes(): void {
		$guard = array( $this, 'can_manage' );

		register_rest_route( self::NS, '/backup/now', array( 'methods' => 'POST', 'callback' => array( $this, 'backup_now' ), 'permission_callback' => $guard ) );
		register_rest_route( self::NS, '/jobs', array( 'methods' => 'GET', 'callback' => array( $this, 'list_jobs' ), 'permission_callback' => $guard ) );
		register_rest_route( self::NS, '/jobs/(?P<id>\d+)', array( 'methods' => 'GET', 'callback' => array( $this, 'get_job' ), 'permission_callback' => $guard ) );
		register_rest_route( self::NS, '/jobs/(?P<id>\d+)/pass', array( 'methods' => 'POST', 'callback' => array( $this, 'pass' ), 'permission_callback' => $guard ) );
		register_rest_route( self::NS, '/jobs/(?P<id>\d+)/cancel', array( 'methods' => 'POST', 'callback' => array( $this, 'cancel' ), 'permission_callback' => $guard ) );

		register_rest_route( self::NS, '/restore/upload/begin', array( 'methods' => 'POST', 'callback' => array( $this, 'upload_begin' ), 'permission_callback' => $guard ) );
		register_rest_route( self::NS, '/restore/upload/chunk', array( 'methods' => 'POST', 'callback' => array( $this, 'upload_chunk' ), 'permission_callback' => $guard ) );
		register_rest_route( self::NS, '/restore/upload/status', array( 'methods' => 'GET', 'callback' => array( $this, 'upload_status' ), 'permission_callback' => $guard ) );
		register_rest_route( self::NS, '/restore/upload/finish', array( 'methods' => 'POST', 'callback' => array( $this, 'upload_finish' ), 'permission_callback' => $guard ) );
		register_rest_route( self::NS, '/restore/start', array( 'methods' => 'POST', 'callback' => array( $this, 'restore_start' ), 'permission_callback' => $guard ) );
		register_rest_route( self::NS, '/restore/jobs/(?P<id>\d+)/pass', array( 'methods' => 'POST', 'callback' => array( $this, 'restore_pass' ), 'permission_callback' => $guard ) );

		register_rest_route(
			self::NS,
			'/download/(?P<folder>[a-z0-9\-]+)/(?P<filename>[a-z0-9\.\-]+)',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'download' ),
				// A direct capability check, not the nonce-carrying guard —
				// this is followed as a plain browser link/download, which
				// cannot attach a custom X-VH-Backup-Nonce header.
				'permission_callback' => static fn(): bool => is_user_logged_in() && current_user_can( Caps::MANAGE ),
			)
		);
	}

	/**
	 * Stream one file from a completed local backup set.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_Error|void Never returns normally on success — exits after
	 *                       streaming the file.
	 */
	public function download( WP_REST_Request $request ) {
		$folder   = (string) $request->get_param( 'folder' );
		$filename = (string) $request->get_param( 'filename' );
		$path     = VulnHub_Backup_Storage::path_for_download( $folder, $filename );

		if ( '' === $path ) {
			return new WP_Error( 'vulnhub_backup_download', __( 'That file does not exist.', 'vulnhub' ), array( 'status' => 404 ) );
		}

		nocache_headers();
		header( 'Content-Type: application/octet-stream' );
		header( 'Content-Disposition: attachment; filename="' . basename( $path ) . '"' );
		header( 'Content-Length: ' . filesize( $path ) );

		readfile( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		exit;
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
				'vulnhub_backup_forbidden',
				__( 'You do not have permission to manage backups.', 'vulnhub' ),
				array( 'status' => rest_authorization_required_code() )
			);
		}

		$nonce = (string) ( $request->get_header( 'x-vh-backup-nonce' ) ?: $request->get_param( '_vh_nonce' ) );

		if ( ! wp_verify_nonce( $nonce, self::NONCE ) ) {
			return new WP_Error(
				'vulnhub_backup_nonce',
				__( 'That request expired. Reload the page and try again.', 'vulnhub' ),
				array( 'status' => 403 )
			);
		}

		return true;
	}

	/* =================================================================
	 * Backup jobs
	 * ============================================================== */

	/**
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response
	 */
	public function backup_now( WP_REST_Request $request ): WP_REST_Response {
		unset( $request );

		$job_id = VulnHub_Backup_Runner::start_new( 'manual' );

		return rest_ensure_response( array( 'jobId' => $job_id ) );
	}

	/**
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response
	 */
	public function list_jobs( WP_REST_Request $request ): WP_REST_Response {
		$limit = (int) ( $request->get_param( 'limit' ) ?: 25 );
		$jobs  = array_map( array( __CLASS__, 'summarise' ), VulnHub_Backup_Jobs::recent( $limit ) );

		return rest_ensure_response( array( 'jobs' => $jobs ) );
	}

	/**
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function get_job( WP_REST_Request $request ) {
		$job = VulnHub_Backup_Jobs::get( (int) $request->get_param( 'id' ) );

		if ( ! $job ) {
			return new WP_Error( 'vulnhub_backup_missing', __( 'That backup job no longer exists.', 'vulnhub' ), array( 'status' => 404 ) );
		}

		return rest_ensure_response( self::summarise( $job ) );
	}

	/**
	 * Run one short pass inline — what the progress poller calls.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response
	 */
	public function pass( WP_REST_Request $request ): WP_REST_Response {
		$id = (int) $request->get_param( 'id' );

		VulnHub_Backup_Runner::run( $id, VulnHub_Backup_Runner::WEB_BUDGET );

		$job = VulnHub_Backup_Jobs::get( $id );

		return rest_ensure_response( $job ? self::summarise( $job ) : array() );
	}

	/**
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function cancel( WP_REST_Request $request ) {
		$result = VulnHub_Backup_Runner::cancel( (int) $request->get_param( 'id' ) );

		if ( ! $result['ok'] ) {
			return new WP_Error( 'vulnhub_backup_cancel', $result['message'], array( 'status' => 400 ) );
		}

		return rest_ensure_response( $result );
	}

	/**
	 * Flatten a job row into the shape the poller and the screen use.
	 *
	 * @param array<string,mixed> $job Hydrated job row.
	 * @return array<string,mixed>
	 */
	private static function summarise( array $job ): array {
		$counters = (array) $job['counters_arr'];
		$status   = (string) $job['status'];

		/*
		 * Labels, progress and "is this still going" are decided here, once,
		 * rather than in the browser. The screen renders server-side first and
		 * is then updated by polling; working them out in both places is how
		 * the two drift and the bar disagrees with the table under it.
		 */
		return array(
			'id'          => (int) $job['id'],
			'mode'        => (string) $job['mode'],
			'phase'       => (string) $job['phase'],
			'phaseLabel'  => (string) ( VulnHub_Backup_Jobs::phases()[ (string) $job['phase'] ] ?? $job['phase'] ),
			'status'      => $status,
			'statusLabel' => (string) ( VulnHub_Backup_Jobs::statuses()[ $status ] ?? $status ),
			'running'     => VulnHub_Backup_Jobs::RUNNING === $status,
			'progress'    => VulnHub_Backup_Jobs::progress( $job ),
			'folder'      => (string) $job['folder'],
			'error'       => (string) $job['error'],
			'counters'    => $counters,
			'summary'     => self::counter_line( $counters ),
			'createdAt'   => (string) $job['created_at'],
			'startedAt'   => (string) $job['started_at'],
			'startedAgo'  => '' !== (string) $job['started_at'] ? vh_ago( (string) $job['started_at'] ) : '',
			'finishedAt'  => (string) $job['finished_at'],
			'elapsed'     => self::elapsed( $job ),
		);
	}

	/**
	 * One line of what the job has actually moved so far.
	 *
	 * @param array<string,mixed> $counters Job counters.
	 */
	private static function counter_line( array $counters ): string {
		$bits = array();

		if ( (int) ( $counters['tables_total'] ?? 0 ) > 0 ) {
			$bits[] = sprintf(
				/* translators: 1: tables exported, 2: tables in total. */
				__( '%1$s of %2$s tables', 'vulnhub' ),
				number_format_i18n( (int) ( $counters['tables_done'] ?? 0 ) ),
				number_format_i18n( (int) $counters['tables_total'] )
			);
		}

		if ( (int) ( $counters['rows_exported'] ?? 0 ) > 0 ) {
			$bits[] = sprintf(
				/* translators: %s: number of database rows. */
				__( '%s rows', 'vulnhub' ),
				number_format_i18n( (int) $counters['rows_exported'] )
			);
		}

		if ( (int) ( $counters['files_archived'] ?? 0 ) > 0 ) {
			$bits[] = sprintf(
				/* translators: %s: number of files. */
				__( '%s files', 'vulnhub' ),
				number_format_i18n( (int) $counters['files_archived'] )
			);
		}

		$bytes = (int) ( $counters['db_bytes'] ?? 0 ) + (int) ( $counters['zip_bytes'] ?? 0 );

		if ( $bytes > 0 ) {
			$bits[] = size_format( $bytes, 1 );
		}

		return implode( ' · ', $bits );
	}

	/**
	 * How long the job has been going, or took.
	 *
	 * @param array<string,mixed> $job Hydrated job row.
	 */
	private static function elapsed( array $job ): string {
		$started = strtotime( (string) $job['started_at'] . ' UTC' );

		if ( ! $started ) {
			return '';
		}

		$ended = '' !== (string) $job['finished_at']
			? strtotime( (string) $job['finished_at'] . ' UTC' )
			: time();

		return human_time_diff( $started, $ended ?: time() );
	}

	/* =================================================================
	 * Restore: chunked upload — mirrors VulnHub_Import_Rest's uploader.
	 * ============================================================== */

	/**
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function upload_begin( WP_REST_Request $request ) {
		$size = (int) $request->get_param( 'size' );

		if ( $size <= 0 ) {
			return new WP_Error( 'vulnhub_backup_size', __( 'That file is empty.', 'vulnhub' ), array( 'status' => 400 ) );
		}

		if ( $size > VulnHub_Backup_Storage::max_bytes() ) {
			return new WP_Error(
				'vulnhub_backup_size',
				sprintf(
					/* translators: 1: file size, 2: limit. */
					__( 'That file is %1$s. This restore path accepts up to %2$s.', 'vulnhub' ),
					size_format( $size ),
					size_format( VulnHub_Backup_Storage::max_bytes() )
				),
				array( 'status' => 400 )
			);
		}

		$headroom = VulnHub_Backup_Storage::disk_headroom();

		if ( $headroom > 0 && $size > $headroom ) {
			return new WP_Error(
				'vulnhub_backup_disk',
				__( 'Not enough free disk space to stage that file.', 'vulnhub' ),
				array( 'status' => 507 )
			);
		}

		$key = VulnHub_Backup_Storage::begin();

		if ( '' === $key ) {
			return new WP_Error( 'vulnhub_backup_storage', __( 'The staging directory could not be created.', 'vulnhub' ), array( 'status' => 500 ) );
		}

		return rest_ensure_response(
			array(
				'key'       => $key,
				'chunkSize' => VulnHub_Backup_Storage::chunk_size(),
				'maxChunk'  => VulnHub_Backup_Storage::chunk_max(),
			)
		);
	}

	/**
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function upload_status( WP_REST_Request $request ) {
		$key = (string) $request->get_param( 'key' );

		if ( ! VulnHub_Backup_Storage::valid_key( $key ) || ! VulnHub_Backup_Storage::exists( $key ) ) {
			return new WP_Error( 'vulnhub_backup_key', __( 'That upload session is not valid.', 'vulnhub' ), array( 'status' => 404 ) );
		}

		return rest_ensure_response( array( 'received' => VulnHub_Backup_Storage::size( $key ) ) );
	}

	/**
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function upload_chunk( WP_REST_Request $request ) {
		$key    = (string) $request->get_param( 'key' );
		$offset = (int) $request->get_param( 'offset' );
		$files  = $request->get_file_params();
		$file   = (array) ( $files['chunk'] ?? array() );

		if ( ! VulnHub_Backup_Storage::valid_key( $key ) ) {
			return new WP_Error( 'vulnhub_backup_key', __( 'That upload session is not valid.', 'vulnhub' ), array( 'status' => 400 ) );
		}

		if ( ! $file ) {
			return new WP_Error( 'vulnhub_backup_chunk', __( 'No slice was attached to that request.', 'vulnhub' ), array( 'status' => 400 ) );
		}

		$result = VulnHub_Backup_Storage::append( $key, $offset, $file );

		if ( ! $result['ok'] ) {
			return new WP_Error(
				'vulnhub_backup_chunk',
				$result['message'],
				array( 'status' => 400, 'received' => VulnHub_Backup_Storage::size( $key ) )
			);
		}

		return rest_ensure_response( array( 'received' => $result['size'] ) );
	}

	/**
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function upload_finish( WP_REST_Request $request ) {
		$key = (string) $request->get_param( 'key' );

		if ( ! VulnHub_Backup_Storage::valid_key( $key ) || ! VulnHub_Backup_Storage::exists( $key ) ) {
			return new WP_Error( 'vulnhub_backup_key', __( 'That upload session is not valid.', 'vulnhub' ), array( 'status' => 400 ) );
		}

		$sniff = VulnHub_Backup_Storage::sniff( $key );

		if ( ! $sniff['ok'] ) {
			VulnHub_Backup_Storage::delete( $key );
			return new WP_Error( 'vulnhub_backup_content', $sniff['message'], array( 'status' => 400 ) );
		}

		return rest_ensure_response(
			array(
				'key'  => $key,
				'hash' => VulnHub_Backup_Storage::hash( $key ),
				'size' => VulnHub_Backup_Storage::size( $key ),
			)
		);
	}

	/**
	 * Start a restore job from a finished upload. Requires the site's own
	 * domain to have been typed as confirmation — checked here, not just in
	 * the browser, since this is the point of no return.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response|WP_Error
	 */
	public function restore_start( WP_REST_Request $request ) {
		$key      = (string) $request->get_param( 'key' );
		$confirm  = (string) $request->get_param( 'confirmDomain' );
		$expected = (string) wp_parse_url( home_url(), PHP_URL_HOST );

		if ( '' === $confirm || strtolower( trim( $confirm ) ) !== strtolower( $expected ) ) {
			return new WP_Error( 'vulnhub_backup_confirm', __( 'Type this site\'s domain to confirm the restore.', 'vulnhub' ), array( 'status' => 400 ) );
		}

		$job_id = VulnHub_Backup_Restore_Runner::start( $key );

		if ( ! $job_id ) {
			return new WP_Error( 'vulnhub_backup_restore', __( 'The restore could not be started.', 'vulnhub' ), array( 'status' => 400 ) );
		}

		return rest_ensure_response( array( 'jobId' => $job_id ) );
	}

	/**
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response
	 */
	public function restore_pass( WP_REST_Request $request ): WP_REST_Response {
		$id = (int) $request->get_param( 'id' );

		VulnHub_Backup_Restore_Runner::run( $id, VulnHub_Backup_Restore_Runner::budget() );

		$job = VulnHub_Backup_Jobs::get( $id );

		return rest_ensure_response( $job ? self::summarise( $job ) : array() );
	}
}

