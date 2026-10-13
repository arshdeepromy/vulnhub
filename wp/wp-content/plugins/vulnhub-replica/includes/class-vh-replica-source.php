<?php
/**
 * Source side: the endpoints a copy talks to.
 *
 * Every route needs a sync key and nothing else -- no WordPress login, no
 * cookie. The key is checked on every request, so revoking one stops a copy
 * mid-download. What the routes expose is the estate data the portal shows;
 * secrets, credentials and this instance's own job history never leave
 * (see VulnHub_Replica_Schema).
 *
 *   GET    /manifest              what this instance holds
 *   POST   /jobs                  start a package from the copy's fingerprints
 *   POST   /jobs/{id}/step        do one slice of building it
 *   GET    /jobs/{id}             where it is; the chunk list once ready
 *   GET    /jobs/{id}/chunks/{n}  one chunk, raw bytes
 *   DELETE /jobs/{id}             the copy has it; drop it
 *
 * @package VulnHub\Replica
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * REST routes for the source.
 */
final class VulnHub_Replica_Source {

	public const NS = 'vulnhub-replica/v1';

	/** The key that authenticated this request. @var array<string,mixed>|null */
	private static ?array $key = null;

	public static function init(): void {
		add_action( 'rest_api_init', array( __CLASS__, 'routes' ) );
	}

	public static function routes(): void {
		$auth = array( __CLASS__, 'authorise' );

		register_rest_route(
			self::NS,
			'/manifest',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'manifest' ),
				'permission_callback' => $auth,
			)
		);
		register_rest_route(
			self::NS,
			'/jobs',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'create' ),
				'permission_callback' => $auth,
			)
		);
		register_rest_route(
			self::NS,
			'/jobs/(?P<id>[a-z0-9]{24})',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( __CLASS__, 'status' ),
					'permission_callback' => $auth,
				),
				array(
					'methods'             => 'DELETE',
					'callback'            => array( __CLASS__, 'finish' ),
					'permission_callback' => $auth,
				),
			)
		);
		register_rest_route(
			self::NS,
			'/jobs/(?P<id>[a-z0-9]{24})/step',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'step' ),
				'permission_callback' => $auth,
			)
		);
		register_rest_route(
			self::NS,
			'/jobs/(?P<id>[a-z0-9]{24})/chunks/(?P<n>\d+)',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'chunk' ),
				'permission_callback' => $auth,
			)
		);
	}

	/**
	 * @return true|\WP_Error
	 */
	public static function authorise( \WP_REST_Request $request ) {
		$token = (string) $request->get_header( 'x_vulnhub_replica_token' );
		if ( '' === $token ) {
			$auth = (string) $request->get_header( 'authorization' );
			if ( 0 === stripos( $auth, 'Bearer ' ) ) {
				$token = trim( substr( $auth, 7 ) );
			}
		}

		$key = VulnHub_Replica_Tokens::verify( $token );
		if ( ! $key ) {
			return new \WP_Error( 'vulnhub_replica_key', 'A valid sync key is required.', array( 'status' => 401 ) );
		}

		self::$key = $key;
		return true;
	}

	private static function key_id(): int {
		return (int) ( self::$key['id'] ?? 0 );
	}

	public static function manifest(): \WP_REST_Response {
		$tables = array();
		foreach ( VulnHub_Replica_Schema::tables() as $short => $info ) {
			$tables[ $short ] = array(
				'pk'     => $info['pk'],
				'int_pk' => $info['int_pk'],
				'cols'   => $info['cols'],
				'rows'   => $info['rows'],
				'ddl'    => VulnHub_Replica_Schema::ddl( $short ),
			);
		}

		return new \WP_REST_Response(
			array(
				'format'    => 1,
				'instance'  => VulnHub_Replica_Schema::instance_id(),
				'name'      => (string) ( function_exists( 'vulnhub' ) ? vulnhub()->settings->platform( 'org_name', '' ) : '' ),
				'width'     => VulnHub_Replica_Schema::BUCKET_WIDTH,
				'versions'  => VulnHub_Replica_Schema::versions(),
				'tables'    => $tables,
				'zip'       => class_exists( 'ZipArchive' ),
				'generated' => vh_now(),
			)
		);
	}

	/**
	 * @return \WP_REST_Response|\WP_Error
	 */
	public static function create( \WP_REST_Request $request ) {
		if ( ! class_exists( 'ZipArchive' ) ) {
			return new \WP_Error( 'vulnhub_replica_zip', 'This instance cannot build zip packages (the PHP zip extension is missing).', array( 'status' => 501 ) );
		}

		$body = $request->get_json_params();
		if ( ! is_array( $body ) ) {
			$raw  = (string) $request->get_body();
			$body = json_decode( (string) gzdecode( $raw ), true );
		}
		if ( ! is_array( $body ) || ! isset( $body['schema'] ) ) {
			return new \WP_Error( 'vulnhub_replica_body', 'Expected the copy\'s schema and fingerprints.', array( 'status' => 400 ) );
		}

		$job = VulnHub_Replica_Job::create( self::key_id(), $body );

		if ( function_exists( 'vulnhub' ) ) {
			vulnhub()->logger->audit( 'replica.job_started', sprintf( 'Sync package started for key #%d', self::key_id() ), 'replica', (string) self::key_id() );
		}

		return new \WP_REST_Response( $job->status(), 201 );
	}

	/**
	 * @return \WP_REST_Response|\WP_Error
	 */
	public static function status( \WP_REST_Request $request ) {
		$job = VulnHub_Replica_Job::load( (string) $request['id'], self::key_id() );
		if ( ! $job ) {
			return self::gone();
		}
		return new \WP_REST_Response( $job->status() );
	}

	/**
	 * @return \WP_REST_Response|\WP_Error
	 */
	public static function step( \WP_REST_Request $request ) {
		$job = VulnHub_Replica_Job::load( (string) $request['id'], self::key_id() );
		if ( ! $job ) {
			return self::gone();
		}
		return new \WP_REST_Response( $job->step() );
	}

	/**
	 * @return \WP_Error|void
	 */
	public static function chunk( \WP_REST_Request $request ) {
		$job = VulnHub_Replica_Job::load( (string) $request['id'], self::key_id() );
		if ( ! $job ) {
			return self::gone();
		}
		$job->send_chunk( (int) $request['n'] );
	}

	/**
	 * @return \WP_REST_Response|\WP_Error
	 */
	public static function finish( \WP_REST_Request $request ) {
		$job = VulnHub_Replica_Job::load( (string) $request['id'], self::key_id() );
		if ( ! $job ) {
			return self::gone();
		}
		$job->delete();
		return new \WP_REST_Response( array( 'deleted' => true ) );
	}

	private static function gone(): \WP_Error {
		return new \WP_Error( 'vulnhub_replica_gone', 'No such package. It may have expired or been replaced by a newer one.', array( 'status' => 404 ) );
	}
}

