<?php
/**
 * Talking to the Intune Data Warehouse.
 *
 * OData v4 over HTTPS with a bearer token. Two things make it unlike the
 * Graph client next door:
 *
 * 1. The endpoint is per tenant and per scale unit -- something like
 *    `https://fef.msuc03.manage.microsoft.com/ReportingService/DataWarehouseFEService`
 *    -- and is read off the Intune admin centre rather than being a constant.
 *    So the host is configuration, and every URL this class builds is checked
 *    against it before it is called.
 *
 * 2. The token audience is the Intune API, not Graph. Microsoft's own samples
 *    have moved from the v1 `resource=https://api.manage.microsoft.com/` form
 *    to a v2 `scope=…/.default`, and tenants differ on which they accept, so
 *    this asks for v2 first and falls back to v1 rather than making the
 *    operator work out which era their tenant is in.
 *
 * @package VulnHub\IntuneDW
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Intune_DW_Client {

	private const TOKEN_OPTION = 'vh_intune_dw_token';
	private const DEFAULT_SCOPE = 'https://api.manage.microsoft.com/.default';

	private string $feed;
	private string $tenant;
	private string $client_id;
	private string $secret;
	private string $scope;
	private int $calls = 0;

	/** @var callable|null */
	private $logger;

	public function __construct( string $feed, string $tenant, string $client_id, string $secret, string $scope = '', ?callable $logger = null ) {
		$this->feed      = self::normalise_feed( $feed );
		$this->tenant    = trim( $tenant );
		$this->client_id = trim( $client_id );
		$this->secret    = $secret;
		$this->scope     = '' !== trim( $scope ) ? trim( $scope ) : self::DEFAULT_SCOPE;
		$this->logger    = $logger;
	}

	/**
	 * The service root, without the query string the admin centre includes.
	 *
	 * People paste the URL exactly as Intune shows it -- with
	 * `?api-version=v1.0` on the end -- and every path this class builds adds
	 * its own query, so the pasted one has to come off or the second `?`
	 * makes a URL the service rejects.
	 */
	public static function normalise_feed( string $raw ): string {
		$url = trim( $raw );
		$cut = strpos( $url, '?' );

		if ( false !== $cut ) {
			$url = substr( $url, 0, $cut );
		}

		return untrailingslashit( $url );
	}

	/** The api-version the pasted URL asked for, defaulting to v1.0. */
	public static function version_of( string $raw ): string {
		$query = (string) wp_parse_url( trim( $raw ), PHP_URL_QUERY );

		if ( '' === $query ) {
			return 'v1.0';
		}

		parse_str( $query, $parts );

		return (string) ( $parts['api-version'] ?? 'v1.0' );
	}

	public function calls(): int {
		return $this->calls;
	}

	public function feed(): string {
		return $this->feed;
	}

	private function log( string $message ): void {
		if ( is_callable( $this->logger ) ) {
			call_user_func( $this->logger, $message );
		}
	}

	public function is_configured(): bool {
		return '' !== $this->feed && '' !== $this->tenant && '' !== $this->client_id && '' !== $this->secret;
	}

	/** Throw the cached token away, so the next call asks for a fresh one. */
	public function forget_token(): void {
		delete_transient( self::TOKEN_OPTION . '_' . md5( $this->tenant . '|' . $this->client_id ) );
	}

	/**
	 * A bearer token for the Data Warehouse, cached until shortly before it
	 * expires.
	 *
	 * @return array{ok:bool,token:string,error:string}
	 */
	public function token(): array {
		$key    = self::TOKEN_OPTION . '_' . md5( $this->tenant . '|' . $this->client_id );
		$cached = get_transient( $key );

		if ( is_string( $cached ) && '' !== $cached ) {
			return array( 'ok' => true, 'token' => $cached, 'error' => '' );
		}

		// v2 first: the shape Microsoft's current samples use.
		$got = $this->request_token(
			'https://login.microsoftonline.com/' . rawurlencode( $this->tenant ) . '/oauth2/v2.0/token',
			array(
				'grant_type'    => 'client_credentials',
				'client_id'     => $this->client_id,
				'client_secret' => $this->secret,
				'scope'         => $this->scope,
			)
		);

		if ( ! $got['ok'] ) {
			$this->log( 'v2 token request failed (' . $got['error'] . '); trying the v1 resource form.' );

			// v1 fallback: older tenants and older app registrations.
			$got = $this->request_token(
				'https://login.microsoftonline.com/' . rawurlencode( $this->tenant ) . '/oauth2/token',
				array(
					'grant_type'    => 'client_credentials',
					'client_id'     => $this->client_id,
					'client_secret' => $this->secret,
					'resource'      => 'https://api.manage.microsoft.com/',
				)
			);
		}

		if ( $got['ok'] ) {
			// A minute short of the stated life, so a token never expires
			// between being read from cache and being used.
			set_transient( $key, $got['token'], max( 60, $got['expires'] - 60 ) );
		}

		return array( 'ok' => $got['ok'], 'token' => $got['token'], 'error' => $got['error'] );
	}

	/**
	 * @param array<string,string> $body Form fields.
	 * @return array{ok:bool,token:string,expires:int,error:string}
	 */
	private function request_token( string $url, array $body ): array {
		$res = wp_remote_post(
			$url,
			array(
				'timeout' => 30,
				'body'    => $body,
				'headers' => array( 'Content-Type' => 'application/x-www-form-urlencoded' ),
			)
		);

		++$this->calls;

		if ( is_wp_error( $res ) ) {
			return array( 'ok' => false, 'token' => '', 'expires' => 0, 'error' => $res->get_error_message() );
		}

		$code = (int) wp_remote_retrieve_response_code( $res );
		$data = json_decode( (string) wp_remote_retrieve_body( $res ), true );
		$data = is_array( $data ) ? $data : array();

		if ( 200 !== $code || '' === (string) ( $data['access_token'] ?? '' ) ) {
			/*
			 * Entra's own description is far more useful than anything this
			 * class could invent -- it names the missing consent, the wrong
			 * secret, the unknown tenant -- so it is passed through whole,
			 * minus the correlation ids nobody reads.
			 */
			$said = (string) ( $data['error_description'] ?? $data['error'] ?? '' );
			$said = trim( (string) preg_replace( '/\s*(Trace ID|Correlation ID|Timestamp):.*$/ms', '', $said ) );

			return array(
				'ok'      => false,
				'token'   => '',
				'expires' => 0,
				'error'   => '' !== $said ? $said : sprintf( 'HTTP %d from the token endpoint.', $code ),
			);
		}

		return array(
			'ok'      => true,
			'token'   => (string) $data['access_token'],
			'expires' => max( 60, (int) ( $data['expires_in'] ?? 3600 ) ),
			'error'   => '',
		);
	}

	/**
	 * One GET against the feed.
	 *
	 * @param string               $path  Collection name, or '' for the service document.
	 * @param array<string,string> $query Extra OData options.
	 * @return array{ok:bool,status:int,data:array<string,mixed>,error:string}
	 */
	public function get( string $path, array $query = array() ): array {
		$token = $this->token();

		if ( ! $token['ok'] ) {
			return array( 'ok' => false, 'status' => 0, 'data' => array(), 'error' => $token['error'] );
		}

		$url = $this->feed . ( '' !== $path ? '/' . ltrim( $path, '/' ) : '' );
		$url = add_query_arg( array_merge( array( 'api-version' => 'v1.0' ), $query ), $url );

		return $this->fetch( $url, $token['token'] );
	}

	/**
	 * Follow an absolute URL the service handed back (`@odata.nextLink`).
	 *
	 * Checked against the configured feed first: a paging link is data from
	 * the network, and following one to a host nobody configured would send
	 * the tenant's bearer token somewhere it does not belong.
	 *
	 * @return array{ok:bool,status:int,data:array<string,mixed>,error:string}
	 */
	public function next( string $url ): array {
		if ( ! str_starts_with( $url, $this->feed ) ) {
			return array(
				'ok'     => false,
				'status' => 0,
				'data'   => array(),
				'error'  => __( 'The service returned a paging link pointing somewhere else; it was not followed.', 'vulnhub' ),
			);
		}

		$token = $this->token();

		if ( ! $token['ok'] ) {
			return array( 'ok' => false, 'status' => 0, 'data' => array(), 'error' => $token['error'] );
		}

		return $this->fetch( $url, $token['token'] );
	}

	/**
	 * @return array{ok:bool,status:int,data:array<string,mixed>,error:string}
	 */
	private function fetch( string $url, string $token ): array {
		$res = wp_remote_get(
			$url,
			array(
				'timeout' => 60,
				'headers' => array(
					'Authorization' => 'Bearer ' . $token,
					'Accept'        => 'application/json',
				),
			)
		);

		++$this->calls;

		if ( is_wp_error( $res ) ) {
			return array( 'ok' => false, 'status' => 0, 'data' => array(), 'error' => $res->get_error_message() );
		}

		$code = (int) wp_remote_retrieve_response_code( $res );
		$body = (string) wp_remote_retrieve_body( $res );
		$data = json_decode( $body, true );
		$data = is_array( $data ) ? $data : array();

		if ( $code >= 400 ) {
			$said = (string) ( $data['error']['message'] ?? $data['Message'] ?? '' );

			return array(
				'ok'     => false,
				'status' => $code,
				'data'   => $data,
				'error'  => '' !== $said ? $said : self::explain( $code ),
			);
		}

		return array( 'ok' => true, 'status' => $code, 'data' => $data, 'error' => '' );
	}

	/**
	 * What a bare status code means here, said once so three call sites do not
	 * each guess differently.
	 */
	public static function explain( int $code ): string {
		return match ( $code ) {
			401 => __( 'The token was refused. Either the application permission has not been consented, or the secret is wrong.', 'vulnhub' ),
			403 => __( 'Authenticated, but not allowed to read the warehouse. The app needs the Intune API permission get_data_warehouse, granted with admin consent.', 'vulnhub' ),
			404 => __( 'No such collection at that feed URL. Check the URL copied from the Intune admin centre.', 'vulnhub' ),
			429 => __( 'Throttled by the service.', 'vulnhub' ),
			default => sprintf( /* translators: %d: HTTP status. */ __( 'HTTP %d from the Data Warehouse.', 'vulnhub' ), $code ),
		};
	}

	/**
	 * Every collection the feed offers, from the OData service document.
	 *
	 * @return array{ok:bool,names:array<int,string>,error:string}
	 */
	public function collections(): array {
		$res = $this->get( '' );

		if ( ! $res['ok'] ) {
			return array( 'ok' => false, 'names' => array(), 'error' => $res['error'] );
		}

		$names = array();

		foreach ( (array) ( $res['data']['value'] ?? array() ) as $entry ) {
			$name = (string) ( ( (array) $entry )['name'] ?? '' );

			if ( '' !== $name ) {
				$names[] = $name;
			}
		}

		sort( $names );

		return array( 'ok' => true, 'names' => $names, 'error' => '' );
	}

	/**
	 * Read one collection whole, following paging.
	 *
	 * @param callable $on_page Given each page's rows.
	 * @return array{ok:bool,rows:int,pages:int,error:string}
	 */
	public function each( string $collection, callable $on_page, int $max_pages = 200 ): array {
		$res   = $this->get( $collection );
		$rows  = 0;
		$pages = 0;

		while ( true ) {
			if ( ! $res['ok'] ) {
				return array( 'ok' => false, 'rows' => $rows, 'pages' => $pages, 'error' => $res['error'] );
			}

			$page = (array) ( $res['data']['value'] ?? array() );
			$rows += count( $page );
			++$pages;

			if ( $page ) {
				call_user_func( $on_page, $page );
			}

			$next = (string) ( $res['data']['@odata.nextLink'] ?? '' );

			if ( '' === $next || $pages >= $max_pages ) {
				break;
			}

			$res = $this->next( $next );
		}

		return array( 'ok' => true, 'rows' => $rows, 'pages' => $pages, 'error' => '' );
	}
}
