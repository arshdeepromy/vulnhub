<?php
/**
 * The MCP endpoint, and the token authentication in front of it.
 *
 * One route, `POST /wp-json/vulnhub-mcp/v1/mcp`, speaking JSON-RPC 2.0 the way
 * the Model Context Protocol expects: `initialize`, `tools/list`, `tools/call`.
 * A single endpoint rather than a REST route per tool is what lets a client
 * discover the surface at runtime instead of being told about it out of band,
 * and it means adding a tool needs no new route and no client change.
 *
 * Authentication is a bearer token that resolves to a person. From that point
 * the request is that person: `current_user_can()` answers exactly as it would
 * for them in a browser, so an agent's reach is their reach and nothing more.
 * There is no separate permission model to keep in step with the portal's,
 * because there is no second model at all.
 *
 * @package VulnHub\MCP
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * JSON-RPC transport, token authentication and the audit trail for both.
 */
final class VulnHub_MCP_Server {

	/** The revision of MCP this server implements. */
	private const PROTOCOL = '2024-11-05';

	/** Remembered so the audit trail can name the credential, not just the person. */
	private static string $token_label = '';

	public static function init(): void {
		add_filter( 'determine_current_user', array( __CLASS__, 'authenticate' ), 20 );
		add_action( 'rest_api_init', array( __CLASS__, 'register_routes' ) );
	}

	/* -----------------------------------------------------------------
	 * Authentication
	 * --------------------------------------------------------------- */

	/**
	 * Resolve a bearer token to its owner.
	 *
	 * Deliberately scoped to this plugin's own routes. A `determine_current_user`
	 * filter that fired everywhere would be a second front door to the whole
	 * site, which is not what was asked for and not what should exist.
	 *
	 * @param int|false $user_id Whatever WordPress has decided so far.
	 * @return int|false
	 */
	public static function authenticate( $user_id ) {
		if ( ! empty( $user_id ) ) {
			return $user_id;
		}

		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput

		if ( ! str_contains( $uri, VULNHUB_MCP_NS ) ) {
			return $user_id;
		}

		$token = self::presented_token();

		if ( '' === $token ) {
			return $user_id;
		}

		$owner = VulnHub_MCP_Tokens::user_for( $token );

		return $owner > 0 ? $owner : $user_id;
	}

	/**
	 * The token on this request, from either header an MCP client might use.
	 *
	 * `Authorization` is what the protocol's own clients send. `X-VulnHub-Token`
	 * exists because some proxies and FastCGI setups drop Authorization before
	 * PHP ever sees it, and a credential that silently vanishes in transit is
	 * a support ticket nobody enjoys.
	 */
	private static function presented_token(): string {
		$headers = function_exists( 'getallheaders' ) ? (array) getallheaders() : array();
		$lookup  = array();

		foreach ( $headers as $name => $value ) {
			$lookup[ strtolower( (string) $name ) ] = (string) $value;
		}

		if ( ! empty( $lookup['x-vulnhub-token'] ) ) {
			return trim( $lookup['x-vulnhub-token'] );
		}

		$auth = $lookup['authorization'] ?? '';

		if ( '' === $auth && isset( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
			$auth = (string) wp_unslash( $_SERVER['HTTP_AUTHORIZATION'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		}
		if ( '' === $auth && isset( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) ) {
			$auth = (string) wp_unslash( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		}

		if ( 0 === stripos( $auth, 'bearer ' ) ) {
			return trim( substr( $auth, 7 ) );
		}

		return '';
	}

	/* -----------------------------------------------------------------
	 * Route
	 * --------------------------------------------------------------- */

	public static function register_routes(): void {
		register_rest_route(
			VULNHUB_MCP_NS,
			'/mcp',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'handle' ),
				'permission_callback' => array( __CLASS__, 'may_connect' ),
			)
		);

		// A plain GET so somebody testing a URL in a browser gets an answer
		// rather than a 404 that tells them nothing.
		register_rest_route(
			VULNHUB_MCP_NS,
			'/mcp',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'describe' ),
				'permission_callback' => array( __CLASS__, 'may_connect' ),
			)
		);
	}

	/**
	 * @return true|WP_Error
	 */
	public static function may_connect() {
		if ( is_user_logged_in() && current_user_can( Caps::VIEW ) ) {
			return true;
		}

		return new WP_Error(
			'vulnhub_mcp_unauthorised',
			__( 'Present a VulnHub connector token as a bearer token.', 'vulnhub' ),
			array( 'status' => 401 )
		);
	}

	/**
	 * @return WP_REST_Response
	 */
	public static function describe(): WP_REST_Response {
		$user = wp_get_current_user();

		return new WP_REST_Response(
			array(
				'server'      => 'VulnHub',
				'protocol'    => self::PROTOCOL,
				'transport'   => 'POST JSON-RPC 2.0 to this URL',
				'connected_as' => array(
					'name'  => $user->display_name,
					'roles' => array_values( (array) $user->roles ),
				),
				'tools'       => array_keys( VulnHub_MCP_Tools::available() ),
			)
		);
	}

	/* -----------------------------------------------------------------
	 * JSON-RPC
	 * --------------------------------------------------------------- */

	/**
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response
	 */
	public static function handle( WP_REST_Request $request ): WP_REST_Response {
		$body = $request->get_json_params();

		if ( ! is_array( $body ) ) {
			return self::error( null, -32700, 'Parse error: the body must be JSON.' );
		}

		// A batch is a bare array of calls rather than one object.
		if ( isset( $body[0] ) && is_array( $body[0] ) ) {
			$out = array();

			foreach ( $body as $call ) {
				$response = self::dispatch( (array) $call );

				if ( null !== $response ) {
					$out[] = $response;
				}
			}

			return new WP_REST_Response( $out );
		}

		$response = self::dispatch( $body );

		// A notification gets an empty 204-ish acknowledgement, not a result.
		return null === $response
			? new WP_REST_Response( null, 202 )
			: new WP_REST_Response( $response );
	}

	/**
	 * One JSON-RPC call.
	 *
	 * @param array<string,mixed> $call Decoded call.
	 * @return array<string,mixed>|null Null for a notification.
	 */
	private static function dispatch( array $call ): ?array {
		$method = (string) ( $call['method'] ?? '' );
		$id     = $call['id'] ?? null;
		$params = (array) ( $call['params'] ?? array() );

		// No id means a notification: act, answer nothing.
		$is_notification = ! array_key_exists( 'id', $call );

		switch ( $method ) {
			case 'initialize':
				return self::result(
					$id,
					array(
						'protocolVersion' => self::PROTOCOL,
						'capabilities'    => array( 'tools' => array( 'listChanged' => false ) ),
						'serverInfo'      => array(
							'name'    => 'VulnHub',
							'version' => VULNHUB_MCP_VERSION,
						),
						'instructions'    => self::instructions(),
					)
				);

			case 'notifications/initialized':
			case 'notifications/cancelled':
				return null;

			case 'ping':
				return self::result( $id, new stdClass() );

			case 'tools/list':
				$tools = array();

				foreach ( VulnHub_MCP_Tools::available() as $name => $tool ) {
					$tools[] = array(
						'name'        => $name,
						'title'       => (string) $tool['title'],
						'description' => (string) $tool['description'],
						'inputSchema' => $tool['schema'],
					);
				}

				return self::result( $id, array( 'tools' => $tools ) );

			case 'tools/call':
				return self::call_tool( $id, $params );
		}

		if ( $is_notification ) {
			return null;
		}

		return self::error( $id, -32601, sprintf( 'Unknown method "%s".', $method ) );
	}

	/**
	 * Run a tool, with the capability check repeated at the moment of use.
	 *
	 * @param mixed               $id     JSON-RPC id.
	 * @param array<string,mixed> $params Call params.
	 * @return array<string,mixed>
	 */
	private static function call_tool( $id, array $params ): array {
		$name  = (string) ( $params['name'] ?? '' );
		$args  = (array) ( $params['arguments'] ?? array() );
		$tools = VulnHub_MCP_Tools::all();

		if ( ! isset( $tools[ $name ] ) ) {
			return self::error( $id, -32602, sprintf( 'No tool called "%s".', $name ) );
		}

		$tool = $tools[ $name ];

		/*
		 * The list was filtered by capability, but a client may have cached an
		 * older one, or simply guessed. This is the check that actually holds:
		 * it runs as the token's owner, immediately before the work.
		 */
		if ( ! current_user_can( (string) $tool['cap'] ) ) {
			self::audit(
				'tool.denied',
				sprintf( 'Connector tried to call "%s" without the capability for it', $name ),
				array( 'tool' => $name, 'capability' => $tool['cap'] ),
				'warning'
			);

			return self::tool_error( $id, sprintf( 'Your role does not allow "%s".', $name ) );
		}

		try {
			$result = call_user_func( $tool['handler'], $args );
		} catch ( Throwable $e ) {
			return self::tool_error( $id, $e->getMessage() );
		}

		return self::result(
			$id,
			array(
				'content' => array(
					array(
						'type' => 'text',
						'text' => (string) wp_json_encode( $result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ),
					),
				),
			)
		);
	}

	/**
	 * What the model is told about this server before it calls anything.
	 */
	private static function instructions(): string {
		$user = wp_get_current_user();

		return sprintf(
			'VulnHub is a vulnerability and asset management platform. You are connected as %s, and every tool runs with exactly that person\'s permissions — no more. Prefer vulnhub_summary, vulnhub_breakdown and vulnhub_coverage to size a problem before listing individual findings; the estate holds hundreds of thousands of rows and listing is paged at 100. Anything you change is written to the platform audit trail against this connector.',
			$user->display_name
		);
	}

	/* -----------------------------------------------------------------
	 * Envelope helpers
	 * --------------------------------------------------------------- */

	/**
	 * @param mixed $id     JSON-RPC id.
	 * @param mixed $result Result payload.
	 * @return array<string,mixed>
	 */
	private static function result( $id, $result ): array {
		return array(
			'jsonrpc' => '2.0',
			'id'      => $id,
			'result'  => $result,
		);
	}

	/**
	 * A protocol-level failure: the call itself was wrong.
	 *
	 * @param mixed  $id      JSON-RPC id.
	 * @param int    $code    JSON-RPC error code.
	 * @param string $message Human-readable reason.
	 * @return array<string,mixed>
	 */
	private static function error( $id, int $code, string $message ): array {
		return array(
			'jsonrpc' => '2.0',
			'id'      => $id,
			'error'   => array(
				'code'    => $code,
				'message' => $message,
			),
		);
	}

	/**
	 * A tool-level failure.
	 *
	 * MCP wants these as a normal result carrying `isError`, not as a JSON-RPC
	 * error, so the model can read what went wrong and try something else
	 * rather than treating it as a broken connection.
	 *
	 * @param mixed  $id      JSON-RPC id.
	 * @param string $message What went wrong.
	 * @return array<string,mixed>
	 */
	private static function tool_error( $id, string $message ): array {
		return self::result(
			$id,
			array(
				'isError' => true,
				'content' => array(
					array(
						'type' => 'text',
						'text' => $message,
					),
				),
			)
		);
	}

	/* -----------------------------------------------------------------
	 * Audit
	 * --------------------------------------------------------------- */

	/**
	 * Write a connector action to the platform audit trail.
	 *
	 * Prefixed `mcp.` so an auditor can separate what an agent did from what a
	 * person did, which is the first question anybody asks about this feature.
	 *
	 * @param string              $action   Action suffix.
	 * @param string              $summary  One-line description.
	 * @param array<string,mixed> $detail   Structured context.
	 * @param string              $severity info|warning|error|critical.
	 */
	public static function audit( string $action, string $summary, array $detail = array(), string $severity = 'warning' ): void {
		if ( ! function_exists( 'vulnhub' ) ) {
			return;
		}

		$detail['via']   = 'mcp';
		$detail['actor'] = wp_get_current_user()->user_login;

		if ( '' !== self::$token_label ) {
			$detail['token'] = self::$token_label;
		}

		try {
			vulnhub()->logger->audit(
				'mcp.' . $action,
				$summary,
				'mcp',
				get_current_user_id(),
				$detail,
				$severity
			);
		} catch ( Throwable $e ) {
			unset( $e );
		}
	}
}

