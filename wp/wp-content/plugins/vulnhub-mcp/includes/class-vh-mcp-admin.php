<?php
/**
 * The portal screen where a person connects an AI client.
 *
 * Deliberately available to everybody with portal access, not just
 * administrators: a token can never do more than the person who created it, so
 * an analyst minting one for themselves grants an analyst's reach and no more.
 * Restricting this to administrators would only push people towards sharing an
 * administrator's credential, which is the outcome it was meant to prevent.
 *
 * @package VulnHub\MCP
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Section registration and the token forms.
 */
final class VulnHub_MCP_Admin {

	public const SECTION      = 'ai-access';
	public const NONCE_ACTION = 'vulnhub_mcp_tokens';
	public const NONCE_FIELD  = 'vh_mcp_nonce';

	/**
	 * The plaintext token, held for exactly one render after it is created.
	 *
	 * @var array<string,string>
	 */
	private static array $fresh = array();

	public static function init(): void {
		add_filter( 'vulnhub_portal_sections', array( __CLASS__, 'register_section' ) );
		add_action( 'vulnhub_render_portal_section', array( __CLASS__, 'render_section' ) );
		add_action( 'template_redirect', array( __CLASS__, 'handle' ), 5 );
	}

	/**
	 * @param array<string,array<string,mixed>> $sections Section definitions.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_section( array $sections ): array {
		if ( isset( $sections[ self::SECTION ] ) ) {
			return $sections;
		}

		$sections[ self::SECTION ] = array(
			'label'   => __( 'AI access', 'vulnhub' ),
			'cap'     => Caps::VIEW,
			'group'   => 'platform',
			'order'   => 47,
			'summary' => __( 'Connect an AI assistant to VulnHub with your own permissions.', 'vulnhub' ),
		);

		return $sections;
	}

	/**
	 * @param string $section Section slug being rendered.
	 */
	public static function render_section( string $section ): void {
		if ( self::SECTION !== $section || ! current_user_can( Caps::VIEW ) ) {
			return;
		}

		include VULNHUB_MCP_DIR . 'admin/views/ai-access.php';
	}

	/**
	 * @param array<string,string> $args Query arguments.
	 */
	public static function section_url( array $args = array() ): string {
		$base = array( 'section' => self::SECTION );

		if ( class_exists( 'VulnHub_Dash_Portal' ) ) {
			return VulnHub_Dash_Portal::portal_url( VulnHub_Dash_Portal::ADMIN_VIEW, array_merge( $base, $args ) );
		}

		return add_query_arg( array_merge( $base, $args ), home_url( '/portal-admin/' ) );
	}

	/**
	 * The endpoint an MCP client is pointed at.
	 */
	public static function endpoint(): string {
		return rest_url( VULNHUB_MCP_NS . '/mcp' );
	}

	/**
	 * The token created by this request, if any. Shown once and then gone.
	 */
	public static function fresh_token(): array {
		return self::$fresh;
	}

	/* -----------------------------------------------------------------
	 * Form handling
	 * --------------------------------------------------------------- */

	public static function handle(): void {
		if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) {
			return;
		}
		if ( ! isset( $_POST['vh_mcp_action'] ) ) {
			return;
		}

		$nonce = isset( $_POST[ self::NONCE_FIELD ] )
			? sanitize_text_field( wp_unslash( $_POST[ self::NONCE_FIELD ] ) )
			: '';

		if ( ! wp_verify_nonce( $nonce, self::NONCE_ACTION ) ) {
			wp_die( esc_html__( 'That form has expired. Go back, reload the page and try again.', 'vulnhub' ), 403 );
		}
		if ( ! current_user_can( Caps::VIEW ) ) {
			wp_die( esc_html__( 'You do not have portal access.', 'vulnhub' ), 403 );
		}

		$action = sanitize_key( wp_unslash( $_POST['vh_mcp_action'] ) );

		if ( 'create' === $action ) {
			self::do_create();
			return;
		}
		if ( 'revoke' === $action ) {
			self::do_revoke();
		}
	}

	private static function do_create(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- verified above.
		$client = isset( $_POST['client'] ) && 'claude' === sanitize_key( wp_unslash( $_POST['client'] ) ) ? 'claude' : 'generic';
		$label  = isset( $_POST['label'] ) ? sanitize_text_field( wp_unslash( $_POST['label'] ) ) : '';
		$days   = isset( $_POST['days'] ) ? (int) $_POST['days'] : 0;
		// phpcs:enable

		if ( '' === $label ) {
			$label = 'claude' === $client ? __( 'Claude', 'vulnhub' ) : __( 'AI connector', 'vulnhub' );
		}

		$days   = max( 0, min( 3650, $days ) );
		$user   = wp_get_current_user();
		$issued = VulnHub_MCP_Tokens::create( (int) $user->ID, $label, $client, $days );

		VulnHub_MCP_Server::audit(
			'token.created',
			sprintf(
				/* translators: 1: token label, 2: username. */
				__( 'Connector token "%1$s" issued for %2$s', 'vulnhub' ),
				$label,
				$user->user_login
			),
			array(
				'token_id' => $issued['id'],
				'client'   => $client,
				'expires'  => $days > 0 ? $days . ' days' : 'never',
				'roles'    => array_values( (array) $user->roles ),
			),
			'critical'
		);

		self::$fresh = array(
			'token' => $issued['token'],
			'label' => $label,
			'client' => $client,
		);

		/*
		 * Deliberately NOT a redirect. The plaintext exists only in this
		 * request; bouncing through a redirect would mean either losing it or
		 * parking a live credential in a transient or the query string, and
		 * neither is worth the tidier URL.
		 */
		add_filter( 'vulnhub_mcp_just_created', '__return_true' );
	}

	private static function do_revoke(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified above.
		$id  = isset( $_POST['token_id'] ) ? (int) $_POST['token_id'] : 0;
		$row = VulnHub_MCP_Tokens::get( $id );

		if ( ! $row ) {
			return;
		}

		// Your own tokens always; anybody's if you administer the platform.
		$mine = (int) $row['user_id'] === get_current_user_id();

		if ( ! $mine && ! current_user_can( Caps::MANAGE ) ) {
			wp_die( esc_html__( 'That token belongs to somebody else.', 'vulnhub' ), 403 );
		}

		VulnHub_MCP_Tokens::revoke( $id );

		VulnHub_MCP_Server::audit(
			'token.revoked',
			sprintf(
				/* translators: %s: token label. */
				__( 'Connector token "%s" revoked', 'vulnhub' ),
				(string) $row['label']
			),
			array( 'token_id' => $id, 'owner' => (int) $row['user_id'] ),
			'warning'
		);

		wp_safe_redirect( self::section_url( array( 'vh_notice' => 'revoked' ) ) );
		exit;
	}
}

