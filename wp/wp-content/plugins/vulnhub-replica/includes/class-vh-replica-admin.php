<?php
/**
 * Portal admin section "Instance sync": hand out sync keys, see packages
 * being collected, and -- on a copy -- see how the last sync went.
 *
 * @package VulnHub\Replica
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Section registration and the key forms.
 */
final class VulnHub_Replica_Admin {

	public const SECTION      = 'instance-sync';
	public const NONCE_ACTION = 'vulnhub_replica_keys';
	public const NONCE_FIELD  = 'vh_replica_nonce';

	/** The plaintext key, for exactly one render. @var array<string,mixed> */
	private static array $fresh = array();

	public static function init(): void {
		add_filter( 'vulnhub_portal_sections', array( __CLASS__, 'register_section' ) );
		add_action( 'vulnhub_render_portal_section', array( __CLASS__, 'render_section' ) );
		add_action( 'template_redirect', array( __CLASS__, 'handle' ), 5 );
	}

	/**
	 * @param array<string,array<string,mixed>> $sections Sections.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_section( array $sections ): array {
		$sections[ self::SECTION ] = array(
			'label'   => __( 'Instance sync', 'vulnhub' ),
			'cap'     => Caps::MANAGE,
			'group'   => 'platform',
			'order'   => 48,
			'summary' => __( 'Let another instance keep a one-way copy of this one, or make this one a copy.', 'vulnhub' ),
		);
		return $sections;
	}

	public static function render_section( string $section ): void {
		if ( self::SECTION !== $section || ! current_user_can( Caps::MANAGE ) ) {
			return;
		}
		include VULNHUB_REPLICA_DIR . 'admin/views/instance-sync.php';
	}

	/**
	 * @param array<string,string> $args Query args.
	 */
	public static function section_url( array $args = array() ): string {
		$base = array( 'section' => self::SECTION );
		if ( class_exists( 'VulnHub_Dash_Portal' ) ) {
			return VulnHub_Dash_Portal::portal_url( VulnHub_Dash_Portal::ADMIN_VIEW, array_merge( $base, $args ) );
		}
		return add_query_arg( array_merge( $base, $args ), home_url( '/portal-admin/' ) );
	}

	/**
	 * Where the replica connector's settings are edited.
	 */
	public static function connector_url(): string {
		return admin_url( 'admin.php?page=vulnhub-integrations&connector=' . VulnHub_Replica_Connector::ID );
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function fresh_key(): array {
		return self::$fresh;
	}

	public static function handle(): void {
		if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) || ! isset( $_POST['vh_replica_do'] ) ) {
			return;
		}
		$nonce = isset( $_POST[ self::NONCE_FIELD ] ) ? sanitize_text_field( wp_unslash( $_POST[ self::NONCE_FIELD ] ) ) : '';
		if ( ! wp_verify_nonce( $nonce, self::NONCE_ACTION ) ) {
			wp_die( esc_html__( 'That form has expired. Go back, reload the page and try again.', 'vulnhub' ), 403 );
		}
		if ( ! current_user_can( Caps::MANAGE ) ) {
			wp_die( esc_html__( 'Only an administrator can manage instance sync.', 'vulnhub' ), 403 );
		}

		$do = sanitize_key( wp_unslash( $_POST['vh_replica_do'] ) );

		if ( 'create' === $do ) {
			$label = isset( $_POST['label'] ) ? sanitize_text_field( wp_unslash( $_POST['label'] ) ) : '';
			$days  = isset( $_POST['days'] ) ? max( 0, min( 3650, (int) $_POST['days'] ) ) : 0;
			// Deliberately not a redirect: the plaintext lives only in this
			// response, never in a transient or a query string.
			self::$fresh = VulnHub_Replica_Tokens::create( $label, get_current_user_id(), $days );
			return;
		}
		if ( 'revoke' === $do ) {
			VulnHub_Replica_Tokens::revoke( isset( $_POST['id'] ) ? (int) $_POST['id'] : 0 );
			wp_safe_redirect( self::section_url( array( 'vh_notice' => 'revoked' ) ) );
			exit;
		}
		if ( 'full' === $do ) {
			$c = vulnhub()->connectors->get( VulnHub_Replica_Connector::ID );
			if ( $c ) {
				$c->request_full_sync();
			}
			wp_safe_redirect( self::section_url( array( 'vh_notice' => 'full' ) ) );
			exit;
		}
		if ( 'sync' === $do ) {
			\VulnHub\Core\Scheduler::queue_sync( VulnHub_Replica_Connector::ID );
			wp_safe_redirect( self::section_url( array( 'vh_notice' => 'queued' ) ) );
			exit;
		}
	}
}

