<?php
/**
 * The Cloud Exposure map: which assets sit in front of the internet, per account.
 *
 * Built from Plerion's public-exposure snapshot. Port-level communication is
 * not available from Plerion's API, so this is deliberately an exposure map
 * (internet -> exposed -> internal), not a flow diagram, and says so.
 *
 * @package VulnHub\Plerion
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Plerion_Exposure_Page {

	public const VIEW = 'exposure';
	public const SLUG = 'cloud-exposure';

	public static function init(): void {
		add_filter( 'vulnhub_dash_views', array( __CLASS__, 'register_view' ) );
		add_action( 'vulnhub_dash_render_view_' . self::VIEW, array( __CLASS__, 'render' ) );
		add_action( 'init', array( __CLASS__, 'ensure_page' ), 20 );
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'assets' ), 20 );
	}

	/**
	 * @param array<string,array<string,mixed>> $views Existing views.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_view( array $views ): array {
		$out = array();

		foreach ( $views as $key => $def ) {
			$out[ $key ] = $def;

			if ( VulnHub_Plerion_Findings_Page::VIEW === $key ) {
				$out[ self::VIEW ] = array(
					'title' => __( 'Cloud Exposure', 'vulnhub' ),
					'slug'  => self::SLUG,
					'menu'  => __( 'Cloud Exposure', 'vulnhub' ),
					'icon'  => 'M12 3v18M3 12h18',
				);
			}
		}

		return $out;
	}

	public static function ensure_page(): void {
		$map = (array) get_option( 'vulnhub_dash_pages', array() );

		if ( ! empty( $map[ self::VIEW ] ) ) {
			$existing = get_post( (int) $map[ self::VIEW ] );

			if ( $existing && 'trash' !== $existing->post_status ) {
				return;
			}
		}

		$page = get_page_by_path( self::SLUG );

		$id = $page ? (int) $page->ID : wp_insert_post(
			array(
				'post_title'     => __( 'Cloud Exposure', 'vulnhub' ),
				'post_name'      => self::SLUG,
				'post_content'   => '<!-- wp:shortcode -->[vulnhub_app view="' . self::VIEW . '"]<!-- /wp:shortcode -->',
				'post_status'    => 'publish',
				'post_type'      => 'page',
				'comment_status' => 'closed',
				'ping_status'    => 'closed',
			)
		);

		if ( ! is_wp_error( $id ) && $id ) {
			$map[ self::VIEW ] = (int) $id;
			update_option( 'vulnhub_dash_pages', $map, false );
		}
	}

	/**
	 * Snapshot from the connector, enriched with a local count of known assets
	 * per account (the "internal estate" behind the exposed ones).
	 *
	 * @return array<string,mixed>
	 */
	private static function data(): array {
		global $wpdb;

		$snap     = (array) get_option( 'vulnhub_plerion_exposure', array() );
		$accounts = (array) ( $snap['accounts'] ?? array() );

		$counts = array();

		foreach ( (array) $wpdb->get_results( "SELECT cloud_account_id AS a, COUNT(*) AS c FROM " . $wpdb->prefix . "vulnhub_assets WHERE cloud_account_id <> '' GROUP BY cloud_account_id", ARRAY_A ) as $row ) { // phpcs:ignore
			$counts[ (string) $row['a'] ] = (int) $row['c'];
		}

		$out = array();

		foreach ( $accounts as $acct => $exposed ) {
			$out[ (string) $acct ] = array(
				'exposed'  => array_values( (array) $exposed ),
				'internal' => (int) ( $counts[ (string) $acct ] ?? 0 ),
			);
		}

		return array(
			'generated_at' => (string) ( $snap['generated_at'] ?? '' ),
			'accounts'     => $out,
		);
	}

	public static function assets(): void {
		if ( ! is_singular() || ! class_exists( 'VulnHub_Dash_App' ) ) {
			return;
		}

		if ( self::VIEW !== VulnHub_Dash_App::view_for_post( get_post() ) ) {
			return;
		}

		$css_v = @filemtime( VULNHUB_PLERION_DIR . 'assets/plerion.css' ); // phpcs:ignore
		$js_v  = @filemtime( VULNHUB_PLERION_DIR . 'assets/exposure.js' ); // phpcs:ignore

		wp_enqueue_style( 'vulnhub-plerion', VULNHUB_PLERION_URL . 'assets/plerion.css', array( 'vulnhub-app' ), $css_v ? VULNHUB_PLERION_VERSION . '.' . $css_v : VULNHUB_PLERION_VERSION );
		wp_enqueue_script( 'vulnhub-plerion-exposure', VULNHUB_PLERION_URL . 'assets/exposure.js', array(), $js_v ? VULNHUB_PLERION_VERSION . '.' . $js_v : VULNHUB_PLERION_VERSION, true );
		wp_localize_script( 'vulnhub-plerion-exposure', 'VH_PLERION_EXPOSURE', self::data() );
	}

	public static function render(): void {
		echo '<div class="vh-page-head"><div>';
		echo '<h1>' . esc_html__( 'Cloud Exposure', 'vulnhub' ) . ' <span class="vh-chip vh-chip--info vh-plerion-badge">' . esc_html__( 'CSPM · Plerion', 'vulnhub' ) . '</span></h1>';
		echo '<p class="vh-sub">' . esc_html__( 'Which assets sit in front of the internet, per cloud account, from Plerion. The internet-facing assets are drawn first; the internal estate sits behind them.', 'vulnhub' ) . '</p>';
		echo '</div></div>';

		echo '<div class="vh-exp-controls"><label>' . esc_html__( 'Account', 'vulnhub' ) . ' <select data-vh-exp-account></select></label> <span class="vh-meta" data-vh-exp-meta></span></div>';
		echo '<div class="vh-exp-map" data-vh-exp-map role="img" aria-label="' . esc_attr__( 'Network exposure diagram', 'vulnhub' ) . '"></div>';
		echo '<p class="vh-sub vh-muted">' . esc_html__( 'Note: Plerion does not expose security-group port rules, so this is an exposure map (internet → exposed → internal), not a port-level flow diagram. Port-level communication would need the AWS security-group data.', 'vulnhub' ) . '</p>';
	}
}
