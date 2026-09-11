<?php
/**
 * The Threat context screen.
 *
 * Everything the widget infers is adjustable here, and everything adjustable
 * here is explained on the same page. A number nobody can interrogate is a
 * number nobody trusts twice.
 *
 * @package VulnHub\Threat
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Settings, status and the manual refresh.
 */
final class VulnHub_Threat_Admin {

	public const SECTION = 'threat';
	public const NONCE   = 'vulnhub_threat_save';

	private static string $notice = '';

	public static function init(): void {
		add_filter( 'vulnhub_portal_sections', array( __CLASS__, 'register_section' ) );
		add_action( 'vulnhub_render_portal_section', array( __CLASS__, 'render_section' ) );
		add_action( 'template_redirect', array( __CLASS__, 'handle' ), 5 );
		add_action( 'admin_post_vulnhub_threat_save', array( __CLASS__, 'handle_admin_post' ) );
	}

	/**
	 * @param array<string,array<string,mixed>> $sections Section definitions.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_section( array $sections ): array {
		$sections[ self::SECTION ] = array(
			'label'   => __( 'Threat context', 'vulnhub' ),
			'cap'     => Caps::MANAGE,
			'group'   => 'data',
			'order'   => 40,
			'summary' => __( 'Where the exploit intelligence comes from, and how a vulnerability is placed on an attack path.', 'vulnhub' ),
		);

		return $sections;
	}

	/** @param string $section Section slug being rendered. */
	public static function render_section( $section ): void {
		if ( self::SECTION !== (string) $section || ! current_user_can( Caps::MANAGE ) ) {
			return;
		}

		include VULNHUB_THREAT_DIR . 'admin/views/threat.php';
	}

	/** The notice set by the last save, if any. */
	public static function notice(): string {
		return self::$notice;
	}

	public static function handle_admin_post(): void {
		self::process();

		wp_safe_redirect(
			class_exists( 'VulnHub_Dash_Portal' )
				? VulnHub_Dash_Portal::portal_url( VulnHub_Dash_Portal::ADMIN_VIEW, array( 'section' => self::SECTION, 'saved' => '1' ) )
				: admin_url()
		);
		exit;
	}

	public static function handle(): void {
		if ( ! isset( $_POST['vulnhub_threat_action'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			return;
		}

		self::process();
	}

	/**
	 * Save settings, or queue a refresh.
	 *
	 * The refresh is queued rather than run. It downloads about 100 MB and
	 * rewrites 13,000 rows; doing that inside somebody's button press would
	 * hit the web server's timeout halfway through and leave the tables in a
	 * half-ingested state. The cron container polls every 60 seconds and has
	 * no timeout over it, so the honest thing to promise is "shortly".
	 */
	private static function process(): void {
		if ( ! current_user_can( Caps::MANAGE ) ) {
			return;
		}

		$nonce = isset( $_POST['_wpnonce'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['_wpnonce'] ) ) : '';

		if ( ! wp_verify_nonce( $nonce, self::NONCE ) ) {
			self::$notice = __( 'That form had expired. Nothing was changed — please try again.', 'vulnhub' );

			return;
		}

		$action = sanitize_key( wp_unslash( (string) ( $_POST['vulnhub_threat_action'] ?? '' ) ) ); // phpcs:ignore

		if ( 'refresh' === $action ) {
			wp_schedule_single_event( time(), VulnHub_Threat_Feeds::CRON_HOOK );
			self::$notice = __( 'Refresh queued. The cron worker picks it up within a minute; a full first run takes a few minutes while it downloads the NVD year files.', 'vulnhub' );

			return;
		}

		if ( 'reclassify' === $action ) {
			$log = array();
			VulnHub_Threat_Feeds::derive_cve_columns( $log );
			$n = VulnHub_Threat_Classify::rebuild_all();
			$e = VulnHub_Threat_Classify::rebuild_exposure();

			self::$notice = sprintf(
				/* translators: 1: definitions replaced, 2: internet-facing assets. */
				__( 'Re-placed %1$s vulnerability definitions and %2$s internet-facing assets from the intelligence already downloaded.', 'vulnhub' ),
				number_format_i18n( $n ),
				number_format_i18n( $e )
			);

			return;
		}

		$sources = array();

		foreach ( array( 'kev', 'refs', 'epss' ) as $key ) {
			if ( ! empty( $_POST[ 'poc_' . $key ] ) ) { // phpcs:ignore
				$sources[] = $key;
			}
		}

		$epss = isset( $_POST['epss_min'] ) ? (float) wp_unslash( $_POST['epss_min'] ) : 10.0; // phpcs:ignore
		$rule = sanitize_key( wp_unslash( (string) ( $_POST['exposure_rule'] ?? 'servers_and_cloud' ) ) ); // phpcs:ignore
		$key  = sanitize_text_field( wp_unslash( (string) ( $_POST['nvd_key'] ?? '' ) ) ); // phpcs:ignore

		update_option( 'vulnhub_threat_poc_sources', $sources, false );
		update_option( 'vulnhub_threat_epss_min', max( 0, min( 100, $epss ) ) / 100, false );
		update_option( 'vulnhub_threat_exposure_rule', $rule, false );
		update_option( 'vulnhub_threat_backfill_exploit', empty( $_POST['backfill'] ) ? '' : '1', false ); // phpcs:ignore

		// A blank key means "keep what is stored", the same convention the
		// connector screens use, so a saved secret is never echoed back into
		// a form only to be saved as a mask.
		if ( '' !== $key ) {
			update_option( 'vulnhub_threat_nvd_key', $key, false );
		}

		$log = array();
		VulnHub_Threat_Feeds::derive_cve_columns( $log );
		$n = VulnHub_Threat_Classify::rebuild_all();
		$e = VulnHub_Threat_Classify::rebuild_exposure();

		self::$notice = sprintf(
			/* translators: 1: definitions replaced, 2: internet-facing assets. */
			__( 'Saved. %1$s vulnerability definitions and %2$s internet-facing assets re-placed against the new settings.', 'vulnhub' ),
			number_format_i18n( $n ),
			number_format_i18n( $e )
		);
	}
}
