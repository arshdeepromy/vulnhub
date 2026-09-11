<?php
/**
 * Elementor theme locations, and the portal's use of them.
 *
 * @package VulnHub\Elementor
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Hands the portal's chrome to the Elementor Pro Theme Builder.
 *
 * Twenty Twenty-Five is a block theme and declares no Elementor locations of
 * its own, so without this the Theme Builder will happily let somebody build a
 * header template and then never display it. Registering the core locations
 * here means a header, a footer and the single/archive locations all become
 * assignable, and the portal shell asks for the two it cares about.
 */
final class VulnHub_El_Locations {

	/** Stylesheet handle for the small amount of Elementor-only CSS. */
	public const STYLE = 'vulnhub-elementor';

	public static function init(): void {
		add_action( 'elementor/theme/register_locations', array( __CLASS__, 'register' ) );
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'assets' ) );
		add_action( 'elementor/editor/after_enqueue_styles', array( __CLASS__, 'assets' ) );

		// The portal shell calls these two; they are actions rather than a
		// direct call so that switching this plugin off leaves no trace.
		add_action( 'vulnhub_portal_header', array( __CLASS__, 'header' ) );
		add_action( 'vulnhub_portal_footer', array( __CLASS__, 'footer' ) );
		add_action( 'vulnhub_portal_notice', array( __CLASS__, 'notice' ) );
		add_filter( 'template_include', array( __CLASS__, 'template_include' ), 98 );
		add_filter( 'show_admin_bar', array( __CLASS__, 'admin_bar' ), 98 );
		add_filter( 'vulnhub_portal_has_custom_header', array( __CLASS__, 'has_header' ) );
		add_filter( 'vulnhub_portal_has_custom_footer', array( __CLASS__, 'has_footer' ) );
	}

	/**
	 * @param \ElementorPro\Modules\ThemeBuilder\Classes\Locations_Manager $manager Location registrar.
	 */
	public static function register( $manager ): void {
		$manager->register_all_core_location();

		/*
		 * A location of our own, so somebody can drop a standing notice --
		 * a change freeze, a scanning outage -- above every portal view
		 * without editing a template or touching the header.
		 */
		$manager->register_location(
			'vulnhub_notice',
			array(
				'label'           => esc_html__( 'VulnHub portal notice', 'vulnhub' ),
				'multiple'        => true,
				'edit_in_content' => false,
			)
		);
	}

	/**
	 * Draw Elementor pages in the VulnHub shell when the theme cannot.
	 *
	 * A block theme renders through `wp_template` and never calls
	 * `elementor_theme_do_location()`, so a Theme Builder header is assigned,
	 * valid and never printed. Rather than ask somebody to also install a
	 * classic theme, VulnHub supplies the shell -- but only when there is
	 * something to put in it, and never for the portal's own views, which have
	 * their own template at priority 99.
	 *
	 * @param string $template Template chosen so far.
	 */
	public static function template_include( string $template ): string {
		if ( ! is_singular() || is_admin() ) {
			return $template;
		}
		if ( ! wp_is_block_theme() ) {
			return $template;
		}

		$post = get_post();

		if ( ! $post ) {
			return $template;
		}
		// The portal owns its own pages; it filters at 99 and would win
		// anyway, but claiming them here would run this query for nothing.
		if ( class_exists( 'VulnHub_Dash_App' ) && VulnHub_Dash_App::view_for_post( $post ) ) {
			return $template;
		}
		if ( 'builder' !== get_post_meta( $post->ID, '_elementor_edit_mode', true ) ) {
			return $template;
		}
		if ( '' === self::location( 'header' ) && '' === self::location( 'footer' ) ) {
			return $template;
		}

		return VULNHUB_ELEMENTOR_DIR . 'templates/page.php';
	}

	/**
	 * Somebody who only holds VulnHub roles has no use for the WordPress
	 * admin bar anywhere on the site, not just inside the portal.
	 *
	 * @param bool $show Current answer.
	 */
	public static function admin_bar( $show ) {
		if ( class_exists( 'VulnHub_Dash_Portal' ) && VulnHub_Dash_Portal::is_portal_only_user() ) {
			return false;
		}
		return $show;
	}

	/**
	 * Cache-busting version, from the file's own mtime.
	 *
	 * Cloudflare fronts the portal and serves wp-content with
	 * `max-age=14400`, so a stylesheet edit shipped under a version constant
	 * that only moves on release is invisible to anyone who loaded the site
	 * in the previous four hours -- fresh markup, four-hour-old CSS. The
	 * dashboard plugin hit this first; the same reasoning applies here.
	 */
	private static function asset_ver( string $rel ): string {
		$mtime = @filemtime( VULNHUB_ELEMENTOR_DIR . $rel ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		return $mtime ? VULNHUB_ELEMENTOR_VERSION . '.' . $mtime : VULNHUB_ELEMENTOR_VERSION;
	}

	public static function assets(): void {
		wp_register_style( self::STYLE, VULNHUB_ELEMENTOR_URL . 'assets/elementor.css', array(), self::asset_ver( 'assets/elementor.css' ) );

		if ( doing_action( 'elementor/editor/after_enqueue_styles' ) ) {
			wp_enqueue_style( self::STYLE );
		}
	}

	/**
	 * Whether a Theme Builder template is actually assigned to a location.
	 *
	 * `elementor_theme_do_location()` both tests and prints, which is no use
	 * to a template that needs to decide *before* it opens a wrapper. So we
	 * buffer: if the location produced nothing, nothing is echoed and the
	 * caller falls back.
	 */
	private static function location( string $location ): string {
		/*
		 * Memoised because both the "is there one?" filter and the "print it"
		 * action ask, and rendering an Elementor template twice per request is
		 * both wasteful and, for anything with a query loop in it, wrong.
		 */
		static $cache = array();

		if ( isset( $cache[ $location ] ) ) {
			return $cache[ $location ];
		}
		if ( ! function_exists( 'elementor_theme_do_location' ) ) {
			$cache[ $location ] = '';
			return '';
		}

		ob_start();
		$done = elementor_theme_do_location( $location );
		$html = (string) ob_get_clean();

		$cache[ $location ] = $done ? $html : '';
		return $cache[ $location ];
	}

	public static function header(): void {
		echo self::location( 'header' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Elementor's own rendered template.
	}

	public static function footer(): void {
		echo self::location( 'footer' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Elementor's own rendered template.
	}

	public static function notice(): void {
		$html = self::location( 'vulnhub_notice' );

		if ( '' === $html ) {
			return;
		}
		echo '<div class="vh-el__portal-notice">' . $html . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Elementor's own rendered template.
	}

	/**
	 * @param bool $has Current answer.
	 */
	public static function has_header( bool $has ): bool {
		return $has || '' !== self::location( 'header' );
	}

	/**
	 * @param bool $has Current answer.
	 */
	public static function has_footer( bool $has ): bool {
		return $has || '' !== self::location( 'footer' );
	}
}

