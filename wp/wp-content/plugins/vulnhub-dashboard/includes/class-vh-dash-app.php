<?php
/**
 * Front-end application: routing, the app shell, and the five views.
 *
 * The shell is rendered independently of the active theme so the product looks
 * the same whatever theme is installed, while still calling wp_head()/wp_footer()
 * so the admin bar and enqueued assets behave normally.
 *
 * @package VulnHub\Dashboard
 */

declare( strict_types = 1 );

use VulnHub\Core\Repo;
use VulnHub\Core\Tickets;
use VulnHub\Core\Exceptions;
use VulnHub\Core\Mapping;
use VulnHub\Core\Caps;
use VulnHub\Core\Coverage;
use VulnHub\Core\Defender_Coverage;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Dash_App {

	private static string $current_view = 'dashboard';

	public static function init(): void {
		add_shortcode( 'vulnhub_app', array( __CLASS__, 'shortcode' ) );
		add_filter( 'template_include', array( __CLASS__, 'template_include' ), 99 );
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'assets' ) );
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'strip_builder_assets' ), 999 );
		add_filter( 'body_class', array( __CLASS__, 'body_class' ) );
		add_action( 'template_redirect', array( __CLASS__, 'redirect_signed_in' ) );
		add_filter( 'vulnhub_admin_screen_url', array( __CLASS__, 'exceptions_url_in_portal' ), 20, 3 );
	}

	/**
	 * Keep the exception request and decision screens inside the portal.
	 *
	 * Core's exceptions view builds every link and post-save redirect with
	 * vh_admin_url( 'vulnhub-exceptions' ). The portal's own redirect filter
	 * cannot map that screen -- it is a primary-nav view, not an admin
	 * section -- so rendered on the portal it pointed back into wp-admin,
	 * where a portal-only account is turned away. On a portal page it means
	 * the Exceptions view, which renders the same core form in place.
	 *
	 * @param string               $url  Default URL.
	 * @param string               $page Screen slug.
	 * @param array<string,scalar> $args Query arguments.
	 */
	public static function exceptions_url_in_portal( string $url, string $page, array $args ): string {
		if ( 'vulnhub-exceptions' !== $page || is_admin() || '' === self::view_for_post( get_post() ) ) {
			return $url;
		}

		return self::page_url( 'exceptions', $args );
	}

	/* -----------------------------------------------------------------
	 * Routing
	 * --------------------------------------------------------------- */

	/**
	 * Which view, if any, this request is for.
	 */
	public static function view_for_post( ?WP_Post $post ): string {
		if ( ! $post instanceof WP_Post ) {
			return '';
		}
		if ( ! has_shortcode( (string) $post->post_content, 'vulnhub_app' ) ) {
			return '';
		}
		foreach ( vulnhub_dash_views() as $view => $def ) {
			if ( str_contains( (string) $post->post_content, 'view="' . $view . '"' ) ) {
				return $view;
			}
		}
		return 'dashboard';
	}

	/**
	 * Send an already-signed-in visitor from sign-in to the portal.
	 *
	 * On `template_redirect` because that is the last hook before anything is
	 * printed. The same test has always existed at the top of render_login(),
	 * but a view runs long after the document head has gone out, so its
	 * wp_safe_redirect() had no header left to set: it failed, exited, and
	 * left whoever still had a session looking at an empty page.
	 */
	public static function redirect_signed_in(): void {
		if ( ! is_singular() || is_admin() ) {
			return;
		}
		if ( VulnHub_Dash_Portal::LOGIN_VIEW !== self::view_for_post( get_post() ) ) {
			return;
		}
		if ( ! is_user_logged_in() || ! current_user_can( Caps::VIEW ) ) {
			return;
		}

		wp_safe_redirect( VulnHub_Dash_Portal::portal_url() );
		exit;
	}

	public static function template_include( string $template ): string {
		if ( ! is_singular() ) {
			return $template;
		}
		$view = self::view_for_post( get_post() );
		if ( '' === $view ) {
			return $template;
		}

		self::$current_view = $view;
		return VULNHUB_DASH_DIR . 'templates/app.php';
	}

	/**
	 * @param string[] $classes Body classes.
	 * @return string[]
	 */
	public static function body_class( array $classes ): array {
		$view = self::view_for_post( get_post() );

		if ( '' !== $view ) {
			$classes[] = 'vh-app-body';
		}

		/*
		 * The 64px left rail only exists in the DOM when the portal draws its
		 * own chrome: an assigned Elementor Theme Builder header replaces
		 * render_nav() outright (templates/app.php). The stylesheet reserved
		 * the rail's width unconditionally, so with a Theme Builder header
		 * assigned every page sat in a 64px empty gutter with no rail in it.
		 */
		if ( '' !== $view && ! apply_filters( 'vulnhub_portal_has_custom_header', false ) ) {
			$classes[] = 'vh-chrome-rail';
		}

		/*
		 * Sign-in is full-bleed, and the shell's centred, padded main is the
		 * one thing standing in the way of that. The class is what login.css
		 * hangs the override on.
		 */
		if ( VulnHub_Dash_Portal::LOGIN_VIEW === $view ) {
			$classes[] = 'vh-login-body';
		}

		return $classes;
	}

	/**
	 * Registration is unconditional, enqueueing is not.
	 *
	 * A VulnHub Elementor widget can appear on any page in the site, and
	 * `get_style_depends()` can only name a handle WordPress already knows
	 * about -- an unregistered handle is dropped in silence, which shows up as
	 * a correct widget with no styling at all. So register everywhere, and
	 * only enqueue where the portal itself is being served.
	 */
	/**
	 * Cache-busting version for one bundled asset.
	 *
	 * The plugin version alone is not enough. Cloudflare sits in front of the
	 * portal and sends `cache-control: max-age=14400` for CSS, so with a
	 * version string that only moves on release, every stylesheet edit was
	 * invisible to anyone who had loaded the portal in the previous four
	 * hours -- the page served fresh markup styled by four-hour-old CSS,
	 * which is how a finished popover arrived looking like raw fieldsets.
	 *
	 * The file's own mtime moves whenever the file does, so the URL changes
	 * exactly when the bytes change and never otherwise. Falls back to the
	 * plugin version if the file cannot be stat'd.
	 *
	 * @param string $rel Path relative to the plugin directory.
	 */
	private static function asset_ver( string $rel ): string {
		static $cache = array();

		if ( isset( $cache[ $rel ] ) ) {
			return $cache[ $rel ];
		}

		$mtime = @filemtime( VULNHUB_DASH_DIR . $rel ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		$cache[ $rel ] = $mtime ? VULNHUB_DASH_VERSION . '.' . $mtime : VULNHUB_DASH_VERSION;

		return $cache[ $rel ];
	}

	public static function assets(): void {
		wp_register_style( 'vulnhub-app', VULNHUB_DASH_URL . 'assets/app.css', array(), self::asset_ver( 'assets/app.css' ) );
		// Redesign supplement: re-themes components the drop-in app.css does not
		// cover (topbar layout, tables' matrix/segbars/meter, notices, toasts,
		// OS badges, the product widget) and fits the real icon+text shell. Kept
		// as its own file so the design app.css stays a clean drop-in to update.
		wp_register_style( 'vulnhub-app-redesign', VULNHUB_DASH_URL . 'assets/app-redesign.css', array( 'vulnhub-app' ), self::asset_ver( 'assets/app-redesign.css' ) );
		wp_register_script( 'vulnhub-app', VULNHUB_DASH_URL . 'assets/app.js', array( 'wp-api-fetch' ), self::asset_ver( 'assets/app.js' ), true );
		// Motion layer for the dark redesign. Dependency-free and progressive:
		// enqueued after app.css, in the footer; removing it leaves the portal
		// fully usable but static.
		wp_register_script( 'vulnhub-motion', VULNHUB_DASH_URL . 'assets/vh-motion.js', array(), self::asset_ver( 'assets/vh-motion.js' ), true );
		wp_localize_script(
			'vulnhub-app',
			'VulnHubApp',
			array(
				'nonce'    => wp_create_nonce( 'wp_rest' ),
				// Built with rest_url() rather than assembled in JavaScript,
				// so this keeps working on an install in a subdirectory or
				// with plain permalinks.
				'restRoot' => esc_url_raw( rest_url( 'vulnhub-dashboard/v1/' ) ),
				'i18n'     => array(
					'raising'         => __( 'Raising…', 'vulnhub' ),
					'error'           => __( 'Something went wrong.', 'vulnhub' ),
					'noSelect'        => __( 'Select at least one finding first.', 'vulnhub' ),
					'layoutSaved'     => __( 'Dashboard saved', 'vulnhub' ),
					'layoutFailed'    => __( 'That arrangement could not be saved.', 'vulnhub' ),
					/* translators: %d: a number of findings. Keep the %d. */
					'selCount'        => __( '%d selected on this page', 'vulnhub' ),
					/* translators: %d: total number of matching findings. Keep the %d. */
					'selAllMatching'  => __( 'Select all %d matching these filters', 'vulnhub' ),
					/* translators: %d: total number of matching findings. Keep the %d. */
					'selAll'          => __( 'All %d matching findings selected', 'vulnhub' ),
					/* translators: 1: number shown, 2: total. Keep both placeholders. */
					'searchShowing'   => __( '%1$s of %2$s', 'vulnhub' ),
					'searchNoMatch'   => __( 'No products match your search.', 'vulnhub' ),
				),
			)
		);

		$view = self::view_for_post( get_post() );

		if ( '' === $view ) {
			return;
		}
		wp_enqueue_style( 'vulnhub-app' );
		wp_enqueue_style( 'vulnhub-app-redesign' );
		wp_enqueue_script( 'vulnhub-app' );
		wp_enqueue_script( 'vulnhub-motion' );

		if ( VulnHub_Dash_Portal::LOGIN_VIEW !== $view ) {
			return;
		}

		/*
		 * Sign-in is the one screen with its own typefaces and its own animated
		 * scene, and it is also the only screen a signed-out visitor can reach.
		 * Both are loaded here rather than with the app so the product itself
		 * never pays for them.
		 */
		wp_enqueue_style(
			'vulnhub-login-fonts',
			'https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap',
			array(),
			null
		);
		wp_enqueue_style( 'vulnhub-login', VULNHUB_DASH_URL . 'assets/login.css', array( 'vulnhub-app' ), self::asset_ver( 'assets/login.css' ) );
		wp_enqueue_script( 'vulnhub-asm-bg', VULNHUB_DASH_URL . 'assets/attack-surface-bg.js', array(), self::asset_ver( 'assets/attack-surface-bg.js' ), true );
		wp_enqueue_script( 'vulnhub-login', VULNHUB_DASH_URL . 'assets/login.js', array( 'vulnhub-asm-bg' ), self::asset_ver( 'assets/login.js' ), true );
	}

	/**
	 * Keep the page builder off the sign-in screen.
	 *
	 * Elementor enqueues its frontend runtime site-wide, but only prints the
	 * `elementorFrontendConfig` object on documents it actually built. Sign-in
	 * is our own template, so the runtime arrived without its configuration and
	 * threw a ReferenceError on load -- an uncaught exception in the console of
	 * the one page every visitor sees before they are even signed in, plus two
	 * bundles of dead weight on the slowest, coldest request in the product.
	 *
	 * Scoped to the login view on purpose: portal pages can legitimately embed
	 * Elementor-built content, and the admin mirror renders whatever wp-admin
	 * hands it.
	 */
	public static function strip_builder_assets(): void {
		if ( VulnHub_Dash_Portal::LOGIN_VIEW !== self::view_for_post( get_post() ) ) {
			return;
		}

		foreach ( array( 'elementor-frontend', 'elementor-webpack-runtime', 'elementor-frontend-modules', 'elementor-pro-frontend' ) as $handle ) {
			wp_dequeue_script( $handle );
		}

		foreach ( array( 'elementor-frontend', 'elementor-post-13', 'elementor-icons', 'swiper', 'e-swiper' ) as $handle ) {
			wp_dequeue_style( $handle );
		}
	}

	/**
	 * The shortcode is a fallback for when a theme or block context renders the
	 * page without our template — the same view, without the shell chrome.
	 *
	 * @param array<string,string>|string $atts Shortcode attributes.
	 */
	public static function shortcode( $atts = array() ): string {
		$atts = shortcode_atts( array( 'view' => 'dashboard' ), (array) $atts, 'vulnhub_app' );
		$view = array_key_exists( (string) $atts['view'], vulnhub_dash_views() ) ? (string) $atts['view'] : 'dashboard';

		ob_start();
		self::render_view( $view );
		return (string) ob_get_clean();
	}

	public static function current_view(): string {
		return self::$current_view;
	}

	/* -----------------------------------------------------------------
	 * Access control
	 * --------------------------------------------------------------- */

	private static function gate(): bool {
		if ( is_user_logged_in() && current_user_can( Caps::VIEW ) ) {
			return true;
		}

		echo '<div class="vh-gate">';
		echo '<svg viewBox="0 0 24 24" class="vh-gate__icon" aria-hidden="true"><path d="M12 2l9 4v6c0 5-3.8 9.3-9 10-5.2-.7-9-5-9-10V6z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg>';

		if ( is_user_logged_in() ) {
			echo '<h1>' . esc_html__( 'You do not have access to VulnHub', 'vulnhub' ) . '</h1>';
			echo '<p>' . esc_html__( 'Your account is signed in but has not been granted a VulnHub role. Ask an administrator to assign you one.', 'vulnhub' ) . '</p>';
		} else {
			echo '<h1>' . esc_html__( 'Sign in to VulnHub', 'vulnhub' ) . '</h1>';
			echo '<p>' . esc_html__( 'Live vulnerability, asset and ownership intelligence. Sign in to continue.', 'vulnhub' ) . '</p>';
			printf(
				'<a class="vh-btn vh-btn--primary" href="%s">%s</a>',
				esc_url( VulnHub_Dash_Portal::login_url( (string) get_permalink() ) ),
				esc_html__( 'Sign in', 'vulnhub' )
			);
		}
		echo '</div>';

		return false;
	}

	/* -----------------------------------------------------------------
	 * Shell
	 * --------------------------------------------------------------- */

	/**
	 * Extra destinations in the primary navigation.
	 *
	 * The five core views are pages the portal itself owns and renders. This
	 * is for everything else somebody wants alongside them -- an Elementor
	 * page built on VulnHub widgets, a runbook, a link out to Tenable. Each
	 * entry is label, url and an SVG path for the icon; anything else is
	 * ignored, and a link with no url is dropped.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function extra_nav_links(): array {
		$links = (array) apply_filters( 'vulnhub_portal_nav_extra', array() );
		$out   = array();

		foreach ( $links as $link ) {
			if ( ! is_array( $link ) || empty( $link['url'] ) || empty( $link['label'] ) ) {
				continue;
			}

			$out[] = array(
				'label'  => (string) $link['label'],
				'url'    => (string) $link['url'],
				'icon'   => (string) ( $link['icon'] ?? 'M4 4h16v16H4z' ),
				'active' => ! empty( $link['active'] ),
			);
		}

		return $out;
	}

	public static function render_nav(): void {
		$pages   = (array) get_option( 'vulnhub_dash_pages', array() );
		$current = self::$current_view;
		?>
		<header class="vh-topbar">
			<a class="vh-brand" href="<?php echo esc_url( home_url( '/' ) ); ?>">
				<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2l9 4v6c0 5-3.8 9.3-9 10-5.2-.7-9-5-9-10V6z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg>
				<span><?php echo esc_html( (string) vulnhub()->settings->platform( 'org_name', get_bloginfo( 'name' ) ) ); ?></span>
			</a>

			<nav class="vh-nav" aria-label="<?php esc_attr_e( 'VulnHub sections', 'vulnhub' ); ?>">
				<?php foreach ( vulnhub_dash_views() as $view => $def ) : ?>
					<?php
					if ( ! empty( $def['hidden'] ) ) {
						continue;
					}
					$url = ! empty( $pages[ $view ] ) ? get_permalink( (int) $pages[ $view ] ) : '#';
					if ( ! $url ) {
						continue;
					}
					?>
					<a class="vh-nav__link<?php echo $current === $view ? ' is-active' : ''; ?>"
						href="<?php echo esc_url( $url ); ?>"
						<?php echo $current === $view ? ' aria-current="page"' : ''; ?>>
						<svg viewBox="0 0 24 24" aria-hidden="true"><path d="<?php echo esc_attr( $def['icon'] ); ?>" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
						<span class="vh-nav__txt"><?php echo esc_html( $def['menu'] ); ?></span>
					</a>
				<?php endforeach; ?>
				<?php foreach ( self::extra_nav_links() as $link ) : ?>
					<a class="vh-nav__link<?php echo ! empty( $link['active'] ) ? ' is-active' : ''; ?>"
						href="<?php echo esc_url( (string) $link['url'] ); ?>">
						<svg viewBox="0 0 24 24" aria-hidden="true"><path d="<?php echo esc_attr( (string) $link['icon'] ); ?>" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
						<span class="vh-nav__txt"><?php echo esc_html( (string) $link['label'] ); ?></span>
					</a>
				<?php endforeach; ?>
			</nav>

			<div class="vh-topbar__end">
				<?php if ( vulnhub()->settings->mock_mode() ) : ?>
					<span class="vh-chip vh-chip--warn" title="<?php esc_attr_e( 'Running on generated sample data. Add credentials in the admin portal to go live.', 'vulnhub' ); ?>">
						<?php esc_html_e( 'Sample data', 'vulnhub' ); ?>
					</span>
				<?php endif; ?>
				<button type="button" class="vh-iconbtn" data-vh-theme aria-label="<?php esc_attr_e( 'Switch between light and dark', 'vulnhub' ); ?>">
					<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 13a9 9 0 11-10-10 7 7 0 0010 10z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg>
				</button>
				<?php if ( current_user_can( Caps::MANAGE ) ) : ?>
					<a class="vh-nav__link vh-nav__link--admin<?php echo VulnHub_Dash_Portal::ADMIN_VIEW === $current ? ' is-active' : ''; ?>"
						href="<?php echo esc_url( VulnHub_Dash_Portal::portal_url( VulnHub_Dash_Portal::ADMIN_VIEW ) ); ?>"
						title="<?php esc_attr_e( 'Administration', 'vulnhub' ); ?>">
						<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" stroke-width="1.7"/><path d="M19.4 13a1.7 1.7 0 00.3 1.9l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-2.9 1.2V21a2 2 0 11-4 0v-.1a1.7 1.7 0 00-2.9-1.2l-.1.1a2 2 0 11-2.8-2.8l.1-.1A1.7 1.7 0 004.6 15H4.5a2 2 0 110-4h.1a1.7 1.7 0 001.2-2.9l-.1-.1a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 002.9-1.2V4a2 2 0 114 0v.1a1.7 1.7 0 002.9 1.2l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 001.2 2.9h.1a2 2 0 110 4h-.1a1.7 1.7 0 00-1.5 1z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
						<span class="vh-nav__txt"><?php esc_html_e( 'Administration', 'vulnhub' ); ?></span>
					</a>
				<?php endif; ?>
				<?php if ( is_user_logged_in() ) : ?>
					<details class="vh-account">
						<summary aria-label="<?php esc_attr_e( 'Account', 'vulnhub' ); ?>">
							<span class="vh-account__initials"><?php echo esc_html( strtoupper( substr( wp_get_current_user()->display_name, 0, 2 ) ) ); ?></span>
						</summary>
						<div class="vh-account__menu">
							<p class="vh-account__name"><?php echo esc_html( wp_get_current_user()->display_name ); ?></p>
							<p class="vh-account__mail"><?php echo esc_html( wp_get_current_user()->user_email ); ?></p>
							<?php
							/*
							 * The portal's own "Your security" section when the auth
							 * plugin provides it. profile.php is wp-admin, which a
							 * portal-only account is redirected away from, so the
							 * old link sent them straight back to the dashboard.
							 */
							$vh_security = isset( VulnHub_Dash_Portal::sections()['security'] )
								? VulnHub_Dash_Portal::portal_url( VulnHub_Dash_Portal::ADMIN_VIEW, array( 'section' => 'security' ) )
								: admin_url( 'profile.php' );
							?>
							<a href="<?php echo esc_url( $vh_security ); ?>"><?php esc_html_e( 'Security &amp; MFA', 'vulnhub' ); ?></a>
							<a href="<?php echo esc_url( wp_logout_url( VulnHub_Dash_Portal::login_url() ) ); ?>"><?php esc_html_e( 'Sign out', 'vulnhub' ); ?></a>
						</div>
					</details>
				<?php endif; ?>
			</div>
		</header>
		<?php
	}

	/* -----------------------------------------------------------------
	 * Views
	 * --------------------------------------------------------------- */

	public static function render_view( string $view ): void {
		if ( VulnHub_Dash_Portal::LOGIN_VIEW === $view ) {
			VulnHub_Dash_Portal::render_login();
			return;
		}
		if ( ! self::gate() ) {
			return;
		}

		/*
		 * A view contributed by another plugin renders itself. Checked before
		 * the switch so a contributed view cannot be silently swallowed by
		 * the default case and shown as the dashboard, which is a confusing
		 * failure to debug.
		 */
		if ( has_action( 'vulnhub_dash_render_view_' . $view ) ) {
			do_action( 'vulnhub_dash_render_view_' . $view );
			return;
		}

		switch ( $view ) {
			case VulnHub_Dash_Portal::ADMIN_VIEW:
				VulnHub_Dash_Portal::render_admin();
				break;
			case 'vulnerabilities':
				self::view_vulnerabilities();
				break;
			case 'assets':
				self::view_assets();
				break;
			case 'tickets':
				self::view_tickets();
				break;
			case 'exceptions':
				self::view_exceptions();
				break;
			case 'products':
				self::view_products();
				break;
			case 'vendors':
				self::view_vendors();
				break;
			default:
				self::view_dashboard();
		}
	}

	/**
	 * Read a whitelisted filter from the query string.
	 */
	private static function q( string $key, string $default = '' ): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return isset( $_GET[ $key ] ) ? sanitize_text_field( wp_unslash( (string) $_GET[ $key ] ) ) : $default;
	}

	private static function qi( string $key, int $default = 0 ): int {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return isset( $_GET[ $key ] ) ? (int) $_GET[ $key ] : $default;
	}

	private static function page_url( string $view, array $args = array() ): string {
		$pages = (array) get_option( 'vulnhub_dash_pages', array() );
		$base  = ! empty( $pages[ $view ] ) ? (string) get_permalink( (int) $pages[ $view ] ) : home_url( '/' );
		return $args ? add_query_arg( $args, $base ) : $base;
	}

	/* ------------------------------------------------------ dashboard. */

	/**
	 * The dashboard is whatever the person looking at it decided it is.
	 *
	 * Widgets come from the registry, the arrangement comes from the
	 * operator's own saved layout, and the editor below is progressive: with
	 * no JavaScript you still get the dashboard, you just cannot rearrange it.
	 */
	private static function view_dashboard(): void {
		$layout  = VulnHub_Dash_Widgets::layout();
		$all     = VulnHub_Dash_Widgets::all();
		$notice  = self::q( 'vh_layout' );
		$active  = array_column( $layout, 'id' );
		?>
		<div class="vh-page-head">
			<div>
				<h1><?php esc_html_e( 'Security dashboard', 'vulnhub' ); ?></h1>
				<p class="vh-sub"><?php esc_html_e( 'Live exposure across the estate, who owns it, what is being done about it, and what has never been scanned at all.', 'vulnhub' ); ?></p>
			</div>
			<div class="vh-page-head__actions">
				<button type="button" class="vh-btn vh-btn--ghost" data-vh-customise aria-expanded="false" aria-controls="vh-customise" hidden>
					<svg viewBox="0 0 24 24" aria-hidden="true" width="15" height="15"><path d="M4 7h10M18 7h2M4 17h4M12 17h8M14 4v6M8 14v6" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>
					<?php esc_html_e( 'Customise', 'vulnhub' ); ?>
				</button>
			</div>
		</div>

		<?php if ( 'saved' === $notice ) : ?>
			<p class="vh-flash vh-flash--good"><?php esc_html_e( 'Your dashboard has been saved.', 'vulnhub' ); ?></p>
		<?php elseif ( 'reset' === $notice ) : ?>
			<p class="vh-flash"><?php esc_html_e( 'Your dashboard is back to the default arrangement.', 'vulnhub' ); ?></p>
		<?php endif; ?>

		<form class="vh-customise" id="vh-customise" method="post"
			action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" hidden>
			<input type="hidden" name="action" value="vulnhub_save_layout">
			<input type="hidden" name="vh_from_portal" value="1">
			<?php wp_nonce_field( 'vulnhub_save_layout' ); ?>
			<input type="hidden" name="layout" value="" data-vh-layout-field>

			<div class="vh-customise__head">
				<div>
					<h2><?php esc_html_e( 'Build your dashboard', 'vulnhub' ); ?></h2>
					<p class="vh-sub"><?php esc_html_e( 'Add the widgets you care about, set how wide each one sits, and drag to reorder. Saved to your account, so everyone can keep their own view.', 'vulnhub' ); ?></p>
				</div>
				<div class="vh-customise__actions">
					<button type="submit" class="vh-btn"><?php esc_html_e( 'Save dashboard', 'vulnhub' ); ?></button>
					<button type="submit" name="reset" value="1" class="vh-btn vh-btn--ghost"><?php esc_html_e( 'Reset to default', 'vulnhub' ); ?></button>
				</div>
			</div>

			<div class="vh-customise__cols">
				<div class="vh-customise__col">
					<h3><?php esc_html_e( 'On your dashboard', 'vulnhub' ); ?></h3>
					<ol class="vh-picked" data-vh-picked>
						<?php foreach ( $layout as $item ) : ?>
							<?php $def = $all[ $item['id'] ] ?? null; ?>
							<?php if ( ! $def ) : continue; endif; ?>
							<li class="vh-picked__row" draggable="true" data-vh-id="<?php echo esc_attr( $item['id'] ); ?>" data-vh-width="<?php echo esc_attr( (string) $item['width'] ); ?>">
								<span class="vh-picked__grip" aria-hidden="true">⋮⋮</span>
								<span class="vh-picked__label"><?php echo esc_html( (string) $def['label'] ); ?></span>
								<label class="vh-picked__width">
									<span class="screen-reader-text"><?php esc_html_e( 'Width', 'vulnhub' ); ?></span>
									<select data-vh-width-select>
										<?php foreach ( VulnHub_Dash_Widgets::WIDTHS as $w ) : ?>
											<option value="<?php echo esc_attr( (string) $w ); ?>" <?php selected( (int) $item['width'], $w ); ?>>
												<?php
												printf(
													/* translators: %d: number of twelfths of the grid. */
													esc_html__( '%d/12', 'vulnhub' ),
													(int) $w
												);
												?>
											</option>
										<?php endforeach; ?>
									</select>
								</label>
								<button type="button" class="vh-picked__remove" data-vh-remove aria-label="<?php esc_attr_e( 'Remove widget', 'vulnhub' ); ?>">&times;</button>
							</li>
						<?php endforeach; ?>
					</ol>
					<p class="vh-picked__empty" data-vh-picked-empty <?php echo $layout ? 'hidden' : ''; ?>>
						<?php esc_html_e( 'Nothing on the dashboard yet. Add a widget from the right.', 'vulnhub' ); ?>
					</p>
				</div>

				<div class="vh-customise__col">
					<h3><?php esc_html_e( 'Available widgets', 'vulnhub' ); ?></h3>
					<?php foreach ( VulnHub_Dash_Widgets::groups() as $group => $group_label ) : ?>
						<?php
						$in_group = array_filter( $all, static fn( array $w ): bool => ( $w['group'] ?? '' ) === $group );
						if ( ! $in_group ) {
							continue;
						}
						?>
						<p class="vh-customise__group"><?php echo esc_html( $group_label ); ?></p>
						<ul class="vh-available">
							<?php foreach ( $in_group as $id => $def ) : ?>
								<li>
									<button type="button" class="vh-available__add"
										data-vh-add="<?php echo esc_attr( (string) $id ); ?>"
										data-vh-label="<?php echo esc_attr( (string) $def['label'] ); ?>"
										data-vh-default-width="<?php echo esc_attr( (string) $def['width'] ); ?>"
										<?php echo in_array( $id, $active, true ) ? 'disabled' : ''; ?>>
										<span class="vh-available__plus" aria-hidden="true">+</span>
										<span>
											<strong><?php echo esc_html( (string) $def['label'] ); ?></strong>
											<em><?php echo esc_html( (string) ( $def['summary'] ?? '' ) ); ?></em>
										</span>
									</button>
								</li>
							<?php endforeach; ?>
						</ul>
					<?php endforeach; ?>
				</div>
			</div>
		</form>

		<div class="vh-board" data-vh-board>
			<?php
			if ( ! $layout ) {
				echo VulnHub_Dash_Charts::empty_state( esc_html__( 'Your dashboard is empty. Use Customise to add widgets.', 'vulnhub' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			}

			foreach ( $layout as $item ) {
				VulnHub_Dash_Widgets::render( (string) $item['id'], (int) $item['width'] );
			}
			?>
		</div>
		<?php
	}

	/**
	 * Columns the findings table may be sorted by, and the direction each
	 * one should open in. Mirrors the keys Repo::findings() accepts; anything
	 * outside this list falls back to risk_score.
	 *
	 * @var array<string,string>
	 */
	private const SORTABLE = array(
		'risk_score'      => 'DESC',
		'severity'        => 'DESC',
		'title'           => 'ASC',
		'hostname'        => 'ASC',
		'due_at'          => 'ASC',
		'last_found'      => 'DESC',
		'asset_type'      => 'ASC',
		'owner_person_id' => 'DESC',
		'open_critical'   => 'DESC',
		'last_seen'       => 'DESC',
	);

	/**
	 * The systems that know an asset, as chips that filter the list.
	 *
	 * The date is in the tooltip rather than on the chip because a row of
	 * three dated chips is unreadable at a glance, but the date is the whole
	 * point once a reader stops to look: a source that last claimed a machine
	 * eight months ago is the one worth doubting.
	 *
	 * When the list is filtered to one source ("Known by CMDB"), that chip is
	 * drawn first and highlighted. Every source still shows -- the other feeds
	 * are exactly what someone checking CMDB coverage wants to see beside it --
	 * but the eye needs one fixed place to land, row after row, to confirm the
	 * filter is doing what it says.
	 *
	 * @param string $stored The asset's `sources_json` column.
	 * @param bool   $link   Whether chips should filter the assets list.
	 * @param string $focus  Source slug to highlight, or '' for none.
	 * @return string Escaped HTML.
	 */
	private static function source_chips( string $stored, bool $link = true, string $focus = '' ): string {
		$seen = Repo::source_map( $stored );

		if ( ! $seen ) {
			return '<span class="vh-muted" title="' . esc_attr__( 'No feed has claimed this asset.', 'vulnhub' ) . '">&mdash;</span>';
		}

		if ( '' !== $focus && array_key_exists( $focus, $seen ) ) {
			$seen = array( $focus => $seen[ $focus ] ) + $seen;
		}

		$labels = vh_asset_sources();
		$out    = array();

		foreach ( $seen as $slug => $date ) {
			$name = (string) ( $labels[ $slug ] ?? ucfirst( $slug ) );
			$tip  = '' === $date
				/* translators: %s: name of a source system. */
				? sprintf( __( '%s knows this asset. No date recorded.', 'vulnhub' ), $name )
				/* translators: 1: name of a source system, 2: a date. */
				: sprintf( __( '%1$s last claimed this asset on %2$s.', 'vulnhub' ), $name, vh_date( $date ) );

			$is_focus = $slug === $focus;

			if ( $is_focus ) {
				/* translators: %s: the sentence describing when the source last claimed the asset. */
				$tip = sprintf( __( '%s This is the source the list is filtered on.', 'vulnhub' ), $tip );
			}

			$chip = sprintf(
				'<span class="vh-chip vh-chip--src vh-chip--src-%s%s" title="%s">%s</span>',
				esc_attr( $slug ),
				$is_focus ? ' is-focus' : '',
				esc_attr( $tip ),
				esc_html( $name )
			);

			$out[] = $link
				? '<a class="vh-srcs__link" href="' . esc_url( self::page_url( 'assets', array( 'known' => $slug, 'life' => 'reportable' ) ) ) . '">' . $chip . '</a>'
				: $chip;
		}

		return '<span class="vh-srcs">' . implode( ' ', $out ) . '</span>';
	}

	/**
	 * The source the assets list is filtered to, for source_chips() to
	 * highlight. "Known by X" and "Only known by X" name one; "Not known by X"
	 * has nothing to highlight, because no row carries X.
	 *
	 * Read from the query string, so the infinite-scroll endpoint -- a real
	 * GET carrying the same filters -- highlights the rows it appends too.
	 */
	private static function known_focus(): string {
		$known = self::q( 'known' );

		if ( '' === $known || str_starts_with( $known, 'not:' ) ) {
			return '';
		}

		return sanitize_key( str_starts_with( $known, 'only:' ) ? substr( $known, 5 ) : $known );
	}

	/**
	 * A sortable column header: a link that toggles direction, and tells a
	 * screen reader which way the table is currently ordered.
	 */
	private static function sort_th( string $key, string $label, string $orderby, string $order, string $page = 'vulnerabilities', string $suffix = '' ): void {
		$active = $orderby === $key;
		$next   = $active
			? ( 'ASC' === $order ? 'DESC' : 'ASC' )
			: ( self::SORTABLE[ $key ] ?? 'DESC' );

		$params          = $_GET; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$params          = is_array( $params ) ? array_map( 'sanitize_text_field', wp_unslash( $params ) ) : array();
		$params['orderby'] = $key;
		$params['order']   = $next;
		// A new sort starts at page one; keeping the old offset lands the
		// reader in the middle of a list they have not seen the top of.
		unset( $params['vp'], $params['ap'], $params['page_id'] );

		$aria = $active ? ( 'ASC' === $order ? 'ascending' : 'descending' ) : 'none';

		printf(
			'<th aria-sort="%s"><a class="vh-sort%s" href="%s">%s<span class="vh-sort__mark" aria-hidden="true">%s</span></a>%s</th>',
			esc_attr( $aria ),
			$active ? ' is-active' : '',
			esc_url( self::page_url( $page, $params ) ),
			esc_html( $label ),
			$active ? ( 'ASC' === $order ? '&#9650;' : '&#9660;' ) : '',
			$suffix // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- trusted markup (e.g. the owner-privacy toggle).
		);
	}

	/**
	 * The eye toggle that reveals masked owner names in a list header.
	 *
	 * Rendered in any table that masks the Owner column; app.js finds it,
	 * flips the mask on that table, and remembers the choice per viewer.
	 * Masked is the default, so a screenshot or screen-share never leaks names.
	 */
	public static function owner_eye_html(): string {
		return sprintf(
			'<button type="button" class="vh-eye" data-vh-owner-toggle aria-pressed="false" title="%1$s" aria-label="%1$s">'
			. '<svg class="vh-eye__on" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>'
			. '<svg class="vh-eye__off" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 3l18 18M10.6 10.6a3 3 0 004.2 4.2M9.9 5.1A9.9 9.9 0 0112 5c6.5 0 10 7 10 7a13.3 13.3 0 01-2.2 2.8M6.3 6.3A13.3 13.3 0 002 12s3.5 7 10 7a9.8 9.8 0 003.6-.7"/></svg>'
			. '</button>',
			esc_attr__( 'Show owner names', 'vulnhub' )
		);
	}

	/**
	 * Wrap a person's name so the Owner column can mask it by default.
	 */
	public static function owner_mask_html( string $name ): string {
		return '<span class="vh-mask" data-vh-mask><span class="vh-mask__dots" aria-hidden="true">••••••••</span><span class="vh-mask__real">'
			. esc_html( $name ) . '</span></span>';
	}

	/* ------------------------------------------------ vulnerabilities. */

	/**
	 * One vulnerability: what it is, how to fix it, and who has it.
	 *
	 * The list answers "what is wrong across the estate"; this answers "what
	 * *is* this thing". Tenable's own words for that -- the description, the
	 * solution, the plugin family that names the affected product -- were
	 * being imported and stored all along with nowhere to read them.
	 *
	 * @param int $vuln_id Vulnerability id.
	 */
	private static function view_vulnerability( int $vuln_id ): void {
		$v = Repo::vuln( $vuln_id );

		if ( ! $v ) {
			echo '<p class="vh-chart-empty">' . esc_html__( 'That vulnerability is not in the catalogue.', 'vulnhub' ) . '</p>';
			return;
		}

		$per   = 25;
		$paged = max( 1, self::qi( 'vp', 1 ) );

		$affected = Repo::findings(
			array(
				'vuln_id' => $vuln_id,
				'state'   => self::q( 'state', 'open_any' ),
				'orderby' => 'risk_score',
				'limit'   => $per,
				'offset'  => ( $paged - 1 ) * $per,
			)
		);

		$all   = Repo::findings( array( 'vuln_id' => $vuln_id, 'limit' => 1 ) );
		$total = (int) $affected['total'];
		$pages = max( 1, (int) ceil( $total / $per ) );
		$cves  = vh_json( (string) $v['cve_json'] );
		$links = array_values( array_filter( array_map( 'trim', preg_split( '/[\r\n]+/', (string) $v['see_also'] ) ?: array() ) ) );
		?>
		<p class="vh-sub">
			<a href="<?php echo esc_url( self::page_url( 'vulnerabilities' ) ); ?>">&larr; <?php esc_html_e( 'All vulnerabilities', 'vulnhub' ); ?></a>
		</p>

		<div class="vh-page-head">
			<div>
				<h1><?php echo esc_html( (string) $v['title'] ); ?></h1>
				<p class="vh-sub">
					<span class="vh-pill vh-pill--<?php echo esc_attr( (string) $v['severity'] ); ?>"><?php echo esc_html( vh_severity_label( (string) $v['severity'] ) ); ?></span>
					<?php if ( $v['family'] ) : ?>
						· <?php echo esc_html( (string) $v['family'] ); ?>
					<?php endif; ?>
					· <span class="vh-mono"><?php echo esc_html( 'plugin ' . $v['plugin_id'] ); ?></span>
				</p>
			</div>
		</div>

		<div class="vh-grid vh-grid--3">
			<section class="vh-panel">
				<header class="vh-panel__head"><h2><?php esc_html_e( 'Scoring', 'vulnhub' ); ?></h2></header>
				<dl class="vh-dl">
					<dt><?php esc_html_e( 'CVSS v3', 'vulnhub' ); ?></dt>
					<dd class="vh-mono"><?php echo esc_html( (float) $v['cvss3_base'] > 0 ? (string) $v['cvss3_base'] : '—' ); ?></dd>
					<dt><?php esc_html_e( 'CVSS v2', 'vulnhub' ); ?></dt>
					<dd class="vh-mono"><?php echo esc_html( (float) $v['cvss2_base'] > 0 ? (string) $v['cvss2_base'] : '—' ); ?></dd>
					<dt><?php esc_html_e( 'VPR', 'vulnhub' ); ?></dt>
					<dd class="vh-mono"><?php echo esc_html( (float) $v['vpr_score'] > 0 ? (string) $v['vpr_score'] : '—' ); ?></dd>
					<dt><?php esc_html_e( 'Exploit', 'vulnhub' ); ?></dt>
					<dd>
						<?php if ( ! empty( $v['exploit_available'] ) ) : ?>
							<span class="vh-chip vh-chip--bad"><?php esc_html_e( 'Available in the wild', 'vulnhub' ); ?></span>
						<?php else : ?>
							<span class="vh-sub"><?php esc_html_e( 'None reported', 'vulnhub' ); ?></span>
						<?php endif; ?>
					</dd>
					<dt><?php esc_html_e( 'Patch published', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( $v['patch_publication_date'] ? vh_date_only( (string) $v['patch_publication_date'] ) : '—' ); ?></dd>
					<dt><?php esc_html_e( 'CVE', 'vulnhub' ); ?></dt>
					<dd class="vh-mono"><?php echo esc_html( $cves ? implode( ', ', array_slice( $cves, 0, 6 ) ) : '—' ); ?></dd>
				</dl>
			</section>

			<section class="vh-panel">
				<header class="vh-panel__head"><h2><?php esc_html_e( 'Exposure', 'vulnhub' ); ?></h2></header>
				<dl class="vh-dl">
					<dt><?php esc_html_e( 'Assets affected', 'vulnhub' ); ?></dt>
					<dd><strong><?php echo esc_html( number_format_i18n( (int) $all['total'] ) ); ?></strong></dd>
					<dt><?php esc_html_e( 'Still open', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( number_format_i18n( (int) Repo::findings( array( 'vuln_id' => $vuln_id, 'state' => 'open_any', 'limit' => 1 ) )['total'] ) ); ?></dd>
					<dt><?php esc_html_e( 'Fixed', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( number_format_i18n( (int) Repo::findings( array( 'vuln_id' => $vuln_id, 'state' => 'fixed', 'limit' => 1 ) )['total'] ) ); ?></dd>
					<dt><?php esc_html_e( 'Past SLA', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( number_format_i18n( (int) Repo::findings( array( 'vuln_id' => $vuln_id, 'state' => 'open_any', 'overdue' => '1', 'limit' => 1 ) )['total'] ) ); ?></dd>
					<dt><?php esc_html_e( 'Source', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( (string) $v['source'] ); ?></dd>
				</dl>
			</section>

			<section class="vh-panel">
				<header class="vh-panel__head"><h2><?php esc_html_e( 'How to fix it', 'vulnhub' ); ?></h2></header>
				<?php if ( trim( (string) $v['solution'] ) !== '' ) : ?>
					<div class="vh-prose"><?php echo esc_html( (string) $v['solution'] ); ?></div>
				<?php else : ?>
					<p class="vh-sub"><?php esc_html_e( 'The scanner did not supply a remediation for this plugin.', 'vulnhub' ); ?></p>
				<?php endif; ?>
				<?php if ( $links ) : ?>
					<h3 class="vh-h3"><?php esc_html_e( 'References', 'vulnhub' ); ?></h3>
					<ul class="vh-links">
						<?php foreach ( array_slice( $links, 0, 8 ) as $link ) : ?>
							<li>
								<?php if ( str_starts_with( $link, 'http' ) ) : ?>
									<a href="<?php echo esc_url( $link ); ?>" target="_blank" rel="noopener noreferrer nofollow"><?php echo esc_html( vh_trim( $link, 70 ) ); ?></a>
								<?php else : ?>
									<?php echo esc_html( vh_trim( $link, 70 ) ); ?>
								<?php endif; ?>
							</li>
						<?php endforeach; ?>
					</ul>
				<?php endif; ?>
			</section>
		</div>

		<section class="vh-panel">
			<header class="vh-panel__head"><h2><?php esc_html_e( 'What this is', 'vulnhub' ); ?></h2></header>
			<?php if ( trim( (string) $v['description'] ) !== '' ) : ?>
				<?php \VulnHub\Core\Prose::render( (string) $v['description'] ); ?>
			<?php else : ?>
				<p class="vh-sub"><?php esc_html_e( 'No description was supplied for this plugin.', 'vulnhub' ); ?></p>
			<?php endif; ?>
		</section>

		<section class="vh-panel">
			<header class="vh-panel__head">
				<h2><?php esc_html_e( 'Affected assets', 'vulnhub' ); ?></h2>
				<?php
				/*
				 * The same export as the vulnerability list, narrowed to this
				 * one plugin. Somebody who has opened a KB with 433 affected
				 * machines is very often here to hand that list to whoever
				 * patches them, and until now the only way to get it was to
				 * go back out and rebuild the filter on the list screen.
				 */
				VulnHub_Dash_Export::button(
					'findings',
					array(
						'vuln'  => $vuln_id,
						'state' => self::q( 'state', 'open_any' ),
					)
				);
				?>
			</header>

			<form class="vh-filters" method="get">
				<input type="hidden" name="vuln" value="<?php echo esc_attr( (string) $vuln_id ); ?>">
				<label><?php esc_html_e( 'State', 'vulnhub' ); ?>
					<select name="state">
						<option value="open_any" <?php selected( self::q( 'state', 'open_any' ), 'open_any' ); ?>><?php esc_html_e( 'Open', 'vulnhub' ); ?></option>
						<option value="fixed" <?php selected( self::q( 'state' ), 'fixed' ); ?>><?php esc_html_e( 'Fixed', 'vulnhub' ); ?></option>
						<option value="" <?php selected( self::q( 'state' ), '' ); ?>><?php esc_html_e( 'Any state', 'vulnhub' ); ?></option>
					</select>
				</label>
				<button class="vh-btn"><?php esc_html_e( 'Apply', 'vulnhub' ); ?></button>
			</form>

			<?php if ( ! $affected['rows'] ) : ?>
				<p class="vh-ok-note"><?php esc_html_e( 'No assets match that state.', 'vulnhub' ); ?></p>
			<?php else : ?>
				<div class="vh-tablewrap">
					<table class="vh-table">
						<thead><tr>
							<th><?php esc_html_e( 'Asset', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'Type', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'App', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'Install path', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'Owner', 'vulnhub' ); ?><?php echo self::owner_eye_html(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></th>
							<th><?php esc_html_e( 'State', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'First found', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'Due', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'Ticket', 'vulnhub' ); ?></th>
						</tr></thead>
						<tbody>
						<?php foreach ( $affected['rows'] as $f ) : ?>
							<?php $overdue = ! empty( $f['due_at'] ) && strtotime( (string) $f['due_at'] . ' UTC' ) < time(); ?>
							<tr>
								<td>
									<a class="vh-mono" href="<?php echo esc_url( self::page_url( 'assets', array( 'asset' => (int) $f['asset_id'] ) ) ); ?>"><strong><?php echo esc_html( (string) $f['hostname'] ); ?></strong></a>
									<span class="vh-meta"><?php echo esc_html( (string) $f['ipv4'] ); ?></span>
								</td>
								<td><?php echo esc_html( vh_asset_types()[ (string) $f['asset_type'] ] ?? '' ); ?></td>
								<td>
									<?php if ( ! empty( $f['bundle_app'] ) ) : ?>
										<span class="vh-appcell">
											<?php echo VulnHub_Dash_Widgets::product_icon( (string) ( $f['bundle_app_slug'] ?? '' ), 'application', (string) $f['bundle_app'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
											<span><?php echo esc_html( (string) $f['bundle_app'] ); ?></span>
										</span>
									<?php else : ?>
										<span class="vh-meta">&mdash;</span>
									<?php endif; ?>
								</td>
								<td>
									<?php $vh_path = VH_Product::install_path( (string) ( $f['output'] ?? '' ) ); ?>
									<?php if ( '' !== $vh_path ) : ?>
										<code class="vh-path" title="<?php echo esc_attr( $vh_path ); ?>"><?php echo esc_html( $vh_path ); ?></code>
									<?php else : ?>
										<span class="vh-meta">&mdash;</span>
									<?php endif; ?>
								</td>
								<td>
									<?php if ( ! empty( $f['owner_name'] ) ) : ?>
										<?php echo self::owner_mask_html( (string) $f['owner_name'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
										<span class="vh-meta"><?php echo esc_html( (string) ( $f['team_name'] ?: '' ) ); ?></span>
									<?php elseif ( ! empty( $f['team_name'] ) ) : ?>
										<?php echo esc_html( (string) $f['team_name'] ); ?>
									<?php else : ?>
										<span class="vh-chip vh-chip--warn"><?php esc_html_e( 'Unassigned', 'vulnhub' ); ?></span>
									<?php endif; ?>
								</td>
								<td><?php echo esc_html( ucfirst( (string) $f['state'] ) ); ?></td>
								<td><?php echo esc_html( $f['first_found'] ? vh_ago( (string) $f['first_found'] ) : '—' ); ?></td>
								<td class="<?php echo $overdue ? 'vh-overdue' : ''; ?>"><?php echo esc_html( $f['due_at'] ? vh_ago( (string) $f['due_at'] ) : '—' ); ?></td>
								<td>
									<?php if ( ! empty( $f['ticket_key'] ) ) : ?>
										<a class="vh-mono" href="<?php echo esc_url( (string) $f['ticket_url'] ); ?>" target="_blank" rel="noopener noreferrer"><?php echo esc_html( (string) $f['ticket_key'] ); ?></a>
									<?php else : ?>—<?php endif; ?>
								</td>
							</tr>
						<?php endforeach; ?>
						</tbody>
					</table>
				</div>
				<?php self::pager( $paged, $pages, 'vp' ); ?>
			<?php endif; ?>
		</section>
		<?php
	}

	private static function view_vulnerabilities(): void {
		$vh_one = self::qi( 'vuln' );

		if ( $vh_one > 0 ) {
			self::view_vulnerability( $vh_one );
			return;
		}

		$per   = 25;
		$paged = max( 1, self::qi( 'vp', 1 ) );

		// Repo::findings() has always understood these; the portal never sent
		// them, so its table could not be sorted at all. wp-admin's findings
		// screen did, which is how it went unnoticed.
		$orderby = self::q( 'orderby', 'risk_score' );
		$order   = 'ASC' === strtoupper( self::q( 'order', 'DESC' ) ) ? 'ASC' : 'DESC';

		if ( ! isset( self::SORTABLE[ $orderby ] ) ) {
			$orderby = 'risk_score';
		}

		/*
		 * Lifecycle scope, the same vocabulary the assets list uses.
		 *
		 * This screen had no lifecycle filter at all. It looked right because
		 * the archive sweep takes findings off an asset when it leaves the
		 * estate, so they stop matching `open_any` -- but that is a side
		 * effect, not a filter, and nothing here would notice a sweep that
		 * missed. Asking explicitly means the list is right on its own terms.
		 */
		$vh_vlife     = self::q( 'life' );
		$vh_vlife_bad = '';
		$vh_vlife_ok  = array_merge( array( 'reportable', 'in_service_all', 'all' ), array_keys( vh_lifecycle_statuses() ) );

		if ( '' !== $vh_vlife && ! in_array( $vh_vlife, $vh_vlife_ok, true ) ) {
			$vh_vlife_bad = $vh_vlife;
			$vh_vlife     = '';
		}

		$args = array_merge(
			self::findings_base_args( $orderby, $order, $vh_vlife ),
			array(
				'limit'  => $per,
				'offset' => ( $paged - 1 ) * $per,
			)
		);
		$q     = Repo::findings( array_filter( $args, static fn( $v ): bool => '' !== $v && 0 !== $v ) );
		$total = (int) $q['total'];
		$pages = max( 1, (int) ceil( $total / $per ) );

		/*
		 * Two views over the same filtered set: the findings list, and a
		 * product breakdown of exactly those findings. The tab links carry
		 * every active filter so switching between them never changes scope.
		 */
		$vh_tab       = in_array( self::q( 'tab' ), array( 'products', 'vuln_assets' ), true ) ? self::q( 'tab' ) : 'findings';
		$vh_tab_carry = self::current_filters( array(
			'search', 'patch_available', 'ticketed', 'os_eol', 'support', 'severity', 'asset_type', 'team_id', 'department',
			'age', 'overdue', 'life', 'product', 'zone', 'platform', 'sev_not', 'route',
			'delivery', 'poc', 'hosting', 'asset', 'state', 'orderby', 'order', 'location_id',
		) );
		$vh_find_url  = self::page_url( 'vulnerabilities', $vh_tab_carry );
		$vh_prod_url  = self::page_url( 'vulnerabilities', array_merge( $vh_tab_carry, array( 'tab' => 'products' ) ) );
		$vh_va_url    = self::page_url( 'vulnerabilities', array_merge( $vh_tab_carry, array( 'tab' => 'vuln_assets' ) ) );

		/*
		 * What the Export button will actually hand over, spelled out on the
		 * button itself. The CSV export is the whole filtered set, not the
		 * page or a tick-box selection, and the only honest way to say so is
		 * to put the number the count line shows onto the download control.
		 * On the per-vulnerability tab that number is vulnerabilities, not
		 * findings, so it is counted the way that tab groups.
		 */
		if ( 'vuln_assets' === $vh_tab ) {
			$vh_group_ct              = array_filter( $args, static fn( $v ): bool => '' !== $v && 0 !== $v );
			$vh_group_ct['group']     = 'vuln';
			$vh_group_ct['limit']     = 1;
			unset( $vh_group_ct['offset'] );
			$vh_export_count          = (int) ( Repo::findings( $vh_group_ct )['total'] ?? 0 );
			$vh_export_noun           = _n( 'vulnerability', 'vulnerabilities', $vh_export_count, 'vulnhub' );
		} else {
			$vh_export_count = $total;
			$vh_export_noun  = _n( 'finding', 'findings', $total, 'vulnhub' );
		}
		?>
		<div class="vh-page-head">
			<div>
				<h1><?php esc_html_e( 'Vulnerabilities', 'vulnhub' ); ?></h1>
				<p class="vh-sub">
					<?php
					printf(
						/* translators: %s: number of findings. */
						esc_html( _n( '%s finding matches these filters.', '%s findings match these filters.', $total, 'vulnhub' ) ),
						'<strong>' . esc_html( number_format_i18n( $total ) ) . '</strong>'
					);
					?>
				</p>
			</div>
			<div class="vh-page-head__actions">
				<?php if ( 'vuln_assets' === $vh_tab ) : ?>
					<?php VulnHub_Dash_Export::link_button( 'vuln_assets', $args, '', $vh_export_count, $vh_export_noun ); ?>
				<?php elseif ( 'products' === $vh_tab ) : ?>
					<?php VulnHub_Dash_Export::link_button( 'product_remediation', $args, __( 'Export remediation CSV', 'vulnhub' ) ); ?>
				<?php else : ?>
					<?php VulnHub_Dash_Export::button( 'findings', $args, $vh_export_count, $vh_export_noun ); ?>
				<?php endif; ?>
				<?php if ( current_user_can( Caps::RAISE_TICKET ) ) : ?>
					<button type="button" class="vh-btn vh-btn--primary" data-vh-raise><?php esc_html_e( 'Raise ticket for selected', 'vulnhub' ); ?></button>
				<?php endif; ?>
			</div>
		</div>

		<div class="vh-tabs" role="tablist">
			<a class="vh-tabs__tab <?php echo 'findings' === $vh_tab ? 'is-active' : ''; ?>" href="<?php echo esc_url( $vh_find_url ); ?>"><?php esc_html_e( 'Findings', 'vulnhub' ); ?></a>
			<a class="vh-tabs__tab <?php echo 'products' === $vh_tab ? 'is-active' : ''; ?>" href="<?php echo esc_url( $vh_prod_url ); ?>"><?php esc_html_e( 'By product', 'vulnhub' ); ?></a>
			<a class="vh-tabs__tab <?php echo 'vuln_assets' === $vh_tab ? 'is-active' : ''; ?>" href="<?php echo esc_url( $vh_va_url ); ?>"><?php esc_html_e( 'Vulnerability on assets', 'vulnhub' ); ?></a>
		</div>

		<?php
		/*
		 * When the reader arrived from the patch chart, say so. A list that
		 * silently holds a filter nobody can see is how people end up
		 * reporting "the numbers are wrong".
		 */
		$vh_patch = self::q( 'patch_available' );
		?>
		<?php if ( '' !== $vh_vlife_bad ) : ?>
			<div class="vh-notice vh-notice--warn">
				<?php
				printf(
					/* translators: %s: the unrecognised value supplied in the URL. */
					esc_html__( '%s is not a lifecycle filter this page knows, so it has been ignored and the default reporting scope applied.', 'vulnhub' ),
					'<code>life=' . esc_html( $vh_vlife_bad ) . '</code>'
				);
				?>
			</div>
		<?php endif; ?>
		<?php
		/*
		 * Say which estate these findings belong to. A count with no scope
		 * beside it is the thing people re-derive by hand and disagree about.
		 */
		$vh_vscope_label = array(
			'reportable'     => __( 'assets the dashboard reports on', 'vulnhub' ),
			'in_service_all' => __( 'assets with an owner expectation', 'vulnhub' ),
			'all'            => __( 'every asset, retired ones included', 'vulnhub' ),
		);
		$vh_vscope_now   = '' === $vh_vlife ? 'reportable' : $vh_vlife;
		$vh_vscope_text  = $vh_vscope_label[ $vh_vscope_now ]
			?? sprintf(
				/* translators: %s: a lifecycle status label. */
				__( 'assets whose lifecycle status is "%s"', 'vulnhub' ),
				strtolower( (string) ( vh_lifecycle_statuses()[ $vh_vscope_now ]['label'] ?? $vh_vscope_now ) )
			);
		?>
		<p class="vh-sub vh-muted">
			<?php
			printf(
				/* translators: %s: description of the lifecycle scope in force. */
				esc_html__( 'Counting findings on %s.', 'vulnhub' ),
				esc_html( $vh_vscope_text )
			);
			?>
			<?php if ( 'all' !== $vh_vscope_now ) : ?>
				<a href="<?php echo esc_url( self::page_url( 'vulnerabilities', array_merge( self::current_filters( array( 'search', 'patch_available', 'ticketed', 'os_eol', 'severity', 'asset_type', 'team_id', 'age', 'overdue' ) ), array( 'life' => 'all' ) ) ) ); ?>">
					<?php esc_html_e( 'Include every asset', 'vulnhub' ); ?>
				</a>
			<?php endif; ?>
		</p>
		<?php
		/*
		 * A zone filter came from a widget tile, so say so. A list quietly
		 * holding a filter nobody can see is how people end up reporting that
		 * the numbers are wrong.
		 */
		$vh_zone     = self::q( 'zone' );
		$vh_platform = self::q( 'platform' );
		?>
		<?php if ( 'downloads' === $vh_zone ) : ?>
			<div class="vh-notice vh-notice--info">
				<?php
				if ( '' !== $vh_platform ) {
					printf(
						/* translators: %s: platform name, e.g. Windows. */
						esc_html__( 'Only findings whose vulnerable files sit in a user download folder, on %s machines.', 'vulnhub' ),
						esc_html( \VulnHub\Core\Os::platform_label( $vh_platform ) )
					);
				} else {
					esc_html_e( 'Only findings whose vulnerable files sit in a user download folder.', 'vulnhub' );
				}
				/*
				 * Spell the severity cut out. Tenable's forensic plugins list
				 * the contents of a download folder at severity info, so
				 * without this the reader cannot tell whether a much larger
				 * number is missing or was never exposure in the first place.
				 */
				if ( 'info' === self::q( 'sev_not' ) ) {
					echo ' ';
					esc_html_e( 'Informational file listings are excluded.', 'vulnhub' );
				} elseif ( 'info' === self::q( 'severity' ) ) {
					echo ' ';
					esc_html_e( 'These are Tenable\'s informational file listings, not vulnerabilities.', 'vulnhub' );
				}
				?>
				<a href="<?php echo esc_url( self::page_url( 'vulnerabilities', self::current_filters( array( 'search', 'severity', 'asset_type', 'team_id', 'age', 'overdue', 'life' ) ) ) ); ?>">
					<?php esc_html_e( 'Clear this filter', 'vulnhub' ); ?>
				</a>
			</div>
		<?php endif; ?>
		<?php $vh_prod = self::q( 'product' ); ?>
		<?php if ( '' !== $vh_prod ) : ?>
			<div class="vh-notice vh-notice--info">
				<?php
				printf(
					/* translators: %s: a product name/slug. */
					esc_html__( 'Showing findings attributed to %s.', 'vulnhub' ),
					'<strong>' . esc_html( $vh_prod ) . '</strong>'
				);
				?>
				<a href="<?php echo esc_url( remove_query_arg( 'product' ) ); ?>"><?php esc_html_e( 'Clear this filter', 'vulnhub' ); ?></a>
			</div>
		<?php endif; ?>
		<?php if ( '' !== $vh_patch ) : ?>
			<div class="vh-notice vh-notice--info">
				<?php
				echo esc_html(
					match ( true ) {
						'direct' === $vh_patch => __( 'Showing only findings with a vendor update for the vulnerable software itself.', 'vulnhub' ),
						'app' === $vh_patch    => __( 'Showing only findings in components shipped inside another application (such as a library in a driver folder). Tenable\'s fix is for the component; it arrives through an update to that application, if its vendor has shipped one.', 'vulnhub' ),
						'app_shipped' === $vh_patch => __( 'Showing components shipped inside another application where a fixed build has been seen in the estate (a fixed copy at the same path, or resolved on machines that kept the application): updating the application fixes these.', 'vulnhub' ),
						'app_waiting' === $vh_patch => __( 'Showing components shipped inside another application where no fixed build has been seen: the newest copy at that path is still vulnerable and nothing has been resolved. Updating will likely not help yet; remove the component, add a compensating control or record an exception.', 'vulnhub' ),
						'app_unknown' === $vh_patch => __( 'Showing components shipped inside another application where the estate gives no evidence either way.', 'vulnhub' ),
						in_array( $vh_patch, array( '1', 'yes', 'true' ), true ) => __( 'Showing findings with a fix: a direct vendor update, or an update to the application that ships the component.', 'vulnhub' ),
						default                => __( 'Showing only findings with no known fix. These cannot be patched; they need a compensating control, an exception or a decommission.', 'vulnhub' ),
					}
				);
				?>
				<a href="<?php echo esc_url( remove_query_arg( 'patch_available' ) ); ?>"><?php esc_html_e( 'Clear this filter', 'vulnhub' ); ?></a>
			</div>
		<?php endif; ?>
		<?php $vh_os_eol = self::q( 'os_eol' ); ?>
		<?php if ( in_array( $vh_os_eol, array( 'yes', 'no' ), true ) ) : ?>
			<div class="vh-notice vh-notice--info">
				<?php
				echo esc_html(
					'yes' === $vh_os_eol
						? __( 'Showing only findings on machines whose operating system is past vendor support. Add "Patch available" to see what can still be patched on them.', 'vulnhub' )
						: __( 'Showing only findings on machines whose operating system is still supported.', 'vulnhub' )
				);
				?>
				<a href="<?php echo esc_url( remove_query_arg( 'os_eol' ) ); ?>"><?php esc_html_e( 'Clear this filter', 'vulnhub' ); ?></a>
			</div>
		<?php endif; ?>
		<?php $vh_ticketed = self::q( 'ticketed' ); ?>
		<?php if ( in_array( $vh_ticketed, array( 'yes', 'no' ), true ) ) : ?>
			<div class="vh-notice vh-notice--info">
				<?php
				echo esc_html(
					'no' === $vh_ticketed
						? __( 'Showing only findings not yet on a ticket. Select them (or "Select all matching") and raise a ticket.', 'vulnhub' )
						: __( 'Showing only findings already on a ticket.', 'vulnhub' )
				);
				?>
				<a href="<?php echo esc_url( remove_query_arg( 'ticketed' ) ); ?>"><?php esc_html_e( 'Clear this filter', 'vulnhub' ); ?></a>
			</div>
		<?php endif; ?>
		<?php $vh_support = self::q( 'support' ); ?>
		<?php if ( in_array( $vh_support, array( 'eol', 'insupport' ), true ) ) : ?>
			<div class="vh-notice vh-notice--info">
				<?php
				echo esc_html(
					'eol' === $vh_support
						? __( 'Showing only end-of-life findings: a missing update for an operating system the vendor no longer supports, or a detection of software that is itself discontinued. There is no patch to apply — the fix is to upgrade or retire.', 'vulnhub' )
						: __( 'Showing only in-support findings: the operating system is still supported and the affected software is not discontinued, so a vendor fix exists or will.', 'vulnhub' )
				);
				?>
				<a href="<?php echo esc_url( remove_query_arg( 'support' ) ); ?>"><?php esc_html_e( 'Clear this filter', 'vulnhub' ); ?></a>
			</div>
		<?php endif; ?>

		<form class="vh-filters" method="get">
			<?php
			/*
			 * `product` is NOT listed here, and that is the point.
			 *
			 * This list means "the form has its own control for this, so do
			 * not also emit it as a hidden input". The product filter arrives
			 * from the exposure-by-product widget and has no select of its
			 * own -- only the banner above, with its Clear link. Listing it
			 * meant Apply silently dropped it, so narrowing libcurl down to
			 * servers threw the libcurl part away.
			 */
			self::hidden_filters(
				array( 'search', 'fix', 'excepted', 'patch_available', 'ticketed', 'os_eol', 'support', 'severity', 'asset_type', 'team_id', 'department', 'age', 'overdue', 'life' )
			);
			?>
			<label><?php esc_html_e( 'Search', 'vulnhub' ); ?>
				<input type="search" name="search" value="<?php echo esc_attr( self::q( 'search' ) ); ?>" placeholder="<?php esc_attr_e( 'CVE, host, owner, plugin…', 'vulnhub' ); ?>">
			</label>
			<label><?php esc_html_e( 'Action', 'vulnhub' ); ?>
				<select name="fix">
					<option value=""><?php esc_html_e( 'Any action', 'vulnhub' ); ?></option>
					<?php foreach ( VH_Action::classes() as $vh_ac => $vh_al ) : ?>
						<option value="<?php echo esc_attr( $vh_ac ); ?>" <?php selected( self::q( 'fix' ), $vh_ac ); ?>
							title="<?php echo esc_attr( VH_Action::description( $vh_ac ) ); ?>"><?php echo esc_html( $vh_al ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label><?php esc_html_e( 'Exceptions', 'vulnhub' ); ?>
				<select name="excepted">
					<option value=""><?php esc_html_e( 'Include accepted risk', 'vulnhub' ); ?></option>
					<option value="exclude" <?php selected( self::q( 'excepted' ), 'exclude' ); ?>><?php esc_html_e( 'Exclude accepted risk', 'vulnhub' ); ?></option>
					<option value="only" <?php selected( self::q( 'excepted' ), 'only' ); ?>><?php esc_html_e( 'Only accepted risk', 'vulnhub' ); ?></option>
				</select>
			</label>
			<label><?php esc_html_e( 'Patch', 'vulnhub' ); ?>
				<select name="patch_available">
					<option value=""><?php esc_html_e( 'Any', 'vulnhub' ); ?></option>
					<option value="direct" <?php selected( self::q( 'patch_available' ), 'direct' ); ?>><?php esc_html_e( 'Patch available', 'vulnhub' ); ?></option>
					<option value="app" <?php selected( self::q( 'patch_available' ), 'app' ); ?>><?php esc_html_e( 'Update the app that ships it', 'vulnhub' ); ?></option>
					<option value="app_shipped" <?php selected( self::q( 'patch_available' ), 'app_shipped' ); ?>><?php esc_html_e( '… and a fixed build has been seen', 'vulnhub' ); ?></option>
					<option value="app_waiting" <?php selected( self::q( 'patch_available' ), 'app_waiting' ); ?>><?php esc_html_e( '… but no fixed build seen yet', 'vulnhub' ); ?></option>
					<option value="app_unknown" <?php selected( self::q( 'patch_available' ), 'app_unknown' ); ?>><?php esc_html_e( '… not enough evidence', 'vulnhub' ); ?></option>
					<option value="1" <?php selected( self::q( 'patch_available' ), '1' ); ?>><?php esc_html_e( 'Any fix (either of the above)', 'vulnhub' ); ?></option>
					<option value="0" <?php selected( self::q( 'patch_available' ), '0' ); ?>><?php esc_html_e( 'No fix known', 'vulnhub' ); ?></option>
				</select>
			</label>
			<label><?php esc_html_e( 'Operating system', 'vulnhub' ); ?>
				<select name="os_eol">
					<option value=""><?php esc_html_e( 'Any OS', 'vulnhub' ); ?></option>
					<option value="yes" <?php selected( self::q( 'os_eol' ), 'yes' ); ?>><?php esc_html_e( 'End-of-life OS', 'vulnhub' ); ?></option>
					<option value="no" <?php selected( self::q( 'os_eol' ), 'no' ); ?>><?php esc_html_e( 'Supported OS', 'vulnhub' ); ?></option>
				</select>
			</label>
			<label><?php esc_html_e( 'Ticket', 'vulnhub' ); ?>
				<select name="ticketed">
					<option value=""><?php esc_html_e( 'Raised or not', 'vulnhub' ); ?></option>
					<option value="no" <?php selected( self::q( 'ticketed' ), 'no' ); ?>><?php esc_html_e( 'Not raised', 'vulnhub' ); ?></option>
					<option value="yes" <?php selected( self::q( 'ticketed' ), 'yes' ); ?>><?php esc_html_e( 'On a ticket', 'vulnhub' ); ?></option>
				</select>
			</label>
			<label><?php esc_html_e( 'Lifecycle support', 'vulnhub' ); ?>
				<select name="support">
					<option value=""><?php esc_html_e( 'EOL and in-support', 'vulnhub' ); ?></option>
					<option value="eol" <?php selected( self::q( 'support' ), 'eol' ); ?>><?php esc_html_e( 'End of life only', 'vulnhub' ); ?></option>
					<option value="insupport" <?php selected( self::q( 'support' ), 'insupport' ); ?>><?php esc_html_e( 'In support only', 'vulnhub' ); ?></option>
				</select>
			</label>
			<label><?php esc_html_e( 'Severity', 'vulnhub' ); ?>
				<select name="severity">
					<option value=""><?php esc_html_e( 'All severities', 'vulnhub' ); ?></option>
					<?php foreach ( VulnHub_Dash_Charts::severity_order() as $sev ) : ?>
						<option value="<?php echo esc_attr( $sev ); ?>" <?php selected( self::q( 'severity' ), $sev ); ?>><?php echo esc_html( vh_severity_label( $sev ) ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label><?php esc_html_e( 'Asset type', 'vulnhub' ); ?>
				<select name="asset_type">
					<option value=""><?php esc_html_e( 'All types', 'vulnhub' ); ?></option>
					<?php foreach ( vh_asset_types() as $k => $l ) : ?>
						<option value="<?php echo esc_attr( $k ); ?>" <?php selected( self::q( 'asset_type' ), $k ); ?>><?php echo esc_html( $l ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label><?php esc_html_e( 'Team', 'vulnhub' ); ?>
				<select name="team_id">
					<option value="0"><?php esc_html_e( 'All teams', 'vulnhub' ); ?></option>
					<?php foreach ( Repo::teams() as $t ) : ?>
						<option value="<?php echo esc_attr( (string) $t['id'] ); ?>" <?php selected( self::qi( 'team_id' ), (int) $t['id'] ); ?>><?php echo esc_html( (string) $t['name'] ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<?php if ( class_exists( 'VulnHub_Departments' ) ) : ?>
				<label><?php esc_html_e( 'Department', 'vulnhub' ); ?>
					<select name="department">
						<?php echo VulnHub_Departments::filter_options( self::q( 'department' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
					</select>
				</label>
			<?php endif; ?>
			<label><?php esc_html_e( 'Age', 'vulnhub' ); ?>
				<select name="age">
					<option value=""><?php esc_html_e( 'Any age', 'vulnhub' ); ?></option>
					<?php foreach ( Repo::age_bands() as $vh_band_key => $vh_band ) : ?>
						<option value="<?php echo esc_attr( (string) $vh_band_key ); ?>" <?php selected( self::q( 'age' ), (string) $vh_band_key ); ?>>
							<?php echo esc_html( (string) $vh_band['label'] ); ?>
						</option>
					<?php endforeach; ?>
				</select>
			</label>
			<label><?php esc_html_e( 'Lifecycle', 'vulnhub' ); ?>
				<select name="life">
					<option value=""><?php esc_html_e( 'Reporting scope (what the dashboard counts)', 'vulnhub' ); ?></option>
					<option value="in_service_all" <?php selected( self::q( 'life' ), 'in_service_all' ); ?>><?php esc_html_e( 'Everything with an owner expectation', 'vulnhub' ); ?></option>
					<option value="all" <?php selected( self::q( 'life' ), 'all' ); ?>><?php esc_html_e( 'Every asset, including retired', 'vulnhub' ); ?></option>
					<?php foreach ( vh_lifecycle_statuses() as $vh_ls => $vh_lm ) : ?>
						<option value="<?php echo esc_attr( $vh_ls ); ?>" <?php selected( self::q( 'life' ), $vh_ls ); ?>><?php echo esc_html( (string) $vh_lm['label'] ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label class="vh-check">
				<input type="checkbox" name="overdue" value="1" <?php checked( self::q( 'overdue' ), '1' ); ?>>
				<?php esc_html_e( 'Past SLA only', 'vulnhub' ); ?>
			</label>
			<button class="vh-btn"><?php esc_html_e( 'Apply', 'vulnhub' ); ?></button>
			<a class="vh-btn vh-btn--ghost" href="<?php echo esc_url( self::page_url( 'vulnerabilities' ) ); ?>"><?php esc_html_e( 'Reset', 'vulnhub' ); ?></a>
		</form>

		<?php if ( 'products' === $vh_tab ) : ?>
			<?php
			$vh_pargs = array_filter( $args, static fn( $v ): bool => '' !== $v && 0 !== $v );
			unset( $vh_pargs['offset'] );
			$vh_pargs['group'] = 'product';
			$vh_pargs['limit'] = 100;
			$vh_prows = (array) ( Repo::findings( $vh_pargs )['products'] ?? array() );
			?>
			<?php if ( ! $vh_prows ) : ?>
				<p class="vh-chart-empty"><?php esc_html_e( 'No classified products for these filters.', 'vulnhub' ); ?></p>
			<?php else : ?>
				<?php
				$vh_pmax = max( 1, (int) $vh_prows[0]['assets'] );
				$vh_pcar = self::current_filters( array(
					'search', 'patch_available', 'ticketed', 'os_eol', 'severity', 'asset_type', 'team_id', 'department',
					'age', 'overdue', 'life', 'zone', 'platform', 'sev_not', 'route', 'delivery',
					'poc', 'hosting', 'asset', 'state',
				) );
				?>
				<ul class="vh-prodlist vh-prodlist--exp">
					<?php foreach ( $vh_prows as $vh_pr ) : ?>
						<?php
						$vh_pa   = (int) $vh_pr['assets'];
						$vh_ppct = (int) round( 100 * $vh_pa / $vh_pmax );
						$vh_purl = self::page_url( 'vulnerabilities', array_merge( $vh_pcar, array( 'product' => (string) $vh_pr['product_slug'] ) ) );
						?>
						<li class="vh-prodrow">
							<details class="vh-prodrow__exp" data-vh-product="<?php echo esc_attr( (string) $vh_pr['product_slug'] ); ?>">
								<summary class="vh-prodrow__sum">
									<?php echo VulnHub_Dash_Widgets::product_icon( (string) $vh_pr['product_slug'], (string) $vh_pr['component_class'], (string) $vh_pr['product'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
									<div class="vh-prodrow__main">
										<div class="vh-prodrow__head">
											<a class="vh-prodrow__name" href="<?php echo esc_url( $vh_purl ); ?>"><?php echo esc_html( (string) $vh_pr['product'] ); ?></a>
											<?php echo VulnHub_Dash_Widgets::product_kind_badge( (string) $vh_pr['product_kind'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
											<span class="vh-prodrow__nums">
												<?php
												printf(
													/* translators: 1: asset count, 2: finding count. */
													esc_html__( '%1$s assets · %2$s findings', 'vulnhub' ),
													'<strong>' . esc_html( number_format_i18n( $vh_pa ) ) . '</strong>',
													esc_html( number_format_i18n( (int) $vh_pr['findings'] ) )
												);
												?>
											</span>
										</div>
										<div class="vh-prodrow__bar"><span style="width:<?php echo (int) $vh_ppct; ?>%"></span></div>
									</div>
								</summary>
								<div class="vh-prodrow__body" data-vh-product-assets data-vh-loaded="0">
									<p class="vh-sub vh-muted"><?php esc_html_e( 'Loading affected assets…', 'vulnhub' ); ?></p>
								</div>
							</details>
						</li>
					<?php endforeach; ?>
				</ul>
				<p class="vh-sub vh-muted"><?php esc_html_e( 'Expand a product to see the outdated assets one update would fix, and export the remediation list.', 'vulnhub' ); ?></p>
				<p class="vh-sub"><?php esc_html_e( 'Products behind the findings in this scope, ranked by assets affected. A bundled library is attributed to the app that ships it. Select a product to filter the findings list to it.', 'vulnhub' ); ?></p>
			<?php endif; ?>
		<?php elseif ( 'vuln_assets' === $vh_tab ) : ?>
			<?php
			/*
			 * One row per vulnerability, over exactly the filtered set the
			 * other two tabs show. Each row expands to the assets that vuln
			 * touches, fetched on first open from /vuln-assets so a page of
			 * 25 vulns does not pull thousands of asset rows nobody has asked
			 * to see yet. `total` here counts distinct vulnerabilities, so the
			 * pager pages vulns, not findings.
			 */
			$vh_vargs           = array_filter( $args, static fn( $v ): bool => '' !== $v && 0 !== $v );
			$vh_vargs['group']  = 'vuln';
			$vh_vargs['limit']  = $per;
			$vh_vargs['offset'] = ( $paged - 1 ) * $per;
			$vh_vres            = Repo::findings( $vh_vargs );
			$vh_vrows           = (array) ( $vh_vres['vulns'] ?? array() );
			$vh_vtotal          = (int) ( $vh_vres['total'] ?? 0 );
			$vh_vpages          = max( 1, (int) ceil( $vh_vtotal / $per ) );
			?>
			<?php echo VulnHub_Dash_Charts::severity_legend(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			<p class="vh-sub vh-muted">
				<?php
				printf(
					/* translators: %s: number of distinct vulnerabilities. */
					esc_html( _n( '%s vulnerability across these findings. Expand one to see the assets it affects.', '%s vulnerabilities across these findings. Expand one to see the assets it affects.', $vh_vtotal, 'vulnhub' ) ),
					'<strong>' . esc_html( number_format_i18n( $vh_vtotal ) ) . '</strong>'
				);
				?>
			</p>

			<?php if ( ! $vh_vrows ) : ?>
				<p class="vh-chart-empty"><?php esc_html_e( 'Nothing matches. Try widening the filters.', 'vulnhub' ); ?></p>
			<?php else : ?>
				<div class="vh-vulnlist">
					<?php foreach ( $vh_vrows as $vh_v ) : ?>
						<?php
						$vh_vcves  = vh_json( (string) ( $vh_v['cve_json'] ?? '' ) );
						$vh_vpatch = Repo::has_patch( $vh_v );
						$vh_va     = (int) $vh_v['assets'];
						?>
						<details class="vh-vulnrow" data-vh-vuln="<?php echo esc_attr( (string) $vh_v['vuln_id'] ); ?>">
							<summary class="vh-vulnrow__sum">
								<span class="vh-pill vh-pill--<?php echo esc_attr( (string) $vh_v['severity'] ); ?>"><?php echo esc_html( vh_severity_label( (string) $vh_v['severity'] ) ); ?></span>
								<span class="vh-vulnrow__main">
									<span class="vh-vulnrow__name"><?php echo esc_html( vh_trim( (string) $vh_v['title'], 90 ) ); ?></span>
									<span class="vh-meta">
										<?php echo esc_html( ( $vh_v['family'] ? $vh_v['family'] . ' · ' : '' ) . 'plugin ' . $vh_v['plugin_id'] ); ?>
										<?php if ( $vh_vcves ) : ?>· <?php echo esc_html( implode( ', ', array_slice( $vh_vcves, 0, 3 ) ) ); ?><?php endif; ?>
									</span>
								</span>
								<span class="vh-vulnrow__tags">
									<?php if ( ! empty( $vh_v['exploit_available'] ) ) : ?><span class="vh-flag"><?php esc_html_e( 'exploit', 'vulnhub' ); ?></span><?php endif; ?>
									<span class="vh-chip <?php echo $vh_vpatch ? 'vh-chip--good' : 'vh-chip--warn'; ?>"><?php echo esc_html( $vh_vpatch ? __( 'patch available', 'vulnhub' ) : __( 'no patch', 'vulnhub' ) ); ?></span>
								</span>
								<span class="vh-vulnrow__count">
									<strong><?php echo esc_html( number_format_i18n( $vh_va ) ); ?></strong>
									<?php echo esc_html( _n( 'asset', 'assets', $vh_va, 'vulnhub' ) ); ?>
								</span>
							</summary>
							<div class="vh-vulnrow__body" data-vh-vuln-assets data-vh-loaded="0">
								<p class="vh-sub vh-muted vh-vulnrow__loading"><?php esc_html_e( 'Loading affected assets…', 'vulnhub' ); ?></p>
							</div>
						</details>
					<?php endforeach; ?>
				</div>
				<?php self::pager( $paged, $vh_vpages, 'vp' ); ?>
			<?php endif; ?>
		<?php else : ?>
		<?php echo VulnHub_Dash_Charts::severity_legend(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>

		<?php if ( ! $q['rows'] ) : ?>
			<p class="vh-chart-empty"><?php esc_html_e( 'Nothing matches. Try widening the filters.', 'vulnhub' ); ?></p>
		<?php else : ?>
			<?php
			/*
			 * Selection bar. Ticking the header box selects the rows on the
			 * page; when the filter matches more than one page it then offers
			 * to select every matching finding, and the count and the export
			 * follow whichever the reader chose. Hidden until something is
			 * selected, and inert without JavaScript -- the checkboxes and the
			 * always-present Export button still work on their own.
			 */
			?>
			<div class="vh-selbar" data-vh-selbar data-vh-total="<?php echo esc_attr( (string) $total ); ?>" hidden>
				<strong class="vh-selbar__count" data-vh-selcount aria-live="polite"></strong>
				<button type="button" class="vh-linkbtn vh-selbar__all" data-vh-selall hidden></button>
				<span class="vh-selbar__sp"></span>
				<button type="button" class="vh-btn vh-btn--sm vh-btn--primary" data-vh-selexport><?php esc_html_e( 'Export selected', 'vulnhub' ); ?></button>
				<button type="button" class="vh-linkbtn" data-vh-selclear><?php esc_html_e( 'Clear', 'vulnhub' ); ?></button>
			</div>
			<div class="vh-tablewrap vh-tablewrap--cards">
				<table class="vh-table">
					<thead>
						<tr>
							<th class="vh-col-check"><input type="checkbox" data-vh-all aria-label="<?php esc_attr_e( 'Select all', 'vulnhub' ); ?>"></th>
							<?php
							self::sort_th( 'severity', __( 'Severity', 'vulnhub' ), $orderby, $order );
							self::sort_th( 'title', __( 'Vulnerability', 'vulnhub' ), $orderby, $order );
							self::sort_th( 'hostname', __( 'Asset', 'vulnhub' ), $orderby, $order );
							?>
							<?php if ( self::show_reach() ) : ?>
								<th><?php esc_html_e( 'Reachable via', 'vulnhub' ); ?></th>
							<?php endif; ?>
							<th><?php esc_html_e( 'Location', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'File path', 'vulnhub' ); ?></th>
							<th>
								<?php esc_html_e( 'Owner', 'vulnhub' ); ?>
								<button type="button" class="vh-eye" data-vh-owner-toggle aria-pressed="false"
									title="<?php esc_attr_e( 'Show owner names', 'vulnhub' ); ?>"
									aria-label="<?php esc_attr_e( 'Show owner names', 'vulnhub' ); ?>">
									<svg class="vh-eye__on" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>
									<svg class="vh-eye__off" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 3l18 18M10.6 10.6a3 3 0 004.2 4.2M9.9 5.1A9.9 9.9 0 0112 5c6.5 0 10 7 10 7a13.3 13.3 0 01-2.2 2.8M6.3 6.3A13.3 13.3 0 002 12s3.5 7 10 7a9.8 9.8 0 003.6-.7"/></svg>
								</button>
							</th>
							<?php self::sort_th( 'due_at', __( 'Due', 'vulnhub' ), $orderby, $order ); ?>
							<th><?php esc_html_e( 'Ticket', 'vulnhub' ); ?></th>
							<th></th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $q['rows'] as $f ) : ?>
						<?php echo self::finding_row_html( $f ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
					<?php endforeach; ?>
					<?php
					/*
					 * Inside the tbody, not after the closing </div>.
					 *
					 * A <tr> outside a table is not invalid markup that
					 * degrades -- the HTML parser throws it away, so the
					 * sentinel never reached the DOM, the observer never
					 * attached, and infinite scroll on this table had simply
					 * never run. Nothing looked broken because the classic
					 * pager is still rendered underneath and quietly did the
					 * job. It also has to sit in the tbody rather than merely
					 * inside the table, because the loader inserts each new
					 * page with insertAdjacentHTML('beforebegin') and those
					 * rows have to land among the others.
					 */
					?>
					<tr class="vh-sentinel" id="vh-findings-sentinel" data-vh-infinite="findings" data-offset="<?php echo esc_attr( (string) ( $paged * $per ) ); ?>" data-total="<?php echo esc_attr( (string) $total ); ?>" data-per="<?php echo esc_attr( (string) $per ); ?>" aria-hidden="true"><td colspan="<?php echo esc_attr( (string) ( self::show_reach() ? 11 : 10 ) ); ?>"></td></tr>
					</tbody>
				</table>
			</div>
			<?php self::pager( $paged, $pages, 'vp' ); ?>
		<?php endif; ?>
		<?php endif; /* tab */ ?>
		<?php
	}

	/**
	 * Render one findings-table row. Shared by the server-rendered first
	 * page and the /findings-more REST fragment used for infinite scroll,
	 * so there is exactly one place that knows this markup (including the
	 * capability-gated action buttons, which only PHP can decide).
	 *
	 * @param array<string,mixed> $f One row from Repo::findings().
	 * @return string
	 */

	/**
	 * Render one assets-table row. Shared by the server-rendered first
	 * page and the /assets-more REST fragment used for infinite scroll.
	 *
	 * @param array<string,mixed> $a           One row from Repo::assets().
	 * @param bool                $vh_can_edit Whether to render the bulk-select checkbox column.
	 * @return string
	 */
	/**
	 * The assets filter args view_assets() builds from $_GET, minus
	 * limit/offset -- shared with the /assets-more REST fragment.
	 *
	 * @param array<string,string> $vh_scope  Lifecycle scope flags.
	 * @param array<string,string> $vh_source Source-filter flags.
	 * @param string               $orderby   Orderby column.
	 * @param string               $order     'ASC' or 'DESC'.
	 * @return array<string,mixed>
	 */
	public static function assets_base_args( array $vh_scope, array $vh_source, string $orderby, string $order ): array {
		return array(
			'lifecycle_status'    => $vh_scope['lifecycle_status'],
			'in_service_only'     => $vh_scope['in_service_only'],
			'out_of_service_only' => $vh_scope['out_of_service_only'],
			'reportable_only'     => $vh_scope['reportable_only'],
			'not_reportable_only' => $vh_scope['not_reportable_only'],
			'source'           => $vh_source['source'],
			'without_source'   => $vh_source['without_source'],
			'sole_source'      => $vh_source['sole_source'],
			'search'           => self::q( 'search' ),
			'asset_type'       => self::q( 'asset_type' ),
			'team_id'          => self::qi( 'team_id' ),
			'needs_user'       => self::q( 'needs_user' ),
			'coverage'         => self::q( 'coverage' ),
			'defender'         => self::q( 'defender' ),
			'location_id'      => self::q( 'location_id' ),
			'primary_source'   => self::q( 'primary_source' ),
			'operating_system' => self::q( 'operating_system' ),
			'patch_group'      => self::q( 'patch_group' ),
			'eol'              => self::q( 'eol' ),
			/*
			 * Answered by vulnhub-hosting through `vulnhub_assets_query`; core
			 * neither knows nor needs to know what a hosting environment is.
			 */
			'hosting'          => self::q( 'hosting' ),
			/*
			 * Inventory comparison, as the source-gap screen links it:
			 * `has=tenable&missing=cmdb` is "Tenable scans it, the register has
			 * never heard of it". Comma-separated, and passed through as typed
			 * -- Repo sanitises each slug.
			 */
			'has'              => self::q( 'has' ),
			'missing'          => self::q( 'missing' ),
			'orderby'          => $orderby,
			'order'            => $order,
		);
	}

	/**
	 * Validate the assets list's orderby/order/lifecycle/known-source
	 * scope from $_GET, exactly as view_assets() does, for the
	 * /assets-more REST fragment to reuse.
	 *
	 * @return array{orderby:string,order:string,scope:array<string,string>,source:array<string,string>}
	 */
	public static function assets_validated_scope(): array {
		$orderby = self::q( 'orderby' ) ?: 'risk_score';
		$order   = 'ASC' === strtoupper( self::q( 'order' ) ) ? 'ASC' : 'DESC';

		$vh_known  = self::q( 'known' );
		$vh_source = array( 'source' => '', 'without_source' => '', 'sole_source' => '' );

		if ( str_starts_with( $vh_known, 'only:' ) ) {
			$vh_source['source']      = substr( $vh_known, 5 );
			$vh_source['sole_source'] = '1';
		} elseif ( str_starts_with( $vh_known, 'not:' ) ) {
			$vh_source['without_source'] = substr( $vh_known, 4 );
		} elseif ( '' !== $vh_known ) {
			$vh_source['source'] = $vh_known;
		}

		$vh_life    = self::q( 'life' );
		$vh_life_ok = array_merge(
			array( 'reportable', 'in_service_all', 'not_reported', 'retired_all', 'all' ),
			array_keys( vh_lifecycle_statuses() )
		);

		if ( '' !== $vh_life && ! in_array( $vh_life, $vh_life_ok, true ) ) {
			$vh_life = '';
		}

		$vh_scope = array(
			'lifecycle_status'    => '',
			'in_service_only'     => '',
			'out_of_service_only' => '',
			'reportable_only'     => '',
			'not_reportable_only' => '',
		);

		if ( '' === $vh_life || 'reportable' === $vh_life ) {
			$vh_scope['reportable_only'] = '1';
		} elseif ( 'in_service_all' === $vh_life ) {
			$vh_scope['in_service_only'] = '1';
		} elseif ( 'not_reported' === $vh_life ) {
			$vh_scope['not_reportable_only'] = '1';
		} elseif ( 'retired_all' === $vh_life ) {
			$vh_scope['out_of_service_only'] = '1';
		} elseif ( 'all' !== $vh_life ) {
			$vh_scope['lifecycle_status'] = $vh_life;
		}

		return array(
			'orderby' => $orderby,
			'order'   => $order,
			'scope'   => $vh_scope,
			'source'  => $vh_source,
		);
	}

	public static function asset_row_html( array $a, bool $vh_can_edit ): string {
		ob_start();
		?>
				<?php
				$owner = Repo::person( (int) $a['owner_person_id'] );
				$team  = Repo::team( (int) $a['team_id'] );
				$needs = in_array( (string) $a['asset_type'], vh_user_bound_asset_types(), true );
				$counts = array(
					'critical' => (int) $a['open_critical'],
					'high'     => (int) $a['open_high'],
					'medium'   => (int) $a['open_medium'],
					'low'      => (int) $a['open_low'],
				);
				$sum = array_sum( $counts );
				?>
				<?php $vh_in_svc = in_array( (string) $a['lifecycle_status'], vh_in_service_statuses(), true ); ?>
				<tr<?php echo $vh_in_svc ? '' : ' class="vh-row--retired"'; ?>>
					<?php if ( $vh_can_edit ) : ?>
						<td class="vh-tick">
							<input type="checkbox" name="assets[]" value="<?php echo esc_attr( (string) (int) $a['id'] ); ?>" data-vh-tick
								aria-label="<?php echo esc_attr( sprintf( /* translators: %s: hostname. */ __( 'Select %s', 'vulnhub' ), (string) $a['hostname'] ) ); ?>">
						</td>
					<?php endif; ?>
					<td data-th="<?php esc_attr_e( 'Host', 'vulnhub' ); ?>"><?php
						/**
						 * A mark before the hostname: something true of the machine
						 * that deserves a glance rather than a column of its own.
						 * vulnhub-hosting answers with where the server runs.
						 *
						 * Must return escaped HTML, and must stay small -- this is
						 * the densest cell on the busiest screen.
						 *
						 * @param string              $html Markup, '' by default.
						 * @param array<string,mixed> $a    The asset row.
						 */
						echo apply_filters( 'vulnhub_asset_hostname_mark', '', $a ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- filtered markup is escaped by its producer.
					?><a class="vh-mono" href="<?php echo esc_url( self::page_url( 'assets', array( 'asset' => (int) $a['id'] ) ) ); ?>"><strong><?php echo esc_html( (string) $a['hostname'] ); ?></strong></a>
						<?php if ( ! $vh_in_svc ) : ?>
							<span class="vh-chip vh-chip--warn"><?php echo esc_html( (string) ( vh_lifecycle_statuses()[ (string) $a['lifecycle_status'] ]['label'] ?? $a['lifecycle_status'] ) ); ?></span>
						<?php endif; ?>
						<span class="vh-meta"><?php echo esc_html( (string) $a['ipv4'] ); ?></span></td>
					<td data-th="<?php esc_attr_e( 'Scan coverage', 'vulnhub' ); ?>">
						<?php $vh_cov = (string) ( $a['coverage_state'] ?? '' ); ?>
						<?php if ( $vh_cov ) : ?>
							<span class="vh-chip vh-chip--<?php echo esc_attr( Coverage::tone( $vh_cov ) ); ?>"><?php echo esc_html( Coverage::label( $vh_cov ) ); ?></span>
							<?php if ( ! empty( $a['tenable_last_scan'] ) ) : ?>
								<span class="vh-meta"><?php echo esc_html( vh_ago( (string) $a['tenable_last_scan'] ) ); ?></span>
							<?php endif; ?>
						<?php else : ?>
							<span class="vh-muted">—</span>
						<?php endif; ?>
					</td>
					<td data-th="<?php esc_attr_e( 'EDR coverage', 'vulnhub' ); ?>">
						<?php
						/*
						 * Defender's answer, not Tenable's. `unknown` is
						 * the pre-migration default rather than a state
						 * anybody set, so it shows as no answer instead
						 * of as a finding -- claiming "unknown" for rows
						 * the recalculation has never touched would put
						 * a number on the dashboard that means nothing.
						 */
						$vh_edr = (string) ( $a['defender_coverage_state'] ?? '' );
						?>
						<?php if ( '' !== $vh_edr && 'unknown' !== $vh_edr ) : ?>
							<span class="vh-chip vh-chip--<?php echo esc_attr( Defender_Coverage::tone( $vh_edr ) ); ?>"><?php echo esc_html( Defender_Coverage::label( $vh_edr ) ); ?></span>
							<?php if ( ! empty( $a['defender_last_seen'] ) ) : ?>
								<span class="vh-meta"><?php echo esc_html( vh_ago( (string) $a['defender_last_seen'] ) ); ?></span>
							<?php endif; ?>
						<?php else : ?>
							<span class="vh-muted">—</span>
						<?php endif; ?>
					</td>
					<td data-th="<?php esc_attr_e( 'Known by', 'vulnhub' ); ?>"><?php echo self::source_chips( (string) ( $a['sources_json'] ?? '' ), true, self::known_focus() ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></td>
					<td data-th="<?php esc_attr_e( 'Type', 'vulnhub' ); ?>"><?php echo esc_html( vh_asset_types()[ (string) $a['asset_type'] ] ?? '' ); ?></td>
					<td data-th="<?php esc_attr_e( 'Operating system', 'vulnhub' ); ?>"><?php
						echo $a['operating_system']
							? \VulnHub\Core\Os::badge( (string) $a['operating_system'], true, (string) ( $a['os_version'] ?? '' ), (string) $a['asset_type'] ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
							: '<span class="vh-muted">—</span>';
					?></td>
					<td data-th="<?php esc_attr_e( 'Owner', 'vulnhub' ); ?>">
						<?php if ( $owner ) : ?>
							<?php echo self::owner_mask_html( (string) $owner['display_name'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
						<?php elseif ( $needs ) : ?>
							<span class="vh-chip vh-chip--warn"><?php esc_html_e( 'Missing', 'vulnhub' ); ?></span>
						<?php else : ?>—<?php endif; ?>
					</td>
					<td data-th="<?php esc_attr_e( 'Team', 'vulnhub' ); ?>"><?php echo esc_html( (string) ( $team['name'] ?? '—' ) ); ?></td>
					<td data-th="<?php esc_attr_e( 'Open exposure', 'vulnhub' ); ?>">
						<?php if ( $sum > 0 ) : ?>
							<span class="vh-minibar" role="img" aria-label="<?php echo esc_attr( sprintf( 'Critical %d, high %d, medium %d, low %d', $counts['critical'], $counts['high'], $counts['medium'], $counts['low'] ) ); ?>">
								<?php foreach ( VulnHub_Dash_Charts::severity_order() as $sev ) : ?>
									<?php if ( ! empty( $counts[ $sev ] ) ) : ?>
										<span style="flex:<?php echo esc_attr( (string) $counts[ $sev ] ); ?>;background:<?php echo esc_attr( VulnHub_Dash_Charts::severity_var( $sev ) ); ?>"></span>
									<?php endif; ?>
								<?php endforeach; ?>
							</span>
							<span class="vh-meta"><?php echo esc_html( sprintf( '%d / %d / %d / %d', $counts['critical'], $counts['high'], $counts['medium'], $counts['low'] ) ); ?></span>
						<?php else : ?>
							<span class="vh-sub"><?php esc_html_e( 'clean', 'vulnhub' ); ?></span>
						<?php endif; ?>
					</td>
				</tr>
		<?php
		return (string) ob_get_clean();
	}

	/**
	 * The findings filter args view_vulnerabilities() builds from $_GET,
	 * minus limit/offset -- shared with the /findings-more REST fragment
	 * (a real GET request, so $_GET is populated identically there) so
	 * infinite-scroll pages can never drift from the filters the visible
	 * first page was rendered with.
	 *
	 * @param string $orderby  Validated orderby column.
	 * @param string $order    'ASC' or 'DESC'.
	 * @param string $vh_vlife Validated lifecycle scope ('' = default).
	 * @return array<string,mixed>
	 */
	/**
	 * The affected-assets table for one vulnerability, honouring the
	 * vulnerability list's own filters ($_GET). Rendered server-side and
	 * handed to the "Vulnerability on assets" tab's expandable rows through
	 * the /vuln-assets REST route, so this markup lives in one place and the
	 * asset list under a vuln can never show a machine the filters above it
	 * excluded. Capped so one very common vuln cannot return thousands of
	 * rows into a row nobody has scrolled to; the full list is one click away.
	 *
	 * @param int $vuln_id The vulnerability.
	 * @return string
	 */
	public static function vuln_assets_fragment( int $vuln_id ): string {
		if ( $vuln_id <= 0 ) {
			return '';
		}

		$scope = self::findings_validated_scope();
		$args  = self::findings_base_args( $scope['orderby'], $scope['order'], $scope['lifecycle'] );

		$args['vuln_id'] = $vuln_id;
		$args['limit']   = 100;
		$args['offset']  = 0;

		$q     = Repo::findings( array_filter( $args, static fn( $v ): bool => '' !== $v && 0 !== $v ) );
		$rows  = (array) ( $q['rows'] ?? array() );
		$total = (int) ( $q['total'] ?? 0 );

		if ( ! $rows ) {
			return '<p class="vh-ok-note">' . esc_html__( 'No assets match the current filters for this vulnerability.', 'vulnhub' ) . '</p>';
		}

		ob_start();
		?>
		<div class="vh-tablewrap">
			<table class="vh-table vh-table--sub">
				<thead><tr>
					<th><?php esc_html_e( 'Asset', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Type', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Operating system', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Support', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Owner', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Location', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Install path', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'State', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Due', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Ticket', 'vulnhub' ); ?></th>
				</tr></thead>
				<tbody>
				<?php foreach ( $rows as $f ) : ?>
					<?php
					$overdue = ! empty( $f['due_at'] ) && strtotime( (string) $f['due_at'] . ' UTC' ) < time();
					$is_eol  = \VulnHub\Core\Eol::finding_is_eol( (int) $f['asset_id'], (int) $f['vuln_id'], (string) ( $f['component_class'] ?? '' ) );
					$path    = VH_Product::install_path( (string) ( $f['output'] ?? '' ) );
					?>
					<tr>
						<td>
							<a class="vh-mono" href="<?php echo esc_url( self::page_url( 'assets', array( 'asset' => (int) $f['asset_id'] ) ) ); ?>"><strong><?php echo esc_html( (string) $f['hostname'] ); ?></strong></a>
							<span class="vh-meta"><?php echo esc_html( (string) $f['ipv4'] ); ?></span>
						</td>
						<td><?php echo esc_html( vh_asset_types()[ (string) $f['asset_type'] ] ?? '' ); ?></td>
						<td><span class="vh-meta"><?php echo esc_html( vh_trim( (string) $f['operating_system'], 42 ) ); ?></span></td>
						<td>
							<?php if ( $is_eol ) : ?>
								<span class="vh-chip vh-chip--bad"><?php esc_html_e( 'End of life', 'vulnhub' ); ?></span>
							<?php else : ?>
								<span class="vh-meta"><?php esc_html_e( 'In support', 'vulnhub' ); ?></span>
							<?php endif; ?>
						</td>
						<td>
							<?php if ( ! empty( $f['owner_name'] ) ) : ?>
								<?php echo self::owner_mask_html( (string) $f['owner_name'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
								<span class="vh-meta"><?php echo esc_html( (string) ( $f['team_name'] ?: '' ) ); ?></span>
							<?php elseif ( ! empty( $f['team_name'] ) ) : ?>
								<?php echo esc_html( (string) $f['team_name'] ); ?>
							<?php else : ?>
								<span class="vh-chip vh-chip--warn"><?php esc_html_e( 'Unassigned', 'vulnhub' ); ?></span>
							<?php endif; ?>
						</td>
						<td><span class="vh-meta"><?php echo esc_html( (string) ( $f['location_name'] ?: '—' ) ); ?></span></td>
						<td>
							<?php if ( '' !== $path ) : ?>
								<code class="vh-path" title="<?php echo esc_attr( $path ); ?>"><?php echo esc_html( $path ); ?></code>
							<?php else : ?>
								<span class="vh-meta">—</span>
							<?php endif; ?>
						</td>
						<td><?php echo esc_html( ucfirst( (string) $f['state'] ) ); ?></td>
						<td class="<?php echo $overdue ? 'vh-overdue' : ''; ?>"><?php echo esc_html( $f['due_at'] ? vh_ago( (string) $f['due_at'] ) : '—' ); ?></td>
						<td>
							<?php if ( ! empty( $f['ticket_key'] ) ) : ?>
								<a class="vh-mono" href="<?php echo esc_url( (string) $f['ticket_url'] ); ?>" target="_blank" rel="noopener noreferrer"><?php echo esc_html( (string) $f['ticket_key'] ); ?></a>
							<?php else : ?>—<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php if ( $total > count( $rows ) ) : ?>
			<p class="vh-sub vh-muted">
				<?php
				printf(
					/* translators: 1: shown count, 2: total count. */
					esc_html__( 'Showing %1$s of %2$s affected assets.', 'vulnhub' ),
					esc_html( number_format_i18n( count( $rows ) ) ),
					esc_html( number_format_i18n( $total ) )
				);
				?>
				<a href="<?php echo esc_url( self::page_url( 'vulnerabilities', array( 'vuln' => $vuln_id ) ) ); ?>"><?php esc_html_e( 'Open the full list', 'vulnhub' ); ?></a>
			</p>
		<?php endif; ?>
		<?php
		return (string) ob_get_clean();
	}

	/**
	 * Aggregate the open findings for one product into a single remediation
	 * picture: the version to update to, the vulnerabilities that one update
	 * closes, and the outdated assets. Shared by the "By product" expand and
	 * its CSV export so the two can never disagree.
	 *
	 * @param string $slug   Product slug (the effective slug the list groups on).
	 * @param array<string,mixed> $args Filter args (already includes product_slug).
	 * @return array{product:string,target:string,vulns:int,cves:int,assets:array<int,array<string,mixed>>,cve_list:array<int,string>,max_severity:string,exploit:bool,patchable:bool}
	 */
	public static function product_remediation( string $slug, array $args ): array {
		$args['product_slug'] = $slug;
		$args['state']        = 'open_any';
		$args['limit']        = 2000;
		$args['offset']       = 0;

		$q    = Repo::findings( array_filter( $args, static fn( $v ): bool => '' !== $v && 0 !== $v ) );
		$rows = (array) ( $q['rows'] ?? array() );

		$order   = VulnHub_Dash_Charts::severity_order(); // critical..info
		$rank    = array_flip( $order );
		$assets  = array();
		$vulns   = array();
		$cves    = array();
		$texts   = array();
		$product = '';
		$maxsev  = 'info';
		$exploit = false;
		$patch   = false;

		foreach ( $rows as $f ) {
			$aid = (int) $f['asset_id'];

			if ( ! isset( $assets[ $aid ] ) ) {
				$assets[ $aid ] = array(
					'asset_id'   => $aid,
					'hostname'   => (string) ( $f['hostname'] ?: $f['fqdn'] ),
					'ipv4'       => (string) $f['ipv4'],
					'asset_type' => (string) $f['asset_type'],
					'os'         => (string) $f['operating_system'],
					'owner_name' => (string) ( $f['owner_name'] ?? '' ),
					'team_name'  => (string) ( $f['team_name'] ?? '' ),
					'location'   => (string) ( $f['location_name'] ?? '' ),
					'due_at'     => (string) ( $f['due_at'] ?? '' ),
					'ticket_key' => (string) ( $f['ticket_key'] ?? '' ),
					'ticket_url' => (string) ( $f['ticket_url'] ?? '' ),
					'findings'   => 0,
				);
			}

			++$assets[ $aid ]['findings'];

			// Keep the earliest due date across the product's findings.
			$due = (string) ( $f['due_at'] ?? '' );
			if ( '' !== $due && ( '' === $assets[ $aid ]['due_at'] || $due < $assets[ $aid ]['due_at'] ) ) {
				$assets[ $aid ]['due_at'] = $due;
			}

			$vulns[ (int) $f['vuln_id'] ] = true;
			foreach ( vh_json( (string) ( $f['cve_json'] ?? '' ) ) as $cve ) {
				$cves[ (string) $cve ] = true;
			}
			$texts[ (string) $f['vuln_title'] ] = true;
			if ( '' !== trim( (string) ( $f['solution'] ?? '' ) ) ) {
				$texts[ (string) $f['solution'] ] = true;
			}

			$product = (string) ( $f['product'] ?: $product );
			$sev     = (string) $f['severity'];
			if ( isset( $rank[ $sev ] ) && $rank[ $sev ] < ( $rank[ $maxsev ] ?? 99 ) ) {
				$maxsev = $sev;
			}
			if ( ! empty( $f['exploit_available'] ) ) {
				$exploit = true;
			}
			if ( Repo::has_patch( $f ) ) {
				$patch = true;
			}
		}

		return array(
			'product'      => $product,
			'target'       => VH_Product::latest_fixed_version( array_keys( $texts ) ),
			'vulns'        => count( $vulns ),
			'cves'         => count( $cves ),
			'assets'       => array_values( $assets ),
			'cve_list'     => array_keys( $cves ),
			'max_severity' => $maxsev,
			'exploit'      => $exploit,
			'patchable'    => $patch,
		);
	}

	/**
	 * The expandable body under a product row: one remediation line and the
	 * outdated assets it covers. Lazy-loaded, honouring the list's filters.
	 *
	 * @param string $slug Product slug.
	 * @return string
	 */
	public static function product_assets_fragment( string $slug ): string {
		if ( '' === $slug ) {
			return '';
		}

		$scope = self::findings_validated_scope();
		$args  = self::findings_base_args( $scope['orderby'], $scope['order'], $scope['lifecycle'] );
		$rem   = self::product_remediation( $slug, $args );

		if ( ! $rem['assets'] ) {
			return '<p class="vh-ok-note">' . esc_html__( 'No outdated assets for this product under the current filters.', 'vulnhub' ) . '</p>';
		}

		ob_start();
		?>
		<div class="vh-remediate">
			<span class="vh-remediate__do">
				<?php
				if ( '' !== $rem['target'] ) {
					printf(
						/* translators: 1: product, 2: version. */
						esc_html__( 'Update %1$s to %2$s or later', 'vulnhub' ),
						'<strong>' . esc_html( $rem['product'] ) . '</strong>',
						'<strong>' . esc_html( $rem['target'] ) . '</strong>'
					);
				} else {
					printf(
						/* translators: %s: product. */
						esc_html__( 'Update %s to the latest release', 'vulnhub' ),
						'<strong>' . esc_html( $rem['product'] ) . '</strong>'
					);
				}
				?>
			</span>
			<span class="vh-remediate__why">
				<?php
				printf(
					/* translators: 1: vulnerability count, 2: CVE count, 3: asset count. */
					esc_html__( 'clears %1$s vulnerabilities (%2$s CVEs) on %3$s outdated assets', 'vulnhub' ),
					'<strong>' . esc_html( number_format_i18n( $rem['vulns'] ) ) . '</strong>',
					esc_html( number_format_i18n( $rem['cves'] ) ),
					'<strong>' . esc_html( number_format_i18n( count( $rem['assets'] ) ) ) . '</strong>'
				);
				?>
				<?php if ( $rem['exploit'] ) : ?><span class="vh-flag"><?php esc_html_e( 'exploit available', 'vulnhub' ); ?></span><?php endif; ?>
			</span>
		</div>
		<div class="vh-tablewrap">
			<table class="vh-table vh-table--sub">
				<thead><tr>
					<th><?php esc_html_e( 'Asset', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Type', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Operating system', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Owner', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Location', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Vulns', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Due', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Ticket', 'vulnhub' ); ?></th>
				</tr></thead>
				<tbody>
				<?php foreach ( $rem['assets'] as $a ) : ?>
					<?php $overdue = ! empty( $a['due_at'] ) && strtotime( (string) $a['due_at'] . ' UTC' ) < time(); ?>
					<tr>
						<td>
							<a class="vh-mono" href="<?php echo esc_url( self::page_url( 'assets', array( 'asset' => (int) $a['asset_id'] ) ) ); ?>"><strong><?php echo esc_html( (string) $a['hostname'] ); ?></strong></a>
							<span class="vh-meta"><?php echo esc_html( (string) $a['ipv4'] ); ?></span>
						</td>
						<td><?php echo esc_html( vh_asset_types()[ (string) $a['asset_type'] ] ?? '' ); ?></td>
						<td><span class="vh-meta"><?php echo esc_html( vh_trim( (string) $a['os'], 42 ) ); ?></span></td>
						<td>
							<?php if ( '' !== $a['owner_name'] ) : ?>
								<?php echo self::owner_mask_html( (string) $a['owner_name'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
								<span class="vh-meta"><?php echo esc_html( (string) $a['team_name'] ); ?></span>
							<?php elseif ( '' !== $a['team_name'] ) : ?>
								<?php echo esc_html( (string) $a['team_name'] ); ?>
							<?php else : ?>
								<span class="vh-chip vh-chip--warn"><?php esc_html_e( 'Unassigned', 'vulnhub' ); ?></span>
							<?php endif; ?>
						</td>
						<td><span class="vh-meta"><?php echo esc_html( (string) ( $a['location'] ?: '—' ) ); ?></span></td>
						<td><?php echo esc_html( number_format_i18n( (int) $a['findings'] ) ); ?></td>
						<td class="<?php echo $overdue ? 'vh-overdue' : ''; ?>"><?php echo esc_html( $a['due_at'] ? vh_ago( (string) $a['due_at'] ) : '—' ); ?></td>
						<td>
							<?php if ( '' !== $a['ticket_key'] ) : ?>
								<a class="vh-mono" href="<?php echo esc_url( (string) $a['ticket_url'] ); ?>" target="_blank" rel="noopener noreferrer"><?php echo esc_html( (string) $a['ticket_key'] ); ?></a>
							<?php else : ?>—<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php
		return (string) ob_get_clean();
	}

	public static function findings_base_args( string $orderby, string $order, string $vh_vlife ): array {
		return array(
			'state'      => self::q( 'state', 'open_any' ),
			'lifecycle'  => '' === $vh_vlife ? 'reportable' : $vh_vlife,
			'product_slug' => self::q( 'product' ),
			'severity'   => self::q( 'severity' ),
			'age'        => self::q( 'age' ),
			'route'      => self::q( 'route' ),
			'delivery'   => self::q( 'delivery' ),
			'poc'        => self::q( 'poc' ),
			'asset_type' => self::q( 'asset_type' ),
			'team_id'    => self::qi( 'team_id' ),
			'asset_id'   => self::qi( 'asset' ),
			'department' => self::q( 'department' ),
			'hosting'    => self::q( 'hosting' ),
			'search'     => self::q( 'search' ),
			'overdue'    => self::q( 'overdue' ),
			'patch_available' => self::q( 'patch_available' ),
			// On a ticket or not: `ticketed` on the wire (yes|no), because
			// `ticket` already names the ticket page's own parameter.
			// The host's operating system: `os_eol` = yes|no on the wire.
			'os_support' => match ( self::q( 'os_eol' ) ) {
				'yes'   => 'eol',
				'no'    => 'supported',
				default => '',
			},
			'has_ticket' => match ( self::q( 'ticketed' ) ) {
				'yes'   => '1',
				'no'    => '0',
				default => '',
			},
			/*
			 * `fix` on the wire, `action` in the repository. `action` is
			 * WordPress's own parameter on admin-post.php, and the export
			 * form posts there: a second `action` field overwrote
			 * `vulnhub_export_csv` with the filter's value, so the download
			 * button led nowhere. The screen and the widget links use `fix`;
			 * only the argument passed to Repo keeps the old name.
			 */
			'action'     => self::q( 'fix' ),
			'excepted'   => self::q( 'excepted' ),
			'support'    => self::q( 'support' ),
			'path_zone'  => self::q( 'zone' ),
			'os_platform' => self::q( 'platform' ),
			'severity_not' => self::q( 'sev_not' ),
			'orderby'    => $orderby,
			'order'      => $order,
		);
	}

	/**
	 * Validate the orderby/order/lifecycle query args the same way
	 * view_vulnerabilities() does, for the REST fragment endpoint to reuse.
	 *
	 * @return array{orderby:string,order:string,lifecycle:string}
	 */
	public static function findings_validated_scope(): array {
		$orderby = self::q( 'orderby', 'risk_score' );
		$order   = 'ASC' === strtoupper( self::q( 'order', 'DESC' ) ) ? 'ASC' : 'DESC';

		if ( ! isset( self::SORTABLE[ $orderby ] ) ) {
			$orderby = 'risk_score';
		}

		$vh_vlife    = self::q( 'life' );
		$vh_vlife_ok = array_merge( array( 'reportable', 'in_service_all', 'all' ), array_keys( vh_lifecycle_statuses() ) );

		if ( '' !== $vh_vlife && ! in_array( $vh_vlife, $vh_vlife_ok, true ) ) {
			$vh_vlife = '';
		}

		return array(
			'orderby'   => $orderby,
			'order'     => $order,
			'lifecycle' => $vh_vlife,
		);
	}

	/**
	 * Is this list filtered to the route where reachability is the reason?
	 *
	 * The edge lane claims a finding can be reached from the internet with no
	 * account and no click. Clicking through to a list that shows no sign of
	 * what is listening leaves the reader with an assertion and no way to
	 * check it, so the column appears exactly where that claim was made -- and
	 * nowhere else, because on every other route it would be a column of
	 * dashes.
	 *
	 * Read from the query string so the header, the first page and the
	 * infinite-scroll rows all agree; a flag set in one render path and not
	 * the other would put the cells out of step with the header on scroll.
	 */
	public static function show_reach(): bool {
		return 'edge' === self::q( 'route' ) && class_exists( 'VulnHub_Threat_Ports' );
	}

	/**
	 * What is listening on one asset, or why else it is considered reachable.
	 *
	 * @return array<int,string>
	 */
	public static function reach_evidence( int $asset_id ): array {
		if ( ! class_exists( 'VulnHub_Threat_Ports' ) ) {
			return array();
		}

		return (array) ( VulnHub_Threat_Ports::evidence_map()[ $asset_id ] ?? array() );
	}

	public static function finding_row_html( array $f ): string {
		$cves    = vh_json( (string) $f['cve_json'] );
		$overdue = ! empty( $f['due_at'] ) && strtotime( (string) $f['due_at'] . ' UTC' ) < time();

		ob_start();
		?>
		<tr<?php echo (int) $f['exception_id'] > 0 ? ' class="is-excepted"' : ''; ?>>
			<td><input type="checkbox" class="vh-pick" value="<?php echo esc_attr( (string) $f['id'] ); ?>" aria-label="<?php esc_attr_e( 'Select finding', 'vulnhub' ); ?>"></td>
			<td data-th="<?php esc_attr_e( 'Severity', 'vulnhub' ); ?>"><span class="vh-pill vh-pill--<?php echo esc_attr( (string) $f['severity'] ); ?>"><?php echo esc_html( vh_severity_label( (string) $f['severity'] ) ); ?></span></td>
			<td data-th="<?php esc_attr_e( 'Vulnerability', 'vulnhub' ); ?>">
				<a href="<?php echo esc_url( self::page_url( 'vulnerabilities', array( 'vuln' => (int) $f['vuln_id'] ) ) ); ?>">
					<strong><?php echo esc_html( vh_trim( (string) $f['vuln_title'], 72 ) ); ?></strong>
				</a>
				<span class="vh-meta">
					<?php echo esc_html( ( $f['family'] ? $f['family'] . ' · ' : '' ) . 'plugin ' . $f['plugin_id'] ); ?>
					<?php if ( $cves ) : ?>· <?php echo esc_html( implode( ', ', array_slice( $cves, 0, 2 ) ) ); ?><?php endif; ?>
					<?php if ( ! empty( $f['exploit_available'] ) ) : ?>· <span class="vh-flag"><?php esc_html_e( 'exploit available', 'vulnhub' ); ?></span><?php endif; ?>
				</span>
				<?php $vh_ev = Repo::fix_evidence( $f ); ?>
				<span class="vh-fixroute vh-fixroute--<?php echo esc_attr( $vh_ev['route'] ); ?><?php echo '' !== $vh_ev['verdict'] ? ' vh-fixroute--' . esc_attr( $vh_ev['verdict'] ) : ''; ?>" data-vh-tip="<?php echo esc_attr( $vh_ev['why'] ); ?>"><?php echo esc_html( $vh_ev['short'] ); ?></span>
				<?php
				/*
				 * What the scanner actually says, in the row rather than a
				 * click away on the vulnerability page. Without it a reader
				 * cannot tell a real finding from one of Tenable's
				 * informational enumeration plugins -- "Nessus was able to
				 * generate a report of all files listed in the default user
				 * download folder" is the whole answer to why a .docx is
				 * being reported, and it was only visible after two clicks.
				 *
				 * A <details> rather than always-on text: this is a dense
				 * table and most rows are skimmed, so the prose stays folded
				 * until somebody asks a question of a specific row.
				 */
				$vh_desc = trim( (string) ( $f['description'] ?? '' ) );
				$vh_fix  = trim( (string) ( $f['solution'] ?? '' ) );
				?>
				<?php if ( '' !== $vh_desc || '' !== $vh_fix ) : ?>
					<details class="vh-vdetail">
						<summary><?php esc_html_e( 'What the scanner reports', 'vulnhub' ); ?></summary>
						<p class="vh-vdetail__fix">
							<span class="vh-vdetail__k"><?php esc_html_e( 'Why', 'vulnhub' ); ?></span>
							<?php echo esc_html( $vh_ev['why'] ); ?>
						</p>
						<?php if ( '' !== $vh_desc ) : ?>
							<p class="vh-vdetail__body"><?php echo esc_html( vh_trim( $vh_desc, 420 ) ); ?></p>
						<?php endif; ?>
						<?php if ( '' !== $vh_fix ) : ?>
							<p class="vh-vdetail__fix">
								<span class="vh-vdetail__k"><?php esc_html_e( 'Fix', 'vulnhub' ); ?></span>
								<?php echo esc_html( vh_trim( $vh_fix, 200 ) ); ?>
							</p>
						<?php endif; ?>
						<p class="vh-vdetail__meta">
							<?php
							$vh_bits = array();
							if ( '' !== trim( (string) ( $f['cvss3_base'] ?? '' ) ) ) {
								$vh_bits[] = 'CVSS v3 ' . (string) $f['cvss3_base'];
							}
							if ( '' !== trim( (string) ( $f['vpr_score'] ?? '' ) ) ) {
								$vh_bits[] = 'VPR ' . (string) $f['vpr_score'];
							}
							$vh_bits[] = 'severity ' . vh_severity_label( (string) $f['severity'] );
							$vh_bits[] = 'Tenable plugin ' . (string) $f['plugin_id'];
							echo esc_html( implode( ' · ', $vh_bits ) );
							?>
							<a href="<?php echo esc_url( self::page_url( 'vulnerabilities', array( 'vuln' => (int) $f['vuln_id'] ) ) ); ?>"><?php esc_html_e( 'Full detail', 'vulnhub' ); ?></a>
						</p>
					</details>
				<?php endif; ?>
			</td>
			<td data-th="<?php esc_attr_e( 'Asset', 'vulnhub' ); ?>">
				<a class="vh-mono" href="<?php echo esc_url( self::page_url( 'assets', array( 'asset' => (int) $f['asset_id'] ) ) ); ?>"><?php echo esc_html( (string) $f['hostname'] ); ?></a>
				<span class="vh-meta"><?php echo esc_html( (string) $f['ipv4'] ); ?></span>
			</td>
			<?php if ( self::show_reach() ) : ?>
				<td data-th="<?php esc_attr_e( 'Reachable via', 'vulnhub' ); ?>">
					<?php
					/*
					 * One service per line, each unbreakable. Joined into a
					 * single run they wrapped mid-token in this column's width
					 * -- "http-alt 8080/tcp" split across two lines reads as
					 * two different things.
					 */
					$vh_reach = self::reach_evidence( (int) $f['asset_id'] );
					?>
					<?php if ( $vh_reach ) : ?>
						<ul class="vh-reach">
							<?php foreach ( $vh_reach as $vh_svc ) : ?>
								<li><?php echo esc_html( (string) $vh_svc ); ?></li>
							<?php endforeach; ?>
						</ul>
					<?php else : ?>
						<span class="vh-meta"><?php esc_html_e( 'no listening service recorded', 'vulnhub' ); ?></span>
					<?php endif; ?>
				</td>
			<?php endif; ?>
			<td data-th="<?php esc_attr_e( 'Location', 'vulnhub' ); ?>"><?php echo esc_html( (string) ( $f['location_name'] ?: '—' ) ); ?></td>
			<td data-th="<?php esc_attr_e( 'File path', 'vulnhub' ); ?>">
				<?php
				/*
				 * zone_path first: on a finding that reports several paths it
				 * is the one that put the row in its zone, which is the whole
				 * reason the reader filtered by zone. install_path() is the
				 * fallback for everything else, parsed from the output the
				 * same way it always was.
				 */
				$vh_path = (string) ( $f['zone_path'] ?: VH_Product::install_path( (string) ( $f['output'] ?? '' ) ) );
				?>
				<?php if ( '' !== $vh_path ) : ?>
					<code class="vh-path" title="<?php echo esc_attr( $vh_path ); ?>"><?php echo esc_html( vh_trim( $vh_path, 54 ) ); ?></code>
				<?php else : ?>
					<span class="vh-meta">—</span>
				<?php endif; ?>
			</td>
			<td data-th="<?php esc_attr_e( 'Owner', 'vulnhub' ); ?>">
				<?php if ( ! empty( $f['owner_name'] ) ) : ?>
					<span class="vh-mask" data-vh-mask>
						<span class="vh-mask__dots" aria-hidden="true">••••••••</span>
						<span class="vh-mask__real"><?php echo esc_html( (string) $f['owner_name'] ); ?></span>
					</span>
					<span class="vh-meta"><?php echo esc_html( (string) ( $f['team_name'] ?: '' ) ); ?></span>
				<?php elseif ( ! empty( $f['team_name'] ) ) : ?>
					<?php echo esc_html( (string) $f['team_name'] ); ?>
				<?php else : ?>
					<span class="vh-chip vh-chip--warn"><?php esc_html_e( 'Unassigned', 'vulnhub' ); ?></span>
				<?php endif; ?>
			</td>
			<td class="<?php echo $overdue ? 'vh-overdue' : ''; ?>" data-th="<?php esc_attr_e( 'Due', 'vulnhub' ); ?>"><?php echo esc_html( $f['due_at'] ? vh_ago( (string) $f['due_at'] ) : '—' ); ?></td>
			<td data-th="<?php esc_attr_e( 'Ticket', 'vulnhub' ); ?>">
				<?php if ( ! empty( $f['ticket_key'] ) ) : ?>
					<a class="vh-mono" href="<?php echo esc_url( (string) $f['ticket_url'] ); ?>" target="_blank" rel="noopener noreferrer"><?php echo esc_html( (string) $f['ticket_key'] ); ?></a>
					<span class="vh-meta"><?php echo esc_html( (string) $f['ticket_status'] ); ?></span>
				<?php else : ?>—<?php endif; ?>
			</td>
			<td class="vh-col-act">
				<?php if ( current_user_can( Caps::RAISE_TICKET ) && empty( $f['ticket_key'] ) ) : ?>
					<button type="button" class="vh-btn vh-btn--sm" data-vh-raise data-vh-finding="<?php echo esc_attr( (string) $f['id'] ); ?>"><?php esc_html_e( 'Ticket', 'vulnhub' ); ?></button>
				<?php endif; ?>
				<?php if ( current_user_can( Caps::REQUEST_EXCEPTION ) && (int) $f['exception_id'] === 0 ) : ?>
					<?php // The portal's Exceptions view, not wp-admin: this row is also rendered by the findings-more REST route, where there is no portal post to infer the destination from. ?>
					<a class="vh-btn vh-btn--sm vh-btn--ghost" href="<?php echo esc_url( self::page_url( 'exceptions', array( 'new' => 1, 'finding' => (int) $f['id'] ) ) ); ?>"><?php esc_html_e( 'Except', 'vulnhub' ); ?></a>
				<?php endif; ?>
			</td>
		</tr>
		<?php
		return (string) ob_get_clean();
	}

	/* ----------------------------------------------------------- assets. */

	/* ------------------------------------------------------ products. */

	/**
	 * Every detected product and bundling application, ranked by in-scope
	 * assets affected, with a scope filter (all / workstations / servers /
	 * Windows / Linux) and a CSV export. Reached from the "View all" control
	 * on the dashboard's Exposure-by-product widget; the same query and row
	 * markup as that widget, without the top-N cap.
	 */
	private static function view_products(): void {
		$scopes = VulnHub_Dash_Widgets::product_scopes();
		$scope  = self::q( 'scope' );
		if ( ! array_key_exists( $scope, $scopes ) ) {
			$scope = '';
		}

		$rows = VulnHub_Dash_Widgets::product_rows( 0, $scope );
		$max  = $rows ? max( 1, (int) $rows[0]['assets'] ) : 1;
		$args = '' === $scope ? array() : array( 'scope' => $scope );
		?>
		<div class="vh-page-head">
			<div>
				<h1><?php esc_html_e( 'Exposure by product', 'vulnhub' ); ?></h1>
				<p class="vh-sub">
					<?php
					printf(
						/* translators: %s: number of products. */
						esc_html( _n( '%s product or application detected in this scope.', '%s products and applications detected in this scope.', count( $rows ), 'vulnhub' ) ),
						'<strong>' . esc_html( number_format_i18n( count( $rows ) ) ) . '</strong>'
					);
					?>
				</p>
			</div>
			<div class="vh-page-head__actions">
				<a class="vh-btn vh-btn--ghost vh-btn--sm" href="<?php echo esc_url( self::page_url( 'vendors' ) ); ?>"><?php esc_html_e( 'By vendor', 'vulnhub' ); ?></a>
				<?php VulnHub_Dash_Export::button( 'products', $args ); ?>
			</div>
		</div>

		<nav class="vh-segbar" aria-label="<?php esc_attr_e( 'Filter products by platform', 'vulnhub' ); ?>">
			<?php foreach ( $scopes as $vh_k => $vh_label ) : ?>
				<a class="vh-seg<?php echo $scope === (string) $vh_k ? ' is-active' : ''; ?>"
					href="<?php echo esc_url( self::page_url( 'products', '' === (string) $vh_k ? array() : array( 'scope' => (string) $vh_k ) ) ); ?>"
					<?php echo $scope === (string) $vh_k ? 'aria-current="true"' : ''; ?>>
					<?php echo esc_html( (string) $vh_label ); ?>
				</a>
			<?php endforeach; ?>
		</nav>

		<?php if ( ! $rows ) : ?>
			<div class="vh-card">
				<?php echo VulnHub_Dash_Charts::empty_state( __( 'No products match this filter.', 'vulnhub' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			</div>
		<?php else : ?>
			<div class="vh-prodsearch" data-vh-prodsearch data-vh-total="<?php echo (int) count( $rows ); ?>" hidden>
				<input type="search" class="vh-prodsearch__input" autocomplete="off" spellcheck="false"
					placeholder="<?php esc_attr_e( 'Search products…', 'vulnhub' ); ?>"
					aria-label="<?php esc_attr_e( 'Search products by name', 'vulnhub' ); ?>" />
				<span class="vh-prodsearch__count" role="status" aria-live="polite"></span>
			</div>
			<div class="vh-card vh-card--flush">
				<ul class="vh-prodlist vh-prodlist--full">
					<?php
					foreach ( $rows as $vh_r ) :
						$vh_assets = (int) $vh_r['assets'];
						$vh_pct    = (int) round( 100 * $vh_assets / $max );
						$vh_url    = VulnHub_Dash_Portal::portal_url(
							'vulnerabilities',
							array( 'product' => (string) $vh_r['product_slug'], 'life' => 'reportable', 'state' => 'open_any' )
						);
						$vh_search = strtolower( trim( (string) $vh_r['product'] . ' ' . (string) ( $vh_r['product_kind'] ?? '' ) . ' ' . (string) ( $vh_r['bundles'] ?? '' ) ) );
						?>
						<li class="vh-prodrow" data-vh-name="<?php echo esc_attr( $vh_search ); ?>">
							<?php echo VulnHub_Dash_Widgets::product_icon( (string) $vh_r['product_slug'], (string) $vh_r['component_class'], (string) $vh_r['product'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
							<div class="vh-prodrow__main">
								<div class="vh-prodrow__head">
									<a class="vh-prodrow__name" href="<?php echo esc_url( $vh_url ); ?>"><?php echo esc_html( (string) $vh_r['product'] ); ?></a>
									<?php echo VulnHub_Dash_Widgets::product_kind_badge( (string) $vh_r['product_kind'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
									<span class="vh-prodrow__nums">
										<?php
										printf(
											/* translators: 1: asset count, 2: finding count. */
											esc_html__( '%1$s assets · %2$s findings', 'vulnhub' ),
											'<strong>' . esc_html( number_format_i18n( $vh_assets ) ) . '</strong>',
											esc_html( number_format_i18n( (int) $vh_r['findings'] ) )
										);
										?>
									</span>
								</div>
								<div class="vh-prodrow__bar"><span style="width:<?php echo (int) $vh_pct; ?>%"></span></div>
								<?php
								$vh_bundles = trim( (string) ( $vh_r['bundles'] ?? '' ) );
								if ( '' !== $vh_bundles ) :
									?>
									<p class="vh-prodrow__note">
										<?php
										printf(
											/* translators: %s: comma-separated library names. */
											esc_html__( 'Ships a vulnerable %s inside the app. Update the app, or check the vendor for a fixed release.', 'vulnhub' ),
											'<strong>' . esc_html( $vh_bundles ) . '</strong>'
										);
										?>
									</p>
								<?php endif; ?>
							</div>
						</li>
					<?php endforeach; ?>
				</ul>
				<p class="vh-prodsearch__empty" data-vh-prodsearch-empty hidden><?php esc_html_e( 'No products match your search.', 'vulnhub' ); ?></p>
			</div>
		<?php endif; ?>
		<?php
	}

	/* ------------------------------------------------------- vendors. */

	/**
	 * Every vendor behind the estate -- hardware makers (from an asset's
	 * manufacturer, including archived-but-scanned kit) and software owners
	 * (from a finding's product). Each carries our own exposure, a verified
	 * security-advisory link, a public risk-rating link and a bundled logo.
	 * Filterable by hardware / software / assets missing Tenable+Defender+CMDB.
	 */
	private static function view_vendors(): void {
		$scopes = array(
			''          => __( 'All', 'vulnhub' ),
			'hardware'  => __( 'Hardware', 'vulnhub' ),
			'software'  => __( 'Software', 'vulnhub' ),
			'uncovered' => __( 'Uncovered', 'vulnhub' ),
		);
		$scope = self::q( 'scope' );
		if ( ! array_key_exists( $scope, $scopes ) ) {
			$scope = '';
		}

		$rows = VH_Vendor::vendors( $scope );
		$args = '' === $scope ? array() : array( 'scope' => $scope );
		?>
		<div class="vh-page-head">
			<div>
				<h1><?php esc_html_e( 'Vendors', 'vulnhub' ); ?></h1>
				<p class="vh-sub">
					<?php
					printf(
						/* translators: %s: number of vendors. */
						esc_html( _n( '%s vendor identified across hardware and software in the estate.', '%s vendors identified across hardware and software in the estate.', count( $rows ), 'vulnhub' ) ),
						'<strong>' . esc_html( number_format_i18n( count( $rows ) ) ) . '</strong>'
					);
					?>
				</p>
			</div>
			<div class="vh-page-head__actions">
				<a class="vh-btn vh-btn--ghost vh-btn--sm" href="<?php echo esc_url( self::page_url( 'products' ) ); ?>"><?php esc_html_e( 'By product', 'vulnhub' ); ?></a>
				<?php VulnHub_Dash_Export::button( 'vendors', $args ); ?>
			</div>
		</div>

		<nav class="vh-segbar" aria-label="<?php esc_attr_e( 'Filter vendors', 'vulnhub' ); ?>">
			<?php foreach ( $scopes as $vh_k => $vh_label ) : ?>
				<a class="vh-seg<?php echo $scope === (string) $vh_k ? ' is-active' : ''; ?>"
					href="<?php echo esc_url( self::page_url( 'vendors', '' === (string) $vh_k ? array() : array( 'scope' => (string) $vh_k ) ) ); ?>"
					<?php echo $scope === (string) $vh_k ? 'aria-current="true"' : ''; ?>>
					<?php echo esc_html( (string) $vh_label ); ?>
				</a>
			<?php endforeach; ?>
		</nav>

		<?php if ( 'uncovered' === $scope ) : ?>
			<p class="vh-sub" style="margin:-6px 0 14px">
				<?php esc_html_e( 'Vendors with assets that Tenable has not scanned, Defender has not onboarded, and the CMDB does not record — blind spots that are still real hardware. Some may be archived kit that is still being scanned.', 'vulnhub' ); ?>
			</p>
		<?php endif; ?>

		<?php if ( ! $rows ) : ?>
			<div class="vh-card"><?php echo VulnHub_Dash_Charts::empty_state( __( 'No vendors match this filter.', 'vulnhub' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></div>
		<?php else : ?>
			<ul class="vh-vendorgrid">
				<?php foreach ( $rows as $vh_v ) : ?>
					<li class="vh-vendor">
						<?php echo VulnHub_Dash_Widgets::vendor_icon( (string) $vh_v['slug'], (string) $vh_v['name'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
						<div class="vh-vendor__main">
							<div class="vh-vendor__head">
								<span class="vh-vendor__name"><?php echo esc_html( (string) $vh_v['name'] ); ?></span>
								<span class="vh-kind vh-kind--<?php echo esc_attr( (string) $vh_v['kind'] ); ?>"><?php echo esc_html( (string) $vh_v['kind'] ); ?></span>
								<span class="vh-band vh-band--<?php echo esc_attr( (string) $vh_v['band'] ); ?>" title="<?php esc_attr_e( 'Our exposure to this vendor, from open critical/high findings and coverage gaps.', 'vulnhub' ); ?>">
									<?php echo esc_html( sprintf( /* translators: %s: exposure level. */ __( '%s exposure', 'vulnhub' ), VH_Vendor::band_label( (string) $vh_v['band'] ) ) ); ?>
								</span>
							</div>

							<?php
							$vh_slug = (string) $vh_v['slug'];
							$vh_name = (string) $vh_v['name'];
							/**
							 * One clickable stat. Opens the drill-down modal (app.js)
							 * for this vendor + metric; degrades to a link to the CSV
							 * export of the same list when scripting is off.
							 */
							$vh_stat = function ( string $metric, int $count, string $label, string $extra = '' ) use ( $vh_slug, $vh_name ) {
								if ( $count <= 0 ) {
									return;
								}
								$vh_export = VulnHub_Dash_Export::url(
									in_array( $metric, array( 'products' ), true ) ? 'vendor_products'
										: ( in_array( $metric, array( 'findings', 'critical' ), true ) ? 'vendor_findings' : 'vendor_assets' ),
									in_array( $metric, array( 'products' ), true ) ? array( 'vendor' => $vh_slug )
										: ( in_array( $metric, array( 'findings', 'critical' ), true ) ? array( 'vendor' => $vh_slug, 'severity' => 'critical' === $metric ? 'critical' : '' )
										: array( 'vendor' => $vh_slug, 'metric' => $metric ) )
								);
								printf(
									'<a class="vh-vstat%1$s" href="%2$s" data-vh-drill data-vendor="%3$s" data-metric="%4$s" data-vendor-name="%5$s">'
									. '<strong>%6$s</strong> %7$s</a>',
									$extra ? ' ' . esc_attr( $extra ) : '',
									esc_url( $vh_export ),
									esc_attr( $vh_slug ),
									esc_attr( $metric ),
									esc_attr( $vh_name ),
									esc_html( number_format_i18n( $count ) ),
									esc_html( $label )
								);
							};
							?>
							<div class="vh-vendor__stats">
								<?php
								$vh_stat( 'assets', (int) $vh_v['hw_assets'], _n( 'asset', 'assets', (int) $vh_v['hw_assets'], 'vulnhub' ) );
								$vh_stat( 'products', (int) $vh_v['products'], _n( 'product', 'products', (int) $vh_v['products'], 'vulnhub' ) );
								$vh_stat( 'findings', (int) $vh_v['findings'], __( 'findings', 'vulnhub' ) );
								$vh_stat( 'critical', (int) $vh_v['crit'], __( 'critical', 'vulnhub' ), 'vh-vstat--crit' );
								$vh_stat( 'uncovered', (int) $vh_v['uncovered'], __( 'uncovered', 'vulnhub' ), 'vh-vstat--warn' );
								$vh_stat( 'archived', (int) $vh_v['archived'], __( 'archived', 'vulnhub' ), 'vh-vstat--muted' );
								?>
							</div>

							<div class="vh-vendor__links">
								<?php if ( '' !== (string) $vh_v['advisory'] ) : ?>
									<a class="vh-vendor__link" href="<?php echo esc_url( (string) $vh_v['advisory'] ); ?>" target="_blank" rel="noopener noreferrer">
										<?php esc_html_e( 'Security advisories', 'vulnhub' ); ?> &#8599;
									</a>
								<?php else : ?>
									<span class="vh-vendor__link vh-vendor__link--none"><?php esc_html_e( 'No public advisory page', 'vulnhub' ); ?></span>
								<?php endif; ?>
								<?php if ( '' !== (string) $vh_v['ratings'] ) : ?>
									<a class="vh-vendor__link" href="<?php echo esc_url( (string) $vh_v['ratings'] ); ?>" target="_blank" rel="noopener noreferrer">
										<?php esc_html_e( 'Public risk rating', 'vulnhub' ); ?> &#8599;
									</a>
								<?php endif; ?>
								<?php if ( '' !== (string) $vh_v['hq'] ) : ?>
									<span class="vh-vendor__hq"><?php echo esc_html( (string) $vh_v['hq'] ); ?></span>
								<?php endif; ?>
							</div>
						</div>
					</li>
				<?php endforeach; ?>
			</ul>
			<p class="vh-sub"><?php esc_html_e( 'Exposure is our own measure — open critical/high findings plus assets with no Tenable, Defender or CMDB coverage. Advisory links were checked live; the public risk rating opens the vendor’s SecurityScorecard profile.', 'vulnhub' ); ?></p>
		<?php endif; ?>
		<?php
	}

	private static function view_assets(): void {
		$asset_id = self::qi( 'asset' );

		if ( $asset_id ) {
			$a = Repo::asset( $asset_id );
			if ( ! $a ) {
				echo '<p class="vh-chart-empty">' . esc_html__( 'Asset not found.', 'vulnhub' ) . '</p>';
				return;
			}
			$owner = Repo::person( (int) $a['owner_person_id'] );
			$team  = Repo::team( (int) $a['team_id'] );
			$loc   = Repo::location( (int) $a['location_id'] );
			$find  = Repo::findings( array( 'asset_id' => $asset_id, 'state' => 'open_any', 'limit' => 100 ) );
			$needs = in_array( (string) $a['asset_type'], vh_user_bound_asset_types(), true );
			?>
			<p><a class="vh-back" href="<?php echo esc_url( self::page_url( 'assets' ) ); ?>">&larr; <?php esc_html_e( 'All assets', 'vulnhub' ); ?></a></p>

			<div class="vh-page-head">
				<div>
					<h1 class="vh-mono"><?php echo esc_html( (string) $a['hostname'] ); ?></h1>
					<p class="vh-sub">
						<?php
						echo $a['operating_system']
							? \VulnHub\Core\Os::badge( (string) $a['operating_system'], true, (string) ( $a['os_version'] ?? '' ), (string) $a['asset_type'] ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
							: esc_html__( 'Unknown', 'vulnhub' );
						?>
						· <?php echo esc_html( vh_asset_types()[ (string) $a['asset_type'] ] ?? '' ); ?>
						· <?php echo esc_html( (string) $a['ipv4'] ); ?>
					</p>
				</div>
			</div>

			<div class="vh-grid vh-grid--3">
				<section class="vh-panel">
					<header class="vh-panel__head"><h2><?php esc_html_e( 'Ownership', 'vulnhub' ); ?></h2></header>
					<?php if ( $needs && ! $owner ) : ?>
						<p class="vh-warn-note"><?php esc_html_e( 'This is a user-bound asset with no owner resolved. Intune did not report a primary user, or that user has not synced yet.', 'vulnhub' ); ?></p>
					<?php endif; ?>
					<dl class="vh-dl">
						<dt><?php esc_html_e( 'Owner', 'vulnhub' ); ?></dt>
						<dd><?php echo $owner ? esc_html( (string) $owner['display_name'] ) : '<span class="vh-chip vh-chip--warn">' . esc_html__( 'Unassigned', 'vulnhub' ) . '</span>'; // phpcs:ignore ?></dd>
						<dt><?php esc_html_e( 'Email', 'vulnhub' ); ?></dt>
						<dd><?php echo esc_html( (string) ( $owner['upn'] ?? '—' ) ); ?></dd>
						<dt><?php esc_html_e( 'Department', 'vulnhub' ); ?></dt>
						<dd><?php echo esc_html( (string) ( $owner['department'] ?? '—' ) ); ?></dd>
						<dt><?php esc_html_e( 'Team', 'vulnhub' ); ?></dt>
						<dd><?php echo esc_html( (string) ( $team['name'] ?? '—' ) ); ?></dd>
						<dt><?php esc_html_e( 'Location', 'vulnhub' ); ?></dt>
						<dd><?php echo esc_html( (string) ( $loc['name'] ?? ( $owner['office_location'] ?? '—' ) ) ); ?></dd>
						<dt><?php esc_html_e( 'Resolved by', 'vulnhub' ); ?></dt>
						<dd class="vh-sub"><?php echo esc_html( (string) ( $a['owner_rule'] ?: '—' ) ); ?></dd>
					</dl>
				</section>

				<section class="vh-panel">
					<header class="vh-panel__head"><h2><?php esc_html_e( 'Identity', 'vulnhub' ); ?></h2></header>
					<dl class="vh-dl">
						<dt><?php esc_html_e( 'FQDN', 'vulnhub' ); ?></dt><dd class="vh-mono"><?php echo esc_html( (string) ( $a['fqdn'] ?: '—' ) ); ?></dd>
						<dt><?php esc_html_e( 'Serial', 'vulnhub' ); ?></dt><dd class="vh-mono"><?php echo esc_html( (string) ( $a['serial_number'] ?: '—' ) ); ?></dd>
						<dt><?php esc_html_e( 'Hardware', 'vulnhub' ); ?></dt><dd><?php echo esc_html( trim( $a['manufacturer'] . ' ' . $a['model'] ) ?: '—' ); ?></dd>
						<dt><?php esc_html_e( 'Support ends', 'vulnhub' ); ?></dt>
						<dd>
							<?php
							/*
							 * A machine past its warranty is a security fact, not
							 * only a finance one: when the next critical lands the
							 * vendor will not be shipping it a fix.
							 */
							$vh_support_end = (string) ( $a['support_end_date'] ?? '' );
							$vh_expired     = '' !== $vh_support_end && strtotime( $vh_support_end ) < time();
							?>
							<?php if ( '' === $vh_support_end ) : ?>
								—
							<?php elseif ( $vh_expired ) : ?>
								<span class="vh-chip vh-chip--bad"><?php echo esc_html( vh_date_only( $vh_support_end ) ); ?></span>
								<span class="vh-meta"><?php esc_html_e( 'out of support', 'vulnhub' ); ?></span>
							<?php else : ?>
								<?php echo esc_html( vh_date_only( $vh_support_end ) ); ?>
							<?php endif; ?>
						</dd>
						<dt><?php esc_html_e( 'Known by', 'vulnhub' ); ?></dt>
						<dd>
							<?php echo self::source_chips( (string) ( $a['sources_json'] ?? '' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
							<?php
							$vh_seen = Repo::source_map( (string) ( $a['sources_json'] ?? '' ) );
							$vh_srcl = vh_asset_sources();
							$vh_when = array();

							foreach ( $vh_seen as $vh_slug => $vh_date ) {
								if ( '' !== $vh_date ) {
									$vh_when[] = ( $vh_srcl[ $vh_slug ] ?? $vh_slug ) . ' ' . vh_ago( $vh_date );
								}
							}
							?>
							<?php if ( $vh_when ) : ?>
								<span class="vh-meta"><?php echo esc_html( implode( ', ', $vh_when ) ); ?></span>
							<?php endif; ?>
						</dd>
						<dt><?php esc_html_e( 'Scan coverage', 'vulnhub' ); ?></dt>
						<dd>
							<?php $vh_a_cov = (string) ( $a['coverage_state'] ?? '' ); ?>
							<?php if ( '' !== $vh_a_cov && 'unknown' !== $vh_a_cov ) : ?>
								<span class="vh-chip vh-chip--<?php echo esc_attr( Coverage::tone( $vh_a_cov ) ); ?>"><?php echo esc_html( Coverage::label( $vh_a_cov ) ); ?></span>
								<?php if ( ! empty( $a['tenable_last_scan'] ) ) : ?>
									<span class="vh-meta">
										<?php
										printf(
											/* translators: %s: a human time difference such as "3 days ago". */
											esc_html__( 'Tenable scanned %s', 'vulnhub' ),
											esc_html( vh_ago( (string) $a['tenable_last_scan'] ) )
										);
										?>
									</span>
								<?php endif; ?>
							<?php else : ?>—<?php endif; ?>
						</dd>
						<dt><?php esc_html_e( 'EDR coverage', 'vulnhub' ); ?></dt>
						<dd>
							<?php $vh_a_edr = (string) ( $a['defender_coverage_state'] ?? '' ); ?>
							<?php if ( '' !== $vh_a_edr && 'unknown' !== $vh_a_edr ) : ?>
								<span class="vh-chip vh-chip--<?php echo esc_attr( Defender_Coverage::tone( $vh_a_edr ) ); ?>"><?php echo esc_html( Defender_Coverage::label( $vh_a_edr ) ); ?></span>
								<?php if ( ! empty( $a['defender_last_seen'] ) ) : ?>
									<span class="vh-meta">
										<?php
										printf(
											/* translators: %s: a human time difference such as "3 days ago". */
											esc_html__( 'Defender heard from it %s', 'vulnhub' ),
											esc_html( vh_ago( (string) $a['defender_last_seen'] ) )
										);
										?>
									</span>
								<?php endif; ?>
								<?php if ( (string) ( $a['defender_managed_by'] ?? '' ) ) : ?>
									<span class="vh-meta">
										<?php
										printf(
											/* translators: %s: the tool managing the sensor, e.g. Intune. */
											esc_html__( 'managed by %s', 'vulnhub' ),
											esc_html( (string) $a['defender_managed_by'] )
										);
										?>
									</span>
								<?php endif; ?>
							<?php else : ?>—<?php endif; ?>
						</dd>
						<dt><?php esc_html_e( 'Discovered by', 'vulnhub' ); ?></dt>
						<dd class="vh-sub"><?php echo esc_html( (string) ( $a['primary_source'] ?: '—' ) ); ?></dd>
						<dt><?php esc_html_e( 'CMDB ref', 'vulnhub' ); ?></dt>
						<dd class="vh-mono"><?php echo esc_html( (string) ( $a['cmdb_key'] ?: '—' ) ); ?></dd>
						<dt><?php esc_html_e( 'Lifecycle', 'vulnhub' ); ?></dt>
						<dd>
							<?php
							$vh_a_life   = (string) $a['lifecycle_status'];
							$vh_a_in_svc = in_array( $vh_a_life, vh_in_service_statuses(), true );
							$vh_a_arch   = \VulnHub\Core\Lifecycle::archived_count( (int) $a['id'] );
							?>
							<span class="vh-chip <?php echo $vh_a_in_svc ? '' : 'vh-chip--warn'; ?>">
								<?php echo esc_html( (string) ( vh_lifecycle_statuses()[ $vh_a_life ]['label'] ?? $vh_a_life ) ); ?>
							</span>
							<?php if ( $vh_a_arch > 0 ) : ?>
								<span class="vh-meta">
									<?php
									printf(
										/* translators: %s: number of findings. */
										esc_html( _n( '%s finding archived with it', '%s findings archived with it', $vh_a_arch, 'vulnhub' ) ),
										esc_html( number_format_i18n( $vh_a_arch ) )
									);
									?>
								</span>
							<?php endif; ?>

							<?php if ( current_user_can( \VulnHub\Core\Caps::TRIAGE ) ) : ?>
								<?php
								/*
								 * The same action the list offers, for the case where
								 * somebody has opened one machine to check it before
								 * deciding. It posts the same form to the same handler
								 * so there is one code path, not two.
								 */
								$vh_a_live = \VulnHub\Core\Lifecycle::live_finding_count( array( (int) $a['id'] ) );
								?>
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-life1">
									<input type="hidden" name="action" value="vulnhub_set_lifecycle">
									<input type="hidden" name="assets[]" value="<?php echo esc_attr( (string) (int) $a['id'] ); ?>">
									<input type="hidden" name="back" value="<?php echo esc_url( self::page_url( 'assets', array( 'asset' => (int) $a['id'] ) ) ); ?>">
									<?php wp_nonce_field( 'vulnhub_set_lifecycle' ); ?>
									<?php if ( $vh_a_in_svc ) : ?>
										<button type="submit" name="lifecycle" value="retired" class="vh-btn vh-btn--danger vh-btn--sm"
											data-vh-confirm="<?php echo esc_attr( sprintf( /* translators: %s: number of findings. */ _n( 'Mark this asset decommissioned? %s open finding will be archived and removed from the totals.', 'Mark this asset decommissioned? %s open findings will be archived and removed from the totals.', $vh_a_live, 'vulnhub' ), number_format_i18n( $vh_a_live ) ) ); ?>">
											<?php esc_html_e( 'Mark decommissioned', 'vulnhub' ); ?>
										</button>
									<?php else : ?>
										<button type="submit" name="lifecycle" value="in_service" class="vh-btn vh-btn--sm">
											<?php esc_html_e( 'Return to service', 'vulnhub' ); ?>
										</button>
									<?php endif; ?>
								</form>
							<?php endif; ?>
						</dd>
						<dt><?php esc_html_e( 'Criticality', 'vulnhub' ); ?></dt><dd><?php echo esc_html( ucfirst( (string) $a['criticality'] ) ); ?></dd>
						<dt><?php esc_html_e( 'Compliance', 'vulnhub' ); ?></dt><dd><?php echo esc_html( (string) ( $a['compliance_state'] ?: '—' ) ); ?></dd>
						<dt><?php esc_html_e( 'Business service', 'vulnhub' ); ?></dt><dd><?php echo esc_html( (string) ( $a['business_service'] ?: '—' ) ); ?></dd>
						<dt><?php esc_html_e( 'Environment', 'vulnhub' ); ?></dt><dd><?php echo esc_html( (string) ( $a['environment'] ?: '—' ) ); ?></dd>
						<dt><?php esc_html_e( 'Patch group', 'vulnhub' ); ?></dt>
						<dd><?php echo $a['patch_group'] ? '<span class="vh-chip">' . esc_html( (string) $a['patch_group'] ) . '</span>' : '—'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></dd>
						<dt><?php esc_html_e( 'Last seen', 'vulnhub' ); ?></dt><dd><?php echo esc_html( vh_ago( (string) $a['last_seen'] ) ); ?></dd>
					</dl>

					<?php
					/*
					 * Only drawn for machines that actually live in a cloud
					 * account. `cloud_account_id` is the AWS account the
					 * instance runs in, not a person -- the column it comes
					 * from is called `aws_owner_id`, which is exactly the
					 * trap this panel exists to avoid.
					 */
					$vh_cloud_raw = vh_json( (string) $a['raw_json'] );
					$vh_cloud     = is_array( $vh_cloud_raw['cloud'] ?? null ) ? $vh_cloud_raw['cloud'] : array();
					?>
					<?php if ( $a['cloud_account_id'] || $a['aws_instance_id'] || $vh_cloud ) : ?>
						<h3 class="vh-h3"><?php esc_html_e( 'Cloud', 'vulnhub' ); ?></h3>
						<dl class="vh-dl">
							<dt><?php esc_html_e( 'Account', 'vulnhub' ); ?></dt>
							<dd class="vh-mono"><?php echo esc_html( (string) ( $a['cloud_account_id'] ?: '—' ) ); ?>
								<?php if ( $a['cloud_provider'] ) : ?>
									<span class="vh-meta"><?php echo esc_html( strtoupper( (string) $a['cloud_provider'] ) ); ?></span>
								<?php endif; ?>
							</dd>
							<dt><?php esc_html_e( 'Region', 'vulnhub' ); ?></dt>
							<dd class="vh-mono"><?php echo esc_html( (string) ( $a['cloud_region'] ?: '—' ) ); ?>
								<?php if ( ! empty( $vh_cloud['zone'] ) ) : ?>
									<span class="vh-meta"><?php echo esc_html( (string) $vh_cloud['zone'] ); ?></span>
								<?php endif; ?>
							</dd>
							<dt><?php esc_html_e( 'Instance', 'vulnhub' ); ?></dt>
							<dd class="vh-mono"><?php echo esc_html( (string) ( $a['aws_instance_id'] ?: '—' ) ); ?>
								<span class="vh-meta">
									<?php echo esc_html( trim( (string) ( $vh_cloud['instance_type'] ?? '' ) . ' ' . (string) ( $vh_cloud['state'] ?? '' ) ) ); ?>
								</span>
							</dd>
							<?php if ( ! empty( $vh_cloud['vpc_id'] ) ) : ?>
								<dt><?php esc_html_e( 'Network', 'vulnhub' ); ?></dt>
								<dd class="vh-mono"><?php echo esc_html( (string) $vh_cloud['vpc_id'] ); ?>
									<span class="vh-meta"><?php echo esc_html( (string) ( $vh_cloud['subnet_id'] ?? '' ) ); ?></span>
								</dd>
							<?php endif; ?>
						</dl>
					<?php endif; ?>
				</section>

				<section class="vh-panel">
					<header class="vh-panel__head"><h2><?php esc_html_e( 'Open exposure', 'vulnhub' ); ?></h2></header>
					<div class="vh-sevgrid">
						<?php
						foreach ( array( 'critical' => 'open_critical', 'high' => 'open_high', 'medium' => 'open_medium', 'low' => 'open_low' ) as $sev => $col ) :
							?>
							<div class="vh-sevgrid__cell">
								<span class="vh-sevgrid__n" style="color:<?php echo esc_attr( VulnHub_Dash_Charts::severity_var( $sev ) ); ?>"><?php echo esc_html( number_format_i18n( (int) $a[ $col ] ) ); ?></span>
								<span class="vh-sevgrid__l"><?php echo esc_html( vh_severity_label( $sev ) ); ?></span>
							</div>
						<?php endforeach; ?>
					</div>
					<?php $tags = vh_json( (string) $a['tags_json'] ); ?>
					<?php if ( $tags ) : ?>
						<h3 class="vh-h3"><?php esc_html_e( 'Tags', 'vulnhub' ); ?></h3>
						<p class="vh-tags">
							<?php foreach ( array_slice( $tags, 0, 10 ) as $tag ) : ?>
								<span class="vh-chip"><?php echo esc_html( is_array( $tag ) ? ( ( $tag['key'] ?? '' ) . ': ' . ( $tag['value'] ?? '' ) ) : (string) $tag ); ?></span>
							<?php endforeach; ?>
						</p>
					<?php endif; ?>
				</section>
			</div>

			<section class="vh-panel">
				<header class="vh-panel__head"><h2><?php esc_html_e( 'Open findings', 'vulnhub' ); ?></h2></header>
				<?php echo VulnHub_Dash_Charts::severity_legend(); // phpcs:ignore ?>
				<?php if ( ! $find['rows'] ) : ?>
					<p class="vh-ok-note"><?php esc_html_e( 'No open findings on this asset.', 'vulnhub' ); ?></p>
				<?php else : ?>
					<div class="vh-tablewrap">
						<table class="vh-table">
							<thead><tr>
								<th><?php esc_html_e( 'Severity', 'vulnhub' ); ?></th>
								<th><?php esc_html_e( 'Vulnerability', 'vulnhub' ); ?></th>
								<th><?php esc_html_e( 'Remediation', 'vulnhub' ); ?></th>
								<th><?php esc_html_e( 'Due', 'vulnhub' ); ?></th>
								<th></th>
							</tr></thead>
							<tbody>
							<?php foreach ( $find['rows'] as $f ) : ?>
								<tr>
									<td><span class="vh-pill vh-pill--<?php echo esc_attr( (string) $f['severity'] ); ?>"><?php echo esc_html( vh_severity_label( (string) $f['severity'] ) ); ?></span></td>
									<td>
										<a href="<?php echo esc_url( self::page_url( 'vulnerabilities', array( 'vuln' => (int) $f['vuln_id'] ) ) ); ?>">
											<strong><?php echo esc_html( vh_trim( (string) $f['vuln_title'], 70 ) ); ?></strong>
										</a>
										<span class="vh-meta"><?php echo esc_html( (string) ( $f['family'] ?: '' ) ); ?></span>
									</td>
									<td class="vh-sub"><?php echo esc_html( vh_trim( (string) $f['solution'], 90 ) ); ?></td>
									<td><?php echo esc_html( $f['due_at'] ? vh_ago( (string) $f['due_at'] ) : '—' ); ?></td>
									<td class="vh-col-act">
										<?php if ( current_user_can( Caps::RAISE_TICKET ) && empty( $f['ticket_key'] ) ) : ?>
											<button type="button" class="vh-btn vh-btn--sm" data-vh-raise data-vh-finding="<?php echo esc_attr( (string) $f['id'] ); ?>"><?php esc_html_e( 'Ticket', 'vulnhub' ); ?></button>
										<?php elseif ( ! empty( $f['ticket_key'] ) ) : ?>
											<a class="vh-mono" href="<?php echo esc_url( (string) $f['ticket_url'] ); ?>" target="_blank" rel="noopener noreferrer"><?php echo esc_html( (string) $f['ticket_key'] ); ?></a>
										<?php endif; ?>
									</td>
								</tr>
							<?php endforeach; ?>
							</tbody>
						</table>
					</div>
				<?php endif; ?>
			</section>
			<?php
			return;
		}

		// ---- list.
		$per   = 25;
		$paged = max( 1, self::qi( 'ap', 1 ) );
		$orderby = self::q( 'orderby' ) ?: 'risk_score';
		$order   = 'ASC' === strtoupper( self::q( 'order' ) ) ? 'ASC' : 'DESC';
		/*
		 * The last four have no control in the form. They exist so that a
		 * bar on a dashboard coverage chart can hand the reader the exact
		 * slice it was counting -- "the 146 workstations with a gap", "the
		 * 42 servers Tenable has never seen at this site". A chart that
		 * cannot be clicked through to its own rows is a picture, not a
		 * tool. What is applied is shown as removable chips below.
		 */
		/*
		 * One control, three questions. "Known by Intune" is the ordinary
		 * one; "only Intune" and "not in Intune" are the ones a reader asks
		 * when they suspect a feed has gone stale, and they are the reason
		 * this exists -- a record only the CMDB still believes in is either a
		 * machine that left the network or a row nobody retired.
		 */
		$vh_known  = self::q( 'known' );
		$vh_source = array( 'source' => '', 'without_source' => '', 'sole_source' => '' );

		if ( str_starts_with( $vh_known, 'only:' ) ) {
			$vh_source['source']      = substr( $vh_known, 5 );
			$vh_source['sole_source'] = '1';
		} elseif ( str_starts_with( $vh_known, 'not:' ) ) {
			$vh_source['without_source'] = substr( $vh_known, 4 );
		} elseif ( '' !== $vh_known ) {
			$vh_source['source'] = $vh_known;
		}

		/*
		 * Lifecycle scope, defaulting to the estate that is actually running.
		 *
		 * An inventory that lists every machine the organisation has ever
		 * owned is an archive, not an inventory -- and the whole point of
		 * decommissioning an asset is that it stops appearing in the work.
		 * `life=all` and `life=<status>` bring it back, and the header says
		 * how many rows the default is holding back so nothing is silently
		 * missing.
		 */
		$vh_life = self::q( 'life' );

		/*
		 * Validate before use, and say so when it fails.
		 *
		 * An unrecognised value used to reach Repo::assets() as a
		 * `lifecycle_status`, where vh_normalise_lifecycle() answered
		 * `unknown` for anything it did not recognise -- so `?life=typo`
		 * quietly returned the 194-asset Unknown list and presented it as
		 * though it were what had been asked for. A filter nobody chose is
		 * worse than an error, because the page looks like it worked.
		 */
		$vh_life_bad = '';
		$vh_life_ok  = array_merge(
			array( 'reportable', 'in_service_all', 'not_reported', 'retired_all', 'all' ),
			array_keys( vh_lifecycle_statuses() )
		);

		if ( '' !== $vh_life && ! in_array( $vh_life, $vh_life_ok, true ) ) {
			$vh_life_bad = $vh_life;
			$vh_life     = '';
		}

		$vh_scope = array(
			'lifecycle_status'    => '',
			'in_service_only'     => '',
			'out_of_service_only' => '',
			'reportable_only'     => '',
			'not_reportable_only' => '',
		);

		if ( '' === $vh_life || 'reportable' === $vh_life ) {
			// The default is the reporting scope, so the header on this page
			// and the number on the widget that linked here are one figure.
			$vh_scope['reportable_only'] = '1';
		} elseif ( 'in_service_all' === $vh_life ) {
			// The ownership scope: everything that should resolve to an owner,
			// quarantine and in-repair machines included.
			$vh_scope['in_service_only'] = '1';
		} elseif ( 'not_reported' === $vh_life ) {
			$vh_scope['not_reportable_only'] = '1';
		} elseif ( 'retired_all' === $vh_life ) {
			$vh_scope['out_of_service_only'] = '1';
		} elseif ( 'all' !== $vh_life ) {
			$vh_scope['lifecycle_status'] = $vh_life;
		}

		$args  = array_merge(
			self::assets_base_args( $vh_scope, $vh_source, $orderby, $order ),
			array(
				'limit'  => $per,
				'offset' => ( $paged - 1 ) * $per,
			)
		);
		$q     = Repo::assets( array_filter( $args, static fn( $v ): bool => '' !== $v && 0 !== $v ) );
		$pages = max( 1, (int) ceil( (int) $q['total'] / $per ) );
		?>
		<div class="vh-page-head">
			<div>
				<h1><?php esc_html_e( 'Assets &amp; owners', 'vulnhub' ); ?></h1>
				<?php $vh_own = Repo::summary(); ?>
				<p class="vh-sub">
					<?php
					printf(
						/* translators: %s: number of assets. */
						esc_html( _n( '%s asset in the inventory.', '%s assets in the inventory.', (int) $q['total'], 'vulnhub' ) ),
						'<strong>' . esc_html( number_format_i18n( (int) $q['total'] ) ) . '</strong>'
					);
					?>
					<?php if ( (int) $vh_own['assets_total'] > 0 ) : ?>
						<?php
						printf(
							/* translators: 1: assets with a named owner, 2: user-bound assets still missing one. */
							esc_html__( '%1$s have a named owner; %2$s still need one.', 'vulnhub' ),
							'<strong>' . esc_html( number_format_i18n( (int) $vh_own['assets_owned'] ) ) . '</strong>',
							'<a href="' . esc_url( self::page_url( 'assets', array( 'needs_user' => '1' ) ) ) . '">' . esc_html( number_format_i18n( (int) $vh_own['users_missing'] ) ) . '</a>'
						);
						?>
						<?php if ( (int) $vh_own['sites_missing'] > 0 ) : ?>
							<?php
							/*
							 * Alongside the owner gap, and for the same reason.
							 * An asset with no site is one nobody can send an
							 * engineer to -- and it is where coverage gaps
							 * accumulate unseen, because until the site filter
							 * existed the unplaced pile had no list of its own.
							 */
							printf(
								/* translators: %s: number of in-service assets with no site recorded. */
								esc_html__( '%s have no site recorded.', 'vulnhub' ),
								'<a href="' . esc_url( self::page_url( 'assets', array( 'location_id' => 'none' ) ) ) . '">'
									. esc_html( number_format_i18n( (int) $vh_own['sites_missing'] ) ) . '</a>'
							);
							?>
						<?php endif; ?>
					<?php endif; ?>
				</p>
				<?php
				/*
				 * A default filter nobody can see is a lie by omission. If the
				 * in-service default is hiding rows, the header says how many
				 * and offers them.
				 */
				$vh_hidden = ( '' === $vh_life || 'reportable' === $vh_life )
					? (int) Repo::assets( array( 'not_reportable_only' => '1', 'limit' => 1 ) )['total']
					: 0;
				?>
				<?php if ( '' !== $vh_life_bad ) : ?>
					<div class="vh-notice vh-notice--warn">
						<?php
						printf(
							/* translators: %s: the unrecognised value supplied in the URL. */
							esc_html__( '%s is not a lifecycle filter this page knows, so it has been ignored and the default reporting scope applied. Nothing below is filtered by it.', 'vulnhub' ),
							'<code>life=' . esc_html( $vh_life_bad ) . '</code>'
						);
						?>
					</div>
				<?php endif; ?>
				<?php if ( $vh_hidden > 0 ) : ?>
					<p class="vh-sub vh-muted">
						<?php
						printf(
							/* translators: %s: a link showing the hidden assets. */
							esc_html__( 'Showing the assets the dashboard reports on. %s hidden.', 'vulnhub' ),
							'<a href="' . esc_url( self::page_url( 'assets', array( 'life' => 'not_reported' ) ) ) . '">'
								. esc_html(
									sprintf(
										/* translators: %s: number of assets. */
										_n( '%s asset outside the reporting scope', '%s assets outside the reporting scope', $vh_hidden, 'vulnhub' ),
										number_format_i18n( $vh_hidden )
									)
								) . '</a>'
						);
						?>
					</p>
				<?php endif; ?>
			</div>
			<div class="vh-page-head__actions">
				<?php VulnHub_Dash_Export::button( 'assets', $args ); ?>
			</div>
		</div>

		<?php
		/*
		 * The reader arrived here from a bar on the end-of-life chart, so
		 * say which one. Without this the page reads as "104 assets in the
		 * inventory", which is a different and alarming claim.
		 */
		$vh_eol_key = self::q( 'eol' );
		?>
		<?php if ( '' !== $vh_eol_key ) : ?>
			<?php $vh_eol_row = \VulnHub\Core\Eol::table()[ $vh_eol_key ] ?? null; ?>
			<div class="vh-notice vh-notice--info">
				<?php
				if ( $vh_eol_row ) {
					$vh_eol_state = \VulnHub\Core\Eol::status( (string) $vh_eol_row['eol'] );

					printf(
						/* translators: 1: product and release, 2: status, 3: date. */
						esc_html__( 'Showing assets running %1$s. %2$s%3$s', 'vulnhub' ),
						'<strong>' . esc_html( trim( $vh_eol_row['product'] . ' ' . $vh_eol_row['release'] ) ) . '</strong>',
						esc_html( (string) $vh_eol_state['label'] ),
						(string) $vh_eol_row['eol'] ? esc_html( ' — ' . $vh_eol_row['eol'] . '.' ) : '.'
					);
				} else {
					esc_html_e( 'Showing assets whose operating system release the inventory does not record.', 'vulnhub' );
				}
				?>
				<a href="<?php echo esc_url( remove_query_arg( 'eol' ) ); ?>"><?php esc_html_e( 'Clear this filter', 'vulnhub' ); ?></a>
			</div>
		<?php endif; ?>

		<?php
		/*
		 * What just happened, in the numbers that matter: how many assets
		 * moved and how many findings went with them. A lifecycle change that
		 * silently removed two thousand findings from the totals would be
		 * indistinguishable from a bug.
		 */
		$vh_done = self::q( 'vh_life' );
		?>
		<?php if ( '' !== $vh_done ) : ?>
			<?php
			$vh_n_assets   = self::qi( 'vh_assets' );
			$vh_n_archived = self::qi( 'vh_archived' );
			$vh_n_restored = self::qi( 'vh_restored' );
			?>
			<div class="vh-notice <?php echo 'none' === $vh_done ? 'vh-notice--warn' : 'vh-notice--good'; ?>">
				<?php if ( 'none' === $vh_done ) : ?>
					<?php esc_html_e( 'Nothing was selected, so nothing changed.', 'vulnhub' ); ?>
				<?php else : ?>
					<?php
					printf(
						/* translators: 1: number of assets, 2: lifecycle status label. */
						esc_html( _n( '%1$s asset set to %2$s.', '%1$s assets set to %2$s.', $vh_n_assets, 'vulnhub' ) ),
						'<strong>' . esc_html( number_format_i18n( $vh_n_assets ) ) . '</strong>',
						esc_html( strtolower( (string) ( vh_lifecycle_statuses()[ $vh_done ]['label'] ?? $vh_done ) ) )
					);
					?>
					<?php if ( $vh_n_archived > 0 ) : ?>
						<?php
						printf(
							/* translators: %s: number of findings. */
							esc_html( _n( '%s finding archived and taken out of the totals.', '%s findings archived and taken out of the totals.', $vh_n_archived, 'vulnhub' ) ),
							'<strong>' . esc_html( number_format_i18n( $vh_n_archived ) ) . '</strong>'
						);
						?>
					<?php endif; ?>
					<?php if ( $vh_n_restored > 0 ) : ?>
						<?php
						printf(
							/* translators: %s: number of findings. */
							esc_html( _n( '%s finding brought back.', '%s findings brought back.', $vh_n_restored, 'vulnhub' ) ),
							'<strong>' . esc_html( number_format_i18n( $vh_n_restored ) ) . '</strong>'
						);
						?>
					<?php endif; ?>
				<?php endif; ?>
			</div>
		<?php endif; ?>

		<form class="vh-filters" method="get">
			<?php
			self::hidden_filters(
				/*
				 * The names this form owns, so they are not also written as
				 * hidden inputs. `has` and `missing` are deliberately absent:
				 * they have no control of their own, arrive from the source
				 * comparison screen, and must survive Apply -- which is exactly
				 * what being left out of this list does for them.
				 */
				array( 'search', 'asset_type', 'team_id', 'coverage', 'defender', 'known', 'life', 'needs_user', 'location_id', 'hosting' )
			);
			?>
			<label><?php esc_html_e( 'Search', 'vulnhub' ); ?>
				<input type="search" name="search" value="<?php echo esc_attr( self::q( 'search' ) ); ?>" placeholder="<?php esc_attr_e( 'hostname, IP, owner, serial…', 'vulnhub' ); ?>">
			</label>
			<label><?php esc_html_e( 'Type', 'vulnhub' ); ?>
				<select name="asset_type">
					<option value=""><?php esc_html_e( 'All types', 'vulnhub' ); ?></option>
					<?php foreach ( vh_asset_types() as $k => $l ) : ?>
						<option value="<?php echo esc_attr( $k ); ?>" <?php selected( self::q( 'asset_type' ), $k ); ?>><?php echo esc_html( $l ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label><?php esc_html_e( 'Team', 'vulnhub' ); ?>
				<select name="team_id">
					<option value="0"><?php esc_html_e( 'All teams', 'vulnhub' ); ?></option>
					<?php foreach ( Repo::teams() as $t ) : ?>
						<option value="<?php echo esc_attr( (string) $t['id'] ); ?>" <?php selected( self::qi( 'team_id' ), (int) $t['id'] ); ?>><?php echo esc_html( (string) $t['name'] ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<span><?php esc_html_e( 'Site', 'vulnhub' ); ?></span>
				<select name="location_id">
					<option value=""><?php esc_html_e( 'All sites', 'vulnhub' ); ?></option>
					<?php
					/*
					 * "No site recorded" is a first-class option, not an
					 * afterthought. It is the largest group on this estate and
					 * the one holding the most coverage gaps, and until this
					 * existed there was no way to ask for it from the UI at all.
					 */
					?>
					<option value="none" <?php selected( self::q( 'location_id' ), 'none' ); ?>>
						<?php esc_html_e( 'No site recorded', 'vulnhub' ); ?>
					</option>
					<?php foreach ( Repo::locations() as $vh_loc ) : ?>
						<option value="<?php echo esc_attr( (string) $vh_loc['id'] ); ?>" <?php selected( self::q( 'location_id' ), (string) $vh_loc['id'] ); ?>>
							<?php echo esc_html( (string) $vh_loc['name'] ); ?>
						</option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<span><?php esc_html_e( 'Scan coverage', 'vulnhub' ); ?></span>
				<select name="coverage">
					<option value=""><?php esc_html_e( 'Any coverage', 'vulnhub' ); ?></option>
					<option value="gap" <?php selected( self::q( 'coverage' ), 'gap' ); ?>><?php esc_html_e( 'Any coverage gap', 'vulnhub' ); ?></option>
					<?php foreach ( Coverage::states() as $vh_cov_state => $vh_cov_def ) : ?>
						<option value="<?php echo esc_attr( (string) $vh_cov_state ); ?>" <?php selected( self::q( 'coverage' ), (string) $vh_cov_state ); ?>>
							<?php echo esc_html( (string) $vh_cov_def['label'] ); ?>
						</option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<span><?php esc_html_e( 'Endpoint', 'vulnhub' ); ?></span>
				<select name="defender">
					<option value=""><?php esc_html_e( 'Any endpoint state', 'vulnhub' ); ?></option>
					<option value="gap" <?php selected( self::q( 'defender' ), 'gap' ); ?>><?php esc_html_e( 'No Defender sensor', 'vulnhub' ); ?></option>
					<?php foreach ( Defender_Coverage::states() as $vh_dcov_state => $vh_dcov_def ) : ?>
						<option value="<?php echo esc_attr( (string) $vh_dcov_state ); ?>" <?php selected( self::q( 'defender' ), (string) $vh_dcov_state ); ?>>
							<?php echo esc_html( (string) $vh_dcov_def['label'] ); ?>
						</option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<span><?php esc_html_e( 'Known by', 'vulnhub' ); ?></span>
				<select name="known">
					<option value=""><?php esc_html_e( 'Any source', 'vulnhub' ); ?></option>
					<optgroup label="<?php esc_attr_e( 'Known by', 'vulnhub' ); ?>">
						<?php foreach ( vh_asset_sources() as $vh_s => $vh_sl ) : ?>
							<option value="<?php echo esc_attr( $vh_s ); ?>" <?php selected( self::q( 'known' ), $vh_s ); ?>><?php echo esc_html( $vh_sl ); ?></option>
						<?php endforeach; ?>
					</optgroup>
					<optgroup label="<?php esc_attr_e( 'Known only by', 'vulnhub' ); ?>">
						<?php foreach ( vh_asset_sources() as $vh_s => $vh_sl ) : ?>
							<option value="only:<?php echo esc_attr( $vh_s ); ?>" <?php selected( self::q( 'known' ), 'only:' . $vh_s ); ?>>
								<?php
								printf(
									/* translators: %s: name of a source system. */
									esc_html__( '%s only', 'vulnhub' ),
									esc_html( $vh_sl )
								);
								?>
							</option>
						<?php endforeach; ?>
					</optgroup>
					<optgroup label="<?php esc_attr_e( 'Missing from', 'vulnhub' ); ?>">
						<?php foreach ( vh_asset_sources() as $vh_s => $vh_sl ) : ?>
							<option value="not:<?php echo esc_attr( $vh_s ); ?>" <?php selected( self::q( 'known' ), 'not:' . $vh_s ); ?>>
								<?php
								printf(
									/* translators: %s: name of a source system. */
									esc_html__( 'Not in %s', 'vulnhub' ),
									esc_html( $vh_sl )
								);
								?>
							</option>
						<?php endforeach; ?>
					</optgroup>
				</select>
			</label>
			<?php if ( class_exists( 'VulnHub_Hosting' ) ) : ?>
				<label>
					<span><?php esc_html_e( 'Hosting', 'vulnhub' ); ?></span>
					<select name="hosting">
						<option value=""><?php esc_html_e( 'Anywhere', 'vulnhub' ); ?></option>
						<?php foreach ( VulnHub_Hosting::environment_labels() as $vh_env => $vh_env_label ) : ?>
							<option value="<?php echo esc_attr( (string) $vh_env ); ?>" <?php selected( self::q( 'hosting' ), (string) $vh_env ); ?>>
								<?php echo esc_html( $vh_env_label ); ?>
							</option>
						<?php endforeach; ?>
					</select>
				</label>
			<?php endif; ?>
			<label>
				<span><?php esc_html_e( 'Lifecycle', 'vulnhub' ); ?></span>
				<select name="life">
					<option value=""><?php esc_html_e( 'Reporting scope (what the dashboard counts)', 'vulnhub' ); ?></option>
					<option value="in_service_all" <?php selected( self::q( 'life' ), 'in_service_all' ); ?>><?php esc_html_e( 'Everything with an owner expectation', 'vulnhub' ); ?></option>
					<option value="all" <?php selected( self::q( 'life' ), 'all' ); ?>><?php esc_html_e( 'Everything, including retired', 'vulnhub' ); ?></option>
					<option value="not_reported" <?php selected( self::q( 'life' ), 'not_reported' ); ?>><?php esc_html_e( 'Outside the reporting scope', 'vulnhub' ); ?></option>
					<option value="retired_all" <?php selected( self::q( 'life' ), 'retired_all' ); ?>><?php esc_html_e( 'Out of service only', 'vulnhub' ); ?></option>
					<?php foreach ( vh_lifecycle_statuses() as $vh_ls => $vh_lm ) : ?>
						<option value="<?php echo esc_attr( $vh_ls ); ?>" <?php selected( self::q( 'life' ), $vh_ls ); ?>><?php echo esc_html( (string) $vh_lm['label'] ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label class="vh-check">
				<input type="checkbox" name="needs_user" value="1" <?php checked( self::q( 'needs_user' ), '1' ); ?>>
				<?php esc_html_e( 'Missing a user', 'vulnhub' ); ?>
			</label>
			<button class="vh-btn"><?php esc_html_e( 'Apply', 'vulnhub' ); ?></button>
			<a class="vh-btn vh-btn--ghost" href="<?php echo esc_url( self::page_url( 'assets' ) ); ?>"><?php esc_html_e( 'Reset', 'vulnhub' ); ?></a>
		</form>

		<?php
		/*
		 * Filters that arrived from a dashboard chart have no control in the
		 * form above, so without this the reader sees a short list and no
		 * explanation for why. Each chip says what is narrowing the list and
		 * removes just itself.
		 */
		$vh_chips = array();

		foreach ( array(
			'primary_source'   => __( 'Discovered by', 'vulnhub' ),
			'operating_system' => __( 'Operating system', 'vulnhub' ),
			'patch_group'      => __( 'Patch group', 'vulnhub' ),
		) as $vh_key => $vh_label ) {
			$vh_value = self::q( $vh_key );

			if ( '' !== $vh_value ) {
				$vh_chips[ $vh_key ] = $vh_label . ': ' . $vh_value;
			}
		}

		if ( '' !== $vh_known ) {
			$vh_src_labels = vh_asset_sources();
			$vh_bare       = (string) preg_replace( '/^(only|not):/', '', $vh_known );
			$vh_src_name   = (string) ( $vh_src_labels[ $vh_bare ] ?? $vh_bare );

			if ( str_starts_with( $vh_known, 'only:' ) ) {
				/* translators: %s: name of a source system. */
				$vh_chips['known'] = sprintf( __( 'Known only by %s', 'vulnhub' ), $vh_src_name );
			} elseif ( str_starts_with( $vh_known, 'not:' ) ) {
				/* translators: %s: name of a source system. */
				$vh_chips['known'] = sprintf( __( 'Not in %s', 'vulnhub' ), $vh_src_name );
			} else {
				/* translators: %s: name of a source system. */
				$vh_chips['known'] = sprintf( __( 'Known by %s', 'vulnhub' ), $vh_src_name );
			}
		}

		/*
		 * The inventory-comparison filters. They arrive from the source
		 * comparison screen with no control of their own, and they are the
		 * filters most capable of misleading: a list of 210 assets headed
		 * "Assets & owners" with nothing saying "in Tenable, missing from the
		 * CMDB" reads as the whole estate. Named in words, both together when
		 * both are set, and removable as one.
		 */
		$vh_src_names = static function ( string $raw ): string {
			$labels = vh_asset_sources();
			$out    = array();

			foreach ( Repo::source_slugs( $raw ) as $vh_slug ) {
				$out[] = (string) ( $labels[ $vh_slug ] ?? $vh_slug );
			}

			return implode( ', ', $out );
		};

		$vh_has     = $vh_src_names( self::q( 'has' ) );
		$vh_missing = $vh_src_names( self::q( 'missing' ) );

		if ( '' !== $vh_has && '' !== $vh_missing ) {
			$vh_chips['has|missing'] = sprintf(
				/* translators: 1: systems the asset is in, 2: systems it is missing from. */
				__( 'In %1$s, not in %2$s', 'vulnhub' ),
				$vh_has,
				$vh_missing
			);
		} elseif ( '' !== $vh_has ) {
			/* translators: %s: one or more source systems. */
			$vh_chips['has'] = sprintf( __( 'In %s', 'vulnhub' ), $vh_has );
		} elseif ( '' !== $vh_missing ) {
			/* translators: %s: one or more source systems. */
			$vh_chips['missing'] = sprintf( __( 'Not in %s', 'vulnhub' ), $vh_missing );
		}

		$vh_loc = self::qi( 'location_id' );

		if ( $vh_loc > 0 ) {
			$vh_place = Repo::location( $vh_loc );
			$vh_chips['location_id'] = __( 'Site', 'vulnhub' ) . ': ' . (string) ( $vh_place['name'] ?? $vh_loc );
		}
		?>
		<?php if ( $vh_chips ) : ?>
			<p class="vh-chips">
				<?php foreach ( $vh_chips as $vh_key => $vh_text ) : ?>
					<?php
					// phpcs:ignore WordPress.Security.NonceVerification.Recommended
					$vh_rest = is_array( $_GET ) ? array_map( 'sanitize_text_field', wp_unslash( $_GET ) ) : array();
					unset( $vh_rest['ap'], $vh_rest['page_id'] );

					/*
					 * A chip may stand for more than one parameter -- "In
					 * Tenable, not in CMDB" is two -- and removing half of a
					 * sentence leaves the list filtered by something no chip
					 * now explains. The key carries every name it speaks for.
					 */
					foreach ( explode( '|', (string) $vh_key ) as $vh_drop ) {
						unset( $vh_rest[ $vh_drop ] );
					}
					?>
					<a class="vh-chip vh-chip--filter" href="<?php echo esc_url( self::page_url( 'assets', $vh_rest ) ); ?>">
						<?php echo esc_html( $vh_text ); ?>
						<span aria-hidden="true">&times;</span>
						<span class="screen-reader-text"><?php esc_html_e( 'Remove this filter', 'vulnhub' ); ?></span>
					</a>
				<?php endforeach; ?>
			</p>
		<?php endif; ?>

		<?php
		/*
		 * Decommissioning is a run, not a single act: somebody works down a
		 * filtered list of a hundred CMDB-only rows deciding which machines
		 * are really gone. So it is a bulk action on the list, not a button
		 * buried on each asset's own page.
		 *
		 * Gated on TRIAGE. A read-only viewer gets the same table without the
		 * checkbox column rather than a column of controls that refuse them.
		 */
		$vh_can_edit = current_user_can( \VulnHub\Core\Caps::TRIAGE );

		/*
		 * Outside the bulk form on purpose: the dialog holds a form of its
		 * own, and a form nested in a form is dropped by the parser.
		 */
		VulnHub_Dash_Tickets::raise_button( $args, (int) $q['total'] );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$vh_here     = self::page_url( 'assets', array_diff_key( is_array( $_GET ) ? array_map( 'sanitize_text_field', wp_unslash( $_GET ) ) : array(), array_flip( array( 'page_id', 'vh_life', 'vh_assets', 'vh_archived', 'vh_restored' ) ) ) );
		?>
		<?php if ( $vh_can_edit ) : ?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-bulk" data-vh-bulk>
			<input type="hidden" name="action" value="vulnhub_set_lifecycle">
			<input type="hidden" name="back" value="<?php echo esc_url( $vh_here ); ?>">
			<?php wp_nonce_field( 'vulnhub_set_lifecycle' ); ?>
		<?php endif; ?>

		<div class="vh-tablewrap vh-tablewrap--cards">
			<table class="vh-table">
				<thead><tr>
					<?php if ( $vh_can_edit ) : ?>
						<th class="vh-tick">
							<input type="checkbox" data-vh-tick-all aria-label="<?php esc_attr_e( 'Select every asset on this page', 'vulnhub' ); ?>">
						</th>
					<?php endif; ?>
					<?php self::sort_th( 'hostname', __( 'Host', 'vulnhub' ), $orderby, $order, 'assets' ); ?>
					<th>
						<?php esc_html_e( 'Scan coverage', 'vulnhub' ); ?>
						<span class="vh-th__src"><?php esc_html_e( 'Tenable', 'vulnhub' ); ?></span>
					</th>
					<th>
						<?php esc_html_e( 'EDR coverage', 'vulnhub' ); ?>
						<span class="vh-th__src"><?php esc_html_e( 'Defender', 'vulnhub' ); ?></span>
					</th>
					<th><?php esc_html_e( 'Known by', 'vulnhub' ); ?></th>
					<?php self::sort_th( 'asset_type', __( 'Type', 'vulnhub' ), $orderby, $order, 'assets' ); ?>
					<th><?php esc_html_e( 'Operating system', 'vulnhub' ); ?></th>
					<?php self::sort_th( 'owner_person_id', __( 'Owner', 'vulnhub' ), $orderby, $order, 'assets', self::owner_eye_html() ); ?>
					<th><?php esc_html_e( 'Team', 'vulnhub' ); ?></th>
					<?php self::sort_th( 'risk_score', __( 'Open exposure', 'vulnhub' ), $orderby, $order, 'assets' ); ?>
				</tr></thead>
				<tbody>
				<?php foreach ( $q['rows'] as $a ) : ?>
					<?php echo self::asset_row_html( $a, $vh_can_edit ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
				<?php endforeach; ?>
				<tr class="vh-sentinel" id="vh-assets-sentinel" data-vh-infinite="assets" data-offset="<?php echo esc_attr( (string) ( $paged * $per ) ); ?>" data-total="<?php echo esc_attr( (string) $q['total'] ); ?>" data-per="<?php echo esc_attr( (string) $per ); ?>" data-can-edit="<?php echo esc_attr( $vh_can_edit ? '1' : '0' ); ?>" aria-hidden="true"><td colspan="99"></td></tr>
				</tbody>
			</table>
		</div>

		<?php if ( $vh_can_edit ) : ?>
			<div class="vh-bulk__bar">
				<p class="vh-sub">
					<span data-vh-tick-count>0</span>
					<?php esc_html_e( 'selected.', 'vulnhub' ); ?>
					<span class="vh-muted"><?php esc_html_e( 'Decommissioning takes an asset out of scan coverage and archives its open findings, so the totals stop counting risk you no longer carry. Nothing is deleted, and returning an asset to service puts every finding back as it was.', 'vulnhub' ); ?></span>
				</p>
				<div class="vh-bulk__actions">
					<button type="submit" name="lifecycle" value="retired" class="vh-btn vh-btn--danger" data-vh-bulk-submit
						data-vh-confirm="<?php esc_attr_e( 'Mark the selected assets decommissioned? Their open findings will be archived and removed from every total. You can undo this by returning them to service.', 'vulnhub' ); ?>">
						<?php esc_html_e( 'Mark decommissioned', 'vulnhub' ); ?>
					</button>
					<button type="submit" name="lifecycle" value="in_service" class="vh-btn vh-btn--ghost" data-vh-bulk-submit>
						<?php esc_html_e( 'Return to service', 'vulnhub' ); ?>
					</button>
					<?php
					/*
					 * Its own field name, not a second control called `lifecycle`.
					 * A select and a submit button sharing one name both post, and
					 * PHP keeps whichever came last in the markup -- so an empty
					 * dropdown would quietly cancel the button the operator
					 * actually pressed.
					 */
					?>
					<label class="vh-bulk__more">
						<span class="screen-reader-text"><?php esc_html_e( 'Another status', 'vulnhub' ); ?></span>
						<select name="lifecycle_other" data-vh-bulk-select>
							<option value=""><?php esc_html_e( 'Another status…', 'vulnhub' ); ?></option>
							<?php foreach ( vh_lifecycle_statuses() as $vh_ls => $vh_lm ) : ?>
								<?php if ( in_array( $vh_ls, array( 'retired', 'in_service' ), true ) ) : continue; endif; ?>
								<option value="<?php echo esc_attr( $vh_ls ); ?>"><?php echo esc_html( (string) $vh_lm['label'] ); ?></option>
							<?php endforeach; ?>
						</select>
					</label>
					<button type="submit" name="apply_other" value="1" class="vh-btn vh-btn--ghost" data-vh-bulk-submit>
						<?php esc_html_e( 'Apply', 'vulnhub' ); ?>
					</button>
				</div>
			</div>
		</form>
		<?php endif; ?>

		<?php self::pager( $paged, $pages, 'ap' ); ?>
		<?php
	}

	/* ---------------------------------------------------------- tickets. */

	private static function view_tickets(): void {
		if ( self::qi( 'ticket' ) > 0 ) {
			VulnHub_Dash_Tickets::render_detail( self::qi( 'ticket' ) );
			return;
		}

		$s       = Repo::summary();
		$per     = 25;
		$paged   = max( 1, self::qi( 'tp', 1 ) );
		$vh_sla  = in_array( self::q( 'sla' ), array( 'met', 'on_track', 'breached', 'overdue', 'no_due' ), true ) ? self::q( 'sla' ) : '';
		$vh_tsev = in_array( self::q( 'tsev' ), array( 'critical', 'high', 'medium', 'low', 'asset' ), true ) ? self::q( 'tsev' ) : '';
		$vh_ids  = VulnHub_Dash_Ticket_Report::ids_for( $vh_sla, $vh_tsev );
		$q       = Tickets::query(
			array_filter(
				array(
					'ids'                => $vh_ids,
					'status_category'    => self::q( 'status_category' ),
					'verification_state' => self::q( 'verification_state' ),
					'kind'               => self::q( 'kind' ),
					'search'             => self::q( 'search' ),
					'limit'              => $per,
					'offset'             => ( $paged - 1 ) * $per,
				),
				static fn( $v ): bool => '' !== $v && null !== $v
			)
		);
		$pages = max( 1, (int) ceil( (int) $q['total'] / $per ) );
		?>
		<div class="vh-page-head">
			<div>
				<h1><?php esc_html_e( 'Remediation tickets', 'vulnhub' ); ?></h1>
				<p class="vh-sub"><?php esc_html_e( 'Every ticket raised from a finding or an asset list, and whether the data agrees the work is actually done.', 'vulnhub' ); ?></p>
			</div>
		</div>

		<?php VulnHub_Dash_Ticket_Report::render_coverage(); ?>
		<?php VulnHub_Dash_Ticket_Report::render_report(); ?>

		<h2 class="vh-trep__listhead" id="vh-ticket-list"><?php esc_html_e( 'All tickets', 'vulnhub' ); ?></h2>
		<section class="vh-tiles">
			<?php
			echo VulnHub_Dash_Charts::stat_tile( array( 'label' => __( 'Open', 'vulnhub' ), 'value' => (int) $s['tickets_open'], 'tone' => 'neutral' ) ); // phpcs:ignore
			echo VulnHub_Dash_Charts::stat_tile( array( 'label' => __( 'Closed', 'vulnhub' ), 'value' => (int) $s['tickets_done'], 'tone' => 'good' ) ); // phpcs:ignore
			echo VulnHub_Dash_Charts::stat_tile( array( 'label' => __( 'Awaiting verification', 'vulnhub' ), 'value' => (int) $s['awaiting_verify'], 'tone' => 'warning', 'meta' => __( 'closed in Jira, not yet re-scanned', 'vulnhub' ) ) ); // phpcs:ignore
			echo VulnHub_Dash_Charts::stat_tile( array( 'label' => __( 'Closed but still detected', 'vulnhub' ), 'value' => (int) $s['verify_failed'], 'tone' => (int) $s['verify_failed'] > 0 ? 'critical' : 'good', 'meta' => __( 'the scanner disagrees', 'vulnhub' ) ) ); // phpcs:ignore
			?>
		</section>

		<?php if ( '' !== $vh_sla || '' !== $vh_tsev ) : ?>
			<div class="vh-notice vh-notice--info">
				<?php
				$vh_parts = array();
				if ( '' !== $vh_tsev ) {
					$vh_parts[] = 'asset' === $vh_tsev ? __( 'asset requests', 'vulnhub' ) : sprintf( /* translators: %s: severity. */ __( '%s tickets', 'vulnhub' ), strtolower( vh_severity_label( $vh_tsev ) ) );
				}
				if ( '' !== $vh_sla ) {
					$vh_parts[] = strtolower( VulnHub_Dash_Ticket_Report::sla_label( $vh_sla ) );
				}
				/* translators: %s: description of the filter. */
				echo esc_html( sprintf( __( 'Showing %s.', 'vulnhub' ), implode( ', ', $vh_parts ) ) );
				?>
				<a href="<?php echo esc_url( remove_query_arg( array( 'sla', 'tsev', 'tp' ) ) ); ?>"><?php esc_html_e( 'Clear this filter', 'vulnhub' ); ?></a>
			</div>
		<?php endif; ?>

		<form class="vh-filters" method="get">
			<?php self::hidden_filters( array( 'search', 'status_category', 'verification_state', 'kind' ) ); ?>
			<label><?php esc_html_e( 'Search', 'vulnhub' ); ?>
				<input type="search" name="search" value="<?php echo esc_attr( self::q( 'search' ) ); ?>" placeholder="<?php esc_attr_e( 'key or summary…', 'vulnhub' ); ?>">
			</label>
			<label><?php esc_html_e( 'Status', 'vulnhub' ); ?>
				<select name="status_category">
					<option value=""><?php esc_html_e( 'All', 'vulnhub' ); ?></option>
					<option value="new" <?php selected( self::q( 'status_category' ), 'new' ); ?>><?php esc_html_e( 'To do', 'vulnhub' ); ?></option>
					<option value="indeterminate" <?php selected( self::q( 'status_category' ), 'indeterminate' ); ?>><?php esc_html_e( 'In progress', 'vulnhub' ); ?></option>
					<option value="done" <?php selected( self::q( 'status_category' ), 'done' ); ?>><?php esc_html_e( 'Done', 'vulnhub' ); ?></option>
				</select>
			</label>
			<label><?php esc_html_e( 'Request type', 'vulnhub' ); ?>
				<select name="kind">
					<option value=""><?php esc_html_e( 'All', 'vulnhub' ); ?></option>
					<?php foreach ( Tickets::kinds() as $vh_kind => $vh_kind_def ) : ?>
						<option value="<?php echo esc_attr( (string) $vh_kind ); ?>" <?php selected( self::q( 'kind' ), (string) $vh_kind ); ?>><?php echo esc_html( (string) $vh_kind_def['label'] ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label><?php esc_html_e( 'Verification', 'vulnhub' ); ?>
				<select name="verification_state">
					<option value=""><?php esc_html_e( 'All', 'vulnhub' ); ?></option>
					<?php foreach ( Tickets::verification_labels() as $k => $l ) : ?>
						<option value="<?php echo esc_attr( $k ); ?>" <?php selected( self::q( 'verification_state' ), $k ); ?>><?php echo esc_html( $l ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<button class="vh-btn"><?php esc_html_e( 'Apply', 'vulnhub' ); ?></button>
			<a class="vh-btn vh-btn--ghost" href="<?php echo esc_url( self::page_url( 'tickets' ) ); ?>"><?php esc_html_e( 'Reset', 'vulnhub' ); ?></a>
		</form>

		<?php if ( VulnHub_Dash_Tickets::can_check() ) : ?>
			<div class="vh-check-bar">
				<button type="button" class="vh-btn vh-btn--sm" data-vh-check-all><?php esc_html_e( 'Verify all tickets', 'vulnhub' ); ?></button>
				<span class="vh-meta"><?php esc_html_e( 'Verify reads each ticket\'s status from Jira, rescans its network-scanned workstations in Tenable and re-checks its findings. Servers are never rescanned from here, and agent-based machines are checked on their latest results. Tickets already verified fixed are skipped. Without anyone pressing Verify, each ticket is checked at 10:00 the morning after its assets\' scheduled Tenable scan runs, and on its due date.', 'vulnhub' ); ?></span>
			</div>
			<?php echo VulnHub_Dash_Tickets::check_panel(); // phpcs:ignore WordPress.Security.EscapeOutput ?>
		<?php endif; ?>

		<?php if ( ! $q['rows'] ) : ?>
			<p class="vh-chart-empty"><?php esc_html_e( 'No tickets match. Raise one from the Vulnerabilities screen, or from a filtered list on Assets & owners.', 'vulnhub' ); ?></p>
		<?php else : ?>
			<div class="vh-tablewrap">
				<table class="vh-table">
					<thead><tr>
						<th><?php esc_html_e( 'Key', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Type', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Summary', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Status', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Assignee', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Covers', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Verification', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Last check', 'vulnhub' ); ?></th>
						<?php if ( VulnHub_Dash_Tickets::can_check() ) : ?><th><span class="screen-reader-text"><?php esc_html_e( 'Verify', 'vulnhub' ); ?></span></th><?php endif; ?>
					</tr></thead>
					<tbody>
					<?php foreach ( $q['rows'] as $t ) : ?>
						<?php
						$vstate = (string) $t['verification_state'];
						$vtone  = match ( $vstate ) {
							Tickets::VERIFY_CONFIRMED  => 'good',
							Tickets::VERIFY_STILL_OPEN => 'bad',
							Tickets::VERIFY_PENDING    => 'warn',
							default                    => 'neutral',
						};
						?>
						<tr>
							<td>
								<a class="vh-mono" href="<?php echo esc_url( self::page_url( 'tickets', array( 'ticket' => (int) $t['id'] ) ) ); ?>"><strong><?php echo esc_html( (string) $t['external_key'] ); ?></strong></a>
								<?php if ( '' !== (string) $t['url'] ) : ?>
									<a class="vh-meta" href="<?php echo esc_url( (string) $t['url'] ); ?>" target="_blank" rel="noopener noreferrer" aria-label="<?php esc_attr_e( 'Open in Jira', 'vulnhub' ); ?>">&nearr;</a>
								<?php endif; ?>
							</td>
							<td><?php echo esc_html( Tickets::kind_label( (string) $t['kind'] ) ); ?></td>
							<td><?php echo esc_html( vh_trim( (string) $t['summary'], 78 ) ); ?></td>
							<td><span class="vh-chip vh-chip--<?php echo 'done' === $t['status_category'] ? 'good' : 'neutral'; ?>"><?php echo esc_html( (string) $t['status'] ); ?></span></td>
							<td><?php echo esc_html( (string) ( $t['assignee'] ?: '—' ) ); ?></td>
							<td>
								<?php
								echo esc_html(
									(int) $t['asset_count'] > 0
										/* translators: %s: number of assets. */
										? sprintf( _n( '%s asset', '%s assets', (int) $t['asset_count'], 'vulnhub' ), number_format_i18n( (int) $t['asset_count'] ) )
										/* translators: %s: number of findings. */
										: sprintf( _n( '%s finding', '%s findings', (int) $t['finding_count'], 'vulnhub' ), number_format_i18n( (int) $t['finding_count'] ) )
								);
								?>
							</td>
							<td><span class="vh-chip vh-chip--<?php echo esc_attr( $vtone ); ?>"><?php echo esc_html( Tickets::verification_labels()[ $vstate ] ?? '—' ); ?></span></td>
							<td><?php echo VulnHub_Dash_Tickets::last_check_html( $t ); // phpcs:ignore WordPress.Security.EscapeOutput ?></td>
							<?php if ( VulnHub_Dash_Tickets::can_check() ) : ?><td><?php echo VulnHub_Dash_Tickets::verify_button( $t ); // phpcs:ignore WordPress.Security.EscapeOutput ?></td><?php endif; ?>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			</div>
			<?php self::pager( $paged, $pages, 'tp' ); ?>
		<?php endif; ?>
		<?php
	}

	/* ------------------------------------------------------- exceptions. */

	private static function view_exceptions(): void {
		/*
		 * Requesting an exception (?new=1&finding=…) and deciding one
		 * (?exception=…) are core's screens. Drawn here in place, so the Except
		 * button on a finding and the Ref link below never leave the portal;
		 * exceptions_url_in_portal() keeps that screen's own links and
		 * post-save redirect here too. Its REST calls go through wp.apiFetch,
		 * which app.js already depends on.
		 */
		$vh_new_ok = isset( $_GET['new'] ) && current_user_can( Caps::REQUEST_EXCEPTION ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( $vh_new_ok || self::qi( 'exception' ) > 0 ) {
			echo '<div class="vh-page-head"><div><h1>' . esc_html( $vh_new_ok ? __( 'Request an exception', 'vulnhub' ) : __( 'Exception', 'vulnhub' ) ) . '</h1></div></div>';
			echo '<div class="vh-core-screen">';
			vulnhub()->admin->render_screen( 'vulnhub-exceptions' );
			echo '</div>';
			return;
		}

		$s = Repo::summary();
		$q = Exceptions::query( array( 'status' => self::q( 'status' ), 'limit' => 100 ) );
		?>
		<div class="vh-page-head">
			<div>
				<h1><?php esc_html_e( 'Exception register', 'vulnhub' ); ?></h1>
				<p class="vh-sub"><?php esc_html_e( 'Time-boxed, justified risk acceptances. Nothing is hidden — an expired exception puts its findings straight back into the open count.', 'vulnhub' ); ?></p>
			</div>
			<?php if ( current_user_can( Caps::REQUEST_EXCEPTION ) ) : ?>
				<a class="vh-btn vh-btn--primary" href="<?php echo esc_url( self::page_url( 'vulnerabilities' ) ); ?>"><?php esc_html_e( 'Find a finding to except', 'vulnhub' ); ?></a>
			<?php endif; ?>
		</div>

		<?php if ( '' !== self::q( 'vh_msg' ) ) : // Set by core's request and decision screens after they save. ?>
			<p class="vh-flash vh-flash--good" role="status"><?php echo esc_html( self::q( 'vh_msg' ) ); ?></p>
		<?php endif; ?>

		<section class="vh-tiles">
			<?php
			echo VulnHub_Dash_Charts::stat_tile( array( 'label' => __( 'Awaiting approval', 'vulnhub' ), 'value' => (int) $s['exceptions_open'], 'tone' => (int) $s['exceptions_open'] > 0 ? 'warning' : 'neutral' ) ); // phpcs:ignore
			echo VulnHub_Dash_Charts::stat_tile( array( 'label' => __( 'Active', 'vulnhub' ), 'value' => (int) $s['exceptions_active'], 'tone' => 'neutral' ) ); // phpcs:ignore
			echo VulnHub_Dash_Charts::stat_tile( array( 'label' => __( 'Findings suppressed', 'vulnhub' ), 'value' => (int) $s['excepted'], 'tone' => 'neutral', 'meta' => __( 'still tracked, not counted as open', 'vulnhub' ) ) ); // phpcs:ignore
			echo VulnHub_Dash_Charts::stat_tile( array( 'label' => __( 'Expiring in 30 days', 'vulnhub' ), 'value' => (int) Exceptions::query( array( 'expiring_days' => 30, 'limit' => 1 ) )['total'], 'tone' => 'warning' ) ); // phpcs:ignore
			?>
		</section>

		<?php
		/*
		 * The status filter existed in the query for a long time with no way
		 * to reach it except by typing the query string. A register you can
		 * only narrow by hand-editing the URL is a register nobody narrows.
		 */
		?>
		<form class="vh-filters" method="get">
			<?php self::hidden_filters( array( 'status' ) ); ?>
			<label><?php esc_html_e( 'Status', 'vulnhub' ); ?>
				<select name="status">
					<option value=""><?php esc_html_e( 'All statuses', 'vulnhub' ); ?></option>
					<?php foreach ( Exceptions::statuses() as $vh_st => $vh_st_label ) : ?>
						<option value="<?php echo esc_attr( (string) $vh_st ); ?>" <?php selected( self::q( 'status' ), (string) $vh_st ); ?>>
							<?php echo esc_html( (string) $vh_st_label ); ?>
						</option>
					<?php endforeach; ?>
				</select>
			</label>
			<button class="vh-btn"><?php esc_html_e( 'Apply', 'vulnhub' ); ?></button>
			<a class="vh-btn vh-btn--ghost" href="<?php echo esc_url( self::page_url( 'exceptions' ) ); ?>"><?php esc_html_e( 'Reset', 'vulnhub' ); ?></a>
		</form>

		<?php if ( ! $q['rows'] ) : ?>
			<p class="vh-chart-empty">
				<?php
				echo esc_html(
					'' !== self::q( 'status' )
						? __( 'No exceptions with that status.', 'vulnhub' )
						: __( 'No exceptions on record. Raise one from a finding when remediation genuinely is not possible.', 'vulnhub' )
				);
				?>
			</p>
		<?php else : ?>
			<div class="vh-tablewrap">
				<table class="vh-table">
					<thead><tr>
						<th><?php esc_html_e( 'Ref', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Title', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Reason', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Findings', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Status', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Requested by', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Expires', 'vulnhub' ); ?></th>
					</tr></thead>
					<tbody>
					<?php foreach ( $q['rows'] as $e ) : ?>
						<tr>
							<td class="vh-mono"><strong><a href="<?php echo esc_url( self::page_url( 'exceptions', array( 'exception' => (int) $e['id'] ) ) ); ?>"><?php echo esc_html( (string) $e['reference'] ); ?></a></strong></td>
							<td><?php echo esc_html( vh_trim( (string) $e['title'], 62 ) ); ?></td>
							<td class="vh-sub"><?php echo esc_html( Exceptions::reasons()[ (string) $e['reason'] ] ?? '' ); ?></td>
							<td><?php echo esc_html( number_format_i18n( (int) $e['affected_count'] ) ); ?></td>
							<td>
								<?php
								$tone = match ( (string) $e['status'] ) {
									'approved' => 'good',
									'pending'  => 'warn',
									'rejected', 'revoked' => 'bad',
									default    => 'neutral',
								};
								?>
								<span class="vh-chip vh-chip--<?php echo esc_attr( $tone ); ?>"><?php echo esc_html( Exceptions::statuses()[ (string) $e['status'] ] ?? '' ); ?></span>
							</td>
							<td><?php echo esc_html( (string) $e['requested_by_name'] ); ?></td>
							<td><?php echo esc_html( $e['expires_at'] ? vh_date( (string) $e['expires_at'], 'j M Y' ) : '—' ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		<?php endif; ?>
		<?php
	}

	/* -----------------------------------------------------------------
	 * Shared bits
	 * --------------------------------------------------------------- */

	/**
	 * Carry the filters this form has no control for.
	 *
	 * A GET form submits its own fields and nothing else, so pressing Apply
	 * on a list reached from a chart used to throw away whichever filter the
	 * chart applied. Arriving on 5,361 findings from the attack-path widget
	 * and narrowing to Critical silently dropped `route` and `poc` and
	 * returned 2,459 -- a different question, answered without saying so.
	 *
	 * Anything already in the query string that the form cannot express is
	 * re-submitted as a hidden field. Paging keys are deliberately not: page
	 * four of the old filter is not page four of the new one.
	 *
	 * @param string[] $own Field names this form already renders.
	 */
	/**
	 * The filters currently in the query string, for building a link that
	 * changes one of them and keeps the rest.
	 *
	 * Paging keys are left out for the same reason hidden_filters() drops
	 * them: page four of the old filter is not page four of the new one.
	 *
	 * @param string[] $keys Query keys worth carrying.
	 * @return array<string,string>
	 */
	private static function current_filters( array $keys ): array {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$get = is_array( $_GET ) ? wp_unslash( $_GET ) : array();
		$out = array();

		foreach ( $keys as $key ) {
			if ( isset( $get[ $key ] ) && ! is_array( $get[ $key ] ) && '' !== $get[ $key ] ) {
				$out[ $key ] = sanitize_text_field( (string) $get[ $key ] );
			}
		}

		return $out;
	}

	private static function hidden_filters( array $own ): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$get  = is_array( $_GET ) ? wp_unslash( $_GET ) : array();
		$skip = array_merge( $own, array( 'page_id', 'ap', 'vp', 'tp', 'ep', 'paged', 'asset', 'vuln', 'ticket', 'raise_ticket', 'vh_ticket_err', 'vh_ticket_key', 'tap', 'outcome' ) );

		foreach ( $get as $key => $value ) {
			if ( is_array( $value ) || in_array( (string) $key, $skip, true ) ) {
				continue;
			}

			$name = sanitize_key( (string) $key );

			if ( '' === $name ) {
				continue;
			}

			printf(
				'<input type="hidden" name="%s" value="%s">',
				esc_attr( $name ),
				esc_attr( sanitize_text_field( (string) $value ) )
			);
		}
	}

	private static function pager( int $current, int $pages, string $key ): void {
		if ( $pages < 2 ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$base = remove_query_arg( $key, add_query_arg( array_map( 'sanitize_text_field', wp_unslash( $_GET ) ) ) );

		echo '<nav class="vh-pager" aria-label="' . esc_attr__( 'Pagination', 'vulnhub' ) . '">';
		if ( $current > 1 ) {
			echo '<a class="vh-btn vh-btn--ghost" href="' . esc_url( add_query_arg( $key, $current - 1, $base ) ) . '">&larr; ' . esc_html__( 'Previous', 'vulnhub' ) . '</a>';
		}
		printf(
			'<span class="vh-pager__count">%s</span>',
			esc_html(
				sprintf(
					/* translators: 1: current page, 2: total pages. */
					__( 'Page %1$d of %2$d', 'vulnhub' ),
					$current,
					$pages
				)
			)
		);
		if ( $current < $pages ) {
			echo '<a class="vh-btn vh-btn--ghost" href="' . esc_url( add_query_arg( $key, $current + 1, $base ) ) . '">' . esc_html__( 'Next', 'vulnhub' ) . ' &rarr;</a>';
		}
		echo '</nav>';
	}
}

