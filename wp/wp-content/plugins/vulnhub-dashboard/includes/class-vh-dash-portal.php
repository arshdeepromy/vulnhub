<?php
/**
 * Portal authentication and the front-end admin area.
 *
 * The goal is a clean separation: wp-admin is for WordPress itself, and every
 * VulnHub task — including configuring integrations, importing data and editing
 * rules — happens in the portal at the product's own domain. A user whose only
 * role is a VulnHub one never sees a WordPress screen.
 *
 * @package VulnHub\Dashboard
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Dash_Portal {

	public const LOGIN_VIEW = 'login';
	public const ADMIN_VIEW = 'admin';

	/**
	 * wp-admin screens the portal already covers with a section of its own,
	 * or that live in the primary navigation rather than the admin shell.
	 * Everything else is mirrored automatically.
	 *
	 * @var string[]
	 */
	private const ADMIN_PAGES_HANDLED_ELSEWHERE = array(
		'vulnhub',
		'vulnhub-findings',
		'vulnhub-assets',
		'vulnhub-ownership',
		'vulnhub-tickets',
		'vulnhub-exceptions',
		'vulnhub-integrations',
		'vulnhub-sync',
		'vulnhub-audit',
		'vulnhub-settings',
	);

	/** Prefix that marks a section as a mirrored wp-admin screen. */
	public const MIRROR_PREFIX = 'screen-';

	public static function init(): void {
		add_action( 'template_redirect', array( __CLASS__, 'guard_portal' ) );
		add_action( 'admin_init', array( __CLASS__, 'keep_portal_users_out_of_wp_admin' ), 1 );
		add_action( 'admin_page_access_denied', array( __CLASS__, 'keep_portal_users_out_of_wp_admin' ), 1 );
		add_filter( 'login_redirect', array( __CLASS__, 'after_login' ), 10, 3 );
		add_filter( 'logout_redirect', array( __CLASS__, 'after_logout' ), 10, 3 );
		add_action( 'wp_before_admin_bar_render', array( __CLASS__, 'tidy_admin_bar' ) );
		add_action( 'template_redirect', array( __CLASS__, 'handle_login_post' ) );
		add_action( 'wp', array( __CLASS__, 'hide_wp_chrome_in_portal' ) );
		add_filter( 'vulnhub_admin_screen_url', array( __CLASS__, 'keep_redirects_in_portal' ), 10, 3 );
	}

	/**
	 * The portal is the product; WordPress is the frame it is built on, and
	 * the operator should never see the frame. Hide the admin bar on every
	 * portal page, for everyone -- an administrator looking at the security
	 * dashboard is not administering WordPress.
	 */
	public static function hide_wp_chrome_in_portal(): void {
		if ( is_admin() || ! is_singular() ) {
			return;
		}
		if ( '' === VulnHub_Dash_App::view_for_post( get_post() ) ) {
			return;
		}

		show_admin_bar( false );
		add_filter( 'show_admin_bar', '__return_false', 99 );
	}

	/**
	 * Send an admin-screen redirect back into the portal when that is where
	 * the operator started.
	 *
	 * @param string               $url  Default wp-admin URL.
	 * @param string               $page Screen slug.
	 * @param array<string,scalar> $args Query arguments.
	 */
	public static function keep_redirects_in_portal( string $url, string $page, array $args ): string {
		if ( ! self::request_came_from_portal() ) {
			return $url;
		}

		$section = self::section_for_admin_page( $page );

		return $section
			? self::portal_url( self::ADMIN_VIEW, array_merge( array( 'section' => $section ), $args ) )
			: $url;
	}

	/**
	 * Did this request originate on a portal screen?
	 *
	 * A form rendered by the portal posts to admin-post.php exactly like a
	 * wp-admin one, so the referer is the only honest signal available by the
	 * time the handler runs.
	 */
	private static function request_came_from_portal(): bool {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( ! empty( $_REQUEST['vh_from_portal'] ) ) {
			return true;
		}

		$referer = (string) wp_get_referer();

		if ( '' === $referer ) {
			return false;
		}

		return str_contains( $referer, wp_parse_url( self::portal_url( self::ADMIN_VIEW ), PHP_URL_PATH ) ?: '###' );
	}

	/**
	 * The portal section slug that mirrors a wp-admin screen, or '' if the
	 * screen is not mirrored.
	 */
	public static function section_for_admin_page( string $page ): string {
		if ( in_array( $page, self::ADMIN_PAGES_HANDLED_ELSEWHERE, true ) ) {
			return self::native_section_for( $page );
		}

		return self::MIRROR_PREFIX . $page;
	}

	/** Portal sections that already existed before the mirror. */
	private static function native_section_for( string $page ): string {
		$map = array(
			'vulnhub-integrations' => 'integrations',
			'vulnhub-sync'         => 'activity',
			'vulnhub-audit'        => 'audit',
			'vulnhub-settings'     => 'settings',
		);

		return $map[ $page ] ?? '';
	}

	/**
	 * Every VulnHub admin screen an integration registered, as a portal
	 * section.
	 *
	 * Integration plugins register their screens on `vulnhub_admin_pages` and
	 * draw them on `vulnhub_render_admin_page`. Mirroring that contract here
	 * rather than asking each plugin to register twice means Tenable, Intune,
	 * Jira, CMDB, Automation and Authentication are all configurable from the
	 * portal without a line of change in any of them -- and the next
	 * integration is too, for free.
	 *
	 * @return array<string,array<string,mixed>>
	 */
	private static function mirrored_sections(): array {
		if ( ! function_exists( 'vulnhub' ) || ! isset( vulnhub()->admin ) ) {
			return array();
		}

		$out   = array();
		$order = 100;

		foreach ( (array) vulnhub()->admin->pages() as $slug => $page ) {
			if ( in_array( $slug, self::ADMIN_PAGES_HANDLED_ELSEWHERE, true ) ) {
				continue;
			}

			/*
			 * Authentication and the end-of-life table are platform policy,
			 * not data sources. Filing them under Integrations would put
			 * "when does Windows 10 stop getting patches" next to a Jira
			 * API token, which is where settings go to be lost.
			 */
			$group = str_contains( $slug, 'auth' ) || str_contains( $slug, 'lifecycle' )
				? 'platform'
				: 'integrations';

			$out[ self::MIRROR_PREFIX . $slug ] = array(
				'label'   => wp_strip_all_tags( (string) ( $page['menu'] ?? $slug ) ),
				'cap'     => (string) ( $page['cap'] ?? Caps::MANAGE ),
				'group'   => $group,
				'order'   => 'platform' === $group ? 15 : $order,
				'summary' => wp_strip_all_tags( (string) ( $page['title'] ?? '' ) ),
				'screen'  => $slug,
			);

			$order += 5;
		}

		return $out;
	}

	/* -----------------------------------------------------------------
	 * Where people land
	 * --------------------------------------------------------------- */

	public static function portal_url( string $view = 'dashboard', array $args = array() ): string {
		$pages = (array) get_option( 'vulnhub_dash_pages', array() );
		$base  = ! empty( $pages[ $view ] ) ? (string) get_permalink( (int) $pages[ $view ] ) : home_url( '/' );

		return $args ? add_query_arg( $args, $base ) : $base;
	}

	public static function login_url( string $redirect_to = '' ): string {
		$url = self::portal_url( self::LOGIN_VIEW );
		return $redirect_to ? add_query_arg( 'redirect_to', rawurlencode( $redirect_to ), $url ) : $url;
	}

	/**
	 * Someone who only holds VulnHub roles has no business in wp-admin, and
	 * sending them there is how a security tool starts looking like a blog.
	 * WordPress administrators are deliberately left alone.
	 */
	public static function is_portal_only_user( ?WP_User $user = null ): bool {
		$user = $user ?: wp_get_current_user();

		if ( ! $user || ! $user->ID ) {
			return false;
		}
		if ( user_can( $user, 'manage_options' ) ) {
			return false;
		}
		return user_can( $user, Caps::VIEW );
	}

	/**
	 * Fired from `admin_init` and from `admin_page_access_denied`.
	 *
	 * The second hook matters more than it looks. `wp-admin/menu.php` is
	 * required at line 163 of `wp-admin/admin.php`, seventeen lines *before*
	 * `do_action( 'admin_init' )`, and it calls `user_can_access_admin_page()`
	 * itself. So any screen a portal-only person cannot hold the capability
	 * for -- plugins.php, themes.php, users.php -- dies with a bare WordPress
	 * 403 before our `admin_init` redirect ever gets a turn. Catching
	 * `admin_page_access_denied` is the only seam WordPress offers between
	 * that check and the `wp_die()` on the next line.
	 */
	public static function keep_portal_users_out_of_wp_admin(): void {
		if ( wp_doing_ajax() || ! is_admin() ) {
			return;
		}

		/*
		 * admin-post.php and admin-ajax.php are endpoints, not screens. Every
		 * form the portal renders posts to admin-post.php, so redirecting
		 * them here meant a portal-only user could not save anything at all
		 * -- the submission was swallowed and they landed on the dashboard.
		 */
		$script = basename( (string) ( $_SERVER['SCRIPT_NAME'] ?? '' ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		if ( in_array( $script, array( 'admin-post.php', 'admin-ajax.php' ), true ) ) {
			return;
		}

		if ( ! self::is_portal_only_user() ) {
			return;
		}

		wp_safe_redirect( self::portal_url() );
		exit;
	}

	/**
	 * @param string           $redirect_to Requested destination.
	 * @param string           $requested   Raw request.
	 * @param WP_User|WP_Error $user        Authenticated user.
	 */
	public static function after_login( string $redirect_to, string $requested, $user ): string {
		unset( $requested );

		if ( ! $user instanceof WP_User ) {
			return $redirect_to;
		}
		// An explicit destination inside the site is always honoured.
		if ( $redirect_to && ! str_contains( $redirect_to, 'wp-admin' ) ) {
			return $redirect_to;
		}
		if ( self::is_portal_only_user( $user ) ) {
			return self::portal_url();
		}
		return $redirect_to;
	}

	/**
	 * @param string           $redirect_to Requested destination.
	 * @param string           $requested   Raw request.
	 * @param WP_User|WP_Error $user        The user logging out.
	 */
	public static function after_logout( string $redirect_to, string $requested, $user ): string {
		unset( $requested, $user );
		return $redirect_to ?: self::login_url();
	}

	public static function tidy_admin_bar(): void {
		global $wp_admin_bar;

		if ( ! self::is_portal_only_user() || ! $wp_admin_bar ) {
			return;
		}
		foreach ( array( 'wp-logo', 'comments', 'new-content', 'edit', 'site-name', 'updates', 'search' ) as $node ) {
			$wp_admin_bar->remove_node( $node );
		}
	}

	/* -----------------------------------------------------------------
	 * Login
	 * --------------------------------------------------------------- */

	/**
	 * Handle a submission from the portal's own sign-in form.
	 *
	 * Deliberately delegates to wp_signon() rather than reimplementing
	 * authentication, so the MFA challenge, SSO enforcement, LDAP bind and
	 * lockout logic in vulnhub-auth all still apply exactly as they do on
	 * wp-login.php.
	 */
	public static function handle_login_post(): void {
		if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) {
			return;
		}
		if ( ! isset( $_POST['vh_login_nonce'] ) ) {
			return;
		}
		if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['vh_login_nonce'] ) ), 'vulnhub_portal_login' ) ) {
			self::redirect_login( __( 'That sign-in form expired. Please try again.', 'vulnhub' ) );
		}

		$creds = array(
			'user_login'    => isset( $_POST['log'] ) ? sanitize_user( wp_unslash( $_POST['log'] ) ) : '',
			'user_password' => isset( $_POST['pwd'] ) ? (string) wp_unslash( $_POST['pwd'] ) : '',
			'remember'      => isset( $_POST['rememberme'] ),
		);

		if ( '' === $creds['user_login'] || '' === $creds['user_password'] ) {
			self::redirect_login( __( 'Enter both your username and your password.', 'vulnhub' ) );
		}

		$user = wp_signon( $creds, is_ssl() );

		if ( is_wp_error( $user ) ) {
			// WordPress error strings carry markup and internal links; keep the
			// portal's message plain and non-enumerating.
			self::redirect_login( __( 'Those credentials were not accepted.', 'vulnhub' ) );
		}

		wp_set_current_user( $user->ID );

		$requested = isset( $_POST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_POST['redirect_to'] ) ) : '';
		$target    = $requested ?: self::portal_url();

		wp_safe_redirect( $target );
		exit;
	}

	private static function redirect_login( string $message ): void {
		wp_safe_redirect( add_query_arg( 'vh_err', rawurlencode( $message ), self::login_url() ) );
		exit;
	}

	/**
	 * The single-sign-on start URL, if any provider is switched on.
	 *
	 * The auth plugin owns SSO and may not be installed, so this asks rather
	 * than assumes. An empty string means the button renders but does not
	 * pretend to work.
	 */
	private static function sso_start_url( string $redirect ): string {
		if ( ! class_exists( 'VulnHub_Auth_SSO' ) ) {
			return '';
		}

		foreach ( \VulnHub_Auth_SSO::provider_ids() as $provider ) {
			if ( ! \VulnHub_Auth_SSO::is_active( $provider ) ) {
				continue;
			}

			$args = array(
				'action'   => \VulnHub_Auth_SSO::ACTION_START,
				'provider' => $provider,
			);

			if ( '' !== $redirect ) {
				$args['redirect_to'] = $redirect;
			}

			return add_query_arg( $args, site_url( 'wp-login.php', 'login' ) );
		}

		return '';
	}

	/**
	 * The sign-in screen.
	 *
	 * Built to the signed-off design: a full-viewport scene with the animated
	 * asset sphere behind a glass card. The markup is the design's; the form
	 * inside it is WordPress's -- same field names, same nonce, same redirect
	 * contract as before, so nothing about how people actually sign in moved.
	 */
	public static function render_login(): void {
		/*
		 * Signed-in visitors are already gone by now -- redirect_signed_in()
		 * moved them on at template_redirect, while a header could still be
		 * set. This is the fallback for anything that renders the view
		 * directly, such as the shortcode on another page: there is no header
		 * left to send, so it draws the screen rather than exiting into a
		 * blank one.
		 */
		if ( is_user_logged_in() && current_user_can( Caps::VIEW ) && ! headers_sent() ) {
			wp_safe_redirect( self::portal_url() );
			exit;
		}

		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$error    = isset( $_GET['vh_err'] ) ? sanitize_text_field( wp_unslash( $_GET['vh_err'] ) ) : '';
		$redirect = isset( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : '';
		// phpcs:enable

		/**
		 * The wordmark beside the logo mark.
		 *
		 * Defaults to the product name. A filter is cheaper than editing a
		 * template on a rebrand, and keeps the org name setting -- which is a
		 * long legal name in most installs -- out of a 16px slot. A deployment
		 * sets its own brand with the 'vulnhub_portal_login_wordmark' filter.
		 */
		$word = (string) apply_filters( 'vulnhub_portal_login_wordmark', 'VulnHub' );

		/*
		 * An optional label under the sign-in card. Left empty by default so
		 * the deployment's own hostname is never printed on the login screen;
		 * set the 'vulnhub_portal_login_host' filter to show a chosen label.
		 */
		$host = (string) apply_filters( 'vulnhub_portal_login_host', '' );
		$sso  = self::sso_start_url( $redirect );

		$chips = array(
			__( 'Asset register', 'vulnhub' ),
			__( 'Vuln scanner', 'vulnhub' ),
			__( 'Intune', 'vulnhub' ),
			__( 'Defender', 'vulnhub' ),
			__( 'Ticketing', 'vulnhub' ),
		);
		?>
		<div class="vh-login">
			<canvas class="vh-login__canvas" aria-hidden="true"></canvas>
			<div class="vh-login__vignette" aria-hidden="true"></div>
			<div class="vh-login__grid" aria-hidden="true"></div>

			<div class="vh-login__inner">
				<header class="vh-login__header">
					<div class="vh-login__brand">
						<div class="vh-login__mark" aria-hidden="true">vul</div>
						<div class="vh-login__word"><?php echo esc_html( $word ); ?></div>
					</div>
					<div class="vh-login__status">
						<span class="vh-login__dot" aria-hidden="true"></span>
						<?php esc_html_e( 'SOURCES SYNCED', 'vulnhub' ); ?>
					</div>
				</header>

				<main class="vh-login__main">
					<div class="vh-login__copy">
						<div class="vh-login__eyebrow"><?php esc_html_e( 'VULNERABILITY INTELLIGENCE &amp; PRIORITISATION', 'vulnhub' ); ?></div>
						<h1 class="vh-login__h1"><?php esc_html_e( 'Every vulnerability, mapped to the asset that owns it.', 'vulnhub' ); ?></h1>
						<p class="vh-login__lede"><?php esc_html_e( 'Correlates your asset register, vulnerability scanner, Intune and Defender into one inventory — with location, impact and priority — then raises tickets and exceptions where the work happens.', 'vulnhub' ); ?></p>
						<div class="vh-login__chips">
							<?php foreach ( $chips as $vh_chip ) : ?>
								<span class="vh-login__chip"><?php echo esc_html( $vh_chip ); ?></span>
							<?php endforeach; ?>
						</div>
					</div>

					<form method="post" class="vh-login__card">
						<?php wp_nonce_field( 'vulnhub_portal_login', 'vh_login_nonce' ); ?>
						<input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect ); ?>">

						<div class="vh-login__cardhead">
							<div class="vh-login__title"><?php esc_html_e( 'Sign in', 'vulnhub' ); ?></div>
							<?php if ( '' !== $host ) : ?>
								<div class="vh-login__host"><?php echo esc_html( $host ); ?></div>
							<?php endif; ?>
						</div>

						<?php if ( $error ) : ?>
							<p class="vh-login__error" role="alert"><?php echo esc_html( $error ); ?></p>
						<?php endif; ?>

						<?php
						/** Lets the auth plugin put its own providers above the form. */
						do_action( 'vulnhub_portal_login_top' );
						?>

						<label class="vh-login__field" for="vh-login-log">
							<?php esc_html_e( 'Email', 'vulnhub' ); ?>
							<?php
							/*
							 * Labelled Email because that is what people sign in
							 * with here, but typed text on purpose: WordPress
							 * accepts a username in this field too, and type=email
							 * would have the browser refuse to submit one.
							 */
							?>
							<input class="vh-login__input" type="text" inputmode="email" id="vh-login-log" name="log"
								placeholder="you@company.com" autocomplete="username" required autofocus>
						</label>

						<label class="vh-login__field" for="vh-login-pwd">
							<span class="vh-login__labelrow">
								<?php esc_html_e( 'Password', 'vulnhub' ); ?>
								<a href="<?php echo esc_url( wp_lostpassword_url( self::login_url() ) ); ?>"><?php esc_html_e( 'Forgot?', 'vulnhub' ); ?></a>
							</span>
							<span class="vh-login__pw">
								<input class="vh-login__input" type="password" id="vh-login-pwd" name="pwd"
									placeholder="••••••••••" autocomplete="current-password" required>
								<button type="button" class="vh-login__toggle" aria-controls="vh-login-pwd"
									aria-pressed="false" aria-label="<?php esc_attr_e( 'Show password', 'vulnhub' ); ?>">SHOW</button>
							</span>
						</label>

						<label class="vh-login__check">
							<input type="checkbox" name="rememberme" value="forever">
							<?php esc_html_e( 'Keep me signed in on this device', 'vulnhub' ); ?>
						</label>

						<button type="submit" class="vh-login__submit"
							data-busy="<?php esc_attr_e( 'Authenticating…', 'vulnhub' ); ?>"><?php esc_html_e( 'Sign in', 'vulnhub' ); ?></button>

						<div class="vh-login__or"><span aria-hidden="true"></span><?php esc_html_e( 'or', 'vulnhub' ); ?><span aria-hidden="true"></span></div>

						<?php if ( '' !== $sso ) : ?>
							<a class="vh-login__sso" href="<?php echo esc_url( $sso ); ?>">
								<span class="vh-login__ssoicon" aria-hidden="true"></span>
								<?php esc_html_e( 'Continue with SSO', 'vulnhub' ); ?>
							</a>
						<?php else : ?>
							<span class="vh-login__sso" aria-disabled="true"
								title="<?php esc_attr_e( 'Single sign-on has not been configured for this portal yet.', 'vulnhub' ); ?>">
								<span class="vh-login__ssoicon" aria-hidden="true"></span>
								<?php esc_html_e( 'Continue with SSO', 'vulnhub' ); ?>
							</span>
						<?php endif; ?>

						<?php do_action( 'vulnhub_portal_login_bottom' ); ?>

						<div class="vh-login__foot">
							<?php esc_html_e( 'No account?', 'vulnhub' ); ?>
							<a href="<?php echo esc_url( (string) apply_filters( 'vulnhub_portal_request_access_url', '#' ) ); ?>"><?php esc_html_e( 'Request access', 'vulnhub' ); ?></a>
						</div>
					</form>
				</main>

				<footer class="vh-login__footer">
					<div>
						<?php
						printf(
							/* translators: 1: four-digit year, 2: organisation wordmark. */
							esc_html__( '© %1$s %2$s', 'vulnhub' ),
							esc_html( wp_date( 'Y' ) ),
							esc_html( strtoupper( $word ) )
						);
						?>
					</div>
					<div class="vh-login__links">
						<a href="<?php echo esc_url( (string) apply_filters( 'vulnhub_portal_privacy_url', get_privacy_policy_url() ?: '#' ) ); ?>"><?php esc_html_e( 'Privacy', 'vulnhub' ); ?></a>
						<a href="<?php echo esc_url( (string) apply_filters( 'vulnhub_portal_terms_url', '#' ) ); ?>"><?php esc_html_e( 'Terms', 'vulnhub' ); ?></a>
						<a href="<?php echo esc_url( (string) apply_filters( 'vulnhub_portal_status_url', '#' ) ); ?>"><?php esc_html_e( 'Status', 'vulnhub' ); ?></a>
					</div>
				</footer>
			</div>
		</div>
		<?php
	}

	/* -----------------------------------------------------------------
	 * Front-end admin area
	 * --------------------------------------------------------------- */

	/**
	 * Sections of the portal admin area.
	 *
	 * Integration plugins add their own screens here rather than in wp-admin.
	 *
	 * @return array<string,array{label:string,cap:string,group:string,order:int,summary?:string}>
	 */
	public static function sections(): array {
		$sections = array(
			'overview'     => array(
				'screen'  => 'vulnhub',
				'label'   => __( 'Admin overview', 'vulnhub' ),
				'cap'     => Caps::MANAGE,
				'group'   => 'platform',
				'order'   => 5,
				'summary' => __( 'Connector health, data freshness and what needs attention.', 'vulnhub' ),
			),
			'integrations' => array(
				'screen'  => 'vulnhub-integrations',
				'label'   => __( 'Integrations', 'vulnhub' ),
				'cap'     => Caps::MANAGE,
				'group'   => 'integrations',
				'order'   => 10,
				'summary' => __( 'Every connected system, with its settings, health and screens.', 'vulnhub' ),
			),
			'imports'      => array(
				'label'   => __( 'Imports', 'vulnhub' ),
				'cap'     => Caps::MANAGE,
				'group'   => 'data',
				'order'   => 20,
				'summary' => __( 'Upload CMDB and Tenable CSV exports, including very large files.', 'vulnhub' ),
			),
			'rules'        => array(
				'label'   => __( 'Rules', 'vulnhub' ),
				'cap'     => Caps::MANAGE,
				'group'   => 'data',
				'order'   => 30,
				'summary' => __( 'Categorise and prioritise assets, and decide who owns what.', 'vulnhub' ),
			),
			'teams'        => array(
				'screen'  => 'vulnhub-ownership',
				'label'   => __( 'Teams &amp; SLAs', 'vulnhub' ),
				'cap'     => Caps::MANAGE,
				'group'   => 'data',
				'order'   => 40,
				'summary' => __( 'Remediation owners, Jira routing and response targets.', 'vulnhub' ),
			),
			'activity'     => array(
				'screen'  => 'vulnhub-sync',
				'label'   => __( 'Sync activity', 'vulnhub' ),
				'cap'     => Caps::VIEW,
				'group'   => 'platform',
				'order'   => 50,
				'summary' => __( 'Every connector run, with its log.', 'vulnhub' ),
			),
			'audit'        => array(
				'screen'  => 'vulnhub-audit',
				'label'   => __( 'Audit trail', 'vulnhub' ),
				'cap'     => Caps::VIEW_AUDIT,
				'group'   => 'platform',
				'order'   => 60,
				'summary' => __( 'Who changed what, and when.', 'vulnhub' ),
			),
			'settings'     => array(
				'screen'  => 'vulnhub-settings',
				'label'   => __( 'Settings', 'vulnhub' ),
				'cap'     => Caps::MANAGE,
				'group'   => 'platform',
				'order'   => 70,
				'summary' => __( 'Platform behaviour, ownership policy and retention.', 'vulnhub' ),
			),
		);

		$sections = array_merge( $sections, self::mirrored_sections() );

		/**
		 * Filters the portal admin sections.
		 *
		 * @param array<string,array<string,mixed>> $sections Section definitions.
		 */
		$sections = (array) apply_filters( 'vulnhub_portal_sections', $sections );

		uasort(
			$sections,
			static fn( array $a, array $b ): int => ( (int) ( $a['order'] ?? 99 ) ) <=> ( (int) ( $b['order'] ?? 99 ) )
		);

		return $sections;
	}

	/**
	 * Sections an integration card links to, and so kept out of the nav.
	 *
	 * Tenable's dashboard, Jira routing, AWS accounts and the rest belong to
	 * one product each, and each product has a card on Integrations that
	 * links to them. Listing them again in the navigation put the same
	 * destination in two places and pushed Integrations itself off screen.
	 * Platform sections are never hidden: Authentication is linked from the
	 * sign-in providers' cards but is policy for the whole install.
	 *
	 * @param array<string,array<string,mixed>> $sections All sections.
	 * @return string[] Section slugs.
	 */
	public static function card_sections( array $sections ): array {
		if ( ! function_exists( 'vh_integration_brand' ) || ! function_exists( 'vulnhub' ) || ! isset( vulnhub()->connectors ) ) {
			return array();
		}

		$out = array();

		foreach ( array_keys( (array) vulnhub()->connectors->all() ) as $id ) {
			foreach ( vh_integration_brand( (string) $id )['links'] as $link ) {
				$slug = ! empty( $link['page'] )
					? self::section_for_admin_page( (string) $link['page'] )
					: (string) ( $link['section'] ?? '' );

				if ( '' !== $slug && isset( $sections[ $slug ] ) && 'platform' !== ( $sections[ $slug ]['group'] ?? 'platform' ) ) {
					$out[] = $slug;
				}
			}
		}

		return array_values( array_unique( $out ) );
	}

	public static function current_section(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$requested = isset( $_GET['section'] ) ? sanitize_key( wp_unslash( $_GET['section'] ) ) : 'overview';
		$sections  = self::sections();

		return isset( $sections[ $requested ] ) ? $requested : 'overview';
	}

	/**
	 * Block the admin area for anyone without a management capability.
	 */
	public static function guard_portal(): void {
		if ( ! is_singular() ) {
			return;
		}

		$view = VulnHub_Dash_App::view_for_post( get_post() );

		// Not a portal page at all: an Elementor page, a post, the privacy
		// policy. WordPress owns those and this has no business there.
		if ( '' === $view ) {
			return;
		}

		/*
		 * Sign-in is the destination, so it can never be the thing being
		 * guarded. VulnHub_Dash_App::redirect_signed_in() handles the other
		 * direction -- somebody who still has a session landing here.
		 */
		if ( self::LOGIN_VIEW === $view ) {
			return;
		}

		/*
		 * Signed in but without a VulnHub role is not an authentication
		 * problem and must not be bounced to sign-in: the account is already
		 * authenticated, and sending it back to a login form it has already
		 * satisfied is a loop the user cannot break. That case belongs to
		 * VulnHub_Dash_App::gate(), which explains it and says who to ask.
		 */
		if ( is_user_logged_in() ) {
			return;
		}

		$here  = (string) get_permalink();
		$login = self::login_url( $here );

		/*
		 * portal_url() falls back to the site root when the page it wants is
		 * missing, and the site root is the dashboard -- so a deleted sign-in
		 * page would turn this redirect into an infinite one. Compare paths
		 * and fall through to the gate rather than loop.
		 */
		if ( self::same_path( $login, $here ) ) {
			return;
		}

		wp_safe_redirect( $login );
		exit;
	}

	/**
	 * Do two URLs point at the same page, ignoring any query string?
	 */
	private static function same_path( string $a, string $b ): bool {
		$pa = wp_parse_url( $a, PHP_URL_PATH );
		$pb = wp_parse_url( $b, PHP_URL_PATH );

		if ( ! is_string( $pa ) || ! is_string( $pb ) ) {
			return false;
		}

		return untrailingslashit( $pa ) === untrailingslashit( $pb );
	}

	public static function render_admin(): void {
		$section  = self::current_section();
		$sections = self::sections();
		$def      = $sections[ $section ];

		if ( ! current_user_can( (string) $def['cap'] ) ) {
			echo '<div class="vh-gate"><h1>' . esc_html__( 'You do not have access to that screen', 'vulnhub' ) . '</h1>'
				. '<p>' . esc_html__( 'Ask a VulnHub administrator if you need it.', 'vulnhub' ) . '</p></div>';
			return;
		}

		$groups = array(
			'data'         => __( 'Data', 'vulnhub' ),
			'integrations' => __( 'Integrations', 'vulnhub' ),
			'platform'     => __( 'Platform', 'vulnhub' ),
		);

		/*
		 * Connector health for the context bar. `$conn_bad` also drives the red
		 * dot on the Integrations nav row.
		 *
		 * Ask the connector, do not re-derive it. Reading `last_run` directly
		 * was cheaper by a query per connector and wrong in two ways that both
		 * showed on screen: it counted connectors nobody has turned on -- a
		 * disabled AWS whose last attempt failed months ago was reported as "1
		 * connector failing" beside a header calling it "not enabled" -- and it
		 * knew nothing of a sync running right now, so a transient failure kept
		 * the badge red while the next run was already succeeding. health() is
		 * the one definition of failing, and the Integrations header counts the
		 * same way, so the two cannot disagree again.
		 */
		$conn_total = 0;
		$conn_bad   = 0;
		$conn_on    = 0;

		if ( function_exists( 'vulnhub' ) && isset( vulnhub()->connectors ) ) {
			foreach ( (array) vulnhub()->connectors->all() as $conn ) {
				++$conn_total;

				$state = (string) ( $conn->health()['state'] ?? '' );

				if ( 'error' === $state ) {
					++$conn_bad;
				} elseif ( 'off' !== $state ) {
					++$conn_on;
				}
			}
		}

		$group_label = (string) ( $groups[ $def['group'] ?? 'platform' ] ?? '' );
		$from_card   = self::card_sections( $sections );
		$nav_current = in_array( $section, $from_card, true ) ? 'integrations' : $section;
		$mock        = function_exists( 'vulnhub' ) && vulnhub()->settings->mock_mode();
		?>
		<div class="vh-adm">
			<div class="vh-adm__context">
				<nav class="vh-adm__crumbs" aria-label="<?php esc_attr_e( 'Breadcrumb', 'vulnhub' ); ?>">
					<span><?php esc_html_e( 'Administration', 'vulnhub' ); ?></span>
					<?php if ( 'integrations' !== $nav_current || 'integrations' === $section ) : ?>
						<span class="sep">/</span><span><?php echo esc_html( $group_label ); ?></span>
					<?php else : ?>
						<span class="sep">/</span><a href="<?php echo esc_url( self::portal_url( self::ADMIN_VIEW, array( 'section' => 'integrations' ) ) ); ?>"><?php esc_html_e( 'Integrations', 'vulnhub' ); ?></a>
					<?php endif; ?>
					<span class="sep">/</span><span class="cur" aria-current="page"><?php echo esc_html( (string) $def['label'] ); ?></span>
				</nav>
				<span class="vh-adm__spacer"></span>
				<?php if ( $mock ) : ?>
					<span class="vh-adm__mock"><?php esc_html_e( 'MOCK DATA', 'vulnhub' ); ?></span>
				<?php endif; ?>
				<?php if ( $conn_total > 0 ) : ?>
					<span class="vh-adm__health<?php echo $conn_bad > 0 ? ' is-bad' : ''; ?>">
						<?php
						echo esc_html(
							$conn_bad > 0
								/* translators: %s: number of connectors whose last run failed. */
								? sprintf( _n( '%s connector failing', '%s connectors failing', $conn_bad, 'vulnhub' ), number_format_i18n( $conn_bad ) )
								/*
								 * The ones actually in use, said the way the
								 * Integrations header says it. Counting every
								 * connector and calling them "idle" read as
								 * "10 connectors idle" on a site where three
								 * were working and one was mid-sync.
								 */
								/* translators: %s: connectors that are enabled and not failing. */
								: sprintf( _n( '%s connector active', '%s connectors active', $conn_on, 'vulnhub' ), number_format_i18n( $conn_on ) )
						);
						?>
					</span>
				<?php endif; ?>
			</div>

			<div class="vh-adm__cols">
				<aside class="vh-adm__nav" aria-label="<?php esc_attr_e( 'Admin sections', 'vulnhub' ); ?>" data-vh-adm-nav>
					<input type="search" class="vh-adm__filter" data-vh-adm-filter
						placeholder="<?php esc_attr_e( 'Filter sections…', 'vulnhub' ); ?>"
						aria-label="<?php esc_attr_e( 'Filter admin sections', 'vulnhub' ); ?>" autocomplete="off">
					<?php foreach ( $groups as $group => $glabel ) : ?>
						<?php
						$in_group = array_filter(
							$sections,
							static fn( array $s ): bool => ( $s['group'] ?? 'platform' ) === $group
						);
						$in_group = array_filter(
							$in_group,
							static fn( array $s, string $slug ): bool => current_user_can( (string) $s['cap'] ) && ! in_array( $slug, $from_card, true ),
							ARRAY_FILTER_USE_BOTH
						);
						if ( ! $in_group ) {
							continue;
						}
						?>
						<p class="vh-adm__group"><?php echo esc_html( $glabel ); ?></p>
						<ul>
							<?php foreach ( $in_group as $slug => $s ) : ?>
								<?php $is_wp = str_starts_with( (string) $slug, self::MIRROR_PREFIX ); ?>
								<li>
									<a class="vh-adm__item<?php echo $slug === $nav_current ? ' is-active' : ''; ?>"
										href="<?php echo esc_url( self::portal_url( self::ADMIN_VIEW, array( 'section' => $slug ) ) ); ?>"
										data-vh-adm-item="<?php echo esc_attr( $slug ); ?>"
										<?php echo $slug === $nav_current ? ' aria-current="page"' : ''; ?>>
										<span class="vh-adm__label"><?php echo esc_html( (string) $s['label'] ); ?></span>
										<?php if ( 'integrations' === $slug && $conn_bad > 0 ) : ?>
											<span class="vh-adm__dot" title="<?php esc_attr_e( 'A connector is failing', 'vulnhub' ); ?>"></span>
										<?php endif; ?>
										<?php if ( $is_wp ) : ?>
											<span class="vh-adm__wp">WP</span>
										<?php endif; ?>
									</a>
								</li>
							<?php endforeach; ?>
						</ul>
					<?php endforeach; ?>
					<p class="vh-adm__nomatch" data-vh-adm-nomatch hidden><?php esc_html_e( 'Nothing matches that.', 'vulnhub' ); ?></p>
				</aside>

				<div class="vh-adm__body">
					<div class="vh-adm__head">
						<div>
							<h1><?php echo esc_html( (string) $def['label'] ); ?></h1>
							<?php if ( ! empty( $def['summary'] ) ) : ?>
								<p class="vh-sub"><?php echo esc_html( (string) $def['summary'] ); ?></p>
							<?php endif; ?>
						</div>
						<?php
						// The save handler redirects back with vh_type=success and a
						// vh_msg; the portal keeps those params. Show it as a chip.
						// phpcs:ignore WordPress.Security.NonceVerification.Recommended
						if ( 'success' === ( $_GET['vh_type'] ?? '' ) ) :
							// phpcs:ignore WordPress.Security.NonceVerification.Recommended
							$vh_msg = isset( $_GET['vh_msg'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['vh_msg'] ) ) : '';
							?>
							<span class="vh-adm__saved"><?php echo esc_html( '' !== $vh_msg ? $vh_msg : __( 'Saved', 'vulnhub' ) ); ?></span>
						<?php endif; ?>
					</div>

					<div class="vh-adm__view">
						<?php
						$view = VULNHUB_DASH_DIR . 'admin-views/' . $section . '.php';

						if ( ! empty( $def['screen'] ) ) {
							// Core owns the screen registry and the view files, so ask
							// it to draw the body. Integration screens it has no view
							// for fall through to `vulnhub_render_admin_page` inside.
							vulnhub()->admin->render_screen( (string) $def['screen'] );
						} elseif ( is_readable( $view ) ) {
							include $view;
						} else {
							/**
							 * Lets a plugin render a portal admin section it registered.
							 *
							 * @param string $section Section slug.
							 */
							do_action( 'vulnhub_render_portal_section', $section );
						}
						?>
					</div>
				</div>
			</div>

			<?php self::render_admin_footer(); ?>
		</div>
		<?php
	}

	/**
	 * Per-source freshness and the platform version line at the foot of the
	 * admin shell. Fed from the sync-run ledger, exactly as before.
	 */
	private static function render_admin_footer(): void {
		$srcs = array(
			'tenable' => __( 'Tenable', 'vulnhub' ),
			'cmdb'    => __( 'CMDB', 'vulnhub' ),
			'intune'  => __( 'Intune', 'vulnhub' ),
			'jira'    => __( 'Jira', 'vulnhub' ),
		);

		echo '<footer class="vh-adm__foot">';

		if ( function_exists( 'vulnhub' ) && isset( vulnhub()->logger ) ) {
			foreach ( $srcs as $id => $label ) {
				$lr   = vulnhub()->logger->last_run( (string) $id );
				$when = $lr && ! empty( $lr['finished_at'] )
					? vh_ago( (string) $lr['finished_at'] )
					: __( 'never', 'vulnhub' );

				printf(
					'<span><span class="src">%s</span> %s</span>',
					esc_html( $label ),
					esc_html( $when )
				);
			}
		}

		echo '<span class="vh-adm__spacer"></span>';

		printf(
			'<span>%s</span>',
			esc_html(
				sprintf(
					/* translators: 1: core version, 2: database schema version. */
					__( 'core %1$s · schema %2$s', 'vulnhub' ),
					defined( 'VULNHUB_VERSION' ) ? VULNHUB_VERSION : '—',
					(string) get_option( 'vulnhub_db_version', '—' )
				)
			)
		);

		echo '</footer>';
	}
}

