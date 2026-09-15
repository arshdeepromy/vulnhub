<?php
/**
 * Second-factor interception of the WordPress login flow.
 *
 * HOW THE INTERRUPTION WORKS, AND WHY THIS WAY
 *
 * WordPress has no "half authenticated" state. The safe place to insert a
 * second factor is therefore after the password has been proved correct but
 * before the session is allowed to survive: `wp_signon()` validates the
 * password, calls `wp_set_auth_cookie()`, then fires `wp_login`. Hooking
 * `wp_login` and immediately calling `wp_clear_auth_cookie()` +
 * `wp_destroy_current_session()` leaves the browser with no usable session,
 * and we then render the challenge ourselves and `exit` before wp-login.php
 * gets to redirect. This is the same shape the core Two Factor feature plugin
 * uses, and it is deliberate:
 *
 *  - Rejecting inside the `authenticate` filter instead would mean either
 *    re-implementing password checking or handing back a WP_Error, neither of
 *    which can carry a pending-login state.
 *  - Letting the cookie stand and "requiring" MFA on the next page load would
 *    be no control at all: the cookie is the session.
 *
 * The pending user is carried across the challenge by an HMAC-signed,
 * single-use token (see VulnHub_Auth_User_MFA::issue_challenge_token) rather
 * than a bare user id in a hidden field.
 *
 * @package VulnHub\Auth
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Wires the second factor into wp-login.php.
 */
final class VulnHub_Auth_Login {

	/** Query action used for the challenge form. */
	public const ACTION = 'vh_mfa';

	/** Set while an SSO sign-in is completing, so we do not double-challenge. */
	public static bool $sso_in_progress = false;

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public static function init(): void {
		add_action( 'wp_login', array( __CLASS__, 'maybe_challenge' ), 10, 2 );
		add_action( 'login_form_' . self::ACTION, array( __CLASS__, 'handle_challenge' ) );
		add_action( 'wp_logout', array( __CLASS__, 'on_logout' ) );
		add_action( 'wp_login_failed', array( __CLASS__, 'on_password_failure' ) );
		add_action( 'admin_init', array( __CLASS__, 'force_enrolment' ) );
		add_action( 'admin_notices', array( __CLASS__, 'enrolment_notice' ) );
		/*
		 * The portal equivalent of force_enrolment(). Priority 20, after
		 * VulnHub_Dash_Portal::guard_portal() (10) has had its say about
		 * signed-out visitors: authentication first, then enrolment.
		 */
		add_action( 'template_redirect', array( __CLASS__, 'force_enrolment_portal' ), 20 );
	}

	/* -----------------------------------------------------------------
	 * Interception
	 * --------------------------------------------------------------- */

	/**
	 * Decide whether this successful password login needs a second factor.
	 *
	 * @param string        $user_login Username.
	 * @param \WP_User|null $user       Authenticated user.
	 * @return void
	 */
	public static function maybe_challenge( string $user_login, $user = null ): void {
		if ( ! $user instanceof \WP_User ) {
			$user = get_user_by( 'login', $user_login );
		}
		if ( ! $user instanceof \WP_User || ! $user->ID ) {
			return;
		}

		VulnHub_Auth_Audit::log(
			'login.password_ok',
			sprintf( 'Password accepted for %s', $user->user_login ),
			$user->ID,
			array( 'login' => $user->user_login )
		);

		if ( ! self::challenge_required( $user ) ) {
			return;
		}

		// If we cannot render an interstitial in this context (XML-RPC, a REST
		// call, anything that is not wp-login.php) then fail closed: an
		// enforced second factor must not be skippable by choosing a different
		// entry point.
		if ( ! function_exists( 'login_header' ) || headers_sent() ) {
			wp_clear_auth_cookie();
			wp_destroy_current_session();

			VulnHub_Auth_Audit::log(
				'mfa.blocked',
				sprintf( 'Blocked sign-in for %s: MFA required but no challenge could be presented', $user->user_login ),
				$user->ID,
				array( 'context' => defined( 'XMLRPC_REQUEST' ) ? 'xmlrpc' : 'non-interactive' ),
				'warning'
			);
			return;
		}

		// Password was right, but the session does not survive this request.
		wp_clear_auth_cookie();
		wp_destroy_current_session();

		VulnHub_Auth_Audit::log(
			'mfa.challenge',
			sprintf( 'Second-factor challenge issued to %s', $user->user_login ),
			$user->ID
		);

		$remember    = ! empty( $_POST['rememberme'] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- wp-login.php's own field, read only as a boolean.
		$redirect_to = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification

		self::render_challenge( $user, $redirect_to, $remember );
		exit;
	}

	/**
	 * Does this user have to complete a second factor right now?
	 *
	 * @param \WP_User $user User.
	 * @return bool
	 */
	public static function challenge_required( \WP_User $user ): bool {
		if ( ! VulnHub_Auth_Policy::enabled() ) {
			return false;
		}
		if ( ! VulnHub_Auth_User_MFA::is_enabled( $user->ID ) ) {
			// Nothing to challenge with. Enforcement of enrolment is handled
			// separately so that a required-but-unenrolled user is nudged to
			// the profile screen rather than locked out.
			return false;
		}
		if ( self::$sso_in_progress && VulnHub_Auth_Policy::get( 'skip_for_sso' ) ) {
			return false;
		}
		if ( VulnHub_Auth_User_MFA::is_trusted_device( $user->ID ) ) {
			VulnHub_Auth_Audit::log(
				'mfa.trusted_device',
				sprintf( 'Second factor skipped for %s on a remembered device', $user->user_login ),
				$user->ID
			);
			return false;
		}

		return true;
	}

	/* -----------------------------------------------------------------
	 * The challenge screen
	 * --------------------------------------------------------------- */

	/**
	 * Render the second-factor form on wp-login.php and stop.
	 *
	 * @param \WP_User      $user        Pending user.
	 * @param string        $redirect_to Post-login destination.
	 * @param bool          $remember    Whether "remember me" was ticked.
	 * @param \WP_Error|null $error      Error from a previous attempt.
	 * @return void
	 */
	public static function render_challenge( \WP_User $user, string $redirect_to, bool $remember, ?\WP_Error $error = null ): void {
		try {
			$token = VulnHub_Auth_User_MFA::issue_challenge_token( $user->ID );
		} catch ( \Throwable $e ) {
			wp_die( esc_html__( 'Could not start the second-factor challenge. Please try signing in again.', 'vulnhub' ) );
		}

		$remaining = VulnHub_Auth_User_MFA::recovery_remaining( $user->ID );

		login_header(
			__( 'Two-factor authentication', 'vulnhub' ),
			'',
			$error instanceof \WP_Error ? $error : new \WP_Error()
		);
		?>
		<form name="vh_mfa_form" id="loginform"
			action="<?php echo esc_url( site_url( 'wp-login.php?action=' . self::ACTION, 'login_post' ) ); ?>"
			method="post" autocomplete="off">

			<p style="margin-bottom:16px">
				<?php
				printf(
					/* translators: %s: user login name. */
					esc_html__( 'Signed in as %s. Enter the six-digit code from your authenticator app to finish.', 'vulnhub' ),
					'<strong>' . esc_html( $user->user_login ) . '</strong>' // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inline.
				);
				?>
			</p>

			<p>
				<label for="vh_auth_code"><?php esc_html_e( 'Authentication code', 'vulnhub' ); ?></label>
				<input type="text" name="vh_auth_code" id="vh_auth_code" class="input"
					value="" size="20" autocomplete="one-time-code" inputmode="numeric"
					pattern="[0-9A-Za-z\-]*" autocapitalize="off" spellcheck="false" autofocus />
			</p>

			<?php if ( $remaining > 0 ) : ?>
				<p class="description" style="margin-bottom:16px">
					<?php
					printf(
						/* translators: %d: number of unused recovery codes. */
						esc_html__( 'Lost your device? You can type one of your %d remaining recovery codes here instead.', 'vulnhub' ),
						(int) $remaining
					);
					?>
				</p>
			<?php endif; ?>

			<?php if ( VulnHub_Auth_Policy::get( 'remember_enabled' ) ) : ?>
				<p class="forgetmenot">
					<input name="vh_auth_trust" type="checkbox" id="vh_auth_trust" value="1" />
					<label for="vh_auth_trust">
						<?php
						printf(
							/* translators: %d: number of days. */
							esc_html__( 'Trust this browser for %d days', 'vulnhub' ),
							(int) VulnHub_Auth_Policy::get( 'remember_days', 30 )
						);
						?>
					</label>
				</p>
			<?php endif; ?>

			<?php wp_nonce_field( 'vh_auth_mfa_challenge', 'vh_auth_nonce' ); ?>
			<input type="hidden" name="vh_auth_token" value="<?php echo esc_attr( $token ); ?>" />
			<input type="hidden" name="rememberme" value="<?php echo $remember ? '1' : '0'; ?>" />
			<input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect_to ); ?>" />

			<p class="submit">
				<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large"
					value="<?php esc_attr_e( 'Verify', 'vulnhub' ); ?>" />
			</p>
		</form>

		<p id="nav" style="margin-top:16px">
			<a href="<?php echo esc_url( wp_login_url() ); ?>"><?php esc_html_e( '&larr; Start again', 'vulnhub' ); ?></a>
		</p>
		<?php
		login_footer( 'vh_auth_code' );
	}

	/**
	 * Handle a submitted (or reloaded) second-factor challenge.
	 *
	 * @return void
	 */
	public static function handle_challenge(): void {
		// A GET to this action has no pending login attached to it; send the
		// visitor back to the start rather than showing an empty form.
		if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		check_admin_referer( 'vh_auth_mfa_challenge', 'vh_auth_nonce' );

		$token   = isset( $_POST['vh_auth_token'] ) ? sanitize_text_field( wp_unslash( $_POST['vh_auth_token'] ) ) : '';
		$user_id = VulnHub_Auth_User_MFA::redeem_challenge_token( $token );

		if ( $user_id <= 0 ) {
			VulnHub_Auth_Audit::log(
				'mfa.token_invalid',
				'Second-factor challenge token was missing, expired or already used',
				0,
				array(),
				'warning'
			);
			wp_safe_redirect( add_query_arg( 'vh_auth', 'expired', wp_login_url() ) );
			exit;
		}

		$user = get_user_by( 'id', $user_id );
		if ( ! $user instanceof \WP_User ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		$redirect_to = isset( $_POST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_POST['redirect_to'] ) ) : '';
		$remember    = ! empty( $_POST['rememberme'] ) && '0' !== (string) $_POST['rememberme'];
		$trust       = ! empty( $_POST['vh_auth_trust'] );
		$code        = isset( $_POST['vh_auth_code'] ) ? sanitize_text_field( wp_unslash( $_POST['vh_auth_code'] ) ) : '';

		// --- lockout ------------------------------------------------------
		$locked = VulnHub_Auth_Throttle::locked_for( $user->ID );
		if ( $locked > 0 ) {
			VulnHub_Auth_Audit::log(
				'mfa.locked_out',
				sprintf( 'Second-factor attempt refused for %s: locked out', $user->user_login ),
				$user->ID,
				array( 'seconds_remaining' => $locked ),
				'warning'
			);

			$error = new \WP_Error(
				'vh_auth_locked',
				sprintf(
					/* translators: %d: minutes remaining. */
					esc_html__( 'Too many incorrect codes. Try again in %d minutes.', 'vulnhub' ),
					(int) ceil( $locked / 60 )
				)
			);
			self::render_challenge( $user, $redirect_to, $remember, $error );
			exit;
		}

		// --- verify -------------------------------------------------------
		$reason   = '';
		$verified = false;
		$method   = 'totp';

		if ( VulnHub_Auth_User_MFA::verify_code( $user->ID, $code, $reason ) ) {
			$verified = true;
		} elseif ( 'replay' !== $reason && VulnHub_Auth_User_MFA::consume_recovery_code( $user->ID, $code ) ) {
			$verified = true;
			$method   = 'recovery_code';
		}

		if ( ! $verified ) {
			$threshold = (int) VulnHub_Auth_Policy::get( 'lockout_threshold', 5 );
			$minutes   = (int) VulnHub_Auth_Policy::get( 'lockout_minutes', 15 );
			$tripped   = VulnHub_Auth_Throttle::fail( $user->ID, $threshold, $minutes );

			VulnHub_Auth_Audit::log(
				'mfa.failure',
				sprintf( 'Second-factor code rejected for %s (%s)', $user->user_login, $reason ?: 'invalid' ),
				$user->ID,
				array(
					'reason'   => $reason ?: 'invalid',
					'failures' => VulnHub_Auth_Throttle::failures( $user->ID ),
				),
				'warning'
			);

			if ( $tripped ) {
				VulnHub_Auth_Audit::log(
					'mfa.lockout',
					sprintf( 'Locked %s out of second-factor attempts for %d minutes', $user->user_login, $minutes ),
					$user->ID,
					array( 'threshold' => $threshold ),
					'error'
				);
			}

			$message = 'replay' === $reason
				? __( 'That code has already been used. Wait for your authenticator to show the next one.', 'vulnhub' )
				: __( 'That code is not valid. Check your authenticator app and try again.', 'vulnhub' );

			if ( $tripped ) {
				$message = sprintf(
					/* translators: %d: lockout minutes. */
					__( 'Too many incorrect codes. Sign-in is blocked for %d minutes.', 'vulnhub' ),
					$minutes
				);
			}

			self::render_challenge( $user, $redirect_to, $remember, new \WP_Error( 'vh_auth_invalid', esc_html( $message ) ) );
			exit;
		}

		// --- success ------------------------------------------------------
		VulnHub_Auth_Throttle::clear( $user->ID );

		if ( $trust && VulnHub_Auth_Policy::get( 'remember_enabled' ) ) {
			try {
				VulnHub_Auth_User_MFA::trust_device( $user->ID, (int) VulnHub_Auth_Policy::get( 'remember_days', 30 ) );
				VulnHub_Auth_Audit::log(
					'mfa.device_trusted',
					sprintf( '%s marked this browser as trusted', $user->user_login ),
					$user->ID
				);
			} catch ( \Throwable $e ) {
				unset( $e );
			}
		}

		wp_set_auth_cookie( $user->ID, $remember );
		wp_set_current_user( $user->ID );

		if ( 'recovery_code' === $method ) {
			VulnHub_Auth_Audit::log(
				'mfa.recovery_used',
				sprintf( '%s signed in with a recovery code (%d left)', $user->user_login, VulnHub_Auth_User_MFA::recovery_remaining( $user->ID ) ),
				$user->ID,
				array( 'remaining' => VulnHub_Auth_User_MFA::recovery_remaining( $user->ID ) ),
				'warning'
			);
		} else {
			VulnHub_Auth_Audit::log(
				'mfa.success',
				sprintf( 'Second factor verified for %s', $user->user_login ),
				$user->ID,
				array( 'method' => $method )
			);
		}

		VulnHub_Auth_Audit::log(
			'login.success',
			sprintf( '%s signed in with password and a second factor', $user->user_login ),
			$user->ID,
			array( 'method' => $method )
		);

		$destination = $redirect_to ? $redirect_to : admin_url();
		wp_safe_redirect( apply_filters( 'login_redirect', $destination, $destination, $user ) );
		exit;
	}

	/* -----------------------------------------------------------------
	 * Other login events
	 * --------------------------------------------------------------- */

	/**
	 * Audit a failed password attempt.
	 *
	 * @param string $username Attempted login.
	 * @return void
	 */
	public static function on_password_failure( $username ): void {
		$username = sanitize_user( (string) $username, true );
		$user     = $username ? get_user_by( 'login', $username ) : false;

		VulnHub_Auth_Audit::log(
			'login.failure',
			sprintf( 'Failed sign-in attempt for %s', $username ?: '(no username)' ),
			$user instanceof \WP_User ? $user->ID : 0,
			array( 'login' => $username ),
			'warning'
		);
	}

	/**
	 * Audit sign-out.
	 *
	 * @param int $user_id User id.
	 * @return void
	 */
	public static function on_logout( $user_id = 0 ): void {
		$user_id = (int) $user_id;
		$user    = $user_id ? get_user_by( 'id', $user_id ) : null;

		VulnHub_Auth_Audit::log(
			'logout',
			sprintf( '%s signed out', $user instanceof \WP_User ? $user->user_login : 'A user' ),
			$user_id
		);
	}

	/* -----------------------------------------------------------------
	 * Forced enrolment
	 * --------------------------------------------------------------- */

	/**
	 * Send a user who must enrol to their profile screen.
	 *
	 * A redirect rather than a hard block: the account still works, but the
	 * only place it goes is the page where MFA is set up.
	 *
	 * @return void
	 */
	public static function force_enrolment(): void {
		if ( wp_doing_ajax() || ! is_user_logged_in() ) {
			return;
		}

		$user = wp_get_current_user();
		if ( ! VulnHub_Auth_Policy::must_enrol( $user ) ) {
			return;
		}

		global $pagenow;
		$allowed = array( 'profile.php', 'admin-post.php', 'admin-ajax.php', 'options.php' );
		if ( in_array( (string) $pagenow, $allowed, true ) ) {
			return;
		}

		wp_safe_redirect( add_query_arg( 'vh_mfa', 'required', admin_url( 'profile.php' ) ) . '#vulnhub-mfa' );
		exit;
	}

	/**
	 * Require enrolment on the portal, the way force_enrolment() does in
	 * wp-admin.
	 *
	 * A portal-only account -- signed in, holding vulnhub_view, without
	 * manage_options -- is redirected out of wp-admin, so the admin_init hook
	 * above never ran for exactly the people the policy is usually written
	 * for: everyday users of the product. "Required for selected roles" was
	 * enforced against administrators and nobody else.
	 *
	 * Deliberately narrow. It acts only on the portal's own views, so a
	 * marketing page, the privacy policy or an Elementor page built on
	 * VulnHub widgets is never interrupted, and it leaves wp-admin to the
	 * hook that already covers it.
	 */
	public static function force_enrolment_portal(): void {
		/*
		 * admin-post.php and admin-ajax.php are admin context and never reach
		 * template_redirect; REST does not either. So the portal's forms and
		 * its infinite-scroll endpoints keep working while a redirect is
		 * pending -- which matters, because the enrolment form itself posts
		 * to admin-post.php.
		 */
		if ( is_admin() || wp_doing_ajax() || ! is_user_logged_in() ) {
			return;
		}

		if ( ! is_singular() || ! class_exists( 'VulnHub_Dash_App' ) || ! class_exists( 'VulnHub_Dash_Portal' ) ) {
			return;
		}

		$view = VulnHub_Dash_App::view_for_post( get_post() );

		// Not a portal page, or the sign-in screen -- which must stay
		// reachable, and which redirect_signed_in() already owns.
		if ( '' === $view || VulnHub_Dash_Portal::LOGIN_VIEW === $view ) {
			return;
		}

		if ( ! VulnHub_Auth_Policy::must_enrol( wp_get_current_user() ) ) {
			return;
		}

		/*
		 * Loop safety, part one: there has to be somewhere to send them.
		 *
		 * portal_url() falls back to the site root when the page it wants is
		 * missing, and the site root is the dashboard -- itself a portal view
		 * this method would redirect again, forever. If the administration
		 * page is not mapped, enrolment has no home in the portal and this
		 * steps aside rather than trapping the person in a redirect they
		 * cannot break.
		 */
		$pages = (array) get_option( 'vulnhub_dash_pages', array() );

		if ( empty( $pages[ VulnHub_Dash_Portal::ADMIN_VIEW ] ) ) {
			return;
		}

		/*
		 * Part two: do not redirect somebody to where they already are. The
		 * destination is one section of the admin view, so being on the admin
		 * view is not enough to stop -- a person sitting on ?section=integrations
		 * still needs sending along -- but being on this section is.
		 */
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$section = isset( $_GET['section'] ) ? sanitize_key( wp_unslash( $_GET['section'] ) ) : '';

		if ( VulnHub_Dash_Portal::ADMIN_VIEW === $view && VulnHub_Auth_Profile::SECTION === $section ) {
			return;
		}

		$url = VulnHub_Auth_Profile::section_url( array( 'vh_mfa' => 'required' ) );

		if ( '' === $url ) {
			return;
		}

		wp_safe_redirect( $url );
		exit;
	}

	/**
	 * Explain the redirect once the user lands on their profile.
	 *
	 * @return void
	 */
	public static function enrolment_notice(): void {
		if ( ! is_user_logged_in() ) {
			return;
		}
		$user = wp_get_current_user();
		if ( ! VulnHub_Auth_Policy::must_enrol( $user ) ) {
			return;
		}

		printf(
			'<div class="notice notice-error"><p><strong>%s</strong> %s</p></div>',
			esc_html__( 'Two-factor authentication is required.', 'vulnhub' ),
			esc_html__( 'Your grace period has ended. Set up an authenticator app below to carry on using the platform.', 'vulnhub' )
		);
	}
}

