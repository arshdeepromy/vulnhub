<?php
/**
 * MFA enrolment on the WordPress profile screen.
 *
 * Enrolment is deliberately two-step: generate a secret, then prove a code
 * from it before MFA is switched on. Without the proof step it is trivially
 * easy to enrol against a mistyped or unsaved secret and lock yourself out.
 *
 * The secret is shown exactly once — inside the QR code and as text for manual
 * entry — and only to the account's own owner on their own profile screen. It
 * is never rendered again, and never rendered at all on another user's profile.
 *
 * @package VulnHub\Auth
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Profile-screen enrolment UI and its form handlers.
 */
final class VulnHub_Auth_Profile {

	/** Transient prefix for the one-time recovery code display. */
	private const CODES_TRANSIENT = 'vh_auth_codes_';

	/** Portal admin section where people manage their own second factor. */
	public const SECTION = 'security';

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public static function init(): void {
		add_action( 'show_user_profile', array( __CLASS__, 'render' ) );
		add_action( 'edit_user_profile', array( __CLASS__, 'render' ) );

		add_action( 'admin_post_vulnhub_auth_mfa_begin', array( __CLASS__, 'handle_begin' ) );
		add_action( 'admin_post_vulnhub_auth_mfa_confirm', array( __CLASS__, 'handle_confirm' ) );
		add_action( 'admin_post_vulnhub_auth_mfa_cancel', array( __CLASS__, 'handle_cancel' ) );
		add_action( 'admin_post_vulnhub_auth_mfa_disable', array( __CLASS__, 'handle_disable' ) );
		add_action( 'admin_post_vulnhub_auth_mfa_recovery', array( __CLASS__, 'handle_recovery' ) );
		add_action( 'admin_post_vulnhub_auth_mfa_forget', array( __CLASS__, 'handle_forget' ) );
		add_action( 'admin_post_vulnhub_auth_mfa_reset', array( __CLASS__, 'handle_reset' ) );

		/*
		 * The same panel, in the portal. profile.php is a wp-admin screen, and
		 * the portal keeps portal-only accounts out of wp-admin -- so the
		 * account menu's "Security & MFA" link bounced exactly the people it
		 * was for back to the dashboard, with no way to enrol at all.
		 */
		add_filter( 'vulnhub_portal_sections', array( __CLASS__, 'register_section' ) );
		add_action( 'vulnhub_render_portal_section', array( __CLASS__, 'render_section' ) );
	}

	/* -----------------------------------------------------------------
	 * Portal section
	 * --------------------------------------------------------------- */

	/**
	 * Register "Your security" in the portal admin area.
	 *
	 * VIEW, not MANAGE: every portal account has a second factor to manage,
	 * and the section only ever shows the signed-in person their own.
	 *
	 * @param array<string,array<string,mixed>> $sections Section definitions.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_section( array $sections ): array {
		if ( isset( $sections[ self::SECTION ] ) || ! class_exists( 'VulnHub\\Core\\Caps' ) ) {
			return $sections;
		}

		$sections[ self::SECTION ] = array(
			'label'   => __( 'Your security', 'vulnhub' ),
			'cap'     => \VulnHub\Core\Caps::VIEW,
			'group'   => 'platform',
			'order'   => 12,
			'summary' => __( 'Your own two-factor authentication: set up an authenticator app, reissue recovery codes, forget remembered browsers.', 'vulnhub' ),
		);

		return $sections;
	}

	/**
	 * Draw the panel for the signed-in person, with its redirect notice.
	 *
	 * @param string $section Section slug being rendered.
	 */
	public static function render_section( string $section ): void {
		if ( self::SECTION !== $section || ! is_user_logged_in() ) {
			return;
		}

		self::portal_notice();
		self::render( wp_get_current_user() );
	}

	/**
	 * URL of the portal section, or '' when the portal is not active.
	 *
	 * @param array<string,string> $args Query arguments.
	 */
	public static function section_url( array $args = array() ): string {
		if ( ! class_exists( 'VulnHub_Dash_Portal' ) ) {
			return '';
		}

		return VulnHub_Dash_Portal::portal_url( VulnHub_Dash_Portal::ADMIN_VIEW, array_merge( array( 'section' => self::SECTION ), $args ) );
	}

	/**
	 * The redirect notice, in the portal's own classes (it has no wp-admin
	 * notice styling).
	 */
	private static function portal_notice(): void {
		ob_start();
		self::notices();
		$html = (string) ob_get_clean();

		if ( '' === $html ) {
			return;
		}

		$good = str_contains( $html, 'notice-success' ) || str_contains( $html, 'notice-info' );

		printf(
			'<p class="%1$s" role="status">%2$s</p>',
			esc_attr( $good ? 'vh-flash vh-flash--good' : 'vh-warn-note' ),
			esc_html( wp_strip_all_tags( $html ) )
		);
	}

	/* -----------------------------------------------------------------
	 * Rendering
	 * --------------------------------------------------------------- */

	/**
	 * Render the MFA section on a profile screen.
	 *
	 * @param \WP_User $user The profile being viewed.
	 * @return void
	 */
	public static function render( $user ): void {
		if ( ! $user instanceof \WP_User ) {
			return;
		}

		$is_self = get_current_user_id() === $user->ID;
		if ( ! $is_self && ! current_user_can( 'edit_user', $user->ID ) ) {
			return;
		}

		$status  = VulnHub_Auth_User_MFA::status( $user->ID );
		$pending = $is_self ? VulnHub_Auth_User_MFA::pending_secret( $user->ID ) : '';
		$codes   = $is_self ? get_transient( self::CODES_TRANSIENT . $user->ID ) : false;

		if ( is_array( $codes ) ) {
			delete_transient( self::CODES_TRANSIENT . $user->ID );
		}

		echo '<h2 id="vulnhub-mfa">' . esc_html__( 'Two-factor authentication', 'vulnhub' ) . '</h2>';

		if ( ! VulnHub_Auth_Policy::enabled() ) {
			printf(
				'<p class="description">%s</p>',
				esc_html__( 'Two-factor authentication is switched off for this platform. An administrator can enable it under VulnHub → Authentication.', 'vulnhub' )
			);
			return;
		}

		echo '<table class="form-table" role="presentation"><tbody>';

		// --- status row ---------------------------------------------------
		echo '<tr><th scope="row">' . esc_html__( 'Status', 'vulnhub' ) . '</th><td>';
		if ( $status['enabled'] ) {
			printf(
				'<span class="vh-state vh-state--fixed">%s</span> <span class="vh-muted">%s</span>',
				esc_html__( 'Active', 'vulnhub' ),
				esc_html(
					sprintf(
						/* translators: 1: enrolment date, 2: recovery codes left. */
						__( 'Enrolled %1$s · %2$d recovery codes left', 'vulnhub' ),
						$status['enrolled_at'] ? vh_date( (string) $status['enrolled_at'], 'j M Y' ) : '—',
						(int) $status['recovery']
					)
				)
			);
		} else {
			printf(
				'<span class="vh-state vh-state--open">%s</span>',
				esc_html__( 'Not set up', 'vulnhub' )
			);
			if ( VulnHub_Auth_Policy::required_for( $user ) ) {
				echo ' <span class="vh-muted">' . esc_html__( 'Required by policy for this account.', 'vulnhub' ) . '</span>';
			}
		}
		echo '</td></tr>';

		if ( $status['enabled'] && $status['devices'] > 0 ) {
			echo '<tr><th scope="row">' . esc_html__( 'Remembered browsers', 'vulnhub' ) . '</th><td>';
			printf(
				'%s ',
				esc_html( sprintf( /* translators: %d: device count. */ _n( '%d browser is trusted', '%d browsers are trusted', (int) $status['devices'], 'vulnhub' ), (int) $status['devices'] ) )
			);
			if ( $is_self ) {
				self::button_form( 'vulnhub_auth_mfa_forget', $user->ID, __( 'Forget them all', 'vulnhub' ) );
			}
			echo '</td></tr>';
		}

		echo '</tbody></table>';

		// --- one-time recovery codes ---------------------------------------
		if ( is_array( $codes ) && $codes ) {
			self::render_recovery_codes( $codes );
		}

		// --- enrolment ------------------------------------------------------
		if ( $is_self ) {
			if ( $status['enabled'] ) {
				self::render_manage( $user );
			} elseif ( '' !== $pending ) {
				self::render_confirm( $user, $pending );
			} else {
				self::render_start( $user );
			}
		} elseif ( current_user_can( 'edit_user', $user->ID ) ) {
			self::render_admin_reset( $user, (bool) $status['enabled'] );
		}
	}

	/**
	 * Step one: offer to begin enrolment.
	 *
	 * @param \WP_User $user User.
	 * @return void
	 */
	private static function render_start( \WP_User $user ): void {
		?>
		<div class="vh-card" style="max-width:640px">
			<p><?php esc_html_e( 'Add a time-based one-time password from an authenticator app such as Microsoft Authenticator, Google Authenticator or 1Password.', 'vulnhub' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="vulnhub_auth_mfa_begin" />
				<input type="hidden" name="user_id" value="<?php echo esc_attr( (string) $user->ID ); ?>" />
				<?php wp_nonce_field( 'vulnhub_auth_mfa_begin_' . $user->ID ); ?>
				<button type="submit" class="button button-primary"><?php esc_html_e( 'Set up an authenticator app', 'vulnhub' ); ?></button>
			</form>
		</div>
		<?php
	}

	/**
	 * Step two: show the QR code and take a confirming code.
	 *
	 * @param \WP_User $user   User.
	 * @param string   $secret Pending base32 secret.
	 * @return void
	 */
	private static function render_confirm( \WP_User $user, string $secret ): void {
		$issuer  = VulnHub_Auth_Policy::issuer_label();
		$account = $user->user_email ? $user->user_email : $user->user_login;
		$uri     = VulnHub_Auth_TOTP::provisioning_uri( $secret, $account, $issuer );

		// Drawn here, in this process. The secret never leaves the server.
		$svg = VulnHub_Auth_QR::svg( $uri, 5, __( 'Authenticator enrolment QR code', 'vulnhub' ) );
		?>
		<div class="vh-card" style="max-width:640px">
			<h3 style="margin-top:0"><?php esc_html_e( 'Scan this with your authenticator app', 'vulnhub' ); ?></h3>

			<div style="display:flex;gap:24px;flex-wrap:wrap;align-items:flex-start">
				<div style="background:#fff;padding:8px;border:1px solid #dcdcde;border-radius:4px;line-height:0">
					<?php
					if ( '' !== $svg ) {
						// Generated entirely by VulnHub_Auth_QR: a fixed set of
						// <svg>, <rect> and <path> elements with numeric
						// attributes, so it is safe to print as markup.
						echo wp_kses(
							$svg,
							array(
								'svg'  => array(
									'xmlns'      => true,
									'width'      => true,
									'height'     => true,
									'viewbox'    => true,
									'role'       => true,
									'aria-label' => true,
								),
								'rect' => array(
									'width'  => true,
									'height' => true,
									'fill'   => true,
								),
								'path' => array(
									'd'    => true,
									'fill' => true,
								),
							)
						);
					} else {
						echo '<p class="vh-muted">' . esc_html__( 'The QR code could not be drawn; use the manual key instead.', 'vulnhub' ) . '</p>';
					}
					?>
				</div>

				<div style="flex:1;min-width:260px">
					<p><?php esc_html_e( 'Cannot scan? Enter this key manually:', 'vulnhub' ); ?></p>
					<p class="vh-mono" style="font-size:15px;letter-spacing:.08em;word-break:break-all">
						<?php echo esc_html( trim( chunk_split( $secret, 4, ' ' ) ) ); ?>
					</p>
					<p class="vh-muted">
						<?php esc_html_e( 'Time-based, 6 digits, 30-second period, SHA-1. This key is shown once and never again.', 'vulnhub' ); ?>
					</p>
				</div>
			</div>

			<hr />

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="vulnhub_auth_mfa_confirm" />
				<input type="hidden" name="user_id" value="<?php echo esc_attr( (string) $user->ID ); ?>" />
				<?php wp_nonce_field( 'vulnhub_auth_mfa_confirm_' . $user->ID ); ?>
				<p>
					<label for="vh_auth_confirm_code"><strong><?php esc_html_e( 'Enter the six-digit code your app is showing', 'vulnhub' ); ?></strong></label><br />
					<input type="text" id="vh_auth_confirm_code" name="vh_auth_code" class="regular-text"
						inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" maxlength="6" required />
				</p>
				<p>
					<button type="submit" class="button button-primary"><?php esc_html_e( 'Confirm and switch on', 'vulnhub' ); ?></button>
				</p>
			</form>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="vulnhub_auth_mfa_cancel" />
				<input type="hidden" name="user_id" value="<?php echo esc_attr( (string) $user->ID ); ?>" />
				<?php wp_nonce_field( 'vulnhub_auth_mfa_cancel_' . $user->ID ); ?>
				<button type="submit" class="button-link"><?php esc_html_e( 'Cancel this setup', 'vulnhub' ); ?></button>
			</form>
		</div>
		<?php
	}

	/**
	 * Controls for a user who is already enrolled.
	 *
	 * @param \WP_User $user User.
	 * @return void
	 */
	private static function render_manage( \WP_User $user ): void {
		?>
		<div class="vh-card" style="max-width:640px">
			<h3 style="margin-top:0"><?php esc_html_e( 'Manage your second factor', 'vulnhub' ); ?></h3>
			<p class="vh-muted"><?php esc_html_e( 'Both actions need a current code from your authenticator app, or one of your recovery codes.', 'vulnhub' ); ?></p>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-bottom:18px">
				<input type="hidden" name="action" value="vulnhub_auth_mfa_recovery" />
				<input type="hidden" name="user_id" value="<?php echo esc_attr( (string) $user->ID ); ?>" />
				<?php wp_nonce_field( 'vulnhub_auth_mfa_recovery_' . $user->ID ); ?>
				<label for="vh_auth_recovery_code"><?php esc_html_e( 'Current code', 'vulnhub' ); ?></label>
				<input type="text" id="vh_auth_recovery_code" name="vh_auth_code" class="small-text" inputmode="numeric" autocomplete="one-time-code" required />
				<button type="submit" class="button"><?php esc_html_e( 'Generate new recovery codes', 'vulnhub' ); ?></button>
			</form>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="vulnhub_auth_mfa_disable" />
				<input type="hidden" name="user_id" value="<?php echo esc_attr( (string) $user->ID ); ?>" />
				<?php wp_nonce_field( 'vulnhub_auth_mfa_disable_' . $user->ID ); ?>
				<label for="vh_auth_disable_code"><?php esc_html_e( 'Current code', 'vulnhub' ); ?></label>
				<input type="text" id="vh_auth_disable_code" name="vh_auth_code" class="small-text" inputmode="numeric" autocomplete="one-time-code" required />
				<button type="submit" class="button button-link-delete"><?php esc_html_e( 'Turn two-factor off', 'vulnhub' ); ?></button>
			</form>
		</div>
		<?php
	}

	/**
	 * Administrator's view of somebody else's enrolment.
	 *
	 * @param \WP_User $user    User.
	 * @param bool     $enabled Whether MFA is on.
	 * @return void
	 */
	private static function render_admin_reset( \WP_User $user, bool $enabled ): void {
		if ( ! $enabled ) {
			printf(
				'<p class="description">%s</p>',
				esc_html__( 'This user has not set up two-factor authentication. Only they can enrol, from their own profile screen.', 'vulnhub' )
			);
			return;
		}
		?>
		<div class="vh-card" style="max-width:640px">
			<p><?php esc_html_e( 'Resetting removes this user\'s authenticator secret and recovery codes. They will be asked to enrol again, and will sign in with only a password until they do.', 'vulnhub' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="vulnhub_auth_mfa_reset" />
				<input type="hidden" name="user_id" value="<?php echo esc_attr( (string) $user->ID ); ?>" />
				<?php wp_nonce_field( 'vulnhub_auth_mfa_reset_' . $user->ID ); ?>
				<button type="submit" class="button button-link-delete"
					onclick="return confirm('<?php echo esc_js( __( 'Reset two-factor authentication for this user?', 'vulnhub' ) ); ?>');">
					<?php esc_html_e( 'Reset two-factor authentication', 'vulnhub' ); ?>
				</button>
			</form>
		</div>
		<?php
	}

	/**
	 * Show a freshly generated set of recovery codes, once.
	 *
	 * @param array<int,string> $codes Plaintext codes.
	 * @return void
	 */
	public static function render_recovery_codes( array $codes ): void {
		?>
		<div class="vh-card vh-card--warn" style="max-width:640px">
			<h3 style="margin-top:0"><?php esc_html_e( 'Save your recovery codes now', 'vulnhub' ); ?></h3>
			<p><?php esc_html_e( 'Each code works once, if you lose your authenticator. This is the only time they are shown — they are stored hashed and cannot be recovered.', 'vulnhub' ); ?></p>
			<p class="vh-mono" style="font-size:15px;line-height:2;letter-spacing:.06em">
				<?php foreach ( $codes as $code ) : ?>
					<?php echo esc_html( $code ); ?><br />
				<?php endforeach; ?>
			</p>
		</div>
		<?php
	}

	/**
	 * A tiny nonce-protected POST button.
	 *
	 * @param string $action  admin-post action.
	 * @param int    $user_id Subject user.
	 * @param string $label   Button label.
	 * @return void
	 */
	private static function button_form( string $action, int $user_id, string $label ): void {
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline">
			<input type="hidden" name="action" value="<?php echo esc_attr( $action ); ?>" />
			<input type="hidden" name="user_id" value="<?php echo esc_attr( (string) $user_id ); ?>" />
			<?php wp_nonce_field( $action . '_' . $user_id ); ?>
			<button type="submit" class="button button-small"><?php echo esc_html( $label ); ?></button>
		</form>
		<?php
	}

	/* -----------------------------------------------------------------
	 * Handlers
	 * --------------------------------------------------------------- */

	/**
	 * Validate a request that acts on the current user's own enrolment.
	 *
	 * @param string $action Nonce action prefix.
	 * @return int User id.
	 */
	private static function guard_self( string $action ): int {
		$user_id = isset( $_POST['user_id'] ) ? (int) $_POST['user_id'] : 0; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		check_admin_referer( $action . '_' . $user_id );

		if ( $user_id <= 0 || get_current_user_id() !== $user_id ) {
			wp_die( esc_html__( 'You can only change your own two-factor settings.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}

		return $user_id;
	}

	/**
	 * Send the user back to their profile with a notice.
	 *
	 * @param int    $user_id User id.
	 * @param string $notice  Notice key.
	 * @return never
	 */
	private static function back( int $user_id, string $notice ): void {
		$url = get_current_user_id() === $user_id
			? admin_url( 'profile.php' )
			: admin_url( 'user-edit.php?user_id=' . $user_id );

		// Came from the portal's "Your security" section: go back there, not
		// to profile.php, which a portal-only account is not allowed to see.
		// The nonce field carries the referer, so this is the page the form
		// was actually on.
		$referer = wp_get_referer();
		if (
			get_current_user_id() === $user_id
			&& is_string( $referer )
			&& str_contains( $referer, 'section=' . self::SECTION )
			&& '' !== self::section_url()
		) {
			wp_safe_redirect( self::section_url( array( 'vh_mfa' => $notice ) ) );
			exit;
		}

		wp_safe_redirect( add_query_arg( 'vh_mfa', $notice, $url ) . '#vulnhub-mfa' );
		exit;
	}

	/**
	 * Begin enrolment.
	 *
	 * @return void
	 */
	public static function handle_begin(): void {
		$user_id = self::guard_self( 'vulnhub_auth_mfa_begin' );

		try {
			VulnHub_Auth_User_MFA::begin_enrolment( $user_id );
		} catch ( \Throwable $e ) {
			self::back( $user_id, 'error' );
		}

		VulnHub_Auth_Audit::log( 'mfa.enrol_started', 'Started two-factor enrolment', $user_id );
		self::back( $user_id, 'setup' );
	}

	/**
	 * Confirm enrolment with a code.
	 *
	 * @return void
	 */
	public static function handle_confirm(): void {
		$user_id = self::guard_self( 'vulnhub_auth_mfa_confirm' );
		$code    = isset( $_POST['vh_auth_code'] ) ? sanitize_text_field( wp_unslash( $_POST['vh_auth_code'] ) ) : '';

		if ( ! VulnHub_Auth_User_MFA::confirm_enrolment( $user_id, $code ) ) {
			VulnHub_Auth_Audit::log( 'mfa.enrol_failed', 'Two-factor enrolment code was rejected', $user_id, array(), 'warning' );
			self::back( $user_id, 'badcode' );
		}

		try {
			$codes = VulnHub_Auth_User_MFA::generate_recovery_codes( $user_id );
			set_transient( self::CODES_TRANSIENT . $user_id, $codes, 5 * MINUTE_IN_SECONDS );
		} catch ( \Throwable $e ) {
			unset( $e );
		}

		VulnHub_Auth_Audit::log( 'mfa.enrolled', 'Two-factor authentication switched on', $user_id );
		self::back( $user_id, 'enrolled' );
	}

	/**
	 * Abandon enrolment.
	 *
	 * @return void
	 */
	public static function handle_cancel(): void {
		$user_id = self::guard_self( 'vulnhub_auth_mfa_cancel' );
		VulnHub_Auth_User_MFA::cancel_enrolment( $user_id );
		self::back( $user_id, 'cancelled' );
	}

	/**
	 * Turn MFA off, after proving a current code.
	 *
	 * @return void
	 */
	public static function handle_disable(): void {
		$user_id = self::guard_self( 'vulnhub_auth_mfa_disable' );
		$code    = isset( $_POST['vh_auth_code'] ) ? sanitize_text_field( wp_unslash( $_POST['vh_auth_code'] ) ) : '';

		$reason = '';
		$ok     = VulnHub_Auth_User_MFA::verify_code( $user_id, $code, $reason )
			|| VulnHub_Auth_User_MFA::consume_recovery_code( $user_id, $code );

		if ( ! $ok ) {
			VulnHub_Auth_Audit::log( 'mfa.disable_refused', 'Refused to disable two-factor: code was not valid', $user_id, array(), 'warning' );
			self::back( $user_id, 'badcode' );
		}

		VulnHub_Auth_User_MFA::disable( $user_id );
		VulnHub_Auth_Audit::log( 'mfa.disabled', 'Two-factor authentication switched off by the user', $user_id, array(), 'warning' );
		self::back( $user_id, 'disabled' );
	}

	/**
	 * Reissue recovery codes.
	 *
	 * @return void
	 */
	public static function handle_recovery(): void {
		$user_id = self::guard_self( 'vulnhub_auth_mfa_recovery' );
		$code    = isset( $_POST['vh_auth_code'] ) ? sanitize_text_field( wp_unslash( $_POST['vh_auth_code'] ) ) : '';

		$reason = '';
		if ( ! VulnHub_Auth_User_MFA::verify_code( $user_id, $code, $reason ) ) {
			self::back( $user_id, 'badcode' );
		}

		try {
			$codes = VulnHub_Auth_User_MFA::generate_recovery_codes( $user_id );
			set_transient( self::CODES_TRANSIENT . $user_id, $codes, 5 * MINUTE_IN_SECONDS );
		} catch ( \Throwable $e ) {
			self::back( $user_id, 'error' );
		}

		VulnHub_Auth_Audit::log( 'mfa.recovery_reissued', 'Reissued ten recovery codes', $user_id );
		self::back( $user_id, 'recovery' );
	}

	/**
	 * Forget every trusted browser.
	 *
	 * @return void
	 */
	public static function handle_forget(): void {
		$user_id = self::guard_self( 'vulnhub_auth_mfa_forget' );
		VulnHub_Auth_User_MFA::forget_devices( $user_id );
		VulnHub_Auth_Audit::log( 'mfa.devices_forgotten', 'Cleared all remembered browsers', $user_id );
		self::back( $user_id, 'forgotten' );
	}

	/**
	 * Administrator reset of another user's MFA.
	 *
	 * @return void
	 */
	public static function handle_reset(): void {
		$user_id = isset( $_POST['user_id'] ) ? (int) $_POST['user_id'] : 0; // phpcs:ignore WordPress.Security.NonceVerification.Missing
		check_admin_referer( 'vulnhub_auth_mfa_reset_' . $user_id );

		if ( $user_id <= 0 || ! current_user_can( 'edit_user', $user_id ) ) {
			wp_die( esc_html__( 'You do not have permission to reset this user\'s two-factor authentication.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}

		$subject = get_user_by( 'id', $user_id );
		VulnHub_Auth_User_MFA::disable( $user_id );
		VulnHub_Auth_Throttle::clear( $user_id );

		VulnHub_Auth_Audit::log(
			'mfa.reset',
			sprintf(
				'%s reset two-factor authentication for %s',
				wp_get_current_user()->user_login,
				$subject instanceof \WP_User ? $subject->user_login : ( 'user ' . $user_id )
			),
			$user_id,
			array( 'by' => get_current_user_id() ),
			'warning'
		);

		// Redirect target depends on where the reset came from.
		$referer = wp_get_referer();
		if ( is_string( $referer ) && str_contains( $referer, 'page=' . VULNHUB_AUTH_USERS_PAGE ) ) {
			wp_safe_redirect( add_query_arg( 'vh_mfa', 'reset', vh_admin_url( VULNHUB_AUTH_USERS_PAGE ) ) );
			exit;
		}

		self::back( $user_id, 'reset' );
	}

	/* -----------------------------------------------------------------
	 * Notices
	 * --------------------------------------------------------------- */

	/**
	 * Notice text for a redirect flag.
	 *
	 * @return void
	 */
	public static function notices(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$flag = isset( $_GET['vh_mfa'] ) ? sanitize_key( wp_unslash( $_GET['vh_mfa'] ) ) : '';
		if ( '' === $flag ) {
			return;
		}

		$messages = array(
			'setup'     => array( 'info', __( 'Scan the QR code below with your authenticator app, then enter a code to finish.', 'vulnhub' ) ),
			'enrolled'  => array( 'success', __( 'Two-factor authentication is now on. Save the recovery codes below — they are shown only once.', 'vulnhub' ) ),
			'badcode'   => array( 'error', __( 'That code was not valid. Check your authenticator app and try again.', 'vulnhub' ) ),
			'cancelled' => array( 'info', __( 'Two-factor setup cancelled.', 'vulnhub' ) ),
			'disabled'  => array( 'warning', __( 'Two-factor authentication has been switched off for your account.', 'vulnhub' ) ),
			'recovery'  => array( 'success', __( 'New recovery codes issued. The old ones no longer work.', 'vulnhub' ) ),
			'forgotten' => array( 'success', __( 'Every remembered browser has been forgotten.', 'vulnhub' ) ),
			'reset'     => array( 'warning', __( 'Two-factor authentication has been reset for that user.', 'vulnhub' ) ),
			'required'  => array( 'error', __( 'Two-factor authentication is required for your account. Set it up below to continue.', 'vulnhub' ) ),
			'error'     => array( 'error', __( 'Something went wrong. Please try again.', 'vulnhub' ) ),
		);

		if ( ! isset( $messages[ $flag ] ) ) {
			return;
		}

		printf(
			'<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>',
			esc_attr( $messages[ $flag ][0] ),
			esc_html( $messages[ $flag ][1] )
		);
	}
}

