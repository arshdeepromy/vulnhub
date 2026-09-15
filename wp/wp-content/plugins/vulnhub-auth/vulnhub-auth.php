<?php
/**
 * Plugin Name:       VulnHub Authentication
 * Plugin URI:        https://github.com/arshdeepromy/vulnhub
 * Description:       Portal account management, multi-factor authentication and enterprise single sign-on for the VulnHub platform — RFC 6238 TOTP with recovery codes, Okta OIDC, Microsoft Entra ID OIDC, generic OpenID Connect, and Active Directory / LDAP.
 * Version:           1.1.0
 * Requires at least: 6.5
 * Requires PHP:      8.1
 * Author:            Romy Sidhu
 * License:           GPL-2.0-or-later
 * Text Domain:       vulnhub
 *
 * @package VulnHub\Auth
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_AUTH_VERSION', '1.1.0' );
define( 'VULNHUB_AUTH_DIR', plugin_dir_path( __FILE__ ) );
define( 'VULNHUB_AUTH_URL', plugin_dir_url( __FILE__ ) );
define( 'VULNHUB_AUTH_USERS_PAGE', 'vulnhub-auth' );

/**
 * Core carries the credential vault, the audit trail and the role definitions
 * this plugin writes to.
 *
 * We deliberately do NOT test for it here. WordPress loads active plugins in
 * alphabetical order, so `vulnhub-auth` is loaded BEFORE `vulnhub-core` and
 * `vulnhub()` does not exist yet at this point in the request. Returning early
 * on that basis would silently disable MFA and SSO entirely. Instead we load
 * our own classes unconditionally — they have no core dependency at file scope
 * — and check for core on `plugins_loaded`, by which time every plugin file
 * has been read.
 */
add_action(
	'plugins_loaded',
	static function (): void {
		if ( function_exists( 'vulnhub' ) ) {
			return;
		}
		add_action(
			'admin_notices',
			static function (): void {
				if ( ! current_user_can( 'activate_plugins' ) ) {
					return;
				}
				printf(
					'<div class="notice notice-error"><p><strong>%s</strong> %s</p></div>',
					esc_html__( 'VulnHub Authentication:', 'vulnhub' ),
					esc_html__( 'VulnHub Core must be active for MFA and SSO to work. Activate it, or deactivate this plugin.', 'vulnhub' )
				);
			}
		);
	},
	1
);

/* -------------------------------------------------------------------------
 * Load order matters: the shared abstract connector must exist before the
 * four provider subclasses, and TOTP/QR/JWT are leaf dependencies.
 * ---------------------------------------------------------------------- */
require_once VULNHUB_AUTH_DIR . 'includes/class-vh-auth-audit.php';
require_once VULNHUB_AUTH_DIR . 'includes/class-vh-auth-totp.php';
require_once VULNHUB_AUTH_DIR . 'includes/class-vh-auth-qr.php';
require_once VULNHUB_AUTH_DIR . 'includes/class-vh-auth-jwt.php';
require_once VULNHUB_AUTH_DIR . 'includes/class-vh-auth-policy.php';
require_once VULNHUB_AUTH_DIR . 'includes/class-vh-auth-user-mfa.php';
require_once VULNHUB_AUTH_DIR . 'includes/class-vh-auth-oidc-client.php';
require_once VULNHUB_AUTH_DIR . 'includes/class-vh-auth-sso.php';
require_once VULNHUB_AUTH_DIR . 'includes/class-vh-auth-ldap.php';
require_once VULNHUB_AUTH_DIR . 'includes/class-vh-auth-login.php';
require_once VULNHUB_AUTH_DIR . 'includes/class-vh-auth-profile.php';
require_once VULNHUB_AUTH_DIR . 'includes/class-vh-auth-mail.php';
require_once VULNHUB_AUTH_DIR . 'includes/class-vh-auth-people.php';

/**
 * Boot the runtime pieces.
 *
 * These hook into the WordPress login flow, so they must be registered on
 * every request — including wp-login.php, which never loads the admin.
 */
add_action(
	'plugins_loaded',
	static function (): void {
		if ( ! function_exists( 'vulnhub' ) ) {
			return;
		}
		VulnHub_Auth_Mail::init();
		VulnHub_Auth_People::init();
		VulnHub_Auth_Login::init();
		VulnHub_Auth_Profile::init();
		VulnHub_Auth_SSO::init();
		VulnHub_Auth_LDAP::init();
	},
	20
);

add_action( 'admin_notices', array( 'VulnHub_Auth_Profile', 'notices' ) );

/**
 * Register one connector per identity provider so each gets its own card and
 * credential storage on the Integrations screen.
 */
add_action(
	'vulnhub_register_connectors',
	static function ( \VulnHub\Core\Connectors $connectors ): void {
		require_once VULNHUB_AUTH_DIR . 'includes/class-vh-auth-connector.php';
		require_once VULNHUB_AUTH_DIR . 'includes/class-vh-okta-connector.php';
		require_once VULNHUB_AUTH_DIR . 'includes/class-vh-entra-connector.php';
		require_once VULNHUB_AUTH_DIR . 'includes/class-vh-oidc-connector.php';
		require_once VULNHUB_AUTH_DIR . 'includes/class-vh-ldap-connector.php';
		require_once VULNHUB_AUTH_DIR . 'includes/class-vh-mail-connector.php';

		$connectors->register( new VulnHub_Okta_Connector() );
		$connectors->register( new VulnHub_Entra_Connector() );
		$connectors->register( new VulnHub_OIDC_Connector() );
		$connectors->register( new VulnHub_LDAP_Connector() );
		$connectors->register( new VulnHub_Mail_Connector() );
	}
);

/**
 * Add the Authentication screen to the VulnHub menu.
 *
 * @param array<string,array<string,mixed>> $pages Existing screens.
 * @return array<string,array<string,mixed>>
 */
add_action(
	'init',
	static function (): void {
		add_filter(
			'vulnhub_admin_pages',
			static function ( array $pages ): array {
				$insert = array(
					VULNHUB_AUTH_USERS_PAGE => array(
						'title' => __( 'Authentication &amp; MFA', 'vulnhub' ),
						'menu'  => __( 'Authentication', 'vulnhub' ),
						'cap'   => \VulnHub\Core\Caps::MANAGE,
						'view'  => 'vulnhub-auth-screen',
					),
				);

				// Slot it in just before Settings so the menu reads sensibly.
				$out = array();
				foreach ( $pages as $slug => $page ) {
					if ( 'vulnhub-settings' === $slug ) {
						$out = array_merge( $out, $insert );
						$insert = array();
					}
					$out[ $slug ] = $page;
				}

				return array_merge( $out, $insert );
			}
		);
	}
);

/**
 * Render our screen. Core fires this when it has no view file of its own for
 * the requested slug.
 */
add_action(
	'vulnhub_render_admin_page',
	static function ( string $slug ): void {
		if ( VULNHUB_AUTH_USERS_PAGE === $slug ) {
			include VULNHUB_AUTH_DIR . 'admin/views/auth.php';
		}
	}
);

/**
 * Save the MFA policy.
 */
add_action(
	'admin_post_vulnhub_auth_save_policy',
	static function (): void {
		if ( ! current_user_can( \VulnHub\Core\Caps::MANAGE ) ) {
			wp_die( esc_html__( 'You do not have permission to change authentication policy.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'vulnhub_auth_save_policy' );

		$saved = VulnHub_Auth_Policy::save(
			array(
				'mode'              => isset( $_POST['mode'] ) ? sanitize_key( wp_unslash( $_POST['mode'] ) ) : '',
				'roles'             => isset( $_POST['roles'] ) ? (array) wp_unslash( $_POST['roles'] ) : array(),
				'grace_days'        => isset( $_POST['grace_days'] ) ? (int) $_POST['grace_days'] : 7,
				'remember_enabled'  => isset( $_POST['remember_enabled'] ),
				'remember_days'     => isset( $_POST['remember_days'] ) ? (int) $_POST['remember_days'] : 30,
				'lockout_threshold' => isset( $_POST['lockout_threshold'] ) ? (int) $_POST['lockout_threshold'] : 5,
				'lockout_minutes'   => isset( $_POST['lockout_minutes'] ) ? (int) $_POST['lockout_minutes'] : 15,
				'skip_for_sso'      => isset( $_POST['skip_for_sso'] ),
				'issuer_label'      => isset( $_POST['issuer_label'] ) ? sanitize_text_field( wp_unslash( $_POST['issuer_label'] ) ) : '',
			)
		);

		VulnHub_Auth_Audit::log(
			'auth.policy_saved',
			sprintf(
				/* translators: %s: policy mode. */
				__( 'MFA policy set to "%s"', 'vulnhub' ),
				VulnHub_Auth_Policy::modes()[ $saved['mode'] ] ?? $saved['mode']
			),
			get_current_user_id(),
			$saved,
			'warning'
		);

		wp_safe_redirect(
			add_query_arg(
				array(
					'vh_msg'  => __( 'Authentication policy saved.', 'vulnhub' ),
					'vh_type' => 'success',
				),
				vh_admin_url( VULNHUB_AUTH_USERS_PAGE )
			)
		);
		exit;
	}
);

/**
 * Save the IdP group → VulnHub role mapping table.
 */
add_action(
	'admin_post_vulnhub_auth_save_rolemap',
	static function (): void {
		if ( ! current_user_can( \VulnHub\Core\Caps::MANAGE ) ) {
			wp_die( esc_html__( 'You do not have permission to change role mapping.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'vulnhub_auth_save_rolemap' );

		$providers = isset( $_POST['provider'] ) ? (array) wp_unslash( $_POST['provider'] ) : array();
		$groups    = isset( $_POST['group'] ) ? (array) wp_unslash( $_POST['group'] ) : array();
		$roles     = isset( $_POST['role'] ) ? (array) wp_unslash( $_POST['role'] ) : array();

		$rows = array();
		foreach ( $providers as $i => $provider ) {
			$group = trim( (string) ( $groups[ $i ] ?? '' ) );
			if ( '' === $group ) {
				continue;
			}
			$rows[] = array(
				'provider' => (string) $provider,
				'group'    => $group,
				'role'     => (string) ( $roles[ $i ] ?? '' ),
			);
		}

		$saved = VulnHub_Auth_SSO::save_role_map( $rows );

		VulnHub_Auth_Audit::log(
			'auth.role_map_saved',
			sprintf(
				/* translators: %d: number of mapping rows. */
				__( 'SSO role mapping saved (%d rules)', 'vulnhub' ),
				count( $saved )
			),
			get_current_user_id(),
			array( 'rules' => $saved ),
			'warning'
		);

		wp_safe_redirect(
			add_query_arg(
				array(
					'tab'     => 'sso',
					'vh_msg'  => __( 'Role mapping saved.', 'vulnhub' ),
					'vh_type' => 'success',
				),
				vh_admin_url( VULNHUB_AUTH_USERS_PAGE )
			)
		);
		exit;
	}
);

/**
 * Toggle SSO-only mode.
 */
add_action(
	'admin_post_vulnhub_auth_save_ssoonly',
	static function (): void {
		if ( ! current_user_can( \VulnHub\Core\Caps::MANAGE ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'vulnhub_auth_save_ssoonly' );

		$on = isset( $_POST['sso_only'] );
		update_option( 'vulnhub_auth_sso_only', $on ? 1 : 0, false );

		VulnHub_Auth_Audit::log(
			$on ? 'auth.sso_only_enabled' : 'auth.sso_only_disabled',
			$on
				? __( 'SSO-only login enabled — the password form is now hidden', 'vulnhub' )
				: __( 'SSO-only login disabled — the password form is visible again', 'vulnhub' ),
			get_current_user_id(),
			array(),
			'warning'
		);

		wp_safe_redirect(
			add_query_arg(
				array(
					'tab'     => 'sso',
					'vh_msg'  => $on
						? __( 'SSO-only mode is on. Keep the escape-hatch URL somewhere safe.', 'vulnhub' )
						: __( 'SSO-only mode is off.', 'vulnhub' ),
					'vh_type' => $on ? 'warning' : 'success',
				),
				vh_admin_url( VULNHUB_AUTH_USERS_PAGE )
			)
		);
		exit;
	}
);

/**
 * On activation, make sure the policy option exists so the screen has
 * something sane to render before anyone saves it.
 */
register_activation_hook(
	__FILE__,
	static function (): void {
		if ( ! get_option( 'vulnhub_auth_policy' ) ) {
			require_once VULNHUB_AUTH_DIR . 'includes/class-vh-auth-policy.php';
			update_option( 'vulnhub_auth_policy', VulnHub_Auth_Policy::defaults(), false );
		}
	}
);

