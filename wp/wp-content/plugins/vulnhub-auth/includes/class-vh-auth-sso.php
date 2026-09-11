<?php
/**
 * Single sign-on: provider registry, the authorisation-code flow endpoints,
 * user provisioning and group-to-role mapping.
 *
 * The flow, end to end:
 *
 *   1. /wp-login.php?action=vh_sso&provider=okta
 *      -> mint state + nonce + PKCE verifier, stash them in a 10-minute
 *         transient keyed by a hash of the state, bind that record to this
 *         browser with a random cookie value, redirect to /v1/authorize.
 *   2. The provider sends the browser back to
 *      /wp-login.php?action=vh_sso_callback&provider=okta with code + state.
 *   3. state is looked up and the browser binding checked, so a callback
 *      replayed from another browser (or forged entirely) finds nothing.
 *   4. code + code_verifier are exchanged at /v1/token.
 *   5. the ID token's SIGNATURE is verified against the provider's JWKS before
 *      a single claim is used (see VulnHub_Auth_OIDC_Client::verify_id_token).
 *   6. only then are the claims turned into a WordPress user.
 *
 * @package VulnHub\Auth
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * SSO front controller.
 */
final class VulnHub_Auth_SSO {

	/** Login action that starts a sign-in. */
	public const ACTION_START = 'vh_sso';

	/** Login action that receives the provider's redirect. */
	public const ACTION_CALLBACK = 'vh_sso_callback';

	/** Option holding the group -> role mapping table. */
	public const ROLE_MAP_OPTION = 'vulnhub_auth_role_map';

	/**
	 * Query parameter that re-enables the password form when "SSO only" is on.
	 *
	 * Documented on the settings screen. This is not a security boundary — a
	 * password is still required — it exists so that a misconfigured identity
	 * provider cannot permanently lock every administrator out of the site.
	 */
	public const BYPASS_PARAM = 'vh_sso_bypass';

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public static function init(): void {
		add_action( 'login_form_' . self::ACTION_START, array( __CLASS__, 'handle_start' ) );
		add_action( 'login_form_' . self::ACTION_CALLBACK, array( __CLASS__, 'handle_callback' ) );
		add_action( 'login_form', array( __CLASS__, 'render_buttons' ) );
		add_action( 'login_head', array( __CLASS__, 'login_styles' ) );
		add_filter( 'authenticate', array( __CLASS__, 'enforce_sso_only' ), 5, 3 );
		add_filter( 'login_message', array( __CLASS__, 'login_message' ) );
	}

	/* -----------------------------------------------------------------
	 * Provider registry
	 * --------------------------------------------------------------- */

	/**
	 * Provider ids this plugin can drive an OIDC flow with.
	 *
	 * @return array<int,string>
	 */
	public static function provider_ids(): array {
		return array( 'okta', 'entra', 'oidc' );
	}

	/**
	 * Human labels for the sign-in buttons.
	 *
	 * @return array<string,string>
	 */
	public static function provider_labels(): array {
		return array(
			'okta'  => __( 'Sign in with Okta', 'vulnhub' ),
			'entra' => __( 'Sign in with Microsoft', 'vulnhub' ),
			'oidc'  => __( 'Sign in with single sign-on', 'vulnhub' ),
		);
	}

	/**
	 * Is this provider switched on and configured enough to try?
	 *
	 * @param string $provider Provider id.
	 * @return bool
	 */
	public static function is_active( string $provider ): bool {
		if ( ! function_exists( 'vulnhub' ) ) {
			return false;
		}
		$connector = vulnhub()->connectors->get( $provider );
		if ( ! $connector || 'auth' !== $connector->category() ) {
			return false;
		}
		if ( ! $connector->is_enabled() ) {
			return false;
		}

		$settings = vulnhub()->settings;
		return '' !== trim( (string) $settings->get( $provider, 'client_id', '' ) );
	}

	/**
	 * The redirect URI registered with the provider.
	 *
	 * @param string $provider Provider id.
	 * @return string
	 */
	public static function redirect_uri( string $provider ): string {
		return site_url( 'wp-login.php?action=' . self::ACTION_CALLBACK . '&provider=' . rawurlencode( $provider ), 'login' );
	}

	/**
	 * Build a configured OIDC client for a provider.
	 *
	 * @param string $provider Provider id.
	 * @return VulnHub_Auth_OIDC_Client|null
	 */
	public static function client( string $provider ): ?VulnHub_Auth_OIDC_Client {
		if ( ! function_exists( 'vulnhub' ) || ! in_array( $provider, self::provider_ids(), true ) ) {
			return null;
		}

		$settings = vulnhub()->settings;
		$config   = self::endpoints( $provider );

		if ( '' === $config['discovery_url'] ) {
			return null;
		}

		return new VulnHub_Auth_OIDC_Client(
			array(
				'provider'        => $provider,
				'discovery_url'   => $config['discovery_url'],
				'issuer'          => $config['issuer'],
				'client_id'       => (string) $settings->get( $provider, 'client_id', '' ),
				'client_secret'   => $settings->secret( $provider, 'client_secret' ),
				'scopes'          => self::scopes( $provider ),
				'allowed_tenants' => $config['allowed_tenants'],
			)
		);
	}

	/**
	 * Work out the discovery URL and expected issuer for a provider.
	 *
	 * This is where the Okta Org-versus-Custom authorization server difference
	 * and the Entra tenant shape are turned into concrete URLs.
	 *
	 * @param string $provider Provider id.
	 * @return array{discovery_url:string,issuer:string,allowed_tenants:array<int,string>}
	 */
	public static function endpoints( string $provider ): array {
		$out = array(
			'discovery_url'   => '',
			'issuer'          => '',
			'allowed_tenants' => array(),
		);

		if ( ! function_exists( 'vulnhub' ) ) {
			return $out;
		}
		$settings = vulnhub()->settings;

		if ( 'okta' === $provider ) {
			$domain = trim( (string) $settings->get( 'okta', 'okta_domain', '' ) );
			$domain = preg_replace( '#^https?://#', '', $domain ) ?? '';
			$domain = rtrim( $domain, '/' );
			if ( '' === $domain ) {
				return $out;
			}

			$server = trim( (string) $settings->get( 'okta', 'auth_server', 'default' ) );

			if ( 'org' === $server ) {
				// Org authorization server: metadata and issuer sit at the root.
				$out['issuer']        = 'https://' . $domain;
				$out['discovery_url'] = 'https://' . $domain . '/.well-known/openid-configuration';
			} else {
				// Custom authorization server ("default" unless renamed): both
				// the metadata path and the iss claim carry /oauth2/{id}.
				$server               = sanitize_key( $server ) ?: 'default';
				$out['issuer']        = 'https://' . $domain . '/oauth2/' . $server;
				$out['discovery_url'] = 'https://' . $domain . '/oauth2/' . $server . '/.well-known/openid-configuration';
			}

			return $out;
		}

		if ( 'entra' === $provider ) {
			$tenant = trim( (string) $settings->get( 'entra', 'tenant_id', '' ) );
			if ( '' === $tenant ) {
				return $out;
			}
			$tenant = rawurlencode( $tenant );

			$out['discovery_url'] = 'https://login.microsoftonline.com/' . $tenant . '/v2.0/.well-known/openid-configuration';

			// For a single-tenant registration the discovery document returns a
			// concrete issuer and we let the pinning in the client handle it.
			// For common/organizations/consumers Microsoft returns the literal
			// template "https://login.microsoftonline.com/{tenantid}/v2.0", so
			// the issuer is resolved per token against the allow-list below.
			$allowed = array();
			foreach ( preg_split( '/[\s,]+/', (string) $settings->get( 'entra', 'allowed_tenants', '' ) ) ?: array() as $entry ) {
				$entry = trim( (string) $entry );
				if ( '' !== $entry ) {
					$allowed[] = $entry;
				}
			}
			if ( ! $allowed && ! in_array( $tenant, array( 'common', 'organizations', 'consumers' ), true ) ) {
				$allowed[] = rawurldecode( $tenant );
			}
			$out['allowed_tenants'] = $allowed;

			return $out;
		}

		// Generic OIDC: the administrator supplies the discovery URL directly.
		$discovery = trim( (string) $settings->get( 'oidc', 'discovery_url', '' ) );
		if ( '' === $discovery ) {
			return $out;
		}
		$out['discovery_url'] = $discovery;
		$out['issuer']        = trim( (string) $settings->get( 'oidc', 'issuer', '' ) );

		return $out;
	}

	/**
	 * Scopes requested from a provider.
	 *
	 * @param string $provider Provider id.
	 * @return string Space-separated scopes.
	 */
	public static function scopes( string $provider ): string {
		$configured = function_exists( 'vulnhub' )
			? trim( (string) vulnhub()->settings->get( $provider, 'scopes', '' ) )
			: '';

		if ( '' !== $configured ) {
			return $configured;
		}

		if ( 'entra' === $provider ) {
			// offline_access is what makes Entra issue a refresh token; it is
			// harmless when unused and saves a re-registration later.
			return 'openid profile email offline_access';
		}
		if ( 'okta' === $provider ) {
			// "groups" is an Okta-specific scope; it only produces a claim when
			// the app's ID token group filter is configured to allow it.
			return 'openid profile email groups';
		}

		return 'openid profile email';
	}

	/* -----------------------------------------------------------------
	 * Flow: start
	 * --------------------------------------------------------------- */

	/**
	 * Begin an SSO sign-in.
	 *
	 * @return void
	 */
	public static function handle_start(): void {
		$provider = isset( $_GET['provider'] ) ? sanitize_key( wp_unslash( $_GET['provider'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification

		if ( ! self::is_active( $provider ) ) {
			self::fail( __( 'That single sign-on provider is not enabled.', 'vulnhub' ) );
		}

		$client = self::client( $provider );
		if ( ! $client ) {
			self::fail( __( 'That single sign-on provider is not fully configured.', 'vulnhub' ) );
		}

		$redirect_to = isset( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification

		try {
			$request = $client->authorization_request( self::redirect_uri( $provider ), $redirect_to );
		} catch ( \Throwable $e ) {
			VulnHub_Auth_Audit::log(
				'sso.start_failed',
				sprintf( 'Could not start %s sign-in: %s', $provider, $e->getMessage() ),
				0,
				array( 'provider' => $provider ),
				'error'
			);
			self::fail( $e->getMessage() );
		}

		// Bind the pending request to this browser: the callback must arrive
		// with both the state (from the provider) and the binder (from our own
		// cookie), so a state value leaked in a referrer or a log is not enough
		// on its own to complete somebody else's sign-in.
		try {
			$binder = bin2hex( random_bytes( 16 ) );
		} catch ( \Throwable $e ) {
			self::fail( __( 'Secure random numbers are unavailable on this server.', 'vulnhub' ) );
		}

		$record           = $request['request'];
		$record['binder'] = hash_hmac( 'sha256', $binder, wp_salt( 'auth' ) );

		set_transient( self::state_key( $request['state'] ), $record, VulnHub_Auth_OIDC_Client::REQUEST_TTL );

		setcookie(
			self::binder_cookie(),
			$binder,
			array(
				'expires'  => time() + VulnHub_Auth_OIDC_Client::REQUEST_TTL,
				'path'     => COOKIEPATH ? COOKIEPATH : '/',
				'domain'   => COOKIE_DOMAIN,
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);

		VulnHub_Auth_Audit::log(
			'sso.start',
			sprintf( 'Started %s single sign-on', $provider ),
			0,
			array( 'provider' => $provider )
		);

		// Deliberately not wp_safe_redirect(): the destination is the identity
		// provider, which is off-site by definition. It comes from the
		// discovery document of a provider an administrator configured, not
		// from user input.
		wp_redirect( $request['url'] ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
		exit;
	}

	/* -----------------------------------------------------------------
	 * Flow: callback
	 * --------------------------------------------------------------- */

	/**
	 * Receive the provider's redirect and finish the sign-in.
	 *
	 * @return void
	 */
	public static function handle_callback(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- state is the CSRF token for this leg, per OAuth 2.0.
		$provider = isset( $_GET['provider'] ) ? sanitize_key( wp_unslash( $_GET['provider'] ) ) : '';
		$state    = isset( $_GET['state'] ) ? sanitize_text_field( wp_unslash( $_GET['state'] ) ) : '';
		$code     = isset( $_GET['code'] ) ? sanitize_text_field( wp_unslash( $_GET['code'] ) ) : '';
		$error    = isset( $_GET['error'] ) ? sanitize_text_field( wp_unslash( $_GET['error'] ) ) : '';
		// phpcs:enable

		if ( '' !== $error ) {
			VulnHub_Auth_Audit::log(
				'sso.provider_error',
				sprintf( '%s returned an error during sign-in: %s', $provider, $error ),
				0,
				array( 'provider' => $provider ),
				'warning'
			);
			self::fail( __( 'The identity provider refused the sign-in.', 'vulnhub' ) );
		}

		if ( '' === $state || '' === $code ) {
			self::fail( __( 'The sign-in response was incomplete.', 'vulnhub' ) );
		}

		$record = get_transient( self::state_key( $state ) );
		delete_transient( self::state_key( $state ) ); // Single use, whatever happens next.

		if ( ! is_array( $record ) || ( $record['provider'] ?? '' ) !== $provider ) {
			VulnHub_Auth_Audit::log(
				'sso.state_invalid',
				'Single sign-on callback carried an unknown or expired state value',
				0,
				array( 'provider' => $provider ),
				'warning'
			);
			self::fail( __( 'This sign-in link has expired. Please try again.', 'vulnhub' ) );
		}

		// Browser binding.
		$cookie = isset( $_COOKIE[ self::binder_cookie() ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::binder_cookie() ] ) ) : '';
		if ( '' === $cookie || ! hash_equals( (string) $record['binder'], hash_hmac( 'sha256', $cookie, wp_salt( 'auth' ) ) ) ) {
			VulnHub_Auth_Audit::log(
				'sso.binding_invalid',
				'Single sign-on callback did not come from the browser that started it',
				0,
				array( 'provider' => $provider ),
				'warning'
			);
			self::fail( __( 'This sign-in did not start in this browser. Please try again.', 'vulnhub' ) );
		}

		$client = self::client( $provider );
		if ( ! $client ) {
			self::fail( __( 'That single sign-on provider is not configured.', 'vulnhub' ) );
		}

		try {
			$tokens = $client->exchange_code( $code, (string) $record['verifier'], (string) $record['redirect_uri'] );
			$claims = $client->verify_id_token( (string) $tokens['id_token'], (string) $record['nonce'] );
		} catch ( \Throwable $e ) {
			VulnHub_Auth_Audit::log(
				'sso.token_invalid',
				sprintf( '%s sign-in rejected: %s', $provider, $e->getMessage() ),
				0,
				array( 'provider' => $provider ),
				'error'
			);
			self::fail( $e->getMessage() );
		}

		$user = self::resolve_user( $provider, $claims );
		if ( is_wp_error( $user ) ) {
			self::fail( $user->get_error_message() );
		}

		self::apply_role_mapping( $provider, $user, $claims );

		// Complete the WordPress session. The MFA interceptor sees this flag
		// and honours the "second factor already satisfied by the IdP" policy.
		VulnHub_Auth_Login::$sso_in_progress = true;

		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, false );
		do_action( 'wp_login', $user->user_login, $user );

		VulnHub_Auth_Login::$sso_in_progress = false;

		VulnHub_Auth_Audit::log(
			'sso.login',
			sprintf( '%s signed in through %s', $user->user_login, $provider ),
			$user->ID,
			array(
				'provider' => $provider,
				'subject'  => (string) ( $claims['sub'] ?? '' ),
			)
		);

		$destination = ! empty( $record['redirect_to'] ) ? (string) $record['redirect_to'] : admin_url();
		wp_safe_redirect( apply_filters( 'login_redirect', $destination, $destination, $user ) );
		exit;
	}

	/* -----------------------------------------------------------------
	 * Provisioning
	 * --------------------------------------------------------------- */

	/**
	 * Find or create the WordPress user a set of verified claims refers to.
	 *
	 * Matching order: a previously linked subject, then email, then the login
	 * name derived from the UPN. Only the subject link is immutable; email
	 * matching is what makes "link my existing account" work on first sign-in.
	 *
	 * @param string              $provider Provider id.
	 * @param array<string,mixed> $claims   Verified ID token claims.
	 * @return \WP_User|\WP_Error
	 */
	public static function resolve_user( string $provider, array $claims ): \WP_User|\WP_Error {
		$subject = (string) ( $claims['sub'] ?? '' );
		$email   = self::claim_email( $claims );
		$name    = (string) ( $claims['name'] ?? '' );

		// 1. Already linked?
		$linked = get_users(
			array(
				'meta_key'   => self::subject_meta( $provider ), // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
				'meta_value' => $subject,                        // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_value
				'number'     => 1,
				'fields'     => 'all',
			)
		);
		if ( $linked ) {
			return $linked[0];
		}

		if ( '' === $email ) {
			return new \WP_Error(
				'vh_auth_no_email',
				__( 'The identity provider did not return an email address or username, so the account could not be matched.', 'vulnhub' )
			);
		}

		// 2. Existing account with that address.
		$user = get_user_by( 'email', $email );
		if ( ! $user ) {
			$user = get_user_by( 'login', $email );
		}

		if ( $user ) {
			update_user_meta( $user->ID, self::subject_meta( $provider ), $subject );
			VulnHub_Auth_Audit::log(
				'sso.linked',
				sprintf( 'Linked %s to their %s identity', $user->user_login, $provider ),
				$user->ID,
				array( 'provider' => $provider )
			);
			return $user;
		}

		// 3. Create, if the administrator allowed it.
		if ( ! function_exists( 'vulnhub' ) || ! vulnhub()->settings->get_bool( $provider, 'auto_create', false ) ) {
			VulnHub_Auth_Audit::log(
				'sso.denied',
				sprintf( 'Refused %s sign-in for %s: no matching account and auto-creation is off', $provider, $email ),
				0,
				array( 'provider' => $provider ),
				'warning'
			);
			return new \WP_Error(
				'vh_auth_no_account',
				__( 'There is no account here for that identity, and automatic account creation is switched off.', 'vulnhub' )
			);
		}

		$login = sanitize_user( (string) ( $claims['preferred_username'] ?? $email ), true );
		if ( '' === $login || username_exists( $login ) ) {
			$login = sanitize_user( $email, true );
		}
		if ( '' === $login || username_exists( $login ) ) {
			$login = 'sso_' . substr( md5( $provider . '|' . $subject ), 0, 12 );
		}

		$user_id = wp_insert_user(
			array(
				'user_login'   => $login,
				'user_email'   => $email,
				'display_name' => '' !== $name ? $name : $login,
				'first_name'   => (string) ( $claims['given_name'] ?? '' ),
				'last_name'    => (string) ( $claims['family_name'] ?? '' ),
				// A long random password nobody ever learns: the account is
				// only reachable through the identity provider unless an
				// administrator sets one deliberately.
				'user_pass'    => wp_generate_password( 64, true, true ),
				'role'         => self::default_role( $provider ),
			)
		);

		if ( is_wp_error( $user_id ) ) {
			return $user_id;
		}

		update_user_meta( $user_id, self::subject_meta( $provider ), $subject );

		VulnHub_Auth_Audit::log(
			'sso.provisioned',
			sprintf( 'Created %s from a verified %s identity', $login, $provider ),
			(int) $user_id,
			array(
				'provider' => $provider,
				'role'     => self::default_role( $provider ),
			)
		);

		return new \WP_User( (int) $user_id );
	}

	/**
	 * Best email/UPN from the claims.
	 *
	 * @param array<string,mixed> $claims Verified claims.
	 * @return string
	 */
	private static function claim_email( array $claims ): string {
		foreach ( array( 'email', 'preferred_username', 'upn', 'unique_name' ) as $key ) {
			$value = trim( (string) ( $claims[ $key ] ?? '' ) );
			if ( '' !== $value && is_email( $value ) ) {
				return strtolower( $value );
			}
		}
		return '';
	}

	/**
	 * Meta key linking a user to a provider subject.
	 *
	 * @param string $provider Provider id.
	 * @return string
	 */
	public static function subject_meta( string $provider ): string {
		return '_vh_auth_sso_' . $provider . '_sub';
	}

	/**
	 * Role given to a newly provisioned account.
	 *
	 * @param string $provider Provider id.
	 * @return string
	 */
	public static function default_role( string $provider ): string {
		$role = function_exists( 'vulnhub' )
			? sanitize_key( (string) vulnhub()->settings->get( $provider, 'default_role', 'vulnhub_viewer' ) )
			: 'vulnhub_viewer';

		return wp_roles()->is_role( $role ) ? $role : 'vulnhub_viewer';
	}

	/* -----------------------------------------------------------------
	 * Group -> role mapping
	 * --------------------------------------------------------------- */

	/**
	 * The whole mapping table.
	 *
	 * @return array<int,array{provider:string,group:string,role:string}>
	 */
	public static function role_map(): array {
		$rows = get_option( self::ROLE_MAP_OPTION, array() );
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Persist a sanitised mapping table.
	 *
	 * @param array<int,array<string,string>> $rows Raw rows.
	 * @return array<int,array{provider:string,group:string,role:string}>
	 */
	public static function save_role_map( array $rows ): array {
		$vulnhub_roles = array_keys( \VulnHub\Core\Caps::roles() );
		$clean         = array();

		foreach ( $rows as $row ) {
			$provider = sanitize_key( (string) ( $row['provider'] ?? '' ) );
			$group    = sanitize_text_field( (string) ( $row['group'] ?? '' ) );
			$role     = sanitize_key( (string) ( $row['role'] ?? '' ) );

			if ( '' === $group || ! in_array( $provider, array_merge( self::provider_ids(), array( 'ldap' ) ), true ) ) {
				continue;
			}
			if ( ! in_array( $role, $vulnhub_roles, true ) ) {
				continue;
			}

			$clean[] = array(
				'provider' => $provider,
				'group'    => $group,
				'role'     => $role,
			);
		}

		update_option( self::ROLE_MAP_OPTION, $clean, false );

		return $clean;
	}

	/**
	 * Extract group/role names from an identity provider's claims.
	 *
	 * Also detects the Entra ID groups overage: when a user is in more groups
	 * than fit in a token, Microsoft omits `groups` entirely and instead sends
	 * `_claim_names` / `_claim_sources` pointing at a Microsoft Graph endpoint
	 * (`.../users/{id}/getMemberObjects`). Silently mapping nothing in that
	 * case would quietly strip an administrator's access, so it is reported
	 * instead.
	 *
	 * @param array<string,mixed> $claims   Verified claims.
	 * @param bool                $overage  Out: true when groups were truncated.
	 * @param string              $endpoint Out: the Graph endpoint to call.
	 * @return array<int,string> Group and role names/ids.
	 */
	public static function claim_groups( array $claims, bool &$overage = false, string &$endpoint = '' ): array {
		$overage  = false;
		$endpoint = '';

		$names = $claims['_claim_names'] ?? array();
		if ( is_array( $names ) && isset( $names['groups'] ) ) {
			$overage = true;
			$source  = (string) $names['groups'];
			$sources = $claims['_claim_sources'] ?? array();
			if ( is_array( $sources ) && isset( $sources[ $source ]['endpoint'] ) ) {
				$endpoint = (string) $sources[ $source ]['endpoint'];
			}
		}

		$groups = array();
		foreach ( array( 'groups', 'roles', 'wids' ) as $key ) {
			foreach ( (array) ( $claims[ $key ] ?? array() ) as $value ) {
				if ( is_scalar( $value ) && '' !== (string) $value ) {
					$groups[] = (string) $value;
				}
			}
		}

		return array_values( array_unique( $groups ) );
	}

	/**
	 * Apply the mapping table to a user's VulnHub roles.
	 *
	 * Only `vulnhub_*` roles are touched. A WordPress `administrator` keeps
	 * their administrator role no matter what the identity provider says, so
	 * an IdP misconfiguration cannot demote the site owner.
	 *
	 * @param string              $provider Provider id.
	 * @param \WP_User            $user     User.
	 * @param array<string,mixed> $claims   Verified claims.
	 * @return void
	 */
	public static function apply_role_mapping( string $provider, \WP_User $user, array $claims ): void {
		$overage  = false;
		$endpoint = '';
		$groups   = self::claim_groups( $claims, $overage, $endpoint );

		if ( $overage ) {
			update_user_meta( $user->ID, '_vh_auth_groups_overage', $endpoint );
			VulnHub_Auth_Audit::log(
				'sso.groups_overage',
				sprintf(
					'%s has too many %s groups to fit in the token; group mapping needs a Microsoft Graph lookup',
					$user->user_login,
					$provider
				),
				$user->ID,
				array(
					'provider' => $provider,
					'endpoint' => $endpoint,
				),
				'warning'
			);
		} else {
			delete_user_meta( $user->ID, '_vh_auth_groups_overage' );
		}

		$map     = self::role_map();
		$matched = array();

		foreach ( $map as $row ) {
			if ( $row['provider'] !== $provider ) {
				continue;
			}
			foreach ( $groups as $group ) {
				// Case-insensitive because Okta group names and Entra role
				// values are both authored by hand in a console.
				if ( 0 === strcasecmp( $group, $row['group'] ) ) {
					$matched[] = $row['role'];
				}
			}
		}

		$matched = array_values( array_unique( $matched ) );

		if ( ! $matched ) {
			if ( $groups || $overage ) {
				VulnHub_Auth_Audit::log(
					'sso.role_map_none',
					sprintf( 'No VulnHub role mapping matched for %s; existing roles left unchanged', $user->user_login ),
					$user->ID,
					array(
						'provider' => $provider,
						'groups'   => count( $groups ),
						'overage'  => $overage,
					)
				);
			}
			return;
		}

		$vulnhub_roles = array_keys( \VulnHub\Core\Caps::roles() );
		$before        = array_values( array_intersect( (array) $user->roles, $vulnhub_roles ) );

		foreach ( $before as $role ) {
			if ( ! in_array( $role, $matched, true ) ) {
				$user->remove_role( $role );
			}
		}
		foreach ( $matched as $role ) {
			if ( ! in_array( $role, (array) $user->roles, true ) ) {
				$user->add_role( $role );
			}
		}

		if ( $before !== $matched ) {
			VulnHub_Auth_Audit::log(
				'sso.role_mapped',
				sprintf( 'Mapped %s onto %s from their %s groups', $user->user_login, implode( ', ', $matched ), $provider ),
				$user->ID,
				array(
					'provider' => $provider,
					'before'   => $before,
					'after'    => $matched,
				)
			);
		}
	}

	/* -----------------------------------------------------------------
	 * Login screen integration
	 * --------------------------------------------------------------- */

	/**
	 * Is the password form currently suppressed?
	 *
	 * @return bool
	 */
	public static function sso_only(): bool {
		if ( ! function_exists( 'vulnhub' ) ) {
			return false;
		}
		if ( ! (bool) VulnHub_Auth_Policy::get( 'sso_only', false ) && ! self::any_sso_only_flag() ) {
			return false;
		}
		return ! self::bypass_requested();
	}

	/**
	 * The "SSO only" switch lives with the SSO settings rather than the MFA
	 * policy, so it is read from whichever provider set it.
	 *
	 * @return bool
	 */
	private static function any_sso_only_flag(): bool {
		if ( ! function_exists( 'vulnhub' ) ) {
			return false;
		}
		return (bool) get_option( 'vulnhub_auth_sso_only', false );
	}

	/**
	 * Has the administrator asked for the password form back?
	 *
	 * @return bool
	 */
	public static function bypass_requested(): bool {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		if ( isset( $_REQUEST[ self::BYPASS_PARAM ] ) && '1' === (string) $_REQUEST[ self::BYPASS_PARAM ] ) {
			return true;
		}
		// phpcs:enable
		return false;
	}

	/**
	 * Refuse password sign-in while "SSO only" is on.
	 *
	 * @param null|\WP_User|\WP_Error $user     Result so far.
	 * @param string                  $username Submitted username.
	 * @param string                  $password Submitted password.
	 * @return null|\WP_User|\WP_Error
	 */
	public static function enforce_sso_only( $user, $username = '', $password = '' ) {
		unset( $password );

		if ( '' === (string) $username || ! self::sso_only() ) {
			return $user;
		}

		VulnHub_Auth_Audit::log(
			'sso.password_blocked',
			sprintf( 'Password sign-in refused for %s: the site is in single sign-on only mode', sanitize_user( (string) $username, true ) ),
			0,
			array(),
			'warning'
		);

		return new \WP_Error(
			'vh_auth_sso_only',
			sprintf(
				/* translators: %s: escape-hatch URL. */
				__( '<strong>Single sign-on only.</strong> Use one of the sign-in buttons above. An administrator can restore the password form with %s.', 'vulnhub' ),
				'<code>?' . esc_html( self::BYPASS_PARAM ) . '=1</code>'
			)
		);
	}

	/**
	 * Render the provider buttons under the login form.
	 *
	 * @return void
	 */
	public static function render_buttons(): void {
		$active = array_filter( self::provider_ids(), array( __CLASS__, 'is_active' ) );
		if ( ! $active ) {
			return;
		}

		$labels = self::provider_labels();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$redirect_to = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : '';
		?>
		<div class="vh-sso">
			<div class="vh-sso__rule"><span><?php esc_html_e( 'or', 'vulnhub' ); ?></span></div>
			<?php foreach ( $active as $provider ) : ?>
				<?php
				$args = array(
					'action'   => self::ACTION_START,
					'provider' => $provider,
				);
				if ( '' !== $redirect_to ) {
					$args['redirect_to'] = $redirect_to;
				}
				?>
				<a class="button button-secondary button-large vh-sso__button"
					href="<?php echo esc_url( add_query_arg( $args, site_url( 'wp-login.php', 'login' ) ) ); ?>">
					<?php echo esc_html( $labels[ $provider ] ?? $provider ); ?>
				</a>
			<?php endforeach; ?>
		</div>
		<?php

		if ( self::bypass_requested() ) {
			printf( '<input type="hidden" name="%s" value="1" />', esc_attr( self::BYPASS_PARAM ) );
		}
	}

	/**
	 * Styling for the buttons, plus hiding the credential fields in SSO-only
	 * mode. The CSS is cosmetic — the real control is enforce_sso_only().
	 *
	 * @return void
	 */
	public static function login_styles(): void {
		$active = array_filter( self::provider_ids(), array( __CLASS__, 'is_active' ) );
		if ( ! $active ) {
			return;
		}
		?>
		<style id="vulnhub-auth-login">
			.vh-sso { margin-top: 20px; }
			.vh-sso__rule { position: relative; text-align: center; margin: 18px 0 14px; color: #646970; font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }
			.vh-sso__rule::before { content: ""; position: absolute; left: 0; right: 0; top: 50%; border-top: 1px solid #dcdcde; }
			.vh-sso__rule span { position: relative; background: #fff; padding: 0 10px; }
			.vh-sso__button { display: block !important; text-align: center; margin-bottom: 8px; }
		</style>
		<?php
		if ( self::sso_only() ) {
			?>
			<style id="vulnhub-auth-sso-only">
				#loginform .user-pass-wrap,
				#loginform > p:first-of-type,
				#loginform .forgetmenot,
				#loginform .submit { display: none; }
			</style>
			<?php
		}
	}

	/**
	 * Explain SSO-only mode and any error carried in the query string.
	 *
	 * @param string $message Existing message markup.
	 * @return string
	 */
	public static function login_message( $message ): string {
		$message = (string) $message;

		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$flag = isset( $_GET['vh_auth'] ) ? sanitize_key( wp_unslash( $_GET['vh_auth'] ) ) : '';
		$note = isset( $_GET['vh_auth_error'] ) ? sanitize_text_field( wp_unslash( $_GET['vh_auth_error'] ) ) : '';
		// phpcs:enable

		if ( 'expired' === $flag ) {
			$message .= '<div id="login_error" class="notice notice-error">'
				. esc_html__( 'That two-factor challenge expired or had already been used. Please sign in again.', 'vulnhub' )
				. '</div>';
		}

		if ( '' !== $note ) {
			$message .= '<div id="login_error" class="notice notice-error">'
				. esc_html( $note )
				. '</div>';
		}

		if ( self::sso_only() ) {
			$message .= '<p class="message">' . esc_html__( 'This site uses single sign-on. Choose your provider below.', 'vulnhub' ) . '</p>';
		}

		return $message;
	}

	/* -----------------------------------------------------------------
	 * Helpers
	 * --------------------------------------------------------------- */

	/**
	 * Transient key for a pending authorisation request.
	 *
	 * The state itself is never used as a key directly, so the key cannot be
	 * guessed from a leaked state without the salt.
	 *
	 * @param string $state State value.
	 * @return string
	 */
	private static function state_key( string $state ): string {
		return 'vh_auth_state_' . hash_hmac( 'sha256', $state, wp_salt( 'auth' ) );
	}

	/**
	 * Cookie name for the browser binding.
	 *
	 * @return string
	 */
	private static function binder_cookie(): string {
		return 'vh_auth_sso_' . COOKIEHASH;
	}

	/**
	 * Abort the flow with a message on the login screen.
	 *
	 * @param string $message Reason.
	 * @return never
	 */
	private static function fail( string $message ): void {
		wp_safe_redirect(
			add_query_arg(
				array(
					'vh_auth_error' => rawurlencode( wp_strip_all_tags( $message ) ),
					self::BYPASS_PARAM => '1',
				),
				wp_login_url()
			)
		);
		exit;
	}
}

