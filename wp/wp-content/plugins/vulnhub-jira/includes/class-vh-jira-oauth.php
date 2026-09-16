<?php
/**
 * Jira Cloud OAuth 2.0 (3LO): "Connect to Jira", then act as the person who
 * clicked Allow.
 *
 * The flow, against Atlassian's documented endpoints
 * (developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps):
 *
 *   1. start     admin-post.php?action=vulnhub_jira_oauth_start (nonce, MANAGE)
 *                -> mint state + PKCE verifier, stash them in a 10-minute
 *                   transient keyed by an HMAC of the state, bind that record
 *                   to this browser with a cookie and to this WordPress user
 *                -> 302 https://auth.atlassian.com/authorize?audience=api.atlassian.com…
 *   2. callback  admin-post.php?action=vulnhub_jira_oauth_cb&code=…&state=…
 *                -> state looked up once and deleted, browser binding and user
 *                   checked, code exchanged at POST /oauth/token with the
 *                   verifier, tokens stored encrypted, then
 *                   GET /oauth/token/accessible-resources picks the cloudId
 *                   whose URL matches the configured site
 *   3. use       VulnHub_Jira_Client calls
 *                https://api.atlassian.com/ex/jira/<cloudId>/rest/… with a
 *                Bearer token from access_token(), which refreshes first when
 *                the token is within a minute of expiry
 *
 * Refresh tokens rotate: every refresh returns a new one and the old one stops
 * working after Atlassian's reuse interval. So the new refresh token is always
 * stored, and refreshing takes a short lock -- two workers refreshing at once
 * would otherwise race to spend the same token, and the loser would disconnect
 * the integration.
 *
 * The state-in-transient and browser-binder shape is the one vulnhub-auth
 * already uses for OIDC sign-in (VulnHub_Auth_SSO), for the same reasons.
 *
 * Nothing here writes a token, a code, or a verifier to any log.
 *
 * @package VulnHub\Jira
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * OAuth 2.0 authorization-code + PKCE for the Jira connector.
 */
final class VulnHub_Jira_OAuth {

	public const ACTION_START      = 'vulnhub_jira_oauth_start';
	public const ACTION_CALLBACK   = 'vulnhub_jira_oauth_cb';
	public const ACTION_DISCONNECT = 'vulnhub_jira_oauth_disconnect';

	public const AUTHORIZE_URL = 'https://auth.atlassian.com/authorize';
	public const TOKEN_URL     = 'https://auth.atlassian.com/oauth/token';
	public const RESOURCES_URL = 'https://api.atlassian.com/oauth/token/accessible-resources';
	public const GATEWAY       = 'https://api.atlassian.com/ex/jira/';

	/**
	 * Classic scopes covering raise, read, comment and attach, on both the
	 * platform API and the JSM request API. `offline_access` is what makes
	 * Atlassian issue a refresh token at all.
	 *
	 * Scopes are product-wide: none of them can be narrowed to one project.
	 * The project allowlist in the connector is what does that.
	 */
	public const DEFAULT_SCOPES = 'read:jira-work write:jira-work read:jira-user read:servicedesk-request write:servicedesk-request offline_access';

	/** How long a started authorisation stays valid. */
	private const REQUEST_TTL = 600;

	/** Refresh when the access token has less than this many seconds left. */
	private const EXPIRY_SKEW = 60;

	/** A refresh lock older than this belongs to a worker that died. */
	private const LOCK_TTL = 30;

	private const LOCK_OPTION = 'vulnhub_jira_oauth_refresh_lock';

	/**
	 * Connection state lives in its own option, not the connector settings.
	 *
	 * Core's Settings::update() writes the whole settings array back from the
	 * copy the request loaded. A sync that started before a token refresh
	 * would then restore the old expiry -- or, after a Disconnect, the old
	 * cloudId. Kept apart and always read fresh, neither can happen.
	 */
	public const STATE_OPTION = 'vulnhub_jira_oauth';

	/** Secret keys, stored encrypted by core's Settings. */
	private const SECRET_ACCESS  = 'oauth_access_token';
	private const SECRET_REFRESH = 'oauth_refresh_token';

	private VulnHub_Jira_Connector $connector;

	public function __construct( VulnHub_Jira_Connector $connector ) {
		$this->connector = $connector;
	}

	public static function hooks(): void {
		add_action( 'admin_post_' . self::ACTION_START, array( __CLASS__, 'handle_start' ) );
		add_action( 'admin_post_' . self::ACTION_CALLBACK, array( __CLASS__, 'handle_callback' ) );
		add_action( 'admin_post_' . self::ACTION_DISCONNECT, array( __CLASS__, 'handle_disconnect' ) );
	}

	/* =================================================================
	 * Configuration
	 * ============================================================== */

	/**
	 * The callback registered with Atlassian. Must match byte for byte.
	 *
	 * Derived from this install's own admin-post.php unless an operator has
	 * set one -- which they do when the browser that clicks Allow reaches the
	 * stack under a different host than WordPress believes it has (localhost
	 * against a public site URL, or the reverse).
	 */
	public function redirect_uri(): string {
		$set = trim( (string) $this->connector->get( 'oauth_redirect_uri', '' ) );

		return '' !== $set ? $set : self::default_redirect_uri();
	}

	public static function default_redirect_uri(): string {
		return add_query_arg( 'action', self::ACTION_CALLBACK, admin_url( 'admin-post.php' ) );
	}

	public function client_id(): string {
		return trim( (string) $this->connector->get( 'oauth_client_id', '' ) );
	}

	private function client_secret(): string {
		return $this->connector->secret( 'oauth_client_secret' );
	}

	public function scopes(): string {
		$set = trim( (string) preg_replace( '/\s+/', ' ', (string) $this->connector->get( 'oauth_scopes', '' ) ) );
		$set = '' !== $set ? $set : self::DEFAULT_SCOPES;

		// Without it there is no refresh token and the connection silently
		// dies an hour after Allow.
		return str_contains( ' ' . $set . ' ', ' offline_access ' ) ? $set : $set . ' offline_access';
	}

	public function has_app(): bool {
		return '' !== $this->client_id() && '' !== $this->client_secret();
	}

	/* =================================================================
	 * State of the connection
	 * ============================================================== */

	public function is_connected(): bool {
		return '' !== $this->cloud_id() && vulnhub()->settings->has_secret( $this->connector->id(), self::SECRET_REFRESH );
	}

	public function cloud_id(): string {
		return trim( (string) $this->fresh( 'oauth_cloud_id' ) );
	}

	/**
	 * Who connected, and to what, for the settings screen.
	 *
	 * @return array{connected:bool,site:string,account:string,account_id:string,connected_at:string,expires_at:int,scopes:string,last_message:string,last_type:string,last_at:string}
	 */
	public function status(): array {
		return array(
			'connected'    => $this->is_connected(),
			'site'         => (string) $this->fresh( 'oauth_site_url' ),
			'account'      => (string) $this->fresh( 'oauth_account_name' ),
			'account_id'   => (string) $this->fresh( 'oauth_account_id' ),
			'connected_at' => (string) $this->fresh( 'oauth_connected_at' ),
			'expires_at'   => (int) $this->fresh( 'oauth_expires_at' ),
			'scopes'       => (string) $this->fresh( 'oauth_granted_scopes' ),
			'last_message' => (string) $this->fresh( 'oauth_last_message' ),
			'last_type'    => (string) $this->fresh( 'oauth_last_type' ),
			'last_at'      => (string) $this->fresh( 'oauth_last_at' ),
		);
	}

	/**
	 * A setting read straight from the option, not the per-request cache.
	 *
	 * Another worker may have refreshed the token since this request loaded
	 * the settings, and a stale expiry or cloudId would make this one refresh
	 * a token that has already been rotated.
	 */
	private function fresh( string $key ): mixed {
		wp_cache_delete( self::STATE_OPTION, 'options' );
		$all = (array) get_option( self::STATE_OPTION, array() );

		return $all[ $key ] ?? '';
	}

	/**
	 * @param array<string,mixed> $values State to merge in.
	 */
	private static function save_state( array $values ): void {
		wp_cache_delete( self::STATE_OPTION, 'options' );
		update_option( self::STATE_OPTION, array_merge( (array) get_option( self::STATE_OPTION, array() ), $values ), false );
	}

	/* =================================================================
	 * Tokens
	 * ============================================================== */

	/**
	 * A usable access token, refreshing first if it is about to expire.
	 *
	 * @param bool $force Refresh even if the stored token looks valid -- used
	 *                    after the API answered 401.
	 * @return string '' when there is no connection or the refresh failed.
	 */
	public function access_token( bool $force = false ): string {
		if ( ! $this->is_connected() ) {
			return '';
		}

		$token   = vulnhub()->settings->secret( $this->connector->id(), self::SECRET_ACCESS );
		$expires = (int) $this->fresh( 'oauth_expires_at' );

		if ( ! $force && '' !== $token && $expires - self::EXPIRY_SKEW > time() ) {
			return $token;
		}

		return $this->refresh( $token );
	}

	/**
	 * Spend the refresh token for a new pair, under a lock.
	 *
	 * @param string $stale The access token the caller found wanting; if a
	 *                      different one is stored by the time the lock is
	 *                      held, somebody else already refreshed.
	 */
	private function refresh( string $stale ): string {
		if ( ! $this->lock() ) {
			// Another worker is refreshing. Give it a moment and use its result.
			usleep( 1500000 );

			$token = vulnhub()->settings->secret( $this->connector->id(), self::SECRET_ACCESS );

			return $token !== $stale && (int) $this->fresh( 'oauth_expires_at' ) > time() ? $token : '';
		}

		try {
			$current = vulnhub()->settings->secret( $this->connector->id(), self::SECRET_ACCESS );

			if ( '' !== $current && $current !== $stale && (int) $this->fresh( 'oauth_expires_at' ) - self::EXPIRY_SKEW > time() ) {
				return $current;
			}

			// JSON body, as Atlassian's 3LO documentation specifies for both
			// the code exchange and the refresh.
			$response = $this->http()->request(
				'POST',
				self::TOKEN_URL,
				array(
					'body'    => array(
						'grant_type'    => 'refresh_token',
						'client_id'     => $this->client_id(),
						'client_secret' => $this->client_secret(),
						'refresh_token' => vulnhub()->settings->secret( $this->connector->id(), self::SECRET_REFRESH ),
					),
					'retries' => 2,
				)
			);

			$data = $response->data();

			if ( ! $response->ok() || empty( $data['access_token'] ) ) {
				$this->connector->log(
					sprintf(
						'Jira OAuth refresh failed (HTTP %d): %s',
						$response->status,
						vh_trim( $response->error_message(), 160 )
					)
				);

				/*
				 * invalid_grant means the refresh token is dead -- revoked in
				 * Atlassian, rotated past its reuse window, or the app lost its
				 * consent. No retry will fix that, so say so plainly rather
				 * than failing every call for ever with a 401.
				 */
				if ( 'invalid_grant' === (string) ( $data['error'] ?? '' ) ) {
					$this->forget( 'refresh token rejected' );
				}

				return '';
			}

			$this->store_tokens( $data );

			return (string) $data['access_token'];
		} finally {
			$this->unlock();
		}
	}

	/**
	 * @param array<string,mixed> $data Token endpoint response.
	 */
	private function store_tokens( array $data ): void {
		$id = $this->connector->id();

		vulnhub()->settings->set_secret( $id, self::SECRET_ACCESS, (string) $data['access_token'] );

		// Rotating refresh tokens: always keep the newest one.
		if ( ! empty( $data['refresh_token'] ) ) {
			vulnhub()->settings->set_secret( $id, self::SECRET_REFRESH, (string) $data['refresh_token'] );
		}

		self::save_state(
			array(
				'oauth_expires_at'     => time() + max( 60, (int) ( $data['expires_in'] ?? 3600 ) ),
				'oauth_granted_scopes' => (string) ( $data['scope'] ?? $this->fresh( 'oauth_granted_scopes' ) ),
			)
		);
	}

	private function lock(): bool {
		if ( add_option( self::LOCK_OPTION, (string) time(), '', false ) ) {
			return true;
		}

		if ( (int) get_option( self::LOCK_OPTION, 0 ) < time() - self::LOCK_TTL ) {
			delete_option( self::LOCK_OPTION );

			return add_option( self::LOCK_OPTION, (string) time(), '', false );
		}

		return false;
	}

	private function unlock(): void {
		delete_option( self::LOCK_OPTION );
	}

	/**
	 * Drop every token and connection detail locally.
	 */
	public function forget( string $reason ): void {
		$id = $this->connector->id();

		vulnhub()->settings->set_secret( $id, self::SECRET_ACCESS, null );
		vulnhub()->settings->set_secret( $id, self::SECRET_REFRESH, null );
		self::save_state(
			array(
				'oauth_cloud_id'       => '',
				'oauth_site_url'       => '',
				'oauth_account_name'   => '',
				'oauth_account_id'     => '',
				'oauth_connected_at'   => '',
				'oauth_expires_at'     => 0,
				'oauth_granted_scopes' => '',
			)
		);

		vulnhub()->logger->audit(
			'jira.oauth_disconnected',
			sprintf( 'Jira OAuth connection removed: %s', $reason ),
			'connector',
			$id,
			array( 'reason' => $reason ),
			'warning'
		);
	}

	private function http(): \VulnHub\Core\Http {
		return new \VulnHub\Core\Http( '', array( $this->connector, 'log' ) );
	}

	/* =================================================================
	 * The flow
	 * ============================================================== */

	/**
	 * URL a "Connect" button points at: nonce-protected, so a link on some
	 * other site cannot start a connection in an administrator's browser.
	 */
	public static function start_url(): string {
		return wp_nonce_url( add_query_arg( 'action', self::ACTION_START, admin_url( 'admin-post.php' ) ), self::ACTION_START );
	}

	public static function disconnect_url(): string {
		return wp_nonce_url( add_query_arg( 'action', self::ACTION_DISCONNECT, admin_url( 'admin-post.php' ) ), self::ACTION_DISCONNECT );
	}

	/**
	 * Build the authorisation request and the record the callback needs.
	 *
	 * @return array{url:string,state:string,record:array<string,mixed>}
	 */
	public function authorization_request(): array {
		$state    = self::b64url( random_bytes( 32 ) );
		$verifier = self::b64url( random_bytes( 48 ) );

		$url = add_query_arg(
			array_map(
				'rawurlencode',
				array(
					'audience'              => 'api.atlassian.com',
					'client_id'             => $this->client_id(),
					'scope'                 => $this->scopes(),
					'redirect_uri'          => $this->redirect_uri(),
					'state'                 => $state,
					'response_type'         => 'code',
					// Re-consent every time, so connecting is always a visible,
					// deliberate act rather than a silent reuse of an old grant.
					'prompt'                => 'consent',
					'code_challenge'        => self::b64url( hash( 'sha256', $verifier, true ) ),
					'code_challenge_method' => 'S256',
				)
			),
			self::AUTHORIZE_URL
		);

		return array(
			'url'    => $url,
			'state'  => $state,
			'record' => array(
				'verifier'     => $verifier,
				'redirect_uri' => $this->redirect_uri(),
				'user_id'      => get_current_user_id(),
			),
		);
	}

	public static function handle_start(): void {
		self::guard();
		check_admin_referer( self::ACTION_START );

		$oauth = self::instance();

		if ( ! $oauth->has_app() ) {
			self::back( __( 'Enter the OAuth client ID and secret from the Atlassian developer console, save, then connect.', 'vulnhub' ), 'error' );
		}

		try {
			$request = $oauth->authorization_request();
			$binder  = bin2hex( random_bytes( 16 ) );
		} catch ( \Throwable $e ) {
			self::back( __( 'Secure random numbers are unavailable on this server.', 'vulnhub' ), 'error' );
		}

		$record           = $request['record'];
		$record['binder'] = hash_hmac( 'sha256', $binder, wp_salt( 'auth' ) );

		set_transient( self::state_key( $request['state'] ), $record, self::REQUEST_TTL );

		setcookie(
			self::binder_cookie(),
			$binder,
			array(
				'expires'  => time() + self::REQUEST_TTL,
				'path'     => COOKIEPATH ? COOKIEPATH : '/',
				'domain'   => COOKIE_DOMAIN,
				'secure'   => is_ssl(),
				'httponly' => true,
				// Lax, not Strict: the callback is a top-level navigation back
				// from auth.atlassian.com, which Strict would strip the cookie from.
				'samesite' => 'Lax',
			)
		);

		vulnhub()->logger->audit( 'jira.oauth_start', 'Started connecting Jira over OAuth', 'connector', 'jira' );

		// Off-site by definition: the destination is Atlassian's authorize
		// endpoint, a constant, not user input.
		wp_redirect( $request['url'] ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
		exit;
	}

	public static function handle_callback(): void {
		self::guard();

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- state is the CSRF token for this leg, per OAuth 2.0.
		$state = isset( $_GET['state'] ) ? sanitize_text_field( wp_unslash( $_GET['state'] ) ) : '';
		$code  = isset( $_GET['code'] ) ? sanitize_text_field( wp_unslash( $_GET['code'] ) ) : '';
		$error = isset( $_GET['error'] ) ? sanitize_text_field( wp_unslash( $_GET['error'] ) ) : '';
		// phpcs:enable

		$record = '' !== $state ? get_transient( self::state_key( $state ) ) : false;

		if ( '' !== $state ) {
			delete_transient( self::state_key( $state ) ); // Single use, whatever happens next.
		}

		if ( '' !== $error ) {
			vulnhub()->logger->audit( 'jira.oauth_refused', sprintf( 'Atlassian returned an error while connecting: %s', $error ), 'connector', 'jira', array(), 'warning' );
			self::back(
				'access_denied' === $error
					? __( 'Connection cancelled: Allow was not clicked on the Atlassian consent screen.', 'vulnhub' )
					/* translators: %s: OAuth error code. */
					: sprintf( __( 'Atlassian refused the connection (%s).', 'vulnhub' ), $error ),
				'error'
			);
		}

		if ( ! is_array( $record ) || '' === $code ) {
			self::back( __( 'That connection attempt has expired or was already used. Start again.', 'vulnhub' ), 'error' );
		}

		$cookie = isset( $_COOKIE[ self::binder_cookie() ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::binder_cookie() ] ) ) : '';

		if ( '' === $cookie || ! hash_equals( (string) $record['binder'], hash_hmac( 'sha256', $cookie, wp_salt( 'auth' ) ) )
			|| (int) $record['user_id'] !== get_current_user_id() ) {
			vulnhub()->logger->audit( 'jira.oauth_binding_invalid', 'Jira OAuth callback did not come from the browser and user that started it', 'connector', 'jira', array(), 'warning' );
			self::back( __( 'This connection was not started in this browser by this account. Start again.', 'vulnhub' ), 'error' );
		}

		setcookie( self::binder_cookie(), '', array( 'expires' => time() - 3600, 'path' => COOKIEPATH ? COOKIEPATH : '/', 'domain' => COOKIE_DOMAIN ) );

		$result = self::instance()->complete( $code, (string) $record['verifier'], (string) $record['redirect_uri'] );

		self::back( $result['message'], $result['ok'] ? 'success' : 'error' );
	}

	/**
	 * Exchange the code, store the tokens, and find the site.
	 *
	 * Public and separate from the request handler so it can be exercised
	 * without a browser.
	 *
	 * @return array{ok:bool,message:string}
	 */
	public function complete( string $code, string $verifier, string $redirect_uri ): array {
		$http     = $this->http();
		$response = $http->request(
			'POST',
			self::TOKEN_URL,
			array(
				'body'    => array(
					'grant_type'    => 'authorization_code',
					'client_id'     => $this->client_id(),
					'client_secret' => $this->client_secret(),
					'code'          => $code,
					'redirect_uri'  => $redirect_uri,
					'code_verifier' => $verifier,
				),
				'retries' => 1,
			)
		);

		$data = $response->data();

		if ( ! $response->ok() || empty( $data['access_token'] ) || empty( $data['refresh_token'] ) ) {
			$why = ! empty( $data['access_token'] ) && empty( $data['refresh_token'] )
				? __( 'Atlassian issued no refresh token. Add the offline_access scope to the app and connect again.', 'vulnhub' )
				: sprintf(
					/* translators: 1: HTTP status, 2: error. */
					__( 'The code exchange failed (HTTP %1$d): %2$s. Check the client secret, and that the callback URL registered with Atlassian is exactly %3$s.', 'vulnhub' ),
					$response->status,
					vh_trim( $response->error_message(), 160 ),
					$redirect_uri
				);

			vulnhub()->logger->audit( 'jira.oauth_exchange_failed', $why, 'connector', 'jira', array( 'status' => $response->status ), 'error' );

			return array( 'ok' => false, 'message' => $why );
		}

		/*
		 * Which site. accessible-resources lists every Atlassian site the grant
		 * reaches; the configured site URL picks one. With no site configured
		 * and exactly one resource, that one is unambiguous. With several and
		 * no match, guessing would point the integration at somebody else's
		 * Jira, so refuse.
		 */
		$resources = $http->get(
			self::RESOURCES_URL,
			array(),
			array( 'Authorization' => 'Bearer ' . (string) $data['access_token'] ),
			array( 'retries' => 2 )
		);

		$sites = array_values(
			array_filter(
				(array) $resources->data(),
				static fn( $r ): bool => is_array( $r ) && ! empty( $r['id'] )
			)
		);

		$wanted = VulnHub_Jira_Client::normalise_base_url( (string) $this->connector->get( 'base_url', '' ) );
		$match  = null;

		foreach ( $sites as $site ) {
			if ( '' !== $wanted && VulnHub_Jira_Client::normalise_base_url( (string) ( $site['url'] ?? '' ) ) === $wanted ) {
				$match = $site;
				break;
			}
		}

		if ( ! $match && 1 === count( $sites ) && ( '' === $wanted || str_contains( $wanted, 'yoursite.atlassian.net' ) ) ) {
			$match = $sites[0];
		}

		if ( ! $match ) {
			$found = implode( ', ', array_map( static fn( array $s ): string => (string) ( $s['url'] ?? '' ), $sites ) );
			$why   = '' === $found
				? __( 'The grant reaches no Jira site. Check the app has the Jira API permission added in the developer console.', 'vulnhub' )
				: sprintf(
					/* translators: 1: configured site, 2: sites the grant reaches. */
					__( 'Connected, but none of the sites this grant reaches matches the configured Jira site URL (%1$s). It reaches: %2$s. Set the site URL to the one you mean and connect again.', 'vulnhub' ),
					'' !== $wanted ? $wanted : __( 'not set', 'vulnhub' ),
					$found
				);

			vulnhub()->logger->audit( 'jira.oauth_no_site', $why, 'connector', 'jira', array(), 'error' );

			return array( 'ok' => false, 'message' => $why );
		}

		$id = $this->connector->id();

		$this->store_tokens( $data );
		self::save_state(
			array(
				'oauth_cloud_id'     => (string) $match['id'],
				'oauth_site_url'     => VulnHub_Jira_Client::normalise_base_url( (string) ( $match['url'] ?? '' ) ),
				'oauth_connected_at' => vh_now(),
			)
		);

		// Who clicked Allow -- through the gateway, which also proves the
		// cloudId and token work together before anything relies on them.
		$me   = $http->get(
			self::GATEWAY . rawurlencode( (string) $match['id'] ) . VulnHub_Jira_Client::API . '/myself',
			array(),
			array( 'Authorization' => 'Bearer ' . (string) $data['access_token'] ),
			array( 'retries' => 2 )
		);
		$who  = $me->data();
		$name = (string) ( $who['displayName'] ?? '' );

		self::save_state(
			array(
				'oauth_account_name' => $name,
				'oauth_account_id'   => (string) ( $who['accountId'] ?? '' ),
			)
		);

		vulnhub()->logger->audit(
			'jira.oauth_connected',
			sprintf( 'Jira connected over OAuth to %s', (string) ( $match['url'] ?? '' ) ),
			'connector',
			$id,
			array( 'site' => (string) ( $match['url'] ?? '' ), 'account_id' => (string) ( $who['accountId'] ?? '' ) )
		);

		return array(
			'ok'      => true,
			'message' => '' !== $name
				/* translators: 1: person, 2: site. */
				? sprintf( __( 'Connected to %2$s as %1$s.', 'vulnhub' ), $name, (string) ( $match['url'] ?? '' ) )
				/* translators: %s: site. */
				: sprintf( __( 'Connected to %s, but reading your profile through the API failed. Run Test connection.', 'vulnhub' ), (string) ( $match['url'] ?? '' ) ),
		);
	}

	public static function handle_disconnect(): void {
		self::guard();
		check_admin_referer( self::ACTION_DISCONNECT );

		/*
		 * Local only. Atlassian documents no token-revocation endpoint for
		 * 3LO apps: a grant is withdrawn by its owner under Atlassian account
		 * settings → Connected apps. So Disconnect makes the tokens unusable
		 * here and says where to finish the job, rather than calling an
		 * undocumented URL and reporting a revoke it cannot vouch for.
		 */
		self::instance()->forget( 'disconnected by an administrator' );

		self::back(
			__( 'Disconnected: the Jira tokens were deleted from this server. To withdraw the grant itself, remove the app under your Atlassian account settings → Connected apps.', 'vulnhub' ),
			'success'
		);
	}

	/* =================================================================
	 * Helpers
	 * ============================================================== */

	private static function instance(): self {
		$connector = vulnhub_jira_connector();

		if ( ! $connector ) {
			wp_die( esc_html__( 'The Jira connector is not available.', 'vulnhub' ), '', array( 'response' => 500 ) );
		}

		return $connector->oauth();
	}

	private static function guard(): void {
		if ( ! is_user_logged_in() || ! current_user_can( \VulnHub\Core\Caps::MANAGE ) ) {
			wp_die( esc_html__( 'You do not have permission to connect integrations.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}
	}

	/**
	 * Back to the Jira settings screen, in the portal when that is where the
	 * operator came from.
	 */
	private static function back( string $message, string $type ): void {
		/*
		 * Kept as well as passed in the URL: the portal only surfaces a
		 * success chip, and "the code exchange failed" is exactly the message
		 * an operator must not miss. The settings screen shows it beside the
		 * Connect button until the next attempt.
		 */
		self::save_state(
			array(
				'oauth_last_message' => $message,
				'oauth_last_type'    => $type,
				'oauth_last_at'      => vh_now(),
			)
		);

		$args = array(
			'connector' => 'jira',
			'vh_msg'    => rawurlencode( $message ),
			'vh_type'   => $type,
		);

		$url = class_exists( 'VulnHub_Dash_Portal' )
			? VulnHub_Dash_Portal::portal_url( VulnHub_Dash_Portal::ADMIN_VIEW, array_merge( array( 'section' => 'integrations' ), $args ) )
			: vh_admin_url( 'vulnhub-integrations', $args );

		wp_safe_redirect( $url );
		exit;
	}

	private static function state_key( string $state ): string {
		return 'vh_jira_oauth_' . hash_hmac( 'sha256', $state, wp_salt( 'auth' ) );
	}

	private static function binder_cookie(): string {
		return 'vh_jira_oauth_' . COOKIEHASH;
	}

	private static function b64url( string $bytes ): string {
		return rtrim( strtr( base64_encode( $bytes ), '+/', '-_' ), '=' );
	}
}
