<?php
/**
 * Active Directory / LDAP authentication.
 *
 * THE ANONYMOUS BIND TRAP: `ldap_bind($ldap, $dn, '')` with an empty password
 * is not a failed authentication — it is an UNAUTHENTICATED bind request, and
 * RFC 4513 §5.1.2 says a server may treat it as an anonymous bind and return
 * success. Active Directory does exactly that. An LDAP login handler that
 * passes the submitted password straight to ldap_bind() therefore accepts an
 * empty password for every account in the directory: a complete authentication
 * bypass. Every bind below refuses an empty (or whitespace-only) password
 * before it goes anywhere near the server.
 *
 * The PHP `ldap` extension is not installed in this container, so everything
 * here degrades to a clear administrative message rather than a fatal error.
 *
 * @package VulnHub\Auth
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Thin, dependency-free AD/LDAP client.
 */
final class VulnHub_Auth_LDAP {

	/** Connector id in core settings. */
	public const ID = 'ldap';

	/** Attributes fetched for a matched user. */
	private const USER_ATTRIBUTES = array(
		'dn',
		'samaccountname',
		'userprincipalname',
		'mail',
		'displayname',
		'givenname',
		'sn',
		'memberof',
		'useraccountcontrol',
	);

	/**
	 * Is the PHP ldap extension present?
	 *
	 * @return bool
	 */
	public static function available(): bool {
		return function_exists( 'ldap_connect' ) && function_exists( 'ldap_bind' );
	}

	/**
	 * Read a connector setting.
	 *
	 * @param string $key     Setting key.
	 * @param string $default Fallback.
	 * @return string
	 */
	private static function setting( string $key, string $default = '' ): string {
		if ( ! function_exists( 'vulnhub' ) ) {
			return $default;
		}
		return trim( (string) vulnhub()->settings->get( self::ID, $key, $default ) );
	}

	/**
	 * The LDAP URI built from the configured host, port and TLS choice.
	 *
	 * @return string
	 */
	public static function uri(): string {
		$host = self::setting( 'host' );
		if ( '' === $host ) {
			return '';
		}
		$host = preg_replace( '#^ldaps?://#i', '', $host ) ?? '';

		$use_tls = ! function_exists( 'vulnhub' ) || vulnhub()->settings->get_bool( self::ID, 'use_ldaps', true );
		$port    = (int) ( self::setting( 'port', '' ) ?: ( $use_tls ? '636' : '389' ) );

		return ( $use_tls ? 'ldaps://' : 'ldap://' ) . $host . ':' . $port;
	}

	/**
	 * Open a connection and bind with the service account.
	 *
	 * @return array{ok:bool,message:string,conn:mixed}
	 */
	public static function service_connect(): array {
		if ( ! self::available() ) {
			return array(
				'ok'      => false,
				'message' => __( 'The PHP ldap extension is not installed on this server, so Active Directory authentication cannot run.', 'vulnhub' ),
				'conn'    => null,
			);
		}

		$uri = self::uri();
		if ( '' === $uri ) {
			return array(
				'ok'      => false,
				'message' => __( 'No directory server host is configured.', 'vulnhub' ),
				'conn'    => null,
			);
		}

		$bind_dn = self::setting( 'bind_dn' );
		$bind_pw = function_exists( 'vulnhub' ) ? vulnhub()->settings->secret( self::ID, 'bind_password' ) : '';

		if ( '' === $bind_dn || '' === trim( $bind_pw ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'A service account DN and password are required. Anonymous binds are refused.', 'vulnhub' ),
				'conn'    => null,
			);
		}

		$conn = @ldap_connect( $uri ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( ! $conn ) {
			return array(
				'ok'      => false,
				'message' => __( 'Could not open a connection to the directory server.', 'vulnhub' ),
				'conn'    => null,
			);
		}

		ldap_set_option( $conn, LDAP_OPT_PROTOCOL_VERSION, 3 );
		// AD returns referrals that a simple client cannot chase; following
		// them turns a clean "no such user" into a confusing bind error.
		ldap_set_option( $conn, LDAP_OPT_REFERRALS, 0 );
		ldap_set_option( $conn, LDAP_OPT_NETWORK_TIMEOUT, 10 );

		if ( ! @ldap_bind( $conn, $bind_dn, $bind_pw ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			// ldap_error() describes the failure without echoing the credential.
			return array(
				'ok'      => false,
				/* translators: %s: LDAP error string. */
				'message' => sprintf( __( 'The service account bind was rejected: %s', 'vulnhub' ), ldap_error( $conn ) ),
				'conn'    => null,
			);
		}

		return array(
			'ok'      => true,
			'message' => '',
			'conn'    => $conn,
		);
	}

	/**
	 * Verify configuration by binding and reading the base DN.
	 *
	 * @return array{ok:bool,message:string,detail:array<string,mixed>}
	 */
	public static function test(): array {
		$connection = self::service_connect();
		if ( ! $connection['ok'] ) {
			return array(
				'ok'      => false,
				'message' => $connection['message'],
				'detail'  => array( 'extension' => self::available() ),
			);
		}

		$conn    = $connection['conn'];
		$base_dn = self::setting( 'base_dn' );

		// Read the RootDSE first: it proves the bind really succeeded and tells
		// us the naming contexts the server will serve.
		$contexts = array();
		$root     = @ldap_read( $conn, '', '(objectClass=*)', array( 'namingcontexts', 'defaultnamingcontext' ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( $root ) {
			$entries = ldap_get_entries( $conn, $root );
			foreach ( (array) ( $entries[0]['namingcontexts'] ?? array() ) as $key => $value ) {
				if ( 'count' !== $key ) {
					$contexts[] = (string) $value;
				}
			}
		}

		if ( '' === $base_dn ) {
			ldap_unbind( $conn );
			return array(
				'ok'      => false,
				'message' => __( 'The service account bound successfully but no search base DN is configured.', 'vulnhub' ),
				'detail'  => array( 'naming_contexts' => $contexts ),
			);
		}

		$search = @ldap_search( $conn, $base_dn, '(objectClass=organizationalUnit)', array( 'dn' ), 0, 5 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $search ) {
			$error = ldap_error( $conn );
			ldap_unbind( $conn );
			return array(
				'ok'      => false,
				/* translators: 1: base DN, 2: LDAP error. */
				'message' => sprintf( __( 'Bound as the service account, but could not search %1$s: %2$s', 'vulnhub' ), $base_dn, $error ),
				'detail'  => array( 'naming_contexts' => $contexts ),
			);
		}

		$count = ldap_count_entries( $conn, $search );
		ldap_unbind( $conn );

		return array(
			'ok'      => true,
			'message' => sprintf(
				/* translators: 1: base DN, 2: number of organizational units. */
				__( 'Service account bind succeeded. Readable base DN: %1$s (%2$d organizational units visible).', 'vulnhub' ),
				$base_dn,
				(int) $count
			),
			'detail'  => array(
				'base_dn'         => $base_dn,
				'naming_contexts' => $contexts,
				'uri'             => self::uri(),
			),
		);
	}

	/**
	 * Authenticate a username and password against the directory.
	 *
	 * @param string $username sAMAccountName or userPrincipalName.
	 * @param string $password Plaintext password.
	 * @return array{ok:bool,message:string,attributes:array<string,mixed>,groups:array<int,string>}
	 */
	public static function authenticate( string $username, string $password ): array {
		$fail = static function ( string $message ): array {
			return array(
				'ok'         => false,
				'message'    => $message,
				'attributes' => array(),
				'groups'     => array(),
			);
		};

		// *** The bypass guard. Do not move this below the bind. ***
		if ( '' === trim( $password ) ) {
			return $fail( __( 'A password is required. An empty password would be an anonymous bind, which is never an authentication.', 'vulnhub' ) );
		}
		if ( '' === trim( $username ) ) {
			return $fail( __( 'A username is required.', 'vulnhub' ) );
		}

		$connection = self::service_connect();
		if ( ! $connection['ok'] ) {
			return $fail( $connection['message'] );
		}

		$conn    = $connection['conn'];
		$base_dn = self::setting( 'base_dn' );
		if ( '' === $base_dn ) {
			ldap_unbind( $conn );
			return $fail( __( 'No search base DN is configured.', 'vulnhub' ) );
		}

		// Escape for a filter context so a username cannot inject filter syntax.
		$escaped = ldap_escape( $username, '', LDAP_ESCAPE_FILTER );
		$filter  = sprintf(
			'(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=%1$s)(userPrincipalName=%1$s)))',
			$escaped
		);

		$search = @ldap_search( $conn, $base_dn, $filter, self::USER_ATTRIBUTES, 0, 2 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $search ) {
			$error = ldap_error( $conn );
			ldap_unbind( $conn );
			/* translators: %s: LDAP error string. */
			return $fail( sprintf( __( 'Directory search failed: %s', 'vulnhub' ), $error ) );
		}

		$entries = ldap_get_entries( $conn, $search );
		if ( empty( $entries['count'] ) || 1 !== (int) $entries['count'] ) {
			ldap_unbind( $conn );
			// Same message whether the account is missing or ambiguous, so the
			// directory cannot be enumerated through this form.
			return $fail( __( 'The username or password is incorrect.', 'vulnhub' ) );
		}

		$entry   = $entries[0];
		$user_dn = (string) ( $entry['dn'] ?? '' );
		if ( '' === $user_dn ) {
			ldap_unbind( $conn );
			return $fail( __( 'The directory returned an entry with no distinguished name.', 'vulnhub' ) );
		}

		// Disabled accounts (UF_ACCOUNTDISABLE = 0x0002) must not sign in even
		// with a correct password.
		$uac = (int) ( $entry['useraccountcontrol'][0] ?? 0 );
		if ( $uac & 0x0002 ) {
			ldap_unbind( $conn );
			return $fail( __( 'That directory account is disabled.', 'vulnhub' ) );
		}

		// Rebind as the user. This is the actual password check — and again,
		// an empty password never reaches it.
		$bound = @ldap_bind( $conn, $user_dn, $password ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( ! $bound ) {
			ldap_unbind( $conn );
			return $fail( __( 'The username or password is incorrect.', 'vulnhub' ) );
		}

		$groups = array();
		foreach ( (array) ( $entry['memberof'] ?? array() ) as $key => $value ) {
			if ( 'count' === $key ) {
				continue;
			}
			$groups[] = (string) $value;
		}

		$attributes = array(
			'dn'                => $user_dn,
			'samaccountname'    => (string) ( $entry['samaccountname'][0] ?? '' ),
			'userprincipalname' => (string) ( $entry['userprincipalname'][0] ?? '' ),
			'mail'              => (string) ( $entry['mail'][0] ?? '' ),
			'displayname'       => (string) ( $entry['displayname'][0] ?? '' ),
			'givenname'         => (string) ( $entry['givenname'][0] ?? '' ),
			'sn'                => (string) ( $entry['sn'][0] ?? '' ),
		);

		ldap_unbind( $conn );

		return array(
			'ok'         => true,
			'message'    => '',
			'attributes' => $attributes,
			'groups'     => $groups,
		);
	}

	/**
	 * Reduce a memberOf DN to its common name, which is what an administrator
	 * types into the mapping table.
	 *
	 * @param string $dn Group distinguished name.
	 * @return string
	 */
	public static function group_cn( string $dn ): string {
		if ( preg_match( '/^CN=([^,]+)/i', $dn, $matches ) ) {
			return stripslashes( $matches[1] );
		}
		return $dn;
	}

	/* -----------------------------------------------------------------
	 * WordPress integration
	 * --------------------------------------------------------------- */

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public static function init(): void {
		add_filter( 'authenticate', array( __CLASS__, 'authenticate_filter' ), 25, 3 );
		add_action( 'admin_notices', array( __CLASS__, 'extension_notice' ) );
	}

	/**
	 * Try the directory when local authentication has not produced a user.
	 *
	 * Runs at priority 25, after WordPress' own username/password callbacks at
	 * 20, so a local account always wins and the directory is a fallback.
	 *
	 * @param null|\WP_User|\WP_Error $user     Result so far.
	 * @param string                  $username Submitted username.
	 * @param string                  $password Submitted password.
	 * @return null|\WP_User|\WP_Error
	 */
	public static function authenticate_filter( $user, $username = '', $password = '' ) {
		if ( $user instanceof \WP_User ) {
			return $user;
		}
		if ( ! function_exists( 'vulnhub' ) ) {
			return $user;
		}

		$connector = vulnhub()->connectors->get( self::ID );
		if ( ! $connector || ! $connector->is_enabled() ) {
			return $user;
		}
		if ( '' === trim( (string) $username ) || '' === trim( (string) $password ) ) {
			return $user;
		}
		if ( ! self::available() ) {
			return $user;
		}

		$result = self::authenticate( (string) $username, (string) $password );
		if ( ! $result['ok'] ) {
			VulnHub_Auth_Audit::log(
				'ldap.failure',
				sprintf( 'Directory sign-in refused for %s', sanitize_user( (string) $username, true ) ),
				0,
				array( 'reason' => $result['message'] ),
				'warning'
			);
			return $user;
		}

		$wp_user = self::map_to_wp_user( $result );
		if ( is_wp_error( $wp_user ) ) {
			return $wp_user;
		}

		VulnHub_Auth_Audit::log(
			'ldap.success',
			sprintf( '%s authenticated against Active Directory', $wp_user->user_login ),
			$wp_user->ID,
			array( 'dn' => $result['attributes']['dn'] )
		);

		return $wp_user;
	}

	/**
	 * Find or create the WordPress account for a directory user.
	 *
	 * @param array{attributes:array<string,mixed>,groups:array<int,string>} $result Directory result.
	 * @return \WP_User|\WP_Error
	 */
	private static function map_to_wp_user( array $result ): \WP_User|\WP_Error {
		$attributes = $result['attributes'];
		$email      = strtolower( (string) ( $attributes['mail'] ?: $attributes['userprincipalname'] ) );
		$login      = sanitize_user( (string) ( $attributes['samaccountname'] ?: $email ), true );

		$user = $login ? get_user_by( 'login', $login ) : false;
		if ( ! $user && $email ) {
			$user = get_user_by( 'email', $email );
		}

		if ( ! $user ) {
			if ( ! vulnhub()->settings->get_bool( self::ID, 'auto_create', false ) ) {
				return new \WP_Error(
					'vh_auth_ldap_no_account',
					__( 'Your directory credentials are correct, but there is no account here and automatic creation is switched off.', 'vulnhub' )
				);
			}

			$user_id = wp_insert_user(
				array(
					'user_login'   => $login ?: 'ad_' . substr( md5( (string) $attributes['dn'] ), 0, 12 ),
					'user_email'   => $email,
					'display_name' => (string) ( $attributes['displayname'] ?: $login ),
					'first_name'   => (string) $attributes['givenname'],
					'last_name'    => (string) $attributes['sn'],
					'user_pass'    => wp_generate_password( 64, true, true ),
					'role'         => VulnHub_Auth_SSO::default_role( self::ID ),
				)
			);
			if ( is_wp_error( $user_id ) ) {
				return $user_id;
			}

			VulnHub_Auth_Audit::log(
				'ldap.provisioned',
				sprintf( 'Created %s from Active Directory', $login ),
				(int) $user_id,
				array( 'dn' => $attributes['dn'] )
			);

			$user = new \WP_User( (int) $user_id );
		}

		// Group mapping uses the same table as the OIDC providers, keyed on
		// the "ldap" provider and matched against each memberOf group's CN.
		$groups = array_map( array( __CLASS__, 'group_cn' ), $result['groups'] );
		VulnHub_Auth_SSO::apply_role_mapping( self::ID, $user, array( 'groups' => $groups ) );

		update_user_meta( $user->ID, '_vh_auth_ldap_dn', (string) $attributes['dn'] );

		return $user;
	}

	/**
	 * Warn when the connector is on but the extension is missing.
	 *
	 * @return void
	 */
	public static function extension_notice(): void {
		if ( ! current_user_can( 'vulnhub_manage' ) || ! function_exists( 'vulnhub' ) ) {
			return;
		}

		$connector = vulnhub()->connectors->get( self::ID );
		if ( ! $connector || ! $connector->is_enabled() || self::available() ) {
			return;
		}

		printf(
			'<div class="notice notice-warning"><p><strong>%s</strong> %s</p></div>',
			esc_html__( 'VulnHub Authentication:', 'vulnhub' ),
			esc_html__( 'The Active Directory connector is enabled but the PHP ldap extension is not installed, so directory sign-in is inactive. Install php-ldap (for example: docker-php-ext-install ldap) and restart PHP.', 'vulnhub' )
		);
	}
}

