<?php
/**
 * OpenID Connect relying-party client: discovery, PKCE, token exchange and
 * ID token verification.
 *
 * Written against the provider documentation rather than from memory:
 *
 *  - Okta publishes metadata at `https://{domain}/.well-known/openid-configuration`
 *    for the Org authorization server and at
 *    `https://{domain}/oauth2/{id}/.well-known/openid-configuration` for a
 *    Custom one (`{id}` is usually `default`). The `iss` claim in the tokens
 *    differs the same way — `https://{domain}` versus
 *    `https://{domain}/oauth2/default` — which is why the connector asks which
 *    server is in use instead of guessing. Endpoints hang off the issuer as
 *    `/v1/authorize`, `/v1/token`, `/v1/keys`, `/v1/userinfo`, `/v1/logout`.
 *  - Microsoft Entra ID publishes metadata at
 *    `https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration`
 *    where `{tenant}` is a tenant id, a verified domain, or `common`,
 *    `organizations` or `consumers`. The v2.0 issuer ends in `/v2.0`; the older
 *    v1.0 endpoint issues `https://sts.windows.net/{tid}/`, so a deployment
 *    that still points at v1.0 must not be validated with a v2.0 issuer string.
 *
 * Every endpoint actually used is read from the discovery document, so a
 * provider that moves an endpoint keeps working and a provider that does not
 * advertise the endpoints we need fails loudly at test time.
 *
 * @package VulnHub\Auth
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Raised for any recoverable OIDC problem worth showing an administrator.
 */
class VulnHub_Auth_OIDC_Exception extends \RuntimeException {}

/**
 * A single relying-party configuration talking to one identity provider.
 */
final class VulnHub_Auth_OIDC_Client {

	/** How long a discovery document is cached. */
	private const DISCOVERY_TTL = HOUR_IN_SECONDS;

	/** How long a JWK Set is cached. */
	private const JWKS_TTL = HOUR_IN_SECONDS;

	/** How long an in-flight authorisation request stays valid. */
	public const REQUEST_TTL = 10 * MINUTE_IN_SECONDS;

	/** Provider id: okta|entra|oidc. */
	private string $provider;

	/** Discovery document URL. */
	private string $discovery_url;

	/** Expected issuer, or '' to trust whatever discovery advertises. */
	private string $expected_issuer;

	/** OAuth client id. */
	private string $client_id;

	/** OAuth client secret ('' for a public client). */
	private string $client_secret;

	/** Space-separated scopes. */
	private string $scopes;

	/**
	 * Tenant ids permitted to sign in, for Entra ID deployments pointed at the
	 * multi-tenant `common` / `organizations` endpoints.
	 *
	 * @var array<int,string>
	 */
	private array $allowed_tenants;

	/** HTTP client. */
	private \VulnHub\Core\Http $http;

	/**
	 * @param array{
	 *   provider:string,
	 *   discovery_url:string,
	 *   issuer?:string,
	 *   client_id:string,
	 *   client_secret?:string,
	 *   scopes?:string,
	 *   allowed_tenants?:array<int,string>
	 * } $config Relying-party configuration.
	 */
	public function __construct( array $config ) {
		$this->provider        = (string) $config['provider'];
		$this->discovery_url   = (string) $config['discovery_url'];
		$this->expected_issuer = (string) ( $config['issuer'] ?? '' );
		$this->client_id       = (string) $config['client_id'];
		$this->client_secret   = (string) ( $config['client_secret'] ?? '' );
		$this->scopes          = (string) ( $config['scopes'] ?? 'openid profile email' );
		$this->allowed_tenants = array_values( array_filter( array_map( 'strval', (array) ( $config['allowed_tenants'] ?? array() ) ) ) );
		$this->http            = new \VulnHub\Core\Http();
	}

	/**
	 * Provider id.
	 */
	public function provider(): string {
		return $this->provider;
	}

	/* -----------------------------------------------------------------
	 * Discovery
	 * --------------------------------------------------------------- */

	/**
	 * Fetch (and cache) the provider's OpenID configuration.
	 *
	 * @param bool $force Bypass the cache.
	 * @return array<string,mixed> Discovery document.
	 * @throws VulnHub_Auth_OIDC_Exception When the document cannot be fetched or is unusable.
	 */
	public function discovery( bool $force = false ): array {
		$key = 'vulnhub_auth_disco_' . $this->provider;

		if ( ! $force ) {
			$cached = get_transient( $key );
			if ( is_array( $cached ) && ! empty( $cached['issuer'] ) ) {
				return $cached;
			}
		}

		if ( '' === $this->discovery_url ) {
			throw new VulnHub_Auth_OIDC_Exception( __( 'No discovery URL is configured for this provider.', 'vulnhub' ) );
		}
		if ( ! wp_http_validate_url( $this->discovery_url ) || ! str_starts_with( $this->discovery_url, 'https://' ) ) {
			throw new VulnHub_Auth_OIDC_Exception( __( 'The discovery URL must be a valid https:// URL.', 'vulnhub' ) );
		}

		$response = $this->http->get( $this->discovery_url );
		if ( ! $response->ok() ) {
			/* translators: %s: error detail from the identity provider. */
			throw new VulnHub_Auth_OIDC_Exception( sprintf( __( 'Could not read the discovery document: %s', 'vulnhub' ), $response->error_message() ) );
		}

		$document = $response->data();
		foreach ( array( 'issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri' ) as $required ) {
			if ( empty( $document[ $required ] ) ) {
				/* translators: %s: metadata field name. */
				throw new VulnHub_Auth_OIDC_Exception( sprintf( __( 'The discovery document does not advertise %s.', 'vulnhub' ), $required ) );
			}
		}

		// Pin the issuer when the administrator configured one. This is the
		// anchor for every later `iss` comparison, so a wrong or hijacked
		// discovery URL cannot silently redefine who we trust.
		if ( '' !== $this->expected_issuer && ! hash_equals( $this->expected_issuer, (string) $document['issuer'] ) ) {
			throw new VulnHub_Auth_OIDC_Exception( __( 'The issuer advertised by the discovery document does not match the configured issuer.', 'vulnhub' ) );
		}

		set_transient( $key, $document, self::DISCOVERY_TTL );

		return $document;
	}

	/**
	 * The issuer this client will accept in ID tokens.
	 *
	 * @return string Issuer URL.
	 * @throws VulnHub_Auth_OIDC_Exception On discovery failure.
	 */
	public function issuer(): string {
		return (string) $this->discovery()['issuer'];
	}

	/* -----------------------------------------------------------------
	 * JWKS
	 * --------------------------------------------------------------- */

	/**
	 * Fetch (and cache) the provider's JWK Set.
	 *
	 * @param bool $force Bypass the cache — used on a `kid` miss, because a
	 *                    provider that has just rotated its signing key will
	 *                    publish a new `kid` before our cache expires.
	 * @return array<string,mixed> JWK Set.
	 * @throws VulnHub_Auth_OIDC_Exception When the set cannot be fetched.
	 */
	public function jwks( bool $force = false ): array {
		$key = 'vulnhub_auth_jwks_' . $this->provider;

		if ( ! $force ) {
			$cached = get_transient( $key );
			if ( is_array( $cached ) && ! empty( $cached['keys'] ) ) {
				return $cached;
			}
		}

		$uri      = (string) $this->discovery()['jwks_uri'];
		$response = $this->http->get( $uri );
		if ( ! $response->ok() ) {
			/* translators: %s: error detail from the identity provider. */
			throw new VulnHub_Auth_OIDC_Exception( sprintf( __( 'Could not read the signing keys: %s', 'vulnhub' ), $response->error_message() ) );
		}

		$set = $response->data();
		if ( empty( $set['keys'] ) || ! is_array( $set['keys'] ) ) {
			throw new VulnHub_Auth_OIDC_Exception( __( 'The JWKS endpoint returned no keys.', 'vulnhub' ) );
		}

		set_transient( $key, $set, self::JWKS_TTL );

		return $set;
	}

	/**
	 * Drop cached metadata for this provider.
	 */
	public function flush_cache(): void {
		delete_transient( 'vulnhub_auth_disco_' . $this->provider );
		delete_transient( 'vulnhub_auth_jwks_' . $this->provider );
	}

	/* -----------------------------------------------------------------
	 * Authorisation request
	 * --------------------------------------------------------------- */

	/**
	 * Build the authorisation URL and the state that must be remembered.
	 *
	 * PKCE (RFC 7636) is used even though this is a confidential client: it
	 * costs nothing and removes the authorisation code interception class of
	 * attack entirely. `code_challenge` is base64url(SHA-256(verifier)) with
	 * `code_challenge_method=S256`; the plain method is never offered.
	 *
	 * @param string $redirect_uri Callback URL registered with the provider.
	 * @param string $redirect_to  Where to send the user after login.
	 * @return array{url:string,state:string,request:array<string,mixed>}
	 * @throws VulnHub_Auth_OIDC_Exception On discovery failure.
	 * @throws \Random\RandomException When the CSPRNG is unavailable.
	 */
	public function authorization_request( string $redirect_uri, string $redirect_to = '' ): array {
		$document = $this->discovery();

		// A 43-character minimum, unreserved-character verifier (RFC 7636 §4.1).
		$verifier  = VulnHub_Auth_JWT::b64url_encode( random_bytes( 48 ) );
		$challenge = VulnHub_Auth_JWT::b64url_encode( hash( 'sha256', $verifier, true ) );

		$state = wp_generate_password( 32, false, false );
		$nonce = wp_generate_password( 32, false, false );

		$args = array(
			'client_id'             => $this->client_id,
			'response_type'         => 'code',
			'scope'                 => $this->scopes,
			'redirect_uri'          => $redirect_uri,
			'state'                 => $state,
			'nonce'                 => $nonce,
			'code_challenge'        => $challenge,
			'code_challenge_method' => 'S256',
		);

		// Entra ID needs response_mode=query for a plain code flow through a
		// GET callback; Okta defaults to query already but being explicit
		// avoids a form_post surprise if the app registration says otherwise.
		$args['response_mode'] = 'query';

		$request = array(
			'provider'     => $this->provider,
			'verifier'     => $verifier,
			'nonce'        => $nonce,
			'redirect_uri' => $redirect_uri,
			'redirect_to'  => $redirect_to,
			'issuer'       => (string) $document['issuer'],
			'created'      => time(),
		);

		return array(
			'url'     => add_query_arg( array_map( 'rawurlencode', $args ), (string) $document['authorization_endpoint'] ),
			'state'   => $state,
			'request' => $request,
		);
	}

	/* -----------------------------------------------------------------
	 * Token exchange
	 * --------------------------------------------------------------- */

	/**
	 * Exchange an authorisation code for tokens.
	 *
	 * @param string $code         Authorisation code.
	 * @param string $verifier     PKCE code verifier.
	 * @param string $redirect_uri The exact redirect_uri sent to /authorize.
	 * @return array<string,mixed> Token response.
	 * @throws VulnHub_Auth_OIDC_Exception When the exchange fails.
	 */
	public function exchange_code( string $code, string $verifier, string $redirect_uri ): array {
		$document = $this->discovery();

		$fields = array(
			'grant_type'    => 'authorization_code',
			'code'          => $code,
			'redirect_uri'  => $redirect_uri,
			'client_id'     => $this->client_id,
			'code_verifier' => $verifier,
		);

		$headers = array();
		if ( '' !== $this->client_secret ) {
			// client_secret_basic is the method every provider in scope lists
			// first in token_endpoint_auth_methods_supported, and it keeps the
			// secret out of the request body.
			$headers['Authorization'] = 'Basic ' . base64_encode(
				rawurlencode( $this->client_id ) . ':' . rawurlencode( $this->client_secret )
			);
		}

		$response = $this->http->post_form( (string) $document['token_endpoint'], $fields, $headers );

		if ( ! $response->ok() ) {
			// error_message() decodes the provider's error envelope; it never
			// contains our secret because the secret went in a header.
			/* translators: %s: error detail from the identity provider. */
			throw new VulnHub_Auth_OIDC_Exception( sprintf( __( 'Token exchange failed: %s', 'vulnhub' ), $response->error_message() ) );
		}

		$tokens = $response->data();
		if ( empty( $tokens['id_token'] ) ) {
			throw new VulnHub_Auth_OIDC_Exception( __( 'The token response contained no ID token.', 'vulnhub' ) );
		}

		return $tokens;
	}

	/* -----------------------------------------------------------------
	 * ID token verification
	 * --------------------------------------------------------------- */

	/**
	 * Verify an ID token end to end and return its claims.
	 *
	 * Order matters and is deliberate:
	 *   1. parse the compact JWS (no trust yet);
	 *   2. pick the key by `kid` from the cached JWKS;
	 *   3. on a `kid` miss, refetch the JWKS once (key rotation) and retry;
	 *   4. verify the RS256 signature with openssl_verify;
	 *   5. only then validate iss / aud / azp / exp / nbf / iat / nonce / sub.
	 *
	 * Nothing in the payload is read for any purpose before step 4 succeeds.
	 *
	 * @param string $id_token Compact JWS.
	 * @param string $nonce    Nonce from the authorisation request.
	 * @return array<string,mixed> Verified claims.
	 * @throws VulnHub_Auth_OIDC_Exception When verification fails.
	 */
	public function verify_id_token( string $id_token, string $nonce ): array {
		try {
			$parsed = VulnHub_Auth_JWT::parse( $id_token );

			$jwks = $this->jwks();
			$jwk  = VulnHub_Auth_JWT::select_key( $parsed['header'], $jwks );

			if ( null === $jwk ) {
				// Key rotation: the provider signed with a key minted after we
				// cached the set. Refetch exactly once, then give up.
				$jwks = $this->jwks( true );
				$jwk  = VulnHub_Auth_JWT::select_key( $parsed['header'], $jwks );
			}

			if ( null === $jwk ) {
				throw new VulnHub_Auth_OIDC_Exception( __( 'No published signing key matches the key id in the ID token.', 'vulnhub' ) );
			}

			if ( ! VulnHub_Auth_JWT::verify_signature( $id_token, $jwk ) ) {
				throw new VulnHub_Auth_OIDC_Exception( __( 'The ID token signature is not valid.', 'vulnhub' ) );
			}

			VulnHub_Auth_JWT::validate_claims(
				$parsed['payload'],
				array(
					'issuer'    => $this->expected_issuer_for( $parsed['payload'] ),
					'client_id' => $this->client_id,
					'nonce'     => $nonce,
					'leeway'    => 120,
				)
			);

			return $parsed['payload'];
		} catch ( VulnHub_Auth_JWT_Exception $e ) {
			throw new VulnHub_Auth_OIDC_Exception( $e->getMessage(), 0, $e );
		}
	}

	/**
	 * Work out which issuer string this particular token must carry.
	 *
	 * Nearly always this is simply the issuer from the discovery document.
	 * The exception is Microsoft Entra ID pointed at a multi-tenant endpoint:
	 * `https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration`
	 * advertises the LITERAL string
	 * `https://login.microsoftonline.com/{tenantid}/v2.0`, because the real
	 * issuer depends on which tenant the user signed in from. Comparing that
	 * template to a token's `iss` would fail every time, and the tempting
	 * shortcut — skipping the issuer check for multi-tenant apps — is exactly
	 * the mistake that lets any Microsoft tenant in the world sign in to your
	 * application.
	 *
	 * So the template is filled in from the token's `tid` claim, and `tid` is
	 * required to be on an administrator-configured allow-list first. With no
	 * allow-list configured the sign-in is refused rather than opened up.
	 *
	 * @param array<string,mixed> $payload Unverified payload (signature has
	 *                                     already been checked by the caller).
	 * @return string Issuer to compare against.
	 * @throws VulnHub_Auth_OIDC_Exception When the tenant is not permitted.
	 */
	private function expected_issuer_for( array $payload ): string {
		$issuer = $this->issuer();

		if ( ! str_contains( $issuer, '{tenantid}' ) ) {
			return $issuer;
		}

		$tid = (string) ( $payload['tid'] ?? '' );
		if ( '' === $tid ) {
			throw new VulnHub_Auth_OIDC_Exception( __( 'The identity provider uses a multi-tenant issuer but the ID token carries no tenant id.', 'vulnhub' ) );
		}

		if ( ! $this->allowed_tenants ) {
			throw new VulnHub_Auth_OIDC_Exception( __( 'This provider is configured against a multi-tenant endpoint but no tenant ids are allowed. Add the tenant ids that may sign in.', 'vulnhub' ) );
		}

		$permitted = false;
		foreach ( $this->allowed_tenants as $candidate ) {
			if ( hash_equals( strtolower( $candidate ), strtolower( $tid ) ) ) {
				$permitted = true;
			}
		}
		if ( ! $permitted ) {
			throw new VulnHub_Auth_OIDC_Exception( __( 'The tenant this identity came from is not on the allowed list.', 'vulnhub' ) );
		}

		return str_replace( '{tenantid}', $tid, $issuer );
	}

	/* -----------------------------------------------------------------
	 * Diagnostics
	 * --------------------------------------------------------------- */

	/**
	 * Inspect the provider's metadata without using any credential.
	 *
	 * Used by every OIDC connector's test_connection(). It proves the provider
	 * is reachable, that it advertises the endpoints this flow needs, and that
	 * it supports PKCE with S256 — the three things that actually break a
	 * deployment. No secret is sent and none appears in the result.
	 *
	 * @return array{ok:bool,message:string,detail:array<string,mixed>}
	 */
	public function probe(): array {
		try {
			$document = $this->discovery( true );
		} catch ( \Throwable $e ) {
			return array(
				'ok'      => false,
				'message' => $e->getMessage(),
				'detail'  => array(),
			);
		}

		$problems = array();

		$methods = array_map( 'strval', (array) ( $document['code_challenge_methods_supported'] ?? array() ) );
		if ( ! in_array( 'S256', $methods, true ) ) {
			$problems[] = __( 'the provider does not advertise PKCE with S256', 'vulnhub' );
		}

		$response_types = array_map( 'strval', (array) ( $document['response_types_supported'] ?? array() ) );
		if ( $response_types && ! in_array( 'code', $response_types, true ) ) {
			$problems[] = __( 'the provider does not advertise the authorization code response type', 'vulnhub' );
		}

		$algs = array_map( 'strval', (array) ( $document['id_token_signing_alg_values_supported'] ?? array() ) );
		if ( $algs && ! array_intersect( array( 'RS256', 'RS384', 'RS512' ), $algs ) ) {
			$problems[] = __( 'the provider does not sign ID tokens with the RSA algorithms this plugin verifies', 'vulnhub' );
		}

		$key_count = 0;
		try {
			$key_count = count( (array) $this->jwks( true )['keys'] );
		} catch ( \Throwable $e ) {
			$problems[] = $e->getMessage();
		}

		$detail = array(
			'issuer'                 => (string) $document['issuer'],
			'authorization_endpoint' => (string) $document['authorization_endpoint'],
			'token_endpoint'         => (string) $document['token_endpoint'],
			'jwks_uri'               => (string) $document['jwks_uri'],
			'userinfo_endpoint'      => (string) ( $document['userinfo_endpoint'] ?? '' ),
			'end_session_endpoint'   => (string) ( $document['end_session_endpoint'] ?? '' ),
			'signing_keys'           => $key_count,
			'pkce_s256'              => in_array( 'S256', $methods, true ),
		);

		if ( $problems ) {
			return array(
				'ok'      => false,
				/* translators: 1: issuer URL, 2: list of problems. */
				'message' => sprintf( __( 'Reached %1$s but %2$s.', 'vulnhub' ), (string) $document['issuer'], implode( '; ', $problems ) ),
				'detail'  => $detail,
			);
		}

		return array(
			'ok'      => true,
			'message' => sprintf(
				/* translators: 1: issuer URL, 2: number of signing keys. */
				__( 'Discovery OK. Issuer %1$s advertises the authorization code flow with PKCE S256 and publishes %2$d signing key(s).', 'vulnhub' ),
				(string) $document['issuer'],
				$key_count
			),
			'detail'  => $detail,
		);
	}

	/**
	 * Build an RP-initiated logout URL when the provider advertises one.
	 *
	 * Okta and Entra both implement `end_session_endpoint` and both accept
	 * `id_token_hint` plus `post_logout_redirect_uri`.
	 *
	 * @param string $id_token_hint The ID token from the session.
	 * @param string $post_logout   Where to return afterwards.
	 * @return string Logout URL, or '' when the provider has no endpoint.
	 */
	public function logout_url( string $id_token_hint, string $post_logout ): string {
		try {
			$document = $this->discovery();
		} catch ( \Throwable $e ) {
			return '';
		}

		$endpoint = (string) ( $document['end_session_endpoint'] ?? '' );
		if ( '' === $endpoint ) {
			return '';
		}

		$args = array( 'post_logout_redirect_uri' => $post_logout );
		if ( '' !== $id_token_hint ) {
			$args['id_token_hint'] = $id_token_hint;
		} else {
			// Entra accepts the tenant-scoped logout without a hint.
			$args['client_id'] = $this->client_id;
		}

		return add_query_arg( array_map( 'rawurlencode', $args ), $endpoint );
	}
}

