<?php
/**
 * Okta OIDC connector.
 *
 * @package VulnHub\Auth
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Okta as an OpenID Connect identity provider.
 */
final class VulnHub_Okta_Connector extends VulnHub_Auth_Connector {

	/**
	 * Machine id.
	 */
	public function id(): string {
		return 'okta';
	}

	/**
	 * Human label.
	 */
	public function label(): string {
		return __( 'Okta (OIDC single sign-on)', 'vulnhub' );
	}

	/**
	 * One-line description for the Integrations card.
	 */
	public function description(): string {
		return __( 'Sign in to VulnHub with Okta using authorization code flow with PKCE, and map Okta groups onto VulnHub roles.', 'vulnhub' );
	}

	/**
	 * Dashicon.
	 */
	public function icon(): string {
		return 'dashicons-admin-network';
	}

	/**
	 * Settings fields.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public function fields(): array {
		return array_merge(
			array(
				array(
					'key'         => 'okta_domain',
					'label'       => __( 'Okta domain', 'vulnhub' ),
					'type'        => 'text',
					'required'    => true,
					'placeholder' => 'example.okta.com',
					'help'        => __( 'Your Okta org host, without https://. Use the -admin-free hostname (example.okta.com, not example-admin.okta.com).', 'vulnhub' ),
				),
				array(
					'key'     => 'auth_server',
					'label'   => __( 'Authorization server', 'vulnhub' ),
					'type'    => 'text',
					'default' => 'default',
					'help'    => __( 'Enter "default" for the built-in custom authorization server (issuer https://your-domain/oauth2/default), "org" for the Org authorization server (issuer https://your-domain), or the id of another custom server. This choice changes both the discovery URL and the iss claim, so it must match the app registration.', 'vulnhub' ),
				),
			),
			$this->common_oidc_fields()
		);
	}

	/**
	 * Fetch and validate the Okta discovery document.
	 *
	 * @return array{ok:bool,message:string,detail?:array<string,mixed>}
	 */
	public function test_connection(): array {
		return $this->probe_oidc( $this->id() );
	}
}

