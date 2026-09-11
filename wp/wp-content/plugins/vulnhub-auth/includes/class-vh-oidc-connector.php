<?php
/**
 * Generic OpenID Connect connector for any compliant provider.
 *
 * @package VulnHub\Auth
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Any standards-compliant OpenID Connect identity provider.
 */
final class VulnHub_OIDC_Connector extends VulnHub_Auth_Connector {

	/**
	 * Machine id.
	 */
	public function id(): string {
		return 'oidc';
	}

	/**
	 * Human label.
	 */
	public function label(): string {
		return __( 'OpenID Connect (generic)', 'vulnhub' );
	}

	/**
	 * One-line description for the Integrations card.
	 */
	public function description(): string {
		return __( 'Sign in through any OpenID Connect provider that publishes a discovery document, supports PKCE with S256 and signs ID tokens with RS256.', 'vulnhub' );
	}

	/**
	 * Dashicon.
	 */
	public function icon(): string {
		return 'dashicons-id-alt';
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
					'key'         => 'discovery_url',
					'label'       => __( 'Discovery document URL', 'vulnhub' ),
					'type'        => 'url',
					'required'    => true,
					'placeholder' => 'https://idp.example.com/.well-known/openid-configuration',
					'help'        => __( 'Must be https. Every endpoint used during sign-in is read from this document.', 'vulnhub' ),
				),
				array(
					'key'         => 'issuer',
					'label'       => __( 'Expected issuer', 'vulnhub' ),
					'type'        => 'text',
					'placeholder' => 'https://idp.example.com',
					'help'        => __( 'Optional but recommended. When set, the issuer advertised by the discovery document must match it exactly, and every ID token is checked against it.', 'vulnhub' ),
				),
			),
			$this->common_oidc_fields()
		);
	}

	/**
	 * Fetch and validate the provider's discovery document.
	 *
	 * @return array{ok:bool,message:string,detail?:array<string,mixed>}
	 */
	public function test_connection(): array {
		return $this->probe_oidc( $this->id() );
	}
}

