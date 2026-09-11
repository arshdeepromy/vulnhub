<?php
/**
 * Microsoft Entra ID OIDC connector.
 *
 * @package VulnHub\Auth
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Microsoft Entra ID as an OpenID Connect identity provider.
 */
final class VulnHub_Entra_Connector extends VulnHub_Auth_Connector {

	/**
	 * Machine id.
	 */
	public function id(): string {
		return 'entra';
	}

	/**
	 * Human label.
	 */
	public function label(): string {
		return __( 'Microsoft Entra ID (OIDC single sign-on)', 'vulnhub' );
	}

	/**
	 * One-line description for the Integrations card.
	 */
	public function description(): string {
		return __( 'Sign in with a Microsoft work or school account through the Entra ID v2.0 endpoint, with app roles and security groups mapped onto VulnHub roles.', 'vulnhub' );
	}

	/**
	 * Dashicon.
	 */
	public function icon(): string {
		return 'dashicons-cloud';
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
					'key'         => 'tenant_id',
					'label'       => __( 'Directory (tenant) ID', 'vulnhub' ),
					'type'        => 'text',
					'required'    => true,
					'placeholder' => '00000000-0000-0000-0000-000000000000',
					'help'        => __( 'A tenant GUID or verified domain for a single-tenant app. "common", "organizations" or "consumers" are accepted for a multi-tenant app, but then the allowed tenant list below becomes mandatory.', 'vulnhub' ),
				),
				array(
					'key'         => 'allowed_tenants',
					'label'       => __( 'Allowed tenant IDs', 'vulnhub' ),
					'type'        => 'textarea',
					'placeholder' => "00000000-0000-0000-0000-000000000000\n11111111-1111-1111-1111-111111111111",
					'help'        => __( 'Only needed for a multi-tenant registration. One tenant GUID per line; a token whose tid is not listed is rejected. Leave blank for a single-tenant app.', 'vulnhub' ),
				),
			),
			$this->common_oidc_fields()
		);
	}

	/**
	 * Fetch and validate the Entra ID discovery document.
	 *
	 * @return array{ok:bool,message:string,detail?:array<string,mixed>}
	 */
	public function test_connection(): array {
		$result = $this->probe_oidc( $this->id() );

		$tenant = trim( (string) $this->get( 'tenant_id', '' ) );
		if ( in_array( strtolower( $tenant ), array( 'common', 'organizations', 'consumers' ), true ) ) {
			$allowed = trim( (string) $this->get( 'allowed_tenants', '' ) );
			if ( '' === $allowed ) {
				return array(
					'ok'      => false,
					'message' => __( 'This is a multi-tenant configuration, so every Microsoft tenant in the world could reach the sign-in. Add the tenant IDs that are allowed before enabling it.', 'vulnhub' ),
					'detail'  => $result['detail'] ?? array(),
				);
			}
		}

		return $result;
	}
}

