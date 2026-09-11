<?php
/**
 * Shared behaviour for every identity-provider connector.
 *
 * These connectors exist so each identity provider gets its own card on the
 * Integrations screen with its own credentials, health and test button. They
 * authenticate people rather than importing data, so they sit in the `auth`
 * category and opt out of scheduled syncs entirely.
 *
 * @package VulnHub\Auth
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Base class for the Okta, Entra, generic OIDC and LDAP connectors.
 */
abstract class VulnHub_Auth_Connector extends \VulnHub\Core\Connector {

	/**
	 * Grouped under "Authentication & SSO" on the Integrations screen.
	 */
	public function category(): string {
		return 'auth';
	}

	/**
	 * Authentication connectors never pull data on a schedule: they act during
	 * a sign-in, driven by a person in a browser.
	 */
	public function supports_sync(): bool {
		return false;
	}

	/**
	 * No schedule to offer.
	 */
	public function default_interval(): string {
		return 'manual';
	}

	/**
	 * Required by the abstract parent; there is nothing to sync.
	 *
	 * @param array<string,mixed> $args Unused.
	 * @return array{ok:bool,message:string}
	 */
	protected function do_sync( array $args = array() ): array {
		unset( $args );

		return array(
			'ok'      => true,
			'message' => __( 'This connector authenticates people; it does not import data, so there is nothing to sync.', 'vulnhub' ),
		);
	}

	/**
	 * Fields every OIDC provider needs, appended to the provider-specific ones.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	protected function common_oidc_fields(): array {
		return array(
			array(
				'key'         => 'client_id',
				'label'       => __( 'Client ID', 'vulnhub' ),
				'type'        => 'text',
				'required'    => true,
				'help'        => __( 'The application (client) ID from the identity provider.', 'vulnhub' ),
			),
			array(
				'key'      => 'client_secret',
				'label'    => __( 'Client secret', 'vulnhub' ),
				'type'     => 'text',
				'secret'   => true,
				'help'     => __( 'Stored encrypted. Leave blank to keep the existing value. Omit only for a public client.', 'vulnhub' ),
			),
			array(
				'key'         => 'scopes',
				'label'       => __( 'Scopes', 'vulnhub' ),
				'type'        => 'text',
				'placeholder' => 'openid profile email',
				'help'        => __( 'Space-separated. Leave blank for the recommended defaults.', 'vulnhub' ),
			),
			array(
				'key'            => 'auto_create',
				'label'          => __( 'Account creation', 'vulnhub' ),
				'type'           => 'checkbox',
				'checkbox_label' => __( 'Create a WordPress account the first time a verified identity signs in', 'vulnhub' ),
				'help'           => __( 'With this off, only people who already have an account here can use single sign-on.', 'vulnhub' ),
			),
			array(
				'key'     => 'default_role',
				'label'   => __( 'Role for new accounts', 'vulnhub' ),
				'type'    => 'select',
				'options' => self::role_choices(),
				'default' => 'vulnhub_viewer',
				'help'    => __( 'Group mapping on the Authentication screen can promote them from here.', 'vulnhub' ),
			),
		);
	}

	/**
	 * VulnHub role choices for a select field.
	 *
	 * @return array<string,string>
	 */
	protected static function role_choices(): array {
		$choices = array();
		foreach ( \VulnHub\Core\Caps::roles() as $slug => $definition ) {
			$choices[ $slug ] = (string) $definition['label'];
		}
		return $choices;
	}

	/**
	 * Probe an OIDC provider's metadata, shared by all three OIDC connectors.
	 *
	 * @param string $provider Provider id.
	 * @return array{ok:bool,message:string,detail?:array<string,mixed>}
	 */
	protected function probe_oidc( string $provider ): array {
		$endpoints = VulnHub_Auth_SSO::endpoints( $provider );

		if ( '' === $endpoints['discovery_url'] ) {
			return array(
				'ok'      => false,
				'message' => __( 'Fill in the provider details first — there is not enough here to build a discovery URL.', 'vulnhub' ),
			);
		}

		$client = VulnHub_Auth_SSO::client( $provider );
		if ( ! $client ) {
			return array(
				'ok'      => false,
				'message' => __( 'The connector could not be built from the current settings.', 'vulnhub' ),
			);
		}

		$result = $client->probe();

		// Report the redirect URI too: a mismatch here is the single most
		// common reason an otherwise correct OIDC app fails at sign-in.
		$result['detail']['redirect_uri']  = VulnHub_Auth_SSO::redirect_uri( $provider );
		$result['detail']['discovery_url'] = $endpoints['discovery_url'];
		$result['detail']['client_id_set'] = '' !== trim( (string) $this->get( 'client_id', '' ) );
		$result['detail']['secret_set']    = $this->settings->has_secret( $provider, 'client_secret' );

		return $result;
	}

	/**
	 * Authentication connectors are usable without a "live" credential test,
	 * so mock mode is reported but never blocks a genuine discovery probe.
	 */
	public function is_configured(): bool {
		foreach ( $this->fields() as $field ) {
			if ( empty( $field['required'] ) ) {
				continue;
			}
			$key = (string) $field['key'];
			if ( ! empty( $field['secret'] ) ) {
				if ( ! $this->settings->has_secret( $this->id(), $key ) ) {
					return false;
				}
			} elseif ( '' === trim( (string) $this->settings->get( $this->id(), $key, '' ) ) ) {
				return false;
			}
		}
		return true;
	}
}

