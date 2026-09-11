<?php
/**
 * Active Directory / LDAP connector.
 *
 * @package VulnHub\Auth
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Active Directory over LDAPS, using a service account to search and then a
 * user bind to prove the password.
 */
final class VulnHub_LDAP_Connector extends VulnHub_Auth_Connector {

	/**
	 * Machine id.
	 */
	public function id(): string {
		return 'ldap';
	}

	/**
	 * Human label.
	 */
	public function label(): string {
		return __( 'Active Directory / LDAP', 'vulnhub' );
	}

	/**
	 * One-line description for the Integrations card.
	 */
	public function description(): string {
		return __( 'Authenticate against Active Directory over LDAPS with a service account, matching on sAMAccountName or userPrincipalName and mapping memberOf groups onto VulnHub roles.', 'vulnhub' );
	}

	/**
	 * Dashicon.
	 */
	public function icon(): string {
		return 'dashicons-groups';
	}

	/**
	 * Settings fields.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public function fields(): array {
		return array(
			array(
				'key'         => 'host',
				'label'       => __( 'Domain controller', 'vulnhub' ),
				'type'        => 'text',
				'required'    => true,
				'placeholder' => 'dc01.corp.example.com',
				'help'        => __( 'Hostname only. Use a name that matches the certificate, otherwise LDAPS will refuse the connection.', 'vulnhub' ),
			),
			array(
				'key'            => 'use_ldaps',
				'label'          => __( 'Transport', 'vulnhub' ),
				'type'           => 'checkbox',
				'checkbox_label' => __( 'Use LDAPS (port 636)', 'vulnhub' ),
				'default'        => 1,
				'help'           => __( 'Leave this on. A plain LDAP bind sends the password in clear text across the network.', 'vulnhub' ),
			),
			array(
				'key'         => 'port',
				'label'       => __( 'Port', 'vulnhub' ),
				'type'        => 'number',
				'placeholder' => '636',
				'help'        => __( 'Leave blank for 636 with LDAPS or 389 without.', 'vulnhub' ),
			),
			array(
				'key'         => 'base_dn',
				'label'       => __( 'Search base DN', 'vulnhub' ),
				'type'        => 'text',
				'required'    => true,
				'placeholder' => 'OU=Staff,DC=corp,DC=example,DC=com',
				'help'        => __( 'The subtree searched for user accounts.', 'vulnhub' ),
			),
			array(
				'key'         => 'bind_dn',
				'label'       => __( 'Service account DN', 'vulnhub' ),
				'type'        => 'text',
				'required'    => true,
				'placeholder' => 'CN=svc-vulnhub,OU=Service Accounts,DC=corp,DC=example,DC=com',
				'help'        => __( 'A read-only account used to find the user before their own bind is attempted.', 'vulnhub' ),
			),
			array(
				'key'      => 'bind_password',
				'label'    => __( 'Service account password', 'vulnhub' ),
				'type'     => 'text',
				'secret'   => true,
				'required' => true,
				'help'     => __( 'Stored encrypted. Leave blank to keep the existing value.', 'vulnhub' ),
			),
			array(
				'key'            => 'auto_create',
				'label'          => __( 'Account creation', 'vulnhub' ),
				'type'           => 'checkbox',
				'checkbox_label' => __( 'Create a WordPress account the first time a directory user signs in', 'vulnhub' ),
			),
			array(
				'key'     => 'default_role',
				'label'   => __( 'Role for new accounts', 'vulnhub' ),
				'type'    => 'select',
				'options' => self::role_choices(),
				'default' => 'vulnhub_viewer',
			),
		);
	}

	/**
	 * Bind with the service account and report the readable base DN.
	 *
	 * @return array{ok:bool,message:string,detail?:array<string,mixed>}
	 */
	public function test_connection(): array {
		if ( ! VulnHub_Auth_LDAP::available() ) {
			return array(
				'ok'      => false,
				'message' => __( 'The PHP ldap extension is not installed on this server. Install php-ldap and restart PHP before configuring this connector.', 'vulnhub' ),
				'detail'  => array( 'extension_loaded' => false ),
			);
		}

		$result = VulnHub_Auth_LDAP::test();

		return array(
			'ok'      => (bool) $result['ok'],
			'message' => (string) $result['message'],
			'detail'  => (array) $result['detail'],
		);
	}
}

