<?php
/**
 * AWS IAM Identity Center (SSO) device-authorization login for the connector.
 *
 * The same flow as `aws sso login`: register a public OIDC client, start a
 * device authorization (the operator approves it in a browser), then poll for
 * a token. The token lasts hours and carries a refresh token, so the connector
 * renews it without the operator re-pasting anything. The token is then
 * exchanged for short-lived read credentials per account through the SSO
 * portal — no long-lived key, and nothing created in AWS.
 *
 * OIDC register/start/token calls are unsigned (public client). Portal calls
 * carry the access token in the x-amz-sso_bearer_token header. Neither is
 * SigV4, so this needs no credentials of its own.
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The SSO OIDC + portal client.
 */
final class VulnHub_AWS_SSO {

	private \VulnHub\Core\Http $http;
	private string $region;

	public function __construct( string $region, ?callable $log = null ) {
		$this->region = '' !== trim( $region ) ? trim( $region ) : 'us-east-1';
		$this->http   = new \VulnHub\Core\Http( 'VulnHub-AWS-SSO', $log );
	}

	private function oidc(): string {
		return 'https://oidc.' . $this->region . '.amazonaws.com';
	}

	private function portal(): string {
		return 'https://portal.sso.' . $this->region . '.amazonaws.com';
	}

	/** @return array<string,mixed> */
	private function post_json( string $url, array $body ): array {
		$res  = $this->http->post( $url, $body, array( 'content-type' => 'application/json' ) );
		$data = (array) $res->data();

		return $data + array( '_ok' => $res->ok(), '_status' => (int) $res->status, '_error' => (string) $res->error_message() );
	}

	/** Register a public OIDC client. @return array<string,mixed> */
	public function register_client(): array {
		return $this->post_json(
			$this->oidc() . '/client/register',
			array( 'clientName' => 'vulnhub-aws-' . gmdate( 'Ymd' ), 'clientType' => 'public', 'scopes' => array( 'sso:account:access' ) )
		);
	}

	/** Begin device authorization. @return array<string,mixed> */
	public function start_device( string $client_id, string $client_secret, string $start_url ): array {
		return $this->post_json(
			$this->oidc() . '/device_authorization',
			array( 'clientId' => $client_id, 'clientSecret' => $client_secret, 'startUrl' => $start_url )
		);
	}

	/** Poll for a token; returns error=authorization_pending until approved. @return array<string,mixed> */
	public function create_token( string $client_id, string $client_secret, string $device_code ): array {
		return $this->post_json(
			$this->oidc() . '/token',
			array(
				'clientId'     => $client_id,
				'clientSecret' => $client_secret,
				'grantType'    => 'urn:ietf:params:oauth:grant-type:device_code',
				'deviceCode'   => $device_code,
			)
		);
	}

	/** Exchange a refresh token for a fresh access token. @return array<string,mixed> */
	public function refresh( string $client_id, string $client_secret, string $refresh_token ): array {
		return $this->post_json(
			$this->oidc() . '/token',
			array(
				'clientId'     => $client_id,
				'clientSecret' => $client_secret,
				'grantType'    => 'refresh_token',
				'refreshToken' => $refresh_token,
			)
		);
	}

	/** @return array<string,mixed> */
	private function portal_get( string $path, string $token, array $query = array() ): array {
		$res  = $this->http->get( $this->portal() . $path, $query, array( 'x-amz-sso_bearer_token' => $token ) );
		$data = (array) $res->data();

		return $data + array( '_ok' => $res->ok(), '_status' => (int) $res->status, '_error' => (string) $res->error_message() );
	}

	/** Every account the login can reach. @return array<int,array<string,mixed>> */
	public function list_accounts( string $token ): array {
		$out  = array();
		$next = '';

		do {
			$q = array( 'max_result' => 100 );
			if ( '' !== $next ) { $q['next_token'] = $next; }

			$res = $this->portal_get( '/assignment/accounts', $token, $q );

			if ( empty( $res['_ok'] ) ) { break; }

			foreach ( (array) ( $res['accountList'] ?? array() ) as $a ) { $out[] = (array) $a; }
			$next = (string) ( $res['nextToken'] ?? '' );
		} while ( '' !== $next && count( $out ) < 2000 );

		return $out;
	}

	/** Role names assigned in one account. @return string[] */
	public function list_roles( string $token, string $account_id ): array {
		$res  = $this->portal_get( '/assignment/roles', $token, array( 'account_id' => $account_id, 'max_result' => 100 ) );
		$out  = array();

		foreach ( (array) ( $res['roleList'] ?? array() ) as $r ) {
			if ( ! empty( $r['roleName'] ) ) { $out[] = (string) $r['roleName']; }
		}

		return $out;
	}

	/** Short-lived AWS credentials for account+role. @return array<string,mixed> */
	public function role_credentials( string $token, string $account_id, string $role_name ): array {
		$res = $this->portal_get( '/federation/credentials', $token, array( 'account_id' => $account_id, 'role_name' => $role_name ) );

		return (array) ( $res['roleCredentials'] ?? array() ) + array( '_ok' => ! empty( $res['_ok'] ), '_error' => (string) ( $res['_error'] ?? '' ) );
	}
}
