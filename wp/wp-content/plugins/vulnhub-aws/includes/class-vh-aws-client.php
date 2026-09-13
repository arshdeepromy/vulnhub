<?php
/**
 * A signed HTTP client for the handful of AWS APIs this app reads.
 *
 * Deliberately small. It knows how to sign a request, send it through
 * WordPress's HTTP layer, and tell a throttle apart from a permission error --
 * which is all four read-only Describe/List calls need. It is not an SDK and
 * should not grow into one.
 *
 * Credentials are passed in rather than read from the environment. The stack
 * runs on-prem in Docker with no instance profile, so there is no metadata
 * service to fall back on, and an accidental fallback to some ambient
 * credential would be worse than a clear failure.
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Signed requests to AWS.
 */
final class VulnHub_AWS_Client {

	private string $key;
	private string $secret;
	private string $token;
	private int $timeout;

	/** Requests sent, for the sync log. */
	private int $calls = 0;

	public function __construct( string $key, string $secret, string $token = '', int $timeout = 30 ) {
		$this->key     = $key;
		$this->secret  = $secret;
		$this->token   = $token;
		$this->timeout = $timeout;
	}

	public function calls(): int {
		return $this->calls;
	}

	/**
	 * POST a JSON body to a REST-JSON service (Inspector, and most newer APIs).
	 *
	 * @param array<string,mixed> $body Request body.
	 * @return array{ok:bool,status:int,data:array<string,mixed>,error:string}
	 */
	public function json( string $service, string $region, string $path, array $body ): array {
		$url  = sprintf( 'https://%s.%s.amazonaws.com%s', $service, $region, $path );
		$json = wp_json_encode( $body );

		if ( ! is_string( $json ) ) {
			return self::fail( 0, 'could not encode the request body' );
		}

		$headers = VulnHub_AWS_SigV4::headers(
			'POST',
			$url,
			$json,
			array( 'content-type' => 'application/json' ),
			$region,
			$service,
			$this->key,
			$this->secret,
			$this->token
		);

		++$this->calls;

		$res = wp_remote_post(
			$url,
			array(
				'headers' => $headers,
				'body'    => $json,
				'timeout' => $this->timeout,
			)
		);

		if ( is_wp_error( $res ) ) {
			return self::fail( 0, $res->get_error_message() );
		}

		$status = (int) wp_remote_retrieve_response_code( $res );
		$raw    = (string) wp_remote_retrieve_body( $res );
		$data   = json_decode( $raw, true );
		$data   = is_array( $data ) ? $data : array();

		if ( $status >= 200 && $status < 300 ) {
			return array(
				'ok'     => true,
				'status' => $status,
				'data'   => $data,
				'error'  => '',
			);
		}

		/*
		 * AWS puts the useful part of an error in different places depending on
		 * the protocol -- a `message`, a `Message`, or only in the
		 * x-amzn-errortype header. Read all three: "AccessDeniedException" with
		 * no body is the single most likely response while somebody is still
		 * fitting the IAM policy, and an empty error string there would send
		 * them looking at the wrong thing.
		 */
		$type = (string) wp_remote_retrieve_header( $res, 'x-amzn-errortype' );
		$type = explode( ':', $type )[0];

		$msg = (string) ( $data['message'] ?? $data['Message'] ?? '' );

		return self::fail( $status, trim( $type . ( '' !== $msg ? ': ' . $msg : '' ) ) ?: $raw );
	}

	/**
	 * POST a form-encoded query to one of the older XML services (EC2, STS).
	 *
	 * @param array<string,string> $params Action, Version and arguments.
	 * @return array{ok:bool,status:int,xml:?SimpleXMLElement,error:string}
	 */
	public function query( string $service, string $region, array $params, string $host = '' ): array {
		$url  = '' !== $host ? 'https://' . $host . '/' : sprintf( 'https://%s.%s.amazonaws.com/', $service, $region );
		$body = http_build_query( $params, '', '&', PHP_QUERY_RFC3986 );

		$headers = VulnHub_AWS_SigV4::headers(
			'POST',
			$url,
			$body,
			array( 'content-type' => 'application/x-www-form-urlencoded; charset=utf-8' ),
			$region,
			$service,
			$this->key,
			$this->secret,
			$this->token
		);

		++$this->calls;

		$res = wp_remote_post(
			$url,
			array(
				'headers' => $headers,
				'body'    => $body,
				'timeout' => $this->timeout,
			)
		);

		if ( is_wp_error( $res ) ) {
			return array(
				'ok'     => false,
				'status' => 0,
				'xml'    => null,
				'error'  => $res->get_error_message(),
			);
		}

		$status = (int) wp_remote_retrieve_response_code( $res );
		$raw    = (string) wp_remote_retrieve_body( $res );

		// Malformed XML must not raise a warning into the page.
		$prev = libxml_use_internal_errors( true );
		$xml  = simplexml_load_string( $raw );
		libxml_clear_errors();
		libxml_use_internal_errors( $prev );

		if ( $status >= 200 && $status < 300 && false !== $xml ) {
			return array(
				'ok'     => true,
				'status' => $status,
				'xml'    => $xml,
				'error'  => '',
			);
		}

		$err = '';

		if ( false !== $xml && isset( $xml->Errors->Error ) ) { // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
			$err = (string) $xml->Errors->Error->Code . ': ' . (string) $xml->Errors->Error->Message; // phpcs:ignore
		} elseif ( false !== $xml && isset( $xml->Error ) ) { // phpcs:ignore
			$err = (string) $xml->Error->Code . ': ' . (string) $xml->Error->Message; // phpcs:ignore
		}

		return array(
			'ok'     => false,
			'status' => $status,
			'xml'    => null,
			'error'  => '' !== $err ? $err : substr( $raw, 0, 300 ),
		);
	}

	/**
	 * Who are these credentials? The cheapest possible permission check --
	 * sts:GetCallerIdentity is allowed for every principal and cannot be
	 * denied by policy, so a failure here is a bad key rather than a missing
	 * grant.
	 *
	 * @return array{ok:bool,account:string,arn:string,error:string}
	 */
	public function caller_identity(): array {
		$res = $this->query(
			'sts',
			'us-east-1',
			array(
				'Action'  => 'GetCallerIdentity',
				'Version' => '2011-06-15',
			),
			'sts.amazonaws.com'
		);

		if ( ! $res['ok'] ) {
			return array(
				'ok'      => false,
				'account' => '',
				'arn'     => '',
				'error'   => (string) $res['error'],
			);
		}

		$r = $res['xml']->GetCallerIdentityResult ?? null; // phpcs:ignore

		return array(
			'ok'      => true,
			'account' => (string) ( $r->Account ?? '' ), // phpcs:ignore
			'arn'     => (string) ( $r->Arn ?? '' ), // phpcs:ignore
			'error'   => '',
		);
	}

	/**
	 * Borrow a role in another account.
	 *
	 * This is what makes fifty-eight accounts tractable. One base credential
	 * assumes the same read-only role in every member account, so adding an
	 * account is entering its number -- not minting, storing and rotating
	 * another key pair. It is also the only arrangement that survives contact
	 * with short-term SSO credentials, which expire hourly and would otherwise
	 * have to be re-pasted fifty-eight times.
	 *
	 * The returned credentials are temporary by construction, which is the
	 * point: nothing long-lived is created in the member account, and
	 * revoking access is deleting one role rather than hunting for keys.
	 *
	 * @param string $role_arn    Role to assume in the target account.
	 * @param string $external_id Shared secret the role's trust policy requires.
	 * @return array{ok:bool,client:?self,error:string,expires:string}
	 */
	public function assume( string $role_arn, string $external_id = '', string $session = 'vulnhub' ): array {
		$params = array(
			'Action'          => 'AssumeRole',
			'Version'         => '2011-06-15',
			'RoleArn'         => $role_arn,
			'RoleSessionName' => substr( preg_replace( '/[^A-Za-z0-9=,.@-]/', '-', $session ) ?: 'vulnhub', 0, 64 ),
			'DurationSeconds' => '3600',
		);

		if ( '' !== $external_id ) {
			$params['ExternalId'] = $external_id;
		}

		$res = $this->query( 'sts', 'us-east-1', $params, 'sts.amazonaws.com' );

		if ( ! $res['ok'] ) {
			return array(
				'ok'      => false,
				'client'  => null,
				'error'   => (string) $res['error'],
				'expires' => '',
			);
		}

		$creds = $res['xml']->AssumeRoleResult->Credentials ?? null; // phpcs:ignore

		if ( ! $creds ) {
			return array(
				'ok'      => false,
				'client'  => null,
				'error'   => __( 'AWS returned no credentials for that role.', 'vulnhub' ),
				'expires' => '',
			);
		}

		return array(
			'ok'      => true,
			'client'  => new self(
				(string) $creds->AccessKeyId, // phpcs:ignore
				(string) $creds->SecretAccessKey, // phpcs:ignore
				(string) $creds->SessionToken, // phpcs:ignore
				$this->timeout
			),
			'error'   => '',
			'expires' => (string) ( $creds->Expiration ?? '' ), // phpcs:ignore
		);
	}

	/**
	 * @return array{ok:bool,status:int,data:array<string,mixed>,error:string}
	 */
	private static function fail( int $status, string $error ): array {
		return array(
			'ok'     => false,
			'status' => $status,
			'data'   => array(),
			'error'  => $error,
		);
	}
}
