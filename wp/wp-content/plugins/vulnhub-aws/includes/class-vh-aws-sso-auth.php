<?php
/**
 * The "Authenticate with AWS SSO" flow for the AWS integration card.
 *
 * A two-step device-authorization login, mirroring how the Jira connector
 * offers "Connect": start it, approve in a browser tab, complete it. The
 * resulting token (with its refresh token) is stored on the connector so the
 * sync renews it on its own. Nothing is created in AWS; this is the operator's
 * own SSO login, approved for VulnHub.
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;
use VulnHub\Core\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_AWS_SSO_Auth {

	public static function init(): void {
		add_action( 'admin_post_vulnhub_aws_sso_start', array( __CLASS__, 'handle_start' ) );
		add_action( 'admin_post_vulnhub_aws_sso_finish', array( __CLASS__, 'handle_finish' ) );
		add_action( 'admin_post_vulnhub_aws_sso_disconnect', array( __CLASS__, 'handle_disconnect' ) );
	}

	private static function settings(): Settings {
		return new Settings();
	}

	private static function pending_key(): string {
		return 'vulnhub_aws_sso_pending_' . get_current_user_id();
	}

	public static function start_url(): string {
		return wp_nonce_url( admin_url( 'admin-post.php?action=vulnhub_aws_sso_start' ), 'vulnhub_aws_sso' );
	}

	public static function finish_url(): string {
		return wp_nonce_url( admin_url( 'admin-post.php?action=vulnhub_aws_sso_finish' ), 'vulnhub_aws_sso' );
	}

	public static function disconnect_url(): string {
		return wp_nonce_url( admin_url( 'admin-post.php?action=vulnhub_aws_sso_disconnect' ), 'vulnhub_aws_sso' );
	}

	/** @return array<string,mixed>|null */
	public static function pending(): ?array {
		$p = get_transient( self::pending_key() );

		return is_array( $p ) ? $p : null;
	}

	public static function is_connected(): bool {
		$t = json_decode( (string) self::settings()->secret( 'aws', 'sso_token' ), true );

		return is_array( $t ) && ! empty( $t['accessToken'] );
	}

	private static function guard(): void {
		if ( ! isset( $_GET['_wpnonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ), 'vulnhub_aws_sso' ) ) {
			wp_die( esc_html__( 'That link expired. Go back and try again.', 'vulnhub' ) );
		}

		if ( ! current_user_can( Caps::MANAGE ) ) {
			wp_die( esc_html__( 'You do not have permission to manage integrations.', 'vulnhub' ) );
		}
	}

	private static function back( string $type, string $msg = '' ): void {
		$to = wp_get_referer() ?: admin_url();
		wp_safe_redirect( add_query_arg( array( 'aws_sso' => $type, 'aws_sso_msg' => rawurlencode( $msg ) ), $to ) );
		exit;
	}

	public static function handle_start(): void {
		self::guard();

		$s      = self::settings();
		$url    = trim( (string) $s->get( 'aws', 'sso_start_url', '' ) );
		$region = trim( (string) $s->get( 'aws', 'sso_region', (string) $s->get( 'aws', 'region', 'us-east-1' ) ) );

		if ( '' === $url ) {
			self::back( 'error', __( 'Enter and save your AWS SSO start URL first.', 'vulnhub' ) );
		}

		$sso = new VulnHub_AWS_SSO( $region );
		$reg = $sso->register_client();

		if ( empty( $reg['_ok'] ) || empty( $reg['clientId'] ) ) {
			self::back( 'error', __( 'Could not register with AWS SSO: ', 'vulnhub' ) . (string) ( $reg['_error'] ?? '' ) );
		}

		$dev = $sso->start_device( (string) $reg['clientId'], (string) $reg['clientSecret'], $url );

		if ( empty( $dev['_ok'] ) || empty( $dev['deviceCode'] ) ) {
			self::back( 'error', __( 'Could not start the SSO login: ', 'vulnhub' ) . (string) ( $dev['error'] ?? $dev['_error'] ?? '' ) );
		}

		set_transient(
			self::pending_key(),
			array(
				'clientId'     => (string) $reg['clientId'],
				'clientSecret' => (string) $reg['clientSecret'],
				'deviceCode'   => (string) $dev['deviceCode'],
				'region'       => $region,
				'verify'       => (string) ( $dev['verificationUriComplete'] ?? $dev['verificationUri'] ?? '' ),
				'userCode'     => (string) ( $dev['userCode'] ?? '' ),
			),
			(int) ( $dev['expiresIn'] ?? 600 )
		);

		self::back( 'pending', __( 'Approve the login in the AWS tab, then click Complete.', 'vulnhub' ) );
	}

	public static function handle_finish(): void {
		self::guard();

		$p = self::pending();

		if ( ! $p ) {
			self::back( 'error', __( 'No pending login — start again.', 'vulnhub' ) );
		}

		$sso = new VulnHub_AWS_SSO( (string) $p['region'] );
		$tok = $sso->create_token( (string) $p['clientId'], (string) $p['clientSecret'], (string) $p['deviceCode'] );

		if ( empty( $tok['_ok'] ) || empty( $tok['accessToken'] ) ) {
			$err = (string) ( $tok['error'] ?? $tok['_error'] ?? '' );

			if ( false !== strpos( $err, 'authorization_pending' ) || false !== strpos( $err, 'slow_down' ) ) {
				self::back( 'pending', __( 'Not approved yet — click Allow in the AWS tab, then Complete.', 'vulnhub' ) );
			}

			self::back( 'error', __( 'SSO login failed: ', 'vulnhub' ) . $err );
		}

		self::settings()->set_secret(
			'aws',
			'sso_token',
			(string) wp_json_encode(
				array(
					'accessToken'  => (string) $tok['accessToken'],
					'refreshToken' => (string) ( $tok['refreshToken'] ?? '' ),
					'expires'      => time() + (int) ( $tok['expiresIn'] ?? 3600 ),
					'clientId'     => (string) $p['clientId'],
					'clientSecret' => (string) $p['clientSecret'],
					'region'       => (string) $p['region'],
				)
			)
		);

		delete_transient( self::pending_key() );
		self::back( 'success', __( 'Connected to AWS via SSO.', 'vulnhub' ) );
	}

	public static function handle_disconnect(): void {
		self::guard();
		self::settings()->set_secret( 'aws', 'sso_token', null );
		delete_transient( self::pending_key() );
		self::back( 'info', __( 'Disconnected from AWS SSO.', 'vulnhub' ) );
	}
}
