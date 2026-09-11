<?php
/**
 * Outbound email as a first-class integration.
 *
 * Email is the only channel the portal has for reaching a person who does not
 * yet have an account — the invitation with the one-time password link — so it
 * belongs on the Integrations screen beside Tenable and Jira rather than
 * buried in a settings tab. Registering it as a connector means it gets the
 * things every other integration already has for free: a card with a health
 * light, an enable switch, encrypted credential storage, and a Test button
 * that a portal administrator can press without leaving the portal.
 *
 * It is not a data source, so it opts out of scheduled syncs and out of mock
 * mode: there is no such thing as pretending to send an email, and a health
 * light that says "Mock data" over a mail server would be a lie.
 *
 * @package VulnHub\Auth
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * SMTP delivery for portal email.
 */
final class VulnHub_Mail_Connector extends \VulnHub\Core\Connector {

	public function id(): string {
		return VulnHub_Auth_Mail::SETTINGS;
	}

	public function label(): string {
		return __( 'Email delivery (SMTP)', 'vulnhub' );
	}

	public function description(): string {
		return __( 'Where the portal posts its mail. Invitations, password links and any future notification go out through here — with it off, a new account can only be onboarded by reading the one-time link off the screen.', 'vulnhub' );
	}

	public function icon(): string {
		return 'dashicons-email-alt';
	}

	public function category(): string {
		return 'email';
	}

	/**
	 * Nothing to pull on a schedule.
	 */
	public function supports_sync(): bool {
		return false;
	}

	public function default_interval(): string {
		return 'manual';
	}

	/**
	 * There is no sample mail server, and a health light claiming otherwise
	 * would hide a genuinely broken transport.
	 */
	public function is_mock(): bool {
		return false;
	}

	public function supports_mock(): bool {
		return false;
	}

	/**
	 * @param array<string,mixed> $args Unused.
	 * @return array{ok:bool,message:string}
	 */
	protected function do_sync( array $args = array() ): array {
		unset( $args );

		return array(
			'ok'      => true,
			'message' => __( 'This connector sends mail; it does not import anything, so there is nothing to sync.', 'vulnhub' ),
		);
	}

	/**
	 * @return array<int,array<string,mixed>>
	 */
	public function fields(): array {
		return array(
			array(
				'key'         => 'from_address',
				'label'       => __( 'From address', 'vulnhub' ),
				'type'        => 'email',
				'required'    => true,
				'placeholder' => 'no-reply@' . (string) wp_parse_url( home_url(), PHP_URL_HOST ),
				'help'        => __( 'Must be a real address at a domain this mail server is authorised to send for. A mismatch here is why invitations land in spam — or are refused outright.', 'vulnhub' ),
			),
			array(
				'key'         => 'from_name',
				'label'       => __( 'From name', 'vulnhub' ),
				'type'        => 'text',
				'placeholder' => __( 'VulnHub', 'vulnhub' ),
				'help'        => __( 'Leave blank to use the organisation name from Settings.', 'vulnhub' ),
			),
			array(
				'key'         => 'smtp_host',
				'label'       => __( 'SMTP host', 'vulnhub' ),
				'type'        => 'text',
				'required'    => true,
				'placeholder' => 'smtp.example.com',
				'help'        => __( 'This container has no sendmail binary, so without an SMTP host nothing is delivered at all — PHP has nowhere to hand the message to.', 'vulnhub' ),
			),
			array(
				'key'         => 'smtp_port',
				'label'       => __( 'Port', 'vulnhub' ),
				'type'        => 'number',
				'default'     => 587,
				'placeholder' => '587',
				'help'        => __( '587 with STARTTLS is the usual answer. 465 means implicit TLS; 25 is normally an internal relay only.', 'vulnhub' ),
			),
			array(
				'key'     => 'smtp_secure',
				'label'   => __( 'Encryption', 'vulnhub' ),
				'type'    => 'select',
				'options' => array(
					''    => __( 'None — plain, internal relay only', 'vulnhub' ),
					'tls' => __( 'STARTTLS (usually port 587)', 'vulnhub' ),
					'ssl' => __( 'Implicit TLS (usually port 465)', 'vulnhub' ),
				),
				'default' => 'tls',
				'help'    => __( 'Choose None only for a relay on a network you control. Credentials sent over an unencrypted connection are readable in transit.', 'vulnhub' ),
			),
			array(
				'key'   => 'smtp_user',
				'label' => __( 'Username', 'vulnhub' ),
				'type'  => 'text',
				'help'  => __( 'Leave blank for an unauthenticated relay. Anything else — Microsoft 365, Google Workspace, SES, Postmark — needs one.', 'vulnhub' ),
			),
			array(
				'key'    => 'smtp_pass',
				'label'  => __( 'Password', 'vulnhub' ),
				'type'   => 'text',
				'secret' => true,
				'help'   => __( 'Stored encrypted. Leave blank to keep the existing value. For Microsoft 365 or Google Workspace this is an app password, not the account password.', 'vulnhub' ),
			),
		);
	}

	/**
	 * Actually send a message, and report exactly what the transport said.
	 *
	 * A connection probe would be cheaper and would prove less: a server can
	 * accept a TCP connection and a login and still refuse the envelope
	 * sender. So the test is a real message to the person who pressed the
	 * button — if it arrives, invitations will arrive.
	 *
	 * @return array{ok:bool,message:string,detail?:array<string,mixed>}
	 */
	public function test_connection(): array {
		$to = (string) wp_get_current_user()->user_email;

		if ( ! is_email( $to ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'Your own account has no valid email address, so there is nowhere to send the test.', 'vulnhub' ),
			);
		}

		if ( ! $this->is_enabled() ) {
			return array(
				'ok'      => false,
				'message' => __( 'This integration is disabled, so the portal is not using these settings. Enable it, save, then test.', 'vulnhub' ),
			);
		}

		$result = VulnHub_Auth_Mail::send_test( $to );

		return array(
			'ok'      => $result['ok'],
			'message' => $result['message'],
			'detail'  => array(
				'host'      => VulnHub_Auth_Mail::host(),
				'port'      => VulnHub_Auth_Mail::port(),
				'encrypted' => VulnHub_Auth_Mail::get( 'smtp_secure' ) ?: 'none',
				'auth'      => '' !== VulnHub_Auth_Mail::get( 'smtp_user' ) ? 'yes' : 'no',
				'from'      => VulnHub_Auth_Mail::from_address( '' ),
				'sent_to'   => $to,
			),
		);
	}

	/**
	 * Health that describes a mail server rather than a data feed.
	 *
	 * The parent would say "Never synced" for a perfectly healthy transport,
	 * because it measures a connector by its last run. This one is measured
	 * by whether the last message got out.
	 *
	 * @return array{state:string,label:string,detail:string}
	 */
	public function health(): array {
		if ( ! $this->is_enabled() ) {
			return array(
				'state'  => 'off',
				'label'  => __( 'Disabled', 'vulnhub' ),
				'detail' => __( 'The portal sends no email. Invitations have to be handed over as a link.', 'vulnhub' ),
			);
		}

		if ( ! $this->is_configured() ) {
			return array(
				'state'  => 'warn',
				'label'  => __( 'Not configured', 'vulnhub' ),
				'detail' => __( 'A From address and an SMTP host are both needed before anything can be sent.', 'vulnhub' ),
			);
		}

		$failure = VulnHub_Auth_Mail::last_failure();

		if ( $failure ) {
			return array(
				'state'  => 'error',
				'label'  => __( 'Last message failed', 'vulnhub' ),
				'detail' => vh_trim( $failure['message'], 140 ),
			);
		}

		return array(
			'state'  => 'ok',
			'label'  => __( 'Active', 'vulnhub' ),
			'detail' => sprintf(
				/* translators: 1: host, 2: port. */
				__( 'Sending through %1$s on port %2$d. Nothing has failed since this was last changed.', 'vulnhub' ),
				VulnHub_Auth_Mail::host(),
				VulnHub_Auth_Mail::port()
			),
		);
	}
}

