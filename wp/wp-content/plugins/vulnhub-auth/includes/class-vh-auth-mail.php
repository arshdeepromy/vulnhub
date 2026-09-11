<?php
/**
 * Outbound mail for the portal.
 *
 * The portal sends exactly one kind of message that matters — the invitation
 * that lets a new person set their first password — so mail is not optional
 * decoration here: if it does not leave the building, nobody can be onboarded.
 *
 * This container has no `sendmail` binary at all (`sendmail_path` points at
 * `/usr/sbin/sendmail`, which does not exist), and the default From address
 * derived from a `localhost` site URL is rejected by PHPMailer as invalid
 * before a transport is even attempted. Both failures are silent: `wp_mail()`
 * returns false and WordPress says nothing. So this class does three things.
 *
 *  - Gives every message a From address that is actually deliverable.
 *  - Routes mail over SMTP when a host is configured, because PHP's own
 *    `SMTP` ini setting is Windows-only and does nothing on Linux.
 *  - Remembers the last failure, so the People screen can say "invitations
 *    are not being delivered" instead of quietly doing nothing.
 *
 * Settings live under the `mail` namespace of the core settings store, which
 * means the SMTP password is encrypted at rest like any other credential.
 *
 * @package VulnHub\Auth
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * From address, SMTP transport and delivery status.
 */
final class VulnHub_Auth_Mail {

	/** Settings namespace inside the core credential store. */
	public const SETTINGS = 'mail';

	/** Option holding the most recent delivery failure. */
	private const FAILURE_OPTION = 'vulnhub_auth_mail_failure';

	public static function init(): void {
		add_filter( 'wp_mail_from', array( __CLASS__, 'from_address' ), 20 );
		add_filter( 'wp_mail_from_name', array( __CLASS__, 'from_name' ), 20 );
		add_action( 'phpmailer_init', array( __CLASS__, 'configure_transport' ) );
		add_action( 'wp_mail_failed', array( __CLASS__, 'remember_failure' ) );
		add_action( 'wp_mail_succeeded', array( __CLASS__, 'clear_failure' ) );
	}

	/* -----------------------------------------------------------------
	 * Settings access
	 * --------------------------------------------------------------- */

	/**
	 * A configured value, or the given default.
	 *
	 * @param string $key     Setting key.
	 * @param string $default Fallback.
	 */
	public static function get( string $key, string $default = '' ): string {
		if ( ! function_exists( 'vulnhub' ) ) {
			return $default;
		}
		$value = (string) vulnhub()->settings->get( self::SETTINGS, $key, $default );
		return '' === $value ? $default : $value;
	}

	/**
	 * The SMTP password, decrypted.
	 */
	private static function password(): string {
		return function_exists( 'vulnhub' ) ? vulnhub()->settings->secret( self::SETTINGS, 'smtp_pass' ) : '';
	}

	/**
	 * Persist the delivery settings.
	 *
	 * A blank password field means "keep the stored one" — that is the core
	 * settings store's own convention and it is what stops an admin wiping a
	 * credential every time they change the port.
	 *
	 * @param array<string,string> $values Raw, already-sanitised values.
	 */
	public static function save( array $values ): void {
		if ( ! function_exists( 'vulnhub' ) ) {
			return;
		}

		vulnhub()->settings->update(
			self::SETTINGS,
			array(
				'from_address' => $values['from_address'] ?? '',
				'from_name'    => $values['from_name'] ?? '',
				'smtp_host'    => $values['smtp_host'] ?? '',
				'smtp_port'    => $values['smtp_port'] ?? '',
				'smtp_secure'  => $values['smtp_secure'] ?? '',
				'smtp_user'    => $values['smtp_user'] ?? '',
			)
		);

		vulnhub()->settings->set_secret( self::SETTINGS, 'smtp_pass', $values['smtp_pass'] ?? '' );
	}

	/* -----------------------------------------------------------------
	 * From address
	 * --------------------------------------------------------------- */

	/**
	 * A From address that will survive PHPMailer's validator.
	 *
	 * WordPress's default is `wordpress@` plus the site host. On this
	 * deployment the stored site URL is `http://localhost:8093`, which yields
	 * `wordpress@localhost` — no dot, no TLD, rejected outright, and the
	 * error the operator sees is the unhelpful "Invalid address: (From)".
	 * A host with no dot in it is therefore never used; the site's own admin
	 * address is the fallback, because whatever else is true of it, mail to
	 * it has already been shown to work.
	 *
	 * @param string $from Address WordPress proposes.
	 */
	public static function from_address( string $from ): string {
		$configured = self::get( 'from_address' );

		if ( '' !== $configured && is_email( $configured ) ) {
			return $configured;
		}

		$host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$host = preg_replace( '/^www\./', '', strtolower( $host ) ) ?? '';

		if ( '' !== $host && str_contains( $host, '.' ) ) {
			return 'no-reply@' . $host;
		}

		$admin = (string) get_option( 'admin_email' );

		return is_email( $admin ) ? $admin : $from;
	}

	/**
	 * @param string $name Name WordPress proposes.
	 */
	public static function from_name( string $name ): string {
		$configured = self::get( 'from_name' );

		if ( '' !== $configured ) {
			return $configured;
		}

		$org = function_exists( 'vulnhub' )
			? (string) vulnhub()->settings->platform( 'org_name', '' )
			: '';

		return $org ? $org . ' — VulnHub' : ( 'WordPress' === $name ? 'VulnHub' : $name );
	}

	/* -----------------------------------------------------------------
	 * Transport
	 * --------------------------------------------------------------- */

	/**
	 * Has a portal administrator switched email delivery on?
	 *
	 * The switch is the Integrations card's own "Enable this integration",
	 * so turning the connector off really does stop the portal using these
	 * settings rather than merely hiding them.
	 */
	public static function is_enabled(): bool {
		if ( ! function_exists( 'vulnhub' ) ) {
			return false;
		}

		return vulnhub()->settings->get_bool( self::SETTINGS, 'enabled', false );
	}

	/**
	 * Is there a transport at all?
	 *
	 * Either the SMTP connector is enabled and pointed at a host, or the PHP
	 * mail() route has a real binary behind it. Anything else means
	 * invitations will not arrive — and this container has no such binary.
	 */
	public static function is_configured(): bool {
		if ( self::is_enabled() && '' !== self::host() ) {
			return true;
		}

		$path   = (string) ini_get( 'sendmail_path' );
		$binary = strtok( trim( $path ), ' ' );

		return is_string( $binary ) && '' !== $binary && is_executable( $binary );
	}

	/**
	 * SMTP host, from a wp-config constant first so a deployment can pin it.
	 */
	public static function host(): string {
		if ( defined( 'VULNHUB_SMTP_HOST' ) && '' !== (string) VULNHUB_SMTP_HOST ) {
			return (string) VULNHUB_SMTP_HOST;
		}
		return self::get( 'smtp_host' );
	}

	public static function port(): int {
		if ( defined( 'VULNHUB_SMTP_PORT' ) && (int) VULNHUB_SMTP_PORT > 0 ) {
			return (int) VULNHUB_SMTP_PORT;
		}
		$port = (int) self::get( 'smtp_port', '0' );
		return $port > 0 ? $port : 25;
	}

	/**
	 * Point PHPMailer at SMTP when a host is configured.
	 *
	 * @param PHPMailer\PHPMailer\PHPMailer $mailer The mailer about to send.
	 */
	public static function configure_transport( $mailer ): void {
		$host = self::host();

		// A disabled integration must not quietly keep routing mail.
		if ( '' === $host || ! self::is_enabled() ) {
			return;
		}

		$mailer->isSMTP();
		$mailer->Host    = $host; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
		$mailer->Port    = self::port(); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
		$mailer->Timeout = 15; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase

		$secure = self::get( 'smtp_secure' );

		if ( in_array( $secure, array( 'tls', 'ssl' ), true ) ) {
			$mailer->SMTPSecure = $secure; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
		} else {
			$mailer->SMTPAutoTLS = false; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
			$mailer->SMTPSecure  = ''; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
		}

		$user = self::get( 'smtp_user' );
		$pass = self::password();

		if ( '' !== $user ) {
			$mailer->SMTPAuth = true; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
			$mailer->Username = $user; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
			$mailer->Password = $pass; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
		} else {
			$mailer->SMTPAuth = false; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
		}
	}

	/* -----------------------------------------------------------------
	 * Delivery status
	 * --------------------------------------------------------------- */

	/**
	 * @param WP_Error $error The failure WordPress reported.
	 */
	public static function remember_failure( $error ): void {
		if ( ! is_wp_error( $error ) ) {
			return;
		}

		update_option(
			self::FAILURE_OPTION,
			array(
				'message' => (string) $error->get_error_message(),
				'at'      => time(),
			),
			false
		);
	}

	public static function clear_failure(): void {
		delete_option( self::FAILURE_OPTION );
	}

	/**
	 * The last delivery failure, if one is on record.
	 *
	 * @return array{message:string,at:int}|null
	 */
	public static function last_failure(): ?array {
		$stored = get_option( self::FAILURE_OPTION );

		if ( ! is_array( $stored ) || empty( $stored['message'] ) ) {
			return null;
		}

		return array(
			'message' => (string) $stored['message'],
			'at'      => (int) ( $stored['at'] ?? 0 ),
		);
	}

	/**
	 * Send a test message and report what happened.
	 *
	 * @param string $to Recipient.
	 * @return array{ok:bool,message:string}
	 */
	public static function send_test( string $to ): array {
		if ( ! is_email( $to ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'That is not a valid email address.', 'vulnhub' ),
			);
		}

		self::clear_failure();

		$sent = wp_mail(
			$to,
			__( 'VulnHub test message', 'vulnhub' ),
			__( "This is a test from the VulnHub portal.\n\nIf you are reading it, invitations to new users will be delivered too.", 'vulnhub' )
		);

		if ( $sent ) {
			return array(
				'ok'      => true,
				/* translators: %s: email address. */
				'message' => sprintf( __( 'Test message accepted for delivery to %s.', 'vulnhub' ), $to ),
			);
		}

		$failure = self::last_failure();

		return array(
			'ok'      => false,
			'message' => $failure
				/* translators: %s: error reported by the mail transport. */
				? sprintf( __( 'The test message was not sent: %s', 'vulnhub' ), $failure['message'] )
				: __( 'The test message was not sent, and the mail transport gave no reason.', 'vulnhub' ),
		);
	}
}

