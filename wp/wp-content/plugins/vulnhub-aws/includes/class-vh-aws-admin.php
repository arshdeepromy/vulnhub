<?php
/**
 * The AWS accounts screen.
 *
 * Its own section rather than more fields on the Integrations form, because
 * the question at fifty-eight accounts is not "are the credentials right" but
 * "which of these is not reporting, and what exactly could it not read". That
 * is a table, and a settings form has nowhere to put one.
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Add, list and check AWS accounts.
 */
final class VulnHub_AWS_Admin {

	public const SECTION = 'aws-accounts';
	private const NONCE  = 'vh_aws_accounts';

	/** @var array{text:string,tone:string}|null */
	private static ?array $notice = null;

	public static function init(): void {
		add_filter( 'vulnhub_portal_sections', array( __CLASS__, 'register_section' ) );
		add_action( 'vulnhub_render_portal_section', array( __CLASS__, 'render_section' ) );
		add_action( 'template_redirect', array( __CLASS__, 'handle' ), 5 );
	}

	/**
	 * @param array<string,array<string,mixed>> $sections Section definitions.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_section( array $sections ): array {
		$sections[ self::SECTION ] = array(
			'label'   => __( 'AWS accounts', 'vulnhub' ),
			'cap'     => Caps::MANAGE,
			'group'   => 'integrations',
			'order'   => 12,
			'summary' => __( 'Every AWS account read for network exposure, and what each one last managed to read.', 'vulnhub' ),
		);

		return $sections;
	}

	/** @param string $section Section slug being rendered. */
	public static function render_section( $section ): void {
		if ( self::SECTION !== (string) $section || ! current_user_can( Caps::MANAGE ) ) {
			return;
		}

		$notice   = self::$notice;
		$accounts = VulnHub_AWS_Accounts::all();
		$summary  = VulnHub_AWS_Accounts::summary();
		$types    = VulnHub_AWS_Accounts::data_types();
		$edit     = isset( $_GET['edit'] ) ? VulnHub_AWS_Accounts::get( (int) $_GET['edit'] ) : null; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		include VULNHUB_AWS_DIR . 'admin/views/accounts.php';
	}

	public static function handle(): void {
		if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) {
			return;
		}

		if ( ! isset( $_POST['vh_aws_nonce'] ) ) {
			return;
		}

		if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['vh_aws_nonce'] ) ), self::NONCE ) ) {
			self::$notice = array( 'text' => __( 'That form expired. Try again.', 'vulnhub' ), 'tone' => 'bad' );

			return;
		}

		if ( ! current_user_can( Caps::MANAGE ) ) {
			return;
		}

		$action = sanitize_key( wp_unslash( (string) ( $_POST['vh_action'] ?? '' ) ) );

		switch ( $action ) {
			case 'save':
				self::do_save();
				break;
			case 'delete':
				VulnHub_AWS_Accounts::delete( (int) ( $_POST['id'] ?? 0 ) );
				self::$notice = array( 'text' => __( 'Account removed.', 'vulnhub' ), 'tone' => 'ok' );
				break;
			case 'test':
				self::do_test( (int) ( $_POST['id'] ?? 0 ) );
				break;
			case 'bulk_add':
				self::do_bulk_add();
				break;
		}
	}

	private static function do_save(): void {
		$res = VulnHub_AWS_Accounts::save(
			array(
				'id'                => (int) ( $_POST['id'] ?? 0 ), // phpcs:ignore
				'account_id'        => wp_unslash( (string) ( $_POST['account_id'] ?? '' ) ), // phpcs:ignore
				'label'             => wp_unslash( (string) ( $_POST['label'] ?? '' ) ), // phpcs:ignore
				'auth_mode'         => wp_unslash( (string) ( $_POST['auth_mode'] ?? 'role' ) ), // phpcs:ignore
				'access_key_id'     => wp_unslash( (string) ( $_POST['access_key_id'] ?? '' ) ), // phpcs:ignore
				'secret_access_key' => wp_unslash( (string) ( $_POST['secret_access_key'] ?? '' ) ), // phpcs:ignore
				'session_token'     => wp_unslash( (string) ( $_POST['session_token'] ?? '' ) ), // phpcs:ignore
				'role_arn'          => wp_unslash( (string) ( $_POST['role_arn'] ?? '' ) ), // phpcs:ignore
				'external_id'       => wp_unslash( (string) ( $_POST['external_id'] ?? '' ) ), // phpcs:ignore
				'regions'           => wp_unslash( (string) ( $_POST['regions'] ?? '' ) ), // phpcs:ignore
				'enabled'           => isset( $_POST['enabled'] ), // phpcs:ignore
			)
		);

		self::$notice = array(
			'text' => $res['message'],
			'tone' => $res['ok'] ? 'ok' : 'bad',
		);
	}

	/**
	 * Paste a column of account numbers and add them all.
	 *
	 * Fifty-eight accounts entered one form at a time is fifty-eight page
	 * loads, and the numbers almost always already exist somewhere as a list
	 * -- an Organizations export, a spreadsheet column. Anything that is not
	 * twelve digits is reported rather than silently skipped, because a
	 * truncated paste should not look like a successful one.
	 */
	private static function do_bulk_add(): void {
		$raw   = wp_unslash( (string) ( $_POST['bulk'] ?? '' ) ); // phpcs:ignore
		$mode  = sanitize_key( wp_unslash( (string) ( $_POST['bulk_auth_mode'] ?? 'role' ) ) ); // phpcs:ignore
		$regs  = sanitize_text_field( wp_unslash( (string) ( $_POST['bulk_regions'] ?? '' ) ) ); // phpcs:ignore
		$added = 0;
		$dupe  = 0;
		$bad   = array();

		foreach ( preg_split( '/[\r\n]+/', $raw ) ?: array() as $line ) {
			$line = trim( $line );

			if ( '' === $line ) {
				continue;
			}

			// "123456789012" or "123456789012, Production" or "123456789012 Production".
			$parts   = preg_split( '/[,\t]+|\s{2,}/', $line, 2 );
			$account = preg_replace( '/\D+/', '', (string) ( $parts[0] ?? '' ) );
			$label   = trim( (string) ( $parts[1] ?? '' ) );

			if ( 12 !== strlen( (string) $account ) ) {
				$bad[] = mb_substr( $line, 0, 40 );
				continue;
			}

			$res = VulnHub_AWS_Accounts::save(
				array(
					'account_id' => $account,
					'label'      => $label,
					'auth_mode'  => $mode,
					'regions'    => $regs,
					'enabled'    => true,
				)
			);

			if ( $res['ok'] ) {
				++$added;
			} else {
				++$dupe;
			}
		}

		$text = sprintf(
			/* translators: 1: added, 2: already present. */
			__( '%1$d account(s) added, %2$d already on the list.', 'vulnhub' ),
			$added,
			$dupe
		);

		if ( $bad ) {
			$text .= ' ' . sprintf(
				/* translators: %s: the lines that were not account numbers. */
				__( 'Not recognised as account IDs: %s', 'vulnhub' ),
				implode( '; ', array_slice( $bad, 0, 5 ) )
			);
		}

		self::$notice = array(
			'text' => $text,
			'tone' => $bad ? 'warn' : 'ok',
		);
	}

	/** Read one account now, so the result is visible while somebody watches. */
	private static function do_test( int $id ): void {
		$account = VulnHub_AWS_Accounts::get( $id );

		if ( ! $account ) {
			return;
		}

		$connector = vulnhub()->connectors->get( 'aws' );

		if ( ! $connector instanceof VulnHub_AWS_Connector ) {
			return;
		}

		$res = $connector->sync_account( $account );

		self::$notice = array(
			'text' => sprintf( '%s — %s', $account['account_id'], $res['message'] ),
			'tone' => $res['ok'] ? 'ok' : 'bad',
		);
	}

	public static function nonce_field(): void {
		wp_nonce_field( self::NONCE, 'vh_aws_nonce' );
	}
}
