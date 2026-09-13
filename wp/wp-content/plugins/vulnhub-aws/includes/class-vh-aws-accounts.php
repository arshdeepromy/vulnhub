<?php
/**
 * The AWS accounts this connector reads, and what each last managed to read.
 *
 * One set of credentials in a settings form works for one account. At fifty-
 * eight it stops working for two reasons at once: short-term SSO credentials
 * expire within hours, so that is fifty-eight pairs to re-paste every morning,
 * and a single form has nowhere to say which account failed and why.
 *
 * So accounts are rows, and each row records what its last sync actually
 * managed to read -- instances, security groups, routing, load balancers,
 * Inspector -- rather than a single pass/fail. On a large estate the
 * interesting failure is never "it broke", it is "forty-one accounts are fine
 * and these three cannot see their load balancers", and that is invisible
 * unless it is recorded per account.
 *
 * Credentials go through the core settings encryption rather than into this
 * table. Secrets live in one place with one implementation, and a row that
 * only holds an access key id can be read and exported without thinking about
 * what is in it.
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Stored AWS accounts.
 */
final class VulnHub_AWS_Accounts {

	public static function table(): string {
		global $wpdb;

		return $wpdb->prefix . 'vulnhub_aws_accounts';
	}

	public static function install(): void {
		global $wpdb;

		$t       = self::table();
		$charset = $wpdb->get_charset_collate();

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		dbDelta(
			"CREATE TABLE {$t} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				account_id varchar(24) NOT NULL DEFAULT '',
				label varchar(191) NOT NULL DEFAULT '',
				auth_mode varchar(12) NOT NULL DEFAULT 'role',
				access_key_id varchar(128) NOT NULL DEFAULT '',
				role_arn varchar(255) NOT NULL DEFAULT '',
				external_id varchar(128) NOT NULL DEFAULT '',
				regions varchar(255) NOT NULL DEFAULT '',
				enabled tinyint(1) NOT NULL DEFAULT 1,
				last_sync_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				last_status varchar(16) NOT NULL DEFAULT 'never',
				last_message varchar(500) NOT NULL DEFAULT '',
				stats_json longtext NULL,
				created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				PRIMARY KEY  (id),
				UNIQUE KEY account (account_id),
				KEY enabled (enabled)
			) {$charset};"
		);
	}

	/**
	 * @return array<int,array<string,mixed>>
	 */
	public static function all( bool $enabled_only = false ): array {
		global $wpdb;

		$t     = self::table();
		$where = $enabled_only ? 'WHERE enabled = 1' : '';

		$rows = (array) $wpdb->get_results( "SELECT * FROM {$t} {$where} ORDER BY label, account_id", ARRAY_A ); // phpcs:ignore

		return array_map( array( __CLASS__, 'shape' ), $rows );
	}

	/** @return array<string,mixed>|null */
	public static function get( int $id ): ?array {
		global $wpdb;

		$row = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . self::table() . ' WHERE id = %d', $id ), ARRAY_A ); // phpcs:ignore

		return $row ? self::shape( (array) $row ) : null;
	}

	/**
	 * @param array<string,mixed> $row Raw row.
	 * @return array<string,mixed>
	 */
	private static function shape( array $row ): array {
		$row['id']      = (int) $row['id'];
		$row['enabled'] = (bool) (int) $row['enabled'];
		$row['stats']   = json_decode( (string) ( $row['stats_json'] ?? '' ), true ) ?: array();

		unset( $row['stats_json'] );

		return $row;
	}

	/**
	 * Add or update one account.
	 *
	 * @param array<string,mixed> $data Field values.
	 * @return array{ok:bool,id:int,message:string}
	 */
	public static function save( array $data ): array {
		global $wpdb;

		$account = preg_replace( '/\D+/', '', (string) ( $data['account_id'] ?? '' ) );

		// AWS account numbers are exactly twelve digits. Catching it here
		// rather than at sync time means the mistake is corrected while the
		// person still has the console open.
		if ( 12 !== strlen( (string) $account ) ) {
			return array(
				'ok'      => false,
				'id'      => 0,
				'message' => __( 'An AWS account ID is exactly 12 digits.', 'vulnhub' ),
			);
		}

		$id   = (int) ( $data['id'] ?? 0 );
		$mode = in_array( (string) ( $data['auth_mode'] ?? 'role' ), array( 'role', 'keys' ), true )
			? (string) $data['auth_mode']
			: 'role';

		$fields = array(
			'account_id'    => $account,
			'label'         => sanitize_text_field( (string) ( $data['label'] ?? '' ) ),
			'auth_mode'     => $mode,
			'access_key_id' => sanitize_text_field( (string) ( $data['access_key_id'] ?? '' ) ),
			'role_arn'      => sanitize_text_field( (string) ( $data['role_arn'] ?? '' ) ),
			'external_id'   => sanitize_text_field( (string) ( $data['external_id'] ?? '' ) ),
			'regions'       => sanitize_text_field( (string) ( $data['regions'] ?? '' ) ),
			'enabled'       => empty( $data['enabled'] ) ? 0 : 1,
		);

		if ( $id > 0 ) {
			$wpdb->update( self::table(), $fields, array( 'id' => $id ) ); // phpcs:ignore
		} else {
			$existing = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT id FROM ' . self::table() . ' WHERE account_id = %s', $account ) ); // phpcs:ignore

			if ( $existing > 0 ) {
				return array(
					'ok'      => false,
					'id'      => $existing,
					'message' => sprintf(
						/* translators: %s: AWS account id. */
						__( 'Account %s is already on the list.', 'vulnhub' ),
						$account
					),
				);
			}

			$fields['created_at'] = vh_now();

			$wpdb->insert( self::table(), $fields ); // phpcs:ignore
			$id = (int) $wpdb->insert_id;
		}

		// Secrets never touch this table.
		if ( isset( $data['secret_access_key'] ) && '' !== trim( (string) $data['secret_access_key'] ) ) {
			self::set_secret( $id, 'secret', (string) $data['secret_access_key'] );
		}

		if ( isset( $data['session_token'] ) ) {
			$tok = trim( (string) $data['session_token'] );
			self::set_secret( $id, 'token', '' !== $tok ? $tok : null );
		}

		return array(
			'ok'      => true,
			'id'      => $id,
			'message' => __( 'Saved.', 'vulnhub' ),
		);
	}

	public static function delete( int $id ): void {
		global $wpdb;

		self::set_secret( $id, 'secret', null );
		self::set_secret( $id, 'token', null );

		$wpdb->delete( self::table(), array( 'id' => $id ) ); // phpcs:ignore
	}

	/** Per-account secrets, stored with everything else that is encrypted. */
	public static function set_secret( int $id, string $which, ?string $value ): void {
		vulnhub()->settings->set_secret( 'aws', sprintf( 'acct_%d_%s', $id, $which ), $value );
	}

	public static function secret( int $id, string $which ): string {
		return (string) vulnhub()->settings->secret( 'aws', sprintf( 'acct_%d_%s', $id, $which ) );
	}

	public static function has_secret( int $id, string $which ): bool {
		return vulnhub()->settings->has_secret( 'aws', sprintf( 'acct_%d_%s', $id, $which ) );
	}

	/**
	 * Record what a sync managed to read for one account.
	 *
	 * @param array<string,mixed> $stats What each API returned, or refused.
	 */
	public static function record( int $id, string $status, string $message, array $stats ): void {
		global $wpdb;

		$wpdb->update( // phpcs:ignore
			self::table(),
			array(
				'last_sync_at' => vh_now(),
				'last_status'  => $status,
				'last_message' => mb_substr( $message, 0, 500 ),
				'stats_json'   => (string) wp_json_encode( $stats ),
			),
			array( 'id' => $id )
		);
	}

	/**
	 * The data types a sync reports on, and how to label them.
	 *
	 * Kept in one place because the account list, the per-account detail and
	 * the sync log all name the same things, and three copies of this list
	 * would disagree within a release.
	 *
	 * @return array<string,string>
	 */
	public static function data_types(): array {
		return array(
			'instances'       => __( 'EC2 instances', 'vulnhub' ),
			'security_groups' => __( 'Security groups', 'vulnhub' ),
			'route_tables'    => __( 'Route tables', 'vulnhub' ),
			'subnets'         => __( 'Subnets', 'vulnhub' ),
			'load_balancers'  => __( 'Load balancers', 'vulnhub' ),
			'inspector'       => __( 'Inspector reachability', 'vulnhub' ),
			'reachable'       => __( 'Reachable instances', 'vulnhub' ),
			'matched'         => __( 'Matched to our assets', 'vulnhub' ),
		);
	}

	/** How many accounts are in each state, for the screen header. */
	public static function summary(): array {
		global $wpdb;

		$t = self::table();

		return array(
			'total'    => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$t}" ), // phpcs:ignore
			'enabled'  => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$t} WHERE enabled = 1" ), // phpcs:ignore
			'ok'       => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$t} WHERE last_status = 'ok'" ), // phpcs:ignore
			'failed'   => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$t} WHERE last_status = 'failed'" ), // phpcs:ignore
			'never'    => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$t} WHERE last_status = 'never'" ), // phpcs:ignore
		);
	}
}
