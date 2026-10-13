<?php
/**
 * Sync keys: what one instance hands another so it can copy its data.
 *
 * A sync key is not a person. It can do exactly one thing -- read this
 * instance's estate data through the replica endpoints -- and nothing else:
 * no portal, no write, no other REST route. Only a SHA-256 of it is kept;
 * the plaintext exists once, in the response that created it.
 *
 * @package VulnHub\Replica
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Issue, verify, list and revoke sync keys.
 */
final class VulnHub_Replica_Tokens {

	private const SCHEMA_VERSION = '1';
	private const SCHEMA_OPTION  = 'vulnhub_replica_schema';

	/** Recognisable on sight and greppable in a log. */
	public const PREFIX = 'vhr_';

	public static function table(): string {
		global $wpdb;

		return $wpdb->prefix . 'vulnhub_replica_tokens';
	}

	public static function maybe_install(): void {
		if ( get_option( self::SCHEMA_OPTION ) === self::SCHEMA_VERSION ) {
			return;
		}

		global $wpdb;

		$table   = self::table();
		$collate = $wpdb->get_charset_collate();

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		dbDelta(
			"CREATE TABLE {$table} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				label varchar(120) NOT NULL DEFAULT '',
				token_hash char(64) NOT NULL,
				hint varchar(20) NOT NULL DEFAULT '',
				created_by bigint(20) unsigned NOT NULL DEFAULT 0,
				created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				expires_at datetime DEFAULT NULL,
				revoked_at datetime DEFAULT NULL,
				last_used_at datetime DEFAULT NULL,
				last_used_ip varchar(45) NOT NULL DEFAULT '',
				calls bigint(20) unsigned NOT NULL DEFAULT 0,
				PRIMARY KEY  (id),
				UNIQUE KEY token_hash (token_hash)
			) {$collate};"
		);

		update_option( self::SCHEMA_OPTION, self::SCHEMA_VERSION, false );
	}

	/**
	 * @return array{id:int,token:string}
	 */
	public static function create( string $label, int $user_id, int $days = 0 ): array {
		global $wpdb;

		$token = self::PREFIX . bin2hex( random_bytes( 24 ) );

		$wpdb->insert(
			self::table(),
			array(
				'label'      => '' !== $label ? $label : __( 'Instance copy', 'vulnhub' ),
				'token_hash' => hash( 'sha256', $token ),
				'hint'       => substr( $token, 0, 8 ) . '…' . substr( $token, -4 ),
				'created_by' => $user_id,
				'created_at' => vh_now(),
				'expires_at' => $days > 0 ? gmdate( 'Y-m-d H:i:s', time() + $days * DAY_IN_SECONDS ) : null,
			)
		);

		if ( function_exists( 'vulnhub' ) ) {
			vulnhub()->logger->audit( 'replica.key_created', sprintf( 'Sync key "%s" created', $label ), 'replica', (string) $wpdb->insert_id );
		}

		return array(
			'id'    => (int) $wpdb->insert_id,
			'token' => $token,
		);
	}

	/**
	 * The live key row for a presented secret, or null.
	 *
	 * @return array<string,mixed>|null
	 */
	public static function verify( string $token ): ?array {
		global $wpdb;

		$token = trim( $token );
		if ( ! str_starts_with( $token, self::PREFIX ) || strlen( $token ) < 20 ) {
			return null;
		}

		$row = $wpdb->get_row(
			$wpdb->prepare( 'SELECT * FROM ' . self::table() . ' WHERE token_hash = %s', hash( 'sha256', $token ) ),
			ARRAY_A
		);

		if ( ! $row || ! empty( $row['revoked_at'] ) ) {
			return null;
		}
		if ( ! empty( $row['expires_at'] ) && strtotime( $row['expires_at'] . ' UTC' ) < time() ) {
			return null;
		}

		// Usage, without a write on every chunk of a large download.
		if ( empty( $row['last_used_at'] ) || strtotime( $row['last_used_at'] . ' UTC' ) < time() - 60 ) {
			$wpdb->query(
				$wpdb->prepare(
					'UPDATE ' . self::table() . ' SET last_used_at = %s, last_used_ip = %s, calls = calls + 1 WHERE id = %d',
					vh_now(),
					substr( sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ?? '' ) ), 0, 45 ),
					(int) $row['id']
				)
			);
		}

		return $row;
	}

	public static function revoke( int $id ): bool {
		global $wpdb;

		$done = (bool) $wpdb->update( self::table(), array( 'revoked_at' => vh_now() ), array( 'id' => $id ) );

		if ( $done && function_exists( 'vulnhub' ) ) {
			vulnhub()->logger->audit( 'replica.key_revoked', sprintf( 'Sync key #%d revoked', $id ), 'replica', (string) $id );
		}
		if ( $done && class_exists( 'VulnHub_Replica_Job' ) ) {
			VulnHub_Replica_Job::drop_for_token( $id );
		}

		return $done;
	}

	/**
	 * @return array<int,array<string,mixed>>
	 */
	public static function all(): array {
		global $wpdb;

		return (array) $wpdb->get_results( 'SELECT * FROM ' . self::table() . ' ORDER BY revoked_at IS NULL DESC, id DESC', ARRAY_A );
	}
}

