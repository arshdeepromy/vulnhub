<?php
/**
 * Connector tokens.
 *
 * A token is a credential belonging to one person. It carries no permissions
 * of its own: every request it authenticates runs as that person, through the
 * same `current_user_can()` checks the portal itself uses. A viewer's token
 * can read; an administrator's token can administer. Change somebody's role
 * and their agent's reach changes with it, immediately and without reissuing
 * anything -- which is the property that makes this worth having at all.
 *
 * Only a SHA-256 of the secret is stored. The plaintext exists once, in the
 * response to the request that created it, and never again -- which is why the
 * screen says "copy it now" rather than offering to show it later.
 *
 * @package VulnHub\MCP
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Issue, verify, list and revoke connector tokens.
 */
final class VulnHub_MCP_Tokens {

	/** Bumped when the table shape changes. */
	private const SCHEMA_VERSION = '1';

	/** Option holding the installed schema version. */
	private const SCHEMA_OPTION = 'vulnhub_mcp_schema';

	/**
	 * Human-visible prefix, so a leaked one is recognisable on sight and
	 * greppable in a log.
	 */
	private const PREFIX = 'vhm_';

	public static function table(): string {
		global $wpdb;

		return $wpdb->prefix . 'vulnhub_mcp_tokens';
	}

	/**
	 * Create the table the first time, and after a schema bump.
	 */
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
				user_id bigint(20) unsigned NOT NULL,
				label varchar(120) NOT NULL DEFAULT '',
				client varchar(40) NOT NULL DEFAULT 'generic',
				token_hash char(64) NOT NULL,
				hint varchar(20) NOT NULL DEFAULT '',
				created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				last_used_at datetime DEFAULT NULL,
				last_used_ip varchar(45) NOT NULL DEFAULT '',
				expires_at datetime DEFAULT NULL,
				revoked_at datetime DEFAULT NULL,
				calls bigint(20) unsigned NOT NULL DEFAULT 0,
				PRIMARY KEY  (id),
				UNIQUE KEY token_hash (token_hash),
				KEY user_id (user_id)
			) {$collate};"
		);

		update_option( self::SCHEMA_OPTION, self::SCHEMA_VERSION, false );
	}

	/* -----------------------------------------------------------------
	 * Issuing
	 * --------------------------------------------------------------- */

	/**
	 * Mint a token for a user.
	 *
	 * @param int    $user_id Owner.
	 * @param string $label   What it is for, in the owner's words.
	 * @param string $client  Client hint: 'claude' or 'generic'.
	 * @param int    $days    Days until it expires; 0 for no expiry.
	 * @return array{id:int,token:string,hint:string}
	 */
	public static function create( int $user_id, string $label, string $client = 'generic', int $days = 0 ): array {
		global $wpdb;

		self::maybe_install();

		$secret = self::PREFIX . strtolower( bin2hex( random_bytes( 24 ) ) );

		$wpdb->insert(
			self::table(),
			array(
				'user_id'    => $user_id,
				'label'      => mb_substr( $label, 0, 120 ),
				'client'     => 'claude' === $client ? 'claude' : 'generic',
				'token_hash' => hash( 'sha256', $secret ),
				'hint'       => substr( $secret, 0, 12 ),
				'created_at' => current_time( 'mysql', true ),
				'expires_at' => $days > 0 ? gmdate( 'Y-m-d H:i:s', time() + $days * DAY_IN_SECONDS ) : null,
			)
		);

		return array(
			'id'    => (int) $wpdb->insert_id,
			'token' => $secret,
			'hint'  => substr( $secret, 0, 12 ),
		);
	}

	/**
	 * Resolve a presented secret to its owner.
	 *
	 * Unknown, revoked and expired all return 0 and look identical from
	 * outside, which is the point.
	 *
	 * @param string $secret Presented token.
	 * @return int User id, or 0.
	 */
	public static function user_for( string $secret ): int {
		global $wpdb;

		$secret = trim( $secret );

		if ( '' === $secret || ! str_starts_with( $secret, self::PREFIX ) ) {
			return 0;
		}

		$table = self::table();
		$row   = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT id, user_id, expires_at, revoked_at FROM {$table} WHERE token_hash = %s", // phpcs:ignore WordPress.DB.PreparedSQL
				hash( 'sha256', $secret )
			),
			ARRAY_A
		);

		if ( ! $row || ! empty( $row['revoked_at'] ) ) {
			return 0;
		}
		if ( ! empty( $row['expires_at'] ) && strtotime( (string) $row['expires_at'] ) < time() ) {
			return 0;
		}

		$user = get_userdata( (int) $row['user_id'] );

		// A deleted or suspended account takes its tokens with it: suspension
		// empties the role, so the capability check below stops being true.
		if ( ! $user || ! user_can( $user, \VulnHub\Core\Caps::VIEW ) ) {
			return 0;
		}

		self::touch( (int) $row['id'] );

		return (int) $row['user_id'];
	}

	/**
	 * Record that a token was used -- the only way to answer "is this still
	 * in use, or can I revoke it?"
	 *
	 * @param int $id Token id.
	 */
	private static function touch( int $id ): void {
		global $wpdb;

		$table = self::table();

		$wpdb->query(
			$wpdb->prepare(
				"UPDATE {$table} SET last_used_at = %s, last_used_ip = %s, calls = calls + 1 WHERE id = %d", // phpcs:ignore WordPress.DB.PreparedSQL
				current_time( 'mysql', true ),
				self::client_ip(),
				$id
			)
		);
	}

	private static function client_ip(): string {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$ip = filter_var( $ip, FILTER_VALIDATE_IP );

		return is_string( $ip ) ? $ip : '';
	}

	/* -----------------------------------------------------------------
	 * Listing and revoking
	 * --------------------------------------------------------------- */

	/**
	 * @param int $user_id Owner.
	 * @return array<int,array<string,mixed>>
	 */
	public static function for_user( int $user_id ): array {
		global $wpdb;

		self::maybe_install();

		$table = self::table();

		return (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE user_id = %d ORDER BY revoked_at IS NOT NULL, id DESC", // phpcs:ignore WordPress.DB.PreparedSQL
				$user_id
			),
			ARRAY_A
		);
	}

	/**
	 * Every token on the platform, for an administrator's overview.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function all(): array {
		global $wpdb;

		self::maybe_install();

		$table = self::table();

		return (array) $wpdb->get_results(
			"SELECT * FROM {$table} ORDER BY revoked_at IS NOT NULL, id DESC", // phpcs:ignore WordPress.DB.PreparedSQL
			ARRAY_A
		);
	}

	/**
	 * @param int $id Token id.
	 * @return array<string,mixed>|null
	 */
	public static function get( int $id ): ?array {
		global $wpdb;

		$table = self::table();
		$row   = $wpdb->get_row(
			$wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d", $id ), // phpcs:ignore WordPress.DB.PreparedSQL
			ARRAY_A
		);

		return $row ?: null;
	}

	/**
	 * Revoke rather than delete: the row is the evidence the thing existed,
	 * and an audit six months from now will want it.
	 *
	 * @param int $id Token id.
	 */
	public static function revoke( int $id ): void {
		global $wpdb;

		$wpdb->update(
			self::table(),
			array( 'revoked_at' => current_time( 'mysql', true ) ),
			array( 'id' => $id )
		);
	}

	/**
	 * @param array<string,mixed> $row Token row.
	 */
	public static function is_live( array $row ): bool {
		if ( ! empty( $row['revoked_at'] ) ) {
			return false;
		}
		if ( ! empty( $row['expires_at'] ) && strtotime( (string) $row['expires_at'] ) < time() ) {
			return false;
		}

		return true;
	}
}

