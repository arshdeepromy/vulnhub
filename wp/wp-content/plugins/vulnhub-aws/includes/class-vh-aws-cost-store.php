<?php
/**
 * Where the AWS cost view keeps what it read, and what people decided.
 *
 * A snapshot is one complete read of the estate -- Cost Explorer, the
 * instances, their CloudWatch usage, the price list -- summarised and stored
 * as one JSON document. The pages only ever read the newest *complete*
 * snapshot, so a refresh that fails half-way never shows a half-read estate
 * as if it were the whole one (see CLAUDE.md: a truncated read is
 * indistinguishable from a shrunken source).
 *
 * Decisions (accept / drop a suggestion) are shared across users and outlive
 * snapshots: they are keyed by the suggestion's stable id, and carry a copy
 * of what was accepted so the plan still reads correctly after the resource
 * it named has gone.
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_AWS_Cost_Store {

	private const DB_VERSION   = '1';
	private const OPT_DB       = 'vulnhub_aws_cost_db';
	private const OPT_DECIDE   = 'vulnhub_aws_cost_decisions';
	private const OPT_PROGRESS = 'vulnhub_aws_cost_progress';
	private const KEEP         = 6;

	public const ACCEPTED  = 'accepted';
	public const DISMISSED = 'dismissed';

	public static function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'vulnhub_aws_cost_snapshots';
	}

	public static function install(): void {
		if ( self::DB_VERSION === get_option( self::OPT_DB ) ) {
			return;
		}

		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$t = self::table();
		$c = $wpdb->get_charset_collate();

		dbDelta(
			"CREATE TABLE {$t} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				started_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				finished_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				status varchar(16) NOT NULL DEFAULT 'ok',
				message varchar(500) NOT NULL DEFAULT '',
				data longtext NULL,
				PRIMARY KEY  (id),
				KEY status (status)
			) {$c};"
		);

		update_option( self::OPT_DB, self::DB_VERSION, false );
	}

	/**
	 * Store a finished read. Only `ok` snapshots are ever shown.
	 *
	 * @param array<string,mixed> $data The summarised read.
	 */
	public static function save( array $data, string $started_at, string $status, string $message ): int {
		global $wpdb;

		$json = wp_json_encode( $data );

		$wpdb->insert(
			self::table(),
			array(
				'started_at'  => $started_at,
				'finished_at' => vh_now(),
				'status'      => $status,
				'message'     => mb_substr( $message, 0, 500 ),
				'data'        => is_string( $json ) ? $json : '{}',
			)
		);

		$id = (int) $wpdb->insert_id;

		// Keep the newest few; the pages only need the latest, the rest are
		// there to compare against when a number moves.
		$t    = self::table();
		$keep = (array) $wpdb->get_col( $wpdb->prepare( "SELECT id FROM {$t} ORDER BY id DESC LIMIT %d", self::KEEP ) ); // phpcs:ignore
		if ( $keep ) {
			$wpdb->query( "DELETE FROM {$t} WHERE id NOT IN (" . implode( ',', array_map( 'intval', $keep ) ) . ')' ); // phpcs:ignore
		}

		return $id;
	}

	/**
	 * The newest complete snapshot, or null when there has never been one.
	 *
	 * @return array{id:int,started_at:string,finished_at:string,data:array<string,mixed>}|null
	 */
	public static function latest(): ?array {
		static $memo = null;
		if ( null !== $memo ) {
			return $memo ?: null;
		}

		global $wpdb;
		$t   = self::table();
		$row = $wpdb->get_row( "SELECT id, started_at, finished_at, data FROM {$t} WHERE status = 'ok' ORDER BY id DESC LIMIT 1", ARRAY_A ); // phpcs:ignore

		if ( ! $row ) {
			$memo = array();
			return null;
		}

		$data = json_decode( (string) $row['data'], true );
		$memo = array(
			'id'          => (int) $row['id'],
			'started_at'  => (string) $row['started_at'],
			'finished_at' => (string) $row['finished_at'],
			'data'        => is_array( $data ) ? $data : array(),
		);

		return $memo;
	}

	/** The last attempt of any status, for "last refresh failed because…". @return array<string,string>|null */
	public static function last_attempt(): ?array {
		global $wpdb;
		$t   = self::table();
		$row = $wpdb->get_row( "SELECT id, started_at, finished_at, status, message FROM {$t} ORDER BY id DESC LIMIT 1", ARRAY_A ); // phpcs:ignore
		return $row ? array_map( 'strval', $row ) : null;
	}

	/* ---------------------------------------------------------------- progress */

	/** @param array<string,mixed> $p */
	public static function set_progress( array $p ): void {
		update_option( self::OPT_PROGRESS, $p + array( 'heartbeat' => vh_now() ), false );
	}

	/** @return array<string,mixed> */
	public static function progress(): array {
		wp_cache_delete( self::OPT_PROGRESS, 'options' );
		return (array) get_option( self::OPT_PROGRESS, array() );
	}

	/* --------------------------------------------------------------- decisions */

	/** @return array<string,array<string,mixed>> Suggestion id => decision. */
	public static function decisions(): array {
		wp_cache_delete( self::OPT_DECIDE, 'options' );
		return (array) get_option( self::OPT_DECIDE, array() );
	}

	/**
	 * Record (or clear, with an empty status) a decision on one suggestion.
	 *
	 * @param array<string,mixed> $rec The suggestion as shown, copied so the
	 *                                 plan can still describe it later.
	 */
	public static function decide( string $rec_id, string $status, string $note, array $rec ): array {
		$all  = self::decisions();
		$user = wp_get_current_user();

		if ( '' === $status ) {
			unset( $all[ $rec_id ] );
		} else {
			$all[ $rec_id ] = array(
				'status'  => $status,
				'note'    => mb_substr( $note, 0, 1000 ),
				'by'      => $user && $user->ID ? (string) $user->display_name : 'system',
				'at'      => vh_now(),
				'title'   => (string) ( $rec['title'] ?? '' ),
				'saving'  => isset( $rec['saving'] ) && is_numeric( $rec['saving'] ) ? (float) $rec['saving'] : null,
				'kind'    => (string) ( $rec['kind'] ?? '' ),
				'account' => (string) ( $rec['account_name'] ?? '' ),
			);
		}

		update_option( self::OPT_DECIDE, $all, false );

		if ( class_exists( '\\VulnHub\\Core\\Logger' ) ) {
			( new \VulnHub\Core\Logger() )->audit(
				'aws_cost_decision',
				'' === $status
					/* translators: %s: suggestion title. */
					? sprintf( __( 'Cleared the decision on cost suggestion: %s', 'vulnhub' ), (string) ( $rec['title'] ?? $rec_id ) )
					/* translators: 1: accepted/dismissed, 2: suggestion title. */
					: sprintf( __( 'Cost suggestion %1$s: %2$s', 'vulnhub' ), $status, (string) ( $rec['title'] ?? $rec_id ) ),
				'aws_cost_suggestion',
				$rec_id,
				array( 'status' => $status, 'note' => $note, 'saving' => $rec['saving'] ?? null )
			);
		}

		return $all;
	}
}

