<?php
/**
 * The import job record: schema, lifecycle and the atomic run lock.
 *
 * A job is the only durable state an import has. Everything the runner needs
 * to pick a half-finished 300 MB file back up — the byte offset, the column
 * map, the counters and the storage key of the temporary file — lives in one
 * row, so a pass can end anywhere (a cron tick expiring, PHP being killed, the
 * operator closing the tab) and the next pass simply continues.
 *
 * This plugin owns its own table. Core's schema is never touched.
 *
 * @package VulnHub\Import
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Create, read and update import jobs.
 */
final class VulnHub_Import_Jobs {

	/** Option holding the installed schema version. */
	public const VERSION_OPTION = 'vulnhub_import_db_version';

	/** Bumped whenever the CREATE TABLE below changes. */
	public const DB_VERSION = '3';

	/** Job is uploaded and mapped but has not been started. */
	public const PENDING = 'pending';

	/** Job is being processed, pass by pass. */
	public const RUNNING = 'running';

	/** Job stopped itself and is waiting to be resumed. */
	public const PAUSED = 'paused';

	/** Job read every row. */
	public const DONE = 'done';

	/** Job hit an unrecoverable error. */
	public const FAILED = 'failed';

	/** Job was cancelled by an operator. */
	public const CANCELLED = 'cancelled';

	/** How many failing rows are remembered in full. */
	public const MAX_FAILURES = 100;

	/**
	 * Fully qualified jobs table name.
	 *
	 * @return string
	 */
	public static function table(): string {
		global $wpdb;

		return $wpdb->prefix . 'vulnhub_import_jobs';
	}

	/**
	 * Create or migrate the jobs table with dbDelta.
	 *
	 * dbDelta is fussy: two spaces after PRIMARY KEY, lowercase column types,
	 * KEY rather than INDEX, and no backticks around index names.
	 *
	 * @return void
	 */
	public static function install(): void {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$table   = self::table();
		$charset = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			type varchar(32) NOT NULL DEFAULT 'tenable',
			shape varchar(32) NOT NULL DEFAULT '',
			filename varchar(191) NOT NULL DEFAULT '',
			storage_key varchar(64) NOT NULL DEFAULT '',
			size_bytes bigint(20) unsigned NOT NULL DEFAULT 0,
			content_hash char(64) NOT NULL DEFAULT '',
			status varchar(16) NOT NULL DEFAULT 'pending',
			byte_offset bigint(20) unsigned NOT NULL DEFAULT 0,
			rows_total_estimate bigint(20) unsigned NOT NULL DEFAULT 0,
			rows_done bigint(20) unsigned NOT NULL DEFAULT 0,
			counters longtext NULL,
			column_map longtext NULL,
			error text NULL,
			locked_until datetime NULL,
			created_by bigint(20) unsigned NOT NULL DEFAULT 0,
			created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			updated_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			started_at datetime NULL,
			finished_at datetime NULL,
			PRIMARY KEY  (id),
			KEY status (status),
			KEY content_hash (content_hash),
			KEY created_at (created_at)
		) {$charset};";

		dbDelta( $sql );

		update_option( self::VERSION_OPTION, self::DB_VERSION, false );
	}

	/**
	 * Install the table if this site has never seen it, or the schema moved on.
	 *
	 * Activation already does this; this covers a plugin dropped in by hand and
	 * a schema bump shipped in an update.
	 *
	 * @return void
	 */
	public static function maybe_install(): void {
		if ( (string) get_option( self::VERSION_OPTION, '0' ) === self::DB_VERSION ) {
			return;
		}

		self::install();
	}

	/**
	 * Human labels for every status.
	 *
	 * @return array<string,string>
	 */
	public static function statuses(): array {
		return array(
			self::PENDING   => __( 'Waiting to start', 'vulnhub' ),
			self::RUNNING   => __( 'Running', 'vulnhub' ),
			self::PAUSED    => __( 'Paused', 'vulnhub' ),
			self::DONE      => __( 'Finished', 'vulnhub' ),
			self::FAILED    => __( 'Failed', 'vulnhub' ),
			self::CANCELLED => __( 'Cancelled', 'vulnhub' ),
		);
	}

	/**
	 * The importers this plugin offers.
	 *
	 * @return array<string,string>
	 */
	public static function types(): array {
		return array(
			'cmdb'    => __( 'CMDB asset export', 'vulnhub' ),
			'tenable' => __( 'Tenable export', 'vulnhub' ),
		);
	}

	/**
	 * A zeroed counter set. Every job carries exactly these keys so the UI
	 * never has to guard against a missing one.
	 *
	 * @return array<string,mixed>
	 */
	public static function blank_counters(): array {
		return array(
			'rows_read'         => 0,
			'assets_created'    => 0,
			'assets_updated'    => 0,
			'vulns_created'     => 0,
			'vulns_updated'     => 0,
			'findings_created'  => 0,
			'findings_updated'  => 0,
			'findings_reopened' => 0,
			'assets_unmatched'  => 0,
			'assets_unissued'   => 0,
			'cloud_enriched'    => 0,
			'patch_groups_set'  => 0,
			'people_created'    => 0,
			'people_seen'       => 0,
			'owners_set'        => 0,
			'no_owner'          => 0,
			'defender_onboarded'   => 0,
			'defender_onboardable' => 0,
			'defender_unsupported' => 0,
			'defender_name_clash'  => 0,
			'rows_rejected'        => 0,
			'rows_skipped'      => 0,
			'rows_failed'       => 0,
			'passes'            => 0,
			'seconds'           => 0.0,
			'peak_memory'       => 0,
			'failures'          => array(),
		);
	}

	/**
	 * Create a job row.
	 *
	 * @param array<string,mixed> $data Column values.
	 * @return int New job id, or 0.
	 */
	public static function create( array $data ): int {
		global $wpdb;

		$now = current_time( 'mysql', true );

		$row = array(
			'type'                => (string) ( $data['type'] ?? 'tenable' ),
			'shape'               => (string) ( $data['shape'] ?? '' ),
			'filename'            => substr( (string) ( $data['filename'] ?? '' ), 0, 191 ),
			'storage_key'         => (string) ( $data['storage_key'] ?? '' ),
			'size_bytes'          => (int) ( $data['size_bytes'] ?? 0 ),
			'content_hash'        => (string) ( $data['content_hash'] ?? '' ),
			'status'              => (string) ( $data['status'] ?? self::PENDING ),
			'byte_offset'         => (int) ( $data['byte_offset'] ?? 0 ),
			'rows_total_estimate' => (int) ( $data['rows_total_estimate'] ?? 0 ),
			'rows_done'           => 0,
			'counters'            => (string) wp_json_encode( self::blank_counters() ),
			'column_map'          => (string) wp_json_encode( (array) ( $data['column_map'] ?? array() ) ),
			'error'               => '',
			'created_by'          => get_current_user_id(),
			'created_at'          => $now,
			'updated_at'          => $now,
		);

		$wpdb->insert( self::table(), $row ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

		return (int) $wpdb->insert_id;
	}

	/**
	 * Update a job row.
	 *
	 * @param int                 $id   Job id.
	 * @param array<string,mixed> $data Column values.
	 * @return void
	 */
	public static function update( int $id, array $data ): void {
		global $wpdb;

		if ( ! $id ) {
			return;
		}

		$data['updated_at'] = current_time( 'mysql', true );

		$wpdb->update( self::table(), $data, array( 'id' => $id ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}

	/**
	 * Fetch one job.
	 *
	 * @param int $id Job id.
	 * @return array<string,mixed>|null
	 */
	public static function get( int $id ): ?array {
		global $wpdb;

		if ( ! $id ) {
			return null;
		}

		$table = self::table();
		$row   = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d", $id ), ARRAY_A ); // phpcs:ignore WordPress.DB

		return $row ? self::hydrate( $row ) : null;
	}

	/**
	 * Recent jobs, newest first.
	 *
	 * @param int $limit How many rows.
	 * @return array<int,array<string,mixed>>
	 */
	public static function recent( int $limit = 25 ): array {
		global $wpdb;

		$limit = max( 1, min( 200, $limit ) );
		$table = self::table();

		$rows = (array) $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} ORDER BY id DESC LIMIT %d", $limit ), ARRAY_A ); // phpcs:ignore WordPress.DB

		return array_map( array( __CLASS__, 'hydrate' ), $rows );
	}

	/**
	 * Jobs that should still be making progress.
	 *
	 * @param int $limit How many rows.
	 * @return array<int,array<string,mixed>>
	 */
	public static function resumable( int $limit = 10 ): array {
		global $wpdb;

		$limit = max( 1, min( 50, $limit ) );
		$table = self::table();

		$rows = (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE status = %s ORDER BY id ASC LIMIT %d", // phpcs:ignore WordPress.DB
				self::RUNNING,
				$limit
			),
			ARRAY_A
		);

		return array_map( array( __CLASS__, 'hydrate' ), $rows );
	}

	/**
	 * Earlier finished jobs that carried the same file content.
	 *
	 * @param string $hash    sha256 of the file.
	 * @param int    $exclude Job id to leave out.
	 * @return array<string,mixed>|null
	 */
	public static function previous_with_hash( string $hash, int $exclude = 0 ): ?array {
		global $wpdb;

		if ( 64 !== strlen( $hash ) ) {
			return null;
		}

		$table = self::table();

		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE content_hash = %s AND id <> %d AND status IN ( %s, %s ) ORDER BY id DESC LIMIT 1", // phpcs:ignore WordPress.DB
				$hash,
				$exclude,
				self::DONE,
				self::RUNNING
			),
			ARRAY_A
		);

		return $row ? self::hydrate( $row ) : null;
	}

	/**
	 * Decode the JSON columns of a raw row.
	 *
	 * @param array<string,mixed> $row Raw database row.
	 * @return array<string,mixed>
	 */
	public static function hydrate( array $row ): array {
		$counters = json_decode( (string) ( $row['counters'] ?? '' ), true );
		$map      = json_decode( (string) ( $row['column_map'] ?? '' ), true );

		$row['counters_arr']   = is_array( $counters ) ? array_merge( self::blank_counters(), $counters ) : self::blank_counters();
		$row['column_map_arr'] = is_array( $map ) ? $map : array();

		return $row;
	}

	/**
	 * Persist a counter set.
	 *
	 * @param int                 $id       Job id.
	 * @param array<string,mixed> $counters Counters.
	 * @return void
	 */
	public static function save_counters( int $id, array $counters ): void {
		self::update( $id, array( 'counters' => (string) wp_json_encode( $counters ) ) );
	}

	/**
	 * Record a failing row, keeping only the first MAX_FAILURES in detail.
	 *
	 * @param array<string,mixed> $counters Counters, by reference.
	 * @param int                 $row      Row number in the file.
	 * @param string              $reason   Why it failed.
	 * @return void
	 */
	public static function note_failure( array &$counters, int $row, string $reason ): void {
		if ( ! isset( $counters['rows_failed'] ) ) {
			$counters['rows_failed'] = 0;
		}

		if ( ! isset( $counters['failures'] ) || ! is_array( $counters['failures'] ) ) {
			$counters['failures'] = array();
		}

		++$counters['rows_failed'];

		if ( count( (array) $counters['failures'] ) >= self::MAX_FAILURES ) {
			return;
		}

		$counters['failures'][] = array(
			'row'    => $row,
			'reason' => mb_substr( $reason, 0, 200 ),
		);
	}

	/**
	 * Take the run lock for a job, atomically.
	 *
	 * A single UPDATE … WHERE locked_until IS NULL OR locked_until < UTC_TIMESTAMP()
	 * is the whole mechanism: MySQL decides the winner, so a cron tick and an
	 * operator's browser poll can never process the same rows twice.
	 *
	 * @param int $id      Job id.
	 * @param int $seconds How long the lease lasts.
	 * @return bool True when this process now holds the lock.
	 */
	public static function claim( int $id, int $seconds = 120 ): bool {
		global $wpdb;

		$table = self::table();
		$until = gmdate( 'Y-m-d H:i:s', time() + max( 10, $seconds ) );

		$claimed = $wpdb->query( // phpcs:ignore WordPress.DB
			$wpdb->prepare(
				"UPDATE {$table} SET locked_until = %s WHERE id = %d AND ( locked_until IS NULL OR locked_until < UTC_TIMESTAMP() )", // phpcs:ignore WordPress.DB
				$until,
				$id
			)
		);

		return (int) $claimed > 0;
	}

	/**
	 * Extend the lease held by this process.
	 *
	 * @param int $id      Job id.
	 * @param int $seconds Lease length.
	 * @return void
	 */
	public static function touch( int $id, int $seconds = 120 ): void {
		self::update( $id, array( 'locked_until' => gmdate( 'Y-m-d H:i:s', time() + max( 10, $seconds ) ) ) );
	}

	/**
	 * Release the run lock.
	 *
	 * @param int $id Job id.
	 * @return void
	 */
	public static function release( int $id ): void {
		self::update( $id, array( 'locked_until' => null ) );
	}
}

