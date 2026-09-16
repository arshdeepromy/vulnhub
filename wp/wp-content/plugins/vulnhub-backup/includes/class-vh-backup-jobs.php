<?php
/**
 * The backup job record: schema, lifecycle and the atomic run lock.
 *
 * A job is the only durable state a backup has. Everything the runner needs
 * to pick a half-finished export back up — which table and row offset the DB
 * export is at, which relative path the files archive got to, the S3
 * multipart upload id and which parts are done — lives in one row, so a pass
 * can end anywhere and the next pass simply continues.
 *
 * This plugin owns its own table, exactly as vulnhub-import owns
 * wp_vulnhub_import_jobs. Core's schema is never touched.
 *
 * @package VulnHub\Backup
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Create, read and update backup jobs.
 */
final class VulnHub_Backup_Jobs {

	/** Option holding the installed schema version. */
	public const VERSION_OPTION = 'vulnhub_backup_db_version';

	/** Bumped whenever the CREATE TABLE below changes. */
	public const DB_VERSION = '1';

	/** Job phases, in order. */
	public const PHASE_DB_EXPORT    = 'db_export';
	public const PHASE_FILES_ARCHIVE = 'files_archive';
	/*
	 * Packing the three members into the single .tar.gz an operator
	 * downloads. Declared here with its siblings; the runner owns the
	 * behaviour and refers to this constant.
	 */
	public const PHASE_PACKAGE      = 'package';
	public const PHASE_UPLOAD       = 'upload';
	public const PHASE_RETENTION    = 'retention';
	public const PHASE_DONE         = 'done';

	/** Job is prepared but has not started a pass. */
	public const PENDING = 'pending';

	/** Job is being processed, pass by pass. */
	public const RUNNING = 'running';

	/** Job finished every phase. */
	public const DONE = 'done';

	/** Job hit an unrecoverable error. */
	public const FAILED = 'failed';

	/** Job was cancelled by an operator. */
	public const CANCELLED = 'cancelled';

	/**
	 * Fully qualified jobs table name.
	 *
	 * @return string
	 */
	public static function table(): string {
		global $wpdb;

		return $wpdb->prefix . 'vulnhub_backup_jobs';
	}

	/**
	 * Create or migrate the jobs table with dbDelta.
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
			mode varchar(16) NOT NULL DEFAULT 'manual',
			phase varchar(24) NOT NULL DEFAULT 'db_export',
			status varchar(16) NOT NULL DEFAULT 'pending',
			folder varchar(64) NOT NULL DEFAULT '',
			storage_key varchar(64) NOT NULL DEFAULT '',
			size_bytes bigint(20) unsigned NOT NULL DEFAULT 0,
			content_hash char(64) NOT NULL DEFAULT '',
			table_cursor longtext NULL,
			files_cursor longtext NULL,
			counters longtext NULL,
			error text NULL,
			locked_until datetime NULL,
			created_by bigint(20) unsigned NOT NULL DEFAULT 0,
			created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			updated_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
			started_at datetime NULL,
			finished_at datetime NULL,
			PRIMARY KEY  (id),
			KEY status (status),
			KEY created_at (created_at)
		) {$charset};";

		dbDelta( $sql );

		update_option( self::VERSION_OPTION, self::DB_VERSION, false );
	}

	/**
	 * Install the table if this site has never seen it, or the schema moved on.
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
			self::DONE      => __( 'Finished', 'vulnhub' ),
			self::FAILED    => __( 'Failed', 'vulnhub' ),
			self::CANCELLED => __( 'Cancelled', 'vulnhub' ),
		);
	}

	/**
	 * Human labels for every phase.
	 *
	 * The raw slugs were being printed at the operator ("db_export",
	 * "files_archive"), which reads like debug output and says nothing about
	 * how much is left. These are also the labels the progress panel steps
	 * through, so they are written as what is happening now, not as a noun.
	 *
	 * @return array<string,string>
	 */
	public static function phases(): array {
		return array(
			self::PHASE_DB_EXPORT      => __( 'Exporting the database', 'vulnhub' ),
			self::PHASE_FILES_ARCHIVE  => __( 'Archiving plugin, theme and upload files', 'vulnhub' ),
			self::PHASE_PACKAGE        => __( 'Packing everything into one file', 'vulnhub' ),
			self::PHASE_UPLOAD         => __( 'Uploading to S3', 'vulnhub' ),
			self::PHASE_RETENTION      => __( 'Tidying up older backups', 'vulnhub' ),
			self::PHASE_DONE           => __( 'Finished', 'vulnhub' ),
		);
	}

	/**
	 * The phases a job walks through, in order, for a progress readout.
	 *
	 * @return array<int,string>
	 */
	public static function phase_order(): array {
		return array(
			self::PHASE_DB_EXPORT,
			self::PHASE_FILES_ARCHIVE,
			self::PHASE_PACKAGE,
			self::PHASE_UPLOAD,
			self::PHASE_RETENTION,
		);
	}

	/**
	 * Roughly how far through a job is, 0-100.
	 *
	 * Deliberately coarse: only the database phase knows its own denominator
	 * (tables), and the file phase does not know how many files it will find
	 * until it has found them. So each phase is worth an equal slice, and the
	 * database phase refines its own slice by tables done. A bar that lies
	 * precisely is worse than one that is honestly approximate.
	 *
	 * @param array<string,mixed> $job Hydrated job row.
	 */
	public static function progress( array $job ): int {
		$status = (string) ( $job['status'] ?? '' );

		if ( in_array( $status, array( self::DONE, self::FAILED, self::CANCELLED ), true ) ) {
			return 100;
		}

		$order = self::phase_order();
		$index = array_search( (string) ( $job['phase'] ?? '' ), $order, true );

		if ( false === $index ) {
			return 0;
		}

		$slice    = 100 / max( 1, count( $order ) );
		$counters = (array) ( $job['counters_arr'] ?? array() );
		$within   = 0.0;

		if ( self::PHASE_DB_EXPORT === (string) $job['phase'] && (int) ( $counters['tables_total'] ?? 0 ) > 0 ) {
			$within = min( 1.0, (int) $counters['tables_done'] / (int) $counters['tables_total'] );
		}

		return (int) min( 99, round( ( $index + $within ) * $slice ) );
	}

	/**
	 * A zeroed counter set. Every job carries exactly these keys so the UI
	 * never has to guard against a missing one.
	 *
	 * @return array<string,mixed>
	 */
	public static function blank_counters(): array {
		return array(
			'tables_total'    => 0,
			'tables_done'     => 0,
			'rows_exported'   => 0,
			'files_archived'  => 0,
			'db_bytes'        => 0,
			'zip_bytes'       => 0,
			'upload_id'       => '',
			'parts_done'      => array(),
			'objects_deleted' => 0,
			'sets_deleted'    => 0,
			'seconds'         => 0.0,
			'passes'          => 0,
			'peak_memory'     => 0,
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
			'mode'         => (string) ( $data['mode'] ?? 'manual' ),
			'phase'        => (string) ( $data['phase'] ?? self::PHASE_DB_EXPORT ),
			'status'       => (string) ( $data['status'] ?? self::PENDING ),
			'folder'       => (string) ( $data['folder'] ?? '' ),
			'storage_key'  => (string) ( $data['storage_key'] ?? '' ),
			'size_bytes'   => (int) ( $data['size_bytes'] ?? 0 ),
			'content_hash' => (string) ( $data['content_hash'] ?? '' ),
			'table_cursor' => (string) wp_json_encode( (array) ( $data['table_cursor'] ?? array() ) ),
			'files_cursor' => (string) ( $data['files_cursor'] ?? '' ),
			'counters'     => (string) wp_json_encode( self::blank_counters() ),
			'error'        => '',
			'created_by'   => get_current_user_id(),
			'created_at'   => $now,
			'updated_at'   => $now,
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
	 * Completed backups, newest first — what retention counts against.
	 *
	 * @param int $limit How many rows.
	 * @return array<int,array<string,mixed>>
	 */
	public static function completed( int $limit = 200 ): array {
		global $wpdb;

		$limit = max( 1, min( 1000, $limit ) );
		$table = self::table();

		$rows = (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE status = %s ORDER BY id DESC LIMIT %d", // phpcs:ignore WordPress.DB
				self::DONE,
				$limit
			),
			ARRAY_A
		);

		return array_map( array( __CLASS__, 'hydrate' ), $rows );
	}

	/**
	 * Decode the JSON columns of a raw row.
	 *
	 * @param array<string,mixed> $row Raw database row.
	 * @return array<string,mixed>
	 */
	public static function hydrate( array $row ): array {
		$counters = json_decode( (string) ( $row['counters'] ?? '' ), true );
		$cursor   = json_decode( (string) ( $row['table_cursor'] ?? '' ), true );

		$row['counters_arr']     = is_array( $counters ) ? array_merge( self::blank_counters(), $counters ) : self::blank_counters();
		$row['table_cursor_arr'] = is_array( $cursor ) ? $cursor : array();

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
	 * Take the run lock for a job, atomically.
	 *
	 * A single UPDATE … WHERE locked_until IS NULL OR locked_until < UTC_TIMESTAMP()
	 * is the whole mechanism: MySQL decides the winner, so a cron tick and an
	 * operator's browser poll can never process the same batch twice.
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
	 * Release the run lock.
	 *
	 * @param int $id Job id.
	 * @return void
	 */
	public static function release( int $id ): void {
		self::update( $id, array( 'locked_until' => null ) );
	}
}

