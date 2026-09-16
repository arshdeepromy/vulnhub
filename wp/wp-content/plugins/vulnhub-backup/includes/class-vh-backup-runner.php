<?php
/**
 * The backup pass engine: bounded batches, checkpointed phases, and resume.
 *
 * A job never runs to completion in one request. It moves through phases
 * (db_export -> files_archive -> package -> upload -> retention -> done), and
 * within each phase it runs bounded batches — the same BATCH_SECONDS/
 * WEB_BUDGET/CLI_BUDGET shape as VulnHub_Import_Runner. After every batch the
 * cursor for whichever phase is active is written back to the job row, so the
 * work already done survives a timeout, a killed process, or a container
 * restart.
 *
 * `package` is what makes a backup one file rather than three: it streams
 * manifest.json, db.sql.gz and wp-content.zip into a single .tar.gz and then
 * deletes the working folder. It is a phase of its own, with its own cursor,
 * so packing 150MB never has to fit inside one pass either.
 *
 * @package VulnHub\Backup
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Runs backup jobs, one bounded batch at a time.
 */
final class VulnHub_Backup_Runner {

	/** Cron hook that continues one job. */
	public const PASS_HOOK = 'vulnhub_backup_run_pass';

	/** Cron hook that re-arms jobs whose pass event went missing. */
	public const SWEEP_HOOK = 'vulnhub_backup_sweep';

	/**
	 * Phase that packs the finished members into one .tar.gz.
	 *
	 * Declared here rather than beside the other phases in
	 * VulnHub_Backup_Jobs because that file is owned elsewhere; the column is
	 * a plain string and nothing validates against a list, so this works —
	 * but it belongs next to its siblings when the two can be touched
	 * together.
	 */
	public const PHASE_PACKAGE = VulnHub_Backup_Jobs::PHASE_PACKAGE;

	/** Members of the archive, in the order they are written. */
	private const MEMBERS = array( 'manifest.json', 'db.sql.gz', 'wp-content.zip' );

	/** Rows fetched per table batch. */
	public const BATCH_ROWS = 2000;

	/** Wall-clock seconds per batch before the checkpoint is written. */
	public const BATCH_SECONDS = 20.0;

	/** Budget for a pass driven by the operator's browser. */
	public const WEB_BUDGET = 12.0;

	/**
	 * Budget for a pass driven by cron or WP-CLI.
	 *
	 * Deliberately under the cron worker's 60-second tick. That worker runs
	 * `wp cron event run` under `flock -n`, so whatever a pass holds, it holds
	 * against every other scheduled job: at the old 240s a backup blocked four
	 * ticks in a row, and because passes chain, a long backup starved the
	 * connector syncs and the 5-minute staged-sync resume sweep for as long as
	 * it ran. 45s finishes inside a tick and lets the queue interleave; a
	 * backup takes a few more passes and nothing else stops.
	 */
	public const CLI_BUDGET = 45.0;

	/** How long a run lock is leased for. */
	private const LEASE = 300;

	/** Files archived per files_archive batch. */
	private const FILES_PER_BATCH = 500;

	/**
	 * Register the cron hooks.
	 *
	 * @return void
	 */
	public static function hooks(): void {
		add_action( self::PASS_HOOK, array( __CLASS__, 'on_pass' ), 10, 1 );
		add_action( self::SWEEP_HOOK, array( __CLASS__, 'on_sweep' ) );

		if ( ! wp_next_scheduled( self::SWEEP_HOOK ) ) {
			wp_schedule_event( time() + 60, 'vh_5min', self::SWEEP_HOOK );
		}
	}

	/**
	 * Cron callback: continue one job.
	 *
	 * @param mixed $job_id Job id.
	 * @return void
	 */
	public static function on_pass( mixed $job_id = 0 ): void {
		self::run( (int) $job_id, self::budget() );
	}

	/**
	 * Cron callback: re-arm anything that should be running but is not, and
	 * tidy staged restore uploads nothing refers to any more.
	 *
	 * @return void
	 */
	public static function on_sweep(): void {
		foreach ( VulnHub_Backup_Jobs::resumable( 5 ) as $job ) {
			self::schedule( (int) $job['id'] );
		}

		VulnHub_Backup_Storage::sweep();
	}

	/**
	 * How long this process may spend inside one pass.
	 *
	 * @return float Seconds.
	 */
	public static function budget(): float {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() ) {
			return self::CLI_BUDGET;
		}

		return self::WEB_BUDGET;
	}

	/**
	 * Queue the next pass for a job.
	 *
	 * @param int $job_id Job id.
	 * @param int $delay  Seconds to wait.
	 * @return void
	 */
	public static function schedule( int $job_id, int $delay = 0 ): void {
		if ( ! $job_id ) {
			return;
		}

		$args = array( $job_id );

		if ( wp_next_scheduled( self::PASS_HOOK, $args ) ) {
			return;
		}

		wp_schedule_single_event( time() + max( 0, $delay ), self::PASS_HOOK, $args );
	}

	/* =================================================================
	 * Lifecycle
	 * ============================================================== */

	/**
	 * Create a new job and queue its first pass.
	 *
	 * @param string $mode 'manual' or 'scheduled'.
	 * @return int New job id, or 0.
	 */
	public static function start_new( string $mode ): int {
		$job_id = VulnHub_Backup_Jobs::create(
			array(
				'mode'  => $mode,
				'phase' => VulnHub_Backup_Jobs::PHASE_DB_EXPORT,
				'status' => VulnHub_Backup_Jobs::RUNNING,
			)
		);

		if ( ! $job_id ) {
			return 0;
		}

		VulnHub_Backup_Jobs::update(
			$job_id,
			array(
				'folder'     => VulnHub_Backup_Storage::new_folder( $job_id ),
				'started_at' => current_time( 'mysql', true ),
			)
		);

		if ( function_exists( 'vulnhub' ) ) {
			vulnhub()->logger->audit( 'backup.start', sprintf( 'Started a %s backup', $mode ), 'backup_job', $job_id );
		}

		/*
		 * Queue it and hand the browser back straight away.
		 *
		 * This used to run a pass inline first, which meant the "Backup now"
		 * POST sat there for up to WEB_BUDGET seconds before it could even
		 * redirect -- the operator pressed a button and watched a dead tab,
		 * on the request least able to afford it. The job is picked up by the
		 * next cron tick and the panel renders a running job on load, so
		 * nothing is lost by returning now.
		 */
		self::schedule( $job_id );

		return $job_id;
	}

	/**
	 * Run one pass of a job: as many bounded batches, across as many phases,
	 * as the budget allows.
	 *
	 * @param int   $job_id Job id.
	 * @param float $budget Seconds this process may spend.
	 * @return array{ok:bool,ran:bool,status:string}
	 */
	public static function run( int $job_id, float $budget = 0.0 ): array {
		$idle = array( 'ok' => true, 'ran' => false, 'status' => '' );

		$job = VulnHub_Backup_Jobs::get( $job_id );

		if ( ! $job ) {
			return $idle;
		}

		$idle['status'] = (string) $job['status'];

		if ( VulnHub_Backup_Jobs::RUNNING !== (string) $job['status'] ) {
			return $idle;
		}

		if ( $budget <= 0.0 ) {
			$budget = self::budget();
		}

		if ( ! VulnHub_Backup_Jobs::claim( $job_id, self::LEASE ) ) {
			return $idle;
		}

		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( (int) $budget + 120 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}

		$deadline = microtime( true ) + $budget;
		$began    = microtime( true );

		while ( microtime( true ) < $deadline ) {
			$job = VulnHub_Backup_Jobs::get( $job_id );

			if ( ! $job || VulnHub_Backup_Jobs::RUNNING !== (string) $job['status'] ) {
				break;
			}

			$phase = (string) $job['phase'];
			$done  = match ( $phase ) {
				VulnHub_Backup_Jobs::PHASE_DB_EXPORT     => self::batch_db_export( $job ),
				VulnHub_Backup_Jobs::PHASE_FILES_ARCHIVE  => self::batch_files_archive( $job ),
				self::PHASE_PACKAGE                       => self::batch_package( $job ),
				VulnHub_Backup_Jobs::PHASE_UPLOAD         => self::batch_upload( $job ),
				VulnHub_Backup_Jobs::PHASE_RETENTION      => self::batch_retention( $job ),
				default                                    => true,
			};

			// Re-fetch: the batch function above already wrote its own fresh
			// counters (tables_total, rows_exported, etc.) straight to the
			// row. Merging passes/seconds/peak_memory into the *stale*
			// pre-batch $job['counters_arr'] here would overwrite that work
			// with old values every single iteration.
			$after    = VulnHub_Backup_Jobs::get( $job_id );
			$counters = (array) ( $after['counters_arr'] ?? $job['counters_arr'] );

			$counters['passes']      = (int) ( $counters['passes'] ?? 0 ) + 1;
			$counters['seconds']     = round( (float) ( $counters['seconds'] ?? 0 ) + ( microtime( true ) - $began ), 2 );
			$counters['peak_memory'] = max( (int) ( $counters['peak_memory'] ?? 0 ), memory_get_peak_usage( true ) );
			$began = microtime( true );

			VulnHub_Backup_Jobs::update(
				$job_id,
				array(
					'counters'     => (string) wp_json_encode( $counters ),
					'locked_until' => gmdate( 'Y-m-d H:i:s', time() + self::LEASE ),
				)
			);

			// A batch function may have already called finish() itself on
			// failure (still returning true, meaning "stop looping this
			// phase") — never advance phase on top of a job that is no
			// longer running, or a failed job ends up mislabelled with the
			// next phase instead of the one it actually failed in.
			if ( $done && VulnHub_Backup_Jobs::RUNNING === (string) $after['status'] ) {
				$next = self::next_phase( $phase );

				if ( null === $next ) {
					self::finish( $job_id, VulnHub_Backup_Jobs::DONE );
					return array( 'ok' => true, 'ran' => true, 'status' => VulnHub_Backup_Jobs::DONE );
				}

				VulnHub_Backup_Jobs::update( $job_id, array( 'phase' => $next ) );
			} elseif ( $done ) {
				break;
			}
		}

		VulnHub_Backup_Jobs::release( $job_id );

		$job = VulnHub_Backup_Jobs::get( $job_id );

		if ( $job && VulnHub_Backup_Jobs::RUNNING === (string) $job['status'] ) {
			self::schedule( $job_id );
		}

		return array( 'ok' => true, 'ran' => true, 'status' => $job ? (string) $job['status'] : '' );
	}

	/**
	 * The phase that follows the given one, or null when it was the last.
	 *
	 * @param string $phase Current phase.
	 * @return string|null
	 */
	private static function next_phase( string $phase ): ?string {
		return match ( $phase ) {
			VulnHub_Backup_Jobs::PHASE_DB_EXPORT      => VulnHub_Backup_Jobs::PHASE_FILES_ARCHIVE,
			VulnHub_Backup_Jobs::PHASE_FILES_ARCHIVE  => self::PHASE_PACKAGE,
			self::PHASE_PACKAGE                       => VulnHub_Backup_Jobs::PHASE_UPLOAD,
			VulnHub_Backup_Jobs::PHASE_UPLOAD         => VulnHub_Backup_Jobs::PHASE_RETENTION,
			VulnHub_Backup_Jobs::PHASE_RETENTION      => null,
			default                                    => null,
		};
	}

	/**
	 * Close a job out: status, audit entry, sync_runs summary (so the
	 * existing "last run" card in integrations.php can be reused verbatim by
	 * treating 'backup_s3' as a pseudo-connector id).
	 *
	 * @param int    $job_id Job id.
	 * @param string $status Terminal status.
	 * @param string $error  Error text, if any.
	 * @return void
	 */
	private static function finish( int $job_id, string $status, string $error = '' ): void {
		$job = VulnHub_Backup_Jobs::get( $job_id );

		if ( ! $job ) {
			return;
		}

		$counters = (array) ( $job['counters_arr'] ?? VulnHub_Backup_Jobs::blank_counters() );

		VulnHub_Backup_Jobs::update(
			$job_id,
			array(
				'status'       => $status,
				'error'        => mb_substr( $error, 0, 2000 ),
				'finished_at'  => current_time( 'mysql', true ),
				'locked_until' => null,
			)
		);

		$hook = wp_next_scheduled( self::PASS_HOOK, array( $job_id ) );

		if ( $hook ) {
			wp_unschedule_event( (int) $hook, self::PASS_HOOK, array( $job_id ) );
		}

		if ( ! function_exists( 'vulnhub' ) ) {
			return;
		}

		$run_id = vulnhub()->logger->start_run( 'backup_s3', (string) $job['mode'] );
		vulnhub()->logger->finish_run(
			$run_id,
			VulnHub_Backup_Jobs::DONE === $status ? 'success' : 'failed',
			array(
				'processed' => (int) ( $counters['tables_done'] ?? 0 ),
				'created'   => (int) ( $counters['files_archived'] ?? 0 ),
				'updated'   => 0,
				'skipped'   => (int) ( $counters['sets_deleted'] ?? 0 ),
				'failed'    => VulnHub_Backup_Jobs::DONE === $status ? 0 : 1,
			),
			$error
		);

		vulnhub()->logger->audit(
			'backup.' . $status,
			sprintf( 'Backup %s (%s)', $status, (string) $job['folder'] ),
			'backup_job',
			$job_id,
			array( 'status' => $status, 'error' => $error, 'counters' => $counters ),
			VulnHub_Backup_Jobs::FAILED === $status ? 'error' : 'info'
		);
	}

	/**
	 * Cancel a running job.
	 *
	 * @param int $job_id Job id.
	 * @return array{ok:bool,message:string}
	 */
	public static function cancel( int $job_id ): array {
		$job = VulnHub_Backup_Jobs::get( $job_id );

		if ( ! $job ) {
			return array( 'ok' => false, 'message' => __( 'That backup job no longer exists.', 'vulnhub' ) );
		}

		if ( in_array( (string) $job['status'], array( VulnHub_Backup_Jobs::DONE, VulnHub_Backup_Jobs::CANCELLED, VulnHub_Backup_Jobs::FAILED ), true ) ) {
			return array( 'ok' => false, 'message' => __( 'That job has already stopped.', 'vulnhub' ) );
		}

		self::finish( $job_id, VulnHub_Backup_Jobs::CANCELLED );

		return array( 'ok' => true, 'message' => __( 'Backup cancelled.', 'vulnhub' ) );
	}

	/* =================================================================
	 * Phase: db_export — pure-PHP, batched per table (no mysqldump binary
	 * exists in this container, confirmed before implementation began).
	 * ============================================================== */

	/**
	 * Process one bounded batch of the DB export.
	 *
	 * @param array<string,mixed> $job Job row.
	 * @return bool True once every table has been fully exported.
	 */
	private static function batch_db_export( array $job ): bool {
		global $wpdb;

		$job_id = (int) $job['id'];
		$dir    = VulnHub_Backup_Storage::set_dir( (string) $job['folder'] );

		if ( '' === $dir ) {
			self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, __( 'The backup storage directory could not be created.', 'vulnhub' ) );
			return true;
		}

		$cursor = (array) $job['table_cursor_arr'];

		if ( empty( $cursor ) ) {
			$tables = (array) $wpdb->get_col( 'SHOW TABLES' );
			// Exclude our own job-tracking table. A currently-*running*
			// backup or restore job lives as a row in this very table;
			// dumping it (and a restore later replaying that dump's
			// DROP TABLE/CREATE TABLE/INSERT against a live site) would
			// wipe out and replace the row the *currently executing*
			// restore job depends on to track its own progress -- confirmed
			// by reproducing exactly that during testing. Transient job
			// queue state is never meaningful to carry into a restore
			// anyway; a fresh site should start with an empty queue.
			$tables = array_values( array_diff( $tables, array( $wpdb->prefix . 'vulnhub_backup_jobs' ) ) );
			sort( $tables );
			$cursor = array(
				'tables'      => $tables,
				'table_index' => 0,
				'offset'      => 0,
			);

			// Fresh export: truncate/create the gz stream.
			$path = $dir . '/db.sql.gz';
			$gz   = gzopen( $path, 'wb9' );
			if ( $gz ) {
				gzwrite( $gz, "-- VulnHub backup, generated " . gmdate( 'c' ) . "\nSET NAMES utf8mb4;\nSET FOREIGN_KEY_CHECKS=0;\n\n" );
				gzclose( $gz );
			}
		}

		$tables = (array) $cursor['tables'];
		$index  = (int) $cursor['table_index'];

		if ( $index >= count( $tables ) ) {
			return true;
		}

		$table  = (string) $tables[ $index ];
		$offset = (int) $cursor['offset'];

		$path = $dir . '/db.sql.gz';
		$gz   = gzopen( $path, 'ab9' );

		if ( ! $gz ) {
			self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, __( 'The database export file could not be written.', 'vulnhub' ) );
			return true;
		}

		if ( 0 === $offset ) {
			gzwrite( $gz, "\n-- Table: {$table}\nDROP TABLE IF EXISTS `{$table}`;\n" );
			$create = $wpdb->get_row( "SHOW CREATE TABLE `{$table}`", ARRAY_N ); // phpcs:ignore WordPress.DB
			if ( $create && isset( $create[1] ) ) {
				gzwrite( $gz, $create[1] . ";\n" );
			}
		}

		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM `{$table}` LIMIT %d OFFSET %d", self::BATCH_ROWS, $offset ), ARRAY_A ); // phpcs:ignore WordPress.DB
		$row_count = is_array( $rows ) ? count( $rows ) : 0;

		if ( $row_count > 0 ) {
			$columns = array_keys( $rows[0] );
			$column_list = '`' . implode( '`, `', $columns ) . '`';

			foreach ( $rows as $row ) {
				$values = array();

				foreach ( $row as $value ) {
					$values[] = null === $value ? 'NULL' : "'" . $wpdb->_real_escape( (string) $value ) . "'";
				}

				gzwrite( $gz, "INSERT INTO `{$table}` ({$column_list}) VALUES (" . implode( ', ', $values ) . ");\n" );
			}
		}

		gzclose( $gz );

		$counters = (array) $job['counters_arr'];
		$counters['rows_exported'] = (int) ( $counters['rows_exported'] ?? 0 ) + $row_count;

		if ( $row_count < self::BATCH_ROWS ) {
			// This table is done; advance to the next one.
			$counters['tables_done'] = (int) ( $counters['tables_done'] ?? 0 ) + 1;
			$cursor['table_index']   = $index + 1;
			$cursor['offset']        = 0;
		} else {
			$cursor['offset'] = $offset + self::BATCH_ROWS;
		}

		$counters['tables_total'] = count( $tables );
		clearstatcache( true, $path );
		$counters['db_bytes'] = (int) filesize( $path );

		VulnHub_Backup_Jobs::update(
			$job_id,
			array(
				'table_cursor' => (string) wp_json_encode( $cursor ),
				'counters'     => (string) wp_json_encode( $counters ),
			)
		);

		return $cursor['table_index'] >= count( $tables );
	}

	/* =================================================================
	 * Phase: files_archive — wp-content/{plugins,themes,uploads,mu-plugins}
	 * into a ZipArchive, batched by file count.
	 * ============================================================== */

	/**
	 * Process one bounded batch of the files archive.
	 *
	 * @param array<string,mixed> $job Job row.
	 * @return bool True once every file has been archived.
	 */
	private static function batch_files_archive( array $job ): bool {
		$job_id = (int) $job['id'];
		$dir    = VulnHub_Backup_Storage::set_dir( (string) $job['folder'] );

		if ( '' === $dir ) {
			self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, __( 'The backup storage directory could not be created.', 'vulnhub' ) );
			return true;
		}

		$zip_path    = $dir . '/wp-content.zip';
		$content_dir = rtrim( WP_CONTENT_DIR, '/\\' );

		$file_list = get_transient( 'vulnhub_backup_file_list_' . $job_id );

		if ( false === $file_list ) {
			$file_list = array();

			foreach ( array( 'plugins', 'themes', 'uploads', 'mu-plugins' ) as $sub ) {
				$base = $content_dir . '/' . $sub;

				if ( ! is_dir( $base ) ) {
					continue;
				}

				$iterator = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $base, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);

				foreach ( $iterator as $file ) {
					if ( ! $file->isFile() ) {
						continue;
					}
					// Never archive our own staged backups back into themselves.
					if ( str_contains( (string) $file->getPathname(), '/uploads/vulnhub-backup/' ) ) {
						continue;
					}
					$file_list[] = $file->getPathname();
				}
			}

			set_transient( 'vulnhub_backup_file_list_' . $job_id, $file_list, 6 * HOUR_IN_SECONDS );

			// Do not pre-create the zip here: libzip writes nothing to disk
			// for an archive with zero entries, so an open()+close() with
			// nothing added in between silently produces no file at all,
			// and every later open() (without CREATE) then fails. Creation
			// happens on the first real open() below instead, in the same
			// call that adds the first batch of files.
		}

		$cursor = (int) ( $job['files_cursor'] ?: 0 );
		$total  = count( $file_list );

		if ( 0 === $total ) {
			// Nothing under wp-content worth archiving; move on without a
			// wp-content.zip (write_manifest()/restore both tolerate its
			// absence).
			delete_transient( 'vulnhub_backup_file_list_' . $job_id );
			return true;
		}

		if ( $cursor >= $total ) {
			delete_transient( 'vulnhub_backup_file_list_' . $job_id );
			return true;
		}

		$zip  = new ZipArchive();
		$mode = 0 === $cursor ? ( ZipArchive::CREATE | ZipArchive::OVERWRITE ) : ZipArchive::CREATE;

		if ( true !== $zip->open( $zip_path, $mode ) ) {
			self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, __( 'The wp-content archive could not be opened.', 'vulnhub' ) );
			return true;
		}

		$end       = min( $total, $cursor + self::FILES_PER_BATCH );
		$deadline  = microtime( true ) + self::BATCH_SECONDS;
		$content_len = strlen( $content_dir );
		$archived  = 0;

		for ( $i = $cursor; $i < $end; $i++ ) {
			$path      = (string) $file_list[ $i ];
			$local_name = 'wp-content' . substr( $path, $content_len );
			$zip->addFile( $path, $local_name );
			++$archived;

			if ( microtime( true ) >= $deadline ) {
				$end = $i + 1;
				break;
			}
		}

		$zip->close();

		$counters = (array) $job['counters_arr'];
		$counters['files_archived'] = (int) ( $counters['files_archived'] ?? 0 ) + $archived;
		clearstatcache( true, $zip_path );
		$counters['zip_bytes'] = is_file( $zip_path ) ? (int) filesize( $zip_path ) : 0;

		VulnHub_Backup_Jobs::update(
			$job_id,
			array(
				'files_cursor' => (string) $end,
				'counters'     => (string) wp_json_encode( $counters ),
			)
		);

		if ( $end >= $total ) {
			delete_transient( 'vulnhub_backup_file_list_' . $job_id );
			self::write_manifest( $job_id, $dir );
			return true;
		}

		return false;
	}

	/**
	 * Write manifest.json once both archives are complete: hashes, sizes,
	 * counts — what a restore validates against before touching anything.
	 *
	 * @param int    $job_id Job id.
	 * @param string $dir    Backup set directory.
	 * @return void
	 */
	private static function write_manifest( int $job_id, string $dir ): void {
		$job = VulnHub_Backup_Jobs::get( $job_id );

		if ( ! $job ) {
			return;
		}

		$db_path  = $dir . '/db.sql.gz';
		$zip_path = $dir . '/wp-content.zip';

		$manifest = array(
			'job_id'        => $job_id,
			'created_at'    => current_time( 'mysql', true ),
			'app_version'   => defined( 'VULNHUB_VERSION' ) ? VULNHUB_VERSION : '',
			// What a restore is looking at. Bundles written before packing
			// existed have no `format` key at all, which is how they are told
			// apart from these.
			'format'        => 'tar.gz.v1',
			'db_bytes'      => is_file( $db_path ) ? filesize( $db_path ) : 0,
			'db_sha256'     => is_file( $db_path ) ? hash_file( 'sha256', $db_path ) : '',
			'zip_bytes'     => is_file( $zip_path ) ? filesize( $zip_path ) : 0,
			'zip_sha256'    => is_file( $zip_path ) ? hash_file( 'sha256', $zip_path ) : '',
			'tables_done'   => (int) ( $job['counters_arr']['tables_done'] ?? 0 ),
			'files_archived' => (int) ( $job['counters_arr']['files_archived'] ?? 0 ),
		);

		file_put_contents( $dir . '/manifest.json', (string) wp_json_encode( $manifest, JSON_PRETTY_PRINT ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions
	}

	/* =================================================================
	 * Phase: package — manifest.json + db.sql.gz + wp-content.zip into one
	 * .tar.gz, a chunk at a time, then throw the loose copies away.
	 * ============================================================== */

	/**
	 * Process one bounded batch of the packing step.
	 *
	 * The cursor (which member, and how far into it) lives in the counters
	 * blob, so a pass that runs out of budget half way through a 100MB member
	 * picks up exactly where it stopped. Appending to a gzip file is legal and
	 * produces a multi-member stream every reader handles, which is what makes
	 * that possible without holding the archive open across requests.
	 *
	 * @param array<string,mixed> $job Job row.
	 * @return bool True once the archive is complete.
	 */
	private static function batch_package( array $job ): bool {
		$job_id  = (int) $job['id'];
		$folder  = (string) $job['folder'];
		$dir     = VulnHub_Backup_Storage::set_dir( $folder );
		$archive = VulnHub_Backup_Storage::archive_path( $folder );

		if ( '' === $dir || '' === $archive ) {
			self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, __( 'The backup storage directory could not be created.', 'vulnhub' ) );
			return true;
		}

		$counters = (array) $job['counters_arr'];
		$cursor   = (array) ( $counters['package'] ?? array() );
		$index    = (int) ( $cursor['index'] ?? 0 );
		$offset   = (int) ( $cursor['offset'] ?? 0 );

		// Only the members that exist: wp-content.zip is absent when there was
		// nothing under wp-content to archive.
		$members = array_values(
			array_filter(
				self::MEMBERS,
				static fn( string $name ): bool => is_file( $dir . '/' . $name )
			)
		);

		if ( ! $members ) {
			self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, __( 'There is nothing to pack — the backup produced no files.', 'vulnhub' ) );
			return true;
		}

		// A restart of this phase (index 0, nothing written yet) must not
		// append to a half-written archive from an interrupted attempt.
		if ( 0 === $index && 0 === $offset && is_file( $archive ) ) {
			wp_delete_file( $archive );
		}

		$gz = VulnHub_Backup_Storage::tar_open( $archive );

		if ( ! $gz ) {
			self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, __( 'The backup archive could not be written.', 'vulnhub' ) );
			return true;
		}

		$deadline = microtime( true ) + self::BATCH_SECONDS;
		$done     = false;

		while ( $index < count( $members ) ) {
			$name = (string) $members[ $index ];
			$path = $dir . '/' . $name;
			$size = (int) filesize( $path );

			if ( 0 === $offset ) {
				gzwrite( $gz, VulnHub_Backup_Storage::tar_header( $name, $size, (int) filemtime( $path ) ) );
			}

			$written = VulnHub_Backup_Storage::tar_copy_member( $gz, $path, $offset, $deadline );

			if ( $written < 0 ) {
				gzclose( $gz );
				self::finish(
					$job_id,
					VulnHub_Backup_Jobs::FAILED,
					sprintf(
						/* translators: %s: file name. */
						__( '%s could not be read while packing the backup.', 'vulnhub' ),
						$name
					)
				);
				return true;
			}

			$offset = $written;

			if ( $offset >= $size ) {
				// Members are padded to a 512-byte boundary; the next header
				// has to start on one.
				gzwrite( $gz, VulnHub_Backup_Storage::tar_padding( $size ) );
				++$index;
				$offset = 0;
			}

			if ( $index >= count( $members ) ) {
				VulnHub_Backup_Storage::tar_terminate( $gz );
				$done = true;
				break;
			}

			if ( microtime( true ) >= $deadline ) {
				break;
			}
		}

		gzclose( $gz );

		$counters['package'] = array( 'index' => $index, 'offset' => $offset );
		clearstatcache( true, $archive );
		$counters['archive_bytes'] = is_file( $archive ) ? (int) filesize( $archive ) : 0;

		if ( ! $done ) {
			VulnHub_Backup_Jobs::save_counters( $job_id, $counters );
			return false;
		}

		/*
		 * Packed. The hash is of the archive as a whole, recorded on the job
		 * (it cannot live inside the manifest, which is inside the archive) so
		 * an operator can check a downloaded copy byte for byte. A restore
		 * does not depend on it: it verifies each member against the manifest
		 * and treats a missing tar end-marker as a truncated download.
		 */
		$hash = (string) hash_file( 'sha256', $archive );

		$counters['archive_sha256'] = $hash;
		$counters['archive_name']   = VulnHub_Backup_Storage::archive_name( $folder );

		VulnHub_Backup_Jobs::save_counters( $job_id, $counters );
		VulnHub_Backup_Jobs::update(
			$job_id,
			array(
				'size_bytes'   => (string) ( $counters['archive_bytes'] ?? 0 ),
				'content_hash' => $hash,
			)
		);

		// The members now live in the archive; the working folder is litter.
		VulnHub_Backup_Storage::delete_work_dir( $folder );

		return true;
	}

	/* =================================================================
	 * Phase: upload — push the packed archive to S3 when configured.
	 * put_object() under the 100MB threshold, multipart in checkpointed
	 * 32MB part-batches above it.
	 * ============================================================== */

	/**
	 * Process one bounded batch of the S3 upload.
	 *
	 * @param array<string,mixed> $job Job row.
	 * @return bool True once every file (or nothing, if S3 is disabled) has
	 *              been pushed.
	 */
	private static function batch_upload( array $job ): bool {
		$job_id = (int) $job['id'];

		if ( ! function_exists( 'vulnhub' ) ) {
			return true;
		}

		$settings = vulnhub()->settings;

		if ( ! $settings->get_bool( 'backup_s3', 'enabled', false ) ) {
			return true;
		}

		$s3 = self::s3_client();

		if ( ! $s3 || ! $s3->configured() ) {
			self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, __( 'S3 is enabled but not fully configured (access key, secret key or bucket missing).', 'vulnhub' ) );
			return true;
		}

		$folder = (string) $job['folder'];

		$s3->ensure_lifecycle_rule( (string) $settings->get( 'backup_s3', 'prefix', 'vulnhub-backups' ) );

		/*
		 * One object per backup now, not three. The key keeps the backup's own
		 * name so what lands in the bucket is the same file an operator would
		 * download from the backups screen -- and so retention, which groups
		 * by the segment after the prefix, still sees one backup as one unit.
		 */
		$files = array(
			VulnHub_Backup_Storage::archive_name( $folder ) => 'application/gzip',
		);

		$counters = (array) $job['counters_arr'];
		$upload_state = (array) ( $counters['upload_state'] ?? array() );

		foreach ( $files as $name => $content_type ) {
			$path = VulnHub_Backup_Storage::archive_path( $folder );

			if ( '' === $path || ! is_file( $path ) ) {
				continue;
			}
			if ( ! empty( $upload_state[ $name ]['done'] ) ) {
				continue;
			}

			$size = filesize( $path );
			$key  = self::s3_prefix() . $name;

			if ( $size < VulnHub_Backup_S3::MULTIPART_THRESHOLD ) {
				$body   = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
				$result = $s3->put_object( $key, (string) $body, $content_type );

				if ( ! $result['ok'] ) {
					self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, sprintf( 'S3 upload of %s failed: %s', $name, $result['error'] ) );
					return true;
				}

				$upload_state[ $name ] = array( 'done' => true );
			} else {
				$done = self::multipart_upload_step( $s3, $key, $content_type, $path, $upload_state[ $name ] ?? array() );

				if ( ! $done['ok'] ) {
					self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, sprintf( 'S3 multipart upload of %s failed: %s', $name, $done['error'] ) );
					return true;
				}

				$upload_state[ $name ] = $done['state'];

				$counters['upload_state'] = $upload_state;
				VulnHub_Backup_Jobs::save_counters( $job_id, $counters );

				if ( ! $done['state']['done'] ) {
					// Ran out of batch time mid-file; resume next pass.
					return false;
				}
			}

			$counters['upload_state'] = $upload_state;
			VulnHub_Backup_Jobs::save_counters( $job_id, $counters );
		}

		return true;
	}

	/**
	 * One checkpointed batch of a multipart upload: as many 32MB parts as fit
	 * in BATCH_SECONDS, picking up the upload id and part list from state.
	 *
	 * @param VulnHub_Backup_S3   $s3           S3 client.
	 * @param string              $key          Object key.
	 * @param string              $content_type MIME type.
	 * @param string              $path         Local file path.
	 * @param array<string,mixed> $state        {uploadId, parts[], bytesDone, done}.
	 * @return array{ok:bool,state:array<string,mixed>,error:string}
	 */
	private static function multipart_upload_step( VulnHub_Backup_S3 $s3, string $key, string $content_type, string $path, array $state ): array {
		$upload_id  = (string) ( $state['uploadId'] ?? '' );
		$parts      = (array) ( $state['parts'] ?? array() );
		$bytes_done = (int) ( $state['bytesDone'] ?? 0 );

		if ( '' === $upload_id ) {
			$created = $s3->create_multipart_upload( $key, $content_type );

			if ( ! $created['ok'] ) {
				return array( 'ok' => false, 'state' => $state, 'error' => $created['error'] );
			}

			$upload_id = $created['uploadId'];
		}

		$size     = filesize( $path );
		$handle   = fopen( $path, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$deadline = microtime( true ) + self::BATCH_SECONDS;

		fseek( $handle, $bytes_done );

		while ( $bytes_done < $size && microtime( true ) < $deadline ) {
			$chunk = fread( $handle, VulnHub_Backup_S3::PART_SIZE );

			if ( false === $chunk || '' === $chunk ) {
				break;
			}

			$part_number = count( $parts ) + 1;
			$result      = $s3->upload_part( $key, $upload_id, $part_number, $chunk );

			if ( ! $result['ok'] ) {
				fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions
				return array(
					'ok'    => false,
					'state' => array( 'uploadId' => $upload_id, 'parts' => $parts, 'bytesDone' => $bytes_done, 'done' => false ),
					'error' => $result['error'],
				);
			}

			$parts[]     = array( 'partNumber' => $part_number, 'etag' => $result['etag'] );
			$bytes_done += strlen( $chunk );
		}

		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( $bytes_done >= $size ) {
			$complete = $s3->complete_multipart_upload( $key, $upload_id, $parts );

			if ( ! $complete['ok'] ) {
				return array(
					'ok'    => false,
					'state' => array( 'uploadId' => $upload_id, 'parts' => $parts, 'bytesDone' => $bytes_done, 'done' => false ),
					'error' => $complete['error'],
				);
			}

			return array(
				'ok'    => true,
				'state' => array( 'uploadId' => $upload_id, 'parts' => $parts, 'bytesDone' => $bytes_done, 'done' => true ),
				'error' => '',
			);
		}

		return array(
			'ok'    => true,
			'state' => array( 'uploadId' => $upload_id, 'parts' => $parts, 'bytesDone' => $bytes_done, 'done' => false ),
			'error' => '',
		);
	}

	/**
	 * The configured S3 key prefix, with a trailing slash.
	 *
	 * It used to take the backup folder and return a per-backup prefix, back
	 * when a backup was three objects that needed a folder of their own in the
	 * bucket. One object needs no folder — the archive's own name carries the
	 * date and job id.
	 *
	 * @return string
	 */
	private static function s3_prefix(): string {
		$prefix = function_exists( 'vulnhub' ) ? (string) vulnhub()->settings->get( 'backup_s3', 'prefix', 'vulnhub-backups' ) : 'vulnhub-backups';

		return trim( $prefix, '/' ) . '/';
	}

	/**
	 * Build an S3 client from the stored settings, or null if not configured.
	 *
	 * @return VulnHub_Backup_S3|null
	 */
	public static function s3_client(): ?VulnHub_Backup_S3 {
		if ( ! function_exists( 'vulnhub' ) ) {
			return null;
		}

		$settings = vulnhub()->settings;

		$access_key = $settings->secret( 'backup_s3', 'access_key_id' );
		$secret_key = $settings->secret( 'backup_s3', 'secret_access_key' );
		$region     = (string) $settings->get( 'backup_s3', 'region', 'us-east-1' );
		$bucket     = (string) $settings->get( 'backup_s3', 'bucket', '' );

		if ( '' === $access_key || '' === $secret_key || '' === $bucket ) {
			return null;
		}

		return new VulnHub_Backup_S3( $access_key, $secret_key, $region, $bucket );
	}

	/* =================================================================
	 * Phase: retention — keep the newest N backup sets, locally and in S3.
	 * ============================================================== */

	/**
	 * Enforce the configured retention count, locally and in S3.
	 *
	 * @param array<string,mixed> $job Job row.
	 * @return bool Always true — retention is a single bounded step.
	 */
	private static function batch_retention( array $job ): bool {
		$job_id = (int) $job['id'];
		$keep   = function_exists( 'vulnhub' ) ? max( 1, (int) vulnhub()->settings->get( 'backup_s3', 'retention_count', 10 ) ) : 10;

		$local_sets = VulnHub_Backup_Storage::list_local();
		$counters   = (array) $job['counters_arr'];
		$deleted    = 0;

		foreach ( array_slice( $local_sets, $keep ) as $set ) {
			if ( VulnHub_Backup_Storage::delete_local_set( (string) $set['folder'] ) ) {
				++$deleted;
			}
		}

		$counters['sets_deleted'] = $deleted;

		$s3 = self::s3_client();

		if ( $s3 && $s3->configured() && function_exists( 'vulnhub' ) && vulnhub()->settings->get_bool( 'backup_s3', 'enabled', false ) ) {
			$prefix   = trim( (string) vulnhub()->settings->get( 'backup_s3', 'prefix', 'vulnhub-backups' ), '/' ) . '/';
			$all_keys = $s3->list_all( $prefix );

			// Group by the segment right after the prefix, so retention counts
			// one backup as one unit whichever shape it is in the bucket: a
			// packed `<folder>.tar.gz` object, or the `<folder>/` of three
			// objects an older install uploaded.
			$folders = array();
			foreach ( $all_keys as $entry ) {
				$rest = substr( (string) $entry['key'], strlen( $prefix ) );
				$folder = strtok( $rest, '/' );
				if ( '' !== $folder && false !== $folder ) {
					$folders[ $folder ][] = (string) $entry['key'];
				}
			}

			krsort( $folders );
			$to_delete = array();
			$i         = 0;

			foreach ( $folders as $keys ) {
				++$i;
				if ( $i > $keep ) {
					$to_delete = array_merge( $to_delete, $keys );
				}
			}

			if ( $to_delete ) {
				$result = $s3->delete_objects( $to_delete );
				$counters['objects_deleted'] = (int) ( $counters['objects_deleted'] ?? 0 ) + $result['deleted'];
			}
		}

		VulnHub_Backup_Jobs::save_counters( $job_id, $counters );

		return true;
	}
}

