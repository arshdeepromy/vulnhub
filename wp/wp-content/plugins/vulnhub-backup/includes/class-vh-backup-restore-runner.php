<?php
/**
 * Restore: validate an uploaded backup, then replace wp-content and the
 * database with it. Destructive by design — v1 targets the stated use case of
 * standing a backup up on a fresh stack, not merging into a live one.
 *
 * The operator uploads one file: the .tar.gz the backup screen produced. A
 * .zip bundle from an older install is still accepted (see do_validate()).
 *
 * Same pass/batch/claim skeleton as VulnHub_Backup_Runner, mirrored phases:
 * validate -> extract_files (staged, then atomically renamed over the live
 * tree) -> apply_sql (checkpointed statement batches, never one giant query
 * against a 500MB+ dump).
 *
 * @package VulnHub\Backup
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Runs restore jobs, one bounded batch at a time.
 */
final class VulnHub_Backup_Restore_Runner {

	public const PASS_HOOK = 'vulnhub_backup_restore_pass';

	public const PHASE_VALIDATE      = 'validate';
	public const PHASE_EXTRACT_FILES = 'extract_files';
	public const PHASE_APPLY_SQL     = 'apply_sql';
	public const PHASE_DONE          = 'done';

	private const BATCH_SECONDS = 20.0;
	private const LEASE         = 300;

	/** SQL statements executed per batch. */
	private const STATEMENTS_PER_BATCH = 200;

	/**
	 * @return void
	 */
	public static function hooks(): void {
		add_action( self::PASS_HOOK, array( __CLASS__, 'on_pass' ), 10, 1 );
	}

	/**
	 * @param mixed $job_id Job id.
	 * @return void
	 */
	public static function on_pass( mixed $job_id = 0 ): void {
		self::run( (int) $job_id, self::budget() );
	}

	/**
	 * @return float
	 */
	public static function budget(): float {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() ) {
			return 240.0;
		}

		return 12.0;
	}

	/**
	 * Queue the next pass.
	 *
	 * @param int $job_id Job id.
	 * @return void
	 */
	public static function schedule( int $job_id ): void {
		if ( ! $job_id || wp_next_scheduled( self::PASS_HOOK, array( $job_id ) ) ) {
			return;
		}

		wp_schedule_single_event( time(), self::PASS_HOOK, array( $job_id ) );
	}

	/**
	 * Start a restore from a staged, uploaded bundle. Uses the same jobs
	 * table as backups — a restore is a job with mode 'restore'.
	 *
	 * @param string $storage_key The chunked-upload storage key.
	 * @return int New job id, or 0.
	 */
	public static function start( string $storage_key ): int {
		if ( ! VulnHub_Backup_Storage::valid_key( $storage_key ) || ! VulnHub_Backup_Storage::exists( $storage_key ) ) {
			return 0;
		}

		$job_id = VulnHub_Backup_Jobs::create(
			array(
				'mode'        => 'restore',
				'phase'       => self::PHASE_VALIDATE,
				'status'      => VulnHub_Backup_Jobs::RUNNING,
				'storage_key' => $storage_key,
			)
		);

		if ( ! $job_id ) {
			return 0;
		}

		VulnHub_Backup_Jobs::update( $job_id, array( 'started_at' => current_time( 'mysql', true ) ) );

		if ( function_exists( 'vulnhub' ) ) {
			vulnhub()->logger->audit( 'backup.restore_start', 'Started a restore from an uploaded backup', 'backup_job', $job_id, array(), 'warning' );
		}

		self::schedule( $job_id );
		self::run( $job_id, self::budget() );

		return $job_id;
	}

	/**
	 * Run one pass.
	 *
	 * @param int   $job_id Job id.
	 * @param float $budget Seconds.
	 * @return void
	 */
	public static function run( int $job_id, float $budget ): void {
		$job = VulnHub_Backup_Jobs::get( $job_id );

		if ( ! $job || VulnHub_Backup_Jobs::RUNNING !== (string) $job['status'] ) {
			return;
		}

		if ( ! VulnHub_Backup_Jobs::claim( $job_id, self::LEASE ) ) {
			return;
		}

		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( (int) $budget + 120 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}

		$deadline = microtime( true ) + $budget;

		while ( microtime( true ) < $deadline ) {
			$job = VulnHub_Backup_Jobs::get( $job_id );

			if ( ! $job || VulnHub_Backup_Jobs::RUNNING !== (string) $job['status'] ) {
				break;
			}

			$phase = (string) $job['phase'];
			$done  = match ( $phase ) {
				self::PHASE_VALIDATE      => self::do_validate( $job ),
				self::PHASE_EXTRACT_FILES => self::do_extract_files( $job ),
				self::PHASE_APPLY_SQL     => self::do_apply_sql( $job ),
				default                    => true,
			};

			VulnHub_Backup_Jobs::update( $job_id, array( 'locked_until' => gmdate( 'Y-m-d H:i:s', time() + self::LEASE ) ) );

			// A phase that failed the job returns true to stop; it must not
			// then be advanced, or finished again as "done" over its error.
			$after = VulnHub_Backup_Jobs::get( $job_id );

			if ( $done && ( ! $after || VulnHub_Backup_Jobs::RUNNING !== (string) $after['status'] ) ) {
				return;
			}

			if ( $done ) {
				$next = match ( $phase ) {
					self::PHASE_VALIDATE      => self::PHASE_EXTRACT_FILES,
					self::PHASE_EXTRACT_FILES => self::PHASE_APPLY_SQL,
					self::PHASE_APPLY_SQL     => null,
					default                    => null,
				};

				if ( null === $next ) {
					self::finish( $job_id, VulnHub_Backup_Jobs::DONE );
					return;
				}

				VulnHub_Backup_Jobs::update( $job_id, array( 'phase' => $next ) );
			}
		}

		VulnHub_Backup_Jobs::release( $job_id );

		$job = VulnHub_Backup_Jobs::get( $job_id );

		if ( $job && VulnHub_Backup_Jobs::RUNNING === (string) $job['status'] ) {
			self::schedule( $job_id );
		}
	}

	/**
	 * Close a restore job out.
	 *
	 * @param int    $job_id Job id.
	 * @param string $status Terminal status.
	 * @param string $error  Error text, if any.
	 * @return void
	 */
	private static function finish( int $job_id, string $status, string $error = '' ): void {
		$job = VulnHub_Backup_Jobs::get( $job_id );

		VulnHub_Backup_Jobs::update(
			$job_id,
			array(
				'status'       => $status,
				'error'        => mb_substr( $error, 0, 2000 ),
				'finished_at'  => current_time( 'mysql', true ),
				'locked_until' => null,
			)
		);

		if ( $job && '' !== (string) $job['storage_key'] ) {
			VulnHub_Backup_Storage::delete( (string) $job['storage_key'] );
		}

		$staging = self::staging_dir( $job_id );

		if ( is_dir( $staging ) ) {
			self::rrmdir( $staging );
		}

		if ( function_exists( 'vulnhub' ) ) {
			vulnhub()->logger->audit(
				'backup.restore_' . $status,
				sprintf( 'Restore %s', $status ),
				'backup_job',
				$job_id,
				array( 'error' => $error ),
				VulnHub_Backup_Jobs::FAILED === $status ? 'error' : 'warning'
			);
		}
	}

	private static function ensure_staging_root(): string {
		$root = rtrim( dirname( WP_CONTENT_DIR ), '/\\' ) . '/vulnhub-restore-staging';

		if ( ! is_dir( $root ) && ! wp_mkdir_p( $root ) ) {
			return '';
		}

		$guards = array(
			'index.php'  => "<?php\n// Silence is golden.\n",
			'.htaccess'  => "# VulnHub restore staging.\n<IfModule mod_authz_core.c>\n\tRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n\tOrder allow,deny\n\tDeny from all\n</IfModule>\n",
			'web.config' => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration><system.webServer><authorization><deny users=\"*\" /></authorization></system.webServer></configuration>\n",
		);

		foreach ( $guards as $name => $contents ) {
			$path = $root . '/' . $name;
			if ( ! file_exists( $path ) ) {
				file_put_contents( $path, $contents ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			}
		}

		return $root;
	}

	private static function staging_dir( int $job_id ): string {
		$root = self::ensure_staging_root();

		if ( '' === $root ) {
			return '';
		}

		return $root . '/restore-staging-' . $job_id;
	}

	/**
	 * Recursively delete a directory.
	 *
	 * @param string $dir Directory path.
	 * @return void
	 */
	private static function rrmdir( string $dir ): void {
		$items = scandir( $dir );

		if ( ! is_array( $items ) ) {
			return;
		}

		foreach ( $items as $item ) {
			if ( '.' === $item || '..' === $item ) {
				continue;
			}

			$path = $dir . '/' . $item;

			if ( is_dir( $path ) ) {
				self::rrmdir( $path );
			} else {
				wp_delete_file( $path );
			}
		}

		@rmdir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
	}

	/* =================================================================
	 * Phase: validate
	 * ============================================================== */

	/**
	 * Sniff the uploaded bundle and open it into a staging directory,
	 * verifying the manifest's checksums before anything is trusted.
	 *
	 * @param array<string,mixed> $job Job row.
	 * @return bool
	 */
	private static function do_validate( array $job ): bool {
		$job_id = (int) $job['id'];
		$key    = (string) $job['storage_key'];
		$path   = VulnHub_Backup_Storage::path( $key );

		if ( '' === $path || ! is_readable( $path ) ) {
			self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, __( 'The uploaded backup file is no longer staged on the server.', 'vulnhub' ) );
			return true;
		}

		$staging = self::staging_dir( $job_id );

		if ( '' === $staging || ! wp_mkdir_p( $staging ) ) {
			self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, __( 'The restore staging directory could not be created.', 'vulnhub' ) );
			return true;
		}

		/*
		 * Two shapes arrive here. A backup taken now is one .tar.gz holding
		 * the three members; one taken before that change is a .zip of the
		 * same three. Both are read, because the whole point of a backup is
		 * that it still works when you need it, and the format it was written
		 * in is not the operator's problem.
		 *
		 * The format is decided by the file's first bytes rather than its
		 * name: this file was uploaded, so its extension proves nothing.
		 */
		$handle = fopen( $path, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$head   = $handle ? (string) fread( $handle, 4 ) : '';

		if ( $handle ) {
			fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}

		$format = VulnHub_Backup_Storage::format_of( $head );

		if ( 'targz' === $format ) {
			$result = VulnHub_Backup_Storage::extract_targz(
				$path,
				$staging,
				array( 'manifest.json', 'db.sql.gz', 'wp-content.zip' )
			);

			if ( ! $result['ok'] ) {
				self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, (string) $result['error'] );
				return true;
			}
		} elseif ( 'zip' === $format ) {
			$zip = new ZipArchive();

			if ( true !== $zip->open( $path ) ) {
				self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, __( 'That file is not a valid backup bundle.', 'vulnhub' ) );
				return true;
			}

			$zip->extractTo( $staging );
			$zip->close();
		} else {
			self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, __( 'That file is not a VulnHub backup. Upload the .tar.gz the backup screen produced.', 'vulnhub' ) );
			return true;
		}

		$manifest_path = $staging . '/manifest.json';

		if ( ! is_file( $manifest_path ) ) {
			self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, __( 'That bundle has no manifest.json — it is not a VulnHub backup.', 'vulnhub' ) );
			return true;
		}

		$manifest = json_decode( (string) file_get_contents( $manifest_path ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( ! is_array( $manifest ) ) {
			self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, __( 'The manifest could not be read.', 'vulnhub' ) );
			return true;
		}

		foreach ( array( 'db.sql.gz' => 'db_sha256', 'wp-content.zip' => 'zip_sha256' ) as $file => $hash_key ) {
			$full = $staging . '/' . $file;

			if ( ! is_file( $full ) ) {
				self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, sprintf( 'The bundle is missing %s.', $file ) );
				return true;
			}

			$expected = (string) ( $manifest[ $hash_key ] ?? '' );

			if ( '' !== $expected && ! hash_equals( $expected, (string) hash_file( 'sha256', $full ) ) ) {
				self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, sprintf( '%s does not match the checksum recorded in the manifest — the file may be corrupt.', $file ) );
				return true;
			}
		}

		VulnHub_Backup_Storage::delete( $key );

		return true;
	}

	/* =================================================================
	 * Phase: extract_files — staged, then an atomic rename over the live
	 * wp-content tree so a crash mid-restore never leaves a half-replaced
	 * install.
	 * ============================================================== */

	/**
	 * @param array<string,mixed> $job Job row.
	 * @return bool
	 */
	private static function do_extract_files( array $job ): bool {
		$job_id  = (int) $job['id'];
		$staging = self::staging_dir( $job_id );

		if ( '' === $staging ) {
			self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, __( 'The restore staging directory is no longer available.', 'vulnhub' ) );
			return true;
		}

		$inner   = $staging . '/wp-content.zip';

		$extract_to = $staging . '/wp-content-new';

		if ( ! is_dir( $extract_to ) ) {
			wp_mkdir_p( $extract_to );

			$zip = new ZipArchive();

			if ( true !== $zip->open( $inner ) ) {
				self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, __( 'wp-content.zip could not be opened.', 'vulnhub' ) );
				return true;
			}

			$zip->extractTo( $extract_to );
			$zip->close();
		}

		$live    = rtrim( WP_CONTENT_DIR, '/\\' );
		$old     = $staging . '/wp-content-old';
		$new_sub = $extract_to . '/wp-content';

		// Already swapped by a pass that died before recording the phase as
		// done: the restored tree is live and the old one is aside.
		$swapped = ! is_dir( $new_sub ) && is_dir( $old ) && is_dir( $live );

		if ( ! $swapped ) {
			if ( ! is_dir( $new_sub ) ) {
				self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, __( 'The extracted archive did not contain a wp-content directory.', 'vulnhub' ) );
				return true;
			}

			// Atomic swap: rename live out of the way, rename new one in. If the
			// process dies between these two lines, wp-content-old still exists
			// under staging and nothing has silently vanished.
			if ( ! is_dir( $old ) ) {
				if ( ! rename( $live, $old ) ) {
					self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, __( 'Could not move the live wp-content directory aside. The site has not been touched.', 'vulnhub' ) );
					return true;
				}
			}

			if ( ! rename( $new_sub, $live ) ) {
				self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, __( 'Could not move the restored files into place. The previous wp-content is preserved under the staging directory.', 'vulnhub' ) );
				return true;
			}
		}

		self::carry_over( $old, $live );

		return true;
	}

	/**
	 * Bring back what a restore must not take away.
	 *
	 * The old tree sits under staging, and finish() deletes staging. Without
	 * this, restoring deleted every local backup set (the store is never
	 * archived — a backup cannot contain itself) along with the upload being
	 * restored from, and anything at wp-content's top level the bundle did not
	 * carry: object-cache.php from bundles made before drop-ins were
	 * archived, and the logs, which never are.
	 *
	 * @param string $old  The previous wp-content, moved aside.
	 * @param string $live The restored wp-content, now live.
	 * @return void
	 */
	private static function carry_over( string $old, string $live ): void {
		$store = '/uploads/' . VulnHub_Backup_Storage::DIRNAME;

		if ( is_dir( $old . $store ) && ! file_exists( $live . $store ) ) {
			wp_mkdir_p( dirname( $live . $store ) );
			rename( $old . $store, $live . $store );
		}

		$items = scandir( $old );

		foreach ( is_array( $items ) ? $items : array() as $item ) {
			if ( '.' !== $item && '..' !== $item && ! file_exists( $live . '/' . $item ) ) {
				rename( $old . '/' . $item, $live . '/' . $item );
			}
		}
	}

	/* =================================================================
	 * Phase: apply_sql — checkpointed statement batches against the
	 * gzipped dump, never one giant $wpdb->query() call.
	 * ============================================================== */

	/**
	 * @param array<string,mixed> $job Job row.
	 * @return bool
	 */
	private static function do_apply_sql( array $job ): bool {
		global $wpdb;

		$job_id  = (int) $job['id'];
		$staging = self::staging_dir( $job_id );
		$sql_gz  = $staging . '/db.sql.gz';

		if ( ! is_file( $sql_gz ) ) {
			self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, __( 'db.sql.gz is missing from the staged bundle.', 'vulnhub' ) );
			return true;
		}

		$cursor = (array) $job['table_cursor_arr'];
		$offset = (int) ( $cursor['sql_offset'] ?? 0 );

		/*
		 * Apply from an inflated copy, not the .gz. gzseek() on a read stream
		 * gets there by decompressing from the start, so every pass re-read
		 * everything before its offset — some 3,000 passes over a gigabyte
		 * for a real estate. Inflated once, each pass seeks straight there.
		 * The offset is into the uncompressed SQL either way.
		 */
		$sql = $staging . '/db.sql';

		if ( ! is_file( $sql ) && ! self::inflate( $sql_gz, $sql ) ) {
			self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, __( 'The database dump could not be unpacked for restore.', 'vulnhub' ) );
			return true;
		}

		$fh = fopen( $sql, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( ! $fh || 0 !== fseek( $fh, $offset ) ) {
			self::finish( $job_id, VulnHub_Backup_Jobs::FAILED, __( 'The database dump could not be read.', 'vulnhub' ) );
			return true;
		}

		$statements = 0;
		$buffer     = '';
		$deadline   = microtime( true ) + self::BATCH_SECONDS;
		$eof        = false;

		// Whole lines only, and the batch ends only between statements: the
		// offset saved below is where the next pass starts, so it must never
		// fall inside one. Dump rows run to megabytes.
		while ( '' !== $buffer || ( $statements < self::STATEMENTS_PER_BATCH && microtime( true ) < $deadline ) ) {
			$line = fgets( $fh );

			if ( false === $line ) {
				$eof = true;
				break;
			}

			$trimmed = ltrim( $line );

			if ( '' === $buffer && ( '' === trim( $trimmed ) || str_starts_with( $trimmed, '--' ) ) ) {
				continue;
			}

			$buffer .= $line;

			if ( str_ends_with( rtrim( $line ), ';' ) ) {
				// The dump came out of this database; do not let wpdb reject
				// a row over its own charset heuristics.
				$wpdb->check_current_query = false;

				if ( false === $wpdb->query( $buffer ) ) { // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL
					$cursor['failed'] = (int) ( $cursor['failed'] ?? 0 ) + 1;
					if ( ! isset( $cursor['first_error'] ) ) {
						$cursor['first_error'] = mb_substr( (string) $wpdb->last_error, 0, 500 );
					}
				} elseif ( str_starts_with( $buffer, 'INSERT INTO `' ) ) {
					$cursor['rows'] = (int) ( $cursor['rows'] ?? 0 ) + 1;
				} elseif ( str_starts_with( $buffer, 'CREATE TABLE `' ) ) {
					$cursor['tables'] = (int) ( $cursor['tables'] ?? 0 ) + 1;
				}

				$buffer = '';
				++$statements;
			}
		}

		$new_offset = ftell( $fh );
		fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		$cursor['sql_offset'] = $new_offset;

		VulnHub_Backup_Jobs::update(
			$job_id,
			array( 'table_cursor' => (string) wp_json_encode( $cursor ) )
		);

		if ( $eof ) {
			// Every table was just replaced underneath the object cache
			// (Redis here), which would otherwise go on serving the settings,
			// users and options from before the restore.
			wp_cache_flush();

			self::check_applied( $job_id, $staging, $cursor );
		}

		return $eof;
	}

	/**
	 * Decompress the dump to a plain file, via a .part so a pass that dies
	 * half way never leaves a short db.sql that looks finished.
	 *
	 * @param string $source db.sql.gz.
	 * @param string $dest   db.sql.
	 * @return bool
	 */
	private static function inflate( string $source, string $dest ): bool {
		$in  = gzopen( $source, 'rb' );
		$out = fopen( $dest . '.part', 'wb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$ok  = $in && $out;

		while ( $ok && ! gzeof( $in ) ) {
			$chunk = gzread( $in, VulnHub_Backup_Storage::COPY_CHUNK );
			$ok    = false !== $chunk && false !== fwrite( $out, $chunk ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}

		if ( $in ) {
			gzclose( $in );
		}

		if ( $out ) {
			fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}

		return $ok && rename( $dest . '.part', $dest );
	}

	/**
	 * Fail the restore, loudly, when the dump did not all go in.
	 *
	 * Keeps going past a failed statement rather than stopping half way —
	 * a half-applied dump is worse than a fully-applied one with a named
	 * gap — but never lets that end as "done".
	 *
	 * @param int                 $job_id  Job id.
	 * @param string              $staging Staging directory (holds manifest.json).
	 * @param array<string,mixed> $cursor  Final apply cursor.
	 * @return void
	 */
	private static function check_applied( int $job_id, string $staging, array $cursor ): void {
		$problems = array();
		$failed   = (int) ( $cursor['failed'] ?? 0 );

		if ( $failed > 0 ) {
			$problems[] = sprintf(
				/* translators: 1: number of statements, 2: database error. */
				__( '%1$s statements failed (first error: %2$s)', 'vulnhub' ),
				number_format_i18n( $failed ),
				(string) ( $cursor['first_error'] ?? '' )
			);
		}

		$manifest = json_decode( (string) @file_get_contents( $staging . '/manifest.json' ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions,WordPress.PHP.NoSilencedErrors

		// Only bundles written since the manifest started recording counts
		// can be checked this way.
		if ( is_array( $manifest ) && isset( $manifest['rows_exported'], $manifest['tables_total'] ) ) {
			$rows   = (int) ( $cursor['rows'] ?? 0 );
			$tables = (int) ( $cursor['tables'] ?? 0 );

			if ( $rows !== (int) $manifest['rows_exported'] || $tables !== (int) $manifest['tables_total'] ) {
				$problems[] = sprintf(
					/* translators: 1: tables restored, 2: tables in the backup, 3: rows restored, 4: rows in the backup. */
					__( 'restored %1$s of %2$s tables and %3$s of %4$s rows', 'vulnhub' ),
					number_format_i18n( $tables ),
					number_format_i18n( (int) $manifest['tables_total'] ),
					number_format_i18n( $rows ),
					number_format_i18n( (int) $manifest['rows_exported'] )
				);
			}
		}

		if ( $problems ) {
			self::finish(
				$job_id,
				VulnHub_Backup_Jobs::FAILED,
				__( 'The database restore is incomplete: ', 'vulnhub' ) . implode( '; ', $problems ) . '.'
			);
		}
	}
}

