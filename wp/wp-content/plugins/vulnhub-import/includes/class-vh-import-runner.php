<?php
/**
 * The pass engine: bounded batches, byte-offset checkpoints, and resume.
 *
 * A job never runs to completion in one request. It runs in *passes*, and a
 * pass runs in *batches* of at most 2,000 rows or 20 seconds, whichever comes
 * first. After every batch the byte offset, the row count and the counters are
 * written back to the job row, so the work already done survives anything —
 * the request timing out, PHP being killed, the container being restarted, the
 * operator closing the tab.
 *
 * Continuation is deliberately driven from two directions:
 *
 *  - WP-Cron schedules the next pass, so a job finishes whether or not anybody
 *    is watching, and a five-minute sweep re-arms any job whose event was lost;
 *  - the operator's browser polls an authenticated REST route which runs a
 *    short pass inline, so a watched import advances immediately rather than
 *    at the mercy of the cron tick.
 *
 * Both take the same atomic row lock, so they can never process the same rows
 * twice.
 *
 * @package VulnHub\Import
 */

declare( strict_types = 1 );

use VulnHub\Core\Coverage;
use VulnHub\Core\Mapping;
use VulnHub\Core\Repo;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Runs import jobs, one bounded batch at a time.
 */
final class VulnHub_Import_Runner {

	/** Cron hook that continues one job. */
	public const PASS_HOOK = 'vulnhub_import_run_pass';

	/** Cron hook that re-arms jobs whose pass event went missing. */
	public const SWEEP_HOOK = 'vulnhub_import_sweep';

	/** Most rows in one batch before the checkpoint is written. */
	public const BATCH_ROWS = 2000;

	/** Most wall-clock seconds in one batch before the checkpoint is written. */
	public const BATCH_SECONDS = 20.0;

	/** Budget for a pass driven by the operator's browser. */
	public const WEB_BUDGET = 12.0;

	/** Budget for a pass driven by cron or WP-CLI, which have no page to hold. */
	public const CLI_BUDGET = 240.0;

	/** How long a run lock is leased for. */
	private const LEASE = 300;

	/**
	 * Register the cron hooks.
	 *
	 * @return void
	 */
	public static function hooks(): void {
		add_action( self::PASS_HOOK, array( __CLASS__, 'on_pass' ), 10, 1 );
		add_action( self::SWEEP_HOOK, array( __CLASS__, 'on_sweep' ) );

		// A site that had the plugin dropped in rather than activated still
		// needs the sweep, and re-adding an existing schedule is a no-op.
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
	 * tidy staged files nothing refers to any more.
	 *
	 * @return void
	 */
	public static function on_sweep(): void {
		foreach ( VulnHub_Import_Jobs::resumable( 10 ) as $job ) {
			self::schedule( (int) $job['id'] );
		}

		VulnHub_Import_Storage::sweep();
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
	 * Move a prepared job into `running` and queue its first pass.
	 *
	 * @param int $job_id Job id.
	 * @return array{ok:bool,message:string}
	 */
	public static function start( int $job_id ): array {
		$job = VulnHub_Import_Jobs::get( $job_id );

		if ( ! $job ) {
			return array(
				'ok'      => false,
				'message' => __( 'That import job no longer exists.', 'vulnhub' ),
			);
		}

		if ( in_array( (string) $job['status'], array( VulnHub_Import_Jobs::RUNNING, VulnHub_Import_Jobs::DONE ), true ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'That job is already running or finished.', 'vulnhub' ),
			);
		}

		if ( ! VulnHub_Import_Storage::exists( (string) $job['storage_key'] ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'The uploaded file is no longer staged on the server. Upload it again.', 'vulnhub' ),
			);
		}

		VulnHub_Import_Jobs::update(
			$job_id,
			array(
				'status'     => VulnHub_Import_Jobs::RUNNING,
				'error'      => '',
				'started_at' => current_time( 'mysql', true ),
			)
		);

		vulnhub()->logger->audit(
			'import.start',
			sprintf(
				/* translators: 1: importer type, 2: file name. */
				__( 'Started a %1$s CSV import of %2$s', 'vulnhub' ),
				(string) $job['type'],
				(string) $job['filename']
			),
			'import_job',
			$job_id,
			array(
				'type'         => (string) $job['type'],
				'shape'        => (string) $job['shape'],
				'filename'     => (string) $job['filename'],
				'size_bytes'   => (int) $job['size_bytes'],
				'content_hash' => (string) $job['content_hash'],
				'rows_est'     => (int) $job['rows_total_estimate'],
			)
		);

		self::schedule( $job_id );

		return array(
			'ok'      => true,
			'message' => __( 'Import started.', 'vulnhub' ),
		);
	}

	/**
	 * Stop a job. Rows already imported stay imported — this is a stop, not a
	 * rollback — but the staged file goes immediately.
	 *
	 * @param int $job_id Job id.
	 * @return array{ok:bool,message:string}
	 */
	public static function cancel( int $job_id ): array {
		$job = VulnHub_Import_Jobs::get( $job_id );

		if ( ! $job ) {
			return array(
				'ok'      => false,
				'message' => __( 'That import job no longer exists.', 'vulnhub' ),
			);
		}

		if ( in_array( (string) $job['status'], array( VulnHub_Import_Jobs::DONE, VulnHub_Import_Jobs::CANCELLED, VulnHub_Import_Jobs::FAILED ), true ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'That job has already stopped.', 'vulnhub' ),
			);
		}

		self::finish( $job, VulnHub_Import_Jobs::CANCELLED, '' );

		return array(
			'ok'      => true,
			'message' => __( 'Import cancelled.', 'vulnhub' ),
		);
	}

	/**
	 * Close a job out: status, audit entry, staged file removal.
	 *
	 * @param array<string,mixed> $job    Job row.
	 * @param string              $status Terminal status.
	 * @param string              $error  Error text, if any.
	 * @return void
	 */
	private static function finish( array $job, string $status, string $error = '' ): void {
		$job_id   = (int) $job['id'];
		$counters = (array) ( $job['counters_arr'] ?? VulnHub_Import_Jobs::blank_counters() );

		VulnHub_Import_Jobs::update(
			$job_id,
			array(
				'status'       => $status,
				'error'        => mb_substr( $error, 0, 2000 ),
				'finished_at'  => current_time( 'mysql', true ),
				'locked_until' => null,
			)
		);

		VulnHub_Import_Storage::delete( (string) $job['storage_key'] );

		$hook = wp_next_scheduled( self::PASS_HOOK, array( $job_id ) );

		if ( $hook ) {
			wp_unschedule_event( (int) $hook, self::PASS_HOOK, array( $job_id ) );
		}

		if ( VulnHub_Import_Jobs::DONE === $status ) {
			/*
			 * Before the recounts, not after. A Tenable export lists the
			 * machines it scanned during the period, decommissioned ones
			 * included, and re-opens their findings -- so an estate that was
			 * tidy last night quietly grows its risk back every import. The
			 * sweep puts them away again, and running it here means the
			 * roll-up below counts the estate as it actually stands.
			 */
			\VulnHub\Core\Lifecycle::sweep();

			/*
			 * Then the duplicates, before anything is counted.
			 *
			 * `Repo::match_asset()` stops a feed writing a machine down twice,
			 * but only for the spellings it already knows -- and every export
			 * eventually invents a new one. Defender flattened five FQDNs to
			 * `nzaklp1mcapprh1-amssmp-local`; Tenable truncated names to the
			 * NetBIOS limit of 15. Each wrote a second copy of a machine the
			 * CMDB already held, and each copy reported "Not in Tenable" while
			 * its twin was scanned weekly. Sweeping here means the next import
			 * corrects it, rather than a person noticing months later.
			 */
			/*
			 * And records that stopped qualifying as assets.
			 *
			 * The creation rule keeps new paperwork out, but an asset already
			 * in the inventory can drift: the CMDB retires it, and nothing has
			 * scanned it since. Anything a scanner or sensor has touched, or
			 * that carries a finding, ticket or exception, is never taken --
			 * only rows whose sole evidence was a CI record that has now been
			 * withdrawn.
			 */
			$stale = Repo::collect_stale_assets();

			if ( $stale ) {
				( new \VulnHub\Core\Logger() )->audit(
					'asset.stale_records_collected',
					sprintf(
						/* translators: %d: number of rows held. */
						__( 'Import housekeeping held %d asset row(s) that no longer meet the CMDB existence rule.', 'vulnhub' ),
						count( $stale )
					),
					'import_job',
					$job_id,
					array( 'held' => $stale ),
					'warning'
				);
			}

			$folded = Repo::sweep_duplicates();

			if ( $folded['merged'] || $folded['skipped'] ) {
				( new \VulnHub\Core\Logger() )->audit(
					'asset.duplicates_swept',
					sprintf(
						/* translators: 1: rows folded, 2: pairs left for a person. */
						__( 'Import housekeeping folded %1$d duplicate asset row(s); %2$d pair(s) need a person.', 'vulnhub' ),
						count( $folded['merged'] ),
						count( $folded['skipped'] )
					),
					'import_job',
					$job_id,
					$folded,
					$folded['skipped'] ? 'warning' : 'info'
				);
			}

			// Asset-level severity rollups are derived, not imported; one pass
			// at the end is far cheaper than recomputing them per row.
			Repo::recalculate_asset_rollups();

			/*
			 * Ownership and team routing are decided by the rules engine, and
			 * until now it only ever ran after a *connector* sync -- so an
			 * estate loaded entirely from CSV came out with every asset on
			 * team 0 and the "Servers default to Infrastructure" rule never
			 * firing. An import changes exactly the inputs those rules read,
			 * so it has to trigger them too.
			 */
			( new Mapping() )->run();

			/*
			 * Scan coverage is derived the same way, and an import is exactly
			 * the event that changes it: a Tenable file moves assets into
			 * "covered", and every asset it does not mention is a device the
			 * scanner has never seen. Without this the whole estate reads
			 * "unknown" until the nightly housekeeping run -- which is the one
			 * night the answer actually mattered.
			 */
			Coverage::recalculate();
		}

		vulnhub()->logger->audit(
			'import.' . $status,
			sprintf(
				/* translators: 1: status, 2: file name, 3: rows imported. */
				__( 'Import %1$s: %2$s (%3$s rows read)', 'vulnhub' ),
				$status,
				(string) $job['filename'],
				number_format_i18n( (int) ( $counters['rows_read'] ?? 0 ) )
			),
			'import_job',
			$job_id,
			array(
				'status'   => $status,
				'error'    => $error,
				'counters' => array_diff_key( $counters, array( 'failures' => true ) ),
			),
			VulnHub_Import_Jobs::FAILED === $status ? 'error' : 'info'
		);
	}

	/* =================================================================
	 * The pass
	 * ============================================================== */

	/**
	 * Run one pass of a job: as many bounded batches as the budget allows.
	 *
	 * @param int   $job_id Job id.
	 * @param float $budget Seconds this process may spend.
	 * @return array{ok:bool,ran:bool,message:string,status:string,rows:int}
	 */
	public static function run( int $job_id, float $budget = 0.0 ): array {
		$idle = array(
			'ok'      => true,
			'ran'     => false,
			'message' => '',
			'status'  => '',
			'rows'    => 0,
		);

		$job = VulnHub_Import_Jobs::get( $job_id );

		if ( ! $job ) {
			return $idle;
		}

		$idle['status'] = (string) $job['status'];

		if ( VulnHub_Import_Jobs::RUNNING !== (string) $job['status'] ) {
			return $idle;
		}

		if ( $budget <= 0.0 ) {
			$budget = self::budget();
		}

		// Only one process may hold a job. The loser simply returns; it is not
		// an error, and the winner is already doing the work.
		if ( ! VulnHub_Import_Jobs::claim( $job_id, self::LEASE ) ) {
			$idle['message'] = __( 'Another pass is already running for this job.', 'vulnhub' );
			return $idle;
		}

		if ( function_exists( 'ignore_user_abort' ) ) {
			ignore_user_abort( true );
		}
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( (int) $budget + 120 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}

		$path = VulnHub_Import_Storage::path( (string) $job['storage_key'] );

		if ( '' === $path || ! is_readable( $path ) ) {
			self::finish( $job, VulnHub_Import_Jobs::FAILED, __( 'The staged file has gone from the server, so the import cannot continue.', 'vulnhub' ) );

			return array(
				'ok'      => false,
				'ran'     => false,
				'message' => __( 'The staged file has gone from the server.', 'vulnhub' ),
				'status'  => VulnHub_Import_Jobs::FAILED,
				'rows'    => 0,
			);
		}

		$plan      = (array) $job['column_map_arr'];
		$headers   = array_map( 'strval', (array) ( $plan['headers'] ?? array() ) );
		$delimiter = (string) ( $plan['delimiter'] ?? ',' );
		$map       = (array) ( $plan['map'] ?? array() );
		$shape     = (string) $job['shape'];
		$start     = (int) $job['byte_offset'] > 0 ? (int) $job['byte_offset'] : (int) ( $plan['header_offset'] ?? 0 );

		if ( ! $headers || ! $map ) {
			self::finish( $job, VulnHub_Import_Jobs::FAILED, __( 'The job has no column mapping, so nothing can be read.', 'vulnhub' ) );

			return array(
				'ok'      => false,
				'ran'     => false,
				'message' => __( 'The job has no column mapping.', 'vulnhub' ),
				'status'  => VulnHub_Import_Jobs::FAILED,
				'rows'    => 0,
			);
		}

		$counters  = (array) $job['counters_arr'];
		$rows_done = (int) $job['rows_done'];
		$reader    = new VulnHub_Import_Reader( $path, $delimiter, $headers, $start );
		$tenable   = new VulnHub_Import_Tenable();
		$deadline  = microtime( true ) + $budget;
		$began     = microtime( true );
		$rows_now  = 0;
		$eof       = false;
		$stopped   = '';

		do {
			$batch = self::batch( $shape, $map, $reader, $tenable, $counters, $rows_done );

			$rows_now                += $batch['rows'];
			$eof                      = $batch['eof'];
			$counters['rows_read']    = $rows_done;
			$counters['peak_memory']  = max( (int) $counters['peak_memory'], memory_get_peak_usage( true ) );
			$counters['seconds']      = round( (float) $counters['seconds'] + ( microtime( true ) - $began ), 2 );
			$began                    = microtime( true );
			++$counters['passes'];

			// The checkpoint. Everything above this line is now durable.
			VulnHub_Import_Jobs::update(
				$job_id,
				array(
					'byte_offset'  => $reader->offset(),
					'rows_done'    => $rows_done,
					'counters'     => (string) wp_json_encode( $counters ),
					'locked_until' => gmdate( 'Y-m-d H:i:s', time() + self::LEASE ),
				)
			);

			if ( $eof ) {
				break;
			}

			$stopped = self::current_status( $job_id );

			if ( VulnHub_Import_Jobs::RUNNING !== $stopped ) {
				break;
			}
		} while ( microtime( true ) < $deadline );

		$reader->close();

		$job = VulnHub_Import_Jobs::get( $job_id ) ?? $job;

		if ( $eof ) {
			self::finish( $job, VulnHub_Import_Jobs::DONE );

			return array(
				'ok'      => true,
				'ran'     => true,
				'message' => __( 'Import finished.', 'vulnhub' ),
				'status'  => VulnHub_Import_Jobs::DONE,
				'rows'    => $rows_now,
			);
		}

		VulnHub_Import_Jobs::release( $job_id );

		$status = self::current_status( $job_id );

		if ( VulnHub_Import_Jobs::RUNNING === $status ) {
			self::schedule( $job_id );
		}

		return array(
			'ok'      => true,
			'ran'     => true,
			'message' => '',
			'status'  => $status,
			'rows'    => $rows_now,
		);
	}

	/**
	 * The status column, read fresh — this is how a cancel reaches a pass that
	 * is already several batches deep.
	 *
	 * @param int $job_id Job id.
	 * @return string
	 */
	private static function current_status( int $job_id ): string {
		global $wpdb;

		$table = VulnHub_Import_Jobs::table();

		return (string) $wpdb->get_var( $wpdb->prepare( "SELECT status FROM {$table} WHERE id = %d", $job_id ) ); // phpcs:ignore WordPress.DB
	}

	/**
	 * Process one bounded batch.
	 *
	 * @param string                       $shape     Shape key.
	 * @param array<string,string>         $map       canonical field => header.
	 * @param VulnHub_Import_Reader        $reader    Open reader.
	 * @param VulnHub_Import_Tenable       $tenable   Tenable importer instance.
	 * @param array<string,mixed>          $counters  Counters, by reference.
	 * @param int                          $rows_done Rows read so far, by reference.
	 * @return array{rows:int,eof:bool}
	 */
	private static function batch( string $shape, array $map, VulnHub_Import_Reader $reader, VulnHub_Import_Tenable $tenable, array &$counters, int &$rows_done ): array {
		$deadline = microtime( true ) + self::BATCH_SECONDS;
		$rows     = 0;
		$eof      = false;
		$records  = array();
		$lines    = array();

		while ( $rows < self::BATCH_ROWS ) {
			$row = $reader->next();

			if ( null === $row ) {
				$eof = true;
				break;
			}

			++$rows;
			++$rows_done;

			$record = VulnHub_Import_Schema::apply( $row, $map );

			try {
				switch ( $shape ) {
					case VulnHub_Import_Schema::SHAPE_VULN:
						$tenable->import_vuln_row( $record, $rows_done, $counters );
						break;

					case VulnHub_Import_Schema::SHAPE_ASSET:
						$tenable->import_asset_row( $record, $rows_done, $counters );
						break;

					case VulnHub_Import_Schema::SHAPE_VULN_ENRICH:
						$tenable->enrich_vuln_row( $record, $rows_done, $counters );
						break;

					case VulnHub_Import_Schema::SHAPE_INTUNE:
						VulnHub_Import_Intune::import_row( $record, $rows_done, $counters );
						break;

					case VulnHub_Import_Schema::SHAPE_DEFENDER:
						VulnHub_Import_Defender::import_row( $record, $rows_done, $counters );
						break;

					default:
						$canonical = VulnHub_Import_Cmdb::map_row( $row, $map );
						$problem   = VulnHub_Import_Cmdb::validate( $canonical );

						if ( '' !== $problem ) {
							VulnHub_Import_Jobs::note_failure( $counters, $rows_done, $problem );
							break;
						}

						$records[] = $canonical;
						$lines[]   = $rows_done;
						break;
				}
			} catch ( \Throwable $e ) {
				VulnHub_Import_Jobs::note_failure( $counters, $rows_done, $e->getMessage() );
			}

			if ( microtime( true ) >= $deadline ) {
				break;
			}
		}

		if ( $records ) {
			try {
				VulnHub_Import_Cmdb::import( $records, $lines, $counters );
			} catch ( \Throwable $e ) {
				foreach ( $lines as $line ) {
					VulnHub_Import_Jobs::note_failure( $counters, (int) $line, $e->getMessage() );
				}
			}
		}

		return array(
			'rows' => $rows,
			'eof'  => $eof,
		);
	}
}

