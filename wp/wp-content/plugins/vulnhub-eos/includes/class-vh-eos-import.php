<?php
/**
 * Loading the programme's reconciliation sheet.
 *
 * The workbook is the reconciled output of four source systems; this reads the
 * Reconciled sheet as CSV and stores the fields the portal needs. It matches
 * rows to assets by hostname and NEVER creates an asset: a server that only the
 * programme knows about stays a plan row with no asset, which is itself worth
 * seeing.
 *
 * Re-importing is the normal case (the spec proposes monthly), so the import is
 * an upsert keyed on hostname and is safe to run repeatedly.
 *
 * @package VulnHub\EOS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * CSV import and asset re-linking.
 */
final class VH_EOS_Import {

	public const OPT_LAST = 'vulnhub_eos_last_import';

	/** Largest upload accepted, in bytes. The real sheet is ~40 KB. */
	private const MAX_BYTES = 8 * MB_IN_BYTES;

	/**
	 * Headers as the Reconciled sheet spells them, mapped to our columns.
	 *
	 * Matching is done on a normalised form of the header (lower-cased,
	 * non-alphanumerics collapsed), so a re-export that changes "Notes /
	 * Exceptions" to "Notes/Exceptions" still lands.
	 *
	 * @return array<string,string> normalised header => column.
	 */
	private static function column_map(): array {
		return array(
			'hostname'                 => 'hostname',
			'environment arch'         => 'environment',
			'application purpose arch' => 'purpose',
			'os arch'                  => 'os_text',
			'treatment plan project arch' => 'project',
			'timeframe arch'           => 'timeframe',
			'controls arch'            => 'controls',
			'inherent risk arch'       => 'inherent_risk',
			'residual risk arch'       => 'residual_risk',
			'jsm status'               => 'jsm_status',
			'jsm location'             => 'jsm_location',
			'state label'              => 'state',
			'environment tier'         => 'env_tier',
			'rag'                      => 'rag',
			'notes exceptions'         => 'notes',
		);
	}

	public static function init(): void {
		/*
		 * A sync that adds an asset the programme already knew about should
		 * close that gap on its own -- 34 of the programme's hosts had no
		 * asset the day this was written, and someone re-uploading the same
		 * workbook to pick up a link the scanner just created would be busy
		 * work.
		 */
		add_action( 'vulnhub_sync_complete', array( __CLASS__, 'relink' ), 20, 0 );
		add_action( 'vulnhub_import_complete', array( __CLASS__, 'relink' ), 20, 0 );
	}

	/**
	 * Normalise a header cell for matching.
	 */
	private static function norm_header( string $header ): string {
		$header = strtolower( trim( $header ) );
		$header = preg_replace( '/[^a-z0-9]+/', ' ', $header ) ?? '';

		return trim( (string) $header );
	}

	/**
	 * Normalise a hostname to the form we match and store on.
	 *
	 * Lower-cased and trimmed, and any domain suffix dropped: the workbook
	 * carries bare hostnames while some inventories carry FQDNs, and the
	 * programme's naming convention makes the first label unique.
	 */
	public static function norm_hostname( string $hostname ): string {
		$hostname = strtolower( trim( $hostname ) );
		$hostname = trim( $hostname, "\"' \t\r\n" );

		if ( false !== strpos( $hostname, '.' ) ) {
			$hostname = (string) strtok( $hostname, '.' );
		}

		return mb_substr( $hostname, 0, 191 );
	}

	/**
	 * Map the sheet's State Label to the stored vocabulary.
	 */
	public static function norm_state( string $label, string $number = '' ): string {
		$key = self::norm_header( $label );

		$map = array(
			'in support'     => 'in_support',
			'remediated'     => 'remediated',
			'planned'        => 'planned',
			'no plan'        => 'no_plan',
			'visibility gap' => 'visibility_gap',
		);

		if ( isset( $map[ $key ] ) ) {
			return $map[ $key ];
		}

		/*
		 * Fall back to the numeric State column when the label is missing or
		 * spelled differently: the spec defines the numbers, and they are the
		 * more stable of the two.
		 */
		$by_number = array(
			'0' => 'in_support',
			'1' => 'remediated',
			'2' => 'planned',
			'3' => 'no_plan',
			'4' => 'visibility_gap',
		);

		return (string) ( $by_number[ trim( $number ) ] ?? '' );
	}

	/** Critical / Lower, as stored. */
	public static function norm_tier( string $tier ): string {
		$tier = self::norm_header( $tier );

		if ( 'critical' === $tier ) {
			return 'critical';
		}

		return '' === $tier ? '' : 'lower';
	}

	/** Red / Amber / Green, as stored. */
	public static function norm_rag( string $rag ): string {
		$rag = self::norm_header( $rag );

		return in_array( $rag, array( 'red', 'amber', 'green' ), true ) ? $rag : '';
	}

	/* =================================================================
	 * Reading the file
	 * ============================================================== */

	/**
	 * Parse a CSV into plan rows without touching the database.
	 *
	 * Returns the rows it would write plus a report, so the screen can show a
	 * dry run before anyone commits to it.
	 *
	 * @param string $path File path.
	 * @return array{error?:string,rows:array<int,array<string,mixed>>,report:array<string,mixed>}
	 */
	public static function parse( string $path ): array {
		$report = array(
			'read'      => 0,
			'blank'     => 0,
			'no_state'  => 0,
			'duplicate' => 0,
			'rows'      => 0,
		);

		if ( ! is_readable( $path ) ) {
			return array(
				'error'  => __( 'That file could not be read.', 'vulnhub' ),
				'rows'   => array(),
				'report' => $report,
			);
		}

		$handle = fopen( $path, 'r' ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( ! $handle ) {
			return array(
				'error'  => __( 'That file could not be opened.', 'vulnhub' ),
				'rows'   => array(),
				'report' => $report,
			);
		}

		$header = fgetcsv( $handle );

		if ( ! $header ) {
			fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions

			return array(
				'error'  => __( 'That file is empty.', 'vulnhub' ),
				'rows'   => array(),
				'report' => $report,
			);
		}

		// Strip a UTF-8 BOM off the first header cell, or nothing matches.
		$header[0] = preg_replace( '/^\xEF\xBB\xBF/', '', (string) $header[0] );

		$map     = self::column_map();
		$columns = array();

		foreach ( $header as $i => $cell ) {
			$key = self::norm_header( (string) $cell );

			if ( isset( $map[ $key ] ) ) {
				$columns[ $map[ $key ] ] = (int) $i;
			}

			if ( 'state' === $key ) {
				$columns['state_number'] = (int) $i;
			}

			if ( 'notes arch' === $key && ! isset( $columns['notes_arch'] ) ) {
				$columns['notes_arch'] = (int) $i;
			}
		}

		if ( ! isset( $columns['hostname'] ) ) {
			fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions

			return array(
				'error'  => __( 'That file has no Hostname column — this wants the workbook\'s "Reconciled" sheet saved as CSV.', 'vulnhub' ),
				'rows'   => array(),
				'report' => $report,
			);
		}

		$rows = array();
		$seen = array();
		$now  = vh_now();

		while ( false !== ( $line = fgetcsv( $handle ) ) ) {
			++$report['read'];

			$get = static function ( string $column ) use ( $line, $columns ): string {
				if ( ! isset( $columns[ $column ] ) ) {
					return '';
				}

				return trim( (string) ( $line[ $columns[ $column ] ] ?? '' ) );
			};

			$hostname = self::norm_hostname( $get( 'hostname' ) );

			/*
			 * The sheet is padded with empty rows below the data. They are not
			 * errors and should not be reported as skipped records.
			 */
			if ( '' === $hostname && '' === implode( '', array_map( 'trim', array_map( 'strval', $line ) ) ) ) {
				++$report['blank'];
				continue;
			}

			if ( '' === $hostname ) {
				++$report['blank'];
				continue;
			}

			$state = self::norm_state( $get( 'state' ), $get( 'state_number' ) );

			/*
			 * A row with a hostname but no state has not been through the
			 * programme's assessment. Counting it as "no plan" would invent a
			 * finding the programme never made.
			 */
			if ( '' === $state ) {
				++$report['no_state'];
				continue;
			}

			if ( isset( $seen[ $hostname ] ) ) {
				++$report['duplicate'];
				continue;
			}

			$seen[ $hostname ] = true;

			$notes = $get( 'notes' );
			$arch  = $get( 'notes_arch' );

			if ( '' !== $arch ) {
				$notes = '' === $notes ? $arch : $notes . "\n" . $arch;
			}

			$timeframe = $get( 'timeframe' );

			$rows[] = array(
				'hostname'      => $hostname,
				'environment'   => mb_substr( $get( 'environment' ), 0, 64 ),
				'purpose'       => mb_substr( $get( 'purpose' ), 0, 191 ),
				'os_text'       => mb_substr( $get( 'os_text' ), 0, 191 ),
				'project'       => mb_substr( $get( 'project' ), 0, 191 ),
				'timeframe'     => mb_substr( $timeframe, 0, 32 ),
				'deadline'      => VH_EOS_Repo::deadline_for( $timeframe ),
				'state'         => $state,
				'env_tier'      => self::norm_tier( $get( 'env_tier' ) ),
				'rag'           => self::norm_rag( $get( 'rag' ) ),
				'controls'      => mb_substr( $get( 'controls' ), 0, 191 ),
				'inherent_risk' => mb_substr( $get( 'inherent_risk' ), 0, 32 ),
				'residual_risk' => mb_substr( $get( 'residual_risk' ), 0, 32 ),
				'jsm_status'    => mb_substr( $get( 'jsm_status' ), 0, 64 ),
				'jsm_location'  => mb_substr( $get( 'jsm_location' ), 0, 128 ),
				'notes'         => $notes,
				'updated_at'    => $now,
			);
		}

		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		$report['rows'] = count( $rows );

		return array(
			'rows'   => $rows,
			'report' => $report,
		);
	}

	/**
	 * Parse a file and report what an import would do, without writing.
	 *
	 * @return array<string,mixed>
	 */
	public static function dry_run( string $path, string $filename = '' ): array {
		$parsed = self::parse( $path );

		if ( isset( $parsed['error'] ) ) {
			return $parsed;
		}

		$matches   = self::match_assets( array_column( $parsed['rows'], 'hostname' ) );
		$unmatched = array();
		$coverage  = array(
			VH_EOS_Repo::COVERED   => 0,
			VH_EOS_Repo::OVERDUE   => 0,
			VH_EOS_Repo::UNCOVERED => 0,
		);

		foreach ( $parsed['rows'] as $row ) {
			if ( empty( $matches[ $row['hostname'] ] ) ) {
				$unmatched[] = $row['hostname'];
			}

			++$coverage[ VH_EOS_Repo::coverage_for_row( $row ) ];
		}

		return array(
			'filename'  => $filename,
			'rows'      => $parsed['report']['rows'],
			'report'    => $parsed['report'],
			'matched'   => count( $parsed['rows'] ) - count( $unmatched ),
			'unmatched' => $unmatched,
			'coverage'  => $coverage,
			'dry_run'   => true,
		);
	}

	/* =================================================================
	 * Writing
	 * ============================================================== */

	/**
	 * Import a CSV: upsert every row, link what matches an asset, and record
	 * what happened.
	 *
	 * @param string $path     File path.
	 * @param string $filename Original name, for the record.
	 * @return array<string,mixed> The import report (see OPT_LAST).
	 */
	public static function import_file( string $path, string $filename = '' ): array {
		global $wpdb;

		if ( ! VH_EOS_Schema::ready() ) {
			VH_EOS_Schema::install();
		}

		$parsed = self::parse( $path );

		if ( isset( $parsed['error'] ) ) {
			return $parsed;
		}

		$table   = VH_EOS_Schema::table();
		$batch   = substr( (string) wp_generate_uuid4(), 0, 32 );
		$now     = vh_now();
		$matches = self::match_assets( array_column( $parsed['rows'], 'hostname' ) );

		$imported  = 0;
		$updated   = 0;
		$unmatched = array();
		$coverage  = array(
			VH_EOS_Repo::COVERED   => 0,
			VH_EOS_Repo::OVERDUE   => 0,
			VH_EOS_Repo::UNCOVERED => 0,
		);

		foreach ( $parsed['rows'] as $row ) {
			$hostname = (string) $row['hostname'];
			$asset_id = (int) ( $matches[ $hostname ] ?? 0 );

			if ( 0 === $asset_id ) {
				$unmatched[] = $hostname;
			}

			++$coverage[ VH_EOS_Repo::coverage_for_row( $row ) ];

			$row['asset_id'] = $asset_id;
			$row['batch_id'] = $batch;

			$existing = (int) $wpdb->get_var( // phpcs:ignore WordPress.DB
				$wpdb->prepare( "SELECT id FROM {$table} WHERE hostname = %s", $hostname ) // phpcs:ignore WordPress.DB
			);

			if ( $existing ) {
				$wpdb->update( $table, $row, array( 'id' => $existing ) ); // phpcs:ignore WordPress.DB
				++$updated;
				continue;
			}

			$row['imported_at'] = $now;

			$wpdb->insert( $table, $row ); // phpcs:ignore WordPress.DB
			++$imported;
		}

		$report = array(
			'at'         => $now,
			'file'       => $filename,
			'batch'      => $batch,
			'rows'       => (int) $parsed['report']['rows'],
			'read'       => (int) $parsed['report']['read'],
			'blank'      => (int) $parsed['report']['blank'],
			'no_state'   => (int) $parsed['report']['no_state'],
			'duplicate'  => (int) $parsed['report']['duplicate'],
			'imported'   => $imported,
			'updated'    => $updated,
			'matched'    => count( $parsed['rows'] ) - count( $unmatched ),
			'unmatched'  => $unmatched,
			'coverage'   => $coverage,
		);

		update_option( self::OPT_LAST, $report, false );

		if ( function_exists( 'vulnhub' ) && isset( vulnhub()->logger ) ) {
			vulnhub()->logger->audit(
				'eos.import',
				sprintf(
					/* translators: 1: rows imported, 2: rows updated, 3: rows with no matching asset. */
					__( 'EOS programme import: %1$d new, %2$d updated, %3$d with no matching asset.', 'vulnhub' ),
					$imported,
					$updated,
					count( $unmatched )
				),
				'eos_plan',
				$batch,
				$report
			);
		}

		/*
		 * The widget reads this data, and its rendered HTML is cached. Without
		 * a bust the board keeps yesterday's split until something else
		 * happens to invalidate it.
		 */
		if ( class_exists( 'VulnHub_Dash_Widgets' ) ) {
			VulnHub_Dash_Widgets::bust();
		}

		return $report;
	}

	/**
	 * Asset ids for a list of normalised hostnames.
	 *
	 * Matches on the asset's own hostname, and on the first label of its FQDN
	 * so an inventory that stores `host.example.net` still links.
	 *
	 * @param array<int,string> $hostnames Normalised hostnames.
	 * @return array<string,int> hostname => asset id.
	 */
	public static function match_assets( array $hostnames ): array {
		global $wpdb;

		$hostnames = array_values( array_unique( array_filter( array_map( 'strval', $hostnames ) ) ) );

		if ( ! $hostnames ) {
			return array();
		}

		$a   = vh_table( 'assets' );
		$out = array();

		/*
		 * Chunked: one IN list per 500 hostnames keeps the query inside every
		 * server's placeholder and packet limits, whatever the sheet grows to.
		 */
		foreach ( array_chunk( $hostnames, 500 ) as $chunk ) {
			$placeholders = implode( ',', array_fill( 0, count( $chunk ), '%s' ) );

			$rows = (array) $wpdb->get_results( // phpcs:ignore WordPress.DB
				$wpdb->prepare(
					"SELECT id, LOWER(hostname) AS host, LOWER(SUBSTRING_INDEX(fqdn, '.', 1)) AS fqdn_host
					 FROM {$a}
					 WHERE LOWER(hostname) IN ( {$placeholders} )
						OR LOWER(SUBSTRING_INDEX(fqdn, '.', 1)) IN ( {$placeholders} )", // phpcs:ignore WordPress.DB
					array_merge( $chunk, $chunk )
				),
				ARRAY_A
			);

			foreach ( $rows as $row ) {
				foreach ( array( (string) $row['host'], (string) $row['fqdn_host'] ) as $candidate ) {
					if ( '' !== $candidate && in_array( $candidate, $chunk, true ) && empty( $out[ $candidate ] ) ) {
						$out[ $candidate ] = (int) $row['id'];
					}
				}
			}
		}

		return $out;
	}

	/**
	 * Re-match plan rows that had no asset when they were imported.
	 *
	 * Cheap when there is nothing to do: one indexed count, then nothing.
	 *
	 * @return int Rows newly linked.
	 */
	public static function relink(): int {
		global $wpdb;

		if ( ! VH_EOS_Schema::ready() ) {
			return 0;
		}

		$table = VH_EOS_Schema::table();

		$pending = array_map(
			'strval',
			(array) $wpdb->get_col( "SELECT hostname FROM {$table} WHERE asset_id = 0" ) // phpcs:ignore WordPress.DB
		);

		if ( ! $pending ) {
			return 0;
		}

		$matches = self::match_assets( $pending );
		$linked  = 0;

		foreach ( $matches as $hostname => $asset_id ) {
			if ( $asset_id <= 0 ) {
				continue;
			}

			$wpdb->update( // phpcs:ignore WordPress.DB
				$table,
				array(
					'asset_id'   => (int) $asset_id,
					'updated_at' => vh_now(),
				),
				array( 'hostname' => $hostname )
			);

			++$linked;
		}

		if ( $linked > 0 && class_exists( 'VulnHub_Dash_Widgets' ) ) {
			VulnHub_Dash_Widgets::bust();
		}

		return $linked;
	}

	/**
	 * Largest upload accepted.
	 */
	public static function max_bytes(): int {
		return self::MAX_BYTES;
	}
}
