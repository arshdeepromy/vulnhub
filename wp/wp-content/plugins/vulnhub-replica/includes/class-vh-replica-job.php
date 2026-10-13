<?php
/**
 * Source side: build one sync package for one copy.
 *
 * A job is asked for by a copy, which sends the fingerprints of what it
 * already holds. The job then works out what differs, writes the differing
 * rows out table by table as gzip'd JSON lines, zips them, and cuts the zip
 * into fixed-size chunks with a SHA-256 each. The copy learns the chunk
 * count, every chunk's size and the total before it downloads a byte.
 *
 * The work is done in time slices, each one driven by a request from the
 * copy: no step depends on this instance's own cron (which may be busy for
 * an hour with a scanner import), no request runs long enough to meet a
 * proxy timeout, and the copy can show exactly how far along the source is.
 * Everything a slice needs to continue is in job.json, so a slice that dies
 * loses at most its own work.
 *
 * @package VulnHub\Replica
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * One package build on the source.
 */
final class VulnHub_Replica_Job {

	/** Seconds of work per slice. */
	private const SLICE = 20;

	/** Rows per read while writing a table out. */
	private const BATCH = 2000;

	/** Untouched jobs are swept after this long. */
	private const TTL = DAY_IN_SECONDS;

	/** Chunk size bounds, bytes. */
	public const CHUNK_MIN     = 1048576;
	public const CHUNK_MAX     = 67108864;
	public const CHUNK_DEFAULT = 8388608;

	/** @var array<string,mixed> */
	private array $job;

	private string $dir;

	/**
	 * @param array<string,mixed> $job State.
	 */
	private function __construct( array $job, string $dir ) {
		$this->job = $job;
		$this->dir = $dir;
	}

	public static function root(): string {
		return VulnHub_Replica_Schema::dir( 'out' );
	}

	private static function valid_id( string $id ): bool {
		return (bool) preg_match( '/^[a-z0-9]{24}$/', $id );
	}

	/* -----------------------------------------------------------------
	 * Lifecycle
	 * --------------------------------------------------------------- */

	/**
	 * Start a job from a copy's request.
	 *
	 * @param array<string,mixed> $request {schema, fingerprints, chunk_size}.
	 */
	public static function create( int $token_id, array $request ): self {
		self::sweep();
		// One live job per key: a copy that starts again has given up on its
		// last package, and keeping both would only double the disk.
		self::drop_for_token( $token_id );

		$id  = strtolower( wp_generate_password( 24, false, false ) );
		$dir = self::root() . '/' . $id;
		wp_mkdir_p( $dir );

		$chunk = (int) ( $request['chunk_size'] ?? self::CHUNK_DEFAULT );
		$chunk = max( self::CHUNK_MIN, min( self::CHUNK_MAX, $chunk ) );

		// What the copy holds is only needed by the first step; keep it out
		// of job.json, which is rewritten after every slice.
		file_put_contents( // phpcs:ignore WordPress.WP.AlternativeFunctions
			$dir . '/copy.json',
			(string) wp_json_encode(
				array(
					'schema'       => (array) ( $request['schema'] ?? array() ),
					'fingerprints' => (array) ( $request['fingerprints'] ?? array() ),
				)
			)
		);

		$order = array_keys( VulnHub_Replica_Schema::tables() );

		$job = new self(
			array(
				'id'           => $id,
				'token_id'     => $token_id,
				'created'      => time(),
				'touched'      => time(),
				'status'       => 'building',
				'error'        => '',
				'step'         => 'compare',
				'chunk_size'   => $chunk,
				'width'        => VulnHub_Replica_Schema::BUCKET_WIDTH,
				'order'        => $order,
				'ti'           => 0,
				'ri'           => 0,
				'last'         => null,
				'offset'       => 0,
				'tables'       => array(),
				'skipped'      => array(),
				'rows_planned' => 0,
				'rows_written' => 0,
				'weight_done'  => 0,
				'weight_total' => 0,
				'manifest'     => null,
			),
			$dir
		);

		// Weight the compare step by table size, so its share of the bar
		// moves as the work does rather than table by table.
		$weight = 0;
		foreach ( VulnHub_Replica_Schema::tables() as $info ) {
			$weight += max( 1, (int) $info['rows'] );
		}
		$job->job['weight_total'] = $weight;
		$job->save();

		return $job;
	}

	public static function load( string $id, int $token_id ): ?self {
		if ( ! self::valid_id( $id ) ) {
			return null;
		}
		$dir  = self::root() . '/' . $id;
		$file = $dir . '/job.json';
		if ( ! is_readable( $file ) ) {
			return null;
		}
		$job = json_decode( (string) file_get_contents( $file ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( ! is_array( $job ) || (int) ( $job['token_id'] ?? 0 ) !== $token_id ) {
			return null; // Another key's job is not this key's business.
		}
		return new self( $job, $dir );
	}

	private function save(): void {
		$this->job['touched'] = time();
		$tmp                  = $this->dir . '/job.json.tmp';
		file_put_contents( $tmp, (string) wp_json_encode( $this->job ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		rename( $tmp, $this->dir . '/job.json' );
	}

	public function delete(): void {
		VulnHub_Replica_Schema::rmdir( $this->dir );
	}

	public static function drop_for_token( int $token_id ): void {
		foreach ( self::all() as $job ) {
			if ( (int) ( $job['token_id'] ?? 0 ) === $token_id ) {
				VulnHub_Replica_Schema::rmdir( self::root() . '/' . $job['id'] );
			}
		}
	}

	/**
	 * Remove jobs nobody has touched for a day: a copy that went away
	 * mid-download must not leave a package on disk for ever.
	 */
	public static function sweep(): int {
		$n = 0;
		foreach ( self::all() as $job ) {
			if ( (int) ( $job['touched'] ?? 0 ) < time() - self::TTL ) {
				VulnHub_Replica_Schema::rmdir( self::root() . '/' . $job['id'] );
				++$n;
			}
		}
		return $n;
	}

	/**
	 * Every job on disk, newest first, for the admin screen.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function all(): array {
		$out  = array();
		$root = self::root();
		foreach ( (array) scandir( $root ) as $id ) {
			if ( ! self::valid_id( (string) $id ) ) {
				continue;
			}
			$file = $root . '/' . $id . '/job.json';
			if ( ! is_readable( $file ) ) {
				// A directory with no state is a create that died: sweep it.
				if ( filemtime( $root . '/' . $id ) < time() - HOUR_IN_SECONDS ) {
					VulnHub_Replica_Schema::rmdir( $root . '/' . $id );
				}
				continue;
			}
			$job = json_decode( (string) file_get_contents( $file ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			if ( is_array( $job ) ) {
				$out[] = $job;
			}
		}
		usort( $out, static fn( $a, $b ) => (int) $b['created'] <=> (int) $a['created'] );
		return $out;
	}

	/* -----------------------------------------------------------------
	 * Status
	 * --------------------------------------------------------------- */

	/**
	 * Where the build is, in numbers a progress bar can use.
	 *
	 * @return array<string,mixed>
	 */
	public function status(): array {
		$j    = $this->job;
		$step = (string) $j['step'];

		// Compare 0-35%, write 35-95%, zip and hash 95-100%.
		$pct  = 0.0;
		$note = '';
		if ( 'compare' === $step ) {
			$pct  = 35 * ( (int) $j['weight_done'] / max( 1, (int) $j['weight_total'] ) );
			$note = sprintf( 'Comparing tables (%d of %d)', min( (int) $j['ti'] + 1, count( $j['order'] ) ), count( $j['order'] ) );
		} elseif ( 'export' === $step ) {
			$pct  = 35 + 60 * ( (int) $j['rows_written'] / max( 1, (int) $j['rows_planned'] ) );
			$note = sprintf( 'Writing changed rows (%s of %s)', number_format( (int) $j['rows_written'] ), number_format( (int) $j['rows_planned'] ) );
		} elseif ( 'pack' === $step ) {
			$pct  = 95;
			$note = 'Zipping and cutting into chunks';
		} elseif ( 'ready' === $step ) {
			$pct  = 100;
			$note = 'Package ready';
		}

		$out = array(
			'job'    => (string) $j['id'],
			'status' => (string) $j['status'],
			'step'   => $step,
			'pct'    => round( min( 100, $pct ), 1 ),
			'note'   => $note,
			'error'  => (string) $j['error'],
		);
		if ( 'ready' === $j['status'] ) {
			$out['manifest'] = $j['manifest'];
		}
		return $out;
	}

	/* -----------------------------------------------------------------
	 * Work
	 * --------------------------------------------------------------- */

	/**
	 * Do one slice of work. Safe to call concurrently: a second caller
	 * finds the lock held and is told to come back.
	 *
	 * @return array<string,mixed>
	 */
	public function step(): array {
		if ( 'building' !== $this->job['status'] ) {
			return $this->status();
		}

		$lock = fopen( $this->dir . '/job.lock', 'c' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( ! $lock || ! flock( $lock, LOCK_EX | LOCK_NB ) ) {
			$s         = $this->status();
			$s['busy'] = true;
			return $s;
		}

		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 300 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
		@ini_set( 'memory_limit', '512M' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors,WordPress.PHP.IniSet.memory_limit_Disallowed

		$until = microtime( true ) + self::SLICE;

		try {
			while ( microtime( true ) < $until && 'building' === $this->job['status'] ) {
				switch ( $this->job['step'] ) {
					case 'compare':
						$this->compare_next();
						break;
					case 'export':
						$this->export_some( $until );
						break;
					case 'pack':
						$this->pack();
						break 2;
					default:
						break 2;
				}
				$this->save();
			}
		} catch ( \Throwable $e ) {
			$this->job['status'] = 'failed';
			$this->job['error']  = $e->getMessage();
		}

		$this->save();
		flock( $lock, LOCK_UN );
		fclose( $lock ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		return $this->status();
	}

	/**
	 * Fingerprint the next table and decide what of it the copy needs.
	 */
	private function compare_next(): void {
		$order = (array) $this->job['order'];
		$ti    = (int) $this->job['ti'];

		if ( $ti >= count( $order ) ) {
			$this->job['step'] = 'export';
			$this->job['ti']   = 0;
			$this->job['ri']   = 0;
			$this->job['last'] = null;
			return;
		}

		static $copy = null;
		if ( null === $copy ) {
			$copy = json_decode( (string) file_get_contents( $this->dir . '/copy.json' ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			$copy = is_array( $copy ) ? $copy : array();
		}

		$short  = (string) $order[ $ti ];
		$tables = VulnHub_Replica_Schema::tables();
		$info   = $tables[ $short ] ?? null;
		$theirs = $copy['schema'][ $short ] ?? null;

		$this->job['ti']           = $ti + 1;
		$this->job['weight_done'] += max( 1, (int) ( $info['rows'] ?? 1 ) );

		if ( ! $info ) {
			return;
		}
		if ( ! is_array( $theirs ) ) {
			$this->job['skipped'][] = array( 'table' => $short, 'why' => 'The copy does not have this table. Update its code to match.' );
			return;
		}

		$cols = VulnHub_Replica_Schema::shared_columns( $info['cols'], (array) ( $theirs['cols'] ?? array() ) );
		if ( ! $cols ) {
			$this->job['skipped'][] = array( 'table' => $short, 'why' => 'No columns in common.' );
			return;
		}
		$pk = (array) $info['pk'];
		if ( array_diff( $pk, $cols ) ) {
			$this->job['skipped'][] = array( 'table' => $short, 'why' => 'The key columns differ between the two instances.' );
			return;
		}

		$same_key = $pk === (array) ( $theirs['pk'] ?? array() );
		$mode     = ( $info['int_pk'] && $same_key ) ? 'buckets' : 'table';
		$mine     = VulnHub_Replica_Schema::fingerprint( $short, $cols, (string) $pk[0], $mode, (string) $info['update_time'] );
		$total    = 0;
		foreach ( $mine as $fp ) {
			$total += (int) $fp[0];
		}

		$theirs_fp = (array) ( $copy['fingerprints'][ $short ] ?? array() );
		$entry     = array(
			'table' => $short,
			'cols'  => $cols,
			'pk'    => $pk,
			'total' => $total,
		);

		if ( 'buckets' === $mode && 'buckets' === ( $theirs['mode'] ?? '' ) ) {
			$changed = array();
			foreach ( array_unique( array_merge( array_keys( $mine ), array_keys( $theirs_fp ) ) ) as $b ) {
				$a = $mine[ $b ] ?? null;
				$c = $theirs_fp[ $b ] ?? null;
				if ( ! $a || ! $c || (int) $a[0] !== (int) $c[0] || (string) $a[1] !== (string) $c[1] ) {
					$changed[] = (int) $b;
				}
			}
			if ( ! $changed ) {
				return; // Identical.
			}
			sort( $changed );

			$rows = 0;
			foreach ( $changed as $b ) {
				$rows += (int) ( $mine[ (string) $b ][0] ?? 0 );
			}

			$entry['mode']   = 'ranges';
			$entry['ranges'] = self::ranges( $changed, (int) $this->job['width'], $mine );
			$entry['rows']   = $rows;
		} else {
			$a = $mine['all'] ?? array( 0, '0' );
			if ( 'buckets' === $mode ) {
				// The copy cannot bucket this table its way: compare whole.
				$a = array( $total, '' );
			}
			$c = $theirs_fp['all'] ?? null;
			if ( $c && (int) $a[0] === (int) $c[0] && (string) $a[1] === (string) $c[1] ) {
				return; // Identical.
			}
			$entry['mode'] = 'replace';
			$entry['rows'] = $total;
		}

		$entry['file']            = $short . '.ndjson.gz';
		$entry['written']         = 0;
		$this->job['tables'][]    = $entry;
		$this->job['rows_planned'] = (int) $this->job['rows_planned'] + (int) $entry['rows'];
	}

	/**
	 * Contiguous changed buckets as key ranges [from, to).
	 *
	 * Neighbours are merged, but only up to a few thousand rows: a range is
	 * one transaction on the copy and its unit of resumption, and on a
	 * first sync every bucket has changed -- unmerged that is a thousand
	 * tiny statements, merged without a cap it is one transaction holding
	 * the whole table.
	 *
	 * @param array<int,int>                     $buckets Sorted bucket numbers.
	 * @param array<string,array{0:int,1:string}> $counts  This side's fingerprints.
	 * @return array<int,array{0:int,1:int}>
	 */
	private static function ranges( array $buckets, int $width, array $counts ): array {
		$cap  = 5000;
		$out  = array();
		$rows = 0;
		foreach ( $buckets as $b ) {
			$from = $b * $width;
			$to   = ( $b + 1 ) * $width;
			$n    = (int) ( $counts[ (string) $b ][0] ?? 0 );
			$last = count( $out ) - 1;
			if ( $last >= 0 && $out[ $last ][1] === $from && $rows + $n <= $cap ) {
				$out[ $last ][1] = $to;
				$rows           += $n;
			} else {
				$out[] = array( $from, $to );
				$rows  = $n;
			}
		}
		return $out;
	}

	/**
	 * Write rows out until the slice is spent.
	 */
	private function export_some( float $until ): void {
		global $wpdb;

		$tables = (array) $this->job['tables'];
		$ti     = (int) $this->job['ti'];

		if ( $ti >= count( $tables ) ) {
			$this->write_options();
			$this->job['step'] = 'pack';
			return;
		}

		$t     = $tables[ $ti ];
		$table = VulnHub_Replica_Schema::ident( VulnHub_Replica_Schema::full( (string) $t['table'] ) );
		$cols  = implode( ', ', array_map( array( 'VulnHub_Replica_Schema', 'ident' ), (array) $t['cols'] ) );
		$gz    = gzopen( $this->dir . '/' . $t['file'], 'ab6' );
		if ( ! $gz ) {
			throw new \RuntimeException( 'Could not write the package.' );
		}

		$written = 0;

		while ( microtime( true ) < $until ) {
			if ( 'ranges' === $t['mode'] ) {
				$ranges = (array) $t['ranges'];
				$ri     = (int) $this->job['ri'];
				if ( $ri >= count( $ranges ) ) {
					break;
				}
				$pk   = VulnHub_Replica_Schema::ident( (string) $t['pk'][0] );
				$from = (int) $ranges[ $ri ][0];
				$to   = (int) $ranges[ $ri ][1];
				$last = $this->job['last'];
				$sql  = "SELECT {$cols} FROM {$table} WHERE {$pk} >= {$from} AND {$pk} < {$to}"
					. ( null !== $last ? " AND {$pk} > " . (int) $last : '' )
					. " ORDER BY {$pk} LIMIT " . self::BATCH;
				$rows = (array) $wpdb->get_results( $sql, ARRAY_N ); // phpcs:ignore WordPress.DB.PreparedSQL -- identifiers checked, integers cast.
				if ( $wpdb->last_error ) {
					throw new \RuntimeException( 'Reading ' . $t['table'] . ': ' . $wpdb->last_error );
				}
				$pk_at = array_search( (string) $t['pk'][0], (array) $t['cols'], true );
				foreach ( $rows as $r ) {
					gzwrite( $gz, VulnHub_Replica_Schema::encode_row( $r ) . "\n" );
				}
				$written += count( $rows );
				if ( count( $rows ) < self::BATCH ) {
					$this->job['ri']   = $ri + 1;
					$this->job['last'] = null;
				} else {
					$this->job['last'] = (int) $rows[ count( $rows ) - 1 ][ (int) $pk_at ];
				}
			} else {
				$order  = implode( ', ', array_map( array( 'VulnHub_Replica_Schema', 'ident' ), (array) $t['pk'] ) );
				$offset = (int) $this->job['offset'];
				if ( 1 === count( (array) $t['pk'] ) ) {
					// One key column: page by key, not by offset. OFFSET re-reads
					// every row it skips, so on a large table the last page costs
					// as much as all the pages before it.
					$last = $this->job['last'];
					$sql  = "SELECT {$cols} FROM {$table}"
						. ( null !== $last ? " WHERE {$order} > '" . esc_sql( (string) $last ) . "'" : '' )
						. " ORDER BY {$order} LIMIT " . self::BATCH;
				} else {
					$sql = "SELECT {$cols} FROM {$table} ORDER BY {$order} LIMIT " . self::BATCH . " OFFSET {$offset}";
				}
				$rows   = (array) $wpdb->get_results( $sql, ARRAY_N ); // phpcs:ignore WordPress.DB.PreparedSQL -- identifiers checked, integers cast.
				if ( $wpdb->last_error ) {
					throw new \RuntimeException( 'Reading ' . $t['table'] . ': ' . $wpdb->last_error );
				}
				foreach ( $rows as $r ) {
					gzwrite( $gz, VulnHub_Replica_Schema::encode_row( $r ) . "\n" );
				}
				$written                += count( $rows );
				$this->job['offset']     = $offset + count( $rows );
				if ( $rows && 1 === count( (array) $t['pk'] ) ) {
					$at                = (int) array_search( (string) $t['pk'][0], (array) $t['cols'], true );
					$this->job['last'] = (string) $rows[ count( $rows ) - 1 ][ $at ];
				}
				if ( count( $rows ) < self::BATCH ) {
					$this->job['ri'] = PHP_INT_MAX; // Done.
					break;
				}
			}
		}

		gzclose( $gz );

		$this->job['tables'][ $ti ]['written'] = (int) $t['written'] + $written;
		$this->job['rows_written']             = (int) $this->job['rows_written'] + $written;

		$done = 'ranges' === $t['mode']
			? (int) $this->job['ri'] >= count( (array) $t['ranges'] )
			: PHP_INT_MAX === (int) $this->job['ri'];

		if ( $done ) {
			// What was actually written is what the copy will count against;
			// rows that arrived since the compare are simply included.
			$this->job['tables'][ $ti ]['rows'] = (int) $this->job['tables'][ $ti ]['written'];
			$this->job['ti']                    = $ti + 1;
			$this->job['ri']                    = 0;
			$this->job['last']                  = null;
			$this->job['offset']                = 0;
		}
	}

	private function write_options(): void {
		file_put_contents( // phpcs:ignore WordPress.WP.AlternativeFunctions
			$this->dir . '/options.json',
			(string) wp_json_encode( VulnHub_Replica_Schema::export_options() )
		);
	}

	/**
	 * Zip the table files, cut the zip into chunks and fingerprint each.
	 *
	 * The table files are already gzip'd, so they are stored in the zip, not
	 * compressed again: that would cost minutes of CPU for nothing.
	 */
	private function pack(): void {
		$tables = array();
		$total  = 0;
		foreach ( (array) $this->job['tables'] as $t ) {
			$tables[] = array(
				'table'  => $t['table'],
				'mode'   => $t['mode'],
				'cols'   => $t['cols'],
				'pk'     => $t['pk'],
				'ranges' => $t['ranges'] ?? array(),
				'rows'   => (int) $t['rows'],
				'total'  => (int) $t['total'],
				'file'   => $t['file'],
			);
			$total += (int) $t['rows'];
		}

		$inner = array(
			'format'    => 1,
			'instance'  => VulnHub_Replica_Schema::instance_id(),
			'built_at'  => vh_now(),
			'width'     => (int) $this->job['width'],
			'versions'  => VulnHub_Replica_Schema::versions(),
			'tables'    => $tables,
			'skipped'   => $this->job['skipped'],
			'records'   => $total,
			'runs'      => self::last_runs(),
		);
		file_put_contents( $this->dir . '/manifest.json', (string) wp_json_encode( $inner ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		$zip_path = $this->dir . '/package.zip';
		@unlink( $zip_path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$zip = new \ZipArchive();
		if ( true !== $zip->open( $zip_path, \ZipArchive::CREATE | \ZipArchive::OVERWRITE ) ) {
			throw new \RuntimeException( 'Could not create the zip.' );
		}
		$files = array( 'manifest.json', 'options.json' );
		foreach ( $tables as $t ) {
			if ( file_exists( $this->dir . '/' . $t['file'] ) ) {
				$files[] = $t['file'];
			} else {
				// A range whose rows have all gone is still a range to clear.
				$gz = gzopen( $this->dir . '/' . $t['file'], 'wb6' );
				gzclose( $gz );
				$files[] = $t['file'];
			}
		}
		foreach ( $files as $f ) {
			$zip->addFile( $this->dir . '/' . $f, $f );
			$zip->setCompressionName( $f, str_ends_with( $f, '.gz' ) ? \ZipArchive::CM_STORE : \ZipArchive::CM_DEFLATE );
		}
		if ( ! $zip->close() ) {
			throw new \RuntimeException( 'Could not finish the zip.' );
		}
		foreach ( $files as $f ) {
			@unlink( $this->dir . '/' . $f ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
		@unlink( $this->dir . '/copy.json' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors

		// Chunks are byte ranges of the one zip, hashed as they will be sent.
		$size   = (int) filesize( $zip_path );
		$csize  = (int) $this->job['chunk_size'];
		$chunks = array();
		$whole  = hash_init( 'sha256' );
		$fh     = fopen( $zip_path, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		for ( $n = 0; $n * $csize < $size; $n++ ) {
			$h    = hash_init( 'sha256' );
			$left = min( $csize, $size - $n * $csize );
			$len  = $left;
			while ( $left > 0 ) {
				$buf = (string) fread( $fh, min( 1048576, $left ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions
				if ( '' === $buf ) {
					break;
				}
				hash_update( $h, $buf );
				hash_update( $whole, $buf );
				$left -= strlen( $buf );
			}
			$chunks[] = array(
				'n'      => $n,
				'bytes'  => $len,
				'sha256' => hash_final( $h ),
			);
		}
		fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		$summary = array();
		foreach ( $tables as $t ) {
			$summary[] = array(
				'table' => $t['table'],
				'mode'  => $t['mode'],
				'rows'  => $t['rows'],
			);
		}

		$this->job['manifest'] = array(
			'job'         => (string) $this->job['id'],
			'bytes_total' => $size,
			'chunk_size'  => $csize,
			'chunk_count' => count( $chunks ),
			'chunks'      => $chunks,
			'sha256'      => hash_final( $whole ),
			'records'     => $total,
			'tables'      => $summary,
			'skipped'     => $this->job['skipped'],
		);
		$this->job['step']   = 'ready';
		$this->job['status'] = 'ready';
	}

	/**
	 * Each connector's last finished run here, so a copy can say when the
	 * data it holds was last refreshed at the source rather than "never".
	 *
	 * @return array<int,array<string,mixed>>
	 */
	private static function last_runs(): array {
		global $wpdb;

		$t = vh_table( 'sync_runs' );
		return (array) $wpdb->get_results(
			"SELECT r.connector, r.status, r.started_at, r.finished_at, r.duration_ms, r.processed, r.created, r.updated, r.skipped, r.failed, r.message
			 FROM {$t} r JOIN ( SELECT MAX(id) AS id FROM {$t} WHERE finished_at IS NOT NULL AND connector <> 'replica' GROUP BY connector ) m ON m.id = r.id",
			ARRAY_A
		);
	}

	/* -----------------------------------------------------------------
	 * Download
	 * --------------------------------------------------------------- */

	/**
	 * Send chunk $n as raw bytes and stop. Never returns.
	 */
	public function send_chunk( int $n ): void {
		$m = (array) $this->job['manifest'];
		if ( 'ready' !== $this->job['status'] || ! isset( $m['chunks'][ $n ] ) ) {
			status_header( 404 );
			exit;
		}
		$chunk = $m['chunks'][ $n ];
		$path  = $this->dir . '/package.zip';
		$fh    = fopen( $path, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( ! $fh ) {
			status_header( 410 );
			exit;
		}

		$this->save(); // A download in progress is a job still in use.

		while ( ob_get_level() ) {
			ob_end_clean();
		}
		status_header( 200 );
		header( 'Content-Type: application/octet-stream' );
		header( 'Content-Length: ' . (int) $chunk['bytes'] );
		header( 'X-VulnHub-Chunk: ' . $n . '/' . count( $m['chunks'] ) );
		header( 'X-VulnHub-Chunk-Sha256: ' . $chunk['sha256'] );
		header( 'Cache-Control: no-store' );

		fseek( $fh, $n * (int) $m['chunk_size'] );
		$left = (int) $chunk['bytes'];
		while ( $left > 0 && ! feof( $fh ) ) {
			$buf = (string) fread( $fh, min( 1048576, $left ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			echo $buf; // phpcs:ignore WordPress.Security.EscapeOutput -- binary payload.
			$left -= strlen( $buf );
			flush();
		}
		fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		exit;
	}
}

