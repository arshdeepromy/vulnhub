<?php
/**
 * On-disk staging for a Tenable sync.
 *
 * The sync is split in two so a crash can never cost the whole run: first the
 * raw export is DOWNLOADED to disk, chunk by chunk, exactly as Tenable hands
 * it over; then it is PROCESSED off disk in bounded batches. Each phase writes
 * a checkpoint to state.json after every step, so an interrupted sync -- a
 * killed container, a reboot -- resumes from where it stopped instead of
 * starting the multi-hundred-thousand-row import again from zero.
 *
 * One directory per connector under uploads, guarded so the web server never
 * serves the raw scan data back out.
 *
 * @package VulnHub\Tenable
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VH_Tenable_Store {

	private const DIRNAME = 'vulnhub-sync';

	/**
	 * gzip level for staged chunks. The export JSON is ~92% a repeating plugin
	 * metadata block, so it compresses ~13:1; a full 5.3GB download lands as
	 * ~400MB on disk. Level 4 keeps the compression cheap enough not to lengthen
	 * a large sync noticeably while capturing almost all of that win.
	 *
	 * Chunks keep their `.json` filename but hold gzip bytes. The readers below
	 * open every chunk through gzopen(), which reads gzip and legacy plain JSON
	 * alike, so a resume that straddles this change still reads old chunks.
	 */
	private const GZIP_LEVEL = 4;

	/**
	 * The staging directory for one connector, created and guarded.
	 *
	 * @param string $connector Connector id.
	 * @return string Absolute path, or '' if uploads are unwritable.
	 */
	public static function dir( string $connector ): string {
		$uploads = wp_upload_dir();

		if ( ! empty( $uploads['error'] ) || empty( $uploads['basedir'] ) ) {
			return '';
		}

		$base = rtrim( (string) $uploads['basedir'], '/\\' ) . '/' . self::DIRNAME;
		$dir  = $base . '/' . sanitize_key( $connector );

		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return '';
		}

		// Never let the raw export be fetched over HTTP.
		$guards = array(
			'index.php' => "<?php\n// Silence is golden.\n",
			'.htaccess' => "Require all denied\n",
		);
		foreach ( $guards as $name => $contents ) {
			$path = $base . '/' . $name;
			if ( ! file_exists( $path ) ) {
				file_put_contents( $path, $contents ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			}
		}

		return $dir;
	}

	/**
	 * Path to one downloaded chunk file. `kind` is `assets` or `vulns`.
	 *
	 * @param string $connector Connector id.
	 * @param string $kind      Export kind.
	 * @param int    $index     1-based chunk number.
	 * @return string
	 */
	public static function chunk_path( string $connector, string $kind, int $index ): string {
		$dir = self::dir( $connector );
		return '' === $dir ? '' : sprintf( '%s/%s-%d.json', $dir, sanitize_key( $kind ), $index );
	}

	/**
	 * Save one raw chunk to disk. Written to a temp file and renamed, so a
	 * chunk file is only ever seen complete -- a half-written chunk from a
	 * crash mid-write is never mistaken for a finished one.
	 *
	 * @param string $connector Connector id.
	 * @param string $kind      Export kind.
	 * @param int    $index     1-based chunk number.
	 * @param string $json      Raw JSON body.
	 * @return int Bytes of JSON saved (uncompressed), or 0 on failure.
	 */
	public static function save_chunk( string $connector, string $kind, int $index, string $json ): int {
		$path = self::chunk_path( $connector, $kind, $index );

		if ( '' === $path ) {
			return 0;
		}

		// Store gzip, keep the .json name (see the class note). gzencode holds
		// the whole body in memory, which is fine here: save_chunk() only ever
		// takes an already-decoded asset chunk, which is small. Large vuln
		// chunks are streamed to disk by the client and compressed by
		// compress_chunk() instead, which never holds the whole file.
		$gz = gzencode( $json, self::GZIP_LEVEL );
		if ( false === $gz ) {
			$gz = $json; // fall back to plain; gzopen() reads it back either way
		}

		$tmp = $path . '.part';
		if ( false === file_put_contents( $tmp, $gz ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
			return 0;
		}

		rename( $tmp, $path );

		return strlen( $json );
	}

	/**
	 * Compress an already-downloaded chunk in place, streaming so peak memory is
	 * one read buffer regardless of chunk size. The client streams each raw vuln
	 * chunk straight to disk (a chunk can be hundreds of MB, far too big to hold
	 * in memory), and this is called right after to shrink it ~13:1. Idempotent:
	 * a chunk that is already gzip (a resumed download re-seeing it) is skipped.
	 *
	 * @param string $connector Connector id.
	 * @param string $kind      Export kind.
	 * @param int    $index     1-based chunk number.
	 * @return int Compressed size on disk, or 0 if there was nothing to do.
	 */
	public static function compress_chunk( string $connector, string $kind, int $index ): int {
		$path = self::chunk_path( $connector, $kind, $index );

		if ( '' === $path || ! is_file( $path ) ) {
			return 0;
		}

		$in = fopen( $path, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( ! $in ) {
			return 0;
		}

		// Already gzip? (gzip magic bytes 0x1f 0x8b) Leave it be.
		if ( "\x1f\x8b" === fread( $in, 2 ) ) {
			fclose( $in ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			return (int) filesize( $path );
		}
		fseek( $in, 0 );

		$tmp = $path . '.gz.part';
		$out = gzopen( $tmp, 'wb' . self::GZIP_LEVEL );
		if ( ! $out ) {
			fclose( $in ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			return 0;
		}

		while ( ! feof( $in ) ) {
			$buf = fread( $in, 1 << 20 ); // 1 MiB
			if ( false === $buf || '' === $buf ) {
				break;
			}
			gzwrite( $out, $buf );
		}

		fclose( $in ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		gzclose( $out );
		rename( $tmp, $path ); // atomic swap: the .json now holds gzip

		return (int) filesize( $path );
	}

	/**
	 * Records in a saved chunk, decoded. Returns [] if the chunk is missing.
	 *
	 * @param string $connector Connector id.
	 * @param string $kind      Export kind.
	 * @param int    $index     1-based chunk number.
	 * @return array<int,array<string,mixed>>
	 */
	public static function read_chunk( string $connector, string $kind, int $index ): array {
		$path = self::chunk_path( $connector, $kind, $index );

		if ( '' === $path || ! is_file( $path ) ) {
			return array();
		}

		// gzopen reads a gzip chunk and a legacy plain-JSON one alike.
		$fh = gzopen( $path, 'rb' );
		if ( ! $fh ) {
			return array();
		}
		$json = '';
		while ( ! gzeof( $fh ) ) {
			$buf = gzread( $fh, 1 << 20 );
			if ( false === $buf || '' === $buf ) {
				break;
			}
			$json .= $buf;
		}
		gzclose( $fh );

		$decoded = json_decode( $json, true );

		return is_array( $decoded ) ? $decoded : array();
	}

	public static function chunk_exists( string $connector, string $kind, int $index ): bool {
		$path = self::chunk_path( $connector, $kind, $index );
		return '' !== $path && is_file( $path );
	}

	/**
	 * Delete one chunk file once it has been imported, so disk is freed as
	 * processing goes rather than only at the very end. Safe against resume:
	 * the checkpoint has already advanced past this chunk before it is
	 * deleted, so a restart never looks for a chunk that is gone.
	 *
	 * @param string $connector Connector id.
	 * @param string $kind      Export kind.
	 * @param int    $index     1-based chunk number.
	 */
	public static function delete_chunk( string $connector, string $kind, int $index ): void {
		$path = self::chunk_path( $connector, $kind, $index );

		if ( '' !== $path && is_file( $path ) ) {
			unlink( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}
	}

	/**
	 * Remove the downloaded chunk files but keep state.json. Used when a
	 * download (re)starts: the old, possibly partial, chunks from an
	 * interrupted run are cleared so they cannot pile up, while the state that
	 * marks a run in progress survives.
	 *
	 * @param string $connector Connector id.
	 */
	public static function clear_chunks( string $connector ): void {
		$dir = self::dir( $connector );

		if ( '' === $dir || ! is_dir( $dir ) ) {
			return;
		}

		foreach ( (array) glob( $dir . '/*.json' ) as $file ) {
			if ( is_file( $file ) && 'state.json' !== basename( $file ) ) {
				unlink( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			}
		}
		// Any half-written .part file from a crash mid-write.
		foreach ( (array) glob( $dir . '/*.part' ) as $file ) {
			if ( is_file( $file ) ) {
				unlink( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			}
		}
	}

	/**
	 * The run state. A plain array, persisted as state.json.
	 *
	 * @param string $connector Connector id.
	 * @return array<string,mixed>
	 */
	public static function read_state( string $connector ): array {
		$dir = self::dir( $connector );

		if ( '' === $dir || ! is_file( $dir . '/state.json' ) ) {
			return array();
		}

		$decoded = json_decode( (string) file_get_contents( $dir . '/state.json' ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		return is_array( $decoded ) ? $decoded : array();
	}

	/**
	 * Persist the run state atomically (temp file + rename), so a checkpoint
	 * is never read back half-written.
	 *
	 * @param string              $connector Connector id.
	 * @param array<string,mixed> $state     State to store.
	 */
	public static function write_state( string $connector, array $state ): void {
		$dir = self::dir( $connector );

		if ( '' === $dir ) {
			return;
		}

		$tmp = $dir . '/state.json.part';
		file_put_contents( $tmp, (string) wp_json_encode( $state ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		rename( $tmp, $dir . '/state.json' );
	}

	/**
	 * Delete everything for a connector's run -- chunks and state alike.
	 * Called once a run has fully completed and its data is safely imported.
	 *
	 * @param string $connector Connector id.
	 */
	public static function clear( string $connector ): void {
		$dir = self::dir( $connector );

		if ( '' === $dir || ! is_dir( $dir ) ) {
			return;
		}

		foreach ( (array) glob( $dir . '/*' ) as $file ) {
			if ( is_file( $file ) ) {
				unlink( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			}
		}
	}

	/**
	 * Total bytes downloaded so far, for the download progress readout.
	 *
	 * @param string $connector Connector id.
	 * @return int
	 */
	public static function bytes_on_disk( string $connector ): int {
		$dir = self::dir( $connector );

		if ( '' === $dir ) {
			return 0;
		}

		$total = 0;
		foreach ( (array) glob( $dir . '/*.json' ) as $file ) {
			$total += (int) filesize( $file );
		}

		return $total;
	}

	/**
	 * Stream one saved chunk record by record, decoding a single object at a
	 * time instead of the whole file at once.
	 *
	 * A Tenable chunk is one JSON array of records that can run to hundreds of
	 * megabytes; json_decode()'ing it whole builds a multi-gigabyte PHP array
	 * and is what OOM-kills the worker. This walks the top-level array with a
	 * byte scanner -- tracking string state, escapes and brace/bracket depth --
	 * and hands each complete top-level element to the callback on its own, so
	 * peak memory is one record plus a small read buffer regardless of how big
	 * the chunk is. The callback receives a decoded array; malformed elements
	 * are skipped. Returns the number of records handed over.
	 *
	 * @param string                             $connector Connector id.
	 * @param string                             $kind      Export kind.
	 * @param int                                $index     1-based chunk number.
	 * @param callable(array<string,mixed>):void $cb        Per-record handler.
	 * @return int
	 */
	public static function stream_records( string $connector, string $kind, int $index, callable $cb ): int {
		$path = self::chunk_path( $connector, $kind, $index );

		if ( '' === $path || ! is_file( $path ) ) {
			return 0;
		}

		// gzopen decompresses a gzip chunk on the fly and reads a legacy plain
		// chunk unchanged, so the byte scanner below is oblivious to which it is
		// and peak memory stays one read buffer either way.
		$fh = gzopen( $path, 'rb' );
		if ( ! $fh ) {
			return 0;
		}

		$count     = 0;
		$buf       = '';
		$depth     = 0;     // brace/bracket depth within the top-level array
		$in_string = false;
		$escaped   = false;
		$capturing = false; // accumulating one top-level element
		$started   = false; // seen the opening top-level '['

		while ( ! gzeof( $fh ) ) {
			$data = gzread( $fh, 1 << 20 ); // 1 MiB
			if ( false === $data || '' === $data ) {
				break;
			}

			$len = strlen( $data );
			for ( $i = 0; $i < $len; $i++ ) {
				$ch = $data[ $i ];

				// Everything inside a top-level element is copied verbatim,
				// including the opening char, which is set below on entry.
				if ( $capturing ) {
					$buf .= $ch;
				}

				if ( $in_string ) {
					if ( $escaped ) {
						$escaped = false;
					} elseif ( '\\' === $ch ) {
						$escaped = true;
					} elseif ( '"' === $ch ) {
						$in_string = false;
					}
					continue;
				}

				if ( '"' === $ch ) {
					$in_string = true;
					continue;
				}

				if ( ! $started ) {
					if ( '[' === $ch ) {
						$started = true;
					}
					continue;
				}

				if ( '{' === $ch || '[' === $ch ) {
					if ( 0 === $depth && ! $capturing ) {
						$capturing = true;
						$buf       = $ch; // first char of the element
					}
					++$depth;
					continue;
				}

				if ( '}' === $ch || ']' === $ch ) {
					if ( 0 === $depth ) {
						continue; // the top-level array's own closing bracket
					}
					--$depth;
					if ( 0 === $depth && $capturing ) {
						$record = json_decode( $buf, true );
						if ( is_array( $record ) ) {
							$cb( $record );
							++$count;
						}
						$capturing = false;
						$buf       = '';
					}
					continue;
				}
			}
		}

		gzclose( $fh );

		return $count;
	}
}
