<?php
/**
 * Where a very large upload lives while it is being imported.
 *
 * The php.ini upload limits are per *request*, not per file, and raising them
 * to 500 M would not help anyway: a single half-gigabyte request is a bad idea
 * whatever the limit says, and one dropped connection loses all of it. Instead
 * the browser slices the file and posts it a few megabytes at a time, and this
 * class appends those slices into one temporary file that the streaming reader
 * then walks with a byte offset. The size of file the importer accepts is
 * therefore governed by `max_bytes()` and by free disk, not by php.ini.
 *
 * Nothing here trusts the client. The storage key is generated server side and
 * is the only thing that ever reaches the filesystem; the browser-supplied
 * filename is kept purely to show the operator what they picked. The directory
 * is created with an `index.php` and an Apache/Nginx deny rule so a CSV full of
 * internal hostnames is never served over HTTP.
 *
 * @package VulnHub\Import
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Chunked upload assembly and the protected staging directory.
 */
final class VulnHub_Import_Storage {

	/** Directory name inside wp-content/uploads. */
	private const DIRNAME = 'vulnhub-import';

	/**
	 * Slice size the browser starts with: 8 MB.
	 *
	 * It is a starting point, not a rule. The uploader times each slice and
	 * adapts -- bigger on a fast link so a 500 MB file is tens of requests
	 * rather than hundreds, smaller on a slow one so no single request runs
	 * long enough to hit a proxy's idle timeout. Cloudflare, which sits in
	 * front of this origin, gives up on a request at 100 seconds.
	 */
	private const CHUNK_BYTES = 8388608;

	/**
	 * The largest slice the browser may work up to: 32 MB.
	 *
	 * Bounded by two things above php.ini. Cloudflare's plan limit on a
	 * request body is 100 MB, and a slice that fails has to be sent again --
	 * past about this size the retry costs more than the round trips saved.
	 */
	private const MAX_CHUNK_BYTES = 33554432;

	/** Hard ceiling on an assembled file: 2 GB. */
	private const MAX_BYTES = 2147483648;

	/** Leave this much disk unused after a staged file: 2 GB. */
	private const DISK_RESERVE = 2147483648;

	/** Extensions the importer will look at. */
	private const EXTENSIONS = array( 'csv', 'tsv', 'txt' );

	/**
	 * Slice size the browser should use.
	 *
	 * @return int
	 */
	public static function chunk_size(): int {
		return (int) min( self::CHUNK_BYTES, self::chunk_max() );
	}

	/**
	 * The largest slice this server will accept.
	 *
	 * The uploader adapts upward towards this and never past it.
	 *
	 * @return int
	 */
	public static function chunk_max(): int {
		$ceiling = min(
			self::bytes_from_ini( (string) ini_get( 'upload_max_filesize' ) ),
			self::bytes_from_ini( (string) ini_get( 'post_max_size' ) )
		);

		if ( $ceiling <= 0 ) {
			return self::CHUNK_BYTES;
		}

		// Half of the ini ceiling: generous headroom for the multipart
		// envelope, the key and offset fields, and any proxy that rewrites
		// the body on the way through.
		return (int) max( 262144, min( self::MAX_CHUNK_BYTES, (int) floor( $ceiling * 0.5 ) ) );
	}

	/**
	 * Largest assembled file accepted.
	 *
	 * @return int
	 */
	public static function max_bytes(): int {
		/**
		 * Filters the largest file the importer will accept.
		 *
		 * @param int $bytes Default 2 GB.
		 */
		return (int) apply_filters( 'vulnhub_import_max_bytes', self::MAX_BYTES );
	}

	/**
	 * Free bytes on the staging volume, minus a reserve.
	 *
	 * A staged file competes for disk with the database, the uploads folder
	 * and everything else on the box. Accepting a 500 MB upload on to a
	 * volume with 400 MB left fails two hundred slices in, after the operator
	 * has waited ten minutes -- so refuse it in `upload/begin` instead, where
	 * the message can still be useful.
	 *
	 * @return int Zero when the free space cannot be determined.
	 */
	public static function disk_headroom(): int {
		$dir = self::ensure_dir();

		if ( '' === $dir ) {
			return 0;
		}

		$free = @disk_free_space( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors

		if ( ! is_float( $free ) && ! is_int( $free ) ) {
			return 0;
		}

		return (int) max( 0, (int) $free - self::DISK_RESERVE );
	}

	/**
	 * How many bytes of a session have actually landed.
	 *
	 * The uploader asks for this after a failed slice so it can carry on from
	 * where the server got to rather than starting a 500 MB file again.
	 *
	 * @param string $key Storage key.
	 * @return int
	 */
	public static function staged_size( string $key ): int {
		return self::size( $key );
	}

	/**
	 * Convert a php.ini shorthand size ("64M") to bytes.
	 *
	 * @param string $value Raw ini value.
	 * @return int
	 */
	private static function bytes_from_ini( string $value ): int {
		$value = trim( $value );

		if ( '' === $value ) {
			return 0;
		}

		$unit   = strtolower( substr( $value, -1 ) );
		$number = (int) $value;

		return match ( $unit ) {
			'g'     => $number * 1024 * 1024 * 1024,
			'm'     => $number * 1024 * 1024,
			'k'     => $number * 1024,
			default => $number,
		};
	}

	/**
	 * Absolute path of the staging directory, created and protected on demand.
	 *
	 * @return string Empty string when it could not be created.
	 */
	public static function ensure_dir(): string {
		$uploads = wp_upload_dir();

		if ( ! empty( $uploads['error'] ) || empty( $uploads['basedir'] ) ) {
			return '';
		}

		$dir = rtrim( (string) $uploads['basedir'], '/\\' ) . '/' . self::DIRNAME;

		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return '';
		}

		$guards = array(
			'index.php'  => "<?php\n// Silence is golden.\n",
			'.htaccess'  => "# VulnHub Import staging. Never serve these files.\n<IfModule mod_authz_core.c>\n\tRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n\tOrder allow,deny\n\tDeny from all\n</IfModule>\n",
			'web.config' => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration><system.webServer><authorization><deny users=\"*\" /></authorization></system.webServer></configuration>\n",
		);

		foreach ( $guards as $name => $contents ) {
			$path = $dir . '/' . $name;

			if ( ! file_exists( $path ) ) {
				file_put_contents( $path, $contents ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			}
		}

		return $dir;
	}

	/**
	 * A fresh, unguessable storage key.
	 *
	 * @return string 32 hex characters.
	 */
	public static function new_key(): string {
		return bin2hex( random_bytes( 16 ) );
	}

	/**
	 * Is this a key this class could have issued?
	 *
	 * @param string $key Candidate key.
	 * @return bool
	 */
	public static function valid_key( string $key ): bool {
		return 1 === preg_match( '/^[a-f0-9]{32}$/', $key );
	}

	/**
	 * Absolute path for a storage key.
	 *
	 * @param string $key Storage key.
	 * @return string Empty string when the key is not ours.
	 */
	public static function path( string $key ): string {
		if ( ! self::valid_key( $key ) ) {
			return '';
		}

		$dir = self::ensure_dir();

		return '' === $dir ? '' : $dir . '/' . $key . '.part';
	}

	/**
	 * Does the staged file for this key still exist?
	 *
	 * @param string $key Storage key.
	 * @return bool
	 */
	public static function exists( string $key ): bool {
		$path = self::path( $key );

		return '' !== $path && is_readable( $path );
	}

	/**
	 * Bytes staged so far for this key.
	 *
	 * @param string $key Storage key.
	 * @return int
	 */
	public static function size( string $key ): int {
		$path = self::path( $key );

		if ( '' === $path || ! is_readable( $path ) ) {
			return 0;
		}

		clearstatcache( true, $path );

		return (int) filesize( $path );
	}

	/**
	 * Reduce a browser-supplied filename to something safe to display.
	 *
	 * The result is never used as a path — only as a label and as the source of
	 * an extension to validate.
	 *
	 * @param string $raw Client filename.
	 * @return string
	 */
	public static function safe_name( string $raw ): string {
		$name = sanitize_file_name( wp_basename( $raw ) );

		return '' === $name ? 'upload.csv' : mb_substr( $name, 0, 180 );
	}

	/**
	 * Is the extension one this importer reads?
	 *
	 * @param string $name Safe filename.
	 * @return bool
	 */
	public static function allowed_extension( string $name ): bool {
		$extension = strtolower( (string) pathinfo( $name, PATHINFO_EXTENSION ) );

		return in_array( $extension, self::EXTENSIONS, true );
	}

	/**
	 * Start a new staged file.
	 *
	 * @return string Storage key, or an empty string on failure.
	 */
	public static function begin(): string {
		$key  = self::new_key();
		$path = self::path( $key );

		if ( '' === $path ) {
			return '';
		}

		$handle = fopen( $path, 'wb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( ! $handle ) {
			return '';
		}

		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		chmod( $path, 0600 );

		return $key;
	}

	/**
	 * Append one uploaded slice to a staged file.
	 *
	 * The caller states the offset it believes it is writing at; the append is
	 * refused unless that matches the file's current length exactly, which
	 * makes a retried, reordered or duplicated slice a no-op error rather than
	 * silent corruption of a 300 MB import.
	 *
	 * @param string              $key    Storage key.
	 * @param int                 $offset Byte offset this slice starts at.
	 * @param array<string,mixed> $file   One entry from $_FILES.
	 * @return array{ok:bool,size:int,message:string}
	 */
	public static function append( string $key, int $offset, array $file ): array {
		$fail = static fn( string $message ): array => array(
			'ok'      => false,
			'size'    => 0,
			'message' => $message,
		);

		$path = self::path( $key );

		if ( '' === $path || ! is_file( $path ) ) {
			return $fail( __( 'That upload session is no longer available. Start the upload again.', 'vulnhub' ) );
		}

		$error = (int) ( $file['error'] ?? UPLOAD_ERR_NO_FILE );

		if ( UPLOAD_ERR_OK !== $error ) {
			/* translators: %d: PHP upload error code. */
			return $fail( sprintf( __( 'A slice of the upload did not arrive (error %d).', 'vulnhub' ), $error ) );
		}

		$tmp = (string) ( $file['tmp_name'] ?? '' );

		// The single most important check here: a genuine upload, never an
		// arbitrary path a caller managed to inject into the request.
		if ( '' === $tmp || ! is_uploaded_file( $tmp ) || ! is_readable( $tmp ) ) {
			return $fail( __( 'The uploaded slice could not be read.', 'vulnhub' ) );
		}

		clearstatcache( true, $path );
		$current = (int) filesize( $path );

		if ( $offset !== $current ) {
			return $fail(
				sprintf(
					/* translators: 1: expected offset, 2: offset sent. */
					__( 'Upload slices arrived out of order (expected offset %1$d, got %2$d).', 'vulnhub' ),
					$current,
					$offset
				)
			);
		}

		$incoming = (int) filesize( $tmp );

		if ( $current + $incoming > self::MAX_BYTES ) {
			return $fail( __( 'That file is larger than this importer accepts.', 'vulnhub' ) );
		}

		$target = fopen( $path, 'ab' ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( ! $target ) {
			return $fail( __( 'The staged file could not be written to.', 'vulnhub' ) );
		}

		if ( ! flock( $target, LOCK_EX ) ) {
			fclose( $target ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			return $fail( __( 'The staged file is busy. Try again.', 'vulnhub' ) );
		}

		$source = fopen( $tmp, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( ! $source ) {
			flock( $target, LOCK_UN );
			fclose( $target ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			return $fail( __( 'The uploaded slice could not be read.', 'vulnhub' ) );
		}

		// stream_copy_to_stream never materialises the slice in PHP memory.
		$copied = stream_copy_to_stream( $source, $target );

		fclose( $source ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		fflush( $target );
		flock( $target, LOCK_UN );
		fclose( $target ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		clearstatcache( true, $path );

		if ( false === $copied ) {
			return $fail( __( 'The staged file could not be written to.', 'vulnhub' ) );
		}

		return array(
			'ok'      => true,
			'size'    => (int) filesize( $path ),
			'message' => '',
		);
	}

	/**
	 * sha256 of a staged file, hashed a block at a time.
	 *
	 * @param string $key Storage key.
	 * @return string 64 hex characters, or an empty string.
	 */
	public static function hash( string $key ): string {
		$path = self::path( $key );

		if ( '' === $path || ! is_readable( $path ) ) {
			return '';
		}

		$hash = hash_file( 'sha256', $path );

		return is_string( $hash ) ? $hash : '';
	}

	/**
	 * Does the head of the staged file look like delimited text?
	 *
	 * A .xlsx renamed to .csv is a ZIP archive, and this is what catches it,
	 * along with anything else carrying NUL bytes or no delimiter at all.
	 *
	 * @param string $key Storage key.
	 * @return array{ok:bool,message:string}
	 */
	public static function sniff( string $key ): array {
		$path = self::path( $key );

		if ( '' === $path || ! is_readable( $path ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'The staged file could not be read.', 'vulnhub' ),
			);
		}

		$handle = fopen( $path, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( ! $handle ) {
			return array(
				'ok'      => false,
				'message' => __( 'The staged file could not be read.', 'vulnhub' ),
			);
		}

		$head = (string) fread( $handle, 8192 );
		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( '' === trim( $head ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'That file is empty.', 'vulnhub' ),
			);
		}

		if ( str_contains( $head, "\0" ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'That file contains binary data. Export it as CSV rather than as a workbook.', 'vulnhub' ),
			);
		}

		$first = (string) strtok( $head, "\r\n" );

		if ( '' === trim( $first ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'The first line of that file is blank; it must name the columns.', 'vulnhub' ),
			);
		}

		$delimiters = 0;
		foreach ( array( ',', ';', "\t", '|' ) as $delimiter ) {
			$delimiters += substr_count( $first, $delimiter );
		}

		if ( $delimiters < 1 ) {
			return array(
				'ok'      => false,
				'message' => __( 'The first line has no delimiter, so this is not a CSV.', 'vulnhub' ),
			);
		}

		if ( function_exists( 'finfo_open' ) ) {
			$finfo = finfo_open( FILEINFO_MIME_TYPE );

			if ( false !== $finfo ) {
				$mime = (string) finfo_file( $finfo, $path );
				finfo_close( $finfo );

				$allowed = array( 'text/csv', 'text/plain', 'text/tab-separated-values', 'application/csv', 'application/vnd.ms-excel' );

				if ( '' !== $mime && ! str_starts_with( $mime, 'text/' ) && ! in_array( $mime, $allowed, true ) ) {
					return array(
						'ok'      => false,
						'message' => __( 'That file does not look like a CSV once its contents are inspected.', 'vulnhub' ),
					);
				}
			}
		}

		return array(
			'ok'      => true,
			'message' => '',
		);
	}

	/**
	 * Delete a staged file. Called whenever a job finishes, fails or is
	 * cancelled — a temporary copy of the estate's vulnerabilities has no
	 * business outliving the import that needed it.
	 *
	 * @param string $key Storage key.
	 * @return void
	 */
	public static function delete( string $key ): void {
		$path = self::path( $key );

		if ( '' !== $path && is_file( $path ) ) {
			wp_delete_file( $path );
		}
	}

	/**
	 * Remove staged files older than a day that no live job refers to.
	 *
	 * @return int Files removed.
	 */
	public static function sweep(): int {
		global $wpdb;

		$dir = self::ensure_dir();

		if ( '' === $dir ) {
			return 0;
		}

		$files = glob( $dir . '/*.part' );

		if ( ! is_array( $files ) || ! $files ) {
			return 0;
		}

		$table   = VulnHub_Import_Jobs::table();
		$removed = 0;
		$cutoff  = time() - DAY_IN_SECONDS;

		foreach ( $files as $file ) {
			if ( ! is_file( $file ) || (int) filemtime( $file ) > $cutoff ) {
				continue;
			}

			$key = (string) pathinfo( $file, PATHINFO_FILENAME );

			$live = (int) $wpdb->get_var( // phpcs:ignore WordPress.DB
				$wpdb->prepare(
					"SELECT COUNT(*) FROM {$table} WHERE storage_key = %s AND status IN ( %s, %s, %s )", // phpcs:ignore WordPress.DB
					$key,
					VulnHub_Import_Jobs::PENDING,
					VulnHub_Import_Jobs::RUNNING,
					VulnHub_Import_Jobs::PAUSED
				)
			);

			if ( $live > 0 ) {
				continue;
			}

			wp_delete_file( $file );
			++$removed;
		}

		return $removed;
	}
}

