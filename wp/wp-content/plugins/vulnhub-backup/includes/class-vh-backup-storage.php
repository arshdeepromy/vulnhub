<?php
/**
 * Where finished backups and in-progress restore uploads live.
 *
 * Two things share this directory: completed backup sets (one folder per
 * backup, containing db.sql.gz, wp-content.zip and manifest.json) and staged
 * restore-upload files (.part files assembled the same chunked way
 * vulnhub-import stages a CSV, since the mechanics are file-format-agnostic).
 * Both are behind an index.php + deny-all guard so nothing here is ever
 * served over HTTP by accident — a stray request for db.sql.gz would hand
 * over the whole database.
 *
 * @package VulnHub\Backup
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Local storage for backup sets and chunked restore uploads.
 */
final class VulnHub_Backup_Storage {

	/** Directory name inside wp-content/uploads. */
	private const DIRNAME = 'vulnhub-backup';

	/** Slice size the browser starts with for a restore upload: 8 MB. */
	private const CHUNK_BYTES = 8388608;

	/** The largest slice the browser may work up to: 32 MB. */
	private const MAX_CHUNK_BYTES = 33554432;

	/** Hard ceiling on an uploaded restore archive: 4 GB. */
	private const MAX_BYTES = 4294967296;

	/** Leave this much disk unused after staging: 2 GB. */
	private const DISK_RESERVE = 2147483648;

	/**
	 * Absolute path of the storage directory, created and protected on demand.
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
			'.htaccess'  => "# VulnHub Backup storage. Never serve these files.\n<IfModule mod_authz_core.c>\n\tRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n\tOrder allow,deny\n\tDeny from all\n</IfModule>\n",
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

	/* =================================================================
	 * Finished backup sets
	 * ============================================================== */

	/**
	 * Directory for one backup set, created on demand.
	 *
	 * @param string $folder Folder name (e.g. backup-20260911-123000-42).
	 * @return string Empty string when it could not be created.
	 */
	public static function set_dir( string $folder ): string {
		if ( ! self::valid_folder( $folder ) ) {
			return '';
		}

		$base = self::ensure_dir();

		if ( '' === $base ) {
			return '';
		}

		$dir = $base . '/' . $folder;

		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return '';
		}

		return $dir;
	}

	/**
	 * Is this a folder name this class could have issued?
	 *
	 * @param string $folder Candidate folder name.
	 * @return bool
	 */
	public static function valid_folder( string $folder ): bool {
		return 1 === preg_match( '/^backup-\d{8}-\d{6}-\d+$/', $folder );
	}

	/**
	 * A fresh folder name for a new backup set.
	 *
	 * @param int $job_id Job id, appended so it is always unique.
	 * @return string
	 */
	public static function new_folder( int $job_id ): string {
		return 'backup-' . gmdate( 'Ymd-His' ) . '-' . $job_id;
	}

	/**
	 * List completed local backup sets with their file sizes.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function list_local(): array {
		$base = self::ensure_dir();

		if ( '' === $base ) {
			return array();
		}

		$dirs = glob( $base . '/backup-*', GLOB_ONLYDIR );

		if ( ! is_array( $dirs ) ) {
			return array();
		}

		$sets = array();

		foreach ( $dirs as $dir ) {
			$folder = basename( $dir );

			if ( ! self::valid_folder( $folder ) ) {
				continue;
			}

			$files     = glob( $dir . '/*' );
			$total     = 0;
			$manifest  = array();
			$has_files = false;

			foreach ( (array) $files as $file ) {
				if ( ! is_file( $file ) ) {
					continue;
				}
				$has_files = true;
				$total    += (int) filesize( $file );

				if ( 'manifest.json' === basename( $file ) ) {
					$decoded  = json_decode( (string) file_get_contents( $file ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions
					$manifest = is_array( $decoded ) ? $decoded : array();
				}
			}

			if ( ! $has_files ) {
				continue;
			}

			$sets[] = array(
				'folder'    => $folder,
				'sizeBytes' => $total,
				'sizeLabel' => size_format( $total, 1 ),
				'createdAt' => (string) ( $manifest['created_at'] ?? gmdate( 'Y-m-d H:i:s', (int) filemtime( $dir ) ) ),
				'manifest'  => $manifest,
			);
		}

		usort( $sets, static fn( array $a, array $b ): int => strcmp( (string) $b['folder'], (string) $a['folder'] ) );

		return $sets;
	}

	/**
	 * Delete one local backup set entirely.
	 *
	 * @param string $folder Folder name.
	 * @return bool
	 */
	public static function delete_local_set( string $folder ): bool {
		if ( ! self::valid_folder( $folder ) ) {
			return false;
		}

		$dir = self::set_dir( $folder );

		if ( '' === $dir || ! is_dir( $dir ) ) {
			return false;
		}

		$files = glob( $dir . '/*' );

		foreach ( (array) $files as $file ) {
			if ( is_file( $file ) ) {
				wp_delete_file( $file );
			}
		}

		return @rmdir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
	}

	/**
	 * Safe absolute path to one file inside one backup set, for the download
	 * endpoint. Refuses anything outside the set's own directory.
	 *
	 * @param string $folder   Folder name.
	 * @param string $filename File name inside that folder.
	 * @return string Empty string when the path is not valid.
	 */
	public static function path_for_download( string $folder, string $filename ): string {
		if ( ! self::valid_folder( $folder ) ) {
			return '';
		}

		$dir  = self::set_dir( $folder );
		$name = basename( $filename );

		if ( '' === $dir || '' === $name || ! in_array( $name, array( 'db.sql.gz', 'wp-content.zip', 'manifest.json' ), true ) ) {
			return '';
		}

		$path = $dir . '/' . $name;

		return is_readable( $path ) ? $path : '';
	}

	/**
	 * Build a single downloadable zip (db.sql.gz + wp-content.zip +
	 * manifest.json at its root) from a finished backup set.
	 *
	 * @param string $folder Folder name.
	 * @return string Temp file path, or an empty string on failure.
	 */
	public static function build_bundle_temp( string $folder ): string {
		if ( ! self::valid_folder( $folder ) ) {
			return '';
		}

		$dir = self::set_dir( $folder );

		if ( '' === $dir ) {
			return '';
		}

		$parts = array( 'manifest.json', 'db.sql.gz', 'wp-content.zip' );

		foreach ( $parts as $name ) {
			if ( ! is_readable( $dir . '/' . $name ) ) {
				return '';
			}
		}

		$tmp = wp_tempnam( 'vulnhub-backup-bundle' );

		if ( ! $tmp ) {
			return '';
		}

		$zip = new ZipArchive();

		if ( true !== $zip->open( $tmp, ZipArchive::OVERWRITE ) ) {
			wp_delete_file( $tmp );
			return '';
		}

		foreach ( $parts as $name ) {
			$zip->addFile( $dir . '/' . $name, $name );
		}

		$zip->close();

		return $tmp;
	}

	/* =================================================================
	 * Chunked restore upload — mirrors VulnHub_Import_Storage exactly;
	 * the mechanics (offset-verified append, flock, adaptive chunk size)
	 * are file-format-agnostic.
	 * ============================================================== */

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

		return (int) max( 262144, min( self::MAX_CHUNK_BYTES, (int) floor( $ceiling * 0.5 ) ) );
	}

	/**
	 * Largest assembled restore upload accepted.
	 *
	 * @return int
	 */
	public static function max_bytes(): int {
		return (int) apply_filters( 'vulnhub_backup_restore_max_bytes', self::MAX_BYTES );
	}

	/**
	 * Free bytes on the staging volume, minus a reserve.
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
	 * A fresh, unguessable storage key for a restore upload session.
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
	 * Absolute path for a restore-upload storage key.
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
	 * Does the staged restore-upload file for this key still exist?
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
	 * Start a new staged restore-upload file.
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
	 * Append one uploaded slice to a staged restore-upload file.
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
			return $fail( __( 'That file is larger than this restore path accepts.', 'vulnhub' ) );
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
	 * Does the head of the staged file look like a zip archive?
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

		$head = (string) fread( $handle, 4 );
		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		// A zip local-file-header signature: 'PK\x03\x04' (or the empty-archive
		// variant 'PK\x05\x06'). A VulnHub backup bundle is a zip of a zip plus
		// a gzip file plus a manifest, so this is the outer container's sniff.
		if ( ! str_starts_with( $head, "PK\x03\x04" ) && ! str_starts_with( $head, "PK\x05\x06" ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'That does not look like a VulnHub backup bundle.', 'vulnhub' ),
			);
		}

		return array(
			'ok'      => true,
			'message' => '',
		);
	}

	/**
	 * Delete a staged restore-upload file.
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
	 * Remove staged restore uploads older than a day that no live job refers
	 * to. Mirrors VulnHub_Import_Storage::sweep().
	 *
	 * @return int Files removed.
	 */
	public static function sweep(): int {
		$dir = self::ensure_dir();

		if ( '' === $dir ) {
			return 0;
		}

		$files = glob( $dir . '/*.part' );

		if ( ! is_array( $files ) || ! $files ) {
			return 0;
		}

		$removed = 0;
		$cutoff  = time() - DAY_IN_SECONDS;

		foreach ( $files as $file ) {
			if ( ! is_file( $file ) || (int) filemtime( $file ) > $cutoff ) {
				continue;
			}

			wp_delete_file( $file );
			++$removed;
		}

		return $removed;
	}
}

