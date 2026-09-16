<?php
/**
 * Where finished backups and in-progress restore uploads live.
 *
 * Two things share this directory: completed backups and staged restore-upload
 * files (.part files assembled the same chunked way vulnhub-import stages a
 * CSV, since the mechanics are file-format-agnostic). Both are behind an
 * index.php + deny-all guard so nothing here is ever served over HTTP by
 * accident — a stray request for db.sql.gz would hand over the whole database.
 *
 * A finished backup is ONE file: `backup-<date>-<id>.tar.gz`, holding
 * manifest.json, db.sql.gz and wp-content.zip. It used to be a folder with
 * those three files loose in it, which meant an operator had to download three
 * things and keep them together to have a backup at all. The folder still
 * exists while a job runs — it is the working directory the members are built
 * in — and is deleted once they have been packed.
 *
 * Backups taken before that change are still folders on disk, so everything
 * here reads both shapes: `list_local()` returns either, and download and
 * delete work on either. Only the writing side is single-file.
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
	 * A fresh folder name for a new backup, which becomes the archive's name.
	 *
	 * Site-local time, deliberately, and the only place in this plugin that
	 * is: everything stored or compared stays UTC, but this string is read by
	 * a person choosing which backup to restore. A backup taken at 12:20pm in
	 * Auckland that calls itself 00:20 is a trap, and the name is the one
	 * label a downloaded file keeps once it is off this machine.
	 *
	 * @param int $job_id Job id, appended so it is always unique.
	 * @return string
	 */
	public static function new_folder( int $job_id ): string {
		return 'backup-' . wp_date( 'Ymd-His' ) . '-' . $job_id;
	}

	/**
	 * The single-file name a finished backup is packed into.
	 *
	 * @param string $folder Folder name (e.g. backup-20260911-123000-42).
	 * @return string
	 */
	public static function archive_name( string $folder ): string {
		return $folder . '.tar.gz';
	}

	/**
	 * Absolute path of a finished backup archive.
	 *
	 * The archive is a SIBLING of the working folder, not inside it, so that
	 * once packing is done the folder can be deleted outright and the backup
	 * is exactly one file on disk.
	 *
	 * @param string $folder Folder name.
	 * @return string Empty string when the folder name is not ours.
	 */
	public static function archive_path( string $folder ): string {
		if ( ! self::valid_folder( $folder ) ) {
			return '';
		}

		$base = self::ensure_dir();

		return '' === $base ? '' : $base . '/' . self::archive_name( $folder );
	}

	/**
	 * Has this backup been packed into its single file yet?
	 *
	 * @param string $folder Folder name.
	 * @return bool
	 */
	public static function has_archive( string $folder ): bool {
		$path = self::archive_path( $folder );

		return '' !== $path && is_readable( $path );
	}

	/* =================================================================
	 * Writing the archive: a tar built a chunk at a time, straight into a
	 * gzip stream.
	 *
	 * Written by hand rather than with PharData because PharData builds a
	 * whole .tar first and compresses it afterwards -- two full passes and a
	 * second copy of a multi-hundred-megabyte file on disk -- and because
	 * `phar.readonly` is on in this container, which is a setting a host can
	 * change underneath us. Shelling out to tar(1) was the other option, but
	 * the cron container that runs most passes is a different image from the
	 * web one, so "tar exists" is not a safe assumption to build a backup on.
	 *
	 * Appending to a gzip file produces a multi-member gzip stream, which is
	 * valid and which gzip, zcat and tar all read transparently -- that is
	 * what makes a resumable, checkpointed pack possible at all.
	 * ============================================================== */

	/** Bytes copied per read/write while packing or extracting. */
	public const COPY_CHUNK = 1048576;

	/**
	 * One 512-byte ustar header block.
	 *
	 * @param string $name  Member name (must be under 100 bytes; every member
	 *                      this plugin writes is a fixed short name).
	 * @param int    $size  Member size in bytes.
	 * @param int    $mtime Modification time.
	 * @return string 512 bytes.
	 */
	public static function tar_header( string $name, int $size, int $mtime ): string {
		$header = pack( 'a100', $name )
			. pack( 'a8', '0000644' . chr( 0 ) )
			. pack( 'a8', '0000000' . chr( 0 ) )
			. pack( 'a8', '0000000' . chr( 0 ) )
			. pack( 'a12', sprintf( '%011o', $size ) . chr( 0 ) )
			. pack( 'a12', sprintf( '%011o', $mtime ) . chr( 0 ) )
			. str_repeat( ' ', 8 )
			. pack( 'a1', '0' )
			. pack( 'a100', '' )
			. pack( 'a6', 'ustar' )
			. pack( 'a2', '00' )
			. pack( 'a32', 'vulnhub' )
			. pack( 'a32', 'vulnhub' )
			. pack( 'a8', '' )
			. pack( 'a8', '' )
			. pack( 'a155', '' )
			. str_repeat( chr( 0 ), 12 );

		$sum = 0;

		for ( $i = 0, $len = strlen( $header ); $i < $len; $i++ ) {
			$sum += ord( $header[ $i ] );
		}

		// The checksum field is written last, over the spaces it was summed with.
		return substr_replace( $header, sprintf( '%06o', $sum ) . chr( 0 ) . ' ', 148, 8 );
	}

	/**
	 * Zero padding that takes a member up to the next 512-byte boundary.
	 *
	 * @param int $size Member size in bytes.
	 * @return string
	 */
	public static function tar_padding( int $size ): string {
		$remainder = $size % 512;

		return 0 === $remainder ? '' : str_repeat( chr( 0 ), 512 - $remainder );
	}

	/**
	 * Open the archive for appending (creating it if this is the first pass).
	 *
	 * @param string $path Archive path.
	 * @return resource|false
	 */
	public static function tar_open( string $path ) {
		return gzopen( $path, 'ab9' );
	}

	/**
	 * Copy part of a member into the archive, stopping at the deadline.
	 *
	 * @param resource $gz       Open gzip handle.
	 * @param string   $source   File being packed.
	 * @param int      $offset   Bytes of it already written.
	 * @param float    $deadline microtime after which to stop and checkpoint.
	 * @return int New offset, or -1 when the source could not be read.
	 */
	public static function tar_copy_member( $gz, string $source, int $offset, float $deadline ): int {
		$handle = fopen( $source, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( ! $handle ) {
			return -1;
		}

		if ( $offset > 0 && 0 !== fseek( $handle, $offset ) ) {
			fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			return -1;
		}

		while ( ! feof( $handle ) ) {
			$chunk = fread( $handle, self::COPY_CHUNK );

			if ( false === $chunk || '' === $chunk ) {
				break;
			}

			if ( false === gzwrite( $gz, $chunk ) ) {
				fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions
				return -1;
			}

			$offset += strlen( $chunk );

			if ( microtime( true ) >= $deadline ) {
				break;
			}
		}

		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		return $offset;
	}

	/**
	 * Write the two zero blocks that mark the end of a tar.
	 *
	 * Their absence is how a truncated archive is recognised on the way back
	 * in — see extract_targz().
	 *
	 * @param resource $gz Open gzip handle.
	 * @return void
	 */
	public static function tar_terminate( $gz ): void {
		gzwrite( $gz, str_repeat( chr( 0 ), 1024 ) );
	}

	/* =================================================================
	 * Reading the archive back
	 * ============================================================== */

	/**
	 * Stream a .tar.gz into a directory.
	 *
	 * Refuses any member that is not one of the names we write: a backup
	 * archive is an operator-supplied file arriving over an upload form, so
	 * it gets treated as hostile — no absolute paths, no traversal, nothing
	 * outside the expected three names, and no symlinks or devices.
	 *
	 * A short read, or the end of the file arriving before the terminator
	 * blocks, is reported as truncation rather than quietly restoring half a
	 * database.
	 *
	 * @param string             $archive Archive path.
	 * @param string             $dest    Directory to extract into.
	 * @param array<int,string>  $allow   Permitted member names.
	 * @return array{ok:bool,members:array<int,string>,error:string}
	 */
	public static function extract_targz( string $archive, string $dest, array $allow ): array {
		$fail = static fn( string $message ): array => array(
			'ok'      => false,
			'members' => array(),
			'error'   => $message,
		);

		$gz = gzopen( $archive, 'rb' );

		if ( ! $gz ) {
			return $fail( __( 'The archive could not be opened.', 'vulnhub' ) );
		}

		$members    = array();
		$terminated = false;

		while ( true ) {
			$header = gzread( $gz, 512 );

			if ( false === $header || '' === $header ) {
				break;
			}

			if ( 512 !== strlen( $header ) ) {
				gzclose( $gz );
				return $fail( __( 'The archive ends mid-header — the file is truncated or corrupt.', 'vulnhub' ) );
			}

			// Two zero blocks end the archive.
			if ( '' === trim( $header, chr( 0 ) ) ) {
				$terminated = true;
				break;
			}

			$name = trim( substr( $header, 0, 100 ), chr( 0 ) . ' ' );
			$size = (int) octdec( trim( substr( $header, 124, 12 ), chr( 0 ) . ' ' ) );
			$type = substr( $header, 156, 1 );

			if ( ! in_array( $name, $allow, true ) || '0' !== $type && chr( 0 ) !== $type ) {
				gzclose( $gz );

				return $fail(
					sprintf(
						/* translators: %s: name of an unexpected file inside the archive. */
						__( 'The archive contains something a VulnHub backup never holds (%s).', 'vulnhub' ),
						'' === $name ? '?' : $name
					)
				);
			}

			$target = $dest . '/' . $name;
			$out    = fopen( $target, 'wb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions

			if ( ! $out ) {
				gzclose( $gz );
				return $fail( __( 'A file from the archive could not be written to the staging directory.', 'vulnhub' ) );
			}

			$left = $size;

			while ( $left > 0 ) {
				$chunk = gzread( $gz, (int) min( self::COPY_CHUNK, $left ) );

				if ( false === $chunk || '' === $chunk ) {
					fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions
					gzclose( $gz );
					return $fail( __( 'The archive ends part-way through a file — the download is incomplete.', 'vulnhub' ) );
				}

				fwrite( $out, $chunk ); // phpcs:ignore WordPress.WP.AlternativeFunctions
				$left -= strlen( $chunk );
			}

			fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions

			$padding = self::tar_padding( $size );

			if ( '' !== $padding ) {
				gzread( $gz, strlen( $padding ) );
			}

			$members[] = $name;
		}

		gzclose( $gz );

		if ( ! $terminated ) {
			return $fail( __( 'The archive has no end marker — it did not finish downloading.', 'vulnhub' ) );
		}

		return array( 'ok' => true, 'members' => $members, 'error' => '' );
	}

	/**
	 * Read manifest.json out of an archive without unpacking the rest.
	 *
	 * The manifest is written first precisely so this costs one small read —
	 * the backups list calls it for every row on the page.
	 *
	 * @param string $archive Archive path.
	 * @return array<string,mixed>
	 */
	public static function manifest_from_archive( string $archive ): array {
		$gz = gzopen( $archive, 'rb' );

		if ( ! $gz ) {
			return array();
		}

		$header = gzread( $gz, 512 );

		if ( ! is_string( $header ) || 512 !== strlen( $header ) ) {
			gzclose( $gz );
			return array();
		}

		$name = trim( substr( $header, 0, 100 ), chr( 0 ) . ' ' );
		$size = (int) octdec( trim( substr( $header, 124, 12 ), chr( 0 ) . ' ' ) );

		if ( 'manifest.json' !== $name || $size <= 0 || $size > 1048576 ) {
			gzclose( $gz );
			return array();
		}

		$body = (string) gzread( $gz, $size );
		gzclose( $gz );

		$decoded = json_decode( $body, true );

		return is_array( $decoded ) ? $decoded : array();
	}

	/**
	 * List completed local backups: packed archives and any older folders.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function list_local(): array {
		$base = self::ensure_dir();

		if ( '' === $base ) {
			return array();
		}

		$sets = array();
		$seen = array();

		// Packed backups: one file each, newest first once sorted below.
		foreach ( (array) glob( $base . '/backup-*.tar.gz' ) as $archive ) {
			if ( ! is_file( $archive ) ) {
				continue;
			}

			$folder = substr( basename( $archive ), 0, -7 );

			if ( ! self::valid_folder( $folder ) ) {
				continue;
			}

			$manifest = self::manifest_from_archive( $archive );
			$size     = (int) filesize( $archive );

			$seen[ $folder ] = true;

			$sets[] = array(
				'folder'       => $folder,
				'format'       => 'archive',
				'file'         => basename( $archive ),
				'downloadName' => self::archive_name( $folder ),
				// What the backups screen offers for download. One entry, because
				// that is now the whole backup.
				'files'        => array( self::archive_name( $folder ) ),
				'sizeBytes'    => $size,
				'sizeLabel'    => size_format( $size, 1 ),
				'createdAt'    => (string) ( $manifest['created_at'] ?? gmdate( 'Y-m-d H:i:s', (int) filemtime( $archive ) ) ),
				'manifest'     => $manifest,
			);
		}

		/*
		 * Folders: either a backup taken before backups became one file, or
		 * the working directory of a job that is still running. Both are worth
		 * listing -- the first so it can still be downloaded and restored, the
		 * second so an interrupted job is visible rather than invisible -- but
		 * a folder whose archive already exists is just leftovers.
		 */
		foreach ( (array) glob( $base . '/backup-*', GLOB_ONLYDIR ) as $dir ) {
			$folder = basename( $dir );

			if ( ! self::valid_folder( $folder ) || isset( $seen[ $folder ] ) ) {
				continue;
			}

			$files     = glob( $dir . '/*' );
			$total     = 0;
			$manifest  = array();
			$names     = array();

			foreach ( (array) $files as $file ) {
				if ( ! is_file( $file ) ) {
					continue;
				}
				$name    = basename( $file );
				$names[] = $name;
				$total  += (int) filesize( $file );

				if ( 'manifest.json' === $name ) {
					$decoded  = json_decode( (string) file_get_contents( $file ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions
					$manifest = is_array( $decoded ) ? $decoded : array();
				}
			}

			if ( ! $names ) {
				continue;
			}

			$sets[] = array(
				'folder'       => $folder,
				'format'       => 'folder',
				'file'         => '',
				'downloadName' => '',
				// Whatever this one actually has: an older three-file backup
				// offers three downloads, and a job still running offers the
				// members it has finished so far.
				'files'        => $names,
				'sizeBytes'    => $total,
				'sizeLabel'    => size_format( $total, 1 ),
				'createdAt'    => (string) ( $manifest['created_at'] ?? gmdate( 'Y-m-d H:i:s', (int) filemtime( $dir ) ) ),
				'manifest'     => $manifest,
			);
		}

		usort( $sets, static fn( array $a, array $b ): int => strcmp( (string) $b['folder'], (string) $a['folder'] ) );

		return $sets;
	}

	/**
	 * Delete one local backup entirely: the archive, and the working folder if
	 * an interrupted job left one behind.
	 *
	 * @param string $folder Folder name.
	 * @return bool True when something was actually removed.
	 */
	public static function delete_local_set( string $folder ): bool {
		if ( ! self::valid_folder( $folder ) ) {
			return false;
		}

		$removed = false;
		$archive = self::archive_path( $folder );

		if ( '' !== $archive && is_file( $archive ) ) {
			wp_delete_file( $archive );
			$removed = true;
		}

		$removed = self::delete_work_dir( $folder ) || $removed;

		return $removed;
	}

	/**
	 * Remove a backup's working directory and everything in it.
	 *
	 * Called after packing (the members now live in the archive) and by
	 * delete_local_set().
	 *
	 * @param string $folder Folder name.
	 * @return bool
	 */
	public static function delete_work_dir( string $folder ): bool {
		if ( ! self::valid_folder( $folder ) ) {
			return false;
		}

		$base = self::ensure_dir();
		$dir  = '' === $base ? '' : $base . '/' . $folder;

		if ( '' === $dir || ! is_dir( $dir ) ) {
			return false;
		}

		foreach ( (array) glob( $dir . '/*' ) as $file ) {
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

		$name = basename( $filename );

		/*
		 * The whole backup, which is the only thing worth downloading now:
		 * asked for by its own name, or by the word "archive" so a caller can
		 * link to it without knowing the naming scheme.
		 */
		if ( 'archive' === $name || self::archive_name( $folder ) === $name ) {
			$archive = self::archive_path( $folder );

			return '' !== $archive && is_readable( $archive ) ? $archive : '';
		}

		// A backup taken before packing existed: its three files, individually.
		if ( ! in_array( $name, array( 'db.sql.gz', 'wp-content.zip', 'manifest.json' ), true ) ) {
			return '';
		}

		// Read-only: set_dir() would create the folder, littering an empty
		// directory beside a packed backup every time someone asked it for a
		// member it no longer has.
		$base = self::ensure_dir();
		$dir  = '' === $base ? '' : $base . '/' . $folder;

		if ( '' === $dir || ! is_dir( $dir ) ) {
			return '';
		}

		$path = $dir . '/' . $name;

		return is_readable( $path ) ? $path : '';
	}

	/*
	 * build_bundle_temp() used to zip a finished set into one downloadable
	 * file on demand. The backup is now written as one file to begin with, so
	 * there is nothing left to bundle: path_for_download() hands back the
	 * archive itself, with no temp copy of a multi-hundred-megabyte file.
	 */

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
	 * Does the head of the staged file look like a backup we can read?
	 *
	 * @param string $key Storage key.
	 * @return array{ok:bool,message:string,format:string}
	 */
	public static function sniff( string $key ): array {
		$path = self::path( $key );

		if ( '' === $path || ! is_readable( $path ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'The staged file could not be read.', 'vulnhub' ),
				'format'  => '',
			);
		}

		$handle = fopen( $path, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( ! $handle ) {
			return array(
				'ok'      => false,
				'message' => __( 'The staged file could not be read.', 'vulnhub' ),
				'format'  => '',
			);
		}

		$head = (string) fread( $handle, 4 );
		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		$format = self::format_of( $head );

		if ( '' === $format ) {
			return array(
				'ok'      => false,
				'message' => __( 'That does not look like a VulnHub backup. Upload the .tar.gz the backup screen produced.', 'vulnhub' ),
				'format'  => '',
			);
		}

		return array(
			'ok'      => true,
			'message' => '',
			'format'  => $format,
		);
	}

	/**
	 * Which backup format a file's first bytes say it is.
	 *
	 * `targz` is what backups are written as now. `zip` is the bundle shape
	 * downloaded from an older install — still accepted, because a backup
	 * nobody can restore is not a backup.
	 *
	 * @param string $head First few bytes of the file.
	 * @return string 'targz', 'zip', or '' when it is neither.
	 */
	public static function format_of( string $head ): string {
		if ( str_starts_with( $head, "\x1f\x8b" ) ) {
			return 'targz';
		}

		// Zip local-file-header signature, or the empty-archive variant.
		if ( str_starts_with( $head, "PK\x03\x04" ) || str_starts_with( $head, "PK\x05\x06" ) ) {
			return 'zip';
		}

		return '';
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

