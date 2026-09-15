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
	 * @return int Bytes written, or 0 on failure.
	 */
	public static function save_chunk( string $connector, string $kind, int $index, string $json ): int {
		$path = self::chunk_path( $connector, $kind, $index );

		if ( '' === $path ) {
			return 0;
		}

		$tmp   = $path . '.part';
		$bytes = file_put_contents( $tmp, $json ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( false === $bytes ) {
			return 0;
		}

		rename( $tmp, $path );

		return (int) $bytes;
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

		$decoded = json_decode( (string) file_get_contents( $path ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions

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
}
