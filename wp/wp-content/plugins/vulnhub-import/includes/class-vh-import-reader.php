<?php
/**
 * The streaming CSV reader.
 *
 * This is the piece that makes a 300 MB import possible at all. The file is
 * never read with file_get_contents(), never split into an array of lines, and
 * never held in memory beyond the single row being mapped: `fopen`, `fgetcsv`,
 * and an `ftell` after every record so a pass can stop anywhere and the next
 * one can `fseek` straight back to the byte it left off at.
 *
 * `ftell` is taken *after* a complete record rather than after a line, so a
 * quoted field containing newlines — Tenable's Plugin Output is full of them —
 * still leaves the offset on a record boundary.
 *
 * @package VulnHub\Import
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * A resumable, forward-only reader over one delimited file.
 */
final class VulnHub_Import_Reader {

	/** Most columns read from one file. */
	public const MAX_COLUMNS = 120;

	/** Delimiters tried, in order of likelihood. */
	private const DELIMITERS = array( ',', ';', "\t", '|' );

	/** Open file handle. */
	private mixed $handle = null;

	/** Field delimiter in use. */
	private string $delimiter;

	/**
	 * Column headers, in file order.
	 *
	 * @var array<int,string>
	 */
	private array $headers;

	/** True once the end of the file has been reached. */
	private bool $done = false;

	/**
	 * Open a file for reading at a known byte offset.
	 *
	 * @param string            $path      Absolute path.
	 * @param string            $delimiter Field delimiter.
	 * @param array<int,string> $headers   Column headers.
	 * @param int               $offset    Byte offset to resume from.
	 */
	public function __construct( string $path, string $delimiter, array $headers, int $offset = 0 ) {
		$this->delimiter = '' === $delimiter ? ',' : $delimiter;
		$this->headers   = array_values( array_map( 'strval', $headers ) );

		$handle = fopen( $path, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( ! $handle ) {
			$this->done = true;
			return;
		}

		if ( $offset > 0 ) {
			fseek( $handle, $offset );
		}

		$this->handle = $handle;
	}

	/**
	 * Read the next data row.
	 *
	 * @return array<string,string>|null Row keyed by header, or null at EOF.
	 */
	public function next(): ?array {
		if ( $this->done || ! is_resource( $this->handle ) ) {
			return null;
		}

		while ( true ) {
			$cells = fgetcsv( $this->handle, 0, $this->delimiter, '"', '\\' );

			if ( false === $cells || null === $cells ) {
				$this->done = true;
				return null;
			}

			// fgetcsv yields [null] for a blank line.
			if ( array( null ) === $cells ) {
				continue;
			}

			$cells = array_slice( $cells, 0, self::MAX_COLUMNS );

			if ( '' === trim( implode( '', array_map( 'strval', $cells ) ) ) ) {
				continue;
			}

			$row = array();
			foreach ( $this->headers as $index => $header ) {
				$row[ $header ] = self::clean( $cells[ $index ] ?? '' );
			}

			return $row;
		}
	}

	/**
	 * Current byte offset — the checkpoint written after every batch.
	 *
	 * @return int
	 */
	public function offset(): int {
		if ( ! is_resource( $this->handle ) ) {
			return 0;
		}

		$offset = ftell( $this->handle );

		return false === $offset ? 0 : (int) $offset;
	}

	/**
	 * Has the reader reached the end of the file?
	 *
	 * @return bool
	 */
	public function finished(): bool {
		return $this->done;
	}

	/**
	 * Close the handle.
	 *
	 * @return void
	 */
	public function close(): void {
		if ( is_resource( $this->handle ) ) {
			fclose( $this->handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}

		$this->handle = null;
	}

	/* =================================================================
	 * Static helpers
	 * ============================================================== */

	/**
	 * Tidy one cell: collapse whitespace, drop control characters and tags.
	 *
	 * @param mixed $value Raw cell.
	 * @return string
	 */
	public static function clean( mixed $value ): string {
		if ( ! is_scalar( $value ) ) {
			return '';
		}

		$text = (string) $value;

		if ( '' === $text ) {
			return '';
		}

		$text = str_replace( array( "\xc2\xa0", "\r\n", "\r", "\n", "\t" ), ' ', $text );

		// The /u modifier returns null on invalid UTF-8, and a vendor export
		// with one mangled byte must not silently blank the whole column.
		$squashed = preg_replace( '/\s+/u', ' ', $text );

		if ( null === $squashed ) {
			$squashed = (string) preg_replace( '/\s+/', ' ', $text );
		}

		return trim( (string) $squashed );
	}

	/**
	 * Pick the delimiter that yields the most columns on the header line.
	 *
	 * @param string $path Absolute path.
	 * @return string
	 */
	public static function detect_delimiter( string $path ): string {
		$handle = fopen( $path, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( ! $handle ) {
			return ',';
		}

		$line = '';

		while ( ! feof( $handle ) ) {
			$candidate = (string) fgets( $handle, 65536 );

			if ( '' !== trim( $candidate ) ) {
				$line = $candidate;
				break;
			}
		}

		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		$best  = ',';
		$score = 0;

		foreach ( self::DELIMITERS as $delimiter ) {
			$count = substr_count( $line, $delimiter );

			if ( $count > $score ) {
				$score     = $count;
				$best      = $delimiter;
			}
		}

		return $best;
	}

	/**
	 * Read the header row and report where the data starts.
	 *
	 * @param string $path Absolute path.
	 * @return array{ok:bool,headers:array<int,string>,delimiter:string,offset:int,message:string}
	 */
	public static function read_header( string $path ): array {
		$fail = static fn( string $message ): array => array(
			'ok'        => false,
			'headers'   => array(),
			'delimiter' => ',',
			'offset'    => 0,
			'message'   => $message,
		);

		if ( ! is_readable( $path ) ) {
			return $fail( __( 'The staged file could not be read.', 'vulnhub' ) );
		}

		$delimiter = self::detect_delimiter( $path );
		$handle    = fopen( $path, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( ! $handle ) {
			return $fail( __( 'The staged file could not be read.', 'vulnhub' ) );
		}

		$headers = array();
		$offset  = 0;

		while ( true ) {
			$cells = fgetcsv( $handle, 0, $delimiter, '"', '\\' );

			if ( false === $cells || null === $cells ) {
				break;
			}

			$offset = (int) ftell( $handle );

			if ( array( null ) === $cells ) {
				continue;
			}

			$cells = array_slice( array_map( static fn( $cell ): string => self::clean( $cell ), $cells ), 0, self::MAX_COLUMNS );

			if ( '' === trim( implode( '', $cells ) ) ) {
				continue; // Leading blank lines before the header row.
			}

			$headers = self::unique_headers( self::strip_bom( $cells ) );
			break;
		}

		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( ! $headers ) {
			return $fail( __( 'No header row was found. The first non-empty line must name the columns.', 'vulnhub' ) );
		}

		return array(
			'ok'        => true,
			'headers'   => $headers,
			'delimiter' => $delimiter,
			'offset'    => $offset,
			'message'   => '',
		);
	}

	/**
	 * Read the first few data rows, for the mapping preview and for estimating
	 * how many rows the whole file holds.
	 *
	 * @param string            $path      Absolute path.
	 * @param string            $delimiter Field delimiter.
	 * @param array<int,string> $headers   Column headers.
	 * @param int               $offset    Byte offset of the first data row.
	 * @param int               $limit     How many rows to read.
	 * @return array{rows:array<int,array<string,string>>,bytes:int}
	 */
	public static function sample( string $path, string $delimiter, array $headers, int $offset, int $limit = 20 ): array {
		$reader = new self( $path, $delimiter, $headers, $offset );
		$rows   = array();
		$limit  = max( 1, min( 200, $limit ) );

		while ( count( $rows ) < $limit ) {
			$row = $reader->next();

			if ( null === $row ) {
				break;
			}

			$rows[] = $row;
		}

		$bytes = max( 0, $reader->offset() - $offset );
		$reader->close();

		return array(
			'rows'  => $rows,
			'bytes' => $bytes,
		);
	}

	/**
	 * Estimate the total number of data rows from a sample.
	 *
	 * @param int $size          File size in bytes.
	 * @param int $header_offset Byte offset of the first data row.
	 * @param int $sample_bytes  Bytes consumed by the sample.
	 * @param int $sample_rows   Rows in the sample.
	 * @return int
	 */
	public static function estimate_rows( int $size, int $header_offset, int $sample_bytes, int $sample_rows ): int {
		if ( $sample_rows < 1 || $sample_bytes < 1 ) {
			return 0;
		}

		$body = max( 0, $size - $header_offset );

		return (int) round( $body / ( $sample_bytes / $sample_rows ) );
	}

	/**
	 * Strip a UTF-8 byte-order mark from the first header cell.
	 *
	 * Excel writes one on every "CSV UTF-8" export, and without this the first
	 * column is called "\xEF\xBB\xBFPlugin" and never auto-maps.
	 *
	 * @param array<int,string> $cells Header cells.
	 * @return array<int,string>
	 */
	private static function strip_bom( array $cells ): array {
		if ( isset( $cells[0] ) ) {
			$cells[0] = (string) preg_replace( '/^\xEF\xBB\xBF/', '', $cells[0] );
		}

		return $cells;
	}

	/**
	 * Guarantee unique, non-empty header names.
	 *
	 * @param array<int,string> $cells Header cells.
	 * @return array<int,string>
	 */
	private static function unique_headers( array $cells ): array {
		$headers = array();
		$seen    = array();

		foreach ( $cells as $index => $cell ) {
			$header = trim( (string) $cell );

			if ( '' === $header ) {
				/* translators: %d: column number. */
				$header = sprintf( __( 'Column %d', 'vulnhub' ), (int) $index + 1 );
			}

			$base    = $header;
			$counter = 2;

			while ( isset( $seen[ $header ] ) ) {
				$header = $base . ' (' . $counter . ')';
				++$counter;
			}

			$seen[ $header ] = true;
			$headers[]       = $header;
		}

		return $headers;
	}
}

