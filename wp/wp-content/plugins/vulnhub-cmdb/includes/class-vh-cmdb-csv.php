<?php
/**
 * CSV parsing and upload validation.
 *
 * This is the back end that always works: no API, no credentials, no vendor.
 * It is also the one most likely to be handed a file exported from Excel by
 * somebody who has never seen this screen before, so it is deliberately
 * forgiving about delimiters, byte-order marks and ragged rows — and
 * deliberately unforgiving about anything that touches the filesystem.
 *
 * The uploaded file is never moved out of PHP's temporary directory and never
 * written inside the web root. It is parsed in place and then discarded; only
 * the parsed rows survive, in a short-lived transient.
 *
 * @package VulnHub\Cmdb
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * CSV reader plus the upload guard rails.
 */
final class VulnHub_Cmdb_Csv {

	/** Largest upload accepted, in bytes. */
	public const MAX_BYTES = 2097152;

	/** Largest number of data rows read from one file. */
	public const MAX_ROWS = 5000;

	/** Largest number of columns read from one file. */
	private const MAX_COLUMNS = 60;

	/** Delimiters tried, in order of likelihood. */
	private const DELIMITERS = array( ',', ';', "\t", '|' );

	/**
	 * Validate an entry from `$_FILES` and return the temporary path to parse.
	 *
	 * Everything here is about not trusting the client: the browser-supplied
	 * name is only ever used to read an extension, the size is checked against
	 * our own ceiling rather than the one in php.ini, and the real content type
	 * is sniffed from the bytes on disk.
	 *
	 * @param array<string,mixed> $file One entry from $_FILES.
	 * @return array{ok:bool,path:string,name:string,message:string}
	 */
	public static function validate_upload( array $file ): array {
		$fail = static fn( string $message ): array => array(
			'ok'      => false,
			'path'    => '',
			'name'    => '',
			'message' => $message,
		);

		$error = (int) ( $file['error'] ?? UPLOAD_ERR_NO_FILE );

		if ( UPLOAD_ERR_NO_FILE === $error ) {
			return $fail( __( 'Choose a CSV file to upload.', 'vulnhub' ) );
		}
		if ( UPLOAD_ERR_INI_SIZE === $error || UPLOAD_ERR_FORM_SIZE === $error ) {
			return $fail( __( 'That file is larger than this server accepts.', 'vulnhub' ) );
		}
		if ( UPLOAD_ERR_OK !== $error ) {
			/* translators: %d: PHP upload error code. */
			return $fail( sprintf( __( 'The upload did not complete (error %d).', 'vulnhub' ), $error ) );
		}

		$tmp = (string) ( $file['tmp_name'] ?? '' );

		// The single most important check on this screen: only a genuine
		// upload, never an arbitrary path a caller managed to inject.
		if ( '' === $tmp || ! is_uploaded_file( $tmp ) || ! is_readable( $tmp ) ) {
			return $fail( __( 'The uploaded file could not be read.', 'vulnhub' ) );
		}

		$size = (int) ( $file['size'] ?? 0 );

		if ( $size <= 0 ) {
			return $fail( __( 'The uploaded file is empty.', 'vulnhub' ) );
		}
		if ( $size > self::MAX_BYTES ) {
			return $fail(
				sprintf(
					/* translators: %s: maximum file size. */
					__( 'That file is %s; the importer accepts up to 2 MB. Split it, or point the connector at ServiceNow instead.', 'vulnhub' ),
					size_format( $size )
				)
			);
		}

		// The client filename is used for one thing only: reading an extension
		// and showing the operator what they picked. It never touches a path.
		$name      = sanitize_file_name( wp_basename( (string) ( $file['name'] ?? 'upload.csv' ) ) );
		$extension = strtolower( (string) pathinfo( $name, PATHINFO_EXTENSION ) );

		if ( ! in_array( $extension, array( 'csv', 'tsv', 'txt' ), true ) ) {
			return $fail( __( 'Only .csv, .tsv and .txt files are accepted.', 'vulnhub' ) );
		}

		// WordPress checks the extension against its own allow list and, where
		// the fileinfo extension is present, cross-checks the real type.
		$checked = wp_check_filetype_and_ext(
			$tmp,
			$name,
			array(
				'csv' => 'text/csv',
				'tsv' => 'text/tab-separated-values',
				'txt' => 'text/plain',
			)
		);

		if ( empty( $checked['ext'] ) ) {
			return $fail( __( 'That file does not look like a CSV once its contents are inspected.', 'vulnhub' ) );
		}

		if ( ! self::looks_like_text( $tmp ) ) {
			return $fail( __( 'That file contains binary data. Export it as CSV rather than as a workbook.', 'vulnhub' ) );
		}

		return array(
			'ok'      => true,
			'path'    => $tmp,
			'name'    => $name,
			'message' => '',
		);
	}

	/**
	 * Sniff the first kilobyte for NUL bytes and a plausible text media type.
	 *
	 * A .xlsx renamed to .csv is a ZIP archive, and this is what catches it.
	 */
	private static function looks_like_text( string $path ): bool {
		$handle = fopen( $path, 'rb' );

		if ( ! $handle ) {
			return false;
		}

		$head = (string) fread( $handle, 1024 );
		fclose( $handle );

		if ( '' === $head || str_contains( $head, "\0" ) ) {
			return false;
		}

		if ( function_exists( 'finfo_open' ) ) {
			$finfo = finfo_open( FILEINFO_MIME_TYPE );
			if ( false !== $finfo ) {
				$mime = (string) finfo_file( $finfo, $path );
				finfo_close( $finfo );

				// Some servers report CSV as application/csv or
				// application/vnd.ms-excel; anything else non-text is out.
				$allowed = array( 'text/csv', 'text/plain', 'text/tab-separated-values', 'application/csv', 'application/vnd.ms-excel' );
				if ( '' !== $mime && ! str_starts_with( $mime, 'text/' ) && ! in_array( $mime, $allowed, true ) ) {
					return false;
				}
			}
		}

		return true;
	}

	/**
	 * Parse a delimited file into headers and rows.
	 *
	 * @param string $path Readable path (a PHP upload temporary file).
	 * @return array{headers:array<int,string>,rows:array<int,array<string,string>>,errors:array<int,array{line:int,message:string}>,delimiter:string,truncated:bool}
	 */
	public static function parse( string $path ): array {
		$result = array(
			'headers'   => array(),
			'rows'      => array(),
			'errors'    => array(),
			'delimiter' => ',',
			'truncated' => false,
		);

		if ( ! is_readable( $path ) ) {
			$result['errors'][] = array(
				'line'    => 0,
				'message' => __( 'The file could not be opened.', 'vulnhub' ),
			);
			return $result;
		}

		$delimiter            = self::detect_delimiter( $path );
		$result['delimiter']  = $delimiter;
		$handle               = fopen( $path, 'rb' );

		if ( ! $handle ) {
			$result['errors'][] = array(
				'line'    => 0,
				'message' => __( 'The file could not be opened.', 'vulnhub' ),
			);
			return $result;
		}

		$line    = 0;
		$headers = array();

		while ( true ) {
			$cells = fgetcsv( $handle, 0, $delimiter, '"', '\\' );

			if ( false === $cells || null === $cells ) {
				break;
			}

			++$line;

			// fgetcsv yields [null] for a blank line.
			if ( array( null ) === $cells ) {
				continue;
			}

			$cells = array_slice( array_map( static fn( $cell ): string => VulnHub_Cmdb_Schema::clean( $cell ), $cells ), 0, self::MAX_COLUMNS );

			if ( ! $headers ) {
				if ( '' === trim( implode( '', $cells ) ) ) {
					continue; // Leading blank lines before the header row.
				}

				$headers            = self::unique_headers( self::strip_bom( $cells ) );
				$result['headers']  = $headers;
				continue;
			}

			if ( '' === trim( implode( '', $cells ) ) ) {
				continue;
			}

			if ( count( $result['rows'] ) >= self::MAX_ROWS ) {
				$result['truncated'] = true;
				break;
			}

			if ( count( $cells ) > count( $headers ) ) {
				$result['errors'][] = array(
					'line'    => $line,
					'message' => sprintf(
						/* translators: 1: number of values, 2: number of columns. */
						__( 'Row has %1$d values but the header has %2$d columns; the extra values were ignored.', 'vulnhub' ),
						count( $cells ),
						count( $headers )
					),
				);
			}

			$row = array();
			foreach ( $headers as $index => $header ) {
				$row[ $header ] = (string) ( $cells[ $index ] ?? '' );
			}

			$row['__line'] = (string) $line;
			$result['rows'][] = $row;
		}

		fclose( $handle );

		if ( ! $headers ) {
			$result['errors'][] = array(
				'line'    => 0,
				'message' => __( 'No header row was found. The first non-empty line must name the columns.', 'vulnhub' ),
			);
		}

		return $result;
	}

	/**
	 * Pick the delimiter that yields the most columns on the header line.
	 */
	private static function detect_delimiter( string $path ): string {
		$handle = fopen( $path, 'rb' );

		if ( ! $handle ) {
			return ',';
		}

		$line = '';
		while ( ! feof( $handle ) ) {
			$candidate = (string) fgets( $handle, 8192 );
			if ( '' !== trim( $candidate ) ) {
				$line = $candidate;
				break;
			}
		}
		fclose( $handle );

		$best  = ',';
		$score = 0;

		foreach ( self::DELIMITERS as $delimiter ) {
			$count = substr_count( $line, $delimiter );
			if ( $count > $score ) {
				$score = $count;
				$best  = $delimiter;
			}
		}

		return $best;
	}

	/**
	 * Strip a UTF-8 byte-order mark from the first header cell.
	 *
	 * Excel writes one on every "CSV UTF-8" export, and without this the first
	 * column is called "\xEF\xBB\xBFHostname" and never auto-maps.
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

	/**
	 * Path to the sample file shipped with the plugin.
	 */
	public static function sample_path(): string {
		return VULNHUB_CMDB_DIR . 'data/sample-cmdb.csv';
	}
}

