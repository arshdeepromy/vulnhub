<?php
/**
 * Ticket attachments: the local copy, the preview, and serving the file.
 *
 * The list of files on a ticket arrives with the ticketing provider's poll
 * (Tickets::attachments()). The bytes do not: they are fetched the first
 * time somebody opens a file, through `vulnhub_ticket_attachment_bytes`,
 * and kept under uploads/vulnhub-attachments so the second look costs
 * nothing. A provider's attachment id never changes its content -- Jira has
 * no "replace file", only "add another" -- so the copy never goes stale; it
 * only ages out when the folder outgrows its cap.
 *
 * The browser is never sent to the provider. Every byte comes through this
 * site, under the viewer's own session, and only for an id that is on that
 * ticket's own list.
 *
 * What a preview may do is deliberately narrow. Spreadsheets, CSV and Word
 * documents are parsed here and handed to the page as data, which the page
 * writes as text. Images, PDF, audio and video are served inline with
 * nosniff, a type chosen from the file's extension and confirmed against
 * its contents, and -- except for PDF, whose viewer will not run under it
 * -- a sandboxing Content-Security-Policy. HTML is shown as source, never
 * rendered. Anything else is offered as a download.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Attachments {

	/** Folder under uploads. Excluded from backups: it is a re-fetchable cache. */
	public const DIRNAME = 'vulnhub-attachments';

	/** Rows of a table shown in a preview. The download has the rest. */
	public const PREVIEW_ROWS = 500;

	/** Columns of a table shown in a preview. */
	public const PREVIEW_COLS = 60;

	/** Characters kept per cell. */
	public const CELL_CHARS = 500;

	/** Sheets of a workbook previewed. */
	public const MAX_SHEETS = 12;

	/** Bytes of a text file shown. */
	public const TEXT_BYTES = 262144;

	/** The most any single entry inside a zip-based file may inflate to. */
	public const ZIP_ENTRY_CAP = 67108864;

	/**
	 * Extension => [kind, MIME served]. The served type comes from here,
	 * never from the provider: a file called report.png that Jira says is
	 * text/html is still not served as HTML.
	 *
	 * @var array<string,array{0:string,1:string}>
	 */
	private const TYPES = array(
		'png'  => array( 'image', 'image/png' ),
		'jpg'  => array( 'image', 'image/jpeg' ),
		'jpeg' => array( 'image', 'image/jpeg' ),
		'gif'  => array( 'image', 'image/gif' ),
		'webp' => array( 'image', 'image/webp' ),
		'bmp'  => array( 'image', 'image/bmp' ),
		'avif' => array( 'image', 'image/avif' ),
		'svg'  => array( 'image', 'image/svg+xml' ),
		'pdf'  => array( 'pdf', 'application/pdf' ),
		'csv'  => array( 'table', 'text/csv' ),
		'tsv'  => array( 'table', 'text/tab-separated-values' ),
		'xlsx' => array( 'sheet', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' ),
		'xlsm' => array( 'sheet', 'application/vnd.ms-excel.sheet.macroEnabled.12' ),
		'xltx' => array( 'sheet', 'application/vnd.openxmlformats-officedocument.spreadsheetml.template' ),
		'docx' => array( 'doc', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' ),
		'docm' => array( 'doc', 'application/vnd.ms-word.document.macroEnabled.12' ),
		'dotx' => array( 'doc', 'application/vnd.openxmlformats-officedocument.wordprocessingml.template' ),
		'mp4'  => array( 'video', 'video/mp4' ),
		'webm' => array( 'video', 'video/webm' ),
		'ogv'  => array( 'video', 'video/ogg' ),
		'mp3'  => array( 'audio', 'audio/mpeg' ),
		'wav'  => array( 'audio', 'audio/wav' ),
		'ogg'  => array( 'audio', 'audio/ogg' ),
		'm4a'  => array( 'audio', 'audio/mp4' ),
	);

	/**
	 * Extensions shown as plain text. HTML and SVG source included: shown,
	 * never rendered.
	 */
	private const TEXT_EXT = array(
		'txt', 'log', 'json', 'xml', 'md', 'markdown', 'yaml', 'yml', 'ini', 'conf', 'cfg', 'toml',
		'properties', 'sh', 'bash', 'ps1', 'psm1', 'bat', 'cmd', 'py', 'js', 'ts', 'php', 'rb', 'go',
		'java', 'cs', 'sql', 'css', 'html', 'htm', 'eml', 'nessus', 'out', 'diff', 'patch', 'tf', 'hcl',
	);

	/**
	 * Formats people will expect to preview and that are refused on
	 * purpose, with why -- better than a silent "no preview".
	 *
	 * @return array<string,string>
	 */
	private static function refused(): array {
		return array(
			'xls'  => __( 'An old-format Excel workbook (.xls) cannot be previewed here. Download it, or save it as .xlsx.', 'vulnhub' ),
			'doc'  => __( 'An old-format Word document (.doc) cannot be previewed here. Download it.', 'vulnhub' ),
			'ppt'  => __( 'PowerPoint files are not previewed. Download it.', 'vulnhub' ),
			'pptx' => __( 'PowerPoint files are not previewed. Download it.', 'vulnhub' ),
			'msg'  => __( 'Outlook messages are not previewed. Download it.', 'vulnhub' ),
			'zip'  => __( 'Archives are not opened here. Download it.', 'vulnhub' ),
			'7z'   => __( 'Archives are not opened here. Download it.', 'vulnhub' ),
			'rar'  => __( 'Archives are not opened here. Download it.', 'vulnhub' ),
			'gz'   => __( 'Archives are not opened here. Download it.', 'vulnhub' ),
			'exe'  => __( 'Programs are never opened here. Download it only if you trust where it came from.', 'vulnhub' ),
			'msi'  => __( 'Programs are never opened here. Download it only if you trust where it came from.', 'vulnhub' ),
		);
	}

	/**
	 * The largest file this site will fetch from the provider.
	 *
	 * Filter `vulnhub_ticket_attachment_fetch_limit`.
	 */
	public static function fetch_cap(): int {
		return max( 1, (int) apply_filters( 'vulnhub_ticket_attachment_fetch_limit', 25 * MB_IN_BYTES ) );
	}

	/**
	 * The most the local copies may take up before the oldest go.
	 *
	 * Filter `vulnhub_ticket_attachment_cache_limit`.
	 */
	public static function cache_cap(): int {
		return max( 1, (int) apply_filters( 'vulnhub_ticket_attachment_cache_limit', 512 * MB_IN_BYTES ) );
	}

	/**
	 * Lower-case extension of a file name, or ''.
	 */
	public static function ext( string $name ): string {
		$dot = strrpos( $name, '.' );

		return false === $dot ? '' : strtolower( substr( $name, $dot + 1 ) );
	}

	/**
	 * What kind of preview a file gets: image, pdf, table, sheet, doc, text,
	 * video, audio or none.
	 */
	public static function kind( string $name, string $mime = '' ): string {
		$ext = self::ext( $name );

		if ( isset( self::TYPES[ $ext ] ) ) {
			return self::TYPES[ $ext ][0];
		}
		if ( in_array( $ext, self::TEXT_EXT, true ) ) {
			return 'text';
		}
		if ( isset( self::refused()[ $ext ] ) ) {
			return 'none';
		}

		// No telling extension: trust a plain text type, nothing more.
		return str_starts_with( strtolower( $mime ), 'text/' ) ? 'text' : 'none';
	}

	/**
	 * Decorate a stored attachment for the page: kind, readable size and age,
	 * whether this site's own account added it, and the two URLs.
	 *
	 * @param array<string,mixed> $a         One entry from Tickets::attachments().
	 * @param string              $own       The provider account this site acts as.
	 * @param string              $list_file The last list this site sent, if any.
	 * @return array<string,mixed>
	 */
	public static function describe( int $ticket_id, array $a, string $own = '', string $list_file = '' ): array {
		$name = (string) ( $a['filename'] ?? '' );
		$id   = (string) ( $a['id'] ?? '' );
		$base = rest_url( Rest::NS . '/tickets/' . $ticket_id . '/attachments/' . rawurlencode( $id ) . '/file' );
		$nonce = wp_create_nonce( 'wp_rest' );

		return $a + array(
			'kind'       => self::kind( $name, (string) ( $a['mime'] ?? '' ) ),
			'ext'        => self::ext( $name ),
			'size_label' => size_format( (int) ( $a['size'] ?? 0 ) ) ?: '0 B',
			'ago'        => vh_ago( (string) ( $a['created'] ?? '' ) ),
			'when'       => vh_date( (string) ( $a['created'] ?? '' ) ),
			'mine'       => self::is_ours( $a, $own, $list_file ),
			'too_big'    => (int) ( $a['size'] ?? 0 ) > self::fetch_cap(),
			'view_url'   => add_query_arg( array( '_wpnonce' => $nonce ), $base ),
			'download'   => add_query_arg( array( '_wpnonce' => $nonce, 'download' => 1 ), $base ),
		);
	}

	/**
	 * Was this file added by us -- the ticketing account this site is
	 * connected as, or the last list this site sent -- rather than by
	 * somebody else?
	 *
	 * @param array<string,mixed> $a Attachment.
	 */
	public static function is_ours( array $a, string $own, string $list_file = '' ): bool {
		return ( '' !== $own && $own === (string) ( $a['author_id'] ?? '' ) )
			|| ( '' !== $list_file && $list_file === (string) ( $a['filename'] ?? '' ) );
	}

	/**
	 * How many files a ticket has, split by who added them -- for the
	 * Tickets list, which shows this without any round trip.
	 *
	 * @param array<string,mixed> $ticket Ticket row.
	 * @return array{total:int,ours:int,theirs:int,newest_theirs:string}
	 */
	public static function counts( array $ticket, string $own ): array {
		$sent  = Tickets::list_sent( $ticket );
		$file  = is_array( $sent ) ? (string) ( $sent['file'] ?? '' ) : '';
		$out   = array( 'total' => 0, 'ours' => 0, 'theirs' => 0, 'newest_theirs' => '' );

		foreach ( Tickets::attachments( $ticket ) as $a ) {
			++$out['total'];

			if ( self::is_ours( (array) $a, $own, $file ) ) {
				++$out['ours'];
				continue;
			}

			++$out['theirs'];
			$out['newest_theirs'] = max( $out['newest_theirs'], (string) ( $a['created'] ?? '' ) );
		}

		return $out;
	}

	/* =================================================================
	 * The local copy
	 * ============================================================== */

	/**
	 * The cache folder, made and fenced off on first use.
	 */
	public static function dir(): string {
		$uploads = wp_upload_dir( null, false );
		$dir     = rtrim( (string) $uploads['basedir'], '/\\' ) . '/' . self::DIRNAME;

		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}

		foreach ( array(
			'.htaccess'  => "# VulnHub ticket attachments. Served only through the REST route, never directly.\n<IfModule mod_authz_core.c>\n\tRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n\tOrder allow,deny\n\tDeny from all\n</IfModule>\n",
			'index.php'  => "<?php\n// Silence.\n",
			'index.html' => '',
		) as $file => $body ) {
			if ( ! file_exists( $dir . '/' . $file ) ) {
				file_put_contents( $dir . '/' . $file, $body ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			}
		}

		return $dir;
	}

	/**
	 * Path of the local copy of one attachment (which may not exist yet).
	 *
	 * @param array<string,mixed> $a Attachment.
	 */
	private static function path_for( int $ticket_id, array $a ): string {
		$id = preg_replace( '/[^0-9A-Za-z_-]/', '', (string) ( $a['id'] ?? '' ) );

		return self::dir() . '/' . $ticket_id . '-' . $id . '.bin';
	}

	/**
	 * The attachment on disk, fetching it from the provider if this is the
	 * first look.
	 *
	 * @param array<string,mixed> $ticket Ticket row.
	 * @param array<string,mixed> $a      Attachment (already checked to be on the ticket).
	 * @return array{ok:bool,message:string,path:string}
	 */
	public static function local( array $ticket, array $a ): array {
		$path = self::path_for( (int) $ticket['id'], $a );
		$size = (int) ( $a['size'] ?? 0 );

		if ( is_file( $path ) && ( $size <= 0 || filesize( $path ) === $size ) ) {
			// Touched, so the oldest-first pruning means least recently used.
			@touch( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors

			return array( 'ok' => true, 'message' => '', 'path' => $path );
		}

		/**
		 * Filters fetching one attachment's bytes from the ticketing system.
		 *
		 * @param array<string,mixed>|null $result {ok, message, bytes, mime}.
		 * @param array<string,mixed>      $ticket Ticket row.
		 * @param array<string,mixed>      $a      Attachment.
		 * @param int                      $cap    Most bytes to accept.
		 */
		$got = apply_filters( 'vulnhub_ticket_attachment_bytes', null, $ticket, $a, self::fetch_cap() );

		if ( ! is_array( $got ) ) {
			return array( 'ok' => false, 'message' => __( 'No ticketing integration can fetch this file.', 'vulnhub' ), 'path' => '' );
		}
		if ( empty( $got['ok'] ) ) {
			return array( 'ok' => false, 'message' => (string) ( $got['message'] ?? __( 'The file could not be fetched.', 'vulnhub' ) ), 'path' => '' );
		}

		$tmp = $path . '.' . bin2hex( random_bytes( 4 ) ) . '.part';

		if ( false === file_put_contents( $tmp, (string) $got['bytes'], LOCK_EX ) || ! rename( $tmp, $path ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
			@unlink( $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors

			return array( 'ok' => false, 'message' => __( 'The file was fetched but could not be kept on this server.', 'vulnhub' ), 'path' => '' );
		}

		self::prune();

		return array( 'ok' => true, 'message' => '', 'path' => $path );
	}

	/**
	 * Delete the least recently opened copies until the folder is back under
	 * 80% of its cap. Cheap: one directory listing, only when a file is added.
	 */
	public static function prune(): void {
		$files = glob( self::dir() . '/*.bin' ) ?: array();
		$sizes = array();
		$total = 0;

		foreach ( $files as $f ) {
			$sizes[ $f ] = array( (int) filemtime( $f ), (int) filesize( $f ) );
			$total      += $sizes[ $f ][1];
		}

		if ( $total <= self::cache_cap() ) {
			return;
		}

		uasort( $sizes, static fn( array $x, array $y ): int => $x[0] <=> $y[0] );

		foreach ( $sizes as $f => $info ) {
			if ( $total <= (int) ( self::cache_cap() * 0.8 ) ) {
				break;
			}
			@unlink( $f ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$total -= $info[1];
		}
	}

	/* =================================================================
	 * Serving the file
	 * ============================================================== */

	/**
	 * Send the file and stop.
	 *
	 * Inline only for the kinds the preview shows inline, and only when the
	 * bytes agree with the extension; everything else is a download.
	 */
	public static function stream( string $path, string $name, bool $download ): void {
		$ext    = self::ext( $name );
		$kind   = self::kind( $name );
		$inline = ! $download && in_array( $kind, array( 'image', 'pdf', 'video', 'audio' ), true ) && self::bytes_match( $path, $ext );
		$type   = $inline ? self::TYPES[ $ext ][1] : 'application/octet-stream';
		$safe   = str_replace( array( '"', "\r", "\n", '\\' ), '', $name );
		$ascii  = preg_replace( '/[^\x20-\x7E]/', '_', $safe );

		while ( ob_get_level() > 0 ) {
			ob_end_clean();
		}

		nocache_headers();
		header( 'Cache-Control: private, max-age=600' );
		header( 'Content-Type: ' . $type );
		header( 'Content-Length: ' . (string) filesize( $path ) );
		header( 'Content-Disposition: ' . ( $inline ? 'inline' : 'attachment' ) . '; filename="' . $ascii . '"; filename*=UTF-8\'\'' . rawurlencode( $safe ) );
		header( 'X-Content-Type-Options: nosniff' );
		header( 'X-Frame-Options: SAMEORIGIN' );
		header( 'Referrer-Policy: no-referrer' );

		// A PDF viewer will not start inside a sandbox; everything else is
		// boxed, so an SVG opened in its own tab still runs nothing.
		if ( 'pdf' !== $kind ) {
			header( "Content-Security-Policy: default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'; sandbox" );
		}

		readfile( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		exit;
	}

	/**
	 * Do the first bytes of the file agree with its extension?
	 *
	 * A file named .png that is really HTML would otherwise be served with
	 * an image type the browser ignores under nosniff -- harmless, but a
	 * broken preview. This makes it a download instead, and says nothing
	 * the extension did not.
	 */
	private static function bytes_match( string $path, string $ext ): bool {
		if ( ! function_exists( 'finfo_open' ) ) {
			return 'svg' !== $ext;
		}

		$finfo = finfo_open( FILEINFO_MIME_TYPE );
		$found = $finfo ? (string) finfo_file( $finfo, $path ) : '';

		$kind = self::TYPES[ $ext ][0] ?? '';

		return match ( true ) {
			'svg' === $ext   => in_array( $found, array( 'image/svg+xml', 'text/xml', 'application/xml', 'text/plain', 'text/html' ), true ) && self::looks_like_svg( $path ),
			'image' === $kind => str_starts_with( $found, 'image/' ),
			'pdf' === $kind   => 'application/pdf' === $found,
			'video' === $kind, 'audio' === $kind => str_starts_with( $found, 'video/' ) || str_starts_with( $found, 'audio/' ) || 'application/octet-stream' === $found,
			default          => false,
		};
	}

	private static function looks_like_svg( string $path ): bool {
		$head = (string) file_get_contents( $path, false, null, 0, 4096 ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		return false !== stripos( $head, '<svg' );
	}

	/* =================================================================
	 * Preview
	 * ============================================================== */

	/**
	 * What the preview pop-up needs, as data.
	 *
	 * @return array<string,mixed>
	 */
	public static function preview( string $path, string $name, string $mime = '' ): array {
		$kind = '' === $path ? 'none' : self::kind( $name, $mime );
		$ext  = self::ext( $name );
		$out  = array( 'ok' => true, 'kind' => $kind, 'name' => $name, 'size' => '' === $path ? 0 : (int) filesize( $path ) );

		try {
			switch ( $kind ) {
				case 'image':
				case 'pdf':
				case 'video':
				case 'audio':
					if ( ! self::bytes_match( $path, $ext ) ) {
						return array(
							'ok'      => true,
							'kind'    => 'none',
							'name'    => $name,
							'message' => __( 'The file’s contents do not match its name, so it is not shown here. Download it to look at it.', 'vulnhub' ),
						);
					}
					return $out;

				case 'table':
					return array_merge( $out, self::table( (string) file_get_contents( $path ), 'tsv' === $ext ? "\t" : '' ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions

				case 'sheet':
					return array_merge( $out, self::workbook( $path ) );

				case 'doc':
					return array_merge( $out, self::docx( $path ) );

				case 'text':
					return array_merge( $out, self::text( $path, $ext ) );
			}
		} catch ( \Throwable $e ) {
			return array(
				'ok'      => true,
				'kind'    => 'none',
				'name'    => $name,
				'message' => sprintf(
					/* translators: %s: parser error. */
					__( 'This file could not be read for a preview (%s). Download it instead.', 'vulnhub' ),
					vh_trim( $e->getMessage(), 140 )
				),
			);
		}

		return array(
			'ok'      => true,
			'kind'    => 'none',
			'name'    => $name,
			'message' => self::refused()[ $ext ] ?? __( 'There is no preview for this kind of file. Download it to open it.', 'vulnhub' ),
		);
	}

	/**
	 * Bytes as UTF-8, whatever Excel or a scanner saved them as.
	 */
	private static function utf8( string $raw ): string {
		if ( str_starts_with( $raw, "\xEF\xBB\xBF" ) ) {
			return substr( $raw, 3 );
		}
		if ( str_starts_with( $raw, "\xFF\xFE" ) ) {
			return (string) mb_convert_encoding( substr( $raw, 2 ), 'UTF-8', 'UTF-16LE' );
		}
		if ( str_starts_with( $raw, "\xFE\xFF" ) ) {
			return (string) mb_convert_encoding( substr( $raw, 2 ), 'UTF-8', 'UTF-16BE' );
		}

		return mb_check_encoding( $raw, 'UTF-8' ) ? $raw : (string) mb_convert_encoding( $raw, 'UTF-8', 'Windows-1252' );
	}

	private static function cell( mixed $v ): string {
		$v = trim( (string) $v );

		return mb_strlen( $v ) > self::CELL_CHARS ? mb_substr( $v, 0, self::CELL_CHARS ) . '…' : $v;
	}

	/**
	 * A CSV or TSV as rows.
	 *
	 * @return array<string,mixed>
	 */
	private static function table( string $raw, string $delimiter = '' ): array {
		$text = self::utf8( $raw );

		if ( '' === $delimiter ) {
			$first = strtok( $text, "\n" );
			$first = false === $first ? '' : $first;
			$best  = ',';
			$most  = -1;

			foreach ( array( ',', ';', "\t", '|' ) as $d ) {
				$n = substr_count( $first, $d );
				if ( $n > $most ) {
					$most = $n;
					$best = $d;
				}
			}
			$delimiter = $best;
		}

		$h = fopen( 'php://temp', 'r+' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		fwrite( $h, $text ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		rewind( $h );

		$rows  = array();
		$total = 0;
		$wide  = 0;

		while ( false !== ( $r = fgetcsv( $h, null, $delimiter, '"', '' ) ) ) {
			if ( array( null ) === $r ) {
				continue;
			}
			++$total;
			$wide = max( $wide, count( $r ) );

			if ( count( $rows ) < self::PREVIEW_ROWS ) {
				$rows[] = array_map( array( self::class, 'cell' ), array_slice( $r, 0, self::PREVIEW_COLS ) );
			}
		}
		fclose( $h ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		return array(
			'sheets' => array(
				array(
					'name'       => '',
					'rows'       => $rows,
					'total_rows' => $total,
					'total_cols' => $wide,
				),
			),
			'delimiter' => "\t" === $delimiter ? 'tab' : $delimiter,
		);
	}

	/**
	 * Read one entry of a zip-based Office file, refusing anything that
	 * inflates past the entry cap.
	 */
	private static function zip_entry( \ZipArchive $zip, string $name ): ?string {
		$stat = $zip->statName( $name );

		if ( false === $stat ) {
			return null;
		}
		if ( (int) $stat['size'] > self::ZIP_ENTRY_CAP ) {
			throw new \RuntimeException( 'a part of the file is larger than this preview will unpack' );
		}

		$data = $zip->getFromName( $name );

		return false === $data ? null : $data;
	}

	private static function xml_reader( string $xml ): \XMLReader {
		$r = \XMLReader::XML( $xml, null, LIBXML_NONET | LIBXML_COMPACT | LIBXML_PARSEHUGE );

		if ( ! $r instanceof \XMLReader ) {
			throw new \RuntimeException( 'unreadable XML' );
		}

		return $r;
	}

	/**
	 * An .xlsx workbook: every sheet's first rows, cells typed as Excel shows
	 * them closely enough to read -- shared strings resolved, booleans as
	 * TRUE/FALSE, and date-formatted numbers as dates.
	 *
	 * @return array<string,mixed>
	 */
	private static function workbook( string $path ): array {
		if ( ! class_exists( '\ZipArchive' ) ) {
			throw new \RuntimeException( 'this server cannot open zip files' );
		}

		$zip = new \ZipArchive();

		if ( true !== $zip->open( $path, \ZipArchive::RDONLY ) ) {
			throw new \RuntimeException( 'not a valid workbook' );
		}
		if ( $zip->numFiles > 20000 ) {
			throw new \RuntimeException( 'too many parts' );
		}

		// Sheet names, in workbook order, and where each one lives.
		$book = self::zip_entry( $zip, 'xl/workbook.xml' );
		$rels = self::zip_entry( $zip, 'xl/_rels/workbook.xml.rels' );

		if ( null === $book ) {
			throw new \RuntimeException( 'no workbook part' );
		}

		$targets = array();
		if ( null !== $rels ) {
			$r = self::xml_reader( $rels );
			while ( $r->read() ) {
				if ( \XMLReader::ELEMENT === $r->nodeType && 'Relationship' === $r->localName ) {
					$targets[ (string) $r->getAttribute( 'Id' ) ] = (string) $r->getAttribute( 'Target' );
				}
			}
			$r->close();
		}

		$sheets = array();
		$r      = self::xml_reader( $book );
		$date1904 = false;
		while ( $r->read() ) {
			if ( \XMLReader::ELEMENT !== $r->nodeType ) {
				continue;
			}
			if ( 'workbookPr' === $r->localName ) {
				$date1904 = in_array( (string) $r->getAttribute( 'date1904' ), array( '1', 'true' ), true );
			}
			if ( 'sheet' === $r->localName ) {
				$rid    = (string) $r->getAttributeNs( 'id', 'http://schemas.openxmlformats.org/officeDocument/2006/relationships' );
				$target = $targets[ $rid ] ?? '';
				if ( '' === $target ) {
					continue;
				}
				$target   = str_starts_with( $target, '/' ) ? ltrim( $target, '/' ) : 'xl/' . $target;
				$sheets[] = array( 'name' => (string) $r->getAttribute( 'name' ), 'part' => $target, 'hidden' => '' !== (string) $r->getAttribute( 'state' ) && 'visible' !== (string) $r->getAttribute( 'state' ) );
			}
		}
		$r->close();

		$strings = self::shared_strings( $zip );
		$dates   = self::date_styles( $zip );
		$out     = array();

		foreach ( array_slice( $sheets, 0, self::MAX_SHEETS ) as $sheet ) {
			$xml = self::zip_entry( $zip, $sheet['part'] );
			if ( null === $xml ) {
				continue;
			}
			$out[] = array( 'name' => $sheet['name'], 'hidden' => $sheet['hidden'] ) + self::sheet_rows( $xml, $strings, $dates, $date1904 );
		}

		$zip->close();

		return array(
			'sheets'       => $out,
			'total_sheets' => count( $sheets ),
		);
	}

	/**
	 * @return string[]
	 */
	private static function shared_strings( \ZipArchive $zip ): array {
		$xml = self::zip_entry( $zip, 'xl/sharedStrings.xml' );

		if ( null === $xml ) {
			return array();
		}

		$out  = array();
		$r    = self::xml_reader( $xml );
		$cur  = null;
		$skip = 0;

		while ( $r->read() ) {
			if ( \XMLReader::ELEMENT === $r->nodeType ) {
				if ( 'si' === $r->localName ) {
					$cur = '';
				} elseif ( 'rPh' === $r->localName && ! $r->isEmptyElement ) {
					// Phonetic guide text: not part of what the cell shows.
					++$skip;
				} elseif ( 't' === $r->localName && null !== $cur && 0 === $skip ) {
					$cur .= $r->readString();
				}
			} elseif ( \XMLReader::END_ELEMENT === $r->nodeType ) {
				if ( 'rPh' === $r->localName && $skip > 0 ) {
					--$skip;
				} elseif ( 'si' === $r->localName ) {
					$out[] = (string) $cur;
					$cur   = null;
				}
			}
		}
		$r->close();

		return $out;
	}

	/**
	 * Which cell style indexes are date or time formats.
	 *
	 * @return array<int,string> style index => 'date' | 'datetime' | 'time'
	 */
	private static function date_styles( \ZipArchive $zip ): array {
		$xml = self::zip_entry( $zip, 'xl/styles.xml' );

		if ( null === $xml ) {
			return array();
		}

		$builtin = array(
			14 => 'date', 15 => 'date', 16 => 'date', 17 => 'date', 22 => 'datetime',
			18 => 'time', 19 => 'time', 20 => 'time', 21 => 'time', 45 => 'time', 46 => 'time', 47 => 'time',
		);
		$custom  = array();
		$out     = array();
		$in_xfs  = false;
		$index   = 0;
		$r       = self::xml_reader( $xml );

		while ( $r->read() ) {
			if ( \XMLReader::ELEMENT === $r->nodeType ) {
				if ( 'numFmt' === $r->localName ) {
					$code = strtolower( (string) preg_replace( '/"[^"]*"|\[(?![hms]+\])[^\]]*\]|\\\\./', '', (string) $r->getAttribute( 'formatCode' ) ) );
					// `m` is a month unless an hour or second sits with it.
					$t    = (bool) preg_match( '/[hs]/', $code );
					$d    = (bool) preg_match( '/[dy]/', $code ) || ( str_contains( $code, 'm' ) && ! $t );
					if ( $d || $t ) {
						$custom[ (int) $r->getAttribute( 'numFmtId' ) ] = $d && $t ? 'datetime' : ( $d ? 'date' : 'time' );
					}
				} elseif ( 'cellXfs' === $r->localName ) {
					$in_xfs = ! $r->isEmptyElement;
				} elseif ( 'xf' === $r->localName && $in_xfs ) {
					$fmt = (int) $r->getAttribute( 'numFmtId' );
					if ( isset( $custom[ $fmt ] ) || isset( $builtin[ $fmt ] ) ) {
						$out[ $index ] = $custom[ $fmt ] ?? $builtin[ $fmt ];
					}
					++$index;
				}
			} elseif ( \XMLReader::END_ELEMENT === $r->nodeType && 'cellXfs' === $r->localName ) {
				$in_xfs = false;
			}
		}
		$r->close();

		return $out;
	}

	/**
	 * Column letters to a zero-based index: A => 0, AA => 26.
	 */
	private static function col_index( string $ref ): int {
		$letters = strtoupper( (string) preg_replace( '/[^A-Za-z]/', '', $ref ) );
		$n       = 0;

		for ( $i = 0, $len = strlen( $letters ); $i < $len; $i++ ) {
			$n = $n * 26 + ( ord( $letters[ $i ] ) - 64 );
		}

		return max( 0, $n - 1 );
	}

	/**
	 * An Excel serial date as text. 1900 system, with Excel's phantom
	 * 29 Feb 1900 accounted for.
	 */
	private static function serial_date( float $serial, string $style, bool $date1904 ): string {
		$days = $date1904 ? $serial + 1462 : $serial;
		$unix = (int) round( ( $days - 25569 ) * 86400 );

		return match ( $style ) {
			'time'     => gmdate( 'H:i:s', $unix ),
			'datetime' => gmdate( 'Y-m-d H:i', $unix ),
			default    => gmdate( 'Y-m-d', $unix ),
		};
	}

	/**
	 * @param string[]          $strings Shared strings.
	 * @param array<int,string> $dates   Date styles.
	 * @return array<string,mixed>
	 */
	private static function sheet_rows( string $xml, array $strings, array $dates, bool $date1904 ): array {
		$rows  = array();
		$total = 0;
		$wide  = 0;
		$r     = self::xml_reader( $xml );
		$row   = null;
		$col   = 0;
		$type  = '';
		$style = 0;
		$value = null;

		while ( $r->read() ) {
			if ( \XMLReader::ELEMENT === $r->nodeType ) {
				switch ( $r->localName ) {
					case 'row':
						++$total;
						$row = $total <= self::PREVIEW_ROWS ? array() : null;
						$col = 0;
						if ( $r->isEmptyElement && null !== $row ) {
							$rows[] = array();
							$row    = null;
						}
						break;

					case 'c':
						$ref   = (string) $r->getAttribute( 'r' );
						$col   = '' !== $ref ? self::col_index( $ref ) : $col;
						$type  = (string) $r->getAttribute( 't' );
						$style = (int) $r->getAttribute( 's' );
						$value = null;
						$wide  = max( $wide, $col + 1 );
						if ( $r->isEmptyElement ) {
							++$col;
						}
						break;

					case 'v':
						if ( null !== $row ) {
							$value = $r->readString();
						}
						break;

					case 'is':
						if ( null !== $row ) {
							$value = $r->readString();
							$type  = 'inlineStr';
						}
						break;
				}
			} elseif ( \XMLReader::END_ELEMENT === $r->nodeType ) {
				if ( 'c' === $r->localName ) {
					if ( null !== $row && null !== $value && $col < self::PREVIEW_COLS ) {
						$row[ $col ] = self::cell( self::cell_text( (string) $value, $type, $style, $strings, $dates, $date1904 ) );
					}
					++$col;
				} elseif ( 'row' === $r->localName && null !== $row ) {
					$filled = array();
					if ( $row ) {
						$last = max( array_keys( $row ) );
						for ( $i = 0; $i <= $last; $i++ ) {
							$filled[] = $row[ $i ] ?? '';
						}
					}
					$rows[] = $filled;
					$row    = null;
				}
			}
		}
		$r->close();

		// Excel writes formatting-only rows past the data; drop the empty tail.
		while ( $rows && ! array_filter( end( $rows ), static fn( $c ): bool => '' !== $c ) ) {
			array_pop( $rows );
		}

		return array(
			'rows'       => $rows,
			'total_rows' => $total,
			'total_cols' => $wide,
		);
	}

	/**
	 * @param string[]          $strings Shared strings.
	 * @param array<int,string> $dates   Date styles.
	 */
	private static function cell_text( string $v, string $type, int $style, array $strings, array $dates, bool $date1904 ): string {
		switch ( $type ) {
			case 's':
				return (string) ( $strings[ (int) $v ] ?? '' );
			case 'b':
				return '1' === $v ? 'TRUE' : 'FALSE';
			case 'str':
			case 'inlineStr':
			case 'e':
				return $v;
		}

		if ( is_numeric( $v ) && isset( $dates[ $style ] ) ) {
			return self::serial_date( (float) $v, $dates[ $style ], $date1904 );
		}

		// Excel stores 0.1 as 0.10000000000000001; show what a person typed.
		if ( is_numeric( $v ) && str_contains( $v, '.' ) ) {
			return (string) ( 0 + round( (float) $v, 10 ) );
		}

		return $v;
	}

	/** Word previews: at most this many blocks (paragraphs, tables, cells' paragraphs). */
	public const DOCX_BLOCKS = 6000;

	/** Word previews: embedded pictures shown, and their total size. */
	public const DOCX_IMAGES      = 40;
	public const DOCX_IMAGE_BYTES = 8388608;

	/** Above this, document.xml is read as plain text rather than parsed whole. */
	private const DOCX_DOM_CAP = 26214400;

	private const NS_W   = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main';
	private const NS_R   = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships';
	private const NS_A   = 'http://schemas.openxmlformats.org/drawingml/2006/main';
	private const NS_V   = 'urn:schemas-microsoft-com:vml';
	private const NS_REL = 'http://schemas.openxmlformats.org/package/2006/relationships';

	/**
	 * A Word document as the preview draws it: headings, paragraphs with
	 * bold / italic / underline / strike, bullet and numbered lists, links,
	 * tables (with merged cells) and the pictures embedded in it.
	 *
	 * Questionnaires and assessments arrive as Word files that are mostly
	 * tables, and screenshots pasted into a document are often the whole
	 * point of it -- a text dump of either reads as a jumble or as nothing.
	 *
	 * Everything is data: text is returned as text and set with textContent
	 * by the page; a link is kept only for http(s) and mailto; a picture is
	 * returned only when its bytes are really the image type its name says
	 * (PNG, JPEG, GIF, WebP, BMP -- never SVG), as a data URI the page puts in
	 * an <img>. Nothing in the file is executed or fetched: external images
	 * and linked files are named, not loaded.
	 *
	 * Returns `blocks` and `images`, and `paragraphs` (plain text) for
	 * anything that still reads the old shape.
	 *
	 * @return array<string,mixed>
	 */
	private static function docx( string $path ): array {
		if ( ! class_exists( '\ZipArchive' ) ) {
			throw new \RuntimeException( 'this server cannot open zip files' );
		}

		$zip = new \ZipArchive();

		if ( true !== $zip->open( $path, \ZipArchive::RDONLY ) ) {
			throw new \RuntimeException( 'not a valid Word document' );
		}

		try {
			$stat = $zip->statName( 'word/document.xml' );

			if ( false === $stat ) {
				throw new \RuntimeException( 'no document part' );
			}

			// A very large body is read the old way, as text, rather than
			// held whole in memory as a tree.
			if ( (int) $stat['size'] > self::DOCX_DOM_CAP || ! class_exists( '\DOMDocument' ) ) {
				return self::docx_text( (string) self::zip_entry( $zip, 'word/document.xml' ) );
			}

			$xml = (string) self::zip_entry( $zip, 'word/document.xml' );
			$dom = new \DOMDocument();

			if ( ! $dom->loadXML( $xml, LIBXML_NONET | LIBXML_COMPACT | LIBXML_PARSEHUGE ) ) {
				throw new \RuntimeException( 'unreadable document XML' );
			}
			unset( $xml );

			$ctx = array(
				'zip'      => $zip,
				'rels'     => self::docx_rels( $zip ),
				'styles'   => self::docx_styles( $zip ),
				'numbers'  => self::docx_numbering( $zip ),
				'counters' => array(),
				'blocks'   => 0,
				'bytes'    => 0,
				'cut'      => false,
				'images'   => array(),
				'img_ids'  => array(),
				'img_size' => 0,
				'skipped'  => 0,
			);

			$body = $dom->getElementsByTagNameNS( self::NS_W, 'body' )->item( 0 );

			if ( ! $body ) {
				throw new \RuntimeException( 'no document body' );
			}

			$blocks = self::docx_children( $body, $ctx );
		} finally {
			$zip->close();
		}

		$plain = array();
		self::docx_plain( $blocks, $plain );

		return array(
			'blocks'         => $blocks,
			'images'         => $ctx['images'],
			'images_skipped' => $ctx['skipped'],
			'paragraphs'     => $plain,
			'truncated'      => $ctx['cut'],
		);
	}

	/**
	 * The old reading: every paragraph's text, in order. Kept for bodies too
	 * large to parse whole.
	 *
	 * @return array{paragraphs:string[],truncated:bool}
	 */
	private static function docx_text( string $xml ): array {
		$paras = array();
		$cur   = null;
		$bytes = 0;
		$cut   = false;
		$r     = self::xml_reader( $xml );

		while ( $r->read() ) {
			if ( \XMLReader::ELEMENT === $r->nodeType ) {
				if ( 'p' === $r->localName ) {
					$cur = '';
				} elseif ( null !== $cur ) {
					if ( 't' === $r->localName ) {
						$cur .= $r->readString();
					} elseif ( 'tab' === $r->localName ) {
						$cur .= "\t";
					} elseif ( 'br' === $r->localName || 'cr' === $r->localName ) {
						$cur .= "\n";
					}
				}
			} elseif ( \XMLReader::END_ELEMENT === $r->nodeType && 'p' === $r->localName && null !== $cur ) {
				$paras[] = $cur;
				$bytes  += strlen( $cur );
				$cur     = null;
				if ( $bytes > self::TEXT_BYTES ) {
					$cut = true;
					break;
				}
			}
		}
		$r->close();

		$out = array();
		foreach ( $paras as $p ) {
			if ( '' === trim( $p ) && ( ! $out || '' === end( $out ) ) ) {
				continue;
			}
			$out[] = '' === trim( $p ) ? '' : $p;
		}

		return array( 'paragraphs' => $out, 'truncated' => $cut );
	}

	/** The w:val attribute, or ''. */
	private static function wval( ?\DOMElement $el ): string {
		return $el ? (string) $el->getAttributeNS( self::NS_W, 'val' ) : '';
	}

	/** The first direct child with this Word local name. */
	private static function wchild( \DOMNode $el, string $name ): ?\DOMElement {
		foreach ( $el->childNodes as $c ) {
			if ( $c instanceof \DOMElement && self::NS_W === $c->namespaceURI && $name === $c->localName ) {
				return $c;
			}
		}

		return null;
	}

	/**
	 * relationship id => [target, external].
	 *
	 * @return array<string,array{0:string,1:bool}>
	 */
	private static function docx_rels( \ZipArchive $zip ): array {
		$xml = self::zip_entry( $zip, 'word/_rels/document.xml.rels' );
		$out = array();

		if ( null === $xml ) {
			return $out;
		}

		$dom = new \DOMDocument();
		if ( ! $dom->loadXML( $xml, LIBXML_NONET ) ) {
			return $out;
		}

		foreach ( $dom->getElementsByTagNameNS( self::NS_REL, 'Relationship' ) as $rel ) {
			$out[ (string) $rel->getAttribute( 'Id' ) ] = array( (string) $rel->getAttribute( 'Target' ), 'External' === (string) $rel->getAttribute( 'TargetMode' ) );
		}

		return $out;
	}

	/**
	 * Paragraph style id => heading level (1-6), from the style's own name
	 * ("heading 2", "Title"), so a renamed or translated id still reads.
	 *
	 * @return array<string,int>
	 */
	private static function docx_styles( \ZipArchive $zip ): array {
		$xml = self::zip_entry( $zip, 'word/styles.xml' );
		$out = array();

		if ( null === $xml ) {
			return $out;
		}

		$dom = new \DOMDocument();
		if ( ! $dom->loadXML( $xml, LIBXML_NONET | LIBXML_PARSEHUGE ) ) {
			return $out;
		}

		foreach ( $dom->getElementsByTagNameNS( self::NS_W, 'style' ) as $st ) {
			$id   = (string) $st->getAttributeNS( self::NS_W, 'styleId' );
			$name = strtolower( trim( self::wval( self::wchild( $st, 'name' ) ) ) );

			if ( preg_match( '/^heading\s*([1-6])$/', $name, $m ) ) {
				$out[ $id ] = (int) $m[1];
			} elseif ( 'title' === $name ) {
				$out[ $id ] = 1;
			} elseif ( 'subtitle' === $name ) {
				$out[ $id ] = 2;
			}
		}

		return $out;
	}

	/**
	 * numId => level => number format ("bullet", "decimal", "lowerLetter"…).
	 *
	 * @return array<string,array<int,string>>
	 */
	private static function docx_numbering( \ZipArchive $zip ): array {
		$xml = self::zip_entry( $zip, 'word/numbering.xml' );
		$out = array();

		if ( null === $xml ) {
			return $out;
		}

		$dom = new \DOMDocument();
		if ( ! $dom->loadXML( $xml, LIBXML_NONET | LIBXML_PARSEHUGE ) ) {
			return $out;
		}

		$abstract = array();
		foreach ( $dom->getElementsByTagNameNS( self::NS_W, 'abstractNum' ) as $an ) {
			$levels = array();
			foreach ( $an->getElementsByTagNameNS( self::NS_W, 'lvl' ) as $lvl ) {
				$levels[ (int) $lvl->getAttributeNS( self::NS_W, 'ilvl' ) ] = self::wval( self::wchild( $lvl, 'numFmt' ) ) ?: 'decimal';
			}
			$abstract[ (string) $an->getAttributeNS( self::NS_W, 'abstractNumId' ) ] = $levels;
		}

		foreach ( $dom->getElementsByTagNameNS( self::NS_W, 'num' ) as $num ) {
			$aid = self::wval( self::wchild( $num, 'abstractNumId' ) );
			$out[ (string) $num->getAttributeNS( self::NS_W, 'numId' ) ] = $abstract[ $aid ] ?? array();
		}

		return $out;
	}

	/**
	 * The block-level children of a body, cell or content control.
	 *
	 * @param array<string,mixed> $ctx Reading state.
	 * @return array<int,array<string,mixed>>
	 */
	private static function docx_children( \DOMNode $parent, array &$ctx ): array {
		$out = array();

		foreach ( $parent->childNodes as $n ) {
			if ( $ctx['cut'] ) {
				break;
			}
			if ( ! $n instanceof \DOMElement || self::NS_W !== $n->namespaceURI ) {
				continue;
			}

			if ( 'p' === $n->localName ) {
				$out[] = self::docx_para( $n, $ctx );
			} elseif ( 'tbl' === $n->localName ) {
				$out[] = self::docx_table( $n, $ctx );
			} elseif ( 'sdt' === $n->localName || 'customXml' === $n->localName ) {
				$inner = self::wchild( $n, 'sdtContent' ) ?? $n;
				$out   = array_merge( $out, self::docx_children( $inner, $ctx ) );
			}

			if ( ++$ctx['blocks'] > self::DOCX_BLOCKS || $ctx['bytes'] > self::TEXT_BYTES ) {
				$ctx['cut'] = true;
			}
		}

		// Collapse runs of empty paragraphs to one.
		$tidy = array();
		foreach ( $out as $b ) {
			$empty = 'p' === $b['t'] && ! $b['runs'];
			if ( $empty && ( ! $tidy || ( 'p' === end( $tidy )['t'] && ! end( $tidy )['runs'] ) ) ) {
				continue;
			}
			$tidy[] = $b;
		}

		return $tidy;
	}

	/**
	 * One paragraph: heading level, list marker, and its runs.
	 *
	 * @param array<string,mixed> $ctx Reading state.
	 * @return array<string,mixed>
	 */
	private static function docx_para( \DOMElement $p, array &$ctx ): array {
		$block = array( 't' => 'p', 'runs' => array() );
		$ppr   = self::wchild( $p, 'pPr' );

		if ( $ppr ) {
			$style = self::wval( self::wchild( $ppr, 'pStyle' ) );

			if ( isset( $ctx['styles'][ $style ] ) ) {
				$block['h'] = $ctx['styles'][ $style ];
			}

			$num = self::wchild( $ppr, 'numPr' );

			if ( $num ) {
				$id  = self::wval( self::wchild( $num, 'numId' ) );
				$lvl = max( 0, min( 8, (int) self::wval( self::wchild( $num, 'ilvl' ) ) ) );

				if ( '' !== $id && '0' !== $id ) {
					$block['list'] = array( 'lvl' => $lvl, 'label' => self::docx_label( $ctx, $id, $lvl ) );
				}
			}

			$jc = self::wval( self::wchild( $ppr, 'jc' ) );
			if ( in_array( $jc, array( 'center', 'right' ), true ) ) {
				$block['align'] = $jc;
			}
		}

		self::docx_runs( $p, $ctx, $block['runs'], '' );

		// Merge neighbouring runs that look the same: fewer nodes to draw.
		$merged = array();
		foreach ( $block['runs'] as $r ) {
			$last = $merged ? $merged[ count( $merged ) - 1 ] : null;

			if ( $last && isset( $r['x'], $last['x'] ) && array_diff_key( $r, array( 'x' => 1 ) ) === array_diff_key( $last, array( 'x' => 1 ) ) ) {
				$merged[ count( $merged ) - 1 ]['x'] .= $r['x'];
			} else {
				$merged[] = $r;
			}
		}
		$block['runs'] = $merged;

		// A paragraph of nothing but spaces is a gap, not text.
		if ( $block['runs'] && ! array_filter( $block['runs'], static fn( array $r ): bool => isset( $r['img'] ) || isset( $r['note'] ) || '' !== trim( (string) ( $r['x'] ?? '' ) ) ) ) {
			$block['runs'] = array();
		}

		return $block;
	}

	/**
	 * The marker a list item shows: a bullet, or its number in the list's own
	 * format, counted per list and level (a deeper level restarts when a
	 * shallower one moves on).
	 *
	 * @param array<string,mixed> $ctx Reading state.
	 */
	private static function docx_label( array &$ctx, string $id, int $lvl ): string {
		$fmt = (string) ( $ctx['numbers'][ $id ][ $lvl ] ?? 'bullet' );

		if ( 'bullet' === $fmt || 'none' === $fmt ) {
			return 'none' === $fmt ? '' : ( 0 === $lvl % 3 ? '•' : ( 1 === $lvl % 3 ? '◦' : '▪' ) );
		}

		$ctx['counters'][ $id ][ $lvl ] = ( $ctx['counters'][ $id ][ $lvl ] ?? 0 ) + 1;
		foreach ( array_keys( $ctx['counters'][ $id ] ) as $deeper ) {
			if ( $deeper > $lvl ) {
				unset( $ctx['counters'][ $id ][ $deeper ] );
			}
		}

		$n = $ctx['counters'][ $id ][ $lvl ];

		return match ( $fmt ) {
			'lowerLetter' => self::docx_letters( $n ) . '.',
			'upperLetter' => strtoupper( self::docx_letters( $n ) ) . '.',
			'lowerRoman'  => strtolower( self::docx_roman( $n ) ) . '.',
			'upperRoman'  => self::docx_roman( $n ) . '.',
			default       => $n . '.',
		};
	}

	private static function docx_letters( int $n ): string {
		$s = '';
		while ( $n > 0 ) {
			--$n;
			$s = chr( 97 + $n % 26 ) . $s;
			$n = intdiv( $n, 26 );
		}
		return $s;
	}

	private static function docx_roman( int $n ): string {
		$map = array( 'M' => 1000, 'CM' => 900, 'D' => 500, 'CD' => 400, 'C' => 100, 'XC' => 90, 'L' => 50, 'XL' => 40, 'X' => 10, 'IX' => 9, 'V' => 5, 'IV' => 4, 'I' => 1 );
		$s   = '';
		foreach ( $map as $r => $v ) {
			while ( $n >= $v ) {
				$s .= $r;
				$n -= $v;
			}
		}
		return $s;
	}

	/**
	 * Walk a paragraph's inline content in order: runs, and the wrappers runs
	 * sit in (links, insertions, smart tags, fields, content controls).
	 * Deleted text is left out, as Word shows it once changes are accepted.
	 *
	 * @param array<string,mixed>            $ctx  Reading state.
	 * @param array<int,array<string,mixed>> $runs Collected runs.
	 */
	private static function docx_runs( \DOMNode $node, array &$ctx, array &$runs, string $href ): void {
		foreach ( $node->childNodes as $c ) {
			if ( ! $c instanceof \DOMElement || self::NS_W !== $c->namespaceURI ) {
				continue;
			}

			switch ( $c->localName ) {
				case 'r':
					self::docx_run( $c, $ctx, $runs, $href );
					break;
				case 'hyperlink':
					$rid  = (string) $c->getAttributeNS( self::NS_R, 'id' );
					$url  = isset( $ctx['rels'][ $rid ] ) && $ctx['rels'][ $rid ][1] ? $ctx['rels'][ $rid ][0] : '';
					$safe = preg_match( '#^(?:https?://|mailto:)#i', $url ) ? $url : '';
					self::docx_runs( $c, $ctx, $runs, '' !== $safe ? $safe : $href );
					break;
				case 'sdt':
					self::docx_runs( self::wchild( $c, 'sdtContent' ) ?? $c, $ctx, $runs, $href );
					break;
				case 'ins':
				case 'smartTag':
				case 'fldSimple':
				case 'customXml':
				case 'moveTo':
					self::docx_runs( $c, $ctx, $runs, $href );
					break;
			}
		}
	}

	/**
	 * One run: its formatting, then its text, tabs, breaks and pictures.
	 *
	 * @param array<string,mixed>            $ctx  Reading state.
	 * @param array<int,array<string,mixed>> $runs Collected runs.
	 */
	private static function docx_run( \DOMElement $r, array &$ctx, array &$runs, string $href ): void {
		$fmt = array();
		$rpr = self::wchild( $r, 'rPr' );

		if ( $rpr ) {
			foreach ( array( 'b' => 'b', 'i' => 'i', 'strike' => 's' ) as $tag => $key ) {
				$el = self::wchild( $rpr, $tag );
				if ( $el && ! in_array( self::wval( $el ), array( '0', 'false', 'off' ), true ) ) {
					$fmt[ $key ] = 1;
				}
			}
			$u = self::wchild( $rpr, 'u' );
			if ( $u && ! in_array( self::wval( $u ), array( 'none', '0', 'false' ), true ) ) {
				$fmt['u'] = 1;
			}
		}
		if ( '' !== $href ) {
			$fmt['href'] = $href;
		}

		foreach ( $r->childNodes as $c ) {
			if ( ! $c instanceof \DOMElement ) {
				continue;
			}

			if ( self::NS_W === $c->namespaceURI ) {
				$text = match ( $c->localName ) {
					't'       => (string) $c->textContent,
					'tab'     => "\t",
					'br', 'cr' => "\n",
					'noBreakHyphen' => '-',
					default   => null,
				};

				if ( null !== $text ) {
					$ctx['bytes'] += strlen( $text );
					$runs[]        = array( 'x' => $text ) + $fmt;
					continue;
				}

				if ( 'drawing' === $c->localName || 'pict' === $c->localName || 'object' === $c->localName ) {
					self::docx_pictures( $c, $ctx, $runs );
				}
			}
		}
	}

	/**
	 * Pictures in a drawing (DrawingML blip) or an old VML shape.
	 *
	 * @param array<string,mixed>            $ctx  Reading state.
	 * @param array<int,array<string,mixed>> $runs Collected runs.
	 */
	private static function docx_pictures( \DOMElement $el, array &$ctx, array &$runs ): void {
		$ids = array();

		foreach ( $el->getElementsByTagNameNS( self::NS_A, 'blip' ) as $blip ) {
			$ids[] = (string) ( $blip->getAttributeNS( self::NS_R, 'embed' ) ?: $blip->getAttributeNS( self::NS_R, 'link' ) );
		}
		foreach ( $el->getElementsByTagNameNS( self::NS_V, 'imagedata' ) as $img ) {
			$ids[] = (string) $img->getAttributeNS( self::NS_R, 'id' );
		}

		foreach ( array_filter( $ids ) as $rid ) {
			$i = self::docx_image( $ctx, $rid );
			$runs[] = null === $i
				? array( 'note' => __( 'A picture is here in the document; it cannot be shown in this preview. Download the file to see it.', 'vulnhub' ) )
				: array( 'img' => $i );
		}
	}

	/**
	 * One embedded picture as a data URI, once per relationship; null when
	 * it is linked from outside, not an image this preview shows, over the
	 * limits, or not really what its name says.
	 *
	 * @param array<string,mixed> $ctx Reading state.
	 */
	private static function docx_image( array &$ctx, string $rid ): ?int {
		if ( array_key_exists( $rid, $ctx['img_ids'] ) ) {
			return $ctx['img_ids'][ $rid ];
		}

		$ctx['img_ids'][ $rid ] = null;
		$rel                    = $ctx['rels'][ $rid ] ?? null;

		if ( ! $rel || $rel[1] || count( $ctx['images'] ) >= self::DOCX_IMAGES ) {
			++$ctx['skipped'];
			return null;
		}

		// Targets are relative to word/; resolve "../" without leaving the package.
		$parts = array();
		foreach ( explode( '/', 'word/' . ltrim( $rel[0], '/' ) ) as $seg ) {
			if ( '..' === $seg ) {
				array_pop( $parts );
			} elseif ( '' !== $seg && '.' !== $seg ) {
				$parts[] = $seg;
			}
		}
		$name = implode( '/', $parts );
		$mime = array( 'png' => 'image/png', 'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'gif' => 'image/gif', 'webp' => 'image/webp', 'bmp' => 'image/bmp' )[ self::ext( $name ) ] ?? '';
		$stat = '' !== $mime ? $ctx['zip']->statName( $name ) : false;

		if ( false === $stat || $ctx['img_size'] + (int) $stat['size'] > self::DOCX_IMAGE_BYTES ) {
			++$ctx['skipped'];
			return null;
		}

		$bytes = (string) $ctx['zip']->getFromName( $name );
		$real  = class_exists( '\finfo' ) ? (string) ( new \finfo( FILEINFO_MIME_TYPE ) )->buffer( $bytes ) : '';

		// The bytes must be the image the name claims, or nothing is shown.
		if ( '' === $bytes || ( '' !== $real && $real !== $mime && ! ( 'image/bmp' === $mime && 'image/x-ms-bmp' === $real ) ) ) {
			++$ctx['skipped'];
			return null;
		}

		$ctx['img_size']       += strlen( $bytes );
		$ctx['images'][]        = 'data:' . $mime . ';base64,' . base64_encode( $bytes );
		$ctx['img_ids'][ $rid ] = count( $ctx['images'] ) - 1;

		return $ctx['img_ids'][ $rid ];
	}

	/**
	 * A table, row by row. Horizontally merged cells carry `span`; a
	 * vertically merged cell carries `rows` on its first row and the cells
	 * under it are marked `merged`, so the page can draw rowspan.
	 *
	 * @param array<string,mixed> $ctx Reading state.
	 * @return array<string,mixed>
	 */
	private static function docx_table( \DOMElement $tbl, array &$ctx ): array {
		$rows = array();
		$open = array(); // column => [row index, cell index] of the cell a vertical merge started in.

		foreach ( $tbl->childNodes as $tr ) {
			if ( $ctx['cut'] ) {
				break;
			}
			if ( ! $tr instanceof \DOMElement || self::NS_W !== $tr->namespaceURI || 'tr' !== $tr->localName ) {
				continue;
			}

			$row = array();
			$col = 0;

			foreach ( $tr->childNodes as $tc ) {
				if ( ! $tc instanceof \DOMElement || self::NS_W !== $tc->namespaceURI ) {
					continue;
				}
				if ( 'sdt' === $tc->localName ) {
					$tc = self::wchild( self::wchild( $tc, 'sdtContent' ) ?? $tc, 'tc' );
					if ( ! $tc ) {
						continue;
					}
				}
				if ( 'tc' !== $tc->localName ) {
					continue;
				}

				$pr    = self::wchild( $tc, 'tcPr' );
				$span  = max( 1, (int) self::wval( $pr ? self::wchild( $pr, 'gridSpan' ) : null ) );
				$vm    = $pr ? self::wchild( $pr, 'vMerge' ) : null;
				$cell  = array( 'blocks' => self::docx_children( $tc, $ctx ) );

				if ( $span > 1 ) {
					$cell['span'] = $span;
				}

				if ( $vm && 'restart' !== self::wval( $vm ) && isset( $open[ $col ] ) ) {
					// A continuation: the cell above grows, this one is not drawn.
					[ $ri, $ci ] = $open[ $col ];
					$rows[ $ri ][ $ci ]['rows'] = ( $rows[ $ri ][ $ci ]['rows'] ?? 1 ) + 1;
					$cell                         = array( 'merged' => 1 );
				} elseif ( $vm ) {
					$open[ $col ] = array( count( $rows ), count( $row ) );
				} else {
					unset( $open[ $col ] );
				}

				$row[] = $cell;
				$col  += $span;
			}

			$rows[] = $row;
		}

		return array( 't' => 'table', 'rows' => $rows );
	}

	/**
	 * Plain text of the blocks, in reading order, for the old shape.
	 *
	 * @param array<int,array<string,mixed>> $blocks Blocks.
	 * @param string[]                       $out    Paragraphs.
	 */
	private static function docx_plain( array $blocks, array &$out ): void {
		foreach ( $blocks as $b ) {
			if ( 'table' === $b['t'] ) {
				foreach ( $b['rows'] as $row ) {
					foreach ( $row as $cell ) {
						self::docx_plain( (array) ( $cell['blocks'] ?? array() ), $out );
					}
				}
				continue;
			}

			$out[] = implode( '', array_map( static fn( array $r ): string => (string) ( $r['x'] ?? '' ), (array) $b['runs'] ) );
		}
	}


	/**
	 * A text file, as text. Binary dressed up as text is refused.
	 *
	 * @return array<string,mixed>
	 */
	private static function text( string $path, string $ext ): array {
		$size = (int) filesize( $path );
		$raw  = (string) file_get_contents( $path, false, null, 0, self::TEXT_BYTES + 4 ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( str_contains( substr( $raw, 0, 8192 ), "\0" ) && ! str_starts_with( $raw, "\xFF\xFE" ) && ! str_starts_with( $raw, "\xFE\xFF" ) ) {
			return array(
				'kind'    => 'none',
				'message' => __( 'This file holds binary data, not text. Download it to open it.', 'vulnhub' ),
			);
		}

		$cut  = $size > self::TEXT_BYTES;
		$text = self::utf8( $cut ? mb_strcut( $raw, 0, self::TEXT_BYTES, '8bit' ) : $raw );

		if ( ! mb_check_encoding( $text, 'UTF-8' ) ) {
			$text = mb_scrub( $text, 'UTF-8' );
		}

		// A whole JSON document is easier to read laid out.
		if ( 'json' === $ext && ! $cut ) {
			$decoded = json_decode( $text, true );
			if ( null !== $decoded || 'null' === trim( $text ) ) {
				$text = (string) wp_json_encode( $decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
			}
		}

		return array(
			'text'      => $text,
			'truncated' => $cut,
			'lang'      => $ext,
		);
	}
}

