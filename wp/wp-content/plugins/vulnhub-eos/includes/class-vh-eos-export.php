<?php
/**
 * "Send me the list" — the EOL remediation plan as a CSV.
 *
 * The audience for this file is a steering pack or a conversation with an
 * application owner, so it exports what is on screen: the same filters, the
 * whole filtered set rather than the page being looked at, and one row per
 * server with the plan, the date, and what the scanner currently sees on it.
 *
 * It deliberately reuses VH_EOS_View::repo_args() rather than re-reading
 * the query string with its own rules. Two parsers for one set of filters is
 * how an export quietly stops matching the screen it came from.
 *
 * @package VulnHub\EOS
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * CSV export for the EOL remediation plan.
 */
final class VH_EOS_Export {

	public const ACTION = 'vulnhub_eos_export_csv';

	/**
	 * Rows read per repository call while streaming. 500 matches the
	 * repository's own page ceiling elsewhere in the product.
	 */
	private const PAGE = 500;

	/** A courtesy ceiling: this programme is ~130 servers, not 130,000. */
	private const MAX_ROWS = 20000;

	public static function init(): void {
		add_action( 'admin_post_' . self::ACTION, array( __CLASS__, 'handle' ) );
	}

	/* =================================================================
	 * The button
	 * ============================================================== */

	/**
	 * @param array<string,mixed> $args Filters in force on the screen.
	 */
	public static function url( array $args = array() ): string {
		return wp_nonce_url(
			add_query_arg(
				array_merge(
					self::carried( $args ),
					array( 'action' => self::ACTION )
				),
				admin_url( 'admin-post.php' )
			),
			self::ACTION
		);
	}

	/**
	 * The export control, with the number it will actually write on it.
	 *
	 * Saying "Export 37 servers" rather than "Export CSV" is the difference
	 * between trusting the filters and opening the file to check them.
	 *
	 * @param int                 $count Rows matching the current filters.
	 * @param array<string,mixed> $args  Filters in force.
	 */
	public static function button( int $count, array $args = array() ): void {
		if ( ! current_user_can( Caps::VIEW ) ) {
			return;
		}

		$label = $count > 0
			? sprintf(
				/* translators: %s: a formatted number of servers. */
				_n( 'Export %s server', 'Export %s servers', $count, 'vulnhub' ),
				number_format_i18n( $count )
			)
			: __( 'Export CSV', 'vulnhub' );
		?>
		<a class="vh-btn vh-btn--ghost vh-btn--sm" href="<?php echo esc_url( self::url( $args ) ); ?>">
			<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false" width="14" height="14">
				<path d="M12 3v11m0 0l-4-4m4 4l4-4M4 17v2a2 2 0 002 2h12a2 2 0 002-2v-2" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
			</svg>
			<?php echo esc_html( $label ); ?>
		</a>
		<?php
	}

	/**
	 * The filters an export inherits from the screen it was launched from.
	 *
	 * @param array<string,mixed> $args Filters.
	 * @return array<string,string>
	 */
	private static function carried( array $args ): array {
		$keep = array( 'coverage', 'state', 'timeframe', 'tier', 'rag', 'project', 'key', 'eol', 'search', 'team', 'site', 'life', 'orderby', 'order' );
		$out  = array();

		foreach ( $keep as $name ) {
			if ( ! isset( $args[ $name ] ) ) {
				continue;
			}

			$value = (string) $args[ $name ];

			if ( '' === $value || '0' === $value ) {
				continue;
			}

			$out[ $name ] = $value;
		}

		return $out;
	}

	/* =================================================================
	 * The file
	 * ============================================================== */

	/**
	 * The columns, in file order: label, and how to read it off a row.
	 *
	 * Declared once so the header line and the body can never disagree about
	 * what is in column seven.
	 *
	 * @return array<string,array{label:string,value:callable}>
	 */
	private static function columns(): array {
		$states    = VH_EOS_View::states();
		$coverages = VH_EOS_View::coverages();

		$text = static fn( array $r, string $key ): string => (string) ( $r[ $key ] ?? '' );

		return array(
			'hostname'      => array(
				'label' => __( 'Server', 'vulnhub' ),
				'value' => static fn( array $r ): string => $text( $r, 'hostname' ),
			),
			'in_inventory'  => array(
				'label' => __( 'In inventory', 'vulnhub' ),
				'value' => static fn( array $r ): string => (int) ( $r['asset_id'] ?? 0 ) > 0 ? __( 'Yes', 'vulnhub' ) : __( 'No', 'vulnhub' ),
			),
			'coverage'      => array(
				'label' => __( 'Coverage', 'vulnhub' ),
				'value' => static function ( array $r ) use ( $coverages ): string {
					$key = (string) ( $r['coverage'] ?? '' );

					return isset( $coverages[ $key ] ) ? (string) $coverages[ $key ]['label'] : $key;
				},
			),
			'state'         => array(
				'label' => __( 'Programme state', 'vulnhub' ),
				'value' => static function ( array $r ) use ( $states ): string {
					$key = (string) ( $r['state'] ?? '' );

					return $states[ $key ] ?? $key;
				},
			),
			'project'       => array(
				'label' => __( 'Treatment plan / project', 'vulnhub' ),
				'value' => static fn( array $r ): string => $text( $r, 'project' ),
			),
			'timeframe'     => array(
				'label' => __( 'Timeframe', 'vulnhub' ),
				'value' => static fn( array $r ): string => $text( $r, 'timeframe' ),
			),
			'deadline'      => array(
				'label' => __( 'Due by', 'vulnhub' ),
				'value' => static function ( array $r ): string {
					$d = (string) ( $r['deadline'] ?? '' );

					// A calendar date: formatted, never shifted. See vh_date_only().
					return '' !== $d ? substr( $d, 0, 10 ) : '';
				},
			),
			'overdue'       => array(
				'label' => __( 'Overdue', 'vulnhub' ),
				'value' => static fn( array $r ): string => 'overdue' === (string) ( $r['coverage'] ?? '' ) ? __( 'Yes', 'vulnhub' ) : '',
			),
			'rag'           => array(
				'label' => __( 'RAG', 'vulnhub' ),
				'value' => static fn( array $r ): string => ucfirst( $text( $r, 'rag' ) ),
			),
			'environment'   => array(
				'label' => __( 'Environment', 'vulnhub' ),
				'value' => static fn( array $r ): string => $text( $r, 'environment' ),
			),
			'env_tier'      => array(
				'label' => __( 'Environment tier', 'vulnhub' ),
				'value' => static fn( array $r ): string => ucfirst( $text( $r, 'env_tier' ) ),
			),
			'purpose'       => array(
				'label' => __( 'Application / purpose', 'vulnhub' ),
				'value' => static fn( array $r ): string => $text( $r, 'purpose' ),
			),
			'os'            => array(
				'label' => __( 'Operating system (inventory)', 'vulnhub' ),
				'value' => static function ( array $r ) use ( $text ): string {
					$os = $text( $r, 'operating_system' );
					$ver = $text( $r, 'os_version' );

					return '' !== $ver ? trim( $os . ' ' . $ver ) : $os;
				},
			),
			'os_text'       => array(
				'label' => __( 'Operating system (programme)', 'vulnhub' ),
				'value' => static fn( array $r ): string => $text( $r, 'os_text' ),
			),
			'team'          => array(
				'label' => __( 'Owner team', 'vulnhub' ),
				'value' => static fn( array $r ): string => $text( $r, 'team_name' ),
			),
			'site'          => array(
				'label' => __( 'Site', 'vulnhub' ),
				'value' => static fn( array $r ): string => (string) ( $r['site_name'] ?? $r['location_name'] ?? '' ),
			),
			'open_critical' => array(
				'label' => __( 'Open critical findings', 'vulnhub' ),
				'value' => static fn( array $r ): string => (int) ( $r['asset_id'] ?? 0 ) > 0 ? (string) (int) ( $r['open_critical'] ?? 0 ) : '',
			),
			'open_high'     => array(
				'label' => __( 'Open high findings', 'vulnhub' ),
				'value' => static fn( array $r ): string => (int) ( $r['asset_id'] ?? 0 ) > 0 ? (string) (int) ( $r['open_high'] ?? 0 ) : '',
			),
			'last_scan'     => array(
				'label' => __( 'Last scan', 'vulnhub' ),
				'value' => static function ( array $r ): string {
					$s = (string) ( $r['tenable_last_scan'] ?? $r['last_scan'] ?? '' );

					// An instant, so it reads in the site timezone like the screen does.
					return '' !== $s ? vh_date( $s, 'Y-m-d' ) : '';
				},
			),
			'controls'      => array(
				'label' => __( 'Controls', 'vulnhub' ),
				'value' => static fn( array $r ): string => $text( $r, 'controls' ),
			),
			'inherent_risk' => array(
				'label' => __( 'Inherent risk', 'vulnhub' ),
				'value' => static fn( array $r ): string => $text( $r, 'inherent_risk' ),
			),
			'residual_risk' => array(
				'label' => __( 'Residual risk', 'vulnhub' ),
				'value' => static fn( array $r ): string => $text( $r, 'residual_risk' ),
			),
			'jsm_status'    => array(
				'label' => __( 'JSM status', 'vulnhub' ),
				'value' => static fn( array $r ): string => $text( $r, 'jsm_status' ),
			),
			'jsm_location'  => array(
				'label' => __( 'JSM location', 'vulnhub' ),
				'value' => static fn( array $r ): string => $text( $r, 'jsm_location' ),
			),
			'notes'         => array(
				'label' => __( 'Notes', 'vulnhub' ),
				'value' => static fn( array $r ): string => $text( $r, 'notes' ),
			),
		);
	}

	public static function handle(): void {
		if ( ! is_user_logged_in() || ! current_user_can( Caps::VIEW ) ) {
			wp_die( esc_html__( 'You do not have permission to export that.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}

		check_admin_referer( self::ACTION );

		if ( ! class_exists( 'VH_EOS_Repo' ) ) {
			wp_die( esc_html__( 'The remediation programme data is not available.', 'vulnhub' ), '', array( 'response' => 500 ) );
		}

		$args = VH_EOS_View::repo_args();

		if ( function_exists( 'vulnhub' ) && isset( vulnhub()->logger ) ) {
			vulnhub()->logger->audit(
				'export.csv',
				__( 'Exported the EOL remediation plan as CSV', 'vulnhub' ),
				'export',
				VH_EOS_View::VIEW,
				array( 'filters' => array_filter( $args, static fn( $v ): bool => '' !== $v && 0 !== $v ) )
			);
		}

		self::stream( $args );
	}

	/**
	 * @param array<string,mixed> $args Repository arguments.
	 */
	private static function stream( array $args ): void {
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 0 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}

		$cols = self::columns();

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . self::filename( $args ) . '"' );

		// Anything already emitted would arrive as the first line of the file.
		while ( ob_get_level() > 0 ) {
			ob_end_clean();
		}

		$out = fopen( 'php://output', 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( ! $out ) {
			exit;
		}

		/*
		 * A BOM, because this file is opened in Excel, which reads a UTF-8 CSV
		 * without one as Windows-1252.
		 */
		fwrite( $out, "\xEF\xBB\xBF" ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		self::put( $out, array_map( static fn( array $c ): string => (string) $c['label'], array_values( $cols ) ) );

		$offset  = 0;
		$written = 0;

		do {
			$result = (array) VH_EOS_Repo::rows(
				array_merge(
					$args,
					array(
						'limit'  => self::PAGE,
						'offset' => $offset,
					)
				)
			);

			$rows = (array) ( $result['rows'] ?? array() );

			foreach ( $rows as $row ) {
				$line = array();

				foreach ( $cols as $col ) {
					$line[] = (string) call_user_func( $col['value'], (array) $row );
				}

				self::put( $out, $line );
				++$written;

				if ( $written >= self::MAX_ROWS ) {
					break 2;
				}
			}

			$offset += self::PAGE;
		} while ( count( $rows ) === self::PAGE );

		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		exit;
	}

	/**
	 * A filename that says which slice of the plan this is, so three of them
	 * in a downloads folder are still tellable apart.
	 *
	 * @param array<string,mixed> $args Repository arguments.
	 */
	private static function filename( array $args ): string {
		$parts = array( 'vulnhub', 'eol-plan' );

		foreach ( array( 'coverage', 'state', 'env_tier', 'rag', 'timeframe', 'eol_status' ) as $key ) {
			$value = (string) ( $args[ $key ] ?? '' );

			if ( '' === $value ) {
				continue;
			}

			$slug = sanitize_title( $value );

			if ( '' !== $slug ) {
				$parts[] = $slug;
			}
		}

		$parts[] = wp_date( 'Y-m-d-Hi' );

		return implode( '-', $parts ) . '.csv';
	}

	/**
	 * @param resource      $out Output handle.
	 * @param array<int,string> $row Row.
	 */
	private static function put( $out, array $row ): void {
		// A newline inside a cell is legal CSV and still breaks half the tools
		// this file is opened in.
		$row = array_map(
			static fn( $v ): string => (string) preg_replace( '/[\r\n]+/', '  ', (string) $v ),
			$row
		);

		/*
		 * The empty escape string gives plain doubled-quote escaping (RFC
		 * 4180). PHP's default backslash is not part of the standard and
		 * Excel does not undo it.
		 */
		fputcsv( $out, $row, ',', '"', '' );
	}
}
