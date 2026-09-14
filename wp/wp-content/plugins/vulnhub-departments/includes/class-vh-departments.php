<?php
/**
 * Department enrichment and the department dimension.
 *
 * People carry a `department` (from Entra). This plugin fills that column from
 * an uploaded Entra user export — matching ONLY people who already exist, by
 * UPN, never creating anyone — and then makes department a dimension you can
 * filter, chart and export by. A finding's department is the department of the
 * owner of the asset it sits on: finding -> asset -> owner (person) -> department.
 *
 * @package VulnHub\Departments
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Wires the department feature into the portal.
 */
final class VulnHub_Departments {

	public const SECTION    = 'departments';
	public const WIDGET     = 'department_exposure';
	public const IMPORT_ACT = 'vulnhub_dept_import';
	public const OPT_LAST   = 'vulnhub_dept_last_import';

	public static function init(): void {
		// Department as a findings filter (list + CSV export both route here).
		add_filter( 'vulnhub_findings_query', array( __CLASS__, 'findings_query' ), 10, 2 );

		// Admin screen to upload the Entra export.
		add_filter( 'vulnhub_portal_sections', array( __CLASS__, 'register_section' ) );
		add_action( 'vulnhub_render_portal_section', array( __CLASS__, 'render_section' ) );
		add_action( 'admin_post_' . self::IMPORT_ACT, array( __CLASS__, 'handle_import' ) );

		// The dashboard widget.
		add_filter( 'vulnhub_dashboard_widgets', array( __CLASS__, 'register_widget' ) );
		add_filter( 'vulnhub_dashboard_default_layout', array( __CLASS__, 'place_widget' ) );
	}

	/* =================================================================
	 * The department dimension: resolve findings by owner's department
	 * ============================================================== */

	/**
	 * Asset ids owned by a person in the given department.
	 *
	 * @return int[]
	 */
	public static function asset_ids_for_department( string $department ): array {
		global $wpdb;

		if ( '' === $department ) {
			return array();
		}

		$a = vh_table( 'assets' );
		$p = vh_table( 'people' );

		return array_map(
			'intval',
			(array) $wpdb->get_col( // phpcs:ignore WordPress.DB
				$wpdb->prepare(
					"SELECT a.id FROM {$a} a INNER JOIN {$p} p ON p.id = a.owner_person_id WHERE p.department = %s", // phpcs:ignore WordPress.DB
					$department
				)
			)
		);
	}

	/**
	 * Teach the central findings query about a `department` argument.
	 *
	 * Resolved to the small set of asset ids the department owns, so the query
	 * is an index range on `asset_id` rather than a per-row join.
	 *
	 * @param array<string,mixed> $ext  Extension clauses.
	 * @param array<string,mixed> $args Query args.
	 * @return array<string,mixed>
	 */
	public static function findings_query( array $ext, array $args ): array {
		$department = trim( (string) ( $args['department'] ?? '' ) );

		if ( '' === $department ) {
			return $ext;
		}

		$ids = self::asset_ids_for_department( $department );

		$ext['where'][] = $ids
			? 'f.asset_id IN (' . implode( ',', $ids ) . ')'
			: '1=0';

		return $ext;
	}

	/** Distinct departments currently on people, in display order. @return string[] */
	public static function departments_list(): array {
		global $wpdb;

		$p = vh_table( 'people' );

		return array_map(
			'strval',
			(array) $wpdb->get_col( // phpcs:ignore WordPress.DB
				"SELECT DISTINCT department FROM {$p} WHERE department <> '' ORDER BY department" // phpcs:ignore WordPress.DB
			)
		);
	}

	/** Options for the vulnerability-list Department filter. */
	public static function filter_options( string $current ): string {
		$out = '<option value="">' . esc_html__( 'All departments', 'vulnhub' ) . '</option>';

		foreach ( self::departments_list() as $dept ) {
			$out .= sprintf(
				'<option value="%s"%s>%s</option>',
				esc_attr( $dept ),
				selected( $current, $dept, false ),
				esc_html( $dept )
			);
		}

		return $out;
	}

	/* =================================================================
	 * The widget: vulnerabilities by department
	 * ============================================================== */

	/**
	 * @param array<string,array<string,mixed>> $w Widget registry.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_widget( array $w ): array {
		$w[ self::WIDGET ] = array(
			'label'   => __( 'Vulnerabilities by department', 'vulnhub' ),
			'summary' => __( 'Open findings by the department that owns the device, coloured by severity.', 'vulnhub' ),
			'group'   => 'ownership',
			'width'   => 6,
			'depends' => array( 'findings', 'assets' ),
			'render'  => array( __CLASS__, 'render_widget' ),
			'data'    => array( __CLASS__, 'data_widget' ),
		);

		return $w;
	}

	/**
	 * @param array<int,array{id:string,width:int}> $layout Default layout.
	 * @return array<int,array{id:string,width:int}>
	 */
	public static function place_widget( array $layout ): array {
		foreach ( $layout as $entry ) {
			if ( self::WIDGET === ( $entry['id'] ?? '' ) ) {
				return $layout;
			}
		}

		$out = array();

		// Sit it beside "Exposure by team".
		foreach ( $layout as $entry ) {
			$out[] = $entry;
			if ( 'team_exposure' === ( $entry['id'] ?? '' ) ) {
				$out[] = array( 'id' => self::WIDGET, 'width' => 6 );
			}
		}

		// If team_exposure was not in the layout, append at the end.
		$has = false;
		foreach ( $out as $entry ) {
			if ( self::WIDGET === ( $entry['id'] ?? '' ) ) {
				$has = true;
				break;
			}
		}
		if ( ! $has ) {
			$out[] = array( 'id' => self::WIDGET, 'width' => 6 );
		}

		return $out;
	}

	/**
	 * Severity-stacked open findings per department.
	 *
	 * @param int $limit Top-N departments.
	 * @return array<int,array<string,mixed>>
	 */
	public static function widget_rows( int $limit = 12 ): array {
		global $wpdb;

		$f = vh_table( 'findings' );
		$a = vh_table( 'assets' );
		$p = vh_table( 'people' );

		$sql = "SELECT p.department AS label,
				SUM(f.severity = 'critical') AS critical,
				SUM(f.severity = 'high')     AS high,
				SUM(f.severity = 'medium')   AS medium,
				SUM(f.severity = 'low')      AS low,
				SUM(f.severity = 'info')     AS info,
				COUNT(*)                     AS total,
				COUNT(DISTINCT f.asset_id)   AS assets
			FROM {$f} f
			INNER JOIN {$a} a ON a.id = f.asset_id
			INNER JOIN {$p} p ON p.id = a.owner_person_id
			WHERE f.state IN ('open','reopened') AND f.exception_id = 0 AND p.department <> ''
			GROUP BY p.department
			ORDER BY critical DESC, high DESC, total DESC
			LIMIT %d";

		return (array) $wpdb->get_results( $wpdb->prepare( $sql, $limit ), ARRAY_A ); // phpcs:ignore WordPress.DB
	}

	/** Portal URL to the findings of one department (+ optional severity). */
	private static function dept_url( string $department, string $severity = '' ): string {
		$args = array( 'department' => $department, 'state' => 'open_any' );

		if ( '' !== $severity ) {
			$args['severity'] = $severity;
		}

		return VulnHub_Dash_Portal::portal_url( 'vulnerabilities', $args );
	}

	public static function render_widget(): void {
		$rows = self::widget_rows();

		if ( ! $rows ) {
			$msg = self::has_departments()
				? __( 'No open findings resolve to a department yet.', 'vulnhub' )
				: __( 'No departments recorded. Upload an Entra user export under Admin → Departments.', 'vulnhub' );

			echo class_exists( 'VulnHub_Dash_Charts' )
				? VulnHub_Dash_Charts::empty_state( $msg ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				: '<p class="vh-chart-empty">' . esc_html( $msg ) . '</p>';

			return;
		}

		echo VulnHub_Dash_Charts::severity_stack( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			array_map(
				static function ( array $r ): array {
					$dept = (string) $r['label'];

					return array(
						'label'     => vh_trim( $dept, 24 ),
						'href'      => self::dept_url( $dept ),
						'seg_hrefs' => array(
							'critical' => self::dept_url( $dept, 'critical' ),
							'high'     => self::dept_url( $dept, 'high' ),
							'medium'   => self::dept_url( $dept, 'medium' ),
							'low'      => self::dept_url( $dept, 'low' ),
							'info'     => self::dept_url( $dept, 'info' ),
						),
						'counts'    => array(
							'critical' => (int) $r['critical'],
							'high'     => (int) $r['high'],
							'medium'   => (int) $r['medium'],
							'low'      => (int) $r['low'],
							'info'     => (int) $r['info'],
						),
					);
				},
				$rows
			),
			array( 'caption' => __( 'Open findings by owning department. Select a bar for the devices and vulnerabilities behind it.', 'vulnhub' ) )
		);
	}

	/**
	 * @return array{headers:string[],rows:array<int,array<int,scalar>>}
	 */
	public static function data_widget(): array {
		$rows = array();

		foreach ( self::widget_rows( 200 ) as $r ) {
			$rows[] = array(
				(string) $r['label'],
				(int) $r['critical'],
				(int) $r['high'],
				(int) $r['medium'],
				(int) $r['low'],
				(int) $r['total'],
				(int) $r['assets'],
			);
		}

		return array(
			'headers' => array(
				__( 'Department', 'vulnhub' ),
				__( 'Critical', 'vulnhub' ),
				__( 'High', 'vulnhub' ),
				__( 'Medium', 'vulnhub' ),
				__( 'Low', 'vulnhub' ),
				__( 'Open findings', 'vulnhub' ),
				__( 'Devices', 'vulnhub' ),
			),
			'rows'    => $rows,
		);
	}

	private static function has_departments(): bool {
		global $wpdb;
		$p = vh_table( 'people' );

		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$p} WHERE department <> ''" ) > 0; // phpcs:ignore WordPress.DB
	}

	/* =================================================================
	 * Admin section: upload the Entra export
	 * ============================================================== */

	/**
	 * @param array<string,array<string,mixed>> $sections Admin sections.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_section( array $sections ): array {
		$sections[ self::SECTION ] = array(
			'label'   => __( 'Departments', 'vulnhub' ),
			'cap'     => Caps::MANAGE,
			'group'   => 'data',
			'order'   => 35,
			'summary' => __( 'Fill in each existing person\'s department from an Entra user export.', 'vulnhub' ),
		);

		return $sections;
	}

	public static function render_section( string $section ): void {
		if ( self::SECTION !== $section ) {
			return;
		}

		global $wpdb;
		$p = vh_table( 'people' );

		$people    = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$p}" ); // phpcs:ignore WordPress.DB
		$have      = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$p} WHERE department <> ''" ); // phpcs:ignore WordPress.DB
		$depts     = count( self::departments_list() );
		$last      = (array) get_option( self::OPT_LAST, array() );
		$pct       = $people > 0 ? round( 100 * $have / $people ) : 0;
		?>
		<div class="vh-dept-admin">
			<div class="vh-tiles" style="margin-bottom:14px">
				<div class="vh-tile vh-tile--neutral">
					<span class="vh-tile__label"><?php esc_html_e( 'People with a department', 'vulnhub' ); ?></span>
					<span class="vh-tile__value"><?php echo esc_html( number_format_i18n( $have ) ); ?></span>
					<span class="vh-tile__meta"><?php
						/* translators: 1: people with a department, 2: total people, 3: percentage. */
						echo esc_html( sprintf( __( '%1$s of %2$s people (%3$s%%)', 'vulnhub' ), number_format_i18n( $have ), number_format_i18n( $people ), $pct ) );
					?></span>
				</div>
				<div class="vh-tile vh-tile--neutral">
					<span class="vh-tile__label"><?php esc_html_e( 'Distinct departments', 'vulnhub' ); ?></span>
					<span class="vh-tile__value"><?php echo esc_html( number_format_i18n( $depts ) ); ?></span>
					<span class="vh-tile__meta"><?php esc_html_e( 'from your existing people', 'vulnhub' ); ?></span>
				</div>
			</div>

			<div class="vh-card">
				<h2><?php esc_html_e( 'Upload an Entra user export', 'vulnhub' ); ?></h2>
				<p class="vh-card__meta" style="line-height:1.6;max-width:64ch">
					<?php esc_html_e( 'A CSV with a userPrincipalName column and a department column (the standard Entra / Azure AD user export). Each existing person is matched by UPN and given their department. Rows for anyone not already in your data are skipped — this never creates users, and it imports nothing but the department.', 'vulnhub' ); ?>
				</p>

				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" enctype="multipart/form-data" class="vh-dept-form" style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:8px">
					<?php wp_nonce_field( self::IMPORT_ACT ); ?>
					<input type="hidden" name="action" value="<?php echo esc_attr( self::IMPORT_ACT ); ?>">
					<input type="file" name="dept_csv" accept=".csv,text/csv" required>
					<button type="submit" class="vh-btn vh-btn--primary"><?php esc_html_e( 'Process file', 'vulnhub' ); ?></button>
				</form>
			</div>

			<?php if ( $last ) : ?>
				<div class="vh-card" style="margin-top:14px">
					<h2><?php esc_html_e( 'Last import', 'vulnhub' ); ?></h2>
					<div class="vh-detail">
						<dl>
							<dt><?php esc_html_e( 'When', 'vulnhub' ); ?></dt>
							<dd class="vh-mono"><?php echo esc_html( (string) ( $last['at'] ?? '—' ) ); ?></dd>
							<dt><?php esc_html_e( 'File', 'vulnhub' ); ?></dt>
							<dd class="vh-mono"><?php echo esc_html( (string) ( $last['file'] ?? '—' ) ); ?></dd>
							<dt><?php esc_html_e( 'Rows read', 'vulnhub' ); ?></dt>
							<dd class="vh-mono"><?php echo esc_html( number_format_i18n( (int) ( $last['rows'] ?? 0 ) ) ); ?></dd>
							<dt><?php esc_html_e( 'Existing people matched', 'vulnhub' ); ?></dt>
							<dd class="vh-mono"><?php echo esc_html( number_format_i18n( (int) ( $last['matched'] ?? 0 ) ) ); ?></dd>
							<dt><?php esc_html_e( 'Departments set or updated', 'vulnhub' ); ?></dt>
							<dd class="vh-mono"><?php echo esc_html( number_format_i18n( (int) ( $last['updated'] ?? 0 ) ) ); ?></dd>
							<dt><?php esc_html_e( 'Rows skipped (not an existing user)', 'vulnhub' ); ?></dt>
							<dd class="vh-mono"><?php echo esc_html( number_format_i18n( (int) ( $last['skipped'] ?? 0 ) ) ); ?></dd>
						</dl>
					</div>
				</div>
			<?php endif; ?>
		</div>
		<?php
	}

	/* =================================================================
	 * Import handler
	 * ============================================================== */

	public static function handle_import(): void {
		if ( ! current_user_can( Caps::MANAGE ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'vulnhub' ) );
		}

		check_admin_referer( self::IMPORT_ACT );

		$back = static function ( string $msg, string $type = 'success' ): void {
			wp_safe_redirect(
				VulnHub_Dash_Portal::portal_url(
					VulnHub_Dash_Portal::ADMIN_VIEW,
					array(
						'section' => self::SECTION,
						'vh_msg'  => $msg,
						'vh_type' => $type,
					)
				)
			);
			exit;
		};

		if ( empty( $_FILES['dept_csv']['tmp_name'] ) || ! is_uploaded_file( (string) $_FILES['dept_csv']['tmp_name'] ) ) {
			$back( __( 'No file was uploaded.', 'vulnhub' ), 'error' );
		}

		if ( (int) ( $_FILES['dept_csv']['size'] ?? 0 ) > 25 * MB_IN_BYTES ) {
			$back( __( 'That file is too large (limit 25 MB).', 'vulnhub' ), 'error' );
		}

		$res = self::enrich_from_file(
			(string) $_FILES['dept_csv']['tmp_name'],
			sanitize_file_name( (string) ( $_FILES['dept_csv']['name'] ?? 'upload.csv' ) )
		);

		if ( isset( $res['error'] ) ) {
			$back( (string) $res['error'], 'error' );
		}

		$back(
			sprintf(
				/* translators: 1: people matched, 2: departments set/updated. */
				__( 'Matched %1$s existing people; set or updated %2$s departments.', 'vulnhub' ),
				number_format_i18n( (int) $res['matched'] ),
				number_format_i18n( (int) $res['updated'] )
			)
		);
	}

	/**
	 * Parse an Entra user export and set `department` on the existing people it
	 * matches by UPN. Never creates anyone; imports nothing but the department.
	 * Returns the summary, or an array with an `error` key on a bad file.
	 *
	 * Reusable outside the upload path (WP-CLI / tests) — hence not tied to
	 * $_FILES.
	 *
	 * @return array<string,mixed>
	 */
	public static function enrich_from_file( string $path, string $name = '' ): array {
		$map  = array();
		$rows = 0;
		$fh   = fopen( $path, 'r' ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( false === $fh ) {
			return array( 'error' => __( 'The file could not be read.', 'vulnhub' ) );
		}

		$header = fgetcsv( $fh );
		if ( ! is_array( $header ) ) {
			fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			return array( 'error' => __( 'The file has no header row.', 'vulnhub' ) );
		}

		// Strip a UTF-8 BOM from the first header cell, then locate columns by name.
		$header[0] = preg_replace( '/^\xEF\xBB\xBF/', '', (string) $header[0] );
		$idx       = array();
		foreach ( $header as $i => $col ) {
			$idx[ strtolower( trim( (string) $col ) ) ] = $i;
		}

		$upn_col = $idx['userprincipalname'] ?? ( $idx['upn'] ?? null );
		$dep_col = $idx['department'] ?? null;

		if ( null === $upn_col || null === $dep_col ) {
			fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			return array( 'error' => __( 'The file needs both a userPrincipalName and a department column.', 'vulnhub' ) );
		}

		while ( ( $row = fgetcsv( $fh ) ) !== false ) {
			++$rows;
			$upn = strtolower( trim( (string) ( $row[ $upn_col ] ?? '' ) ) );
			$dep = trim( (string) ( $row[ $dep_col ] ?? '' ) );

			if ( '' !== $upn && '' !== $dep ) {
				$map[ $upn ] = $dep;
			}
		}
		fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		// Walk our EXISTING people; never create. Update only when it changes.
		global $wpdb;
		$p       = vh_table( 'people' );
		$people  = (array) $wpdb->get_results( "SELECT id, upn, department FROM {$p} WHERE upn <> ''", ARRAY_A ); // phpcs:ignore WordPress.DB
		$matched = 0;
		$updated = 0;

		foreach ( $people as $person ) {
			$upn = strtolower( trim( (string) $person['upn'] ) );

			if ( ! isset( $map[ $upn ] ) ) {
				continue;
			}

			++$matched;
			$dep = $map[ $upn ];

			if ( (string) $person['department'] !== $dep ) {
				$wpdb->update( // phpcs:ignore WordPress.DB
					$p,
					array( 'department' => $dep, 'last_synced_at' => vh_now() ),
					array( 'id' => (int) $person['id'] )
				);
				++$updated;
			}
		}

		$summary = array(
			'at'      => vh_now(),
			'file'    => '' !== $name ? $name : basename( $path ),
			'rows'    => $rows,
			'matched' => $matched,
			'updated' => $updated,
			'skipped' => max( 0, count( $map ) - $matched ),
		);
		update_option( self::OPT_LAST, $summary, false );

		// Findings widgets read department live, but their markup is cached; bust
		// so the new grouping shows without waiting for the next refresh.
		if ( class_exists( 'VulnHub_Dash_Widgets' ) ) {
			VulnHub_Dash_Widgets::bust();
		}

		if ( function_exists( 'vulnhub' ) && isset( vulnhub()->logger ) ) {
			vulnhub()->logger->audit( 'departments.imported', __( 'Department enrichment imported', 'vulnhub' ), 'people', '', $summary );
		}

		return $summary;
	}
}
