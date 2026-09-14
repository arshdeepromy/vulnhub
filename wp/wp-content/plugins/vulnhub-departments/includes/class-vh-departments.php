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
	public const VIEW       = 'departments';
	public const WIDGET     = 'department_exposure';
	public const IMPORT_ACT  = 'vulnhub_dept_import';
	public const CSV_ACT     = 'vulnhub_dept_devices_csv';
	public const OPT_LAST      = 'vulnhub_dept_last_import';
	public const OPT_ALIASES   = 'vulnhub_dept_aliases';
	public const OPT_OVERRIDES = 'vulnhub_dept_overrides';

	public static function init(): void {
		// Department as a findings filter (list + CSV export both route here).
		add_filter( 'vulnhub_findings_query', array( __CLASS__, 'findings_query' ), 10, 2 );

		// Admin screen to upload the Entra export.
		add_filter( 'vulnhub_portal_sections', array( __CLASS__, 'register_section' ) );
		add_action( 'vulnhub_render_portal_section', array( __CLASS__, 'render_section' ) );
		add_action( 'admin_post_' . self::IMPORT_ACT, array( __CLASS__, 'handle_import' ) );
		add_action( 'admin_post_' . self::CSV_ACT, array( __CLASS__, 'handle_devices_csv' ) );

		// The dashboard widget.
		add_filter( 'vulnhub_dashboard_widgets', array( __CLASS__, 'register_widget' ) );
		add_filter( 'vulnhub_dashboard_default_layout', array( __CLASS__, 'place_widget' ) );

		// A full "all departments" page, reached from the widget's button.
		add_filter( 'vulnhub_dash_views', array( __CLASS__, 'register_view' ) );
		add_action( 'vulnhub_dash_render_view_' . self::VIEW, array( __CLASS__, 'render_view' ) );
		add_action( 'admin_init', array( __CLASS__, 'ensure_page' ) );
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
			'width'   => 12,
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
				$out[] = array( 'id' => self::WIDGET, 'width' => 12 );
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
		/*
		 * The aggregate below groups every open finding by owning department --
		 * a three-table join over hundreds of thousands of rows. The widget
		 * markup is host-cached, but the full "all departments" page and any
		 * cold render run this live, so the result is memoised in an
		 * epoch-keyed transient the way Exposure-by-product caches its rows:
		 * one query per data epoch, shared across hosts and drill-downs, and
		 * rotated automatically whenever a sync or import calls bust().
		 */
		$epoch = class_exists( 'VulnHub_Dash_Widgets' ) ? VulnHub_Dash_Widgets::epoch() : '';
		$ck    = 'vh_dept_rows_' . md5( (string) $limit . '|' . $epoch );
		$hit   = get_transient( $ck );

		if ( is_array( $hit ) ) {
			return $hit;
		}

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

		$rows = (array) $wpdb->get_results( $wpdb->prepare( $sql, $limit ), ARRAY_A ); // phpcs:ignore WordPress.DB

		$ttl = class_exists( 'VulnHub_Dash_Widgets' ) ? VulnHub_Dash_Widgets::stale_ttl() : HOUR_IN_SECONDS;
		set_transient( $ck, $rows, $ttl );

		return $rows;
	}

	/** Portal URL to the findings of one department (+ optional severity). */
	private static function dept_url( string $department, string $severity = '' ): string {
		$args = array( 'department' => $department, 'state' => 'open_any' );

		if ( '' !== $severity ) {
			$args['severity'] = $severity;
		}

		return VulnHub_Dash_Portal::portal_url( 'vulnerabilities', $args );
	}

	/**
	 * The severity-stacked bar list for the top-$limit departments (or the
	 * empty state). Shared by the dashboard widget and the full page.
	 */
	private static function stack_html( int $limit, string $caption ): string {
		$rows = self::widget_rows( $limit );

		if ( ! $rows ) {
			$msg = self::has_departments()
				? __( 'No open findings resolve to a department yet.', 'vulnhub' )
				: __( 'No departments recorded. Upload an Entra user export under Admin → Departments.', 'vulnhub' );

			return class_exists( 'VulnHub_Dash_Charts' )
				? VulnHub_Dash_Charts::empty_state( $msg )
				: '<p class="vh-chart-empty">' . esc_html( $msg ) . '</p>';
		}

		return '<div class="vh-deptstack">' . VulnHub_Dash_Charts::severity_stack(
			array_map(
				static function ( array $r ): array {
					$dept   = (string) $r['label'];
					$assets = (int) $r['assets'];

					return array(
						'label'      => vh_trim( $dept, 32 ),
						'href'       => self::dept_url( $dept ),
						// The findings total links to that department's finding list.
						'value_href' => self::dept_url( $dept ),
						// Trailing column: how many devices carry these findings,
						// linking to the per-device report for the department.
						'extra'      => sprintf(
							/* translators: %s: number of devices. */
							_n( '%s device', '%s devices', $assets, 'vulnhub' ),
							number_format_i18n( $assets )
						),
						'extra_href' => self::view_url( array( 'dept' => $dept ) ),
						'seg_hrefs'  => array(
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
			array( 'caption' => $caption )
		) . '</div>';
	}

	/** Departments that carry at least one open finding. */
	private static function department_count(): int {
		$epoch = class_exists( 'VulnHub_Dash_Widgets' ) ? VulnHub_Dash_Widgets::epoch() : '';
		$ck    = 'vh_dept_count_' . md5( $epoch );
		$hit   = get_transient( $ck );

		if ( false !== $hit ) {
			return (int) $hit;
		}

		global $wpdb;

		$f = vh_table( 'findings' );
		$a = vh_table( 'assets' );
		$p = vh_table( 'people' );

		$n = (int) $wpdb->get_var( // phpcs:ignore WordPress.DB
			"SELECT COUNT(DISTINCT p.department)
			 FROM {$f} f
			 INNER JOIN {$a} a ON a.id = f.asset_id
			 INNER JOIN {$p} p ON p.id = a.owner_person_id
			 WHERE f.state IN ('open','reopened') AND f.exception_id = 0 AND p.department <> ''" // phpcs:ignore WordPress.DB
		);

		$ttl = class_exists( 'VulnHub_Dash_Widgets' ) ? VulnHub_Dash_Widgets::stale_ttl() : HOUR_IN_SECONDS;
		set_transient( $ck, $n, $ttl );

		return $n;
	}

	public static function render_widget(): void {
		echo self::stack_html( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			14,
			__( 'Open findings by owning department. Select a bar for the devices and vulnerabilities behind it.', 'vulnhub' )
		);

		$total = self::department_count();

		if ( $total > 14 ) {
			printf(
				'<p class="vh-prodlist__more"><a class="vh-btn vh-btn--ghost vh-btn--sm" href="%s">%s</a></p>',
				esc_url( self::view_url() ),
				esc_html(
					sprintf(
						/* translators: %s: total number of departments. */
						__( 'View all %s departments →', 'vulnhub' ),
						number_format_i18n( $total )
					)
				)
			);
		}
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
	 * The "all departments" page (reached from the widget)
	 * ============================================================== */

	/**
	 * @param array<string,array<string,mixed>> $views Portal views.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_view( array $views ): array {
		$views[ self::VIEW ] = array(
			'title'  => __( 'Vulnerabilities by department', 'vulnhub' ),
			'slug'   => self::VIEW,
			'menu'   => __( 'Departments', 'vulnhub' ),
			'icon'   => 'M3 21h18M5 21V7l7-4 7 4v14M9 21v-4h6v4M9 10h.01M15 10h.01M12 13h.01',
			'hidden' => true, // Reached from the widget, like the products page.
		);

		return $views;
	}

	/** URL of the full department page. */
	public static function view_url( array $args = array() ): string {
		return VulnHub_Dash_Portal::portal_url( self::VIEW, $args );
	}

	/**
	 * Create the page that hosts the full list, mapped in `vulnhub_dash_pages`
	 * so the navigation and portal_url() can find it — the same contract every
	 * other view follows.
	 */
	public static function ensure_page(): void {
		$map = (array) get_option( 'vulnhub_dash_pages', array() );

		$existing = ! empty( $map[ self::VIEW ] ) ? get_post( (int) $map[ self::VIEW ] ) : null;
		if ( $existing && 'trash' !== $existing->post_status ) {
			return;
		}

		$page = get_page_by_path( self::VIEW );

		if ( $page ) {
			$id = (int) $page->ID;
		} else {
			$id = wp_insert_post(
				array(
					'post_title'     => __( 'Departments', 'vulnhub' ),
					'post_name'      => self::VIEW,
					'post_content'   => '<!-- wp:shortcode -->[vulnhub_app view="' . self::VIEW . '"]<!-- /wp:shortcode -->',
					'post_status'    => 'publish',
					'post_type'      => 'page',
					'comment_status' => 'closed',
					'ping_status'    => 'closed',
				)
			);
		}

		if ( ! is_wp_error( $id ) && $id ) {
			$map[ self::VIEW ] = (int) $id;
			update_option( 'vulnhub_dash_pages', $map, false );
		}
	}

	public static function render_view(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$dept = isset( $_GET['dept'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['dept'] ) ) : '';

		if ( '' !== $dept ) {
			self::render_devices( $dept );
			return;
		}

		$total = self::department_count();
		?>
		<div class="vh-stack">
			<div class="vh-page-head">
				<div>
					<h1><?php esc_html_e( 'Vulnerabilities by department', 'vulnhub' ); ?></h1>
					<p class="vh-sub"><?php
						/* translators: %s: number of departments with open findings. */
						echo esc_html( sprintf( __( 'Open findings across %s departments, by the department that owns the device. Select the findings number for the finding list, or the device count for the devices behind it.', 'vulnhub' ), number_format_i18n( $total ) ) );
					?></p>
				</div>
				<a class="vh-btn vh-btn--ghost vh-btn--sm" href="<?php echo esc_url( VulnHub_Dash_Portal::portal_url( 'dashboard' ) ); ?>"><?php esc_html_e( 'Back to dashboard', 'vulnhub' ); ?></a>
			</div>
			<div class="vh-card">
				<?php
				echo self::stack_html( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					1000,
					__( 'Every department with an open finding, largest first. The number is open findings; the right column is devices affected.', 'vulnhub' )
				);
				?>
			</div>
		</div>
		<?php
	}

	/**
	 * The per-device report for one department: a severity bar per device, the
	 * owner in the right column, and a CSV export.
	 */
	private static function render_devices( string $dept ): void {
		$rows     = self::device_rows( $dept );
		$findings = 0;
		foreach ( $rows as $r ) {
			$findings += (int) $r['total'];
		}
		?>
		<div class="vh-stack">
			<div class="vh-page-head">
				<div>
					<h1><?php echo esc_html( sprintf( /* translators: %s: department name. */ __( 'Devices in %s', 'vulnhub' ), $dept ) ); ?></h1>
					<p class="vh-sub"><?php
						echo esc_html(
							sprintf(
								/* translators: 1: device count, 2: open findings. */
								_n( '%1$s device carrying %2$s open findings. Select a device for its vulnerabilities.', '%1$s devices carrying %2$s open findings. Select a device for its vulnerabilities.', count( $rows ), 'vulnhub' ),
								number_format_i18n( count( $rows ) ),
								number_format_i18n( $findings )
							)
						);
					?></p>
				</div>
				<div class="vh-actions">
					<a class="vh-btn vh-btn--ghost vh-btn--sm" href="<?php echo esc_url( self::view_url() ); ?>"><?php esc_html_e( 'All departments', 'vulnhub' ); ?></a>
					<a class="vh-btn vh-btn--ghost vh-btn--sm" href="<?php echo esc_url( self::devices_csv_url( $dept ) ); ?>"><?php esc_html_e( 'Export CSV', 'vulnhub' ); ?></a>
					<a class="vh-btn vh-btn--primary vh-btn--sm" href="<?php echo esc_url( self::dept_url( $dept ) ); ?>"><?php esc_html_e( 'View findings list', 'vulnhub' ); ?></a>
				</div>
			</div>
			<div class="vh-card">
				<?php echo self::device_stack_html( $rows ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Open findings per device for one department, with the device owner.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function device_rows( string $dept ): array {
		global $wpdb;

		$f = vh_table( 'findings' );
		$a = vh_table( 'assets' );
		$p = vh_table( 'people' );

		return (array) $wpdb->get_results( // phpcs:ignore WordPress.DB
			$wpdb->prepare(
				"SELECT a.id AS asset_id, a.hostname, a.ipv4, a.asset_type, p.display_name AS owner,
					SUM(f.severity = 'critical') AS critical,
					SUM(f.severity = 'high')     AS high,
					SUM(f.severity = 'medium')   AS medium,
					SUM(f.severity = 'low')      AS low,
					SUM(f.severity = 'info')     AS info,
					COUNT(*)                     AS total
				 FROM {$f} f
				 INNER JOIN {$a} a ON a.id = f.asset_id
				 INNER JOIN {$p} p ON p.id = a.owner_person_id
				 WHERE f.state IN ('open','reopened') AND f.exception_id = 0 AND p.department = %s
				 GROUP BY a.id
				 ORDER BY critical DESC, high DESC, total DESC", // phpcs:ignore WordPress.DB
				$dept
			),
			ARRAY_A
		);
	}

	/** @param array<int,array<string,mixed>> $rows */
	private static function device_stack_html( array $rows ): string {
		if ( ! $rows ) {
			return class_exists( 'VulnHub_Dash_Charts' )
				? VulnHub_Dash_Charts::empty_state( __( 'No open findings on any device in this department.', 'vulnhub' ) )
				: '';
		}

		$asset_url = static function ( int $id, string $sev = '' ): string {
			return VulnHub_Dash_Portal::portal_url(
				'vulnerabilities',
				array_filter( array( 'asset' => $id, 'severity' => $sev, 'state' => 'open_any' ) )
			);
		};

		return '<div class="vh-deptstack">' . VulnHub_Dash_Charts::severity_stack(
			array_map(
				static function ( array $r ) use ( $asset_url ): array {
					$id    = (int) $r['asset_id'];
					$host  = '' !== (string) $r['hostname'] ? (string) $r['hostname'] : 'asset ' . $id;
					$owner = '' !== (string) $r['owner'] ? (string) $r['owner'] : '—';

					return array(
						'label'      => vh_trim( $host, 32 ),
						'href'       => $asset_url( $id ),
						'value_href' => $asset_url( $id ),
						'extra'      => vh_trim( $owner, 24 ),
						'extra_href' => VulnHub_Dash_Portal::portal_url( 'assets', array( 'asset' => $id ) ),
						'seg_hrefs'  => array(
							'critical' => $asset_url( $id, 'critical' ),
							'high'     => $asset_url( $id, 'high' ),
							'medium'   => $asset_url( $id, 'medium' ),
							'low'      => $asset_url( $id, 'low' ),
							'info'     => $asset_url( $id, 'info' ),
						),
						'counts'     => array(
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
			array( 'caption' => __( 'Open findings per device, coloured by severity. The right column is the device owner.', 'vulnhub' ) )
		) . '</div>';
	}

	/** Nonced CSV export URL for a department's devices. */
	public static function devices_csv_url( string $dept ): string {
		return wp_nonce_url(
			add_query_arg(
				array(
					'action'     => self::CSV_ACT,
					'department' => rawurlencode( $dept ),
				),
				admin_url( 'admin-post.php' )
			),
			self::CSV_ACT
		);
	}

	public static function handle_devices_csv(): void {
		if ( ! current_user_can( Caps::VIEW ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'vulnhub' ) );
		}

		check_admin_referer( self::CSV_ACT );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$dept = isset( $_GET['department'] ) ? sanitize_text_field( rawurldecode( wp_unslash( (string) $_GET['department'] ) ) ) : '';
		$rows = self::device_rows( $dept );

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="devices-' . sanitize_file_name( '' !== $dept ? $dept : 'department' ) . '.csv"' );

		$out = fopen( 'php://output', 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		fputcsv( $out, array( 'Device', 'IP', 'Owner', 'Type', 'Critical', 'High', 'Medium', 'Low', 'Info', 'Open findings' ) );

		foreach ( $rows as $r ) {
			fputcsv(
				$out,
				array(
					(string) $r['hostname'],
					(string) $r['ipv4'],
					(string) $r['owner'],
					(string) $r['asset_type'],
					(int) $r['critical'],
					(int) $r['high'],
					(int) $r['medium'],
					(int) $r['low'],
					(int) $r['info'],
					(int) $r['total'],
				)
			);
		}
		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		exit;
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
	/**
	 * Canonical alias map for department names that mean the same team.
	 *
	 * Keys are matched case-insensitively (against the trimmed source value);
	 * the value is the canonical name we store. Extend by saving more pairs to
	 * the OPT_ALIASES option, or via the 'vulnhub_department_aliases' filter.
	 *
	 * @return array<string,string> lower-cased source name => canonical name.
	 */
	public static function aliases(): array {
		$defaults = array(
			'platform and services' => 'Platform and Operations',
		);

		$stored = get_option( self::OPT_ALIASES, array() );
		if ( is_array( $stored ) ) {
			foreach ( $stored as $from => $to ) {
				$from = strtolower( trim( (string) $from ) );
				$to   = trim( (string) $to );
				if ( '' !== $from && '' !== $to ) {
					$defaults[ $from ] = $to;
				}
			}
		}

		/** Allow other code to register department aliases. */
		$map = apply_filters( 'vulnhub_department_aliases', $defaults );

		return is_array( $map ) ? $map : $defaults;
	}

	/**
	 * Collapse a source department name onto its canonical alias, if any.
	 *
	 * @param string $dep Raw (already trimmed) department name.
	 * @return string Canonical department name.
	 */
	public static function normalize_department( string $dep ): string {
		$key     = strtolower( $dep );
		$aliases = self::aliases();

		return $aliases[ $key ] ?? $dep;
	}

	/**
	 * Per-person department pins, keyed by lower-cased UPN.
	 *
	 * Unlike aliases (which rename a whole department), an override forces a
	 * specific individual onto a department no matter what the Entra export
	 * says for them -- so it survives every re-import. Stored in the
	 * OPT_OVERRIDES option; also filterable via 'vulnhub_department_overrides'.
	 *
	 * @return array<string,string> lower-cased UPN => canonical department.
	 */
	public static function overrides(): array {
		$stored = get_option( self::OPT_OVERRIDES, array() );
		$out    = array();

		if ( is_array( $stored ) ) {
			foreach ( $stored as $upn => $dep ) {
				$upn = strtolower( trim( (string) $upn ) );
				$dep = trim( (string) $dep );
				if ( '' !== $upn && '' !== $dep ) {
					$out[ $upn ] = self::normalize_department( $dep );
				}
			}
		}

		$out = apply_filters( 'vulnhub_department_overrides', $out );

		return is_array( $out ) ? $out : array();
	}

	/**
	 * Force every pinned person onto their assigned department.
	 *
	 * Runs across ALL existing people (not just those present in an import),
	 * so a pin still applies to someone the latest Entra export omitted.
	 *
	 * @return int Number of people whose department row was changed.
	 */
	public static function apply_overrides(): int {
		global $wpdb;
		$ov = self::overrides();
		if ( ! $ov ) {
			return 0;
		}

		$p       = vh_table( 'people' );
		$people  = (array) $wpdb->get_results( "SELECT id, upn, department FROM {$p} WHERE upn <> ''", ARRAY_A ); // phpcs:ignore WordPress.DB
		$changed = 0;

		foreach ( $people as $person ) {
			$upn = strtolower( trim( (string) $person['upn'] ) );
			if ( ! isset( $ov[ $upn ] ) ) {
				continue;
			}
			$dep = $ov[ $upn ];
			if ( (string) $person['department'] !== $dep ) {
				$wpdb->update( // phpcs:ignore WordPress.DB
					$p,
					array( 'department' => $dep, 'last_synced_at' => vh_now() ),
					array( 'id' => (int) $person['id'] )
				);
				++$changed;
			}
		}

		return $changed;
	}

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
			$dep = self::normalize_department( trim( (string) ( $row[ $dep_col ] ?? '' ) ) );

			if ( '' !== $upn && '' !== $dep ) {
				$map[ $upn ] = $dep;
			}
		}
		fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		// Walk our EXISTING people; never create. Update only when it changes.
		global $wpdb;
		$p       = vh_table( 'people' );
		$people  = (array) $wpdb->get_results( "SELECT id, upn, department FROM {$p} WHERE upn <> ''", ARRAY_A ); // phpcs:ignore WordPress.DB
		$ov      = self::overrides();
		$matched = 0;
		$updated = 0;

		foreach ( $people as $person ) {
			$upn = strtolower( trim( (string) $person['upn'] ) );

			if ( ! isset( $map[ $upn ] ) ) {
				continue;
			}

			++$matched;
			// A per-person pin always wins over whatever the export lists.
			$dep = $ov[ $upn ] ?? $map[ $upn ];

			if ( (string) $person['department'] !== $dep ) {
				$wpdb->update( // phpcs:ignore WordPress.DB
					$p,
					array( 'department' => $dep, 'last_synced_at' => vh_now() ),
					array( 'id' => (int) $person['id'] )
				);
				++$updated;
			}
		}

		// Pin anyone whose UPN was overridden but not present in this export.
		$updated += self::apply_overrides();

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
