<?php
/**
 * "How much of this can we actually fix?"
 *
 * Severity tells you what to worry about. It does not tell you what to do,
 * and on this estate the difference is stark: of 230,000 open findings, the
 * ones with no vendor fix are concentrated on 39 machines. Those 39 are a
 * project — an upgrade, a segmentation change, a decommission — and putting
 * them on a patching queue wastes everybody's month. The rest is patching
 * work and can be scheduled.
 *
 * So this widget draws one bar per severity and splits it: the part somebody
 * can patch, and the part nobody can. Both halves are clickable, and both
 * land on exactly the rows they counted, because the chart and the list are
 * drawn from the same test in Repo (see Repo::patch_sql()).
 *
 * @package VulnHub\Dashboard
 */

declare( strict_types = 1 );

use VulnHub\Core\Repo;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Patch availability, as a chart and as rows.
 */
final class VulnHub_Dash_Patching {

	/**
	 * Severity by patch availability, one row per cell.
	 *
	 * Cached for the same reason every other widget's numbers are: the
	 * aggregate is a full pass over the findings table, it changes only when
	 * an import or a sync runs, and both of those bust the cache.
	 *
	 * @return array<int,array{severity:string,severity_label:string,patchable:bool,vulns:int,findings:int,assets:int}>
	 */
	public static function matrix(): array {
		$rows = Repo::patch_matrix();
		$out  = array();

		foreach ( $rows as $row ) {
			$row['severity_label'] = vh_severity_label( (string) $row['severity'] );
			$out[]                 = $row;
		}

		return $out;
	}

	/**
	 * The same figures shaped as one row per severity.
	 *
	 * `yes` is a direct patch, `app` an update to the application that ships
	 * the component, `no` no known fix.
	 *
	 * @return array<string,array{label:string,yes:array<string,int>,app:array<string,int>,no:array<string,int>}>
	 */
	public static function by_severity(): array {
		$out = array();

		foreach ( self::matrix() as $row ) {
			$sev = (string) $row['severity'];

			if ( ! isset( $out[ $sev ] ) ) {
				$out[ $sev ] = array(
					'label' => (string) $row['severity_label'],
					'yes'   => array( 'vulns' => 0, 'findings' => 0, 'assets' => 0 ),
					'app'   => array( 'vulns' => 0, 'findings' => 0, 'assets' => 0 ),
					'no'    => array( 'vulns' => 0, 'findings' => 0, 'assets' => 0 ),
				);
			}

			$side = array( 'direct' => 'yes', 'app' => 'app', 'none' => 'no' )[ (string) $row['route'] ] ?? 'no';

			$out[ $sev ][ $side ] = array(
				'vulns'    => (int) $row['vulns'],
				'findings' => (int) $row['findings'],
				'assets'   => (int) $row['assets'],
			);
		}

		return $out;
	}

	/**
	 * The vulnerability list, filtered to one cell of the matrix.
	 */
	public static function url( string $severity, string $route ): string {
		return VulnHub_Dash_Portal::portal_url(
			'vulnerabilities',
			array(
				'severity'        => $severity,
				'patch_available' => array( 'direct' => 'direct', 'app' => 'app' )[ $route ] ?? '0',
				'state'           => 'open_any',
				// The matrix excludes accepted risk; the list has to as well,
				// or the segment opens more rows than it counted.
				'excepted'        => 'exclude',
			)
		);
	}

	/* =================================================================
	 * The widget
	 * ============================================================== */

	public static function render(): void {
		$by = self::by_severity();

		if ( ! $by ) {
			echo VulnHub_Dash_Charts::empty_state( esc_html__( 'No open findings to measure yet.', 'vulnhub' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			return;
		}

		$rows      = array();
		$no_patch  = 0;
		$patchable = 0;
		$via_app   = 0;

		foreach ( $by as $sev => $cell ) {
			$yes = (int) $cell['yes']['findings'];
			$app = (int) $cell['app']['findings'];
			$no  = (int) $cell['no']['findings'];

			$patchable += $yes;
			$via_app   += $app;
			$no_patch  += $no;

			$rows[] = array(
				'label'    => (string) $cell['label'],
				'sub'      => sprintf(
					/* translators: %s: number of distinct vulnerabilities. */
					_n( '%s vulnerability', '%s vulnerabilities', (int) $cell['yes']['vulns'] + (int) $cell['app']['vulns'] + (int) $cell['no']['vulns'], 'vulnhub' ),
					number_format_i18n( (int) $cell['yes']['vulns'] + (int) $cell['app']['vulns'] + (int) $cell['no']['vulns'] )
				),
				'segments' => array(
					array(
						'label'  => __( 'Patch available', 'vulnhub' ),
						'value'  => $yes,
						'colour' => 'var(--vh-good)',
						'href'   => self::url( (string) $sev, 'direct' ),
						'title'  => sprintf(
							/* translators: 1: count, 2: severity, 3: assets. */
							__( '%1$s %2$s findings with a patch, on %3$s assets', 'vulnhub' ),
							number_format_i18n( $yes ),
							strtolower( (string) $cell['label'] ),
							number_format_i18n( (int) $cell['yes']['assets'] )
						),
					),
					array(
						'label'  => __( 'Update the app that ships it', 'vulnhub' ),
						'value'  => $app,
						'colour' => 'var(--vh-sev-medium)',
						'href'   => self::url( (string) $sev, 'app' ),
						'title'  => sprintf(
							/* translators: 1: count, 2: severity, 3: assets. */
							__( '%1$s %2$s findings in components shipped inside other applications, on %3$s assets: the fix arrives through an update to that application', 'vulnhub' ),
							number_format_i18n( $app ),
							strtolower( (string) $cell['label'] ),
							number_format_i18n( (int) $cell['app']['assets'] )
						),
					),
					array(
						'label'  => __( 'No patch available', 'vulnhub' ),
						'value'  => $no,
						'colour' => 'var(--vh-sev-critical)',
						'href'   => self::url( (string) $sev, 'none' ),
						'title'  => sprintf(
							/* translators: 1: count, 2: severity, 3: assets. */
							__( '%1$s %2$s findings with no known fix, on %3$s assets', 'vulnhub' ),
							number_format_i18n( $no ),
							strtolower( (string) $cell['label'] ),
							number_format_i18n( (int) $cell['no']['assets'] )
						),
					),
				),
			);
		}

		echo VulnHub_Dash_Charts::segment_bars( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			$rows,
			array(
				'unit'   => __( 'findings', 'vulnhub' ),
				// The question is what proportion of each severity can be
				// fixed, not which severity is largest -- the severity donut
				// already answers that, and on a shared scale the criticals
				// would be a sliver nobody could read the split off.
				'scale'  => 'row',
				'legend' => array(
					array( 'label' => __( 'Patch available', 'vulnhub' ), 'colour' => 'var(--vh-good)' ),
					array( 'label' => __( 'Update the app that ships it', 'vulnhub' ), 'colour' => 'var(--vh-sev-medium)' ),
					array( 'label' => __( 'No patch available', 'vulnhub' ), 'colour' => 'var(--vh-sev-critical)' ),
				),
			)
		);

		$total = $patchable + $via_app + $no_patch;

		if ( $total > 0 && $via_app > 0 ) {
			printf(
				'<p class="vh-w__note">%s</p>',
				esc_html(
					sprintf(
						/* translators: 1: count, 2: percentage. */
						__( '%1$s (%2$s%%) are components shipped inside other applications, such as a libcurl inside a driver: Tenable\'s fix is for the component, and it only arrives when that application\'s vendor ships it.', 'vulnhub' ),
						number_format_i18n( $via_app ),
						number_format_i18n( round( ( $via_app / $total ) * 100, 1 ) )
					)
				)
			);
		}

		if ( $total > 0 ) {
			printf(
				'<p class="vh-w__note">%s</p>',
				esc_html(
					sprintf(
						/* translators: 1: count, 2: percentage. */
						__( '%1$s of %2$s open findings have no vendor fix (%3$s%%). Those need a decision, not a patch window.', 'vulnhub' ),
						number_format_i18n( $no_patch ),
						number_format_i18n( $total ),
						number_format_i18n( round( ( $no_patch / $total ) * 100, 1 ) )
					)
				)
			);
		}

		echo VulnHub_Dash_Charts::table_view( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			array(
				__( 'Severity', 'vulnhub' ),
				__( 'Patch', 'vulnhub' ),
				__( 'Vulnerabilities', 'vulnhub' ),
				__( 'Open findings', 'vulnhub' ),
				__( 'Assets', 'vulnhub' ),
			),
			array_map(
				static fn( array $r ): array => array(
					(string) $r['severity_label'],
					Repo::fix_route_labels()[ (string) $r['route'] ] ?? '',
					number_format_i18n( (int) $r['vulns'] ),
					number_format_i18n( (int) $r['findings'] ),
					number_format_i18n( (int) $r['assets'] ),
				),
				self::matrix()
			),
			__( 'Open findings, excluding accepted exceptions.', 'vulnhub' )
		);
	}

	/**
	 * The rows behind the picture, for the CSV button on the widget.
	 *
	 * @return array{headers:array<int,string>,rows:array<int,array<int,string>>}
	 */
	public static function data(): array {
		return array(
			'headers' => array(
				__( 'Severity', 'vulnhub' ),
				__( 'Fix', 'vulnhub' ),
				__( 'Vulnerabilities', 'vulnhub' ),
				__( 'Open findings', 'vulnhub' ),
				__( 'Assets affected', 'vulnhub' ),
			),
			'rows'    => array_map(
				static fn( array $r ): array => array(
					(string) $r['severity_label'],
					Repo::fix_route_labels()[ (string) $r['route'] ] ?? '',
					(string) $r['vulns'],
					(string) $r['findings'],
					(string) $r['assets'],
				),
				self::matrix()
			),
		);
	}
}

