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
	 * @return array<string,array{label:string,yes:array<string,int>,no:array<string,int>}>
	 */
	public static function by_severity(): array {
		$out = array();

		foreach ( self::matrix() as $row ) {
			$sev = (string) $row['severity'];

			if ( ! isset( $out[ $sev ] ) ) {
				$out[ $sev ] = array(
					'label' => (string) $row['severity_label'],
					'yes'   => array( 'vulns' => 0, 'findings' => 0, 'assets' => 0 ),
					'no'    => array( 'vulns' => 0, 'findings' => 0, 'assets' => 0 ),
				);
			}

			$side = $row['patchable'] ? 'yes' : 'no';

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
	public static function url( string $severity, bool $patchable ): string {
		return VulnHub_Dash_Portal::portal_url(
			'vulnerabilities',
			array(
				'severity'        => $severity,
				'patch_available' => $patchable ? '1' : '0',
				'state'           => 'open_any',
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

		foreach ( $by as $sev => $cell ) {
			$yes = (int) $cell['yes']['findings'];
			$no  = (int) $cell['no']['findings'];

			$patchable += $yes;
			$no_patch  += $no;

			$rows[] = array(
				'label'    => (string) $cell['label'],
				'sub'      => sprintf(
					/* translators: %s: number of distinct vulnerabilities. */
					_n( '%s vulnerability', '%s vulnerabilities', (int) $cell['yes']['vulns'] + (int) $cell['no']['vulns'], 'vulnhub' ),
					number_format_i18n( (int) $cell['yes']['vulns'] + (int) $cell['no']['vulns'] )
				),
				'segments' => array(
					array(
						'label'  => __( 'Patch available', 'vulnhub' ),
						'value'  => $yes,
						'colour' => 'var(--vh-good)',
						'href'   => self::url( (string) $sev, true ),
						'title'  => sprintf(
							/* translators: 1: count, 2: severity, 3: assets. */
							__( '%1$s %2$s findings with a patch, on %3$s assets', 'vulnhub' ),
							number_format_i18n( $yes ),
							strtolower( (string) $cell['label'] ),
							number_format_i18n( (int) $cell['yes']['assets'] )
						),
					),
					array(
						'label'  => __( 'No patch available', 'vulnhub' ),
						'value'  => $no,
						'colour' => 'var(--vh-sev-critical)',
						'href'   => self::url( (string) $sev, false ),
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
					array( 'label' => __( 'No patch available', 'vulnhub' ), 'colour' => 'var(--vh-sev-critical)' ),
				),
			)
		);

		$total = $patchable + $no_patch;

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
					$r['patchable'] ? __( 'Available', 'vulnhub' ) : __( 'None known', 'vulnhub' ),
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
				__( 'Patch available', 'vulnhub' ),
				__( 'Vulnerabilities', 'vulnhub' ),
				__( 'Open findings', 'vulnhub' ),
				__( 'Assets affected', 'vulnhub' ),
			),
			'rows'    => array_map(
				static fn( array $r ): array => array(
					(string) $r['severity_label'],
					$r['patchable'] ? __( 'yes', 'vulnhub' ) : __( 'no', 'vulnhub' ),
					(string) $r['vulns'],
					(string) $r['findings'],
					(string) $r['assets'],
				),
				self::matrix()
			),
		);
	}
}

