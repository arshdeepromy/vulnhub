<?php
/**
 * "What can we actually do about this, and where?"
 *
 * Severity says what to worry about; patch availability says whether a fix
 * exists. Neither says what the work *is*, and on this estate the difference
 * decides whether a number is a patch window, a script, a project, or nothing
 * anybody can act on today.
 *
 * Six answers, in the order a reader should care about them:
 *
 *   patch        a vendor fix exists -- schedule it
 *   remove       the fix is to uninstall the software
 *   config       the fix is a setting: a policy, a registry value, a service off
 *   blocked_eol  no fix, and the platform is past end of support -- replace it
 *   await_fix    no fix published yet -- a watchlist, not work
 *   excepted     someone has accepted this risk in writing
 *
 * The first three are work somebody can start this week. `blocked_eol` is a
 * project, and the EOL remediation plan already tracks whether one exists.
 * `await_fix` is the biggest bucket on this estate by an order of magnitude --
 * around 219,000 of 256,000 open findings, almost all of them Tenable's "Linux
 * Distros Unpatched Vulnerability" plugins, where the distribution has not
 * shipped a fix. Counting those as outstanding work is what makes a
 * vulnerability programme look unwinnable; naming them is what makes the
 * actionable 31,000 visible.
 *
 * Every segment links to the vulnerability list filtered to exactly the rows it
 * counted, so the number can be exported as a CSV from there.
 *
 * @package VulnHub\Dashboard
 */

declare( strict_types = 1 );

use VulnHub\Core\Os;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Actionability of open findings, by hosting environment and by platform.
 */
final class VulnHub_Dash_Action {

	/**
	 * Colour per class. Presentation lives here; the classification does not.
	 *
	 * `VH_Action` owns what a class means, which classes exist, their order and
	 * the SQL that assigns one -- so the bar and the list it opens are the same
	 * test rather than two opinions that drift. This file only decides what the
	 * bar looks like.
	 *
	 * Measured on this estate, 2026-09-16, so the chart is read correctly:
	 * `await_fix` is 219,741 of 256,642 open findings -- almost entirely
	 * Tenable's "Linux Distros Unpatched Vulnerability" plugins -- against
	 * 29,872 patchable, 6,337 blocked by an expired platform and 692 that are
	 * a setting. `remove` and `excepted` are both zero: no solution on this
	 * estate is phrased as an uninstall, and no exception has been raised yet.
	 * A class with no findings draws no segment, so the bar shows what exists
	 * rather than a legend full of zeroes.
	 *
	 * @var array<string,string>
	 */
	private const COLOURS = array(
		'patch'       => 'var(--vh-good)',
		'remove'      => 'var(--vh-series-1)',
		'config'      => 'var(--vh-series-2)',
		'blocked_eol' => 'var(--vh-sev-critical)',
		'await_fix'   => 'var(--vh-sev-info)',
		'excepted'    => 'var(--vh-muted)',
	);


	/**
	 * The classes, in the order they are drawn and read.
	 *
	 * `actionable` is what separates the top of the bar from the tail: work
	 * somebody can begin without waiting for a vendor or a project.
	 *
	 * @return array<string,array{label:string,colour:string,actionable:bool,help:string}>
	 */
	public static function classes(): array {
		if ( ! self::ready() ) {
			return array();
		}

		$actionable = VH_Action::actionable();
		$out        = array();

		foreach ( VH_Action::classes() as $key => $label ) {
			$out[ $key ] = array(
				'label'      => (string) $label,
				'colour'     => (string) ( self::COLOURS[ $key ] ?? 'var(--vh-muted)' ),
				'actionable' => in_array( $key, $actionable, true ),
				'help'       => VH_Action::description( (string) $key ),
			);
		}

		return $out;
	}

	/**
	 * Is the classification installed?
	 *
	 * The widget is a view of `VH_Action`; without it there is nothing to draw
	 * and nothing honest to say, so it says that rather than inventing a second
	 * classification that would disagree with the filter.
	 */
	private static function ready(): bool {
		return class_exists( 'VH_Action' );
	}

	public static function label( string $class ): string {
		$all = self::classes();

		return (string) ( $all[ $class ]['label'] ?? $class );
	}

	/* =================================================================
	 * Classification
	 * ============================================================== */

	/**
	 * The classification, borrowed whole from its owner.
	 *
	 * `VH_Action::sql_case()` is the same expression `VH_Action::sql_for()`
	 * filters the list with, so a segment and the rows it opens cannot drift:
	 * they are one test evaluated twice, not two tests that agree today.
	 */
	private static function class_case(): string {
		return VH_Action::sql_case( 'f', 'v' );
	}

	/**
	 * Count open findings per class for one slice of the estate.
	 *
	 * The scope matches what the vulnerability list shows by default -- open
	 * and reopened, on assets the dashboard reports on -- because the segment
	 * links there and the two numbers have to be the same number.
	 *
	 * @param string $extra_where Additional SQL, already safe, or ''.
	 * @return array<string,int> class => findings.
	 */
	private static function counts( string $extra_where = '' ): array {
		global $wpdb;

		$f = vh_table( 'findings' );
		$v = vh_table( 'vulns' );
		$a = vh_table( 'assets' );

		$class_case = self::class_case();
		$where      = "f.state IN ('open','reopened') AND a.lifecycle_status IN (" . vh_reportable_sql() . ')';

		if ( '' !== $extra_where ) {
			$where .= ' AND ' . $extra_where;
		}

		$rows = (array) $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			"SELECT {$class_case} AS cls, COUNT(*) AS n
			 FROM {$f} f
			 INNER JOIN {$v} v ON v.id = f.vuln_id
			 INNER JOIN {$a} a ON a.id = f.asset_id
			 WHERE {$where}
			 GROUP BY cls", // phpcs:ignore WordPress.DB.PreparedSQL
			ARRAY_A
		);

		$out = array_fill_keys( array_keys( self::classes() ), 0 );

		foreach ( $rows as $row ) {
			$cls = (string) $row['cls'];

			if ( isset( $out[ $cls ] ) ) {
				$out[ $cls ] = (int) $row['n'];
			}
		}

		return $out;
	}

	/* =================================================================
	 * The two dimensions
	 * ============================================================== */

	/**
	 * One row per hosting environment.
	 *
	 * Scoped to servers and cloud instances, not the whole estate, because
	 * that is what the list's `hosting` filter matches
	 * (`VulnHub_Hosting::hosting_asset_ids()` restricts to those types). A bar
	 * counting laptops that the list then refuses to show is the one failure
	 * this widget cannot afford.
	 *
	 * @return array<int,array{key:string,label:string,counts:array<string,int>}>
	 */
	public static function by_environment(): array {
		if ( ! self::ready() || ! class_exists( 'VulnHub_Hosting' ) ) {
			return array();
		}

		$out = array();

		foreach ( VulnHub_Hosting::environment_labels() as $env => $label ) {
			$ids = array_map( 'intval', VulnHub_Hosting::hosting_asset_ids( (string) $env ) );

			if ( ! $ids ) {
				continue;
			}

			$counts = self::counts( 'f.asset_id IN ( ' . implode( ',', $ids ) . ' )' );

			if ( ! array_sum( $counts ) ) {
				continue;
			}

			$out[] = array(
				'key'    => (string) $env,
				'label'  => (string) $label,
				'counts' => $counts,
			);
		}

		return self::sort_rows( $out );
	}

	/**
	 * One row per platform.
	 *
	 * Platform, not release. The vulnerability list can filter by
	 * `platform=windows|linux|…` and nothing finer, so a bar per release would
	 * be a number with no list behind it. `Os::platform_sql()` is the same
	 * expression that filter uses, so each row's count and its link are one
	 * definition. Per-release actionability lives on the EOL remediation plan,
	 * which is built around exactly that question.
	 *
	 * @return array<int,array{key:string,label:string,counts:array<string,int>}>
	 */
	public static function by_platform(): array {
		if ( ! self::ready() ) {
			return array();
		}

		$out = array();

		foreach ( array_keys( Os::platforms() ) as $platform ) {
			$sql = Os::platform_sql( (string) $platform, 'a.operating_system' );

			if ( '' === $sql ) {
				continue;
			}

			$counts = self::counts( $sql );

			if ( ! array_sum( $counts ) ) {
				continue;
			}

			$out[] = array(
				'key'    => (string) $platform,
				'label'  => Os::platform_label( (string) $platform ),
				'counts' => $counts,
			);
		}

		return self::sort_rows( $out );
	}

	/**
	 * Most actionable work first.
	 *
	 * Sorting by total would lead with whichever platform has the most
	 * unpatched distro advisories, which is the one place nobody can do
	 * anything. The row with the most work somebody can start belongs at the
	 * top of a widget whose whole purpose is finding that work.
	 *
	 * @param array<int,array<string,mixed>> $rows Rows to sort.
	 * @return array<int,array<string,mixed>>
	 */
	private static function sort_rows( array $rows ): array {
		usort(
			$rows,
			static function ( array $x, array $y ): int {
				$xa = self::actionable( (array) $x['counts'] );
				$ya = self::actionable( (array) $y['counts'] );

				if ( $xa === $ya ) {
					return array_sum( (array) $y['counts'] ) <=> array_sum( (array) $x['counts'] );
				}

				return $ya <=> $xa;
			}
		);

		return $rows;
	}

	/**
	 * The part of a row somebody can start on.
	 *
	 * @param array<string,int> $counts Per-class counts.
	 */
	private static function actionable( array $counts ): int {
		$n = 0;

		foreach ( self::classes() as $key => $def ) {
			if ( $def['actionable'] ) {
				$n += (int) ( $counts[ $key ] ?? 0 );
			}
		}

		return $n;
	}

	/* =================================================================
	 * Links
	 * ============================================================== */

	/**
	 * The vulnerability list, filtered to one segment.
	 *
	 * `action` is the filter `VulnHub\Core\VH_Action` adds; the dimension
	 * argument is one the list already understands. Both are needed: a segment
	 * means "this class, on this slice", and a link carrying only one of them
	 * would open a longer list than the number it came from.
	 *
	 * @param array<string,string> $dimension The environment or platform argument.
	 * @param string               $class     Action class, or '' for the whole row.
	 */
	private static function url( array $dimension, string $class = '' ): string {
		$args = array_merge(
			$dimension,
			array(
				'state' => 'open_any',
				'life'  => 'reportable',
			)
		);

		if ( '' !== $class ) {
			/*
			 * `fix`, not `action`: admin-post.php reads `action`, and the
			 * findings screen's export form posts there -- a filter of that
			 * name overwrote the export's own action and broke the download.
			 */
			$args['fix'] = $class;
		}

		return VulnHub_Dash_Portal::portal_url( 'vulnerabilities', $args );
	}

	/* =================================================================
	 * Rendering
	 * ============================================================== */

	public static function render_environment(): void {
		self::render_rows(
			self::by_environment(),
			'hosting',
			__( 'No open findings on servers or cloud instances yet.', 'vulnhub' ),
			__( 'Servers and cloud instances only, which is what the hosting filter matches.', 'vulnhub' )
		);
	}

	public static function render_platform(): void {
		self::render_rows(
			self::by_platform(),
			'platform',
			__( 'No open findings to classify yet.', 'vulnhub' ),
			__( 'Every asset the dashboard reports on, grouped by the platform the vulnerability list can filter by.', 'vulnhub' )
		);
	}

	/**
	 * The shared picture: one bar per row, split by what the work is.
	 *
	 * @param array<int,array<string,mixed>> $rows  Dimension rows.
	 * @param string                         $param Query argument the dimension filters on.
	 * @param string                         $empty Empty-state sentence.
	 * @param string                         $scope What the reader is looking at.
	 */
	private static function render_rows( array $rows, string $param, string $empty, string $scope ): void {
		if ( ! $rows ) {
			echo VulnHub_Dash_Charts::empty_state( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				esc_html(
					self::ready()
						? $empty
						: __( 'The remediation classification is not available on this install, so there is nothing to split.', 'vulnhub' )
				)
			);
			return;
		}

		$classes    = self::classes();
		$bars       = array();
		$actionable = 0;
		$total      = 0;

		foreach ( $rows as $row ) {
			$counts   = (array) $row['counts'];
			$row_all  = array_sum( $counts );
			$row_act  = self::actionable( $counts );
			$segments = array();

			$total      += $row_all;
			$actionable += $row_act;

			foreach ( $classes as $key => $def ) {
				$n = (int) ( $counts[ $key ] ?? 0 );

				if ( $n < 1 ) {
					continue;
				}

				$segments[] = array(
					'label'  => (string) $def['label'],
					'value'  => $n,
					'colour' => (string) $def['colour'],
					'href'   => self::url( array( $param => (string) $row['key'] ), (string) $key ),
					'title'  => sprintf(
						/* translators: 1: count, 2: what the fix is, 3: the environment or platform. */
						__( '%1$s open findings on %3$s — %2$s', 'vulnhub' ),
						number_format_i18n( $n ),
						strtolower( (string) $def['label'] ),
						(string) $row['label']
					),
				);
			}

			$bars[] = array(
				'label'       => (string) $row['label'],
				'sub'         => sprintf(
					/* translators: %s: number of findings somebody can act on. */
					__( '%s can be acted on now', 'vulnhub' ),
					number_format_i18n( $row_act )
				),
				'segments'    => $segments,
				'total_href'  => self::url( array( $param => (string) $row['key'] ) ),
				'total_title' => sprintf(
					/* translators: 1: count, 2: the environment or platform. */
					__( 'All %1$s open findings on %2$s', 'vulnhub' ),
					number_format_i18n( $row_all ),
					(string) $row['label']
				),
			);
		}

		echo VulnHub_Dash_Charts::segment_bars( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			$bars,
			array(
				'unit' => __( 'findings', 'vulnhub' ),
				/*
				 * Per row, because the split is the point and the scale would
				 * otherwise be set by the one class nobody can act on. Linux
				 * carries ~219,000 unpatched distro advisories; on a shared
				 * scale every actionable segment in the widget renders as a
				 * sliver against it. The absolute total still sits at the end
				 * of each row, so nothing is hidden by the choice.
				 */
				'scale'  => 'row',
				'legend' => array_map(
					static fn( array $def ): array => array(
						'label'  => (string) $def['label'],
						'colour' => (string) $def['colour'],
					),
					array_values( $classes )
				),
			)
		);

		if ( $total > 0 ) {
			printf(
				'<p class="vh-w__note">%s</p>',
				esc_html(
					sprintf(
						/* translators: 1: actionable count, 2: total, 3: percentage, 4: what the reader is looking at. */
						__( '%1$s of %2$s open findings (%3$s%%) can be acted on without waiting for a vendor or a platform replacement. %4$s', 'vulnhub' ),
						number_format_i18n( $actionable ),
						number_format_i18n( $total ),
						number_format_i18n( round( ( $actionable / $total ) * 100, 1 ) ),
						$scope
					)
				)
			);
		}

		echo VulnHub_Dash_Charts::table_view( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			array_merge(
				array( 'platform' === $param ? __( 'Platform', 'vulnhub' ) : __( 'Environment', 'vulnhub' ) ),
				array_map( static fn( array $d ): string => (string) $d['label'], array_values( $classes ) ),
				array( __( 'Total', 'vulnhub' ) )
			),
			array_map(
				static function ( array $row ) use ( $classes ): array {
					$cells = array( (string) $row['label'] );

					foreach ( array_keys( $classes ) as $key ) {
						$cells[] = number_format_i18n( (int) ( $row['counts'][ $key ] ?? 0 ) );
					}

					$cells[] = number_format_i18n( array_sum( (array) $row['counts'] ) );

					return $cells;
				},
				$rows
			),
			__( 'Open findings on assets the dashboard reports on.', 'vulnhub' )
		);
	}

	/* =================================================================
	 * CSV
	 * ============================================================== */

	public static function data_environment(): array {
		return self::data_rows( self::by_environment(), __( 'Environment', 'vulnhub' ) );
	}

	public static function data_platform(): array {
		return self::data_rows( self::by_platform(), __( 'Platform', 'vulnhub' ) );
	}

	/**
	 * The figures behind the picture, for the widget's own CSV button.
	 *
	 * @param array<int,array<string,mixed>> $rows  Dimension rows.
	 * @param string                         $first Name of the first column.
	 * @return array{headers:array<int,string>,rows:array<int,array<int,string>>}
	 */
	private static function data_rows( array $rows, string $first ): array {
		$classes = self::classes();

		return array(
			'headers' => array_merge(
				array( $first ),
				array_map( static fn( array $d ): string => (string) $d['label'], array_values( $classes ) ),
				array( __( 'Actionable', 'vulnhub' ), __( 'Total', 'vulnhub' ) )
			),
			'rows'    => array_map(
				static function ( array $row ) use ( $classes ): array {
					$cells = array( (string) $row['label'] );

					foreach ( array_keys( $classes ) as $key ) {
						$cells[] = (string) (int) ( $row['counts'][ $key ] ?? 0 );
					}

					$cells[] = (string) self::actionable( (array) $row['counts'] );
					$cells[] = (string) array_sum( (array) $row['counts'] );

					return $cells;
				},
				$rows
			),
		);
	}
}
