<?php
/**
 * The remediation programme, drawn onto the end-of-life bars.
 *
 * "Past end of life" is a fact about an operating system. "Nobody is doing
 * anything about it" is a fact about the organisation, and it is the one that
 * decides whether a number on a dashboard is work or weather. The platforms
 * widget knows the first; this plugin knows the second, so it splits each bar
 * into the part a project has a date for and the part that has nobody.
 *
 * Red deliberately swallows two different situations -- a server whose planned
 * quarter has already passed, and one that was never planned at all. They are
 * different conversations to have, and the detail page separates them, but on
 * a bar they mean the same thing: the date on it is not going to save you.
 *
 * @package VulnHub\EOS
 */

declare( strict_types = 1 );

use VulnHub\Core\Eol;
use VulnHub\Core\Os;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Splits the end-of-life platform bars by remediation coverage.
 */
final class VH_EOS_Widget {

	/**
	 * Per-request memo of key => coverage tally, or null before it is built.
	 *
	 * @var array<string,array<string,int>>|null
	 */
	private static ?array $coverage = null;

	public static function init(): void {
		add_filter( 'vulnhub_eol_bar_segments', array( __CLASS__, 'segments' ), 10, 3 );
		add_filter( 'vulnhub_eol_bar_legend', array( __CLASS__, 'legend' ), 10, 2 );
		add_filter( 'vulnhub_eol_bar_total_href', array( __CLASS__, 'total_href' ), 10, 3 );
		add_filter( 'vulnhub_eol_headline_href', array( __CLASS__, 'headline_href' ), 10, 4 );
	}

	/**
	 * Is there a programme to draw at all?
	 *
	 * Both halves matter. The class check keeps this file harmless if it is
	 * ever loaded without the rest of the plugin; the data check means an
	 * install that has never imported a plan gets the widget exactly as it was
	 * rather than a bar claiming everything is uncovered, which would be a
	 * statement about the import rather than about the estate.
	 */
	private static function ready(): bool {
		return class_exists( 'VH_EOS_Repo' ) && VH_EOS_Repo::has_data();
	}

	/**
	 * Coverage tallies for every release in the estate, in two queries.
	 *
	 * The obvious implementation asks `Eol::asset_ids()` for each bar, but
	 * that method scans the asset table and re-matches every row against the
	 * lifecycle data *per key* -- twelve bars, twelve full passes over the
	 * estate, before the plan table is even consulted. It is written that way
	 * because the assets list only ever wants one key.
	 *
	 * So the grouping is done once here instead: one pass to put every asset
	 * under its release key, one query to fetch the plan rows for all of them.
	 * The key derivation is deliberately identical to `Eol::asset_ids()` --
	 * that method is the definition of record for "which assets are behind
	 * this bar", and the detail page reaches the same set through it, so the
	 * two must not drift. If it changes, this changes with it.
	 *
	 * @return array<string,array<string,int>> key => covered/overdue/uncovered.
	 */
	private static function coverage(): array {
		if ( null !== self::$coverage ) {
			return self::$coverage;
		}

		self::$coverage = array();

		if ( ! self::ready() ) {
			return self::$coverage;
		}

		global $wpdb;

		$assets = (array) $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			'SELECT id, operating_system, os_version, asset_type FROM ' . vh_table( 'assets' )
			. ' WHERE lifecycle_status IN (' . vh_reportable_sql() . ')', // phpcs:ignore WordPress.DB.PreparedSQL
			ARRAY_A
		);

		if ( ! $assets ) {
			return self::$coverage;
		}

		$by_key = array();

		foreach ( $assets as $asset ) {
			$matched = Eol::match_os( $asset );
			$key     = $matched
				? (string) $matched['key']
				: 'unknown:' . Os::parse( (string) $asset['operating_system'] )['family'];

			$by_key[ $key ][] = (int) $asset['id'];
		}

		$plans = VH_EOS_Repo::coverage_for_assets( array_map( 'intval', array_column( $assets, 'id' ) ) );

		foreach ( $by_key as $key => $ids ) {
			$tally = array( 'covered' => 0, 'overdue' => 0, 'uncovered' => 0 );

			foreach ( $ids as $id ) {
				/*
				 * No row is not an absence of information, it is the answer:
				 * a machine past end of life that the programme has never
				 * looked at is exactly what "not covered" means.
				 */
				$plan  = $plans[ $id ] ?? null;
				$state = is_array( $plan ) ? (string) ( $plan['coverage'] ?? '' ) : (string) $plan;

				if ( ! isset( $tally[ $state ] ) ) {
					$state = 'uncovered';
				}

				++$tally[ $state ];
			}

			self::$coverage[ $key ] = $tally;
		}

		return self::$coverage;
	}

	/**
	 * Replace a bar's single status band with covered / not covered.
	 *
	 * @param array<int,array<string,mixed>> $segments Default segments.
	 * @param array<string,mixed>            $row      Estate row.
	 * @param string                         $context  Bar set being drawn.
	 * @return array<int,array<string,mixed>>
	 */
	public static function segments( array $segments, array $row, string $context ): array {
		if ( 'platforms' !== $context ) {
			return $segments;
		}

		$key      = (string) ( $row['key'] ?? '' );
		$coverage = self::coverage();

		if ( '' === $key || ! isset( $coverage[ $key ] ) ) {
			return $segments;
		}

		$total = max( 0, (int) ( $row['assets'] ?? 0 ) );

		if ( ! $total ) {
			return $segments;
		}

		$tally   = $coverage[ $key ];
		$covered = min( (int) $tally['covered'], $total );
		$overdue = (int) $tally['overdue'];

		/*
		 * The remainder, not the tally, so the two bands always add up to the
		 * figure printed at the end of the row. The counts come from the same
		 * pass, so they agree today; they would stop agreeing the moment an
		 * asset changed hands between the two reads, and a bar that quietly
		 * disagrees with its own total is the kind of thing nobody reports
		 * and everybody stops trusting.
		 */
		$not_covered = max( 0, $total - $covered );

		$label   = (string) ( $row['label'] ?? '' );
		$release = (string) ( $row['release'] ?? '' );

		$out = array();

		if ( $covered > 0 ) {
			$out[] = array(
				'label'  => __( 'Covered by a plan', 'vulnhub' ),
				'value'  => $covered,
				'colour' => 'var(--vh-good)',
				'href'   => self::url( $key, 'covered' ),
				'title'  => sprintf(
					/* translators: 1: count, 2: product, 3: release. */
					_n(
						'%1$s asset on %2$s %3$s has a remediation project with a date still ahead of it',
						'%1$s assets on %2$s %3$s have a remediation project with a date still ahead of them',
						$covered,
						'vulnhub'
					),
					number_format_i18n( $covered ),
					$label,
					$release
				),
			);
		}

		if ( $not_covered > 0 ) {
			/*
			 * Overdue is named in the tooltip rather than given its own band.
			 * The user asked for two colours, and a server whose quarter has
			 * been and gone is not covered in any sense that helps -- but the
			 * number is the first thing somebody will ask about, so it has to
			 * be readable without opening the page.
			 */
			$title = $overdue > 0
				? sprintf(
					/* translators: 1: count, 2: product, 3: release, 4: number of those whose planned date has passed. */
					_n(
						'%1$s asset on %2$s %3$s has no plan with a date still ahead of it — including %4$s whose planned date has passed',
						'%1$s assets on %2$s %3$s have no plan with a date still ahead of them — including %4$s whose planned date has passed',
						$not_covered,
						'vulnhub'
					),
					number_format_i18n( $not_covered ),
					$label,
					$release,
					number_format_i18n( min( $overdue, $not_covered ) )
				)
				: sprintf(
					/* translators: 1: count, 2: product, 3: release. */
					_n(
						'%1$s asset on %2$s %3$s has no remediation plan',
						'%1$s assets on %2$s %3$s have no remediation plan',
						$not_covered,
						'vulnhub'
					),
					number_format_i18n( $not_covered ),
					$label,
					$release
				);

			$out[] = array(
				'label'  => __( 'Not covered', 'vulnhub' ),
				'value'  => $not_covered,
				'colour' => 'var(--vh-sev-critical)',
				// not_covered, not uncovered: this band counts the overdue with
				// the unplanned, and the page's `uncovered` is the strict
				// subset that excludes them. Linking to the strict value would
				// open a list shorter than the number printed on the band.
				'href'   => self::url( $key, 'not_covered' ),
				'title'  => $title,
			);
		}

		return $out ? $out : $segments;
	}

	/**
	 * Relabel the key under the bars to match what the colours now mean.
	 *
	 * @param array<int,array{label:string,colour:string}> $legend  Default legend.
	 * @param string                                       $context Bar set being drawn.
	 * @return array<int,array{label:string,colour:string}>
	 */
	public static function legend( array $legend, string $context ): array {
		if ( 'platforms' !== $context || ! self::ready() ) {
			return $legend;
		}

		return array(
			array(
				'label'  => __( 'Covered by a plan', 'vulnhub' ),
				'colour' => 'var(--vh-good)',
			),
			array(
				'label'  => __( 'Not covered, or the date has passed', 'vulnhub' ),
				'colour' => 'var(--vh-sev-critical)',
			),
		);
	}

	/**
	 * The plan page, filtered to one release and one side of the split.
	 */
	private static function url( string $key, string $coverage = '', string $eol = '' ): string {
		// The portal draws these bars, so it is normally present -- but the
		// widget can also be rendered by the Elementor panel widget on a page
		// served with the dashboard plugin disabled. An unlinked band is a
		// smaller failure than a fatal.
		if ( ! class_exists( 'VulnHub_Dash_Portal' ) ) {
			return '';
		}

		return VulnHub_Dash_Portal::portal_url(
			'eol_plan',
			array_filter(
				array(
					'key'      => $key,
					'coverage' => $coverage,
					'eol'      => $eol,
					'life'     => 'reportable',
				),
				static fn( string $v ): bool => '' !== $v
			)
		);
	}

	/**
	 * Where the number beside a bar goes: the same release, both halves.
	 *
	 * No `coverage`, deliberately. The two bands already answer "which of
	 * these are covered"; the total is the only control that answers "show me
	 * the whole release", and its row count matches the number printed because
	 * both come from the same release key.
	 *
	 * @param string              $href    Incoming value.
	 * @param array<string,mixed> $row     Estate row.
	 * @param string              $context Which bars are being drawn.
	 */
	public static function total_href( string $href, array $row, string $context ): string {
		if ( 'platforms' !== $context || ! self::ready() ) {
			return $href;
		}

		$key = (string) ( $row['key'] ?? '' );

		return '' !== $key ? self::url( $key ) : $href;
	}

	/**
	 * Where a headline tile goes.
	 *
	 * Only `past` and `soon`: this screen is about machines that need
	 * remediating, and it has nothing to say about a supported release or one
	 * the lifecycle table cannot identify -- linking those would promise an
	 * answer that is not there. The `eol` filter narrows the screen to the
	 * same population the tile counted, so the two numbers agree.
	 *
	 * @param string            $href    Incoming value.
	 * @param string            $key     past|soon|supported|unknown.
	 * @param array<string,int> $counts  Tile counts.
	 * @param string            $context Which tiles are being drawn.
	 */
	public static function headline_href( string $href, string $key, array $counts, string $context ): string {
		if ( 'platforms' !== $context || ! self::ready() ) {
			return $href;
		}

		if ( ! in_array( $key, array( 'past', 'soon' ), true ) ) {
			return $href;
		}

		/*
		 * A tile reading zero has nothing behind it, and a link to an empty
		 * list is a worse answer than the number already on the tile.
		 */
		if ( (int) ( $counts[ $key ] ?? 0 ) < 1 ) {
			return $href;
		}

		return self::url( '', '', $key );
	}
}

/*
 * Registered here rather than waiting to be called, so the split survives the
 * bootstrap being rearranged: add_filter() needs nothing from the platform, and
 * WordPress ignores a callback registered twice on the same hook, so an
 * explicit VH_EOS_Widget::init() from the plugin file is harmless either way.
 */
add_action( 'plugins_loaded', array( 'VH_EOS_Widget', 'init' ), 20 );
