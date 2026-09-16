<?php
/**
 * The EOL remediation plan screen.
 *
 * The end-of-life widget answers "how much of the estate has run out of
 * support". This screen answers the question that follows it, and the one the
 * programme actually exists to track: *is anybody doing something about it, and
 * by when*. Every server past end of support is either covered by a named
 * project with a date that has not passed, or it is not — and "not" includes
 * the quiet cases: a plan whose date went by, and a machine nobody has assessed
 * at all.
 *
 * The numbers here are programme data, not live scanner data. The Wave 1 spec
 * is explicit that the dashboard "reflects the data as of the last upload, not
 * real time", so the freshness line is the first thing on the page rather than
 * a footnote at the bottom.
 *
 * @package VulnHub\EOS
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;
use VulnHub\Core\Repo;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Portal view: EOL remediation plan.
 */
final class VH_EOS_View {

	public const VIEW = 'eol_plan';
	public const SLUG = 'eol-plan';

	/** Rows per page in the server table. */
	private const PER_PAGE = 50;

	/** Query-string key for the page number, unique to this screen. */
	private const PAGE_KEY = 'pp';

	/**
	 * Sortable columns, and the direction a first click should give.
	 *
	 * Deadline ascending by default: this screen is read in date order, and
	 * "what is due next" is the first question anybody asks of it.
	 */
	private const SORTABLE = array(
		'deadline' => 'ASC',
		'hostname' => 'ASC',
		'state'    => 'ASC',
		'rag'      => 'DESC',
		'tier'     => 'ASC',
		'project'  => 'ASC',
		'exposure' => 'DESC',
	);

	public static function init(): void {
		add_filter( 'vulnhub_dash_views', array( __CLASS__, 'register_view' ) );
		add_action( 'vulnhub_dash_render_view_' . self::VIEW, array( __CLASS__, 'render' ) );
		add_action( 'init', array( __CLASS__, 'ensure_page' ), 20 );
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'assets' ), 20 );
	}

	/* =================================================================
	 * Registration
	 * ============================================================== */

	/**
	 * Sits straight after Assets: the estate, then the plan for the part of it
	 * that has run out of support.
	 *
	 * @param array<string,array<string,mixed>> $views Existing views.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_view( array $views ): array {
		$out = array();

		foreach ( $views as $key => $def ) {
			$out[ $key ] = $def;

			if ( 'assets' === $key ) {
				$out[ self::VIEW ] = self::definition();
			}
		}

		// Assets is a core view and always present, but never assume: a view
		// that silently fails to register is a blank nav entry nobody can
		// debug from the outside.
		if ( ! isset( $out[ self::VIEW ] ) ) {
			$out[ self::VIEW ] = self::definition();
		}

		return $out;
	}

	/**
	 * @return array<string,mixed>
	 */
	private static function definition(): array {
		return array(
			'title' => __( 'EOL remediation plan', 'vulnhub' ),
			'slug'  => self::SLUG,
			'menu'  => __( 'EOL plan', 'vulnhub' ),
			// A calendar with a tick: dated work, and whether it is done.
			'icon'  => 'M4 6h16v14H4zM4 10h16M8 3v4M16 3v4M9 15l2 2 4-4',
		);
	}

	/**
	 * Create the page this view is served from, once.
	 *
	 * The dashboard's own activation hook created the core pages long before
	 * this plugin existed, so a contributed view has to make its own and map
	 * it into `vulnhub_dash_pages` (docs/CORE-API.md). Safe to re-run: it
	 * adopts an existing page with the same slug rather than making a second.
	 */
	public static function ensure_page(): void {
		$map = (array) get_option( 'vulnhub_dash_pages', array() );

		if ( ! empty( $map[ self::VIEW ] ) ) {
			$existing = get_post( (int) $map[ self::VIEW ] );

			if ( $existing && 'trash' !== $existing->post_status ) {
				return;
			}
		}

		$page = get_page_by_path( self::SLUG );

		if ( $page ) {
			$id = (int) $page->ID;
		} else {
			$id = wp_insert_post(
				array(
					'post_title'     => __( 'EOL remediation plan', 'vulnhub' ),
					'post_name'      => self::SLUG,
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

	/**
	 * This screen's URL, with filters applied.
	 *
	 * Public because the dashboard widget links into it: a green or red
	 * segment on the end-of-life bar is one click from exactly those servers.
	 *
	 * @param array<string,mixed> $args Query arguments.
	 */
	public static function url( array $args = array() ): string {
		return VulnHub_Dash_Portal::portal_url( self::VIEW, $args );
	}

	/**
	 * Page CSS, on this view only, versioned by the file's own mtime so a CDN
	 * cannot serve yesterday's stylesheet against today's markup.
	 */
	public static function assets(): void {
		if ( ! is_singular() || ! class_exists( 'VulnHub_Dash_App' ) ) {
			return;
		}

		if ( self::VIEW !== VulnHub_Dash_App::view_for_post( get_post() ) ) {
			return;
		}

		wp_enqueue_style(
			'vulnhub-eos',
			VULNHUB_EOS_URL . 'assets/eos.css',
			array( 'vulnhub-app' ),
			self::asset_ver( 'assets/eos.css' )
		);
	}

	/**
	 * Mirrors VulnHub_Dash_App::asset_ver() — deliberately this plugin's own
	 * copy, so disabling another plugin cannot take this one's versioning
	 * with it.
	 */
	private static function asset_ver( string $rel ): string {
		$mtime = @filemtime( VULNHUB_EOS_DIR . $rel ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		return $mtime ? VULNHUB_EOS_VERSION . '.' . $mtime : VULNHUB_EOS_VERSION;
	}

	/* =================================================================
	 * Query string
	 * ============================================================== */

	private static function q( string $key, string $default = '' ): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return isset( $_GET[ $key ] ) ? sanitize_text_field( wp_unslash( (string) $_GET[ $key ] ) ) : $default;
	}

	private static function qi( string $key, int $default = 0 ): int {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return isset( $_GET[ $key ] ) ? (int) $_GET[ $key ] : $default;
	}

	/**
	 * The filters this screen understands, read from the query string.
	 *
	 * `team` and `site` are this screen's names (the contract's), but the
	 * assets list spells the same two `team_id` and `location_id` — so a link
	 * arriving from there still filters rather than silently showing
	 * everything.
	 *
	 * @return array<string,string|int>
	 */
	public static function filters(): array {
		$team = self::qi( 'team', self::qi( 'team_id' ) );
		$site = self::q( 'site', self::q( 'location_id' ) );

		return array(
			'coverage'  => self::one_of( self::q( 'coverage' ), array_keys( self::coverage_filters() ) ),
			'state'     => self::one_of( self::q( 'state' ), array_keys( self::states() ) ),
			'timeframe' => self::q( 'timeframe' ),
			'tier'      => self::one_of( self::q( 'tier' ), array( 'critical', 'lower' ) ),
			'rag'       => self::one_of( self::q( 'rag' ), array( 'red', 'amber', 'green' ) ),
			'project'   => self::q( 'project' ),
			'key'       => self::q( 'key' ),
			'search'    => self::q( 'search' ),
			'team'      => $team,
			'site'      => $site,
			'life'      => self::q( 'life' ),
		);
	}

	/**
	 * @param string[] $allowed Allowed values.
	 */
	private static function one_of( string $value, array $allowed ): string {
		return in_array( $value, $allowed, true ) ? $value : '';
	}

	/**
	 * The screen's filters translated into the repository's argument names.
	 *
	 * @return array<string,mixed>
	 */
	public static function repo_args(): array {
		$f = self::filters();

		$orderby = self::q( 'orderby', 'deadline' );
		$orderby = array_key_exists( $orderby, self::SORTABLE ) ? $orderby : 'deadline';
		$order   = 'ASC' === strtoupper( self::q( 'order', self::SORTABLE[ $orderby ] ) ) ? 'ASC' : 'DESC';

		return array(
			'coverage'    => $f['coverage'],
			'state'       => $f['state'],
			'timeframe'   => $f['timeframe'],
			'env_tier'    => $f['tier'],
			'rag'         => $f['rag'],
			'project'     => $f['project'],
			'release_key' => $f['key'],
			'search'      => $f['search'],
			'team_id'     => (int) $f['team'],
			// The repository names this one after the column it filters.
			'location_id' => (int) $f['site'],
			'life'        => $f['life'],
			'orderby'     => $orderby,
			'order'       => $order,
		);
	}

	/**
	 * Non-empty filters only, for links that need to carry the current view.
	 *
	 * @return array<string,string|int>
	 */
	private static function active_filters(): array {
		return array_filter(
			self::filters(),
			static fn( $v ): bool => '' !== $v && 0 !== $v
		);
	}

	/**
	 * The filters plus the sort, for the export: a spreadsheet that arrives in
	 * a different order from the screen it was taken from looks like different
	 * data.
	 *
	 * @return array<string,string|int>
	 */
	private static function export_args(): array {
		$args = self::repo_args();

		return array_merge(
			self::active_filters(),
			array(
				'orderby' => (string) $args['orderby'],
				'order'   => (string) $args['order'],
			)
		);
	}

	/**
	 * The five programme states, in the spec's own order and wording.
	 *
	 * @return array<string,string>
	 */
	public static function states(): array {
		return array(
			'in_support'     => __( 'In support', 'vulnhub' ),
			'remediated'     => __( 'Remediated', 'vulnhub' ),
			'planned'        => __( 'Planned', 'vulnhub' ),
			'no_plan'        => __( 'No plan', 'vulnhub' ),
			'visibility_gap' => __( 'Visibility gap', 'vulnhub' ),
		);
	}

	/**
	 * The `coverage` values this screen accepts, and what each one asks for.
	 *
	 * Four, not three, and the reason is the dashboard bar. That bar is a
	 * green/red split, so its red band means "overdue *or* never planned" —
	 * one click, one filter. The page then offers the two halves separately,
	 * because "the plan slipped" and "there is no plan" are different
	 * conversations with different people.
	 *
	 *   not_covered = overdue + uncovered
	 *
	 * An empty or unrecognised value filters nothing.
	 *
	 * @return array<string,array{label:string,help:string}>
	 */
	public static function coverage_filters(): array {
		return array(
			'covered'     => array(
				'label' => __( 'Covered', 'vulnhub' ),
				'help'  => __( 'Remediated, or a named project with a date still ahead of it.', 'vulnhub' ),
			),
			'not_covered' => array(
				'label' => __( 'Not covered (overdue or no plan)', 'vulnhub' ),
				'help'  => __( 'Everything the red band on the dashboard counts.', 'vulnhub' ),
			),
			'overdue'     => array(
				'label' => __( 'Overdue only', 'vulnhub' ),
				'help'  => __( 'A plan exists, but its date has passed without the server being remediated.', 'vulnhub' ),
			),
			'uncovered'   => array(
				'label' => __( 'No plan only', 'vulnhub' ),
				'help'  => __( 'No plan, no date, a visibility gap, or a machine the programme has never assessed.', 'vulnhub' ),
			),
		);
	}

	/**
	 * The three coverage answers a row can actually be in, with the word each
	 * one carries on screen.
	 *
	 * These are display states, not filter values: a row is covered, overdue
	 * or uncovered, and `not_covered` is the pair of the last two asked for
	 * together.
	 *
	 * Colour never carries this on its own: every bar segment, pill and tile
	 * spells the state out.
	 *
	 * @return array<string,array{label:string,tone:string,colour:string,help:string}>
	 */
	public static function coverages(): array {
		return array(
			'covered'   => array(
				'label'  => __( 'Covered', 'vulnhub' ),
				'tone'   => 'good',
				'colour' => 'var(--vh-good)',
				'help'   => __( 'Remediated, or a named project with a date still ahead of it.', 'vulnhub' ),
			),
			'overdue'   => array(
				'label'  => __( 'Overdue', 'vulnhub' ),
				'tone'   => 'bad',
				'colour' => 'var(--vh-bad)',
				'help'   => __( 'A plan exists, but its date has passed without the server being remediated.', 'vulnhub' ),
			),
			'uncovered' => array(
				'label'  => __( 'Not covered', 'vulnhub' ),
				'tone'   => 'bad',
				'colour' => 'var(--vh-sev-critical)',
				'help'   => __( 'No plan, no date, a visibility gap, or a machine the programme has never assessed.', 'vulnhub' ),
			),
		);
	}

	/* =================================================================
	 * Render
	 * ============================================================== */

	public static function render(): void {
		if ( ! is_user_logged_in() || ! current_user_can( Caps::VIEW ) ) {
			return;
		}

		if ( ! class_exists( 'VH_EOS_Repo' ) || ! VH_EOS_Repo::has_data() ) {
			self::render_empty();
			return;
		}

		$args    = self::repo_args();
		$summary = (array) VH_EOS_Repo::summary( $args );
		$page    = max( 1, self::qi( self::PAGE_KEY, 1 ) );

		$result = (array) VH_EOS_Repo::rows(
			array_merge(
				$args,
				array(
					'limit'  => self::PER_PAGE,
					'offset' => ( $page - 1 ) * self::PER_PAGE,
				)
			)
		);

		$rows  = (array) ( $result['rows'] ?? array() );
		$total = (int) ( $result['total'] ?? 0 );
		$pages = (int) max( 1, (int) ceil( $total / self::PER_PAGE ) );

		self::head( $summary, $total );
		self::tiles( $summary );
		self::workload( $summary, $args );
		self::form();
		self::chips();
		self::table( $rows, $total, $args );
		self::pager( $page, $pages );
	}

	/**
	 * Nothing imported yet. Say what the screen is for and where the data
	 * comes from, rather than an empty table nobody can act on.
	 */
	private static function render_empty(): void {
		?>
		<div class="vh-page-head">
			<div>
				<h1><?php esc_html_e( 'EOL remediation plan', 'vulnhub' ); ?></h1>
				<p class="vh-sub"><?php esc_html_e( 'Which end-of-support servers are covered by a project and a date, and which are not.', 'vulnhub' ); ?></p>
			</div>
		</div>
		<div class="vh-card vh-eos__empty">
			<?php echo VulnHub_Dash_Charts::empty_state( __( 'No programme data has been imported yet.', 'vulnhub' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			<p class="vh-sub">
				<?php esc_html_e( 'This screen reads the End-of-Support Server Retirement Programme reconciliation sheet: one row per server, with its treatment plan, timeframe and status. Import it, and every end-of-life bar on the dashboard splits into covered and not covered.', 'vulnhub' ); ?>
			</p>
			<?php if ( current_user_can( Caps::MANAGE ) ) : ?>
				<p>
					<a class="vh-btn vh-btn--primary vh-btn--sm" href="<?php echo esc_url( VulnHub_Dash_Portal::portal_url( 'admin', array( 'section' => VH_EOS_Admin::SECTION ) ) ); ?>">
						<?php esc_html_e( 'Import programme data', 'vulnhub' ); ?>
					</a>
				</p>
			<?php else : ?>
				<p class="vh-meta"><?php esc_html_e( 'A VulnHub administrator can import it under Administration → Data.', 'vulnhub' ); ?></p>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Title, the freshness statement, and the export.
	 *
	 * @param array<string,mixed> $summary Summary figures.
	 * @param int                 $total   Rows matching the current filters.
	 */
	private static function head( array $summary, int $total ): void {
		// The repository hands back the whole import report, not a bare date:
		// when it ran, what it read, and how many hostnames found no asset.
		$report    = (array) ( $summary['last_import'] ?? array() );
		$last      = (string) ( $report['at'] ?? '' );
		$unmatched = is_array( $report['unmatched'] ?? null ) ? count( (array) $report['unmatched'] ) : 0;
		?>
		<div class="vh-page-head">
			<div>
				<h1><?php esc_html_e( 'EOL remediation plan', 'vulnhub' ); ?></h1>
				<p class="vh-sub">
					<?php
					printf(
						/* translators: %s: number of servers. */
						esc_html( _n( '%s server in the end-of-support programme, with what is planned for it and by when.', '%s servers in the end-of-support programme, with what is planned for each and by when.', $total, 'vulnhub' ) ),
						'<strong>' . esc_html( number_format_i18n( $total ) ) . '</strong>'
					);
					?>
				</p>
				<p class="vh-eos__fresh vh-meta">
					<?php
					if ( '' !== $last ) {
						printf(
							/* translators: 1: absolute date and time, 2: relative time such as "3 days ago". */
							esc_html__( 'Programme data as imported %1$s (%2$s) — not live scanner data. Coverage is only as current as the last upload.', 'vulnhub' ),
							esc_html( vh_date( $last ) ),
							esc_html( vh_ago( $last ) )
						);
					} else {
						esc_html_e( 'Programme data from the last import — not live scanner data.', 'vulnhub' );
					}

					if ( $unmatched > 0 ) {
						echo ' ';
						printf(
							/* translators: %s: a count of hostnames. */
							esc_html( _n( '%s hostname in the sheet has no matching asset in the inventory.', '%s hostnames in the sheet have no matching asset in the inventory.', $unmatched, 'vulnhub' ) ),
							esc_html( number_format_i18n( $unmatched ) )
						);
					}
					?>
				</p>
			</div>
			<div class="vh-page-head__actions">
				<?php VH_EOS_Export::button( $total, self::export_args() ); ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Covered / overdue / not covered, each a link that applies that filter.
	 *
	 * @param array<string,mixed> $summary Summary figures.
	 */
	private static function tiles( array $summary ): void {
		$defs    = self::coverages();
		$current = self::q( 'coverage' );
		$counts  = array(
			'covered'   => (int) ( $summary['covered'] ?? 0 ),
			'overdue'   => (int) ( $summary['overdue'] ?? 0 ),
			'uncovered' => (int) ( $summary['uncovered'] ?? 0 ),
		);
		$total   = array_sum( $counts );

		$base = self::active_filters();
		unset( $base['coverage'] );

		echo '<div class="vh-grid vh-grid--4 vh-eos__tiles">';

		echo VulnHub_Dash_Charts::stat_tile( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			array(
				'label' => __( 'In the programme', 'vulnhub' ),
				'value' => $total,
				'tone'  => 'neutral',
				'meta'  => __( 'Servers past end of support, or assessed as part of it', 'vulnhub' ),
				'href'  => self::url( $base ),
			)
		);

		foreach ( $defs as $key => $def ) {
			echo VulnHub_Dash_Charts::stat_tile( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				array(
					'label' => (string) $def['label'],
					'value' => $counts[ $key ],
					'tone'  => 'good' === $def['tone'] ? 'good' : ( 'overdue' === $key ? 'warning' : 'critical' ),
					'meta'  => (string) $def['help'],
					'href'  => self::url( $key === $current ? $base : array_merge( $base, array( 'coverage' => $key ) ) ),
				)
			);
		}

		echo '</div>';

		/*
		 * Arriving from the dashboard's red band asks for both halves at once,
		 * and neither tile above is lit in that state. Say so, and offer the
		 * two halves as the next click.
		 */
		if ( 'not_covered' === $current ) {
			printf(
				'<p class="vh-eos__combined vh-meta">%s <a href="%s">%s</a> · <a href="%s">%s</a></p>',
				esc_html__( 'Showing everything the dashboard counts as not covered — overdue plans and servers with no plan at all.', 'vulnhub' ),
				esc_url( self::url( array_merge( $base, array( 'coverage' => 'overdue' ) ) ) ),
				esc_html__( 'Overdue only', 'vulnhub' ),
				esc_url( self::url( array_merge( $base, array( 'coverage' => 'uncovered' ) ) ) ),
				esc_html__( 'No plan only', 'vulnhub' )
			);
		}
	}

	/**
	 * Forward workload: what still needs doing, by the quarter it is due in.
	 *
	 * The programme's own dashboard leads with this, and it is the one view
	 * that turns a list of overdue servers into a capacity question.
	 *
	 * @param array<string,mixed> $summary Summary figures.
	 */
	private static function workload( array $summary, array $args ): void {
		$quarters = self::quarter_split( $summary, $args );

		if ( ! $quarters ) {
			return;
		}

		$defs  = self::coverages();
		$base  = self::active_filters();
		unset( $base['timeframe'], $base['coverage'] );

		$bars  = array();
		$table = array();

		foreach ( $quarters as $label => $split ) {
			if ( array_sum( $split ) <= 0 ) {
				continue;
			}

			$segments = array();

			foreach ( array( 'covered', 'overdue', 'uncovered' ) as $key ) {
				if ( $split[ $key ] <= 0 ) {
					continue;
				}

				$segments[] = array(
					'label'  => (string) $defs[ $key ]['label'],
					'value'  => $split[ $key ],
					'colour' => (string) $defs[ $key ]['colour'],
					'href'   => self::url( array_merge( $base, array( 'timeframe' => (string) $label, 'coverage' => $key ) ) ),
					'title'  => sprintf(
						/* translators: 1: count, 2: coverage state, 3: timeframe such as "FY27 Q1". */
						__( '%1$s servers — %2$s — due %3$s', 'vulnhub' ),
						number_format_i18n( $split[ $key ] ),
						strtolower( (string) $defs[ $key ]['label'] ),
						(string) $label
					),
				);
			}

			$bars[] = array(
				'label'    => (string) $label,
				'href'     => self::url( array_merge( $base, array( 'timeframe' => (string) $label ) ) ),
				'segments' => $segments,
			);

			$table[] = array(
				(string) $label,
				number_format_i18n( $split['covered'] ),
				number_format_i18n( $split['overdue'] ),
				number_format_i18n( $split['uncovered'] ),
				number_format_i18n( array_sum( $split ) ),
			);
		}

		if ( ! $bars ) {
			return;
		}
		?>
		<div class="vh-card vh-eos__workload">
			<div class="vh-panel__head">
				<h2><?php esc_html_e( 'Forward workload — servers still requiring action, by quarter', 'vulnhub' ); ?></h2>
				<p class="vh-sub">
					<?php esc_html_e( 'Green is covered: remediated, or a project whose date is still ahead. Red is not: the date has passed, or there is no dated plan at all. Select any part of a bar for those servers.', 'vulnhub' ); ?>
				</p>
			</div>
			<?php
			echo VulnHub_Dash_Charts::segment_bars( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				$bars,
				array(
					'unit'   => __( 'servers', 'vulnhub' ),
					'scale'  => 'shared',
					'legend' => array(
						array( 'label' => __( 'Covered', 'vulnhub' ), 'colour' => 'var(--vh-good)' ),
						array( 'label' => __( 'Overdue', 'vulnhub' ), 'colour' => 'var(--vh-bad)' ),
						array( 'label' => __( 'Not covered', 'vulnhub' ), 'colour' => 'var(--vh-sev-critical)' ),
					),
				)
			);

			echo VulnHub_Dash_Charts::table_view( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				array(
					__( 'Timeframe', 'vulnhub' ),
					__( 'Covered', 'vulnhub' ),
					__( 'Overdue', 'vulnhub' ),
					__( 'Not covered', 'vulnhub' ),
					__( 'Total', 'vulnhub' ),
				),
				$table,
				__( 'Servers requiring action, by the timeframe their plan gives them.', 'vulnhub' )
			);
			?>
			<p class="vh-meta vh-eos__fynote">
				<?php esc_html_e( 'Quarters follow a financial year starting 1 April, and "overdue" is measured against the last day of the quarter named. The programme has this listed as an open item — if Acme\'s fiscal calendar differs, the overdue split moves with it.', 'vulnhub' ); ?>
			</p>
		</div>
		<?php
	}

	/**
	 * Each quarter split into covered / overdue / not covered.
	 *
	 * The repository's summary counts servers per quarter but not the split
	 * inside each one, and the split is the entire point of the chart: a
	 * quarter that has gone by is not the same workload as one still ahead.
	 * So the rows are read once, unpaged, and bucketed here. This dataset is
	 * the programme's own list — low hundreds of servers — so one extra pass
	 * costs nothing and keeps the chart exact rather than inferred.
	 *
	 * @param array<string,mixed> $summary Summary figures (for the ordering).
	 * @param array<string,mixed> $args    Repository arguments in force.
	 * @return array<string,array{covered:int,overdue:int,uncovered:int}>
	 */
	private static function quarter_split( array $summary, array $args ): array {
		$order = array_keys( (array) ( $summary['by_quarter'] ?? array() ) );

		if ( ! $order ) {
			return array();
		}

		$result = (array) VH_EOS_Repo::rows(
			array_merge( $args, array( 'limit' => 0, 'offset' => 0 ) )
		);

		$empty = array(
			'covered'   => 0,
			'overdue'   => 0,
			'uncovered' => 0,
		);
		$out   = array();

		foreach ( $order as $label ) {
			$out[ (string) $label ] = $empty;
		}

		foreach ( (array) ( $result['rows'] ?? array() ) as $row ) {
			$quarter  = (string) ( $row['quarter'] ?? '' );
			$coverage = (string) ( $row['coverage'] ?? 'uncovered' );

			if ( '' === $quarter || ! isset( $empty[ $coverage ] ) ) {
				continue;
			}

			if ( ! isset( $out[ $quarter ] ) ) {
				$out[ $quarter ] = $empty;
			}

			++$out[ $quarter ][ $coverage ];
		}

		return $out;
	}

	/**
	 * The filter form. Same markup and the same hidden-field discipline as the
	 * portal's other lists, so a filter with no control of its own survives
	 * Apply instead of being dropped.
	 */
	private static function form(): void {
		$f = self::filters();
		?>
		<form class="vh-filters" method="get">
			<?php
			self::hidden_filters(
				array( 'coverage', 'state', 'timeframe', 'tier', 'rag', 'project', 'search', 'team', 'team_id', 'site', 'location_id', 'life' )
			);
			?>
			<label><?php esc_html_e( 'Search', 'vulnhub' ); ?>
				<input type="search" name="search" value="<?php echo esc_attr( (string) $f['search'] ); ?>" placeholder="<?php esc_attr_e( 'hostname, project, purpose…', 'vulnhub' ); ?>">
			</label>

			<label><?php esc_html_e( 'Coverage', 'vulnhub' ); ?>
				<select name="coverage">
					<option value=""><?php esc_html_e( 'Covered and not', 'vulnhub' ); ?></option>
					<?php foreach ( self::coverage_filters() as $vh_k => $vh_def ) : ?>
						<option value="<?php echo esc_attr( (string) $vh_k ); ?>" <?php selected( (string) $f['coverage'], (string) $vh_k ); ?>>
							<?php echo esc_html( (string) $vh_def['label'] ); ?>
						</option>
					<?php endforeach; ?>
				</select>
			</label>

			<label><?php esc_html_e( 'Programme state', 'vulnhub' ); ?>
				<select name="state">
					<option value=""><?php esc_html_e( 'Any state', 'vulnhub' ); ?></option>
					<?php foreach ( self::states() as $vh_k => $vh_label ) : ?>
						<option value="<?php echo esc_attr( (string) $vh_k ); ?>" <?php selected( (string) $f['state'], (string) $vh_k ); ?>>
							<?php echo esc_html( (string) $vh_label ); ?>
						</option>
					<?php endforeach; ?>
				</select>
			</label>

			<label><?php esc_html_e( 'Timeframe', 'vulnhub' ); ?>
				<select name="timeframe">
					<option value=""><?php esc_html_e( 'Any timeframe', 'vulnhub' ); ?></option>
					<?php foreach ( self::timeframes() as $vh_tf ) : ?>
						<option value="<?php echo esc_attr( (string) $vh_tf ); ?>" <?php selected( (string) $f['timeframe'], (string) $vh_tf ); ?>>
							<?php echo esc_html( (string) $vh_tf ); ?>
						</option>
					<?php endforeach; ?>
				</select>
			</label>

			<label><?php esc_html_e( 'Environment', 'vulnhub' ); ?>
				<select name="tier">
					<option value=""><?php esc_html_e( 'Any environment', 'vulnhub' ); ?></option>
					<option value="critical" <?php selected( (string) $f['tier'], 'critical' ); ?>><?php esc_html_e( 'Critical (prod / preprod)', 'vulnhub' ); ?></option>
					<option value="lower" <?php selected( (string) $f['tier'], 'lower' ); ?>><?php esc_html_e( 'Lower (test / dev / DR)', 'vulnhub' ); ?></option>
				</select>
			</label>

			<label><?php esc_html_e( 'RAG', 'vulnhub' ); ?>
				<select name="rag">
					<option value=""><?php esc_html_e( 'Any rating', 'vulnhub' ); ?></option>
					<option value="red" <?php selected( (string) $f['rag'], 'red' ); ?>><?php esc_html_e( 'Red', 'vulnhub' ); ?></option>
					<option value="amber" <?php selected( (string) $f['rag'], 'amber' ); ?>><?php esc_html_e( 'Amber', 'vulnhub' ); ?></option>
					<option value="green" <?php selected( (string) $f['rag'], 'green' ); ?>><?php esc_html_e( 'Green', 'vulnhub' ); ?></option>
				</select>
			</label>

			<label><?php esc_html_e( 'Project', 'vulnhub' ); ?>
				<select name="project">
					<option value=""><?php esc_html_e( 'Any project', 'vulnhub' ); ?></option>
					<?php foreach ( self::projects() as $vh_p ) : ?>
						<option value="<?php echo esc_attr( (string) $vh_p ); ?>" <?php selected( (string) $f['project'], (string) $vh_p ); ?>>
							<?php echo esc_html( vh_trim( (string) $vh_p, 48 ) ); ?>
						</option>
					<?php endforeach; ?>
				</select>
			</label>

			<label><?php esc_html_e( 'Team', 'vulnhub' ); ?>
				<select name="team">
					<option value="0"><?php esc_html_e( 'All teams', 'vulnhub' ); ?></option>
					<?php foreach ( Repo::teams() as $vh_t ) : ?>
						<option value="<?php echo esc_attr( (string) $vh_t['id'] ); ?>" <?php selected( (int) $f['team'], (int) $vh_t['id'] ); ?>>
							<?php echo esc_html( (string) $vh_t['name'] ); ?>
						</option>
					<?php endforeach; ?>
				</select>
			</label>

			<?php
			/*
			 * No "No site recorded" option here, unlike the assets list: the
			 * repository filters this by location id, so there is no value
			 * that means "none" — and a control that silently does nothing is
			 * worse than one that is absent.
			 */
			?>
			<label><?php esc_html_e( 'Site', 'vulnhub' ); ?>
				<select name="site">
					<option value=""><?php esc_html_e( 'All sites', 'vulnhub' ); ?></option>
					<?php foreach ( Repo::locations() as $vh_loc ) : ?>
						<option value="<?php echo esc_attr( (string) $vh_loc['id'] ); ?>" <?php selected( (string) $f['site'], (string) $vh_loc['id'] ); ?>>
							<?php echo esc_html( (string) $vh_loc['name'] ); ?>
						</option>
					<?php endforeach; ?>
				</select>
			</label>

			<button class="vh-btn vh-btn--primary" type="submit"><?php esc_html_e( 'Apply', 'vulnhub' ); ?></button>
			<a class="vh-btn vh-btn--ghost" href="<?php echo esc_url( self::url() ); ?>"><?php esc_html_e( 'Reset', 'vulnhub' ); ?></a>
		</form>
		<?php
	}

	/**
	 * Carry every other query parameter through the form, so a filter this
	 * screen has no control for — the release key a dashboard bar arrives
	 * with, for one — is not thrown away by pressing Apply.
	 *
	 * @param string[] $own Parameters the form posts itself.
	 */
	private static function hidden_filters( array $own ): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$get  = is_array( $_GET ) ? wp_unslash( $_GET ) : array();
		// orderby/order deliberately ride along: applying a filter should not
		// silently re-sort the table under the reader. The page number does
		// not — a new filter starts at page one.
		$skip = array_merge( $own, array( 'page_id', self::PAGE_KEY, 'paged' ) );

		foreach ( $get as $key => $value ) {
			if ( is_array( $value ) || in_array( (string) $key, $skip, true ) ) {
				continue;
			}

			$name = sanitize_key( (string) $key );

			if ( '' === $name ) {
				continue;
			}

			printf(
				'<input type="hidden" name="%s" value="%s">',
				esc_attr( $name ),
				esc_attr( sanitize_text_field( (string) $value ) )
			);
		}
	}

	/**
	 * A removable chip for each filter that has no control of its own, so
	 * arriving from a dashboard bar says what it filtered to and how to undo.
	 */
	private static function chips(): void {
		$f     = self::filters();
		$chips = array();

		if ( '' !== (string) $f['key'] ) {
			$chips['key'] = sprintf(
				/* translators: %s: an operating-system release, e.g. "RHEL 6". */
				__( 'Release: %s', 'vulnhub' ),
				self::release_label( (string) $f['key'] )
			);
		}

		if ( '' !== (string) $f['life'] ) {
			$chips['life'] = sprintf(
				/* translators: %s: a lifecycle scope name. */
				__( 'Lifecycle: %s', 'vulnhub' ),
				(string) $f['life']
			);
		}

		if ( ! $chips ) {
			return;
		}

		echo '<div class="vh-chips">';

		foreach ( $chips as $key => $label ) {
			$rest = self::active_filters();
			unset( $rest[ $key ] );

			printf(
				'<a class="vh-chip vh-chip--filter" href="%s">%s <span aria-hidden="true">&times;</span><span class="vh-eos__sr">%s</span></a>',
				esc_url( self::url( $rest ) ),
				esc_html( $label ),
				esc_html__( 'Remove this filter', 'vulnhub' )
			);
		}

		echo '</div>';
	}

	/**
	 * The human name for an end-of-life release key, asked of the widget that
	 * owns those keys rather than re-derived here.
	 */
	private static function release_label( string $key ): string {
		if ( class_exists( 'VH_EOS_Widget' ) && method_exists( 'VH_EOS_Widget', 'release_label' ) ) {
			$label = (string) VH_EOS_Widget::release_label( $key );

			if ( '' !== $label ) {
				return $label;
			}
		}

		return $key;
	}

	/* =================================================================
	 * The table
	 * ============================================================== */

	/**
	 * @param array<int,array<string,mixed>> $rows  Plan rows.
	 * @param int                            $total Total matching rows.
	 * @param array<string,mixed>            $args  Repository arguments in force.
	 */
	private static function table( array $rows, int $total, array $args ): void {
		if ( ! $rows ) {
			echo '<div class="vh-card">';
			echo VulnHub_Dash_Charts::empty_state( __( 'No server matches these filters.', 'vulnhub' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo '</div>';
			return;
		}

		$orderby = (string) ( $args['orderby'] ?? 'deadline' );
		$order   = (string) ( $args['order'] ?? 'ASC' );
		?>
		<div class="vh-card vh-eos__list">
			<div class="vh-tablewrap vh-tablewrap--cards">
				<table class="vh-table vh-eos__table">
					<thead>
						<tr>
							<?php
							self::sort_th( 'hostname', __( 'Server', 'vulnhub' ), $orderby, $order );
							?>
							<th scope="col"><?php esc_html_e( 'Operating system', 'vulnhub' ); ?></th>
							<?php
							self::sort_th( 'tier', __( 'Environment', 'vulnhub' ), $orderby, $order );
							self::sort_th( 'project', __( 'Treatment plan', 'vulnhub' ), $orderby, $order );
							self::sort_th( 'deadline', __( 'Timeframe', 'vulnhub' ), $orderby, $order );
							self::sort_th( 'state', __( 'Status', 'vulnhub' ), $orderby, $order );
							self::sort_th( 'rag', __( 'RAG', 'vulnhub' ), $orderby, $order );
							?>
							<th scope="col"><?php esc_html_e( 'Owner team', 'vulnhub' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Site', 'vulnhub' ); ?></th>
							<?php self::sort_th( 'exposure', __( 'Open critical / high', 'vulnhub' ), $orderby, $order ); ?>
							<th scope="col"><?php esc_html_e( 'Last scan', 'vulnhub' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $rows as $row ) : ?>
							<?php self::row( $row ); ?>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
			<p class="vh-meta vh-eos__count">
				<?php
				printf(
					/* translators: 1: rows shown, 2: total rows. */
					esc_html__( 'Showing %1$s of %2$s servers.', 'vulnhub' ),
					esc_html( number_format_i18n( count( $rows ) ) ),
					esc_html( number_format_i18n( $total ) )
				);
				?>
			</p>
		</div>
		<?php
	}

	/**
	 * One server.
	 *
	 * @param array<string,mixed> $row Plan row joined to its asset.
	 */
	private static function row( array $row ): void {
		$coverages = self::coverages();
		$coverage  = (string) ( $row['coverage'] ?? 'uncovered' );
		$cov       = $coverages[ $coverage ] ?? $coverages['uncovered'];
		$asset_id  = (int) ( $row['asset_id'] ?? 0 );
		$hostname  = (string) ( $row['hostname'] ?? '' );
		$states    = self::states();
		$state     = (string) ( $row['state'] ?? '' );
		$rag       = (string) ( $row['rag'] ?? '' );
		$timeframe = (string) ( $row['timeframe'] ?? '' );
		$deadline  = (string) ( $row['deadline'] ?? '' );
		$crit      = (int) ( $row['open_critical'] ?? 0 );
		$high      = (int) ( $row['open_high'] ?? 0 );
		?>
		<tr class="vh-eos__row vh-eos__row--<?php echo esc_attr( $coverage ); ?>">
			<td data-th="<?php esc_attr_e( 'Server', 'vulnhub' ); ?>">
				<?php if ( $asset_id > 0 ) : ?>
					<a class="vh-mono" href="<?php echo esc_url( VulnHub_Dash_Portal::portal_url( 'assets', array( 'asset' => $asset_id ) ) ); ?>">
						<?php echo esc_html( $hostname ); ?>
					</a>
				<?php else : ?>
					<span class="vh-mono"><?php echo esc_html( $hostname ); ?></span>
					<span class="vh-chip vh-chip--warn" title="<?php esc_attr_e( 'In the programme sheet, but no matching asset in the inventory — so nothing here is checked against a scan.', 'vulnhub' ); ?>">
						<?php esc_html_e( 'Not in inventory', 'vulnhub' ); ?>
					</span>
				<?php endif; ?>
				<?php if ( ! empty( $row['purpose'] ) ) : ?>
					<span class="vh-meta"><?php echo esc_html( vh_trim( (string) $row['purpose'], 46 ) ); ?></span>
				<?php endif; ?>
			</td>

			<td data-th="<?php esc_attr_e( 'Operating system', 'vulnhub' ); ?>">
				<?php
				// The inventory's own reading first, the programme sheet's
				// second: where they disagree, the scanner is the one that
				// looked at the machine.
				$os = (string) ( $row['operating_system'] ?? '' );
				$os = '' !== $os ? $os : (string) ( $row['os_text'] ?? '' );
				echo esc_html( '' !== $os ? $os : '—' );
				?>
				<?php if ( ! empty( $row['os_version'] ) ) : ?>
					<span class="vh-meta"><?php echo esc_html( (string) $row['os_version'] ); ?></span>
				<?php endif; ?>
			</td>

			<td data-th="<?php esc_attr_e( 'Environment', 'vulnhub' ); ?>">
				<?php echo esc_html( (string) ( $row['environment'] ?? '—' ) ); ?>
				<?php if ( 'critical' === (string) ( $row['env_tier'] ?? '' ) ) : ?>
					<span class="vh-chip vh-chip--bad"><?php esc_html_e( 'Critical', 'vulnhub' ); ?></span>
				<?php elseif ( 'lower' === (string) ( $row['env_tier'] ?? '' ) ) : ?>
					<span class="vh-chip"><?php esc_html_e( 'Lower', 'vulnhub' ); ?></span>
				<?php endif; ?>
			</td>

			<td data-th="<?php esc_attr_e( 'Treatment plan', 'vulnhub' ); ?>">
				<?php if ( ! empty( $row['project'] ) ) : ?>
					<?php echo esc_html( vh_trim( (string) $row['project'], 52 ) ); ?>
				<?php else : ?>
					<span class="vh-chip vh-chip--bad"><?php esc_html_e( 'No project', 'vulnhub' ); ?></span>
				<?php endif; ?>
			</td>

			<td data-th="<?php esc_attr_e( 'Timeframe', 'vulnhub' ); ?>">
				<?php if ( '' !== $timeframe ) : ?>
					<span class="vh-eos__tf"><?php echo esc_html( $timeframe ); ?></span>
				<?php else : ?>
					<span class="vh-meta"><?php esc_html_e( 'None set', 'vulnhub' ); ?></span>
				<?php endif; ?>
				<?php if ( 'overdue' === $coverage ) : ?>
					<span class="vh-chip vh-chip--bad" title="<?php echo esc_attr( '' !== $deadline ? sprintf( /* translators: %s: a date. */ __( 'Due %s and not yet remediated.', 'vulnhub' ), vh_date_only( $deadline, 'j M Y' ) ) : __( 'The date has passed and the server is not yet remediated.', 'vulnhub' ) ); ?>">
						<?php esc_html_e( 'Overdue', 'vulnhub' ); ?>
					</span>
				<?php elseif ( '' !== $deadline ) : ?>
					<span class="vh-meta"><?php echo esc_html( vh_date_only( $deadline, 'j M Y' ) ); ?></span>
				<?php endif; ?>
			</td>

			<td data-th="<?php esc_attr_e( 'Status', 'vulnhub' ); ?>">
				<span class="vh-pill vh-eos__cov vh-eos__cov--<?php echo esc_attr( $coverage ); ?>">
					<?php echo esc_html( (string) $cov['label'] ); ?>
				</span>
				<?php if ( isset( $states[ $state ] ) ) : ?>
					<span class="vh-meta"><?php echo esc_html( (string) $states[ $state ] ); ?></span>
				<?php endif; ?>
			</td>

			<td data-th="<?php esc_attr_e( 'RAG', 'vulnhub' ); ?>">
				<?php if ( in_array( $rag, array( 'red', 'amber', 'green' ), true ) ) : ?>
					<span class="vh-pill vh-eos__rag vh-eos__rag--<?php echo esc_attr( $rag ); ?>">
						<?php echo esc_html( ucfirst( $rag ) ); ?>
					</span>
				<?php else : ?>
					<span class="vh-meta">—</span>
				<?php endif; ?>
			</td>

			<td data-th="<?php esc_attr_e( 'Owner team', 'vulnhub' ); ?>">
				<?php echo esc_html( (string) ( $row['team_name'] ?? '' ) ?: '—' ); ?>
			</td>

			<td data-th="<?php esc_attr_e( 'Site', 'vulnhub' ); ?>">
				<?php echo esc_html( (string) ( $row['site_name'] ?? $row['location_name'] ?? '' ) ?: '—' ); ?>
			</td>

			<td data-th="<?php esc_attr_e( 'Open critical / high', 'vulnhub' ); ?>">
				<?php if ( $asset_id <= 0 ) : ?>
					<span class="vh-meta"><?php esc_html_e( 'Not scanned here', 'vulnhub' ); ?></span>
				<?php elseif ( $crit > 0 || $high > 0 ) : ?>
					<a href="<?php echo esc_url( VulnHub_Dash_Portal::portal_url( 'vulnerabilities', array( 'asset' => $asset_id, 'state' => 'open_any' ) ) ); ?>">
						<span class="vh-num vh-eos__crit"><?php echo esc_html( number_format_i18n( $crit ) ); ?></span>
						<span class="vh-meta">/</span>
						<span class="vh-num vh-eos__high"><?php echo esc_html( number_format_i18n( $high ) ); ?></span>
					</a>
				<?php else : ?>
					<span class="vh-meta"><?php esc_html_e( 'clean', 'vulnhub' ); ?></span>
				<?php endif; ?>
			</td>

			<td data-th="<?php esc_attr_e( 'Last scan', 'vulnhub' ); ?>">
				<?php
				$scan = (string) ( $row['tenable_last_scan'] ?? $row['last_scan'] ?? '' );
				echo esc_html( '' !== $scan ? vh_ago( $scan ) : '—' );
				?>
			</td>
		</tr>
		<?php
	}

	/**
	 * A sortable header: toggles direction, and tells a screen reader which
	 * way the table is ordered. Filters ride along; the page number does not.
	 */
	private static function sort_th( string $key, string $label, string $orderby, string $order ): void {
		$active = $orderby === $key;
		$next   = $active
			? ( 'ASC' === $order ? 'DESC' : 'ASC' )
			: ( self::SORTABLE[ $key ] ?? 'ASC' );

		$params = array_merge(
			self::active_filters(),
			array(
				'orderby' => $key,
				'order'   => $next,
			)
		);

		$aria = $active ? ( 'ASC' === $order ? 'ascending' : 'descending' ) : 'none';

		printf(
			'<th scope="col" aria-sort="%s"><a class="vh-sort%s" href="%s">%s<span class="vh-sort__mark" aria-hidden="true">%s</span></a></th>',
			esc_attr( $aria ),
			$active ? ' is-active' : '',
			esc_url( self::url( $params ) ),
			esc_html( $label ),
			$active ? ( 'ASC' === $order ? '&#9650;' : '&#9660;' ) : ''
		);
	}

	private static function pager( int $current, int $pages ): void {
		if ( $pages < 2 ) {
			return;
		}

		$base = self::active_filters();
		$sort = array(
			'orderby' => self::q( 'orderby' ),
			'order'   => self::q( 'order' ),
		);
		$base = array_merge( $base, array_filter( $sort, static fn( string $v ): bool => '' !== $v ) );

		echo '<nav class="vh-pager" aria-label="' . esc_attr__( 'Pagination', 'vulnhub' ) . '">';

		if ( $current > 1 ) {
			printf(
				'<a class="vh-btn vh-btn--ghost" href="%s">&larr; %s</a>',
				esc_url( self::url( array_merge( $base, array( self::PAGE_KEY => $current - 1 ) ) ) ),
				esc_html__( 'Previous', 'vulnhub' )
			);
		}

		printf(
			'<span class="vh-pager__count">%s</span>',
			esc_html(
				sprintf(
					/* translators: 1: current page, 2: total pages. */
					__( 'Page %1$d of %2$d', 'vulnhub' ),
					$current,
					$pages
				)
			)
		);

		if ( $current < $pages ) {
			printf(
				'<a class="vh-btn vh-btn--ghost" href="%s">%s &rarr;</a>',
				esc_url( self::url( array_merge( $base, array( self::PAGE_KEY => $current + 1 ) ) ) ),
				esc_html__( 'Next', 'vulnhub' )
			);
		}

		echo '</nav>';
	}

	/* =================================================================
	 * Filter vocabularies
	 * ============================================================== */

	/**
	 * Every timeframe the imported data actually uses, in the order the
	 * repository returns them (chronological, with the undated bucket last).
	 *
	 * @return string[]
	 */
	private static function timeframes(): array {
		return self::options( 'timeframe' );
	}

	/**
	 * @return string[]
	 */
	private static function projects(): array {
		return self::options( 'project' );
	}

	/**
	 * One vocabulary, read from the imported data rather than hard-coded, so a
	 * quarter or a project the programme invents next month appears on its own.
	 *
	 * @return string[]
	 */
	private static function options( string $key ): array {
		static $cache = null;

		if ( null === $cache ) {
			$cache = class_exists( 'VH_EOS_Repo' ) ? (array) VH_EOS_Repo::filter_options() : array();
		}

		return array_values( array_filter( array_map( 'strval', (array) ( $cache[ $key ] ?? array() ) ) ) );
	}
}
