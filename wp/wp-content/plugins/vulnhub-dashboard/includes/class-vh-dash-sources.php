<?php
/**
 * Inventory sources: what each register knows, and what it is missing.
 *
 * Four systems claim to know this estate and none of them agrees with the
 * others. Tenable scans what it can route to, Defender is on whatever was
 * onboarded, Intune has the managed devices, and the CMDB is the register
 * everything is supposed to be written down in. The interesting number is
 * never a total -- it is the difference: the machines one system knows about
 * and another has never heard of.
 *
 * The honest limit of this screen, stated on it: VulnHub only holds an asset
 * once some source has claimed it. It can tell you the CMDB is missing 329
 * machines Defender protects. It cannot tell you about a server that nothing
 * has ever seen, because nothing here would know it exists.
 *
 * @package VulnHub\Dashboard
 */

declare( strict_types = 1 );

use VulnHub\Core\Repo;
use VulnHub\Core\Caps;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The inventory-sources comparison screen.
 */
final class VulnHub_Dash_Sources {

	/** View key, page slug, and the export action. */
	public const VIEW   = 'sources';
	public const SLUG   = 'inventory-sources';
	public const ACTION = 'vulnhub_sources_csv';

	/**
	 * Per-request memo, keyed by scope: the whole screen is one read.
	 *
	 * @var array<string,array<string,mixed>>
	 */
	private static array $memo = array();

	public static function init(): void {
		add_filter( 'vulnhub_dash_views', array( __CLASS__, 'register_view' ) );
		add_action( 'vulnhub_dash_render_view_' . self::VIEW, array( __CLASS__, 'render' ) );
		add_action( 'init', array( __CLASS__, 'ensure_page' ), 20 );
		add_action( 'admin_post_' . self::ACTION, array( __CLASS__, 'handle_csv' ) );
	}

	/* =================================================================
	 * Registration
	 * ============================================================== */

	/**
	 * The view definition. Two overlapping circles: the screen is a Venn
	 * diagram with the numbers filled in.
	 *
	 * @return array<string,mixed>
	 */
	private static function definition(): array {
		return array(
			'title' => __( 'Inventory sources', 'vulnhub' ),
			'slug'  => self::SLUG,
			'menu'  => __( 'Sources', 'vulnhub' ),
			'icon'  => 'M9.5 6a6 6 0 100 12 6 6 0 000-12zM14.5 6a6 6 0 100 12 6 6 0 000-12z',
		);
	}

	/**
	 * Registered next to Assets, because it answers a question about the
	 * asset list: which of these registers is this row missing from.
	 *
	 * @param array<string,array<string,mixed>> $views Views, keyed.
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

		// Assets is a core view and always present, but a view that silently
		// fails to register is a nav entry nobody can debug from outside.
		if ( ! isset( $out[ self::VIEW ] ) ) {
			$out[ self::VIEW ] = self::definition();
		}

		return $out;
	}

	/**
	 * Create the page and map it, once. Safe to re-run: the map is checked
	 * first, then an existing page with the slug is adopted rather than
	 * duplicated.
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
					'post_title'     => __( 'Inventory sources', 'vulnhub' ),
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

	/* =================================================================
	 * Data
	 * ============================================================== */

	/**
	 * Which lifecycle scope the screen is counting in.
	 *
	 * Only two, deliberately: the reporting scope (what every other number in
	 * the product means) and everything. The value is passed straight through
	 * to the assets list on every link, so a cell and the list it opens are
	 * always counting the same population.
	 */
	public static function scope(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$life = isset( $_GET['life'] ) ? sanitize_key( wp_unslash( (string) $_GET['life'] ) ) : '';

		return 'all' === $life ? 'all' : 'reportable';
	}

	/**
	 * Every figure on the screen, from one query and one pass.
	 *
	 * One query, not one per cell: five registers make twenty ordered pairs,
	 * and twenty COUNT(*)s over the asset table to answer a single screen is
	 * the kind of thing that is fine on a laptop and embarrassing on a real
	 * estate. `sources_json` is small, the row count is the asset count, and
	 * the pairing is arithmetic.
	 *
	 * Parsed with Repo::source_map() rather than SQL LIKE, because the column
	 * holds JSON now but held a comma-separated list before, and source_map()
	 * is the one place that knows both shapes.
	 *
	 * @param string $scope reportable|all.
	 * @return array{total:int,sources:array<string,array<string,mixed>>,pairs:array<string,array<string,int>>,scope:string}
	 */
	public static function data( string $scope ): array {
		if ( isset( self::$memo[ $scope ] ) ) {
			return self::$memo[ $scope ];
		}

		global $wpdb;

		$table = vh_table( 'assets' );
		$where = 'all' === $scope
			? ''
			: ' WHERE lifecycle_status IN (' . vh_reportable_sql() . ')';

		$rows = (array) $wpdb->get_col( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			"SELECT sources_json FROM {$table}" . $where // phpcs:ignore WordPress.DB.PreparedSQL
		);

		$labels  = vh_asset_sources();
		$counts  = array();
		$only    = array();
		$last    = array();
		$present = array();

		foreach ( $rows as $stored ) {
			$seen = Repo::source_map( (string) $stored );

			if ( ! $seen ) {
				continue;
			}

			$slugs = array_keys( $seen );

			foreach ( $slugs as $slug ) {
				$present[ $slug ] = true;

				$counts[ $slug ] = ( $counts[ $slug ] ?? 0 ) + 1;

				$date = (string) $seen[ $slug ];

				if ( '' !== $date && $date > (string) ( $last[ $slug ] ?? '' ) ) {
					$last[ $slug ] = $date;
				}

				if ( 1 === count( $slugs ) ) {
					$only[ $slug ] = ( $only[ $slug ] ?? 0 ) + 1;
				}
			}
		}

		// Second pass for the pairs, now that every slug in the data is known:
		// a source is only "missing" a machine relative to sources that exist.
		$order = array();

		foreach ( array_keys( $labels ) as $slug ) {
			if ( isset( $present[ $slug ] ) ) {
				$order[] = $slug;
			}
		}

		foreach ( array_keys( $present ) as $slug ) {
			if ( ! in_array( $slug, $order, true ) ) {
				$order[] = $slug;
			}
		}

		/*
		 * The cell: assets this source knows that the other does not. Counted
		 * in its own pass, because "missing" is only meaningful against the
		 * registers that actually exist in the data -- which is not known
		 * until every row has been read.
		 */
		$pairs = array();

		foreach ( $order as $a ) {
			foreach ( $order as $b ) {
				$pairs[ $a ][ $b ] = 0;
			}
		}

		foreach ( $rows as $stored ) {
			$seen = Repo::source_map( (string) $stored );

			if ( ! $seen ) {
				continue;
			}

			foreach ( $order as $a ) {
				if ( ! isset( $seen[ $a ] ) ) {
					continue;
				}

				foreach ( $order as $b ) {
					if ( $a === $b || isset( $seen[ $b ] ) ) {
						continue;
					}

					++$pairs[ $a ][ $b ];
				}
			}
		}

		$sources = array();

		foreach ( $order as $slug ) {
			$sources[ $slug ] = array(
				'label' => (string) ( $labels[ $slug ] ?? ucfirst( $slug ) ),
				'count' => (int) ( $counts[ $slug ] ?? 0 ),
				'only'  => (int) ( $only[ $slug ] ?? 0 ),
				'last'  => (string) ( $last[ $slug ] ?? '' ),
			);
		}

		self::$memo[ $scope ] = array(
			'total'   => count( $rows ),
			'sources' => $sources,
			'pairs'   => $pairs,
			'scope'   => $scope,
		);

		return self::$memo[ $scope ];
	}

	/* =================================================================
	 * Links
	 * ============================================================== */

	/** This screen, in a given scope. */
	private static function self_url( string $scope ): string {
		return VulnHub_Dash_Portal::portal_url( self::VIEW, 'all' === $scope ? array( 'life' => 'all' ) : array() );
	}

	/**
	 * The assets list, filtered to exactly one cell.
	 *
	 * `has` and `missing` are the assets list's compound source filters: known
	 * by A, and no record in B.
	 */
	private static function cell_url( string $a, string $b, string $scope ): string {
		$args = array( 'has' => $a );

		if ( '' !== $b ) {
			$args['missing'] = $b;
		}

		$args['life'] = 'all' === $scope ? 'all' : 'reportable';

		return VulnHub_Dash_Portal::portal_url( 'assets', $args );
	}

	/* =================================================================
	 * Render
	 * ============================================================== */

	public static function render(): void {
		$scope = self::scope();
		$data  = self::data( $scope );

		?>
		<div class="vh-page-head">
			<div>
				<h1><?php esc_html_e( 'Inventory sources', 'vulnhub' ); ?></h1>
				<p>
					<?php
					echo esc_html(
						sprintf(
							/* translators: 1: number of assets, 2: number of source systems. */
							_n(
								'%1$s asset, as recorded by %2$d source systems that each know part of the estate.',
								'%1$s assets, as recorded by %2$d source systems that each know part of the estate.',
								(int) $data['total'],
								'vulnhub'
							),
							number_format_i18n( (int) $data['total'] ),
							count( $data['sources'] )
						)
					);
					?>
				</p>
			</div>
			<?php if ( count( $data['sources'] ) > 1 ) : ?>
				<div class="vh-page-head__actions">
					<?php self::export_form( $scope ); ?>
				</div>
			<?php endif; ?>
		</div>

		<p class="vh-sub vh-src__caveat">
			<?php esc_html_e( 'This compares the registers against each other. VulnHub holds an asset only once some source has claimed it, so a machine that none of these systems has ever seen appears nowhere here — and nowhere else in the platform either.', 'vulnhub' ); ?>
		</p>

		<?php self::scope_switch( $scope ); ?>

		<?php
		if ( count( $data['sources'] ) < 2 ) {
			echo VulnHub_Dash_Charts::empty_state( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				esc_html__( 'A comparison needs two registers. Only one source has claimed any asset so far, so there is nothing to compare it with yet.', 'vulnhub' )
			);
			return;
		}

		self::gaps( $data );
		self::registers( $data );
		self::matrix( $data );
	}

	/**
	 * The reporting scope is the portal's default lens, and every link on this
	 * screen carries whichever is in force -- so a cell and the list it opens
	 * never count different populations.
	 */
	private static function scope_switch( string $scope ): void {
		$choices = array(
			'reportable' => __( 'Reporting scope', 'vulnhub' ),
			'all'        => __( 'Every asset', 'vulnhub' ),
		);

		echo '<div class="vh-src__scope" role="group" aria-label="' . esc_attr__( 'Which assets to count', 'vulnhub' ) . '">';

		foreach ( $choices as $key => $label ) {
			$is = $key === $scope;

			printf(
				'<a class="vh-chip vh-chip--filter%s" href="%s"%s>%s</a>',
				$is ? ' is-active' : '',
				esc_url( self::self_url( $key ) ),
				$is ? ' aria-current="true"' : '',
				esc_html( $label )
			);
		}

		echo '</div>';
	}

	/**
	 * The two or three gaps worth acting on, as sentences.
	 *
	 * A matrix is a reference; nobody reads a grid and knows what to do. The
	 * largest one-way differences said in words are the point of the screen,
	 * so they go above it.
	 *
	 * @param array<string,mixed> $data Screen data.
	 */
	private static function gaps( array $data ): void {
		$found = array();

		foreach ( (array) $data['pairs'] as $a => $row ) {
			foreach ( (array) $row as $b => $n ) {
				if ( $a === $b || $n < 1 ) {
					continue;
				}

				$found[] = array( 'a' => (string) $a, 'b' => (string) $b, 'n' => (int) $n );
			}
		}

		if ( ! $found ) {
			echo VulnHub_Dash_Charts::empty_state( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				esc_html__( 'Every source knows every asset the others do. There are no gaps between these registers.', 'vulnhub' )
			);
			return;
		}

		/*
		 * Size alone ranks the wrong things first. Defender sees the most, so
		 * a plain sort leads with "Defender knows 455 things Intune does not"
		 * -- true, and not what anyone is going to do something about.
		 *
		 * A gap is worth chasing when it names something missing from a
		 * register that is supposed to be complete: the CMDB is the asset
		 * register of record, and Defender is meant to be on every endpoint.
		 * Those come first, biggest first; everything else follows as
		 * context. `register_of_record` is a filter so an operator whose
		 * source of truth is something else can say so.
		 *
		 * @param array<int,string> $slugs Sources a gap is measured *into*.
		 */
		$registers = (array) apply_filters( 'vulnhub_sources_registers_of_record', array( 'cmdb', 'defender' ) );

		usort(
			$found,
			static function ( array $x, array $y ) use ( $registers ): int {
				$xr = in_array( $x['b'], $registers, true ) ? 1 : 0;
				$yr = in_array( $y['b'], $registers, true ) ? 1 : 0;

				return $xr === $yr ? $y['n'] <=> $x['n'] : $yr <=> $xr;
			}
		);

		$found = array_slice( $found, 0, 3 );

		echo '<div class="vh-card vh-src__gaps"><h2>' . esc_html__( 'Worth chasing', 'vulnhub' ) . '</h2><ul>';

		foreach ( $found as $gap ) {
			$a_label = (string) $data['sources'][ $gap['a'] ]['label'];
			$b_label = (string) $data['sources'][ $gap['b'] ]['label'];

			printf(
				'<li><a href="%s">%s</a></li>',
				esc_url( self::cell_url( $gap['a'], $gap['b'], (string) $data['scope'] ) ),
				esc_html(
					sprintf(
						/* translators: 1: number of assets, 2: source that knows them, 3: source that does not. */
						_n(
							'%1$s asset is known to %2$s but has no record in %3$s.',
							'%1$s assets are known to %2$s but have no record in %3$s.',
							(int) $gap['n'],
							'vulnhub'
						),
						number_format_i18n( (int) $gap['n'] ),
						$a_label,
						$b_label
					)
				)
			);
		}

		echo '</ul></div>';
	}

	/**
	 * What each register holds on its own terms.
	 *
	 * @param array<string,mixed> $data Screen data.
	 */
	private static function registers( array $data ): void {
		$scope = (string) $data['scope'];

		echo '<div class="vh-card"><h2>' . esc_html__( 'Each register', 'vulnhub' ) . '</h2>';
		echo '<div class="vh-tablewrap vh-tablewrap--cards"><table class="vh-table"><thead><tr>'
			. '<th scope="col">' . esc_html__( 'Source', 'vulnhub' ) . '</th>'
			. '<th scope="col">' . esc_html__( 'Assets it knows', 'vulnhub' ) . '</th>'
			. '<th scope="col">' . esc_html__( 'Share of the estate', 'vulnhub' ) . '</th>'
			. '<th scope="col">' . esc_html__( 'Only this source', 'vulnhub' ) . '</th>'
			. '<th scope="col">' . esc_html__( 'Last claimed', 'vulnhub' ) . '</th>'
			. '</tr></thead><tbody>';

		$total = max( 1, (int) $data['total'] );

		foreach ( (array) $data['sources'] as $slug => $src ) {
			$share = (int) round( ( (int) $src['count'] / $total ) * 100 );

			printf(
				'<tr>'
				. '<td data-th="%1$s"><strong>%2$s</strong></td>'
				. '<td data-th="%3$s"><a href="%4$s">%5$s</a></td>'
				. '<td data-th="%6$s">%7$s</td>'
				. '<td data-th="%8$s" title="%9$s">%10$s</td>'
				. '<td data-th="%11$s">%12$s</td>'
				. '</tr>',
				esc_attr__( 'Source', 'vulnhub' ),
				esc_html( (string) $src['label'] ),
				esc_attr__( 'Assets it knows', 'vulnhub' ),
				esc_url( self::cell_url( (string) $slug, '', $scope ) ),
				esc_html( number_format_i18n( (int) $src['count'] ) ),
				esc_attr__( 'Share of the estate', 'vulnhub' ),
				esc_html(
					sprintf(
						/* translators: %d: a percentage. */
						__( '%d%%', 'vulnhub' ),
						$share
					)
				),
				esc_attr__( 'Only this source', 'vulnhub' ),
				esc_attr__( 'No other register has these assets at all.', 'vulnhub' ),
				esc_html( number_format_i18n( (int) $src['only'] ) ),
				esc_attr__( 'Last claimed', 'vulnhub' ),
				esc_html( '' !== (string) $src['last'] ? vh_date_only( (string) $src['last'] ) : '—' )
			);
		}

		echo '</tbody></table></div></div>';
	}

	/**
	 * The matrix: a row per register, a column per register, each cell the
	 * count the row knows and the column does not.
	 *
	 * Read as a sentence -- "Tenable, missing from CMDB, 42" -- which is what
	 * each cell's accessible name says, because a grid of bare numbers is
	 * unreadable to anyone not already holding the axes in their head.
	 *
	 * @param array<string,mixed> $data Screen data.
	 */
	private static function matrix( array $data ): void {
		$scope   = (string) $data['scope'];
		$sources = (array) $data['sources'];

		echo '<div class="vh-card vh-src__matrix"><h2>' . esc_html__( 'What each register is missing', 'vulnhub' ) . '</h2>';
		echo '<p class="vh-sub">' . esc_html__( 'Read a row across: assets that source knows, which the source at the top of the column has no record of. The diagonal is the row’s own total.', 'vulnhub' ) . '</p>';

		echo '<div class="vh-tablewrap vh-tablewrap--cards vh-src__wrap"><table class="vh-table vh-src__grid"><thead><tr>'
			. '<th scope="col">' . esc_html__( 'Knows', 'vulnhub' ) . '</th>';

		foreach ( $sources as $src ) {
			echo '<th scope="col">' . esc_html(
				sprintf(
					/* translators: %s: a source system's name. */
					__( 'Missing from %s', 'vulnhub' ),
					(string) $src['label']
				)
			) . '</th>';
		}

		echo '</tr></thead><tbody>';

		foreach ( $sources as $a => $src_a ) {
			echo '<tr><th scope="row">' . esc_html( (string) $src_a['label'] ) . '</th>';

			foreach ( $sources as $b => $src_b ) {
				$same  = $a === $b;
				$n     = $same ? (int) $src_a['count'] : (int) ( $data['pairs'][ $a ][ $b ] ?? 0 );
				$label = $same
					? sprintf(
						/* translators: 1: number of assets, 2: a source system's name. */
						_n( '%1$s asset known to %2$s in total', '%1$s assets known to %2$s in total', $n, 'vulnhub' ),
						number_format_i18n( $n ),
						(string) $src_a['label']
					)
					: sprintf(
						/* translators: 1: number of assets, 2: source that knows them, 3: source that does not. */
						_n(
							'%1$s asset known to %2$s that %3$s does not have',
							'%1$s assets known to %2$s that %3$s does not have',
							$n,
							'vulnhub'
						),
						number_format_i18n( $n ),
						(string) $src_a['label'],
						(string) $src_b['label']
					);

				$classes = 'vh-src__cell';

				if ( $same ) {
					$classes .= ' vh-src__cell--self';
				} elseif ( $n > 0 ) {
					$classes .= ' vh-src__cell--gap';
				}

				$value = esc_html( number_format_i18n( $n ) );

				// Zero is a fact worth reading as plainly as a gap, and there
				// is nothing behind it to open, so it is never a link.
				$inner = $n > 0
					? sprintf(
						'<a href="%s" aria-label="%s">%s</a>',
						esc_url( self::cell_url( (string) $a, $same ? '' : (string) $b, $scope ) ),
						esc_attr( $label ),
						$value
					)
					: sprintf( '<span aria-label="%s">%s</span>', esc_attr( $label ), $value );

				printf(
					'<td class="%s" data-th="%s">%s</td>',
					esc_attr( $classes ),
					esc_attr(
						$same
							? esc_attr__( 'Total', 'vulnhub' )
							: sprintf(
								/* translators: %s: a source system's name. */
								__( 'Missing from %s', 'vulnhub' ),
								(string) $src_b['label']
							)
					),
					$inner // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built escaped above.
				);
			}

			echo '</tr>';
		}

		echo '</tbody></table></div></div>';
	}

	/* =================================================================
	 * Export
	 * ============================================================== */

	/**
	 * The export posts rather than links, so the nonce is not sitting in a
	 * URL somebody pastes into a ticket.
	 */
	private static function export_form( string $scope ): void {
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-src__export">
			<input type="hidden" name="action" value="<?php echo esc_attr( self::ACTION ); ?>">
			<input type="hidden" name="life" value="<?php echo esc_attr( $scope ); ?>">
			<input type="hidden" name="vh_from_portal" value="1">
			<?php wp_nonce_field( self::ACTION, '_wpnonce', false ); ?>
			<button type="submit" class="vh-btn vh-btn--ghost">
				<?php esc_html_e( 'Export CSV', 'vulnhub' ); ?>
			</button>
		</form>
		<?php
	}

	/**
	 * One rectangular grid, not two stacked tables: a row per source with its
	 * own figures, then a column per source holding what that source is
	 * missing. It opens in a spreadsheet as something you can sort.
	 */
	public static function handle_csv(): void {
		if ( ! is_user_logged_in() || ! current_user_can( Caps::VIEW ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}

		check_admin_referer( self::ACTION );

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- checked above.
		$scope = isset( $_POST['life'] ) && 'all' === sanitize_key( wp_unslash( (string) $_POST['life'] ) ) ? 'all' : 'reportable';
		$data  = self::data( $scope );

		$name = sprintf(
			'vulnhub-inventory-sources-%s-%s.csv',
			$scope,
			wp_date( 'Y-m-d-Hi' )
		);

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . $name . '"' );

		while ( ob_get_level() > 0 ) {
			ob_end_clean();
		}

		$out = fopen( 'php://output', 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( ! $out ) {
			exit;
		}

		// Excel reads a UTF-8 CSV without a BOM as Windows-1252.
		fwrite( $out, "\xEF\xBB\xBF" ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		$sources = (array) $data['sources'];

		$head = array(
			__( 'Source', 'vulnhub' ),
			__( 'Assets it knows', 'vulnhub' ),
			__( 'Only this source', 'vulnhub' ),
			__( 'Last claimed', 'vulnhub' ),
		);

		foreach ( $sources as $src ) {
			$head[] = sprintf(
				/* translators: %s: a source system's name. */
				__( 'Missing from %s', 'vulnhub' ),
				(string) $src['label']
			);
		}

		fputcsv( $out, $head );

		foreach ( $sources as $a => $src ) {
			$line = array(
				(string) $src['label'],
				(int) $src['count'],
				(int) $src['only'],
				(string) $src['last'],
			);

			foreach ( array_keys( $sources ) as $b ) {
				$line[] = $a === $b ? '' : (int) ( $data['pairs'][ $a ][ $b ] ?? 0 );
			}

			fputcsv( $out, $line );
		}

		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		exit;
	}
}
