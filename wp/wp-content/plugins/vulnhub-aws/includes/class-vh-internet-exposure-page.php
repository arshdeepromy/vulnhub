<?php
/**
 * Internet exposure: every public name, and what stands behind it.
 *
 * The estate's public surface is described by four systems that never talk to
 * each other -- the authoritative DNS, the CDN's property configuration, the
 * CDN's WAF coverage, and AWS itself -- and until this page nobody could see
 * a single name end to end. The answer to "what is this, who protects it, and
 * which server does it reach" needed four consoles and a person who knew all
 * four.
 *
 * This draws the chain instead:
 *
 *   the internet -> the CDN edge -> a WAF policy (or none) -> the origin ->
 *   an AWS resource -> the asset in the register
 *
 * Every hop states where it was read from, and a hop nobody can answer says
 * so rather than being left blank -- a gap in the picture is the finding, and
 * a blank that looks like "nothing there" is how those get missed.
 *
 * Two tabs. *Names* is the explorer: every public name, expandable to its
 * chain. *Gaps* is the same data asked the other way round -- what is
 * unprotected, unresolved or contradictory.
 *
 * See docs/AWS-NETWORK.md, "Domain names" and "Edge WAF coverage".
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Internet_Exposure_Page {

	public const VIEW = 'internet_exposure';
	public const SLUG = 'internet-exposure';

	/** Names listed per page. The store holds hundreds; a wall helps nobody. */
	private const PER_PAGE = 60;

	/** @var array<string,array<string,mixed>>|null Assets by every key they can be found under. */
	private static ?array $assets = null;

	public static function init(): void {
		add_filter( 'vulnhub_dash_views', array( __CLASS__, 'register_view' ) );
		add_action( 'vulnhub_dash_render_view_' . self::VIEW, array( __CLASS__, 'render' ) );
		add_action( 'init', array( __CLASS__, 'ensure_page' ), 20 );
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'assets' ), 20 );
	}

	/**
	 * @param array<string,mixed> $views Registered views.
	 * @return array<string,mixed>
	 */
	public static function register_view( array $views ): array {
		$out = array();

		$def = array(
			'title' => __( 'Internet exposure', 'vulnhub' ),
			'slug'  => self::SLUG,
			'menu'  => __( 'Internet exposure', 'vulnhub' ),
			'icon'  => 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c2.5 2.4 2.5 15.6 0 18-2.5-2.4-2.5-15.6 0-18z',
		);

		// Straight after the serverless view: both answer "what can the
		// internet reach", from opposite ends.
		foreach ( $views as $key => $existing ) {
			$out[ $key ] = $existing;

			if ( class_exists( 'VulnHub_AWS_Serverless_Page' ) && VulnHub_AWS_Serverless_Page::VIEW === $key ) {
				$out[ self::VIEW ] = $def;
			}
		}

		if ( ! isset( $out[ self::VIEW ] ) ) {
			$out[ self::VIEW ] = $def;
		}

		return $out;
	}

	public static function ensure_page(): void {
		$map = (array) get_option( 'vulnhub_dash_pages', array() );

		if ( ! empty( $map[ self::VIEW ] ) ) {
			$existing = get_post( (int) $map[ self::VIEW ] );

			if ( $existing && 'trash' !== $existing->post_status ) {
				return;
			}
		}

		$page = get_page_by_path( self::SLUG );

		$id = $page ? (int) $page->ID : wp_insert_post(
			array(
				'post_title'     => __( 'Internet exposure', 'vulnhub' ),
				'post_name'      => self::SLUG,
				'post_content'   => '<!-- wp:shortcode -->[vulnhub_app view="' . self::VIEW . '"]<!-- /wp:shortcode -->',
				'post_status'    => 'publish',
				'post_type'      => 'page',
				'comment_status' => 'closed',
				'ping_status'    => 'closed',
			)
		);

		if ( ! is_wp_error( $id ) && $id ) {
			$map[ self::VIEW ] = (int) $id;
			update_option( 'vulnhub_dash_pages', $map, false );
		}
	}

	public static function assets(): void {
		if ( ! is_singular() || ! class_exists( 'VulnHub_Dash_App' ) ) {
			return;
		}

		if ( self::VIEW !== VulnHub_Dash_App::view_for_post( get_post() ) ) {
			return;
		}

		$ver = @filemtime( VULNHUB_AWS_DIR . 'assets/exposure.css' ); // phpcs:ignore
		wp_enqueue_style( 'vulnhub-aws-exposure', VULNHUB_AWS_URL . 'assets/exposure.css', array( 'vulnhub-app' ), $ver ?: VULNHUB_AWS_VERSION );
	}

	/* =================================================================
	 * Render
	 * ============================================================== */

	public static function render(): void {
		$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'names'; // phpcs:ignore WordPress.Security.NonceVerification

		echo '<div class="vh-page-head"><div>';
		echo '<h1>' . esc_html__( 'Internet exposure', 'vulnhub' ) . '</h1>';
		echo '<p class="vh-sub">' . esc_html__(
			'Every public name the estate is known to answer to, and the chain behind it: the CDN edge, the security policy in front of it, the origin it reaches, and the server that finally serves it. Four systems describe this surface and none of them agrees with the others on its own.',
			'vulnhub'
		) . '</p>';
		echo '</div></div>';

		self::render_tiles();

		echo '<nav class="vh-tabs vh-ie-tabs">';
		foreach ( array(
			'names' => __( 'Names', 'vulnhub' ),
			'gaps'  => __( 'Gaps', 'vulnhub' ),
		) as $key => $label ) {
			printf(
				'<a class="vh-tabs__tab%s" href="%s">%s</a>',
				$key === $tab ? ' is-active' : '',
				esc_url( add_query_arg( 'tab', $key, self::url() ) ),
				esc_html( $label )
			);
		}
		echo '</nav>';

		if ( 'gaps' === $tab ) {
			self::render_gaps();
		} else {
			self::render_names();
		}

		self::render_sources_note();
	}

	private static function render_tiles(): void {
		$s = self::totals();

		echo '<div class="vh-tiles">';
		self::tile( __( 'Public names known', 'vulnhub' ), (string) $s['names'], __( 'from DNS, the CDN, and AWS', 'vulnhub' ) );
		self::tile( __( 'Served through the CDN', 'vulnhub' ), (string) $s['edge'], __( 'an edge property answers for them', 'vulnhub' ) );
		self::tile( __( 'Covered by a WAF policy', 'vulnhub' ), (string) $s['covered'], sprintf( /* translators: %d: hostnames with no policy. */ __( '%d have none', 'vulnhub' ), (int) $s['uncovered'] ) );
		self::tile( __( 'Resolved to something we hold', 'vulnhub' ), (string) $s['resolved'], __( 'a load balancer, gateway, address or server', 'vulnhub' ) );
		echo '</div>';
	}

	private static function tile( string $label, string $value, string $meta ): void {
		echo '<div class="vh-tile">';
		printf( '<div class="vh-tile__label">%s</div>', esc_html( $label ) );
		printf( '<div class="vh-tile__value">%s</div>', esc_html( $value ) );

		if ( '' !== $meta ) {
			printf( '<div class="vh-tile__meta">%s</div>', esc_html( $meta ) );
		}

		echo '</div>';
	}

	/* ---- the explorer ---------------------------------------------- */

	private static function render_names(): void {
		// phpcs:disable WordPress.Security.NonceVerification
		$search = isset( $_GET['q'] ) ? strtolower( sanitize_text_field( wp_unslash( $_GET['q'] ) ) ) : '';
		$cover  = isset( $_GET['cov'] ) ? sanitize_key( wp_unslash( $_GET['cov'] ) ) : '';
		$page   = isset( $_GET['pg'] ) ? max( 1, (int) $_GET['pg'] ) : 1;
		// phpcs:enable

		echo '<form class="vh-filters vh-ie-filters" method="get">';
		printf( '<input type="hidden" name="tab" value="names">' );
		echo '<label>' . esc_html__( 'Search', 'vulnhub' );
		printf( '<input type="search" name="q" value="%s" placeholder="%s">', esc_attr( $search ), esc_attr__( 'a name, a property, an origin', 'vulnhub' ) );
		echo '</label>';
		echo '<label>' . esc_html__( 'WAF', 'vulnhub' );
		echo '<select name="cov">';
		foreach ( array(
			''          => __( 'Any', 'vulnhub' ),
			'covered'   => __( 'Covered', 'vulnhub' ),
			'uncovered' => __( 'Not covered', 'vulnhub' ),
			'unlisted'  => __( 'Not in the export', 'vulnhub' ),
		) as $k => $label ) {
			printf( '<option value="%s"%s>%s</option>', esc_attr( $k ), selected( $cover, $k, false ), esc_html( $label ) );
		}
		echo '</select></label>';
		printf( '<button type="submit" class="vh-btn">%s</button>', esc_html__( 'Filter', 'vulnhub' ) );
		printf( '<a class="vh-btn vh-btn--ghost" href="%s">%s</a>', esc_url( self::url() ), esc_html__( 'Clear', 'vulnhub' ) );
		echo '</form>';

		$rows  = self::names( $search, $cover );
		$total = count( $rows );
		$rows  = array_slice( $rows, ( $page - 1 ) * self::PER_PAGE, self::PER_PAGE );

		printf(
			'<p class="vh-sub vh-muted">%s</p>',
			esc_html(
				sprintf(
					/* translators: 1: shown, 2: total. */
					__( 'Showing %1$d of %2$d names. Open one to follow it from the internet to the server.', 'vulnhub' ),
					count( $rows ),
					$total
				)
			)
		);

		if ( ! $rows ) {
			echo '<div class="vh-card"><p class="vh-sub">' . esc_html__( 'Nothing matches that filter.', 'vulnhub' ) . '</p></div>';

			return;
		}

		foreach ( $rows as $row ) {
			self::render_name_card( $row );
		}

		self::render_pager( $page, $total, $search, $cover );
	}

	/**
	 * One public name, collapsed, opening to its chain.
	 *
	 * @param array<string,mixed> $row One name.
	 */
	private static function render_name_card( array $row ): void {
		echo '<details class="vh-card vh-ie-card">';
		echo '<summary class="vh-ie-head">';
		echo '<span class="vh-sl-caret" aria-hidden="true"></span>';
		echo '<span class="vh-ie-headline">';
		printf( '<span class="vh-ie-name">%s</span>', esc_html( (string) $row['name'] ) );

		if ( '' !== (string) $row['reaches_label'] ) {
			printf( '<span class="vh-ie-reaches">%s</span>', esc_html( (string) $row['reaches_label'] ) );
		}

		echo '</span><span class="vh-ie-chips">';

		$svc = (array) ( $row['service'] ?? array() );

		if ( '' !== (string) ( $svc['environment'] ?? '' ) ) {
			// Production is the only one coloured. The rest are facts, not
			// warnings, and a page of amber chips teaches people to ignore
			// amber chips.
			printf(
				'<span class="vh-chip%1$s">%2$s</span>',
				'production' === (string) $svc['environment'] ? ' vh-chip--info' : '',
				esc_html( (string) $svc['environment'] )
			);
		}

		if ( ! empty( $row['edge'] ) ) {
			printf( '<span class="vh-chip">%s</span>', esc_html( (string) $row['edge']['property'] ) );
		}

		$waf = (array) $row['waf'];

		if ( ! $waf ) {
			printf( '<span class="vh-chip vh-chip--warn">%s</span>', esc_html__( 'not in the WAF export', 'vulnhub' ) );
		} elseif ( empty( $waf['covered'] ) ) {
			printf( '<span class="vh-chip vh-chip--bad">%s</span>', esc_html__( 'no WAF policy', 'vulnhub' ) );
		} else {
			printf( '<span class="vh-chip vh-chip--good">%s</span>', esc_html__( 'WAF covered', 'vulnhub' ) );
		}

		echo '</span></summary>';

		if ( $svc ) {
			printf(
				'<p class="vh-sub vh-ie-what"><strong>%1$s</strong>%2$s%3$s</p>',
				esc_html( (string) $svc['system'] ),
				'' !== (string) $svc['component'] ? ' &middot; ' . esc_html( (string) $svc['component'] ) : '',
				'' !== (string) $svc['purpose'] ? '<br>' . esc_html( (string) $svc['purpose'] ) : ''
			);

			if ( '' !== (string) $svc['architecture'] ) {
				printf(
					'<p class="vh-sub vh-muted vh-ie-arch">%s</p>',
					esc_html(
						sprintf(
							/* translators: %s: the architecture as described by the service owner. */
							__( 'As documented: %s', 'vulnhub' ),
							(string) $svc['architecture']
						)
					)
				);
			}
		}

		echo '<ol class="vh-ie-chain">';

		self::hop(
			'net',
			'globe',
			__( 'The internet', 'vulnhub' ),
			__( 'anyone, anywhere', 'vulnhub' ),
			__( 'the caller', 'vulnhub' )
		);

		if ( ! empty( $row['edge'] ) ) {
			$edge = (array) $row['edge'];

			self::hop(
				'edge',
				'cloud',
				__( 'CDN edge', 'vulnhub' ),
				sprintf(
					/* translators: 1: property name, 2: version. */
					__( 'property %1$s, version %2$s', 'vulnhub' ),
					(string) $edge['property'],
					(string) $edge['version']
				),
				'' !== (string) $edge['siteshield']
					? sprintf( /* translators: %s: site shield map. */ __( 'Site Shield: %s', 'vulnhub' ), (string) $edge['siteshield'] )
					: __( 'no Site Shield on this property', 'vulnhub' ),
				'' !== (string) $edge['siteshield'] ? 'ok' : 'warn'
			);

			self::hop(
				'waf',
				'shield',
				__( 'Security policy', 'vulnhub' ),
				$waf && ! empty( $waf['covered'] )
					? (string) $waf['policy']
					: __( 'none applied to this hostname', 'vulnhub' ),
				$waf
					? sprintf( /* translators: %s: configuration name. */ __( 'configuration: %s', 'vulnhub' ), (string) $waf['config'] ?: __( 'none', 'vulnhub' ) )
					: __( 'this hostname is not in the coverage export at all', 'vulnhub' ),
				$waf && ! empty( $waf['covered'] ) ? 'ok' : 'bad'
			);
		} elseif ( ! empty( $row['dns'] ) ) {
			$dns = (array) $row['dns'];

			self::hop(
				'dns',
				'policy',
				__( 'DNS record', 'vulnhub' ),
				sprintf( '%s -> %s', (string) $dns['record_type'], (string) $dns['target'] ),
				sprintf( /* translators: %s: zone name. */ __( 'zone %s', 'vulnhub' ), (string) $dns['zone'] )
			);
		}

		$origin = (string) $row['origin'];

		if ( '' !== $origin ) {
			self::hop(
				'origin',
				'gateway',
				__( 'Origin', 'vulnhub' ),
				$origin,
				(string) $row['origin_note']
			);
		}

		$res = (array) $row['resolved'];

		if ( $res ) {
			self::hop(
				'res',
				(string) $res['icon'],
				(string) $res['label'],
				(string) $res['sub'],
				(string) $res['meta'],
				'ok'
			);
		} else {
			self::hop(
				'unknown',
				'unknown',
				__( 'Not resolved', 'vulnhub' ),
				'' !== $origin
					? __( 'nothing we hold answers to that origin name', 'vulnhub' )
					: __( 'no target recorded for this name', 'vulnhub' ),
				__( 'a sync or an export is missing, not necessarily the resource', 'vulnhub' ),
				'warn'
			);
		}

		$asset = (array) $row['asset'];

		if ( $asset ) {
			self::hop(
				'asset',
				'database',
				(string) $asset['hostname'],
				sprintf(
					/* translators: 1: asset type, 2: the system it was read from. */
					__( '%1$s, from %2$s', 'vulnhub' ),
					(string) $asset['type'] ?: __( 'asset', 'vulnhub' ),
					(string) $asset['source'] ?: __( 'the register', 'vulnhub' )
				),
				__( 'in the asset register', 'vulnhub' ),
				'ok'
			);
		}

		echo '</ol></details>';
	}

	/**
	 * One step of the chain.
	 */
	private static function hop( string $tone, string $icon, string $label, string $sub, string $meta, string $state = '' ): void {
		printf( '<li class="vh-ie-hop vh-ie-hop--%s%s">', esc_attr( $tone ), '' !== $state ? ' is-' . esc_attr( $state ) : '' );
		printf(
			'<span class="vh-ie-ico"><svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">%s</svg></span>',
			class_exists( 'VulnHub_AWS_Serverless_Page' ) ? VulnHub_AWS_Serverless_Page::glyph( $icon ) : ''
		);
		echo '<span class="vh-ie-hop__text">';
		printf( '<span class="vh-ie-hop__label">%s</span>', esc_html( $label ) );

		if ( '' !== $sub ) {
			printf( '<span class="vh-ie-hop__sub">%s</span>', esc_html( $sub ) );
		}

		if ( '' !== $meta ) {
			printf( '<span class="vh-ie-hop__meta">%s</span>', esc_html( $meta ) );
		}

		echo '</span></li>';
	}

	private static function render_pager( int $page, int $total, string $search, string $cover ): void {
		$pages = (int) ceil( $total / self::PER_PAGE );

		if ( $pages < 2 ) {
			return;
		}

		echo '<nav class="vh-ie-pager">';

		for ( $i = 1; $i <= $pages; $i++ ) {
			if ( $i > 1 && $i < $pages && abs( $i - $page ) > 2 ) {
				if ( $i === $page - 3 || $i === $page + 3 ) {
					echo '<span class="vh-ie-pager__gap">…</span>';
				}

				continue;
			}

			printf(
				'<a class="vh-btn vh-btn--ghost%s" href="%s">%d</a>',
				$i === $page ? ' is-active' : '',
				esc_url(
					add_query_arg(
						array(
							'tab' => 'names',
							'q'   => $search,
							'cov' => $cover,
							'pg'  => $i,
						),
						self::url()
					)
				),
				$i
			);
		}

		echo '</nav>';
	}

	/* ---- the gaps --------------------------------------------------- */

	private static function render_gaps(): void {
		$rows = self::names( '', '' );

		$uncovered = array_values(
			array_filter(
				$rows,
				static fn( array $r ): bool => ! empty( $r['edge'] ) && ( ! $r['waf'] || empty( $r['waf']['covered'] ) )
			)
		);

		$prodish = array_values( array_filter( $uncovered, static fn( array $r ): bool => (bool) $r['looks_prod'] ) );
		$stated  = count( array_filter( $prodish, static fn( array $r ): bool => ! empty( $r['env_known'] ) ) );

		$unresolved = array_values(
			array_filter(
				$rows,
				static fn( array $r ): bool => '' !== (string) $r['origin'] && ! $r['resolved']
			)
		);

		self::gap_block(
			__( 'Behind the CDN with no WAF policy', 'vulnhub' ),
			sprintf(
				/* translators: 1: total, 2: production hostnames, 3: how many of those the catalogue states. */
				__( '%1$d hostname(s), of which %2$d are production -- %3$d because the service catalogue says so, the rest because the name carries no dev, sit, uat or preprod marker. A stated environment beats a guess: a production-shaped name can front a dev pool.', 'vulnhub' ),
				count( $uncovered ),
				count( $prodish ),
				$stated
			),
			$prodish ?: $uncovered
		);

		self::gap_block(
			__( 'Origins nothing in the estate answers to', 'vulnhub' ),
			__( 'The name resolves to an origin, but no AWS resource, address or asset we hold matches it. Usually a sync or an export that has not run rather than a missing server -- worth confirming which.', 'vulnhub' ),
			array_slice( $unresolved, 0, 40 )
		);
	}

	/**
	 * @param array<int,array<string,mixed>> $rows Matching names.
	 */
	private static function gap_block( string $title, string $note, array $rows ): void {
		echo '<section class="vh-card vh-ie-gap">';
		printf( '<h2 class="vh-sl-h3">%s</h2>', esc_html( $title ) );
		printf( '<p class="vh-sub vh-muted">%s</p>', esc_html( $note ) );

		if ( ! $rows ) {
			printf( '<p class="vh-sub vh-ie-clean">%s</p>', esc_html__( 'Nothing here. That is a real answer, not an empty table.', 'vulnhub' ) );
			echo '</section>';

			return;
		}

		echo '<div class="vh-table-wrap"><table class="vh-table">';
		printf(
			'<thead><tr><th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr></thead><tbody>',
			esc_html__( 'Name', 'vulnhub' ),
			esc_html__( 'Edge property', 'vulnhub' ),
			esc_html__( 'Origin', 'vulnhub' ),
			esc_html__( 'Reaches', 'vulnhub' )
		);

		foreach ( $rows as $r ) {
			echo '<tr>';
			printf(
				'<td><a href="%s">%s</a></td>',
				esc_url( add_query_arg( array( 'tab' => 'names', 'q' => (string) $r['name'] ), self::url() ) ),
				esc_html( (string) $r['name'] )
			);
			printf( '<td>%s</td>', esc_html( ! empty( $r['edge'] ) ? (string) $r['edge']['property'] : '—' ) );
			printf( '<td><span class="vh-ie-mono">%s</span></td>', esc_html( (string) $r['origin'] ?: '—' ) );
			printf( '<td>%s</td>', esc_html( (string) $r['reaches_label'] ?: __( 'not resolved', 'vulnhub' ) ) );
			echo '</tr>';
		}

		echo '</tbody></table></div></section>';
	}

	private static function render_sources_note(): void {
		$cover = class_exists( 'VulnHub_AWS_Domains' ) ? VulnHub_AWS_Domains::coverage() : array();
		$imp   = class_exists( 'VulnHub_Domain_Import' ) ? VulnHub_Domain_Import::summary() : array();

		echo '<section class="vh-card vh-ie-sources">';
		echo '<h2 class="vh-sl-h3">' . esc_html__( 'Where each of these came from', 'vulnhub' ) . '</h2>';
		echo '<p class="vh-sub">' . esc_html(
			sprintf(
				/* translators: 1: zone records, 2: zones, 3: WAF hostnames, 4: Route 53 accounts read. */
				__( 'Zone files: %1$d records across %2$d zones, imported by hand. CDN WAF coverage: %3$d hostnames, imported by hand. Route 53 and API Gateway custom domains: read live on each AWS sync, %4$d account(s) so far.', 'vulnhub' ),
				(int) ( $imp['zone_records'] ?? 0 ),
				(int) ( $imp['zones'] ?? 0 ),
				(int) ( $imp['waf_hosts'] ?? 0 ),
				(int) ( $cover['accounts'] ?? 0 )
			)
		) . '</p>';
		if ( self::$skipped > 0 ) {
			printf(
				'<p class="vh-sub vh-muted">%s</p>',
				esc_html(
					sprintf(
						/* translators: %d: records left out. */
						__( 'A further %d record(s) are left out of this page: names whose first label begins with an underscore are certificate validation, DKIM selectors and similar DNS plumbing, which nothing browses and nothing can be exposed through.', 'vulnhub' ),
						self::$skipped
					)
				)
			);
		}

		$cat = class_exists( 'VulnHub_Domain_Import' ) ? VulnHub_Domain_Import::catalog_summary() : array();

		if ( ! empty( $cat['rows'] ) ) {
			printf(
				'<p class="vh-sub">%s</p>',
				esc_html(
					sprintf(
						/* translators: 1: hostnames, 2: systems, 3: production hostnames. */
						__( 'Service catalogue: %1$d hostnames across %2$d systems, %3$d of them production, transcribed from the architecture pages by hand. It is the only source here that says what a name is for and which environment it is; everything else describes the machine behind it. A name not in it is not unknown to the estate, only undocumented here.', 'vulnhub' ),
						(int) $cat['rows'],
						(int) $cat['systems'],
						(int) $cat['production']
					)
				)
			);
		}

		echo '<p class="vh-sub vh-muted">' . esc_html__(
			'The hand-imported sources are point-in-time drops, not feeds: they are as current as the day somebody exported them. Route 53 only covers zones hosted in the AWS accounts this login can read, so a name served from on-premises DNS, a registrar or another provider appears here only if it was in an imported zone file.',
			'vulnhub'
		) . '</p>';

		if ( ! empty( $cover['denied'] ) || ! empty( $cover['failed'] ) ) {
			printf(
				'<p class="vh-sub vh-muted">%s</p>',
				esc_html(
					sprintf(
						/* translators: 1: denied accounts, 2: failed accounts. */
						__( 'Domain names could not be read in %1$d account(s) for want of a grant, and failed in %2$d more.', 'vulnhub' ),
						(int) $cover['denied'],
						(int) $cover['failed']
					)
				)
			);
		}

		echo '</section>';
	}

	/* =================================================================
	 * The model
	 * ============================================================== */

	/**
	 * @return array{names:int,edge:int,covered:int,uncovered:int,resolved:int}
	 */
	private static function totals(): array {
		$rows = self::names( '', '' );

		return array(
			'names'     => count( $rows ),
			'edge'      => count( array_filter( $rows, static fn( array $r ): bool => ! empty( $r['edge'] ) ) ),
			'covered'   => count( array_filter( $rows, static fn( array $r ): bool => $r['waf'] && ! empty( $r['waf']['covered'] ) ) ),
			'uncovered' => count( array_filter( $rows, static fn( array $r ): bool => ! $r['waf'] || empty( $r['waf']['covered'] ) ) ),
			'resolved'  => count( array_filter( $rows, static fn( array $r ): bool => (bool) $r['resolved'] ) ),
		);
	}

	/**
	 * Every public name, assembled from all four sources.
	 *
	 * Assembled in PHP rather than one large join: the store holds hundreds
	 * of names, not millions, and the chain needs a second hop through the
	 * same table (an origin is itself often a name we hold), which SQL
	 * expresses far less clearly than it reads here.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	private static function names( string $search, string $cover ): array {
		static $cache = null;

		if ( null === $cache ) {
			$cache = self::build();
		}

		$out = $cache;

		if ( '' !== $search ) {
			$out = array_filter(
				$out,
				static function ( array $r ) use ( $search ): bool {
					$hay = strtolower(
						(string) $r['name'] . ' ' . (string) $r['origin'] . ' ' .
						( ! empty( $r['edge'] ) ? (string) $r['edge']['property'] : '' ) . ' ' .
						(string) $r['reaches_label']
					);

					return false !== strpos( $hay, $search );
				}
			);
		}

		if ( 'covered' === $cover ) {
			$out = array_filter( $out, static fn( array $r ): bool => $r['waf'] && ! empty( $r['waf']['covered'] ) );
		} elseif ( 'uncovered' === $cover ) {
			$out = array_filter( $out, static fn( array $r ): bool => $r['waf'] && empty( $r['waf']['covered'] ) );
		} elseif ( 'unlisted' === $cover ) {
			$out = array_filter( $out, static fn( array $r ): bool => ! $r['waf'] );
		}

		return array_values( $out );
	}

	/**
	 * @return array<int,array<string,mixed>>
	 */
	private static function build(): array {
		global $wpdb;

		if ( ! class_exists( 'VulnHub_AWS_Domains' ) ) {
			return array();
		}

		$D = VulnHub_AWS_Domains::table();
		$W = class_exists( 'VulnHub_Domain_Import' ) ? VulnHub_Domain_Import::waf_table() : '';

		$domains = (array) $wpdb->get_results( "SELECT name, zone, source, record_type, target, matched_kind, matched_ref, matched_name, detail FROM {$D} ORDER BY name", ARRAY_A ); // phpcs:ignore WordPress.DB

		$waf = array();

		if ( '' !== $W ) {
			foreach ( (array) $wpdb->get_results( "SELECT hostname, covered, status, config, policy FROM {$W}", ARRAY_A ) as $w ) { // phpcs:ignore WordPress.DB
				$waf[ strtolower( (string) $w['hostname'] ) ] = $w;
			}
		}

		// A name may appear from several sources; the CDN record is the most
		// informative, so it wins the summary while the others still feed it.
		$byname = array();
		$bytarget = array();

		foreach ( $domains as $d ) {
			$n = strtolower( (string) $d['name'] );
			$byname[ $n ][] = $d;
			$bytarget[ $n ] = $d;
		}

		// What these names are, as their owners describe them. Read once,
		// not one query per hostname.
		$catalog = class_exists( 'VulnHub_Domain_Import' ) ? VulnHub_Domain_Import::catalog() : array();

		$out     = array();
		$skipped = 0;

		foreach ( $byname as $name => $records ) {
			/*
			 * A label beginning with an underscore is DNS plumbing, not an
			 * endpoint: ACM certificate validation, DKIM selectors, SRV and
			 * the like. Nothing ever browses one, nothing can be exposed
			 * through one, and there are hundreds -- left in, they bury the
			 * few hundred names that are actually the public surface. The
			 * count is reported rather than the rows silently vanishing.
			 */
			if ( false !== strpos( '.' . $name, '._' ) || 0 === strpos( $name, '_' ) ) {
				++$skipped;
				continue;
			}

			$edge = null;
			$dns  = null;

			foreach ( $records as $r ) {
				if ( 'akamai' === $r['source'] && null === $edge ) {
					$detail = (array) ( json_decode( (string) $r['detail'], true ) ?: array() );
					$edge   = array(
						'property'   => (string) ( $detail['property'] ?? '' ),
						'version'    => (string) ( $detail['version'] ?? '' ),
						'siteshield' => (string) ( $detail['siteshield'] ?? '' ),
						'origin'     => (string) $r['target'],
						'matched'    => $r,
					);
				}

				if ( in_array( (string) $r['source'], array( 'zonefile', 'route53' ), true ) && null === $dns ) {
					$dns = $r;
				}
			}

			$origin = $edge ? (string) $edge['origin'] : (string) ( $dns['target'] ?? '' );
			$note   = $edge
				? __( 'the server the edge forwards to', 'vulnhub' )
				: __( 'what the DNS record points at', 'vulnhub' );

			// Second hop: the origin is very often itself a name we hold.
			$hop = $edge ? (array) $edge['matched'] : (array) $dns;
			$key = strtolower( $origin );

			if ( ( '' === (string) ( $hop['matched_kind'] ?? '' ) ) && isset( $bytarget[ $key ] ) ) {
				$hop  = $bytarget[ $key ];
				$note = sprintf(
					/* translators: %s: the record type that resolved it. */
					__( 'resolved one hop further, by a %s record we hold', 'vulnhub' ),
					(string) $hop['record_type']
				);
			}

			$resolved = self::describe( (array) $hop );
			$asset    = self::asset_for( (array) $hop );

			$svc = $catalog[ $name ] ?? array();

			$out[] = array(
				'service'       => $svc,
				'name'          => $name,
				'zone'          => (string) ( $dns['zone'] ?? '' ),
				'edge'          => $edge,
				'dns'           => $dns,
				'waf'           => $waf[ $name ] ?? array(),
				'origin'        => $origin,
				'origin_note'   => $note,
				'resolved'      => $resolved,
				'asset'         => $asset,
				'reaches_label' => $asset
					? (string) $asset['hostname']
					: ( $resolved ? (string) $resolved['label'] : '' ),
				/*
				 * Production, stated where the catalogue knows the name and
				 * guessed from its spelling where it does not.
				 *
				 * The guess is the reason this field exists -- it is what
				 * decides whether a missing WAF policy is a finding or a note
				 * -- and it was always going to be wrong somewhere: a
				 * production-shaped name can front a dev pool, and two of
				 * these do. Where somebody has said what the name is, that
				 * wins, and `env_known` records which of the two answers this
				 * row got so the page can say so rather than implying the
				 * same confidence for both.
				 */
				'environment'   => (string) ( $svc['environment'] ?? '' ),
				'env_known'     => '' !== (string) ( $svc['environment'] ?? '' ),
				'looks_prod'    => isset( $svc['environment'] ) && '' !== (string) $svc['environment']
					? 'production' === (string) $svc['environment']
					: ! preg_match( '/(^|\.)(dev|sit|uat|test|preprod|preprod2|pprd|stage|staging)(\.|$)/', $name ),
			);
		}

		/*
		 * Most useful first: what the CDN serves, then what resolves to
		 * something we hold, then the rest alphabetically. Plain
		 * alphabetical order buries every interesting name behind whatever
		 * happens to start with "a".
		 */
		usort(
			$out,
			static function ( array $a, array $b ): int {
				$rank = static fn( array $r ): int => ( empty( $r['edge'] ) ? 2 : 0 ) + ( $r['resolved'] ? 0 : 1 );

				return $rank( $a ) <=> $rank( $b ) ?: strcmp( (string) $a['name'], (string) $b['name'] );
			}
		);

		self::$skipped = $skipped;

		return $out;
	}

	/** @var int Names left out as DNS plumbing. */
	private static int $skipped = 0;

	/**
	 * What a matched record actually is, in words and an icon.
	 *
	 * @param array<string,mixed> $hop A domains row.
	 * @return array<string,string>
	 */
	private static function describe( array $hop ): array {
		$kind = (string) ( $hop['matched_kind'] ?? '' );

		if ( '' === $kind ) {
			return array();
		}

		$map = array(
			'elb'        => array( 'gateway', __( 'Load balancer', 'vulnhub' ) ),
			'instance'   => array( 'database', __( 'EC2 instance', 'vulnhub' ) ),
			'eni'        => array( 'database', __( 'Network interface', 'vulnhub' ) ),
			'eip'        => array( 'globe', __( 'Elastic IP', 'vulnhub' ) ),
			'apigw'      => array( 'gateway', __( 'API Gateway', 'vulnhub' ) ),
			'cloudfront' => array( 'cloud', __( 'CloudFront distribution', 'vulnhub' ) ),
			's3'         => array( 'bucket', __( 'S3 bucket', 'vulnhub' ) ),
		);

		$def = $map[ $kind ] ?? array( 'database', ucfirst( $kind ) );

		return array(
			'icon'  => (string) $def[0],
			'label' => (string) $def[1],
			'sub'   => (string) ( $hop['matched_name'] ?? '' ) ?: (string) ( $hop['matched_ref'] ?? '' ),
			'meta'  => (string) ( $hop['target'] ?? '' ),
		);
	}

	/**
	 * The asset register row behind a matched hop, if there is one.
	 *
	 * @param array<string,mixed> $hop A domains row.
	 * @return array<string,string>
	 */
	private static function asset_for( array $hop ): array {
		$ref = strtolower( (string) ( $hop['matched_ref'] ?? '' ) );

		if ( '' === $ref ) {
			return array();
		}

		$index = self::asset_index();

		return $index[ $ref ] ?? array();
	}

	/**
	 * @return array<string,array<string,string>>
	 */
	private static function asset_index(): array {
		if ( null !== self::$assets ) {
			return self::$assets;
		}

		global $wpdb;

		self::$assets = array();
		$table        = $wpdb->prefix . 'vulnhub_assets';

		$rows = (array) $wpdb->get_results( // phpcs:ignore WordPress.DB
			"SELECT hostname, fqdn, ipv4, ipv4s, aws_instance_id, asset_type, primary_source
			   FROM {$table} WHERE duplicate_of IS NULL OR duplicate_of = 0",
			ARRAY_A
		);

		foreach ( $rows as $a ) {
			$label = array(
				'hostname' => (string) $a['hostname'],
				'type'     => (string) $a['asset_type'],
				'source'   => (string) $a['primary_source'],
			);

			foreach ( array( (string) $a['aws_instance_id'], (string) $a['fqdn'] ) as $key ) {
				if ( '' !== $key ) {
					self::$assets[ strtolower( $key ) ] = $label;
				}
			}

			foreach ( explode( ',', (string) $a['ipv4'] . ',' . (string) $a['ipv4s'] ) as $ip ) {
				$ip = trim( $ip );

				if ( '' !== $ip ) {
					self::$assets[ $ip ] = $label;
				}
			}
		}

		return self::$assets;
	}

	private static function url(): string {
		$map = (array) get_option( 'vulnhub_dash_pages', array() );
		$id  = (int) ( $map[ self::VIEW ] ?? 0 );

		return $id ? (string) get_permalink( $id ) : home_url( '/' . self::SLUG . '/' );
	}
}

