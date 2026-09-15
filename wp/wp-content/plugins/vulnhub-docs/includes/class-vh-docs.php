<?php
/**
 * Wires the wiki into the portal and draws it.
 *
 * The docs are a first-class portal view, registered the way core documents the
 * extension path: a `vulnhub_dash_views` entry so a page and a nav link appear,
 * and a `vulnhub_dash_render_view_docs` action so the portal hands rendering
 * here. The same body is also reachable from a "Documentation" admin section,
 * because that is where an administrator looks for the manual.
 *
 * @package VulnHub\Docs
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The docs view: registration, routing and rendering.
 */
final class VulnHub_Docs {

	/** The portal view name and its page slug. */
	public const VIEW = 'docs';
	public const SLUG = 'docs';

	/** Admin section slug. */
	public const SECTION = 'documentation';

	public static function init(): void {
		// Appear as a portal view (page + primary-nav link).
		add_filter( 'vulnhub_dash_views', array( __CLASS__, 'register_view' ) );
		add_action( 'vulnhub_dash_render_view_' . self::VIEW, array( __CLASS__, 'render' ) );

		// Appear as an admin section, so it is linked from Administration.
		add_filter( 'vulnhub_portal_sections', array( __CLASS__, 'register_section' ) );
		add_action( 'vulnhub_render_portal_section', array( __CLASS__, 'render_section' ) );

		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'assets' ) );

		// A safety net: if the page went missing (a trashed page, a fresh clone
		// where the activation hook never ran), recreate it once on a portal
		// admin's request rather than leaving a nav link that 404s.
		add_action( 'admin_init', array( __CLASS__, 'ensure_page' ) );
	}

	/* =================================================================
	 * Registration
	 * ============================================================== */

	/**
	 * @param array<string,array<string,mixed>> $views Portal views.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_view( array $views ): array {
		$views[ self::VIEW ] = array(
			'title' => __( 'Documentation', 'vulnhub' ),
			'slug'  => self::SLUG,
			'menu'  => __( 'Docs', 'vulnhub' ),
			// An open book.
			'icon'  => 'M4 5a2 2 0 012-2h5v16H6a2 2 0 00-2 2zM20 5a2 2 0 00-2-2h-5v16h5a2 2 0 012 2z',
		);

		return $views;
	}

	/**
	 * @param array<string,array<string,mixed>> $sections Admin sections.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_section( array $sections ): array {
		$sections[ self::SECTION ] = array(
			'label'   => __( 'Documentation', 'vulnhub' ),
			'cap'     => Caps::VIEW,
			'group'   => 'platform',
			'order'   => 80,
			'summary' => __( 'The handbook and developer wiki for this platform.', 'vulnhub' ),
		);

		return $sections;
	}

	/* =================================================================
	 * Pages & URLs
	 * ============================================================== */

	/** The portal URL of a doc, or of the wiki home when $slug is ''. */
	public static function url( string $slug = '' ): string {
		$args = '' !== $slug ? array( 'doc' => $slug ) : array();

		if ( class_exists( 'VulnHub_Dash_Portal' ) ) {
			return VulnHub_Dash_Portal::portal_url( self::VIEW, $args );
		}

		$pages = (array) get_option( 'vulnhub_dash_pages', array() );
		$base  = ! empty( $pages[ self::VIEW ] ) ? (string) get_permalink( (int) $pages[ self::VIEW ] ) : home_url( '/' );

		return $args ? add_query_arg( $args, $base ) : $base;
	}

	/** The slug requested in the URL, validated against the manifest. */
	private static function current_slug(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$slug = isset( $_GET['doc'] ) ? sanitize_key( wp_unslash( (string) $_GET['doc'] ) ) : '';

		return VulnHub_Docs_Content::exists( $slug ) ? $slug : VulnHub_Docs_Content::home_slug();
	}

	/**
	 * Create the wiki's portal page and remember its id.
	 *
	 * Mirrors the dashboard's own activation routine: a published page whose
	 * only content is the `[vulnhub_app view="docs"]` shortcode, wired into the
	 * `vulnhub_dash_pages` map that the navigation reads.
	 */
	public static function activate(): void {
		self::ensure_page();
	}

	public static function ensure_page(): void {
		$map = (array) get_option( 'vulnhub_dash_pages', array() );

		$existing = ! empty( $map[ self::VIEW ] ) ? get_post( (int) $map[ self::VIEW ] ) : null;
		if ( $existing && 'trash' !== $existing->post_status ) {
			return;
		}

		$page = get_page_by_path( self::SLUG );

		if ( $page ) {
			$id = (int) $page->ID;
		} else {
			$id = wp_insert_post(
				array(
					'post_title'     => __( 'Documentation', 'vulnhub' ),
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
	 * Assets
	 * ============================================================== */

	/**
	 * Cache-busting version for one bundled asset: the plugin version plus the
	 * file's own mtime.
	 *
	 * The plugin version alone moves only on release, so a CDN in front of the
	 * portal (which caches wp-content for hours) serves the old stylesheet to
	 * anyone who loaded the page recently -- new markup styled by old rules,
	 * which is worse than a plainly stale page. The mtime changes exactly when
	 * the bytes do. Mirrors VulnHub_Dash_App::asset_ver().
	 *
	 * @param string $rel Path relative to the plugin directory.
	 */
	private static function asset_ver( string $rel ): string {
		$mtime = @filemtime( VULNHUB_DOCS_DIR . $rel ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		return $mtime ? VULNHUB_DOCS_VERSION . '.' . $mtime : VULNHUB_DOCS_VERSION;
	}

	public static function assets(): void {
		$pages = (array) get_option( 'vulnhub_dash_pages', array() );
		$id    = (int) ( $pages[ self::VIEW ] ?? 0 );

		if ( ! $id || ! is_page( $id ) ) {
			return;
		}

		wp_enqueue_style( 'vulnhub-docs', VULNHUB_DOCS_URL . 'assets/docs.css', array(), self::asset_ver( 'assets/docs.css' ) );
		wp_enqueue_script( 'vulnhub-docs', VULNHUB_DOCS_URL . 'assets/docs.js', array(), self::asset_ver( 'assets/docs.js' ), true );
	}

	/* =================================================================
	 * Rendering — the portal view
	 * ============================================================== */

	public static function render(): void {
		$slug = self::current_slug();
		$meta = VulnHub_Docs_Content::meta( $slug );
		$body = VulnHub_Docs_Content::body_html( $slug );
		$nb   = VulnHub_Docs_Content::neighbours( $slug );

		echo '<div class="vh-docs" data-vh-docs>';

		self::render_sidebar( $slug );

		echo '<div class="vh-docs__body">';

		// Breadcrumb.
		printf(
			'<nav class="vh-docs__crumbs" aria-label="%s"><a href="%s">%s</a><span>/</span><span>%s</span><span>/</span><span aria-current="page">%s</span></nav>',
			esc_attr__( 'Breadcrumb', 'vulnhub' ),
			esc_url( self::url() ),
			esc_html__( 'Docs', 'vulnhub' ),
			esc_html( (string) ( $meta['group_label'] ?? '' ) ),
			esc_html( (string) ( $meta['title'] ?? '' ) )
		);

		echo '<article class="vh-docs__article">';
		printf(
			'<header class="vh-docs__head"><h1>%s</h1>%s</header>',
			esc_html( (string) ( $meta['title'] ?? '' ) ),
			'' !== (string) ( $meta['summary'] ?? '' ) ? '<p class="vh-docs__lede">' . esc_html( (string) $meta['summary'] ) . '</p>' : ''
		);

		if ( '' !== $body ) {
			echo $body; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- trusted plugin content.
		} else {
			printf( '<p class="vh-docs__empty">%s</p>', esc_html__( 'This page has not been written yet.', 'vulnhub' ) );
		}

		echo '</article>';

		// Prev / next.
		if ( $nb['prev'] || $nb['next'] ) {
			echo '<footer class="vh-docs__pager">';
			if ( $nb['prev'] ) {
				printf(
					'<a class="vh-docs__pager-link vh-docs__pager-link--prev" href="%s"><span>%s</span><strong>%s</strong></a>',
					esc_url( self::url( $nb['prev']['slug'] ) ),
					esc_html__( 'Previous', 'vulnhub' ),
					esc_html( $nb['prev']['title'] )
				);
			} else {
				echo '<span></span>';
			}
			if ( $nb['next'] ) {
				printf(
					'<a class="vh-docs__pager-link vh-docs__pager-link--next" href="%s"><span>%s</span><strong>%s</strong></a>',
					esc_url( self::url( $nb['next']['slug'] ) ),
					esc_html__( 'Next', 'vulnhub' ),
					esc_html( $nb['next']['title'] )
				);
			}
			echo '</footer>';
		}

		echo '</div>'; // .vh-docs__body

		// The "on this page" rail is populated from the article's headings by
		// docs.js, so it never drifts from the prose.
		printf(
			'<aside class="vh-docs__toc" aria-label="%s"><p class="vh-docs__toc-h">%s</p><nav data-vh-docs-toc></nav></aside>',
			esc_attr__( 'On this page', 'vulnhub' ),
			esc_html__( 'On this page', 'vulnhub' )
		);

		echo '</div>'; // .vh-docs
	}

	/**
	 * The grouped page list, with a client-side filter box.
	 */
	private static function render_sidebar( string $current ): void {
		echo '<aside class="vh-docs__sidebar" aria-label="' . esc_attr__( 'Documentation contents', 'vulnhub' ) . '">';

		printf(
			'<div class="vh-docs__search"><input type="search" data-vh-docs-search placeholder="%s" aria-label="%s" autocomplete="off"></div>',
			esc_attr__( 'Filter pages…', 'vulnhub' ),
			esc_attr__( 'Filter documentation pages', 'vulnhub' )
		);

		echo '<nav class="vh-docs__toclist">';

		foreach ( VulnHub_Docs_Content::groups() as $group ) {
			printf( '<p class="vh-docs__group">%s</p>', esc_html( (string) $group['label'] ) );
			echo '<ul>';

			foreach ( (array) $group['pages'] as $slug => $meta ) {
				$slug = (string) $slug;
				printf(
					'<li><a class="vh-docs__link%1$s" href="%2$s" data-vh-docs-item data-title="%3$s" data-summary="%4$s"%5$s>%6$s</a></li>',
					$slug === $current ? ' is-active' : '',
					esc_url( self::url( $slug ) ),
					esc_attr( (string) $meta['title'] ),
					esc_attr( (string) ( $meta['summary'] ?? '' ) ),
					$slug === $current ? ' aria-current="page"' : '',
					esc_html( (string) $meta['title'] )
				);
			}

			echo '</ul>';
		}

		echo '</nav>';
		printf( '<p class="vh-docs__nomatch" data-vh-docs-nomatch hidden>%s</p>', esc_html__( 'No pages match.', 'vulnhub' ) );
		echo '</aside>';
	}

	/* =================================================================
	 * Rendering — the admin section
	 * ============================================================== */

	public static function render_section( string $section ): void {
		if ( self::SECTION !== $section ) {
			return;
		}

		echo '<div class="vh-docs-admin">';
		printf( '<h2>%s</h2>', esc_html__( 'Documentation', 'vulnhub' ) );
		printf(
			'<p class="vh-sub">%s</p>',
			esc_html__( 'The full handbook and developer wiki lives inside the portal. It explains every screen and widget, what each number means, how the data is filtered, and how to extend the platform.', 'vulnhub' )
		);

		printf(
			'<p><a class="vh-btn vh-btn--primary" href="%s">%s</a></p>',
			esc_url( self::url() ),
			esc_html__( 'Open the documentation →', 'vulnhub' )
		);

		echo '<ul class="vh-docs-admin__list">';
		foreach ( VulnHub_Docs_Content::groups() as $group ) {
			printf(
				'<li><strong>%s</strong> — %s <a href="%s">%s</a></li>',
				esc_html( (string) $group['label'] ),
				esc_html( (string) ( $group['blurb'] ?? '' ) ),
				esc_url( self::url( (string) array_key_first( (array) $group['pages'] ) ) ),
				esc_html__( 'read →', 'vulnhub' )
			);
		}
		echo '</ul>';

		echo '</div>';
	}
}
