<?php
/**
 * The wiki's table of contents, and the loader for a page's body.
 *
 * The manifest is the single source of truth for what pages exist, what they
 * are called, and the order and grouping they appear in down the sidebar. Each
 * page's prose lives in its own file under `content/<slug>.html` — hand-authored
 * HTML, trusted because it ships with the plugin — so writing documentation is
 * editing a file, not editing PHP.
 *
 * The slug is the whole security boundary: a request only ever names a slug,
 * which is looked up in this manifest, and only a slug that resolves to a known
 * entry loads a file. There is no path built from user input, so there is no
 * traversal to defend against.
 *
 * @package VulnHub\Docs
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The documentation manifest and content loader.
 */
final class VulnHub_Docs_Content {

	/**
	 * The table of contents.
	 *
	 * Groups in display order; within each group, pages in display order. The
	 * first page of the first group is the wiki's home page.
	 *
	 * @return array<int,array{id:string,label:string,blurb:string,pages:array<string,array{title:string,summary:string}>}>
	 */
	public static function groups(): array {
		$groups = array(
			array(
				'id'    => 'start',
				'label' => __( 'Getting started', 'vulnhub' ),
				'blurb' => __( 'What VulnHub is, how to move around it, and the words it uses.', 'vulnhub' ),
				'pages' => array(
					'overview'    => array(
						'title'   => __( 'What VulnHub is', 'vulnhub' ),
						'summary' => __( 'The one-paragraph version, and how the pieces fit together.', 'vulnhub' ),
					),
					'portal-tour' => array(
						'title'   => __( 'A tour of the portal', 'vulnhub' ),
						'summary' => __( 'Every section in the navigation, and what it is for.', 'vulnhub' ),
					),
					'glossary'    => array(
						'title'   => __( 'Glossary', 'vulnhub' ),
						'summary' => __( 'Finding, asset, vulnerability, KEV, EPSS, route — defined once.', 'vulnhub' ),
					),
				),
			),
			array(
				'id'    => 'using',
				'label' => __( 'Using VulnHub', 'vulnhub' ),
				'blurb' => __( 'How to read every screen, widget and number, and how filtering works.', 'vulnhub' ),
				'pages' => array(
					'dashboard'    => array(
						'title'   => __( 'The dashboard, widget by widget', 'vulnhub' ),
						'summary' => __( 'What each widget shows, what every figure means, and where it drills to.', 'vulnhub' ),
					),
					'vulnerabilities' => array(
						'title'   => __( 'The Vulnerabilities list', 'vulnhub' ),
						'summary' => __( 'Every filter on the findings list, and what it selects.', 'vulnhub' ),
					),
					'assets'       => array(
						'title'   => __( 'Assets & owners', 'vulnhub' ),
						'summary' => __( 'The asset register, coverage, ownership and reachability.', 'vulnhub' ),
					),
					'tickets-exceptions' => array(
						'title'   => __( 'Tickets & exceptions', 'vulnhub' ),
						'summary' => __( 'Raising remediation work, and formally accepting a risk.', 'vulnhub' ),
					),
					'products-vendors' => array(
						'title'   => __( 'Products & vendors', 'vulnhub' ),
						'summary' => __( 'Exposure grouped by the software that carries it.', 'vulnhub' ),
					),
					'departments' => array(
						'title'   => __( 'Departments', 'vulnhub' ),
						'summary' => __( 'Enrich people from an Entra export, then filter and chart by department.', 'vulnhub' ),
					),
				),
			),
			array(
				'id'    => 'concepts',
				'label' => __( 'How the data works', 'vulnhub' ),
				'blurb' => __( 'The models behind the numbers — shared reading for users and developers.', 'vulnhub' ),
				'pages' => array(
					'data-sources'   => array(
						'title'   => __( 'Where the data comes from', 'vulnhub' ),
						'summary' => __( 'The connectors, what each one syncs, and how often.', 'vulnhub' ),
					),
					'classification' => array(
						'title'   => __( 'Routes, delivery & reachability', 'vulnhub' ),
						'summary' => __( 'How every finding is placed on an attack path.', 'vulnhub' ),
					),
					'scoring'        => array(
						'title'   => __( 'Severity, KEV, EPSS & VPR', 'vulnhub' ),
						'summary' => __( 'What "exploitable today" is built from.', 'vulnhub' ),
					),
					'lifecycle'      => array(
						'title'   => __( 'Finding lifecycle & scoping', 'vulnhub' ),
						'summary' => __( 'Open, fixed, reopened, excepted — and what "reportable" means.', 'vulnhub' ),
					),
				),
			),
			array(
				'id'    => 'dev',
				'label' => __( 'Developer guide', 'vulnhub' ),
				'blurb' => __( 'The architecture a new developer needs, and how to extend it safely.', 'vulnhub' ),
				'pages' => array(
					'architecture'    => array(
						'title'   => __( 'Architecture & plugins', 'vulnhub' ),
						'summary' => __( 'The fifteen plugins and how a request flows through them.', 'vulnhub' ),
					),
					'data-model'      => array(
						'title'   => __( 'The database schema', 'vulnhub' ),
						'summary' => __( 'Every table, and what its columns mean.', 'vulnhub' ),
					),
					'portal-framework' => array(
						'title'   => __( 'Portal, views & navigation', 'vulnhub' ),
						'summary' => __( 'Add a view, a nav link or an admin section end to end.', 'vulnhub' ),
					),
					'widget-framework' => array(
						'title'   => __( 'Building a dashboard widget', 'vulnhub' ),
						'summary' => __( 'The registry, layout, caching, CSV export — a working recipe.', 'vulnhub' ),
					),
					'extending'       => array(
						'title'   => __( 'Filters & extension points', 'vulnhub' ),
						'summary' => __( 'The hooks that let a plugin add data, filters and pages.', 'vulnhub' ),
					),
				),
			),
		);

		/**
		 * Filters the documentation table of contents.
		 *
		 * A plugin can add its own group, or add pages to an existing group by
		 * merging into it. A page's `slug` must resolve to a readable HTML file;
		 * a plugin providing its own pages should also answer
		 * `vulnhub_docs_body_<slug>` (see {@see body_html()}).
		 *
		 * @param array<int,array<string,mixed>> $groups The manifest.
		 */
		return (array) apply_filters( 'vulnhub_docs_groups', $groups );
	}

	/**
	 * Every page, flattened to slug => metadata (with its group id/label).
	 *
	 * @return array<string,array{title:string,summary:string,group:string,group_label:string}>
	 */
	public static function pages(): array {
		$out = array();

		foreach ( self::groups() as $group ) {
			foreach ( (array) $group['pages'] as $slug => $meta ) {
				$out[ (string) $slug ] = array(
					'title'       => (string) $meta['title'],
					'summary'     => (string) ( $meta['summary'] ?? '' ),
					'group'       => (string) $group['id'],
					'group_label' => (string) $group['label'],
				);
			}
		}

		return $out;
	}

	/** Does this slug name a real page? */
	public static function exists( string $slug ): bool {
		return '' !== $slug && isset( self::pages()[ $slug ] );
	}

	/** The home page: the first page of the first group. */
	public static function home_slug(): string {
		$pages = self::pages();

		return (string) ( array_key_first( $pages ) ?? 'overview' );
	}

	/**
	 * Metadata for one page, or null.
	 *
	 * @return array{title:string,summary:string,group:string,group_label:string}|null
	 */
	public static function meta( string $slug ): ?array {
		return self::pages()[ $slug ] ?? null;
	}

	/**
	 * The rendered body of a page.
	 *
	 * Content is the plugin's own trusted HTML, loaded from `content/<slug>.html`.
	 * A plugin contributing a page it authors elsewhere can answer the
	 * `vulnhub_docs_body_<slug>` filter instead of shipping a file.
	 */
	public static function body_html( string $slug ): string {
		if ( ! self::exists( $slug ) ) {
			return '';
		}

		$file = VULNHUB_DOCS_DIR . 'content/' . $slug . '.html';
		$html = is_readable( $file ) ? (string) file_get_contents( $file ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents

		/**
		 * Filters a documentation page's body HTML.
		 *
		 * @param string $html The trusted body markup.
		 * @param string $slug The page slug.
		 */
		return (string) apply_filters( 'vulnhub_docs_body_' . $slug, $html, $slug );
	}

	/**
	 * Previous and next pages in reading order, for the footer pager.
	 *
	 * @return array{prev:?array{slug:string,title:string},next:?array{slug:string,title:string}}
	 */
	public static function neighbours( string $slug ): array {
		$slugs = array_keys( self::pages() );
		$i     = array_search( $slug, $slugs, true );

		$at = static function ( $key ) use ( $slugs ): ?array {
			if ( ! isset( $slugs[ $key ] ) ) {
				return null;
			}
			$s = (string) $slugs[ $key ];

			return array( 'slug' => $s, 'title' => (string) ( self::meta( $s )['title'] ?? $s ) );
		};

		return array(
			'prev' => false === $i ? null : $at( $i - 1 ),
			'next' => false === $i ? null : $at( $i + 1 ),
		);
	}
}
