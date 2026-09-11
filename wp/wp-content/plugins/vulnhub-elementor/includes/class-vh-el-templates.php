<?php
/**
 * Builds the starting Elementor content: a Theme Builder header and footer,
 * and two Elementor-native pages made of VulnHub widgets.
 *
 * @package VulnHub\Elementor
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Seeds Elementor documents, once, and then gets out of the way.
 *
 * Everything here is a *starting point*, not a managed asset. Once a template
 * exists this class never touches it again -- the whole reason for building
 * the chrome in Elementor is that somebody can change it without a deploy, and
 * a seeder that keeps reasserting its own version would make that impossible.
 * The option below is what makes it a one-off; deleting it re-seeds.
 */
final class VulnHub_El_Templates {

	private const OPTION = 'vulnhub_elementor_seeded';
	private const SEED_VERSION = 2;

	public static function init(): void {
		add_action( 'admin_post_vulnhub_seed_elementor', array( __CLASS__, 'handle_seed' ) );
		add_action( 'init', array( __CLASS__, 'maybe_seed' ), 20 );
		add_filter( 'vulnhub_portal_sections', array( __CLASS__, 'section' ) );
		add_action( 'vulnhub_render_portal_section', array( __CLASS__, 'render_section' ) );
		add_filter( 'vulnhub_portal_nav_extra', array( __CLASS__, 'nav_links' ) );
	}

	/**
	 * Put the two seeded Elementor pages in the portal's navigation.
	 *
	 * A page nobody can find is a page nobody edits, and the point of these
	 * two is that they are the editable examples.
	 *
	 * @param array<int,array<string,mixed>> $links Existing extra links.
	 * @return array<int,array<string,mixed>>
	 */
	public static function nav_links( array $links ): array {
		$docs    = (array) get_option( 'vulnhub_elementor_documents', array() );
		$current = get_queried_object_id();

		$icons = array(
			'overview' => 'M12 3l7 3v5c0 4.4-3 8.4-7 9-4-.6-7-4.6-7-9V6zM9 12l2 2 4-4',
			'estate'   => 'M16 21v-2a4 4 0 00-4-4H6a4 4 0 00-4 4v2M9 11a4 4 0 100-8 4 4 0 000 8M22 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75',
		);

		foreach ( array( 'overview', 'estate' ) as $key ) {
			$id = (int) ( $docs[ $key ] ?? 0 );

			if ( ! $id || 'publish' !== get_post_status( $id ) ) {
				continue;
			}

			$links[] = array(
				'label'  => get_the_title( $id ),
				'url'    => (string) get_permalink( $id ),
				'icon'   => $icons[ $key ],
				'active' => $current === $id,
			);
		}

		return $links;
	}

	/**
	 * An Appearance section in the portal's own administration.
	 *
	 * The whole point of the brief was that nothing about this product should
	 * require a trip to wp-admin, and "edit the header" is no exception.
	 *
	 * @param array<string,array<string,mixed>> $sections Existing sections.
	 * @return array<string,array<string,mixed>>
	 */
	public static function section( array $sections ): array {
		$sections['appearance'] = array(
			'label'   => __( 'Appearance', 'vulnhub' ),
			'cap'     => \VulnHub\Core\Caps::MANAGE,
			'group'   => 'platform',
			'order'   => 65,
			'summary' => __( 'The header, the footer and the Elementor pages built on VulnHub data.', 'vulnhub' ),
		);

		return $sections;
	}

	/**
	 * @param string $section Section being drawn.
	 */
	public static function render_section( string $section ): void {
		if ( 'appearance' !== $section ) {
			return;
		}

		$docs      = (array) get_option( 'vulnhub_elementor_documents', array() );
		$can_edit  = current_user_can( 'edit_pages' );
		$labels    = array(
			'header'   => __( 'Site header', 'vulnhub' ),
			'footer'   => __( 'Site footer', 'vulnhub' ),
			'overview' => __( 'Security overview page', 'vulnhub' ),
			'estate'   => __( 'Estate and ownership page', 'vulnhub' ),
		);

		echo '<div class="vh-card">';
		echo '<p class="vh-sub">' . esc_html__(
			'These are built with Elementor. Editing one changes the product for everybody, immediately.',
			'vulnhub'
		) . '</p>';

		echo '<table class="vh-table"><thead><tr>'
			. '<th scope="col">' . esc_html__( 'What', 'vulnhub' ) . '</th>'
			. '<th scope="col">' . esc_html__( 'Name', 'vulnhub' ) . '</th>'
			. '<th scope="col">' . esc_html__( 'Actions', 'vulnhub' ) . '</th>'
			. '</tr></thead><tbody>';

		foreach ( $labels as $key => $label ) {
			$id    = (int) ( $docs[ $key ] ?? 0 );
			$post  = $id ? get_post( $id ) : null;

			echo '<tr><td>' . esc_html( $label ) . '</td>';

			if ( ! $post ) {
				echo '<td colspan="2"><span class="vh-muted">' . esc_html__( 'Not present', 'vulnhub' ) . '</span></td></tr>';
				continue;
			}

			echo '<td>' . esc_html( get_the_title( $post ) ) . '</td><td>';

			if ( $can_edit ) {
				printf(
					'<a class="vh-btn vh-btn--ghost" href="%s">%s</a> ',
					esc_url( admin_url( 'post.php?post=' . $id . '&action=elementor' ) ),
					esc_html__( 'Edit in Elementor', 'vulnhub' )
				);
			}

			$permalink = 'page' === $post->post_type ? get_permalink( $post ) : '';

			if ( $permalink ) {
				printf(
					'<a class="vh-btn vh-btn--ghost" href="%s">%s</a>',
					esc_url( $permalink ),
					esc_html__( 'View', 'vulnhub' )
				);
			}

			echo '</td></tr>';
		}

		echo '</tbody></table>';

		printf(
			'<form method="post" action="%s"><input type="hidden" name="action" value="vulnhub_seed_elementor">%s'
			. '<p><button type="submit" class="vh-btn">%s</button></p></form>',
			esc_url( admin_url( 'admin-post.php' ) ),
			wp_nonce_field( 'vulnhub_seed_elementor', '_wpnonce', true, false ),
			esc_html__( 'Recreate anything missing', 'vulnhub' )
		);

		echo '</div>';
	}

	public static function maybe_seed(): void {
		if ( (int) get_option( self::OPTION, 0 ) >= self::SEED_VERSION ) {
			return;
		}
		self::seed();
	}

	/**
	 * A button on the integrations screen for anyone who deleted the starting
	 * templates and wants them back.
	 */
	public static function handle_seed(): void {
		if ( ! current_user_can( \VulnHub\Core\Caps::MANAGE ) ) {
			wp_die( esc_html__( 'You are not allowed to do that.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'vulnhub_seed_elementor' );

		delete_option( self::OPTION );
		self::seed();

		wp_safe_redirect( wp_get_referer() ?: home_url( '/' ) );
		exit;
	}

	public static function seed(): void {
		$made = array();

		$made['header'] = self::document(
			'header',
			__( 'VulnHub header', 'vulnhub' ),
			self::header_data(),
			array( 'include/general' )
		);

		$made['footer'] = self::document(
			'footer',
			__( 'VulnHub footer', 'vulnhub' ),
			self::footer_data(),
			array( 'include/general' )
		);

		$made['overview'] = self::page(
			'vulnhub-overview',
			__( 'Security overview', 'vulnhub' ),
			self::overview_data()
		);

		$made['estate'] = self::page(
			'vulnhub-estate',
			__( 'Estate and ownership', 'vulnhub' ),
			self::estate_data()
		);

		update_option( self::OPTION, self::SEED_VERSION, false );
		update_option( 'vulnhub_elementor_documents', array_filter( $made ), false );

		self::refresh_conditions();
	}

	/**
	 * Elementor Pro keeps an option-level index of which template answers
	 * which location. Writing the meta without refreshing it produces a
	 * template that exists, claims a condition, and never displays.
	 */
	private static function refresh_conditions(): void {
		if ( ! class_exists( '\ElementorPro\Modules\ThemeBuilder\Module' ) ) {
			return;
		}

		try {
			\ElementorPro\Modules\ThemeBuilder\Module::instance()
				->get_conditions_manager()
				->get_cache()
				->regenerate();
		} catch ( \Throwable $e ) {
			vulnhub()->logger->audit(
				'elementor.conditions_refresh_failed',
				array( 'message' => $e->getMessage() )
			);
		}
	}

	/* =================================================================
	 * Document creation
	 * ============================================================== */

	/**
	 * @param string               $type       header|footer.
	 * @param string               $title      Post title.
	 * @param array<int,mixed>     $data       Elementor element tree.
	 * @param array<int,string>    $conditions Display conditions.
	 */
	private static function document( string $type, string $title, array $data, array $conditions ): int {
		$existing = get_posts(
			array(
				'post_type'      => 'elementor_library',
				'post_status'    => 'any',
				'posts_per_page' => 1,
				'fields'         => 'ids',
				'meta_query'     => array( // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_query
					array(
						'key'   => '_elementor_template_type',
						'value' => $type,
					),
					array(
						'key'   => '_vulnhub_seeded',
						'value' => '1',
					),
				),
			)
		);

		if ( $existing ) {
			self::refresh_if_untouched( (int) $existing[0], $data );
			return (int) $existing[0];
		}

		$id = wp_insert_post(
			array(
				'post_type'   => 'elementor_library',
				'post_status' => 'publish',
				'post_title'  => $title,
			)
		);

		if ( ! $id || is_wp_error( $id ) ) {
			return 0;
		}

		$id = (int) $id;

		wp_set_object_terms( $id, $type, 'elementor_library_type' );
		self::write_elementor_meta( $id, $data, $type );
		update_post_meta( $id, '_elementor_conditions', $conditions );
		update_post_meta( $id, '_vulnhub_seeded', '1' );

		return $id;
	}

	/**
	 * @param array<int,mixed> $data Elementor element tree.
	 */
	private static function page( string $slug, string $title, array $data ): int {
		$existing = get_page_by_path( $slug );

		if ( $existing ) {
			self::refresh_if_untouched( (int) $existing->ID, $data );
			return (int) $existing->ID;
		}

		$id = wp_insert_post(
			array(
				'post_type'   => 'page',
				'post_status' => 'publish',
				'post_title'  => $title,
				'post_name'   => $slug,
			)
		);

		if ( ! $id || is_wp_error( $id ) ) {
			return 0;
		}

		$id = (int) $id;
		self::write_elementor_meta( $id, $data, 'wp-page' );
		update_post_meta( $id, '_vulnhub_seeded', '1' );

		return $id;
	}

	/**
	 * The four meta keys that make a post an Elementor document. Miss
	 * `_elementor_edit_mode` and the page renders its (empty) post_content
	 * instead, which looks exactly like a broken template.
	 *
	 * @param array<int,mixed> $data Element tree.
	 */
	/**
	 * Bring a seeded document up to the current seed -- but only if nobody
	 * has touched it.
	 *
	 * A hash of exactly what the seeder last wrote is stored alongside the
	 * document. If the current content still hashes to that, the document is
	 * untouched and it is safe to replace; if it does not, somebody has edited
	 * it in Elementor and we leave it entirely alone, even though that means
	 * they miss whatever the new seed added. Silently overwriting a person's
	 * header is a far worse failure than a missing button.
	 *
	 * @param array<int,mixed> $data New element tree.
	 */
	private static function refresh_if_untouched( int $id, array $data ): void {
		$stored  = (string) get_post_meta( $id, '_vulnhub_seed_hash', true );
		$current = (string) get_post_meta( $id, '_elementor_data', true );

		if ( '' === $stored || md5( $current ) !== $stored ) {
			return;
		}

		$type = (string) get_post_meta( $id, '_elementor_template_type', true );
		self::write_elementor_meta( $id, $data, $type ?: 'wp-page' );

		if ( class_exists( '\\Elementor\\Plugin' ) ) {
			// The document's compiled CSS is keyed on its content; leaving the
			// old file in place shows the new markup with the old rules.
			\Elementor\Plugin::$instance->files_manager->clear_cache();
		}
	}

	private static function write_elementor_meta( int $id, array $data, string $type ): void {
		update_post_meta( $id, '_elementor_edit_mode', 'builder' );
		update_post_meta( $id, '_elementor_template_type', $type );
		update_post_meta( $id, '_elementor_version', defined( 'ELEMENTOR_VERSION' ) ? ELEMENTOR_VERSION : '3.0.0' );
		// wp_slash, because update_post_meta unslashes and JSON is full of
		// backslashes the moment a widget setting contains a quote.
		$json = (string) wp_json_encode( $data );
		update_post_meta( $id, '_elementor_data', wp_slash( $json ) );
		// What the seeder wrote, so a later seed can tell "untouched" from
		// "edited by a person" without guessing.
		update_post_meta( $id, '_vulnhub_seed_hash', md5( $json ) );
	}

	/* =================================================================
	 * Element trees
	 *
	 * Hand-written rather than exported from the editor so they stay
	 * readable in review. Ids must be unique within a document; Elementor
	 * only cares that they are 7-character hex-ish strings.
	 * ============================================================== */

	/**
	 * @param array<string,mixed> $settings Widget settings.
	 * @return array<string,mixed>
	 */
	private static function widget( string $id, string $type, array $settings = array() ): array {
		return array(
			'id'         => $id,
			'elType'     => 'widget',
			'widgetType' => $type,
			'settings'   => $settings,
			'elements'   => array(),
		);
	}

	/**
	 * @param array<int,mixed>    $children Child elements.
	 * @param array<string,mixed> $settings Container settings.
	 * @return array<string,mixed>
	 */
	private static function container( string $id, array $children, array $settings = array() ): array {
		return array(
			'id'       => $id,
			'elType'   => 'container',
			'settings' => $settings,
			'elements' => $children,
		);
	}

	/** @return array<int,mixed> */
	private static function header_data(): array {
		return array(
			self::container(
				'vhhdr01',
				array(
					self::widget( 'vhhdr02', 'vulnhub-brand', array( 'vh_show_org' => 'yes', 'vh_link' => 'yes' ) ),
					self::widget( 'vhhdr03', 'vulnhub-nav', array( 'vh_icons' => 'yes' ) ),
					self::widget( 'vhhdr05', 'vulnhub-mode' ),
					self::widget( 'vhhdr06', 'vulnhub-theme-toggle' ),
					self::widget( 'vhhdr04', 'vulnhub-account', array( 'vh_admin_link' => 'yes' ) ),
				),
				array(
					'content_width'   => 'full',
					'flex_direction'  => 'row',
					'flex_align_items' => 'center',
					'flex_gap'        => array(
						'size' => 24,
						'unit' => 'px',
					),
					'padding'         => array(
						'unit'     => 'px',
						'top'      => '10',
						'right'    => '20',
						'bottom'   => '10',
						'left'     => '20',
						'isLinked' => false,
					),
				)
			),
		);
	}

	/** @return array<int,mixed> */
	private static function footer_data(): array {
		return array(
			self::container(
				'vhftr01',
				array(
					self::widget(
						'vhftr02',
						'vulnhub-freshness',
						array( 'vh_sources' => array( 'tenable', 'cmdb', 'intune' ) )
					),
				),
				array(
					'content_width'  => 'full',
					'flex_direction' => 'row',
					'padding'        => array(
						'unit'     => 'px',
						'top'      => '16',
						'right'    => '20',
						'bottom'   => '16',
						'left'     => '20',
						'isLinked' => false,
					),
				)
			),
		);
	}

	/** @return array<int,mixed> */
	private static function overview_data(): array {
		return array(
			self::container(
				'vhovr01',
				array(
					self::widget(
						'vhovr02',
						'vulnhub-kpi',
						array(
							'vh_heading' => __( 'Where we stand today', 'vulnhub' ),
							'vh_tiles'   => array(
								array( '_id' => 'vhkpi1', 'metric' => 'critical' ),
								array( '_id' => 'vhkpi2', 'metric' => 'overdue' ),
								array( '_id' => 'vhkpi3', 'metric' => 'coverage_percent' ),
								array( '_id' => 'vhkpi4', 'metric' => 'coverage_gaps' ),
								array( '_id' => 'vhkpi5', 'metric' => 'users_missing' ),
								array( '_id' => 'vhkpi6', 'metric' => 'verify_failed' ),
							),
						)
					),
				)
			),
			self::container(
				'vhovr03',
				array(
					self::widget(
						'vhovr04',
						'vulnhub-coverage',
						array(
							'vh_heading'      => __( 'Tenable coverage by device type', 'vulnhub' ),
							'vh_dimension'    => 'asset_type',
							'vh_view'         => 'bars',
							'vh_limit'        => 10,
							'vh_show_summary' => 'yes',
						)
					),
					self::widget(
						'vhovr05',
						'vulnhub-coverage',
						array(
							'vh_heading'      => __( 'Coverage states', 'vulnhub' ),
							'vh_view'         => 'donut',
							'vh_show_summary' => '',
						)
					),
				),
				array(
					'flex_direction' => 'row',
					'flex_gap'       => array(
						'size' => 20,
						'unit' => 'px',
					),
				)
			),
			self::container(
				'vhovr06',
				array(
					self::widget(
						'vhovr07',
						'vulnhub-findings',
						array(
							'vh_heading'  => __( 'Critical findings past their SLA', 'vulnhub' ),
							'vh_severity' => 'critical',
							'vh_overdue'  => 'yes',
							'vh_limit'    => 10,
						)
					),
				)
			),
			self::container(
				'vhovr08',
				array(
					self::widget(
						'vhovr09',
						'vulnhub-coverage-gaps',
						array(
							'vh_heading' => __( 'Assets Tenable is not scanning', 'vulnhub' ),
							'vh_limit'   => 15,
						)
					),
				)
			),
		);
	}

	/** @return array<int,mixed> */
	private static function estate_data(): array {
		return array(
			self::container(
				'vhest01',
				array(
					self::widget(
						'vhest02',
						'vulnhub-devices',
						array(
							'vh_heading'     => __( 'Device information', 'vulnhub' ),
							'vh_orderby'     => 'risk_score',
							'vh_limit'       => 25,
							'vh_identifiers' => 'yes',
						)
					),
				)
			),
			self::container(
				'vhest03',
				array(
					self::widget(
						'vhest04',
						'vulnhub-teams',
						array(
							'vh_heading'    => __( 'Who owns what', 'vulnhub' ),
							'vh_columns'    => '3',
							'vh_hide_empty' => 'yes',
						)
					),
				)
			),
			self::container(
				'vhest05',
				array(
					self::widget(
						'vhest06',
						'vulnhub-panel',
						array(
							'vh_panel' => 'ownership_gaps',
							'vh_width' => '12',
						)
					),
				)
			),
		);
	}
}

