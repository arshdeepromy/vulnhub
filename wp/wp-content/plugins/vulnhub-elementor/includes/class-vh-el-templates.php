<?php
/**
 * Builds the starting Elementor content: a Theme Builder header and footer.
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
			'summary' => __( 'The header and footer, built with Elementor.', 'vulnhub' ),
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
}
