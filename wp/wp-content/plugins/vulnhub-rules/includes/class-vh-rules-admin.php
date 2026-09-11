<?php
/**
 * The portal screen for classification rules.
 *
 * Everything happens in the product's own admin area at /portal-admin/, never
 * in wp-admin: the section is registered on `vulnhub_portal_sections` and
 * rendered from `vulnhub_render_portal_section`, and every form posts back to
 * the same portal URL with a nonce and a real capability check.
 *
 * @package VulnHub\Rules
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Controller and form handler for the rules section.
 */
final class VulnHub_Rules_Admin {

	/**
	 * Section slug inside the portal admin area.
	 */
	public const SECTION = 'rules';

	/**
	 * Nonce action and field name.
	 */
	public const NONCE_ACTION = 'vulnhub_rules';
	public const NONCE_FIELD  = 'vh_rules_nonce';

	/**
	 * Validation error raised by the submission being rendered, if any.
	 *
	 * @var string
	 */
	private static string $error = '';

	/**
	 * The rule values that were submitted, so a failed save keeps them.
	 *
	 * @var array<string,mixed>
	 */
	private static array $submitted = array();

	/**
	 * The action of the request currently being rendered.
	 *
	 * @var string
	 */
	private static string $action = '';

	/**
	 * Register hooks.
	 */
	public static function init(): void {
		add_filter( 'vulnhub_portal_sections', array( __CLASS__, 'register_section' ) );
		add_action( 'vulnhub_render_portal_section', array( __CLASS__, 'render_section' ) );
		add_action( 'template_redirect', array( __CLASS__, 'handle' ), 5 );
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'assets' ) );
	}

	/**
	 * Make sure the portal offers a Rules section.
	 *
	 * The dashboard plugin already declares it; this only fills the gap when
	 * it does not, and never overwrites another plugin's definition.
	 *
	 * @param array<string,array<string,mixed>> $sections Section definitions.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_section( array $sections ): array {
		if ( ! isset( $sections[ self::SECTION ] ) ) {
			$sections[ self::SECTION ] = array(
				'label'   => __( 'Rules', 'vulnhub' ),
				'cap'     => Caps::MANAGE,
				'group'   => 'data',
				'order'   => 30,
				'summary' => __( 'Categorise and prioritise assets, and decide who owns what.', 'vulnhub' ),
			);
		}

		return $sections;
	}

	/**
	 * Render the section when the portal asks for it.
	 *
	 * @param string $section Section slug being rendered.
	 */
	public static function render_section( string $section ): void {
		if ( self::SECTION !== $section ) {
			return;
		}
		if ( ! current_user_can( Caps::MANAGE ) ) {
			return;
		}

		include VULNHUB_RULES_DIR . 'admin/views/rules.php';
	}

	/**
	 * Load the screen's CSS and JS on the rules section only.
	 */
	public static function assets(): void {
		if ( ! class_exists( 'VulnHub_Dash_App' ) || ! class_exists( 'VulnHub_Dash_Portal' ) ) {
			return;
		}
		if ( VulnHub_Dash_Portal::ADMIN_VIEW !== VulnHub_Dash_App::view_for_post( get_post() ) ) {
			return;
		}
		if ( self::SECTION !== VulnHub_Dash_Portal::current_section() ) {
			return;
		}

		wp_enqueue_style( 'vulnhub-rules', VULNHUB_RULES_URL . 'assets/rules.css', array( 'vulnhub-app' ), VULNHUB_RULES_VERSION );
		wp_enqueue_script( 'vulnhub-rules', VULNHUB_RULES_URL . 'assets/rules.js', array(), VULNHUB_RULES_VERSION, true );
	}

	/* -----------------------------------------------------------------
	 * Form handling
	 * --------------------------------------------------------------- */

	/**
	 * Handle a submission from the rules screen.
	 *
	 * Runs on template_redirect so a redirect is still possible: every action
	 * that changes state redirects (post/redirect/get), while "preview" falls
	 * through and is rendered by the view without touching anything.
	 */
	public static function handle(): void {
		if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) {
			return;
		}
		if ( ! isset( $_POST['vh_rules_action'] ) ) {
			return;
		}

		$nonce = isset( $_POST[ self::NONCE_FIELD ] ) ? sanitize_text_field( wp_unslash( $_POST[ self::NONCE_FIELD ] ) ) : '';

		if ( ! wp_verify_nonce( $nonce, self::NONCE_ACTION ) ) {
			wp_die( esc_html__( 'That form has expired. Go back, reload the page and try again.', 'vulnhub' ), 403 );
		}
		if ( ! current_user_can( Caps::MANAGE ) ) {
			wp_die( esc_html__( 'You do not have permission to manage classification rules.', 'vulnhub' ), 403 );
		}

		$action       = sanitize_key( wp_unslash( $_POST['vh_rules_action'] ) );
		self::$action = $action;

		switch ( $action ) {
			case 'preview':
				self::$submitted = self::collect_rule_input();
				return;

			case 'save':
				self::$submitted = self::collect_rule_input();

				$result = VulnHub_Rules_Repo::save( self::$submitted );

				if ( is_wp_error( $result ) ) {
					self::$error = (string) $result->get_error_message();
					return;
				}

				self::redirect( array( 'vh_notice' => 'saved' ) );
				return;

			case 'delete':
				VulnHub_Rules_Repo::delete( self::posted_int( 'rule_id' ) );
				self::redirect( array( 'vh_notice' => 'deleted' ) );
				return;

			case 'toggle':
				VulnHub_Rules_Repo::set_enabled( self::posted_int( 'rule_id' ), 1 === self::posted_int( 'enabled' ) );
				self::redirect( array( 'vh_notice' => 'toggled' ) );
				return;

			case 'move':
				VulnHub_Rules_Repo::move( self::posted_int( 'rule_id' ), self::posted_int( 'delta' ) < 0 ? -1 : 1 );
				self::redirect( array( 'vh_notice' => 'reordered' ) );
				return;

			case 'order':
				$order = isset( $_POST['order'] ) ? sanitize_text_field( wp_unslash( $_POST['order'] ) ) : '';
				$ids   = array_filter( array_map( 'intval', explode( ',', $order ) ) );

				if ( $ids ) {
					VulnHub_Rules_Repo::set_order( $ids );
				}

				self::redirect( array( 'vh_notice' => 'reordered' ) );
				return;

			case 'apply':
				$result = VulnHub_Rules_Engine::instance()->run( array( 'trigger' => 'manual' ) );

				self::redirect(
					array(
						'vh_notice'    => 'applied',
						'vh_processed' => (string) $result['processed'],
						'vh_matched'   => (string) $result['matched'],
						'vh_changed'   => (string) $result['changed'],
					)
				);
				return;
		}
	}

	/**
	 * An integer field from the current POST.
	 *
	 * The nonce has already been verified in handle() before this is reached.
	 *
	 * @param string $key Field name.
	 */
	private static function posted_int( string $key ): int {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		return isset( $_POST[ $key ] ) ? (int) $_POST[ $key ] : 0;
	}

	/**
	 * Pull the rule editor's fields out of the current POST.
	 *
	 * Values are only shaped here; they are validated and sanitised against
	 * the engine vocabulary in VulnHub_Rules_Repo::prepare().
	 *
	 * @return array<string,mixed>
	 */
	private static function collect_rule_input(): array {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$raw = isset( $_POST['rule'] ) && is_array( $_POST['rule'] ) ? (array) wp_unslash( $_POST['rule'] ) : array();

		$input = array(
			'id'                   => isset( $raw['id'] ) ? (int) $raw['id'] : 0,
			'name'                 => (string) ( $raw['name'] ?? '' ),
			'description'          => (string) ( $raw['description'] ?? '' ),
			'enabled'              => ! empty( $raw['enabled'] ) ? 1 : 0,
			'match_type'           => (string) ( $raw['match_type'] ?? 'all' ),
			'stop_processing'      => ! empty( $raw['stop_processing'] ) ? 1 : 0,
			'set_environment'      => (string) ( $raw['set_environment'] ?? '' ),
			'set_criticality'      => (string) ( $raw['set_criticality'] ?? '' ),
			'set_asset_type'       => (string) ( $raw['set_asset_type'] ?? '' ),
			'set_business_service' => (string) ( $raw['set_business_service'] ?? '' ),
			'set_priority_weight'  => (string) ( $raw['set_priority_weight'] ?? '' ),
			'conditions'           => array(),
		);

		foreach ( (array) ( $raw['conditions'] ?? array() ) as $condition ) {
			if ( ! is_array( $condition ) ) {
				continue;
			}

			$input['conditions'][] = array(
				'match_field'    => (string) ( $condition['match_field'] ?? '' ),
				'field_key'      => (string) ( $condition['field_key'] ?? '' ),
				'match_operator' => (string) ( $condition['match_operator'] ?? '' ),
				'match_value'    => (string) ( $condition['match_value'] ?? '' ),
			);
		}

		return $input;
	}

	/**
	 * Send the browser back to the rules screen.
	 *
	 * @param array<string,string> $args Query arguments to carry a notice.
	 */
	private static function redirect( array $args ): void {
		wp_safe_redirect( self::section_url( $args ) );
		exit;
	}

	/**
	 * URL of the rules section, optionally with extra query arguments.
	 *
	 * @param array<string,string> $args Query arguments.
	 */
	public static function section_url( array $args = array() ): string {
		$base = array( 'section' => self::SECTION );

		if ( class_exists( 'VulnHub_Dash_Portal' ) ) {
			return VulnHub_Dash_Portal::portal_url( VulnHub_Dash_Portal::ADMIN_VIEW, array_merge( $base, $args ) );
		}

		return add_query_arg( array_merge( $base, $args ), home_url( '/portal-admin/' ) );
	}

	/* -----------------------------------------------------------------
	 * State the view reads
	 * --------------------------------------------------------------- */

	/**
	 * Validation error from the submission being rendered.
	 */
	public static function error(): string {
		return self::$error;
	}

	/**
	 * Is the request being rendered a preview?
	 */
	public static function is_preview(): bool {
		return 'preview' === self::$action && '' === self::$error;
	}

	/**
	 * The rule currently in the editor.
	 *
	 * Order of preference: what was just submitted (so a failed save or a
	 * preview keeps every field), then ?edit=<id>, then a blank rule.
	 *
	 * @return array<string,mixed>
	 */
	public static function editing_rule(): array {
		if ( self::$submitted ) {
			return self::rule_for_display( self::$submitted );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$edit = isset( $_GET['edit'] ) ? (int) $_GET['edit'] : 0;

		if ( $edit > 0 ) {
			$rule = VulnHub_Rules_Repo::rule( $edit );
			if ( $rule ) {
				return $rule;
			}
		}

		return VulnHub_Rules_Repo::blank_rule();
	}

	/**
	 * Shape submitted values like a stored rule so the form can re-render them.
	 *
	 * @param array<string,mixed> $input Collected form values.
	 * @return array<string,mixed>
	 */
	private static function rule_for_display( array $input ): array {
		$rule = array_merge( VulnHub_Rules_Repo::blank_rule(), $input );

		$rule['conditions'] = array();

		foreach ( (array) ( $input['conditions'] ?? array() ) as $condition ) {
			$rule['conditions'][] = array(
				'match_field'    => sanitize_key( (string) ( $condition['match_field'] ?? '' ) ),
				'field_key'      => sanitize_text_field( (string) ( $condition['field_key'] ?? '' ) ),
				'match_operator' => sanitize_key( (string) ( $condition['match_operator'] ?? '' ) ),
				'match_value'    => sanitize_text_field( (string) ( $condition['match_value'] ?? '' ) ),
			);
		}

		return $rule;
	}

	/**
	 * Preview results for the submitted rule, or null when not previewing.
	 *
	 * Nothing here writes: the engine is asked what it would do, and the
	 * answer is rendered.
	 *
	 * @return array{matched:int,scanned:int,changes:int,rows:array<int,array<string,mixed>>}|null
	 */
	public static function preview(): ?array {
		if ( ! self::is_preview() ) {
			return null;
		}

		$draft = VulnHub_Rules_Repo::draft( self::$submitted );

		if ( is_wp_error( $draft ) ) {
			self::$error = (string) $draft->get_error_message();
			return null;
		}

		return VulnHub_Rules_Engine::instance()->preview( array( $draft ) );
	}

	/**
	 * The notice to show, translated from the redirect's query argument.
	 *
	 * @return array{tone:string,text:string}|null
	 */
	public static function notice(): ?array {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$key = isset( $_GET['vh_notice'] ) ? sanitize_key( wp_unslash( $_GET['vh_notice'] ) ) : '';

		if ( '' === $key ) {
			return null;
		}

		switch ( $key ) {
			case 'saved':
				return array(
					'tone' => 'good',
					'text' => __( 'Rule saved. It takes effect on the next run — use Apply now to classify the estate immediately.', 'vulnhub' ),
				);

			case 'deleted':
				return array(
					'tone' => 'good',
					'text' => __( 'Rule deleted.', 'vulnhub' ),
				);

			case 'toggled':
				return array(
					'tone' => 'good',
					'text' => __( 'Rule updated.', 'vulnhub' ),
				);

			case 'reordered':
				return array(
					'tone' => 'good',
					'text' => __( 'Evaluation order updated.', 'vulnhub' ),
				);

			case 'applied':
				$processed = isset( $_GET['vh_processed'] ) ? (int) $_GET['vh_processed'] : 0;
				$matched   = isset( $_GET['vh_matched'] ) ? (int) $_GET['vh_matched'] : 0;
				$changed   = isset( $_GET['vh_changed'] ) ? (int) $_GET['vh_changed'] : 0;

				return array(
					'tone' => 'good',
					'text' => sprintf(
						/* translators: 1: assets examined, 2: assets matched by a rule, 3: assets changed. */
						__( 'Classification run complete: %1$d assets examined, %2$d matched a rule, %3$d changed.', 'vulnhub' ),
						$processed,
						$matched,
						$changed
					),
				);
		}
		// phpcs:enable

		return null;
	}

	/**
	 * Summary of the last engine run, for the header.
	 *
	 * @return array<string,mixed>
	 */
	public static function last_run(): array {
		return (array) get_option( 'vulnhub_rules_last_run', array() );
	}
}

