<?php
/**
 * Shared behaviour for every VulnHub Elementor widget.
 *
 * @package VulnHub\Elementor
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use VulnHub\Core\Caps;

/**
 * The base every VulnHub widget extends.
 *
 * Three things live here rather than in each widget.
 *
 * 1. Capability. These widgets render production vulnerability data. A page
 *    built out of them can be published to any URL, so the *widget* -- not the
 *    page -- is what refuses to draw for somebody without `vulnhub_view`. In
 *    the editor we still draw, otherwise the person laying the page out sees
 *    twelve grey boxes.
 * 2. Assets. The portal's stylesheet is only enqueued on portal views, so an
 *    Elementor page carrying a VulnHub widget has to ask for it explicitly.
 * 3. The empty state. Elementor's own convention is that a widget with nothing
 *    to show says so in the editor and stays silent on the front end.
 */
abstract class VulnHub_El_Widget_Base extends \Elementor\Widget_Base {

	public const CATEGORY = VulnHub_El_Widgets::CATEGORY;

	public function get_categories(): array {
		return array( self::CATEGORY );
	}

	public function get_icon(): string {
		return 'eicon-shield-check';
	}

	public function get_keywords(): array {
		return array( 'vulnhub', 'security', 'vulnerability', 'tenable', 'asset' );
	}

	/**
	 * The portal's stylesheet and chart styles, so a widget dropped on to a
	 * theme page looks the same as it does inside the app.
	 */
	public function get_style_depends(): array {
		return array( 'vulnhub-app', 'vulnhub-elementor' );
	}

	public function get_script_depends(): array {
		return array( 'vulnhub-app' );
	}

	/** True while Elementor is drawing the editor preview or a template preview. */
	protected function in_editor(): bool {
		return \Elementor\Plugin::$instance->editor->is_edit_mode()
			|| \Elementor\Plugin::$instance->preview->is_preview_mode();
	}

	/**
	 * Whether the person looking at this page may see VulnHub data at all.
	 */
	protected function may_view(): bool {
		return current_user_can( Caps::VIEW ) || current_user_can( 'manage_options' );
	}

	/**
	 * A single place for "you cannot see this", so the wording and the markup
	 * never drift between eighteen widgets.
	 */
	protected function render_denied(): void {
		if ( ! $this->in_editor() ) {
			return;
		}
		printf(
			'<div class="vh-el__notice"><p>%s</p></div>',
			esc_html__( 'This widget shows live VulnHub data. Visitors without access to the security portal will not see it.', 'vulnhub' )
		);
	}

	protected function render_empty( string $message ): void {
		printf(
			'<div class="vh-el__notice"><p>%s</p></div>',
			esc_html( $message )
		);
	}

	/**
	 * Section header controls shared by most widgets: an optional heading and
	 * an optional link out to the matching portal view.
	 *
	 * @param string $default_heading Pre-filled heading text.
	 */
	protected function add_heading_controls( string $default_heading = '' ): void {
		$this->add_control(
			'vh_heading',
			array(
				'label'       => esc_html__( 'Heading', 'vulnhub' ),
				'type'        => \Elementor\Controls_Manager::TEXT,
				'default'     => $default_heading,
				'placeholder' => esc_html__( 'Leave empty for no heading', 'vulnhub' ),
				'label_block' => true,
			)
		);
	}

	protected function print_heading(): void {
		$heading = (string) ( $this->get_settings_for_display( 'vh_heading' ) ?? '' );

		if ( '' === trim( $heading ) ) {
			return;
		}
		printf( '<h2 class="vh-el__heading">%s</h2>', esc_html( $heading ) );
	}
}

