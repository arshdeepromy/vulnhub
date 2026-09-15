<?php
/**
 * Plugin Name:  VulnHub for Elementor
 * Description:  Puts VulnHub's live data into Elementor as native widgets, and hands the portal's header and footer to the Elementor Pro Theme Builder so the chrome can be edited without touching PHP.
 * Version:      1.0.7
 * Requires PHP: 8.1
 * Author:       VulnHub
 * Text Domain:  vulnhub
 *
 * Two jobs, and they are deliberately separate.
 *
 * The first is a widget library. Everything the portal draws -- every
 * dashboard widget in the registry, the coverage charts, the estate explorer, the team wall --
 * is already a server-rendered function inside vulnhub-dashboard. Wrapping each
 * one in an `\Elementor\Widget_Base` costs almost nothing and means somebody can
 * assemble a briefing page, a wallboard or a team landing page by dragging,
 * rather than by asking a developer for a template.
 *
 * The second is the chrome. The portal serves its own document via
 * `template_include`, which is what keeps it looking the same under any theme.
 * That takeover is not negotiable -- the app is not a page of content -- but the
 * bar across the top and the strip along the bottom are, so this plugin
 * registers Elementor's theme locations and the portal shell asks
 * `elementor_theme_do_location()` for them first, falling back to its own markup
 * when no template is assigned. Nothing breaks if Elementor is switched off.
 *
 * @package VulnHub\Elementor
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_ELEMENTOR_VERSION', '1.0.7' );
define( 'VULNHUB_ELEMENTOR_DIR', plugin_dir_path( __FILE__ ) );
define( 'VULNHUB_ELEMENTOR_URL', plugin_dir_url( __FILE__ ) );

/**
 * Elementor loads on `plugins_loaded` at the default priority and only then is
 * `\Elementor\Plugin` a real class. Everything here therefore waits until 20,
 * and every entry point re-checks rather than trusting load order.
 */
add_action(
	'plugins_loaded',
	static function (): void {
		if ( ! did_action( 'elementor/loaded' ) || ! function_exists( 'vulnhub' ) ) {
			return;
		}

		/*
		 * The base class extends `\Elementor\Widget_Base`, and that class does
		 * not exist yet at `plugins_loaded` -- Elementor fires
		 * `elementor/loaded` before its own autoloader can resolve the
		 * namespace, so requiring the base here is a fatal. It is loaded from
		 * inside the `elementor/widgets/register` callback instead, which is
		 * the first moment Elementor guarantees its classes.
		 */
		require_once VULNHUB_ELEMENTOR_DIR . 'includes/class-vh-el-widgets.php';
		require_once VULNHUB_ELEMENTOR_DIR . 'includes/class-vh-el-locations.php';
		require_once VULNHUB_ELEMENTOR_DIR . 'includes/class-vh-el-templates.php';

		VulnHub_El_Widgets::init();
		VulnHub_El_Locations::init();
		VulnHub_El_Templates::init();
	},
	20
);

/**
 * A friendly note rather than a silent no-op, because "my widgets are missing"
 * is otherwise a twenty-minute hunt.
 */
add_action(
	'admin_notices',
	static function (): void {
		if ( did_action( 'elementor/loaded' ) || ! current_user_can( 'activate_plugins' ) ) {
			return;
		}
		printf(
			'<div class="notice notice-warning"><p><strong>%s</strong> %s</p></div>',
			esc_html__( 'VulnHub for Elementor:', 'vulnhub' ),
			esc_html__( 'Elementor is not active, so the VulnHub widgets and the Theme Builder header and footer are unavailable.', 'vulnhub' )
		);
	}
);

