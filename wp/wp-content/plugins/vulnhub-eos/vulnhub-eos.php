<?php
/**
 * Plugin Name:       VulnHub EOS Programme
 * Plugin URI:        https://github.com/arshdeepromy/vulnhub
 * Description:       The end-of-support server retirement programme as data: which end-of-life machines have a funded remediation project and a date, which have passed that date, and which have nothing at all. Imported from the programme's reconciliation workbook and matched to existing assets by hostname — it never creates assets. Splits the "platforms past end of life" widget into covered and uncovered, and adds the remediation plan screen behind it.
 * Version:           1.0.0
 * Requires at least: 6.5
 * Requires PHP:      8.1
 * Author:            Romy Sidhu
 * License:           GPL-2.0-or-later
 * Text Domain:       vulnhub
 *
 * @package VulnHub\EOS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_EOS_VERSION', '1.0.0' );
define( 'VULNHUB_EOS_DIR', plugin_dir_path( __FILE__ ) );
define( 'VULNHUB_EOS_URL', plugin_dir_url( __FILE__ ) );

/*
 * All five classes are required here, not lazily: the plugin is three pieces
 * built against one contract (data + import, the portal page, the widget
 * split), and a missing require would show up as a silently absent screen
 * rather than an error anyone can act on.
 */
require_once VULNHUB_EOS_DIR . 'includes/class-vh-eos-schema.php';
require_once VULNHUB_EOS_DIR . 'includes/class-vh-eos-repo.php';
require_once VULNHUB_EOS_DIR . 'includes/class-vh-eos-import.php';
require_once VULNHUB_EOS_DIR . 'includes/class-vh-eos-admin.php';

/*
 * The other two pieces. Guarded because this plugin has to boot with either of
 * them missing -- a half-installed copy should still import and still keep the
 * data model intact, rather than fatal on every request.
 */
foreach ( array( 'class-vh-eos-view.php', 'class-vh-eos-export.php', 'class-vh-eos-widget.php' ) as $vh_eos_part ) {
	if ( is_readable( VULNHUB_EOS_DIR . 'includes/' . $vh_eos_part ) ) {
		require_once VULNHUB_EOS_DIR . 'includes/' . $vh_eos_part;
	}
}

/**
 * Core owns the data model this reads from, and plugins load alphabetically --
 * vulnhub-core comes before vulnhub-eos, but that is an accident of naming, not
 * a contract. Test for it on `plugins_loaded` rather than at file scope.
 */
add_action(
	'plugins_loaded',
	static function (): void {
		if ( ! function_exists( 'vulnhub' ) ) {
			add_action(
				'admin_notices',
				static function (): void {
					if ( current_user_can( 'activate_plugins' ) ) {
						printf(
							'<div class="notice notice-error"><p><strong>%s</strong> %s</p></div>',
							esc_html__( 'VulnHub EOS Programme:', 'vulnhub' ),
							esc_html__( 'VulnHub Core must be active.', 'vulnhub' )
						);
					}
				}
			);

			return;
		}

		VH_EOS_Schema::init();
		VH_EOS_Import::init();
		VH_EOS_Admin::init();

		if ( class_exists( 'VH_EOS_View' ) ) {
			VH_EOS_View::init();
		}
		if ( class_exists( 'VH_EOS_Export' ) ) {
			VH_EOS_Export::init();
		}
		if ( class_exists( 'VH_EOS_Widget' ) ) {
			VH_EOS_Widget::init();
		}
	},
	20
);

/**
 * Create the table on activation.
 *
 * Also checked on every load by VH_EOS_Schema::init(), because a plugin
 * activated before core was ever installed has nothing to create the table
 * against, and because an upgrade does not fire this hook at all.
 */
register_activation_hook(
	__FILE__,
	static function (): void {
		VH_EOS_Schema::install();
	}
);
