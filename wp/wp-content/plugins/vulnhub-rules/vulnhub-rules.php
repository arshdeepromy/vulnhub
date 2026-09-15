<?php
/**
 * Plugin Name:       VulnHub Classification Rules
 * Plugin URI:        https://github.com/arshdeepromy/vulnhub
 * Description:       Saveable, ordered, testable rules that classify assets — environment, business criticality, asset type, business service and a numeric priority weight — from hostname, FQDN, IP/CIDR, OS, Tenable tags, CMDB service, lifecycle and source. Runs before core's ownership mapping.
 * Version:           1.0.0
 * Requires at least: 6.5
 * Requires PHP:      8.1
 * Author:            Romy Sidhu
 * License:           GPL-2.0-or-later
 * Text Domain:       vulnhub
 *
 * @package VulnHub\Rules
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_RULES_VERSION', '1.0.0' );
define( 'VULNHUB_RULES_DIR', plugin_dir_path( __FILE__ ) );
define( 'VULNHUB_RULES_URL', plugin_dir_url( __FILE__ ) );

require_once VULNHUB_RULES_DIR . 'includes/class-vh-rules-install.php';
require_once VULNHUB_RULES_DIR . 'includes/class-vh-rules-repo.php';
require_once VULNHUB_RULES_DIR . 'includes/class-vh-rules-engine.php';
require_once VULNHUB_RULES_DIR . 'includes/class-vh-rules-admin.php';

/**
 * Create the tables and seed the shipped defaults on activation.
 */
register_activation_hook( __FILE__, array( 'VulnHub_Rules_Install', 'activate' ) );

/**
 * Boot once every other plugin is loaded.
 *
 * Core is required: without it there is no asset table to classify and no
 * capability vocabulary to check against.
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
							esc_html__( 'VulnHub Classification Rules:', 'vulnhub' ),
							esc_html__( 'VulnHub Core must be active for classification rules to run.', 'vulnhub' )
						);
					}
				}
			);
			return;
		}

		VulnHub_Rules_Install::maybe_upgrade();
		VulnHub_Rules_Engine::instance()->hooks();
		VulnHub_Rules_Admin::init();
	},
	20
);

/**
 * Amplify an asset's risk score by the priority weight its rules set.
 *
 * The weight is a percentage of normal: the editor accepts 0-1000 and
 * suggests 200, so 200 doubles the score, 50 halves it, and 0 -- the column
 * default, meaning no rule has set one -- leaves the score alone. Folding it
 * into core's roll-up expression keeps the whole thing one set-based UPDATE.
 */
add_filter(
	'vulnhub_asset_risk_score',
	static function ( string $expr ): string {
		$state = VulnHub_Rules_Repo::state_table();

		return "( {$expr} ) * ( COALESCE( NULLIF( ( SELECT w.priority_weight FROM {$state} w WHERE w.asset_id = a.id ), 0 ), 100 ) / 100 )";
	}
);

/**
 * The classification priority weight most recently applied to an asset.
 *
 * A percentage of normal -- see the filter above. 0 means no rule has set one.
 *
 * @param int $asset_id Asset id.
 * @return int Weight, 0 when no rule has set one.
 */
function vulnhub_rules_priority_weight( int $asset_id ): int {
	return VulnHub_Rules_Repo::priority_weight( $asset_id );
}

/**
 * Run the classification engine over the estate.
 *
 * @param array<string,mixed> $args Optional: asset_id to classify one asset.
 * @return array{processed:int,matched:int,changed:int,rules:int}
 */
function vulnhub_rules_run( array $args = array() ): array {
	return VulnHub_Rules_Engine::instance()->run( $args );
}

