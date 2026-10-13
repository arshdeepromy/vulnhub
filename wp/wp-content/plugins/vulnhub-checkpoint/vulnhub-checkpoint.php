<?php
/**
 * Plugin Name:       VulnHub Check Point
 * Description:       Reads Check Point firewall policy (gateways, access and NAT rules, objects) from Smart-1 Cloud or on-prem management through a read-only session, and works out which machines the internet can reach, on which ports, through which rule.
 * Version:           0.1.0
 * Requires at least: 6.4
 * Requires PHP:      8.1
 * Author:            VulnHub
 * License:           GPL-2.0-or-later
 * Text Domain:       vulnhub
 *
 * Read-only, three ways: a read-only administrator on the Check Point side,
 * a read-only session on every login, and a client that refuses to send any
 * command other than login, logout, keepalive and show-*. See
 * docs/CHECKPOINT.md.
 *
 * @package VulnHub\CheckPoint
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_CHECKPOINT_DIR', plugin_dir_path( __FILE__ ) );
define( 'VULNHUB_CHECKPOINT_VERSION', '0.1.0' );

require_once VULNHUB_CHECKPOINT_DIR . 'includes/class-vh-checkpoint-client.php';
require_once VULNHUB_CHECKPOINT_DIR . 'includes/class-vh-checkpoint-policy.php';
require_once VULNHUB_CHECKPOINT_DIR . 'includes/class-vh-checkpoint-store.php';
require_once VULNHUB_CHECKPOINT_DIR . 'includes/class-vh-checkpoint-sites.php';
require_once VULNHUB_CHECKPOINT_DIR . 'includes/class-vh-checkpoint-interfaces.php';
require_once VULNHUB_CHECKPOINT_DIR . 'includes/class-vh-checkpoint-topology.php';
require_once VULNHUB_CHECKPOINT_DIR . 'includes/class-vh-checkpoint-mock.php';
require_once VULNHUB_CHECKPOINT_DIR . 'includes/class-vh-checkpoint-page.php';

add_action(
	'vulnhub_register_connectors',
	/**
	 * @param \VulnHub\Core\Connectors $connectors Core connector registry.
	 */
	static function ( $connectors ): void {
		require_once VULNHUB_CHECKPOINT_DIR . 'includes/class-vh-checkpoint-connector.php';
		VulnHub_CheckPoint_Store::maybe_install();
		$connectors->register( new VulnHub_CheckPoint_Connector() );
	}
);

add_action(
	'plugins_loaded',
	static function (): void {
		if ( ! function_exists( 'vulnhub' ) ) {
			return;
		}

		VulnHub_CheckPoint_Store::maybe_install();
		VulnHub_CheckPoint_Page::init();
		VulnHub_CheckPoint_Topology::init();
	},
	25
);

/**
 * Hand the threat context what the firewall policy allows.
 *
 * Priority 20, after vulnhub-aws (which returns its own map whole), and
 * merged into whatever is already there rather than replacing it: AWS
 * security groups and the Check Point policy are both evidence, and a door
 * either one proves is a door.
 */
add_filter(
	'vulnhub_internet_paths',
	static function ( array $net ): array {
		if ( ! class_exists( 'VulnHub_CheckPoint_Store' ) || VulnHub_CheckPoint_Store::DB_VERSION !== (string) get_option( VulnHub_CheckPoint_Store::VERSION_OPTION, '' ) ) {
			return $net;
		}

		$cp = VulnHub_CheckPoint_Store::internet_paths();

		if ( ! $cp['paths'] && ! $cp['latent'] ) {
			return $net;
		}

		foreach ( array( 'paths', 'latent' ) as $k ) {
			$net[ $k ] = (array) ( $net[ $k ] ?? array() );

			foreach ( $cp[ $k ] as $asset => $ways ) {
				$net[ $k ][ $asset ] = array_merge( (array) ( $net[ $k ][ $asset ] ?? array() ), $ways );
			}
		}

		// The threat context caches on captured_at; a new policy read must
		// move it.
		$net['captured_at'] = trim( (string) ( $net['captured_at'] ?? '' ) . '|cp:' . $cp['stamp'], '|' );

		return $net;
	},
	20
);

add_filter(
	'vulnhub_cloud_reachable_assets',
	static function ( array $assets ): array {
		if ( ! class_exists( 'VulnHub_CheckPoint_Store' ) || VulnHub_CheckPoint_Store::DB_VERSION !== (string) get_option( VulnHub_CheckPoint_Store::VERSION_OPTION, '' ) ) {
			return $assets;
		}

		return $assets + VulnHub_CheckPoint_Store::reachable_assets();
	},
	20
);

/**
 * Addresses move when the asset register does; the policy has not changed,
 * so re-read the stored snapshot rather than the API.
 */
add_action(
	'vulnhub_sync_complete',
	static function ( $connector = '' ): void {
		$id = is_object( $connector ) && method_exists( $connector, 'id' ) ? (string) $connector->id() : (string) $connector;

		if ( ! in_array( $id, array( 'tenable', 'cmdb', 'intune', 'aws', 'plerion', 'defender' ), true ) ) {
			return;
		}

		if ( ! class_exists( 'VulnHub_CheckPoint_Connector' ) || 0 === VulnHub_CheckPoint_Store::counts()['rules'] ) {
			return;
		}

		VulnHub_CheckPoint_Connector::recompute();
	},
	30
);

if ( defined( 'WP_CLI' ) && WP_CLI ) {
	/**
	 * wp vulnhub checkpoint-exposure
	 *
	 * Work out internet exposure again from the stored policy snapshot. No
	 * call to Check Point.
	 */
	WP_CLI::add_command(
		'vulnhub checkpoint-exposure',
		static function (): void {
			require_once VULNHUB_CHECKPOINT_DIR . 'includes/class-vh-checkpoint-connector.php';
			$r = VulnHub_CheckPoint_Connector::recompute();
			WP_CLI::success( sprintf( '%d machine(s) reachable on %d way(s) in; %d allowed but not routed; %d broad rule(s).', $r['assets'], $r['paths'], $r['latent'], $r['broad'] ) );
		}
	);

	/**
	 * wp vulnhub checkpoint-sites [--set=<gateway>] [--site=<site>]
	 *
	 * Work out which firewall is which (site, platform, confidence) and print
	 * the evidence. --set with --site records an override ('' clears it).
	 */
	WP_CLI::add_command(
		'vulnhub checkpoint-sites',
		static function ( array $args, array $assoc ): void {
			if ( isset( $assoc['set'] ) ) {
				VulnHub_CheckPoint_Sites::set_override( (string) $assoc['set'], (string) ( $assoc['site'] ?? '' ) );
			}

			foreach ( VulnHub_CheckPoint_Sites::classify() as $r ) {
				WP_CLI::log( sprintf( '%-55s %-8s %-34s %-6s', '' !== $r['name'] ? $r['name'] : '(unnamed)', $r['platform'], '' !== $r['site'] ? $r['site'] : '?', $r['confidence'] ) );
				foreach ( $r['evidence'] as $e ) {
					WP_CLI::log( '      - ' . $e );
				}
			}
		}
	);

	/**
	 * wp vulnhub checkpoint-preview
	 *
	 * Read the built-in sample policy and print what the reader makes of
	 * it, against sample machines. Writes nothing.
	 */
	WP_CLI::add_command(
		'vulnhub checkpoint-preview',
		static function (): void {
			require_once VULNHUB_CHECKPOINT_DIR . 'includes/class-vh-checkpoint-connector.php';

			$client = new VulnHub_CheckPoint_Client( 'https://mock.invalid/web_api', 'mock', '', null, array( 'VulnHub_CheckPoint_Mock', 'answer' ) );
			$snap   = VulnHub_CheckPoint_Connector::read( $client, array(), static function (): void {} );
			$pol    = new VulnHub_CheckPoint_Policy( $snap['objects'] );
			$pkgs   = array();
			$inline = array();

			foreach ( $snap['rules'] as $r ) {
				if ( $r['_inline'] ) {
					$inline[ $r['_layer_uid'] ][] = $r;
				} else {
					$pkgs[ $r['_package'] ][] = $r;
				}
			}

			$eff = array();
			foreach ( $pkgs as $p => $rules ) {
				$eff[ $p ] = $pol->effective( $rules, $inline );
			}

			$targets = array();
			foreach ( array( 1 => '172.31.250.10', 2 => '172.31.250.20', 3 => '198.51.100.30', 4 => '172.31.250.40', 5 => '172.31.250.50' ) as $id => $ip ) {
				$targets[] = array( 'asset_id' => $id, 'ip' => (int) VulnHub_CheckPoint_Policy::ip2int( $ip ) );
			}

			$out = VulnHub_CheckPoint_Policy::exposure( $targets, $pol->nat_forwards( $snap['nat'] ), $eff, array( 'VulnHub_CheckPoint_Connector', 'rule_label' ) );

			WP_CLI::log( sprintf( 'Requests: %d (all show-* or session).', $client->requests() ) );
			foreach ( $out['paths'] as $p ) {
				WP_CLI::log( sprintf( '%-14s %s %-11s %-7s %-6s via %-6s %-14s %s%s', $p['ip'], $p['protocol'], $p['port_from'] . '-' . $p['port_to'], $p['reach'], $p['sources'], $p['via'], $p['front'], $p['rule'], $p['latent'] ? '  [latent]' : '' ) );
			}
			foreach ( $out['broad'] as $b ) {
				WP_CLI::log( sprintf( 'BROAD %s from %s: %s', $b['rule'], $b['reach'], $b['ports'] ) );
			}
		}
	);
}

