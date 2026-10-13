<?php
/**
 * The Check Point connector: reads policy, never changes it.
 *
 * One run:
 *
 *   1. log in (read-only session, see the client)
 *   2. read gateways, policy packages, and the object inventory
 *      (hosts, networks, ranges, groups, services)
 *   3. read each package's first access layer, the inline layers its rules
 *      apply, and its NAT rulebase
 *   4. log out, write the snapshot, then work out internet exposure from the
 *      stored snapshot and the asset register
 *
 * Any failed or short read throws before anything is written, so a bad run
 * leaves the previous snapshot standing.
 *
 * @package VulnHub\CheckPoint
 */

declare( strict_types = 1 );

use VulnHub\Core\Connector;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_CheckPoint_Connector extends Connector {

	/** Inventory reads: command => details level. */
	private const INVENTORY = array(
		'show-hosts',
		'show-networks',
		'show-address-ranges',
		'show-groups',
		'show-groups-with-exclusion',
		'show-services-tcp',
		'show-services-udp',
		'show-service-groups',
	);

	public function id(): string {
		return 'checkpoint';
	}

	public function label(): string {
		return __( 'Check Point', 'vulnhub' );
	}

	public function description(): string {
		return __( 'Reads gateways, access and NAT policy from Check Point management (Smart-1 Cloud or on-prem) with a read-only session, and works out which machines the internet can reach, on which ports, through which rule.', 'vulnhub' );
	}

	public function icon(): string {
		return 'shield';
	}

	public function category(): string {
		return 'cloud';
	}

	public function default_interval(): string {
		return 'vh_daily';
	}

	/**
	 * @return array<int,array<string,mixed>>
	 */
	public function fields(): array {
		return array(
			array(
				'key'  => 'setup',
				'type' => 'note',
				'help' => __( 'Two different keys. <strong>Management API key</strong> (logs in and reads policy): on Smart-1 Cloud, open the Security Management service in the Check Point Portal, go to <strong>Settings → API &amp; SmartConsole</strong>, and in the <strong>Management API</strong> section click <strong>Generate</strong>; the same page shows the connection string to use as the Management API URL. For read-only, create a dedicated administrator in SmartConsole with authentication method <strong>API Key</strong> and a Read Only profile that allows Management API Login, and use its key instead. <strong>Portal API key</strong> (Client ID, Secret Key, Authentication URL, from the portal API Keys page) is only needed for the through-the-portal mode. Every session this connector opens is read-only, and it only ever sends <code>show-*</code> commands.', 'vulnhub' ),
			),
			array(
				'key'     => 'auth_mode',
				'label'   => __( 'How to reach management', 'vulnhub' ),
				'type'    => 'select',
				'default' => 'portal',
				'options' => array(
					'portal' => __( 'Check Point Portal API key (Client ID + Secret Key)', 'vulnhub' ),
					'direct' => __( 'Directly, with a SmartConsole administrator API key', 'vulnhub' ),
				),
				'help'    => __( 'Portal: the Client ID, Secret Key and Authentication URL from the Check Point Portal API Keys page (service Smart-1 Cloud). That reads the service and its gateways straight away; reading the rule base depends on the management server accepting the portal token, which Test connection checks and reports. Direct: an administrator API key from SmartConsole.', 'vulnhub' ),
			),
			array(
				'key'         => 'auth_url',
				'label'       => __( 'Authentication URL', 'vulnhub' ),
				'type'        => 'url',
				'placeholder' => 'https://cloudinfra-gw.ap.portal.checkpoint.com/auth/external/user',
				'show_when'   => array( 'auth_mode' => array( 'portal' ) ),
				'help'        => __( 'Shown with the portal API key. Use it exactly, including the region (for example cloudinfra-gw.ap.portal.checkpoint.com) and a trailing /user for a user API key.', 'vulnhub' ),
			),
			array(
				'key'       => 'client_id',
				'label'     => __( 'Portal Client ID', 'vulnhub' ),
				'type'      => 'text',
				'show_when' => array( 'auth_mode' => array( 'portal' ) ),
			),
			array(
				'key'       => 'client_secret',
				'label'     => __( 'Portal Secret Key', 'vulnhub' ),
				'type'      => 'text',
				'secret'    => true,
				'show_when' => array( 'auth_mode' => array( 'portal' ) ),
				'help'      => __( 'Encrypted at rest. Leave blank to keep the stored one.', 'vulnhub' ),
			),
			array(
				'key'         => 'base_url',
				'label'       => __( 'Management API URL (optional with a portal key)', 'vulnhub' ),
				'type'        => 'url',
				'placeholder' => 'https://tenant.maas.checkpoint.com/context-id/web_api',
				'help'        => __( 'With a portal key, leave this blank: it is worked out from the Smart-1 Cloud service. Do not put the Authentication URL here. Direct: the Smart-1 Cloud connection string (https://tenant.maas.checkpoint.com/context-id/web_api) or https://your-management-server/web_api. Through the portal: the management URL the portal gives for API calls (https://cloudinfra-gw.portal.checkpoint.com/app/maas/api/v2/environments/environment-id). /web_api is added if missing. The certificate must be valid.', 'vulnhub' ),
			),
			array(
				'key'      => 'api_key',
				'label'    => __( 'Management API key', 'vulnhub' ),
				'type'     => 'text',
				'secret'   => true,
				'help'     => __( 'Optional with a portal key. A single key (not a Client ID and secret): Settings → API &amp; SmartConsole → Management API → Generate, or a read-only API-key administrator from SmartConsole. Encrypted at rest. Leave blank to keep the stored one.', 'vulnhub' ),
			),
			array(
				'key'       => 'mgmt_user',
				'label'     => __( 'Management administrator (user name)', 'vulnhub' ),
				'type'      => 'text',
				'help'      => __( 'Reading the rule base needs a management login: an API key or a user name and password. Use a dedicated administrator with a Read Only permission profile that allows Management API Login (SmartConsole → Manage &amp; Settings → Permissions &amp; Administrators).', 'vulnhub' ),
			),
			array(
				'key'    => 'mgmt_password',
				'label'  => __( 'Management administrator password', 'vulnhub' ),
				'type'   => 'text',
				'secret' => true,
				'help'   => __( 'Encrypted at rest. Leave blank to keep the stored one.', 'vulnhub' ),
			),
			array(
				'key'         => 'domain',
				'label'       => __( 'Domain', 'vulnhub' ),
				'type'        => 'text',
				'placeholder' => '',
				'help'        => __( 'Only for a Multi-Domain server: the domain whose policy to read. Leave blank otherwise.', 'vulnhub' ),
			),
			array(
				'key'         => 'packages',
				'label'       => __( 'Policy packages', 'vulnhub' ),
				'type'        => 'text',
				'placeholder' => 'Perimeter, Cloud',
				'help'        => __( 'Comma separated. Leave blank to read every package.', 'vulnhub' ),
			),
		);
	}

	private function client(): ?VulnHub_CheckPoint_Client {
		if ( $this->is_mock() ) {
			return new VulnHub_CheckPoint_Client( 'https://mock.invalid/web_api', 'mock', '', array( $this, 'log' ), array( 'VulnHub_CheckPoint_Mock', 'answer' ) );
		}

		$base = (string) $this->get( 'base_url', '' );
		$key  = $this->secret( 'api_key' );
		$auth = trim( (string) $this->get( 'auth_url', '' ) );

		// The Authentication URL pasted into the Management API URL box is an
		// easy slip (both are URLs from the same portal page): use it as what
		// it is, and work the management URL out from the service instead.
		if ( str_contains( $base, '/auth/external' ) ) {
			$auth = $base;
			$base = '';
		}

		if ( '' === $auth ) {
			$auth = 'https://cloudinfra-gw.portal.checkpoint.com/auth/external';
		}

		if ( 'portal' === (string) $this->get( 'auth_mode', 'portal' ) ) {
			$id     = (string) $this->get( 'client_id', '' );
			$secret = $this->secret( 'client_secret' );

			if ( '' === $id || '' === $secret ) {
				return null;
			}

			$client = new VulnHub_CheckPoint_Client( $base, $key, (string) $this->get( 'domain', '' ), array( $this, 'log' ) );
			$client->via_portal( $auth, $id, $secret );
			$client->with_user( (string) $this->get( 'mgmt_user', '' ), $this->secret( 'mgmt_password' ) );

			return $client;
		}

		if ( '' === $base || ( '' === $key && ( '' === (string) $this->get( 'mgmt_user', '' ) || '' === $this->secret( 'mgmt_password' ) ) ) ) {
			return null;
		}

		$client = new VulnHub_CheckPoint_Client( $base, $key, (string) $this->get( 'domain', '' ), array( $this, 'log' ) );
		$client->with_user( (string) $this->get( 'mgmt_user', '' ), $this->secret( 'mgmt_password' ) );

		return $client;
	}

	/**
	 * @return array{ok:bool,message:string}
	 */
	public function test_connection(): array {
		$client = $this->client();

		if ( ! $client ) {
			return array( 'ok' => false, 'message' => __( 'Enter the Management API URL and the management API key first (and, through the portal, the Client ID and Secret Key).', 'vulnhub' ) );
		}

		$lines = array();

		if ( 'portal' === (string) $this->get( 'auth_mode', 'portal' ) && ! $this->is_mock() ) {
			try {
				$svc = $this->prepare_portal( $client );
				$gw  = $client->portal_get( 'gateways' );
			} catch ( \Throwable $e ) {
				return array( 'ok' => false, 'message' => $e->getMessage() );
			}

			$lines[] = sprintf(
				/* translators: 1: service, 2: version, 3: gateways. */
				__( 'Portal key accepted. Smart-1 Cloud service %1$s (version %2$s), %3$d gateway(s) registered.', 'vulnhub' ),
				(string) ( $svc['name'] ?? '?' ),
				(string) ( $svc['version'] ?? '?' ),
				(int) ( $gw['total'] ?? count( (array) ( $gw['objects'] ?? array() ) ) )
			);
		}

		try {
			$login = $client->login();
			$gws   = $client->call( 'show-gateways-and-servers', array( 'limit' => 1, 'details-level' => 'uid' ) );
			$pkgs  = $client->call( 'show-packages', array( 'limit' => 1, 'details-level' => 'uid' ) );
		} catch ( \Throwable $e ) {
			if ( $lines ) {
				$lines[] = sprintf(
					/* translators: 1: URL, 2: error. */
					__( 'Reading the rule base needs a management login at %1$s, and it was not accepted: %2$s', 'vulnhub' ),
					$client->base(),
					$e->getMessage()
				);
				$lines[] = $client->has_key()
					? __( 'Check the administrator credentials and that the profile allows Management API Login.', 'vulnhub' )
					: __( 'The portal token alone is not a management login. Gateways are imported; for rules and NAT, add a read-only management administrator (user name and password, or its API key).', 'vulnhub' );

				return array( 'ok' => true, 'message' => implode( ' ', $lines ) );
			}

			return array( 'ok' => false, 'message' => $e->getMessage() );
		} finally {
			$client->logout();
		}

		$lines[] = sprintf(
			/* translators: 1: API version, 2: gateways, 3: packages. */
			__( 'Management login accepted (read-only session, API %1$s). %2$d gateway(s) and server(s), %3$d policy package(s) visible.', 'vulnhub' ),
			(string) ( $login['api-server-version'] ?? '?' ),
			(int) ( $gws['total'] ?? 0 ),
			(int) ( $pkgs['total'] ?? 0 )
		);

		return array( 'ok' => true, 'message' => implode( ' ', $lines ) );
	}

	/**
	 * Portal mode: read the service details, and when no Management API URL
	 * is set, build it from them -- `https://<service>.maas.checkpoint.com/<sharedSecret>/web_api`,
	 * the documented shape (the service API describes sharedSecret as the
	 * part of the Web API URL that is also the mgmt_cli context).
	 *
	 * @return array<string,mixed> The service details.
	 */
	private function prepare_portal( VulnHub_CheckPoint_Client $client ): array {
		$svc = $client->portal_get( 'mgmt-service' );

		if ( '' === $client->base() ) {
			$name   = (string) ( $svc['name'] ?? '' );
			$secret = (string) ( $svc['sharedSecret'] ?? '' );

			if ( '' !== $name && '' !== $secret ) {
				$client->set_base( 'https://' . $name . '.maas.checkpoint.com/' . $secret . '/web_api' );
				$this->log( 'Management API URL built from the Smart-1 Cloud service details (set one in the settings to override).' );
			}
		}

		return $svc;
	}

	/**
	 * @param array<string,mixed> $args
	 * @return array{ok:bool,message:string}
	 */
	protected function do_sync( array $args = array() ): array {
		$client = $this->client();

		if ( ! $client ) {
			return array( 'ok' => false, 'message' => __( 'Not configured.', 'vulnhub' ) );
		}

		VulnHub_CheckPoint_Store::maybe_install();

		$now = vh_now();

		if ( 'portal' === (string) $this->get( 'auth_mode', 'portal' ) && ! $this->is_mock() ) {
			$svc = $this->prepare_portal( $client );
			$gw  = $client->portal_get( 'gateways' );
			$gws = (array) ( $gw['objects'] ?? array() );

			VulnHub_CheckPoint_Store::save_service_gateways( $gws, (string) ( $svc['version'] ?? '' ), $now );
			$this->log( sprintf( 'Smart-1 Cloud service: %d registered gateway(s) stored.', count( $gws ) ) );
			$this->log_sites();

			try {
				$snap = self::read( $client, $this->wanted_packages(), array( $this, 'log' ) );
			} catch ( \Throwable $e ) {
				$this->log( 'Rule base not read: ' . $e->getMessage() );

				return array(
					'ok'      => true,
					'message' => sprintf(
						/* translators: %d: gateways. */
						__( 'Stored %d gateway(s) from the Smart-1 Cloud service. The rule base was not read: the management server did not accept the login (see the run log).', 'vulnhub' ),
						count( $gws )
					),
				);
			}
		} else {
			$snap = self::read( $client, $this->wanted_packages(), array( $this, 'log' ) );
		}

		VulnHub_CheckPoint_Store::save_snapshot( $snap, $now );
		$this->log( sprintf( 'Stored %d gateway(s), %d object(s), %d access rule(s), %d NAT rule(s).', count( $snap['gateways'] ), count( $snap['objects'] ), count( $snap['rules'] ), count( $snap['nat'] ) ) );

		$this->log_sites();

		$res = self::recompute();
		$this->log( sprintf( 'Exposure: %d machine(s) reachable from outside on %d way(s) in; %d more allowed by policy with no public address or NAT; %d broad rule(s).', $res['assets'], $res['paths'], $res['latent'], $res['broad'] ) );

		return array(
			'ok'      => true,
			'message' => sprintf(
				/* translators: 1: rules, 2: packages, 3: machines. */
				__( 'Read %1$d access rule(s) in %2$d package(s); %3$d machine(s) reachable from the internet.', 'vulnhub' ),
				count( $snap['rules'] ),
				count( $snap['packages'] ),
				$res['assets']
			),
		);
	}

	/** Classify the gateways and put a one-line summary in the run log. */
	private function log_sites(): void {
		$rows = VulnHub_CheckPoint_Sites::classify();
		$by   = array();

		foreach ( $rows as $r ) {
			$by[ '' !== $r['site'] ? $r['site'] : 'unplaced' ][] = '' !== $r['name'] ? $r['name'] : '(unnamed)';
		}

		foreach ( $by as $site => $names ) {
			$this->log( sprintf( 'Site %s: %s', $site, implode( ', ', $names ) ) );
		}
	}

	/** @return string[] */
	private function wanted_packages(): array {
		return array_values( array_filter( array_map( 'trim', explode( ',', (string) $this->get( 'packages', '' ) ) ) ) );
	}

	/**
	 * Read everything the policy reader needs. Throws on any short read.
	 *
	 * @param string[] $wanted Package names, or empty for all.
	 * @return array{gateways:array<int,array<string,mixed>>,packages:array<int,string>,objects:array<string,array<string,mixed>>,rules:array<int,array<string,mixed>>,nat:array<int,array<string,mixed>>}
	 */
	public static function read( VulnHub_CheckPoint_Client $client, array $wanted, callable $log ): array {
		$client->login();

		try {
			$gateways = array();
			$client->each(
				'show-gateways-and-servers',
				array( 'details-level' => 'full' ),
				static function ( array $o ) use ( &$gateways ): void {
					$gateways[] = $o;
				}
			);

			$packages = array();
			$client->each(
				'show-packages',
				array( 'details-level' => 'full' ),
				static function ( array $p ) use ( &$packages, $wanted ): void {
					if ( ! $wanted || in_array( (string) ( $p['name'] ?? '' ), $wanted, true ) ) {
						$packages[] = $p;
					}
				},
				'packages'
			);

			$objects = array();

			foreach ( self::INVENTORY as $cmd ) {
				$n = $client->each(
					$cmd,
					array( 'details-level' => 'full' ),
					static function ( array $o ) use ( &$objects ): void {
						if ( isset( $o['uid'] ) ) {
							$objects[ (string) $o['uid'] ] = $o;
						}
					}
				);
				$log( sprintf( '%s: %d', $cmd, $n ) );
			}

			// Gateways answer as hosts when a rule names them.
			foreach ( $gateways as $g ) {
				if ( isset( $g['uid'] ) && ! isset( $objects[ (string) $g['uid'] ] ) ) {
					$objects[ (string) $g['uid'] ] = $g;
				}
			}

			$rules = array();
			$nat   = array();
			$names = array();

			foreach ( $packages as $p ) {
				$pkg    = (string) ( $p['name'] ?? '' );
				$layers = (array) ( $p['access-layers'] ?? array() );
				$names[] = $pkg;

				if ( ! $layers ) {
					$log( sprintf( 'Package %s has no access layer; skipped.', $pkg ) );
					continue;
				}

				// The first ordered layer only (see VulnHub_CheckPoint_Policy).
				$layer = (array) $layers[0];
				$queue = array( array( (string) ( $layer['uid'] ?? '' ), (string) ( $layer['name'] ?? '' ), 0 ) );
				$done  = array();

				while ( $queue ) {
					[ $luid, $lname, $inline ] = array_shift( $queue );

					if ( '' === $luid || isset( $done[ $luid ] ) ) {
						continue;
					}
					$done[ $luid ] = true;

					$rb = $client->rulebase( 'show-access-rulebase', array( 'uid' => $luid ) );

					foreach ( $rb['dictionary'] as $uid => $o ) {
						$objects[ $uid ] = $objects[ $uid ] ?? $o;
					}

					foreach ( $rb['rules'] as $i => $r ) {
						$r['_package']    = $pkg;
						$r['_layer_uid']  = $luid;
						$r['_layer_name'] = $lname;
						$r['_inline']     = $inline;
						$r['_position']   = $i + 1;
						$rules[]          = $r;

						if ( ! empty( $r['inline-layer'] ) ) {
							$queue[] = array( (string) $r['inline-layer'], '', 1 );
						}
					}

					$log( sprintf( 'Package %s, layer %s: %d rule(s).', $pkg, '' !== $lname ? $lname : $luid, count( $rb['rules'] ) ) );
				}

				$nb = $client->rulebase( 'show-nat-rulebase', array( 'package' => $pkg ) );

				foreach ( $nb['dictionary'] as $uid => $o ) {
					$objects[ $uid ] = $objects[ $uid ] ?? $o;
				}

				foreach ( $nb['rules'] as $i => $r ) {
					$r['_package']  = $pkg;
					$r['_position'] = $i + 1;
					$nat[]          = $r;
				}
			}
		} finally {
			$client->logout();
		}

		return array(
			'gateways' => $gateways,
			'packages' => $names,
			'objects'  => $objects,
			'rules'    => $rules,
			'nat'      => $nat,
		);
	}

	/** "Perimeter #12 Web in" */
	public static function rule_label( array $rule, string $package ): string {
		$name = trim( (string) ( $rule['name'] ?? '' ) );

		return trim( $package . ' #' . (string) ( $rule['rule-number'] ?? '?' ) . ( '' !== $name ? ' ' . $name : '' ) );
	}

	/**
	 * Work out exposure from the stored snapshot. Runs after a sync, and
	 * again whenever the asset register moves (addresses change).
	 *
	 * @param array<int,array{asset_id:int,ip:int}>|null $targets Override (tests); null reads the asset register.
	 * @return array{assets:int,paths:int,latent:int,broad:int}
	 */
	public static function recompute( ?array $targets = null ): array {
		$pol   = new VulnHub_CheckPoint_Policy( VulnHub_CheckPoint_Store::objects() );
		$rb    = VulnHub_CheckPoint_Store::rules();
		$nat   = $pol->nat_forwards( VulnHub_CheckPoint_Store::nat_rules() );
		$eff   = array();

		foreach ( $rb['packages'] as $pkg => $rules ) {
			$eff[ $pkg ] = $pol->effective( $rules, $rb['inline'] );
		}

		$out = VulnHub_CheckPoint_Policy::exposure(
			$targets ?? VulnHub_CheckPoint_Store::targets(),
			$nat,
			$eff,
			array( __CLASS__, 'rule_label' )
		);

		VulnHub_CheckPoint_Store::save_exposure( $out['paths'], $out['broad'], vh_now() );

		// The threat context reads these through its filters; tell it the
		// ground moved.
		if ( class_exists( 'VulnHub_Threat_Classify' ) ) {
			VulnHub_Threat_Classify::rebuild_exposure();
		}
		if ( class_exists( 'VulnHub_Dash_Widgets' ) ) {
			VulnHub_Dash_Widgets::bust();
		}

		$c = VulnHub_CheckPoint_Store::counts();

		return array(
			'assets' => $c['assets'],
			'paths'  => $c['paths'],
			'latent' => $c['latent'],
			'broad'  => count( $out['broad'] ),
		);
	}
}

