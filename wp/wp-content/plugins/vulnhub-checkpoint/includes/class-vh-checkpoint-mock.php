<?php
/**
 * Invented Check Point answers, in the Management API's own shapes, for mock
 * mode and for proving the policy reader without a live server.
 *
 * Every address is from the documentation ranges (198.51.100.0/24,
 * 203.0.113.0/24, 192.0.2.0/24) or 172.31.250.0/24, so a mock run can never
 * match a real machine. Every name is invented.
 *
 * The policy is built to exercise each rule of the reader: a group, an
 * automatic and a manual static NAT, a Drop that shadows a later Accept, a
 * listed (non-Any) source, an inline layer, a disabled rule, a broad
 * Any-to-Any rule and the cleanup rule. docs/CHECKPOINT.md lists what the
 * reader should make of it.
 *
 * @package VulnHub\CheckPoint
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_CheckPoint_Mock {

	/** @return array<string,array<int,array<string,mixed>>> command => objects */
	private static function inventory(): array {
		$host = static fn( string $uid, string $name, string $ip, string $nat = '' ): array => array_filter(
			array(
				'uid'          => $uid,
				'name'         => $name,
				'type'         => 'host',
				'ipv4-address' => $ip,
				'nat-settings' => '' !== $nat ? array( 'auto-rule' => true, 'method' => 'static', 'ipv4-address' => $nat, 'install-on' => 'All' ) : null,
			)
		);
		$tcp  = static fn( string $uid, string $name, string $port ): array => array( 'uid' => $uid, 'name' => $name, 'type' => 'service-tcp', 'port' => $port );

		return array(
			'show-gateways-and-servers' => array(
				array( 'uid' => 'gw-1', 'name' => 'edge-gw-01', 'type' => 'simple-gateway', 'ipv4-address' => '198.51.100.1', 'version' => 'R81.20', 'policy' => array( 'access-policy-name' => 'Perimeter', 'access-policy-installed' => true ) ),
				array( 'uid' => 'gw-2', 'name' => 'cloud-gw-01', 'type' => 'simple-gateway', 'ipv4-address' => '192.0.2.1', 'version' => 'R81.20', 'policy' => array( 'access-policy-name' => 'Cloud', 'access-policy-installed' => true ) ),
				array( 'uid' => 'mgmt-1', 'name' => 'mgmt-01', 'type' => 'checkpoint-host', 'ipv4-address' => '172.31.250.2', 'version' => 'R81.20' ),
			),
			'show-packages'             => array(
				array( 'uid' => 'pkg-1', 'name' => 'Perimeter', 'access-layers' => array( array( 'uid' => 'layer-1', 'name' => 'Perimeter Network' ) ), 'installation-targets' => array( array( 'uid' => 'gw-1', 'name' => 'edge-gw-01' ) ) ),
				array( 'uid' => 'pkg-2', 'name' => 'Cloud', 'access-layers' => array( array( 'uid' => 'layer-2', 'name' => 'Cloud Network' ) ), 'installation-targets' => array( array( 'uid' => 'gw-2', 'name' => 'cloud-gw-01' ) ) ),
			),
			'show-hosts'                => array(
				$host( 'h-web', 'web-01', '172.31.250.10', '198.51.100.10' ),
				$host( 'h-mail', 'mail-01', '172.31.250.20', '198.51.100.20' ),
				$host( 'h-portal', 'portal-01', '198.51.100.30' ),
				$host( 'h-app', 'app-01', '172.31.250.40' ),
				$host( 'h-app-pub', 'app-01-public', '198.51.100.40' ),
				$host( 'h-db', 'db-01', '172.31.250.50' ),
			),
			'show-networks'             => array(
				array( 'uid' => 'n-dmz', 'name' => 'dmz-net', 'type' => 'network', 'subnet4' => '172.31.250.0', 'mask-length4' => 24 ),
				array( 'uid' => 'n-partner', 'name' => 'partner-net', 'type' => 'network', 'subnet4' => '203.0.113.0', 'mask-length4' => 24 ),
			),
			'show-address-ranges'       => array(),
			'show-groups'               => array(
				array( 'uid' => 'g-web', 'name' => 'web-servers', 'type' => 'group', 'members' => array( array( 'uid' => 'h-web' ), array( 'uid' => 'h-portal' ) ) ),
			),
			'show-groups-with-exclusion' => array(),
			'show-services-tcp'         => array(
				$tcp( 's-http', 'http', '80' ),
				$tcp( 's-https', 'https', '443' ),
				$tcp( 's-ssh', 'ssh', '22' ),
				$tcp( 's-smtp', 'smtp', '25' ),
				$tcp( 's-rdp', 'rdp', '3389' ),
				$tcp( 's-high', 'high-ports', '>1023' ),
			),
			'show-services-udp'         => array(
				array( 'uid' => 's-dns', 'name' => 'domain-udp', 'type' => 'service-udp', 'port' => '53' ),
			),
			'show-service-groups'       => array(
				array( 'uid' => 'sg-web', 'name' => 'web-services', 'type' => 'service-group', 'members' => array( array( 'uid' => 's-http' ), array( 'uid' => 's-https' ) ) ),
			),
		);
	}

	/** @return array<int,array<string,mixed>> */
	private static function dictionary(): array {
		return array(
			array( 'uid' => 'any', 'name' => 'Any', 'type' => 'CpmiAnyObject' ),
			array( 'uid' => 'internet', 'name' => 'Internet', 'type' => 'CpmiInternet' ),
			array( 'uid' => 'a-accept', 'name' => 'Accept', 'type' => 'RulebaseAction' ),
			array( 'uid' => 'a-drop', 'name' => 'Drop', 'type' => 'RulebaseAction' ),
			array( 'uid' => 'a-layer', 'name' => 'Inner Layer', 'type' => 'RulebaseAction' ),
			array( 'uid' => 'orig', 'name' => 'Original', 'type' => 'Global' ),
		);
	}

	/** @return array<string,array<int,array<string,mixed>>> layer uid => rulebase items */
	private static function layers(): array {
		$rule = static fn( string $uid, int $n, string $name, array $src, array $dst, array $svc, string $act, array $extra = array() ): array => array_merge(
			array(
				'uid'                => $uid,
				'type'               => 'access-rule',
				'rule-number'        => $n,
				'name'               => $name,
				'enabled'            => true,
				'source'             => $src,
				'source-negate'      => false,
				'destination'        => $dst,
				'destination-negate' => false,
				'service'            => $svc,
				'service-negate'     => false,
				'action'             => $act,
			),
			$extra
		);

		return array(
			'layer-1' => array(
				array(
					'type'     => 'access-section',
					'name'     => 'Inbound',
					'rulebase' => array(
						$rule( 'r1', 1, 'Web in', array( 'any' ), array( 'g-web' ), array( 'sg-web' ), 'a-accept' ),
						$rule( 'r2', 2, 'Stealth SSH', array( 'any' ), array( 'n-dmz' ), array( 's-ssh' ), 'a-drop' ),
						$rule( 'r3', 3, 'Admin SSH (shadowed)', array( 'any' ), array( 'h-web' ), array( 's-ssh' ), 'a-accept' ),
						$rule( 'r4', 4, 'Partner RDP', array( 'n-partner' ), array( 'h-app' ), array( 's-rdp' ), 'a-accept' ),
						$rule( 'r5', 5, 'Mail in', array( 'any' ), array( 'h-mail' ), array( 's-smtp' ), 'a-accept' ),
						$rule( 'r6', 6, 'Legacy HTTPS anywhere', array( 'any' ), array( 'any' ), array( 's-https' ), 'a-accept' ),
						$rule( 'r7', 7, 'DMZ', array( 'internet' ), array( 'n-dmz' ), array( 'any' ), 'a-layer', array( 'inline-layer' => 'layer-3' ) ),
					),
				),
				$rule( 'r8', 8, 'Cleanup', array( 'any' ), array( 'any' ), array( 'any' ), 'a-drop' ),
			),
			'layer-2' => array(
				$rule( 'c1', 1, 'Portal', array( 'any' ), array( 'h-portal' ), array( 's-https' ), 'a-accept' ),
				$rule( 'c2', 2, 'Old DB access', array( 'any' ), array( 'h-db' ), array( 's-ssh' ), 'a-accept', array( 'enabled' => false ) ),
				$rule( 'c3', 3, 'Cleanup', array( 'any' ), array( 'any' ), array( 'any' ), 'a-drop' ),
			),
			'layer-3' => array(
				$rule( 'i1', 9, 'DB high ports', array( 'any' ), array( 'h-db' ), array( 's-high' ), 'a-accept' ),
				$rule( 'i2', 10, 'DMZ cleanup', array( 'any' ), array( 'any' ), array( 'any' ), 'a-drop' ),
			),
		);
	}

	/** @return array<string,array<int,array<string,mixed>>> package name => NAT rulebase */
	private static function nat(): array {
		return array(
			'Perimeter' => array(
				array(
					'type'     => 'nat-section',
					'name'     => 'Manual Lower Rules',
					'rulebase' => array(
						array(
							'uid'                    => 'n1',
							'type'                   => 'nat-rule',
							'rule-number'            => 1,
							'enabled'                => true,
							'method'                 => 'static',
							'original-source'        => 'any',
							'original-destination'   => 'h-app-pub',
							'original-service'       => 'any',
							'translated-source'      => 'orig',
							'translated-destination' => 'h-app',
							'translated-service'     => 'orig',
						),
					),
				),
			),
			'Cloud'     => array(),
		);
	}

	/**
	 * Answer one command the way the server would.
	 *
	 * @param array<string,mixed> $payload
	 * @return array<string,mixed>
	 */
	public static function answer( string $command, array $payload ): array {
		$limit  = (int) ( $payload['limit'] ?? 500 );
		$offset = (int) ( $payload['offset'] ?? 0 );

		if ( 'logout' === $command || 'keepalive' === $command ) {
			return array( 'message' => 'OK' );
		}

		$inv = self::inventory();

		if ( isset( $inv[ $command ] ) ) {
			$all  = $inv[ $command ];
			$key  = 'show-packages' === $command ? 'packages' : 'objects';
			$rows = array_slice( $all, $offset, $limit );

			return array( $key => $rows, 'from' => $offset + 1, 'to' => $offset + count( $rows ), 'total' => count( $all ) );
		}

		if ( 'show-access-rulebase' === $command || 'show-nat-rulebase' === $command ) {
			$items = 'show-nat-rulebase' === $command
				? ( self::nat()[ (string) ( $payload['package'] ?? '' ) ] ?? array() )
				: ( self::layers()[ (string) ( $payload['uid'] ?? $payload['name'] ?? '' ) ] ?? array() );

			// Page by rule, as the server does, keeping sections around them.
			$flat = array();
			foreach ( $items as $item ) {
				if ( str_ends_with( (string) $item['type'], '-section' ) ) {
					foreach ( $item['rulebase'] as $r ) {
						$flat[] = array( $item['name'], $r );
					}
				} else {
					$flat[] = array( '', $item );
				}
			}

			$page = array();
			foreach ( array_slice( $flat, $offset, $limit ) as [ $section, $r ] ) {
				$page[] = '' !== $section ? array( 'type' => str_replace( '-rule', '-section', (string) $r['type'] ), 'name' => $section, 'rulebase' => array( $r ) ) : $r;
			}

			$dict = self::dictionary();
			foreach ( $inv as $cmd => $objs ) {
				if ( 'show-gateways-and-servers' !== $cmd && 'show-packages' !== $cmd ) {
					array_push( $dict, ...$objs );
				}
			}

			return array( 'rulebase' => $page, 'objects-dictionary' => $dict, 'from' => $offset + 1, 'to' => $offset + count( $page ), 'total' => count( $flat ) );
		}

		return array( 'objects' => array(), 'total' => 0 );
	}
}

