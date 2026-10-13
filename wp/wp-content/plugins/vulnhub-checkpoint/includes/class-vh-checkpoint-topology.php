<?php
/**
 * Where the firewalls stand in the network the platform already draws.
 *
 * Two places get enriched:
 *
 *   - The Cloud Network estate flowchart (`vulnhub_aws_estate_flow`): the
 *     inline-firewall card names the Check Point gateways actually registered
 *     for AWS, with version and state; the On-premises card says which
 *     on-premises firewalls are there and how AWS reaches them -- the
 *     networks AWS route tables send to the transit gateway, host routes
 *     to named machines, and site-to-site VPN gateways with the networks
 *     they carry.
 *   - An asset's detail page (`vulnhub_asset_detail_network`): which
 *     firewall stands in front of it and how it reaches the rest of the
 *     network.
 *
 * Once the policy has been read, the firewalls' own interface topology
 * (VulnHub_CheckPoint_Interfaces) adds three things: the on-premises
 * firewall AWS traffic comes in through is drawn as its own card between
 * the transit gateway and On-premises; each data-centre cluster lists the
 * segments it is plugged into; and an asset is placed on the segment the
 * firewall says it is on.
 *
 * All of it is read from what is already stored -- the AWS network capture
 * (route tables, nodes), the Check Point gateways and their site verdicts,
 * the asset and location registers. Nothing is fetched here.
 *
 * @package VulnHub\CheckPoint
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_CheckPoint_Topology {

	public static function init(): void {
		add_filter( 'vulnhub_aws_estate_flow', array( __CLASS__, 'enrich_flow' ), 10, 2 );
		add_action( 'vulnhub_asset_detail_network', array( __CLASS__, 'asset_panel' ) );
	}

	private static function aws_ready(): bool {
		return class_exists( 'VulnHub_AWS_Network' );
	}

	/** @return array<int,array<string,mixed>> */
	private static function gateways(): array {
		global $wpdb;

		return array_values( array_filter( VulnHub_CheckPoint_Store::gateway_rows(), static fn( array $g ): bool => '' !== (string) $g['name'] ) );
	}

	/**
	 * VPC key ("account|vpc") => in this environment?
	 *
	 * @return callable(string):bool
	 */
	private static function env_filter( string $env ): callable {
		global $wpdb;

		if ( '' === $env || ! class_exists( 'VulnHub_AWS_Environment' ) ) {
			return static fn( string $k ): bool => true;
		}

		$names  = array();
		$labels = array();

		foreach ( (array) $wpdb->get_results( 'SELECT account_id, resource_id, name FROM ' . VulnHub_AWS_Network::nodes_table() . " WHERE node_type = 'vpc'", ARRAY_A ) as $r ) { // phpcs:ignore
			$names[ $r['account_id'] . '|' . $r['resource_id'] ] = (string) $r['name'];
		}
		foreach ( (array) $wpdb->get_results( 'SELECT account_id, label FROM ' . $wpdb->prefix . 'vulnhub_aws_accounts', ARRAY_A ) as $r ) { // phpcs:ignore
			$labels[ (string) $r['account_id'] ] = (string) $r['label'];
		}

		return static function ( string $k ) use ( $env, $names, $labels ): bool {
			$acct = (string) strtok( $k, '|' );

			return $env === VulnHub_AWS_Environment::classify( (string) ( $names[ $k ] ?? '' ), (string) ( $labels[ $acct ] ?? '' ) );
		};
	}

	/**
	 * How AWS reaches everything that is not AWS.
	 *
	 * @return array{tgw:array<string,array{vpcs:int,accounts:int}>,hosts:array<int,array<string,string>>,vgw:array<string,array<string,mixed>>}
	 */
	public static function hybrid( string $env = '' ): array {
		global $wpdb;

		$out = array( 'tgw' => array(), 'hosts' => array(), 'vgw' => array() );

		if ( ! self::aws_ready() ) {
			return $out;
		}

		$in   = self::env_filter( $env );
		$rows = (array) $wpdb->get_results( 'SELECT account_id, vpc_id, dest_cidr, target_type, target_id FROM ' . VulnHub_AWS_Network::routes_table() . " WHERE dest_cidr <> '0.0.0.0/0' AND ( target_type = 'tgw' OR LOCATE( 'vgw-', target_id ) = 1 )", ARRAY_A ); // phpcs:ignore

		$tgw = array();
		$vgw = array();

		foreach ( $rows as $r ) {
			$k = $r['account_id'] . '|' . $r['vpc_id'];

			if ( ! $in( $k ) ) {
				continue;
			}

			$cidr = (string) $r['dest_cidr'];

			if ( 'tgw' === $r['target_type'] ) {
				$tgw[ $cidr ]['vpcs'][ $k ]                  = true;
				$tgw[ $cidr ]['accts'][ $r['account_id'] ] = true;
			} else {
				$id                          = (string) $r['target_id'];
				$vgw[ $id ]['vpcs'][ $k ]    = true;
				$vgw[ $id ]['cidrs'][ $cidr ] = true;
			}
		}

		// Summaries first (10.0.0.0/8 before a /32), then by reach.
		uksort(
			$tgw,
			static function ( string $a, string $b ) use ( $tgw ): int {
				$la = (int) substr( (string) strrchr( $a, '/' ), 1 );
				$lb = (int) substr( (string) strrchr( $b, '/' ), 1 );

				return array( $la, -count( $tgw[ $a ]['vpcs'] ) ) <=> array( $lb, -count( $tgw[ $b ]['vpcs'] ) );
			}
		);

		foreach ( $tgw as $cidr => $t ) {
			if ( str_ends_with( $cidr, '/32' ) ) {
				$ip = substr( $cidr, 0, -3 );
				$a  = $wpdb->get_row( // phpcs:ignore
					$wpdb->prepare(
						'SELECT a.hostname, l.name AS loc FROM ' . vh_table( 'assets' ) . ' a LEFT JOIN ' . vh_table( 'locations' ) . " l ON l.id = a.location_id
						  WHERE a.duplicate_of IS NULL AND ( a.ipv4 = %s OR LOCATE( %s, CONCAT( ',', a.ipv4s, ',' ) ) > 0 ) LIMIT 1",
						$ip,
						',' . $ip . ','
					),
					ARRAY_A
				);
				$out['hosts'][] = array(
					'ip'   => $ip,
					'host' => (string) ( $a['hostname'] ?? '' ),
					'loc'  => (string) ( $a['loc'] ?? '' ),
					'vpcs' => (string) count( $t['vpcs'] ),
				);
				continue;
			}

			$out['tgw'][ $cidr ] = array( 'vpcs' => count( $t['vpcs'] ), 'accounts' => count( $t['accts'] ) );
		}

		foreach ( $vgw as $id => $v ) {
			$accts = array_unique( array_map( static fn( string $k ): string => (string) strtok( $k, '|' ), array_keys( $v['vpcs'] ) ) );
			$out['vgw'][ $id ] = array(
				'vpcs'     => count( $v['vpcs'] ),
				'accounts' => array_values( $accts ),
				'cidrs'    => array_keys( $v['cidrs'] ),
				'summary'  => self::summarise( array_keys( $v['cidrs'] ) ),
			);
		}

		return $out;
	}

	/**
	 * Many routes as a few /16s: "10.245.0.0/16 (12), 10.250.0.0/16 (9) …".
	 *
	 * @param string[] $cidrs
	 */
	private static function summarise( array $cidrs ): string {
		$by = array();

		foreach ( $cidrs as $c ) {
			$p = explode( '.', (string) strtok( $c, '/' ) );

			if ( count( $p ) === 4 ) {
				$k        = $p[0] . '.' . $p[1] . '.0.0/16';
				$by[ $k ] = ( $by[ $k ] ?? 0 ) + 1;
			}
		}

		arsort( $by );
		$parts = array();

		foreach ( array_slice( $by, 0, 4, true ) as $k => $n ) {
			$parts[] = $k . ' (' . $n . ')';
		}

		return implode( ', ', $parts ) . ( count( $by ) > 4 ? ' …' : '' );
	}

	/**
	 * The on-premises firewalls, grouped as clusters and branches.
	 *
	 * @return array{dc:array<string,array<string,mixed>>,branch:array<int,array<string,mixed>>,aws:array<int,array<string,mixed>>}
	 */
	public static function firewalls(): array {
		$dc     = array();
		$branch = array();
		$aws    = array();

		foreach ( self::gateways() as $g ) {
			$state = (string) ( json_decode( (string) $g['data'], true )['statusDetails']['status'] ?? '' );

			if ( 'aws' === $g['platform'] ) {
				$aws[] = $g + array( 'state' => $state );
			} elseif ( 'cluster' === $g['platform'] ) {
				$key = '' !== (string) $g['cluster'] ? (string) $g['cluster'] : (string) $g['name'];

				$dc[ $key ]['site']      = (string) $g['site'];
				$dc[ $key ]['version']   = (string) $g['version'];
				$dc[ $key ]['members'][] = (string) $g['name'];
				$dc[ $key ]['ips'][]     = (string) $g['ipv4'];
			} else {
				$branch[] = $g + array( 'state' => $state );
			}
		}

		return array( 'dc' => $dc, 'branch' => $branch, 'aws' => $aws );
	}

	/* =================================================================
	 * Cloud Network estate flowchart
	 * ============================================================== */

	/**
	 * @param array<string,mixed> $flow As built by VulnHub_AWS_Network::estate_flow().
	 * @return array<string,mixed>
	 */
	public static function enrich_flow( array $flow, string $env = '' ): array {
		$fw  = self::firewalls();
		$net = self::hybrid( $env );
		$ifm = class_exists( 'VulnHub_CheckPoint_Interfaces' ) ? VulnHub_CheckPoint_Interfaces::model() : array( 'gateways' => array(), 'entry' => null, 'rules' => array() );

		$entry   = $ifm['entry'];
		$by_site = array();
		$by_name = array();

		foreach ( $ifm['gateways'] as $g ) {
			$by_name[ (string) $g['name'] ] = $g;

			if ( 'cluster' === $g['kind'] && '' !== (string) $g['site'] ) {
				$by_site[ (string) $g['site'] ] = $g;
			}
		}

		foreach ( (array) ( $flow['bands'] ?? array() ) as $bi => $band ) {
			foreach ( (array) ( $band['nodes'] ?? array() ) as $ni => $node ) {
				$id = (string) ( $node['id'] ?? '' );

				/* ---- the inline firewall: what Check Point says is there ---- */
				if ( 'fw-stack' === $id && $fw['aws'] ) {
					$ok   = array_filter( $fw['aws'], static fn( array $g ): bool => 'completed' === $g['state'] );
					$rest = count( $fw['aws'] ) - count( $ok );
					$ver  = implode( ', ', array_unique( array_filter( array_column( $fw['aws'], 'version' ) ) ) );

					$node['meta'][] = array(
						'k' => __( 'Check Point members', 'vulnhub' ),
						'v' => sprintf(
							/* translators: 1: registered, 2: version, 3: not completed. */
							__( '%1$d registered (%2$s)%3$s', 'vulnhub' ),
							count( $fw['aws'] ),
							'' !== $ver ? $ver : '?',
							$rest > 0 ? sprintf( /* translators: %d: count */ __( ' · %d not communicating', 'vulnhub' ), $rest ) : ''
						),
					);
					// An AWS appliance group no registered gateway matches is
					// either managed somewhere else or left over.
					$orphans = self::unmatched_groups( $fw['aws'] );
					if ( $orphans ) {
						$node['meta'][] = array(
							'k' => __( 'Not registered in Check Point', 'vulnhub' ),
							'v' => implode( ', ', array_map( static fn( string $n ): string => vh_trim( $n, 40 ), $orphans ) ),
						);
					}

					$node['meta'][] = array(
						'k' => __( 'Gateways', 'vulnhub' ),
						'v' => implode( ', ', array_map( static fn( array $g ): string => vh_trim( (string) $g['name'], 40 ) . ( 'completed' !== $g['state'] && '' !== $g['state'] ? ' (' . $g['state'] . ')' : '' ), $fw['aws'] ) ),
					);
				}

				/* ---- on-premises: which firewalls, and how AWS gets there ---- */
				if ( 'dest-onprem' === $id ) {
					if ( $entry ) {
						$node['meta'][] = array(
							'k' => __( 'AWS comes in through', 'vulnhub' ),
							'v' => array(
								$entry['gateway'] . ( '' !== (string) $entry['site'] ? ' · ' . $entry['site'] : '' ),
								/* translators: 1: interface, 2: subnet. */
								sprintf( __( 'interface %1$s · %2$s', 'vulnhub' ), $entry['iface'], $entry['cidr'] ),
								/* translators: %d: AWS networks. */
								sprintf( _n( '%d AWS network listed behind it', '%d AWS networks listed behind it', (int) $entry['aws'], 'vulnhub' ), (int) $entry['aws'] ),
							),
						);

						$sum = self::rule_summary( $ifm['rules'] );
						if ( $sum ) {
							$node['meta'][] = array( 'k' => __( 'Rules between AWS and on-premises', 'vulnhub' ), 'v' => $sum );
						}
					}

					foreach ( $fw['dc'] as $name => $c ) {
						$lines = array(
							sprintf(
								/* translators: 1: cluster, 2: members, 3: version. */
								__( '%1$s cluster · %2$d members · %3$s', 'vulnhub' ),
								$name,
								count( $c['members'] ),
								$c['version']
							),
						);

						// The segments the cluster is plugged into, from its
						// own interfaces -- the firewall's word, not a guess
						// from asset addresses.
						$g = $by_site[ (string) $c['site'] ] ?? null;
						if ( $g ) {
							$seg   = VulnHub_CheckPoint_Interfaces::segments( $g );
							$lines = array_merge( $lines, array_slice( $seg, 0, 8 ) );
							if ( count( $seg ) > 8 ) {
								/* translators: %d: more interfaces. */
								$lines[] = sprintf( __( '+%d more interfaces', 'vulnhub' ), count( $seg ) - 8 );
							}
						}

						$node['meta'][] = array(
							'k' => '' !== $c['site'] ? $c['site'] : __( 'Data centre', 'vulnhub' ),
							'v' => $lines,
						);
					}

					// List values are one line each in the panel: a run of
					// networks joined with dots reads as one long word.
					if ( $fw['branch'] ) {
						$lines = array();
						foreach ( $fw['branch'] as $g ) {
							$segs    = isset( $by_name[ (string) $g['name'] ] ) ? count( VulnHub_CheckPoint_Interfaces::segments( $by_name[ (string) $g['name'] ] ) ) : 0;
							$lines[] = (string) $g['name'] . ' · ' . ( '' !== (string) $g['site'] ? (string) $g['site'] : __( 'site not known', 'vulnhub' ) )
								. ( $segs > 0 ? ' · ' . sprintf( /* translators: %d: segments */ _n( '%d segment', '%d segments', $segs, 'vulnhub' ), $segs ) : '' )
								. ( '' !== $g['state'] && 'completed' !== $g['state'] ? ' (' . $g['state'] . ')' : '' );
						}
						sort( $lines );
						$node['meta'][] = array(
							/* translators: %d: gateways. */
							'k' => sprintf( _n( '%d branch gateway', '%d branch gateways', count( $lines ), 'vulnhub' ), count( $lines ) ),
							'v' => $lines,
						);
					}

					if ( $net['tgw'] ) {
						$lines = array();
						foreach ( array_slice( $net['tgw'], 0, 8, true ) as $cidr => $t ) {
							/* translators: 1: network, 2: VPC count. */
							$lines[] = sprintf( _n( '%1$s · %2$d VPC', '%1$s · %2$d VPCs', (int) $t['vpcs'], 'vulnhub' ), $cidr, $t['vpcs'] );
						}
						if ( count( $net['tgw'] ) > 8 ) {
							/* translators: %d: more networks. */
							$lines[] = sprintf( __( '+%d more', 'vulnhub' ), count( $net['tgw'] ) - 8 );
						}
						$node['meta'][] = array( 'k' => __( 'Via the transit gateway', 'vulnhub' ), 'v' => $lines );
					}

					if ( $net['hosts'] ) {
						$lines = array();
						foreach ( array_slice( $net['hosts'], 0, 8 ) as $h ) {
							// A hostname that is only a digest is an identifier,
							// not a name; the address says more.
							$name    = preg_match( '/^[0-9a-f]{24,}$/i', $h['host'] ) ? '' : $h['host'];
							$lines[] = ( '' !== $name ? $name . ' (' . $h['ip'] . ')' : $h['ip'] ) . ( '' !== $h['loc'] ? ' · ' . $h['loc'] : '' );
						}
						if ( count( $net['hosts'] ) > 8 ) {
							$lines[] = sprintf( __( '+%d more', 'vulnhub' ), count( $net['hosts'] ) - 8 );
						}
						$node['meta'][] = array( 'k' => __( 'Single-server routes', 'vulnhub' ), 'v' => $lines );
					}

					foreach ( $net['vgw'] as $vid => $v ) {
						$node['meta'][] = array(
							'k' => __( 'Site-to-site VPN', 'vulnhub' ),
							'v' => array(
								sprintf(
									/* translators: 1: gateway id, 2: VPCs, 3: networks. */
									__( '%1$s · %2$s · %3$s', 'vulnhub' ),
									$vid,
									/* translators: %d: VPCs. */
									sprintf( _n( '%d VPC', '%d VPCs', (int) $v['vpcs'], 'vulnhub' ), $v['vpcs'] ),
									/* translators: %d: networks. */
									sprintf( _n( '%d network', '%d networks', count( $v['cidrs'] ), 'vulnhub' ), count( $v['cidrs'] ) )
								),
								$v['summary'],
							),
						);
					}

					$node['note'] = $entry
						? __( 'Read from what is stored. The firewall AWS comes in through is the interface whose topology (its anti-spoofing list) names the most AWS VPC ranges; each cluster\'s segments are its own interfaces. The routes are the AWS route tables: networks sent to the transit gateway, and to any virtual private gateway (a site-to-site VPN straight into a VPC). The rules are the accept rules in that firewall\'s policy with AWS on one side and the rest of the network on the other.', 'vulnhub' )
						: __( 'Read from what is stored: the on-premises firewalls are the Check Point gateways placed at a site; the routes are the AWS route tables (networks sent to the transit gateway, and to any virtual private gateway, which is a site-to-site VPN straight into a VPC). Which firewall the transit gateway lands on is drawn once the firewall policy has been read.', 'vulnhub' );
				}

				$flow['bands'][ $bi ]['nodes'][ $ni ] = $node;
			}
		}

		// Name the corporate-network edge by what it carries.
		if ( $net['tgw'] ) {
			$sum = implode( ', ', array_slice( array_keys( $net['tgw'] ), 0, 3 ) );

			foreach ( (array) ( $flow['links'] ?? array() ) as $li => $l ) {
				if ( 'dest-onprem' === ( $l['to'] ?? '' ) ) {
					/* translators: %s: networks. */
					$flow['links'][ $li ]['label'] = sprintf( __( 'to the corporate network · %s', 'vulnhub' ), $sum );
				}
			}
		}

		return self::draw_entry( $flow, $entry, $ifm['rules'] );
	}

	/**
	 * Put the firewall AWS comes in through on the diagram: its own card in
	 * the firewall band, and the transit gateway's line to On-premises
	 * routed through it.
	 *
	 * @param array<string,mixed>            $flow
	 * @param array<string,mixed>|null       $entry
	 * @param array<int,array<string,mixed>> $rules
	 * @return array<string,mixed>
	 */
	private static function draw_entry( array $flow, ?array $entry, array $rules ): array {
		if ( ! $entry ) {
			return $flow;
		}

		$li = null;
		foreach ( (array) ( $flow['links'] ?? array() ) as $k => $l ) {
			if ( 'dest-onprem' === ( $l['to'] ?? '' ) && 'path-transit' === ( $l['from'] ?? '' ) ) {
				$li = $k;
				break;
			}
		}

		$bi = null;
		foreach ( (array) ( $flow['bands'] ?? array() ) as $k => $b ) {
			if ( 'fw' === ( $b['id'] ?? '' ) ) {
				$bi = $k;
				break;
			}
		}

		if ( null === $li || null === $bi ) {
			return $flow;
		}

		$dir = array( 'aws-onprem' => 0, 'onprem-aws' => 0, 'both' => 0 );
		$any = 0;
		foreach ( $rules as $r ) {
			++$dir[ $r['dir'] ];
			$any += ! empty( $r['anyport'] ) ? 1 : 0;
		}

		$meta = array(
			array( 'k' => __( 'Firewall', 'vulnhub' ), 'v' => $entry['gateway'] . ( '' !== (string) $entry['policy'] ? ' · ' . $entry['policy'] : '' ) ),
			/* translators: 1: interface, 2: subnet. */
			array( 'k' => __( 'AWS comes in on', 'vulnhub' ), 'v' => sprintf( __( '%1$s · %2$s', 'vulnhub' ), $entry['iface'], $entry['cidr'] ) ),
			/* translators: %d: networks. */
			array( 'k' => __( 'AWS networks behind it', 'vulnhub' ), 'v' => sprintf( _n( '%d VPC range', '%d VPC ranges', (int) $entry['aws'], 'vulnhub' ), (int) $entry['aws'] ) ),
		);
		if ( $rules ) {
			$meta[] = array(
				'k' => __( 'Accept rules', 'vulnhub' ),
				/* translators: 1: total, 2: out, 3: in, 4: both. */
				'v' => sprintf( __( '%1$d · %2$d AWS → on-prem · %3$d on-prem → AWS · %4$d both', 'vulnhub' ), count( $rules ), $dir['aws-onprem'], $dir['onprem-aws'], $dir['both'] ),
			);
		}
		if ( $any ) {
			/* translators: %d: rules. */
			$meta[] = array( 'k' => __( 'Open every port', 'vulnhub' ), 'v' => sprintf( _n( '%d rule', '%d rules', $any, 'vulnhub' ), $any ) );
		}

		$flow['bands'][ $bi ]['label']   = __( 'Firewalls', 'vulnhub' );
		$flow['bands'][ $bi ]['nodes'][] = array(
			'id'    => 'fw-onprem',
			'kind'  => 'firewall',
			/* translators: %s: site or firewall. */
			'label' => sprintf( __( 'Check Point — %s', 'vulnhub' ), '' !== (string) $entry['site'] ? $entry['site'] : $entry['gateway'] ),
			'meta'  => $meta,
			'why'   => __( 'How this is worked out', 'vulnhub' ),
			'note'  => __( 'The on-premises firewall AWS traffic comes in through: the interface whose topology lists the most AWS VPC ranges as networks behind it. The rules counted are the accept rules in its policy with AWS on one side and the rest of the network on the other. Firewall policy → AWS ↔ on-premises lists them.', 'vulnhub' ),
		);

		$flow['links'][ $li ]['to'] = 'fw-onprem';
		$flow['links'][]            = array(
			'from'  => 'fw-onprem',
			'to'    => 'dest-onprem',
			/* translators: %d: rules. */
			'label' => $rules ? sprintf( _n( '%d accept rule', '%d accept rules', count( $rules ), 'vulnhub' ), count( $rules ) ) : '',
		);

		return $flow;
	}

	/**
	 * The rules between AWS and on-premises, as panel lines: totals, then
	 * the widest few (every port, or Any on one side) by rule order.
	 *
	 * @param array<int,array<string,mixed>> $rules
	 * @return string[]
	 */
	private static function rule_summary( array $rules ): array {
		if ( ! $rules ) {
			return array();
		}

		$dir = array( 'aws-onprem' => 0, 'onprem-aws' => 0, 'both' => 0 );
		foreach ( $rules as $r ) {
			++$dir[ $r['dir'] ];
		}

		$arrow = array(
			'aws-onprem' => __( 'AWS → on-prem', 'vulnhub' ),
			'onprem-aws' => __( 'on-prem → AWS', 'vulnhub' ),
			'both'       => __( 'both ways', 'vulnhub' ),
		);

		$lines = array(
			/* translators: 1: total, 2: out, 3: in, 4: both. */
			sprintf( __( '%1$d accept rules · %2$d AWS → on-prem · %3$d on-prem → AWS · %4$d both', 'vulnhub' ), count( $rules ), $dir['aws-onprem'], $dir['onprem-aws'], $dir['both'] ),
		);

		$wide = array_values( array_filter( $rules, static fn( array $r ): bool => ! empty( $r['anyport'] ) || ! empty( $r['broad'] ) ) );
		foreach ( array_slice( $wide, 0, 4 ) as $r ) {
			$lines[] = sprintf( '#%s %s · %s · %s', $r['number'], vh_trim( '' !== $r['name'] ? $r['name'] : $r['src'] . ' → ' . $r['dst'], 48 ), $arrow[ $r['dir'] ], vh_trim( (string) $r['ports'], 40 ) );
		}
		if ( count( $wide ) > 4 ) {
			/* translators: %d: more rules. */
			$lines[] = sprintf( __( '+%d more wide rules — see Firewall policy', 'vulnhub' ), count( $wide ) - 4 );
		}

		return $lines;
	}

	/**
	 * AWS auto-scaling groups named like Check Point appliances ("CP" in
	 * the name) that share fewer than two name tokens with any registered
	 * AWS gateway.
	 *
	 * @param array<int,array<string,mixed>> $aws Registered AWS gateways.
	 * @return string[]
	 */
	private static function unmatched_groups( array $aws ): array {
		global $wpdb;

		if ( ! self::aws_ready() ) {
			return array();
		}

		$tok = static fn( string $s ): array => array_values( array_filter( preg_split( '/[^A-Za-z0-9]+/', strtoupper( $s ) ) ?: array(), static fn( string $t ): bool => strlen( $t ) >= 2 && ! ctype_digit( $t ) ) );
		$out = array();

		foreach ( (array) $wpdb->get_col( 'SELECT DISTINCT name FROM ' . VulnHub_AWS_Network::nodes_table() . " WHERE node_type = 'asg'" ) as $name ) { // phpcs:ignore
			$t = $tok( (string) $name );

			if ( ! in_array( 'CP', $t, true ) ) {
				continue;
			}

			$hit = false;
			foreach ( $aws as $g ) {
				if ( count( array_intersect( $t, $tok( (string) $g['name'] ) ) ) >= 2 ) {
					$hit = true;
					break;
				}
			}

			if ( ! $hit ) {
				$out[] = (string) $name;
			}
		}

		return $out;
	}

	/* =================================================================
	 * Asset detail
	 * ============================================================== */

	/**
	 * Lines describing an asset's path through the network.
	 *
	 * @param array<string,mixed> $a Asset row.
	 * @return array<int,array{k:string,v:string}>
	 */
	public static function for_asset( array $a ): array {
		global $wpdb;

		$out = self::firewall_view( $a );

		// On premises: a firewall placed at the asset's location.
		$loc = (int) ( $a['location_id'] ?? 0 );

		if ( $loc > 0 ) {
			$here = array_values( array_filter( self::gateways(), static fn( array $g ): bool => (int) $g['location_id'] === $loc ) );
			$seen = array();

			$aws_members = array_filter( $here, static fn( array $g ): bool => 'aws' === $g['platform'] );
			if ( $aws_members ) {
				$out[] = array(
					'k' => __( 'Firewall at this site', 'vulnhub' ),
					'v' => sprintf( /* translators: %d: members */ _n( 'Check Point inline firewall · %d gateway', 'Check Point inline firewall · %d gateways', count( $aws_members ), 'vulnhub' ), count( $aws_members ) ),
				);
			}

			foreach ( $here as $g ) {
				if ( 'aws' === $g['platform'] ) {
					continue;
				}
				$key = '' !== (string) $g['cluster'] ? (string) $g['cluster'] : (string) $g['name'];

				if ( isset( $seen[ $key ] ) ) {
					continue;
				}
				$seen[ $key ] = true;
				$out[]        = array(
					'k' => __( 'Firewall at this site', 'vulnhub' ),
					'v' => $key . ( 'cluster' === $g['platform'] ? ' ' . __( '(cluster)', 'vulnhub' ) : '' ) . ( '' !== (string) $g['version'] ? ' · ' . $g['version'] : '' ),
				);
			}
		}

		// AWS: how the VPC routes out, read from its route tables.
		$vpc = '';
		$raw = (array) json_decode( (string) ( $a['raw_json'] ?? '' ), true );

		if ( is_array( $raw['cloud'] ?? null ) ) {
			$vpc = (string) ( $raw['cloud']['vpc_id'] ?? '' );
		}

		// Not every source records the VPC on the asset; the AWS capture
		// knows it for any instance it read.
		$rtb = '';

		if ( '' !== (string) ( $a['aws_instance_id'] ?? '' ) && self::aws_ready() ) {
			$nt   = VulnHub_AWS_Network::nodes_table();
			$inst = $wpdb->get_row( $wpdb->prepare( "SELECT vpc_id, subnet_id FROM {$nt} WHERE node_type = 'instance' AND resource_id = %s LIMIT 1", (string) $a['aws_instance_id'] ), ARRAY_A ); // phpcs:ignore

			if ( $inst ) {
				$vpc = '' !== $vpc ? $vpc : (string) $inst['vpc_id'];

				// The subnet's own route table decides the way out, not the
				// VPC's: a VPC behind a gateway load balancer has an
				// internet-gateway route too, in the firewall's own subnet.
				$sub = (string) $wpdb->get_var( $wpdb->prepare( "SELECT detail FROM {$nt} WHERE node_type = 'subnet' AND resource_id = %s LIMIT 1", (string) $inst['subnet_id'] ) ); // phpcs:ignore
				$rtb = (string) ( json_decode( $sub, true )['route_table'] ?? '' );
			}
		}

		if ( '' !== $vpc && self::aws_ready() ) {
			$routes = (array) $wpdb->get_results( // phpcs:ignore
				'' !== $rtb
					? $wpdb->prepare( 'SELECT DISTINCT dest_cidr, target_type, target_id FROM ' . VulnHub_AWS_Network::routes_table() . ' WHERE route_table_id = %s', $rtb )
					: $wpdb->prepare( 'SELECT DISTINCT dest_cidr, target_type, target_id FROM ' . VulnHub_AWS_Network::routes_table() . ' WHERE vpc_id = %s', $vpc ),
				ARRAY_A
			);

			$default = array();
			$onprem  = array();
			$vpn     = array();

			foreach ( $routes as $r ) {
				$t = (string) $r['target_id'];

				if ( '0.0.0.0/0' === $r['dest_cidr'] ) {
					$kind = str_starts_with( $t, 'vpce-' ) ? 'inspected' : ( 'tgw' === $r['target_type'] ? 'transit' : ( 'igw' === $r['target_type'] ? 'direct' : ( 'nat' === $r['target_type'] ? 'nat' : '' ) ) );
					if ( '' !== $kind ) {
						$default[ $kind ] = true;
					}
				} elseif ( 'tgw' === $r['target_type'] ) {
					$onprem[] = (string) $r['dest_cidr'];
				} elseif ( str_starts_with( $t, 'vgw-' ) ) {
					$vpn[ $t ] = true;
				}
			}

			$labels = array(
				'inspected' => __( 'through the Check Point inline firewall (gateway load-balancer endpoint)', 'vulnhub' ),
				'transit'   => __( 'through the transit gateway, which hands internet traffic to the Check Point inline firewall', 'vulnhub' ),
				'direct'    => __( 'straight to an internet gateway — no firewall in between', 'vulnhub' ),
				'nat'       => __( 'through a NAT gateway — outbound only', 'vulnhub' ),
			);

			if ( $default ) {
				// A VPC with several route tables (public and private
				// subnets) has more than one way out; which applies depends
				// on the machine's subnet, so all are named.
				$out[] = array(
					'k' => __( 'Internet traffic', 'vulnhub' ),
					'v' => implode( count( $default ) > 1 ? ' ' . __( 'or', 'vulnhub' ) . ' ' : '', array_map( static fn( string $k ): string => $labels[ $k ], array_keys( $default ) ) )
						. ( count( $default ) > 1 ? ' ' . __( '(depends on the subnet)', 'vulnhub' ) : '' ),
				);
			}
			$out[] = array( 'k' => __( 'VPC', 'vulnhub' ), 'v' => $vpc . ( '' !== $rtb ? ' · ' . $rtb : '' ) );
			if ( $onprem ) {
				$out[] = array( 'k' => __( 'Reaches on-premises', 'vulnhub' ), 'v' => sprintf( /* translators: %s: networks */ __( 'via the transit gateway: %s', 'vulnhub' ), implode( ', ', array_slice( $onprem, 0, 6 ) ) . ( count( $onprem ) > 6 ? ' …' : '' ) ) );
			} elseif ( isset( $default['transit'] ) ) {
				$out[] = array( 'k' => __( 'Reaches on-premises', 'vulnhub' ), 'v' => __( 'via the transit gateway (its default route goes there)', 'vulnhub' ) );
			}

			// The AWS inline firewall stands in the path of inspected and
			// transit traffic, wherever the machine is recorded as located.
			if ( ( isset( $default['inspected'] ) || isset( $default['transit'] ) ) && ! array_filter( $out, static fn( array $r ): bool => str_contains( $r['v'], 'inline firewall ·' ) ) ) {
				$n = count( array_filter( self::gateways(), static fn( array $g ): bool => 'aws' === $g['platform'] ) );
				if ( $n > 0 ) {
					array_unshift(
						$out,
						array(
							'k' => __( 'Firewall in the path', 'vulnhub' ),
							'v' => sprintf( /* translators: %d: members */ _n( 'Check Point inline firewall · %d gateway', 'Check Point inline firewall · %d gateways', $n, 'vulnhub' ), $n ),
						)
					);
				}
			}
			if ( $vpn ) {
				$out[] = array( 'k' => __( 'Site-to-site VPN', 'vulnhub' ), 'v' => implode( ', ', array_keys( $vpn ) ) );
			}
		}

		// What the firewall policy opens to it from outside, when read.
		$ways = (array) $wpdb->get_results( $wpdb->prepare( 'SELECT protocol, port_from, port_to, reach, front, rule_label FROM ' . VulnHub_CheckPoint_Store::table( 'exposure' ) . ' WHERE asset_id = %d AND latent = 0 LIMIT 6', (int) ( $a['id'] ?? 0 ) ), ARRAY_A ); // phpcs:ignore

		foreach ( $ways as $w ) {
			$port  = (int) $w['port_from'] === (int) $w['port_to'] ? (string) $w['port_from'] : $w['port_from'] . '-' . $w['port_to'];
			$out[] = array(
				'k' => __( 'Open from the internet', 'vulnhub' ),
				'v' => sprintf( '%s/%s %s %s · %s', $w['protocol'], $port, 'anyone' === $w['reach'] ? __( 'to anyone', 'vulnhub' ) : __( 'to listed sources', 'vulnhub' ), '' !== (string) $w['front'] ? __( 'on', 'vulnhub' ) . ' ' . $w['front'] : '', $w['rule_label'] ),
			);
		}

		return $out;
	}

	/**
	 * What the firewalls themselves say about an asset's address: the
	 * segment it is on, and, for an AWS machine, the rules that let it
	 * reach on-premises and be reached from there.
	 *
	 * @param array<string,mixed> $a Asset row.
	 * @return array<int,array{k:string,v:string}>
	 */
	private static function firewall_view( array $a ): array {
		if ( ! class_exists( 'VulnHub_CheckPoint_Interfaces' ) ) {
			return array();
		}

		$ip  = trim( (string) ( $a['ipv4'] ?? '' ) );
		$out = array();

		if ( '' === $ip ) {
			return $out;
		}

		$aws = '' !== (string) ( $a['aws_instance_id'] ?? '' ) || 'aws' === strtolower( (string) ( $a['cloud_provider'] ?? '' ) );
		$pl  = VulnHub_CheckPoint_Interfaces::place( $ip );

		if ( $pl ) {
			$where = '' !== $pl['site'] ? ' (' . $pl['site'] . ')' : '';

			$out[] = 'connected' === $pl['how']
				? array(
					'k' => __( 'Network segment', 'vulnhub' ),
					/* translators: 1: subnet, 2: firewall, 3: interface, 4: site. */
					'v' => sprintf( __( '%1$s — on %2$s interface %3$s%4$s', 'vulnhub' ), $pl['cidr'], $pl['gateway'], $pl['iface'], $where ),
				)
				: array(
					'k' => __( 'Seen by the firewall', 'vulnhub' ),
					/* translators: 1: object, 2: range, 3: firewall, 4: interface, 5: site. */
					'v' => sprintf( __( '%1$s (%2$s), listed behind %3$s interface %4$s%5$s', 'vulnhub' ), $pl['label'], $pl['cidr'], $pl['gateway'], $pl['iface'], $where ),
				);

			if ( ! $aws && (int) ( $a['location_id'] ?? 0 ) <= 0 && '' !== $pl['site'] && 'connected' === $pl['how'] ) {
				$out[] = array( 'k' => __( 'Site, by the firewall', 'vulnhub' ), 'v' => $pl['site'] );
			}
		}

		$entry = VulnHub_CheckPoint_Interfaces::model()['entry'];

		if ( $aws && $entry ) {
			$rf = VulnHub_CheckPoint_Interfaces::rules_for( $ip );

			if ( $rf['out'] || $rf['in'] ) {
				$out[] = array(
					'k' => __( 'To and from on-premises', 'vulnhub' ),
					/* translators: 1: firewall, 2: interface, 3: rules out, 4: rules in. */
					'v' => sprintf( __( 'through %1$s interface %2$s · %3$d rules let it reach on-premises · %4$d let on-premises reach it', 'vulnhub' ), $entry['gateway'], $entry['iface'], count( $rf['out'] ), count( $rf['in'] ) ),
				);

				$shown = array();
				foreach ( array_merge( $rf['in'], $rf['out'] ) as $r ) {
					if ( isset( $shown[ $r['label'] ] ) || count( $shown ) >= 4 ) {
						continue;
					}
					$shown[ $r['label'] ] = true;
					$out[]                = array(
						'k' => in_array( $r, $rf['in'], true ) ? __( 'Rule from on-premises', 'vulnhub' ) : __( 'Rule to on-premises', 'vulnhub' ),
						'v' => $r['label'] . ' · ' . ( in_array( $r, $rf['in'], true ) ? $r['src'] : $r['dst'] ) . ' · ' . $r['ports'],
					);
				}
			}
		}

		return $out;
	}

	/** @param array<string,mixed> $a Asset row. */
	public static function asset_panel( array $a ): void {
		$rows = self::for_asset( $a );

		if ( ! $rows ) {
			return;
		}

		echo '<h3 class="vh-h3">' . esc_html__( 'Network path', 'vulnhub' ) . '</h3><dl class="vh-dl">';
		foreach ( $rows as $r ) {
			printf( '<dt>%s</dt><dd>%s</dd>', esc_html( $r['k'] ), esc_html( $r['v'] ) );
		}
		echo '</dl>';
	}
}

