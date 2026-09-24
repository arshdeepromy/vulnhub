<?php
/**
 * Which ports on which servers the internet can open, from the network map.
 *
 * Read from what the network capture already stored -- security groups and
 * their rules, route tables, interfaces and addresses, load balancers -- so it
 * costs AWS nothing and works while nobody is signed in. It answers one
 * question per server and port: is there a way in from outside, and how.
 *
 * A way in needs every link to hold, because each one alone is a confident
 * wrong answer:
 *
 *   a rule admitting 0.0.0.0/0     -- routine on machines in private subnets
 *   a public address                -- means nothing if no rule admits traffic
 *   a route to an internet gateway  -- a property of one subnet's table
 *
 * So a port counts as open *directly* only when a security group on the
 * interface holding a public address admits an outside source on it, and that
 * interface's subnet routes to an internet gateway. It counts as open *through
 * a load balancer* when an internet-facing balancer's listener admits outside
 * traffic and forwards to the machine -- which is how most servers are
 * published, with no public address of their own.
 *
 * Each way in also says whether an inline firewall sits in front of it
 * (`firewall`): `inspected` when the VPC's internet gateway has an ingress
 * route table sending traffic to a Gateway Load Balancer endpoint, `none`
 * when nothing in the VPC routes to one at all, or when the capture read the
 * gateway associations and there is no ingress table -- and `unknown` for a
 * VPC that uses the firewall for something but was captured before gateway
 * associations were recorded. Outbound inspection says nothing about
 * inbound: traffic to a public address arrives through the gateway directly
 * unless that ingress table redirects it.
 *
 * "Outside" is split in two, because the difference is the whole triage:
 * `anyone` (0.0.0.0/0, ::/0) and `listed` (specific public ranges -- a partner,
 * a vendor, an office). Private ranges are never outside.
 *
 * Not modelled: network ACLs and firewall rules in front of the VPC. Both can
 * only close a path this reports as open, never open one it missed, so the
 * error is always "check this one", never "you missed that one".
 *
 * See docs/ATTACK-PATHS.md, "Open to the internet, and vulnerable on that port".
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_AWS_Exposure {

	/** @var array<string,mixed>|null */
	private static ?array $cache = null;

	/**
	 * Every way in, per asset.
	 *
	 * - `paths`: asset id => ways in, each {port_from, port_to, protocol,
	 *   reach (anyone|listed), sources, via (direct|lb), front, rule, route}.
	 *   `firewall` is inspected|none|unknown (see the class note).
	 *   `route` says how sure the routing half is: `subnet` when the subnet's
	 *   own table was read, `vpc` when only the VPC's was (a capture from
	 *   before associations were recorded).
	 * - `latent`: asset id => ways a rule opens to anyone although nothing
	 *   routes from outside today, same shape as `paths`. Not exposure; one
	 *   change away from it.
	 * - `doors`: internet-facing load-balancer listeners with nothing in the
	 *   inventory behind them: targets not captured yet (no `targets`), or
	 *   targets no asset record stands for (`targets` lists them -- an
	 *   instance no scanner knows, a container address; `managed` marks an
	 *   AWS-managed service such as Transfer Family).
	 * - `captured_at`: when the network map was last read.
	 *
	 * @return array{paths:array<int,array<int,array<string,mixed>>>,latent:array<int,array<int,array<string,mixed>>>,doors:array<int,array<string,mixed>>,captured_at:string}
	 */
	public static function all(): array {
		if ( null !== self::$cache ) {
			return self::$cache;
		}

		global $wpdb;

		$nt    = VulnHub_AWS_Network::nodes_table();
		$stamp = (string) $wpdb->get_var( "SELECT MAX(last_seen) FROM {$nt} WHERE source = 'aws'" ); // phpcs:ignore
		$key   = 'vh_aws_exposure_' . md5( $stamp . '|7' );
		$hit   = get_transient( $key );

		if ( is_array( $hit ) ) {
			return self::$cache = $hit;
		}

		self::$cache = self::build( $stamp );
		set_transient( $key, self::$cache, DAY_IN_SECONDS );

		return self::$cache;
	}

	/**
	 * @return array<string,mixed>
	 */
	private static function build( string $stamp ): array {
		global $wpdb;

		$nt = VulnHub_AWS_Network::nodes_table();

		/* ---- rules: which groups admit an outside source, on what ---- */
		$outside = array();

		foreach ( (array) $wpdb->get_results( 'SELECT group_id, protocol, from_port, to_port, source FROM ' . VulnHub_AWS_Network::rules_table() . " WHERE direction = 'in' AND source_type = 'cidr'", ARRAY_A ) as $r ) { // phpcs:ignore
			$src = (string) $r['source'];

			if ( self::is_private( $src ) ) {
				continue;
			}

			[ $from, $to ] = self::range( (string) $r['protocol'], (int) $r['from_port'], (int) $r['to_port'] );

			if ( $from < 0 ) {
				continue; // ICMP: nothing listens on it.
			}

			$is_any = in_array( $src, array( '0.0.0.0/0', '::/0' ), true );
			$proto  = self::protocol( (string) $r['protocol'] );
			$k      = $r['group_id'] . '|' . $r['protocol'] . '|' . $from . '|' . $to;

			if ( ! isset( $outside[ $r['group_id'] ][ $k ] ) ) {
				$outside[ $r['group_id'] ][ $k ] = array(
					'protocol'  => $proto,
					'port_from' => $from,
					'port_to'   => $to,
					'reach'     => 'listed',
					'sources'   => 0,
					'rule'      => (string) $r['group_id'],
				);
			}

			++$outside[ $r['group_id'] ][ $k ]['sources'];

			if ( $is_any ) {
				$outside[ $r['group_id'] ][ $k ]['reach'] = 'anyone';
			}
		}

		/* ---- routing: which subnets reach an internet gateway ---- */
		$table_igw  = array();
		$vpc_igw    = array();
		$table_gwlb = array();
		$vpc_gwlb   = array();

		foreach ( (array) $wpdb->get_results( 'SELECT vpc_id, route_table_id, dest_cidr, target_type, target_id FROM ' . VulnHub_AWS_Network::routes_table(), ARRAY_A ) as $r ) { // phpcs:ignore
			$default = in_array( (string) $r['dest_cidr'], array( '0.0.0.0/0', '::/0' ), true );

			if ( $default && 'igw' === $r['target_type'] ) {
				$table_igw[ (string) $r['route_table_id'] ] = true;
				$vpc_igw[ (string) $r['vpc_id'] ]           = true;
			}
			if ( str_starts_with( (string) $r['target_id'], 'vpce-' ) ) {
				$table_gwlb[ (string) $r['route_table_id'] ] = true;
				$vpc_gwlb[ (string) $r['vpc_id'] ]           = true;
			}
		}

		$subnet_rt = array();
		$vpc_main  = array();
		$vpc_edge  = array();
		$assoc_vpc = array(); // VPCs captured since associations were recorded.

		foreach ( (array) $wpdb->get_results( "SELECT node_type, resource_id, vpc_id, detail FROM {$nt} WHERE node_type IN ('subnet','vpc') AND source = 'aws'", ARRAY_A ) as $r ) { // phpcs:ignore
			$d = json_decode( (string) $r['detail'], true );

			if ( ! is_array( $d ) ) {
				continue;
			}
			if ( 'subnet' === $r['node_type'] && ! empty( $d['route_table'] ) ) {
				$subnet_rt[ (string) $r['resource_id'] ] = (string) $d['route_table'];
				$assoc_vpc[ (string) $r['vpc_id'] ]      = true;
			}
			if ( 'vpc' === $r['node_type'] && ! empty( $d['main_route_table'] ) ) {
				$vpc_main[ (string) $r['resource_id'] ] = (string) $d['main_route_table'];
				$assoc_vpc[ (string) $r['resource_id'] ] = true;
			}
			if ( 'vpc' === $r['node_type'] && ! empty( $d['edge_route_table'] ) ) {
				$vpc_edge[ (string) $r['resource_id'] ] = (string) $d['edge_route_table'];
			}
		}

		// Is there an inline firewall in front of inbound traffic to this VPC?
		$firewall = static function ( string $vpc ) use ( $vpc_gwlb, $vpc_edge, $table_gwlb, $assoc_vpc ): string {
			if ( isset( $vpc_edge[ $vpc ] ) && isset( $table_gwlb[ $vpc_edge[ $vpc ] ] ) ) {
				return 'inspected';
			}
			if ( ! isset( $vpc_gwlb[ $vpc ] ) || isset( $assoc_vpc[ $vpc ] ) ) {
				return 'none';
			}

			return 'unknown';
		};

		// '' when the subnet cannot route out, else how sure that is.
		$routable = static function ( string $subnet, string $vpc ) use ( $subnet_rt, $vpc_main, $table_igw, $vpc_igw ): string {
			$rt = $subnet_rt[ $subnet ] ?? ( $vpc_main[ $vpc ] ?? '' );

			if ( '' !== $rt ) {
				return isset( $table_igw[ $rt ] ) ? 'subnet' : '';
			}

			return isset( $vpc_igw[ $vpc ] ) ? 'vpc' : '';
		};

		/* ---- interfaces: every public address, and the machine behind it ---- */
		$asset_of = array();

		foreach ( (array) $wpdb->get_results( 'SELECT id, aws_instance_id FROM ' . vh_table( 'assets' ) . " WHERE aws_instance_id <> ''", ARRAY_A ) as $r ) { // phpcs:ignore
			$asset_of[ (string) $r['aws_instance_id'] ] = (int) $r['id'];
		}

		$by_private = array();
		$faces      = array();

		foreach ( (array) $wpdb->get_results( "SELECT node_type, resource_id, vpc_id, subnet_id, private_ip, public_ip, sg_ids, detail FROM {$nt} WHERE node_type IN ('instance','eni') AND source = 'aws'", ARRAY_A ) as $r ) { // phpcs:ignore
			$d    = json_decode( (string) $r['detail'], true );
			$iid  = 'instance' === $r['node_type'] ? (string) $r['resource_id'] : (string) ( is_array( $d ) ? ( $d['instance'] ?? '' ) : '' );
			$sgs  = array_values( array_filter( array_map( 'trim', explode( ',', (string) $r['sg_ids'] ) ) ) );

			if ( '' === $iid ) {
				continue;
			}

			if ( '' !== (string) $r['private_ip'] ) {
				$by_private[ (string) $r['private_ip'] ] = $iid;
			}

			$faces[ $iid ][] = array(
				'public' => (string) $r['public_ip'],
				'subnet' => (string) $r['subnet_id'],
				'vpc'    => (string) $r['vpc_id'],
				'sgs'    => $sgs,
			);
		}

		$paths  = array();
		$latent = array();

		foreach ( $faces as $iid => $list ) {
			$asset = $asset_of[ $iid ] ?? 0;

			if ( ! $asset ) {
				continue;
			}

			foreach ( $list as $face ) {
				$route = '' !== $face['public'] ? $routable( $face['subnet'], $face['vpc'] ) : '';

				foreach ( $face['sgs'] as $gid ) {
					foreach ( $outside[ $gid ] ?? array() as $rule ) {
						if ( '' !== $route ) {
							$paths[ $asset ][] = $rule + array(
								'via'      => 'direct',
								'front'    => $face['public'],
								'route'    => $route,
								'firewall' => $firewall( $face['vpc'] ),
							);
						} elseif ( 'anyone' === $rule['reach'] ) {
							$latent[ $asset ][ self::label( $rule ) ] = $rule + array(
								'via'      => 'direct',
								'front'    => '',
								'route'    => '',
								'firewall' => $firewall( $face['vpc'] ),
							);
						}
					}
				}
			}
		}

		/* ---- load balancers: servers published without an address of their own ---- */
		$doors = array();

		foreach ( (array) $wpdb->get_results( "SELECT account_id, resource_id, name, vpc_id, sg_ids, detail FROM {$nt} WHERE node_type = 'elb' AND source = 'aws'", ARRAY_A ) as $r ) { // phpcs:ignore
			$d = json_decode( (string) $r['detail'], true );

			if ( ! is_array( $d ) || 'internet-facing' !== (string) ( $d['scheme'] ?? '' ) ) {
				continue;
			}

			$sgs = array_values( array_filter( array_map( 'trim', explode( ',', (string) $r['sg_ids'] ) ) ) );

			foreach ( (array) ( $d['listeners'] ?? array() ) as $listener ) {
				[ $proto, $port ] = array_pad( explode( '/', (string) $listener, 2 ), 2, '' );
				$port             = (int) $port;
				$admit            = self::admits( $sgs, $outside, $port );

				if ( null === $admit ) {
					continue; // Its own rules keep the internet out.
				}

				if ( ! isset( $d['targets'] ) ) {
					$doors[] = array(
						'name'     => (string) $r['name'],
						'listener' => (string) $listener,
						'reach'    => $admit['reach'],
						'firewall' => $firewall( (string) $r['vpc_id'] ),
					);
					continue;
				}

				$unknown = array();

				foreach ( self::targets_behind( $d, (string) $listener ) as $t ) {
					$iid   = str_starts_with( $t['id'], 'i-' ) ? $t['id'] : ( $by_private[ $t['id'] ] ?? '' );
					$asset = $asset_of[ $iid ] ?? 0;

					// Published, and nothing in the inventory stands behind it:
					// an instance no scanner knows, or a container address.
					if ( ! $asset ) {
						$unknown[] = $t['id'] . ( $t['port'] > 0 ? ':' . $t['port'] : '' );
						continue;
					}
					if ( $t['port'] <= 0 ) {
						continue;
					}

					$paths[ $asset ][] = array(
						'protocol'  => 'tcp',
						'port_from' => $t['port'],
						'port_to'   => $t['port'],
						'reach'     => $admit['reach'],
						'sources'   => $admit['sources'],
						'rule'      => $admit['rule'],
						'via'       => 'lb',
						'front'     => (string) $r['name'] . ' ' . strtolower( $proto ) . '/' . $port,
						'route'     => 'subnet',
						'firewall'  => $firewall( (string) $r['vpc_id'] ),
					);
				}

				if ( $unknown ) {
					$doors[] = array(
						'name'     => (string) $r['name'],
						'listener' => (string) $listener,
						'reach'    => $admit['reach'],
						'firewall' => $firewall( (string) $r['vpc_id'] ),
						'targets'  => array_values( array_unique( $unknown ) ),
						// A managed service (SFTP through Transfer Family) is
						// AWS's to patch, not a server of ours.
						'managed'  => str_contains( strtolower( (string) $r['name'] ), 'transfer-family' ),
					);
				}
			}
		}

		// An instance's primary interface is captured twice, as the instance
		// and as the interface, so the same way in arrives twice.
		foreach ( $paths as $asset => $ways ) {
			$seen = array();

			foreach ( $ways as $w ) {
				$seen[ implode( '|', array( $w['protocol'], $w['port_from'], $w['port_to'], $w['reach'], $w['via'], $w['front'] ) ) ] = $w;
			}

			$paths[ $asset ] = array_values( $seen );
		}

		foreach ( $latent as $asset => $ways ) {
			$latent[ $asset ] = array_values( $ways );
		}

		return array(
			'paths'       => $paths,
			'latent'      => $latent,
			'doors'       => $doors,
			'captured_at' => $stamp,
		);
	}

	/**
	 * Assets with a way in, and the first one described -- what the exposure
	 * verdict records as its reason.
	 *
	 * @return array<int,string>
	 */
	public static function reachable_assets(): array {
		$out = array();

		foreach ( self::all()['paths'] as $asset => $ways ) {
			usort( $ways, static fn( array $a, array $b ): int => ( 'anyone' === $b['reach'] ) <=> ( 'anyone' === $a['reach'] ) );
			$w = $ways[0];

			$out[ (int) $asset ] = sprintf(
				/* translators: 1: port, 2: who, 3: how. */
				__( '%1$s open to %2$s %3$s (AWS security group)', 'vulnhub' ),
				self::label( $w ),
				'anyone' === $w['reach'] ? __( 'anyone', 'vulnhub' ) : __( 'listed outside addresses', 'vulnhub' ),
				'lb' === $w['via'] ? __( 'through a load balancer', 'vulnhub' ) : __( 'on its public address', 'vulnhub' )
			);
		}

		return $out;
	}

	/**
	 * The strongest outside rule among a balancer's groups covering a port,
	 * or null when none admits it. A balancer with no groups (a network load
	 * balancer) admits everything on its listeners.
	 *
	 * @param string[]                                       $sgs     Group ids.
	 * @param array<string,array<string,array<string,mixed>>> $outside Rules by group.
	 * @return array{reach:string,sources:int,rule:string}|null
	 */
	private static function admits( array $sgs, array $outside, int $port ): ?array {
		if ( ! $sgs ) {
			return array( 'reach' => 'anyone', 'sources' => 1, 'rule' => '' );
		}

		$best = null;

		foreach ( $sgs as $gid ) {
			foreach ( $outside[ $gid ] ?? array() as $rule ) {
				if ( $port < $rule['port_from'] || $port > $rule['port_to'] ) {
					continue;
				}
				if ( ! $best || ( 'anyone' === $rule['reach'] && 'anyone' !== $best['reach'] ) ) {
					$best = array( 'reach' => $rule['reach'], 'sources' => (int) $rule['sources'], 'rule' => $gid );
				}
			}
		}

		return $best;
	}

	/**
	 * The targets one listener sends to, with the port on the target.
	 *
	 * @param array<string,mixed> $d Balancer detail.
	 * @return array<int,array{id:string,port:int}>
	 */
	private static function targets_behind( array $d, string $listener ): array {
		$fwd     = (array) ( $d['forwards'][ $listener ] ?? array() );
		$targets = (array) ( $d['targets'] ?? array() );
		$out     = array();

		// Classic: the listener names its instance port, and every instance
		// registered on the balancer receives it.
		foreach ( $fwd as $f ) {
			if ( str_starts_with( (string) $f, 'port:' ) ) {
				foreach ( $targets as $t ) {
					$out[] = array( 'id' => (string) $t['id'], 'port' => (int) substr( (string) $f, 5 ) );
				}

				return $out;
			}
		}

		foreach ( $targets as $t ) {
			if ( in_array( (string) ( $t['tg'] ?? '' ), $fwd, true ) ) {
				$out[] = array( 'id' => (string) $t['id'], 'port' => (int) $t['port'] );
			}
		}

		return $out;
	}

	/**
	 * A rule's ports as one span. Protocol -1 is every port; ICMP has none.
	 *
	 * @return array{0:int,1:int}
	 */
	private static function range( string $protocol, int $from, int $to ): array {
		$protocol = self::protocol( $protocol );

		if ( 'all' === $protocol ) {
			return array( 0, 65535 );
		}
		if ( in_array( $protocol, array( 'icmp', 'icmpv6', '1', '58' ), true ) ) {
			return array( -1, -1 );
		}
		if ( $from < 0 || $to < 0 ) {
			return array( 0, 65535 );
		}

		return array( $from, max( $from, $to ) );
	}

	/**
	 * One spelling per protocol. The capture has written "every protocol"
	 * as both `-1` (the API's value) and `any`, and a rule that is read as
	 * protocol "any" admits nothing -- which is how an every-port rule
	 * matched no service at all.
	 */
	private static function protocol( string $p ): string {
		$p = strtolower( trim( $p ) );

		return match ( $p ) {
			'-1', 'any', 'all', '' => 'all',
			'6'                    => 'tcp',
			'17'                   => 'udp',
			default                => $p,
		};
	}

	/** tcp/22, tcp/1024-65535, all ports. */
	public static function label( array $rule ): string {
		if ( 0 === (int) $rule['port_from'] && 65535 === (int) $rule['port_to'] ) {
			return __( 'every port', 'vulnhub' );
		}

		$proto = 'all' === (string) $rule['protocol'] ? '' : (string) $rule['protocol'] . '/';

		return $proto . ( (int) $rule['port_from'] === (int) $rule['port_to'] ? (string) $rule['port_from'] : $rule['port_from'] . '-' . $rule['port_to'] );
	}

	/**
	 * Whether a CIDR is inside the estate rather than outside it: RFC 1918,
	 * carrier-grade NAT, loopback and link-local, and IPv6 unique-local and
	 * link-local. A source that fails to parse is treated as inside -- it
	 * cannot be shown to be the internet.
	 */
	private static function is_private( string $cidr ): bool {
		$ip = strtolower( trim( (string) strtok( $cidr, '/' ) ) );

		if ( str_contains( $ip, ':' ) ) {
			return '::' !== $ip && ( str_starts_with( $ip, 'fc' ) || str_starts_with( $ip, 'fd' ) || str_starts_with( $ip, 'fe80' ) || '::1' === $ip );
		}

		$long = ip2long( $ip );

		if ( false === $long ) {
			return true;
		}
		if ( '0.0.0.0' === $ip ) {
			return false;
		}

		foreach ( array( '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16' ) as $net ) {
			[ $base, $bits ] = explode( '/', $net );
			$mask            = -1 << ( 32 - (int) $bits );

			if ( ( $long & $mask ) === ( ip2long( $base ) & $mask ) ) {
				return true;
			}
		}

		return false;
	}
}
