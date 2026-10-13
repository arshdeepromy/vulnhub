<?php
/**
 * The firewalls' own view of the network: each gateway's interfaces, the
 * networks its topology says sit behind each one, which interface AWS
 * traffic comes in on, and the rules that carry traffic between AWS and the
 * rest of the network.
 *
 * Everything here is read from the stored policy snapshot (the gateway and
 * cluster objects carry their interfaces and topology; the rule base and
 * objects say what each rule names) and from the AWS network capture (VPC
 * ranges). Nothing is fetched.
 *
 * Why the interface topology matters: it is the firewall's anti-spoofing
 * definition -- the networks a packet arriving on that interface is allowed
 * to come from. An internal interface whose topology lists dozens of AWS
 * VPC ranges is where AWS reaches the on-premises network; an interface
 * defined by its own address and mask is a segment the firewall is plugged
 * straight into. Both are the firewall's word, not an inference from asset
 * addresses.
 *
 * Shape of the model (cached per policy read and AWS capture):
 *
 *   gateways[] = { name, kind (cluster|gateway), site, policy,
 *                  ifaces[] = { name, cidr, from, to, kind (internal|dmz|internet),
 *                               spec (topology group name), behind[] = [from, to, label],
 *                               aws (count of AWS VPC ranges behind it) } }
 *   entry      = { gateway, site, policy, iface, cidr, aws, vpcs } | null
 *   rules[]    = { label, number, name, dir (aws-onprem|onprem-aws|both), src, dst,
 *                  ports, broad, aws_src[[from,to]], aws_dst[[from,to]] }
 *
 * @package VulnHub\CheckPoint
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_CheckPoint_Interfaces {

	private const CACHE = 'vulnhub_cp_ifaces';

	/** Interfaces need at least this many AWS ranges behind them to count as where AWS comes in. */
	private const ENTRY_MIN = 3;

	/** @var array<string,mixed>|null */
	private static ?array $model = null;

	/**
	 * The whole model, from cache when the policy and the AWS capture have
	 * not moved.
	 *
	 * @return array{gateways:array<int,array<string,mixed>>,entry:?array<string,mixed>,rules:array<int,array<string,mixed>>}
	 */
	public static function model(): array {
		if ( null !== self::$model ) {
			return self::$model;
		}

		$empty = array( 'gateways' => array(), 'entry' => null, 'rules' => array() );

		if ( ! class_exists( 'VulnHub_CheckPoint_Store' ) ) {
			return self::$model = $empty;
		}

		$key = self::CACHE . '_' . md5( (string) get_option( VulnHub_CheckPoint_Store::STAMP_OPTION, '' ) . '|' . self::aws_stamp() );
		$hit = get_transient( $key );

		if ( is_array( $hit ) && isset( $hit['gateways'] ) ) {
			return self::$model = $hit;
		}

		$model = self::build();
		set_transient( $key, $model, 12 * HOUR_IN_SECONDS );

		return self::$model = $model;
	}

	private static function aws_stamp(): string {
		global $wpdb;

		if ( ! class_exists( 'VulnHub_AWS_Network' ) ) {
			return '';
		}

		return (string) $wpdb->get_var( 'SELECT MAX(last_seen) FROM ' . VulnHub_AWS_Network::nodes_table() . " WHERE node_type = 'vpc'" ); // phpcs:ignore
	}

	/**
	 * AWS VPC ranges, each with its VPC's name.
	 *
	 * @return array<int,array{0:int,1:int,2:string}>
	 */
	public static function aws_ranges(): array {
		global $wpdb;

		if ( ! class_exists( 'VulnHub_AWS_Network' ) ) {
			return array();
		}

		$names = array();
		$out   = array();

		foreach ( (array) $wpdb->get_results( 'SELECT resource_id, name, detail FROM ' . VulnHub_AWS_Network::nodes_table() . " WHERE node_type = 'vpc'", ARRAY_A ) as $r ) { // phpcs:ignore
			$names[ (string) $r['resource_id'] ] = '' !== (string) $r['name'] ? (string) $r['name'] : (string) $r['resource_id'];
			$cidr                                = str_replace( '\\/', '/', (string) ( json_decode( (string) $r['detail'], true )['cidr'] ?? '' ) );

			if ( '' !== $cidr ) {
				$out[ $cidr . '|' . $r['resource_id'] ] = $cidr;
			}
		}

		// Secondary ranges only show as local routes.
		foreach ( (array) $wpdb->get_results( 'SELECT DISTINCT vpc_id, dest_cidr FROM ' . VulnHub_AWS_Network::routes_table() . " WHERE target_type = 'local' AND LOCATE( ':', dest_cidr ) = 0", ARRAY_A ) as $r ) { // phpcs:ignore
			$out[ $r['dest_cidr'] . '|' . $r['vpc_id'] ] = (string) $r['dest_cidr'];
		}

		$ranges = array();

		foreach ( $out as $k => $cidr ) {
			$vpc = (string) substr( $k, (int) strpos( $k, '|' ) + 1 );
			[ $net, $len ] = array_pad( explode( '/', $cidr ), 2, '32' );

			if ( null === VulnHub_CheckPoint_Policy::ip2int( $net ) ) {
				continue;
			}

			[ $from, $to ] = VulnHub_CheckPoint_Policy::cidr( $net, (int) $len );
			$ranges[]      = array( $from, $to, (string) ( $names[ $vpc ] ?? $vpc ) );
		}

		return $ranges;
	}

	/* =================================================================
	 * Building the model
	 * ============================================================== */

	/** @return array{gateways:array<int,array<string,mixed>>,entry:?array<string,mixed>,rules:array<int,array<string,mixed>>} */
	private static function build(): array {
		global $wpdb;

		$objs = VulnHub_CheckPoint_Store::objects();
		$aws  = self::aws_ranges();
		$site = array();

		foreach ( (array) $wpdb->get_results( 'SELECT name, site FROM ' . VulnHub_CheckPoint_Store::table( 'gateways' ) . " WHERE name <> ''", ARRAY_A ) as $g ) { // phpcs:ignore
			$site[ (string) $g['name'] ] = (string) $g['site'];
		}

		$gateways = array();

		foreach ( $objs as $o ) {
			$type = (string) ( $o['type'] ?? '' );

			if ( 'CpmiGatewayCluster' !== $type && 'simple-gateway' !== $type ) {
				continue;
			}

			$name    = (string) ( $o['name'] ?? '' );
			$members = array_map( 'strval', (array) ( $o['cluster-member-names'] ?? array() ) );
			$where   = (string) ( $site[ $name ] ?? '' );

			foreach ( $members as $m ) {
				if ( '' === $where && '' !== (string) ( $site[ $m ] ?? '' ) ) {
					$where = (string) $site[ $m ];
				}
			}

			$ifaces = array();

			foreach ( (array) ( $o['interfaces'] ?? array() ) as $i ) {
				$row = self::iface( (array) $i, $objs, $aws );

				if ( $row ) {
					$ifaces[] = $row;
				}
			}

			$gateways[] = array(
				'name'    => $name,
				'kind'    => 'CpmiGatewayCluster' === $type ? 'cluster' : 'gateway',
				'members' => $members,
				'site'    => $where,
				'policy'  => (string) ( $o['policy']['access-policy-name'] ?? '' ),
				'ifaces'  => $ifaces,
			);
		}

		usort( $gateways, static fn( array $a, array $b ): int => array( '' === $a['site'], 'cluster' !== $a['kind'], $a['site'], $a['name'] ) <=> array( '' === $b['site'], 'cluster' !== $b['kind'], $b['site'], $b['name'] ) );

		$entry = self::entry( $gateways );
		$rules = $entry ? self::hybrid_rules( $entry['policy'], $objs, $aws ) : array();

		return array( 'gateways' => $gateways, 'entry' => $entry, 'rules' => $rules );
	}

	/**
	 * One interface, its topology resolved.
	 *
	 * @param array<string,mixed>               $i    Interface as the gateway object carries it.
	 * @param array<string,array<string,mixed>> $objs uid => object.
	 * @param array<int,array{0:int,1:int,2:string}> $aws AWS ranges.
	 * @return array<string,mixed>|null
	 */
	private static function iface( array $i, array $objs, array $aws ): ?array {
		$ip  = (string) ( $i['ipv4-address'] ?? '' );
		$len = (int) ( $i['ipv4-mask-length'] ?? 0 );
		$n   = VulnHub_CheckPoint_Policy::ip2int( $ip );

		if ( null === $n || $len < 1 ) {
			return null;
		}

		[ $from, $to ] = VulnHub_CheckPoint_Policy::cidr( $ip, $len );
		$topo          = (array) ( $i['topology'] ?? array() );
		$kind          = ! empty( $topo['leads-to-internet'] ) ? 'internet' : ( ! empty( $topo['leads-to-dmz'] ) ? 'dmz' : 'internal' );
		$spec          = $topo['leads-to-specific-network'] ?? null;
		$behind        = array();
		$spec_name     = '';

		if ( 'internet' !== $kind ) {
			$behind[] = array( $from, $to, __( 'interface subnet', 'vulnhub' ) );

			if ( is_array( $spec ) && '' !== (string) ( $spec['uid'] ?? '' ) ) {
				$spec_name = (string) ( $spec['name'] ?? '' );
				$behind    = array_merge( $behind, self::named_ranges( (string) $spec['uid'], $objs ) );
			}
		}

		$aws_hit = array();

		foreach ( $behind as $b ) {
			foreach ( $aws as $v ) {
				// A range counts as AWS only when it sits inside a VPC range:
				// the RFC 1918 summaries overlap every VPC and say nothing.
				if ( $b[0] >= $v[0] && $b[1] <= $v[1] ) {
					$aws_hit[ $v[2] ] = true;
					break;
				}
			}
		}

		return array(
			'name'   => (string) ( $i['interface-name'] ?? $i['name'] ?? '' ),
			'cidr'   => VulnHub_CheckPoint_Policy::int2ip( $from ) . '/' . $len,
			'ip'     => $ip,
			'from'   => $from,
			'to'     => $to,
			'kind'   => $kind,
			'spec'   => $spec_name,
			'behind' => $behind,
			'aws'    => count( $aws_hit ),
			'vpcs'   => array_slice( array_keys( $aws_hit ), 0, 60 ),
		);
	}

	/**
	 * Networks, hosts and ranges a group stands for, each with its name.
	 *
	 * @param array<string,array<string,mixed>> $objs uid => object.
	 * @param array<string,bool>                $seen Cycle guard.
	 * @return array<int,array{0:int,1:int,2:string}>
	 */
	private static function named_ranges( string $uid, array $objs, array &$seen = array(), int $depth = 0 ): array {
		if ( isset( $seen[ $uid ] ) || $depth > 12 || ! isset( $objs[ $uid ] ) ) {
			return array();
		}
		$seen[ $uid ] = true;

		$o    = $objs[ $uid ];
		$type = (string) ( $o['type'] ?? '' );
		$name = (string) ( $o['name'] ?? '' );

		if ( 'network' === $type && null !== VulnHub_CheckPoint_Policy::ip2int( (string) ( $o['subnet4'] ?? '' ) ) ) {
			[ $a, $b ] = VulnHub_CheckPoint_Policy::cidr( (string) $o['subnet4'], (int) ( $o['mask-length4'] ?? 32 ) );
			return array( array( $a, $b, $name ) );
		}
		if ( 'address-range' === $type ) {
			$a = VulnHub_CheckPoint_Policy::ip2int( (string) ( $o['ipv4-address-first'] ?? '' ) );
			$b = VulnHub_CheckPoint_Policy::ip2int( (string) ( $o['ipv4-address-last'] ?? '' ) );
			return null !== $a && null !== $b ? array( array( min( $a, $b ), max( $a, $b ), $name ) ) : array();
		}
		if ( 'group' === $type ) {
			$out = array();
			foreach ( (array) ( $o['members'] ?? array() ) as $m ) {
				$m   = is_array( $m ) ? (string) ( $m['uid'] ?? '' ) : (string) $m;
				$out = array_merge( $out, self::named_ranges( $m, $objs, $seen, $depth + 1 ) );
			}
			return $out;
		}

		$ip = VulnHub_CheckPoint_Policy::ip2int( (string) ( $o['ipv4-address'] ?? '' ) );

		return null !== $ip ? array( array( $ip, $ip, $name ) ) : array();
	}

	/**
	 * The internal interface with the most AWS ranges behind it.
	 *
	 * @param array<int,array<string,mixed>> $gateways
	 * @return array<string,mixed>|null
	 */
	private static function entry( array $gateways ): ?array {
		$best = null;

		foreach ( $gateways as $g ) {
			foreach ( $g['ifaces'] as $i ) {
				if ( 'internet' === $i['kind'] || $i['aws'] < self::ENTRY_MIN ) {
					continue;
				}
				if ( null === $best || $i['aws'] > $best['aws'] ) {
					$best = array(
						'gateway' => $g['name'],
						'site'    => $g['site'],
						'policy'  => $g['policy'],
						'iface'   => $i['name'],
						'cidr'    => $i['cidr'],
						'spec'    => $i['spec'],
						'aws'     => $i['aws'],
						'vpcs'    => $i['vpcs'],
					);
				}
			}
		}

		return $best;
	}

	/**
	 * Accept rules in the entry gateway's policy that carry traffic between
	 * AWS and anything that is not AWS.
	 *
	 * A side is AWS when it names a range inside an AWS VPC range; it is
	 * the rest of the network when it names a private range outside every
	 * VPC, or Any. A rule whose AWS side is only an RFC 1918 summary does
	 * not count -- it covers AWS by accident, not by intent.
	 *
	 * @param array<string,array<string,mixed>>      $objs uid => object.
	 * @param array<int,array{0:int,1:int,2:string}> $aws  AWS ranges.
	 * @return array<int,array<string,mixed>>
	 */
	private static function hybrid_rules( string $package, array $objs, array $aws ): array {
		if ( '' === $package ) {
			return array();
		}

		$pol = new VulnHub_CheckPoint_Policy( $objs );
		$rb  = VulnHub_CheckPoint_Store::rules();
		$out = array();

		$walk = static function ( array $rules, string $layer ) use ( &$walk, $pol, $rb, $aws, $package, &$out ): void {
			foreach ( $rules as $r ) {
				if ( array_key_exists( 'enabled', $r ) && ! $r['enabled'] ) {
					continue;
				}

				$act = $pol->action( $r );

				if ( 'layer' === $act ) {
					$inner = (string) ( $r['inline-layer'] ?? '' );
					if ( '' !== $inner && isset( $rb['inline'][ $inner ] ) ) {
						$walk( $rb['inline'][ $inner ], (string) ( $r['name'] ?? '' ) );
					}
					continue;
				}
				if ( 'allow' !== $act ) {
					continue;
				}

				$src = self::side( $pol->column( $r['source'] ?? array() ), ! empty( $r['source-negate'] ), $aws );
				$dst = self::side( $pol->column( $r['destination'] ?? array() ), ! empty( $r['destination-negate'] ), $aws );

				$out_dir = ( $src['aws'] && $dst['other'] );
				$in_dir  = ( $src['other'] && $dst['aws'] );

				if ( ! $out_dir && ! $in_dir ) {
					continue;
				}

				$svc   = $pol->rule_services( $r );
				$ports = VulnHub_CheckPoint_Policy::describe_ports( $svc );

				$out[] = array(
					'label'   => trim( $package . ' #' . (string) ( $r['rule-number'] ?? '?' ) . ( '' !== trim( (string) ( $r['name'] ?? '' ) ) ? ' ' . trim( (string) $r['name'] ) : '' ) ),
					'number'  => (string) ( $r['rule-number'] ?? '' ),
					'name'    => trim( (string) ( $r['name'] ?? '' ) ),
					'layer'   => $layer,
					'dir'     => $out_dir && $in_dir ? 'both' : ( $out_dir ? 'aws-onprem' : 'onprem-aws' ),
					'src'     => self::names( $pol, $r['source'] ?? array(), ! empty( $r['source-negate'] ) ),
					'dst'     => self::names( $pol, $r['destination'] ?? array(), ! empty( $r['destination-negate'] ) ),
					'ports'   => '' !== $ports ? $ports : __( 'other protocols only', 'vulnhub' ),
					'anyport' => self::any_port( $svc ),
					'broad'   => $src['any'] || $dst['any'],
					'aws_src' => $src['aws_ranges'],
					'aws_dst' => $dst['aws_ranges'],
				);
			}
		};

		$walk( (array) ( $rb['packages'][ $package ] ?? array() ), '' );

		return $out;
	}

	/**
	 * @param array{any:bool,internet:bool,unknown:int,ranges:array<int,array{0:int,1:int}>} $col
	 * @param array<int,array{0:int,1:int,2:string}>                                          $aws
	 * @return array{any:bool,aws:bool,other:bool,aws_ranges:array<int,array{0:int,1:int}>}
	 */
	private static function side( array $col, bool $negate, array $aws ): array {
		if ( $negate || $col['any'] ) {
			return array( 'any' => true, 'aws' => false, 'other' => true, 'aws_ranges' => array() );
		}

		$aws_r = array();
		$other = $col['internet'];

		foreach ( $col['ranges'] as $r ) {
			$inside = false;

			foreach ( $aws as $v ) {
				if ( $r[0] >= $v[0] && $r[1] <= $v[1] ) {
					$inside = true;
					break;
				}
			}

			if ( $inside ) {
				$aws_r[] = array( $r[0], $r[1] );
			} elseif ( VulnHub_CheckPoint_Policy::is_private( $r[0] ) ) {
				$other = true;
			}
		}

		return array( 'any' => false, 'aws' => (bool) $aws_r, 'other' => $other, 'aws_ranges' => VulnHub_CheckPoint_Policy::merge( $aws_r ) );
	}

	/** @param array<string,array<int,array{0:int,1:int}>> $svc */
	private static function any_port( array $svc ): bool {
		foreach ( array( 'tcp', 'udp' ) as $p ) {
			foreach ( (array) ( $svc[ $p ] ?? array() ) as $iv ) {
				if ( 1 === (int) $iv[0] && 65535 === (int) $iv[1] ) {
					return true;
				}
			}
		}

		return false;
	}

	private static function names( VulnHub_CheckPoint_Policy $pol, mixed $col, bool $negate ): string {
		$names = array();

		foreach ( (array) $col as $v ) {
			$u = is_array( $v ) ? (string) ( $v['uid'] ?? '' ) : (string) $v;
			if ( '' !== $u ) {
				$names[] = $pol->name( $u );
			}
		}

		$s = implode( ', ', array_slice( $names, 0, 3 ) ) . ( count( $names ) > 3 ? sprintf( ' +%d', count( $names ) - 3 ) : '' );

		return ( $negate ? __( 'not ', 'vulnhub' ) : '' ) . ( '' !== $s ? $s : __( 'Any', 'vulnhub' ) );
	}

	/* =================================================================
	 * Lookups for the diagram and the asset page
	 * ============================================================== */

	/**
	 * Where the firewalls place an address: the segment an interface is
	 * plugged into (most specific first), else the most specific network an
	 * interface's topology lists behind it. Summaries wider than /16 are
	 * skipped -- they are anti-spoofing catch-alls, not places.
	 *
	 * @return array{gateway:string,site:string,iface:string,cidr:string,how:string,label:string}|null
	 */
	public static function place( string $ip ): ?array {
		$n = VulnHub_CheckPoint_Policy::ip2int( $ip );

		if ( null === $n ) {
			return null;
		}

		$best = null;
		$size = PHP_INT_MAX;

		foreach ( self::model()['gateways'] as $g ) {
			foreach ( $g['ifaces'] as $i ) {
				if ( 'internet' === $i['kind'] ) {
					continue;
				}

				foreach ( $i['behind'] as $k => $b ) {
					$w = $b[1] - $b[0];

					if ( $n < $b[0] || $n > $b[1] || $w > 65535 ) {
						continue;
					}

					// A directly connected segment wins a tie with a listed one.
					$score = $w * 2 + ( 0 === $k ? 0 : 1 );

					if ( $score < $size ) {
						$size = $score;
						$best = array(
							'gateway' => (string) $g['name'],
							'site'    => (string) $g['site'],
							'iface'   => (string) $i['name'],
							'cidr'    => 0 === $k ? (string) $i['cidr'] : self::span( (int) $b[0], (int) $b[1] ),
							'how'     => 0 === $k ? 'connected' : 'listed',
							'label'   => (string) $b[2],
						);
					}
				}
			}
		}

		return $best;
	}

	/**
	 * Rules that carry traffic for one AWS address, by direction.
	 *
	 * @return array{out:array<int,array<string,mixed>>,in:array<int,array<string,mixed>>}
	 */
	public static function rules_for( string $ip ): array {
		$n   = VulnHub_CheckPoint_Policy::ip2int( $ip );
		$res = array( 'out' => array(), 'in' => array() );

		if ( null === $n ) {
			return $res;
		}

		foreach ( self::model()['rules'] as $r ) {
			if ( VulnHub_CheckPoint_Policy::covers( (array) $r['aws_src'], $n ) ) {
				$res['out'][] = $r;
			}
			if ( VulnHub_CheckPoint_Policy::covers( (array) $r['aws_dst'], $n ) ) {
				$res['in'][] = $r;
			}
		}

		return $res;
	}

	/**
	 * Directly connected internal segments of a gateway, as "eth3 · 10.245.10.0/24".
	 *
	 * @param array<string,mixed> $g Gateway from the model.
	 * @return string[]
	 */
	public static function segments( array $g ): array {
		$out = array();

		foreach ( (array) $g['ifaces'] as $i ) {
			if ( 'internet' === $i['kind'] || str_starts_with( (string) $i['ip'], '169.254.' ) ) {
				continue;
			}
			$out[] = $i['name'] . ' · ' . $i['cidr'] . ( 'dmz' === $i['kind'] ? ' ' . __( '(DMZ)', 'vulnhub' ) : '' );
		}

		return $out;
	}

	/** "10.251.16.0/20" when the range is a block, "10.251.0.1–10.251.0.9" when not. */
	public static function span( int $from, int $to ): string {
		$size = $to - $from + 1;

		if ( $size > 0 && 0 === ( $size & ( $size - 1 ) ) && 0 === $from % $size ) {
			return VulnHub_CheckPoint_Policy::int2ip( $from ) . ( 1 === $size ? '' : '/' . ( 32 - (int) round( log( $size, 2 ) ) ) );
		}

		return VulnHub_CheckPoint_Policy::int2ip( $from ) . '–' . VulnHub_CheckPoint_Policy::int2ip( $to );
	}

	/** Forget the cached model (after a new policy read). */
	public static function flush(): void {
		self::$model = null;
	}
}

