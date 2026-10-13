<?php
/**
 * Reads a Check Point policy the way the gateway does, far enough to say
 * which machines the internet can reach, on which ports, and through which
 * rule.
 *
 * What it models:
 *
 *   - Objects: hosts, networks, address ranges, groups (nested), groups with
 *     exclusion, gateways, `Any`, the `Internet` object and security zones
 *     named as external. Services: TCP and UDP ports and ranges
 *     (`80`, `8080-8090`, `>1023`, `<1024`), service groups, `Any`.
 *   - Negated source, destination and service columns.
 *   - First match, in rule order: an earlier Drop or Reject from the
 *     internet closes those ports for every rule below it, so an Accept
 *     that can never be reached does not count.
 *   - Inline layers: the parent rule narrows what the inner rules can see.
 *   - Static NAT, automatic (from a host's NAT settings) and manual (a NAT
 *     rule from a public address to a private one): a private machine is
 *     reachable on its public address. An access rule naming either address
 *     counts.
 *
 * What it does not (each is said on the page and in docs/CHECKPOINT.md):
 *
 *   - Only the first ordered layer of each package is read. Traffic must
 *     also pass the later layers (application control, for example), so a
 *     port shown open here may still be blocked further on; never the
 *     reverse.
 *   - Which gateway a machine sits behind is not known, so every package is
 *     read against every machine and their answers are combined.
 *   - A rule whose destination is `Any` (or negated) is not mapped onto
 *     machines -- that would call the whole estate reachable. It is listed
 *     as a broad rule instead, which is its own finding.
 *   - Time objects, install-on, VPN columns and access roles are ignored.
 *     Objects it cannot resolve (dynamic, updatable, domain objects) make a
 *     source "listed" rather than "anyone", and a destination unmatched.
 *
 * Pure logic: no database, no network. The connector hands it objects and
 * rules; the store writes what it returns.
 *
 * @package VulnHub\CheckPoint
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_CheckPoint_Policy {

	private const PORT_MAX = 65535;

	/** @var array<string,array<string,mixed>> uid => object */
	private array $objs;

	/** @var array<string,array<string,mixed>> memo for addresses() */
	private array $addr_memo = array();

	/** @var array<string,array<string,array<int,array{0:int,1:int}>>> memo for services() */
	private array $svc_memo = array();

	/**
	 * @param array<string,array<string,mixed>> $objects uid => object, from the inventory and the rulebase dictionaries.
	 */
	public function __construct( array $objects ) {
		$this->objs = $objects;
	}

	/* =================================================================
	 * Addresses and intervals
	 * ============================================================== */

	public static function ip2int( string $ip ): ?int {
		$ip = trim( $ip );

		if ( '' === $ip || false === filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			return null;
		}

		return (int) sprintf( '%u', ip2long( $ip ) );
	}

	public static function int2ip( int $n ): string {
		return (string) long2ip( $n );
	}

	/** RFC 1918, carrier-grade NAT, loopback and link-local. */
	public static function is_private( int $n ): bool {
		foreach ( array( array( '10.0.0.0', 8 ), array( '172.16.0.0', 12 ), array( '192.168.0.0', 16 ), array( '100.64.0.0', 10 ), array( '127.0.0.0', 8 ), array( '169.254.0.0', 16 ) ) as $c ) {
			[ $from, $to ] = self::cidr( $c[0], $c[1] );

			if ( $n >= $from && $n <= $to ) {
				return true;
			}
		}

		return false;
	}

	/** @return array{0:int,1:int} */
	public static function cidr( string $net, int $len ): array {
		$base = (int) self::ip2int( $net );
		$len  = max( 0, min( 32, $len ) );
		$size = 2 ** ( 32 - $len );
		$from = $base - ( $base % $size );

		return array( $from, $from + $size - 1 );
	}

	/**
	 * Sort and merge.
	 *
	 * @param array<int,array{0:int,1:int}> $iv Intervals.
	 * @return array<int,array{0:int,1:int}>
	 */
	public static function merge( array $iv ): array {
		usort( $iv, static fn( array $a, array $b ): int => $a[0] <=> $b[0] );
		$out = array();

		foreach ( $iv as $i ) {
			$n = count( $out );

			if ( $n && $i[0] <= $out[ $n - 1 ][1] + 1 ) {
				$out[ $n - 1 ][1] = max( $out[ $n - 1 ][1], $i[1] );
			} else {
				$out[] = array( (int) $i[0], (int) $i[1] );
			}
		}

		return $out;
	}

	/**
	 * $a minus $b.
	 *
	 * @param array<int,array{0:int,1:int}> $a
	 * @param array<int,array{0:int,1:int}> $b
	 * @return array<int,array{0:int,1:int}>
	 */
	public static function subtract( array $a, array $b ): array {
		$out = array();
		$b   = self::merge( $b );

		foreach ( self::merge( $a ) as $i ) {
			$parts = array( $i );

			foreach ( $b as $x ) {
				$next = array();

				foreach ( $parts as $p ) {
					if ( $x[1] < $p[0] || $x[0] > $p[1] ) {
						$next[] = $p;
						continue;
					}
					if ( $x[0] > $p[0] ) {
						$next[] = array( $p[0], $x[0] - 1 );
					}
					if ( $x[1] < $p[1] ) {
						$next[] = array( $x[1] + 1, $p[1] );
					}
				}

				$parts = $next;
			}

			array_push( $out, ...$parts );
		}

		return $out;
	}

	/**
	 * @param array<int,array{0:int,1:int}> $a
	 * @param array<int,array{0:int,1:int}> $b
	 * @return array<int,array{0:int,1:int}>
	 */
	public static function intersect( array $a, array $b ): array {
		$out = array();

		foreach ( self::merge( $a ) as $x ) {
			foreach ( self::merge( $b ) as $y ) {
				$lo = max( $x[0], $y[0] );
				$hi = min( $x[1], $y[1] );

				if ( $lo <= $hi ) {
					$out[] = array( $lo, $hi );
				}
			}
		}

		return self::merge( $out );
	}

	/** @param array<int,array{0:int,1:int}> $iv */
	public static function covers( array $iv, int $n ): bool {
		foreach ( $iv as $i ) {
			if ( $n >= $i[0] && $n <= $i[1] ) {
				return true;
			}
		}

		return false;
	}

	/** Uids out of a column that may hold uids or objects. */
	private static function uids( mixed $col ): array {
		$out = array();

		foreach ( (array) $col as $v ) {
			if ( is_array( $v ) ) {
				$v = (string) ( $v['uid'] ?? '' );
			}
			if ( '' !== (string) $v ) {
				$out[] = (string) $v;
			}
		}

		return $out;
	}

	public function object( string $uid ): array {
		return (array) ( $this->objs[ $uid ] ?? array() );
	}

	public function name( string $uid ): string {
		$o = $this->object( $uid );

		return (string) ( $o['name'] ?? $uid );
	}

	/**
	 * What an address object stands for.
	 *
	 * @return array{any:bool,internet:bool,unknown:int,ranges:array<int,array{0:int,1:int}>}
	 */
	public function addresses( string $uid, int $depth = 0 ): array {
		if ( isset( $this->addr_memo[ $uid ] ) ) {
			return $this->addr_memo[ $uid ];
		}

		$none = array( 'any' => false, 'internet' => false, 'unknown' => 0, 'ranges' => array() );

		if ( $depth > 20 ) {
			return $none;
		}

		$o    = $this->object( $uid );
		$type = strtolower( (string) ( $o['type'] ?? '' ) );
		$name = strtolower( (string) ( $o['name'] ?? '' ) );
		$res  = $none;

		if ( 'cpmianyobject' === $type || ( '' === $type && 'any' === $name ) ) {
			$res['any'] = true;
		} elseif ( str_contains( $type, 'internet' ) || 'internet' === $name ) {
			$res['internet'] = true;
		} elseif ( 'security-zone' === $type ) {
			if ( str_contains( $name, 'external' ) ) {
				$res['internet'] = true;
			} else {
				++$res['unknown'];
			}
		} elseif ( 'network' === $type ) {
			$net = (string) ( $o['subnet4'] ?? '' );
			$len = (int) ( $o['mask-length4'] ?? 32 );

			if ( null !== self::ip2int( $net ) ) {
				$res['ranges'][] = self::cidr( $net, $len );
			} else {
				++$res['unknown'];
			}
		} elseif ( 'address-range' === $type ) {
			$a = self::ip2int( (string) ( $o['ipv4-address-first'] ?? '' ) );
			$b = self::ip2int( (string) ( $o['ipv4-address-last'] ?? '' ) );

			if ( null !== $a && null !== $b ) {
				$res['ranges'][] = array( min( $a, $b ), max( $a, $b ) );
			} else {
				++$res['unknown'];
			}
		} elseif ( 'group' === $type ) {
			foreach ( self::uids( $o['members'] ?? array() ) as $m ) {
				$res = self::union( $res, $this->addresses( $m, $depth + 1 ) );
			}
		} elseif ( 'group-with-exclusion' === $type ) {
			$inc = $this->addresses( (string) ( self::uids( array( $o['include'] ?? '' ) )[0] ?? '' ), $depth + 1 );
			$exc = $this->addresses( (string) ( self::uids( array( $o['except'] ?? '' ) )[0] ?? '' ), $depth + 1 );
			$res = $inc;

			$res['ranges'] = self::subtract( $inc['ranges'], $exc['ranges'] );
		} else {
			// Hosts, gateways, cluster members, servers: whatever address
			// they carry. Anything else (dynamic, updatable, domain
			// objects, access roles) is unknown.
			$ip = self::ip2int( (string) ( $o['ipv4-address'] ?? '' ) );

			if ( null !== $ip ) {
				$res['ranges'][] = array( $ip, $ip );
			} else {
				++$res['unknown'];
			}
		}

		$res['ranges'] = self::merge( $res['ranges'] );

		return $this->addr_memo[ $uid ] = $res;
	}

	private static function union( array $a, array $b ): array {
		return array(
			'any'      => $a['any'] || $b['any'],
			'internet' => $a['internet'] || $b['internet'],
			'unknown'  => $a['unknown'] + $b['unknown'],
			'ranges'   => array_merge( $a['ranges'], $b['ranges'] ),
		);
	}

	/**
	 * A column of address objects, merged.
	 *
	 * @return array{any:bool,internet:bool,unknown:int,ranges:array<int,array{0:int,1:int}>}
	 */
	public function column( mixed $col ): array {
		$res = array( 'any' => false, 'internet' => false, 'unknown' => 0, 'ranges' => array() );

		foreach ( self::uids( $col ) as $u ) {
			$res = self::union( $res, $this->addresses( $u ) );
		}

		$res['ranges'] = self::merge( $res['ranges'] );

		return $res;
	}

	/* =================================================================
	 * Services
	 * ============================================================== */

	/** @return array{0:int,1:int}|null */
	public static function port_range( string $spec ): ?array {
		$spec = trim( $spec );

		if ( '' === $spec ) {
			return null;
		}
		if ( preg_match( '/^(\d+)$/', $spec, $m ) ) {
			return array( (int) $m[1], (int) $m[1] );
		}
		if ( preg_match( '/^(\d+)\s*-\s*(\d+)$/', $spec, $m ) ) {
			return array( min( (int) $m[1], (int) $m[2] ), max( (int) $m[1], (int) $m[2] ) );
		}
		if ( preg_match( '/^>\s*(\d+)$/', $spec, $m ) ) {
			return array( (int) $m[1] + 1, self::PORT_MAX );
		}
		if ( preg_match( '/^<\s*(\d+)$/', $spec, $m ) ) {
			return array( 1, max( 1, (int) $m[1] - 1 ) );
		}

		return null;
	}

	/**
	 * Ports a service object opens, by protocol.
	 *
	 * @return array<string,array<int,array{0:int,1:int}>>
	 */
	public function services( string $uid, int $depth = 0 ): array {
		if ( isset( $this->svc_memo[ $uid ] ) ) {
			return $this->svc_memo[ $uid ];
		}

		$out = array( 'tcp' => array(), 'udp' => array() );

		if ( $depth > 20 ) {
			return $out;
		}

		$o    = $this->object( $uid );
		$type = strtolower( (string) ( $o['type'] ?? '' ) );
		$name = strtolower( (string) ( $o['name'] ?? '' ) );

		if ( 'cpmianyobject' === $type || ( '' === $type && 'any' === $name ) ) {
			$out = array( 'tcp' => array( array( 1, self::PORT_MAX ) ), 'udp' => array( array( 1, self::PORT_MAX ) ) );
		} elseif ( 'service-tcp' === $type || 'service-udp' === $type ) {
			$r = self::port_range( (string) ( $o['port'] ?? '' ) );

			if ( $r ) {
				$out[ 'service-tcp' === $type ? 'tcp' : 'udp' ][] = $r;
			}
		} elseif ( 'service-group' === $type ) {
			foreach ( self::uids( $o['members'] ?? array() ) as $m ) {
				$s          = $this->services( $m, $depth + 1 );
				$out['tcp'] = array_merge( $out['tcp'], $s['tcp'] );
				$out['udp'] = array_merge( $out['udp'], $s['udp'] );
			}
		}
		// ICMP, other IP protocols, RPC and application objects open no
		// port anything listens on, and are left out.

		$out['tcp'] = self::merge( $out['tcp'] );
		$out['udp'] = self::merge( $out['udp'] );

		return $this->svc_memo[ $uid ] = $out;
	}

	/**
	 * A rule's service column, negation applied.
	 *
	 * @param array<string,mixed> $rule
	 * @return array<string,array<int,array{0:int,1:int}>>
	 */
	public function rule_services( array $rule ): array {
		$out = array( 'tcp' => array(), 'udp' => array() );

		foreach ( self::uids( $rule['service'] ?? array() ) as $u ) {
			$s          = $this->services( $u );
			$out['tcp'] = array_merge( $out['tcp'], $s['tcp'] );
			$out['udp'] = array_merge( $out['udp'], $s['udp'] );
		}

		$out['tcp'] = self::merge( $out['tcp'] );
		$out['udp'] = self::merge( $out['udp'] );

		if ( ! empty( $rule['service-negate'] ) ) {
			$all = array( array( 1, self::PORT_MAX ) );
			$out = array( 'tcp' => self::subtract( $all, $out['tcp'] ), 'udp' => self::subtract( $all, $out['udp'] ) );
		}

		return $out;
	}

	/* =================================================================
	 * Rules
	 * ============================================================== */

	/**
	 * Can traffic from the internet match this rule's source column?
	 *
	 * @param array<string,mixed> $rule
	 * @return array{reach:string,sources:int} reach: anyone | listed | none.
	 */
	public function source_reach( array $rule ): array {
		$col = $this->column( $rule['source'] ?? array() );

		if ( ! empty( $rule['source-negate'] ) ) {
			// "Anything except X": the internet is in it unless X already is.
			if ( $col['any'] || $col['internet'] ) {
				return array( 'reach' => 'none', 'sources' => 0 );
			}

			return array( 'reach' => 'anyone', 'sources' => 0 );
		}

		if ( $col['any'] || $col['internet'] ) {
			return array( 'reach' => 'anyone', 'sources' => 0 );
		}

		$public = 0;

		foreach ( $col['ranges'] as $r ) {
			// A range is public if any part of it is. Private-only sources
			// are internal traffic and say nothing about the internet.
			if ( ! self::is_private( $r[0] ) || ! self::is_private( $r[1] ) ) {
				++$public;
			}
		}

		if ( $public > 0 || $col['unknown'] > 0 ) {
			return array( 'reach' => 'listed', 'sources' => $public + $col['unknown'] );
		}

		return array( 'reach' => 'none', 'sources' => 0 );
	}

	/**
	 * Addresses the destination column names, or null for `Any` / negated
	 * (a broad rule, not mapped onto machines).
	 *
	 * @param array<string,mixed> $rule
	 * @return array<int,array{0:int,1:int}>|null
	 */
	public function rule_destinations( array $rule ): ?array {
		if ( ! empty( $rule['destination-negate'] ) ) {
			return null;
		}

		$col = $this->column( $rule['destination'] ?? array() );

		if ( $col['any'] || $col['internet'] ) {
			return null;
		}

		return $col['ranges'];
	}

	/** allow | deny | layer | other. */
	public function action( array $rule ): string {
		$a    = $rule['action'] ?? '';
		$name = strtolower( is_array( $a ) ? (string) ( $a['name'] ?? '' ) : $this->name( (string) $a ) );

		if ( ! empty( $rule['inline-layer'] ) ) {
			return 'layer';
		}

		return match ( true ) {
			in_array( $name, array( 'accept', 'ask', 'inform', 'allow' ), true ) => 'allow',
			in_array( $name, array( 'drop', 'reject' ), true ) => 'deny',
			str_contains( $name, 'layer' ) => 'layer',
			default => 'other',
		};
	}

	/**
	 * The rules a packet from outside can meet, inline layers expanded and
	 * narrowed by their parent, in evaluation order.
	 *
	 * @param array<int,array<string,mixed>>               $rules  A layer's rules.
	 * @param array<string,array<int,array<string,mixed>>> $layers Inline layer uid => rules.
	 * @param array<string,mixed>|null                     $parent Narrowing from an enclosing rule.
	 * @return array<int,array<string,mixed>>
	 */
	public function effective( array $rules, array $layers, ?array $parent = null, int $depth = 0 ): array {
		$out = array();

		foreach ( $rules as $rule ) {
			if ( array_key_exists( 'enabled', $rule ) && ! $rule['enabled'] ) {
				continue;
			}

			$src = $this->source_reach( $rule );

			if ( 'none' === $src['reach'] ) {
				continue;
			}

			$dst = $this->rule_destinations( $rule );
			$svc = $this->rule_services( $rule );
			$act = $this->action( $rule );

			if ( $parent ) {
				if ( 'listed' === $parent['reach'] && 'anyone' === $src['reach'] ) {
					$src = array( 'reach' => 'listed', 'sources' => $parent['sources'] );
				}
				if ( null === $dst ) {
					$dst = $parent['dst'];
				} elseif ( null !== $parent['dst'] ) {
					$dst = self::intersect( $dst, $parent['dst'] );
				}
				$svc = array(
					'tcp' => self::intersect( $svc['tcp'], $parent['svc']['tcp'] ),
					'udp' => self::intersect( $svc['udp'], $parent['svc']['udp'] ),
				);
			}

			$row = array(
				'rule'    => $rule,
				'reach'   => $src['reach'],
				'sources' => $src['sources'],
				'dst'     => $dst,
				'svc'     => $svc,
				'action'  => $act,
			);

			if ( 'layer' === $act ) {
				$inner = (string) ( $rule['inline-layer'] ?? '' );

				if ( '' !== $inner && isset( $layers[ $inner ] ) && $depth < 5 ) {
					array_push( $out, ...$this->effective( $layers[ $inner ], $layers, $row, $depth + 1 ) );
				}
				continue;
			}

			$out[] = $row;
		}

		return $out;
	}

	/**
	 * Where the internet gets in.
	 *
	 * A private machine is reached through its NAT forwards. A forward can be
	 * narrower than the machine: a manual NAT rule names the original
	 * service (one port forwarded, not all of them) and the original source
	 * (only some callers translated). Both narrow what the access rule
	 * opens: the ports are intersected with the forward's, and a forward
	 * from listed sources makes the way "listed" even under a rule from
	 * Any. Treating every forward as a whole-machine mapping called servers
	 * open on every port when one port was forwarded to them.
	 *
	 * @param array<int,array{asset_id:int,ip:int}>         $targets Machine addresses.
	 * @param array<int,array<int,array<string,mixed>>>     $nat     Private address => forwards (nat_forwards()).
	 * @param array<string,array<int,array<string,mixed>>>  $eff     Package name => effective rules.
	 * @param callable                                      $label   fn( array $rule, string $package ): string.
	 * @return array{paths:array<int,array<string,mixed>>,broad:array<int,array<string,mixed>>}
	 */
	public static function exposure( array $targets, array $nat, array $eff, callable $label ): array {
		$paths = array();
		$broad = array();

		foreach ( $eff as $package => $rules ) {
			foreach ( $rules as $r ) {
				if ( null === $r['dst'] && 'allow' === $r['action'] && ( $r['svc']['tcp'] || $r['svc']['udp'] ) ) {
					$broad[] = array(
						'package' => (string) $package,
						'rule'    => $label( $r['rule'], (string) $package ),
						'reach'   => $r['reach'],
						'sources' => $r['sources'],
						'ports'   => self::describe_ports( $r['svc'] ),
					);
				}
			}

			foreach ( $targets as $t ) {
				$ip     = (int) $t['ip'];
				$public = ! self::is_private( $ip );

				// Only a public front is a way in from the internet; a NAT to
				// another private address is internal plumbing.
				$fronts = $public
					? array( array( 'pub' => $ip, 'svc' => null, 'reach' => 'anyone' ) )
					: array_values( array_filter( (array) ( $nat[ $ip ] ?? array() ), static fn( array $f ): bool => ! self::is_private( (int) $f['pub'] ) ) );

				$decided = array( 'tcp' => array(), 'udp' => array() );

				foreach ( $rules as $r ) {
					if ( null === $r['dst'] || 'other' === $r['action'] ) {
						continue;
					}

					$on_ip = self::covers( $r['dst'], $ip );
					$via   = array();

					foreach ( $fronts as $f ) {
						if ( $on_ip || self::covers( $r['dst'], (int) $f['pub'] ) ) {
							$via[] = $f;
						}
					}

					if ( ! $on_ip && ! $via ) {
						continue;
					}

					foreach ( array( 'tcp', 'udp' ) as $proto ) {
						$open = self::subtract( $r['svc'][ $proto ], $decided[ $proto ] );

						if ( ! $open ) {
							continue;
						}

						if ( 'allow' === $r['action'] ) {
							$base = array(
								'asset_id' => (int) $t['asset_id'],
								'ip'       => self::int2ip( $ip ),
								'protocol' => $proto,
								'sources'  => (int) $r['sources'],
								'package'  => (string) $package,
								'rule'     => $label( $r['rule'], (string) $package ),
								'rule_uid' => (string) ( $r['rule']['uid'] ?? '' ),
							);

							if ( $fronts ) {
								foreach ( $via as $f ) {
									$ports = null === $f['svc'] ? $open : self::intersect( $open, (array) ( $f['svc'][ $proto ] ?? array() ) );

									foreach ( $ports as $iv ) {
										$paths[] = $base + array(
											'port_from' => $iv[0],
											'port_to'   => $iv[1],
											'reach'     => 'anyone' === $r['reach'] && 'anyone' === $f['reach'] ? 'anyone' : 'listed',
											'via'       => $public ? 'direct' : 'nat',
											'front'     => self::int2ip( (int) $f['pub'] ),
											'latent'    => 0,
										);
									}
								}
							} else {
								// Allowed by policy, but no public address or NAT
								// reaches it: open if a route appears.
								foreach ( $open as $iv ) {
									$paths[] = $base + array( 'port_from' => $iv[0], 'port_to' => $iv[1], 'reach' => $r['reach'], 'via' => 'direct', 'front' => '', 'latent' => 1 );
								}
							}
						}

						if ( 'anyone' === $r['reach'] ) {
							$decided[ $proto ] = self::merge( array_merge( $decided[ $proto ], $open ) );
						}
					}
				}
			}
		}

		return array( 'paths' => $paths, 'broad' => $broad );
	}

	/** "tcp 443, 8080-8090; udp 53" */
	public static function describe_ports( array $svc ): string {
		$parts = array();

		foreach ( array( 'tcp', 'udp' ) as $proto ) {
			$list = array();

			foreach ( (array) ( $svc[ $proto ] ?? array() ) as $iv ) {
				$list[] = $iv[0] === $iv[1] ? (string) $iv[0] : ( 1 === $iv[0] && self::PORT_MAX === $iv[1] ? 'any' : $iv[0] . '-' . $iv[1] );
			}

			if ( $list ) {
				$parts[] = $proto . ' ' . implode( ', ', array_slice( $list, 0, 12 ) ) . ( count( $list ) > 12 ? ', …' : '' );
			}
		}

		return implode( '; ', $parts );
	}

	/**
	 * NAT forwards: private address => the public addresses that reach it,
	 * each with the ports it forwards (null = every port) and who it is
	 * translated for (anyone | listed). Automatic static NAT forwards every
	 * port for anyone; a manual rule forwards its original service for its
	 * original source. A rule whose original source is only private
	 * addresses is internal and left out.
	 *
	 * @param array<int,array<string,mixed>> $nat_rules NAT rules from every package.
	 * @return array<int,array<int,array{pub:int,svc:?array,reach:string}>>
	 */
	public function nat_forwards( array $nat_rules ): array {
		$out = array();

		foreach ( $this->objs as $o ) {
			$ns = (array) ( $o['nat-settings'] ?? array() );

			if ( empty( $ns['auto-rule'] ) || 'static' !== strtolower( (string) ( $ns['method'] ?? '' ) ) ) {
				continue;
			}

			$priv = self::ip2int( (string) ( $o['ipv4-address'] ?? '' ) );
			$pub  = self::ip2int( (string) ( $ns['ipv4-address'] ?? '' ) );

			if ( null !== $priv && null !== $pub && $priv !== $pub ) {
				$out[ $priv ][ $pub . '|*' ] = array( 'pub' => $pub, 'svc' => null, 'reach' => 'anyone' );
			}
		}

		foreach ( $nat_rules as $r ) {
			if ( array_key_exists( 'enabled', $r ) && ! $r['enabled'] ) {
				continue;
			}

			$od = $this->column( $r['original-destination'] ?? array() );
			$td = $this->column( $r['translated-destination'] ?? array() );

			if ( 1 !== count( $od['ranges'] ) || 1 !== count( $td['ranges'] ) ) {
				continue;
			}

			[ $a, $b ] = $od['ranges'][0];
			[ $c, $d ] = $td['ranges'][0];

			if ( $a !== $b || $c !== $d || $a === $c ) {
				continue;
			}

			$src = $this->source_reach( array( 'source' => $r['original-source'] ?? array() ) );
			if ( 'none' === $src['reach'] ) {
				continue;
			}

			$os  = $this->column_is_any( $r['original-service'] ?? array() ) ? null : $this->rule_services( array( 'service' => $r['original-service'] ?? array() ) );
			$key = $a . '|' . md5( (string) json_encode( $os ) ) . '|' . $src['reach'];

			if ( null !== $os && ! $os['tcp'] && ! $os['udp'] ) {
				continue; // ICMP and the like: no port to reach.
			}

			$out[ $c ][ $key ] = array( 'pub' => $a, 'svc' => $os, 'reach' => $src['reach'] );
		}

		return array_map( 'array_values', $out );
	}

	/** Is a column empty or Any? */
	private function column_is_any( mixed $col ): bool {
		$uids = self::uids( $col );

		if ( ! $uids ) {
			return true;
		}

		foreach ( $uids as $u ) {
			$o = $this->object( $u );
			if ( 'cpmianyobject' === strtolower( (string) ( $o['type'] ?? '' ) ) || 'any' === strtolower( (string) ( $o['name'] ?? '' ) ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Static NAT: private address => public addresses.
	 *
	 * @param array<int,array<string,mixed>> $nat_rules NAT rules from every package.
	 * @return array<int,array<int,int>>
	 */
	public function nat_map( array $nat_rules ): array {
		$map = array();

		// Automatic: a host's own NAT settings.
		foreach ( $this->objs as $o ) {
			$ns = (array) ( $o['nat-settings'] ?? array() );

			if ( empty( $ns['auto-rule'] ) || 'static' !== strtolower( (string) ( $ns['method'] ?? '' ) ) ) {
				continue;
			}

			$priv = self::ip2int( (string) ( $o['ipv4-address'] ?? '' ) );
			$pub  = self::ip2int( (string) ( $ns['ipv4-address'] ?? '' ) );

			if ( null !== $priv && null !== $pub && $priv !== $pub ) {
				$map[ $priv ][ $pub ] = $pub;
			}
		}

		// Manual: original destination (one public address) translated to
		// one private address.
		foreach ( $nat_rules as $r ) {
			if ( array_key_exists( 'enabled', $r ) && ! $r['enabled'] ) {
				continue;
			}

			$od = $this->column( $r['original-destination'] ?? array() );
			$td = $this->column( $r['translated-destination'] ?? array() );

			if ( 1 !== count( $od['ranges'] ) || 1 !== count( $td['ranges'] ) ) {
				continue;
			}

			[ $a, $b ] = $od['ranges'][0];
			[ $c, $d ] = $td['ranges'][0];

			if ( $a !== $b || $c !== $d || $a === $c ) {
				continue;
			}

			$map[ $c ][ $a ] = $a;
		}

		return array_map( 'array_values', $map );
	}
}

