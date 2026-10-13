<?php
/**
 * Which firewall is which: site, platform and how sure we are.
 *
 * Check Point knows a gateway's name, type and address, not where it is. The
 * platform knows a great deal about places: the location register, the
 * machines at each one and their addresses, the AWS accounts, auto-scaling
 * groups and subnets. This puts the two together, and records every piece of
 * evidence it used so a person can check the answer.
 *
 * Evidence, strongest first:
 *
 *   1. an operator's override (`wp vulnhub checkpoint-site`), always wins;
 *   2. AWS: an instance id or region in the name, an auto-scaling gateway, an
 *      AWS auto-scaling group whose name shares the gateway's tokens;
 *   3. a location in the register named by a token of the gateway's name --
 *      the token as the start of a word ("NTH" → "… North Campus") or as a common
 *      city code ("WLG" → Wellington, from the table below);
 *   4. machines in the same /24 as the gateway: their location, or a word in
 *      their hostnames that the gateway's token starts ("RVR" and a switch
 *      called "…-riverside-sw01");
 *   5. the gateway's own description ("Internet gateway, Sydney").
 *
 * Nothing about any one estate is written here: places come from the
 * location register and the asset names, and the city codes are the public
 * ones. Overrides live in an option on the box.
 *
 * @package VulnHub\CheckPoint
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_CheckPoint_Sites {

	public const OVERRIDES = 'vulnhub_checkpoint_site_overrides';

	/**
	 * Common city codes (airport codes, and a few short forms in common use)
	 * for the places gateways usually sit. Filterable.
	 *
	 * @return array<string,string>
	 */
	public static function city_codes(): array {
		return (array) apply_filters(
			'vulnhub_checkpoint_city_codes',
			array(
				'AKL' => 'Auckland', 'WLG' => 'Wellington', 'CHC' => 'Christchurch', 'DUD' => 'Dunedin',
				'HLZ' => 'Hamilton', 'NPE' => 'Napier', 'NAP' => 'Napier', 'NSN' => 'Nelson', 'NPL' => 'New Plymouth',
				'PMR' => 'Palmerston North', 'ROT' => 'Rotorua', 'TRG' => 'Tauranga', 'ZQN' => 'Queenstown',
				'IVC' => 'Invercargill', 'WRE' => 'Whangarei', 'GIS' => 'Gisborne', 'BHE' => 'Blenheim',
				'SYD' => 'Sydney', 'MEL' => 'Melbourne', 'BNE' => 'Brisbane', 'ADL' => 'Adelaide',
				'PER' => 'Perth', 'CBR' => 'Canberra', 'HBA' => 'Hobart', 'DRW' => 'Darwin',
				'SIN' => 'Singapore', 'LON' => 'London', 'LHR' => 'London', 'NYC' => 'New York',
			)
		);
	}

	/** @return array<string,string> gateway name (lower) => site */
	public static function overrides(): array {
		return array_change_key_case( (array) get_option( self::OVERRIDES, array() ), CASE_LOWER );
	}

	public static function set_override( string $gateway, string $site ): void {
		$o = (array) get_option( self::OVERRIDES, array() );

		if ( '' === trim( $site ) ) {
			unset( $o[ $gateway ] );
		} else {
			$o[ $gateway ] = trim( $site );
		}

		update_option( self::OVERRIDES, $o, false );
	}

	/** Name split into upper-case tokens. @return string[] */
	private static function tokens( string $name ): array {
		return array_values( array_filter( preg_split( '/[^A-Za-z0-9]+/', strtoupper( $name ) ) ?: array() ) );
	}

	/**
	 * Classify every stored gateway and write the verdicts back.
	 *
	 * @return array<int,array<string,mixed>> The verdicts.
	 */
	public static function classify(): array {
		global $wpdb;

		$gt   = VulnHub_CheckPoint_Store::table( 'gateways' );
		$gws  = (array) $wpdb->get_results( "SELECT uid, name, type, ipv4, data FROM {$gt}", ARRAY_A ); // phpcs:ignore
		$locs = (array) $wpdb->get_results( 'SELECT id, name FROM ' . vh_table( 'locations' ), ARRAY_A ); // phpcs:ignore
		$over = self::overrides();
		$city = self::city_codes();

		// AWS auto-scaling groups (where the AWS connector has captured them).
		$asgs = array();
		if ( class_exists( 'VulnHub_AWS_Network' ) ) {
			$asgs = (array) $wpdb->get_results( 'SELECT account_id, region, name FROM ' . VulnHub_AWS_Network::nodes_table() . " WHERE node_type = 'asg'", ARRAY_A ); // phpcs:ignore
		}

		$aws_loc = null;
		foreach ( $locs as $l ) {
			if ( preg_match( '/\baws\b|amazon/i', (string) $l['name'] ) ) {
				$aws_loc = $l;
				break;
			}
		}

		$out = array();

		foreach ( $gws as $g ) {
			$name  = (string) $g['name'];
			$type  = (string) $g['type'];
			$ip    = (string) $g['ipv4'];
			$data  = (array) json_decode( (string) $g['data'], true );
			$desc  = (string) ( $data['description'] ?? $data['comments'] ?? '' );
			$toks  = self::tokens( $name );
			$ev    = array();
			$site  = '';
			$loc   = 0;
			$plat  = '';
			$conf  = 'low';

			/* ---- platform ---- */
			if ( preg_match( '/\bi-[0-9a-f]{8,17}\b/i', $name, $m ) ) {
				$plat = 'aws';
				$ev[] = sprintf( 'AWS instance %s in the name', $m[0] );
			}
			if ( preg_match( '/\b([a-z]{2}-[a-z]+-\d)\b/i', str_replace( '--', ' ', $name ), $m ) ) {
				$plat = 'aws';
				$ev[] = sprintf( 'AWS region %s in the name', strtolower( $m[1] ) );
			}
			if ( stripos( $type, 'autoscaling' ) !== false ) {
				$plat = 'aws';
				$ev[] = 'registered as an auto-scaling gateway';
			}
			if ( '' === $plat ) {
				$plat = str_contains( strtolower( $type ), 'cluster' ) ? 'cluster' : ( '' !== $type ? 'gateway' : 'unknown' );
			}

			if ( 'aws' === $plat ) {
				foreach ( $asgs as $a ) {
					$shared = array_intersect( $toks, self::tokens( (string) $a['name'] ) );
					$shared = array_filter( $shared, static fn( string $t ): bool => strlen( $t ) >= 2 && ! ctype_digit( $t ) );

					if ( count( $shared ) >= 2 ) {
						$ev[] = sprintf( 'AWS auto-scaling group %s (account %s, %s) shares %s', (string) $a['name'], (string) $a['account_id'], (string) $a['region'], implode( ', ', $shared ) );
						break;
					}
				}
				if ( $aws_loc ) {
					$site = (string) $aws_loc['name'];
					$loc  = (int) $aws_loc['id'];
				} else {
					$site = 'AWS';
				}
				$conf = 'high';
			}

			/* ---- a location named by a token ---- */
			if ( '' === $site ) {
				foreach ( $toks as $t ) {
					if ( strlen( $t ) < 3 || ctype_digit( $t ) ) {
						continue;
					}

					$want = $city[ $t ] ?? '';

					foreach ( $locs as $l ) {
						$words = self::tokens( (string) $l['name'] );
						$hit   = '' !== $want && false !== stripos( (string) $l['name'], $want );
						$why   = $hit ? sprintf( 'code %s = %s', $t, $want ) : '';

						if ( ! $hit ) {
							foreach ( $words as $w ) {
								if ( strlen( $w ) > strlen( $t ) && str_starts_with( $w, $t ) ) {
									$hit = true;
									$why = sprintf( '%s starts "%s"', $t, ucfirst( strtolower( $w ) ) );
									break;
								}
							}
						}

						if ( $hit ) {
							$cands[ $t ][] = array( $l, $why );
						}
					}
				}

				// When a token matches several locations: a cluster is usually a
				// data-centre pair, a single gateway usually an office or branch.
				$want_dc = 'cluster' === $plat;
				foreach ( (array) ( $cands ?? array() ) as $t => $list ) {
					usort(
						$list,
						static function ( array $a, array $b ) use ( $want_dc ): int {
							$da = (int) ( false !== stripos( (string) $a[0]['name'], 'data cent' ) );
							$db = (int) ( false !== stripos( (string) $b[0]['name'], 'data cent' ) );

							return $want_dc ? $db <=> $da : $da <=> $db;
						}
					);
					[ $l, $why ] = $list[0];
					$site        = (string) $l['name'];
					$loc         = (int) $l['id'];
					$conf        = 'medium';
					$ev[]        = sprintf( 'location "%s" from the name (%s)', $site, $why );
					if ( count( $list ) > 1 ) {
						$ev[] = sprintf( 'also matched: %s', implode( '; ', array_map( static fn( array $x ): string => (string) $x[0]['name'], array_slice( $list, 1, 4 ) ) ) );
					}
					break;
				}
				unset( $cands );

				// A city code with no location row still names the place.
				if ( '' === $site ) {
					foreach ( $toks as $t ) {
						if ( isset( $city[ $t ] ) ) {
							$site = $city[ $t ];
							$conf = 'medium';
							$ev[] = sprintf( 'code %s = %s (no location of that name in the register)', $t, $city[ $t ] );
							break;
						}
					}
				}
			}

			/* ---- neighbours in the same /24 ---- */
			$n = VulnHub_CheckPoint_Policy::ip2int( $ip );

			if ( null !== $n && ! str_starts_with( $ip, '100.100.' ) ) {
				$prefix = implode( '.', array_slice( explode( '.', $ip ), 0, 3 ) ) . '.';
				$near   = (array) $wpdb->get_results( // phpcs:ignore
					$wpdb->prepare(
						'SELECT a.hostname, a.location_id, l.name AS loc FROM ' . vh_table( 'assets' ) . ' a LEFT JOIN ' . vh_table( 'locations' ) . " l ON l.id = a.location_id
						  WHERE a.duplicate_of IS NULL AND ( LOCATE( %s, a.ipv4 ) = 1 OR LOCATE( %s, CONCAT( ',', a.ipv4s ) ) > 0 ) LIMIT 50",
						$prefix,
						',' . $prefix
					),
					ARRAY_A
				);

				$by_loc = array();
				foreach ( $near as $r ) {
					if ( '' !== (string) $r['loc'] ) {
						$by_loc[ (string) $r['loc'] ][] = (int) $r['location_id'];
					}

					foreach ( self::tokens( (string) $r['hostname'] ) as $w ) {
						foreach ( $toks as $t ) {
							if ( strlen( $t ) >= 3 && strlen( $w ) > strlen( $t ) + 1 && str_starts_with( $w, $t ) && ! ctype_digit( $t ) ) {
								$ev[] = sprintf( 'neighbour %s in %s0/24 — %s starts "%s"', (string) $r['hostname'], $prefix, $t, ucfirst( strtolower( $w ) ) );
								if ( '' === $site ) {
									$site = ucfirst( strtolower( $w ) );
									$conf = 'medium';
								}
								break 2;
							}
						}
					}
				}

				if ( $by_loc ) {
					arsort( $by_loc );
					$top = (string) array_key_first( $by_loc );
					$ev[] = sprintf( '%d machine(s) at "%s" in %s0/24', count( $by_loc[ $top ] ), $top, $prefix );

					if ( '' === $site ) {
						$site = $top;
						$loc  = (int) $by_loc[ $top ][0];
						$conf = 'medium';
					} elseif ( $top === $site ) {
						$conf = 'high';
					}
				}
			} elseif ( str_starts_with( $ip, '100.100.' ) ) {
				$ev[] = 'address is in the cloud management overlay range, not a site network';
			}

			/* ---- description ---- */
			if ( '' !== $desc ) {
				foreach ( array_unique( array_values( $city ) ) as $c ) {
					if ( false !== stripos( $desc, $c ) ) {
						$ev[] = sprintf( 'description says "%s"', $desc );
						if ( '' === $site ) {
							$site = $c;
							$conf = 'medium';
						} elseif ( false !== stripos( $site, $c ) ) {
							$conf = 'high';
						}
						break;
					}
				}
			}

			/* ---- status ---- */
			$status = (string) ( $data['statusDetails']['status'] ?? '' );
			if ( '' !== $status && 'completed' !== $status ) {
				$ev[] = sprintf( 'registration %s: %s', $status, (string) ( $data['statusDetails']['message'] ?? '' ) );
			}
			if ( '' === $name ) {
				$ev[] = 'no name: a registration that never completed';
			}

			/* ---- override ---- */
			if ( isset( $over[ strtolower( $name ) ] ) ) {
				$site = (string) $over[ strtolower( $name ) ];
				$loc  = 0;
				foreach ( $locs as $l ) {
					if ( 0 === strcasecmp( (string) $l['name'], $site ) ) {
						$loc = (int) $l['id'];
					}
				}
				$conf = 'set';
				array_unshift( $ev, 'set by hand' );
			}

			$row = array(
				'uid'         => (string) $g['uid'],
				'name'        => $name,
				'platform'    => $plat,
				'site'        => '' !== $site ? $site : '',
				'location_id' => $loc,
				'confidence'  => '' !== $site ? $conf : 'none',
				'cluster'     => preg_replace( '/[AB]$/', '', $name ) !== $name && 'cluster' === $plat ? (string) preg_replace( '/[AB]$/', '', $name ) : '',
				'evidence'    => $ev,
			);

			$wpdb->update( // phpcs:ignore
				$gt,
				array(
					'site'        => substr( $row['site'], 0, 191 ),
					'location_id' => $row['location_id'],
					'platform'    => $row['platform'],
					'confidence'  => $row['confidence'],
					'cluster'     => substr( $row['cluster'], 0, 191 ),
					'evidence'    => (string) wp_json_encode( $ev ),
				),
				array( 'uid' => $row['uid'] )
			);

			$out[] = $row;
		}

		return $out;
	}
}

