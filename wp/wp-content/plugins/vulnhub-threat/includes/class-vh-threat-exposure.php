<?php
/**
 * Open to the internet, and vulnerable on that port.
 *
 * The lanes say which findings *could* be used from outside. This says which
 * ones *can*, today, on which machine and port -- the list to work first. A
 * finding is on it only when all three hold:
 *
 *   1. a way in     the internet can open a port on the machine: a security
 *                   group admits an outside source on an address that routes
 *                   from an internet gateway, or an internet-facing load
 *                   balancer forwards to it (vulnhub-aws), or it answers on a
 *                   public address and something listens (the scanner)
 *   2. the service  the vulnerable component is the thing on that port --
 *                   OpenSSH on 22, httpd on 443, Windows on 3389
 *                   (VulnHub_Threat_Services)
 *   3. the finding  open, not risk-accepted
 *
 * Then ranked, because the difference between "anyone" and "three listed
 * partner addresses", and between "on CISA's exploited list" and "a medium
 * nobody has written an exploit for", is the whole of the triage:
 *
 *   now     open to anyone, and exploitable today; or on the exploited list
 *           and reachable from anywhere outside
 *   next    open to anyone and critical or high; or open to listed
 *           addresses and exploitable today
 *   review  every other vulnerable service with a way in
 *
 * Alongside: ports open to anyone that route nowhere today (`latent`, one
 * change away), servers with a way in and nothing known vulnerable behind it,
 * and internet-facing load balancers whose targets were not captured.
 *
 * See docs/ATTACK-PATHS.md, "Open to the internet, and vulnerable on that port".
 *
 * @package VulnHub\Threat
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Threat_Exposure {

	public const TIERS = array( 'now', 'next', 'review' );

	/** @var array<string,mixed>|null */
	private static ?array $cache = null;

	/**
	 * Everything the panel and the CSV draw.
	 *
	 * @return array{items:array<int,array<string,mixed>>,latent:array<int,array<string,mixed>>,quiet:array<int,array<string,mixed>>,blind:array<int,array<string,mixed>>,door_assets:int[],doors:array<int,array<string,mixed>>,counts:array<string,int>,captured_at:string,has_map:bool}
	 */
	public static function data(): array {
		if ( null !== self::$cache ) {
			return self::$cache;
		}

		$net   = (array) apply_filters( 'vulnhub_internet_paths', array() );
		$epoch = class_exists( 'VulnHub_Dash_Widgets' ) ? VulnHub_Dash_Widgets::epoch() : '';
		// Classification and every sync move the widget epoch; a new network
		// capture moves captured_at.
		$key   = 'vh_threat_expo_' . md5( $epoch . '|' . (string) ( $net['captured_at'] ?? '' ) . '|11' );
		$hit   = get_transient( $key );

		if ( is_array( $hit ) ) {
			return self::$cache = $hit;
		}

		self::$cache = self::build( $net );
		set_transient( $key, self::$cache, HOUR_IN_SECONDS );

		return self::$cache;
	}

	/**
	 * Finding ids behind one tier, `latent`, or every tier -- what the
	 * `expo` filter on the Vulnerabilities list narrows to.
	 *
	 * @return int[]
	 */
	public static function finding_ids( string $which ): array {
		$d   = self::data();
		$ids = array();
		$src = 'latent' === $which ? $d['latent'] : $d['items'];

		foreach ( $src as $item ) {
			if ( 'latent' === $which || 'all' === $which || $item['tier'] === $which ) {
				array_push( $ids, ...$item['findings'] );
			}
		}

		return array_values( array_unique( array_map( 'intval', $ids ) ) );
	}

	/**
	 * @param array<string,mixed> $net vulnhub_internet_paths.
	 * @return array<string,mixed>
	 */
	private static function build( array $net ): array {
		global $wpdb;

		$paths  = (array) ( $net['paths'] ?? array() );
		$latent = (array) ( $net['latent'] ?? array() );

		/*
		 * Off the cloud map: a machine answering on a public address, with
		 * what the scanner saw listening on it. Weaker -- nothing here reads
		 * the firewall in front of it -- so it is labelled as observed and
		 * never outranks a proven rule.
		 */
		foreach ( self::public_hosts() as $asset => $ip ) {
			if ( isset( $paths[ $asset ] ) ) {
				continue;
			}

			foreach ( VulnHub_Threat_Ports::remote_ports( $asset ) as $p ) {
				$paths[ $asset ][] = array(
					'protocol'  => (string) $p['protocol'],
					'port_from' => (int) $p['port'],
					'port_to'   => (int) $p['port'],
					'reach'     => 'observed',
					'sources'   => 0,
					'rule'      => '',
					'via'       => 'observed',
					'front'     => $ip,
					'route'     => '',
					'firewall'  => 'unknown',
				);
			}
		}

		$assets = array_values( array_unique( array_merge( array_keys( $paths ), array_keys( $latent ) ) ) );
		$items     = array();
		$late      = array();
		$quiet     = array();
		$blind     = array();
		$listening = array();

		if ( $assets ) {
			$meta = self::assets_meta( $assets );

			foreach ( array_chunk( $assets, 200 ) as $chunk ) {
				foreach ( self::findings_on( $chunk ) as $f ) {
					$svc = VulnHub_Threat_Services::of( $f );

					if ( ! $svc ) {
						continue;
					}

					$asset = (int) $f['asset_id'];

					if ( ! isset( $listening[ $asset ] ) ) {
						$listening[ $asset ] = array_map( static fn( array $p ): string => $p['protocol'] . '/' . $p['port'], VulnHub_Threat_Ports::remote_ports( $asset ) );
					}

					foreach ( array( 'open' => $paths[ $asset ] ?? array(), 'latent' => $latent[ $asset ] ?? array() ) as $kind => $ways ) {
						$best = null;
						$port = '';

						foreach ( $ways as $way ) {
							$hit = VulnHub_Threat_Services::pick( $svc['ports'], $way, $listening[ $asset ] );

							if ( '' === $hit ) {
								continue;
							}

							// A wider door wins; between equal doors, the port
							// something is seen answering on.
							$heard = in_array( $hit, $listening[ $asset ], true );

							if ( ! $best
								|| self::way_rank( $way ) < self::way_rank( $best )
								|| ( self::way_rank( $way ) === self::way_rank( $best ) && $heard && ! in_array( $port, $listening[ $asset ], true ) )
							) {
								$best = $way;
								$port = $hit;
							}
						}

						if ( ! $best ) {
							continue;
						}

						$k = $asset . '|' . $port;

						if ( 'open' === $kind ) {
							$items[ $k ] = self::fold( $items[ $k ] ?? self::item( $asset, $port, $svc, $best, $meta[ $asset ] ?? array() ), $f );
						} else {
							$late[ $k ] = self::fold( $late[ $k ] ?? self::item( $asset, $port, $svc, $best, $meta[ $asset ] ?? array() ), $f );
						}
						break;
					}
				}
			}

			/*
			 * A way in with nothing known vulnerable behind it -- which means
			 * two different things. Scanned and clean is less surface worth
			 * closing. Never scanned is a blind spot: "no findings" on a
			 * machine nobody has looked at is not an all-clear, and one open
			 * to the internet is a finding in its own right.
			 */
			$vuln_assets = array_flip( array_map( static fn( array $i ): int => (int) $i['asset_id'], $items ) );
			$scanned     = self::scanned( array_keys( $paths ) );

			foreach ( $paths as $asset => $ways ) {
				if ( isset( $vuln_assets[ $asset ] ) ) {
					continue;
				}

				$any  = array_values( array_filter( $ways, static fn( array $w ): bool => 'anyone' === $w['reach'] ) );
				$pick = $any ?: $ways;
				$row  = array(
					'asset_id' => (int) $asset,
					'host'     => (string) ( $meta[ $asset ]['hostname'] ?? '' ),
					'team'     => (string) ( $meta[ $asset ]['team'] ?? '' ),
					'reach'    => $any ? 'anyone' : (string) $ways[0]['reach'],
					'ports'    => array_values( array_unique( array_map( array( __CLASS__, 'way_label' ), $pick ) ) ),
					'front'    => (string) $pick[0]['front'],
					'via'      => (string) $pick[0]['via'],
					'firewall' => self::firewall_of( $pick ),
				);

				if ( isset( $scanned[ $asset ] ) ) {
					$quiet[] = $row;
				} else {
					$blind[] = $row;
				}
			}

			usort( $blind, static fn( array $a, array $b ): int => ( 'anyone' === $b['reach'] ) <=> ( 'anyone' === $a['reach'] ) );
		}

		/*
		 * Is anything actually answering on the port? Where the scanner read
		 * the host's listening table, it says so either way; where it did
		 * not, the door is inferred from the package alone and says that.
		 */
		foreach ( $items as $k => $item ) {
			$a = (int) $item['asset_id'];

			$items[ $k ]['listening'] = ! $listening[ $a ] ? 'unknown' : ( in_array( $item['port'], $listening[ $a ], true ) ? 'yes' : 'no' );
			$items[ $k ]              = self::finish( $items[ $k ] );
		}
		foreach ( $late as $k => $item ) {
			$late[ $k ] = self::finish( $item );
		}

		$items = array_values( $items );
		$late  = array_values( $late );
		usort( $items, array( __CLASS__, 'compare' ) );
		usort( $late, array( __CLASS__, 'compare' ) );

		$counts = array(
			'now'      => 0,
			'next'     => 0,
			'review'   => 0,
			'servers'  => count( array_unique( array_column( $items, 'asset_id' ) ) ),
			'findings' => 0,
			'latent'   => count( array_unique( array_column( $late, 'asset_id' ) ) ),
			'quiet'    => count( $quiet ),
			'blind'    => count( $blind ),
			'doors'    => count( (array) ( $net['doors'] ?? array() ) ),
		);

		foreach ( $items as $item ) {
			++$counts[ $item['tier'] ];
			$counts['findings'] += count( $item['findings'] );
		}

		return array(
			'items'       => $items,
			'latent'      => $late,
			'quiet'       => $quiet,
			'blind'       => $blind,
			'door_assets' => array_map( 'intval', array_keys( $paths ) ),
			'doors'       => (array) ( $net['doors'] ?? array() ),
			'counts'      => $counts,
			'captured_at' => (string) ( $net['captured_at'] ?? '' ),
			'has_map'     => ! empty( $net ),
		);
	}

	/**
	 * Open, non-accepted findings on these assets, with what placing them
	 * needs. A package check's output is loaded only for the rows whose title
	 * does not name the package -- it is a longtext on every row.
	 *
	 * @param int[] $assets Asset ids.
	 * @return array<int,array<string,mixed>>
	 */
	private static function findings_on( array $assets ): array {
		global $wpdb;

		$in    = implode( ',', array_map( 'intval', $assets ) );
		$paths = VulnHub_Threat_Install::table( 'vuln_paths' );
		$rows  = (array) $wpdb->get_results( // phpcs:ignore
			'SELECT f.id, f.asset_id, f.vuln_id, f.port, f.protocol, f.severity, f.ticket_id,
			        v.title, v.family, v.product, v.product_slug, v.product_kind,
			        p.route, p.has_poc, p.kev, p.top_epss, p.top_cve
			 FROM ' . vh_table( 'findings' ) . ' f
			 JOIN ' . vh_table( 'vulns' ) . " v ON v.id = f.vuln_id
			 LEFT JOIN {$paths} p ON p.vuln_id = f.vuln_id
			 WHERE f.asset_id IN ({$in}) AND f.state IN ('open','reopened')
			   AND f.severity IN ('critical','high','medium','low') AND f.exception_id = 0",
			ARRAY_A
		);

		$need = array();

		foreach ( $rows as $i => $r ) {
			if ( VulnHub_Threat_Services::needs_output( $r ) ) {
				$need[ (int) $r['id'] ] = $i;
			}
		}

		foreach ( array_chunk( array_keys( $need ), 500 ) as $ids ) {
			foreach ( (array) $wpdb->get_results( 'SELECT id, LEFT(output, 4000) AS output FROM ' . vh_table( 'findings' ) . ' WHERE id IN (' . implode( ',', $ids ) . ')', ARRAY_A ) as $o ) { // phpcs:ignore
				$rows[ $need[ (int) $o['id'] ] ]['output'] = (string) $o['output'];
			}
		}

		return $rows;
	}

	/**
	 * Which of these assets any scanner has ever reported on.
	 *
	 * @param int[] $assets Asset ids.
	 * @return array<int,bool>
	 */
	private static function scanned( array $assets ): array {
		global $wpdb;

		if ( ! $assets ) {
			return array();
		}

		$in  = implode( ',', array_map( 'intval', $assets ) );
		$ids = array_merge(
			(array) $wpdb->get_col( 'SELECT id FROM ' . vh_table( 'assets' ) . " WHERE id IN ({$in}) AND tenable_last_scan IS NOT NULL" ), // phpcs:ignore
			(array) $wpdb->get_col( 'SELECT DISTINCT asset_id FROM ' . vh_table( 'findings' ) . " WHERE asset_id IN ({$in})" ) // phpcs:ignore
		);

		return array_fill_keys( array_map( 'intval', $ids ), true );
	}

	/**
	 * The weakest firewall answer among some ways in: one uninspected door
	 * is enough.
	 *
	 * @param array<int,array<string,mixed>> $ways Ways in.
	 */
	private static function firewall_of( array $ways ): string {
		$seen = array_map( static fn( array $w ): string => (string) ( $w['firewall'] ?? 'unknown' ), $ways );

		foreach ( array( 'none', 'unknown', 'inspected' ) as $f ) {
			if ( in_array( $f, $seen, true ) ) {
				return $f;
			}
		}

		return 'unknown';
	}

	/**
	 * @param int[] $assets Asset ids.
	 * @return array<int,array<string,string>>
	 */
	private static function assets_meta( array $assets ): array {
		global $wpdb;

		$out = array();
		$in  = implode( ',', array_map( 'intval', $assets ) );

		foreach ( (array) $wpdb->get_results( // phpcs:ignore
			'SELECT a.id, a.hostname, a.operating_system, a.environment, t.name AS team
			 FROM ' . vh_table( 'assets' ) . ' a LEFT JOIN ' . vh_table( 'teams' ) . " t ON t.id = a.team_id
			 WHERE a.id IN ({$in})",
			ARRAY_A
		) as $r ) {
			$out[ (int) $r['id'] ] = $r;
		}

		return $out;
	}

	/**
	 * Machines answering on a public address, off the cloud map.
	 *
	 * @return array<int,string> asset id => the address.
	 */
	private static function public_hosts(): array {
		global $wpdb;

		$out = array();

		foreach ( (array) $wpdb->get_results( 'SELECT id, ipv4, ipv4s FROM ' . vh_table( 'assets' ) . " WHERE ipv4 <> '' OR ipv4s <> ''", ARRAY_A ) as $r ) { // phpcs:ignore
			$ip = VulnHub_Threat_Classify::public_address( $r );

			if ( '' !== $ip ) {
				$out[ (int) $r['id'] ] = $ip;
			}
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $svc  The service.
	 * @param array<string,mixed> $way  How the internet gets to it.
	 * @param array<string,mixed> $meta The asset.
	 * @return array<string,mixed>
	 */
	private static function item( int $asset, string $port, array $svc, array $way, array $meta ): array {
		return array(
			'asset_id' => $asset,
			'host'     => (string) ( $meta['hostname'] ?? '' ),
			'team'     => (string) ( $meta['team'] ?? '' ),
			'os'       => (string) ( $meta['operating_system'] ?? '' ),
			'port'     => $port,
			'service'  => (string) $svc['label'],
			'service_key' => (string) $svc['key'],
			'component'   => (string) $svc['component'],
			'reach'    => (string) $way['reach'],
			'sources'  => (int) $way['sources'],
			'via'      => (string) $way['via'],
			'front'    => (string) $way['front'],
			'rule'     => (string) $way['rule'],
			'route'    => (string) $way['route'],
			'firewall' => (string) ( $way['firewall'] ?? 'unknown' ),
			'findings' => array(),
			'ticketed' => 0,
			'ticket_ids' => array(),
			'tickets'  => array(),
			'vulns'    => array(),
			'kev'      => 0,
			'poc'      => 0,
			'epss'     => 0.0,
			'cve'      => '',
			'severity' => 'low',
			'edge'     => 0,
		);
	}

	/**
	 * Add one finding to an item.
	 *
	 * @param array<string,mixed> $item Item so far.
	 * @param array<string,mixed> $f    Finding row.
	 * @return array<string,mixed>
	 */
	private static function fold( array $item, array $f ): array {
		$item['findings'][] = (int) $f['id'];

		if ( (int) $f['ticket_id'] > 0 ) {
			$item['ticket_ids'][ (int) $f['ticket_id'] ] = true;
			++$item['ticketed'];
		}
		$item['kev']       += (int) $f['kev'];
		$item['poc']       += (int) $f['has_poc'];
		$item['edge']      += 'edge' === (string) $f['route'] ? 1 : 0;

		if ( (float) $f['top_epss'] > $item['epss'] ) {
			$item['epss'] = (float) $f['top_epss'];
		}
		if ( self::sev_rank( (string) $f['severity'] ) < self::sev_rank( $item['severity'] ) ) {
			$item['severity'] = (string) $f['severity'];
		}

		$vid = (int) $f['vuln_id'];

		if ( ! isset( $item['vulns'][ $vid ] ) ) {
			$item['vulns'][ $vid ] = array(
				'title'    => (string) $f['title'],
				'severity' => (string) $f['severity'],
				'kev'      => (int) $f['kev'],
				'poc'      => (int) $f['has_poc'],
				'epss'     => (float) $f['top_epss'],
				'cve'      => (string) $f['top_cve'],
				'product'  => (string) $f['product'],
			);
		}

		return $item;
	}

	/**
	 * Rank the item and keep its worst few vulnerabilities for display.
	 *
	 * @param array<string,mixed> $item Item.
	 * @return array<string,mixed>
	 */
	private static function finish( array $item ): array {
		$vulns = array_values( $item['vulns'] );

		usort(
			$vulns,
			static fn( array $a, array $b ): int => array( -$a['kev'], -$a['poc'], self::sev_rank( $a['severity'] ), -$a['epss'] )
				<=> array( -$b['kev'], -$b['poc'], self::sev_rank( $b['severity'] ), -$b['epss'] )
		);

		$item['vuln_count'] = count( $vulns );
		$item['vulns']      = array_slice( $vulns, 0, 5 );
		$item['cve']        = (string) ( $vulns[0]['cve'] ?? '' );
		$item['tickets']    = self::tickets( array_keys( $item['ticket_ids'] ) );
		$item['tier']       = self::tier( $item );
		$item['do']         = self::advice( $item );

		return $item;
	}

	/**
	 * The tickets a service's findings are on: key, status and whether it is
	 * closed, so the panel can say "already raised" and link to it.
	 *
	 * @param int[] $ids Ticket ids.
	 * @return array<int,array{id:int,key:string,status:string,done:bool}>
	 */
	private static function tickets( array $ids ): array {
		global $wpdb;

		if ( ! $ids ) {
			return array();
		}

		$out = array();

		foreach ( (array) $wpdb->get_results( 'SELECT id, external_key, status, status_category FROM ' . vh_table( 'tickets' ) . ' WHERE id IN (' . implode( ',', array_map( 'intval', $ids ) ) . ')', ARRAY_A ) as $t ) { // phpcs:ignore
			$out[] = array(
				'id'     => (int) $t['id'],
				'key'    => (string) $t['external_key'],
				'status' => (string) $t['status'],
				'done'   => 'done' === (string) $t['status_category'],
			);
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $i Item.
	 */
	private static function tier( array $i ): string {
		// The scanner read the listening table and nothing answers there:
		// a vulnerable package behind a closed port is not a way in.
		if ( 'no' === ( $i['listening'] ?? 'unknown' ) ) {
			return 'review';
		}

		$exploitable = $i['kev'] > 0 || $i['poc'] > 0;
		$serious     = in_array( $i['severity'], array( 'critical', 'high' ), true );

		if ( 'anyone' === $i['reach'] && $exploitable ) {
			return 'now';
		}
		if ( $i['kev'] > 0 && 'listed' === $i['reach'] ) {
			return 'now';
		}
		if ( ( 'anyone' === $i['reach'] && $serious ) || ( in_array( $i['reach'], array( 'listed', 'observed' ), true ) && $exploitable ) ) {
			return 'next';
		}

		return 'review';
	}

	/**
	 * What to do first, in a line. Closing a door is faster than patching
	 * behind it, and for remote administration there is rarely a reason for
	 * the door to be open to the whole internet.
	 *
	 * @param array<string,mixed> $i Item.
	 */
	private static function advice( array $i ): string {
		$admin = in_array( $i['service_key'], array( 'ssh', 'rdp', 'smb', 'mssql', 'oracle', 'mysql', 'postgres', 'redis', 'mongodb', 'search', 'cache', 'windows', 'ftp', 'queue' ), true )
			|| in_array( $i['port'], array( 'tcp/22', 'tcp/3389', 'tcp/445', 'tcp/139', 'tcp/135', 'tcp/5985', 'tcp/5986', 'tcp/1433', 'tcp/3306', 'tcp/5432', 'tcp/1521' ), true );
		$patch = sprintf(
			/* translators: %s: vulnerability title. */
			__( 'patch %s', 'vulnhub' ),
			vh_trim( (string) $i['component'] ?: (string) ( $i['vulns'][0]['title'] ?? '' ), 60 )
		);

		if ( 'observed' === $i['reach'] ) {
			return sprintf( /* translators: %s: patch step. */ __( 'Confirm whether the firewall in front publishes %1$s; %2$s.', 'vulnhub' ), $i['port'], $patch );
		}
		if ( 'anyone' === $i['reach'] && $admin ) {
			return sprintf( /* translators: 1: port, 2: patch step. */ __( 'Close %1$s to the internet, or restrict it to known addresses; then %2$s.', 'vulnhub' ), $i['port'], $patch );
		}
		if ( 'listed' === $i['reach'] ) {
			return sprintf( /* translators: 1: number of sources, 2: patch step. */ _n( 'Confirm the %1$s listed outside address still needs it; %2$s.', 'Confirm the %1$s listed outside addresses still need it; %2$s.', max( 1, (int) $i['sources'] ), 'vulnhub' ), number_format_i18n( max( 1, (int) $i['sources'] ) ), $patch );
		}

		return ucfirst( $patch ) . '. ' . __( 'It is published on purpose, so the patch is the mitigation.', 'vulnhub' );
	}

	/** @param array<string,mixed> $a @param array<string,mixed> $b */
	private static function compare( array $a, array $b ): int {
		$heard = static fn( array $i ): int => (int) array_search( $i['listening'] ?? 'unknown', array( 'yes', 'unknown', 'no' ), true );

		return array( array_search( $a['tier'], self::TIERS, true ), self::reach_rank( $a['reach'] ), $heard( $a ), -min( 1, $a['kev'] ), -min( 1, $a['poc'] ), self::sev_rank( $a['severity'] ), -$a['epss'], -count( $a['findings'] ) )
			<=> array( array_search( $b['tier'], self::TIERS, true ), self::reach_rank( $b['reach'] ), $heard( $b ), -min( 1, $b['kev'] ), -min( 1, $b['poc'] ), self::sev_rank( $b['severity'] ), -$b['epss'], -count( $b['findings'] ) );
	}

	/** Lower is a wider door. @param array<string,mixed> $w */
	private static function way_rank( array $w ): int {
		return self::reach_rank( (string) $w['reach'] ) * 3 + array_search( (string) $w['via'], array( 'direct', 'lb', 'observed' ), true );
	}

	private static function reach_rank( string $reach ): int {
		return (int) array_search( $reach, array( 'anyone', 'listed', 'observed' ), true );
	}

	private static function sev_rank( string $sev ): int {
		$i = array_search( $sev, array( 'critical', 'high', 'medium', 'low' ), true );

		return false === $i ? 4 : (int) $i;
	}

	/** "tcp/22", "every port" for one way in. @param array<string,mixed> $w */
	public static function way_label( array $w ): string {
		if ( 0 === (int) $w['port_from'] && 65535 === (int) $w['port_to'] ) {
			return __( 'every port', 'vulnhub' );
		}

		$proto = 'all' === (string) $w['protocol'] ? 'tcp' : (string) $w['protocol'];

		return $proto . '/' . ( (int) $w['port_from'] === (int) $w['port_to'] ? (string) $w['port_from'] : $w['port_from'] . '-' . $w['port_to'] );
	}

	/* =================================================================
	 * CSV
	 * ============================================================== */

	/**
	 * `admin-post.php?action=vulnhub_threat_exposure_csv`: one row per
	 * exposed service, every tier, then the latent ones.
	 */
	public static function csv(): void {
		if ( ! current_user_can( \VulnHub\Core\Caps::VIEW ) ) {
			wp_die( esc_html__( 'You are not allowed to export this.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}

		check_admin_referer( 'vulnhub_threat_exposure_csv' );

		$d = self::data();

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="internet-exposure-' . gmdate( 'Y-m-d' ) . '.csv"' );

		$out = fopen( 'php://output', 'w' );
		fwrite( $out, "\xEF\xBB\xBF" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite

		fputcsv( $out, array( 'Priority', 'Host', 'Team', 'Port', 'Service', 'Open to', 'Outside sources', 'How', 'Front door', 'Inline firewall', 'Listening', 'Security group', 'Findings', 'On a ticket', 'Tickets', 'Vulnerabilities', 'Worst severity', 'Known exploited', 'Exploit available', 'Top EPSS', 'Top CVE', 'Worst vulnerability', 'Do first' ) );

		foreach ( array( 'open' => $d['items'], 'latent' => $d['latent'] ) as $set => $rows ) {
			foreach ( $rows as $i ) {
				fputcsv(
					$out,
					array_map(
						array( __CLASS__, 'cell' ),
						array(
							'latent' === $set ? 'latent' : $i['tier'],
							$i['host'],
							$i['team'],
							$i['port'],
							$i['service'],
							$i['reach'],
							$i['sources'],
							$i['via'],
							$i['front'],
							$i['firewall'],
							$i['listening'] ?? 'unknown',
							$i['rule'],
							count( $i['findings'] ),
							(int) ( $i['ticketed'] ?? 0 ),
							implode( ' ', array_map( static fn( array $t ): string => $t['key'] . ( '' !== $t['status'] ? ' (' . $t['status'] . ')' : '' ), (array) ( $i['tickets'] ?? array() ) ) ),
							$i['vuln_count'],
							$i['severity'],
							$i['kev'] > 0 ? 'yes' : 'no',
							$i['poc'] > 0 ? 'yes' : 'no',
							$i['epss'] > 0 ? number_format( 100 * $i['epss'], 1 ) . '%' : '',
							$i['cve'],
							(string) ( $i['vulns'][0]['title'] ?? '' ),
							'latent' === $set ? __( 'Not reachable today: a rule opens it to anyone but nothing routes in. Narrow the rule before a route change makes it real.', 'vulnhub' ) : $i['do'],
						)
					)
				);
			}
		}

		// Open from outside, never scanned: a row each, so the export is
		// not quieter than the screen about the blind spots.
		foreach ( $d['blind'] as $b ) {
			fputcsv(
				$out,
				array_map(
					array( __CLASS__, 'cell' ),
					array( 'unscanned', $b['host'], $b['team'], implode( ' ', $b['ports'] ), '', $b['reach'], '', $b['via'], $b['front'], $b['firewall'], 'unknown', '', 0, 0, '', 0, '', '', '', '', '', '', __( 'Never scanned: put a scanner on it or close the ports. No findings here means nobody has looked.', 'vulnhub' ) )
				)
			);
		}

		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose

		vulnhub()->logger->audit( 'export.internet_exposure', sprintf( 'Internet exposure CSV: %d services', count( $d['items'] ) ), 'widget', 'threat' );
		exit;
	}

	/** Neutralise a cell a spreadsheet would read as a formula. @param mixed $v */
	private static function cell( $v ): string {
		$v = (string) $v;

		return '' !== $v && in_array( $v[0], array( '=', '+', '-', '@', "\t", "\r" ), true ) ? "'" . $v : $v;
	}
}
