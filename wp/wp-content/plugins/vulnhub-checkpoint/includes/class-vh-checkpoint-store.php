<?php
/**
 * Where the Check Point import lives, and what the rest of the platform
 * reads from it.
 *
 * Five tables, all owned here:
 *
 *   cp_gateways  gateways and management servers, with the installed policy
 *   cp_objects   every network and service object seen (inventory and the
 *                rulebase dictionaries), as the API returned it
 *   cp_rules     access rules, flattened, per package and layer, in order
 *   cp_nat       NAT rules per package
 *   cp_exposure  what the policy reader concluded: machine, port, who, how
 *
 * A run writes everything with one timestamp and prunes rows older than it
 * only when the whole read succeeded, so a failed run leaves the last good
 * snapshot in place rather than a half-imported one.
 *
 * @package VulnHub\CheckPoint
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_CheckPoint_Store {

	public const DB_VERSION = '2';
	public const VERSION_OPTION = 'vulnhub_checkpoint_db';
	public const BROAD_OPTION = 'vulnhub_checkpoint_broad';
	public const STAMP_OPTION = 'vulnhub_checkpoint_stamp';

	public static function table( string $name ): string {
		global $wpdb;

		return $wpdb->prefix . 'vulnhub_cp_' . $name;
	}

	public static function maybe_install(): void {
		if ( self::DB_VERSION === (string) get_option( self::VERSION_OPTION, '' ) ) {
			return;
		}

		self::install();
	}

	public static function install(): void {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$c = $wpdb->get_charset_collate();

		dbDelta(
			'CREATE TABLE ' . self::table( 'gateways' ) . " (
				uid varchar(64) NOT NULL,
				name varchar(191) NOT NULL DEFAULT '',
				type varchar(64) NOT NULL DEFAULT '',
				ipv4 varchar(45) NOT NULL DEFAULT '',
				version varchar(32) NOT NULL DEFAULT '',
				policy varchar(191) NOT NULL DEFAULT '',
				data longtext NULL,
				site varchar(191) NOT NULL DEFAULT '',
				location_id bigint(20) unsigned NOT NULL DEFAULT 0,
				platform varchar(16) NOT NULL DEFAULT '',
				confidence varchar(8) NOT NULL DEFAULT '',
				cluster varchar(191) NOT NULL DEFAULT '',
				evidence text NULL,
				last_seen datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				PRIMARY KEY  (uid)
			) {$c};"
		);

		dbDelta(
			'CREATE TABLE ' . self::table( 'objects' ) . " (
				uid varchar(64) NOT NULL,
				name varchar(191) NOT NULL DEFAULT '',
				type varchar(64) NOT NULL DEFAULT '',
				data longtext NULL,
				last_seen datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				PRIMARY KEY  (uid),
				KEY type (type)
			) {$c};"
		);

		dbDelta(
			'CREATE TABLE ' . self::table( 'rules' ) . " (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				package varchar(191) NOT NULL DEFAULT '',
				layer_uid varchar(64) NOT NULL DEFAULT '',
				layer_name varchar(191) NOT NULL DEFAULT '',
				inline tinyint(1) NOT NULL DEFAULT 0,
				position int(10) unsigned NOT NULL DEFAULT 0,
				rule_uid varchar(64) NOT NULL DEFAULT '',
				rule_number varchar(16) NOT NULL DEFAULT '',
				section varchar(191) NOT NULL DEFAULT '',
				name varchar(191) NOT NULL DEFAULT '',
				enabled tinyint(1) NOT NULL DEFAULT 1,
				data longtext NULL,
				last_seen datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				PRIMARY KEY  (id),
				KEY layer (layer_uid, position),
				KEY package (package)
			) {$c};"
		);

		dbDelta(
			'CREATE TABLE ' . self::table( 'nat' ) . " (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				package varchar(191) NOT NULL DEFAULT '',
				position int(10) unsigned NOT NULL DEFAULT 0,
				rule_uid varchar(64) NOT NULL DEFAULT '',
				rule_number varchar(16) NOT NULL DEFAULT '',
				section varchar(191) NOT NULL DEFAULT '',
				method varchar(32) NOT NULL DEFAULT '',
				enabled tinyint(1) NOT NULL DEFAULT 1,
				data longtext NULL,
				last_seen datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				PRIMARY KEY  (id),
				KEY package (package, position)
			) {$c};"
		);

		dbDelta(
			'CREATE TABLE ' . self::table( 'exposure' ) . " (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				asset_id bigint(20) unsigned NOT NULL DEFAULT 0,
				ip varchar(45) NOT NULL DEFAULT '',
				via varchar(12) NOT NULL DEFAULT '',
				front varchar(45) NOT NULL DEFAULT '',
				reach varchar(12) NOT NULL DEFAULT '',
				sources int(10) unsigned NOT NULL DEFAULT 0,
				protocol varchar(8) NOT NULL DEFAULT 'tcp',
				port_from int(10) unsigned NOT NULL DEFAULT 0,
				port_to int(10) unsigned NOT NULL DEFAULT 0,
				package varchar(191) NOT NULL DEFAULT '',
				rule_uid varchar(64) NOT NULL DEFAULT '',
				rule_label varchar(255) NOT NULL DEFAULT '',
				latent tinyint(1) NOT NULL DEFAULT 0,
				computed_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				PRIMARY KEY  (id),
				KEY asset (asset_id),
				KEY latent (latent)
			) {$c};"
		);

		update_option( self::VERSION_OPTION, self::DB_VERSION, false );
	}

	/**
	 * Insert rows in batches.
	 *
	 * @param array<int,array<string,mixed>> $rows Same keys in every row.
	 */
	private static function insert( string $table, array $rows, bool $replace = false ): void {
		global $wpdb;

		if ( ! $rows ) {
			return;
		}

		$cols = array_keys( $rows[0] );

		foreach ( array_chunk( $rows, 200 ) as $chunk ) {
			$values = array();
			$params = array();

			foreach ( $chunk as $r ) {
				$ph = array();

				foreach ( $cols as $c ) {
					$v      = $r[ $c ];
					$ph[]   = is_int( $v ) ? '%d' : '%s';
					$params[] = is_int( $v ) ? $v : (string) $v;
				}

				$values[] = '(' . implode( ',', $ph ) . ')';
			}

			$sql = ( $replace ? 'REPLACE' : 'INSERT' ) . " INTO {$table} (" . implode( ',', $cols ) . ') VALUES ' . implode( ',', $values );

			$wpdb->query( $wpdb->prepare( $sql, ...$params ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		}
	}

	/**
	 * Write one complete snapshot and drop whatever it no longer contains.
	 *
	 * @param array<string,mixed> $snap gateways, objects, rules, nat (as built by the connector).
	 */
	public static function save_snapshot( array $snap, string $now ): void {
		global $wpdb;

		$enc = static fn( $v ): string => (string) wp_json_encode( $v );

		$wpdb->query( 'START TRANSACTION' ); // phpcs:ignore

		$rows = array();
		foreach ( (array) $snap['gateways'] as $g ) {
			$rows[] = array(
				'uid'       => substr( (string) ( $g['uid'] ?? '' ), 0, 64 ),
				'name'      => substr( (string) ( $g['name'] ?? '' ), 0, 191 ),
				'type'      => substr( (string) ( $g['type'] ?? '' ), 0, 64 ),
				'ipv4'      => substr( (string) ( $g['ipv4-address'] ?? '' ), 0, 45 ),
				'version'   => substr( (string) ( $g['version'] ?? '' ), 0, 32 ),
				'policy'    => substr( (string) ( $g['policy']['access-policy-name'] ?? '' ), 0, 191 ),
				'data'      => $enc( $g ),
				'last_seen' => $now,
			);
		}
		self::insert( self::table( 'gateways' ), $rows, true );

		$rows = array();
		foreach ( (array) $snap['objects'] as $uid => $o ) {
			$rows[] = array(
				'uid'       => substr( (string) $uid, 0, 64 ),
				'name'      => substr( (string) ( $o['name'] ?? '' ), 0, 191 ),
				'type'      => substr( (string) ( $o['type'] ?? '' ), 0, 64 ),
				'data'      => $enc( $o ),
				'last_seen' => $now,
			);
		}
		self::insert( self::table( 'objects' ), $rows, true );

		// Rules and NAT carry no stable natural key across reorders, so the
		// snapshot replaces them whole.
		$wpdb->query( 'DELETE FROM ' . self::table( 'rules' ) ); // phpcs:ignore
		$rows = array();
		foreach ( (array) $snap['rules'] as $r ) {
			$rows[] = array(
				'package'     => substr( (string) $r['_package'], 0, 191 ),
				'layer_uid'   => substr( (string) $r['_layer_uid'], 0, 64 ),
				'layer_name'  => substr( (string) $r['_layer_name'], 0, 191 ),
				'inline'      => (int) $r['_inline'],
				'position'    => (int) $r['_position'],
				'rule_uid'    => substr( (string) ( $r['uid'] ?? '' ), 0, 64 ),
				'rule_number' => substr( (string) ( $r['rule-number'] ?? '' ), 0, 16 ),
				'section'     => substr( (string) ( $r['_section'] ?? '' ), 0, 191 ),
				'name'        => substr( (string) ( $r['name'] ?? '' ), 0, 191 ),
				'enabled'     => array_key_exists( 'enabled', $r ) && ! $r['enabled'] ? 0 : 1,
				'data'        => $enc( $r ),
				'last_seen'   => $now,
			);
		}
		self::insert( self::table( 'rules' ), $rows );

		$wpdb->query( 'DELETE FROM ' . self::table( 'nat' ) ); // phpcs:ignore
		$rows = array();
		foreach ( (array) $snap['nat'] as $r ) {
			$rows[] = array(
				'package'     => substr( (string) $r['_package'], 0, 191 ),
				'position'    => (int) $r['_position'],
				'rule_uid'    => substr( (string) ( $r['uid'] ?? '' ), 0, 64 ),
				'rule_number' => substr( (string) ( $r['rule-number'] ?? '' ), 0, 16 ),
				'section'     => substr( (string) ( $r['_section'] ?? '' ), 0, 191 ),
				'method'      => substr( (string) ( $r['method'] ?? '' ), 0, 32 ),
				'enabled'     => array_key_exists( 'enabled', $r ) && ! $r['enabled'] ? 0 : 1,
				'data'        => $enc( $r ),
				'last_seen'   => $now,
			);
		}
		self::insert( self::table( 'nat' ), $rows );

		$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . self::table( 'gateways' ) . ' WHERE last_seen < %s', $now ) ); // phpcs:ignore
		$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . self::table( 'objects' ) . ' WHERE last_seen < %s', $now ) ); // phpcs:ignore

		$wpdb->query( 'COMMIT' ); // phpcs:ignore

		update_option( self::STAMP_OPTION, $now, false );
	}

	/**
	 * Gateways as the Smart-1 Cloud service lists them (portal key only).
	 * The one-time registration token each record carries is dropped, never
	 * stored.
	 *
	 * @param array<int,array<string,mixed>> $rows
	 */
	public static function save_service_gateways( array $rows, string $version, string $now ): void {
		global $wpdb;

		$out = array();

		foreach ( $rows as $g ) {
			unset( $g['token'], $g['tokenExpiresAt'] );

			$out[] = array(
				'uid'       => substr( 'svc-' . (string) ( $g['id'] ?? $g['name'] ?? '' ), 0, 64 ),
				'name'      => substr( (string) ( $g['name'] ?? '' ), 0, 191 ),
				'type'      => substr( (string) ( $g['type'] ?? '' ), 0, 64 ),
				'ipv4'      => substr( (string) ( $g['ip'] ?? '' ), 0, 45 ),
				'version'   => substr( $version, 0, 32 ),
				'policy'    => substr( (string) ( $g['statusDetails']['status'] ?? '' ), 0, 191 ),
				'data'      => (string) wp_json_encode( $g ),
				'last_seen' => $now,
			);
		}

		self::insert( self::table( 'gateways' ), $out, true );
		// LOCATE, not LIKE: no literal % in a prepared fragment (CLAUDE.md).
		$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . self::table( 'gateways' ) . " WHERE LOCATE('svc-', uid) = 1 AND last_seen < %s", $now ) ); // phpcs:ignore
	}

	/**
	 * One row per firewall.
	 *
	 * The table holds two views of the same gateways once the policy has
	 * been read: the Smart-1 Cloud service's (uid "svc-…", with connection
	 * status) and the management server's (object uid, with the name the
	 * service sometimes leaves blank). The service row is kept, named from
	 * the management row with the same address when it has no name; a
	 * management row is kept only when the service has no row for it.
	 * Cluster objects are left out -- their members already stand for them.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function gateway_rows(): array {
		global $wpdb;

		$all  = (array) $wpdb->get_results( 'SELECT uid, name, type, ipv4, version, policy, site, location_id, platform, confidence, cluster, evidence, data FROM ' . self::table( 'gateways' ), ARRAY_A ); // phpcs:ignore
		$svc  = array();
		$mgmt = array();

		foreach ( $all as $r ) {
			if ( 'CpmiGatewayCluster' === (string) $r['type'] ) {
				continue;
			}
			if ( str_starts_with( (string) $r['uid'], 'svc-' ) ) {
				$svc[] = $r;
			} else {
				$mgmt[] = $r;
			}
		}

		$by_ip   = array();
		$by_name = array();
		foreach ( $mgmt as $r ) {
			$by_ip[ (string) $r['ipv4'] ]   = $r;
			$by_name[ (string) $r['name'] ] = $r;
		}

		$out   = array();
		$taken = array();

		foreach ( $svc as $r ) {
			if ( '' === (string) $r['name'] && isset( $by_ip[ (string) $r['ipv4'] ] ) ) {
				$m             = $by_ip[ (string) $r['ipv4'] ];
				$r['name']     = (string) $m['name'];
				$r['policy']   = '' !== (string) $r['policy'] ? $r['policy'] : (string) $m['policy'];
				$r['version']  = '' !== (string) $r['version'] ? $r['version'] : (string) $m['version'];
			}
			$taken[ (string) $r['name'] ] = true;
			$taken[ 'ip:' . $r['ipv4'] ]  = true;
			$out[]                        = $r;
		}

		foreach ( $mgmt as $r ) {
			if ( isset( $taken[ (string) $r['name'] ] ) || isset( $taken[ 'ip:' . $r['ipv4'] ] ) ) {
				continue;
			}
			$out[] = $r;
		}

		usort( $out, static fn( array $a, array $b ): int => array( (string) $a['site'], (string) $a['name'] ) <=> array( (string) $b['site'], (string) $b['name'] ) );

		return $out;
	}

	/* =================================================================
	 * Reading the snapshot back for the policy reader
	 * ============================================================== */

	/** @return array<string,array<string,mixed>> uid => object */
	public static function objects(): array {
		global $wpdb;

		$out = array();

		foreach ( (array) $wpdb->get_results( 'SELECT uid, data FROM ' . self::table( 'objects' ), ARRAY_A ) as $r ) { // phpcs:ignore
			$out[ (string) $r['uid'] ] = (array) json_decode( (string) $r['data'], true );
		}

		return $out;
	}

	/**
	 * Top layers by package, and inline layers by uid.
	 *
	 * @return array{packages:array<string,array<int,array<string,mixed>>>,inline:array<string,array<int,array<string,mixed>>>}
	 */
	public static function rules(): array {
		global $wpdb;

		$packages = array();
		$inline   = array();

		foreach ( (array) $wpdb->get_results( 'SELECT package, layer_uid, inline, data FROM ' . self::table( 'rules' ) . ' ORDER BY package, layer_uid, position', ARRAY_A ) as $r ) { // phpcs:ignore
			$rule = (array) json_decode( (string) $r['data'], true );

			if ( (int) $r['inline'] ) {
				$inline[ (string) $r['layer_uid'] ][] = $rule;
			} else {
				$packages[ (string) $r['package'] ][] = $rule;
			}
		}

		return array( 'packages' => $packages, 'inline' => $inline );
	}

	/** @return array<int,array<string,mixed>> */
	public static function nat_rules(): array {
		global $wpdb;

		return array_map(
			static fn( array $r ): array => (array) json_decode( (string) $r['data'], true ),
			(array) $wpdb->get_results( 'SELECT data FROM ' . self::table( 'nat' ) . ' ORDER BY package, position', ARRAY_A ) // phpcs:ignore
		);
	}

	/**
	 * Every address a machine is known by.
	 *
	 * @return array<int,array{asset_id:int,ip:int}>
	 */
	public static function targets(): array {
		global $wpdb;

		$a    = vh_table( 'assets' );
		$rows = (array) $wpdb->get_results( "SELECT id, ipv4, ipv4s FROM {$a} WHERE duplicate_of IS NULL AND lifecycle_status IN (" . vh_reportable_sql() . ')', ARRAY_A ); // phpcs:ignore
		$out  = array();
		$seen = array();

		foreach ( $rows as $r ) {
			foreach ( array_merge( array( (string) $r['ipv4'] ), explode( ',', (string) $r['ipv4s'] ) ) as $ip ) {
				$n = VulnHub_CheckPoint_Policy::ip2int( $ip );

				if ( null === $n || isset( $seen[ $r['id'] . '|' . $n ] ) ) {
					continue;
				}

				$seen[ $r['id'] . '|' . $n ] = true;
				$out[]                     = array( 'asset_id' => (int) $r['id'], 'ip' => $n );
			}
		}

		return $out;
	}

	/**
	 * Replace the exposure verdicts.
	 *
	 * @param array<int,array<string,mixed>> $paths From VulnHub_CheckPoint_Policy::exposure().
	 * @param array<int,array<string,mixed>> $broad Broad rules.
	 */
	public static function save_exposure( array $paths, array $broad, string $now ): void {
		global $wpdb;

		$rows = array();
		$seen = array();

		foreach ( $paths as $p ) {
			$k = implode( '|', array( $p['asset_id'], $p['ip'], $p['via'], $p['front'], $p['protocol'], $p['port_from'], $p['port_to'], $p['reach'], $p['latent'] ) );

			// The first rule (in package order) that opens a port is the one
			// shown; the same door through a second package adds nothing.
			if ( isset( $seen[ $k ] ) ) {
				continue;
			}
			$seen[ $k ] = true;

			$rows[] = array(
				'asset_id'    => (int) $p['asset_id'],
				'ip'          => (string) $p['ip'],
				'via'         => (string) $p['via'],
				'front'       => (string) $p['front'],
				'reach'       => (string) $p['reach'],
				'sources'     => (int) $p['sources'],
				'protocol'    => (string) $p['protocol'],
				'port_from'   => (int) $p['port_from'],
				'port_to'     => (int) $p['port_to'],
				'package'     => substr( (string) $p['package'], 0, 191 ),
				'rule_uid'    => substr( (string) $p['rule_uid'], 0, 64 ),
				'rule_label'  => substr( (string) $p['rule'], 0, 255 ),
				'latent'      => (int) $p['latent'],
				'computed_at' => $now,
			);
		}

		$wpdb->query( 'START TRANSACTION' ); // phpcs:ignore
		$wpdb->query( 'DELETE FROM ' . self::table( 'exposure' ) ); // phpcs:ignore
		self::insert( self::table( 'exposure' ), $rows );
		$wpdb->query( 'COMMIT' ); // phpcs:ignore

		update_option( self::BROAD_OPTION, array( 'at' => $now, 'rules' => array_slice( $broad, 0, 500 ) ), false );
	}

	/* =================================================================
	 * What the platform reads
	 * ============================================================== */

	/**
	 * Ways in, shaped for `vulnhub_internet_paths` (see vulnhub-threat).
	 *
	 * @return array{paths:array<int,array<int,array<string,mixed>>>,latent:array<int,array<int,array<string,mixed>>>,stamp:string}
	 */
	public static function internet_paths(): array {
		global $wpdb;

		$out = array( 'paths' => array(), 'latent' => array(), 'stamp' => (string) get_option( self::STAMP_OPTION, '' ) );

		foreach ( (array) $wpdb->get_results( 'SELECT * FROM ' . self::table( 'exposure' ), ARRAY_A ) as $r ) { // phpcs:ignore
			$way = array(
				'protocol'  => (string) $r['protocol'],
				'port_from' => (int) $r['port_from'],
				'port_to'   => (int) $r['port_to'],
				'reach'     => (string) $r['reach'],
				'sources'   => (int) $r['sources'],
				'rule'      => (string) $r['rule_label'],
				'via'       => (string) $r['via'],
				'front'     => (string) $r['front'],
				'route'     => '',
				'firewall'  => 'policy',
			);

			$out[ (int) $r['latent'] ? 'latent' : 'paths' ][ (int) $r['asset_id'] ][] = $way;
		}

		return $out;
	}

	/**
	 * Asset id => why, for `vulnhub_cloud_reachable_assets`.
	 *
	 * @return array<int,string>
	 */
	public static function reachable_assets(): array {
		global $wpdb;

		$out  = array();
		$rows = (array) $wpdb->get_results( 'SELECT asset_id, protocol, port_from, port_to, reach, via, front, rule_label FROM ' . self::table( 'exposure' ) . " WHERE latent = 0 ORDER BY reach = 'anyone' DESC, id", ARRAY_A ); // phpcs:ignore

		foreach ( $rows as $r ) {
			$id = (int) $r['asset_id'];

			if ( isset( $out[ $id ] ) ) {
				continue;
			}

			$port = (int) $r['port_from'] === (int) $r['port_to'] ? (string) $r['port_from'] : $r['port_from'] . '-' . $r['port_to'];

			$out[ $id ] = sprintf(
				/* translators: 1: protocol/port, 2: who, 3: address, 4: rule. */
				__( '%1$s open to %2$s on %3$s (Check Point %4$s)', 'vulnhub' ),
				$r['protocol'] . '/' . $port,
				'anyone' === $r['reach'] ? __( 'anyone', 'vulnhub' ) : __( 'listed outside addresses', 'vulnhub' ),
				(string) $r['front'],
				(string) $r['rule_label']
			);
		}

		return $out;
	}

	/** @return array<string,int> */
	public static function counts(): array {
		global $wpdb;

		$e = self::table( 'exposure' );

		return array(
			'gateways' => count( self::gateway_rows() ),
			'objects'  => (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . self::table( 'objects' ) ), // phpcs:ignore
			'rules'    => (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . self::table( 'rules' ) ), // phpcs:ignore
			'nat'      => (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . self::table( 'nat' ) ), // phpcs:ignore
			'assets'   => (int) $wpdb->get_var( "SELECT COUNT(DISTINCT asset_id) FROM {$e} WHERE latent = 0" ), // phpcs:ignore
			'paths'    => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$e} WHERE latent = 0" ), // phpcs:ignore
			'latent'   => (int) $wpdb->get_var( "SELECT COUNT(DISTINCT asset_id) FROM {$e} WHERE latent = 1" ), // phpcs:ignore
		);
	}
}

