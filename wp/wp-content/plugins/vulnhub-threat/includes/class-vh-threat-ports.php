<?php
/**
 * What each machine is actually listening on.
 *
 * Exposure used to be decided by asset type: anything typed `server` or
 * `cloud` was called reachable from the internet. On this estate that made
 * 388 assets internet-facing on the strength of a label, and the widget then
 * reported five thousand findings as "reached straight from the internet --
 * no account, no user, no click". A type is not a listening socket.
 *
 * The evidence to do better was already in the database and unreadable.
 * Tenable runs Netstat Portscanner (WMI) on Windows and (SSH) on Unix, and
 * both return the host's full listening table. They are informational
 * findings, and informational findings are suppressed estate-wide, so the
 * whole port inventory sat in a column nothing queried.
 *
 * This class reads those outputs and turns them into rows. It answers "is
 * anything listening, and is it the kind of service another machine could
 * connect to" -- not "can the internet reach it", which needs firewall and
 * routing data no connector here supplies. Keeping those two questions apart
 * is the point: the first is observed, the second is inferred, and the widget
 * should never print the second in the voice of the first.
 *
 * @package VulnHub\Threat
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Listening-port inventory, parsed out of the scanner's own output.
 */
final class VulnHub_Threat_Ports {

	/**
	 * The Tenable plugins that report a host's listening table.
	 *
	 * Both are informational. Do not filter these by finding state -- they
	 * live in `suppressed` along with every other informational row, which is
	 * exactly why this data was invisible before.
	 */
	private const PLUGINS = array( 34220, 14272 );

	/**
	 * Listening ports that another machine could connect to, and what kind of
	 * service each one is.
	 *
	 * Deliberately not "every port in the netstat table". A Windows desktop
	 * reports thirty-odd listeners and almost all of them are local plumbing:
	 * RPC control channels, mDNS, SSDP, Delivery Optimization. Counting those
	 * as network reachability would put every laptop in the estate back in the
	 * internet lane, which is the error this class exists to correct.
	 *
	 * The class matters as much as the port. 445 is listening on very nearly
	 * every Windows machine here, so "has a remote listener" is true of the
	 * whole estate and tells nobody anything -- but SMB reachable from the
	 * internet would be an emergency, while HTTPS reachable from the internet
	 * is Tuesday. Splitting them is what makes the number mean something:
	 *
	 *   web    normally published on purpose
	 *   mail   normally published on purpose
	 *   shell  remote control -- ssh, rdp, winrm, vnc
	 *   file   file sharing -- smb, nfs, ftp
	 *   db     a database engine, never knowingly published
	 *   dir    directory and name services -- ldap, dns, snmp
	 */
	private const REMOTE = array(
		21    => array( 'ftp', 'file' ),
		22    => array( 'ssh', 'shell' ),
		23    => array( 'telnet', 'shell' ),
		25    => array( 'smtp', 'mail' ),
		53    => array( 'dns', 'dir' ),
		80    => array( 'http', 'web' ),
		110   => array( 'pop3', 'mail' ),
		143   => array( 'imap', 'mail' ),
		161   => array( 'snmp', 'dir' ),
		389   => array( 'ldap', 'dir' ),
		443   => array( 'https', 'web' ),
		445   => array( 'smb', 'file' ),
		465   => array( 'smtps', 'mail' ),
		587   => array( 'smtp', 'mail' ),
		636   => array( 'ldaps', 'dir' ),
		993   => array( 'imaps', 'mail' ),
		995   => array( 'pop3s', 'mail' ),
		1433  => array( 'mssql', 'db' ),
		1521  => array( 'oracle', 'db' ),
		2049  => array( 'nfs', 'file' ),
		3306  => array( 'mysql', 'db' ),
		3389  => array( 'rdp', 'shell' ),
		5432  => array( 'postgres', 'db' ),
		5900  => array( 'vnc', 'shell' ),
		5985  => array( 'winrm', 'shell' ),
		5986  => array( 'winrm-tls', 'shell' ),
		6379  => array( 'redis', 'db' ),
		8080  => array( 'http-alt', 'web' ),
		8443  => array( 'https-alt', 'web' ),
		9200  => array( 'elasticsearch', 'db' ),
		11211 => array( 'memcached', 'db' ),
		27017 => array( 'mongodb', 'db' ),
	);

	/**
	 * Service classes that are routinely published to the internet on purpose.
	 *
	 * A machine listening on one of these is a plausible perimeter host worth
	 * confirming. A machine listening only on `file` or `shell` is one whose
	 * exposure would be a mistake, not a design -- a different conversation,
	 * and not evidence that it faces the internet.
	 */
	private const PUBLISHABLE = array( 'web', 'mail' );

	/**
	 * Rebuild whenever a connector finishes, on the connectors that can move
	 * this data.
	 *
	 * The listening table only changes when a scan result does, so there is
	 * nothing to gain from a timer: a nightly job would either run long after
	 * the data changed or long before. Tenable is the only source of the two
	 * portscanner plugins today, but the check is on "does this connector
	 * import findings" rather than on the literal id, so a second scanner
	 * feeding the same plugins does not need this line edited to work.
	 *
	 * Exposure is rebuilt in the same pass because it reads this table -- and
	 * leaving the two out of step would mean serving a verdict derived from
	 * ports the scan no longer reports.
	 */
	public static function init(): void {
		add_action( 'vulnhub_sync_complete', array( __CLASS__, 'on_sync' ), 20, 1 );
	}

	/**
	 * @param string $connector Connector id that just finished.
	 */
	public static function on_sync( string $connector = '' ): void {
		$scan = '' === $connector || in_array( $connector, self::SOURCES, true );

		// The verdict also moves when the cloud map or the posture inventory
		// does: an AWS capture is what proves a port open. Without this an
		// exposure stayed as the last Tenable sync left it.
		if ( ! $scan && ! in_array( $connector, self::EXPOSURE_SOURCES, true ) ) {
			return;
		}

		if ( $scan ) {
			self::rebuild();
		}

		if ( class_exists( 'VulnHub_Threat_Classify' ) ) {
			VulnHub_Threat_Classify::rebuild_exposure();
		}
	}

	/** Connectors whose sync can change what a host reports listening. */
	private const SOURCES = array( 'tenable' );

	/** Connectors that move reachability without moving the port inventory. */
	private const EXPOSURE_SOURCES = array( 'aws', 'plerion' );

	/** Table name. */
	public static function table(): string {
		return VulnHub_Threat_Install::table( 'asset_ports' );
	}

	/**
	 * Is this a port another machine would connect to?
	 *
	 * @param int $port Port number.
	 */
	public static function is_remote( int $port ): bool {
		/*
		 * An allow-list, not a heuristic. Everything outside it -- the
		 * ephemeral range above 49152, RPC endpoints handed out at boot, mDNS,
		 * SSDP, Delivery Optimization -- is local plumbing that happens to
		 * hold a socket open, and counting it as reachability is what put
		 * every laptop in the internet lane to begin with.
		 */
		return isset( self::REMOTE[ $port ] );
	}

	/** The service name for a port, or '' when it is not one we name. */
	public static function service( int $port ): string {
		return (string) ( self::REMOTE[ $port ][0] ?? '' );
	}

	/** Which kind of service a port is -- web, mail, shell, file, db, dir. */
	public static function kind( int $port ): string {
		return (string) ( self::REMOTE[ $port ][1] ?? '' );
	}

	/** Is this the sort of service that gets published to the internet? */
	public static function is_publishable( int $port ): bool {
		return in_array( self::kind( $port ), self::PUBLISHABLE, true );
	}

	/**
	 * Parse one plugin output into [ port => protocol ].
	 *
	 * Two shapes are in the wild. Tenable's export API returns JSON --
	 * {"listening":[{"port":135,"protocol":"TCP",...}]} -- while a CSV export
	 * of the same plugin gives the human-readable text block. Both are read
	 * here so a change of import route does not silently empty this table.
	 *
	 * @return array<int,string> Port => protocol.
	 */
	public static function parse( string $output ): array {
		$out = array();

		if ( '' === trim( $output ) ) {
			return $out;
		}

		$json = json_decode( $output, true );

		if ( is_array( $json ) && ! empty( $json['listening'] ) && is_array( $json['listening'] ) ) {
			foreach ( $json['listening'] as $row ) {
				if ( ! is_array( $row ) ) {
					continue;
				}

				$port = (int) ( $row['port'] ?? 0 );

				if ( $port > 0 && $port <= 65535 ) {
					$out[ $port ] = strtolower( (string) ( $row['protocol'] ?? 'tcp' ) ) ?: 'tcp';
				}
			}

			return $out;
		}

		/*
		 * Text shape, e.g. "Port 22/tcp was found to be open" or a bare
		 * "  22/tcp" listing. Anchored on the slash so a version string like
		 * "8.1.3" cannot be read as a port.
		 */
		if ( preg_match_all( '~\b(\d{1,5})/(tcp|udp)\b~i', $output, $m, PREG_SET_ORDER ) ) {
			foreach ( $m as $hit ) {
				$port = (int) $hit[1];

				if ( $port > 0 && $port <= 65535 ) {
					$out[ $port ] = strtolower( $hit[2] );
				}
			}
		}

		return $out;
	}

	/**
	 * Rebuild the table from the scanner output currently held.
	 *
	 * @return array{assets:int,ports:int,remote_assets:int}
	 */
	public static function rebuild(): array {
		global $wpdb;

		$t     = self::table();
		$f     = vh_table( 'findings' );
		$v     = vh_table( 'vulns' );
		$now   = vh_now();
		$ids   = implode( ',', array_map( 'intval', self::PLUGINS ) );

		$rows = (array) $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			"SELECT f.asset_id, f.output, v.plugin_id
			   FROM {$f} f
			   INNER JOIN {$v} v ON v.id = f.vuln_id
			  WHERE v.plugin_id IN ({$ids}) AND f.output <> ''", // phpcs:ignore
			ARRAY_A
		);

		$seen = array();

		foreach ( $rows as $row ) {
			$asset = (int) $row['asset_id'];

			if ( $asset < 1 ) {
				continue;
			}

			foreach ( self::parse( (string) $row['output'] ) as $port => $proto ) {
				// An asset can be scanned by both plugins, or rescanned. Key on
				// asset+port+protocol so the newest read simply wins.
				$seen[ $asset . ':' . $port . ':' . $proto ] = array( $asset, $port, $proto, (int) $row['plugin_id'] );
			}
		}

		$wpdb->query( "TRUNCATE TABLE {$t}" ); // phpcs:ignore

		$values = array();
		$params = array();
		$stored = 0;

		foreach ( $seen as $hit ) {
			[ $asset, $port, $proto, $plugin ] = $hit;

			$values[] = '(%d,%d,%s,%d,%s,%s,%d,%s)';
			array_push( $params, $asset, $port, $proto, self::is_remote( $port ) ? 1 : 0, self::service( $port ), self::kind( $port ), $plugin, $now );

			if ( count( $values ) >= 300 ) {
				self::write( $values, $params );
				$stored += count( $values );
				$values  = array();
				$params  = array();
			}
		}

		if ( $values ) {
			self::write( $values, $params );
			$stored += count( $values );
		}

		return array(
			'assets'        => (int) $wpdb->get_var( "SELECT COUNT(DISTINCT asset_id) FROM {$t}" ), // phpcs:ignore
			'ports'         => $stored,
			'remote_assets' => (int) $wpdb->get_var( "SELECT COUNT(DISTINCT asset_id) FROM {$t} WHERE remote = 1" ), // phpcs:ignore
			'publishable'   => count( self::publishable_ids() ),
		);
	}

	/**
	 * @param string[]         $values Placeholder groups.
	 * @param array<int,mixed> $params Bound values.
	 */
	private static function write( array $values, array $params ): void {
		global $wpdb;

		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared
			$wpdb->prepare(
				'INSERT INTO ' . self::table() . ' (asset_id,port,protocol,remote,service,kind,plugin_id,updated_at) VALUES ' // phpcs:ignore
				. implode( ',', $values )
				. ' ON DUPLICATE KEY UPDATE remote=VALUES(remote), service=VALUES(service), kind=VALUES(kind), plugin_id=VALUES(plugin_id), updated_at=VALUES(updated_at)',
				...$params
			)
		);
	}

	/** Assets with at least one remote-reachable listener. @return int[] */
	public static function remote_listener_ids(): array {
		global $wpdb;

		return array_map(
			'intval',
			(array) $wpdb->get_col( 'SELECT DISTINCT asset_id FROM ' . self::table() . ' WHERE remote = 1' ) // phpcs:ignore
		);
	}

	/**
	 * Assets listening on a service of the kind that gets published.
	 *
	 * This is the honest shortlist for "might really face the internet". It is
	 * evidence of a plausible perimeter host, not proof of reachability --
	 * nothing here can see a firewall rule.
	 *
	 * @return int[]
	 */
	public static function publishable_ids(): array {
		global $wpdb;

		$kinds = "'" . implode( "','", array_map( 'esc_sql', self::PUBLISHABLE ) ) . "'";

		return array_map(
			'intval',
			(array) $wpdb->get_col( 'SELECT DISTINCT asset_id FROM ' . self::table() . " WHERE kind IN ({$kinds})" ) // phpcs:ignore
		);
	}

	/**
	 * What one machine listens on that another machine could connect to.
	 *
	 * @return array<int,array{port:int,protocol:string,service:string}>
	 */
	public static function remote_ports( int $asset_id ): array {
		global $wpdb;

		return array_map(
			static fn( array $r ): array => array( 'port' => (int) $r['port'], 'protocol' => (string) ( $r['protocol'] ?: 'tcp' ), 'service' => (string) $r['service'] ),
			(array) $wpdb->get_results( $wpdb->prepare( 'SELECT port, protocol, service FROM ' . self::table() . ' WHERE asset_id = %d AND remote = 1', $asset_id ), ARRAY_A ) // phpcs:ignore
		);
	}

	/** Assets we have any listening data for at all. @return int[] */
	public static function scanned_ids(): array {
		global $wpdb;

		return array_map(
			'intval',
			(array) $wpdb->get_col( 'SELECT DISTINCT asset_id FROM ' . self::table() ) // phpcs:ignore
		);
	}

	/** Do we hold any port data? Cheap enough to call on every render. */
	public static function has_data(): bool {
		global $wpdb;

		$t = self::table();

		if ( (string) $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $t ) ) !== $t ) { // phpcs:ignore
			return false;
		}

		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$t} LIMIT 1" ) > 0; // phpcs:ignore
	}

	/**
	 * The listening services on one asset, remote-relevant first.
	 *
	 * @return array<int,array{port:int,protocol:string,service:string,remote:bool}>
	 */
	public static function for_asset( int $asset_id ): array {
		global $wpdb;

		$rows = (array) $wpdb->get_results( // phpcs:ignore
			$wpdb->prepare(
				'SELECT port, protocol, service, remote FROM ' . self::table() // phpcs:ignore
				. ' WHERE asset_id = %d ORDER BY remote DESC, port ASC',
				$asset_id
			),
			ARRAY_A
		);

		return array_map(
			static fn( array $r ): array => array(
				'port'     => (int) $r['port'],
				'protocol' => (string) $r['protocol'],
				'service'  => (string) $r['service'],
				'remote'   => (bool) (int) $r['remote'],
			),
			$rows
		);
	}

	/**
	 * Why each reachable asset is considered reachable, ready to print.
	 *
	 * Loaded for the whole internet-facing set in one query rather than per
	 * row. The set is the 23 assets the exposure rule confirmed, so this is a
	 * couple of dozen rows however many findings the reader is paging through
	 * -- and a findings list filtered to the edge route cannot contain an
	 * asset that is not in it.
	 *
	 * A verdict with no port behind it still gets an entry: exposure can be
	 * decided by a tag or a public address, and a blank cell on those rows
	 * would read as "no evidence" when the real answer is "evidence of a
	 * different kind".
	 *
	 * @return array<int,array<int,string>> Asset id => the listening services,
	 *         or a single-entry list carrying the reason it is reachable.
	 */
	public static function evidence_map(): array {
		global $wpdb;

		static $map = null;

		if ( null !== $map ) {
			return $map;
		}

		$map  = array();
		$expo = VulnHub_Threat_Install::table( 'asset_exposure' );

		$facing = (array) $wpdb->get_results( // phpcs:ignore
			"SELECT asset_id, reason FROM {$expo} WHERE internet_facing = 1", // phpcs:ignore
			ARRAY_A
		);

		if ( ! $facing ) {
			return $map;
		}

		$ids = array_map( static fn( array $r ): int => (int) $r['asset_id'], $facing );

		$ports = (array) $wpdb->get_results( // phpcs:ignore
			'SELECT asset_id, port, protocol, service, kind FROM ' . self::table() // phpcs:ignore
			. ' WHERE remote = 1 AND asset_id IN (' . implode( ',', $ids ) . ')'
			. ' ORDER BY FIELD(kind,' . "'web','mail','shell','file','db','dir'" . '), port',
			ARRAY_A
		);

		$by_asset = array();

		foreach ( $ports as $row ) {
			$id = (int) $row['asset_id'];

			$by_asset[ $id ][] = sprintf(
				'%s %d/%s',
				(string) $row['service'] ?: __( 'service', 'vulnhub' ),
				(int) $row['port'],
				(string) $row['protocol']
			);
		}

		foreach ( $facing as $row ) {
			$id = (int) $row['asset_id'];

			$map[ $id ] = isset( $by_asset[ $id ] )
				? array_slice( $by_asset[ $id ], 0, 4 )
				: array( (string) $row['reason'] );
		}

		return $map;
	}

	/**
	 * Which remote services are listening across the estate, and on how many.
	 *
	 * @return array<int,array{port:int,service:string,assets:int}>
	 */
	public static function remote_summary( int $limit = 12 ): array {
		global $wpdb;

		$rows = (array) $wpdb->get_results( // phpcs:ignore
			$wpdb->prepare(
				'SELECT port, service, kind, COUNT(DISTINCT asset_id) n FROM ' . self::table() // phpcs:ignore
				. ' WHERE remote = 1 GROUP BY port, service, kind ORDER BY n DESC, port ASC LIMIT %d',
				$limit
			),
			ARRAY_A
		);

		return array_map(
			static fn( array $r ): array => array(
				'port'    => (int) $r['port'],
				'service' => (string) $r['service'],
				'kind'    => (string) $r['kind'],
				'assets'  => (int) $r['n'],
			),
			$rows
		);
	}
}
