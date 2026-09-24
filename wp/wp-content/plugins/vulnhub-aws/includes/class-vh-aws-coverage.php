<?php
/**
 * Are the machines running in AWS scanned and protected?
 *
 * **What is in scope, and why.** Tenable Vulnerability Management reaches a
 * machine through an agent or a network scan -- both need an operating system
 * that the machine runs and we own. In AWS that is an EC2 instance, and only
 * that: a Lambda function, a Fargate/ECS task, an RDS database, an S3 bucket
 * or a managed service (Transfer Family, AppStream's own hosts) has no OS of
 * ours to put an agent on, and a network scan of a managed endpoint tests
 * AWS's patching, not ours. Defender for Endpoint has the same boundary. So
 * coverage is measured on EC2 instances, and everything else is listed as
 * *not Tenable's to scan* -- its posture comes from Plerion.
 *
 * AppStream is the exception that proves it: its instances are AWS's, but the
 * image is ours and carries the agent, so it is covered through its fleet
 * record (see docs/APPSTREAM.md), not here.
 *
 * **Where the instances come from.** The network capture (every instance, with
 * its state and Name tag, in the accounts the sign-in reaches), plus the
 * posture inventory's EC2 list for accounts the sign-in cannot read. Stopped
 * instances are counted apart: an agent reports when the machine is on.
 *
 * **Linking twins.** The posture inventory names an instance with no Name tag
 * by its id, so a domain controller Intune and Defender already know as `ad01`
 * came in a second time as `i-0…`: one row said "Defender, not in AWS", the
 * other "in AWS, no Defender", and the machine read as a gap it is not.
 * link_twins() joins them on two agreeing facts -- the instance's private
 * address *and* its name -- and nothing weaker.
 *
 * Every number the widget draws is a `Repo::assets()` count with the same
 * arguments as the list it links to (`aws=ec2` plus the existing `coverage`
 * and `defender` filters), so a number and its list cannot disagree.
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_AWS_Coverage {

	public const WIDGET = 'aws_coverage';

	/** Values the `aws` asset filter takes. */
	public const SCOPES = array( 'ec2', 'ec2_stopped' );

	/** @var array<string,array<int,string>>|null */
	private static ?array $ids = null;

	public static function init(): void {
		add_filter( 'vulnhub_assets_query', array( __CLASS__, 'assets_query' ), 10, 2 );
		add_filter( 'vulnhub_dashboard_widgets', array( __CLASS__, 'register' ) );
		add_filter( 'vulnhub_dashboard_default_layout', array( __CLASS__, 'place' ) );
		// After the capture and the posture sync, before coverage is recounted.
		add_action( 'vulnhub_sync_complete', array( __CLASS__, 'on_sync' ), 12, 1 );
	}

	public static function on_sync( string $connector = '' ): void {
		if ( ! in_array( $connector, array( 'aws', 'plerion' ), true ) ) {
			return;
		}

		$moved = 0;

		if ( 'aws' === $connector ) {
			$moved += self::register_missing()['created'];
			$moved += self::retire_gone();
		}

		$moved += self::link_twins()['linked'];
		$moved += self::enrich();

		if ( $moved > 0 && class_exists( '\\VulnHub\\Core\\Coverage' ) ) {
			\VulnHub\Core\Coverage::recalculate();
		}
	}

	/**
	 * Give every running instance with no record one of its own.
	 *
	 * An EC2 instance is a server Tenable can scan and Defender can protect,
	 * so it belongs in the inventory and its filters -- or its gap cannot be
	 * listed, only mentioned. Named by instance id, because the Name tag is
	 * not unique (an Elastic Beanstalk environment names every instance the
	 * same), and a shared name would fold two machines into one row; the tag
	 * goes to `business_service`, where for these it is exactly that.
	 *
	 * @return array{created:int}
	 */
	public static function register_missing(): array {
		global $wpdb;

		$out     = array( 'created' => 0 );
		$running = self::ids( 'ec2' );

		if ( ! $running ) {
			return $out;
		}

		$known = array_flip(
			array_map(
				'strval',
				(array) $wpdb->get_col( $wpdb->prepare( 'SELECT aws_instance_id FROM ' . vh_table( 'assets' ) . ' WHERE aws_instance_id IN (' . implode( ',', array_fill( 0, count( $running ), '%s' ) ) . ')', ...$running ) ) // phpcs:ignore
			)
		);
		$all   = self::instances();

		foreach ( $running as $iid ) {
			if ( isset( $known[ $iid ] ) || 'aws' !== ( $all[ $iid ]['from'] ?? '' ) ) {
				continue;
			}

			$i      = $all[ $iid ];
			$result = \VulnHub\Core\Repo::upsert_asset(
				array(
					'primary_source'   => 'aws',
					'source'           => 'aws',
					'hostname'         => $iid,
					'aws_instance_id'  => $iid,
					'asset_type'       => 'server',
					'cloud_provider'   => 'AWS',
					'cloud_account_id' => $i['account'],
					'ipv4'             => $i['ip'],
					'business_service' => mb_substr( $i['name'], 0, 191 ),
					'last_seen'        => vh_now(),
				)
			);

			$out['created'] += ! empty( $result['created'] ) ? 1 : 0;
		}

		return $out;
	}

	/**
	 * Tell each EC2 record what the capture knows about its instance.
	 *
	 * A record the posture inventory made is often an instance id and nothing
	 * else. The capture holds the Name tag, the private address, the region,
	 * the platform and whether it is running, and all of it belongs on the
	 * record:
	 *
	 * - **Name.** The tag becomes the hostname when it is unique among
	 *   instances and no other asset already carries that name -- a shared
	 *   name would let a later import fold two machines into one row. An
	 *   FQDN-shaped tag gives hostname and fqdn. Otherwise the id stays, and
	 *   the tag goes to `business_service` either way.
	 * - **Running or not.** A stopped instance is `spare` -- it exists, it is
	 *   not in service -- so it leaves the reporting scope and the agent-gap
	 *   lists; a running one is `in_service`. Only on records AWS or the
	 *   posture inventory made: a lifecycle the CMDB set is the CMDB's.
	 * - **Appliances.** Instances in the inline firewall's account are
	 *   appliances, not servers.
	 * - Address, region and OS fill in where empty, and never overwrite.
	 *
	 * @return int Records changed.
	 */
	public static function enrich(): int {
		global $wpdb;

		$a    = vh_table( 'assets' );
		$all  = self::instances();
		$tags = array_count_values( array_filter( array_map( static fn( array $i ): string => strtolower( trim( $i['name'] ) ), $all ) ) );
		$n    = 0;

		if ( ! $all ) {
			return 0;
		}

		$ids  = array_keys( $all );
		$rows = (array) $wpdb->get_results( // phpcs:ignore
			$wpdb->prepare(
				"SELECT id, aws_instance_id, hostname, fqdn, ipv4, operating_system, cloud_region, business_service, asset_type, lifecycle_status, primary_source
				 FROM {$a} WHERE lifecycle_status <> 'retired' AND aws_instance_id IN (" . implode( ',', array_fill( 0, count( $ids ), '%s' ) ) . ')',
				...$ids
			),
			ARRAY_A
		);

		foreach ( $rows as $r ) {
			$i     = $all[ (string) $r['aws_instance_id'] ];
			$ours  = in_array( (string) $r['primary_source'], array( 'aws', 'plerion' ), true );
			$tag   = trim( $i['name'] );
			$set   = array();

			if ( '' !== $tag && '' === (string) $r['business_service'] ) {
				$set['business_service'] = mb_substr( $tag, 0, 191 );
			}

			if ( $ours && '' !== $tag && preg_match( '/^i-[0-9a-f]{8,17}$/', (string) $r['hostname'] ) && 1 === ( $tags[ strtolower( $tag ) ] ?? 0 ) ) {
				$fqdn = 1 === preg_match( '/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i', $tag ) ? strtolower( $tag ) : '';
				$host = strtolower( '' !== $fqdn ? (string) strtok( $fqdn, '.' ) : preg_replace( '/\s+/', '-', $tag ) );
				$host = mb_substr( $host, 0, 191 );
				$used = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$a} WHERE id <> %d AND LOWER(hostname) = %s", (int) $r['id'], $host ) ); // phpcs:ignore

				if ( 0 === $used ) {
					$set['hostname'] = $host;

					if ( '' !== $fqdn && '' === (string) $r['fqdn'] ) {
						$set['fqdn'] = $fqdn;
					}
				}
			}

			if ( '' === (string) $r['ipv4'] && '' !== $i['ip'] ) {
				$set['ipv4'] = $i['ip'];
			}
			if ( '' === (string) $r['cloud_region'] && '' !== $i['region'] ) {
				$set['cloud_region'] = $i['region'];
			}
			if ( '' === (string) $r['operating_system'] && '' !== $i['platform'] ) {
				$set['operating_system'] = str_starts_with( $i['platform'], 'Linux/UNIX' ) ? 'Linux' : $i['platform'];
			}

			if ( '' !== ( $i['appliance'] ?? '' ) && in_array( (string) $r['asset_type'], array( 'server', 'unknown', '' ), true ) ) {
				$set['asset_type'] = 'appliance';
			}

			if ( $ours ) {
				$want = 'running' === $i['state'] ? 'in_service' : 'spare';

				if ( in_array( (string) $r['lifecycle_status'], array( 'unknown', 'in_service', 'spare', '' ), true ) && $want !== (string) $r['lifecycle_status'] ) {
					$set['lifecycle_status'] = $want;
				}
			}

			if ( $set ) {
				$set['updated_at'] = vh_now();
				$wpdb->update( $a, $set, array( 'id' => (int) $r['id'] ) );
				++$n;
			}
		}

		return $n;
	}

	/**
	 * Retire the records this capture made for instances that are gone --
	 * only in accounts the capture read, so a partial read never retires
	 * anything it simply did not look at.
	 */
	public static function retire_gone(): int {
		global $wpdb;

		$read = VulnHub_AWS_Network::accounts();
		$live = array_keys( self::instances() );

		if ( ! $read ) {
			return 0;
		}

		$rows = (array) $wpdb->get_results( // phpcs:ignore
			$wpdb->prepare(
				'SELECT id, aws_instance_id FROM ' . vh_table( 'assets' ) . " WHERE primary_source = 'aws' AND lifecycle_status <> 'retired'
				 AND cloud_account_id IN (" . implode( ',', array_fill( 0, count( $read ), '%s' ) ) . ')',
				...$read
			),
			ARRAY_A
		);
		$live = array_flip( $live );
		$n    = 0;

		foreach ( $rows as $r ) {
			if ( ! isset( $live[ (string) $r['aws_instance_id'] ] ) ) {
				$wpdb->update( vh_table( 'assets' ), array( 'lifecycle_status' => 'retired', 'updated_at' => vh_now() ), array( 'id' => (int) $r['id'] ) );
				++$n;
			}
		}

		return $n;
	}

	/* =================================================================
	 * The instances
	 * ============================================================== */

	/**
	 * Every EC2 instance we know of: id => {account, name, ip, state, from}.
	 *
	 * @return array<string,array<string,string>>
	 */
	public static function instances(): array {
		global $wpdb;

		$nt  = VulnHub_AWS_Network::nodes_table();
		$out = array();

		foreach ( (array) $wpdb->get_results( "SELECT resource_id, account_id, region, name, private_ip, state, detail FROM {$nt} WHERE node_type = 'instance' AND source = 'aws'", ARRAY_A ) as $r ) { // phpcs:ignore
			$d = json_decode( (string) $r['detail'], true );
			$d = is_array( $d ) ? $d : array();

			$out[ (string) $r['resource_id'] ] = array(
				'account'  => (string) $r['account_id'],
				'region'   => (string) $r['region'],
				'name'     => (string) $r['name'],
				'ip'       => (string) $r['private_ip'],
				'state'    => '' !== (string) $r['state'] ? (string) $r['state'] : 'running',
				'platform' => (string) ( $d['platform'] ?? '' ),
				'size'     => (string) ( $d['instance_type'] ?? '' ),
				'from'     => 'aws',
			);
		}

		$appliance = array_flip( VulnHub_AWS_Network::appliance_accounts() );

		/*
		 * Accounts the sign-in cannot read: the posture inventory's list.
		 * It lists what exists, not whether it is running, so these count as
		 * running -- the direction that shows a gap rather than hides one.
		 */
		$captured = array_flip( VulnHub_AWS_Network::accounts() );
		$cr       = $wpdb->prefix . 'vulnhub_cloud_resources';

		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $cr ) ) === $cr ) {
			foreach ( (array) $wpdb->get_results( "SELECT account_id, resource_id, name FROM {$cr} WHERE kind = 'ec2'", ARRAY_A ) as $r ) { // phpcs:ignore
				if ( isset( $captured[ (string) $r['account_id'] ] ) || ! preg_match( '/(i-[0-9a-f]{8,17})/', (string) $r['resource_id'], $m ) || isset( $out[ $m[1] ] ) ) {
					continue;
				}

				$out[ $m[1] ] = array(
					'account'  => (string) $r['account_id'],
					'region'   => '',
					'name'     => (string) $r['name'],
					'ip'       => '',
					'state'    => 'running',
					'platform' => '',
					'size'     => '',
					'from'     => 'plerion',
				);
			}
		}

		// The inline firewall's account: vendor appliances, no agent.
		foreach ( $out as $id => $i ) {
			$out[ $id ]['appliance'] = isset( $appliance[ $i['account'] ] ) ? '1' : '';
		}

		return $out;
	}

	/**
	 * Instance ids in one scope.
	 *
	 * @return string[]
	 */
	public static function ids( string $scope ): array {
		if ( null === self::$ids ) {
			self::$ids = array( 'ec2' => array(), 'ec2_stopped' => array(), 'appliance' => array() );

			foreach ( self::instances() as $id => $i ) {
				$bucket = '' !== $i['appliance'] ? 'appliance' : ( 'running' === $i['state'] ? 'ec2' : 'ec2_stopped' );

				self::$ids[ $bucket ][] = (string) $id;
			}
		}

		return self::$ids[ $scope ] ?? array();
	}

	/**
	 * The `aws` argument of `Repo::assets()`: assets that are EC2 instances
	 * in this scope, matched on the instance id.
	 *
	 * @param array<string,mixed> $ext  Clauses so far.
	 * @param array<string,mixed> $args Query arguments.
	 * @return array<string,mixed>
	 */
	public static function assets_query( array $ext, array $args ): array {
		$scope = (string) ( $args['aws'] ?? '' );

		if ( ! in_array( $scope, self::SCOPES, true ) ) {
			return $ext;
		}

		$ids = self::ids( $scope );

		if ( ! $ids ) {
			$ext['where'][] = '1=0';

			return $ext;
		}

		$ext['where'][] = 'aws_instance_id IN (' . implode( ',', array_fill( 0, count( $ids ), '%s' ) ) . ')';
		$ext['params']  = array_merge( (array) ( $ext['params'] ?? array() ), $ids );

		return $ext;
	}

	/* =================================================================
	 * Linking twins
	 * ============================================================== */

	/**
	 * Join an instance's record to the one another feed already holds for the
	 * same machine, when -- and only when -- the private address and the name
	 * both agree and exactly one row does.
	 *
	 * The instance's own row (the posture inventory's, named by id) is folded
	 * into the twin with `Duplicates::merge()`, which carries the instance id
	 * and cloud fields across and retires the id-named row; with no row of its
	 * own, the twin simply takes the instance id.
	 *
	 * @return array{linked:int,ambiguous:int,dry_run:bool,pairs:array<int,array<string,mixed>>}
	 */
	public static function link_twins( bool $dry_run = false ): array {
		global $wpdb;

		$a   = vh_table( 'assets' );
		$out = array( 'linked' => 0, 'ambiguous' => 0, 'dry_run' => $dry_run, 'pairs' => array() );

		foreach ( self::instances() as $iid => $i ) {
			if ( '' === $i['ip'] || '' === $i['name'] ) {
				continue;
			}

			$tag   = strtolower( trim( $i['name'] ) );
			$own   = $wpdb->get_row( $wpdb->prepare( "SELECT id, hostname, primary_source FROM {$a} WHERE aws_instance_id = %s AND lifecycle_status <> 'retired' ORDER BY id LIMIT 1", $iid ), ARRAY_A ); // phpcs:ignore

			// Already on a named record: nothing to join.
			if ( $own && ! preg_match( '/^i-[0-9a-f]{8,17}$/', (string) $own['hostname'] ) ) {
				continue;
			}

			$twins = (array) $wpdb->get_results( // phpcs:ignore
				$wpdb->prepare(
					"SELECT id, hostname FROM {$a}
					 WHERE id <> %d AND ( aws_instance_id = '' OR aws_instance_id IS NULL )
					   AND lifecycle_status <> 'retired'
					   AND ( ipv4 = %s OR FIND_IN_SET( %s, REPLACE( REPLACE( ipv4s, ' ', '' ), ';', ',' ) ) > 0 )
					   AND hostname <> ''",
					$own ? (int) $own['id'] : 0,
					$i['ip'],
					$i['ip']
				),
				ARRAY_A
			);

			/*
			 * The name half: the Name tag *is* the hostname, or is the
			 * hostname followed by a separator -- `ad01.corp.example`,
			 * `appsrv01-p1aa`, `appsrv01_2019-upgrade`. The address has
			 * already agreed; this only confirms it is the same machine and
			 * not a reused address.
			 */
			$twins = array_values(
				array_filter(
					$twins,
					static function ( array $t ) use ( $tag ): bool {
						$h = strtolower( trim( (string) $t['hostname'] ) );

						return $h === $tag || ( str_starts_with( $tag, $h ) && in_array( substr( $tag, strlen( $h ), 1 ), array( '-', '_', '.' ), true ) );
					}
				)
			);

			if ( 1 !== count( $twins ) ) {
				$out['ambiguous'] += count( $twins ) > 1 ? 1 : 0;
				continue;
			}

			$twin = (int) $twins[0]['id'];
			$out['pairs'][] = array( 'instance' => $iid, 'name' => $i['name'], 'twin' => $twin, 'own' => $own ? (int) $own['id'] : 0 );

			if ( $dry_run ) {
				continue;
			}

			if ( $own ) {
				$merged = \VulnHub\Core\Duplicates::merge( (int) $own['id'], $twin, false );

				if ( empty( $merged['ok'] ) ) {
					continue;
				}

				// The id now lives on the twin. Left on the retired row too, the
				// next posture sync could match that row instead -- which is how
				// a merge comes undone.
				$wpdb->update( $a, array( 'aws_instance_id' => '' ), array( 'id' => (int) $own['id'] ) );
			} else {
				$wpdb->update(
					$a,
					array(
						'aws_instance_id'  => $iid,
						'cloud_provider'   => 'AWS',
						'cloud_account_id' => $i['account'],
						'updated_at'       => vh_now(),
					),
					array( 'id' => $twin )
				);
			}

			++$out['linked'];
		}

		if ( ! $dry_run && $out['linked'] > 0 ) {
			vulnhub()->logger->audit( 'aws.twins_linked', sprintf( 'Linked %d EC2 instances to the records other feeds hold for them', $out['linked'] ), 'connector', 'aws', $out['pairs'] );
		}

		return $out;
	}

	/* =================================================================
	 * The widget
	 * ============================================================== */

	/**
	 * @param array<string,array<string,mixed>> $w Widget registry.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register( array $w ): array {
		$w[ self::WIDGET ] = array(
			'label'   => __( 'AWS servers: Tenable and Defender coverage', 'vulnhub' ),
			'summary' => __( 'Every EC2 instance running in AWS, whether Tenable scans it and whether Defender protects it — and what in AWS is not Tenable\'s to scan.', 'vulnhub' ),
			'group'   => 'coverage',
			'width'   => 12,
			'render'  => array( __CLASS__, 'render' ),
			'data'    => array( __CLASS__, 'data' ),
		);

		return $w;
	}

	/**
	 * Beside the other coverage widgets. A saved board picks it up too: the
	 * dashboard adds default widgets a user has not seen yet.
	 *
	 * @param array<int,array{id:string,width:int}> $layout Default layout.
	 * @return array<int,array{id:string,width:int}>
	 */
	public static function place( array $layout ): array {
		if ( in_array( self::WIDGET, array_column( $layout, 'id' ), true ) ) {
			return $layout;
		}

		$out    = array();
		$placed = false;

		foreach ( $layout as $entry ) {
			$out[] = $entry;

			if ( ! $placed && in_array( (string) ( $entry['id'] ?? '' ), array( 'coverage_by_type', 'coverage_summary' ), true ) ) {
				$out[]  = array( 'id' => self::WIDGET, 'width' => 12 );
				$placed = true;
			}
		}

		if ( ! $placed ) {
			$out[] = array( 'id' => self::WIDGET, 'width' => 12 );
		}

		return $out;
	}

	private static function count( array $args ): int {
		return (int) ( \VulnHub\Core\Repo::assets( $args + array( 'limit' => 1 ) )['total'] ?? 0 );
	}

	/**
	 * @return array<string,mixed>
	 */
	public static function data(): array {
		global $wpdb;

		$base  = array( 'aws' => 'ec2' );
		$cells = array();

		foreach ( array( 'ok', 'gap' ) as $t ) {
			foreach ( array( 'ok', 'gap' ) as $d ) {
				$cells[ $t . '_' . $d ] = self::count( $base + array( 'coverage' => $t, 'defender' => $d ) );
			}
		}

		$running = self::ids( 'ec2' );
		$known   = $running
			? array_map( 'strval', (array) $wpdb->get_col( $wpdb->prepare( 'SELECT DISTINCT aws_instance_id FROM ' . vh_table( 'assets' ) . ' WHERE aws_instance_id IN (' . implode( ',', array_fill( 0, count( $running ), '%s' ) ) . ')', ...$running ) ) ) // phpcs:ignore
			: array();
		$all     = self::instances();
		$missing = array();

		foreach ( array_diff( $running, $known ) as $iid ) {
			$missing[] = array( 'id' => $iid ) + $all[ $iid ];
		}

		// The gap list: running, Tenable does not hold it.
		$gaps = \VulnHub\Core\Repo::assets( $base + array( 'coverage' => 'gap', 'limit' => 50, 'orderby' => 'hostname' ) );
		$open = class_exists( 'VulnHub_AWS_Exposure' ) ? array_flip( array_map( 'intval', array_keys( VulnHub_AWS_Exposure::all()['paths'] ) ) ) : array();
		$rows = array();

		foreach ( (array) ( $gaps['rows'] ?? array() ) as $r ) {
			$iid    = (string) $r['aws_instance_id'];
			$rows[] = array(
				'id'       => (int) $r['id'],
				'host'     => (string) $r['hostname'],
				'tag'      => (string) ( $all[ $iid ]['name'] ?? '' ),
				'account'  => (string) $r['cloud_account_id'],
				'os'       => (string) $r['operating_system'],
				'defender' => (string) $r['defender_coverage_state'],
				'open'     => isset( $open[ (int) $r['id'] ] ),
			);
		}

		usort( $rows, static fn( array $a, array $b ): int => array( ! $a['open'], 'onboarded' === $a['defender'], $a['tag'] ) <=> array( ! $b['open'], 'onboarded' === $b['defender'], $b['tag'] ) );

		return array(
			'running'     => count( $running ),
			'stopped'     => count( self::ids( 'ec2_stopped' ) ),
			'appliances'  => count( self::ids( 'appliance' ) ),
			'in_register' => self::count( $base ),
			'cells'       => $cells,
			'tenable_gap' => self::count( $base + array( 'coverage' => 'gap' ) ),
			'defender_gap' => self::count( $base + array( 'defender' => 'gap' ) ),
			'gaps'        => $rows,
			'missing'     => $missing,
			'services'    => self::services(),
			'labels'      => self::labels(),
			'captured_at' => (string) $wpdb->get_var( 'SELECT MAX(last_seen) FROM ' . VulnHub_AWS_Network::nodes_table() . " WHERE source = 'aws'" ), // phpcs:ignore
		);
	}

	/**
	 * What runs in AWS that Tenable does not scan, by kind.
	 *
	 * @return array<int,array{kind:string,label:string,n:int,why:string}>
	 */
	private static function services(): array {
		global $wpdb;

		$cr  = $wpdb->prefix . 'vulnhub_cloud_resources';
		$out = array();
		$n   = array();

		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $cr ) ) === $cr ) {
			foreach ( (array) $wpdb->get_results( "SELECT kind, COUNT(*) n FROM {$cr} GROUP BY kind", ARRAY_A ) as $r ) { // phpcs:ignore
				$n[ (string) $r['kind'] ] = (int) $r['n'];
			}
		}

		$def = array(
			'lambda'   => array( __( 'Lambda functions', 'vulnhub' ), __( 'code on AWS\'s runtime; no OS of ours', 'vulnhub' ) ),
			'ecs'      => array( __( 'ECS services', 'vulnhub' ), __( 'containers; the image is scanned by a container scanner, not an agent', 'vulnhub' ) ),
			'rds'      => array( __( 'RDS databases', 'vulnhub' ), __( 'AWS patches the engine host', 'vulnhub' ) ),
			'dynamodb' => array( __( 'DynamoDB tables', 'vulnhub' ), __( 'a managed service', 'vulnhub' ) ),
			's3'       => array( __( 'S3 buckets', 'vulnhub' ), __( 'storage; its risk is configuration', 'vulnhub' ) ),
			'alb'      => array( __( 'Load balancers', 'vulnhub' ), __( 'managed; what is behind them is what gets scanned', 'vulnhub' ) ),
		);

		foreach ( $def as $kind => [ $label, $why ] ) {
			if ( ! empty( $n[ $kind ] ) ) {
				$out[] = array( 'kind' => $kind, 'label' => $label, 'n' => $n[ $kind ], 'why' => $why );
			}
		}

		return $out;
	}

	/** @return array<string,string> Account id => label. */
	private static function labels(): array {
		global $wpdb;

		$out = array();

		foreach ( (array) $wpdb->get_results( 'SELECT account_id, label FROM ' . $wpdb->prefix . 'vulnhub_aws_accounts', ARRAY_A ) as $r ) { // phpcs:ignore
			if ( '' !== (string) $r['label'] ) {
				$out[ (string) $r['account_id'] ] = (string) $r['label'];
			}
		}

		return $out;
	}

	private static function url( array $args ): string {
		return class_exists( 'VulnHub_Dash_Portal' ) ? VulnHub_Dash_Portal::portal_url( 'assets', $args ) : '';
	}

	public static function render(): void {
		$d = self::data();

		if ( 0 === $d['running'] ) {
			echo '<p class="vh-chart-empty">' . esc_html__( 'No EC2 instances yet. Sign in to AWS and capture the network, or connect the posture inventory.', 'vulnhub' ) . '</p>';

			return;
		}

		$c     = $d['cells'];
		$base  = array( 'aws' => 'ec2' );
		$pct   = static fn( int $n ): string => number_format_i18n( 100 * $n / max( 1, $d['in_register'] ) ) . '%';
		$other = $d['in_register'] - array_sum( $c );

		echo '<div class="vh-awscov">';

		// Headline tiles.
		echo '<div class="vh-tiles vh-awscov__tiles">';
		$meta = sprintf( /* translators: %s: stopped count. */ __( '%s stopped, not counted', 'vulnhub' ), number_format_i18n( $d['stopped'] ) )
			. ( $d['appliances'] ? ' · ' . sprintf( /* translators: %s: count. */ _n( '%s firewall appliance set aside', '%s firewall appliances set aside', $d['appliances'], 'vulnhub' ), number_format_i18n( $d['appliances'] ) ) : '' );
		echo VulnHub_Dash_Charts::stat_tile( array( 'label' => __( 'EC2 instances running', 'vulnhub' ), 'value' => $d['running'], 'tone' => 'neutral', 'meta' => $meta, 'href' => self::url( $base ) ) ); // phpcs:ignore
		echo VulnHub_Dash_Charts::stat_tile( array( 'label' => __( 'Scanned by Tenable', 'vulnhub' ), 'value' => $d['in_register'] - $d['tenable_gap'], 'tone' => $d['tenable_gap'] ? 'warning' : 'good', 'meta' => sprintf( /* translators: %s: gap count. */ __( '%s not scanned', 'vulnhub' ), number_format_i18n( $d['tenable_gap'] ) ), 'href' => self::url( $base + array( 'coverage' => 'ok' ) ) ) ); // phpcs:ignore
		echo VulnHub_Dash_Charts::stat_tile( array( 'label' => __( 'Protected by Defender', 'vulnhub' ), 'value' => $d['in_register'] - $d['defender_gap'], 'tone' => $d['defender_gap'] ? 'warning' : 'good', 'meta' => sprintf( /* translators: %s: gap count. */ __( '%s without a sensor', 'vulnhub' ), number_format_i18n( $d['defender_gap'] ) ), 'href' => self::url( $base + array( 'defender' => 'ok' ) ) ) ); // phpcs:ignore
		echo VulnHub_Dash_Charts::stat_tile( array( 'label' => __( 'Neither', 'vulnhub' ), 'value' => $c['gap_gap'], 'tone' => $c['gap_gap'] ? 'critical' : 'good', 'meta' => __( 'nobody is looking at these', 'vulnhub' ), 'href' => self::url( $base + array( 'coverage' => 'gap', 'defender' => 'gap' ) ) ) ); // phpcs:ignore
		echo '</div>';

		// The two-by-two.
		$cell = static function ( string $key, string $label, string $tone, array $args ) use ( $c, $pct ): string {
			return sprintf(
				'<a class="vh-awscov__cell vh-awscov__cell--%1$s" href="%2$s"><b>%3$s</b><span>%4$s</span><i>%5$s</i></a>',
				esc_attr( $tone ),
				esc_url( self::url( array( 'aws' => 'ec2' ) + $args ) ),
				esc_html( number_format_i18n( $c[ $key ] ) ),
				esc_html( $label ),
				esc_html( $pct( $c[ $key ] ) )
			);
		};

		echo '<div class="vh-awscov__grid" role="group" aria-label="' . esc_attr__( 'Tenable against Defender', 'vulnhub' ) . '">';
		echo '<span class="vh-awscov__axis vh-awscov__axis--top">' . esc_html__( 'Defender sensor', 'vulnhub' ) . '</span>';
		echo '<span class="vh-awscov__axis vh-awscov__axis--side">' . esc_html__( 'Tenable', 'vulnhub' ) . '</span>';
		echo '<span class="vh-awscov__h">' . esc_html__( 'yes', 'vulnhub' ) . '</span><span class="vh-awscov__h">' . esc_html__( 'no', 'vulnhub' ) . '</span>';
		echo '<span class="vh-awscov__r">' . esc_html__( 'scanned', 'vulnhub' ) . '</span>';
		echo $cell( 'ok_ok', __( 'both', 'vulnhub' ), 'good', array( 'coverage' => 'ok', 'defender' => 'ok' ) ); // phpcs:ignore
		echo $cell( 'ok_gap', __( 'Tenable only', 'vulnhub' ), 'warn', array( 'coverage' => 'ok', 'defender' => 'gap' ) ); // phpcs:ignore
		echo '<span class="vh-awscov__r">' . esc_html__( 'not scanned', 'vulnhub' ) . '</span>';
		echo $cell( 'gap_ok', __( 'Defender only', 'vulnhub' ), 'warn', array( 'coverage' => 'gap', 'defender' => 'ok' ) ); // phpcs:ignore
		echo $cell( 'gap_gap', __( 'neither', 'vulnhub' ), 'bad', array( 'coverage' => 'gap', 'defender' => 'gap' ) ); // phpcs:ignore
		echo '</div>';

		if ( $other > 0 ) {
			printf( '<p class="vh-sub vh-awscov__other">%s</p>', esc_html( sprintf( /* translators: %s: count. */ _n( '%s more is out of scope for one of the two (retired, or a device type the product does not cover).', '%s more are out of scope for one of the two (retired, or a device type the product does not cover).', $other, 'vulnhub' ), number_format_i18n( $other ) ) ) );
		}

		// The gap list.
		if ( $d['gaps'] ) {
			echo '<h4 class="vh-awscov__h4">' . esc_html__( 'Running, and Tenable is not scanning them', 'vulnhub' ) . '</h4>';
			echo '<ul class="vh-awscov__list">';

			foreach ( array_slice( $d['gaps'], 0, 12 ) as $g ) {
				$acct = $d['labels'][ $g['account'] ] ?? $g['account'];
				printf(
					'<li><a href="%1$s">%2$s</a>%3$s<span class="vh-awscov__os">%4$s</span><span class="vh-awscov__acct">%5$s</span>%6$s%7$s</li>',
					esc_url( self::url( array( 'asset' => $g['id'] ) ) ),
					esc_html( '' !== $g['tag'] ? $g['tag'] : $g['host'] ),
					'' !== $g['tag'] && $g['tag'] !== $g['host'] ? '<span class="vh-awscov__id">' . esc_html( $g['host'] ) . '</span>' : '',
					esc_html( '' !== $g['os'] ? $g['os'] : __( 'OS unknown', 'vulnhub' ) ),
					esc_html( $acct ),
					'onboarded' === $g['defender'] ? '<span class="vh-awscov__chip vh-awscov__chip--ok">' . esc_html__( 'Defender', 'vulnhub' ) . '</span>' : '<span class="vh-awscov__chip vh-awscov__chip--bad">' . esc_html__( 'no Defender', 'vulnhub' ) . '</span>',
					$g['open'] ? '<span class="vh-awscov__chip vh-awscov__chip--open" title="' . esc_attr__( 'The internet can open a port on it (see How an attacker gets in).', 'vulnhub' ) . '">' . esc_html__( 'open from outside', 'vulnhub' ) . '</span>' : ''
				);
			}

			echo '</ul>';

			if ( count( $d['gaps'] ) > 12 ) {
				printf( '<p class="vh-sub"><a href="%1$s">%2$s</a></p>', esc_url( self::url( $base + array( 'coverage' => 'gap' ) ) ), esc_html( sprintf( /* translators: %s: count. */ __( 'All %s →', 'vulnhub' ), number_format_i18n( $d['tenable_gap'] ) ) ) );
			}
		}

		if ( $d['missing'] ) {
			printf(
				'<p class="vh-awscov__missing">%1$s %2$s</p>',
				esc_html( sprintf( /* translators: %s: count. */ _n( '%s running instance has no asset record at all, so no coverage can be measured for it:', '%s running instances have no asset record at all, so no coverage can be measured for them:', count( $d['missing'] ), 'vulnhub' ), number_format_i18n( count( $d['missing'] ) ) ) ),
				esc_html( implode( ', ', array_map( static fn( array $m ): string => ( '' !== $m['name'] ? $m['name'] . ' ' : '' ) . '(' . $m['id'] . ')', array_slice( $d['missing'], 0, 8 ) ) ) )
			);
		}

		// Not Tenable's to scan.
		if ( $d['services'] ) {
			echo '<div class="vh-awscov__svc">';
			printf( '<h4 class="vh-awscov__h4">%s</h4>', esc_html__( 'In AWS, and not Tenable\'s to scan', 'vulnhub' ) );
			printf( '<p class="vh-sub">%s</p>', esc_html__( 'Tenable and Defender need an operating system we run. These have none of ours: their risk is configuration, which the cloud posture scan covers.', 'vulnhub' ) );
			echo '<ul class="vh-awscov__svclist">';

			foreach ( $d['services'] as $s ) {
				printf( '<li title="%1$s"><b>%2$s</b> %3$s</li>', esc_attr( $s['why'] ), esc_html( number_format_i18n( $s['n'] ) ), esc_html( $s['label'] ) );
			}

			echo '</ul></div>';
		}

		if ( '' !== $d['captured_at'] ) {
			printf( '<p class="vh-sub vh-awscov__when">%s</p>', esc_html( sprintf( /* translators: %s: time ago. */ __( 'Instances from the AWS network capture, read %s, plus the posture inventory for accounts the sign-in cannot reach. AppStream is covered through its fleet record.', 'vulnhub' ), vh_ago( $d['captured_at'] ) ) ) );
		}

		echo '</div>';
	}
}
