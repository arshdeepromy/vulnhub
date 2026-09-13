<?php
/**
 * Deriving what the internet can actually reach.
 *
 * Every link in the chain has to hold, and the reason to insist on that is
 * that each one on its own produces a confident wrong answer:
 *
 *   a security group open to 0.0.0.0/0   -- routine on instances in private
 *                                           subnets nothing can route to
 *   a public IP on the interface         -- means nothing if no rule admits
 *                                           traffic
 *   a route to an internet gateway       -- a property of the subnet, not of
 *                                           the machine
 *
 * So an instance is called reachable only when a security group admits the
 * internet AND the subnet routes to an internet gateway AND there is an
 * address to arrive on -- or when it sits behind an internet-facing load
 * balancer, which reaches instances that have no public IP at all and is
 * invisible to every other signal this app has.
 *
 * What it deliberately does not model: network ACLs that deny narrower than
 * the security group allows, and paths in through a peered VPC or Transit
 * Gateway. Both make this over-report rather than under-report, which is the
 * safer direction, and both are exactly what Amazon Inspector evaluates
 * properly -- which is why the connector prefers Inspector when it is on.
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

use VulnHub\Core\Connector;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Walks the EC2 exposure chain, region by region.
 */
final class VulnHub_AWS_Reachability {

	private VulnHub_AWS_Client $client;
	private ?Connector $connector;

	public function __construct( VulnHub_AWS_Client $client, ?Connector $connector = null ) {
		$this->client    = $client;
		$this->connector = $connector;
	}

	public static function table(): string {
		global $wpdb;

		return $wpdb->prefix . 'vulnhub_aws_exposure';
	}

	/** Create the table. Called on plugin load, like the other installers. */
	public static function install(): void {
		global $wpdb;

		$t       = self::table();
		$charset = $wpdb->get_charset_collate();

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		dbDelta(
			"CREATE TABLE {$t} (
				instance_id varchar(64) NOT NULL,
				region varchar(32) NOT NULL,
				account_id varchar(24) NOT NULL DEFAULT '',
				protocol varchar(8) NOT NULL DEFAULT 'tcp',
				port_from int(10) unsigned NOT NULL DEFAULT 0,
				port_to int(10) unsigned NOT NULL DEFAULT 0,
				source_cidr varchar(64) NOT NULL DEFAULT '',
				via varchar(16) NOT NULL DEFAULT 'direct',
				detail varchar(191) NOT NULL DEFAULT '',
				updated_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				PRIMARY KEY  (instance_id,protocol,port_from,port_to,via),
				KEY region (region),
				KEY via (via)
			) {$charset};"
		);
	}

	/**
	 * Read one region and record what the internet can reach.
	 *
	 * @return array{instances:int,reachable:int,calls:int}
	 */
	public function region( string $region ): array {
		$before = $this->client->calls();

		$instances = $this->instances( $region );

		if ( ! $instances ) {
			return array(
				'instances' => 0,
				'reachable' => 0,
				'calls'     => $this->client->calls() - $before,
			);
		}

		$groups = $this->security_groups( $region );
		$public = $this->public_subnets( $region );

		global $wpdb;

		$now  = vh_now();
		$rows = array();

		foreach ( $instances as $id => $inst ) {
			// No address to arrive on, and no public subnet, means no direct
			// path however open the security group is.
			$has_address = '' !== $inst['public_ip'];
			$routable    = isset( $public[ $inst['subnet'] ] );

			if ( ! $has_address || ! $routable ) {
				continue;
			}

			foreach ( $inst['groups'] as $gid ) {
				foreach ( (array) ( $groups[ $gid ] ?? array() ) as $rule ) {
					$rows[] = array(
						$id,
						$region,
						$inst['account'],
						$rule['protocol'],
						$rule['from'],
						$rule['to'],
						$rule['cidr'],
						'direct',
						$gid,
						$now,
					);
				}
			}
		}

		// Instances published only through a load balancer have no public IP
		// of their own; without this pass they read as unreachable.
		foreach ( $this->load_balanced( $region, $instances ) as $hit ) {
			$rows[] = array(
				$hit['instance'],
				$region,
				(string) ( $instances[ $hit['instance'] ]['account'] ?? '' ),
				$hit['protocol'],
				$hit['port'],
				$hit['port'],
				'0.0.0.0/0',
				'elb',
				$hit['lb'],
				$now,
			);
		}

		$this->store( $region, $rows );

		$reachable = count( array_unique( array_column( $rows, 0 ) ) );

		return array(
			'instances' => count( $instances ),
			'reachable' => $reachable,
			'calls'     => $this->client->calls() - $before,
		);
	}

	/**
	 * Every instance in the region, paginated.
	 *
	 * @return array<string,array<string,mixed>>
	 */
	private function instances( string $region ): array {
		$out   = array();
		$token = '';

		do {
			$params = array(
				'Action'      => 'DescribeInstances',
				'Version'     => '2016-11-15',
				'MaxResults'  => '200',
			);

			if ( '' !== $token ) {
				$params['NextToken'] = $token;
			}

			$res = $this->client->query( 'ec2', $region, $params );

			if ( ! $res['ok'] ) {
				$this->log( sprintf( '%s: DescribeInstances failed: %s', $region, $res['error'] ) );

				return $out;
			}

			$xml = $res['xml'];

			foreach ( $xml->reservationSet->item ?? array() as $reservation ) { // phpcs:ignore
				$account = (string) ( $reservation->ownerId ?? '' ); // phpcs:ignore

				foreach ( $reservation->instancesSet->item ?? array() as $inst ) { // phpcs:ignore
					$state = (string) ( $inst->instanceState->name ?? '' ); // phpcs:ignore

					// A stopped instance cannot be reached, and reporting one
					// as exposed sends somebody to investigate nothing.
					if ( 'running' !== $state ) {
						continue;
					}

					$id = (string) ( $inst->instanceId ?? '' ); // phpcs:ignore

					if ( '' === $id ) {
						continue;
					}

					$groups = array();

					foreach ( $inst->groupSet->item ?? array() as $g ) { // phpcs:ignore
						$groups[] = (string) ( $g->groupId ?? '' ); // phpcs:ignore
					}

					$out[ $id ] = array(
						'account'   => $account,
						'subnet'    => (string) ( $inst->subnetId ?? '' ), // phpcs:ignore
						'vpc'       => (string) ( $inst->vpcId ?? '' ), // phpcs:ignore
						'public_ip' => (string) ( $inst->ipAddress ?? '' ), // phpcs:ignore
						'private_ip' => (string) ( $inst->privateIpAddress ?? '' ), // phpcs:ignore
						'groups'    => array_values( array_filter( $groups ) ),
					);
				}
			}

			$token = (string) ( $xml->nextToken ?? '' ); // phpcs:ignore
		} while ( '' !== $token );

		return $out;
	}

	/**
	 * Ingress rules that admit the whole internet, keyed by security group.
	 *
	 * Only 0.0.0.0/0 and ::/0 count. A rule admitting one office range is not
	 * internet exposure, and folding the two together is how a dashboard ends
	 * up reporting a VPN-only management port as publicly reachable.
	 *
	 * @return array<string,array<int,array<string,mixed>>>
	 */
	private function security_groups( string $region ): array {
		$out   = array();
		$token = '';

		do {
			$params = array(
				'Action'     => 'DescribeSecurityGroups',
				'Version'    => '2016-11-15',
				'MaxResults' => '1000',
			);

			if ( '' !== $token ) {
				$params['NextToken'] = $token;
			}

			$res = $this->client->query( 'ec2', $region, $params );

			if ( ! $res['ok'] ) {
				$this->log( sprintf( '%s: DescribeSecurityGroups failed: %s', $region, $res['error'] ) );

				return $out;
			}

			$xml = $res['xml'];

			foreach ( $xml->securityGroupInfo->item ?? array() as $sg ) { // phpcs:ignore
				$gid = (string) ( $sg->groupId ?? '' ); // phpcs:ignore

				foreach ( $sg->ipPermissions->item ?? array() as $perm ) { // phpcs:ignore
					$proto = (string) ( $perm->ipProtocol ?? '' ); // phpcs:ignore

					// "-1" is every protocol and every port.
					$all  = '-1' === $proto;
					$from = $all ? 0 : (int) ( $perm->fromPort ?? 0 ); // phpcs:ignore
					$to   = $all ? 65535 : (int) ( $perm->toPort ?? 0 ); // phpcs:ignore

					$cidrs = array();

					foreach ( $perm->ipRanges->item ?? array() as $r ) { // phpcs:ignore
						$cidrs[] = (string) ( $r->cidrIp ?? '' ); // phpcs:ignore
					}

					foreach ( $perm->ipv6Ranges->item ?? array() as $r ) { // phpcs:ignore
						$cidrs[] = (string) ( $r->cidrIpv6 ?? '' ); // phpcs:ignore
					}

					foreach ( $cidrs as $cidr ) {
						if ( '0.0.0.0/0' !== $cidr && '::/0' !== $cidr ) {
							continue;
						}

						$out[ $gid ][] = array(
							'protocol' => $all ? 'any' : strtolower( $proto ),
							'from'     => $from,
							'to'       => $to,
							'cidr'     => $cidr,
						);
					}
				}
			}

			$token = (string) ( $xml->nextToken ?? '' ); // phpcs:ignore
		} while ( '' !== $token );

		return $out;
	}

	/**
	 * Subnets with a default route to an internet gateway.
	 *
	 * A subnet with no explicit association falls back to the VPC's main
	 * route table, which is why the main tables are tracked separately and
	 * applied to anything the explicit associations did not cover. Missing
	 * that fallback makes every instance in a default-configured VPC look
	 * unroutable.
	 *
	 * @return array<string,true>
	 */
	private function public_subnets( string $region ): array {
		$res = $this->client->query(
			'ec2',
			$region,
			array(
				'Action'  => 'DescribeRouteTables',
				'Version' => '2016-11-15',
			)
		);

		if ( ! $res['ok'] ) {
			$this->log( sprintf( '%s: DescribeRouteTables failed: %s', $region, $res['error'] ) );

			return array();
		}

		$public   = array();
		$main_vpc = array();
		$assigned = array();

		foreach ( $res['xml']->routeTableSet->item ?? array() as $rt ) { // phpcs:ignore
			$vpc     = (string) ( $rt->vpcId ?? '' ); // phpcs:ignore
			$to_igw  = false;
			$is_main = false;

			foreach ( $rt->routeSet->item ?? array() as $route ) { // phpcs:ignore
				$dest = (string) ( $route->destinationCidrBlock ?? '' ); // phpcs:ignore
				$gw   = (string) ( $route->gatewayId ?? '' ); // phpcs:ignore

				if ( ( '0.0.0.0/0' === $dest || '::/0' === $dest ) && str_starts_with( $gw, 'igw-' ) ) {
					$to_igw = true;
				}
			}

			foreach ( $rt->associationSet->item ?? array() as $assoc ) { // phpcs:ignore
				if ( 'true' === (string) ( $assoc->main ?? '' ) ) { // phpcs:ignore
					$is_main = true;
					continue;
				}

				$subnet = (string) ( $assoc->subnetId ?? '' ); // phpcs:ignore

				if ( '' === $subnet ) {
					continue;
				}

				$assigned[ $subnet ] = true;

				if ( $to_igw ) {
					$public[ $subnet ] = true;
				}
			}

			if ( $is_main && $to_igw && '' !== $vpc ) {
				$main_vpc[ $vpc ] = true;
			}
		}

		if ( ! $main_vpc ) {
			return $public;
		}

		// Anything not explicitly associated inherits its VPC's main table.
		$subnets = $this->client->query(
			'ec2',
			$region,
			array(
				'Action'  => 'DescribeSubnets',
				'Version' => '2016-11-15',
			)
		);

		if ( $subnets['ok'] ) {
			foreach ( $subnets['xml']->subnetSet->item ?? array() as $sn ) { // phpcs:ignore
				$id  = (string) ( $sn->subnetId ?? '' ); // phpcs:ignore
				$vpc = (string) ( $sn->vpcId ?? '' ); // phpcs:ignore

				if ( '' !== $id && ! isset( $assigned[ $id ] ) && isset( $main_vpc[ $vpc ] ) ) {
					$public[ $id ] = true;
				}
			}
		}

		return $public;
	}

	/**
	 * Instances sitting behind an internet-facing load balancer.
	 *
	 * @param array<string,array<string,mixed>> $instances Known instances.
	 * @return array<int,array<string,mixed>>
	 */
	private function load_balanced( string $region, array $instances ): array {
		$lbs = $this->client->query(
			'elasticloadbalancing',
			$region,
			array(
				'Action'  => 'DescribeLoadBalancers',
				'Version' => '2015-12-01',
			)
		);

		if ( ! $lbs['ok'] ) {
			// Optional permission: say so once and carry on with the direct
			// paths rather than failing the whole region.
			$this->log( sprintf( '%s: load balancers not readable (%s)', $region, $lbs['error'] ) );

			return array();
		}

		$out = array();

		foreach ( $lbs['xml']->DescribeLoadBalancersResult->LoadBalancers->member ?? array() as $lb ) { // phpcs:ignore
			if ( 'internet-facing' !== (string) ( $lb->Scheme ?? '' ) ) { // phpcs:ignore
				continue;
			}

			$arn  = (string) ( $lb->LoadBalancerArn ?? '' ); // phpcs:ignore
			$name = (string) ( $lb->LoadBalancerName ?? '' ); // phpcs:ignore

			if ( '' === $arn ) {
				continue;
			}

			$listeners = $this->client->query(
				'elasticloadbalancing',
				$region,
				array(
					'Action'          => 'DescribeListeners',
					'Version'         => '2015-12-01',
					'LoadBalancerArn' => $arn,
				)
			);

			$ports = array();

			if ( $listeners['ok'] ) {
				foreach ( $listeners['xml']->DescribeListenersResult->Listeners->member ?? array() as $l ) { // phpcs:ignore
					$ports[] = array(
						'port'     => (int) ( $l->Port ?? 0 ), // phpcs:ignore
						'protocol' => strtolower( (string) ( $l->Protocol ?? 'tcp' ) ), // phpcs:ignore
					);
				}
			}

			if ( ! $ports ) {
				continue;
			}

			$tgs = $this->client->query(
				'elasticloadbalancing',
				$region,
				array(
					'Action'          => 'DescribeTargetGroups',
					'Version'         => '2015-12-01',
					'LoadBalancerArn' => $arn,
				)
			);

			if ( ! $tgs['ok'] ) {
				continue;
			}

			foreach ( $tgs['xml']->DescribeTargetGroupsResult->TargetGroups->member ?? array() as $tg ) { // phpcs:ignore
				$tg_arn = (string) ( $tg->TargetGroupArn ?? '' ); // phpcs:ignore

				if ( '' === $tg_arn ) {
					continue;
				}

				$health = $this->client->query(
					'elasticloadbalancing',
					$region,
					array(
						'Action'         => 'DescribeTargetHealth',
						'Version'        => '2015-12-01',
						'TargetGroupArn' => $tg_arn,
					)
				);

				if ( ! $health['ok'] ) {
					continue;
				}

				foreach ( $health['xml']->DescribeTargetHealthResult->TargetHealthDescriptions->member ?? array() as $t ) { // phpcs:ignore
					$target = (string) ( $t->Target->Id ?? '' ); // phpcs:ignore

					// Targets can be IPs or Lambda ARNs; only instances match
					// anything we hold.
					if ( ! str_starts_with( $target, 'i-' ) || ! isset( $instances[ $target ] ) ) {
						continue;
					}

					foreach ( $ports as $p ) {
						$out[] = array(
							'instance' => $target,
							'port'     => $p['port'],
							'protocol' => in_array( $p['protocol'], array( 'http', 'https' ), true ) ? 'tcp' : $p['protocol'],
							'lb'       => $name,
						);
					}
				}
			}
		}

		return $out;
	}

	/**
	 * Replace this region's rows with what we just read.
	 *
	 * Scoped to the region so a failure reading one does not erase another,
	 * and so a shrinking estate does not leave stale exposure behind.
	 *
	 * @param array<int,array<int,mixed>> $rows Value tuples.
	 */
	private function store( string $region, array $rows ): void {
		global $wpdb;

		$t = self::table();

		$wpdb->query( $wpdb->prepare( "DELETE FROM {$t} WHERE region = %s", $region ) ); // phpcs:ignore

		if ( ! $rows ) {
			return;
		}

		foreach ( array_chunk( $rows, 200 ) as $chunk ) {
			$values = array();
			$params = array();

			foreach ( $chunk as $row ) {
				$values[] = '(%s,%s,%s,%s,%d,%d,%s,%s,%s,%s)';

				foreach ( $row as $v ) {
					$params[] = $v;
				}
			}

			$wpdb->query( // phpcs:ignore
				$wpdb->prepare(
					"INSERT INTO {$t} (instance_id,region,account_id,protocol,port_from,port_to,source_cidr,via,detail,updated_at) VALUES " // phpcs:ignore
					. implode( ',', $values )
					. ' ON DUPLICATE KEY UPDATE source_cidr=VALUES(source_cidr), detail=VALUES(detail), updated_at=VALUES(updated_at)',
					...$params
				)
			);
		}
	}

	/**
	 * Match what AWS said to the assets we hold, and hand the verdict to the
	 * exposure rule.
	 *
	 * @return int Assets matched.
	 */
	public static function apply_to_assets(): int {
		global $wpdb;

		$t = self::table();
		$a = vh_table( 'assets' );

		$rows = (array) $wpdb->get_results( // phpcs:ignore
			"SELECT s.id, e.port_from, e.port_to, e.protocol, e.via, e.detail
			   FROM {$t} e
			   INNER JOIN {$a} s ON s.aws_instance_id = e.instance_id", // phpcs:ignore
			ARRAY_A
		);

		$by_asset = array();

		foreach ( $rows as $row ) {
			$by_asset[ (int) $row['id'] ][] = $row;
		}

		update_option( 'vulnhub_aws_reachable', array_keys( $by_asset ), false );

		if ( class_exists( 'VulnHub_Threat_Classify' ) ) {
			VulnHub_Threat_Classify::rebuild_exposure();
		}

		return count( $by_asset );
	}

	/**
	 * Which assets AWS says are reachable, and why, for the exposure rule.
	 *
	 * @return array<int,string>
	 */
	public static function reachable_assets(): array {
		global $wpdb;

		$t = self::table();
		$a = vh_table( 'assets' );

		if ( (string) $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $t ) ) !== $t ) { // phpcs:ignore
			return array();
		}

		$rows = (array) $wpdb->get_results( // phpcs:ignore
			"SELECT s.id, e.port_from, e.port_to, e.via, COUNT(*) n
			   FROM {$t} e
			   INNER JOIN {$a} s ON s.aws_instance_id = e.instance_id
			  GROUP BY s.id, e.port_from, e.port_to, e.via", // phpcs:ignore
			ARRAY_A
		);

		$out = array();

		foreach ( $rows as $row ) {
			$id = (int) $row['id'];

			if ( isset( $out[ $id ] ) ) {
				continue;
			}

			$from = (int) $row['port_from'];
			$to   = (int) $row['port_to'];
			$port = $from === $to ? (string) $from : $from . '-' . $to;

			$out[ $id ] = 'elb' === (string) $row['via']
				? sprintf(
					/* translators: %s: port or port range. */
					__( 'published on port %s through an internet-facing load balancer', 'vulnhub' ),
					$port
				)
				: sprintf(
					/* translators: %s: port or port range. */
					__( 'AWS allows the internet to reach port %s', 'vulnhub' ),
					$port
				);
		}

		return $out;
	}

	private function log( string $message ): void {
		if ( $this->connector ) {
			$this->connector->log( $message );
		}
	}
}
