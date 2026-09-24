<?php
/**
 * The raw AWS network graph, per account, for topology / dataflow diagrams.
 *
 * Reachability answers a yes/no question and stores only its verdict. A
 * diagram needs the graph itself: the instances (nodes), the VPCs and subnets
 * that contain them, the security groups they belong to, and every
 * security-group rule (the edges — who may reach whom, from which source, on
 * which ports). This captures and stores that graph so a page can draw it.
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Stores the raw per-account AWS network graph.
 */
final class VulnHub_AWS_Network {

	public static function nodes_table(): string {
		global $wpdb;
		return $wpdb->prefix . 'vulnhub_aws_net_nodes';
	}

	public static function sgs_table(): string {
		global $wpdb;
		return $wpdb->prefix . 'vulnhub_aws_net_sgs';
	}

	public static function rules_table(): string {
		global $wpdb;
		return $wpdb->prefix . 'vulnhub_aws_net_rules';
	}

	public static function routes_table(): string {
		global $wpdb;
		return $wpdb->prefix . 'vulnhub_aws_net_routes';
	}

	public static function install(): void {
		global $wpdb;
		$charset = $wpdb->get_charset_collate();
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$n = self::nodes_table();
		dbDelta(
			"CREATE TABLE {$n} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				account_id varchar(24) NOT NULL DEFAULT '',
				region varchar(32) NOT NULL DEFAULT '',
				node_type varchar(16) NOT NULL DEFAULT '',
				resource_id varchar(128) NOT NULL DEFAULT '',
				name varchar(255) NOT NULL DEFAULT '',
				vpc_id varchar(64) NOT NULL DEFAULT '',
				subnet_id varchar(64) NOT NULL DEFAULT '',
				private_ip varchar(64) NOT NULL DEFAULT '',
				public_ip varchar(64) NOT NULL DEFAULT '',
				state varchar(24) NOT NULL DEFAULT '',
				sg_ids varchar(512) NOT NULL DEFAULT '',
				source varchar(12) NOT NULL DEFAULT 'aws',
				detail text NOT NULL,
				last_seen datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				PRIMARY KEY  (id),
				UNIQUE KEY res (account_id, resource_id),
				KEY acct (account_id),
				KEY type (node_type),
				KEY vpc (vpc_id)
			) {$charset};"
		);

		$s = self::sgs_table();
		dbDelta(
			"CREATE TABLE {$s} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				account_id varchar(24) NOT NULL DEFAULT '',
				region varchar(32) NOT NULL DEFAULT '',
				group_id varchar(64) NOT NULL DEFAULT '',
				name varchar(255) NOT NULL DEFAULT '',
				vpc_id varchar(64) NOT NULL DEFAULT '',
				last_seen datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				PRIMARY KEY  (id),
				UNIQUE KEY grp (account_id, group_id),
				KEY acct (account_id)
			) {$charset};"
		);

		$r = self::rules_table();
		dbDelta(
			"CREATE TABLE {$r} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				account_id varchar(24) NOT NULL DEFAULT '',
				region varchar(32) NOT NULL DEFAULT '',
				group_id varchar(64) NOT NULL DEFAULT '',
				direction varchar(4) NOT NULL DEFAULT 'in',
				protocol varchar(12) NOT NULL DEFAULT '',
				from_port int(11) NOT NULL DEFAULT 0,
				to_port int(11) NOT NULL DEFAULT 0,
				source_type varchar(8) NOT NULL DEFAULT '',
				source varchar(128) NOT NULL DEFAULT '',
				last_seen datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				PRIMARY KEY  (id),
				KEY acct (account_id),
				KEY grp (account_id, group_id)
			) {$charset};"
		);

		$rt2 = self::routes_table();
		dbDelta(
			"CREATE TABLE {$rt2} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				account_id varchar(24) NOT NULL DEFAULT '',
				region varchar(32) NOT NULL DEFAULT '',
				vpc_id varchar(64) NOT NULL DEFAULT '',
				route_table_id varchar(64) NOT NULL DEFAULT '',
				dest_cidr varchar(64) NOT NULL DEFAULT '',
				target_type varchar(16) NOT NULL DEFAULT '',
				target_id varchar(128) NOT NULL DEFAULT '',
				last_seen datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				PRIMARY KEY  (id),
				KEY acct (account_id),
				KEY vpc (account_id, vpc_id)
			) {$charset};"
		);
	}

	/**
	 * Capture and store the network graph for one account+region.
	 *
	 * @return int Rows written (nodes + sgs + rules).
	 */
	public static function capture( VulnHub_AWS_Client $client, string $account, string $region, string $now ): int {
		global $wpdb;

		/*
		 * Replace this account+region's slice so a re-sync reflects deletions
		 * -- but only the rows this capture wrote. The same table also holds
		 * nodes imported from the cloud-posture inventory, for the accounts
		 * this login cannot reach at all, and a blind DELETE would throw those
		 * away every time a neighbouring account synced.
		 */
		$wpdb->query( $wpdb->prepare( "DELETE FROM " . self::nodes_table() . " WHERE account_id = %s AND region = %s AND source = 'aws'", $account, $region ) ); // phpcs:ignore

		foreach ( array( self::sgs_table(), self::rules_table(), self::routes_table() ) as $t ) {
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$t} WHERE account_id = %s AND region = %s", $account, $region ) ); // phpcs:ignore
		}

		$written  = 0;
		$written += self::capture_instances( $client, $account, $region, $now );
		$written += self::capture_containers( $client, $account, $region, $now );
		$written += self::capture_security_groups( $client, $account, $region, $now );
		$written += self::capture_infra( $client, $account, $region, $now );
		$written += self::capture_routes( $client, $account, $region, $now );
		$written += self::capture_enis( $client, $account, $region, $now );
		$written += self::capture_addresses( $client, $account, $region, $now );
		$written += self::capture_load_balancers( $client, $account, $region, $now );
		$written += self::capture_vpc_endpoints( $client, $account, $region, $now );

		return $written;
	}

	private static function tag_name( $item ): string {
		foreach ( $item->tagSet->item ?? array() as $t ) { // phpcs:ignore
			if ( 'Name' === (string) ( $t->key ?? '' ) ) { // phpcs:ignore
				return (string) ( $t->value ?? '' ); // phpcs:ignore
			}
		}
		return '';
	}

	private static function capture_instances( VulnHub_AWS_Client $client, string $account, string $region, string $now ): int {
		global $wpdb;
		$t     = self::nodes_table();
		$token = '';
		$n     = 0;

		do {
			$params = array( 'Action' => 'DescribeInstances', 'Version' => '2016-11-15', 'MaxResults' => '200' );
			if ( '' !== $token ) { $params['NextToken'] = $token; }

			$res = $client->query( 'ec2', $region, $params );
			if ( empty( $res['ok'] ) ) { return $n; }
			$xml = $res['xml'];

			foreach ( $xml->reservationSet->item ?? array() as $r ) { // phpcs:ignore
				foreach ( $r->instancesSet->item ?? array() as $inst ) { // phpcs:ignore
					$id = (string) ( $inst->instanceId ?? '' ); // phpcs:ignore
					if ( '' === $id ) { continue; }

					$groups = array();
					foreach ( $inst->groupSet->item ?? array() as $g ) { // phpcs:ignore
						$groups[] = (string) ( $g->groupId ?? '' ); // phpcs:ignore
					}

					$wpdb->query( // phpcs:ignore
						$wpdb->prepare(
							"INSERT INTO {$t} (account_id, region, node_type, resource_id, name, vpc_id, subnet_id, private_ip, public_ip, state, sg_ids, last_seen)
							 VALUES (%s,%s,'instance',%s,%s,%s,%s,%s,%s,%s,%s,%s)
							 ON DUPLICATE KEY UPDATE region=VALUES(region), node_type='instance', name=VALUES(name), vpc_id=VALUES(vpc_id), subnet_id=VALUES(subnet_id), private_ip=VALUES(private_ip), public_ip=VALUES(public_ip), state=VALUES(state), sg_ids=VALUES(sg_ids), last_seen=VALUES(last_seen)",
							$account, $region, $id, self::tag_name( $inst ),
							(string) ( $inst->vpcId ?? '' ), // phpcs:ignore
							(string) ( $inst->subnetId ?? '' ), // phpcs:ignore
							(string) ( $inst->privateIpAddress ?? '' ), // phpcs:ignore
							(string) ( $inst->ipAddress ?? '' ), // phpcs:ignore
							(string) ( $inst->instanceState->name ?? '' ), // phpcs:ignore
							implode( ',', array_values( array_filter( $groups ) ) ),
							$now
						)
					);

					/*
					 * What the machine is: enough to put an OS, a size and an
					 * image on the asset record, which is otherwise only an
					 * instance id when the posture inventory created it.
					 */
					foreach ( array(
						'platform'      => (string) ( $inst->platformDetails ?? $inst->platform ?? '' ), // phpcs:ignore
						'instance_type' => (string) ( $inst->instanceType ?? '' ), // phpcs:ignore
						'image_id'      => (string) ( $inst->imageId ?? '' ), // phpcs:ignore
						'launched'      => (string) ( $inst->launchTime ?? '' ), // phpcs:ignore
					) as $k => $v ) {
						if ( '' !== $v ) {
							self::set_detail( $account, $region, 'instance', $id, $k, $v );
						}
					}

					++$n;
				}
			}

			$token = (string) ( $xml->nextToken ?? '' ); // phpcs:ignore
		} while ( '' !== $token );

		return $n;
	}

	private static function capture_containers( VulnHub_AWS_Client $client, string $account, string $region, string $now ): int {
		global $wpdb;
		$t = self::nodes_table();
		$n = 0;

		foreach ( array( 'vpc' => array( 'DescribeVpcs', 'vpcSet', 'vpcId' ), 'subnet' => array( 'DescribeSubnets', 'subnetSet', 'subnetId' ) ) as $type => $spec ) {
			$res = $client->query( 'ec2', $region, array( 'Action' => $spec[0], 'Version' => '2016-11-15' ) );
			if ( empty( $res['ok'] ) ) { continue; }

			$set = $spec[1];
			$idk = $spec[2];

			foreach ( $res['xml']->{$set}->item ?? array() as $item ) { // phpcs:ignore
				$id = (string) ( $item->{$idk} ?? '' );
				if ( '' === $id ) { continue; }

				$wpdb->query( // phpcs:ignore
					$wpdb->prepare(
						"INSERT INTO {$t} (account_id, region, node_type, resource_id, name, vpc_id, detail, last_seen)
						 VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
						 ON DUPLICATE KEY UPDATE region=VALUES(region), node_type=VALUES(node_type), name=VALUES(name), vpc_id=VALUES(vpc_id), detail=VALUES(detail), last_seen=VALUES(last_seen)",
						$account, $region, $type, $id, self::tag_name( $item ),
						'subnet' === $type ? (string) ( $item->vpcId ?? '' ) : $id, // phpcs:ignore
						// The address range: what lets an address seen by a
						// scanner be placed in a subnet, and so in whatever
						// the subnet is for (an AppStream fleet, say).
						(string) wp_json_encode( array( 'cidr' => (string) ( $item->cidrBlock ?? '' ) ) ), // phpcs:ignore
						$now
					)
				);
				++$n;
			}
		}

		return $n;
	}

	private static function capture_security_groups( VulnHub_AWS_Client $client, string $account, string $region, string $now ): int {
		global $wpdb;
		$sgt   = self::sgs_table();
		$rt    = self::rules_table();
		$token = '';
		$n     = 0;

		do {
			$params = array( 'Action' => 'DescribeSecurityGroups', 'Version' => '2016-11-15', 'MaxResults' => '1000' );
			if ( '' !== $token ) { $params['NextToken'] = $token; }

			$res = $client->query( 'ec2', $region, $params );
			if ( empty( $res['ok'] ) ) { return $n; }
			$xml = $res['xml'];

			foreach ( $xml->securityGroupInfo->item ?? array() as $sg ) { // phpcs:ignore
				$gid = (string) ( $sg->groupId ?? '' ); // phpcs:ignore
				if ( '' === $gid ) { continue; }

				$wpdb->query( // phpcs:ignore
					$wpdb->prepare(
						"INSERT INTO {$sgt} (account_id, region, group_id, name, vpc_id, last_seen)
						 VALUES (%s,%s,%s,%s,%s,%s)
						 ON DUPLICATE KEY UPDATE region=VALUES(region), name=VALUES(name), vpc_id=VALUES(vpc_id), last_seen=VALUES(last_seen)",
						$account, $region, $gid,
						(string) ( $sg->groupName ?? '' ), // phpcs:ignore
						(string) ( $sg->vpcId ?? '' ), // phpcs:ignore
						$now
					)
				);
				++$n;

				$n += self::store_rules( $rt, $account, $region, $gid, $sg->ipPermissions->item ?? array(), 'in', $now ); // phpcs:ignore
				$n += self::store_rules( $rt, $account, $region, $gid, $sg->ipPermissionsEgress->item ?? array(), 'out', $now ); // phpcs:ignore
			}

			$token = (string) ( $xml->nextToken ?? '' ); // phpcs:ignore
		} while ( '' !== $token );

		return $n;
	}

	/** @param iterable $perms */
	private static function store_rules( string $rt, string $account, string $region, string $gid, $perms, string $dir, string $now ): int {
		global $wpdb;
		$n = 0;

		foreach ( $perms as $perm ) { // phpcs:ignore
			$proto = (string) ( $perm->ipProtocol ?? '' ); // phpcs:ignore
			$all   = '-1' === $proto;
			$from  = $all ? 0 : (int) ( $perm->fromPort ?? 0 ); // phpcs:ignore
			$to    = $all ? 65535 : (int) ( $perm->toPort ?? 0 ); // phpcs:ignore
			$proto = $all ? 'any' : strtolower( $proto );

			$sources = array();
			foreach ( $perm->ipRanges->item ?? array() as $x ) { // phpcs:ignore
				$sources[] = array( 'cidr', (string) ( $x->cidrIp ?? '' ) ); // phpcs:ignore
			}
			foreach ( $perm->ipv6Ranges->item ?? array() as $x ) { // phpcs:ignore
				$sources[] = array( 'cidr', (string) ( $x->cidrIpv6 ?? '' ) ); // phpcs:ignore
			}
			foreach ( $perm->groups->item ?? array() as $x ) { // phpcs:ignore
				$sources[] = array( 'sg', (string) ( $x->groupId ?? '' ) ); // phpcs:ignore
			}

			foreach ( $sources as $src ) {
				if ( '' === $src[1] ) { continue; }

				$wpdb->query( // phpcs:ignore
					$wpdb->prepare(
						"INSERT INTO {$rt} (account_id, region, group_id, direction, protocol, from_port, to_port, source_type, source, last_seen)
						 VALUES (%s,%s,%s,%s,%s,%d,%d,%s,%s,%s)",
						$account, $region, $gid, $dir, $proto, $from, $to, $src[0], $src[1], $now
					)
				);
				++$n;
			}
		}

		return $n;
	}

	/** Gateways and peering: transit gateways, NAT, internet gateways, VPC peering. */
	private static function capture_infra( VulnHub_AWS_Client $client, string $account, string $region, string $now ): int {
		global $wpdb;
		$t = self::nodes_table();
		$n = 0;

		$specs = array(
			'igw' => array( 'DescribeInternetGateways', 'internetGatewaySet', 'internetGatewayId', '' ),
			'nat' => array( 'DescribeNatGateways', 'natGatewaySet', 'natGatewayId', 'vpcId' ),
			'tgw' => array( 'DescribeTransitGateways', 'transitGatewaySet', 'transitGatewayId', '' ),
			'pcx' => array( 'DescribeVpcPeeringConnections', 'vpcPeeringConnectionSet', 'vpcPeeringConnectionId', '' ),
		);

		foreach ( $specs as $type => $spec ) {
			$res = $client->query( 'ec2', $region, array( 'Action' => $spec[0], 'Version' => '2016-11-15' ) );
			if ( empty( $res['ok'] ) ) { continue; }

			foreach ( $res['xml']->{$spec[1]}->item ?? array() as $item ) { // phpcs:ignore
				$id = (string) ( $item->{$spec[2]} ?? '' );
				if ( '' === $id ) { continue; }
				$vpc = '' !== $spec[3] ? (string) ( $item->{$spec[3]} ?? '' ) : '';

				$wpdb->query( $wpdb->prepare( "INSERT INTO {$t} (account_id, region, node_type, resource_id, name, vpc_id, last_seen) VALUES (%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE region=VALUES(region), node_type=VALUES(node_type), name=VALUES(name), vpc_id=VALUES(vpc_id), last_seen=VALUES(last_seen)", $account, $region, $type, $id, self::tag_name( $item ), $vpc, $now ) ); // phpcs:ignore
				++$n;
			}
		}

		// Which VPCs attach to which transit gateway -- the hub-and-spoke edges.
		$att = $client->query( 'ec2', $region, array( 'Action' => 'DescribeTransitGatewayVpcAttachments', 'Version' => '2016-11-15' ) );
		if ( ! empty( $att['ok'] ) ) {
			foreach ( $att['xml']->transitGatewayVpcAttachments->item ?? array() as $a ) { // phpcs:ignore
				$id = 'tgwa-' . (string) ( $a->transitGatewayAttachmentId ?? '' );
				$wpdb->query( $wpdb->prepare( "INSERT INTO {$t} (account_id, region, node_type, resource_id, name, vpc_id, subnet_id, last_seen) VALUES (%s,%s,'tgw-attach',%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE region=VALUES(region), node_type='tgw-attach', vpc_id=VALUES(vpc_id), subnet_id=VALUES(subnet_id), last_seen=VALUES(last_seen)", $account, $region, $id, (string) ( $a->transitGatewayId ?? '' ), (string) ( $a->vpcId ?? '' ), (string) ( $a->transitGatewayId ?? '' ), $now ) ); // phpcs:ignore
				++$n;
			}
		}

		return $n;
	}

	/**
	 * Network interfaces -- the missing link between a security group and a thing.
	 *
	 * A security group means nothing on its own: `sg-x opens tcp/443 to the
	 * world` is only alarming if something is behind it. The binding is the ENI,
	 * and it is the *only* binding for everything that is not an EC2 instance --
	 * load balancers, VPC endpoints, RDS, NAT gateways, Lambda in a VPC. Without
	 * this table the map could show a port but never say whose it was, and an
	 * open group attached to nothing looked identical to one attached to a
	 * public server.
	 *
	 * The `description` is how AWS says what an ENI belongs to ("Interface for
	 * NAT Gateway nat-...", "VPC Endpoint Interface vpce-...", "ELB net/...").
	 */
	private static function capture_enis( VulnHub_AWS_Client $client, string $account, string $region, string $now ): int {
		global $wpdb;
		$t = self::nodes_table();
		$n = 0;

		$res = $client->query( 'ec2', $region, array( 'Action' => 'DescribeNetworkInterfaces', 'Version' => '2016-11-15' ) );
		if ( empty( $res['ok'] ) ) { return $n; }

		foreach ( $res['xml']->networkInterfaceSet->item ?? array() as $e ) { // phpcs:ignore
			$id = (string) ( $e->networkInterfaceId ?? '' );
			if ( '' === $id ) { continue; }

			$sgs = array();
			foreach ( $e->groupSet->item ?? array() as $g ) { // phpcs:ignore
				$sgs[] = (string) ( $g->groupId ?? '' );
			}

			$detail = array(
				'desc'     => (string) ( $e->description ?? '' ),
				'type'     => (string) ( $e->interfaceType ?? '' ),
				'instance' => (string) ( $e->attachment->instanceId ?? '' ),
				'managed'  => 'true' === (string) ( $e->requesterManaged ?? '' ),
			);

			$wpdb->query( $wpdb->prepare( "INSERT INTO {$t} (account_id, region, node_type, resource_id, name, vpc_id, subnet_id, private_ip, public_ip, state, sg_ids, detail, last_seen) VALUES (%s,%s,'eni',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE region=VALUES(region), node_type='eni', name=VALUES(name), vpc_id=VALUES(vpc_id), subnet_id=VALUES(subnet_id), private_ip=VALUES(private_ip), public_ip=VALUES(public_ip), state=VALUES(state), sg_ids=VALUES(sg_ids), detail=VALUES(detail), last_seen=VALUES(last_seen)", // phpcs:ignore
				$account, $region, $id,
				(string) ( $e->description ?? '' ),
				(string) ( $e->vpcId ?? '' ),
				(string) ( $e->subnetId ?? '' ),
				(string) ( $e->privateIpAddress ?? '' ),
				(string) ( $e->association->publicIp ?? '' ),
				(string) ( $e->status ?? '' ),
				implode( ',', array_filter( $sgs ) ),
				(string) wp_json_encode( $detail ),
				$now
			) );
			++$n;
		}

		return $n;
	}

	/**
	 * Elastic IPs -- an account's public addresses.
	 *
	 * `public_ip` on an instance row only ever covers EC2, so an account whose
	 * only public address sits on a NAT gateway or a load balancer read as
	 * having none at all. An EIP is attached to an ENI, which is how it reaches
	 * whatever actually holds it.
	 */
	private static function capture_addresses( VulnHub_AWS_Client $client, string $account, string $region, string $now ): int {
		global $wpdb;
		$t = self::nodes_table();
		$n = 0;

		$res = $client->query( 'ec2', $region, array( 'Action' => 'DescribeAddresses', 'Version' => '2016-11-15' ) );
		if ( empty( $res['ok'] ) ) { return $n; }

		foreach ( $res['xml']->addressesSet->item ?? array() as $a ) { // phpcs:ignore
			$ip = (string) ( $a->publicIp ?? '' );
			if ( '' === $ip ) { continue; }

			$id     = (string) ( $a->allocationId ?? '' );
			$id     = '' !== $id ? $id : 'eip-' . $ip;
			$detail = array(
				'eni'      => (string) ( $a->networkInterfaceId ?? '' ),
				'instance' => (string) ( $a->instanceId ?? '' ),
				'domain'   => (string) ( $a->domain ?? '' ),
			);

			$wpdb->query( $wpdb->prepare( "INSERT INTO {$t} (account_id, region, node_type, resource_id, name, private_ip, public_ip, detail, last_seen) VALUES (%s,%s,'eip',%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE region=VALUES(region), node_type='eip', name=VALUES(name), private_ip=VALUES(private_ip), public_ip=VALUES(public_ip), detail=VALUES(detail), last_seen=VALUES(last_seen)", // phpcs:ignore
				$account, $region, $id, self::tag_name( $a ),
				(string) ( $a->privateIpAddress ?? '' ), $ip,
				(string) wp_json_encode( $detail ), $now
			) );
			++$n;
		}

		return $n;
	}

	/**
	 * Load balancers, and the ports they actually listen on.
	 *
	 * A listener is a better answer than a security-group rule: it is what the
	 * balancer accepts, stated by the service that owns it, and a network load
	 * balancer may carry no security group at all. `scheme` is the one fact
	 * that separates an internet-facing balancer from an internal one.
	 *
	 * Both API generations are read. A tenant running classic balancers would
	 * otherwise show an empty Entry column while Plerion listed them.
	 */
	private static function capture_load_balancers( VulnHub_AWS_Client $client, string $account, string $region, string $now ): int {
		global $wpdb;
		$t = self::nodes_table();
		$n = 0;

		$v2 = $client->query( 'elasticloadbalancing', $region, array( 'Action' => 'DescribeLoadBalancers', 'Version' => '2015-12-01' ) );
		if ( ! empty( $v2['ok'] ) ) {
			foreach ( $v2['xml']->DescribeLoadBalancersResult->LoadBalancers->member ?? array() as $lb ) { // phpcs:ignore
				$arn = (string) ( $lb->LoadBalancerArn ?? '' );
				if ( '' === $arn ) { continue; }

				// The ARN tail (net/name/hash) is unique per account+region and
				// fits the column; the full ARN would not.
				$rid = ( false !== strpos( $arn, ':loadbalancer/' ) )
					? substr( $arn, strpos( $arn, ':loadbalancer/' ) + 14 )
					: substr( $arn, -120 );

				$sgs = array();
				foreach ( $lb->SecurityGroups->member ?? array() as $g ) { $sgs[] = (string) $g; } // phpcs:ignore
				$subnets = array();
				foreach ( $lb->AvailabilityZones->member ?? array() as $z ) { $subnets[] = (string) ( $z->SubnetId ?? '' ); } // phpcs:ignore

				$forwards = array();
				$detail   = array(
					'arn'       => $arn,
					'dns'       => (string) ( $lb->DNSName ?? '' ),
					'scheme'    => (string) ( $lb->Scheme ?? '' ),
					'lbtype'    => (string) ( $lb->Type ?? '' ),
					'subnets'   => array_values( array_filter( $subnets ) ),
					'listeners' => self::listeners_for( $client, $region, $arn, $forwards ),
				);

				/*
				 * What an internet-facing balancer hands traffic to. Without
				 * it, a server published only through a load balancer -- the
				 * usual way to publish one -- has no public address of its
				 * own and reads as unreachable. Internal balancers are
				 * skipped: two calls per target group buys nothing there.
				 */
				if ( 'internet-facing' === $detail['scheme'] ) {
					$detail['forwards'] = $forwards;
					$detail['targets']  = self::targets_for( $client, $region, $arn );
				}

				$wpdb->query( $wpdb->prepare( "INSERT INTO {$t} (account_id, region, node_type, resource_id, name, vpc_id, subnet_id, state, sg_ids, detail, last_seen) VALUES (%s,%s,'elb',%s,%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE region=VALUES(region), node_type='elb', name=VALUES(name), vpc_id=VALUES(vpc_id), subnet_id=VALUES(subnet_id), state=VALUES(state), sg_ids=VALUES(sg_ids), detail=VALUES(detail), last_seen=VALUES(last_seen)", // phpcs:ignore
					$account, $region, $rid,
					(string) ( $lb->LoadBalancerName ?? '' ),
					(string) ( $lb->VpcId ?? '' ),
					(string) ( $subnets[0] ?? '' ),
					(string) ( $lb->State->Code ?? '' ),
					implode( ',', array_filter( $sgs ) ),
					(string) wp_json_encode( $detail ), $now
				) );
				++$n;
			}
		}

		$v1 = $client->query( 'elasticloadbalancing', $region, array( 'Action' => 'DescribeLoadBalancers', 'Version' => '2012-06-01' ) );
		if ( ! empty( $v1['ok'] ) ) {
			foreach ( $v1['xml']->DescribeLoadBalancersResult->LoadBalancerDescriptions->member ?? array() as $lb ) { // phpcs:ignore
				$nm = (string) ( $lb->LoadBalancerName ?? '' );
				if ( '' === $nm ) { continue; }

				$ports    = array();
				$forwards = array();
				foreach ( $lb->ListenerDescriptions->member ?? array() as $l ) { // phpcs:ignore
					$label      = strtolower( (string) ( $l->Listener->Protocol ?? '' ) ) . '/' . (string) ( $l->Listener->LoadBalancerPort ?? '' );
					$ports[]    = $label;
					$forwards[ $label ] = array( 'port:' . (int) ( $l->Listener->InstancePort ?? 0 ) );
				}
				$targets = array();
				foreach ( $lb->Instances->member ?? array() as $i ) { // phpcs:ignore
					$targets[] = array( 'tg' => '', 'id' => (string) ( $i->InstanceId ?? '' ), 'port' => 0 );
				}
				$sgs = array();
				foreach ( $lb->SecurityGroups->member ?? array() as $g ) { $sgs[] = (string) $g; } // phpcs:ignore

				$detail = array(
					'dns'       => (string) ( $lb->DNSName ?? '' ),
					'scheme'    => (string) ( $lb->Scheme ?? '' ),
					'lbtype'    => 'classic',
					'listeners' => array_values( array_unique( array_filter( $ports ) ) ),
				);

				// A classic balancer lists its instances and each listener's
				// instance port on the balancer itself: no extra call.
				if ( 'internet-facing' === $detail['scheme'] ) {
					$detail['forwards'] = $forwards;
					$detail['targets']  = array_values( array_filter( $targets, static fn( array $t ): bool => '' !== $t['id'] ) );
				}

				$wpdb->query( $wpdb->prepare( "INSERT INTO {$t} (account_id, region, node_type, resource_id, name, vpc_id, state, sg_ids, detail, last_seen) VALUES (%s,%s,'elb',%s,%s,%s,'',%s,%s,%s) ON DUPLICATE KEY UPDATE region=VALUES(region), node_type='elb', name=VALUES(name), vpc_id=VALUES(vpc_id), sg_ids=VALUES(sg_ids), detail=VALUES(detail), last_seen=VALUES(last_seen)", // phpcs:ignore
					$account, $region, 'classic/' . $nm, $nm,
					(string) ( $lb->VPCId ?? '' ),
					implode( ',', array_filter( $sgs ) ),
					(string) wp_json_encode( $detail ), $now
				) );
				++$n;
			}
		}

		return $n;
	}

	/**
	 * Listener ports for one v2 balancer.
	 *
	 * @param array<string,string[]> $forwards Filled with listener => the
	 *                                         target groups its default action
	 *                                         forwards to (ARN tails).
	 * @return string[]
	 */
	private static function listeners_for( VulnHub_AWS_Client $client, string $region, string $arn, array &$forwards = array() ): array {
		$out = array();
		$res = $client->query( 'elasticloadbalancing', $region, array( 'Action' => 'DescribeListeners', 'Version' => '2015-12-01', 'LoadBalancerArn' => $arn ) );
		if ( empty( $res['ok'] ) ) { return $out; }

		foreach ( $res['xml']->DescribeListenersResult->Listeners->member ?? array() as $l ) { // phpcs:ignore
			$label = strtolower( (string) ( $l->Protocol ?? '' ) ) . '/' . (string) ( $l->Port ?? '' );
			$out[] = $label;

			foreach ( $l->DefaultActions->member ?? array() as $a ) { // phpcs:ignore
				$tgs = array( (string) ( $a->TargetGroupArn ?? '' ) );

				foreach ( $a->ForwardConfig->TargetGroups->member ?? array() as $tg ) { // phpcs:ignore
					$tgs[] = (string) ( $tg->TargetGroupArn ?? '' );
				}

				foreach ( array_filter( $tgs ) as $tg ) {
					$forwards[ $label ][] = self::arn_tail( $tg );
				}
			}
		}

		return array_values( array_unique( array_filter( $out, static fn( $x ) => '/' !== $x ) ) );
	}

	/**
	 * The instances behind one v2 balancer, with the port each is sent
	 * traffic on. IP targets are kept too: an address in the VPC resolves to
	 * an instance through its interface.
	 *
	 * @return array<int,array{tg:string,id:string,port:int}>
	 */
	private static function targets_for( VulnHub_AWS_Client $client, string $region, string $arn ): array {
		$out = array();
		$res = $client->query( 'elasticloadbalancing', $region, array( 'Action' => 'DescribeTargetGroups', 'Version' => '2015-12-01', 'LoadBalancerArn' => $arn ) );
		if ( empty( $res['ok'] ) ) { return $out; }

		foreach ( $res['xml']->DescribeTargetGroupsResult->TargetGroups->member ?? array() as $tg ) { // phpcs:ignore
			$tg_arn = (string) ( $tg->TargetGroupArn ?? '' );
			if ( '' === $tg_arn ) { continue; }

			$health = $client->query( 'elasticloadbalancing', $region, array( 'Action' => 'DescribeTargetHealth', 'Version' => '2015-12-01', 'TargetGroupArn' => $tg_arn ) );
			if ( empty( $health['ok'] ) ) { continue; }

			foreach ( $health['xml']->DescribeTargetHealthResult->TargetHealthDescriptions->member ?? array() as $d ) { // phpcs:ignore
				$id = (string) ( $d->Target->Id ?? '' );
				if ( '' === $id ) { continue; }

				$out[] = array(
					'tg'   => self::arn_tail( $tg_arn ),
					'id'   => $id,
					'port' => (int) ( $d->Target->Port ?? $tg->Port ?? 0 ),
				);
			}
		}

		return $out;
	}

	/** The name/hash end of an ARN, which is unique and fits a column. */
	private static function arn_tail( string $arn ): string {
		$at = strpos( $arn, ':targetgroup/' );

		return false !== $at ? substr( $arn, $at + 13 ) : substr( $arn, -120 );
	}

	/** Route tables: where each 0.0.0.0/0 (and other) route points -- IGW, NAT, TGW, peering. */
	/**
	 * VPC endpoints — and the one that matters is the Gateway Load Balancer.
	 *
	 * A workload VPC whose default route points at a `vpce-` is sending
	 * everything internet-bound into an inline inspection appliance. Until
	 * this reader existed the route was all we had: the screen could say
	 * traffic left through *an* endpoint, and nothing about what was on the
	 * other side of it.
	 *
	 * The endpoint's `serviceName` closes that gap. It is the same string in
	 * every VPC pointed at the same appliance, so it is the join that turns
	 * dozens of unrelated `vpce-` ids into one firewall on the diagram —
	 * without matching on anybody's resource name, which is the mistake
	 * recorded under *The direct-vs-inspected story*.
	 */
	private static function capture_vpc_endpoints( VulnHub_AWS_Client $client, string $account, string $region, string $now ): int {
		global $wpdb;
		$nt = self::nodes_table();
		$n  = 0;

		$res = $client->query( 'ec2', $region, array( 'Action' => 'DescribeVpcEndpoints', 'Version' => '2016-11-15' ) );

		if ( empty( $res['ok'] ) ) {
			return $n;
		}

		foreach ( $res['xml']->vpcEndpointSet->item ?? array() as $e ) { // phpcs:ignore
			$id   = (string) ( $e->vpcEndpointId ?? '' ); // phpcs:ignore
			$type = (string) ( $e->vpcEndpointType ?? '' ); // phpcs:ignore

			if ( '' === $id ) {
				continue;
			}

			/*
			 * Only the ones that can be in a data path. An Interface endpoint
			 * to a service like SSM or ECR is a private route to an AWS API,
			 * not a hop in this estate's topology, and drawing hundreds of
			 * them would bury the one that is.
			 */
			if ( 'GatewayLoadBalancer' !== $type ) {
				continue;
			}

			$wpdb->query(
				$wpdb->prepare(
					"INSERT INTO {$nt} (account_id, region, node_type, resource_id, name, vpc_id, subnet_id, private_ip, public_ip, state, sg_ids, detail, last_seen)
					 VALUES (%s,%s,'vpce',%s,%s,%s,'','','',%s,'',%s,%s)
					 ON DUPLICATE KEY UPDATE name = VALUES(name), vpc_id = VALUES(vpc_id), state = VALUES(state), detail = VALUES(detail), last_seen = VALUES(last_seen)", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					$account,
					$region,
					$id,
					// The service is the node's identity here, not the endpoint
					// id: two VPCs pointing at the same service are behind the
					// same appliance, and that is the fact the diagram needs.
					(string) ( $e->serviceName ?? '' ), // phpcs:ignore
					(string) ( $e->vpcId ?? '' ), // phpcs:ignore
					(string) ( $e->state ?? '' ), // phpcs:ignore
					(string) wp_json_encode( array( 'endpoint_type' => $type ) ),
					$now
				)
			);
			++$n;
		}

		return $n;
	}

	private static function capture_routes( VulnHub_AWS_Client $client, string $account, string $region, string $now ): int {
		global $wpdb;
		$rt = self::routes_table();
		$n  = 0;

		$res = $client->query( 'ec2', $region, array( 'Action' => 'DescribeRouteTables', 'Version' => '2016-11-15' ) );
		if ( empty( $res['ok'] ) ) { return $n; }

		foreach ( $res['xml']->routeTableSet->item ?? array() as $r ) { // phpcs:ignore
			$rtid = (string) ( $r->routeTableId ?? '' );
			$vpc  = (string) ( $r->vpcId ?? '' );

			foreach ( $r->routeSet->item ?? array() as $rte ) { // phpcs:ignore
				$dst = (string) ( $rte->destinationCidrBlock ?? $rte->destinationIpv6CidrBlock ?? '' );
				if ( '' === $dst ) { continue; }

				$ttype = ''; $tid = '';
				$gw = (string) ( $rte->gatewayId ?? '' );
				if ( '' !== $gw ) { $ttype = 0 === strpos( $gw, 'igw-' ) ? 'igw' : ( 'local' === $gw ? 'local' : 'gw' ); $tid = $gw; }
				elseif ( ! empty( $rte->natGatewayId ) ) { $ttype = 'nat'; $tid = (string) $rte->natGatewayId; } // phpcs:ignore
				elseif ( ! empty( $rte->transitGatewayId ) ) { $ttype = 'tgw'; $tid = (string) $rte->transitGatewayId; } // phpcs:ignore
				elseif ( ! empty( $rte->vpcPeeringConnectionId ) ) { $ttype = 'pcx'; $tid = (string) $rte->vpcPeeringConnectionId; } // phpcs:ignore
				elseif ( ! empty( $rte->networkInterfaceId ) ) { $ttype = 'eni'; $tid = (string) $rte->networkInterfaceId; } // phpcs:ignore
				else { continue; }

				$wpdb->query( $wpdb->prepare( "INSERT INTO {$rt} (account_id, region, vpc_id, route_table_id, dest_cidr, target_type, target_id, last_seen) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)", $account, $region, $vpc, $rtid, $dst, $ttype, $tid, $now ) ); // phpcs:ignore
				++$n;
			}

			/*
			 * Which subnets use this table. "The VPC routes to an internet
			 * gateway" is a property of one subnet's table, not of the VPC:
			 * a machine with a public address in a private subnet has no
			 * way in. Recorded on the subnet (and the main table on the
			 * VPC, for subnets with no association of their own) so the
			 * exposure check can ask the right table.
			 */
			foreach ( $r->associationSet->item ?? array() as $assoc ) { // phpcs:ignore
				$subnet = (string) ( $assoc->subnetId ?? '' );

				$gateway = (string) ( $assoc->gatewayId ?? '' );

				if ( '' !== $subnet ) {
					self::set_detail( $account, $region, 'subnet', $subnet, 'route_table', $rtid );
				} elseif ( str_starts_with( $gateway, 'igw-' ) && '' !== $vpc ) {
					// An edge association: the table the internet gateway
					// applies to traffic *arriving*. It is the only way inbound
					// traffic to a public address passes an inline firewall.
					self::set_detail( $account, $region, 'vpc', $vpc, 'edge_route_table', $rtid );
				} elseif ( 'true' === strtolower( (string) ( $assoc->main ?? '' ) ) && '' !== $vpc ) {
					self::set_detail( $account, $region, 'vpc', $vpc, 'main_route_table', $rtid );
				}
			}
		}

		return $n;
	}

	/**
	 * Set one key in a captured node's detail, leaving the rest alone.
	 */
	private static function set_detail( string $account, string $region, string $type, string $id, string $key, string $value ): void {
		global $wpdb;

		$wpdb->query( // phpcs:ignore
			$wpdb->prepare(
				'UPDATE ' . self::nodes_table() . " SET detail = JSON_SET(IF(detail IS NULL OR detail = '' OR JSON_VALID(detail) = 0, '{}', detail), %s, %s)
				 WHERE account_id = %s AND region = %s AND node_type = %s AND resource_id = %s AND source = 'aws'",
				'$.' . $key,
				$value,
				$account,
				$region,
				$type,
				$id
			)
		);
	}

	/** Plerion resource types that are hops, and the node type each becomes. */
	private const PLERION_NET_TYPES = array(
		'AWS::ElasticLoadBalancingV2::LoadBalancer' => 'elb',
		'AWS::EC2::TransitGateway'                  => 'tgw',
		'AWS::AutoScaling::AutoScalingGroup'        => 'asg',
		'AWS::EC2::Instance'                        => 'instance',
	);

	/**
	 * Fill in the accounts this login cannot read, from the posture inventory.
	 *
	 * The estate's inspection appliances sit in a network account that the SSO
	 * login has no assignment to -- `list_roles` returns nothing for it -- so
	 * the AWS capture can never see the load balancer every other account
	 * routes into, nor the firewalls behind it, nor the transit gateway that
	 * owns the hub. The posture connector *can* see it, because it is
	 * onboarded centrally rather than per account.
	 *
	 * So the middle of the diagram comes from there. The rows are written with
	 * `source = 'plerion'`, which is what keeps a neighbouring account's
	 * capture from deleting them, and is also the honest label: they are an
	 * inventory record, not a live read of that account's configuration. What
	 * they cannot give is a security group, a route table or an interface --
	 * only that the resource exists, in which account and region.
	 *
	 * Accounts the AWS capture already reads are skipped: a live read beats an
	 * inventory every time, and importing both would draw each node twice.
	 *
	 * @return array{imported:int,accounts:int,skipped:int}
	 */
	public static function import_posture_network(): array {
		global $wpdb;

		$out = array( 'imported' => 0, 'accounts' => 0, 'skipped' => 0 );

		if ( ! function_exists( 'vulnhub' ) || ! class_exists( 'VulnHub_Plerion_Client' ) ) {
			return $out;
		}

		$connector = vulnhub()->connectors->get( 'plerion' );

		if ( ! $connector || ! $connector->is_enabled() ) {
			return $out;
		}

		try {
			$ref    = new ReflectionMethod( $connector, 'client' );
			$ref->setAccessible( true );
			$client = $ref->invoke( $connector );
		} catch ( \Throwable $e ) {
			return $out;
		}

		$nt   = self::nodes_table();
		$live = array();

		foreach ( (array) $wpdb->get_col( "SELECT DISTINCT account_id FROM {$nt} WHERE source = 'aws'" ) as $a ) { // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$live[ (string) $a ] = true;
		}

		$now  = vh_now();
		$seen = array();

		try {
			$client->each_asset(
				array( 'providers' => 'AWS', 'resourceTypes' => implode( ',', array_keys( self::PLERION_NET_TYPES ) ) ),
				static function ( array $r ) use ( &$out, &$seen, $live, $nt, $now, $wpdb ): void {
					$acct = (string) ( $r['providerAccountId'] ?? '' );
					$type = (string) ( $r['resourceType'] ?? '' );
					$name = (string) ( $r['resourceName'] ?? '' );

					if ( '' === $acct || isset( $live[ $acct ] ) ) {
						++$out['skipped'];
						return;
					}

					$kind = self::PLERION_NET_TYPES[ $type ] ?? '';

					if ( '' === $kind ) {
						return;
					}

					// The inventory's own id is a PRN; keep a stable, readable
					// key so a re-import updates rather than duplicates.
					$id = (string) ( $r['resourceId'] ?? '' );
					$id = '' !== $name ? $kind . ':' . $name : $kind . ':' . md5( $id );

					$wpdb->query(
						$wpdb->prepare(
							"INSERT INTO {$nt} (account_id, region, node_type, resource_id, name, vpc_id, subnet_id, private_ip, public_ip, state, sg_ids, detail, source, last_seen)
							 VALUES (%s,%s,%s,%s,%s,'','','','','','',%s,'plerion',%s)
							 ON DUPLICATE KEY UPDATE name = VALUES(name), node_type = VALUES(node_type), detail = VALUES(detail), last_seen = VALUES(last_seen)", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
							$acct,
							(string) ( $r['region'] ?? '' ),
							$kind,
							$id,
							$name,
							(string) wp_json_encode( array(
								'resource_type' => $type,
								'exposed'       => ! empty( $r['isPubliclyExposed'] ),
							) ),
							$now
						)
					);

					++$out['imported'];
					$seen[ $acct ] = true;
				}
			);
		} catch ( \Throwable $e ) {
			return $out;
		}

		$out['accounts'] = count( $seen );

		return $out;
	}

	/** Accounts that have a captured network graph. @return string[] */
	public static function accounts(): array {
		global $wpdb;
		return array_map( 'strval', (array) $wpdb->get_col( 'SELECT DISTINCT account_id FROM ' . self::sgs_table() . " WHERE account_id <> '' ORDER BY account_id" ) ); // phpcs:ignore
	}

	private static function port_label( array $r ): string {
		$proto = (string) $r['protocol'];
		if ( 'any' === $proto ) { return 'all'; }
		$from = (int) $r['from_port'];
		$to   = (int) $r['to_port'];
		if ( 0 === $from && 65535 === $to ) { return $proto . '/all'; }
		return $from === $to ? $proto . '/' . $from : $proto . '/' . $from . '-' . $to;
	}

	/**
	 * The dataflow graph for one account: security groups as nodes, inbound
	 * rules as directed edges (source -> group, port-labelled). Internet is
	 * 0.0.0.0/0; a named external CIDR is its own source node.
	 *
	 * @return array<string,mixed>
	 */
	public static function graph( string $account, string $vpc = '' ): array {
		global $wpdb;
		$sgt = self::sgs_table();
		$rt  = self::rules_table();
		$nt  = self::nodes_table();

		$where  = 'account_id = %s';
		$params = array( $account );
		if ( '' !== $vpc ) { $where .= ' AND vpc_id = %s'; $params[] = $vpc; }

		$sgs = array();
		foreach ( (array) $wpdb->get_results( $wpdb->prepare( "SELECT group_id, name, vpc_id FROM {$sgt} WHERE {$where}", ...$params ), ARRAY_A ) as $r ) { // phpcs:ignore
			$sgs[ (string) $r['group_id'] ] = array( 'id' => (string) $r['group_id'], 'name' => (string) $r['name'], 'vpc' => (string) $r['vpc_id'], 'instances' => 0, 'internet' => false );
		}

		// Instance counts per SG.
		foreach ( (array) $wpdb->get_results( $wpdb->prepare( "SELECT sg_ids FROM {$nt} WHERE account_id = %s AND node_type = 'instance'", $account ), ARRAY_A ) as $in ) { // phpcs:ignore
			foreach ( explode( ',', (string) $in['sg_ids'] ) as $g ) {
				if ( isset( $sgs[ $g ] ) ) { ++$sgs[ $g ]['instances']; }
			}
		}

		// Inbound rules -> edges, ports aggregated per source->dest.
		$emap = array();
		foreach ( (array) $wpdb->get_results( $wpdb->prepare( "SELECT group_id, protocol, from_port, to_port, source_type, source FROM {$rt} WHERE account_id = %s AND direction = 'in'", $account ), ARRAY_A ) as $ru ) { // phpcs:ignore
			$to = (string) $ru['group_id'];
			if ( ! isset( $sgs[ $to ] ) ) { continue; }

			$src   = (string) $ru['source'];
			$stype = (string) $ru['source_type'];

			if ( 'cidr' === $stype && ( '0.0.0.0/0' === $src || '::/0' === $src ) ) {
				$from = 'internet'; $ftype = 'internet'; $sgs[ $to ]['internet'] = true;
			} elseif ( 'sg' === $stype ) {
				if ( ! isset( $sgs[ $src ] ) ) { continue; }
				$from = $src; $ftype = 'sg';
			} else {
				$from = $src; $ftype = 'cidr';
			}

			$key = $ftype . '|' . $from . '|' . $to;
			if ( ! isset( $emap[ $key ] ) ) { $emap[ $key ] = array( 'from' => $from, 'from_type' => $ftype, 'to' => $to, 'ports' => array() ); }
			$emap[ $key ]['ports'][ self::port_label( $ru ) ] = true;
		}

		$edges = array();
		foreach ( $emap as $e ) {
			$labels = array_keys( $e['ports'] );
			$e['ports'] = implode( ', ', array_slice( $labels, 0, 5 ) ) . ( count( $labels ) > 5 ? ' +' . ( count( $labels ) - 5 ) : '' );
			$edges[] = $e;
		}

		$vpcs = array();
		foreach ( (array) $wpdb->get_results( $wpdb->prepare( "SELECT resource_id, name FROM {$nt} WHERE account_id = %s AND node_type = 'vpc'", $account ), ARRAY_A ) as $v ) { // phpcs:ignore
			$vpcs[ (string) $v['resource_id'] ] = (string) ( $v['name'] ?: $v['resource_id'] );
		}

		return array( 'sgs' => array_values( $sgs ), 'edges' => $edges, 'vpcs' => $vpcs );
	}

	/**
	 * Architecture graph for one account: real resources tiered entry ->
	 * compute -> data, plus how the account reaches the internet (IGW direct,
	 * NAT outbound, or Transit Gateway to the central inspection hub).
	 *
	 * @return array<string,mixed>
	 */
	/**
	 * What an ENI belongs to, in words.
	 *
	 * AWS states this only in the interface description, in a different shape
	 * per service ("Interface for NAT Gateway nat-...", "VPC Endpoint Interface
	 * vpce-...", "ELB net/name/hash"). Reading it is how an open port gets an
	 * owner; without it the map can say a port is open but not on what.
	 *
	 * @param array<string,mixed> $eni ENI node row, `detail` already decoded.
	 * @return array{kind:string,label:string}
	 */
	private static function eni_owner( array $eni ): array {
		$d    = (array) ( $eni['detail'] ?? array() );
		$desc = (string) ( $d['desc'] ?? '' );
		$inst = (string) ( $d['instance'] ?? '' );

		if ( '' !== $inst ) {
			return array( 'kind' => 'instance', 'label' => sprintf( 'EC2 %s', $inst ) );
		}
		if ( preg_match( '/vpce-[0-9a-f]+/i', $desc, $m ) ) {
			return array( 'kind' => 'vpce', 'label' => sprintf( 'VPC endpoint %s', $m[0] ) );
		}
		if ( preg_match( '/nat-[0-9a-f]+/i', $desc, $m ) ) {
			return array( 'kind' => 'nat', 'label' => sprintf( 'NAT gateway %s', $m[0] ) );
		}
		if ( preg_match( '#ELB\s+(?:app|net)/([^/]+)#i', $desc, $m ) ) {
			return array( 'kind' => 'elb', 'label' => sprintf( 'Load balancer %s', $m[1] ) );
		}
		if ( preg_match( '#ELB\s+(.+)#i', $desc, $m ) ) {
			return array( 'kind' => 'elb', 'label' => sprintf( 'Load balancer %s', trim( $m[1] ) ) );
		}
		if ( 'lambda' === strtolower( (string) ( $d['type'] ?? '' ) ) ) {
			return array( 'kind' => 'lambda', 'label' => 'Lambda (VPC-attached)' );
		}
		if ( '' !== $desc ) {
			return array( 'kind' => 'other', 'label' => $desc );
		}

		return array( 'kind' => 'other', 'label' => (string) $eni['resource_id'] );
	}

	public static function arch_graph( string $account, string $vpc = '' ): array {
		global $wpdb;
		$cr     = $wpdb->prefix . 'vulnhub_cloud_resources';
		$assets = $wpdb->prefix . 'vulnhub_assets';
		$ple    = $wpdb->prefix . 'vulnhub_plerion_findings';
		$rt     = self::routes_table();
		$nt     = self::nodes_table();
		$rl     = self::rules_table();

		// Real EC2 facts (name tag, IPs, subnet, state, SGs) keyed by instance id.
		$inst = array();
		foreach ( (array) $wpdb->get_results( $wpdb->prepare( "SELECT resource_id, name, vpc_id, subnet_id, private_ip, public_ip, state, sg_ids FROM {$nt} WHERE account_id = %s AND node_type = 'instance'", $account ), ARRAY_A ) as $r ) { // phpcs:ignore
			$inst[ (string) $r['resource_id'] ] = $r;
		}

		// Tenable / Defender posture per instance, keyed by AWS instance id.
		$ten = array();
		foreach ( (array) $wpdb->get_results( $wpdb->prepare( "SELECT aws_instance_id, hostname, open_critical, open_high, open_medium, open_low, defender_health, last_seen, lifecycle_status FROM {$assets} WHERE aws_instance_id <> '' AND ( cloud_account_id = %s OR cloud_account_id = '' )", $account ), ARRAY_A ) as $r ) { // phpcs:ignore
			$ten[ (string) $r['aws_instance_id'] ] = $r;
		}

		// Plerion CSPM finding counts, keyed by resource name (lower-cased).
		$plemap = array();
		foreach ( (array) $wpdb->get_results( $wpdb->prepare( "SELECT LOWER(resource_name) rn, SUM( severity = 'CRITICAL' ) c, SUM( severity = 'HIGH' ) h FROM {$ple} WHERE account_id = %s AND resource_name <> '' GROUP BY rn", $account ), ARRAY_A ) as $r ) { // phpcs:ignore
			$plemap[ (string) $r['rn'] ] = array( 'c' => (int) $r['c'], 'h' => (int) $r['h'] );
		}
		$cloudguard = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$ple} WHERE account_id = %s AND ( resource_name LIKE '%%CloudGuard%%' OR resource_name LIKE '%%heckPoint%%' OR message LIKE '%%CloudGuard%%' )", $account ) ) > 0; // phpcs:ignore

		// Security-group ids that are open to the internet, and the ports each exposes.
		$open_sg = array();
		foreach ( (array) $wpdb->get_results( $wpdb->prepare( "SELECT group_id, protocol, from_port, to_port FROM {$rl} WHERE account_id = %s AND direction = 'in' AND source IN ('0.0.0.0/0','::/0')", $account ), ARRAY_A ) as $r ) { // phpcs:ignore
			$gid = (string) $r['group_id'];
			$open_sg[ $gid ][] = self::port_label( array( 'protocol' => (string) $r['protocol'], 'from_port' => (int) $r['from_port'], 'to_port' => (int) $r['to_port'] ) );
		}

		$plefor = function ( $node ) use ( $plemap ) {
			$out = array( 'c' => 0, 'h' => 0 );
			foreach ( array( strtolower( (string) ( $node['name'] ?? '' ) ), strtolower( (string) ( $node['id'] ?? '' ) ) ) as $key ) {
				if ( '' !== $key && isset( $plemap[ $key ] ) ) { $out['c'] += $plemap[ $key ]['c']; $out['h'] += $plemap[ $key ]['h']; }
			}
			return $out;
		};

		// Load balancers the AWS read actually found, by name. A balancer the
		// cloud-posture inventory still lists but AWS no longer returns is
		// either deleted or unreadable -- either way the screen must not call
		// it internet-facing on the strength of a stale record.
		$seen_lbs = array();
		foreach ( (array) $wpdb->get_col( $wpdb->prepare( "SELECT name FROM {$nt} WHERE account_id = %s AND node_type = 'elb'", $account ) ) as $nm ) { // phpcs:ignore
			$seen_lbs[ strtolower( (string) $nm ) ] = true;
		}

		$entry = array(); $compute = array(); $data = array();
		foreach ( (array) $wpdb->get_results( $wpdb->prepare( "SELECT kind, resource_id, name, exposed FROM {$cr} WHERE account_id = %s ORDER BY exposed DESC, kind, name LIMIT 800", $account ), ARRAY_A ) as $r ) { // phpcs:ignore
			$k   = (string) $r['kind'];
			$rid = (string) $r['resource_id'];

			// Plerion stores EC2 as a PRN in resource_id and the i- instance id in
			// name; the AWS capture keys on the instance id, so bridge the two.
			$iid = '';
			if ( preg_match( '/(i-[0-9a-f]+)/', (string) $r['name'] . ' ' . $rid, $m ) ) { $iid = $m[1]; }
			$lookup = '' !== $iid ? $iid : (string) $r['name'];
			$row = isset( $inst[ $lookup ] ) ? $inst[ $lookup ] : ( isset( $inst[ $rid ] ) ? $inst[ $rid ] : null );
			$id  = '' !== $iid ? $iid : $rid;

			// Prefer the real EC2 Name tag over the Plerion resource id.
			$name = $row && '' !== (string) $row['name'] ? (string) $row['name'] : (string) ( $r['name'] ?: $id );

			$node = array(
				'kind'    => $k,
				'id'      => $id,
				'name'    => $name,
				'exposed' => (int) $r['exposed'],
			);

			if ( $row ) {
				$sgids = array_filter( array_map( 'trim', explode( ',', (string) $row['sg_ids'] ) ) );
				$ports = array();
				$net_open = false;
				foreach ( $sgids as $g ) {
					if ( isset( $open_sg[ $g ] ) ) { $net_open = true; $ports = array_merge( $ports, $open_sg[ $g ] ); }
				}
				$ports = array_values( array_unique( $ports ) );
				sort( $ports );

				$node['ip']     = (string) $row['private_ip'];
				$node['pubip']  = (string) $row['public_ip'];
				$node['subnet'] = (string) $row['subnet_id'];
				$node['vpc']    = (string) $row['vpc_id'];
				$node['state']  = (string) $row['state'];
				$node['ports']  = array_slice( $ports, 0, 8 );
				// Directly reachable from the internet only if it holds a public IP;
				// otherwise an internet-open SG means it is fronted (LB / Check Point).
				$node['direct'] = '' !== (string) $row['public_ip'];
				if ( $net_open || '' !== (string) $row['public_ip'] ) { $node['exposed'] = 1; }

				if ( isset( $ten[ $id ] ) ) {
					$t = $ten[ $id ];
					$node['ten'] = array(
						'c'      => (int) $t['open_critical'],
						'h'      => (int) $t['open_high'],
						'm'      => (int) $t['open_medium'],
						'l'      => (int) $t['open_low'],
						'health' => (string) $t['defender_health'],
						'seen'   => (string) $t['last_seen'],
						'host'   => (string) $t['hostname'],
						'life'   => (string) $t['lifecycle_status'],
						'known'  => true,
					);
				}
			}

			$node['ple'] = $plefor( $node );

			if ( $node['exposed'] || in_array( $k, array( 'alb', 'apigw' ), true ) ) {
				$node['scheme'] = ( false !== stripos( $name, 'internal' ) ) ? 'internal' : 'internet-facing';

				if ( 'alb' === $k && ! isset( $seen_lbs[ strtolower( $name ) ] ) ) {
					$node['unconfirmed'] = true;
					$node['scheme']      = '';
				}

				$entry[] = $node;
			} elseif ( in_array( $k, array( 'rds', 's3', 'dynamodb' ), true ) ) {
				$data[] = $node;
			} else {
				$compute[] = $node;
			}
		}

		// Group compute by subnet so a large fleet reads as tiers, not a wall.
		usort( $compute, function ( $a, $b ) {
			return array( (string) ( $a['subnet'] ?? '' ), (string) $a['name'] ) <=> array( (string) ( $b['subnet'] ?? '' ), (string) $b['name'] );
		} );

		$routing = array( 'igw' => 0, 'nat' => 0, 'tgw' => 0 );
		foreach ( (array) $wpdb->get_results( $wpdb->prepare( "SELECT target_type tt, COUNT(*) c FROM {$rt} WHERE account_id = %s AND dest_cidr = '0.0.0.0/0' GROUP BY target_type", $account ), ARRAY_A ) as $x ) { // phpcs:ignore
			if ( isset( $routing[ (string) $x['tt'] ] ) ) { $routing[ (string) $x['tt'] ] = (int) $x['c']; }
		}
		$tgws = array_map( 'strval', (array) $wpdb->get_col( $wpdb->prepare( "SELECT DISTINCT target_id FROM {$rt} WHERE account_id = %s AND target_type = 'tgw'", $account ) ) ); // phpcs:ignore

		$vpcs = array();
		foreach ( (array) $wpdb->get_results( $wpdb->prepare( "SELECT resource_id, name FROM {$nt} WHERE account_id = %s AND node_type = 'vpc'", $account ), ARRAY_A ) as $v ) { // phpcs:ignore
			$vpcs[ (string) $v['resource_id'] ] = (string) ( $v['name'] ?: $v['resource_id'] );
		}

		$open = array();
		foreach ( (array) $wpdb->get_results( $wpdb->prepare( "SELECT DISTINCT protocol, from_port, to_port FROM {$rl} WHERE account_id = %s AND direction = 'in' AND source IN ('0.0.0.0/0','::/0') ORDER BY from_port LIMIT 20", $account ), ARRAY_A ) as $x ) { // phpcs:ignore
			$open[ self::port_label( array( 'protocol' => (string) $x['protocol'], 'from_port' => (int) $x['from_port'], 'to_port' => (int) $x['to_port'] ) ) ] = true;
		}
		$open = array_slice( array_keys( $open ), 0, 8 );

		// ---- cross-account connectivity ----
		// The Transit Gateway hub: which other accounts hang off the same TGW as
		// this one, and the named VPC peerings that wire specific workloads
		// together across account lines.
		$peers = array( 'tgw' => array(), 'pcx' => array() );

		$hub = array();
		foreach ( (array) $wpdb->get_results( $wpdb->prepare(
			"SELECT DISTINCT b.account_id acct, a.name tgw
			 FROM {$nt} a JOIN {$nt} b ON b.name = a.name AND b.node_type = 'tgw-attach' AND b.account_id <> a.account_id
			 WHERE a.account_id = %s AND a.node_type = 'tgw-attach' AND a.name <> ''",
			$account
		), ARRAY_A ) as $r ) { // phpcs:ignore
			$hub[ (string) $r['tgw'] ][] = (string) $r['acct'];
		}
		foreach ( $hub as $tgw => $accts ) {
			$accts = array_values( array_unique( $accts ) );
			sort( $accts );
			$peers['tgw'][] = array(
				'tgw'      => (string) $tgw,
				'count'    => count( $accts ),
				'accounts' => array_slice( $accts, 0, 40 ),
			);
		}

		foreach ( (array) $wpdb->get_results( $wpdb->prepare(
			"SELECT DISTINCT b.account_id peer, a.name nm, a.resource_id pcx
			 FROM {$nt} a JOIN {$nt} b ON b.resource_id = a.resource_id AND b.account_id <> a.account_id
			 WHERE a.account_id = %s AND a.node_type = 'pcx' AND b.node_type = 'pcx'
			 ORDER BY a.name LIMIT 60",
			$account
		), ARRAY_A ) as $r ) { // phpcs:ignore
			$peers['pcx'][] = array(
				'peer' => (string) $r['peer'],
				'name' => (string) $r['nm'],
				'pcx'  => (string) $r['pcx'],
			);
		}

		// ---- who actually holds an open port, and is it reachable ----
		//
		// An open security group is not an exposure until something is behind
		// it, and the ENI is the only thing that says what. Resolving it is the
		// difference between "tcp/443 open to the world" and "tcp/443 on three
		// private VPC endpoints with no route in".
		$enis = array();
		foreach ( (array) $wpdb->get_results( $wpdb->prepare( "SELECT resource_id, name, vpc_id, subnet_id, private_ip, public_ip, state, sg_ids, detail FROM {$nt} WHERE account_id = %s AND node_type = 'eni'", $account ), ARRAY_A ) as $e ) { // phpcs:ignore
			$e['detail'] = (array) json_decode( (string) $e['detail'], true );
			$enis[]      = $e;
		}

		$sg_names = array();
		foreach ( (array) $wpdb->get_results( $wpdb->prepare( "SELECT group_id, name FROM " . self::sgs_table() . " WHERE account_id = %s", $account ), ARRAY_A ) as $g ) { // phpcs:ignore
			$sg_names[ (string) $g['group_id'] ] = (string) $g['name'];
		}

		// Every public address in the account, whatever holds it.
		$public_ips = array();
		foreach ( $enis as $e ) {
			if ( '' !== (string) $e['public_ip'] ) {
				$own            = self::eni_owner( $e );
				$public_ips[ (string) $e['public_ip'] ] = array( 'ip' => (string) $e['public_ip'], 'on' => $own['label'], 'kind' => $own['kind'], 'eni' => (string) $e['resource_id'] );
			}
		}
		foreach ( (array) $wpdb->get_results( $wpdb->prepare( "SELECT resource_id, name, public_ip, detail FROM {$nt} WHERE account_id = %s AND node_type = 'eip'", $account ), ARRAY_A ) as $a ) { // phpcs:ignore
			$ip = (string) $a['public_ip'];
			if ( '' === $ip ) { continue; }
			$d   = (array) json_decode( (string) $a['detail'], true );
			$on  = '';
			foreach ( $enis as $e ) {
				if ( (string) $e['resource_id'] === (string) ( $d['eni'] ?? '' ) ) { $o = self::eni_owner( $e ); $on = $o['label']; break; }
			}
			$public_ips[ $ip ] = array(
				'ip'   => $ip,
				'on'   => $on ?: ( (string) $a['name'] ?: 'unattached Elastic IP' ),
				'kind' => '' !== $on ? 'eip' : 'unattached',
				'name' => (string) $a['name'],
			);
		}
		$public_ips = array_values( $public_ips );

		// Each world-open rule, resolved to the interfaces that carry its group.
		$inbound = array();
		foreach ( (array) $wpdb->get_results( $wpdb->prepare( "SELECT group_id, protocol, from_port, to_port, source FROM {$rl} WHERE account_id = %s AND direction = 'in' AND source IN ('0.0.0.0/0','::/0') ORDER BY from_port LIMIT 40", $account ), ARRAY_A ) as $r ) { // phpcs:ignore
			$gid     = (string) $r['group_id'];
			$targets = array();
			$reach   = false;

			foreach ( $enis as $e ) {
				$on_eni = in_array( $gid, array_filter( array_map( 'trim', explode( ',', (string) $e['sg_ids'] ) ) ), true );
				if ( ! $on_eni ) { continue; }
				$own       = self::eni_owner( $e );
				$has_pub   = '' !== (string) $e['public_ip'];
				$reach     = $reach || $has_pub;
				$targets[] = array(
					'label'  => $own['label'],
					'kind'   => $own['kind'],
					'ip'     => (string) $e['private_ip'],
					'pubip'  => (string) $e['public_ip'],
					'subnet' => (string) $e['subnet_id'],
					'eni'    => (string) $e['resource_id'],
				);
			}

			foreach ( $inst as $iid => $row ) {
				if ( in_array( $gid, array_filter( array_map( 'trim', explode( ',', (string) $row['sg_ids'] ) ) ), true ) ) {
					$has_pub   = '' !== (string) $row['public_ip'];
					$reach     = $reach || $has_pub;
					$targets[] = array(
						'label'  => sprintf( 'EC2 %s', (string) ( $row['name'] ?: $iid ) ),
						'kind'   => 'instance',
						'ip'     => (string) $row['private_ip'],
						'pubip'  => (string) $row['public_ip'],
						'subnet' => (string) $row['subnet_id'],
						'eni'    => '',
					);
				}
			}

			$inbound[] = array(
				'port'      => self::port_label( array( 'protocol' => (string) $r['protocol'], 'from_port' => (int) $r['from_port'], 'to_port' => (int) $r['to_port'] ) ),
				'source'    => (string) $r['source'],
				'sg'        => $gid,
				'sg_name'   => (string) ( $sg_names[ $gid ] ?? '' ),
				'targets'   => $targets,
				'reachable' => $reach,
			);
		}

		// A balancer with an internet-facing scheme is a real front door even
		// when it carries no security group of its own (network balancers often
		// do not), so its listeners count as an inbound path.
		$lbs = array();
		foreach ( (array) $wpdb->get_results( $wpdb->prepare( "SELECT resource_id, name, vpc_id, state, sg_ids, detail FROM {$nt} WHERE account_id = %s AND node_type = 'elb'", $account ), ARRAY_A ) as $l ) { // phpcs:ignore
			$d     = (array) json_decode( (string) $l['detail'], true );
			$lbs[] = array(
				'id'        => (string) $l['resource_id'],
				'name'      => (string) $l['name'],
				'dns'       => (string) ( $d['dns'] ?? '' ),
				'scheme'    => (string) ( $d['scheme'] ?? '' ),
				'lbtype'    => (string) ( $d['lbtype'] ?? '' ),
				'listeners' => array_values( (array) ( $d['listeners'] ?? array() ) ),
				'vpc'       => (string) $l['vpc_id'],
			);
		}
		$lb_facing = array_values( array_filter( $lbs, static fn( $l ) => 'internet-facing' === $l['scheme'] ) );

		// ---- direct vs inspected, from the route table and nothing else ----
		//
		// This used to flip to "inspected" on a Plerion finding whose resource
		// name merely contained "CloudGuard" -- so an account whose default
		// route went straight out of the internet gateway was labelled as
		// inspected by Check Point because it happened to hold an IAM role of
		// that name. A role name is not a data path. The routing table is.
		$inspected = $routing['tgw'] > 0;
		$direct    = $routing['igw'] > 0;

		$igw_default = (string) $wpdb->get_var( $wpdb->prepare( "SELECT target_id FROM {$rt} WHERE account_id = %s AND dest_cidr = '0.0.0.0/0' AND target_type = 'igw' LIMIT 1", $account ) ); // phpcs:ignore
		$nat_default = (string) $wpdb->get_var( $wpdb->prepare( "SELECT target_id FROM {$rt} WHERE account_id = %s AND dest_cidr = '0.0.0.0/0' AND target_type = 'nat' LIMIT 1", $account ) ); // phpcs:ignore
		$igw_total   = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$nt} WHERE account_id = %s AND node_type = 'igw'", $account ) ); // phpcs:ignore

		// Is there any way in at all? Only if something open is reachable, or an
		// internet-facing balancer is listening.
		$reachable_in = ! empty( $lb_facing );
		foreach ( $inbound as $i ) { $reachable_in = $reachable_in || $i['reachable']; }

		$exposure = array(
			'inbound'      => $inbound,
			'public_ips'   => $public_ips,
			'lbs'          => $lbs,
			'inbound_path' => $reachable_in,
			'igw_default'  => $igw_default,
			'nat_default'  => $nat_default,
			'igw_total'    => $igw_total,
			'cloudguard'   => $cloudguard,
		);

		return array(
			'account'    => $account,
			'entry'      => $entry,
			'compute'    => $compute,
			'data'       => $data,
			'routing'    => $routing,
			'tgws'       => $tgws,
			'vpcs'       => $vpcs,
			'open_ports' => $open,
			'inspected'  => $inspected,
			'direct'     => $direct,
			'exposure'   => $exposure,
			'cloudguard' => $cloudguard,
			'peers'      => $peers,
		);
	}

	/**
	 * The inline inspection stack: the gateway load balancer and what is behind it.
	 *
	 * Only the appliances in the account that owns the gateway load balancer
	 * count. Every auto-scaling group in the estate arrives through the same
	 * posture import, and one of them is the posture vendor's own scanning
	 * appliance sitting in its own account -- which is not a firewall and is
	 * not in anybody's data path. Tying the set to the load balancer's account
	 * is the data-driven cut; matching on what things are named is the mistake
	 * this file already records once.
	 *
	 * `accounts` is the same cut expressed as a lookup, which is what makes an
	 * EC2 instance an appliance rather than a server. It is an account-level
	 * answer, so a non-appliance instance in the inspection account would be
	 * counted as a device: group membership would be the exact signal, and it
	 * is not captured. On this estate the account holds nothing else.
	 *
	 * Read once per request -- `estate_flow()` asks twice, for the counts and
	 * then for the firewall band.
	 *
	 * @return array{gwlbs:array<int,array<string,string>>,firewalls:array<int,array<string,string>>,accounts:array<string,bool>}
	 */
	/**
	 * Accounts that hold the inline inspection appliances -- the account that
	 * owns the gateway load balancer, never a name. Their instances are vendor
	 * appliances: nothing takes an agent there.
	 *
	 * @return string[]
	 */
	public static function appliance_accounts(): array {
		return array_map( 'strval', array_keys( self::inspection_stack()['accounts'] ) );
	}

	private static function inspection_stack(): array {
		static $cache = null;

		if ( null !== $cache ) {
			return $cache;
		}

		global $wpdb;
		$nt         = self::nodes_table();
		$appliances = array();

		foreach ( (array) $wpdb->get_results( "SELECT node_type, name, account_id FROM {$nt} WHERE node_type IN ('elb','asg') AND source = 'plerion'", ARRAY_A ) as $r ) { // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$appliances[] = array(
				'type' => (string) $r['node_type'],
				'name' => (string) $r['name'],
				'acct' => (string) $r['account_id'],
			);
		}

		$gwlbs    = array_values( array_filter( $appliances, static fn( array $a ): bool => 'elb' === $a['type'] ) );
		$accounts = array();

		foreach ( $gwlbs as $g ) {
			$accounts[ (string) $g['acct'] ] = true;
		}

		$cache = array(
			'gwlbs'     => $gwlbs,
			'accounts'  => $accounts,
			'firewalls' => array_values(
				array_filter(
					$appliances,
					static fn( array $a ): bool => 'asg' === $a['type'] && isset( $accounts[ (string) $a['acct'] ] )
				)
			),
		);

		return $cache;
	}

	/**
	 * Is this thing a device, or something running on one?
	 *
	 * The diagram was mixing the two. An elastic network interface was being
	 * listed beside servers, and a NAT gateway was being counted as if it were
	 * a host -- which is like putting a patch-panel port and a switch in the
	 * same inventory as the database server plugged into them.
	 *
	 * The test is what the thing would be if the estate were built out of
	 * metal: would it be its own box in a rack?
	 *
	 * | AWS                                  | In a rack                    | Class    |
	 * |--------------------------------------|------------------------------|----------|
	 * | internet gateway                     | border router                | network  |
	 * | NAT gateway                          | NAT router                   | network  |
	 * | transit gateway                      | core router                  | network  |
	 * | load balancer (app / net / gateway)  | load-balancer appliance      | network  |
	 * | VPC endpoint                         | service proxy                | network  |
	 * | EC2 in the inspection stack          | the firewall appliance       | network  |
	 * | WorkSpaces desktop                   | a desk, not a rack           | desktop  |
	 * | **any other EC2**                    | **a server**                 | server   |
	 * | **elastic network interface**        | **a NIC — a port on a box**  | **none** |
	 *
	 * An interface is deliberately never a device. It is a port, and it always
	 * belongs to one of the rows above; resolving it to its owner is what
	 * `estate_flow()` does before anything gets counted.
	 *
	 * **An EC2 instance is a server.** It was briefly classed by
	 * `sourceDestCheck`, on the reasoning that an instance forwarding traffic
	 * for other hosts is a hop rather than a host. That is true of the packet
	 * and wrong about the estate: a box someone patches, backs up and owns is
	 * a server whatever it does with a route, and moving a handful of them out
	 * of the server count made the fleet smaller than it is. The single
	 * exception is the inline firewall, which happens to be a vendor appliance
	 * shipped as an AMI -- nobody administers it as a server, and it is the
	 * one EC2 that genuinely belongs in the network cabinet.
	 *
	 * That exception is decided by `inspection_stack()`, from the account that
	 * owns the gateway load balancer -- not from what anything is called.
	 *
	 * @param string $kind      What the resource is (`nat_gateway`, `instance`, …).
	 * @param bool   $appliance This instance is part of the inspection stack.
	 */
	public static function device_class( string $kind, bool $appliance = false ): string {
		$network = array( 'nat_gateway', 'nat', 'igw', 'tgw', 'elb', 'load_balancer', 'network_load_balancer', 'gateway_load_balancer', 'vpce', 'vpc_endpoint', 'asg' );

		if ( in_array( $kind, $network, true ) ) {
			return 'network';
		}

		if ( 'workspace' === $kind ) {
			return 'desktop';
		}

		if ( 'instance' === $kind ) {
			return $appliance ? 'network' : 'server';
		}

		return 'server';
	}

	/** What to call each class on screen. */
	public static function device_label( string $class ): string {
		return match ( $class ) {
			'network' => __( 'network device', 'vulnhub' ),
			'desktop' => __( 'virtual desktop', 'vulnhub' ),
			default   => __( 'server', 'vulnhub' ),
		};
	}

	/**
	 * How an internet-bound default route is read as a path off the internet.
	 *
	 * The route table says which one applies; nothing here is matched on a
	 * resource's name. A Gateway Load Balancer endpoint is a `vpce-` sitting
	 * in the `gatewayId` of a `0.0.0.0/0` route, which is exactly how an
	 * inline inspection appliance is wired, so that is what it is called --
	 * not "Check Point", which would be reading a vendor into a route id.
	 * Where the appliance's own name is captured it is shown on the node.
	 *
	 * @return array<string,array<string,string>>
	 */
	private static function path_kinds(): array {
		return array(
			'inspected' => array(
				'kind'  => 'firewall',
				'label' => __( 'Inspected — gateway load-balancer endpoint', 'vulnhub' ),
				'help'  => __( 'The VPC sends everything internet-bound to a gateway load-balancer endpoint, which is how an inline inspection appliance is wired in. Inbound and outbound both pass through it.', 'vulnhub' ),
			),
			'appliance' => array(
				'kind'  => 'firewall',
				'label' => __( 'Inspected — inline appliance', 'vulnhub' ),
				'help'  => __( 'The default route points at a network interface, so a virtual appliance in this VPC is in the path.', 'vulnhub' ),
			),
			'transit'   => array(
				'kind'  => 'tgw',
				'label' => __( 'Via transit gateway', 'vulnhub' ),
				'help'  => __( 'Everything internet-bound leaves through a transit gateway, so the egress and any inspection happen in whichever account owns that hub — not here.', 'vulnhub' ),
			),
			'direct'    => array(
				'kind'  => 'igw',
				'label' => __( 'Direct — internet gateway', 'vulnhub' ),
				'help'  => __( 'The default route goes straight out of an internet gateway. Anything in this VPC holding a public address is reachable from the internet with nothing in between.', 'vulnhub' ),
			),
			'egress'    => array(
				'kind'  => 'nat',
				'label' => __( 'Outbound only — NAT gateway', 'vulnhub' ),
				'help'  => __( 'The default route is a NAT gateway: these workloads can start a connection outwards, and nothing on the internet can start one inwards.', 'vulnhub' ),
			),
		);
	}

	/** Which path a default route represents, from its target. '' = not a path. */
	private static function path_for_route( string $target_type, string $target_id ): string {
		if ( 'tgw' === $target_type || 0 === strpos( $target_id, 'tgw-' ) ) {
			return 'transit';
		}
		if ( 'igw' === $target_type || 0 === strpos( $target_id, 'igw-' ) ) {
			return 'direct';
		}
		if ( 'nat' === $target_type || 0 === strpos( $target_id, 'nat-' ) ) {
			return 'egress';
		}
		if ( 0 === strpos( $target_id, 'vpce-' ) ) {
			return 'inspected';
		}
		if ( 'eni' === $target_type || 0 === strpos( $target_id, 'eni-' ) ) {
			return 'appliance';
		}

		return '';
	}

	/**
	 * The whole estate as one tree, rooted at the internet.
	 *
	 * The per-account map answers "how is this account wired". This answers
	 * the question you cannot ask it 43 accounts at a time: **by what route
	 * does anything here meet the internet, and what is behind each one.**
	 *
	 * Three things shape it:
	 *
	 * - **The branches are paths, and a path is a property of a VPC's route
	 *   table, not of an account.** So the first level under the internet is
	 *   how traffic actually leaves -- an inspection endpoint, a transit
	 *   gateway, an internet gateway, a NAT gateway -- and a VPC appears under
	 *   every path its own route tables really have. A VPC with a public
	 *   subnet and a private one has two, and showing it once would be picking
	 *   which half to tell you about.
	 * - **No route tables as nodes.** They decide the shape and then stay out
	 *   of it; a route table is not a thing anyone is looking for on a map of
	 *   what is exposed.
	 * - **Applications and data sit apart, and say why.** The posture
	 *   inventory records no VPC for Lambda, ECS, load balancers, RDS, S3 or
	 *   DynamoDB, so hanging them under a network path would be an invention.
	 *   They get their own branch, per account, labelled for what it is.
	 *
	 * Everything is returned in one payload and the browser expands branches
	 * from it, so opening one costs nothing and there is no spinner on a
	 * click. Only leaf lists are capped.
	 *
	 * @return array<string,mixed>
	 */
	public static function estate_tree(): array {
		global $wpdb;

		$nt     = self::nodes_table();
		$rt     = self::routes_table();
		$rl     = self::rules_table();
		$cr     = $wpdb->prefix . 'vulnhub_cloud_resources';
		$assets = $wpdb->prefix . 'vulnhub_assets';
		$acct_t = $wpdb->prefix . 'vulnhub_aws_accounts';

		/* ---- labels ---- */
		$labels = array();
		foreach ( (array) $wpdb->get_results( "SELECT account_id, label FROM {$acct_t}", ARRAY_A ) as $r ) { // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			if ( '' !== (string) $r['label'] ) {
				$labels[ (string) $r['account_id'] ] = (string) $r['label'];
			}
		}

		$vpc_names = array();
		foreach ( (array) $wpdb->get_results( "SELECT account_id, resource_id, name FROM {$nt} WHERE node_type = 'vpc'", ARRAY_A ) as $r ) { // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$vpc_names[ $r['account_id'] . '|' . $r['resource_id'] ] = (string) $r['name'];
		}

		/* ---- security groups open to the internet, and on which ports ---- */
		$open_sg = array();
		foreach ( (array) $wpdb->get_results( "SELECT account_id, group_id, protocol, from_port, to_port FROM {$rl} WHERE direction = 'in' AND source IN ('0.0.0.0/0','::/0')", ARRAY_A ) as $r ) { // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$open_sg[ $r['account_id'] . '|' . $r['group_id'] ][] = self::port_label(
				array( 'protocol' => (string) $r['protocol'], 'from_port' => (int) $r['from_port'], 'to_port' => (int) $r['to_port'] )
			);
		}

		/* ---- posture per instance ---- */
		$posture = array();
		foreach ( (array) $wpdb->get_results( "SELECT id, aws_instance_id, hostname, open_critical, open_high, lifecycle_status FROM {$assets} WHERE aws_instance_id <> ''", ARRAY_A ) as $r ) { // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$posture[ (string) $r['aws_instance_id'] ] = $r;
		}

		/* ---- paths, per account+VPC ---- */
		$paths   = self::path_kinds();
		$members = array();   // path => acct|vpc => [ target ids ]
		$targets = array();   // path => target id => true

		foreach ( (array) $wpdb->get_results( "SELECT account_id, vpc_id, target_type, target_id FROM {$rt} WHERE dest_cidr IN ('0.0.0.0/0','::/0')", ARRAY_A ) as $r ) { // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$path = self::path_for_route( (string) $r['target_type'], (string) $r['target_id'] );

			if ( '' === $path || '' === (string) $r['vpc_id'] ) {
				continue;
			}

			$members[ $path ][ $r['account_id'] . '|' . $r['vpc_id'] ][ (string) $r['target_id'] ] = true;
			$targets[ $path ][ (string) $r['target_id'] ]                                          = true;
		}

		/* ---- instances, by account+VPC ---- */
		$servers = array();
		$counts  = array( 'instances' => 0, 'public' => 0 );

		foreach ( (array) $wpdb->get_results( "SELECT account_id, resource_id, name, vpc_id, subnet_id, private_ip, public_ip, state, sg_ids FROM {$nt} WHERE node_type = 'instance'", ARRAY_A ) as $r ) { // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$acct  = (string) $r['account_id'];
			$id    = (string) $r['resource_id'];
			$ports = array();

			foreach ( array_filter( array_map( 'trim', explode( ',', (string) $r['sg_ids'] ) ) ) as $gid ) {
				if ( isset( $open_sg[ $acct . '|' . $gid ] ) ) {
					$ports = array_merge( $ports, $open_sg[ $acct . '|' . $gid ] );
				}
			}

			$ports = array_values( array_unique( $ports ) );
			sort( $ports );

			$public = '' !== (string) $r['public_ip'];
			$meta   = array();

			if ( $public ) {
				$meta[] = array( 'k' => __( 'Public IP', 'vulnhub' ), 'v' => (string) $r['public_ip'] );
			}
			if ( '' !== (string) $r['private_ip'] ) {
				$meta[] = array( 'k' => __( 'Private IP', 'vulnhub' ), 'v' => (string) $r['private_ip'] );
			}
			if ( '' !== (string) $r['state'] ) {
				$meta[] = array( 'k' => __( 'State', 'vulnhub' ), 'v' => (string) $r['state'] );
			}
			if ( $ports ) {
				$meta[] = array( 'k' => __( 'Open to 0.0.0.0/0', 'vulnhub' ), 'v' => implode( ', ', array_slice( $ports, 0, 8 ) ) );
			}

			$node = array(
				'id'    => $id,
				'kind'  => 'ec2',
				'label' => '' !== (string) $r['name'] ? (string) $r['name'] : $id,
				'sub'   => $id,
				'meta'  => $meta,
				'open'  => $public || (bool) $ports,
			);

			if ( isset( $posture[ $id ] ) ) {
				$node['sev'] = array(
					'c' => (int) $posture[ $id ]['open_critical'],
					'h' => (int) $posture[ $id ]['open_high'],
				);
				$node['meta'][] = array( 'k' => __( 'Lifecycle', 'vulnhub' ), 'v' => (string) $posture[ $id ]['lifecycle_status'] );
			}

			$servers[ $acct . '|' . (string) $r['vpc_id'] ][] = $node;
			++$counts['instances'];

			if ( $public ) {
				++$counts['public'];
			}
		}

		/* ---- applications and data, per account (no VPC is recorded for them) ---- */
		$app_kinds  = array( 'lambda' => 1, 'ecs' => 1, 'alb' => 1, 'apigw' => 1 );
		$data_kinds = array( 'rds' => 1, 's3' => 1, 'dynamodb' => 1 );
		$by_account = array();

		foreach ( (array) $wpdb->get_results( "SELECT account_id, kind, resource_id, name, exposed FROM {$cr} WHERE kind <> 'ec2' ORDER BY exposed DESC, kind, name", ARRAY_A ) as $r ) { // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$kind = (string) $r['kind'];
			$tier = isset( $app_kinds[ $kind ] ) ? 'apps' : ( isset( $data_kinds[ $kind ] ) ? 'data' : '' );

			if ( '' === $tier ) {
				continue;
			}

			$by_account[ (string) $r['account_id'] ][ $tier ][] = array(
				'id'    => (string) $r['resource_id'],
				'kind'  => $kind,
				'label' => '' !== (string) $r['name'] ? (string) $r['name'] : (string) $r['resource_id'],
				'sub'   => strtoupper( $kind ),
				'open'  => (bool) $r['exposed'],
				'meta'  => (bool) $r['exposed'] ? array( array( 'k' => __( 'Exposure', 'vulnhub' ), 'v' => __( 'the posture source reports this publicly exposed', 'vulnhub' ) ) ) : array(),
			);
		}

		/* ---- build ---- */
		/*
		 * Not typed `string $acct`, deliberately. An AWS account id is twelve
		 * digits, and PHP turns a numeric string used as an array key into an
		 * int -- so every key read back out of these maps arrives as an int
		 * and a typed parameter is a TypeError under strict_types. Cast on the
		 * way in and the call sites stay readable.
		 */
		$name_of = static function ( $acct ) use ( $labels ): string {
			$acct = (string) $acct;

			return isset( $labels[ $acct ] ) ? $labels[ $acct ] . ' (' . $acct . ')' : $acct;
		};

		$branches = array();

		foreach ( $paths as $path => $def ) {
			if ( empty( $members[ $path ] ) ) {
				continue;
			}

			$by_acct = array();

			foreach ( array_keys( $members[ $path ] ) as $key ) {
				list( $acct, $vpc ) = explode( '|', $key, 2 );

				$rows  = $servers[ $key ] ?? array();
				$open  = array_values( array_filter( $rows, static fn( array $n ): bool => ! empty( $n['open'] ) ) );
				$shut  = array_values( array_filter( $rows, static fn( array $n ): bool => empty( $n['open'] ) ) );
				$kids  = array();

				if ( $open ) {
					$kids[] = self::tier_node( 'open', __( 'Reachable — public address or a group open to 0.0.0.0/0', 'vulnhub' ), $open );
				}
				if ( $shut ) {
					$kids[] = self::tier_node( 'internal', __( 'Internal only', 'vulnhub' ), $shut );
				}

				$vname = (string) ( $vpc_names[ $key ] ?? '' );

				$by_acct[ $acct ][] = array(
					'id'       => $path . ':' . $key,
					'kind'     => 'vpc',
					'label'    => '' !== $vname ? $vname : $vpc,
					'sub'      => $vpc,
					'count'    => count( $rows ),
					'countfor' => _n( 'server', 'servers', count( $rows ), 'vulnhub' ),
					'meta'     => array( array( 'k' => __( 'Leaves through', 'vulnhub' ), 'v' => implode( ', ', array_keys( $members[ $path ][ $key ] ) ) ) ),
					'children' => $kids,
				);
			}

			ksort( $by_acct );
			$acct_nodes = array();
			$vpc_total  = 0;

			foreach ( $by_acct as $acct => $vpcs ) {
				usort( $vpcs, static fn( array $a, array $b ): int => strcasecmp( (string) $a['label'], (string) $b['label'] ) );
				$vpc_total += count( $vpcs );

				$acct_nodes[] = array(
					'id'       => $path . ':acct:' . $acct,
					'kind'     => 'account',
					'label'    => $name_of( $acct ),
					'count'    => count( $vpcs ),
					'countfor' => _n( 'VPC', 'VPCs', count( $vpcs ), 'vulnhub' ),
					'children' => $vpcs,
				);
			}

			$branches[] = array(
				'id'       => 'path:' . $path,
				'kind'     => (string) $def['kind'],
				'label'    => (string) $def['label'],
				'help'     => (string) $def['help'],
				'count'    => count( $acct_nodes ),
				'countfor' => _n( 'account', 'accounts', count( $acct_nodes ), 'vulnhub' ),
				'meta'     => array(
					array( 'k' => __( 'VPCs on this path', 'vulnhub' ), 'v' => (string) $vpc_total ),
					array( 'k' => __( 'Gateways', 'vulnhub' ), 'v' => implode( ', ', array_slice( array_keys( $targets[ $path ] ?? array() ), 0, 6 ) ) ),
				),
				'children' => $acct_nodes,
			);
		}

		/*
		 * Anything the branches above did not account for.
		 *
		 * A VPC lands on a branch by having an internet-bound default route.
		 * A VPC that has none -- a fully private one, or one whose route
		 * tables the read could not see -- would otherwise take its servers
		 * out of the picture entirely, and a map that quietly omits machines
		 * is worse than one that admits it cannot place them. On this estate
		 * the branch is empty, and it exists so that it cannot stop being
		 * true without saying so.
		 */
		$unplaced = array();

		foreach ( $servers as $key => $rows ) {
			foreach ( $paths as $path => $unused ) {
				if ( isset( $members[ $path ][ $key ] ) ) {
					continue 2;
				}
			}

			list( $acct, $vpc ) = explode( '|', (string) $key, 2 );
			$vname              = (string) ( $vpc_names[ $key ] ?? '' );

			$unplaced[ $acct ][] = array(
				'id'       => 'orphan:' . $key,
				'kind'     => 'vpc',
				'label'    => '' !== $vname ? $vname : $vpc,
				'sub'      => $vpc,
				'count'    => count( $rows ),
				'countfor' => _n( 'server', 'servers', count( $rows ), 'vulnhub' ),
				'children' => array( self::tier_node( 'unplaced', __( 'Servers', 'vulnhub' ), $rows ) ),
			);
		}

		if ( $unplaced ) {
			ksort( $unplaced );
			$nodes = array();

			foreach ( $unplaced as $acct => $vpcs ) {
				$nodes[] = array(
					'id'       => 'orphan:acct:' . $acct,
					'kind'     => 'account',
					'label'    => $name_of( $acct ),
					'count'    => count( $vpcs ),
					'countfor' => _n( 'VPC', 'VPCs', count( $vpcs ), 'vulnhub' ),
					'children' => $vpcs,
				);
			}

			$branches[] = array(
				'id'       => 'path:unplaced',
				'kind'     => 'service',
				'label'    => __( 'No internet-bound route recorded', 'vulnhub' ),
				'help'     => __( 'These VPCs hold servers but have no default route in the capture — either they are genuinely private, or the route tables could not be read for that account. They are listed here rather than left off the map.', 'vulnhub' ),
				'count'    => count( $nodes ),
				'countfor' => _n( 'account', 'accounts', count( $nodes ), 'vulnhub' ),
				'children' => $nodes,
			);
		}

		/* ---- the branch that is not a network path ---- */
		ksort( $by_account );
		$svc_accounts = array();
		$svc_total    = 0;

		foreach ( $by_account as $acct => $tiers ) {
			$kids = array();

			if ( ! empty( $tiers['apps'] ) ) {
				$kids[] = self::tier_node( 'apps', __( 'Applications', 'vulnhub' ), $tiers['apps'] );
			}
			if ( ! empty( $tiers['data'] ) ) {
				$kids[] = self::tier_node( 'data', __( 'Data stores', 'vulnhub' ), $tiers['data'] );
			}

			if ( ! $kids ) {
				continue;
			}

			$n          = count( $tiers['apps'] ?? array() ) + count( $tiers['data'] ?? array() );
			$svc_total += $n;

			$svc_accounts[] = array(
				'id'       => 'svc:acct:' . $acct,
				'kind'     => 'account',
				'label'    => $name_of( $acct ),
				'count'    => $n,
				'countfor' => _n( 'resource', 'resources', $n, 'vulnhub' ),
				'children' => $kids,
			);
		}

		if ( $svc_accounts ) {
			$branches[] = array(
				'id'       => 'path:services',
				'kind'     => 'service',
				'label'    => __( 'Applications and data — not placed on a network path', 'vulnhub' ),
				'help'     => __( 'Lambda, ECS, load balancers, RDS, S3 and DynamoDB come from the cloud-posture inventory, which records no VPC for them. They are listed per account rather than under a route they cannot be shown to use. Anything marked exposed is reported publicly reachable by that source.', 'vulnhub' ),
				'count'    => count( $svc_accounts ),
				'countfor' => _n( 'account', 'accounts', count( $svc_accounts ), 'vulnhub' ),
				'meta'     => array( array( 'k' => __( 'Resources', 'vulnhub' ), 'v' => (string) $svc_total ) ),
				'children' => $svc_accounts,
			);
		}

		return array(
			'generated_at' => vh_now(),
			'stats'        => array(
				'accounts'  => count( array_unique( array_merge( array_keys( $by_account ), array_map( static fn( string $k ): string => explode( '|', $k )[0], array_keys( $servers ) ) ) ) ),
				'vpcs'      => count( $vpc_names ),
				'instances' => $counts['instances'],
				'public'    => $counts['public'],
			),
			'root'         => array(
				'id'       => 'internet',
				'kind'     => 'internet',
				'label'    => __( 'Internet', 'vulnhub' ),
				'help'     => __( 'Every way anything in the estate meets the internet, read from the route tables rather than from a resource name. Open a branch to follow it.', 'vulnhub' ),
				'count'    => count( $branches ),
				'countfor' => _n( 'path', 'paths', count( $branches ), 'vulnhub' ),
				'children' => $branches,
			),
		);
	}

	/**
	 * A tier node, with its leaf list capped and the cap declared.
	 *
	 * A truncated list that does not say it is truncated is the one thing a
	 * map of an estate must not do, so the node carries both the real total
	 * and how many of them are below it.
	 *
	 * @param array<int,array<string,mixed>> $rows Leaf nodes.
	 * @return array<string,mixed>
	 */
	private static function tier_node( string $id, string $label, array $rows ): array {
		$total = count( $rows );
		$shown = array_slice( $rows, 0, self::TIER_CAP );

		return array(
			'id'       => 'tier:' . $id . ':' . wp_generate_uuid4(),
			'kind'     => 'tier',
			'label'    => $label,
			'count'    => $total,
			'countfor' => _n( 'resource', 'resources', $total, 'vulnhub' ),
			'capped'   => $total > count( $shown ) ? $total - count( $shown ) : 0,
			'children' => $shown,
		);
	}

	/**
	 * The estate as a flowchart: bands top to bottom, links between them.
	 *
	 * The tree this replaced answered "what is under here" one branch at a
	 * time. That is the wrong question for a network: nobody wants to know
	 * what is *inside* the internet, they want to know **which way traffic
	 * goes and what stands in it**. So the shape is a flowchart -- four bands,
	 * every node naming the band-above nodes it feeds -- and the renderer only
	 * has to draw what this returns.
	 *
	 * The bands, top to bottom, are destinations, then what stands in the
	 * path, then the workloads, then the data they reach. Reading upwards from
	 * a workload gives you its exit; reading down from the internet gives you
	 * everything that can be reached that way.
	 *
	 * @param string $env '' for everything, or VulnHub_AWS_Environment::PROD / NONPROD.
	 * @return array<string,mixed>
	 */
	public static function estate_flow( string $env = '' ): array {
		global $wpdb;

		$nt = self::nodes_table();
		$rt = self::routes_table();

		/* ---- names, so a VPC can be placed and labelled ---- */
		$vpc_name = array();
		$acct_of  = array();

		foreach ( (array) $wpdb->get_results( "SELECT account_id, resource_id, name FROM {$nt} WHERE node_type = 'vpc'", ARRAY_A ) as $r ) { // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$key              = $r['account_id'] . '|' . $r['resource_id'];
			$vpc_name[ $key ] = (string) $r['name'];
			$acct_of[ $key ]  = (string) $r['account_id'];
		}

		$labels = array();
		foreach ( (array) $wpdb->get_results( 'SELECT account_id, label FROM ' . $wpdb->prefix . 'vulnhub_aws_accounts', ARRAY_A ) as $r ) { // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			if ( '' !== (string) $r['label'] ) {
				$labels[ (string) $r['account_id'] ] = (string) $r['label'];
			}
		}

		/* ---- servers per VPC ---- */
		/*
		 * Counted apart from network devices, because they are different
		 * things -- but an EC2 instance is a server. The only instance that
		 * is not is the inline firewall, which is a vendor appliance that
		 * happens to be shipped as an AMI. See device_class().
		 */
		$fw_accounts = self::inspection_stack()['accounts'];
		$servers     = array();
		$devices     = array();
		$public      = array();

		foreach ( (array) $wpdb->get_results( "SELECT account_id, vpc_id, public_ip FROM {$nt} WHERE node_type = 'instance' AND source = 'aws'", ARRAY_A ) as $r ) { // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$key = $r['account_id'] . '|' . $r['vpc_id'];

			if ( 'network' === self::device_class( 'instance', isset( $fw_accounts[ (string) $r['account_id'] ] ) ) ) {
				$devices[ $key ] = ( $devices[ $key ] ?? 0 ) + 1;
			} else {
				$servers[ $key ] = ( $servers[ $key ] ?? 0 ) + 1;
			}

			if ( '' !== (string) $r['public_ip'] ) {
				$public[ $key ] = ( $public[ $key ] ?? 0 ) + 1;
			}
		}

		/*
		 * What the internet is allowed to reach, per VPC.
		 *
		 * A lane on the diagram is only half an answer without this: "traffic
		 * leaves through an internet gateway" and "tcp/443 is open to the
		 * world" are different facts, and the second is the one somebody acts
		 * on. Security groups carry their VPC, so the rules can be attributed
		 * without going near an instance.
		 */
		$sg_vpc = array();
		foreach ( (array) $wpdb->get_results( 'SELECT account_id, group_id, vpc_id FROM ' . self::sgs_table(), ARRAY_A ) as $r ) { // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$sg_vpc[ $r['account_id'] . '|' . $r['group_id'] ] = $r['account_id'] . '|' . $r['vpc_id'];
		}

		$ports = array();
		foreach ( (array) $wpdb->get_results( "SELECT account_id, group_id, direction, protocol, from_port, to_port FROM " . self::rules_table() . " WHERE source IN ('0.0.0.0/0','::/0')", ARRAY_A ) as $r ) { // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$key = $sg_vpc[ $r['account_id'] . '|' . $r['group_id'] ] ?? '';

			if ( '' === $key ) {
				continue;
			}

			$ports[ $key ][ (string) $r['direction'] ][ self::port_label( array(
				'protocol'  => (string) $r['protocol'],
				'from_port' => (int) $r['from_port'],
				'to_port'   => (int) $r['to_port'],
			) ) ] = true;
		}

		/*
		 * The addresses the internet actually arrives on. An instance's own
		 * public IP, and every interface holding one -- which is how a NAT
		 * gateway's or a balancer's address is found, since neither is an
		 * instance.
		 */
		/*
		 * The asset record behind each instance: its hostname and what is open
		 * on it. This is what turns a public address from a fact into a thing
		 * somebody can go and fix.
		 */
		$posture = array();
		foreach ( (array) $wpdb->get_results( 'SELECT id, aws_instance_id, hostname, open_critical, open_high FROM ' . $wpdb->prefix . "vulnhub_assets WHERE aws_instance_id <> ''", ARRAY_A ) as $r ) { // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$posture[ (string) $r['aws_instance_id'] ] = $r;
		}

		/*
		 * Every instance by its id, so an interface can name the server it is
		 * plugged into rather than calling itself "interface".
		 */
		$inst_by_id = array();
		foreach ( (array) $wpdb->get_results( "SELECT resource_id, name, private_ip, account_id FROM {$nt} WHERE node_type = 'instance' AND source = 'aws'", ARRAY_A ) as $r ) { // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$inst_by_id[ (string) $r['resource_id'] ] = $r;
		}

		/*
		 * A public address is only useful if you can tell whose it is.
		 *
		 * "interface" is not an answer to "which server do I go and look at",
		 * and it was all this list said. AWS writes the owner into the
		 * interface's own description for the services that have no instance
		 * -- `Interface for NAT Gateway nat-…`, `ELB net/name/hash` -- and
		 * hands back the instance id for the ones that do, so each address can
		 * be resolved to a named thing, and an instance can be followed all
		 * the way to its asset record, its hostname and its open findings.
		 */
		$entries = array();
		foreach ( (array) $wpdb->get_results( "SELECT vpc_id, account_id, node_type, resource_id, name, public_ip, detail FROM {$nt} WHERE public_ip <> '' AND node_type IN ('instance','eni')", ARRAY_A ) as $r ) { // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$key  = $r['account_id'] . '|' . $r['vpc_id'];
			$d    = (array) json_decode( (string) $r['detail'], true );
			$desc = (string) ( $d['desc'] ?? '' );
			$iid  = '';
			$what = '';
			$owner = '';

			$class = 'server';

			if ( 'instance' === (string) $r['node_type'] ) {
				$iid   = (string) $r['resource_id'];
				$class = self::device_class( 'instance', isset( $fw_accounts[ (string) $r['account_id'] ] ) );
				$what  = self::device_label( $class );
				$owner = (string) $r['name'] ?: $iid;
			} else {
				$iid = (string) ( $d['instance'] ?? '' );

				if ( '' !== $iid ) {
					$class = self::device_class( 'instance', isset( $fw_accounts[ (string) ( $inst_by_id[ $iid ]['account_id'] ?? $r['account_id'] ) ] ) );
					$what  = self::device_label( $class );
					$owner = (string) ( $inst_by_id[ $iid ]['name'] ?? $iid );
				} elseif ( preg_match( '/NAT Gateway (nat-[0-9a-f]+)/i', $desc, $m ) ) {
					$class = 'network';
					$what  = __( 'NAT gateway', 'vulnhub' );
					$owner = $m[1];
				} elseif ( preg_match( '#ELB (?:app|net)/([^/]+)/#i', $desc, $m ) ) {
					$class = 'network';
					$what  = __( 'load balancer', 'vulnhub' );
					$owner = $m[1];
				} elseif ( preg_match( '/VPC Endpoint Interface (vpce-[0-9a-f]+)/i', $desc, $m ) ) {
					$class = 'network';
					$what  = __( 'VPC endpoint', 'vulnhub' );
					$owner = $m[1];
				} elseif ( preg_match( '/Created By Amazon Workspaces/i', $desc ) ) {
					$class = 'desktop';
					$what  = __( 'WorkSpaces desktop', 'vulnhub' );
					$owner = __( 'managed by the WorkSpaces service', 'vulnhub' );
				} else {
					/*
					 * An interface with nothing attached and no description is
					 * still a port, not a device. It is labelled as one so the
					 * list never implies a machine that is not there.
					 */
					$class = 'network';
					$what  = __( 'unattached interface', 'vulnhub' );
					$owner = '' !== $desc ? $desc : __( 'no owner reported', 'vulnhub' );
				}
			}

			$entry = array(
				'ip'    => (string) $r['public_ip'],
				'what'  => $what,
				'owner' => $owner,
				'class' => $class,
			);

			// A server can be followed: hostname, open findings, and the link
			// to its asset record, which is where the work actually happens.
			if ( '' !== $iid && isset( $posture[ $iid ] ) ) {
				$entry['host']  = (string) $posture[ $iid ]['hostname'];
				$entry['asset'] = (int) $posture[ $iid ]['id'];
				$entry['sev']   = array(
					'c' => (int) $posture[ $iid ]['open_critical'],
					'h' => (int) $posture[ $iid ]['open_high'],
				);
			}

			$entries[ $key ][] = $entry;
		}

		/* ---- which path each VPC takes ---- */
		$lanes = array();

		foreach ( (array) $wpdb->get_results( "SELECT account_id, vpc_id, target_type, target_id FROM {$rt} WHERE dest_cidr IN ('0.0.0.0/0','::/0')", ARRAY_A ) as $r ) { // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$lane = self::path_for_route( (string) $r['target_type'], (string) $r['target_id'] );

			if ( '' === $lane || '' === (string) $r['vpc_id'] ) {
				continue;
			}

			$lanes[ $lane ][ $r['account_id'] . '|' . $r['vpc_id'] ] = true;
		}

		/* ---- the appliances that stand in those paths ---- */
		$inspection = self::inspection_stack();
		$gwlbs      = $inspection['gwlbs'];
		$firewalls  = $inspection['firewalls'];

		/* ---- build the bands ---- */
		$in_env = static function ( string $key ) use ( $env, $vpc_name, $labels, $acct_of ): bool {
			if ( '' === $env ) {
				return true;
			}

			$acct = $acct_of[ $key ] ?? '';

			return $env === VulnHub_AWS_Environment::classify(
				(string) ( $vpc_name[ $key ] ?? '' ),
				(string) ( $labels[ $acct ] ?? '' )
			);
		};

		$lane_def = array(
			'inspected' => array(
				'label' => __( 'Inspected — gateway load balancer', 'vulnhub' ),
				'kind'  => 'firewall',
				'up'    => 'dest-internet',
				'note'  => __( 'The VPC sends everything internet-bound into a gateway load-balancer endpoint, which is how an inline firewall is put in the path. Inbound and outbound both pass through it.', 'vulnhub' ),
			),
			'transit'   => array(
				'label' => __( 'Transit gateway — to on-premises', 'vulnhub' ),
				'kind'  => 'tgw',
				'up'    => 'dest-onprem',
				'note'  => __( 'The default route leaves through the shared transit gateway, which is how these workloads reach the corporate network rather than the internet. The hub is owned by another account, and its outbound security appliances stand in that path.', 'vulnhub' ),
			),
			'appliance' => array(
				'label' => __( 'Inline appliance', 'vulnhub' ),
				'kind'  => 'firewall',
				'up'    => 'dest-internet',
				'note'  => __( 'The default route points at a network interface, so a virtual appliance inside the VPC is in the path.', 'vulnhub' ),
			),
			'direct'    => array(
				'label' => __( 'Internet gateway — nothing in between', 'vulnhub' ),
				'kind'  => 'igw',
				'up'    => 'dest-internet',
				'note'  => __( 'Straight out of an internet gateway. Anything here holding a public address is reachable from the internet with no inspection in the way.', 'vulnhub' ),
			),
			'egress'    => array(
				'label' => __( 'NAT gateway — outbound only', 'vulnhub' ),
				'kind'  => 'nat',
				'up'    => 'dest-internet',
				'note'  => __( 'Outbound connections only. Nothing on the internet can open one inwards.', 'vulnhub' ),
			),
		);

		$has_fw   = (bool) ( $gwlbs || $firewalls );
		$mid      = array();
		$work     = array();
		$links    = array();
		$totals   = array( 'vpcs' => 0, 'servers' => 0, 'devices' => 0, 'public' => 0 );
		$used_dst = array();

		foreach ( $lane_def as $lane => $def ) {
			$keys = array_keys( $lanes[ $lane ] ?? array() );
			$keys = array_values( array_filter( $keys, $in_env ) );

			if ( ! $keys ) {
				continue;
			}

			$srv = 0;
			$dev = 0;
			$pub = 0;
			$acc = array();
			$vp  = array();

			foreach ( $keys as $k ) {
				$srv += $servers[ $k ] ?? 0;
				$dev += $devices[ $k ] ?? 0;
				$pub += $public[ $k ] ?? 0;
				$acc[ $acct_of[ $k ] ?? '' ] = true;
				$vp[] = array(
					'label'   => (string) ( $vpc_name[ $k ] ?: explode( '|', $k )[1] ),
					'sub'     => explode( '|', $k )[1],
					'account' => (string) ( $labels[ $acct_of[ $k ] ?? '' ] ?? ( $acct_of[ $k ] ?? '' ) ),
					'servers' => (int) ( $servers[ $k ] ?? 0 ),
					'devices' => (int) ( $devices[ $k ] ?? 0 ),
					'public'  => (int) ( $public[ $k ] ?? 0 ),
				);
			}

			usort( $vp, static fn( array $a, array $b ): int => $b['servers'] <=> $a['servers'] ?: strcasecmp( $a['label'], $b['label'] ) );

			$lane_in      = array();
			$lane_out     = array();
			$lane_entries = array();

			foreach ( $keys as $k ) {
				foreach ( array_keys( $ports[ $k ]['in'] ?? array() ) as $pl ) {
					$lane_in[ $pl ] = true;
				}
				foreach ( array_keys( $ports[ $k ]['out'] ?? array() ) as $pl ) {
					$lane_out[ $pl ] = true;
				}
				foreach ( $entries[ $k ] ?? array() as $e ) {
					$lane_entries[ $e['ip'] ] = $e;
				}
			}

			$lane_in  = array_keys( $lane_in );
			$lane_out = array_keys( $lane_out );
			sort( $lane_in );
			sort( $lane_out );
			$lane_ports   = $lane_in;
			$lane_entries = array_values( $lane_entries );

			usort( $lane_entries, static fn( array $a, array $b ): int => strcmp( $a['ip'], $b['ip'] ) );

			$totals['vpcs']   += count( $keys );
			$totals['servers'] = $totals['servers'] + $srv;
			$totals['devices'] = ( $totals['devices'] ?? 0 ) + $dev;
			$totals['public']  = $totals['public'] + $pub;

			$mid_id = 'path-' . $lane;
			$meta   = array();

			$mid[] = array(
				'id'      => $mid_id,
				'kind'    => (string) $def['kind'],
				'label'   => (string) $def['label'],
				'note'    => (string) $def['note'],
				'count'   => count( $keys ),
				'unit'    => _n( 'VPC', 'VPCs', count( $keys ), 'vulnhub' ),
				'accounts'=> count( $acc ),
				'meta'    => $meta,
			);

			$work[] = array(
				'id'      => 'work-' . $lane,
				'kind'    => 'vpc',
				'label'   => sprintf(
					/* translators: 1: VPC count, 2: account count. */
					_n( '%1$d VPC in %2$d account', '%1$d VPCs in %2$d accounts', count( $keys ), 'vulnhub' ),
					count( $keys ),
					count( $acc )
				),
				'servers' => $srv,
				'devices' => $dev,
				'public'  => $pub,
				'vpcs'    => $vp,
				'ports'   => $lane_in,
				'ports_out' => $lane_out,
				'entries' => array_slice( $lane_entries, 0, 60 ),
				'entries_total' => count( $lane_entries ),
			);

			/*
			 * No label between a workload and its lane: the ports are already
			 * chips on the card directly below the line, and printing them
			 * twice within an inch of each other is noise, not emphasis.
			 */
			$links[] = array( 'from' => 'work-' . $lane, 'to' => $mid_id, 'label' => '' );

			/*
			 * Upwards, the label carries both directions, because "what can
			 * reach in" and "what can get out" are different questions and a
			 * firewall is bought to answer the second as much as the first.
			 */
			$both = static function ( array $in, array $out ): string {
				$fmt = static function ( array $set ): string {
					if ( ! $set ) {
						return __( 'none', 'vulnhub' );
					}
					if ( in_array( 'all', $set, true ) ) {
						return __( 'ALL', 'vulnhub' );
					}

					return implode( ' ', array_slice( $set, 0, 3 ) ) . ( count( $set ) > 3 ? sprintf( ' +%d', count( $set ) - 3 ) : '' );
				};

				return sprintf(
					/* translators: 1: inbound ports, 2: outbound ports. */
					__( 'in %1$s · out %2$s', 'vulnhub' ),
					$fmt( $in ),
					$fmt( $out )
				);
			};

			$ports_label = $both( $lane_in, $lane_out );

			/*
			 * A lane that is inspected hands off to the firewall, and the
			 * firewall is what reaches the destination. Drawing the lane
			 * straight to the internet would put the appliance beside the
			 * path it actually stands in.
			 */
			if ( $has_fw && in_array( $lane, array( 'inspected', 'transit' ), true ) ) {
				$links[] = array( 'from' => $mid_id, 'to' => 'fw-stack', 'label' => $ports_label );

				/*
				 * The hub also carries the corporate network, which does not
				 * go out to the internet at all. Deliberately a different
				 * label from the one above it: the same text twice on two
				 * lines out of one card reads as a rendering fault, and the
				 * ports are already stated on the edge into the firewall.
				 */
				if ( 'transit' === $lane ) {
					$links[] = array( 'from' => $mid_id, 'to' => 'dest-onprem', 'label' => __( 'to the corporate network', 'vulnhub' ) );
				}
			} else {
				$out_label = match ( $lane ) {
					'egress' => sprintf(
						/* translators: %s: outbound port summary. */
						__( 'outbound only · %s', 'vulnhub' ),
						$lane_out ? ( in_array( 'all', $lane_out, true ) ? __( 'ALL', 'vulnhub' ) : implode( ' ', array_slice( $lane_out, 0, 3 ) ) ) : __( 'none', 'vulnhub' )
					),
					'direct' => $lane_entries
						? sprintf(
							/* translators: 1: number of public addresses, 2: port summary. */
							_n( '%1$d public address · %2$s', '%1$d public addresses · %2$s', count( $lane_entries ), 'vulnhub' ),
							count( $lane_entries ),
							$ports_label
						)
						: $ports_label,
					default  => $ports_label,
				};

				$links[] = array( 'from' => $mid_id, 'to' => (string) $def['up'], 'label' => $out_label );
			}

			$used_dst[ 'transit' === $lane ? 'dest-onprem' : 'dest-internet' ] = true;
		}

		/*
		 * The firewall is a band of its own, above the lanes that feed it.
		 *
		 * It was a lane beside them, which put the appliance next to the path
		 * it actually stands in -- and left the transit gateway looking like a
		 * peer of the internet gateway when it is one of the things sitting
		 * behind the firewall. Everything inspected now hands upwards to this,
		 * and only this reaches the internet.
		 */
		$fw = array();

		if ( $has_fw ) {
			$fw_meta = array();

			if ( $gwlbs ) {
				$fw_meta[] = array( 'k' => __( 'Load balancer', 'vulnhub' ), 'v' => implode( ', ', array_column( $gwlbs, 'name' ) ) );
			}
			if ( $firewalls ) {
				$fw_meta[] = array(
					'k' => _n( 'Appliance', 'Appliances', count( $firewalls ), 'vulnhub' ),
					'v' => implode( ', ', array_map( static fn( array $a ): string => vh_trim( (string) $a['name'], 34 ), $firewalls ) ),
				);
			}
			if ( $stack ) {
				$fw_meta[] = array( 'k' => __( 'Runs in', 'vulnhub' ), 'v' => sprintf( /* translators: %s: account id. */ __( 'account %s', 'vulnhub' ), implode( ', ', array_keys( $stack ) ) ) );
			}

			$fw[] = array(
				'id'    => 'fw-stack',
				'kind'  => 'firewall',
				'label' => __( 'Check Point — inline firewall', 'vulnhub' ),
				'note'  => __( 'Everything on the inspected lanes passes through here, inbound and outbound. The appliances and the load balancer in front of them run in the network account; which appliance serves which attachment is decided by transit-gateway route tables that live in that account, so that mapping is not captured here.', 'vulnhub' ),
				'meta'  => $fw_meta,
			);

			$links[]                        = array( 'from' => 'fw-stack', 'to' => 'dest-internet', 'label' => __( 'inspected both ways', 'vulnhub' ) );
			$used_dst['dest-internet']      = true;
		}

		$dest = array();

		if ( isset( $used_dst['dest-internet'] ) ) {
			$dest[] = array( 'id' => 'dest-internet', 'kind' => 'internet', 'label' => __( 'Internet', 'vulnhub' ) );
		}
		if ( isset( $used_dst['dest-onprem'] ) ) {
			$dest[] = array( 'id' => 'dest-onprem', 'kind' => 'onprem', 'label' => __( 'On-premises', 'vulnhub' ) );
		}

		return array(
			'env'    => $env,
			'label'  => VulnHub_AWS_Environment::label( $env ),
			'totals' => $totals,
			'bands'  => array(
				array( 'id' => 'dest', 'label' => __( 'Where it goes', 'vulnhub' ), 'nodes' => $dest ),
				array( 'id' => 'fw', 'label' => __( 'Inline firewall', 'vulnhub' ), 'nodes' => $fw ),
				array( 'id' => 'mid', 'label' => __( 'How it leaves the VPC', 'vulnhub' ), 'nodes' => $mid ),
				array( 'id' => 'work', 'label' => __( 'Workloads', 'vulnhub' ), 'nodes' => $work ),
			),
			'links'  => $links,
		);
	}

	/** Leaves listed under one tier before the rest are summarised as a count. */
	private const TIER_CAP = 250;

	/** @return array{accounts:int,instances:int,sgs:int,rules:int} */
	public static function summary(): array {
		global $wpdb;
		return array(
			'accounts'  => (int) $wpdb->get_var( 'SELECT COUNT(DISTINCT account_id) FROM ' . self::nodes_table() ), // phpcs:ignore
			'instances' => (int) $wpdb->get_var( "SELECT COUNT(*) FROM " . self::nodes_table() . " WHERE node_type='instance'" ), // phpcs:ignore
			'sgs'       => (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . self::sgs_table() ), // phpcs:ignore
			'rules'     => (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . self::rules_table() ), // phpcs:ignore
		);
	}
}
