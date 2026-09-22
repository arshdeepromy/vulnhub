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

		// Replace this account+region's slice so a re-sync reflects deletions.
		foreach ( array( self::nodes_table(), self::sgs_table(), self::rules_table(), self::routes_table() ) as $t ) {
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
						"INSERT INTO {$t} (account_id, region, node_type, resource_id, name, vpc_id, last_seen)
						 VALUES (%s,%s,%s,%s,%s,%s,%s)
						 ON DUPLICATE KEY UPDATE region=VALUES(region), node_type=VALUES(node_type), name=VALUES(name), vpc_id=VALUES(vpc_id), last_seen=VALUES(last_seen)",
						$account, $region, $type, $id, self::tag_name( $item ),
						'subnet' === $type ? (string) ( $item->vpcId ?? '' ) : $id, // phpcs:ignore
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

				$detail = array(
					'arn'       => $arn,
					'dns'       => (string) ( $lb->DNSName ?? '' ),
					'scheme'    => (string) ( $lb->Scheme ?? '' ),
					'lbtype'    => (string) ( $lb->Type ?? '' ),
					'subnets'   => array_values( array_filter( $subnets ) ),
					'listeners' => self::listeners_for( $client, $region, $arn ),
				);

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

				$ports = array();
				foreach ( $lb->ListenerDescriptions->member ?? array() as $l ) { // phpcs:ignore
					$ports[] = strtolower( (string) ( $l->Listener->Protocol ?? '' ) ) . '/' . (string) ( $l->Listener->LoadBalancerPort ?? '' );
				}
				$sgs = array();
				foreach ( $lb->SecurityGroups->member ?? array() as $g ) { $sgs[] = (string) $g; } // phpcs:ignore

				$detail = array(
					'dns'       => (string) ( $lb->DNSName ?? '' ),
					'scheme'    => (string) ( $lb->Scheme ?? '' ),
					'lbtype'    => 'classic',
					'listeners' => array_values( array_unique( array_filter( $ports ) ) ),
				);

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

	/** Listener ports for one v2 balancer. @return string[] */
	private static function listeners_for( VulnHub_AWS_Client $client, string $region, string $arn ): array {
		$out = array();
		$res = $client->query( 'elasticloadbalancing', $region, array( 'Action' => 'DescribeListeners', 'Version' => '2015-12-01', 'LoadBalancerArn' => $arn ) );
		if ( empty( $res['ok'] ) ) { return $out; }

		foreach ( $res['xml']->DescribeListenersResult->Listeners->member ?? array() as $l ) { // phpcs:ignore
			$out[] = strtolower( (string) ( $l->Protocol ?? '' ) ) . '/' . (string) ( $l->Port ?? '' );
		}

		return array_values( array_unique( array_filter( $out, static fn( $x ) => '/' !== $x ) ) );
	}

	/** Route tables: where each 0.0.0.0/0 (and other) route points -- IGW, NAT, TGW, peering. */
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
		}

		return $n;
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
