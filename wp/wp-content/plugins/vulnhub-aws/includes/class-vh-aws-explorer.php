<?php
/**
 * Org-wide discovery through AWS Resource Explorer.
 *
 * The per-account role path answers reachability but has to be trusted by each
 * member account one role at a time. Resource Explorer answers a narrower
 * question -- what exists and where -- but answers it for the whole
 * organisation from a single identity in the central account, because the
 * aggregator index is replicated there. No AssumeRole, no per-account trust.
 *
 * What it returns is an index entry, not a configuration: ARN, type, region,
 * owning account and tags. So this inventories assets and security groups
 * across every account; it does NOT return security-group rules or instance
 * exposure -- those are not in the index and stay on the role path. The two
 * are complementary, not alternatives.
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Reads the organisation's resource inventory from Resource Explorer.
 */
final class VulnHub_AWS_Explorer {

	/**
	 * The resource types worth inventorying: the assets and the firewall
	 * groups. Queried one type at a time so each Search stays well inside the
	 * result ceiling and one denied type does not blank the others.
	 */
	public const TYPES = array(
		'ec2:instance',
		'ec2:security-group',
		'ec2:network-interface',
		'elasticloadbalancing:loadbalancer',
	);

	private VulnHub_AWS_Client $client;
	private string $region;
	private string $view_arn;

	public function __construct( VulnHub_AWS_Client $client, string $region, string $view_arn = '' ) {
		$this->client   = $client;
		$this->region   = '' !== $region ? $region : 'us-east-1';
		$this->view_arn = $view_arn;
	}

	/**
	 * One page of resource-explorer-2:Search.
	 *
	 * @return array{ok:bool,status:int,data:array<string,mixed>,error:string}
	 */
	private function page( string $query, string $token ): array {
		$body = array(
			'QueryString' => $query,
			'MaxResults'  => 100,
		);

		if ( '' !== $this->view_arn ) {
			$body['ViewArn'] = $this->view_arn;
		}

		if ( '' !== $token ) {
			$body['NextToken'] = $token;
		}

		return $this->client->json( 'resource-explorer-2', $this->region, '/Search', $body );
	}

	/**
	 * Shape one Search result into an inventory row.
	 *
	 * @param array<string,mixed> $r Raw Search resource.
	 * @return array<string,mixed>
	 */
	private static function normalise( array $r ): array {
		$arn  = (string) ( $r['Arn'] ?? '' );
		$tags = array();
		$name = '';

		foreach ( (array) ( $r['Properties'] ?? array() ) as $p ) {
			if ( 'tags' !== ( $p['Name'] ?? '' ) ) {
				continue;
			}

			foreach ( (array) ( $p['Data'] ?? array() ) as $tag ) {
				$k = (string) ( $tag['Key'] ?? '' );

				if ( '' === $k ) {
					continue;
				}

				$tags[ $k ] = (string) ( $tag['Value'] ?? '' );

				if ( 'Name' === $k ) {
					$name = (string) ( $tag['Value'] ?? '' );
				}
			}
		}

		// No Name tag: fall back to the resource id at the tail of the ARN, so
		// the row is still recognisable in a list.
		if ( '' === $name && '' !== $arn ) {
			$tail = strrchr( $arn, '/' );
			$name = false !== $tail ? substr( $tail, 1 ) : ( strrchr( $arn, ':' ) ? substr( strrchr( $arn, ':' ), 1 ) : $arn );
		}

		return array(
			'arn'              => $arn,
			'account_id'       => (string) ( $r['OwningAccountId'] ?? '' ),
			'region'           => (string) ( $r['Region'] ?? '' ),
			'service'          => (string) ( $r['Service'] ?? '' ),
			'resource_type'    => (string) ( $r['ResourceType'] ?? '' ),
			'name'             => $name,
			'tags'             => $tags,
			'last_reported_at' => (string) ( $r['LastReportedAt'] ?? '' ),
		);
	}

	/**
	 * Enumerate one resource type across the org, upserting each row.
	 *
	 * @param array<string,bool> $accounts Collects the distinct owning accounts seen.
	 * @return array{ok:bool,count:int,error:string}
	 */
	public function collect( string $resource_type, string $now, array &$accounts ): array {
		$query = 'resourcetype:' . $resource_type;
		$token = '';
		$count = 0;

		do {
			$res = $this->page( $query, $token );

			if ( empty( $res['ok'] ) ) {
				return array(
					'ok'    => false,
					'count' => $count,
					'error' => (string) $res['error'],
				);
			}

			$data = (array) $res['data'];

			foreach ( (array) ( $data['Resources'] ?? array() ) as $raw ) {
				$row = self::normalise( (array) $raw );

				if ( '' === $row['arn'] ) {
					continue;
				}

				VulnHub_AWS_Inventory::upsert( $row, $now );

				if ( '' !== $row['account_id'] ) {
					$accounts[ $row['account_id'] ] = true;
				}

				++$count;
			}

			$token = (string) ( $data['NextToken'] ?? '' );
		} while ( '' !== $token );

		return array(
			'ok'    => true,
			'count' => $count,
			'error' => '',
		);
	}

	/**
	 * A cheap read to prove Search works and show how wide the view is.
	 *
	 * @return array{ok:bool,sample:int,accounts:int,error:string}
	 */
	public function probe(): array {
		$res = $this->page( 'resourcetype:ec2:security-group', '' );

		if ( empty( $res['ok'] ) ) {
			return array(
				'ok'       => false,
				'sample'   => 0,
				'accounts' => 0,
				'error'    => (string) $res['error'],
			);
		}

		$data     = (array) $res['data'];
		$resources = (array) ( $data['Resources'] ?? array() );
		$accounts = array();

		foreach ( $resources as $raw ) {
			$a = (string) ( $raw['OwningAccountId'] ?? '' );

			if ( '' !== $a ) {
				$accounts[ $a ] = true;
			}
		}

		return array(
			'ok'       => true,
			'sample'   => count( $resources ),
			'accounts' => count( $accounts ),
			'error'    => '',
		);
	}

	/**
	 * Full inventory run over every type we care about.
	 *
	 * @return array{ok:bool,per_type:array<string,int>,accounts:int,pruned:int,errors:array<string,string>,calls:int}
	 */
	public function sync(): array {
		$now      = gmdate( 'Y-m-d H:i:s' );
		$accounts = array();
		$per_type = array();
		$errors   = array();

		foreach ( self::TYPES as $type ) {
			$r = $this->collect( $type, $now, $accounts );

			$per_type[ $type ] = (int) $r['count'];

			if ( empty( $r['ok'] ) ) {
				$errors[ $type ] = (string) $r['error'];
			}
		}

		// Only prune when every type read cleanly. A transient denial on one
		// type would otherwise delete that whole slice of the inventory.
		$pruned = $errors ? 0 : VulnHub_AWS_Inventory::prune( $now );

		return array(
			'ok'       => empty( $errors ),
			'per_type' => $per_type,
			'accounts' => count( $accounts ),
			'pruned'   => $pruned,
			'errors'   => $errors,
			'calls'    => $this->client->calls(),
		);
	}
}
