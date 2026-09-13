<?php
/**
 * Amazon Inspector, read-only.
 *
 * Inspector is the closest AWS-native analogue to Tenable's cloud connector:
 * it runs continuously against the account, and for EC2 it publishes both
 * package vulnerabilities and NETWORK_REACHABILITY findings that already carry
 * the open port range and the path the traffic takes in.
 *
 * That last part is the reason this class exists before any of the security
 * group plumbing. If Inspector is switched on, it has already done the work of
 * deciding what the internet can reach -- and reading its answer is far less
 * code, and far less to get wrong, than deriving reachability ourselves from
 * gateways, route tables, NACLs and security groups.
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Inspector status and findings.
 */
final class VulnHub_AWS_Inspector {

	private VulnHub_AWS_Client $client;

	public function __construct( VulnHub_AWS_Client $client ) {
		$this->client = $client;
	}

	/**
	 * Is Inspector enabled in this account and region, and for what?
	 *
	 * Asked first and separately, because "no findings" is ambiguous on its
	 * own -- it means either a clean account or a service nobody turned on,
	 * and those call for opposite next steps.
	 *
	 * @param string[] $account_ids Accounts to ask about; the caller's own when empty.
	 * @return array{ok:bool,accounts:array<int,array<string,string>>,error:string}
	 */
	public function status( string $region, array $account_ids = array() ): array {
		$body = $account_ids ? array( 'accountIds' => array_values( $account_ids ) ) : array();

		$res = $this->client->json( 'inspector2', $region, '/status/batch/get', $body );

		if ( ! $res['ok'] ) {
			return array(
				'ok'       => false,
				'accounts' => array(),
				'error'    => (string) $res['error'],
			);
		}

		$out = array();

		foreach ( (array) ( $res['data']['accounts'] ?? array() ) as $acct ) {
			$state = (array) ( $acct['state'] ?? array() );
			$per   = (array) ( $acct['resourceState'] ?? array() );

			$out[] = array(
				'account' => (string) ( $acct['accountId'] ?? '' ),
				'overall' => (string) ( $state['status'] ?? 'UNKNOWN' ),
				'ec2'     => (string) ( $per['ec2']['status'] ?? 'UNKNOWN' ),
				'ecr'     => (string) ( $per['ecr']['status'] ?? 'UNKNOWN' ),
				'lambda'  => (string) ( $per['lambda']['status'] ?? 'UNKNOWN' ),
			);
		}

		return array(
			'ok'       => true,
			'accounts' => $out,
			'error'    => '',
		);
	}

	/**
	 * Pull findings, following the pagination token.
	 *
	 * @param array<string,mixed> $filter  Inspector filterCriteria.
	 * @param int                 $max     Stop after roughly this many findings.
	 * @return array{ok:bool,findings:array<int,array<string,mixed>>,error:string}
	 */
	public function findings( string $region, array $filter = array(), int $max = 200 ): array {
		$out   = array();
		$token = '';

		do {
			$body = array( 'maxResults' => 100 );

			if ( $filter ) {
				$body['filterCriteria'] = $filter;
			}

			if ( '' !== $token ) {
				$body['nextToken'] = $token;
			}

			$res = $this->client->json( 'inspector2', $region, '/findings/list', $body );

			if ( ! $res['ok'] ) {
				// Partial results are still worth reporting on a probe.
				return array(
					'ok'       => false,
					'findings' => $out,
					'error'    => (string) $res['error'],
				);
			}

			foreach ( (array) ( $res['data']['findings'] ?? array() ) as $f ) {
				$out[] = (array) $f;
			}

			$token = (string) ( $res['data']['nextToken'] ?? '' );
		} while ( '' !== $token && count( $out ) < $max );

		return array(
			'ok'       => true,
			'findings' => $out,
			'error'    => '',
		);
	}

	/**
	 * Only the reachability findings, which is the half we cannot get anywhere
	 * else. Package vulnerabilities we already have from Tenable.
	 *
	 * @return array{ok:bool,findings:array<int,array<string,mixed>>,error:string}
	 */
	public function reachability( string $region, int $max = 200 ): array {
		return $this->findings(
			$region,
			array(
				'findingType' => array(
					array(
						'comparison' => 'EQUALS',
						'value'      => 'NETWORK_REACHABILITY',
					),
				),
			),
			$max
		);
	}

	/**
	 * Flatten one reachability finding into the fields we would actually store.
	 *
	 * @param array<string,mixed> $f Raw Inspector finding.
	 * @return array<string,mixed>
	 */
	public static function shape( array $f ): array {
		$net = (array) ( $f['networkReachabilityDetails'] ?? array() );
		$rng = (array) ( $net['openPortRange'] ?? array() );
		$res = (array) ( $f['resources'][0] ?? array() );

		$path = array();

		foreach ( (array) ( $net['networkPath']['steps'] ?? array() ) as $step ) {
			$path[] = (string) ( $step['componentType'] ?? '' );
		}

		return array(
			'instance_id' => (string) ( $res['id'] ?? '' ),
			'account'     => (string) ( $f['awsAccountId'] ?? '' ),
			'region'      => (string) ( $res['region'] ?? '' ),
			'protocol'    => (string) ( $net['protocol'] ?? '' ),
			'port_from'   => (int) ( $rng['begin'] ?? 0 ),
			'port_to'     => (int) ( $rng['end'] ?? 0 ),
			'severity'    => (string) ( $f['severity'] ?? '' ),
			'title'       => (string) ( $f['title'] ?? '' ),
			'path'        => implode( ' → ', array_filter( $path ) ),
		);
	}
}
