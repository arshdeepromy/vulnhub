<?php
/**
 * The AWS cloud connector.
 *
 * Answers the one question no other source here can: not what a host has
 * open, but who is allowed to reach it. The listening-port inventory is a
 * property of the machine; reachability is a property of the network, and on
 * AWS the network will tell you if you ask.
 *
 * Exposure is derived rather than assumed. An instance counts as reachable
 * only when the whole chain holds -- a security group admitting 0.0.0.0/0, a
 * route to an internet gateway, and an address to arrive on -- or when it sits
 * behind an internet-facing load balancer, which is the path that catches
 * instances with no public IP at all and is invisible to every other signal we
 * have.
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

use VulnHub\Core\Connector;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Reads network exposure from an AWS account.
 */
final class VulnHub_AWS_Connector extends Connector {

	public function id(): string {
		return 'aws';
	}

	public function label(): string {
		return __( 'Amazon AWS', 'vulnhub' );
	}

	public function description(): string {
		return __( 'Works out which EC2 instances the internet can actually reach, and on which ports, so a finding on an unreachable machine stops being treated like one on a published service.', 'vulnhub' );
	}

	public function icon(): string {
		return 'cloud';
	}

	public function category(): string {
		return 'cloud';
	}

	public function default_interval(): string {
		return 'hourly';
	}

	/** Nothing here is mocked yet; a fake account would teach nobody anything. */
	public function supports_mock(): bool {
		return false;
	}

	/**
	 * @return array<int,array<string,mixed>>
	 */
	public function fields(): array {
		$regions = VulnHub_AWS_Setup::suggested_regions();
		$first   = $regions[0] ?? 'us-east-1';

		return array(
			// Guidance first, spanning both columns, so the steps read as
			// steps rather than as help text hanging off one input.
			array(
				'key'  => 'setup',
				'type' => 'note',
				'help' => VulnHub_AWS_Setup::instructions( $first ),
			),
			array(
				'key'         => 'account_id',
				'label'       => __( 'AWS account ID', 'vulnhub' ),
				'type'        => 'text',
				'required'    => true,
				'placeholder' => '123456789012',
				'help'        => __( 'From the stack’s Outputs tab — the AccountId row.', 'vulnhub' ),
			),
			array(
				'key'         => 'access_key_id',
				'label'       => __( 'Access key ID', 'vulnhub' ),
				'type'        => 'text',
				'required'    => true,
				'placeholder' => 'AKIA…',
				'help'        => __( 'From the stack’s Outputs tab — the AccessKeyId row.', 'vulnhub' ),
			),
			array(
				'key'      => 'secret_access_key',
				'label'    => __( 'Secret access key', 'vulnhub' ),
				'type'     => 'text',
				'secret'   => true,
				'required' => true,
				'help'     => __( 'The SecretAccessKey row. Encrypted at rest; leave blank to keep the stored one.', 'vulnhub' ),
			),
			array(
				'key'         => 'regions',
				'label'       => __( 'Regions', 'vulnhub' ),
				'type'        => 'text',
				'default'     => implode( ', ', $regions ),
				'placeholder' => 'ap-southeast-2, us-east-1',
				'help'        => $regions
					? sprintf(
						/* translators: %s: comma-separated region list. */
						esc_html__( 'Comma separated. Pre-filled from where your assets already say they run: %s.', 'vulnhub' ),
						esc_html( implode( ', ', $regions ) )
					)
					: esc_html__( 'Comma separated, e.g. ap-southeast-2, us-east-1.', 'vulnhub' ),
			),
			array(
				'key'            => 'use_inspector',
				'label'          => __( 'Amazon Inspector', 'vulnhub' ),
				'type'           => 'checkbox',
				'default'        => true,
				'checkbox_label' => __( 'Use Inspector’s reachability findings when it is switched on', 'vulnhub' ),
				'help'           => __( 'Inspector computes the same answer AWS-side and evaluates paths this connector does not, such as traffic arriving through a peered VPC. When it is off, exposure is derived from security groups, route tables and load balancers instead. Either way nothing is written to your account.', 'vulnhub' ),
			),
		);
	}

	/** A client built from the stored settings, or null when not configured. */
	private function client(): ?VulnHub_AWS_Client {
		$key    = trim( (string) $this->get( 'access_key_id' ) );
		$secret = trim( (string) $this->secret( 'secret_access_key' ) );

		if ( '' === $key || '' === $secret ) {
			return null;
		}

		return new VulnHub_AWS_Client( $key, $secret );
	}

	/** @return string[] */
	private function regions(): array {
		$raw = (string) $this->get( 'regions' );
		$out = array_values( array_filter( array_map( 'trim', explode( ',', $raw ) ) ) );

		return $out ?: VulnHub_AWS_Setup::suggested_regions();
	}

	/**
	 * Prove the credentials work, and say which permission is missing when
	 * they only half do.
	 *
	 * Checked in the order things actually go wrong: the key itself, then the
	 * account being the one they meant, then each permission group separately.
	 * A single pass/fail here would send somebody back to the IAM console with
	 * nothing to go on, which is the experience this connector exists to avoid.
	 *
	 * @return array{ok:bool,message:string}
	 */
	public function test_connection(): array {
		$client = $this->client();

		if ( ! $client ) {
			return array(
				'ok'      => false,
				'message' => __( 'Enter an access key ID and secret access key first.', 'vulnhub' ),
			);
		}

		$who = $client->caller_identity();

		if ( ! $who['ok'] ) {
			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: %s: AWS error. */
					__( 'AWS rejected the credentials: %s', 'vulnhub' ),
					$who['error']
				),
			);
		}

		$notes    = array();
		$expected = trim( (string) $this->get( 'account_id' ) );

		if ( '' !== $expected && $expected !== $who['account'] ) {
			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: 1: configured account, 2: the account the key belongs to. */
					__( 'These credentials belong to account %2$s, but this connector is configured for %1$s. Check which account the stack was created in.', 'vulnhub' ),
					$expected,
					$who['account']
				),
			);
		}

		$region = $this->regions()[0] ?? 'us-east-1';

		// Can we read instances? Without this nothing else matters.
		$ec2 = $client->query(
			'ec2',
			$region,
			array(
				'Action'     => 'DescribeInstances',
				'Version'    => '2016-11-15',
				'MaxResults' => '5',
			)
		);

		if ( ! $ec2['ok'] ) {
			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: 1: region, 2: AWS error. */
					__( 'Signed in as %1$s, but ec2:DescribeInstances was refused in %2$s. Re-create the stack, or add the missing permission.', 'vulnhub' ),
					$who['arn'],
					$region
				) . ' — ' . $ec2['error'],
			);
		}

		$notes[] = __( 'EC2 readable', 'vulnhub' );

		// Load balancers are optional-but-important; a refusal is a warning.
		$elb = $client->query(
			'elasticloadbalancing',
			$region,
			array(
				'Action'   => 'DescribeLoadBalancers',
				'Version'  => '2015-12-01',
				'PageSize' => '5',
			)
		);

		$notes[] = $elb['ok']
			? __( 'load balancers readable', 'vulnhub' )
			: __( 'load balancers NOT readable — instances published only through an ALB will be missed', 'vulnhub' );

		// Inspector is genuinely optional.
		if ( $this->get_bool_setting( 'use_inspector', true ) ) {
			$status = ( new VulnHub_AWS_Inspector( $client ) )->status( $region );

			if ( ! $status['ok'] ) {
				$notes[] = __( 'Inspector not readable (optional)', 'vulnhub' );
			} else {
				$on = false;

				foreach ( $status['accounts'] as $acct ) {
					if ( 'ENABLED' === $acct['ec2'] ) {
						$on = true;
					}
				}

				$notes[] = $on
					? __( 'Inspector EC2 scanning is ON — its reachability findings will be used', 'vulnhub' )
					: __( 'Inspector is off — exposure will be derived from security groups and routing', 'vulnhub' );
			}
		}

		return array(
			'ok'      => true,
			'message' => sprintf(
				/* translators: 1: account id, 2: identity arn, 3: checks. */
				__( 'Connected to account %1$s as %2$s. %3$s.', 'vulnhub' ),
				$who['account'],
				$who['arn'],
				implode( '; ', $notes )
			),
		);
	}

	/** Settings helper: the base class exposes get(), not a typed bool. */
	private function get_bool_setting( string $key, bool $default ): bool {
		return (bool) vulnhub()->settings->get_bool( $this->id(), $key, $default );
	}

	/**
	 * @param array<string,mixed> $args Sync arguments.
	 * @return array{ok:bool,message:string}
	 */
	protected function do_sync( array $args = array() ): array {
		$client = $this->client();

		if ( ! $client ) {
			return array(
				'ok'      => false,
				'message' => __( 'Not configured: no access key stored.', 'vulnhub' ),
			);
		}

		$reach = new VulnHub_AWS_Reachability( $client, $this );
		$total = 0;
		$open  = 0;

		foreach ( $this->regions() as $region ) {
			$res = $reach->region( $region );

			$this->log(
				sprintf(
					'%s: %d instance(s), %d reachable from the internet, %d API call(s)',
					$region,
					$res['instances'],
					$res['reachable'],
					$res['calls']
				)
			);

			$total += (int) $res['instances'];
			$open  += (int) $res['reachable'];

			$this->bump( 'seen', (int) $res['instances'] );
		}

		$linked = VulnHub_AWS_Reachability::apply_to_assets();

		$this->bump( 'updated', $linked );

		return array(
			'ok'      => true,
			'message' => sprintf(
				/* translators: 1: instances seen, 2: reachable, 3: assets matched. */
				__( '%1$d instance(s) read, %2$d reachable from the internet, %3$d matched to assets we hold.', 'vulnhub' ),
				$total,
				$open,
				$linked
			),
		);
	}
}
