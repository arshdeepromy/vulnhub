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
				'help'        => __( 'The 12-digit account number. Shown in the AWS access portal beside the account name, or as the AccountId output of the stack.', 'vulnhub' ),
			),
			array(
				'key'         => 'access_key_id',
				'label'       => __( 'Access key ID', 'vulnhub' ),
				'type'        => 'text',
				'required'    => true,
				'placeholder' => 'AKIA…',
				'help'        => __( 'Starts AKIA for a permanent key, ASIA for a short-term one from the access portal.', 'vulnhub' ),
			),
			array(
				'key'      => 'secret_access_key',
				'label'    => __( 'Secret access key', 'vulnhub' ),
				'type'     => 'text',
				'secret'   => true,
				'required' => true,
				'help'     => __( 'Encrypted at rest. Leave blank to keep the stored one.', 'vulnhub' ),
			),
			array(
				'key'      => 'session_token',
				'label'    => __( 'Session token', 'vulnhub' ),
				'type'     => 'text',
				'secret'   => true,
				'required' => false,
				'help'     => __( '<strong>Required if your access key starts with ASIA.</strong> That is a short-term key, and AWS rejects it without the session token issued alongside it — the AWS_SESSION_TOKEN value on the same screen you copied the key from. Leave blank for a permanent AKIA key. Short-term credentials expire within hours, so they can run a sync you press but will fail on a schedule.', 'vulnhub' ),
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
			array(
				'key'  => 'explorer_note',
				'type' => 'note',
				'help' => __( '<strong>Organisation-wide inventory (optional).</strong> Reads Resource Explorer from this central account to list every asset and security group across all member accounts, with no role to assume in each one. This is an <em>inventory</em>: it records that a resource exists, its account, region and tags. It does not read security-group rules or instance reachability, which still come from the per-account role path above.', 'vulnhub' ),
			),
			array(
				'key'            => 'use_explorer',
				'label'          => __( 'Resource Explorer', 'vulnhub' ),
				'type'           => 'checkbox',
				'default'        => false,
				'checkbox_label' => __( 'Inventory the whole organisation through Resource Explorer', 'vulnhub' ),
				'help'           => __( 'Requires an aggregator index and an organisation view in the region below, and resource-explorer-2:Search on this identity. Nothing is written to any account.', 'vulnhub' ),
			),
			array(
				'key'         => 'explorer_region',
				'label'       => __( 'Resource Explorer region', 'vulnhub' ),
				'type'        => 'text',
				'default'     => $first,
				'placeholder' => 'ap-southeast-2',
				'help'        => __( 'The region that holds the aggregator index and organisation view. Usually where most of the estate runs.', 'vulnhub' ),
			),
			array(
				'key'         => 'explorer_view_arn',
				'label'       => __( 'Organisation view ARN', 'vulnhub' ),
				'type'        => 'text',
				'required'    => false,
				'placeholder' => 'arn:aws:resource-explorer-2:REGION:ACCOUNT:view/OrgView/…',
				'help'        => __( 'Recommended. The organisation view to search, copied from the Resource Explorer console. Left blank, Search uses the default view for this account, which may only cover this one account.', 'vulnhub' ),
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

		// Present only for short-term credentials from the AWS access portal.
		// Signed like any other header when it is there, absent when it is not.
		return new VulnHub_AWS_Client( $key, $secret, trim( (string) $this->secret( 'session_token' ) ) );
	}

	/**
	 * Are we running on credentials that will expire?
	 *
	 * Worth knowing because it changes what the connector can promise. A
	 * short-term key is fine for a sync somebody presses; it cannot hold a
	 * schedule, and the failure arrives hours later as an authentication error
	 * rather than as anything that points at the cause.
	 */
	private function is_temporary(): bool {
		return '' !== trim( (string) $this->secret( 'session_token' ) );
	}

	/** @return string[] */
	private function regions(): array {
		$raw = (string) $this->get( 'regions' );
		$out = array_values( array_filter( array_map( 'trim', explode( ',', $raw ) ) ) );

		return $out ?: VulnHub_AWS_Setup::suggested_regions();
	}

	/** A Resource Explorer reader built from the stored settings, or null. */
	private function explorer(): ?VulnHub_AWS_Explorer {
		$client = $this->client();

		if ( ! $client ) {
			return null;
		}

		$region = trim( (string) $this->get( 'explorer_region' ) );

		if ( '' === $region ) {
			$region = $this->regions()[0] ?? 'us-east-1';
		}

		return new VulnHub_AWS_Explorer( $client, $region, trim( (string) $this->get( 'explorer_view_arn' ) ) );
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

		/*
		 * Two mismatches AWS reports as the same opaque InvalidClientTokenId,
		 * and both are obvious from the key itself. The prefix says which kind
		 * of credential this is: ASIA is short-term and meaningless without
		 * the session token issued alongside it, AKIA is permanent and has no
		 * session token to give. Catching them here costs one string
		 * comparison and replaces "the security token included in the request
		 * is invalid" -- which sends people to check the secret they just
		 * pasted correctly -- with the actual missing step.
		 */
		$key   = trim( (string) $this->get( 'access_key_id' ) );
		$token = trim( (string) $this->secret( 'session_token' ) );

		if ( str_starts_with( $key, 'ASIA' ) && '' === $token ) {
			return array(
				'ok'      => false,
				'message' => __( 'This is a short-term key (it starts with ASIA), which AWS only accepts together with the session token issued with it — and the session token field is empty. Go back to the same “Environment variables” screen you copied the key from and paste AWS_SESSION_TOKEN into the Session token field. It is long, several hundred characters.', 'vulnhub' ),
			);
		}

		if ( str_starts_with( $key, 'AKIA' ) && '' !== $token ) {
			return array(
				'ok'      => false,
				'message' => __( 'This is a permanent key (it starts with AKIA), which has no session token — but the Session token field is filled in. Clear it, or use the short-term key the token belongs to.', 'vulnhub' ),
			);
		}

		$who = $client->caller_identity();

		if ( ! $who['ok'] ) {
			$hint = '';

			// Short-term credentials expire in hours, and an expired one is
			// far more likely than a mistyped one on a key that worked before.
			if ( '' !== $token ) {
				$hint = ' ' . __( 'Short-term credentials expire after a few hours — if this worked earlier today, fetch a fresh set from the AWS access portal and paste all three values again.', 'vulnhub' );
			}

			// AWS is inconsistent about ending its messages with a full stop,
			// so one is added when it is missing rather than letting the hint
			// run straight on from the error.
			$err = rtrim( (string) $who['error'] );

			if ( '' !== $err && ! in_array( substr( $err, -1 ), array( '.', '!', '?' ), true ) ) {
				$err .= '.';
			}

			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: %s: AWS error. */
					__( 'AWS rejected the credentials: %s', 'vulnhub' ),
					$err
				) . $hint,
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

		if ( $this->is_temporary() || str_contains( $who['arn'], ':assumed-role/' ) ) {
			$notes[] = __( 'these are SHORT-TERM credentials — good for a sync you press, but they will expire and a scheduled sync will start failing', 'vulnhub' );
		}

		if ( $this->get_bool_setting( 'use_explorer', false ) ) {
			$probe = $this->explorer()?->probe();

			if ( null === $probe || empty( $probe['ok'] ) ) {
				$notes[] = sprintf(
					/* translators: %s: AWS error. */
					__( 'Resource Explorer NOT readable — %s', 'vulnhub' ),
					null === $probe ? __( 'no base credentials', 'vulnhub' ) : (string) $probe['error']
				);
			} else {
				$notes[] = sprintf(
					/* translators: 1: sample size, 2: distinct accounts in the sample. */
					__( 'Resource Explorer readable — %1$d resource(s) on the first page across %2$d account(s)', 'vulnhub' ),
					(int) $probe['sample'],
					(int) $probe['accounts']
				);
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
	 * Build a client for one stored account.
	 *
	 * Two arrangements, and the difference matters at this scale. `keys` uses
	 * a credential belonging to that account -- fine for one or two. `role`
	 * uses the connector's own base credential to assume a read-only role in
	 * the target account, which is the only arrangement where adding the
	 * fifty-ninth account is typing a number rather than minting, storing and
	 * rotating another key pair.
	 *
	 * @param array<string,mixed> $account Stored account row.
	 * @return array{ok:bool,client:?VulnHub_AWS_Client,error:string}
	 */
	private function client_for( array $account ): array {
		$id = (int) $account['id'];

		if ( 'keys' === (string) $account['auth_mode'] ) {
			$key    = trim( (string) $account['access_key_id'] );
			$secret = VulnHub_AWS_Accounts::secret( $id, 'secret' );

			if ( '' === $key || '' === $secret ) {
				return array(
					'ok'     => false,
					'client' => null,
					'error'  => __( 'No access key stored for this account.', 'vulnhub' ),
				);
			}

			return array(
				'ok'     => true,
				'client' => new VulnHub_AWS_Client( $key, $secret, VulnHub_AWS_Accounts::secret( $id, 'token' ) ),
				'error'  => '',
			);
		}

		$base = $this->client();

		if ( ! $base ) {
			return array(
				'ok'     => false,
				'client' => null,
				'error'  => __( 'No base credentials on the connector to assume a role with. Add them above, or set this account to use its own access key.', 'vulnhub' ),
			);
		}

		$arn = trim( (string) $account['role_arn'] );

		if ( '' === $arn ) {
			$arn = sprintf( 'arn:aws:iam::%s:role/%s', $account['account_id'], self::DEFAULT_ROLE );
		}

		$res = $base->assume( $arn, (string) $account['external_id'], 'vulnhub-' . $account['account_id'] );

		if ( ! $res['ok'] ) {
			return array(
				'ok'     => false,
				'client' => null,
				'error'  => sprintf(
					/* translators: 1: role arn, 2: AWS error. */
					__( 'Could not assume %1$s — %2$s', 'vulnhub' ),
					$arn,
					$res['error']
				),
			);
		}

		return array(
			'ok'     => true,
			'client' => $res['client'],
			'error'  => '',
		);
	}

	/** The role name assumed in each member account when none is given. */
	public const DEFAULT_ROLE = 'VulnHubReadOnly';

	/**
	 * Read one account, and record what it managed to read.
	 *
	 * Returns rather than throws on failure: one account with a missing
	 * permission must not stop the other fifty-seven, and the whole point of
	 * recording per account is that a partial run is the normal outcome at
	 * this scale.
	 *
	 * @param array<string,mixed> $account Stored account row.
	 * @return array{ok:bool,stats:array<string,mixed>,message:string}
	 */
	public function sync_account( array $account ): array {
		$built = $this->client_for( $account );

		if ( ! $built['ok'] ) {
			VulnHub_AWS_Accounts::record( (int) $account['id'], 'failed', (string) $built['error'], array() );

			return array(
				'ok'      => false,
				'stats'   => array(),
				'message' => (string) $built['error'],
			);
		}

		$client  = $built['client'];
		$regions = array_values( array_filter( array_map( 'trim', explode( ',', (string) $account['regions'] ) ) ) );

		if ( ! $regions ) {
			$regions = $this->regions();
		}

		$reach = new VulnHub_AWS_Reachability( $client, $this );

		foreach ( $regions as $region ) {
			$reach->region( $region );
		}

		$stats = $reach->stats();

		// Inspector is optional, and worth recording either way: "off" and
		// "not permitted" call for different actions.
		if ( $this->get_bool_setting( 'use_inspector', true ) ) {
			$status = ( new VulnHub_AWS_Inspector( $client ) )->status( $regions[0] ?? 'us-east-1' );

			if ( ! $status['ok'] ) {
				$stats['inspector'] = 'denied';
			} else {
				$on = false;

				foreach ( $status['accounts'] as $acct ) {
					if ( 'ENABLED' === $acct['ec2'] ) {
						$on = true;
					}
				}

				$stats['inspector'] = $on ? 'enabled' : 'off';
			}
		}

		$stats['regions'] = $regions;
		$stats['calls']   = $client->calls();

		$ok      = empty( $stats['denied']['instances'] );
		$message = $ok
			? sprintf(
				/* translators: 1: instances, 2: reachable. */
				__( '%1$d instance(s), %2$d reachable from the internet.', 'vulnhub' ),
				(int) ( $stats['instances'] ?? 0 ),
				(int) ( $stats['reachable'] ?? 0 )
			)
			: (string) $stats['denied']['instances'];

		VulnHub_AWS_Accounts::record( (int) $account['id'], $ok ? 'ok' : 'failed', $message, $stats );

		return array(
			'ok'      => $ok,
			'stats'   => $stats,
			'message' => $message,
		);
	}

	/**
	 * @param array<string,mixed> $args Sync arguments.
	 * @return array{ok:bool,message:string}
	 */
	protected function do_sync( array $args = array() ): array {
		$accounts = VulnHub_AWS_Accounts::all( true );

		// No accounts on the list: fall back to the single-account settings,
		// which is still the right shape for somebody with one account.
		if ( ! $accounts && $this->client() ) {
			$accounts = array(
				array(
					'id'            => 0,
					'account_id'    => (string) $this->get( 'account_id' ),
					'label'         => __( 'Connector settings', 'vulnhub' ),
					'auth_mode'     => 'keys',
					'access_key_id' => (string) $this->get( 'access_key_id' ),
					'role_arn'      => '',
					'external_id'   => '',
					'regions'       => (string) $this->get( 'regions' ),
				),
			);
		}

		$use_explorer = $this->get_bool_setting( 'use_explorer', false );

		if ( ! $accounts && ! $use_explorer ) {
			return array(
				'ok'      => false,
				'message' => __( 'No AWS accounts configured. Add one on the AWS accounts screen, or switch on Resource Explorer inventory.', 'vulnhub' ),
			);
		}

		$ok     = 0;
		$failed = 0;

		foreach ( $accounts as $account ) {
			// id 0 is the settings-form fallback, which has no row to read a
			// secret from; sync_account() handles it through the same path.
			$res = 0 === (int) $account['id']
				? $this->sync_account_inline( $account )
				: $this->sync_account( $account );

			$this->log(
				sprintf(
					'%s (%s): %s',
					$account['account_id'],
					$account['label'] ?: '—',
					$res['message']
				)
			);

			if ( $res['ok'] ) {
				++$ok;
				$this->bump( 'seen', (int) ( $res['stats']['instances'] ?? 0 ) );
			} else {
				++$failed;
				$this->bump( 'failed' );
			}
		}

		$linked = VulnHub_AWS_Reachability::apply_to_assets();

		$this->bump( 'updated', $linked );

		$explorer_line = '';
		$explorer_ok   = false;

		if ( $use_explorer ) {
			$exp = $this->explorer();

			if ( $exp ) {
				$inv   = $exp->sync();
				$total = array_sum( $inv['per_type'] );

				$this->log(
					sprintf(
						'Resource Explorer: %d resource(s) across %d account(s)%s.',
						$total,
						(int) $inv['accounts'],
						$inv['errors'] ? sprintf( ' — %d type(s) denied', count( $inv['errors'] ) ) : ''
					)
				);

				$this->bump( 'seen', $total );

				$explorer_ok   = $inv['ok'] && $total > 0;
				$explorer_line = sprintf(
					/* translators: 1: resource count, 2: account count. */
					__( ' Inventory: %1$d resource(s) across %2$d account(s).', 'vulnhub' ),
					$total,
					(int) $inv['accounts']
				);
			}
		}

		return array(
			'ok'      => $ok > 0 || $explorer_ok,
			'message' => sprintf(
				/* translators: 1: accounts read, 2: accounts failed, 3: assets matched. */
				__( '%1$d account(s) read, %2$d failed, %3$d asset(s) matched.', 'vulnhub' ),
				$ok,
				$failed,
				$linked
			) . $explorer_line,
		);
	}

	/**
	 * The single-account path, for an install that never added a row.
	 *
	 * @param array<string,mixed> $account Synthetic account.
	 * @return array{ok:bool,stats:array<string,mixed>,message:string}
	 */
	private function sync_account_inline( array $account ): array {
		$client = $this->client();

		if ( ! $client ) {
			return array(
				'ok'      => false,
				'stats'   => array(),
				'message' => __( 'Not configured.', 'vulnhub' ),
			);
		}

		$reach = new VulnHub_AWS_Reachability( $client, $this );

		foreach ( $this->regions() as $region ) {
			$reach->region( $region );
		}

		$stats = $reach->stats();

		return array(
			'ok'      => empty( $stats['denied']['instances'] ),
			'stats'   => $stats,
			'message' => sprintf(
				/* translators: 1: instances, 2: reachable. */
				__( '%1$d instance(s), %2$d reachable from the internet.', 'vulnhub' ),
				(int) ( $stats['instances'] ?? 0 ),
				(int) ( $stats['reachable'] ?? 0 )
			),
		);
	}
}
