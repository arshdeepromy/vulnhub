<?php
/**
 * Akamai: the public edge, read on a schedule.
 *
 * Everything this reads was first imported by hand -- property origins from
 * downloaded metadata, WAF coverage from a console export -- because nobody
 * held an API client. Those were point-in-time drops that went stale the day
 * after they were taken. This connector replaces both with a live read, and
 * writes through exactly the same storage the manual import used, so the
 * Internet exposure page does not care which produced the rows.
 *
 * Two sources:
 *
 *   **Property Manager** -- every property on every contract and group, its
 *   active production version, the hostnames that version serves, and the
 *   origin each hostname reaches. The origin is read from the rule tree, not
 *   assumed: a property routinely sends each hostname to a different origin
 *   through a child rule matching on host, so the default origin alone is
 *   wrong for most hostnames in a multi-environment property.
 *
 *   **Application Security** -- the hostname coverage report: every hostname
 *   the edge serves, whether a security configuration covers it, and which
 *   policy. No AWS API knows this and no DNS record implies it.
 *
 * Read-only throughout. The API client needs nothing beyond READ on Property
 * Manager (PAPI) and Application Security; it never activates, never edits a
 * property, and never touches a security configuration.
 *
 * On field names: Akamai's hostname-coverage response is read defensively,
 * trying the spellings the API has used, and the sync reports how many rows
 * it could not read a hostname out of. A reader that silently stores blanks
 * when a field is renamed is worse than one that says it found nothing.
 *
 * See docs/AKAMAI.md.
 *
 * @package VulnHub\Akamai
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// The base lives in a namespace; this file does not. Without the import,
// `extends Connector` resolves to a global class that does not exist and
// fatals the whole site the moment the plugin is activated.
use VulnHub\Core\Connector;

final class VulnHub_Akamai_Connector extends Connector {

	/** Properties read per run before the connector stops and says so. */
	private const MAX_PROPERTIES = 400;

	public function id(): string {
		return 'akamai';
	}

	public function label(): string {
		return __( 'Akamai', 'vulnhub' );
	}

	/**
	 * Grouped with AWS and Plerion on the Integrations screen: Akamai is the
	 * edge in front of the same estate, so it belongs beside the clouds it
	 * fronts rather than in the "Other" bucket.
	 */
	public function category(): string {
		return 'cloud';
	}

	public function description(): string {
		return __( 'Reads the public edge: every property, the hostnames it serves, the origin behind each one, and which hostnames a WAF policy actually covers. Read-only.', 'vulnhub' );
	}

	/**
	 * @return array<int,array<string,mixed>>
	 */
	public function fields(): array {
		return array(
			array(
				'key'  => 'setup',
				'type' => 'note',
				'help' => __(
					'In Akamai Control Center go to <strong>ACCOUNT ADMIN → Identity &amp; access</strong>, create an API client, and grant it <strong>READ-ONLY</strong> on <em>Property Manager (PAPI)</em> and <em>Application Security</em>. Download the credentials at creation — the client secret is shown once and cannot be recovered. This connector only reads; it never activates a property or edits a security configuration.',
					'vulnhub'
				),
			),
			array(
				'key'         => 'host',
				'label'       => __( 'API host', 'vulnhub' ),
				'type'        => 'text',
				'required'    => true,
				'placeholder' => 'akab-xxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxx.luna.akamaiapis.net',
				'help'        => __( 'The <code>host</code> line from the credentials file, without https://.', 'vulnhub' ),
			),
			array(
				'key'      => 'client_token',
				'label'    => __( 'Client token', 'vulnhub' ),
				'type'     => 'text',
				'required' => true,
				'help'     => __( 'The <code>client_token</code> line.', 'vulnhub' ),
			),
			array(
				'key'      => 'access_token',
				'label'    => __( 'Access token', 'vulnhub' ),
				'type'     => 'text',
				'required' => true,
				'help'     => __( 'The <code>access_token</code> line.', 'vulnhub' ),
			),
			array(
				'key'      => 'client_secret',
				'label'    => __( 'Client secret', 'vulnhub' ),
				'type'     => 'text',
				'secret'   => true,
				'required' => true,
				'help'     => __( 'The <code>client_secret</code> line. Encrypted at rest. Leave blank to keep the stored one.', 'vulnhub' ),
			),
			array(
				'key'         => 'account_key',
				'label'       => __( 'Account switch key', 'vulnhub' ),
				'type'        => 'text',
				'placeholder' => 'A-CCT1234:1-ABCDE',
				'help'        => __( 'Only for a credential issued against one account that must read another. Leave blank for an ordinary account-level API client.', 'vulnhub' ),
			),
			array(
				'key'            => 'read_properties',
				'label'          => __( 'Property origins', 'vulnhub' ),
				'type'           => 'checkbox',
				'default'        => true,
				'checkbox_label' => __( 'Read properties, their hostnames and their origins', 'vulnhub' ),
				'help'           => __( 'This is what turns a public name into the server behind it. Costs a few calls per property, so a large account makes a long sync.', 'vulnhub' ),
			),
			array(
				'key'            => 'read_coverage',
				'label'          => __( 'WAF coverage', 'vulnhub' ),
				'type'           => 'checkbox',
				'default'        => true,
				'checkbox_label' => __( 'Read the hostname coverage report', 'vulnhub' ),
				'help'           => __( 'One call. Says which hostnames a security policy actually covers, which nothing else in this system can tell you.', 'vulnhub' ),
			),
		);
	}

	/**
	 * @return array{ok:bool,message:string}
	 */
	public function test_connection(): array {
		$signer = VulnHub_Akamai_Client::self_test();

		if ( empty( $signer['ok'] ) ) {
			return array(
				'ok'      => false,
				'message' => (string) $signer['message'],
			);
		}

		$client = $this->client();

		if ( ! $client ) {
			return array(
				'ok'      => false,
				'message' => __( 'Enter the host, client token, access token and client secret from your Akamai credentials file.', 'vulnhub' ),
			);
		}

		$groups = $client->get( '/papi/v1/groups' );

		if ( empty( $groups['ok'] ) ) {
			return array(
				'ok'      => false,
				/* translators: %s: error from Akamai. */
				'message' => sprintf( __( 'Property Manager refused the read: %s', 'vulnhub' ), (string) $groups['error'] ),
			);
		}

		$count    = count( (array) ( $groups['data']['groups']['items'] ?? array() ) );
		$coverage = $client->get( '/appsec/v1/hostname-coverage' );

		return array(
			'ok'      => true,
			'message' => sprintf(
				/* translators: 1: group count, 2: whether the security read worked. */
				__( 'Connected. %1$d group(s) readable in Property Manager. Application Security: %2$s', 'vulnhub' ),
				$count,
				! empty( $coverage['ok'] )
					? __( 'readable', 'vulnhub' )
					: __( 'not readable with this client — add the grant, or turn WAF coverage off below', 'vulnhub' )
			),
		);
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
				'message' => __( 'Not configured.', 'vulnhub' ),
			);
		}

		if ( ! class_exists( 'VulnHub_Domain_Import' ) || ! class_exists( 'VulnHub_AWS_Domains' ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'The domain store is unavailable — the AWS plugin provides it.', 'vulnhub' ),
			);
		}

		$said = array();

		if ( $this->get( 'read_properties', true ) ) {
			$said[] = $this->sync_properties( $client );
		}

		if ( $this->get( 'read_coverage', true ) ) {
			$said[] = $this->sync_coverage( $client );
		}

		if ( ! $said ) {
			return array(
				'ok'      => false,
				'message' => __( 'Nothing is turned on to read.', 'vulnhub' ),
			);
		}

		return array(
			'ok'      => true,
			'message' => implode( ' ', array_filter( $said ) ),
		);
	}

	/* =================================================================
	 * Property Manager
	 * ============================================================== */

	private function sync_properties( VulnHub_Akamai_Client $client ): string {
		$scopes = $this->scopes( $client );

		if ( ! $scopes ) {
			return __( 'No contract and group pair was readable, so no property was read.', 'vulnhub' );
		}

		$props   = array();
		$rows    = array();
		$read    = 0;
		$skipped = 0;
		$errors  = 0;

		foreach ( $scopes as $scope ) {
			$list = $client->get(
				'/papi/v1/properties',
				array(
					'contractId' => $scope['contract'],
					'groupId'    => $scope['group'],
				),
				array( 'PAPI-Use-Prefixes' => 'false' )
			);

			if ( empty( $list['ok'] ) ) {
				++$errors;
				continue;
			}

			foreach ( (array) ( $list['data']['properties']['items'] ?? array() ) as $p ) {
				if ( $read >= self::MAX_PROPERTIES ) {
					++$skipped;
					continue;
				}

				$version = (int) ( $p['productionVersion'] ?? 0 );

				// No production version means nothing is live, and nothing
				// live means nothing exposed. A staging-only property in an
				// exposure list is noise.
				if ( $version < 1 ) {
					continue;
				}

				if ( $this->read_property( $client, $scope, (array) $p, $version, $props, $rows ) ) {
					++$read;
				} else {
					++$errors;
				}
			}
		}

		$stored = VulnHub_Domain_Import::store_properties( $props, $rows, 'akamai-api', 0 );

		return sprintf(
			/* translators: 1: properties, 2: hostnames, 3: origins matched, 4: failures. */
			__( 'Read %1$d live propert(ies) covering %2$d hostname(s); %3$d origin(s) matched an AWS resource. %4$d read(s) failed.', 'vulnhub' ),
			(int) $stored['properties'],
			(int) $stored['hostnames'],
			(int) $stored['matched'],
			$errors + $skipped
		);
	}

	/**
	 * Contract and group pairs this credential can see.
	 *
	 * @return array<int,array{contract:string,group:string}>
	 */
	private function scopes( VulnHub_Akamai_Client $client ): array {
		$res = $client->get( '/papi/v1/groups', array(), array( 'PAPI-Use-Prefixes' => 'false' ) );

		if ( empty( $res['ok'] ) ) {
			return array();
		}

		$out = array();

		foreach ( (array) ( $res['data']['groups']['items'] ?? array() ) as $g ) {
			$group = (string) ( $g['groupId'] ?? '' );

			if ( '' === $group ) {
				continue;
			}

			// A group can sit on several contracts, and properties are
			// listed per pair, so both are needed.
			foreach ( (array) ( $g['contractIds'] ?? array() ) as $contract ) {
				$out[] = array(
					'contract' => (string) $contract,
					'group'    => $group,
				);
			}
		}

		return $out;
	}

	/**
	 * One property: its hostnames, and the origin each of them reaches.
	 *
	 * @param array{contract:string,group:string} $scope Contract and group.
	 * @param array<string,mixed>                 $p     Property record.
	 * @param array<string,array<string,mixed>>   $props Collected properties, by reference.
	 * @param array<int,array<string,mixed>>      $rows  Collected hostname rows, by reference.
	 */
	private function read_property( VulnHub_Akamai_Client $client, array $scope, array $p, int $version, array &$props, array &$rows ): bool {
		$id   = (string) ( $p['propertyId'] ?? '' );
		$name = (string) ( $p['propertyName'] ?? '' );

		if ( '' === $id || '' === $name ) {
			return false;
		}

		$query = array(
			'contractId' => $scope['contract'],
			'groupId'    => $scope['group'],
		);

		$hosts = $client->get( '/papi/v1/properties/' . rawurlencode( $id ) . '/versions/' . $version . '/hostnames', $query, array( 'PAPI-Use-Prefixes' => 'false' ) );
		$tree  = $client->get( '/papi/v1/properties/' . rawurlencode( $id ) . '/versions/' . $version . '/rules', $query, array( 'PAPI-Use-Prefixes' => 'false' ) );

		if ( empty( $hosts['ok'] ) || empty( $tree['ok'] ) ) {
			return false;
		}

		$plan = self::read_rules( (array) ( $tree['data']['rules'] ?? array() ) );

		$props[ $name ] = array(
			'origin'  => (string) $plan['default'],
			'version' => (string) $version,
			'otype'   => (string) $plan['type'],
			'shield'  => (string) $plan['shield'],
			'hosts'   => 0,
		);

		foreach ( (array) ( $hosts['data']['hostnames']['items'] ?? array() ) as $h ) {
			$hostname = strtolower( trim( (string) ( $h['cnameFrom'] ?? '' ) ) );

			if ( '' === $hostname ) {
				continue;
			}

			// The per-host override wins. This is the whole reason the rule
			// tree is read rather than just the property's default origin.
			$origin = (string) ( $plan['byhost'][ $hostname ] ?? $plan['default'] );

			++$props[ $name ]['hosts'];

			$match  = '' !== $origin ? VulnHub_AWS_Domains::classify( $origin ) : array(
				'kind' => '',
				'ref'  => '',
				'name' => '',
			);
			$rows[] = array(
				'source'       => 'akamai',
				'zone'         => '',
				'name'         => $hostname,
				'record_type'  => 'PROPERTY',
				'target'       => $origin,
				'private'      => 0,
				'matched_kind' => (string) $match['kind'],
				'matched_ref'  => (string) $match['ref'],
				'matched_name' => (string) $match['name'],
				'detail'       => array(
					'property'   => $name,
					'version'    => (string) $version,
					'originType' => (string) $plan['type'],
					'siteshield' => (string) $plan['shield'],
					'edge'       => (string) ( $h['cnameTo'] ?? '' ),
				),
			);
		}

		return true;
	}

	/**
	 * Walk a rule tree for the origins, the Site Shield map and the origin type.
	 *
	 * A child rule that matches on hostname and sets its own origin is how a
	 * property serves several environments, so those are collected per host
	 * rather than flattened.
	 *
	 * @param array<string,mixed> $rule The rule tree's root.
	 * @return array{default:string,byhost:array<string,string>,shield:string,type:string}
	 */
	private static function read_rules( array $rule ): array {
		$plan = array(
			'default' => '',
			'byhost'  => array(),
			'shield'  => '',
			'type'    => '',
		);

		$walk = static function ( array $node, array $hosts ) use ( &$walk, &$plan ): void {
			foreach ( (array) ( $node['criteria'] ?? array() ) as $c ) {
				if ( 'hostname' === (string) ( $c['name'] ?? '' ) ) {
					foreach ( (array) ( $c['options']['values'] ?? array() ) as $v ) {
						$hosts[] = strtolower( trim( (string) $v ) );
					}
				}
			}

			foreach ( (array) ( $node['behaviors'] ?? array() ) as $b ) {
				$bname = (string) ( $b['name'] ?? '' );
				$opts  = (array) ( $b['options'] ?? array() );

				if ( 'origin' === $bname ) {
					$origin = strtolower( trim( (string) ( $opts['hostname'] ?? '' ) ) );

					if ( '' !== $origin ) {
						if ( $hosts ) {
							foreach ( $hosts as $h ) {
								$plan['byhost'][ $h ] = $origin;
							}
						} elseif ( '' === $plan['default'] ) {
							$plan['default'] = $origin;
						}
					}

					if ( '' === $plan['type'] && ! empty( $opts['originType'] ) ) {
						$plan['type'] = strtolower( (string) $opts['originType'] );
					}
				}

				if ( 'siteShield' === $bname && '' === $plan['shield'] ) {
					$map = $opts['ssmap'] ?? array();
					$map = is_array( $map ) ? ( $map['value'] ?? $map['name'] ?? '' ) : $map;

					$plan['shield'] = (string) $map;
				}
			}

			foreach ( (array) ( $node['children'] ?? array() ) as $child ) {
				$walk( (array) $child, $hosts );
			}
		};

		$walk( $rule, array() );

		return $plan;
	}

	/* =================================================================
	 * Application Security
	 * ============================================================== */

	private function sync_coverage( VulnHub_Akamai_Client $client ): string {
		$res = $client->get( '/appsec/v1/hostname-coverage' );

		if ( empty( $res['ok'] ) ) {
			/* translators: %s: error from Akamai. */
			return sprintf( __( 'WAF coverage was not readable: %s', 'vulnhub' ), (string) $res['error'] );
		}

		$items = (array) ( $res['data']['hostnameCoverage'] ?? $res['data']['hostnames'] ?? array() );
		$rows  = array();
		$blind = 0;

		foreach ( $items as $item ) {
			$item     = (array) $item;
			$hostname = (string) self::pick( $item, array( 'hostname', 'hostName', 'name' ) );

			if ( '' === $hostname ) {
				++$blind;
				continue;
			}

			$status = (string) self::pick( $item, array( 'status', 'coverageStatus' ) );
			$config = (array) ( $item['configuration'] ?? array() );

			$rows[] = array(
				'hostname'  => $hostname,
				'covered'   => 0 === strcasecmp( $status, 'covered' ),
				'status'    => $status,
				'config'    => (string) self::pick( $config, array( 'name', 'configName' ) ),
				'policy'    => self::policy_names( $item ),
				'has_match' => ! empty( $item['hasMatchTarget'] ),
			);
		}

		$stored = VulnHub_Domain_Import::store_waf( $rows, 'akamai-api' );

		$said = sprintf(
			/* translators: 1: hostnames, 2: covered, 3: not covered. */
			__( 'WAF coverage: %1$d hostname(s), %2$d covered, %3$d not.', 'vulnhub' ),
			(int) $stored['rows'],
			(int) $stored['covered'],
			(int) $stored['uncovered']
		);

		if ( $blind > 0 ) {
			$said .= ' ' . sprintf(
				/* translators: %d: rows with no readable hostname. */
				__( '%d row(s) carried no hostname this reader recognises — the response shape may have changed.', 'vulnhub' ),
				$blind
			);
		}

		return $said;
	}

	/**
	 * @param array<string,mixed> $item One coverage row.
	 */
	private static function policy_names( array $item ): string {
		$names = $item['policyNames'] ?? $item['policyName'] ?? $item['policies'] ?? '';

		if ( is_array( $names ) ) {
			$names = array_map(
				static fn( $n ): string => is_array( $n ) ? (string) ( $n['policyName'] ?? $n['name'] ?? '' ) : (string) $n,
				$names
			);

			return implode( ', ', array_filter( $names ) );
		}

		return (string) $names;
	}

	/**
	 * First key that is actually present, so a renamed field is visible as a
	 * miss rather than stored as an empty string.
	 *
	 * @param array<string,mixed> $row  A response row.
	 * @param array<int,string>   $keys Candidate key names.
	 */
	private static function pick( array $row, array $keys ): string {
		foreach ( $keys as $key ) {
			if ( isset( $row[ $key ] ) && '' !== (string) $row[ $key ] ) {
				return trim( (string) $row[ $key ] );
			}
		}

		return '';
	}

	private function client(): ?VulnHub_Akamai_Client {
		$client = new VulnHub_Akamai_Client(
			(string) $this->get( 'host' ),
			(string) $this->get( 'client_token' ),
			(string) $this->secret( 'client_secret' ),
			(string) $this->get( 'access_token' ),
			(string) $this->get( 'account_key' )
		);

		return $client->configured() ? $client : null;
	}
}

