<?php
/**
 * The Plerion cloud connector.
 *
 * Imports cloud compute instances Plerion has discovered across the estate as
 * first-class assets (keyed on their cloud instance id, so they merge with the
 * Tenable/Defender record for the same box), and records which the platform
 * considers publicly exposed. Software vulnerabilities and misconfiguration
 * findings are a deliberate phase two.
 *
 * @package VulnHub\Plerion
 */

declare( strict_types = 1 );

use VulnHub\Core\Connector;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Reads asset inventory and exposure from Plerion.
 */
final class VulnHub_Plerion_Connector extends Connector {

	public const SOURCE = 'plerion';

	/** Host-like resource types imported as assets (v1: compute instances). */
	private const ASSET_TYPES = array( 'AWS::EC2::Instance' );

	public function id(): string {
		return 'plerion';
	}

	public function label(): string {
		return __( 'Plerion', 'vulnhub' );
	}

	public function description(): string {
		return __( 'Reads cloud asset inventory and public exposure from Plerion across every connected AWS, Azure and GCP account, through one read-only API key — no role to assume in each account.', 'vulnhub' );
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

	public function supports_mock(): bool {
		return false;
	}

	/**
	 * @return array<int,array<string,mixed>>
	 */
	public function fields(): array {
		return array(
			array(
				'key'  => 'setup',
				'type' => 'note',
				'help' => __( 'Create a <strong>read-only</strong> tenant API key in Plerion (Settings → API keys) and paste it below. This connector only reads; nothing is written back to Plerion.', 'vulnhub' ),
			),
			array(
				'key'         => 'region',
				'label'       => __( 'Plerion region', 'vulnhub' ),
				'type'        => 'text',
				'required'    => true,
				'default'     => 'us',
				'placeholder' => 'us',
				'help'        => __( 'The region subdomain of your tenant host — the {region} in https://{region}.api.plerion.com (for example us, au or eu).', 'vulnhub' ),
			),
			array(
				'key'      => 'api_key',
				'label'    => __( 'API key', 'vulnhub' ),
				'type'     => 'text',
				'secret'   => true,
				'required' => true,
				'help'     => __( 'A read-only tenant API key. Encrypted at rest. Leave blank to keep the stored one.', 'vulnhub' ),
			),
			array(
				'key'         => 'providers',
				'label'       => __( 'Providers', 'vulnhub' ),
				'type'        => 'text',
				'default'     => 'AWS',
				'placeholder' => 'AWS, Azure, GCP',
				'help'        => __( 'Comma separated. Limit the import to these cloud providers. Blank imports all.', 'vulnhub' ),
			),
			array(
				'key'            => 'use_findings',
				'label'          => __( 'CSPM posture findings', 'vulnhub' ),
				'type'           => 'checkbox',
				'default'        => true,
				'checkbox_label' => __( 'Import Plerion CSPM / misconfiguration findings', 'vulnhub' ),
				'help'           => __( 'Kept in their own store and shown on their own page. They are <strong>never</strong> added to the Vulnerabilities list and <strong>never</strong> flow into a JSM or Jira ticket.', 'vulnhub' ),
			),
			array(
				'key'         => 'finding_severities',
				'label'       => __( 'CSPM severities', 'vulnhub' ),
				'type'        => 'text',
				'default'     => 'CRITICAL, HIGH',
				'placeholder' => 'CRITICAL, HIGH, MEDIUM, LOW',
				'help'        => __( 'Comma separated. Which posture-finding severities to import. Only FAILED checks are recorded.', 'vulnhub' ),
			),
		);
	}

	/** A client from the stored settings, or null when not configured. */
	private function client(): ?VulnHub_Plerion_Client {
		$key = $this->secret( 'api_key' );

		if ( '' === $key ) {
			return null;
		}

		return new VulnHub_Plerion_Client( (string) $this->get( 'region', 'us' ), $key, array( $this, 'log' ) );
	}

	/**
	 * @return array{ok:bool,message:string}
	 */
	public function test_connection(): array {
		$client = $this->client();

		if ( ! $client ) {
			return array( 'ok' => false, 'message' => __( 'Enter your Plerion region and API key first.', 'vulnhub' ) );
		}

		try {
			$tenant = $client->get( '/v1/tenant' );
		} catch ( \Throwable $e ) {
			return array(
				'ok'      => false,
				/* translators: %s: error. */
				'message' => sprintf( __( 'Plerion rejected the key or region: %s', 'vulnhub' ), $e->getMessage() ),
			);
		}

		try {
			$sample = $client->get( '/v1/tenant/assets', array( 'perPage' => 1 ) );
			$total  = (int) ( $sample['meta']['total'] ?? 0 );
		} catch ( \Throwable $e ) {
			return array(
				'ok'      => false,
				/* translators: %s: error. */
				'message' => sprintf( __( 'The key is valid but assets are not readable with it: %s', 'vulnhub' ), $e->getMessage() ),
			);
		}

		$td   = (array) ( $tenant['data'] ?? $tenant );
		$name = (string) ( $td['name'] ?? $td['tenantName'] ?? $td['id'] ?? '' );

		return array(
			'ok'      => true,
			/* translators: 1: tenant name, 2: asset count. */
			'message' => sprintf( __( 'Connected to Plerion tenant %1$s. %2$d asset(s) visible.', 'vulnhub' ), '' !== $name ? $name : '—', $total ),
		);
	}

	/**
	 * @param array<string,mixed> $args Sync arguments.
	 * @return array{ok:bool,message:string}
	 */
	protected function do_sync( array $args = array() ): array {
		$client = $this->client();

		if ( ! $client ) {
			return array( 'ok' => false, 'message' => __( 'Not configured.', 'vulnhub' ) );
		}

		$providers = array_values( array_filter( array_map( 'trim', explode( ',', (string) $this->get( 'providers', 'AWS' ) ) ) ) );

		$query = array( 'resourceTypes' => implode( ',', self::ASSET_TYPES ) );

		if ( $providers ) {
			$query['providers'] = implode( ',', $providers );
		}

		$imported = 0;
		$exposed  = 0;
		$skipped  = 0;

		try {
			$client->each_asset(
				$query,
				function ( array $row ) use ( &$imported, &$exposed, &$skipped ): void {
					if ( $this->import_asset( $row ) ) {
						++$imported;

						if ( ! empty( $row['isPubliclyExposed'] ) ) {
							++$exposed;
						}
					} else {
						++$skipped;
					}
				}
			);
		} catch ( \Throwable $e ) {
			return array(
				'ok'      => false,
				/* translators: %s: error. */
				'message' => sprintf( __( 'Plerion sync failed: %s', 'vulnhub' ), $e->getMessage() ),
			);
		}

		$posture = '';

		if ( (bool) $this->get( 'use_findings', true ) ) {
			$posture = $this->sync_findings( $client );
		}

		$this->bump( 'seen', $imported );

		return array(
			'ok'      => true,
			/* translators: 1: imported, 2: exposed, 3: skipped. */
			'message' => sprintf( __( '%1$d cloud asset(s) imported, %2$d publicly exposed, %3$d skipped.', 'vulnhub' ), $imported, $exposed, $skipped ) . $posture,
		);
	}

	/**
	 * Import CSPM posture findings into their own store. Never core findings.
	 */
	private function sync_findings( VulnHub_Plerion_Client $client ): string {
		$sev       = array_values( array_filter( array_map( 'trim', explode( ',', strtoupper( (string) $this->get( 'finding_severities', 'CRITICAL, HIGH' ) ) ) ) ) );
		$providers = array_values( array_filter( array_map( 'trim', explode( ',', (string) $this->get( 'providers', 'AWS' ) ) ) ) );

		$query = array( 'statuses' => 'FAILED' );

		if ( $sev ) {
			$query['severityLevels'] = implode( ',', $sev );
		}

		if ( $providers ) {
			$query['providers'] = implode( ',', $providers );
		}

		$now = gmdate( 'Y-m-d H:i:s' );
		$n   = 0;

		try {
			$client->each_finding(
				$query,
				function ( array $row ) use ( $now, &$n ): void {
					$this->import_finding( $row, $now );
					++$n;
				}
			);

			VulnHub_Plerion_Findings::prune( $now );
		} catch ( \Throwable $e ) {
			$this->log( 'CSPM findings: ' . $e->getMessage() );

			/* translators: %s: error. */
			return sprintf( __( ' CSPM findings partial: %s.', 'vulnhub' ), $e->getMessage() );
		}

		$this->log( sprintf( 'CSPM findings: %d imported.', $n ) );

		/* translators: %d: finding count. */
		return sprintf( __( ' %d CSPM finding(s) recorded (separate from vulnerabilities and tickets).', 'vulnhub' ), $n );
	}

	/**
	 * Map one Plerion posture finding into the CSPM store.
	 *
	 * @param array<string,mixed> $r   Plerion finding row.
	 * @param string              $now Sync timestamp.
	 */
	private function import_finding( array $r, string $now ): void {
		$prn = (string) ( $r['id'] ?? '' );

		if ( '' === $prn ) {
			return;
		}

		VulnHub_Plerion_Findings::upsert(
			array(
				'finding_prn'    => $prn,
				'detection_id'   => (string) ( $r['detectionId'] ?? '' ),
				'severity'       => (string) ( $r['severityLevel'] ?? '' ),
				'status'         => (string) ( $r['status'] ?? '' ),
				'source'         => (string) ( $r['source'] ?? '' ),
				'message'        => (string) ( $r['message'] ?? '' ),
				'resource_type'  => (string) ( $r['resourceType'] ?? '' ),
				'asset_prn'      => (string) ( $r['assetId'] ?? '' ),
				'account_id'     => (string) ( $r['providerAccountId'] ?? '' ),
				'region'         => (string) ( $r['region'] ?? '' ),
				'resource_name'  => (string) ( $r['resourceName'] ?? '' ),
				'resource_url'   => (string) ( $r['resourceURL'] ?? '' ),
				'first_observed' => (string) ( $r['firstObservedAt'] ?? '' ),
				'last_observed'  => (string) ( $r['lastObservedAt'] ?? '' ),
				'sla_due'        => (string) ( $r['slaDueAt'] ?? '' ),
				'is_exempted'    => ! empty( $r['isExempted'] ),
				'raw_json'       => (string) wp_json_encode( $r ),
			),
			$now
		);
	}

	/**
	 * Map one Plerion asset row onto an asset and upsert it.
	 *
	 * NOTE: the field names below follow the documented schema and are the one
	 * part to confirm against a live record before this ships — chiefly where
	 * the instance id lives (resourceId vs the ARN) and the operatingSystem
	 * shape.
	 *
	 * @param array<string,mixed> $r Plerion asset row.
	 */
	private function import_asset( array $r ): bool {
		$instance = (string) ( $r['resourceId'] ?? '' );

		if ( '' === $instance ) {
			return false;
		}

		$name = self::tag( $r, 'Name' );

		if ( '' === $name ) {
			$rn   = (string) ( $r['resourceName'] ?? '' );
			$name = '' !== $rn ? $rn : $instance;
		}

		$os  = (array) ( $r['operatingSystem'] ?? array() );
		$os0 = isset( $os[0] ) && is_array( $os[0] ) ? (array) $os[0] : $os;

		$provider = (string) ( $r['provider'] ?? '' );

		$payload = array(
			'primary_source'   => self::SOURCE,
			'hostname'         => $name,
			'asset_type'       => 'server',
			'operating_system' => (string) ( $os0['name'] ?? $os0['platform'] ?? '' ),
			'os_version'       => (string) ( $os0['version'] ?? '' ),
			'cloud_provider'   => $provider,
			'cloud_account_id' => (string) ( $r['providerAccountId'] ?? '' ),
			'cloud_region'     => (string) ( $r['region'] ?? '' ),
			'is_managed'       => true,
			'first_seen'       => (string) ( $r['firstObservedAt'] ?? '' ),
			'last_seen'        => (string) ( $r['lastObservedAt'] ?? '' ),
			'raw'              => array( 'plerion' => $r ),
		);

		// Key on the cloud instance id in the column that matches its provider,
		// so the row merges with a Tenable/Defender record for the same box.
		if ( 'AWS' === $provider ) {
			$payload['aws_instance_id'] = $instance;
		} elseif ( 'Azure' === $provider ) {
			$payload['azure_vm_id'] = $instance;
		} elseif ( 'GCP' === $provider ) {
			$payload['gcp_instance_id'] = $instance;
		}

		\VulnHub\Core\Repo::upsert_asset( $payload );

		return true;
	}

	/** Read a tag value by key from Plerion's Key/Value tag array. */
	private static function tag( array $r, string $key ): string {
		foreach ( (array) ( $r['tags'] ?? array() ) as $t ) {
			if ( is_array( $t ) && ( $t['Key'] ?? '' ) === $key ) {
				return (string) ( $t['Value'] ?? '' );
			}
		}

		return '';
	}
}
