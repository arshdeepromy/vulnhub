<?php
/**
 * Mock payload factory.
 *
 * This class does exactly one job: take the shared, deterministic fleet from
 * `\VulnHub\Core\Mock` and re-shape it into *genuine Tenable export JSON*.
 * It performs no importing of its own — the connector feeds these payloads
 * through the very same normalisation methods the live export path uses, so
 * exercising mock mode genuinely exercises the live code.
 *
 * Record shapes follow the Tenable Vulnerability Management export APIs:
 *
 *  Asset chunk record  — id, has_agent, first_seen, last_seen, ipv4s[],
 *                        fqdns[], hostnames[], netbios_name, mac_addresses[],
 *                        operating_systems[], system_types[], sources[],
 *                        tags[{uuid,key,value,added_by,added_at}],
 *                        azure_vm_id, azure_resource_id, acr_score.
 *
 *  Vuln chunk record   — asset{}, plugin{}, port{}, scan{}, output, severity,
 *                        severity_id, severity_default_id, state,
 *                        first_found, last_found, last_fixed, indexed.
 *
 * @package VulnHub\Tenable
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Builds Tenable-shaped export payloads from the shared core fixtures.
 */
final class VulnHub_Tenable_Mock {

	/**
	 * Roughly this percentage of generated findings are already remediated,
	 * so the dashboards have remediation history to chart.
	 */
	private const FIXED_PERCENT = 15;

	/**
	 * Deterministic UUID from an arbitrary seed string.
	 */
	public static function uuid( string $seed ): string {
		$hash = md5( $seed );

		return sprintf(
			'%s-%s-4%s-a%s-%s',
			substr( $hash, 0, 8 ),
			substr( $hash, 8, 4 ),
			substr( $hash, 13, 3 ),
			substr( $hash, 17, 3 ),
			substr( $hash, 20, 12 )
		);
	}

	/**
	 * Stable 0-99 bucket for a (hostname, plugin, salt) triple.
	 */
	private static function bucket( string $hostname, string $plugin_id, string $salt = '' ): int {
		return (int) ( hexdec( substr( md5( $hostname . ':' . $plugin_id . ':' . $salt ), 0, 6 ) ) % 100 );
	}

	/* =================================================================
	 * Assets
	 * ============================================================== */

	/**
	 * Every fixture device, expressed as a Tenable asset export record.
	 *
	 * @param int $max_age_days Mirror of the live `last_assessed` filter:
	 *                          drop assets not scanned inside this window.
	 * @return array<int,array<string,mixed>>
	 */
	public static function asset_records( int $max_age_days = 90 ): array {
		$cutoff  = time() - max( 1, $max_age_days ) * DAY_IN_SECONDS;
		$records = array();

		foreach ( \VulnHub\Core\Mock::devices() as $device ) {
			$last_seen = strtotime( (string) $device['last_seen'] . ' UTC' );

			if ( false !== $last_seen && $last_seen < $cutoff ) {
				continue;
			}

			$records[] = self::asset_record( $device );
		}

		return $records;
	}

	/**
	 * Split asset records into export chunks, the way Tenable does.
	 *
	 * @param int $chunk_size   Assets per chunk (Tenable allows 100-10000).
	 * @param int $max_age_days Freshness window.
	 * @return array<int,array<int,array<string,mixed>>>
	 */
	public static function asset_chunks( int $chunk_size = 1000, int $max_age_days = 90 ): array {
		$records = self::asset_records( $max_age_days );

		return array_chunk( $records, max( 1, $chunk_size ) );
	}

	/**
	 * One fixture device as a Tenable asset export record.
	 *
	 * @param array<string,mixed> $device Core fixture device.
	 * @return array<string,mixed>
	 */
	public static function asset_record( array $device ): array {
		$hostname   = (string) $device['hostname'];
		$type       = (string) $device['asset_type'];
		$first_seen = gmdate( 'c', (int) strtotime( (string) $device['first_seen'] . ' UTC' ) );
		$last_seen  = gmdate( 'c', (int) strtotime( (string) $device['last_seen'] . ' UTC' ) );
		$is_windows = str_contains( (string) $device['operating_system'], 'Windows' );

		$record = array(
			'id'                          => (string) $device['tenable_uuid'],
			'has_agent'                   => (bool) $device['has_agent'],
			'has_plugin_results'          => true,
			'created_at'                  => $first_seen,
			'updated_at'                  => $last_seen,
			'first_seen'                  => $first_seen,
			'last_seen'                   => $last_seen,
			'last_scan_target'            => (string) $device['ipv4'],
			'last_licensed_scan_date'     => $last_seen,
			'last_authenticated_scan_date' => $device['has_agent'] ? $last_seen : null,
			'agent_uuid'                  => $device['has_agent'] ? str_replace( '-', '', self::uuid( 'agent' . $hostname ) ) : null,
			'bios_uuid'                   => self::uuid( 'bios' . $hostname ),
			'network_id'                  => '00000000-0000-0000-0000-000000000000',
			'network_name'                => 'Default',
			'ipv4s'                       => array( (string) $device['ipv4'] ),
			'ipv6s'                       => array(),
			'fqdns'                       => array( (string) $device['fqdn'] ),
			'hostnames'                   => array( $hostname ),
			'netbios_name'                => $is_windows ? strtoupper( $hostname ) : null,
			'mac_addresses'               => array( (string) $device['mac'] ),
			'operating_systems'           => array( self::tenable_os( $device ) ),
			'system_types'                => self::system_types( $device ),
			'agent_names'                 => $device['has_agent'] ? array( strtolower( $hostname ) ) : array(),
			'installed_software'          => array(),
			'sources'                     => array(
				array(
					'name'       => $device['has_agent'] ? 'NESSUS_AGENT' : 'NESSUS_SCAN',
					'first_seen' => $first_seen,
					'last_seen'  => $last_seen,
				),
			),
			'tags'                        => self::tags_for( $device, $last_seen ),
			'acr_score'                   => self::acr_score( (string) $device['criticality'] ),
			'exposure_score'              => 400 + ( self::bucket( $hostname, 'exposure' ) * 4 ),
		);

		/*
		 * Cloud-hosted servers carry Azure identifiers in the real export.
		 * Only the Cloud Platform estate is in Azure in this fixture.
		 */
		if ( 'server' === $type && 'Cloud Platform' === (string) $device['team'] ) {
			$record['azure_vm_id']      = self::uuid( 'azurevm' . $hostname );
			$record['azure_resource_id'] = sprintf(
				'/subscriptions/%s/resourceGroups/rg-%s/providers/Microsoft.Compute/virtualMachines/%s',
				self::uuid( 'sub' . $device['business_service'] ),
				sanitize_title( (string) $device['business_service'] ?: 'core' ),
				strtolower( $hostname )
			);
		}

		return array_filter(
			$record,
			static fn( $value ): bool => null !== $value
		);
	}

	/**
	 * Tenable's Asset Criticality Rating, derived from fixture criticality.
	 */
	private static function acr_score( string $criticality ): int {
		return match ( $criticality ) {
			'critical' => 10,
			'high'     => 8,
			'low'      => 3,
			default    => 5,
		};
	}

	/**
	 * Tenable-style operating system string.
	 *
	 * Tenable reports a full product string ("Microsoft Windows Server 2022
	 * Standard"), not the neutral family name the fixture stores, and the
	 * connector's classifier is written against that real shape.
	 *
	 * @param array<string,mixed> $device Core fixture device.
	 */
	public static function tenable_os( array $device ): string {
		$os      = (string) $device['operating_system'];
		$version = (string) $device['os_version'];

		if ( 'Windows Server' === $os ) {
			$edition = match ( true ) {
				str_starts_with( $version, '10.0.20348' ) => 'Microsoft Windows Server 2022 Standard',
				str_starts_with( $version, '10.0.17763' ) => 'Microsoft Windows Server 2019 Standard',
				str_starts_with( $version, '6.3' )        => 'Microsoft Windows Server 2012 R2 Standard',
				default                                   => 'Microsoft Windows Server',
			};

			return $edition . ' Build ' . $version;
		}

		if ( 'Windows' === $os ) {
			$product = str_starts_with( $version, '10.0.22' ) ? 'Microsoft Windows 11 Enterprise' : 'Microsoft Windows 10 Enterprise';

			return $product . ' Build ' . $version;
		}

		if ( 'macOS' === $os ) {
			return 'macOS ' . $version;
		}

		if ( 'Ubuntu' === $os ) {
			return 'Linux Kernel 5.15.0-105-generic on Ubuntu ' . $version;
		}

		if ( 'Debian' === $os ) {
			return 'Linux Kernel 6.1.0-21-amd64 on Debian ' . $version;
		}

		if ( in_array( $os, array( 'iOS', 'Android' ), true ) ) {
			return $os . ' ' . $version;
		}

		// Network gear: the fixture stores the vendor in `operating_system`
		// and the firmware train in `os_version` ("Cisco" + "IOS-XE 17.09.04a").
		return trim( $os . ' ' . $version );
	}

	/**
	 * Tenable `system_types` values for a fixture device.
	 *
	 * @param array<string,mixed> $device Core fixture device.
	 * @return array<int,string>
	 */
	public static function system_types( array $device ): array {
		if ( 'network' !== (string) $device['asset_type'] ) {
			return array( 'general-purpose' );
		}

		$hostname = strtoupper( (string) $device['hostname'] );

		return match ( true ) {
			str_contains( $hostname, 'FW' )  => array( 'firewall' ),
			str_contains( $hostname, 'WLC' ) => array( 'wireless-access-point' ),
			str_contains( $hostname, 'SW' )  => array( 'switch' ),
			default                          => array( 'router' ),
		};
	}

	/**
	 * Tenable tags for a device: the categories a real deployment uses to
	 * drive ownership — Team, Location, Environment, Business Service — plus
	 * the criticality rating.
	 *
	 * @param array<string,mixed> $device    Core fixture device.
	 * @param string              $added_at  ISO8601 timestamp.
	 * @return array<int,array<string,string>>
	 */
	private static function tags_for( array $device, string $added_at ): array {
		$categories = array(
			'Team'             => (string) $device['team'],
			'Location'         => (string) $device['office_location'],
			'Environment'      => (string) $device['environment'],
			'Business Service' => (string) $device['business_service'],
			'Criticality'      => (string) $device['criticality'],
		);

		$tags = array();

		foreach ( $categories as $key => $value ) {
			if ( '' === trim( $value ) ) {
				continue;
			}

			$tags[] = array(
				'uuid'          => self::uuid( 'tag' . $key . $value ),
				'category_uuid' => self::uuid( 'tagcat' . $key ),
				'key'           => $key,
				'value'         => $value,
				'added_by'      => self::uuid( 'tagger' ),
				'added_at'      => $added_at,
			);
		}

		return $tags;
	}

	/* =================================================================
	 * Vulnerabilities
	 * ============================================================== */

	/**
	 * Vulnerability export chunks. Tenable chunks vuln exports by *asset*,
	 * so each chunk here carries every finding for a batch of assets.
	 *
	 * @param int              $num_assets   Assets per chunk (Tenable: 50-5000).
	 * @param array<int,string> $severities  Severity slugs to include, mirroring
	 *                                       the live `filters.severity` list.
	 * @param int              $max_age_days Freshness window for assets.
	 * @return array<int,array<int,array<string,mixed>>>
	 */
	public static function vuln_chunks( int $num_assets = 500, array $severities = array(), int $max_age_days = 90 ): array {
		$cutoff  = time() - max( 1, $max_age_days ) * DAY_IN_SECONDS;
		$devices = array();

		foreach ( \VulnHub\Core\Mock::devices() as $device ) {
			$last_seen = strtotime( (string) $device['last_seen'] . ' UTC' );
			if ( false !== $last_seen && $last_seen < $cutoff ) {
				continue;
			}
			$devices[] = $device;
		}

		$chunks = array();

		foreach ( array_chunk( $devices, max( 1, $num_assets ) ) as $batch ) {
			$chunk = array();

			foreach ( $batch as $device ) {
				foreach ( self::vuln_records_for_device( $device, $severities ) as $record ) {
					$chunk[] = $record;
				}
			}

			if ( $chunk ) {
				$chunks[] = $chunk;
			}
		}

		return $chunks;
	}

	/**
	 * Tenable vulnerability records for one device.
	 *
	 * `Mock::has_vuln()` is the single source of truth for whether a device has
	 * a given plugin finding, so re-running a sync — or a later closure
	 * verification — always agrees with itself.
	 *
	 * @param array<string,mixed> $device     Core fixture device.
	 * @param array<int,string>   $severities Severity slugs to include (empty = all).
	 * @return array<int,array<string,mixed>>
	 */
	public static function vuln_records_for_device( array $device, array $severities = array() ): array {
		$hostname = (string) $device['hostname'];
		$os       = self::tenable_os( $device );

		// vulns_for_device() matches on the OS string, so hand it the Tenable
		// shaped OS — that is what a real export would contain.
		$catalogue = \VulnHub\Core\Mock::vulns_for_device( array( 'operating_system' => $os ) );
		$out       = array();

		foreach ( $catalogue as $vuln ) {
			$plugin_id = (string) $vuln[0];
			$severity  = (string) $vuln[2];

			if ( $severities && ! in_array( $severity, $severities, true ) ) {
				continue;
			}
			if ( ! \VulnHub\Core\Mock::has_vuln( $hostname, $plugin_id, $severity ) ) {
				continue;
			}

			$out[] = self::vuln_record( $device, $vuln, $os );
		}

		return $out;
	}

	/**
	 * Is this (device, plugin) pair already remediated in the fixture?
	 *
	 * Deterministic, so the importer and the closure verifier agree.
	 */
	public static function is_fixed( string $hostname, string $plugin_id ): bool {
		return self::bucket( $hostname, $plugin_id, 'fixed' ) < self::FIXED_PERCENT;
	}

	/**
	 * Build one Tenable vulnerability export record.
	 *
	 * @param array<string,mixed> $device Core fixture device.
	 * @param array<int,mixed>    $vuln   Positional core vuln fixture row.
	 * @param string              $os     Tenable OS string.
	 * @return array<string,mixed>
	 */
	private static function vuln_record( array $device, array $vuln, string $os ): array {
		$hostname  = (string) $device['hostname'];
		$plugin_id = (string) $vuln[0];
		$severity  = (string) $vuln[2];
		$last_seen = (int) strtotime( (string) $device['last_seen'] . ' UTC' );
		$spread    = self::bucket( $hostname, $plugin_id, 'age' );
		$fixed     = self::is_fixed( $hostname, $plugin_id );

		$first_found = $last_seen - ( 30 + $spread * 3 ) * DAY_IN_SECONDS;
		$last_found  = $fixed ? $last_seen - ( 5 + ( $spread % 20 ) ) * DAY_IN_SECONDS : $last_seen;
		$last_fixed  = $fixed ? $last_found + ( 1 + ( $spread % 4 ) ) * DAY_IN_SECONDS : 0;

		$port = self::port_for( $vuln );

		$record = array(
			'asset'                      => array(
				'device_type'      => 'network' === $device['asset_type'] ? 'network' : 'general-purpose',
				'fqdn'             => (string) $device['fqdn'],
				'hostname'         => $hostname,
				'uuid'             => (string) $device['tenable_uuid'],
				'ipv4'             => (string) $device['ipv4'],
				'mac_address'      => (string) $device['mac'],
				'netbios_name'     => str_contains( $os, 'Windows' ) ? strtoupper( $hostname ) : '',
				'operating_system' => array( $os ),
				'network_id'       => '00000000-0000-0000-0000-000000000000',
				'tracked'          => true,
			),
			'output'                     => self::output_for( $vuln, $device ),
			'plugin'                     => array(
				'id'                     => (int) $plugin_id,
				'name'                   => (string) $vuln[1],
				'family'                 => (string) $vuln[6],
				'family_id'              => (int) ( crc32( (string) $vuln[6] ) % 100000 ),
				'cve'                    => array_values( (array) $vuln[7] ),
				'cvss_base_score'        => (float) $vuln[3],
				'cvss3_base_score'       => (float) $vuln[4],
				'cvss_vector'            => array( 'raw' => 'AV:N/AC:L/Au:N/C:C/I:C/A:C' ),
				'description'            => (string) $vuln[8],
				'solution'               => (string) $vuln[9],
				'synopsis'               => vh_trim( (string) $vuln[8], 140 ),
				'see_also'               => self::see_also_for( $vuln ),
				'risk_factor'            => ucfirst( $severity ),
				'exploit_available'      => (bool) $vuln[10],
				'exploitability_ease'    => $vuln[10] ? 'Exploits are available' : 'No known exploits are available',
				'exploited_by_malware'   => false,
				'has_patch'              => 'n/a' !== (string) $vuln[9],
				'type'                   => 'remote',
				'patch_publication_date' => gmdate( 'Y-m-d\TH:i:s\Z', $first_found - 7 * DAY_IN_SECONDS ),
				'vpr'                    => array(
					'score'   => (float) $vuln[5],
					'drivers' => array(
						'age_of_vuln'        => array( 'lower_bound' => 30, 'upper_bound' => 180 ),
						'threat_intensity'   => $vuln[10] ? 'high' : 'low',
						'threat_sources'     => $vuln[10] ? array( 'Dark Web' ) : array( 'No recorded events' ),
						'product_coverage'   => 'medium',
						'cvss3_impact_score' => (float) $vuln[4],
					),
					'updated' => gmdate( 'Y-m-d\TH:i:s\Z', $last_seen ),
				),
			),
			'port'                       => $port,
			'scan'                       => array(
				'completed_at'   => gmdate( 'Y-m-d\TH:i:s\Z', $last_seen ),
				'schedule_uuid'  => self::uuid( 'schedule' . $device['asset_type'] ),
				'started_at'     => gmdate( 'Y-m-d\TH:i:s\Z', $last_seen - 1800 ),
				'uuid'           => self::uuid( 'scan' . $hostname . gmdate( 'Y-m-d', $last_seen ) ),
			),
			'severity'                   => $severity,
			'severity_id'                => (int) ( vh_severities()[ $severity ]['id'] ?? 0 ),
			'severity_default_id'        => (int) ( vh_severities()[ $severity ]['id'] ?? 0 ),
			'severity_modification_type' => 'NONE',
			'first_found'                => gmdate( 'Y-m-d\TH:i:s\Z', $first_found ),
			'last_found'                 => gmdate( 'Y-m-d\TH:i:s\Z', $last_found ),
			'indexed'                    => gmdate( 'Y-m-d\TH:i:s\Z', $last_seen ),
			'state'                      => $fixed ? 'FIXED' : 'OPEN',
		);

		if ( $fixed ) {
			$record['last_fixed'] = gmdate( 'Y-m-d\TH:i:s\Z', min( time(), $last_fixed ) );
		}

		return $record;
	}

	/**
	 * Deterministic port/protocol/service for a plugin, so the finding
	 * fingerprint (asset, vuln, port, protocol) is stable across syncs.
	 *
	 * @param array<int,mixed> $vuln Core vuln fixture row.
	 * @return array{port:int,protocol:string,service:string}
	 */
	private static function port_for( array $vuln ): array {
		$plugin_id = (string) $vuln[0];
		$family    = (string) $vuln[6];
		$title     = (string) $vuln[1];

		$map = array(
			'157288' => array( 445, 'TCP', 'cifs' ),   // SMB signing.
			'176321' => array( 22, 'TCP', 'ssh' ),     // OpenSSH.
			'155444' => array( 3389, 'TCP', 'msrdp' ), // Terminal Services.
			'171953' => array( 443, 'TCP', 'www' ),    // Expired certificate.
			'168746' => array( 443, 'TCP', 'www' ),    // TLS 1.0/1.1.
			'176900' => array( 443, 'TCP', 'www' ),    // nginx.
			'170233' => array( 3306, 'TCP', 'mysql' ), // MySQL / MariaDB.
			'154002' => array( 0, 'ICMP', '' ),        // ICMP timestamp.
			'183211' => array( 443, 'TCP', 'www' ),    // Cisco IOS XE web UI.
			'179322' => array( 443, 'TCP', 'www' ),    // PAN-OS GlobalProtect.
			'186122' => array( 443, 'TCP', 'www' ),    // Exchange.
		);

		if ( isset( $map[ $plugin_id ] ) ) {
			[ $port, $protocol, $service ] = $map[ $plugin_id ];

			return array(
				'port'     => $port,
				'protocol' => $protocol,
				'service'  => $service,
			);
		}

		if ( 'Web Servers' === $family || str_contains( $title, 'SSL' ) ) {
			return array(
				'port'     => 443,
				'protocol' => 'TCP',
				'service'  => 'www',
			);
		}

		if ( str_contains( $family, 'Microsoft Bulletins' ) ) {
			return array(
				'port'     => 445,
				'protocol' => 'TCP',
				'service'  => 'cifs',
			);
		}

		// Local / credentialed checks report against port 0.
		return array(
			'port'     => 0,
			'protocol' => 'TCP',
			'service'  => '',
		);
	}

	/**
	 * Plausible plugin output text.
	 *
	 * @param array<int,mixed>    $vuln   Core vuln fixture row.
	 * @param array<string,mixed> $device Core fixture device.
	 */
	private static function output_for( array $vuln, array $device ): string {
		$cves = (array) $vuln[7];

		$lines = array(
			sprintf( 'Nessus determined that %s is affected.', (string) $device['hostname'] ),
			'',
			sprintf( '  Plugin      : %s', (string) $vuln[0] ),
			sprintf( '  Installed   : %s %s', (string) $device['operating_system'], (string) $device['os_version'] ),
			sprintf( '  Risk factor : %s', ucfirst( (string) $vuln[2] ) ),
		);

		if ( $cves ) {
			$lines[] = sprintf( '  CVE         : %s', implode( ', ', array_map( 'strval', $cves ) ) );
		}

		$lines[] = '';
		$lines[] = vh_trim( (string) $vuln[9], 200 );

		return implode( "\n", $lines );
	}

	/**
	 * Reference links for a plugin.
	 *
	 * @param array<int,mixed> $vuln Core vuln fixture row.
	 * @return array<int,string>
	 */
	private static function see_also_for( array $vuln ): array {
		$links = array( 'https://www.tenable.com/plugins/nessus/' . (string) $vuln[0] );

		foreach ( (array) $vuln[7] as $cve ) {
			$links[] = 'https://nvd.nist.gov/vuln/detail/' . (string) $cve;
		}

		return $links;
	}
}

