<?php
/**
 * Shape detection and alias-based column mapping.
 *
 * Vendors do not agree with themselves between releases, let alone with each
 * other: the same Tenable tenant will hand you `Plugin` in one export and
 * `Plugin ID` in the next, `Asset Tags` here and `Tags` there. So nothing is
 * hardcoded to a column position — every canonical field carries a list of
 * header spellings, the importer guesses from those, and the operator gets the
 * guess in an editable table before a single row is written.
 *
 * Three shapes are recognised:
 *
 *  - `tenable_vuln`  the vulnerability export, one row per finding;
 *  - `tenable_asset` the asset-only export, which in one real 912-row file
 *                    carried nothing but `id`, `ipv4_addresses`, scan times,
 *                    `sources` and `tags` — no hostname at all;
 *  - `cmdb`          anything the CMDB plugin's own vocabulary recognises.
 *
 * @package VulnHub\Import
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Canonical field vocabularies and the header mapper.
 */
final class VulnHub_Import_Schema {

	/** Tenable vulnerability export: one row per finding. */
	public const SHAPE_VULN = 'tenable_vuln';

	/** Tenable asset export: one row per asset, often with no hostname. */
	public const SHAPE_ASSET = 'tenable_asset';

	/** Backfill plugin output onto existing findings; never creates rows. */
	public const SHAPE_VULN_ENRICH = 'tenable_vuln_enrich';

	/** A CMDB / spreadsheet asset inventory. */
	public const SHAPE_CMDB = 'cmdb';

	/** An Intune device export: devices, and the person who actually uses one. */
	public const SHAPE_INTUNE = 'intune_devices';

	/** A Defender for Endpoint device export: is the sensor actually on it? */
	public const SHAPE_DEFENDER = 'defender_devices';

	/**
	 * Normalise a header cell to a comparison key: lowercase, alphanumeric.
	 *
	 * @param string $header Raw header.
	 * @return string
	 */
	public static function slug( string $header ): string {
		$header = strtolower( trim( wp_strip_all_tags( $header ) ) );

		return (string) preg_replace( '/[^a-z0-9]/', '', $header );
	}

	/**
	 * Every shape this plugin can import, with a human label.
	 *
	 * @return array<string,string>
	 */
	public static function shapes(): array {
		return array(
			self::SHAPE_VULN  => __( 'Tenable vulnerability export (one row per finding)', 'vulnhub' ),
			self::SHAPE_ASSET => __( 'Tenable asset export (one row per asset)', 'vulnhub' ),
			self::SHAPE_VULN_ENRICH => __( 'Tenable enrichment — fill plugin output on existing findings (no new rows)', 'vulnhub' ),
			self::SHAPE_CMDB  => __( 'CMDB asset inventory', 'vulnhub' ),
			self::SHAPE_INTUNE => __( 'Intune device export (device, and its primary user)', 'vulnhub' ),
			self::SHAPE_DEFENDER => __( 'Defender for Endpoint device export (onboarding and sensor health)', 'vulnhub' ),
		);
	}

	/**
	 * Which importer owns a shape.
	 *
	 * @param string $shape Shape key.
	 * @return string `cmdb` or `tenable`.
	 */
	public static function type_for_shape( string $shape ): string {
		return match ( $shape ) {
			self::SHAPE_CMDB   => 'cmdb',
			self::SHAPE_INTUNE => 'intune',
			self::SHAPE_DEFENDER => 'defender',
			default            => 'tenable',
		};
	}

	/**
	 * Shapes an importer can handle.
	 *
	 * @param string $type Importer type.
	 * @return array<int,string>
	 */
	public static function shapes_for_type( string $type ): array {
		return match ( $type ) {
			'cmdb'   => array( self::SHAPE_CMDB ),
			'intune' => array( self::SHAPE_INTUNE ),
			'defender' => array( self::SHAPE_DEFENDER ),
			default  => array( self::SHAPE_VULN, self::SHAPE_ASSET, self::SHAPE_VULN_ENRICH ),
		};
	}

	/**
	 * Work out which of the three shapes a file is, from its headers alone.
	 *
	 * @param array<int,string> $headers Column headers.
	 * @return string Shape key.
	 */
	public static function detect_shape( array $headers ): string {
		$slugs = array();

		foreach ( $headers as $header ) {
			$slug = self::slug( (string) $header );

			if ( '' !== $slug ) {
				$slugs[ $slug ] = true;
			}
		}

		$has = static fn( string ...$keys ): bool => (bool) array_intersect( $keys, array_keys( $slugs ) );

		/*
		 * A Defender export is recognised by its onboarding column, which no
		 * other feed has any equivalent of. Checked first: the file also
		 * carries a device name, a vendor and a model, so both the Intune
		 * test below and the CMDB fallback would otherwise claim it.
		 */
		if ( $has( 'onboardingstatus', 'onboardingstate' )
			|| ( $has( 'healthstatus', 'sensorhealthstate' ) && $has( 'devicename', 'computerdnsname' ) ) ) {
			return self::SHAPE_DEFENDER;
		}

		/*
		 * An Intune device export is recognised by the pairing no other file
		 * has: a device name beside a *primary user*. Checked before the CMDB
		 * fallback, which would otherwise claim it on the strength of having
		 * a serial number and a model.
		 */
		if ( $has( 'devicename', 'manageddevicename', 'devicedisplayname' )
			&& $has( 'primaryuseremailaddress', 'primaryuseremail', 'primaryuserdisplayname', 'primaryusername', 'userprincipalname' ) ) {
			return self::SHAPE_INTUNE;
		}

		/*
		 * Tenable Vulnerability Management exports its own columns named after
		 * the API's object graph -- `definition.id`, `definition.name`,
		 * `asset.id`, `asset.ipv4_addresses` -- and shares not one spelling
		 * with the classic Nessus CSV this detector was written against. A
		 * 333 MB export of 258,545 findings was therefore read as a CMDB
		 * inventory, and every field had to be pointed at its column by hand.
		 *
		 * Checked before the asset export because it is the narrower claim:
		 * an asset-only file has no `definition.*` columns at all.
		 */
		if ( $has( 'definitionid', 'definitionname', 'definitionfamily' )
			&& $has( 'assetid', 'assetipv4addresses', 'assetname' ) ) {
			return self::SHAPE_VULN;
		}

		/*
		 * The asset-only export is unmistakable and is checked first, because
		 * it also carries `tags` and `sources`, which a vulnerability export
		 * can carry too.
		 */
		if ( $has( 'ipv4addresses', 'lastauthenticatedscantime', 'lastlicensedscantime', 'systemtypes', 'agentuuid' ) ) {
			return self::SHAPE_ASSET;
		}

		$plugin   = $has( 'plugin', 'pluginid', 'pluginname', 'definitionid', 'definitionname' );
		$vulnish  = $has( 'severity', 'risk', 'synopsis', 'vprscore', 'pluginoutput', 'cvssv3basescore', 'cvssv2basescore' );

		if ( $plugin && $vulnish ) {
			return self::SHAPE_VULN;
		}

		if ( $has( 'synopsis', 'pluginoutput', 'vprscore' ) ) {
			return self::SHAPE_VULN;
		}

		return self::SHAPE_CMDB;
	}

	/**
	 * Canonical fields for a shape, in the order an operator should see them.
	 *
	 * @param string $shape Shape key.
	 * @return array<string,string> field key => human label.
	 */
	public static function fields( string $shape ): array {
		if ( self::SHAPE_CMDB === $shape ) {
			return VulnHub_Import_Cmdb::fields();
		}

		if ( self::SHAPE_INTUNE === $shape ) {
			return VulnHub_Import_Intune::fields();
		}

		if ( self::SHAPE_DEFENDER === $shape ) {
			return VulnHub_Import_Defender::fields();
		}

		if ( self::SHAPE_VULN_ENRICH === $shape ) {
			// Same columns as a vulnerability export; only plugin_output is written.
			return self::fields( self::SHAPE_VULN );
		}

		if ( self::SHAPE_ASSET === $shape ) {
			return array(
				'asset_uuid'         => __( 'Tenable asset UUID', 'vulnhub' ),
				'ipv4s'              => __( 'IPv4 address(es)', 'vulnhub' ),
				'ipv6s'              => __( 'IPv6 address(es)', 'vulnhub' ),
				'fqdn'               => __( 'FQDN(s)', 'vulnhub' ),
				'hostname'           => __( 'Hostname / NetBIOS name', 'vulnhub' ),
				'netbios_name'       => __( 'NetBIOS name', 'vulnhub' ),
				'mac_address'        => __( 'MAC address(es)', 'vulnhub' ),
				'operating_system'   => __( 'Operating system', 'vulnhub' ),
				'system_type'        => __( 'System type', 'vulnhub' ),
				'object_type'        => __( 'Object type (host / account / identity)', 'vulnhub' ),
				'tags'               => __( 'Tags', 'vulnhub' ),
				'sources'            => __( 'Sources', 'vulnhub' ),
				'agent_uuid'         => __( 'Agent UUID', 'vulnhub' ),
				'installed_software' => __( 'Installed software', 'vulnhub' ),
				'first_seen'         => __( 'First seen', 'vulnhub' ),
				'last_seen'          => __( 'Last seen / last scan', 'vulnhub' ),
				'cloud_provider'     => __( 'Cloud provider', 'vulnhub' ),
				'cloud_account_id'   => __( 'Cloud account ID (AWS owner ID)', 'vulnhub' ),
				'cloud_region'       => __( 'Cloud region', 'vulnhub' ),
				'cloud_zone'         => __( 'Availability zone', 'vulnhub' ),
				'cloud_instance_id'  => __( 'Instance ID', 'vulnhub' ),
				'cloud_instance_type' => __( 'Instance type', 'vulnhub' ),
				'cloud_instance_name' => __( 'Instance name', 'vulnhub' ),
				'cloud_instance_state' => __( 'Instance state', 'vulnhub' ),
				'cloud_image_id'     => __( 'Image / AMI ID', 'vulnhub' ),
				'cloud_vpc_id'       => __( 'VPC ID', 'vulnhub' ),
				'cloud_subnet_id'    => __( 'Subnet ID', 'vulnhub' ),
				'cloud_resource_type' => __( 'Cloud resource type', 'vulnhub' ),
				'cloud_resource_tags' => __( 'Cloud resource tags', 'vulnhub' ),
			);
		}

		return array(
			'plugin_id'         => __( 'Plugin ID', 'vulnhub' ),
			'plugin_name'       => __( 'Plugin name', 'vulnhub' ),
			'family'            => __( 'Plugin family', 'vulnhub' ),
			'severity'          => __( 'Severity', 'vulnhub' ),
			'asset_uuid'        => __( 'Asset UUID', 'vulnhub' ),
			'ip_address'        => __( 'IP address', 'vulnhub' ),
			'dns_name'          => __( 'DNS name', 'vulnhub' ),
			'netbios_name'      => __( 'NetBIOS name', 'vulnhub' ),
			'mac_address'       => __( 'MAC address', 'vulnhub' ),
			'operating_system'  => __( 'Operating system', 'vulnhub' ),
			'port'              => __( 'Port', 'vulnhub' ),
			'protocol'          => __( 'Protocol', 'vulnhub' ),
			'service'           => __( 'Service', 'vulnhub' ),
			'cve'               => __( 'CVE', 'vulnhub' ),
			'cvss2'             => __( 'CVSS v2 base score', 'vulnhub' ),
			'cvss3'             => __( 'CVSS v3 base score', 'vulnhub' ),
			'vpr'               => __( 'VPR score', 'vulnhub' ),
			'exploit_available' => __( 'Exploit available', 'vulnhub' ),
			'synopsis'          => __( 'Synopsis', 'vulnhub' ),
			'description'       => __( 'Description', 'vulnhub' ),
			'solution'          => __( 'Solution', 'vulnhub' ),
			'see_also'          => __( 'See also', 'vulnhub' ),
			'plugin_output'     => __( 'Plugin output', 'vulnhub' ),
			'state'             => __( 'State', 'vulnhub' ),
			'vuln_state'        => __( 'Vulnerability state', 'vulnhub' ),
			'first_discovered'  => __( 'First discovered', 'vulnhub' ),
			'last_observed'     => __( 'Last observed', 'vulnhub' ),
			'plugin_pub_date'   => __( 'Plugin publication date', 'vulnhub' ),
			'patch_pub_date'    => __( 'Patch publication date', 'vulnhub' ),
			'host_start'        => __( 'Host scan start', 'vulnhub' ),
			'host_end'          => __( 'Host scan end', 'vulnhub' ),
			'tags'              => __( 'Asset tags', 'vulnhub' ),
			'scan_uuid'         => __( 'Scan / repository', 'vulnhub' ),
		);
	}

	/**
	 * Fields without which a row of this shape cannot be used at all.
	 *
	 * @param string $shape Shape key.
	 * @return array<int,string>
	 */
	public static function required( string $shape ): array {
		return match ( $shape ) {
			self::SHAPE_VULN   => array( 'plugin_id' ),
			self::SHAPE_VULN_ENRICH => array( 'plugin_id', 'plugin_output' ),
			self::SHAPE_ASSET  => array( 'asset_uuid' ),
			self::SHAPE_INTUNE => VulnHub_Import_Intune::required(),
			self::SHAPE_DEFENDER => VulnHub_Import_Defender::required(),
			default            => array( 'hostname' ),
		};
	}

	/**
	 * Header spellings for each canonical field, most specific first.
	 *
	 * @param string $shape Shape key.
	 * @return array<string,array<int,string>>
	 */
	public static function aliases( string $shape ): array {
		if ( self::SHAPE_CMDB === $shape ) {
			return VulnHub_Import_Cmdb::aliases();
		}

		if ( self::SHAPE_INTUNE === $shape ) {
			return VulnHub_Import_Intune::aliases();
		}

		if ( self::SHAPE_DEFENDER === $shape ) {
			return VulnHub_Import_Defender::aliases();
		}

		if ( self::SHAPE_ASSET === $shape ) {
			/*
			 * `displayfqdn` and `displaymacaddress` come first because the
			 * export also carries plural `fqdns` / `macaddresses` columns
			 * holding a comma-separated list; the display value is the one
			 * Tenable itself considers canonical.
			 *
			 * `hostname` deliberately prefers `hostname`/`netbiosname` over
			 * `name`: for an EC2 instance `name` is the full internal DNS
			 * name, and binding the short name to it would leave the
			 * inventory unable to match anything.
			 */
			return array(
				'asset_uuid'           => array( 'assetuuid', 'uuid', 'assetid', 'id' ),
				'ipv4s'                => array( 'ipv4addresses', 'ipv4address', 'ipv4s', 'ipv4', 'ipaddresses', 'ipaddress', 'ip' ),
				'ipv6s'                => array( 'ipv6addresses', 'ipv6address', 'ipv6s', 'ipv6' ),
				'fqdn'                 => array( 'displayfqdn', 'fqdns', 'fqdn', 'dnsnames', 'dnsname' ),
				'hostname'             => array( 'hostname', 'hostnames', 'netbiosname', 'netbiosnames', 'name' ),
				'netbios_name'         => array( 'netbiosname', 'netbiosnames' ),
				'mac_address'          => array( 'displaymacaddress', 'macaddresses', 'macaddress', 'macs', 'mac' ),
				'operating_system'     => array( 'displayoperatingsystem', 'operatingsystems', 'operatingsystem', 'os' ),
				'system_type'          => array( 'systemtypes', 'systemtype', 'assettype', 'devicetype' ),
				'object_type'          => array( 'types', 'type', 'objecttype' ),
				'tags'                 => array( 'tags', 'assettags' ),
				'sources'              => array( 'sources', 'source' ),
				'agent_uuid'           => array( 'agentuuid', 'agentuuids', 'agentnames', 'hasagent' ),
				'installed_software'   => array( 'installedsoftware', 'software' ),
				'first_seen'           => array( 'firstseen', 'createdat', 'firstscantime' ),
				'last_seen'            => array( 'lastauthenticatedscantime', 'lastlicensedscantime', 'lastseen', 'lastscantime', 'lastobserved', 'updated', 'updatedat' ),
				'cloud_provider'       => array( 'cloudcommonprovider', 'cloudprovider', 'provider' ),
				'cloud_account_id'     => array( 'awsownerid', 'cloudaccountid', 'accountid', 'subscriptionid', 'projectid' ),
				'cloud_region'         => array( 'awsregion', 'cloudruntimeregion', 'cloudregion', 'region' ),
				'cloud_zone'           => array( 'awsavailabilityzone', 'availabilityzone', 'zone' ),
				'cloud_instance_id'    => array( 'awsec2instanceid', 'instanceid' ),
				'cloud_instance_type'  => array( 'awsec2instancetype', 'instancetype' ),
				'cloud_instance_name'  => array( 'awsec2name', 'instancename' ),
				'cloud_instance_state' => array( 'awsec2instancestatename', 'instancestate', 'instancestatename' ),
				'cloud_image_id'       => array( 'awsec2instanceamiid', 'amiid', 'imageid' ),
				'cloud_vpc_id'         => array( 'awsvpcid', 'vpcid' ),
				'cloud_subnet_id'      => array( 'awssubnetid', 'subnetid' ),
				'cloud_resource_type'  => array( 'cloudcommonresourcetype', 'resourcetype' ),
				'cloud_resource_tags'  => array( 'cloudcommonresourcetags', 'resourcetags' ),
			);
		}

		/*
		 * Two vocabularies live in this list. The classic Nessus / Tenable.sc
		 * CSV spells its columns in prose -- "Plugin ID", "DNS Name", "CVSS
		 * v3 Base Score". Tenable Vulnerability Management's export names
		 * them after the API objects instead -- `definition.id`, `asset.name`,
		 * `definition.cvss3_base_score`. Slugging strips the punctuation, so
		 * both are just spellings and both belong here; a file only ever
		 * carries one of them, and a column is consumed once either way.
		 *
		 * Within a field the order is the tie-break: the more specific
		 * spelling comes first, so a file carrying both `asset.fqdn` and
		 * `asset.name` binds the DNS name to the FQDN rather than to whatever
		 * short label the scanner happened to record.
		 */
		return array(
			'plugin_id'         => array( 'pluginid', 'definitionid', 'plugin', 'pluginnumber' ),
			'plugin_name'       => array( 'pluginname', 'definitionname', 'name', 'vulnerabilityname', 'title' ),
			'family'            => array( 'pluginfamily', 'definitionfamily', 'family' ),
			'severity'          => array( 'severity', 'definitionseverity', 'risk', 'riskfactor', 'severitylevel' ),
			'asset_uuid'        => array( 'assetuuid', 'assetid', 'uuid', 'agentuuid' ),
			'ip_address'        => array( 'ipaddress', 'assetipv4addresses', 'assetipv4address', 'ipv4addresses', 'ipv4address', 'ipv4', 'ip', 'hostip' ),
			'dns_name'          => array( 'dnsname', 'assetfqdn', 'assetfqdns', 'fqdn', 'hostname', 'assetname', 'assethostname', 'host', 'dns' ),
			'netbios_name'      => array( 'netbiosname', 'assetnetbiosname', 'netbios' ),
			'mac_address'       => array( 'macaddress', 'assetmacaddress', 'assetmacaddresses', 'mac' ),
			'operating_system'  => array( 'operatingsystem', 'assetoperatingsystem', 'assetoperatingsystems', 'os' ),
			'port'              => array( 'port', 'portnumber' ),
			'protocol'          => array( 'protocol', 'proto' ),
			'service'           => array( 'service', 'servicename', 'svcname' ),
			'cve'               => array( 'cve', 'definitioncve', 'definitioncves', 'cves', 'cveid' ),
			'cvss2'             => array( 'cvssv2basescore', 'definitioncvss2basescore', 'cvss2basescore', 'cvssbasescore', 'cvss' ),
			'cvss3'             => array( 'cvssv3basescore', 'definitioncvss3basescore', 'cvss3basescore', 'cvssv3' ),
			'vpr'               => array( 'vprscore', 'definitionvprscore', 'definitionvpr', 'vpr' ),
			'exploit_available' => array( 'exploitavailable', 'definitionexploitavailable', 'exploit', 'exploitable' ),
			'synopsis'          => array( 'synopsis', 'definitionsynopsis' ),
			'description'       => array( 'description', 'definitiondescription', 'pluginsynopsis' ),
			'solution'          => array( 'solution', 'definitionsolution', 'remediation' ),
			'see_also'          => array( 'seealso', 'definitionseealso', 'definitionreferences', 'references' ),
			'plugin_output'     => array( 'pluginoutput', 'output' ),
			'state'             => array( 'state' ),
			'vuln_state'        => array( 'vulnerabilitystate', 'vulnstate' ),
			'first_discovered'  => array( 'firstdiscovered', 'firstfound', 'firstseen', 'firstobserved' ),
			'last_observed'     => array( 'lastobserved', 'lastfound', 'lastseen' ),
			'plugin_pub_date'   => array( 'pluginpublicationdate', 'definitionvulnerabilitypublished', 'definitionpluginpublished', 'vulnerabilitypublished', 'pluginpublished' ),
			'patch_pub_date'    => array( 'patchpublicationdate', 'definitionpatchpublished', 'patchpublished' ),
			'host_start'        => array( 'hoststart', 'hoststarttime', 'scanstart' ),
			'host_end'          => array( 'hostend', 'hostendtime', 'scanend' ),
			'tags'              => array( 'assettags', 'tags', 'tag' ),
			'scan_uuid'         => array( 'scanuuid', 'scanid', 'repository', 'repositoryname', 'scanname' ),
		);
	}

	/**
	 * Guess which column feeds which canonical field.
	 *
	 * Two passes, both of which consume a column only once, so a sheet with
	 * both "DNS Name" and "NetBIOS Name" never binds them to the same field.
	 * Sample rows, when available, break ties in favour of a column that
	 * actually contains something — a live CMDB export carried both an empty
	 * "Asset Tag" and a fully populated "Key", and name matching alone happily
	 * chose the empty one.
	 *
	 * @param string                          $shape   Shape key.
	 * @param array<int,string>               $headers Column headers.
	 * @param array<int,array<string,string>> $sample  A few decoded rows.
	 * @return array<string,string> canonical field => header (verbatim).
	 */
	public static function detect_mapping( string $shape, array $headers, array $sample = array() ): array {
		$by_slug = array();

		foreach ( $headers as $header ) {
			$slug = self::slug( (string) $header );

			if ( '' === $slug || isset( $by_slug[ $slug ] ) ) {
				continue;
			}

			$by_slug[ $slug ] = (string) $header;
		}

		$populated = array();

		foreach ( $by_slug as $slug => $header ) {
			foreach ( $sample as $row ) {
				if ( is_array( $row ) && '' !== trim( (string) ( $row[ $header ] ?? '' ) ) ) {
					$populated[ $slug ] = true;
					break;
				}
			}
		}

		$has_data = static fn( string $slug ): bool => ! $sample || isset( $populated[ $slug ] );

		$map  = array();
		$used = array();

		// Pass 1: exact header matches, in alias priority order, preferring a
		// column that is not empty in the sample.
		foreach ( self::aliases( $shape ) as $field => $aliases ) {
			$fallback = '';

			foreach ( $aliases as $alias ) {
				if ( ! isset( $by_slug[ $alias ] ) || isset( $used[ $alias ] ) ) {
					continue;
				}

				if ( $has_data( $alias ) ) {
					$map[ $field ]  = $by_slug[ $alias ];
					$used[ $alias ] = true;
					$fallback       = '';
					break;
				}

				if ( '' === $fallback ) {
					$fallback = $alias;
				}
			}

			if ( '' !== $fallback && ! isset( $map[ $field ] ) ) {
				$map[ $field ]     = $by_slug[ $fallback ];
				$used[ $fallback ] = true;
			}
		}

		// Pass 2: substring matches for anything still unclaimed, e.g.
		// "Primary IPv4 Address" or "Tenable Plugin Output (truncated)".
		// The minimum length is deliberately high: matching a four-letter
		// alias inside another word is how "DNS Name" becomes "Plugin Name".
		foreach ( self::aliases( $shape ) as $field => $aliases ) {
			if ( isset( $map[ $field ] ) ) {
				continue;
			}

			foreach ( $aliases as $alias ) {
				if ( strlen( $alias ) < 7 ) {
					continue;
				}

				foreach ( $by_slug as $slug => $header ) {
					if ( ! isset( $used[ $slug ] ) && str_contains( $slug, $alias ) ) {
						$map[ $field ] = $header;
						$used[ $slug ] = true;
						break 2;
					}
				}
			}
		}

		return $map;
	}

	/**
	 * Keep only mappings that name a real column, and only canonical fields.
	 *
	 * @param string                $shape   Shape key.
	 * @param array<string,mixed>   $map     Operator-supplied mapping.
	 * @param array<int,string>     $headers Column headers.
	 * @return array<string,string>
	 */
	public static function sanitise_mapping( string $shape, array $map, array $headers ): array {
		$fields = array_keys( self::fields( $shape ) );
		$valid  = array_flip( array_map( 'strval', $headers ) );
		$clean  = array();

		foreach ( $fields as $field ) {
			$header = isset( $map[ $field ] ) ? (string) $map[ $field ] : '';

			if ( '' !== $header && isset( $valid[ $header ] ) ) {
				$clean[ $field ] = $header;
			}
		}

		return $clean;
	}

	/**
	 * Apply a mapping to one raw row.
	 *
	 * @param array<string,string> $row Raw row keyed by header.
	 * @param array<string,string> $map canonical field => header.
	 * @return array<string,string>
	 */
	public static function apply( array $row, array $map ): array {
		$record = array();

		foreach ( $map as $field => $header ) {
			$record[ $field ] = (string) ( $row[ $header ] ?? '' );
		}

		return $record;
	}
}

