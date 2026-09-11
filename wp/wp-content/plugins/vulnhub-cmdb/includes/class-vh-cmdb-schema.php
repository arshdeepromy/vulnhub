<?php
/**
 * The canonical CMDB record shape, and everything that maps a foreign table
 * on to it.
 *
 * All three back ends — ServiceNow, Confluence and CSV — converge here before
 * a single row reaches `Repo::upsert_asset()`. Keeping the vocabulary in one
 * class is what lets the CSV importer, the Confluence table parser and the
 * admin column-mapping screen agree on what a "column" means.
 *
 * @package VulnHub\Cmdb
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Canonical field vocabulary and value normalisation.
 */
final class VulnHub_Cmdb_Schema {

	/**
	 * Canonical fields, in the order they should be presented to an operator.
	 *
	 * @return array<string,string> field key => human label.
	 */
	public static function fields(): array {
		return array(
			'cmdb_id'          => __( 'CI identifier', 'vulnhub' ),
			'hostname'         => __( 'Hostname', 'vulnhub' ),
			'fqdn'             => __( 'FQDN', 'vulnhub' ),
			'serial_number'    => __( 'Serial number', 'vulnhub' ),
			'ipv4'             => __( 'IPv4 address', 'vulnhub' ),
			'operating_system' => __( 'Operating system', 'vulnhub' ),
			'os_version'       => __( 'OS version', 'vulnhub' ),
			'asset_type'       => __( 'Asset type', 'vulnhub' ),
			'criticality'      => __( 'Business criticality', 'vulnhub' ),
			'environment'      => __( 'Environment', 'vulnhub' ),
			'business_service' => __( 'Business service', 'vulnhub' ),
			'team'             => __( 'Owning team / support group', 'vulnhub' ),
			'location'         => __( 'Location / site', 'vulnhub' ),
			'assigned_to'      => __( 'Assigned to / custodian (person)', 'vulnhub' ),
			'assigned_to_fallback' => __( 'Fallback owner (e.g. last logged-in user)', 'vulnhub' ),
			'mac_address'      => __( 'MAC address', 'vulnhub' ),
			'install_status'   => __( 'Install / lifecycle status', 'vulnhub' ),
			'manufacturer'     => __( 'Manufacturer / make', 'vulnhub' ),
			'model'            => __( 'Model', 'vulnhub' ),
			'support_end_date' => __( 'Support / warranty end date', 'vulnhub' ),
			'cmdb_key'         => __( 'CI reference key', 'vulnhub' ),
			'last_scan'        => __( 'Last scan / last discovered date', 'vulnhub' ),
		);
	}

	/**
	 * Fields an operator really has to map for a row to be usable.
	 *
	 * @return array<int,string>
	 */
	public static function required_fields(): array {
		return array( 'hostname' );
	}

	/**
	 * Header aliases used to auto-detect a column mapping.
	 *
	 * Keys are canonical fields; values are normalised header spellings (see
	 * `slug()`). The first alias that matches a column wins, and each column
	 * is consumed only once, so a sheet with both "Owner" and "Support Group"
	 * does not map them both on to the same field.
	 *
	 * @return array<string,array<int,string>>
	 */
	public static function aliases(): array {
		return array(
			'cmdb_id'          => array( 'cmdbid', 'datacomcmdbid', 'key', 'ciid', 'ci', 'cinumber', 'configurationitem', 'configurationitemid', 'sysid', 'assetid', 'assettag', 'citag', 'number' ),
			'hostname'         => array( 'hostname', 'host', 'ciname', 'devicename', 'computername', 'servername', 'machinename', 'name', 'device', 'server', 'system' ),
			'fqdn'             => array( 'fqdn', 'dnsname', 'fullyqualifieddomainname' ),
			'serial_number'    => array( 'serialnumber', 'serial', 'serialno', 'sn', 'servicetag' ),
			'ipv4'             => array( 'ipaddress', 'ipv4address', 'ipv4', 'ip', 'managementip', 'primaryip', 'mgmtip' ),
			'operating_system' => array( 'operatingsystem', 'os', 'platform', 'osname' ),
			'os_version'       => array( 'osversioncherwell', 'osversion', 'operatingsystemversion', 'osrelease', 'version', 'firmware', 'firmwareversion' ),
			'asset_type'       => array( 'assetcategory', 'assettype', 'citype', 'ciclass', 'sysclassname', 'class', 'devicetype', 'type', 'category' ),
			/*
			 * `servicetier` is listed here rather than left to be swept up by
			 * `business_service`, whose short 'service' alias matched "Service
			 * Tier" on a substring and bound Platinum/Bronze to the business
			 * service column -- while the actual service column, "Parent
			 * Services", went unmapped and criticality stayed empty on every
			 * row. A support tier IS the business's own statement of how much
			 * this machine matters, which is exactly what criticality is for.
			 */
			'criticality'      => array( 'businesscriticality', 'criticality', 'ucriticality', 'servicetier', 'supporttier', 'slatier', 'servicelevel', 'impact', 'businessimpact' ),
			'environment'      => array( 'environment', 'uenvironment', 'env', 'stage', 'tier', 'lifecycleenvironment' ),
			'business_service' => array( 'businessservice', 'service', 'businessapplication', 'application', 'appservice', 'supportedservice', 'systemservice', 'app' ),
			'team'             => array( 'supportgroup', 'assignmentgroup', 'owninggroup', 'owningteam', 'ownerteam', 'team', 'managedby', 'supportteam', 'owner', 'group', 'department' ),
			'location'         => array( 'location', 'site', 'office', 'datacentre', 'datacenter', 'building', 'campus', 'room', 'rack' ),
			'assigned_to'      => array( 'assignedto', 'assignedtoemail', 'assignee', 'primarycustodian', 'custodian', 'primaryuser', 'owneremail', 'useremail', 'upn', 'contact', 'technicalowner', 'responsibleperson' ),
			'assigned_to_fallback' => array( 'lastloggedinuser', 'lastloggedonuser', 'lastuser', 'lastlogonuser', 'currentuser', 'primaryenduser', 'secondarycustodian' ),
			'manufacturer'     => array( 'manufacturer', 'make', 'brand' ),
			'model'            => array( 'model', 'modelnumber', 'modelid', 'hardwaremodel', 'productname' ),
			/*
			 * Warranty expiry. A laptop past its support date cannot be
			 * patched by the vendor when the next critical lands, which
			 * makes it a security fact and not just a finance one.
			 */
			'support_end_date' => array( 'supportenddate', 'warrantyexpirationdate', 'warrantyenddate', 'warrantyexpiry', 'endofsupport', 'supportexpires', 'maintenanceenddate' ),
			/*
			 * The reference people actually quote in a ticket -- BIA-18749 --
			 * as opposed to the opaque hash the CMDB keys rows on.
			 */
			'cmdb_key'         => array( 'key', 'ciref', 'assetkey', 'cireference' ),
			'mac_address'      => array( 'macaddress', 'mac', 'physicaladdress', 'hardwareaddress', 'ethernetaddress' ),
			'install_status'   => array( 'installstatus', 'lifecyclestate', 'lifecycle', 'status', 'state', 'operationalstatus', 'assetstatus' ),
			/*
			 * When the CMDB's own discovery last saw this CI. Not the same
			 * thing as a Tenable scan and never treated as one -- but it is
			 * independent evidence that the machine still exists, which is
			 * what separates "live and unscanned" from "a record nobody
			 * retired". The live export carries it as "Last Scan Date" and
			 * this schema used to drop it on the floor.
			 */
			'last_scan'        => array( 'lastscandate', 'lastscan', 'lastdiscovered', 'lastdiscovereddate', 'lastinventory', 'lastinventorydate', 'lastseen', 'lastseendate', 'lastupdated', 'discoveredon' ),
		);
	}

	/**
	 * Normalise a header cell to a comparison key: lowercase, alphanumeric.
	 */
	public static function slug( string $header ): string {
		$header = strtolower( trim( wp_strip_all_tags( $header ) ) );

		return (string) preg_replace( '/[^a-z0-9]/', '', $header );
	}

	/**
	 * Guess which column feeds which canonical field.
	 *
	 * @param array<int,string> $headers Column headers, in sheet order.
	 * @return array<string,string> canonical field => header (verbatim).
	 */
	public static function detect_mapping( array $headers, array $sample_rows = array() ): array {
		$by_slug = array();

		foreach ( $headers as $header ) {
			$slug = self::slug( (string) $header );
			if ( '' === $slug || isset( $by_slug[ $slug ] ) ) {
				continue;
			}
			$by_slug[ $slug ] = (string) $header;
		}

		/*
		 * Which columns actually carry data?
		 *
		 * Header names alone are not enough. A live CMDB export carried both
		 * "Asset Tag" (0% populated) and "Key" (100% populated, unique); name
		 * matching alone happily bound the CI identifier to the empty one and
		 * every row then imported without an identifier. When sample rows are
		 * available we skip aliases whose column is empty in all of them, and
		 * only fall back to an empty column if nothing better matched.
		 */
		$populated = array();
		if ( $sample_rows ) {
			foreach ( $headers as $i => $header ) {
				$slug = self::slug( (string) $header );
				if ( '' === $slug ) {
					continue;
				}
				foreach ( $sample_rows as $row ) {
					$value = is_array( $row )
						? ( $row[ $i ] ?? ( $row[ $header ] ?? '' ) )
						: '';
					if ( '' !== trim( (string) $value ) ) {
						$populated[ $slug ] = true;
						break;
					}
				}
			}
		}

		$has_data = static function ( string $slug ) use ( $sample_rows, $populated ): bool {
			return ! $sample_rows || isset( $populated[ $slug ] );
		};

		$map  = array();
		$used = array();

		// Pass 1: exact alias matches, in alias priority order, preferring a
		// column that actually contains something.
		foreach ( self::aliases() as $field => $aliases ) {
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

		// Pass 2: substring matches for columns nothing claimed yet, e.g.
		// "Primary IPv4 Address" or "Owning Support Group (L2)".
		foreach ( self::aliases() as $field => $aliases ) {
			if ( isset( $map[ $field ] ) ) {
				continue;
			}
			foreach ( $aliases as $alias ) {
				if ( strlen( $alias ) < 4 ) {
					continue; // Too short to match safely inside another word.
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
	 * Apply a column mapping to one raw row.
	 *
	 * @param array<string,mixed>  $row Raw row keyed by column header.
	 * @param array<string,string> $map canonical field => header.
	 * @return array<string,string> Canonical record.
	 */
	public static function apply_mapping( array $row, array $map ): array {
		$record = array();

		foreach ( array_keys( self::fields() ) as $field ) {
			$header = (string) ( $map[ $field ] ?? '' );
			$value  = '';

			if ( '' !== $header && array_key_exists( $header, $row ) ) {
				$value = self::clean( $row[ $header ] );
			}

			$record[ $field ] = $value;
		}

		return self::normalise( $record );
	}

	/**
	 * Flatten and tidy one cell value.
	 *
	 * @param mixed $value Raw cell.
	 */
	public static function clean( mixed $value ): string {
		if ( is_array( $value ) ) {
			// ServiceNow reference fields arrive as objects.
			$value = $value['display_value'] ?? $value['value'] ?? '';
		}
		if ( ! is_scalar( $value ) ) {
			return '';
		}

		$text = (string) $value;
		$text = str_replace( array( "\xc2\xa0", "\r\n", "\r", "\n", "\t" ), ' ', $text );
		$text = wp_strip_all_tags( $text );
		$text = (string) preg_replace( '/\s+/u', ' ', $text );

		return trim( $text );
	}

	/**
	 * Tidy a whole canonical record: coerce vocabularies, fix obvious operator
	 * mistakes, and fill what can be safely derived.
	 *
	 * @param array<string,string> $record Canonical record.
	 * @return array<string,string>
	 */
	public static function normalise( array $record ): array {
		foreach ( array_keys( self::fields() ) as $field ) {
			$record[ $field ] = (string) ( $record[ $field ] ?? '' );
		}

		/*
		 * Remember whether the source actually named a class, before the
		 * inference below fills the column in. A CI class typed by a CMDB
		 * administrator is evidence; a type guessed from an OS string is not,
		 * and the two must not be trusted equally when deciding whether to
		 * re-type an asset another connector already classified.
		 */
		$record['asset_type_source'] = '' !== trim( $record['asset_type'] ) ? 'explicit' : 'inferred';

		foreach ( array( 'assigned_to_fallback', 'mac_address' ) as $added ) {
			$record[ $added ] = (string) ( $record[ $added ] ?? '' );
		}

		// A CMDB "Owner" column is ambiguous: some organisations put a group
		// there, some an individual. An email address is never a team.
		if ( '' === $record['assigned_to'] && str_contains( $record['team'], '@' ) ) {
			$record['assigned_to'] = $record['team'];
			$record['team']        = '';
		}
		/*
		 * Custodian columns are rarely a bare address. The common real-world
		 * shape is "Aditya Sharma - aditya.sharma@example.co.nz", and simply
		 * rejecting anything that fails is_email() threw the address away
		 * along with the name — which silently cost ownership on every row of
		 * a live export. Pull the address out, and keep the name so a row that
		 * carries no address at all can still be matched by display name.
		 */
		foreach ( array( 'assigned_to', 'assigned_to_fallback' ) as $person_field ) {
			$raw = (string) ( $record[ $person_field ] ?? '' );

			if ( '' === $raw || is_email( $raw ) ) {
				continue;
			}

			$parts = vh_split_person( $raw );

			$record[ $person_field . '_name' ] = $parts['name'];
			$record[ $person_field ]           = $parts['email'] !== '' ? $parts['email'] : $parts['name'];
		}

		// Hostname: accept an FQDN in the hostname column and split it.
		if ( '' === $record['fqdn'] && str_contains( $record['hostname'], '.' ) ) {
			$record['fqdn'] = $record['hostname'];
		}
		if ( str_contains( $record['hostname'], '.' ) ) {
			$record['hostname'] = (string) strtok( $record['hostname'], '.' );
		}
		$record['hostname'] = strtolower( trim( $record['hostname'] ) );
		$record['fqdn']     = strtolower( trim( $record['fqdn'] ) );

		// An IP column sometimes carries a comma or space separated list.
		if ( '' !== $record['ipv4'] ) {
			$candidates     = (array) preg_split( '/[\s,;]+/', $record['ipv4'] );
			$first          = (string) ( $candidates[0] ?? '' );
			$record['ipv4'] = filter_var( $first, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ? $first : '';
		}

		$record['asset_type']  = self::asset_type( $record['asset_type'], $record['operating_system'], $record['hostname'] );
		$record['criticality'] = self::criticality( $record['criticality'] );
		$record['environment'] = self::environment( $record['environment'] );

		return $record;
	}

	/**
	 * Map a foreign class / type string on to core's asset type vocabulary.
	 *
	 * ServiceNow sends `sys_class_name` (cmdb_ci_win_server, cmdb_ci_netgear…),
	 * a Confluence table usually holds free text ("Virtual server", "Core
	 * switch"), and a CSV can hold either. Order matters here for the same
	 * reason it does in the Tenable classifier: "Windows Server" also contains
	 * "Windows", and anything mis-typed as a workstation is then chased for an
	 * individual human owner it will never have.
	 *
	 * @param string $type     Type/class string from the source.
	 * @param string $os       Operating system, used as a fallback signal.
	 * @param string $hostname Hostname, the weakest signal of the three.
	 * @return string One of vh_asset_types().
	 */
	public static function asset_type( string $type, string $os = '', string $hostname = '' ): string {
		$needle = strtolower( trim( $type ) );

		if ( array_key_exists( $needle, vh_asset_types() ) ) {
			return $needle;
		}

		if ( '' !== $needle ) {
			// Network gear first: cmdb_ci_netgear and its descendants
			// (cmdb_ci_ip_switch, cmdb_ci_ip_router, cmdb_ci_ip_firewall).
			if ( preg_match( '/(netgear|switch|router|firewall|wireless|wap|access.?point|load.?balanc|network|wlc|ip_device)/', $needle ) ) {
				return 'network';
			}
			if ( preg_match( '/(server|esx|hypervisor|cluster.?node|database|db.?instance)/', $needle ) ) {
				return 'server';
			}
			if ( preg_match( '/(vm_instance|ec2|virtual.?machine.?instance|cloud|storage.?account|paas|azure|aws|gcp)/', $needle ) ) {
				return 'cloud';
			}
			/*
			 * The register's word for the shape, overruled by the operating
			 * system when the two disagree. ServiceNow calls a Surface Go a
			 * "Tablet"; it runs Windows 11 Enterprise, is patched on the
			 * workstation cycle and has to be scanned on it. Only a device
			 * with a genuine mobile OS -- or none recorded at all -- is
			 * taken at the register's word.
			 */
			if ( preg_match( '/(mobile|phone|tablet|ipad|handheld)/', $needle )
				&& ! vh_is_computer_os( $os ) ) {
				return 'mobile';
			}
			if ( preg_match( '/(printer|ups|appliance|camera|scanner|voip|kiosk|iot)/', $needle ) ) {
				return 'appliance';
			}
			if ( preg_match( '/(computer|workstation|desktop|laptop|notebook|pc|endpoint|client)/', $needle ) ) {
				return 'workstation';
			}
		}

		$os_needle = strtolower( trim( $os ) );

		if ( '' !== $os_needle ) {
			if ( str_contains( $os_needle, 'windows server' ) || preg_match( '/windows (2000|2003|2008|2012|2016|2019|2022|2025)/', $os_needle ) ) {
				return 'server';
			}
			/*
			 * Network firmware is tested BEFORE mobile, and deliberately
			 * includes the vendor names. A switch reports "Cisco IOS
			 * 15.2(7)E6"; matching a bare \bios\b for Apple first would file
			 * every Catalyst in the estate as a mobile device — and mobile is
			 * a user-bound type, so the platform would then chase somebody to
			 * name a human owner for a core switch.
			 */
			if ( preg_match( '/\b(ios-xe|ios xe|nx-os|pan-os|fortios|junos|aos-cx|arubaos|routeros|screenos|comware|big-ip)\b/', $os_needle ) ) {
				return 'network';
			}
			if ( preg_match( '/\b(cisco|juniper|palo alto|fortinet|aruba|mikrotik|ubiquiti|extreme networks|f5 networks)\b/', $os_needle ) ) {
				return 'network';
			}
			if ( preg_match( '/\b(ipados|iphone os|android|windows phone)\b/', $os_needle ) || preg_match( '/\bios\b/', $os_needle ) ) {
				return 'mobile';
			}
			if ( preg_match( '/\b(linux|ubuntu|debian|centos|red hat|rhel|suse|rocky|almalinux|freebsd|solaris|aix|esxi)\b/', $os_needle ) ) {
				return 'server';
			}
			if ( preg_match( '/windows (11|10|8\.1|8|7)/', $os_needle ) || preg_match( '/\b(macos|mac os x|os x|chrome ?os)\b/', $os_needle ) ) {
				return 'workstation';
			}
		}

		$host = strtolower( trim( $hostname ) );

		if ( '' !== $host ) {
			if ( preg_match( '/(^|[-_])(sw|fw|rtr|wlc|ap)([-_0-9]|$)/', $host ) ) {
				return 'network';
			}
			if ( preg_match( '/(^|[-_])(dc|sql|app|web|api|srv|svr|fs|bkp|k8s|prt|mon|vpn|dev|leg)[0-9]*$/', $host ) ) {
				return 'server';
			}
		}

		return 'unknown';
	}

	/**
	 * Map a criticality string on to core's four-step ladder.
	 *
	 * ServiceNow ships "1 - most critical" … "4 - not critical" as the
	 * `business_criticality` choice list; spreadsheets tend to hold High /
	 * Medium / Low, or a 1–5 tier number.
	 */
	public static function criticality( string $value ): string {
		$needle = strtolower( trim( $value ) );

		if ( '' === $needle ) {
			return '';
		}
		if ( in_array( $needle, array( 'critical', 'high', 'medium', 'low' ), true ) ) {
			return $needle;
		}

		/*
		 * Support tiers. Platinum and Bronze are what a managed-services CMDB
		 * records instead of a criticality, and they are a real statement of
		 * business importance -- somebody is paying for that tier. Without
		 * this the column mapped cleanly and then normalised to nothing.
		 */
		$tiers = array(
			'platinum' => 'critical',
			'diamond'  => 'critical',
			'gold'     => 'high',
			'silver'   => 'medium',
			'bronze'   => 'low',
			'standard' => 'low',
			'basic'    => 'low',
		);

		foreach ( $tiers as $tier => $level ) {
			if ( str_contains( $needle, $tier ) ) {
				return $level;
			}
		}
		if ( str_contains( $needle, 'most critical' ) || str_starts_with( $needle, '1' ) ) {
			return 'critical';
		}
		if ( str_contains( $needle, 'somewhat critical' ) || str_starts_with( $needle, '2' ) ) {
			return 'high';
		}
		if ( str_contains( $needle, 'less critical' ) || str_starts_with( $needle, '3' ) ) {
			return 'medium';
		}
		if ( str_contains( $needle, 'not critical' ) || str_starts_with( $needle, '4' ) || str_starts_with( $needle, '5' ) ) {
			return 'low';
		}
		if ( str_contains( $needle, 'crit' ) ) {
			return 'critical';
		}
		if ( str_contains( $needle, 'high' ) ) {
			return 'high';
		}
		if ( str_contains( $needle, 'med' ) || str_contains( $needle, 'moderate' ) ) {
			return 'medium';
		}
		if ( str_contains( $needle, 'low' ) || str_contains( $needle, 'minor' ) ) {
			return 'low';
		}

		return '';
	}

	/**
	 * Normalise environment names so "PROD", "Production" and "prd" are the
	 * same bucket — the mapping engine matches on this string.
	 */
	public static function environment( string $value ): string {
		$needle = strtolower( trim( $value ) );

		if ( '' === $needle ) {
			return '';
		}

		return match ( true ) {
			str_starts_with( $needle, 'prod' ), 'prd' === $needle, 'live' === $needle              => 'production',
			str_starts_with( $needle, 'stag' ), 'stg' === $needle, str_contains( $needle, 'uat' ), str_contains( $needle, 'pre-prod' ), str_contains( $needle, 'preprod' ) => 'staging',
			str_starts_with( $needle, 'dev' ), str_contains( $needle, 'sandbox' )                  => 'development',
			str_starts_with( $needle, 'test' ), 'qa' === $needle                                   => 'test',
			str_starts_with( $needle, 'corp' ), str_contains( $needle, 'office' )                  => 'corporate',
			str_contains( $needle, 'dr' ), str_contains( $needle, 'disaster' )                     => 'disaster-recovery',
			default                                                                                => vh_trim( $needle, 30 ),
		};
	}

	/**
	 * Split a location string into name / city / country for
	 * `Repo::ensure_location()`.
	 *
	 * ServiceNow's Location reference displays as "Auckland HQ" or, when the
	 * full path is shown, "New Zealand/Auckland/Auckland HQ". Confluence and
	 * CSV usually carry a comma-separated "Auckland HQ, Auckland, New Zealand".
	 *
	 * @param string $value Raw location string.
	 * @return array{name:string,city:string,country:string}
	 */
	public static function location_parts( string $value ): array {
		$value = trim( $value );

		if ( '' === $value ) {
			return array(
				'name'    => '',
				'city'    => '',
				'country' => '',
			);
		}

		if ( str_contains( $value, '/' ) ) {
			$parts   = array_values( array_filter( array_map( 'trim', explode( '/', $value ) ) ) );
			$name    = (string) end( $parts );
			$country = count( $parts ) > 1 ? (string) $parts[0] : '';
			$city    = count( $parts ) > 2 ? (string) $parts[ count( $parts ) - 2 ] : '';

			return compact( 'name', 'city', 'country' );
		}

		$parts = array_values( array_filter( array_map( 'trim', explode( ',', $value ) ) ) );

		return array(
			'name'    => (string) ( $parts[0] ?? '' ),
			'city'    => (string) ( $parts[1] ?? '' ),
			'country' => (string) ( $parts[2] ?? '' ),
		);
	}

	/**
	 * Is this record usable at all?
	 *
	 * @param array<string,string> $record Canonical record.
	 * @return string Empty string when valid, otherwise the reason.
	 */
	public static function validate( array $record ): string {
		if ( '' === trim( (string) ( $record['hostname'] ?? '' ) ) && '' === trim( (string) ( $record['cmdb_id'] ?? '' ) ) && '' === trim( (string) ( $record['serial_number'] ?? '' ) ) ) {
			return __( 'No hostname, CI identifier or serial number — the row cannot be matched to an asset.', 'vulnhub' );
		}
		if ( '' === trim( (string) ( $record['hostname'] ?? '' ) ) ) {
			return __( 'No hostname.', 'vulnhub' );
		}
		if ( strlen( (string) $record['hostname'] ) > 191 ) {
			return __( 'Hostname is longer than the 191 characters the asset table stores.', 'vulnhub' );
		}

		return '';
	}
}

