<?php
/**
 * Microsoft Defender for Endpoint device export.
 *
 * Defender answers a question no other feed on this estate can. Tenable says
 * whether a machine has been scanned; the CMDB says whether it is supposed to
 * exist; Intune says who uses it. None of them says whether the endpoint agent
 * is actually running on it -- and a server with no sensor is invisible to
 * detection and response no matter how clean its vulnerability scan looks.
 *
 * The export -- Assets > Devices > Export -- carries a device inventory with
 * an onboarding status and a sensor health beside it. This importer folds it
 * into the existing inventory rather than beside it: an asset the platform
 * already knows gains its Defender identity and a `defender` entry in
 * "known by", and only a device nothing has ever heard of becomes a new row.
 *
 * Three things in a real export will quietly corrupt an inventory if taken at
 * face value, and each is handled here rather than left to the reader:
 *
 *  - `Device IPs` leads with `127.0.0.1` on some rows, which as a primary
 *    address matches every other machine that made the same mistake;
 *  - `Device MACs` repeats the same address six times in one cell;
 *  - `AAD Device Id` is all-zeros on 465 rows and genuinely duplicated across
 *    others, so it is never trusted as an identity without checking that no
 *    other asset already holds it.
 *
 * @package VulnHub\Import
 */

declare( strict_types = 1 );

use VulnHub\Core\Repo;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Row-at-a-time importer for a Defender device export.
 */
final class VulnHub_Import_Defender {

	/** Marks everything this file writes as having come from Defender. */
	public const SOURCE = 'defender-csv';

	/**
	 * Canonical fields this shape understands.
	 *
	 * @return array<string,string>
	 */
	public static function fields(): array {
		return array(
			'defender_id'         => __( 'Defender device ID', 'vulnhub' ),
			'hostname'            => __( 'Device name', 'vulnhub' ),
			'domain'              => __( 'Domain', 'vulnhub' ),
			'azure_ad_device_id'  => __( 'Entra (AAD) device ID', 'vulnhub' ),
			'device_type'         => __( 'Device type', 'vulnhub' ),
			'device_category'     => __( 'Device category', 'vulnhub' ),
			'device_subtype'      => __( 'Device subtype', 'vulnhub' ),
			'onboarding_status'   => __( 'Onboarding status', 'vulnhub' ),
			'health_status'       => __( 'Sensor health status', 'vulnhub' ),
			'risk_level'          => __( 'Risk level', 'vulnhub' ),
			'exposure_level'      => __( 'Exposure level', 'vulnhub' ),
			'managed_by'          => __( 'Managed by', 'vulnhub' ),
			'first_seen'          => __( 'First seen', 'vulnhub' ),
			'last_seen'           => __( 'Last device update', 'vulnhub' ),
			'os_platform'         => __( 'OS platform', 'vulnhub' ),
			'os_distribution'     => __( 'OS distribution', 'vulnhub' ),
			'os_version'          => __( 'OS version', 'vulnhub' ),
			'os_build'            => __( 'OS build', 'vulnhub' ),
			'ipv4s'               => __( 'Device IPs', 'vulnhub' ),
			'mac_address'         => __( 'Device MACs', 'vulnhub' ),
			'manufacturer'        => __( 'Vendor', 'vulnhub' ),
			'model'               => __( 'Model', 'vulnhub' ),
			'device_group'        => __( 'Device group', 'vulnhub' ),
			'tags'                => __( 'Tags', 'vulnhub' ),
			'device_role'         => __( 'Device role', 'vulnhub' ),
			'discovery_sources'   => __( 'Discovery sources', 'vulnhub' ),
		);
	}

	/**
	 * Header spellings, most specific first.
	 *
	 * The Defender portal, the Security Center export and the Graph
	 * `machines` endpoint each spell these differently, and the portal
	 * changed `Last device update` from `Last seen` between releases.
	 *
	 * @return array<string,array<int,string>>
	 */
	public static function aliases(): array {
		return array(
			'defender_id'        => array( 'deviceid', 'machineid', 'mdedeviceid', 'id', 'aadobjectid' ),
			'hostname'           => array( 'devicename', 'computerdnsname', 'machinename', 'name', 'hostname' ),
			'domain'             => array( 'domain', 'dnsdomain', 'domainname' ),
			'azure_ad_device_id' => array( 'aaddeviceid', 'azureaddeviceid', 'entradeviceid' ),
			'device_type'        => array( 'devicetype', 'machinetype' ),
			'device_category'    => array( 'devicecategory', 'category' ),
			'device_subtype'     => array( 'devicesubtype', 'subtype' ),
			'onboarding_status'  => array( 'onboardingstatus', 'onboardingstate', 'onboarding' ),
			'health_status'      => array( 'healthstatus', 'sensorhealthstate', 'healthstate', 'health' ),
			'risk_level'         => array( 'risklevel', 'riskscore', 'risk' ),
			'exposure_level'     => array( 'exposurelevel', 'exposurescore', 'exposure' ),
			'managed_by'         => array( 'managedby', 'managementsource' ),
			'first_seen'         => array( 'firstseen', 'firstseentimestamp', 'firstcontact' ),
			'last_seen'          => array( 'lastdeviceupdate', 'lastseen', 'lastupdatetime', 'lastcontact', 'lastseentimestamp' ),
			'os_platform'        => array( 'osplatform', 'platform' ),
			'os_distribution'    => array( 'osdistribution', 'distribution' ),
			'os_version'         => array( 'osversion', 'windows10version', 'version' ),
			'os_build'           => array( 'osbuild', 'build', 'osbuildnumber' ),
			'ipv4s'              => array( 'deviceips', 'ipaddresses', 'lastipaddress', 'ipaddress', 'ips' ),
			'mac_address'        => array( 'devicemacs', 'macaddresses', 'macaddress', 'macs' ),
			'manufacturer'       => array( 'vendor', 'manufacturer', 'make' ),
			'model'              => array( 'model' ),
			'device_group'       => array( 'group', 'devicegroup', 'machinegroup', 'rbacgroupname' ),
			'tags'               => array( 'tags', 'devicetags', 'machinetags' ),
			'device_role'        => array( 'devicerole', 'role' ),
			'discovery_sources'  => array( 'discoverysources', 'onboardingsource', 'discoverysource' ),
		);
	}

	/**
	 * Without a device name there is nothing to join to.
	 *
	 * The device ID is the stronger key and is always present in a real
	 * export, but it is only ever going to match a previous Defender import.
	 * The name is what joins Defender to Tenable, Intune and the CMDB, and
	 * without it a row can only ever create a new, unjoinable asset.
	 *
	 * @return array<int,string>
	 */
	public static function required(): array {
		return array( 'hostname' );
	}

	/**
	 * Import one row.
	 *
	 * @param array<string,string> $record   Row mapped to canonical fields.
	 * @param int                  $line     Line number, for the failure log.
	 * @param array<string,mixed>  $counters Running job counters, by reference.
	 */
	public static function import_row( array $record, int $line, array &$counters ): void {
		$hostname = strtolower( trim( (string) ( $record['hostname'] ?? '' ) ) );
		$did      = strtolower( trim( (string) ( $record['defender_id'] ?? '' ) ) );

		if ( '' === $hostname ) {
			VulnHub_Import_Jobs::note_failure( $counters, $line, __( 'No device name on this row.', 'vulnhub' ) );
			return;
		}

		/*
		 * Excel turns a hex device name into scientific notation and there is
		 * no way back to the original from the string.
		 */
		if ( 1 === preg_match( '/^\d(\.\d+)?E\+\d+$/i', $hostname ) ) {
			VulnHub_Import_Jobs::note_failure(
				$counters,
				$line,
				sprintf(
					/* translators: %s: the mangled value. */
					__( 'Device name "%s" was mangled into scientific notation by a spreadsheet. Re-export it with the column formatted as text.', 'vulnhub' ),
					$hostname
				)
			);
			return;
		}

		$seen_at  = self::when( (string) ( $record['last_seen'] ?? '' ) );
		$existing = self::locate( $did, $hostname, $record );

		/*
		 * Several Defender records, one name.
		 *
		 * Thirteen names in a real export are shared by up to eight rows --
		 * re-imaged machines that kept their name, and six identical Ricoh
		 * printers that were never given one. Only one Defender record can be
		 * the current one for an asset, and the newest is the only defensible
		 * choice: an older record describes a sensor that has since been
		 * replaced. The losing rows still count, so the operator can see that
		 * the estate has duplicate names rather than wonder why the totals
		 * are short.
		 */
		if ( $existing
			&& '' !== $did
			&& '' !== (string) $existing['defender_id']
			&& $did !== (string) $existing['defender_id'] ) {

			$held = (string) ( $existing['defender_last_seen'] ?? '' );

			if ( '' !== $held && ( '' === $seen_at || $held >= $seen_at ) ) {
				$counters['defender_name_clash'] = (int) ( $counters['defender_name_clash'] ?? 0 ) + 1;
				VulnHub_Import_Jobs::note_failure(
					$counters,
					$line,
					sprintf(
						/* translators: %s: device name. */
						__( 'Another Defender record for "%s" is more recent; this older one was not applied.', 'vulnhub' ),
						$hostname
					)
				);
				return;
			}

			$counters['defender_name_clash'] = (int) ( $counters['defender_name_clash'] ?? 0 ) + 1;
		}

		$type = self::asset_type_for( $record );

		/*
		 * A device Defender found, cannot classify, and nothing else has ever
		 * heard of is not an asset -- it is discovery noise.
		 *
		 * A real export turns up smart lights, a Tuya plug, the office
		 * TP-Link router on 192.168.1.1 and an Inner Range access-control
		 * panel: hostnames that are a bare 40-character hash, OS "Other",
		 * onboarding "insufficient info", no CMDB record. Storing them adds
		 * rows nobody can act on to an inventory whose whole value is that
		 * every row is actionable.
		 *
		 * Deliberately narrow. It fires only when all three are true -- the
		 * row would create a *new* asset, the type cannot be worked out, and
		 * this is the Defender feed. A printer Defender can classify is still
		 * created; an unclassified device the CMDB or Tenable already knows
		 * is still enriched, because there the type is the only thing
		 * missing, not the identity.
		 */
		if ( ! $existing && 'unknown' === $type ) {
			$counters['rows_rejected'] = (int) ( $counters['rows_rejected'] ?? 0 ) + 1;

			VulnHub_Import_Jobs::note_failure(
				$counters,
				$line,
				sprintf(
					/* translators: 1: device name, 2: vendor or "an unknown vendor". */
					__( 'Discovery noise, not stored: "%1$s" (%2$s) has no device type Defender could determine and no record in any other system.', 'vulnhub' ),
					$hostname,
					trim( (string) ( $record['manufacturer'] ?? '' ) ) ?: __( 'unknown vendor', 'vulnhub' )
				)
			);

			return;
		}

		$data = array(
			'hostname' => $hostname,
			'source'   => self::SOURCE,
		);

		if ( '' !== $did ) {
			$data['defender_id'] = $did;
		}

		if ( ! $existing ) {
			// Nothing has met this device before, so Defender is its origin.
			$data['primary_source'] = self::SOURCE;
		}

		/* -------------------------------------------------------------
		 * Defender's own columns. These are always written: they are what
		 * this feed is authoritative for, and nothing else supplies them.
		 * ----------------------------------------------------------- */
		$data['defender_onboarding'] = self::onboarding( (string) ( $record['onboarding_status'] ?? '' ) );
		$data['defender_health']     = trim( (string) ( $record['health_status'] ?? '' ) );
		$data['defender_risk']       = trim( (string) ( $record['risk_level'] ?? '' ) );
		$data['defender_exposure']   = trim( (string) ( $record['exposure_level'] ?? '' ) );
		$data['defender_managed_by'] = trim( (string) ( $record['managed_by'] ?? '' ) );

		if ( '' !== $seen_at ) {
			$data['defender_last_seen'] = $seen_at;
		}

		$born = self::when( (string) ( $record['first_seen'] ?? '' ) );

		if ( '' !== $born ) {
			$data['defender_first_seen'] = $born;
		}

		/*
		 * `last_seen` is the estate-wide "something saw this machine", and it
		 * is only ever moved forward. Defender writing an older date over a
		 * Tenable scan from this morning would turn a live machine into a
		 * coverage gap for no reason.
		 */
		if ( '' !== $seen_at && ( ! $existing || $seen_at > (string) ( $existing['last_seen'] ?? '' ) ) ) {
			$data['last_seen'] = $seen_at;
		}

		if ( '' !== $born && ( ! $existing || '' === (string) ( $existing['first_seen'] ?? '' ) ) ) {
			$data['first_seen'] = $born;
		}

		/*
		 * An onboarded device has the Defender sensor on it by definition,
		 * which is the whole point of the feed. A discovered-but-unsupported
		 * printer does not, and saying otherwise would let it count as
		 * managed on every other screen.
		 */
		if ( 'onboarded' === $data['defender_onboarding'] ) {
			$data['has_agent'] = true;
		}

		/* -------------------------------------------------------------
		 * Shared columns. Written only where nothing better is already
		 * there: Defender's view of an OS or a model is thinner than
		 * Tenable's or the CMDB's, and overwriting is how a good value
		 * becomes a worse one.
		 * ----------------------------------------------------------- */
		if ( ! $existing || in_array( (string) ( $existing['asset_type'] ?? '' ), array( '', 'unknown' ), true ) ) {
			if ( 'unknown' !== $type ) {
				$data['asset_type'] = $type;
			} elseif ( ! $existing ) {
				$data['asset_type'] = 'unknown';
			}
		}

		$soft = array(
			'operating_system' => self::os_name( $record ),
			'os_version'       => trim( (string) ( $record['os_version'] ?? '' ) ),
			'manufacturer'     => trim( (string) ( $record['manufacturer'] ?? '' ) ),
			'model'            => trim( (string) ( $record['model'] ?? '' ) ),
		);

		foreach ( $soft as $column => $value ) {
			if ( '' === $value ) {
				continue;
			}
			if ( ! $existing || '' === trim( (string) ( $existing[ $column ] ?? '' ) ) ) {
				$data[ $column ] = $value;
			}
		}

		$fqdn = self::fqdn( $hostname, (string) ( $record['domain'] ?? '' ) );

		if ( '' !== $fqdn && ( ! $existing || '' === trim( (string) ( $existing['fqdn'] ?? '' ) ) ) ) {
			$data['fqdn'] = $fqdn;
		}

		$ips = self::ips( (string) ( $record['ipv4s'] ?? '' ) );

		if ( $ips && ( ! $existing || '' === trim( (string) ( $existing['ipv4'] ?? '' ) ) ) ) {
			$data['ipv4s'] = implode( ',', $ips );
		}

		$mac = self::mac( (string) ( $record['mac_address'] ?? '' ) );

		if ( '' !== $mac && ( ! $existing || '' === trim( (string) ( $existing['mac_address'] ?? '' ) ) ) ) {
			$data['mac_address'] = $mac;
		}

		/*
		 * Defender is looking at the machine right now, so a device it has
		 * heard from is in service -- but only ever said about an asset
		 * nobody else has classified. The CMDB owns lifecycle, and a server
		 * the CMDB has marked for decommission is not brought back to life
		 * because its sensor is still reporting.
		 */
		if ( ! $existing && 'onboarded' === $data['defender_onboarding'] ) {
			$data['lifecycle_status'] = 'in_service';
		}

		$aad = self::aad( (string) ( $record['azure_ad_device_id'] ?? '' ), $existing );

		if ( '' !== $aad ) {
			$data['azure_ad_device_id'] = $aad;
		}

		$result = Repo::upsert_asset( $data );

		if ( ! empty( $result['created'] ) ) {
			$counters['assets_created'] = (int) ( $counters['assets_created'] ?? 0 ) + 1;
		} else {
			$counters['assets_updated'] = (int) ( $counters['assets_updated'] ?? 0 ) + 1;
		}

		$state = $data['defender_onboarding'];

		if ( 'onboarded' === $state ) {
			$counters['defender_onboarded'] = (int) ( $counters['defender_onboarded'] ?? 0 ) + 1;
		} elseif ( 'can_be_onboarded' === $state ) {
			$counters['defender_onboardable'] = (int) ( $counters['defender_onboardable'] ?? 0 ) + 1;
		} else {
			$counters['defender_unsupported'] = (int) ( $counters['defender_unsupported'] ?? 0 ) + 1;
		}
	}

	/* =================================================================
	 * Helpers
	 * ============================================================== */

	/**
	 * The asset this row is about, if the platform already holds it.
	 *
	 * This asks `Repo::match_asset()` -- the same chain every other feed
	 * uses, and the same one that decides where the write lands a moment
	 * later. It used to ask a narrower question of its own, the Defender ID
	 * and an exact name, and the two disagreeing is precisely how five Linux
	 * servers the CMDB already held were written a second time: Defender
	 * exports them as `appsrv01-corp-example`, which is no name the
	 * CMDB has ever used. Two answers to "which asset is this" is one answer
	 * too many.
	 *
	 * @param string               $defender_id Defender device ID, lowercased.
	 * @param string               $hostname    Device name, lowercased.
	 * @param array<string,string> $record      The whole row, for its domain and address.
	 * @return array<string,mixed>|null
	 */
	private static function locate( string $defender_id, string $hostname, array $record = array() ): ?array {
		global $wpdb;

		$table  = vh_table( 'assets' );
		$select = 'SELECT id, defender_id, defender_last_seen, last_seen, first_seen, asset_type,'
			. ' operating_system, os_version, manufacturer, model, fqdn, ipv4, mac_address,'
			. ' azure_ad_device_id, lifecycle_status FROM ' . $table;

		$ips = self::ips( (string) ( $record['ipv4s'] ?? '' ) );

		$match = Repo::match_asset(
			array(
				'defender_id' => $defender_id,
				'hostname'    => $hostname,
				'fqdn'        => self::fqdn( $hostname, (string) ( $record['domain'] ?? '' ) ),
				'ipv4'        => (string) ( $ips[0] ?? '' ),
			)
		);

		if ( ! $match ) {
			return null;
		}

		$row = $wpdb->get_row( $wpdb->prepare( $select . ' WHERE id = %d LIMIT 1', (int) $match['id'] ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL

		return $row ?: null;
	}

	/**
	 * An Entra device ID worth writing down.
	 *
	 * All-zeros on 465 rows of a real export, and genuinely repeated across
	 * others -- two distinct machines carrying the same value. Because the
	 * repo matches on this column, writing a duplicate would silently merge
	 * two assets on the next import. So it is only ever written when no other
	 * asset already holds it.
	 *
	 * @param string                   $raw      Column value.
	 * @param array<string,mixed>|null $existing The asset this row is about.
	 * @return string
	 */
	private static function aad( string $raw, ?array $existing ): string {
		global $wpdb;

		$v = strtolower( trim( $raw ) );

		if ( '' === $v || '' === trim( $v, '0-' ) ) {
			return '';
		}
		if ( $existing && $v === strtolower( (string) ( $existing['azure_ad_device_id'] ?? '' ) ) ) {
			return '';
		}

		$holder = (int) $wpdb->get_var(
			$wpdb->prepare( 'SELECT id FROM ' . vh_table( 'assets' ) . ' WHERE azure_ad_device_id = %s LIMIT 1', $v ) // phpcs:ignore WordPress.DB.PreparedSQL
		);

		if ( $holder > 0 && ( ! $existing || $holder !== (int) $existing['id'] ) ) {
			return '';
		}

		return $v;
	}

	/**
	 * Defender's onboarding wording, reduced to four states.
	 *
	 * @param string $raw Column value.
	 * @return string onboarded | can_be_onboarded | unsupported | insufficient_info
	 */
	public static function onboarding( string $raw ): string {
		$v = strtolower( trim( $raw ) );

		if ( '' === $v ) {
			return '';
		}
		if ( str_contains( $v, 'can be' ) || str_contains( $v, 'onboardable' ) ) {
			return 'can_be_onboarded';
		}
		if ( str_contains( $v, 'onboard' ) ) {
			return 'onboarded';
		}
		if ( str_contains( $v, 'unsupported' ) || str_contains( $v, 'not supported' ) ) {
			return 'unsupported';
		}
		if ( str_contains( $v, 'insufficient' ) ) {
			return 'insufficient_info';
		}

		return 'insufficient_info';
	}

	/**
	 * Server, workstation, or something that is neither.
	 *
	 * Defender classifies far more than the other feeds do -- an export from
	 * this estate holds thirteen printers, forty-nine switches and eleven
	 * video-conference units alongside the laptops. Filing those as
	 * workstations would put sixty machines nobody can patch onto the
	 * workstation coverage gap list.
	 *
	 * @param array<string,string> $record Mapped row.
	 * @return string A key of vh_asset_types().
	 */
	private static function asset_type_for( array $record ): string {
		$type  = strtolower( trim( (string) ( $record['device_type'] ?? '' ) ) );
		$sub   = strtolower( trim( (string) ( $record['device_subtype'] ?? '' ) ) );
		$group = strtolower( trim( (string) ( $record['device_group'] ?? '' ) ) );
		$os    = strtolower( trim( (string) ( $record['os_platform'] ?? '' ) ) . ' ' . (string) ( $record['os_distribution'] ?? '' ) );

		/*
		 * Defender reports a form factor too, and it is overruled the same
		 * way the CMDB's is: a device it calls Mobile that reports Windows or
		 * a desktop Linux is a computer somebody carries, not a phone.
		 */
		if ( 'mobile' === $type && vh_is_computer_os( $os ) ) {
			$type = 'workstation';
		}

		switch ( $type ) {
			case 'workstation':
				return 'workstation';
			case 'server':
				return 'server';
			case 'mobile':
				return 'mobile';
			case 'network device':
				return 'network';
			case 'printer':
			case 'audio and video':
			case 'communication':
			case 'smart facility':
			case 'smart appliance':
			case 'surveillance':
				return 'appliance';
		}

		// Defender says "Unknown" for 93 devices here. The subtype, the OS and
		// the device group each settle a share of them.
		if ( in_array( $sub, array( 'server', 'servermanagement', 'nas' ), true ) ) {
			return 'server';
		}
		if ( in_array( $sub, array( 'router', 'switch', 'firewall' ), true ) ) {
			return 'network';
		}
		if ( in_array( $sub, array( 'workstation', 'allinone' ), true ) ) {
			return 'workstation';
		}
		if ( in_array( $sub, array( 'smartdisplay', 'videoconference', 'embeddeddevice' ), true ) ) {
			return 'appliance';
		}
		if ( str_contains( $os, 'server' ) ) {
			return 'server';
		}
		if ( str_contains( $group, 'server' ) ) {
			return 'server';
		}

		return 'unknown';
	}

	/**
	 * A readable operating-system name.
	 *
	 * Defender writes `WindowsServer2019` and `Windows11` with no spaces, so
	 * taken raw the OS column on the assets screen reads as a product code.
	 *
	 * @param array<string,string> $record Mapped row.
	 * @return string
	 */
	private static function os_name( array $record ): string {
		$raw = trim( (string) ( $record['os_platform'] ?? '' ) );

		if ( '' === $raw ) {
			$raw = trim( (string) ( $record['os_distribution'] ?? '' ) );
		}
		if ( '' === $raw ) {
			return '';
		}

		$spaced = (string) preg_replace( '/(?<=[a-z])(?=[A-Z0-9])/', ' ', $raw );

		return trim( (string) preg_replace( '/\s+/', ' ', $spaced ) );
	}

	/**
	 * The device's own name plus its domain, where both are real.
	 *
	 * `Workgroup` is not a domain and neither is a cloud-internal suffix that
	 * changes every time an instance is replaced.
	 *
	 * @param string $hostname Short name, lowercased.
	 * @param string $domain   Domain column.
	 * @return string
	 */
	private static function fqdn( string $hostname, string $domain ): string {
		$d = strtolower( trim( $domain ) );

		if ( '' === $d || 'workgroup' === $d || ! str_contains( $d, '.' ) ) {
			return '';
		}
		if ( str_contains( $hostname, '.' ) ) {
			return $hostname;
		}

		return $hostname . '.' . $d;
	}

	/**
	 * Routable addresses from the `Device IPs` cell, in order.
	 *
	 * Eleven rows in a real export lead with `127.0.0.1`. Stored as the
	 * primary address that matches every other machine that did the same,
	 * and the inventory folds them into one.
	 *
	 * @param string $raw Comma-separated list.
	 * @return array<int,string>
	 */
	private static function ips( string $raw ): array {
		$out = array();

		foreach ( explode( ',', $raw ) as $candidate ) {
			$ip = vh_clean_ip( trim( $candidate ) );

			if ( '' === $ip || isset( $out[ $ip ] ) ) {
				continue;
			}
			if ( self::is_local( $ip ) ) {
				continue;
			}

			$out[ $ip ] = true;
		}

		return array_keys( $out );
	}

	/**
	 * Loopback, link-local and unspecified addresses, which identify nothing.
	 *
	 * RFC1918 space is emphatically *not* in this list: almost every asset on
	 * this estate lives on 10.165/16.
	 *
	 * @param string $ip A validated address.
	 * @return bool
	 */
	private static function is_local( string $ip ): bool {
		if ( str_starts_with( $ip, '127.' ) || str_starts_with( $ip, '169.254.' ) ) {
			return true;
		}
		if ( '0.0.0.0' === $ip || '::' === $ip || '::1' === $ip ) {
			return true;
		}

		return str_starts_with( strtolower( $ip ), 'fe80:' );
	}

	/**
	 * One MAC address from a cell that repeats it six times.
	 *
	 * @param string $raw Comma-separated list.
	 * @return string
	 */
	private static function mac( string $raw ): string {
		foreach ( explode( ',', $raw ) as $candidate ) {
			$mac = vh_clean_mac( trim( $candidate ) );

			if ( '' !== $mac && '00:00:00:00:00:00' !== $mac ) {
				return $mac;
			}
		}

		return '';
	}

	/**
	 * A date cell as a timestamp the repo will accept.
	 *
	 * @param string $raw Column value.
	 * @return string
	 */
	private static function when( string $raw ): string {
		return (string) vh_to_mysql( trim( $raw ) );
	}
}
