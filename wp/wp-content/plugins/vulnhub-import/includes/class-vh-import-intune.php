<?php
/**
 * Intune device export: devices and who actually uses them.
 *
 * The gap this fills is ownership. Tenable knows a machine exists and what is
 * wrong with it; it has no idea whose machine it is. Without that, a critical
 * finding on a laptop is a row nobody can be asked about, and "unassigned
 * workstations" stays the largest number on the dashboard.
 *
 * The export from Intune -- Devices › All devices › Export -- carries exactly
 * the missing half: device name, primary user, and their email. This importer
 * joins the two by device name and serial, creating the person if the platform
 * has not met them before, and writes the link through `Repo::upsert_asset()`
 * so the ownership engine, the team rollups and the SLA clock all behave as if
 * a connector had done it.
 *
 * It is a stand-in for the Intune connector rather than a competitor to it:
 * ownership set here is marked `intune-csv`, so when the API integration is
 * finally configured its own data wins and this becomes visible history rather
 * than a conflict.
 *
 * @package VulnHub\Import
 */

declare( strict_types = 1 );

use VulnHub\Core\Repo;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Row-at-a-time importer for an Intune device export.
 */
final class VulnHub_Import_Intune {

	/** Marks both the person and the ownership link as having come from here. */
	public const SOURCE = 'intune-csv';

	/**
	 * Canonical fields this shape understands.
	 *
	 * @return array<string,string>
	 */
	public static function fields(): array {
		return array(
			'hostname'         => __( 'Device name', 'vulnhub' ),
			'owner_email'      => __( 'Primary user email', 'vulnhub' ),
			'owner_name'       => __( 'Primary user display name', 'vulnhub' ),
			'serial_number'    => __( 'Serial number', 'vulnhub' ),
			'operating_system' => __( 'Operating system', 'vulnhub' ),
			'os_version'       => __( 'OS version', 'vulnhub' ),
			'manufacturer'     => __( 'Manufacturer', 'vulnhub' ),
			'model'            => __( 'Model', 'vulnhub' ),
			'intune_id'        => __( 'Intune device id', 'vulnhub' ),
			'azure_ad_device_id' => __( 'Entra device id', 'vulnhub' ),
			/*
			 * Everything below here the Graph connector has always captured
			 * and this importer silently dropped, so an estate loaded from a
			 * CSV had a NULL last check-in on every single device -- and
			 * "when did anything last see this machine" is the question the
			 * coverage screen is built on.
			 */
			'last_check_in'    => __( 'Last check-in / last sync', 'vulnhub' ),
			'compliance_state' => __( 'Compliance state', 'vulnhub' ),
			'enrolled_at'      => __( 'Enrolment date', 'vulnhub' ),
			'join_type'        => __( 'Join type', 'vulnhub' ),
			'enrollment_type'  => __( 'Enrolment type', 'vulnhub' ),
			'ownership'        => __( 'Ownership (corporate / personal)', 'vulnhub' ),
			'management_state' => __( 'Management state', 'vulnhub' ),
			'location'         => __( 'Office / location', 'vulnhub' ),
		);
	}

	/**
	 * Header spellings, most specific first.
	 *
	 * Intune's own export headers change between the portal, Graph and the
	 * older "Devices" report, and somebody will always hand you a version
	 * that has been through Excel. All of them are listed.
	 *
	 * @return array<string,array<int,string>>
	 */
	public static function aliases(): array {
		return array(
			'hostname'           => array( 'devicename', 'devicedisplayname', 'manageddevicename', 'computername', 'name', 'hostname' ),
			'owner_email'        => array( 'primaryuseremailaddress', 'primaryuseremail', 'useremailaddress', 'userprincipalname', 'upn', 'useremail', 'email' ),
			'owner_name'         => array( 'primaryuserdisplayname', 'primaryusername', 'userdisplayname', 'manageddeviceowner', 'displayname' ),
			'serial_number'      => array( 'serialnumber', 'serial' ),
			'operating_system'   => array( 'operatingsystem', 'os', 'platform' ),
			'os_version'         => array( 'osversion', 'operatingsystemversion' ),
			'manufacturer'       => array( 'manufacturer', 'make' ),
			'model'              => array( 'model' ),
			'intune_id'          => array( 'intunedeviceid', 'manageddeviceid', 'deviceid' ),
			'azure_ad_device_id' => array( 'azureaddeviceid', 'entradeviceid', 'aaddeviceid' ),
			/*
			 * The portal export, the Graph export and the older Devices
			 * report each spell the check-in column differently, and a
			 * German or French tenant exports it in that language. All the
			 * English spellings anyone has been seen to produce are listed;
			 * an unrecognised header still maps by hand on the preview
			 * screen.
			 */
			'last_check_in'    => array( 'lastsyncdatetime', 'lastcheckin', 'lastcheckindate', 'lastcheckintime', 'lastcontact', 'lastcontacteddatetime', 'lastseen', 'lastsync', 'lastsyncedon', 'lastsynced' ),
			'compliance_state' => array( 'compliancestate', 'compliance', 'devicecompliancestate', 'compliancestatus' ),
			'enrolled_at'      => array( 'enrolleddatetime', 'enrolmentdate', 'enrollmentdate', 'enrolleddate', 'dateenrolled' ),
			'join_type'        => array( 'jointype', 'azureadjointype', 'entrajointype', 'devicejointype', 'trusttype' ),
			'enrollment_type'  => array( 'deviceenrollmenttype', 'enrollmenttype', 'enrolmenttype', 'managementagent' ),
			'ownership'        => array( 'manageddeviceownertype', 'ownership', 'ownertype', 'devicoeownership', 'deviceownership' ),
			'management_state' => array( 'managementstate', 'managedby', 'managementstatus' ),
			'location'         => array( 'officelocation', 'office', 'location', 'site', 'building', 'city' ),
		);
	}

	/**
	 * Without a device name there is nothing to attach anybody to.
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
		$hostname = trim( (string) ( $record['hostname'] ?? '' ) );

		if ( '' === $hostname ) {
			VulnHub_Import_Jobs::note_failure( $counters, $line, __( 'No device name on this row.', 'vulnhub' ) );
			return;
		}

		/*
		 * Excel turns a device name that looks numeric into scientific
		 * notation -- 8.75438E+14 -- and there is no way back to the original
		 * from the string. Better to refuse the row and say so than to create
		 * an asset called "8.75438E+14".
		 */
		if ( preg_match( '/^\d(\.\d+)?E\+\d+$/i', $hostname ) ) {
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

		$person_id = self::person_for( $record, $counters );

		$data = array(
			'hostname'       => $hostname,
			'primary_source' => self::SOURCE,
		);

		foreach ( array( 'serial_number', 'operating_system', 'os_version', 'manufacturer', 'model', 'intune_id', 'azure_ad_device_id', 'compliance_state', 'join_type', 'enrollment_type' ) as $key ) {
			$value = trim( (string) ( $record[ $key ] ?? '' ) );

			if ( '' !== $value ) {
				$data[ $key ] = $value;
			}
		}

		/*
		 * The check-in date lands in two columns on purpose. `last_seen` is
		 * the estate-wide "something saw this machine" used by coverage;
		 * `last_intune_sync` is Intune's own claim, kept separately so the
		 * two can be compared -- a device Intune synced this morning that
		 * Tenable has never scanned is a very different problem from one
		 * nothing has heard from since March.
		 */
		$checked_in = self::when( (string) ( $record['last_check_in'] ?? '' ) );

		if ( '' !== $checked_in ) {
			$data['last_seen']        = $checked_in;
			$data['last_intune_sync'] = $checked_in;
		}

		$enrolled = self::when( (string) ( $record['enrolled_at'] ?? '' ) );

		if ( '' !== $enrolled ) {
			$data['first_seen'] = $enrolled;
		}

		/*
		 * A row in an Intune export is by definition a managed device with
		 * the Intune agent on it, whatever the management-state column says;
		 * the column only refines whether it is currently reachable.
		 */
		$data['is_managed'] = true;
		$data['has_agent']  = true;

		$location = trim( (string) ( $record['location'] ?? '' ) );

		if ( '' !== $location ) {
			$location_id = self::location_for( $location );

			if ( $location_id > 0 ) {
				$data['location_id'] = $location_id;
			}
		}

		$data['asset_type'] = self::asset_type_for( $record );

		if ( $person_id > 0 ) {
			$data['owner_person_id']  = $person_id;
			$data['owner_source']     = self::SOURCE;
			$data['owner_confidence'] = 'high';
			$data['owner_rule']       = __( 'Intune primary user', 'vulnhub' );
		}

		$result = Repo::upsert_asset( $data );

		if ( ! empty( $result['created'] ) ) {
			$counters['assets_created'] = (int) ( $counters['assets_created'] ?? 0 ) + 1;
		} else {
			$counters['assets_updated'] = (int) ( $counters['assets_updated'] ?? 0 ) + 1;
		}

		if ( $person_id > 0 ) {
			$counters['owners_set'] = (int) ( $counters['owners_set'] ?? 0 ) + 1;
		} else {
			// Shared and kiosk devices have no primary user. Not a failure,
			// but worth counting so the operator can see how much of the
			// estate this file cannot answer for.
			$counters['no_owner'] = (int) ( $counters['no_owner'] ?? 0 ) + 1;
		}
	}

	/**
	 * A date cell from a spreadsheet, as a timestamp the repo will accept.
	 *
	 * The day-first / month-first problem is solved once in
	 * vh_disambiguate_date() so that every import path -- this one, the CMDB
	 * shape and the Tenable asset export -- reads 07/09/2026 the same way.
	 */
	private static function when( string $raw ): string {
		return (string) vh_to_mysql( trim( $raw ) );
	}

	/**
	 * Find or create the site named on the row.
	 *
	 * Intune's own device export carries no office column, but plenty of
	 * organisations join one on before handing the file over, and an Entra
	 * user export has `officeLocation`. When it is there it is worth having:
	 * a coverage gap you cannot place is a gap nobody can send anyone to.
	 */
	private static function location_for( string $name ): int {
		$name = trim( preg_replace( '/\s+/', ' ', $name ) ?? '' );

		if ( '' === $name || strlen( $name ) > 191 ) {
			return 0;
		}

		return (int) Repo::ensure_location( $name );
	}

	/**
	 * Server or workstation?
	 *
	 * Intune enrols cloud instances and virtual machines alongside laptops and
	 * reports all of them as "Windows". Taking that at face value would file
	 * every EC2 instance in the fleet as a workstation, which then inflates
	 * "workstations without an owner" -- a server has no primary user and is
	 * never supposed to have one.
	 *
	 * The manufacturer is the reliable tell: hypervisors and cloud platforms
	 * name themselves there, and a model like `t3.xlarge` or
	 * `ProLiant DL380 Gen10 Plus` settles anything left over.
	 *
	 * @param array<string,string> $record Mapped row.
	 * @return string 'server' or 'workstation'.
	 */
	private static function asset_type_for( array $record ): string {
		$maker = strtolower( trim( (string) ( $record['manufacturer'] ?? '' ) ) );
		$model = strtolower( trim( (string) ( $record['model'] ?? '' ) ) );

		$virtual = array( 'amazon', 'vmware', 'xen', 'qemu', 'nutanix', 'parallels', 'innotek', 'oracle', 'red hat', 'google', 'hpe' );

		foreach ( $virtual as $needle ) {
			if ( '' !== $maker && str_contains( $maker, $needle ) ) {
				return 'server';
			}
		}

		// `t3.xlarge`, `m6i.large`, `c6a.2xlarge` -- an instance type, not a laptop.
		if ( 1 === preg_match( '/^[a-z][a-z0-9]*\.(nano|micro|small|medium|large|metal|[0-9]*xlarge)$/', $model ) ) {
			return 'server';
		}

		foreach ( array( 'proliant', 'poweredge', 'thinksystem', 'system x', 'virtual platform', 'virtual machine', 'rack server' ) as $needle ) {
			if ( '' !== $model && str_contains( $model, $needle ) ) {
				return 'server';
			}
		}

		return 'workstation';
	}

	/**
	 * Find or create the person named on a row.
	 *
	 * @param array<string,string> $record   Mapped row.
	 * @param array<string,mixed>  $counters Job counters, by reference.
	 * @return int Person id, or 0 when the row names nobody.
	 */
	private static function person_for( array $record, array &$counters ): int {
		$email = strtolower( trim( (string) ( $record['owner_email'] ?? '' ) ) );
		$name  = trim( (string) ( $record['owner_name'] ?? '' ) );

		if ( '' === $email || ! is_email( $email ) ) {
			return 0;
		}

		$person = Repo::upsert_person(
			array(
				'source'       => self::SOURCE,
				'source_uid'   => $email,
				'upn'          => $email,
				'email'        => $email,
				'display_name' => '' !== $name ? $name : $email,
			)
		);

		$id = (int) ( $person['id'] ?? 0 );

		if ( $id > 0 ) {
			if ( ! empty( $person['created'] ) ) {
				$counters['people_created'] = (int) ( $counters['people_created'] ?? 0 ) + 1;
			} else {
				$counters['people_seen'] = (int) ( $counters['people_seen'] ?? 0 ) + 1;
			}
		}

		return $id;
	}
}

