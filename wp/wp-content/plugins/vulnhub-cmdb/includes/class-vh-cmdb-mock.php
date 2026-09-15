<?php
/**
 * Mock payload generator.
 *
 * Core's `Mock::devices()` is the one fleet every connector must describe, so
 * the CMDB fixture is not invented here: it is the same devices, reshaped into
 * the exact JSON the ServiceNow Table API returns, and then fed through the
 * connector's live normaliser. Nothing in the sync path knows whether it is
 * looking at mock or live data.
 *
 * Only the server and network entries are emitted. That is the whole point of
 * this connector: those records carry a populated `team`, `business_service`
 * and `environment` and an EMPTY `owner_upn`, because Intune cannot tell you
 * who owns a domain controller. The CMDB can.
 *
 * @package VulnHub\Cmdb
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Builds ServiceNow-shaped and Confluence-shaped fixtures from core's fleet.
 */
final class VulnHub_Cmdb_Mock {

	/**
	 * Instance host used to build believable reference `link` values.
	 */
	private const INSTANCE = 'https://romynz.service-now.com';

	/**
	 * Asset types this connector claims from the shared fleet.
	 *
	 * @return array<int,string>
	 */
	public static function device_types(): array {
		return array( 'server', 'network' );
	}

	/**
	 * The shared devices this connector is responsible for.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function devices(): array {
		return array_values(
			array_filter(
				\VulnHub\Core\Mock::devices(),
				static fn( array $device ): bool => in_array( (string) $device['asset_type'], self::device_types(), true )
			)
		);
	}

	/**
	 * A full ServiceNow Table API response body for one table.
	 *
	 * Shape verified against the Table API reference: a single `result` key
	 * holding an array of records, with `sysparm_display_value=true` semantics
	 * — plain strings for ordinary columns, and
	 * `{"display_value":…, "link":…}` objects for reference columns, beside
	 * flat dot-walked keys such as `assigned_to.email`.
	 *
	 * @param string $table Table name.
	 * @return array{result:array<int,array<string,mixed>>}
	 */
	public static function table_response( string $table ): array {
		$records = array();

		foreach ( self::devices() as $device ) {
			if ( self::table_for( $device ) !== $table ) {
				continue;
			}
			$records[] = self::record( $device );
		}

		return array( 'result' => $records );
	}

	/**
	 * Which CI table a device would live in.
	 *
	 * ServiceNow's class tree puts servers below Computer, so an integration
	 * that queries `cmdb_ci_computer` also receives every `cmdb_ci_server`
	 * row. The fixture mirrors that: a server appears when either table is
	 * asked for, and the connector de-duplicates on `sys_id`.
	 *
	 * @param array<string,mixed> $device Shared fixture device.
	 */
	private static function table_for( array $device ): string {
		return 'network' === (string) $device['asset_type'] ? 'cmdb_ci_netgear' : 'cmdb_ci_server';
	}

	/**
	 * Tables the fixture can answer for.
	 *
	 * @param array<int,string> $requested Tables the operator configured.
	 * @return array<int,string>
	 */
	public static function resolve_tables( array $requested ): array {
		$out = array();

		foreach ( $requested as $table ) {
			$table = strtolower( trim( $table ) );

			if ( '' === $table ) {
				continue;
			}
			// cmdb_ci_computer is a superclass of cmdb_ci_server, so asking
			// for it returns the server rows too.
			if ( 'cmdb_ci_computer' === $table ) {
				$out[] = 'cmdb_ci_server';
				continue;
			}
			$out[] = $table;
		}

		return array_values( array_unique( $out ) );
	}

	/**
	 * One CI record in Table API shape.
	 *
	 * @param array<string,mixed> $device Shared fixture device.
	 * @return array<string,mixed>
	 */
	private static function record( array $device ): array {
		$hostname = (string) $device['hostname'];
		$team     = (string) $device['team'];
		$office   = (string) $device['office_location'];
		$owner    = self::owner_for( $team );
		$location = self::location_for( $office );

		$record = array(
			'sys_id'               => self::sys_id( $hostname ),
			'sys_class_name'       => self::class_name( $device ),
			'name'                 => $hostname,
			'fqdn'                 => (string) $device['fqdn'],
			'serial_number'        => (string) $device['serial'],
			'asset_tag'            => (string) $device['cmdb_id'],
			'ip_address'           => (string) $device['ipv4'],
			'os'                   => (string) $device['operating_system'],
			'os_version'           => (string) $device['os_version'],
			'manufacturer'         => (string) $device['manufacturer'],
			'model_id'             => self::reference( (string) $device['model'], 'cmdb_model', $hostname . 'model' ),
			'support_group'        => self::reference( $team, 'sys_user_group', $team ),
			'support_group.name'   => $team,
			'location'             => self::reference( $location['name'], 'cmn_location', $location['name'] ),
			'location.name'        => $location['name'],
			'location.city'        => $location['city'],
			'location.country'     => $location['country'],
			'company'              => 'Romy NZ Limited',
			'department'           => $team,
			'install_status'       => 'Installed',
			'operational_status'   => 'Operational',
			'business_criticality' => self::business_criticality( (string) $device['criticality'] ),
			'u_environment'        => ucfirst( (string) $device['environment'] ),
			'short_description'    => sprintf( '%s — %s', $hostname, (string) $device['business_service'] ),
			'sys_updated_on'       => (string) $device['last_seen'],
		);

		/*
		 * `assigned_to` is the CI's responsible individual. The shared fleet
		 * deliberately leaves `owner_upn` empty on servers and network gear —
		 * Intune has no primary user for them — so the fixture fills it the
		 * way a real CMDB does: with the manager of the department that owns
		 * the service. That exercises the person_by_upn path without
		 * inventing a person who is not in Mock::people().
		 */
		if ( $owner ) {
			$record['assigned_to']           = self::reference( (string) $owner['displayName'], 'sys_user', (string) $owner['id'] );
			$record['assigned_to.email']     = (string) $owner['mail'];
			$record['assigned_to.user_name'] = (string) $owner['userPrincipalName'];
			$record['assigned_to.name']      = (string) $owner['displayName'];
			$record['managed_by']            = $record['assigned_to'];
			$record['managed_by.email']      = (string) $owner['mail'];
		}

		// A CMDB does not know what "business_service" means to us; it holds
		// the service in its own reference column.
		$record['u_business_service'] = (string) $device['business_service'];

		return $record;
	}

	/**
	 * A ServiceNow reference field as returned with sysparm_display_value=true.
	 *
	 * @param string $display Display value.
	 * @param string $table   Referenced table.
	 * @param string $seed    Seed for the deterministic sys_id in the link.
	 * @return array{display_value:string,link:string}
	 */
	private static function reference( string $display, string $table, string $seed ): array {
		return array(
			'display_value' => $display,
			'link'          => sprintf( '%s/api/now/table/%s/%s', self::INSTANCE, $table, self::sys_id( $seed ) ),
		);
	}

	/**
	 * Deterministic 32-character sys_id.
	 */
	private static function sys_id( string $seed ): string {
		return md5( 'servicenow:' . $seed );
	}

	/**
	 * ServiceNow class name for a device.
	 *
	 * @param array<string,mixed> $device Shared fixture device.
	 */
	private static function class_name( array $device ): string {
		if ( 'network' === (string) $device['asset_type'] ) {
			$model = strtolower( (string) $device['model'] );

			if ( str_contains( $model, 'pa-' ) ) {
				return 'cmdb_ci_ip_firewall';
			}
			return 'cmdb_ci_ip_switch';
		}

		return str_contains( strtolower( (string) $device['operating_system'] ), 'windows' )
			? 'cmdb_ci_win_server'
			: 'cmdb_ci_linux_server';
	}

	/**
	 * Map our criticality ladder on to ServiceNow's choice labels.
	 */
	private static function business_criticality( string $criticality ): string {
		return match ( $criticality ) {
			'critical' => '1 - most critical',
			'high'     => '2 - somewhat critical',
			'medium'   => '3 - less critical',
			default    => '4 - not critical',
		};
	}

	/**
	 * The person a CMDB would name for a team: that department's manager in
	 * the shared people fixture.
	 *
	 * @return array<string,mixed>|null
	 */
	private static function owner_for( string $team ): ?array {
		static $managers = null;

		if ( null === $managers ) {
			$managers = array();
			foreach ( \VulnHub\Core\Mock::people() as $person ) {
				if ( ! empty( $person['isManager'] ) ) {
					$managers[ (string) $person['department'] ] = $person;
				}
			}
		}

		return $managers[ $team ] ?? null;
	}

	/**
	 * Split a fixture office string into the parts a Location record holds.
	 *
	 * @return array{name:string,city:string,country:string}
	 */
	private static function location_for( string $office ): array {
		$cities = array(
			'Auckland HQ'         => array( 'Auckland', 'New Zealand' ),
			'Wellington Office'   => array( 'Wellington', 'New Zealand' ),
			'Christchurch Office' => array( 'Christchurch', 'New Zealand' ),
			'Sydney Office'       => array( 'Sydney', 'Australia' ),
		);

		$parts = $cities[ $office ] ?? array( '', '' );

		return array(
			'name'    => $office,
			'city'    => (string) $parts[0],
			'country' => (string) $parts[1],
		);
	}

	/* =================================================================
	 * Confluence
	 * ============================================================== */

	/**
	 * A Confluence page payload carrying the same fleet as an HTML table in
	 * storage format, so the DOM parser runs over realistic markup.
	 *
	 * @return array<string,mixed>
	 */
	public static function confluence_page(): array {
		$rows = '';

		foreach ( self::devices() as $device ) {
			$rows .= sprintf(
				'<tr><td><p>%s</p></td><td>%s</td><td><p>%s</p></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>',
				esc_html( (string) $device['hostname'] ),
				esc_html( (string) $device['cmdb_id'] ),
				esc_html( (string) $device['team'] ),
				esc_html( (string) $device['business_service'] ),
				esc_html( ucfirst( (string) $device['environment'] ) ),
				esc_html( (string) $device['office_location'] ),
				esc_html( (string) $device['operating_system'] . ' ' . (string) $device['os_version'] ),
				esc_html( (string) $device['criticality'] )
			);
		}

		$storage = '<p>Maintained by the Infrastructure team. Do not edit the column headings.</p>'
			. '<table data-layout="default"><tbody>'
			. '<tr><th><p>Hostname</p></th><th>CI ID</th><th>Support Group</th><th>Business Service</th>'
			. '<th>Environment</th><th>Site</th><th>Operating System</th><th>Criticality</th></tr>'
			. $rows
			. '</tbody></table>'
			. '<ac:structured-macro ac:name="info"><ac:rich-text-body><p>Reviewed quarterly.</p></ac:rich-text-body></ac:structured-macro>';

		return array(
			'id'      => '196611',
			'status'  => 'current',
			'title'   => 'Server and Network Asset Register',
			'spaceId' => '65537',
			'body'    => array(
				'storage' => array(
					'representation' => 'storage',
					'value'          => $storage,
				),
			),
			'_links'  => array( 'webui' => '/spaces/IT/pages/196611/Server+and+Network+Asset+Register' ),
		);
	}

	/* =================================================================
	 * CSV
	 * ============================================================== */

	/**
	 * The sample CSV, rendered from the same fleet.
	 *
	 * Used to write `data/sample-cmdb.csv` and, if that file is ever missing,
	 * to keep the CSV demonstration working.
	 */
	public static function sample_csv(): string {
		$out = "Hostname,CI ID,Serial Number,IP Address,Operating System,OS Version,CI Class,Support Group,Business Service,Environment,Site,Business Criticality,Assigned To,Install Status\n";

		foreach ( self::devices() as $device ) {
			$owner  = self::owner_for( (string) $device['team'] );
			$fields = array(
				(string) $device['hostname'],
				(string) $device['cmdb_id'],
				(string) $device['serial'],
				(string) $device['ipv4'],
				(string) $device['operating_system'],
				(string) $device['os_version'],
				self::class_name( $device ),
				(string) $device['team'],
				(string) $device['business_service'],
				ucfirst( (string) $device['environment'] ),
				(string) $device['office_location'],
				(string) $device['criticality'],
				$owner ? (string) $owner['mail'] : '',
				'Installed',
			);

			$out .= implode(
				',',
				array_map(
					static fn( string $value ): string => str_contains( $value, ',' ) ? '"' . str_replace( '"', '""', $value ) . '"' : $value,
					$fields
				)
			) . "\n";
		}

		return $out;
	}
}

