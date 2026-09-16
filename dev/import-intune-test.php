<?php
/**
 * End-to-end: a realistic Intune portal export, through header detection,
 * mapping and import, then read back off the asset.
 */
global $wpdb;

$headers = array(
	'Device name', 'Managed by', 'Ownership', 'Compliance', 'OS', 'OS version',
	'Primary user UPN', 'Primary user email address', 'Primary user display name',
	'Last check-in', 'Enrolled date', 'Serial number', 'Manufacturer', 'Model',
	'Intune Device ID', 'Azure AD Device ID', 'Join type', 'Office location',
);

$shape = VulnHub_Import_Schema::detect_shape( $headers );
printf( "detected shape: %s\n", $shape );

$map = VulnHub_Import_Schema::detect_mapping( $shape, $headers );

echo "auto-detected mapping:\n";
foreach ( $map as $field => $header ) {
	printf( "  %-18s <- %s\n", $field, $header );
}

$missed = array_diff( array_keys( VulnHub_Import_Schema::fields( $shape ) ), array_keys( array_filter( $map ) ) );
printf( "unmapped fields: %s\n\n", $missed ? implode( ', ', $missed ) : '(none)' );

$row = array(
	'Device name'               => 'VH-CSVTEST-01',
	'Managed by'                => 'MDM',
	'Ownership'                 => 'Corporate',
	'Compliance'                => 'Compliant',
	'OS'                        => 'Windows',
	'OS version'                => '10.0.26100.2033',
	'Primary user UPN'          => 'csvtest.person@example.com',
	'Primary user email address' => 'csvtest.person@example.com',
	'Primary user display name' => 'CSV Test Person',
	'Last check-in'             => '07/09/2026 06:14:22',   // day-first, as an NZ export writes it
	'Enrolled date'             => '2024-02-11T03:00:00Z',
	'Serial number'             => 'CSVTEST12345',
	'Manufacturer'              => 'Dell Inc.',
	'Model'                     => 'Latitude 5450',
	'Intune Device ID'          => 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
	'Azure AD Device ID'        => '11111111-2222-3333-4444-555555555555',
	'Join type'                 => 'Azure AD joined',
	'Office location'           => 'Southern Office',
);

$record   = VulnHub_Import_Schema::apply( $row, $map );
$counters = array();
VulnHub_Import_Intune::import_row( $record, 2, $counters );

$a = $wpdb->get_row(
	$wpdb->prepare( 'SELECT * FROM ' . vh_table( 'assets' ) . ' WHERE hostname = %s', 'vh-csvtest-01' ),
	ARRAY_A
);

if ( ! $a ) {
	echo "FAILED: the asset was not created\n";
	return;
}

foreach ( array( 'hostname', 'serial_number', 'operating_system', 'os_version', 'model',
	'compliance_state', 'join_type', 'enrollment_type', 'is_managed', 'has_agent',
	'last_seen', 'last_intune_sync', 'first_seen', 'location_id', 'asset_type', 'owner_person_id' ) as $k ) {
	printf( "  %-18s %s\n", $k, (string) ( $a[ $k ] ?? '' ) );
}

$loc = VulnHub\Core\Repo::location( (int) $a['location_id'] );
printf( "  %-18s %s\n", 'site name', (string) ( $loc['name'] ?? '(none)' ) );

// Clean up so the estate is left exactly as it was.
$wpdb->delete( vh_table( 'assets' ), array( 'id' => (int) $a['id'] ) );
$wpdb->delete( vh_table( 'locations' ), array( 'id' => (int) $a['location_id'] ) );
$wpdb->delete( vh_table( 'people' ), array( 'email' => 'csvtest.person@example.com' ) );
echo "\n(test asset, site and person removed)\n";
