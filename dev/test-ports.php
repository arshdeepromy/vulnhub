<?php
/**
 * Unit checks for VulnHub_Threat_Ports::parse() and the remote/kind knowledge.
 *
 *     docker compose cp dev/test-ports.php wpcli:/tmp/tp.php
 *     docker compose exec -T wpcli wp eval-file /tmp/tp.php
 *
 * The shapes here are real Netstat Portscanner output from this estate, plus
 * the text form the same plugin produces through a CSV export -- both are read
 * so a change of import route cannot silently empty the table.
 *
 * @package VulnHub
 */

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	exit( "Run this through wp-cli - see the header for the docker compose cp/exec pair.\n" );
}

$fails = 0;
$check = static function ( string $label, $got, $want ) use ( &$fails ): void {
	$ok = $got === $want;
	printf( "  [%s] %s\n", $ok ? ' ok ' : 'FAIL', $label );
	if ( ! $ok ) {
		printf( "         want: %s\n         got : %s\n", var_export( $want, true ), var_export( $got, true ) );
		$fails++;
	}
};

echo "parse():\n";

$json = '{"listening":[{"port":135,"protocol":"TCP","interfaces":null,"all_interfaces":false},'
	. '{"port":445,"protocol":"TCP"},{"port":49664,"protocol":"TCP"}]}';

$check( 'JSON shape, ports and protocols', VulnHub_Threat_Ports::parse( $json ), array( 135 => 'tcp', 445 => 'tcp', 49664 => 'tcp' ) );
$check( 'empty output', VulnHub_Threat_Ports::parse( '' ), array() );
$check( 'json with no listening key', VulnHub_Threat_Ports::parse( '{"other":1}' ), array() );

$check(
	'text shape from a CSV export',
	VulnHub_Threat_Ports::parse( "Port 22/tcp was found to be open\nPort 443/tcp was found to be open" ),
	array( 22 => 'tcp', 443 => 'tcp' )
);

$check( 'udp is kept distinct', VulnHub_Threat_Ports::parse( '161/udp' ), array( 161 => 'udp' ) );

// A version string must never be read as a port.
$check( 'a version number is not a port', VulnHub_Threat_Ports::parse( 'OpenSSL 8.1.3 is installed' ), array() );
$check( 'out-of-range port is dropped', VulnHub_Threat_Ports::parse( '99999/tcp' ), array() );

echo "\nis_remote() / kind():\n";

$check( '443 is remote', VulnHub_Threat_Ports::is_remote( 443 ), true );
$check( '445 is remote', VulnHub_Threat_Ports::is_remote( 445 ), true );
$check( 'an ephemeral port is not', VulnHub_Threat_Ports::is_remote( 49664 ), false );
$check( 'Delivery Optimization (7680) is not', VulnHub_Threat_Ports::is_remote( 7680 ), false );
$check( 'SSDP (1900) is not', VulnHub_Threat_Ports::is_remote( 1900 ), false );

$check( '443 is web', VulnHub_Threat_Ports::kind( 443 ), 'web' );
$check( '445 is file, not web', VulnHub_Threat_Ports::kind( 445 ), 'file' );
$check( '3389 is shell', VulnHub_Threat_Ports::kind( 3389 ), 'shell' );
$check( '1433 is db', VulnHub_Threat_Ports::kind( 1433 ), 'db' );

/*
 * The distinction the whole exposure verdict rests on. SMB listens on nearly
 * every Windows machine here, so if it counted as "published" the observed
 * rule would call the entire estate internet-facing -- exactly the failure it
 * was written to replace.
 */
echo "\nis_publishable():\n";
$check( 'https is publishable', VulnHub_Threat_Ports::is_publishable( 443 ), true );
$check( 'smtp is publishable', VulnHub_Threat_Ports::is_publishable( 25 ), true );
$check( 'SMB is NOT publishable', VulnHub_Threat_Ports::is_publishable( 445 ), false );
$check( 'RDP is NOT publishable', VulnHub_Threat_Ports::is_publishable( 3389 ), false );
$check( 'WinRM is NOT publishable', VulnHub_Threat_Ports::is_publishable( 5985 ), false );
$check( 'a database is NOT publishable', VulnHub_Threat_Ports::is_publishable( 3306 ), false );

printf( "\n%s\n", 0 === $fails ? 'All checks passed.' : $fails . ' check(s) FAILED.' );
