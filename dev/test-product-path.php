<?php
/**
 * Unit checks for VH_Product::product_from_path() and the path knowledge base.
 *
 *     docker compose cp dev/test-product-path.php wpcli:/tmp/tpp.php
 *     docker compose exec -T wpcli wp eval-file /tmp/tpp.php
 *
 * Every path here is real, taken out of this estate's scan output, together
 * with the wrong answer the old folder-picking heuristic gave. They are the
 * regression net for the knowledge base: a new rule that fixes one vendor
 * must not break the ones already working.
 *
 * @package VulnHub
 */

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	exit( "Run this through wp-cli - see the header for the docker compose cp/exec pair.\n" );
}

$fails = 0;
$check = static function ( string $path, string $want, string $was = '' ) use ( &$fails ): void {
	$got = \VH_Product::product_from_path( $path );
	$ok  = $got === $want;
	printf(
		"  [%s] %-58s -> %s%s\n",
		$ok ? ' ok ' : 'FAIL',
		'…' . substr( $path, -57 ),
		'' === $got ? '(none)' : $got,
		$ok ? ( '' !== $was ? '   (was: ' . $was . ')' : '' ) : '   WANT: ' . ( '' === $want ? '(none)' : $want )
	);
	if ( ! $ok ) {
		$fails++;
	}
};

echo "Paths that used to produce a fake product:\n";

$check( 'C:\\Users\\TownshendS\\AppData\\Roaming\\Zoom\\tmp_bin\\libcurl.dll', 'Zoom', 'Tmp_bin' );
$check( 'C:\\Program Files (x86)\\SQL\\sqldeveloper\\sqldeveloper\\lib\\log4j-core.jar', 'Oracle SQL Developer', 'SQL' );
$check( 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\152.0.4191.66\\undocked_copilot\\libcurl.dll', 'Microsoft Edge', 'Deleted' );
$check( '/u01/jde920/e920/system/bin64/openssl', 'Oracle JD Edwards', 'Jde920' );
$check( '/u01/app/jde_home_wls/SCFHA/targets/T1/owl_deployment/webclient.ear/app/web.jar', 'Oracle JD Edwards', 'Jde_home_wls' );
$check( '/u01/clone/dev/mwhome/SOA12.2.1.4/oracle_common/modules/thirdparty/log4j-2.11.1.jar', 'Oracle SOA Suite', 'Clone' );
$check( '/u01/app/oracle/product/agent13c/agent_13.5.0.0.0/sysman/jlib/ocm/log4j-core.jar', 'Oracle Enterprise Manager Agent', 'Agent_software' );
$check( '/oracle/app_old/grid/gridhome_1/suptools/orachk/build/Python37/libssl.so.1.0.0', 'Oracle Grid Infrastructure', 'Oracle App_old' );
$check( '/u03/software/oms/38544605/binary_patches/ohs/solaris_sparc64/38051795/files/oracle.ohs2/x.jar', 'Oracle HTTP Server', 'Oracle.ahf' );
$check( 'C:\\Users\\e_leandar\\.katalon\\packages\\Katalon_Studio_Enterprise_Windows_64-10.2.4\\configuration\\x.jar', 'Katalon Studio', 'Configuration' );

echo "\nPaths where no product is the honest answer:\n";

// The case that prompted all of this.
$check( '/var/app/current/webtier-1.0.9.jar', '', 'current' );
$check( 'C:\\temp\\corrossion\\_internal\\sqlite3.dll', '', 'Internal' );
$check( 'C:\\Windows\\System32\\libcurl.dll', '' );
$check( '/usr/lib64/libcurl.so.4', '' );
$check( 'D:\\SSA\\Software\\installers-22.1-nt\\utilities\\upgrade-index.jar', 'SSA', 'Utilities' );

echo "\nInstalled somewhere unusual - the root folder is still the product:\n";

// Bespoke software really does get installed straight onto a drive, so the
// install root names it. This is the counterpart to the scratch rule above:
// C:\temp\corrossion is a working copy, C:\Corrossion is an installation.
$check( 'C:\\Corrossion\\_internal\\sqlite3.dll', 'Corrossion' );
$check( 'D:\\PasswordManagerPro\\bin\\libcurl.dll', 'ManageEngine Password Manager Pro' );
$check( 'E:\\SikuliX\\lib\\log4j-core.jar', 'SikuliX' );

echo "\nMSIX packages, including the publisher-prefixed ones the map missed:\n";

$check( 'C:\\Program Files\\WindowsApps\\Microsoft.MicrosoftPowerBIDesktop_2.155.756.0_x64__8wekyb3d8bbwe\\x.dll', 'Microsoft Power BI Desktop' );
$check( 'C:\\Program Files\\WindowsApps\\MicrosoftWindows.CrossDevice_1.26071.84.0_x64__cw5n1h2txyewy\\x.dll', 'Microsoft Phone Link' );
$check( 'C:\\Program Files\\WindowsApps\\Microsoft.Windows.Photos_2026.11080.24002.0_x64__8wekyb3d8bbwe\\x.dll', 'Microsoft Photos' );
$check( 'C:\\Program Files\\WindowsApps\\MSTeams_26213.1006.5014.9784_x64__8wekyb3d8bbwe\\x.dll', 'Microsoft Teams' );
$check( 'C:\\Program Files\\WindowsApps\\Microsoft.MicrosoftOfficeHub_19.2609.33021.0_x64__8wekyb3d8bbwe\\x.dll', 'Microsoft Office' );
$check( 'C:\\Program Files\\WindowsApps\\Microsoft.Todos_2.176.7601.0_x64__8wekyb3d8bbwe\\sqlite3.dll', 'Microsoft Todos' );

// Windows stages packages pending removal one level deeper.
$check( 'C:\\Program Files\\WindowsApps\\Deleted\\MSTeams_26198.304.4946.9672_x64__8wekyb3d8bbwe\\libcurl.dll', 'Microsoft Teams' );

echo "\nPaths that already worked and must keep working:\n";

$check( 'C:\\Program Files\\Microsoft Office\\root\\Office16\\libcurl.dll', 'Microsoft Office' );
$check( '/opt/commvault/Base/libcurl.so', 'Commvault' );
$check( 'C:\\Program Files\\Microsoft Teams\\current\\libcurl.dll', 'Microsoft Teams' );
$check( 'C:\\Users\\SinioJ\\Downloads\\SQL Developer\\jdk\\lib\\x.jar', 'Oracle SQL Developer' );
$check( '/opt/tomcat/lib/log4j-core.jar', 'Apache Tomcat' );

printf( "\n%s\n", 0 === $fails ? 'All checks passed.' : $fails . ' check(s) FAILED.' );
