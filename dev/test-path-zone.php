<?php
/**
 * Unit checks for VH_Product::install_path() / downloads_path() / path_zone().
 *
 *     docker compose cp dev/test-path-zone.php wpcli:/tmp/tpz.php
 *     docker compose exec -T wpcli wp eval-file /tmp/tpz.php
 *
 * Every case here is a real shape taken out of this estate's plugin output,
 * including the ones that fooled earlier versions of the parser: the Unquoted
 * Service Path plugin's "Path : <service> : C:\...", the registry listings'
 * "<path>,-242 : <description>", single-line output that runs the next label
 * on with one space, and URLs whose "s://" looks like a drive letter.
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

/* ------------------------------------------------------------------ paths. */

echo "install_path():\n";

$check(
	'padded multi-line format',
	\VH_Product::install_path( "\n  Path              : C:\\Users\\Ray.Cheung\\Downloads\\sqldeveloper\\jdk\\\n  Installed version : 17.0.13\n" ),
	'C:\\Users\\Ray.Cheung\\Downloads\\sqldeveloper\\jdk\\'
);

$check(
	'single-line format, next label one space away',
	\VH_Product::install_path( "' Path : C:\\Users\\Campbell.Hyde\\Downloads\\sqldeveloper\\jdk\\ Installed version : 17.0.13 / build 17.0.13" ),
	'C:\\Users\\Campbell.Hyde\\Downloads\\sqldeveloper\\jdk\\'
);

$check(
	'a directory install with no file extension',
	\VH_Product::install_path( 'Path : C:\\Users\\SinioJ\\Downloads\\SQL Developer\\jdk\\' ),
	'C:\\Users\\SinioJ\\Downloads\\SQL Developer\\jdk\\'
);

$check(
	'a path containing single spaces survives intact',
	\VH_Product::install_path( 'Path : C:\\Program Files\\Windows Identity Foundation\\v3.5\\c2wtshost.exe' ),
	'C:\\Program Files\\Windows Identity Foundation\\v3.5\\c2wtshost.exe'
);

$check(
	'Unquoted Service Path: service name before the path',
	\VH_Product::install_path( 'Unquoted Service Path : c2wts : C:\\Program Files\\Windows Identity Foundation\\v3.5\\c2wtshost.exe' ),
	'C:\\Program Files\\Windows Identity Foundation\\v3.5\\c2wtshost.exe'
);

$check(
	'registry listing: description after the path',
	\VH_Product::install_path( 'c:\\programdata\\microsoft\\windows defender\\platform\\4.18\\mpasdesc.dll,-242 : Helps guard against intrusion' ),
	'c:\\programdata\\microsoft\\windows defender\\platform\\4.18\\mpasdesc.dll,-242'
);

$check(
	'doubled separators are collapsed',
	\VH_Product::install_path( 'C:\\\\Users\\BurgessK\\Downloads\\report.xlsx' ),
	'C:\\Users\\BurgessK\\Downloads\\report.xlsx'
);

$check(
	'a unix path',
	\VH_Product::install_path( "Path : /opt/tomcat/lib/log4j-core.jar\n" ),
	'/opt/tomcat/lib/log4j-core.jar'
);

$check( 'no path at all', \VH_Product::install_path( 'folderid_desktop folderid_documents' ), '' );
$check( 'empty output', \VH_Product::install_path( '' ), '' );

$check(
	'a URL is not a drive letter',
	\VH_Product::install_path( 'See https://www.tenable.com/plugins/nessus/133180 for detail' ),
	''
);

/* ------------------------------------------------------------------ zones. */

echo "\ndownloads_path() / path_zone():\n";

$win = 'Name : Apache Log4j Path : C:\\Users\\SingAs\\Downloads\\sqldeveloper\\lib\\log4j-core.jar Version : unknown';
$check( 'Windows user Downloads', \VH_Product::downloads_path( $win ), 'C:\\Users\\SingAs\\Downloads\\sqldeveloper\\lib\\log4j-core.jar' );
$check( 'zone slug for the same', \VH_Product::path_zone( $win )['zone'], 'downloads' );

$check(
	'Windows drive written with slashes',
	\VH_Product::downloads_path( '/C/Users/matua.pomare/Downloads/review.pdf' ),
	'/C/Users/matua.pomare/Downloads/review.pdf'
);

$check(
	'Linux home Downloads',
	\VH_Product::downloads_path( 'Path : /home/deploy/Downloads/apache-jmeter/lib/log4j-core.jar' ),
	'/home/deploy/Downloads/apache-jmeter/lib/log4j-core.jar'
);

$check( "Linux root's own Downloads", \VH_Product::downloads_path( 'Path : /root/Downloads/tool.jar' ), '/root/Downloads/tool.jar' );
$check( 'macOS Downloads', \VH_Product::downloads_path( 'Path : /Users/jane/Downloads/tool.jar' ), '/Users/jane/Downloads/tool.jar' );

// The false positive that anchoring on a user profile exists to prevent.
$check(
	'a share with a Downloads directory deep inside is NOT a download folder',
	\VH_Product::downloads_path( 'Path : C:\\Windows\\CSC\\v2.0.6\\namespace\\DFS-Data\\ARC_Data\\Downloads\\x.jar' ),
	''
);
$check(
	'AppData is not Downloads',
	\VH_Product::downloads_path( 'C:\\Users\\NguyenN\\AppData\\Roaming\\Microsoft\\Office\\Recent\\draft.docx' ),
	''
);
$check( 'no zone when there is no path', \VH_Product::path_zone( 'folderid_desktop' ), array( 'zone' => '', 'path' => '' ) );

// A finding can list many paths and only one of them be in Downloads; the zone
// has to search the whole blob, not just trust the first path.
$check(
	'finds Downloads even when another path comes first',
	\VH_Product::downloads_path( "/D/Simon/Safety Clipart/dgr29.pdf\n/C/Users/JonasS/Downloads/EV_Day.pdf\n" ),
	'/C/Users/JonasS/Downloads/EV_Day.pdf'
);

printf( "\n%s\n", 0 === $fails ? 'All checks passed.' : $fails . ' check(s) FAILED.' );
