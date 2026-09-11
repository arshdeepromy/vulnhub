<?php
/**
 * Repair operating-system strings mangled by the old whitespace splitter.
 *
 * `VulnHub_Import_Tenable::split_list()` broke the OS field on whitespace, so
 * "Red Hat Enterprise Linux 9.3" was stored as "Red". The splitter is fixed
 * and any future sync writes the whole string, but the rows already in the
 * table cannot repair themselves -- the rest of the value is gone.
 *
 * This walks a Tenable export and puts back the full string for any asset
 * whose stored value is a single bare word. It only ever widens a value:
 * anything already containing a space is left alone.
 *
 * usage: wp eval-file dev/backfill-os.php /path/to/tenable-export.csv [--apply]
 */

$path  = (string) ( $args[0] ?? '' );
$apply = in_array( '--apply', (array) $args, true );

if ( ! is_readable( $path ) ) {
	echo "usage: wp eval-file dev/backfill-os.php <csv> [--apply]\n";
	return;
}

global $wpdb;

$assets = vh_table( 'assets' );

// The rows worth repairing: a stored OS with no space in it is either a
// truncation or a single-word product nobody ships.
$broken = (array) $wpdb->get_results(
	"SELECT id, hostname, fqdn, operating_system FROM {$assets}
	 WHERE operating_system <> '' AND operating_system NOT LIKE '% %'", // phpcs:ignore
	ARRAY_A
);

printf( "%d assets carry a single-word operating system.\n", count( $broken ) );

if ( ! $broken ) {
	return;
}

$by_host = array();

foreach ( $broken as $row ) {
	foreach ( array( (string) $row['hostname'], (string) $row['fqdn'] ) as $key ) {
		$key = strtolower( trim( $key ) );

		if ( '' !== $key ) {
			$by_host[ $key ] = (int) $row['id'];
		}
		// The short name of an FQDN, because the export may carry either.
		if ( '' !== $key && str_contains( $key, '.' ) ) {
			$by_host[ (string) strtok( $key, '.' ) ] = (int) $row['id'];
		}
	}
}

$handle = fopen( $path, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions

if ( ! $handle ) {
	echo "could not open {$path}\n";
	return;
}

$header = fgetcsv( $handle );

if ( ! $header ) {
	echo "no header row\n";
	fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions
	return;
}

$index = array();

foreach ( $header as $i => $name ) {
	$index[ strtolower( trim( (string) $name ) ) ] = $i;
}

$os_col = $index['operating system'] ?? null;
$dns    = $index['dns name'] ?? null;
$nb     = $index['netbios name'] ?? null;

if ( null === $os_col ) {
	echo "no 'Operating System' column in that export\n";
	fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions
	return;
}

$found = array();
$rows  = 0;

while ( ( $line = fgetcsv( $handle ) ) !== false ) {
	++$rows;

	$os = trim( (string) ( $line[ $os_col ] ?? '' ) );

	// Only a full string is worth writing back.
	if ( '' === $os || ! str_contains( $os, ' ' ) ) {
		continue;
	}

	foreach ( array( $dns, $nb ) as $col ) {
		if ( null === $col ) {
			continue;
		}

		$name = strtolower( trim( (string) ( $line[ $col ] ?? '' ) ) );

		if ( str_contains( $name, '\\' ) ) {
			$name = (string) substr( strrchr( $name, '\\' ) ?: '', 1 );
		}
		if ( '' === $name ) {
			continue;
		}

		foreach ( array( $name, (string) strtok( $name, '.' ) ) as $candidate ) {
			if ( isset( $by_host[ $candidate ] ) ) {
				$found[ $by_host[ $candidate ] ] = $os;
			}
		}
	}
}

fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions

printf( "read %s rows; matched %d of %d broken assets.\n", number_format_i18n( $rows ), count( $found ), count( $broken ) );

if ( ! $apply ) {
	$n = 0;
	foreach ( $found as $id => $os ) {
		if ( $n++ >= 8 ) {
			break;
		}
		printf( "  #%d -> %s\n", $id, $os );
	}
	echo "dry run. re-run with --apply to write.\n";
	return;
}

$written = 0;

foreach ( $found as $id => $os ) {
	$written += (int) $wpdb->update(
		$assets,
		array( 'operating_system' => vh_trim( $os, 190 ) ),
		array( 'id' => (int) $id ),
		array( '%s' ),
		array( '%d' )
	);
}

printf( "updated %d assets.\n", $written );

