<?php
/**
 * Load-test driver for vulnhub-import.
 * usage: wp eval-file dev/loadtest.php <storage_key> <filename> [budget]
 */
$key    = (string) ( $args[0] ?? '' );
$name   = (string) ( $args[1] ?? 'tenable-vulns.csv' );
$budget = (float) ( $args[2] ?? 240.0 );

if ( ! VulnHub_Import_Storage::exists( $key ) ) {
	echo "FATAL: no staged file for key {$key}\n";
	return;
}

$wall0 = microtime( true );

$sniff = VulnHub_Import_Storage::sniff( $key );
printf( "sniff: ok=%s %s\n", $sniff['ok'] ? 'yes' : 'no', (string) $sniff['message'] );
if ( ! $sniff['ok'] ) { return; }

$path   = VulnHub_Import_Storage::path( $key );
$size   = VulnHub_Import_Storage::size( $key );
$header = VulnHub_Import_Reader::read_header( $path );
printf( "header: ok=%s cols=%d delim=%s offset=%d\n", $header['ok'] ? 'yes' : 'no', count( (array) $header['headers'] ), var_export( $header['delimiter'], true ), (int) $header['offset'] );
if ( ! $header['ok'] ) { return; }

$sample = VulnHub_Import_Reader::sample( $path, $header['delimiter'], $header['headers'], $header['offset'], 20 );
$shape  = VulnHub_Import_Schema::detect_shape( $header['headers'] );
$map    = VulnHub_Import_Schema::detect_mapping( $shape, $header['headers'], $sample['rows'] );
printf( "shape: %s  mapped_fields=%d\n", $shape, count( array_filter( $map, static function ( $v ) { return '' !== (string) $v; } ) ) );

$ht   = microtime( true );
$hash = VulnHub_Import_Storage::hash( $key );
printf( "hash: %s (%.1fs over %.1f MB = %.1f MB/s)\n", substr( $hash, 0, 24 ), microtime( true ) - $ht, $size / 1048576, ( $size / 1048576 ) / max( 0.001, microtime( true ) - $ht ) );

$est = VulnHub_Import_Reader::estimate_rows( $size, (int) $header['offset'], (int) $sample['bytes'], count( $sample['rows'] ) );

$prev = VulnHub_Import_Jobs::previous_with_hash( $hash, 0 );
printf( "duplicate-file check: %s\n", $prev ? 'MATCHES job #' . (int) $prev['id'] : 'no earlier job with this hash' );

$job_id = VulnHub_Import_Jobs::create(
	array(
		'type'                => VulnHub_Import_Schema::type_for_shape( $shape ),
		'shape'               => $shape,
		'filename'            => $name,
		'storage_key'         => $key,
		'size_bytes'          => $size,
		'content_hash'        => $hash,
		'status'              => VulnHub_Import_Jobs::PENDING,
		'rows_total_estimate' => $est,
		'column_map'          => array(
			'headers'       => $header['headers'],
			'delimiter'     => $header['delimiter'],
			'header_offset' => (int) $header['offset'],
			'map'           => $map,
		),
	)
);
printf( "job: #%d  est_rows=%s\n", $job_id, number_format( $est ) );

$before = array();
global $wpdb;
foreach ( array( 'assets', 'vulns', 'findings' ) as $t ) {
	$before[ $t ] = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . vh_table( $t ) );
}
printf( "before: assets=%d vulns=%d findings=%d\n", $before['assets'], $before['vulns'], $before['findings'] );

$r = VulnHub_Import_Runner::start( $job_id );
printf( "start: ok=%s %s\n\n", $r['ok'] ? 'yes' : 'no', (string) $r['message'] );
if ( ! $r['ok'] ) { return; }

$pass = 0;
while ( true ) {
	++$pass;
	$p0  = microtime( true );
	$res = VulnHub_Import_Runner::run( $job_id, $budget );
	$j   = VulnHub_Import_Jobs::get( $job_id );
	if ( ! $j ) { echo "job vanished\n"; break; }
	$c   = (array) $j['counters_arr'];
	$el  = microtime( true ) - $wall0;
	printf(
		"pass %-3d %-8s bytes %s/%s (%5.1f%%)  rows=%s  rate=%s/s  peak=%.0fMB  pass=%.1fs  wall=%.1fs\n",
		$pass,
		(string) $j['status'],
		number_format( (int) $j['byte_offset'] ),
		number_format( (int) $j['size_bytes'] ),
		$j['size_bytes'] ? 100 * (int) $j['byte_offset'] / (int) $j['size_bytes'] : 0,
		number_format( (int) $j['rows_done'] ),
		number_format( (int) $j['rows_done'] / max( 0.001, (float) $c['seconds'] ) ),
		( (int) $c['peak_memory'] ) / 1048576,
		microtime( true ) - $p0,
		$el
	);
	flush();
	if ( VulnHub_Import_Jobs::RUNNING !== (string) $j['status'] ) { break; }
	if ( $pass > 400 ) { echo "ABORT: too many passes\n"; break; }
}

$j = VulnHub_Import_Jobs::get( $job_id );
$c = (array) $j['counters_arr'];
$after = array();
foreach ( array( 'assets', 'vulns', 'findings' ) as $t ) {
	$after[ $t ] = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . vh_table( $t ) );
}

echo "\n=== RESULT ===\n";
printf( "job #%d  status=%s  error=%s\n", $job_id, (string) $j['status'], (string) $j['error'] );
printf( "wall clock      : %.1f s\n", microtime( true ) - $wall0 );
printf( "import seconds  : %.1f s\n", (float) $c['seconds'] );
printf( "rows read       : %s\n", number_format( (int) $c['rows_read'] ) );
printf( "rows/sec        : %s\n", number_format( (int) $c['rows_read'] / max( 0.001, (float) $c['seconds'] ) ) );
printf( "peak memory     : %.1f MB\n", ( (int) $c['peak_memory'] ) / 1048576 );
printf( "passes          : %d\n", (int) $c['passes'] );
printf( "rows skipped    : %s   failed: %s\n", number_format( (int) $c['rows_skipped'] ), number_format( (int) $c['rows_failed'] ) );
printf( "assets   %7d -> %7d  (created %s, updated %s)\n", $before['assets'], $after['assets'], number_format( (int) $c['assets_created'] ), number_format( (int) $c['assets_updated'] ) );
printf( "vulns    %7d -> %7d  (created %s, updated %s)\n", $before['vulns'], $after['vulns'], number_format( (int) $c['vulns_created'] ), number_format( (int) $c['vulns_updated'] ) );
printf( "findings %7d -> %7d  (created %s, updated %s, reopened %s)\n", $before['findings'], $after['findings'], number_format( (int) $c['findings_created'] ), number_format( (int) $c['findings_updated'] ), number_format( (int) $c['findings_reopened'] ) );
if ( ! empty( $c['failures'] ) ) {
	echo "first failures:\n";
	foreach ( array_slice( (array) $c['failures'], 0, 5 ) as $f ) {
		printf( "  row %s: %s\n", (string) ( $f['row'] ?? '?' ), (string) ( $f['reason'] ?? '?' ) );
	}
}
echo "=== END ===\n";
