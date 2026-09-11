<?php
// Run one action hook with a hard memory cap and report peak usage.
// usage: wp eval-file vh-hookmem.php <hook> [limit]
$hook  = $args[0] ?? '';
$limit = $args[1] ?? '1024M';
if ( ! $hook ) { WP_CLI::error( 'need a hook' ); }
ini_set( 'memory_limit', $limit );
register_shutdown_function( function () use ( $hook ) {
    $e = error_get_last();
    if ( $e && ( $e['type'] & ( E_ERROR | E_USER_ERROR ) ) ) {
        fwrite( STDERR, "\nFATAL in {$hook}: {$e['message']}\n  at {$e['file']}:{$e['line']}\n" );
    }
} );
$t0 = microtime( true );
do_action( $hook );
printf(
    "%-34s ok   peak=%6.1f MB  elapsed=%6.2fs  queries=%d\n",
    $hook,
    memory_get_peak_usage( true ) / 1048576,
    microtime( true ) - $t0,
    $GLOBALS['wpdb']->num_queries
);
