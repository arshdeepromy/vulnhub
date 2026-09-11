<?php
// Run each callback on a hook one at a time, reporting peak memory per callback.
$hook  = $args[0] ?? '';
$limit = $args[1] ?? '1024M';
ini_set( 'memory_limit', $limit );
global $wp_filter;
if ( empty( $wp_filter[ $hook ] ) ) { WP_CLI::error( "no callbacks on {$hook}" ); }
$list = array();
foreach ( $wp_filter[ $hook ]->callbacks as $prio => $cbs ) {
    foreach ( $cbs as $id => $cb ) {
        $f = $cb['function'];
        if ( is_array( $f ) ) {
            $name = ( is_object( $f[0] ) ? get_class( $f[0] ) : (string) $f[0] ) . '::' . $f[1];
        } elseif ( $f instanceof Closure ) {
            $name = 'Closure';
        } else {
            $name = (string) $f;
        }
        $list[] = array( $prio, $name, $f );
    }
}
foreach ( $list as $item ) {
    list( $prio, $name, $f ) = $item;
    fwrite( STDOUT, sprintf( "  -> [%d] %-58s ", $prio, $name ) );
    flush();
    $before = memory_get_usage( true );
    $t0     = microtime( true );
    register_shutdown_function( function () use ( $name ) {
        $e = error_get_last();
        if ( $e && ( $e['type'] & E_ERROR ) ) {
            fwrite( STDOUT, "  <<< DIED HERE: {$name}\n      {$e['message']}\n      at {$e['file']}:{$e['line']}\n" );
        }
    } );
    call_user_func( $f );
    printf(
        "ok  delta=%6.1fMB peak=%6.1fMB %5.2fs\n",
        ( memory_get_usage( true ) - $before ) / 1048576,
        memory_get_peak_usage( true ) / 1048576,
        microtime( true ) - $t0
    );
}
