<?php
/**
 * wp vulnhub-replica — the same controls as the portal section, for a shell.
 *
 * @package VulnHub\Replica
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Manage instance sync.
 */
final class VulnHub_Replica_CLI {

	/**
	 * Create a sync key. Prints it once.
	 *
	 * ## OPTIONS
	 *
	 * [--label=<label>]
	 * : Which copy it is for.
	 *
	 * [--days=<days>]
	 * : Expire after this many days. 0 (default) never expires.
	 *
	 * @param array<int,string>    $args  Positional.
	 * @param array<string,string> $assoc Options.
	 */
	public function key_create( array $args, array $assoc ): void {
		unset( $args );
		$k = VulnHub_Replica_Tokens::create( (string) ( $assoc['label'] ?? '' ), get_current_user_id(), (int) ( $assoc['days'] ?? 0 ) );
		\WP_CLI::line( 'Source address: ' . home_url() );
		\WP_CLI::line( 'Sync key:       ' . $k['token'] );
		\WP_CLI::warning( 'This is the only time the key is shown.' );
	}

	/**
	 * List sync keys.
	 *
	 * @subcommand key-list
	 */
	public function key_list(): void {
		$rows = array();
		foreach ( VulnHub_Replica_Tokens::all() as $k ) {
			$rows[] = array(
				'id'        => $k['id'],
				'label'     => $k['label'],
				'key'       => $k['hint'],
				'status'    => ! empty( $k['revoked_at'] ) ? 'revoked' : 'active',
				'last_used' => $k['last_used_at'] ?: 'never',
				'calls'     => $k['calls'],
			);
		}
		\WP_CLI\Utils\format_items( 'table', $rows, array( 'id', 'label', 'key', 'status', 'last_used', 'calls' ) );
	}

	/**
	 * Revoke a sync key.
	 *
	 * ## OPTIONS
	 *
	 * <id>
	 * : Key id from key-list.
	 *
	 * @subcommand key-revoke
	 * @param array<int,string> $args Positional.
	 */
	public function key_revoke( array $args ): void {
		VulnHub_Replica_Tokens::revoke( (int) $args[0] )
			? \WP_CLI::success( 'Revoked.' )
			: \WP_CLI::error( 'No such key.' );
	}

	/**
	 * Run a sync now (copy side), in this process.
	 *
	 * ## OPTIONS
	 *
	 * [--full]
	 * : Rebuild every table instead of sending only what changed.
	 *
	 * @param array<int,string>    $args  Positional.
	 * @param array<string,string> $assoc Options.
	 */
	public function sync( array $args, array $assoc ): void {
		unset( $args );
		$c = vulnhub()->connectors->get( VulnHub_Replica_Connector::ID );
		if ( ! $c ) {
			\WP_CLI::error( 'The replica connector is not registered.' );
		}
		$r = $c->sync(
			array(
				'mode'  => 'manual',
				'force' => true,
				'full'  => isset( $assoc['full'] ),
			)
		);
		$r['ok'] ? \WP_CLI::success( $r['message'] ) : \WP_CLI::error( $r['message'] );
	}

	/**
	 * Show copy state, the last sync and packages held for copies.
	 */
	public function status(): void {
		\WP_CLI::line( 'Mode:      ' . ( VulnHub_Replica_Guard::active() ? 'copy' : 'primary' ) );
		\WP_CLI::line( 'Instance:  ' . VulnHub_Replica_Schema::instance_id() );
		$last = (array) get_option( VulnHub_Replica_Connector::OPT_LAST, array() );
		if ( $last ) {
			\WP_CLI::line( sprintf( 'Last sync: %s UTC, %d rows, %d bytes in %d chunks, %ds', $last['at'], $last['rows'], $last['bytes'], $last['chunks'], $last['seconds'] ) );
		}
		$run = (array) get_option( VulnHub_Replica_Connector::OPT_RUN, array() );
		if ( ! empty( $run['job'] ) ) {
			\WP_CLI::line( sprintf( 'Unfinished: package %s, %s phase%s', $run['job'], $run['phase'], ! empty( $run['error'] ) ? ' (' . $run['error'] . ')' : '' ) );
		}
		foreach ( VulnHub_Replica_Job::all() as $j ) {
			\WP_CLI::line( sprintf( 'Package %s for key #%d: %s/%s', $j['id'], $j['token_id'], $j['status'], $j['step'] ) );
		}
	}

	/**
	 * Delete packages nobody has collected for a day.
	 */
	public function sweep(): void {
		\WP_CLI::success( sprintf( '%d package(s) removed.', VulnHub_Replica_Job::sweep() ) );
	}
}

