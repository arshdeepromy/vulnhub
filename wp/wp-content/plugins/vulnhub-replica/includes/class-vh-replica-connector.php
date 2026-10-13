<?php
/**
 * Copy side: keep this instance a one-way copy of another.
 *
 * A run has three phases, each resumable from where it stopped:
 *
 *   prepare   fingerprint every local table, send the fingerprints, and drive
 *             the source through building a package of what differs
 *   download  fetch the package chunk by chunk, each checked against the
 *             SHA-256 the source announced; a chunk already on disk and
 *             matching is never fetched again
 *   process   join the chunks, check the whole archive, then apply it table
 *             by table: changed key ranges are cleared and rewritten in one
 *             transaction each; a table without an integer key is rebuilt
 *             beside the live one and swapped in
 *
 * While this connector is switched on the instance is a copy, and
 * VulnHub_Replica_Guard keeps it from acting on any real system.
 *
 * @package VulnHub\Replica
 */

declare( strict_types = 1 );

use VulnHub\Core\Connector;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The replica connector.
 */
final class VulnHub_Replica_Connector extends Connector {

	public const ID = 'replica';

	/** Resume state for the run in progress. */
	public const OPT_RUN = 'vulnhub_replica_run';

	/** Summary of the last run that finished. */
	public const OPT_LAST = 'vulnhub_replica_last';

	/** Option names the last run wrote, so ones gone at the source go here too. */
	public const OPT_OPTIONS = 'vulnhub_replica_options';

	/** Asked-for full resync. */
	public const OPT_FULL = 'vulnhub_replica_full';

	/** Rows per insert statement, and the byte cap that goes with it. */
	private const INSERT_ROWS  = 500;
	private const INSERT_BYTES = 4194304;

	/** @var \mysqli|null */
	private $dbh = null;

	/** @var array<string,mixed> */
	private array $run = array();

	private float $last_report = 0.0;

	public function id(): string {
		return self::ID;
	}

	public function label(): string {
		return __( 'Instance copy (one-way sync)', 'vulnhub' );
	}

	public function description(): string {
		return __( 'Make this instance a read-only copy of another running instance: its data arrives as zipped, chunked packages on a schedule, and nothing here reaches any real system.', 'vulnhub' );
	}

	public function icon(): string {
		return 'dashicons-update';
	}

	public function category(): string {
		return 'other';
	}

	public function supports_mock(): bool {
		return false;
	}

	/**
	 * Never: there is no pretend source to copy, and a fresh install's
	 * platform-wide mock switch must not make the card claim otherwise.
	 */
	public function is_mock(): bool {
		return false;
	}

	public function async_sync(): bool {
		return true;
	}

	public function supports_full_sync(): bool {
		return true;
	}

	public function request_full_sync(): void {
		update_option( self::OPT_FULL, 1, false );
	}

	public function full_sync_note(): string {
		return get_option( self::OPT_FULL ) ? __( 'Full copy requested: the next run rebuilds every table.', 'vulnhub' ) : '';
	}

	/**
	 * Unfinished package on disk, and not inside a back-off window.
	 */
	public function resumable_sync(): bool {
		$run = (array) get_option( self::OPT_RUN, array() );
		return ! empty( $run['job'] ) && $this->is_enabled() && time() >= (int) ( $run['retry_at'] ?? 0 );
	}

	/**
	 * The resume sweep and the schedule both land here; what the copy holds
	 * is recomputed from scratch on the copy, so nothing needs recalculating
	 * after a run -- the source already did it.
	 */
	public function recalculate_after_sync(): bool {
		return false;
	}

	public function default_interval(): string {
		return 'vh_hourly';
	}

	public function fields(): array {
		return array(
			array(
				'key'  => 'setup',
				'type' => 'note',
				'help' => __( 'On the instance you want to copy, open <strong>Instance sync</strong> in the portal admin and create a sync key. Paste its address and the key here, switch this on and pick how often to sync. While this is on, this instance is a copy: every other connector, automation, alert and verification is stopped, outbound calls go nowhere but the source, and email is held. Changes made here are overwritten at the next sync.', 'vulnhub' ),
			),
			array(
				'key'         => 'source_url',
				'label'       => __( 'Source instance address', 'vulnhub' ),
				'type'        => 'url',
				'required'    => true,
				'placeholder' => 'https://vulnhub.corp.example',
				'help'        => __( 'The address you open the source portal on. Use https when the two instances are not on the same private network: the key and the data travel in the request.', 'vulnhub' ),
			),
			array(
				'key'      => 'token',
				'label'    => __( 'Sync key', 'vulnhub' ),
				'type'     => 'text',
				'secret'   => true,
				'required' => true,
				'help'     => __( 'Starts with vhr_. Encrypted at rest. Leave blank to keep the stored one.', 'vulnhub' ),
			),
			array(
				'key'     => 'chunk_mb',
				'label'   => __( 'Chunk size', 'vulnhub' ),
				'type'    => 'select',
				'default' => '8',
				'options' => array(
					'2'  => '2 MB',
					'4'  => '4 MB',
					'8'  => '8 MB',
					'16' => '16 MB',
					'32' => '32 MB',
				),
				'help'    => __( 'Smaller chunks waste less when a slow or flaky link drops one; larger ones are fewer requests.', 'vulnhub' ),
			),
			array(
				'key'   => 'allow_shrink',
				'label' => __( 'Allow a table to shrink by more than half', 'vulnhub' ),
				'type'  => 'checkbox',
				'help'  => __( 'Off by default: a source table that suddenly holds less than half the rows it did is more often a broken source than a real change, so the copy keeps what it has and says so. Turn on to accept it.', 'vulnhub' ),
			),
			array(
				'key'   => 'allow_mail',
				'label' => __( 'Let this copy send email', 'vulnhub' ),
				'type'  => 'checkbox',
				'help'  => __( 'Off by default. The copy holds real people\'s addresses; it should not mail them.', 'vulnhub' ),
			),
		);
	}

	/* -----------------------------------------------------------------
	 * Talking to the source
	 * --------------------------------------------------------------- */

	public function source(): string {
		return untrailingslashit( trim( (string) $this->get( 'source_url', '' ) ) );
	}

	private function endpoint( string $path ): string {
		return $this->source() . '/?rest_route=/' . VulnHub_Replica_Source::NS . $path;
	}

	/**
	 * @param array<string,mixed>|null $body JSON body.
	 * @return array{code:int,json:array<string,mixed>|null,error:string}
	 */
	private function api( string $method, string $path, ?array $body = null, int $timeout = 120 ): array {
		$args = array(
			'method'  => $method,
			'timeout' => $timeout,
			'headers' => array(
				'X-VulnHub-Replica-Token' => $this->secret( 'token' ),
				'Accept'                  => 'application/json',
			),
		);
		if ( null !== $body ) {
			$args['headers']['Content-Type'] = 'application/json';
			$args['body']                    = (string) wp_json_encode( $body );
		}

		$res = wp_remote_request( $this->endpoint( $path ), $args );
		if ( is_wp_error( $res ) ) {
			return array(
				'code'  => 0,
				'json'  => null,
				'error' => $res->get_error_message(),
			);
		}

		$code = (int) wp_remote_retrieve_response_code( $res );
		$json = json_decode( (string) wp_remote_retrieve_body( $res ), true );

		return array(
			'code'  => $code,
			'json'  => is_array( $json ) ? $json : null,
			'error' => $code >= 400 ? (string) ( is_array( $json ) ? ( $json['message'] ?? '' ) : '' ) : '',
		);
	}

	public function test_connection(): array {
		if ( '' === $this->source() || '' === $this->secret( 'token' ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'Add the source address and a sync key first.', 'vulnhub' ),
			);
		}

		$r = $this->api( 'GET', '/manifest', null, 30 );
		if ( 200 !== $r['code'] || ! $r['json'] ) {
			return array(
				'ok'      => false,
				'message' => $r['code']
					? sprintf( 'The source answered %d: %s', $r['code'], $r['error'] ?: 'not a VulnHub instance with instance sync installed' )
					: sprintf( 'Could not reach the source: %s', $r['error'] ),
			);
		}

		$m = $r['json'];
		if ( (string) ( $m['instance'] ?? '' ) === VulnHub_Replica_Schema::instance_id() ) {
			return array(
				'ok'      => false,
				'message' => __( 'That address is this instance. Point the copy at the other one.', 'vulnhub' ),
			);
		}

		$rows = 0;
		foreach ( (array) ( $m['tables'] ?? array() ) as $t ) {
			$rows += (int) ( $t['rows'] ?? 0 );
		}

		$diff = $this->version_drift( (array) ( $m['versions'] ?? array() ) );

		return array(
			'ok'      => true,
			'message' => sprintf(
				'Connected. The source holds %d tables, about %s rows.%s',
				count( (array) ( $m['tables'] ?? array() ) ),
				number_format( $rows ),
				$diff ? ' Code differs from this instance: ' . implode( ', ', $diff ) . '. Tables and columns only one side has are skipped.' : ' Same code on both sides.'
			),
		);
	}

	/**
	 * @param array<string,string> $theirs Source plugin versions.
	 * @return array<int,string>
	 */
	private function version_drift( array $theirs ): array {
		$mine = VulnHub_Replica_Schema::versions();
		$out  = array();
		foreach ( array_unique( array_merge( array_keys( $mine ), array_keys( $theirs ) ) ) as $p ) {
			if ( 'vulnhub-replica' === $p ) {
				continue;
			}
			$a = $mine[ $p ] ?? 'missing';
			$b = $theirs[ $p ] ?? 'missing';
			if ( $a !== $b ) {
				$out[] = sprintf( '%s (here %s, source %s)', $p, $a, $b );
			}
		}
		return $out;
	}

	/* -----------------------------------------------------------------
	 * The run
	 * --------------------------------------------------------------- */

	protected function do_sync( array $args = array() ): array {
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 0 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- cron/CLI.
		}
		@ini_set( 'memory_limit', '512M' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors,WordPress.PHP.IniSet.memory_limit_Disallowed

		if ( ! class_exists( 'ZipArchive' ) ) {
			return array(
				'ok'      => false,
				'message' => 'This instance cannot open zip packages (the PHP zip extension is missing).',
			);
		}
		if ( '' === $this->source() || '' === $this->secret( 'token' ) ) {
			return array(
				'ok'      => false,
				'message' => 'Add the source address and a sync key first.',
			);
		}
		if ( ! empty( $args['full'] ) ) {
			$this->request_full_sync();
		}

		// A run that was killed (container restart, OOM) never closed its row;
		// this one carries on from its checkpoint, so say so and close it.
		global $wpdb;
		$wpdb->query(
			$wpdb->prepare(
				'UPDATE ' . vh_table( 'sync_runs' ) . " SET status = 'failed', finished_at = %s, message = %s
				 WHERE connector = %s AND status = 'running' AND id < %d",
				vh_now(),
				sprintf( 'Interrupted. Run #%d carried on from its checkpoint.', $this->run_id ),
				self::ID,
				$this->run_id
			)
		);

		$this->run = (array) get_option( self::OPT_RUN, array() );
		if ( ! empty( $this->run['job'] ) && (string) ( $this->run['source'] ?? '' ) !== $this->source() ) {
			$this->log( 'The source address changed since the unfinished package was started; starting again.' );
			$this->abandon();
		}

		try {
			$attempts = 0;
			while ( true ) {
				try {
					return $this->drive();
				} catch ( VulnHub_Replica_Lost $lost ) {
					// The source no longer has our package (expired, revoked,
					// replaced, or the source was rebuilt). Start once more.
					if ( ++$attempts > 1 ) {
						throw $lost;
					}
					$this->log( 'The source no longer has the package (' . $lost->getMessage() . '); asking for a new one.' );
					$this->abandon();
				}
			}
		} catch ( \Throwable $e ) {
			// Keep the checkpoint; back off before the resume sweep retries.
			if ( ! empty( $this->run['job'] ) ) {
				$this->run['retry_at'] = time() + 15 * MINUTE_IN_SECONDS;
				$this->run['error']    = $e->getMessage();
				$this->save_run();
			}
			throw $e;
		}
	}

	/**
	 * @return array{ok:bool,message:string}
	 */
	private function drive(): array {
		if ( empty( $this->run['job'] ) ) {
			$this->start();
		} else {
			$this->log( sprintf( 'Resuming package %s at the %s phase.', $this->run['job'], $this->run['phase'] ) );
		}

		if ( 'prepare' === $this->run['phase'] ) {
			$this->prepare();
		}
		if ( 'download' === $this->run['phase'] ) {
			$this->download();
		}
		if ( 'assemble' === $this->run['phase'] ) {
			$this->assemble();
		}
		if ( 'process' === $this->run['phase'] ) {
			$this->process();
		}

		return $this->finish();
	}

	private function save_run(): void {
		update_option( self::OPT_RUN, $this->run, false );
	}

	private function workdir(): string {
		return VulnHub_Replica_Schema::dir( 'in/' . preg_replace( '/[^a-z0-9]/', '', (string) $this->run['job'] ) );
	}

	/**
	 * Forget the unfinished package here (and on the source, best effort).
	 */
	private function abandon(): void {
		if ( ! empty( $this->run['job'] ) ) {
			$this->api( 'DELETE', '/jobs/' . $this->run['job'], null, 15 );
			VulnHub_Replica_Schema::rmdir( $this->workdir() );
		}
		$this->run = array();
		delete_option( self::OPT_RUN );
	}

	/**
	 * Fingerprint every local table and ask the source for a package.
	 */
	private function start(): void {
		$r = $this->api( 'GET', '/manifest', null, 60 );
		if ( 200 !== $r['code'] || ! $r['json'] ) {
			throw new \RuntimeException( $r['code'] ? sprintf( 'The source answered %d: %s', $r['code'], $r['error'] ) : 'Could not reach the source: ' . $r['error'] );
		}
		$m = $r['json'];
		if ( (string) ( $m['instance'] ?? '' ) === VulnHub_Replica_Schema::instance_id() ) {
			throw new \RuntimeException( 'The source address is this instance.' );
		}
		if ( (int) ( $m['width'] ?? 0 ) !== VulnHub_Replica_Schema::BUCKET_WIDTH ) {
			throw new \RuntimeException( 'The source runs a different version of instance sync. Update both to the same code.' );
		}

		foreach ( $this->version_drift( (array) ( $m['versions'] ?? array() ) ) as $d ) {
			$this->log( 'Code differs: ' . $d );
		}

		$full  = (bool) get_option( self::OPT_FULL );
		$local = VulnHub_Replica_Schema::tables();
		$theirs = (array) ( $m['tables'] ?? array() );

		$schema = array();
		$fps    = array();
		$i      = 0;
		$n      = count( $theirs );

		$this->run = array(
			'source'  => $this->source(),
			'job'     => '',
			'phase'   => 'prepare',
			'started' => time(),
			'full'    => $full,
		);

		foreach ( $theirs as $short => $t ) {
			++$i;
			$short = (string) $short;
			$this->report( 'prepare', array( 'prepare_pct' => 0, 'prepare_note' => sprintf( 'Fingerprinting local tables (%d of %d)', $i, $n ) ) );

			if ( ! isset( $local[ $short ] ) && ! empty( $t['ddl'] ) && VulnHub_Replica_Schema::create_from_ddl( $short, (string) $t['ddl'] ) ) {
				// A table the source's features created on first use.
				$this->log( sprintf( 'Created %s here: the source has it and this instance had not created it yet.', $short ) );
				$local = VulnHub_Replica_Schema::tables();
			}
			if ( ! isset( $local[ $short ] ) ) {
				$this->log( sprintf( 'Skipping %s: the source has it and this instance does not.', $short ) );
				continue;
			}
			$info = $local[ $short ];
			$cols = VulnHub_Replica_Schema::shared_columns( (array) ( $t['cols'] ?? array() ), $info['cols'] );
			$same = ! empty( $t['int_pk'] ) && $info['int_pk'] && (array) $t['pk'] === $info['pk'];
			$mode = ( $same && ! $full ) ? 'buckets' : 'table';

			$schema[ $short ] = array(
				'cols' => $info['cols'],
				'pk'   => $info['pk'],
				'mode' => $mode,
			);

			if ( $full || ! $cols || array_diff( $info['pk'], $cols ) ) {
				continue; // No fingerprint: the source sends the table whole.
			}
			$fps[ $short ] = VulnHub_Replica_Schema::fingerprint( $short, $cols, (string) $info['pk'][0], $mode, $info['update_time'] );
		}

		$chunk = max( 1, (int) $this->get( 'chunk_mb', 8 ) ) * 1048576;
		$r     = $this->api(
			'POST',
			'/jobs',
			array(
				'schema'       => $schema,
				'fingerprints' => $fps,
				'chunk_size'   => $chunk,
			),
			120
		);
		if ( 201 !== $r['code'] || empty( $r['json']['job'] ) ) {
			throw new \RuntimeException( $r['code'] ? sprintf( 'The source refused the package request (%d): %s', $r['code'], $r['error'] ) : 'Could not reach the source: ' . $r['error'] );
		}

		$this->run['job'] = (string) $r['json']['job'];
		$this->save_run();
		$this->log( sprintf( 'Package %s requested (%s, %d tables fingerprinted).', $this->run['job'], $full ? 'full copy' : 'changes only', count( $fps ) ) );
	}

	/**
	 * Drive the source through building the package.
	 */
	private function prepare(): void {
		$idle = 0;
		while ( true ) {
			$r = $this->api( 'POST', '/jobs/' . $this->run['job'] . '/step', null, 180 );
			if ( 404 === $r['code'] ) {
				throw new VulnHub_Replica_Lost( 'not found while it was being built' );
			}
			if ( 200 !== $r['code'] || ! $r['json'] ) {
				if ( ++$idle > 5 ) {
					throw new \RuntimeException( $r['code'] ? sprintf( 'The source failed while building the package (%d): %s', $r['code'], $r['error'] ) : 'Lost the source while it was building the package: ' . $r['error'] );
				}
				sleep( 5 );
				continue;
			}
			$idle = 0;
			$s    = $r['json'];

			if ( 'failed' === ( $s['status'] ?? '' ) ) {
				$err = (string) ( $s['error'] ?? 'unknown error' );
				$this->abandon();
				throw new \RuntimeException( 'The source could not build the package: ' . $err );
			}

			$this->report( 'prepare', array( 'prepare_pct' => (float) ( $s['pct'] ?? 0 ), 'prepare_note' => 'Source: ' . (string) ( $s['note'] ?? '' ) ) );

			if ( 'ready' === ( $s['status'] ?? '' ) && ! empty( $s['manifest'] ) ) {
				$m                    = (array) $s['manifest'];
				$this->run['manifest'] = $m;
				$this->run['phase']    = 'download';
				$this->run['done']     = array();
				$this->save_run();
				$this->log(
					sprintf(
						'Package ready: %s in %d chunk(s) of up to %s, %s row(s) across %d changed table(s).',
						size_format( (int) $m['bytes_total'], 1 ),
						(int) $m['chunk_count'],
						size_format( (int) $m['chunk_size'] ),
						number_format( (int) $m['records'] ),
						count( (array) $m['tables'] )
					)
				);
				foreach ( (array) ( $m['skipped'] ?? array() ) as $sk ) {
					$this->log( sprintf( 'Source skipped %s: %s', $sk['table'] ?? '?', $sk['why'] ?? '' ) );
				}
				return;
			}
			if ( ! empty( $s['busy'] ) ) {
				sleep( 2 );
			}
		}
	}

	/**
	 * Fetch every chunk not already on disk and verified.
	 */
	private function download(): void {
		$m     = (array) $this->run['manifest'];
		$dir   = $this->workdir();
		$done  = array_flip( array_map( 'intval', (array) ( $this->run['done'] ?? array() ) ) );
		$bytes = 0;

		foreach ( (array) $m['chunks'] as $c ) {
			$n = (int) $c['n'];
			if ( ! isset( $done[ $n ] ) ) {
				continue;
			}
			$part = sprintf( '%s/part-%05d', $dir, $n );
			if ( is_file( $part ) && filesize( $part ) === (int) $c['bytes'] ) {
				$bytes += (int) $c['bytes'];
			} else {
				unset( $done[ $n ] ); // Recorded but gone from disk: fetch again.
			}
		}
		if ( $done ) {
			$this->log( sprintf( 'Resuming the download: %d of %d chunk(s) already here.', count( $done ), (int) $m['chunk_count'] ) );
		}

		foreach ( (array) $m['chunks'] as $c ) {
			$n    = (int) $c['n'];
			$part = sprintf( '%s/part-%05d', $dir, $n );

			if ( isset( $done[ $n ] ) ) {
				continue;
			}

			$this->report( 'download', $this->dl_stats( $m, count( $done ), $bytes, $n ) );

			$ok = false;
			for ( $try = 1; $try <= 4 && ! $ok; $try++ ) {
				$res = wp_remote_get(
					$this->endpoint( '/jobs/' . $this->run['job'] . '/chunks/' . $n ),
					array(
						'timeout'  => 300,
						'stream'   => true,
						'filename' => $part . '.tmp',
						'headers'  => array( 'X-VulnHub-Replica-Token' => $this->secret( 'token' ) ),
					)
				);
				$code = is_wp_error( $res ) ? 0 : (int) wp_remote_retrieve_response_code( $res );
				if ( 404 === $code ) {
					@unlink( $part . '.tmp' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
					throw new VulnHub_Replica_Lost( 'not found while downloading chunk ' . ( $n + 1 ) );
				}
				if ( 200 === $code && is_file( $part . '.tmp' ) && filesize( $part . '.tmp' ) === (int) $c['bytes'] && hash_file( 'sha256', $part . '.tmp' ) === (string) $c['sha256'] ) {
					rename( $part . '.tmp', $part );
					$ok = true;
					break;
				}
				@unlink( $part . '.tmp' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$this->log( sprintf( 'Chunk %d of %d failed its check (try %d): %s', $n + 1, (int) $m['chunk_count'], $try, is_wp_error( $res ) ? $res->get_error_message() : 'HTTP ' . $code ) );
				sleep( min( 30, 5 * $try ) );
			}
			if ( ! $ok ) {
				throw new \RuntimeException( sprintf( 'Chunk %d of %d would not download intact. The %d already on disk are kept; the next run carries on from here.', $n + 1, (int) $m['chunk_count'], count( $done ) ) );
			}

			$done[ $n ]        = true;
			$bytes            += (int) $c['bytes'];
			$this->run['done'] = array_keys( $done );
			$this->save_run();
		}

		$this->report( 'download', $this->dl_stats( $m, count( $done ), $bytes, -1 ) );
		$this->log( sprintf( 'Downloaded %d chunk(s), %s, each checked.', count( $done ), size_format( $bytes, 1 ) ) );

		$this->run['phase'] = 'assemble';
		$this->save_run();
	}

	/**
	 * @param array<string,mixed> $m Manifest.
	 * @return array<string,mixed>
	 */
	private function dl_stats( array $m, int $chunks_done, int $bytes, int $current ): array {
		return array(
			'bytes'        => $bytes,
			'bytes_total'  => (int) $m['bytes_total'],
			'chunks_done'  => $chunks_done,
			'chunks_total' => (int) $m['chunk_count'],
			'current'      => $current >= 0 ? $current + 1 : null,
		);
	}

	/**
	 * Join the chunks and check the whole archive against the source's hash.
	 */
	private function assemble(): void {
		$m   = (array) $this->run['manifest'];
		$dir = $this->workdir();
		$zip = $dir . '/package.zip';

		$out = fopen( $zip . '.tmp', 'wb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		foreach ( (array) $m['chunks'] as $c ) {
			$part = sprintf( '%s/part-%05d', $dir, (int) $c['n'] );
			$in   = fopen( $part, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			if ( ! $in ) {
				fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions
				$this->run['phase'] = 'download';
				$this->run['done']  = array();
				$this->save_run();
				throw new \RuntimeException( 'A downloaded chunk went missing from disk; downloading again.' );
			}
			stream_copy_to_stream( $in, $out );
			fclose( $in ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}
		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		if ( hash_file( 'sha256', $zip . '.tmp' ) !== (string) $m['sha256'] ) {
			@unlink( $zip . '.tmp' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$this->run['phase'] = 'download';
			$this->run['done']  = array();
			$this->save_run();
			throw new \RuntimeException( 'The reassembled package did not match the source\'s checksum; it will be downloaded again.' );
		}
		rename( $zip . '.tmp', $zip );
		foreach ( (array) $m['chunks'] as $c ) {
			@unlink( sprintf( '%s/part-%05d', $dir, (int) $c['n'] ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}

		$this->run['phase']   = 'process';
		$this->run['ti']      = 0;
		$this->run['ri']      = 0;
		$this->run['applied'] = 0;
		$this->run['tables']  = array();
		$this->save_run();
	}

	/* -----------------------------------------------------------------
	 * Applying
	 * --------------------------------------------------------------- */

	private function db(): \mysqli {
		global $wpdb;

		if ( null === $this->dbh ) {
			$dbh = $wpdb->dbh;
			if ( ! $dbh instanceof \mysqli ) {
				throw new \RuntimeException( 'Expected a mysqli database connection.' );
			}
			$this->dbh = $dbh;
		}
		return $this->dbh;
	}

	private function q( string $sql ): void {
		if ( ! mysqli_query( $this->db(), $sql ) ) { // phpcs:ignore WordPress.DB.RestrictedFunctions
			throw new \RuntimeException( 'Database: ' . mysqli_error( $this->db() ) ); // phpcs:ignore WordPress.DB.RestrictedFunctions
		}
	}

	private function count_rows( string $full ): int {
		$res = mysqli_query( $this->db(), 'SELECT COUNT(*) FROM ' . VulnHub_Replica_Schema::ident( $full ) ); // phpcs:ignore WordPress.DB.RestrictedFunctions
		if ( ! $res ) {
			return 0;
		}
		$row = mysqli_fetch_row( $res ); // phpcs:ignore WordPress.DB.RestrictedFunctions
		return (int) ( $row[0] ?? 0 );
	}

	/**
	 * @param array<int,string|null> $row Values.
	 */
	private function values( array $row ): string {
		$out = array();
		foreach ( $row as $v ) {
			$out[] = null === $v ? 'NULL' : "'" . mysqli_real_escape_string( $this->db(), (string) $v ) . "'"; // phpcs:ignore WordPress.DB.RestrictedFunctions
		}
		return '(' . implode( ',', $out ) . ')';
	}

	private function process(): void {
		$m    = (array) $this->run['manifest'];
		$dir  = $this->workdir();
		$zip  = new \ZipArchive();
		if ( true !== $zip->open( $dir . '/package.zip' ) ) {
			$this->run['phase'] = 'download';
			$this->run['done']  = array();
			$this->save_run();
			throw new \RuntimeException( 'The package could not be opened; it will be downloaded again.' );
		}

		$inner = json_decode( (string) $zip->getFromName( 'manifest.json' ), true );
		if ( ! is_array( $inner ) || 1 !== (int) ( $inner['format'] ?? 0 ) ) {
			throw new \RuntimeException( 'The package manifest is missing or of an unknown format.' );
		}

		$local  = VulnHub_Replica_Schema::tables();
		$tables = (array) $inner['tables'];
		$first  = ! get_option( self::OPT_LAST );

		$old_mode = '';
		$res      = mysqli_query( $this->db(), 'SELECT @@SESSION.sql_mode' ); // phpcs:ignore WordPress.DB.RestrictedFunctions
		if ( $res ) {
			$old_mode = (string) ( mysqli_fetch_row( $res )[0] ?? '' ); // phpcs:ignore WordPress.DB.RestrictedFunctions
		}
		// Keep id 0 as 0, and take dates exactly as the source stored them.
		$this->q( "SET SESSION sql_mode = 'NO_AUTO_VALUE_ON_ZERO'" );
		$this->q( 'SET SESSION foreign_key_checks = 0' );

		try {
			for ( $ti = (int) $this->run['ti']; $ti < count( $tables ); $ti++ ) {
				$t     = (array) $tables[ $ti ];
				$short = (string) $t['table'];

				if ( ! isset( $local[ $short ] ) ) {
					$this->warn( $short, 'Not present on this instance.' );
				} else {
					$why = $this->shrink_check( $t, $first );
					if ( '' !== $why ) {
						$this->warn( $short, $why );
					} else {
						$path = $dir . '/' . basename( (string) $t['file'] );
						if ( ! $zip->extractTo( $dir, array( (string) $t['file'] ) ) ) {
							throw new \RuntimeException( 'Could not unpack ' . $t['file'] . '.' );
						}
						$n = 'ranges' === $t['mode'] ? $this->apply_ranges( $t, $path ) : $this->apply_replace( $t, $path );
						@unlink( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors

						$this->run['tables'][ $short ] = array(
							'mode' => (string) $t['mode'],
							'rows' => $n,
						);
						$this->log( sprintf( '%s: %s row(s) %s.', $short, number_format( $n ), 'ranges' === $t['mode'] ? sprintf( 'rewritten across %d changed range(s)', count( (array) $t['ranges'] ) ) : 'loaded and swapped in' ) );
					}
				}

				$this->run['ti'] = $ti + 1;
				$this->run['ri'] = 0;
				$this->save_run();
			}

			$this->mirror_runs( (array) ( $inner['runs'] ?? array() ) );

			$opts    = json_decode( (string) $zip->getFromName( 'options.json' ), true );
			$written = VulnHub_Replica_Schema::import_options( is_array( $opts ) ? $opts : array(), (array) get_option( self::OPT_OPTIONS, array() ) );
			update_option( self::OPT_OPTIONS, $written, false );
			$this->log( sprintf( '%d setting(s) copied.', count( $written ) ) );
		} finally {
			$this->q( "SET SESSION sql_mode = '" . mysqli_real_escape_string( $this->db(), $old_mode ) . "'" ); // phpcs:ignore WordPress.DB.RestrictedFunctions
			$this->q( 'SET SESSION foreign_key_checks = 1' );
			$zip->close();
		}

		$this->run['phase'] = 'done';
		$this->save_run();
	}

	/**
	 * Show the source's last run per connector in this copy's run history,
	 * marked as the source's, so "last refreshed" reads true here.
	 *
	 * @param array<int,array<string,mixed>> $runs Source runs.
	 */
	private function mirror_runs( array $runs ): void {
		global $wpdb;

		$table = vh_table( 'sync_runs' );
		$wpdb->query( "DELETE FROM {$table} WHERE mode = 'source'" ); // phpcs:ignore WordPress.DB.PreparedSQL
		foreach ( $runs as $r ) {
			if ( self::ID === (string) ( $r['connector'] ?? '' ) || empty( $r['finished_at'] ) ) {
				continue;
			}
			$wpdb->insert(
				$table,
				array(
					'connector'   => substr( (string) $r['connector'], 0, 64 ),
					'mode'        => 'source',
					'status'      => substr( (string) $r['status'], 0, 24 ),
					'started_at'  => (string) $r['started_at'],
					'finished_at' => (string) $r['finished_at'],
					'duration_ms' => (int) $r['duration_ms'],
					'processed'   => (int) $r['processed'],
					'created'     => (int) $r['created'],
					'updated'     => (int) $r['updated'],
					'skipped'     => (int) $r['skipped'],
					'failed'      => (int) $r['failed'],
					'message'     => 'On the source instance: ' . (string) $r['message'],
					'log_text'    => 'This run happened on the source instance; the copy received its results.',
					'created_at'  => vh_now(),
				)
			);
		}
	}

	/**
	 * A source table that has lost more than half its rows since the copy
	 * last saw it is held back unless the operator has said that is fine.
	 * An emptied source and a real clear-out look identical from here; the
	 * cost of guessing wrong is only one way round.
	 *
	 * @param array<string,mixed> $t Table entry.
	 */
	private function shrink_check( array $t, bool $first ): string {
		if ( $first || $this->get_bool_setting( 'allow_shrink' ) || ! empty( $this->run['full'] ) ) {
			return '';
		}
		$have = $this->count_rows( VulnHub_Replica_Schema::full( (string) $t['table'] ) );
		$will = (int) ( $t['total'] ?? 0 );
		if ( $have > 1000 && $will < $have / 2 ) {
			return sprintf( 'Held back: the source now has %s rows where this copy has %s. Turn on "Allow a table to shrink by more than half" to accept it.', number_format( $will ), number_format( $have ) );
		}
		return '';
	}

	private function get_bool_setting( string $key ): bool {
		return (bool) $this->settings->get_bool( $this->id(), $key, false );
	}

	private function warn( string $table, string $why ): void {
		$this->run['warnings'][] = array(
			'table' => $table,
			'why'   => $why,
		);
		$this->log( sprintf( '%s: %s', $table, $why ) );
	}

	/**
	 * Bring each changed key range into line with the source, one
	 * transaction per range, so a reader never sees a range half-written
	 * and a crash loses at most the range in flight.
	 *
	 * A range is changed when any one row in it is, so most of the rows in
	 * it are usually already right. They are upserted rather than deleted
	 * and re-inserted: a row whose values have not changed costs a key
	 * lookup, not a delete and an insert through every secondary index.
	 * Rows the source no longer has in the range are deleted first.
	 *
	 * @param array<string,mixed> $t Table entry.
	 */
	private function apply_ranges( array $t, string $path ): int {
		$full    = VulnHub_Replica_Schema::full( (string) $t['table'] );
		$table   = VulnHub_Replica_Schema::ident( $full );
		$cols    = (array) $t['cols'];
		$pk_name = (string) $t['pk'][0];
		$pk      = VulnHub_Replica_Schema::ident( $pk_name );
		$pk_at   = (int) array_search( $pk_name, $cols, true );
		$set     = array();
		foreach ( $cols as $c ) {
			if ( $c !== $pk_name ) {
				$id    = VulnHub_Replica_Schema::ident( (string) $c );
				$set[] = "{$id} = VALUES({$id})";
			}
		}
		$head   = 'INSERT INTO ' . $table . ' (' . implode( ',', array_map( array( 'VulnHub_Replica_Schema', 'ident' ), $cols ) ) . ') VALUES ';
		$tail   = $set ? ' ON DUPLICATE KEY UPDATE ' . implode( ', ', $set ) : ' ON DUPLICATE KEY UPDATE ' . $pk . ' = ' . $pk;
		$ranges = (array) $t['ranges'];
		$start  = (int) ( $this->run['ri'] ?? 0 );
		$total  = 0;

		$gz = gzopen( $path, 'rb' );
		if ( ! $gz ) {
			throw new \RuntimeException( 'Could not read ' . $t['file'] . '.' );
		}
		$next = function () use ( $gz ): ?array {
			while ( ! gzeof( $gz ) ) {
				$line = gzgets( $gz );
				if ( false === $line ) {
					return null;
				}
				$line = rtrim( $line, "\r\n" );
				if ( '' === $line ) {
					continue;
				}
				$row = VulnHub_Replica_Schema::decode_row( $line );
				if ( null === $row ) {
					throw new \RuntimeException( 'A row in the package could not be read.' );
				}
				return $row;
			}
			return null;
		};

		$row = $next();

		for ( $ri = $start; $ri < count( $ranges ); $ri++ ) {
			$from = (int) $ranges[ $ri ][0];
			$to   = (int) $ranges[ $ri ][1];

			// Rows before this range belong to ranges a previous attempt
			// already committed.
			while ( null !== $row && (int) $row[ $pk_at ] < $from ) {
				$row = $next();
			}

			// A range is capped at a few thousand rows by the source, so it
			// is held whole: its key list decides what to delete.
			$rows = array();
			while ( null !== $row && (int) $row[ $pk_at ] < $to ) {
				$rows[] = $row;
				$row    = $next();
			}

			$this->q( 'START TRANSACTION' );
			try {
				$keep = array();
				foreach ( $rows as $r ) {
					$keep[] = (int) $r[ $pk_at ];
				}
				$this->q(
					"DELETE FROM {$table} WHERE {$pk} >= {$from} AND {$pk} < {$to}"
					. ( $keep ? " AND {$pk} NOT IN (" . implode( ',', $keep ) . ')' : '' )
				);

				$batch = array();
				$size  = 0;
				foreach ( $rows as $r ) {
					$v       = $this->values( $r );
					$batch[] = $v;
					$size   += strlen( $v );
					if ( count( $batch ) >= self::INSERT_ROWS || $size >= self::INSERT_BYTES ) {
						$this->q( $head . implode( ',', $batch ) . $tail );
						$total += count( $batch );
						$batch  = array();
						$size   = 0;
					}
				}
				if ( $batch ) {
					$this->q( $head . implode( ',', $batch ) . $tail );
					$total += count( $batch );
				}
				$this->q( 'COMMIT' );
			} catch ( \Throwable $e ) {
				$this->q( 'ROLLBACK' );
				gzclose( $gz );
				throw $e;
			}

			$this->bump_applied( $total, $ri + 1, (int) count( $ranges ), (string) $t['table'] );
		}

		gzclose( $gz );
		return $total;
	}

	/**
	 * Rebuild a table beside the live one and swap it in.
	 *
	 * @param array<string,mixed> $t Table entry.
	 */
	private function apply_replace( array $t, string $path ): int {
		$full  = VulnHub_Replica_Schema::full( (string) $t['table'] );
		$live  = VulnHub_Replica_Schema::ident( $full );
		$stage = VulnHub_Replica_Schema::ident( $full . VulnHub_Replica_Schema::STAGE_SUFFIX );
		$old   = VulnHub_Replica_Schema::ident( $full . VulnHub_Replica_Schema::OLD_SUFFIX );
		$cols  = (array) $t['cols'];
		$head  = 'INSERT INTO ' . $stage . ' (' . implode( ',', array_map( array( 'VulnHub_Replica_Schema', 'ident' ), $cols ) ) . ') VALUES ';

		$this->q( "DROP TABLE IF EXISTS {$stage}" );
		$this->q( "DROP TABLE IF EXISTS {$old}" );
		$this->q( "CREATE TABLE {$stage} LIKE {$live}" );

		$gz = gzopen( $path, 'rb' );
		if ( ! $gz ) {
			throw new \RuntimeException( 'Could not read ' . $t['file'] . '.' );
		}

		$total = 0;
		$batch = array();
		$size  = 0;
		while ( ! gzeof( $gz ) ) {
			$line = gzgets( $gz );
			if ( false === $line ) {
				break;
			}
			$line = rtrim( $line, "\r\n" );
			if ( '' === $line ) {
				continue;
			}
			$row = VulnHub_Replica_Schema::decode_row( $line );
			if ( null === $row ) {
				gzclose( $gz );
				$this->q( "DROP TABLE IF EXISTS {$stage}" );
				throw new \RuntimeException( 'A row in the package could not be read.' );
			}
			$v       = $this->values( $row );
			$batch[] = $v;
			$size   += strlen( $v );
			if ( count( $batch ) >= self::INSERT_ROWS || $size >= self::INSERT_BYTES ) {
				$this->q( $head . implode( ',', $batch ) );
				$total += count( $batch );
				$batch  = array();
				$size   = 0;
				$this->bump_applied( $total, 0, 0, (string) $t['table'] );
			}
		}
		gzclose( $gz );
		if ( $batch ) {
			$this->q( $head . implode( ',', $batch ) );
			$total += count( $batch );
		}

		// A short file is not a smaller table: refuse to swap it in.
		$have = $this->count_rows( $full . VulnHub_Replica_Schema::STAGE_SUFFIX );
		if ( $have !== (int) $t['rows'] ) {
			$this->q( "DROP TABLE IF EXISTS {$stage}" );
			throw new \RuntimeException( sprintf( '%s: the package said %d rows and %d arrived; the live table was left alone.', $t['table'], (int) $t['rows'], $have ) );
		}

		$this->q( "RENAME TABLE {$live} TO {$old}, {$stage} TO {$live}" );
		$this->q( "DROP TABLE IF EXISTS {$old}" );

		$this->bump_applied( $total, 0, 0, (string) $t['table'] );
		return $total;
	}

	/**
	 * Count rows applied for the bar; checkpoint the range now and then.
	 */
	private function bump_applied( int $table_total, int $range_done, int $range_count, string $table ): void {
		$base = (int) ( $this->run['applied_base'] ?? 0 );
		if ( ( $this->run['applied_table'] ?? '' ) !== $table ) {
			$base                       = (int) ( $this->run['applied'] ?? 0 );
			$this->run['applied_base']  = $base;
			$this->run['applied_table'] = $table;
		}
		$this->run['applied'] = $base + $table_total;
		if ( $range_done > 0 ) {
			$this->run['ri'] = $range_done;
		}

		if ( microtime( true ) - $this->last_report >= 2 ) {
			$this->save_run();
			$m = (array) $this->run['manifest'];
			$this->report(
				'process',
				array(),
				array(
					'records_done'  => (int) $this->run['applied'],
					'records_total' => (int) $m['records'],
					'table'         => $table,
					'tables_done'   => (int) $this->run['ti'],
					'tables_total'  => count( (array) $m['tables'] ),
				)
			);
		}
	}

	/**
	 * Close out: tell the source it can drop the package, tidy up, record
	 * what changed.
	 *
	 * @return array{ok:bool,message:string}
	 */
	private function finish(): array {
		$m = (array) $this->run['manifest'];

		$this->api( 'DELETE', '/jobs/' . $this->run['job'], null, 30 );
		VulnHub_Replica_Schema::rmdir( $this->workdir() );

		$rows    = (int) ( $this->run['applied'] ?? 0 );
		$changed = count( (array) ( $this->run['tables'] ?? array() ) );
		$warn    = (array) ( $this->run['warnings'] ?? array() );

		// The same signal a connector sends after it writes: widget caches
		// move to a new epoch and are rebuilt in the background, while the
		// last ones keep serving. Flushing the whole object cache instead
		// would make the first visit after every sync wait a minute.
		if ( ( $changed > 0 || ! empty( $this->run['full'] ) ) && class_exists( 'VulnHub_Dash_Widgets' ) ) {
			\VulnHub_Dash_Widgets::bust();
		}

		$this->stats['processed'] = $rows;
		$this->stats['updated']   = $changed;
		$this->stats['skipped']   = count( $warn );

		update_option(
			self::OPT_LAST,
			array(
				'at'       => vh_now(),
				'source'   => $this->source(),
				'bytes'    => (int) ( $m['bytes_total'] ?? 0 ),
				'chunks'   => (int) ( $m['chunk_count'] ?? 0 ),
				'rows'     => $rows,
				'tables'   => (array) ( $this->run['tables'] ?? array() ),
				'warnings' => $warn,
				'skipped'  => (array) ( $m['skipped'] ?? array() ),
				'seconds'  => time() - (int) ( $this->run['started'] ?? time() ),
				'full'     => ! empty( $this->run['full'] ),
			),
			false
		);
		delete_option( self::OPT_FULL );
		delete_option( self::OPT_RUN );
		$this->run = array();

		// Own logs only: housekeeping is stopped on a copy (it would rework
		// data the source already worked), so trim them here.
		global $wpdb;
		$keep = (int) $this->settings->platform( 'log_retention_days', 120 );
		$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . vh_table( 'sync_runs' ) . ' WHERE started_at < %s', gmdate( 'Y-m-d H:i:s', time() - $keep * DAY_IN_SECONDS ) ) );

		do_action( 'vulnhub_replica_synced', $changed, $rows );

		$msg = 0 === $changed
			? 'Already up to date.'
			: sprintf( '%s row(s) across %d table(s), %s in %d chunk(s).', number_format( $rows ), $changed, size_format( (int) ( $m['bytes_total'] ?? 0 ), 1 ), (int) ( $m['chunk_count'] ?? 0 ) );
		if ( $warn ) {
			$msg .= sprintf( ' %d table(s) held back — see the log.', count( $warn ) );
		}

		return array(
			'ok'      => true,
			'message' => $msg,
		);
	}

	/* -----------------------------------------------------------------
	 * Progress
	 * --------------------------------------------------------------- */

	/**
	 * Mirror where the run is onto the run row, in the staged-sync shape
	 * the Integrations card draws as two bars.
	 *
	 * @param array<string,mixed> $download Download facts.
	 * @param array<string,mixed> $process  Process facts.
	 */
	private function report( string $phase, array $download = array(), array $process = array() ): void {
		$this->last_report = microtime( true );
		if ( ! $this->run_id ) {
			return;
		}
		$m = (array) ( $this->run['manifest'] ?? array() );
		if ( 'process' === $phase && ! $download && $m ) {
			$download = $this->dl_stats( $m, (int) ( $m['chunk_count'] ?? 0 ), (int) ( $m['bytes_total'] ?? 0 ), -1 );
		}
		if ( ! $process ) {
			$process = array(
				'records_done'  => 0,
				'records_total' => (int) ( $m['records'] ?? 0 ),
			);
		}
		$this->logger->stage_progress(
			$this->run_id,
			array(
				'phase'    => $phase,
				'download' => $download,
				'process'  => $process,
			)
		);
	}

	/**
	 * Newest write in the package directory, for the stall detector: a big
	 * chunk streaming in is progress even before it completes.
	 */
	public static function disk_heartbeat( int $at, string $connector ): int {
		if ( self::ID !== $connector ) {
			return $at;
		}
		$run = (array) get_option( self::OPT_RUN, array() );
		if ( empty( $run['job'] ) ) {
			return $at;
		}
		$dir = VulnHub_Replica_Schema::dir( 'in/' . preg_replace( '/[^a-z0-9]/', '', (string) $run['job'] ) );
		foreach ( (array) glob( $dir . '/*' ) as $f ) {
			$at = max( $at, (int) @filemtime( (string) $f ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
		return $at;
	}
}

/**
 * The source no longer holds the package this copy was working on.
 */
final class VulnHub_Replica_Lost extends \RuntimeException {
}

