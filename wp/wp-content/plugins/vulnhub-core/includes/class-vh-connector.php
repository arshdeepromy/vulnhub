<?php
/**
 * Abstract connector.
 *
 * Every integration plugin (Tenable, Intune, Jira, CMDB, Okta…) extends this
 * class and registers an instance on the `vulnhub_register_connectors` hook.
 * Core then renders its settings screen, schedules its sync, and reports on it
 * without knowing anything about the vendor.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

abstract class Connector {

	protected Settings $settings;
	protected Logger $logger;
	protected Http $http;
	protected int $run_id = 0;

	/** @var array<string,int> */
	protected array $stats = array(
		'processed' => 0,
		'created'   => 0,
		'updated'   => 0,
		'skipped'   => 0,
		'failed'    => 0,
	);

	public function __construct() {
		$core           = vulnhub();
		$this->settings = $core->settings;
		$this->logger   = $core->logger;
		$this->http     = new Http( '', array( $this, 'log' ) );
	}

	/* -----------------------------------------------------------------
	 * Identity — implemented by each connector
	 * --------------------------------------------------------------- */

	/** Machine id, e.g. "tenable". */
	abstract public function id(): string;

	/** Human label, e.g. "Tenable Vulnerability Management". */
	abstract public function label(): string;

	/** One-line description shown on the Integrations screen. */
	abstract public function description(): string;

	/** Dashicon slug for the admin UI. */
	public function icon(): string {
		return 'dashicons-admin-plugins';
	}

	/**
	 * Category used to group connectors: 'vulnerability' | 'identity' | 'itsm' | 'cmdb' | 'auth'.
	 */
	public function category(): string {
		return 'other';
	}

	/**
	 * Field definitions for the settings screen.
	 *
	 * Each field: array{
	 *   key:string, label:string, type:string, secret?:bool, required?:bool,
	 *   help?:string, placeholder?:string, options?:array<string,string>, default?:mixed
	 * }
	 *
	 * @return array<int,array<string,mixed>>
	 */
	abstract public function fields(): array;

	/**
	 * Verify credentials. MUST NOT write any platform data.
	 *
	 * @return array{ok:bool,message:string,detail?:array<string,mixed>}
	 */
	abstract public function test_connection(): array;

	/**
	 * Run a sync. Implementations should call $this->log() liberally and
	 * increment $this->stats.
	 *
	 * @param array<string,mixed> $args Options, e.g. ['full' => true].
	 * @return array{ok:bool,message:string}
	 */
	abstract protected function do_sync( array $args = array() ): array;

	/* -----------------------------------------------------------------
	 * Shared behaviour
	 * --------------------------------------------------------------- */

	/**
	 * Does this connector participate in scheduled syncs?
	 */
	public function supports_sync(): bool {
		return true;
	}

	/**
	 * Should a manual "Sync now" run in the background rather than in the web
	 * request? True for a connector whose sync is long enough that holding the
	 * browser open for it, and losing it if the browser is closed, is the
	 * wrong model. Such a sync is dispatched to cron and watched by the
	 * progress poller instead. Default: run inline (short syncs).
	 */
	public function async_sync(): bool {
		return false;
	}

	/**
	 * Does this connector have a staged sync checkpointed on disk that was
	 * interrupted and should be resumed? The resume sweep uses it. Default:
	 * no staged state to resume.
	 */
	public function resumable_sync(): bool {
		return false;
	}

	/**
	 * Can this connector be asked for a full resync -- everything the source
	 * holds, not just what changed since the last run? A connector that syncs
	 * incrementally from a watermark answers true, and then honours
	 * request_full_sync(). Default: no distinction to make.
	 */
	public function supports_full_sync(): bool {
		return false;
	}

	/**
	 * Ask for the next run to be a full resync.
	 *
	 * A request, not a run: a background sync is dispatched to cron and may
	 * start later, or find an interrupted run to finish first, so the intent
	 * has to outlive the web request that expressed it. Default: nothing to
	 * remember.
	 */
	public function request_full_sync(): void {
	}

	/**
	 * One line for the connector card about full resyncs (last one, next one
	 * due, a pending request). Empty when there is nothing to say.
	 */
	public function full_sync_note(): string {
		return '';
	}

	/**
	 * Is "use mock data instead of the live API" a meaningful choice here?
	 *
	 * It is for anything that imports: a sample fleet flows through the same
	 * normalisation code as the real thing. It is not for a connector that
	 * only sends -- there is no such thing as a pretend mail server, and a
	 * checkbox offering one is a control that silently does nothing.
	 */
	public function supports_mock(): bool {
		return true;
	}

	/**
	 * Default schedule slug (see Scheduler::intervals()).
	 */
	public function default_interval(): string {
		return 'vh_hourly';
	}

	/**
	 * Is the connector configured well enough to run?
	 */
	public function is_configured(): bool {
		if ( $this->is_mock() ) {
			return true;
		}
		foreach ( $this->fields() as $field ) {
			if ( empty( $field['required'] ) ) {
				continue;
			}
			$key = (string) $field['key'];
			if ( ! empty( $field['secret'] ) ) {
				if ( ! $this->settings->has_secret( $this->id(), $key ) ) {
					return false;
				}
			} elseif ( '' === trim( (string) $this->settings->get( $this->id(), $key, '' ) ) ) {
				return false;
			}
		}
		return true;
	}

	public function is_enabled(): bool {
		return $this->settings->get_bool( $this->id(), 'enabled', false );
	}

	/**
	 * Mock mode: either the platform-wide switch or this connector's own.
	 */
	public function is_mock(): bool {
		if ( $this->settings->get( $this->id(), 'mock', null ) !== null ) {
			return $this->settings->get_bool( $this->id(), 'mock', true );
		}
		return $this->settings->mock_mode();
	}

	public function get( string $key, mixed $default = '' ): mixed {
		return $this->settings->get( $this->id(), $key, $default );
	}

	public function secret( string $key ): string {
		return $this->settings->secret( $this->id(), $key );
	}

	/**
	 * Append to the current run log (and the PHP error log when debugging).
	 */
	public function log( string $message ): void {
		if ( $this->run_id ) {
			$this->logger->log_line( $this->run_id, $message );
		}
		// Only mirror to the PHP error log when explicitly asked. A full sync
		// emits hundreds of lines and would otherwise bury real errors.
		if ( $this->settings->get_bool( $this->id(), 'verbose_log', false ) ) {
			error_log( '[vulnhub:' . $this->id() . '] ' . $message ); // phpcs:ignore
		}
	}

	protected function bump( string $key, int $by = 1 ): void {
		$this->stats[ $key ] = ( $this->stats[ $key ] ?? 0 ) + $by;
	}

	/**
	 * Record live progress for the running sync, for the card's progress bar.
	 * A heartbeat rides along, so a poller can tell a working import from a
	 * stalled one. Call it as each batch lands, not per row.
	 *
	 * @param string $stage Human label for the current phase.
	 * @param int    $done  Records processed so far.
	 */
	protected function progress( string $stage, int $done ): void {
		if ( $this->run_id ) {
			$this->logger->progress( $this->run_id, $done, $stage );
		}
	}

	/**
	 * Public sync entry point — wraps do_sync() with run bookkeeping.
	 *
	 * @param array<string,mixed> $args Options.
	 * @return array{ok:bool,message:string,run_id:int,stats:array<string,int>}
	 */
	final public function sync( array $args = array() ): array {
		$mode = (string) ( $args['mode'] ?? ( wp_doing_cron() ? 'scheduled' : 'manual' ) );

		if ( ! $this->is_enabled() && empty( $args['force'] ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'Connector is disabled.', 'vulnhub' ),
				'run_id'  => 0,
				'stats'   => $this->stats,
			);
		}

		$lock = 'vulnhub_sync_lock_' . $this->id();
		if ( get_transient( $lock ) && empty( $args['ignore_lock'] ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'A sync for this connector is already running.', 'vulnhub' ),
				'run_id'  => 0,
				'stats'   => $this->stats,
			);
		}
		set_transient( $lock, time(), 30 * MINUTE_IN_SECONDS );

		$this->run_id = $this->logger->start_run( $this->id(), $mode );
		$this->log( sprintf( 'Starting %s sync (%s mode, %s data)', $this->label(), $mode, $this->is_mock() ? 'MOCK' : 'LIVE' ) );

		try {
			$result = $this->do_sync( $args );
			$status = ! empty( $result['ok'] ) ? 'success' : 'failed';
			$this->log( sprintf( 'Finished: %s', $result['message'] ?? '' ) );
		} catch ( \Throwable $e ) {
			$status = 'failed';
			$result = array(
				'ok'      => false,
				'message' => $e->getMessage(),
			);
			$this->bump( 'failed' );
			$this->log( 'EXCEPTION: ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine() );
		}

		$this->logger->finish_run( $this->run_id, $status, $this->stats, (string) ( $result['message'] ?? '' ) );
		$this->settings->set( $this->id(), 'last_sync', vh_now() );
		delete_transient( $lock );

		/**
		 * Fires after any connector sync completes.
		 *
		 * @param string              $connector Connector id.
		 * @param string              $status    success|failed.
		 * @param array<string,int>   $stats     Counters.
		 */
		do_action( 'vulnhub_sync_complete', $this->id(), $status, $this->stats );

		$run_id       = $this->run_id;
		$this->run_id = 0;

		return array(
			'ok'      => 'success' === $status,
			'message' => (string) ( $result['message'] ?? '' ),
			'run_id'  => $run_id,
			'stats'   => $this->stats,
		);
	}

	/**
	 * Health summary for the Integrations screen.
	 *
	 * @return array{state:string,label:string,detail:string}
	 */
	public function health(): array {
		if ( ! $this->is_enabled() ) {
			return array(
				'state'  => 'off',
				'label'  => __( 'Disabled', 'vulnhub' ),
				'detail' => __( 'Not in use.', 'vulnhub' ),
			);
		}
		if ( $this->is_mock() ) {
			return array(
				'state'  => 'mock',
				'label'  => __( 'Mock data', 'vulnhub' ),
				'detail' => __( 'Running against generated sample data. Add credentials to go live.', 'vulnhub' ),
			);
		}
		if ( ! $this->is_configured() ) {
			return array(
				'state'  => 'warn',
				'label'  => __( 'Not configured', 'vulnhub' ),
				'detail' => __( 'Required credentials are missing.', 'vulnhub' ),
			);
		}

		/*
		 * Report on the last run that actually finished, not merely the last
		 * that started. A sync that is killed mid-run (the Tenable export can
		 * be, on a large account) leaves a row stranded at status 'running'
		 * with no finish time; last_run() would return that and the card
		 * would read "Healthy" with an empty "Last synced —". last_completed_run()
		 * is the row that can answer when the sync finished and how long it
		 * took, which is what the card shows.
		 */
		$last      = $this->logger->last_run( $this->id() );
		$completed = $this->logger->last_completed_run( $this->id() );

		if ( ! $last && ! $completed ) {
			return array(
				'state'  => 'idle',
				'label'  => __( 'Never synced', 'vulnhub' ),
				'detail' => __( 'Configured, waiting for the first run.', 'vulnhub' ),
				'last'   => null,
			);
		}

		if ( $completed && 'failed' === $completed['status'] ) {
			return array(
				'state'  => 'error',
				'label'  => __( 'Last sync failed', 'vulnhub' ),
				'detail' => vh_trim( (string) $completed['message'], 140 ),
				'last'   => $completed,
			);
		}

		if ( ! $completed ) {
			return array(
				'state'  => 'idle',
				'label'  => __( 'Sync in progress', 'vulnhub' ),
				'detail' => __( 'The first sync is still running.', 'vulnhub' ),
				'last'   => null,
			);
		}

		return array(
			'state'  => 'ok',
			'label'  => __( 'Healthy', 'vulnhub' ),
			/* translators: %s: relative time. */
			'detail' => sprintf( __( 'Last synced %s.', 'vulnhub' ), vh_ago( (string) $completed['finished_at'] ) ),
			'last'   => $completed,
		);
	}
}

