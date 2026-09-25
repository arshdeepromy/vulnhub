<?php
/**
 * Cron scheduling for connector syncs and housekeeping.
 *
 * WP-Cron is driven by the `vulnhub-cron` container running
 * `wp cron event run --due-now` every 60s, so DISABLE_WP_CRON is on and
 * schedules fire on time rather than on page views.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

namespace VulnHub\Core;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Scheduler {

	public const HOOK_SYNC       = 'vulnhub_run_connector_sync';
	/** A manual "Sync now" dispatched to the background. */
	public const HOOK_SYNC_NOW   = 'vulnhub_run_connector_sync_now';
	/** Recurring: pick up a staged sync a crash left half-finished. */
	public const HOOK_RESUME     = 'vulnhub_resume_syncs';
	public const HOOK_HOUSEKEEP  = 'vulnhub_housekeeping';
	public const HOOK_VERIFY     = 'vulnhub_cron_verify_closures';

	/**
	 * Read every Tenable agent's connected state and record what changed.
	 *
	 * Hourly, because that is the resolution of the online history it builds
	 * and Tenable keeps none of its own -- every hour not sampled is an hour
	 * nobody can ever ask about afterwards. It is one cheap paged read, not a
	 * sync.
	 */
	public const HOOK_AGENT_STATUS = 'vulnhub_poll_agent_status';
	public const HOOK_AUTOMATION = 'vulnhub_cron_run_automations';
	public const HOOK_SNAPSHOT   = 'vulnhub_daily_snapshot';

	/**
	 * The public extension points these cron events fire.
	 *
	 * These deliberately do NOT match the cron hook names above. They used to,
	 * and because Scheduler is itself a listener the callback re-entered
	 * itself through `do_action()` and recursed until PHP ran out of memory --
	 * a 9.6 GB worker that the container OOM-killed every 60 seconds. Keep the
	 * two namespaces apart.
	 */
	public const ACTION_VERIFY     = 'vulnhub_verify_closures';
	public const ACTION_AUTOMATION = 'vulnhub_run_automations';

	/**
	 * Cron hooks scheduled by earlier versions, unscheduled on sight.
	 *
	 * @var string[]
	 */
	private const LEGACY_HOOKS = array(
		'vulnhub_verify_closures',
		'vulnhub_run_automations',
	);

	/**
	 * Re-entrancy guard, keyed by action name.
	 *
	 * @var array<string,bool>
	 */
	private static array $running = array();

	public function hooks(): void {
		add_filter( 'cron_schedules', array( __CLASS__, 'intervals' ) ); // phpcs:ignore WordPress.WP.CronInterval
		add_action( self::HOOK_SYNC, array( $this, 'run_sync' ), 10, 1 );
		add_action( self::HOOK_SYNC_NOW, array( $this, 'run_sync_now' ), 10, 1 );
		add_action( self::HOOK_RESUME, array( $this, 'resume_syncs' ) );
		add_action( self::HOOK_HOUSEKEEP, array( $this, 'housekeeping' ) );
		add_action( self::HOOK_VERIFY, array( $this, 'verify_closures' ) );
		add_action( self::HOOK_AUTOMATION, array( $this, 'run_automations' ) );
		add_action( self::HOOK_SNAPSHOT, array( $this, 'daily_snapshot' ) );
		// Servers and workstations the CMDB does not list: lifecycle from
		// what the feeds saw (Lifecycle::derive()), after AWS has enriched
		// its records (12) and before caches are busted (99).
		add_action(
			'vulnhub_sync_complete',
			static function ( string $connector = '', string $status = '' ): void {
				if ( 'failed' !== $status ) {
					Lifecycle::derive();
				}
			},
			25,
			2
		);
		// New findings inherit the exceptions already approved for them,
		// before the dashboard caches are busted (priority 99).
		add_action(
			'vulnhub_sync_complete',
			static function ( string $connector = '', string $status = '' ): void {
				if ( 'failed' !== $status ) {
					Exceptions::reapply_active();
				}
			},
			30,
			2
		);
		add_action( 'vulnhub_loaded', array( $this, 'ensure_schedules' ), 20 );
	}

	/**
	 * Custom cron intervals.
	 *
	 * @param array<string,array{interval:int,display:string}> $schedules Existing.
	 * @return array<string,array{interval:int,display:string}>
	 */
	public static function intervals( array $schedules ): array {
		$schedules['vh_5min']    = array(
			'interval' => 5 * MINUTE_IN_SECONDS,
			'display'  => __( 'VulnHub: every 5 minutes', 'vulnhub' ),
		);
		$schedules['vh_15min']   = array(
			'interval' => 15 * MINUTE_IN_SECONDS,
			'display'  => __( 'VulnHub: every 15 minutes', 'vulnhub' ),
		);
		$schedules['vh_30min']   = array(
			'interval' => 30 * MINUTE_IN_SECONDS,
			'display'  => __( 'VulnHub: every 30 minutes', 'vulnhub' ),
		);
		$schedules['vh_hourly']  = array(
			'interval' => HOUR_IN_SECONDS,
			'display'  => __( 'VulnHub: hourly', 'vulnhub' ),
		);
		$schedules['vh_4hours']  = array(
			'interval' => 4 * HOUR_IN_SECONDS,
			'display'  => __( 'VulnHub: every 4 hours', 'vulnhub' ),
		);
		$schedules['vh_12hours'] = array(
			'interval' => 12 * HOUR_IN_SECONDS,
			'display'  => __( 'VulnHub: every 12 hours', 'vulnhub' ),
		);
		$schedules['vh_daily']   = array(
			'interval' => DAY_IN_SECONDS,
			'display'  => __( 'VulnHub: daily', 'vulnhub' ),
		);
		$schedules['vh_weekly']  = array(
			'interval' => WEEK_IN_SECONDS,
			'display'  => __( 'VulnHub: weekly', 'vulnhub' ),
		);

		return $schedules;
	}

	/**
	 * @return array<string,string>
	 */
	public static function interval_choices(): array {
		return array(
			'manual'    => __( 'Manual only', 'vulnhub' ),
			'vh_15min'  => __( 'Every 15 minutes', 'vulnhub' ),
			'vh_30min'  => __( 'Every 30 minutes', 'vulnhub' ),
			'vh_hourly' => __( 'Hourly', 'vulnhub' ),
			'vh_4hours' => __( 'Every 4 hours', 'vulnhub' ),
			'vh_12hours' => __( 'Every 12 hours', 'vulnhub' ),
			'vh_daily'  => __( 'Daily', 'vulnhub' ),
			'vh_weekly' => __( 'Weekly', 'vulnhub' ),
		);
	}

	/**
	 * Reconcile scheduled events with the configured intervals.
	 */
	public function ensure_schedules(): void {
		$core = vulnhub();

		foreach ( $core->connectors->all() as $id => $connector ) {
			if ( ! $connector->supports_sync() ) {
				continue;
			}

			$interval  = (string) $core->settings->get( $id, 'interval', $connector->default_interval() );
			$args      = array( $id );
			$scheduled = wp_next_scheduled( self::HOOK_SYNC, $args );

			if ( ! $connector->is_enabled() || 'manual' === $interval ) {
				if ( $scheduled ) {
					wp_unschedule_event( $scheduled, self::HOOK_SYNC, $args );
				}
				continue;
			}

			$current = wp_get_schedule( self::HOOK_SYNC, $args );
			if ( $current === $interval ) {
				continue;
			}
			if ( $scheduled ) {
				wp_unschedule_event( $scheduled, self::HOOK_SYNC, $args );
			}
			wp_schedule_event( time() + wp_rand( 30, 300 ), $interval, self::HOOK_SYNC, $args );
		}

		// Cron events scheduled under the old names would fire the public
		// action a second time; drop them the first time we see them.
		foreach ( self::LEGACY_HOOKS as $legacy ) {
			$ts = wp_next_scheduled( $legacy );
			while ( $ts ) {
				wp_unschedule_event( $ts, $legacy );
				$ts = wp_next_scheduled( $legacy );
			}
		}

		$standing = array(
			self::HOOK_HOUSEKEEP  => 'vh_daily',
			self::HOOK_VERIFY     => 'vh_hourly',
			self::HOOK_AGENT_STATUS => 'vh_hourly',
			self::HOOK_AUTOMATION => 'vh_15min',
			self::HOOK_RESUME     => 'vh_5min',
			self::HOOK_SNAPSHOT   => 'vh_daily',
		);
		foreach ( $standing as $hook => $interval ) {
			if ( ! wp_next_scheduled( $hook ) ) {
				wp_schedule_event( time() + wp_rand( 60, 600 ), $interval, $hook );
			}
		}
	}

	/**
	 * Cron callback: run one connector.
	 */
	/**
	 * Queue a manual sync to run in the background, and nudge cron so it
	 * starts promptly rather than at the next tick.
	 *
	 * @param string $connector_id Connector id.
	 */
	public static function queue_sync( string $connector_id ): void {
		if ( ! wp_next_scheduled( self::HOOK_SYNC_NOW, array( $connector_id ) ) ) {
			wp_schedule_single_event( time(), self::HOOK_SYNC_NOW, array( $connector_id ) );
		}

		if ( function_exists( 'spawn_cron' ) ) {
			spawn_cron(); // fire-and-forget loopback so it does not wait for the 60s tick
		}
	}

	/**
	 * Background handler for a dispatched manual sync. force + ignore_lock so
	 * it runs even if a stale lock lingers; the staged sync itself resumes any
	 * checkpoint on disk rather than restarting.
	 *
	 * @param string $connector_id Connector id.
	 */
	public function run_sync_now( string $connector_id ): void {
		$connector = vulnhub()->connectors->get( $connector_id );
		if ( ! $connector ) {
			return;
		}
		$connector->sync( array( 'mode' => 'manual', 'force' => true, 'ignore_lock' => true ) );

		/*
		 * Same reason as run_sync() below, and easy to miss: this is the path
		 * every manual sync takes -- the Sync now button, the REST endpoint,
		 * the MCP tool and the resume sweep -- and it did not recalculate.
		 * So a machine whose findings had just been imported kept whatever
		 * coverage state the last nightly run left on it: one asset here was
		 * reading "Not in Tenable" on the assets list while carrying a Tenable
		 * uuid, a Tenable chip and 25 Tenable findings, until housekeeping
		 * caught up hours later.
		 */
		Coverage::recalculate();
	}

	/**
	 * Resume any staged sync a crash left half-finished. Runs every few
	 * minutes: a connector that reports work still on disk, and is not already
	 * running, is dispatched to continue from its last checkpoint -- so an
	 * interrupted import finishes on its own rather than waiting for someone
	 * to press the button again.
	 */
	public function resume_syncs(): void {
		if ( ! function_exists( 'vulnhub' ) || ! isset( vulnhub()->connectors ) ) {
			return;
		}

		foreach ( vulnhub()->connectors->all() as $id => $connector ) {
			if ( ! $connector->resumable_sync() ) {
				continue;
			}
			if ( get_transient( 'vulnhub_sync_lock_' . $id ) ) {
				continue; // a run holds the lock; leave it be
			}
			self::queue_sync( (string) $id );
		}
	}

	public function run_sync( string $connector_id ): void {
		$connector = vulnhub()->connectors->get( $connector_id );
		if ( ! $connector ) {
			return;
		}
		$connector->sync( array( 'mode' => 'scheduled' ) );

		// A sync is the only thing that can change what Tenable has seen, so
		// coverage is only ever wrong between a sync and the next nightly
		// housekeeping run. Close that window here.
		Coverage::recalculate();
	}

	/**
	 * Nightly tidy-up: expire exceptions, trim logs, recompute asset rollups.
	 */
	public function housekeeping(): void {
		global $wpdb;

		$now = vh_now();

		// Expire risk acceptances that have passed their date.
		$expired = $wpdb->query(
			$wpdb->prepare(
				'UPDATE ' . vh_table( 'exceptions' ) . " SET status = 'expired', updated_at = %s
				 WHERE status = 'approved' AND expires_at IS NOT NULL AND expires_at < %s",
				$now,
				$now
			)
		);
		if ( $expired ) {
			vulnhub()->logger->audit(
				'exception.expired',
				sprintf(
					/* translators: %d: number of exceptions. */
					_n( '%d exception expired', '%d exceptions expired', (int) $expired, 'vulnhub' ),
					(int) $expired
				),
				'exception',
				'',
				array( 'count' => (int) $expired ),
				'warning'
			);
		}

		// Detach findings whose exception is no longer active.
		$wpdb->query(
			'UPDATE ' . vh_table( 'findings' ) . ' f
			 LEFT JOIN ' . vh_table( 'exceptions' ) . " e ON e.id = f.exception_id
			 SET f.exception_id = 0
			 WHERE f.exception_id > 0 AND (e.id IS NULL OR e.status <> 'approved')"
		);

		// And cover anything that arrived under a still-active exception.
		Exceptions::reapply_active();

		// Lifecycle for what the CMDB does not list (also after each sync).
		Lifecycle::derive();

		// Trim audit + sync logs.
		$keep_days = (int) vulnhub()->settings->platform( 'log_retention_days', 120 );
		$cutoff    = gmdate( 'Y-m-d H:i:s', time() - ( $keep_days * DAY_IN_SECONDS ) );
		$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . vh_table( 'audit' ) . ' WHERE logged_at < %s', $cutoff ) );
		$wpdb->query( $wpdb->prepare( 'DELETE FROM ' . vh_table( 'sync_runs' ) . ' WHERE started_at < %s', $cutoff ) );

		Repo::recalculate_asset_rollups();
		Coverage::recalculate();
	}

	/**
	 * Hourly: ask each verification-capable connector to confirm closures.
	 */
	public function verify_closures(): void {
		/**
		 * Fires when the platform wants closed tickets re-verified against
		 * the authoritative vulnerability source.
		 */
		self::dispatch( self::ACTION_VERIFY );
	}

	public function run_automations(): void {
		/** Fires when automation rules should be evaluated. */
		self::dispatch( self::ACTION_AUTOMATION );
	}

	/**
	 * Fire a public extension point once, never re-entering it.
	 *
	 * A listener that (directly or through another plugin) triggers the same
	 * action again would otherwise recurse without limit; WordPress does not
	 * guard `do_action()` against that. Bail instead of exhausting memory.
	 */
	private static function dispatch( string $action ): void {
		if ( ! empty( self::$running[ $action ] ) ) {
			vulnhub()->logger->audit(
				'scheduler.reentered',
				sprintf(
					/* translators: %s: action hook name. */
					__( 'Ignored a re-entrant call to %s while it was already running.', 'vulnhub' ),
					$action
				),
				'system',
				'',
				array( 'action' => $action ),
				'warning'
			);
			return;
		}

		self::$running[ $action ] = true;

		try {
			do_action( $action ); // phpcs:ignore WordPress.NamingConventions.ValidHookName.UseUnderscores
		} finally {
			unset( self::$running[ $action ] );
		}
	}

	/**
	 * Store a daily metric snapshot so the dashboard can draw trends.
	 */
	public function daily_snapshot(): void {
		global $wpdb;

		$date = gmdate( 'Y-m-d' );
		$rows = array();

		foreach ( array_keys( vh_severities() ) as $sev ) {
			$rows[ 'open_' . $sev ] = (int) $wpdb->get_var(
				$wpdb->prepare(
					'SELECT COUNT(*) FROM ' . vh_table( 'findings' ) . " WHERE state IN ('open','reopened') AND severity = %s",
					$sev
				)
			);
		}

		$rows['assets_total']      = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . vh_table( 'assets' ) );
		$rows['assets_unowned']    = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . vh_table( 'assets' ) . ' WHERE owner_person_id = 0 AND team_id = 0' );
		$rows['tickets_open']      = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . vh_table( 'tickets' ) . " WHERE status_category <> 'done'" );
		$rows['tickets_done']      = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . vh_table( 'tickets' ) . " WHERE status_category = 'done'" );
		$rows['exceptions_active'] = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . vh_table( 'exceptions' ) . " WHERE status = 'approved'" );
		$rows['findings_overdue']  = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . vh_table( 'findings' ) . " WHERE state IN ('open','reopened') AND due_at IS NOT NULL AND due_at < %s", vh_now() ) );

		foreach ( $rows as $key => $value ) {
			$wpdb->query(
				$wpdb->prepare(
					'INSERT INTO ' . vh_table( 'metrics' ) . ' (snapshot_date, metric_key, dimension, value, created_at)
					 VALUES (%s, %s, %s, %f, %s)
					 ON DUPLICATE KEY UPDATE value = VALUES(value)',
					$date,
					$key,
					'',
					(float) $value,
					vh_now()
				)
			);
		}
	}

	public static function unschedule_all(): void {
		$hooks = array_merge( array( self::HOOK_HOUSEKEEP, self::HOOK_VERIFY, self::HOOK_AUTOMATION, self::HOOK_SNAPSHOT ), self::LEGACY_HOOKS );

		foreach ( $hooks as $hook ) {
			$ts = wp_next_scheduled( $hook );
			while ( $ts ) {
				wp_unschedule_event( $ts, $hook );
				$ts = wp_next_scheduled( $hook );
			}
		}
		wp_clear_scheduled_hook( self::HOOK_SYNC );
	}

	/**
	 * Next scheduled run for a connector, or null.
	 */
	public static function next_run( string $connector_id ): ?int {
		$ts = wp_next_scheduled( self::HOOK_SYNC, array( $connector_id ) );
		return $ts ?: null;
	}
}

