<?php
/**
 * Copy mode: an instance that copies another must never act on a real
 * system.
 *
 * The copy holds the same estate -- the same tickets, the same people, the
 * same alert rules. Left alone it would verify closures against the scanner,
 * re-open tickets, post alerts and mail owners, all a second time and all
 * from data it did not produce. So while the replica connector is switched
 * on, five things hold, each independent of the others:
 *
 *   1. No other connector syncs (core's `vulnhub_connector_sync_blocked`).
 *   2. No VulnHub background job runs except the copy's own sync, cache
 *      warming and operator-started backups/imports: automations,
 *      verification, alert polling and digests, ticket checks, agent status,
 *      threat feeds, snapshots and housekeeping all come off.
 *   3. Outbound HTTP goes to the source and nowhere else (plus this site's
 *      own loopback and WordPress.org updates).
 *   4. Email is held unless the operator has allowed it.
 *   5. Connector settings arrive switched off and without credentials.
 *
 * @package VulnHub\Replica
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Guards that apply while this instance is a copy.
 */
final class VulnHub_Replica_Guard {

	/** The replica connector's id (its class loads later than this one). */
	public const CONNECTOR = 'replica';

	/** Counters for the admin screen. */
	public const OPT_COUNTS = 'vulnhub_replica_guard';

	/**
	 * VulnHub cron hooks a copy still runs. Anything else with a VulnHub
	 * prefix is stripped -- deny by default, so a background job added
	 * later is stopped on a copy without anyone having to remember this.
	 */
	private const CRON_ALLOWED = array(
		'vulnhub_run_connector_sync',
		'vulnhub_run_connector_sync_now',
		'vulnhub_resume_syncs',
		'vulnhub_widget_warm',
		'vulnhub_widget_warm_cron',
		'vulnhub_widget_refresh',
		'vulnhub_backup_sweep',
		'vulnhub_backup_run_cron',
		'vulnhub_backup_run_pass',
		'vulnhub_backup_restore_pass',
		'vulnhub_import_sweep',
		'vulnhub_import_run_pass',
		'vulnhub_replica_sweep',
	);

	/** Public actions that do outward work whoever fires them. */
	private const ACTIONS_STRIPPED = array(
		'vulnhub_verify_closures',
		'vulnhub_run_automations',
	);

	/** @var array<string,int> */
	private static array $counts = array();

	public static function active(): bool {
		$cfg = (array) get_option( 'vulnhub_cfg_' . self::CONNECTOR, array() );
		return ! empty( $cfg['enabled'] );
	}

	public static function init(): void {
		if ( ! self::active() ) {
			return;
		}

		add_filter( 'vulnhub_connector_sync_blocked', array( __CLASS__, 'block_sync' ), 10, 2 );
		add_filter( 'pre_http_request', array( __CLASS__, 'block_http' ), 1, 3 );
		add_filter( 'pre_wp_mail', array( __CLASS__, 'block_mail' ), 1, 2 );
		add_action( 'wp_loaded', array( __CLASS__, 'strip_jobs' ), PHP_INT_MAX );
		add_action( 'vulnhub_portal_notice', array( __CLASS__, 'portal_notice' ) );
		add_action( 'admin_notices', array( __CLASS__, 'admin_notice' ) );
		add_action( 'shutdown', array( __CLASS__, 'flush_counts' ) );
	}

	/**
	 * @param string $blocked   Reason already given, or ''.
	 * @param string $connector Connector asking to sync.
	 */
	public static function block_sync( string $blocked, string $connector ): string {
		if ( '' !== $blocked || self::CONNECTOR === $connector ) {
			return $blocked;
		}
		self::count( 'sync' );
		return __( 'This instance is a copy of another: only the instance copy connector syncs here.', 'vulnhub' );
	}

	/**
	 * Take the callbacks off every VulnHub background job a copy must not
	 * run. Done at wp_loaded, after every plugin has added its own.
	 */
	public static function strip_jobs(): void {
		$hooks = self::ACTIONS_STRIPPED;
		foreach ( (array) _get_cron_array() as $events ) {
			foreach ( array_keys( (array) $events ) as $hook ) {
				$hooks[] = (string) $hook;
			}
		}
		foreach ( array_unique( $hooks ) as $hook ) {
			if ( ! str_starts_with( $hook, 'vulnhub_' ) && ! str_starts_with( $hook, 'vh_' ) ) {
				continue;
			}
			if ( in_array( $hook, self::CRON_ALLOWED, true ) ) {
				continue;
			}
			if ( has_action( $hook ) ) {
				remove_all_actions( $hook );
				add_action( $hook, array( __CLASS__, 'stripped' ) );
			}
		}
	}

	public static function stripped(): void {
		self::count( 'jobs' );
	}

	/**
	 * @param false|array|\WP_Error $pre  Short-circuit value.
	 * @param array<string,mixed>   $args Request args.
	 * @param string                $url  Request URL.
	 * @return false|\WP_Error
	 */
	public static function block_http( $pre, $args, $url ) {
		if ( false !== $pre ) {
			return $pre;
		}
		$host = strtolower( (string) wp_parse_url( (string) $url, PHP_URL_HOST ) );
		if ( '' === $host || in_array( $host, self::allowed_hosts(), true ) ) {
			return false;
		}
		foreach ( array( '.wordpress.org', '.w.org' ) as $suffix ) {
			if ( str_ends_with( $host, $suffix ) || ltrim( $suffix, '.' ) === $host ) {
				return false;
			}
		}
		self::count( 'http' );
		return new \WP_Error( 'vulnhub_replica_blocked', sprintf( 'This instance is a copy: outbound calls to %s are blocked.', $host ) );
	}

	/**
	 * @return array<int,string>
	 */
	private static function allowed_hosts(): array {
		$cfg   = (array) get_option( 'vulnhub_cfg_' . self::CONNECTOR, array() );
		$hosts = array( 'localhost', '127.0.0.1', '::1' );
		foreach ( array( (string) ( $cfg['source_url'] ?? '' ), home_url(), site_url() ) as $u ) {
			$h = strtolower( (string) wp_parse_url( $u, PHP_URL_HOST ) );
			if ( '' !== $h ) {
				$hosts[] = $h;
			}
		}
		return (array) apply_filters( 'vulnhub_replica_allowed_hosts', array_values( array_unique( $hosts ) ) );
	}

	/**
	 * @param null|bool           $pre  Short-circuit value.
	 * @param array<string,mixed> $atts Mail.
	 * @return null|bool
	 */
	public static function block_mail( $pre, $atts ) {
		unset( $atts );
		if ( null !== $pre ) {
			return $pre;
		}
		$cfg = (array) get_option( 'vulnhub_cfg_' . self::CONNECTOR, array() );
		if ( ! empty( $cfg['allow_mail'] ) ) {
			return null;
		}
		self::count( 'mail' );
		return false;
	}

	private static function count( string $what ): void {
		self::$counts[ $what ] = ( self::$counts[ $what ] ?? 0 ) + 1;
	}

	public static function flush_counts(): void {
		if ( ! self::$counts ) {
			return;
		}
		$all = (array) get_option( self::OPT_COUNTS, array() );
		foreach ( self::$counts as $k => $n ) {
			$all[ $k ] = (int) ( $all[ $k ] ?? 0 ) + $n;
		}
		$all['last'] = vh_now();
		update_option( self::OPT_COUNTS, $all, false );
		self::$counts = array();
	}

	private static function banner_text(): string {
		$last = (array) get_option( 'vulnhub_replica_last', array() );
		$when = ! empty( $last['at'] ) ? sprintf( __( 'last synced %s', 'vulnhub' ), vh_ago( (string) $last['at'] ) ) : __( 'not synced yet', 'vulnhub' );
		$cfg  = (array) get_option( 'vulnhub_cfg_' . self::CONNECTOR, array() );
		$url  = (string) ( $cfg['source_url'] ?? '' );
		$host = (string) wp_parse_url( $url, PHP_URL_HOST );
		$port = (int) wp_parse_url( $url, PHP_URL_PORT );
		$host = $port ? $host . ':' . $port : $host;

		return sprintf(
			/* translators: 1: source host, 2: when last synced. */
			__( 'Read-only copy of %1$s, %2$s. Changes made here are overwritten at the next sync.', 'vulnhub' ),
			'' !== $host ? $host : __( 'another instance', 'vulnhub' ),
			$when
		);
	}

	public static function portal_notice(): void {
		if ( ! is_user_logged_in() ) {
			return;
		}
		echo '<div class="vh-warn-note" role="status" style="margin:10px 16px 0;text-align:center">' . esc_html( self::banner_text() ) . '</div>';
	}

	public static function admin_notice(): void {
		echo '<div class="notice notice-warning"><p>' . esc_html( self::banner_text() ) . '</p></div>';
	}
}

