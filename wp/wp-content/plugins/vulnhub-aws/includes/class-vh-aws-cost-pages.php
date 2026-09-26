<?php
/**
 * The two AWS cost screens and the REST routes behind them.
 *
 *  - AWS Cost (`aws-cost`): what the estate costs -- totals, trend, accounts,
 *    services, the biggest usage lines, spikes, and what schedules instances.
 *  - Cost Savings (`aws-savings`): the suggestions, split into confirmed and
 *    needs-confirmation, each one accepted or dropped with a click and the
 *    running plan totalled as you go.
 *
 * Both read the newest complete snapshot; neither calls AWS. Refresh queues a
 * new read on the cron runner.
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_AWS_Cost_Pages {

	public const VIEW_COST    = 'awscost';
	public const SLUG_COST    = 'aws-cost';
	public const VIEW_SAVINGS = 'awssavings';
	public const SLUG_SAVINGS = 'aws-savings';

	public static function init(): void {
		add_filter( 'vulnhub_dash_views', array( __CLASS__, 'register_views' ) );
		add_action( 'vulnhub_dash_render_view_' . self::VIEW_COST, array( __CLASS__, 'render_cost' ) );
		add_action( 'vulnhub_dash_render_view_' . self::VIEW_SAVINGS, array( __CLASS__, 'render_savings' ) );
		add_action( 'init', array( __CLASS__, 'ensure_pages' ), 20 );
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'assets' ), 20 );
		add_action( 'rest_api_init', array( __CLASS__, 'routes' ) );
	}

	/* ============================================================= views */

	/**
	 * @param array<string,array<string,mixed>> $views
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_views( array $views ): array {
		$mine = array(
			self::VIEW_COST    => array(
				'title' => __( 'AWS Cost', 'vulnhub' ),
				'slug'  => self::SLUG_COST,
				'menu'  => __( 'AWS Cost', 'vulnhub' ),
				'icon'  => 'M12 3v18M16 7.5c0-1.9-1.8-3-4-3s-4 1.1-4 3 1.8 2.6 4 3 4 1.2 4 3.1-1.8 3-4 3-4-1.1-4-3',
			),
			self::VIEW_SAVINGS => array(
				'title' => __( 'Cost Savings', 'vulnhub' ),
				'slug'  => self::SLUG_SAVINGS,
				'menu'  => __( 'Cost Savings', 'vulnhub' ),
				'icon'  => 'M4 17l5-5 4 4 7-8M14 8h6v6',
			),
		);

		$out  = array();
		$done = false;
		foreach ( $views as $key => $def ) {
			$out[ $key ] = $def;
			if ( 'network' === $key ) {
				$out  += $mine;
				$done = true;
			}
		}
		return $done ? $out : $out + $mine;
	}

	public static function ensure_pages(): void {
		$map     = (array) get_option( 'vulnhub_dash_pages', array() );
		$changed = false;

		foreach ( array( self::VIEW_COST => array( self::SLUG_COST, __( 'AWS Cost', 'vulnhub' ) ), self::VIEW_SAVINGS => array( self::SLUG_SAVINGS, __( 'Cost Savings', 'vulnhub' ) ) ) as $view => $def ) {
			if ( ! empty( $map[ $view ] ) ) {
				$e = get_post( (int) $map[ $view ] );
				if ( $e && 'trash' !== $e->post_status ) {
					continue;
				}
			}
			$page = get_page_by_path( $def[0] );
			$id   = $page ? (int) $page->ID : wp_insert_post(
				array(
					'post_title'     => $def[1],
					'post_name'      => $def[0],
					'post_content'   => '<!-- wp:shortcode -->[vulnhub_app view="' . $view . '"]<!-- /wp:shortcode -->',
					'post_status'    => 'publish',
					'post_type'      => 'page',
					'comment_status' => 'closed',
					'ping_status'    => 'closed',
				)
			);
			if ( ! is_wp_error( $id ) && $id ) {
				$map[ $view ] = (int) $id;
				$changed      = true;
			}
		}

		if ( $changed ) {
			update_option( 'vulnhub_dash_pages', $map, false );
		}
	}

	public static function assets(): void {
		if ( ! is_singular() || ! class_exists( 'VulnHub_Dash_App' ) ) {
			return;
		}
		$view = VulnHub_Dash_App::view_for_post( get_post() );
		if ( ! in_array( $view, array( self::VIEW_COST, self::VIEW_SAVINGS ), true ) ) {
			return;
		}

		$v = static fn( string $f ): string => (string) ( @filemtime( VULNHUB_AWS_DIR . 'assets/' . $f ) ?: VULNHUB_AWS_VERSION ); // phpcs:ignore

		wp_enqueue_style( 'vulnhub-aws-cost', VULNHUB_AWS_URL . 'assets/cost.css', array( 'vulnhub-app' ), $v( 'cost.css' ) );
		$js = self::VIEW_COST === $view ? 'cost-dashboard.js' : 'cost-savings.js';
		wp_enqueue_script( 'vulnhub-aws-cost', VULNHUB_AWS_URL . 'assets/' . $js, array(), $v( $js ), true );
		wp_localize_script(
			'vulnhub-aws-cost',
			'VH_AWS_COST',
			array(
				'rest'        => esc_url_raw( rest_url( 'vulnhub-aws/v1/cost' ) ),
				'nonce'       => wp_create_nonce( 'wp_rest' ),
				'canDecide'   => self::can_decide(),
				'canRefresh'  => self::can_refresh(),
				'savingsUrl'  => self::url( self::VIEW_SAVINGS, self::SLUG_SAVINGS ),
				'costUrl'     => self::url( self::VIEW_COST, self::SLUG_COST ),
				'networkUrl'  => home_url( '/cloud-network/' ),
			)
		);
	}

	private static function url( string $view, string $slug ): string {
		$map = (array) get_option( 'vulnhub_dash_pages', array() );
		return ! empty( $map[ $view ] ) ? (string) get_permalink( (int) $map[ $view ] ) : home_url( '/' . $slug . '/' );
	}

	/** Title and description, shared by the page and the exported file. */
	private static function head_html( string $which ): string {
		if ( 'cost' === $which ) {
			return '<h1>' . esc_html__( 'AWS Cost', 'vulnhub' ) . ' <span class="vh-chip vh-chip--info">' . esc_html__( 'Cost Explorer · CloudWatch · AWS Price List', 'vulnhub' ) . '</span></h1>'
				. '<p class="vh-sub">' . esc_html__( 'What every AWS account costs, where the money goes, what spiked, and what starts and stops your instances. Read-only, from your AWS SSO login. Amounts are in USD as AWS bills them.', 'vulnhub' ) . '</p>';
		}
		return '<h1>' . esc_html__( 'Cost Savings', 'vulnhub' ) . ' <span class="vh-chip vh-chip--info">' . esc_html__( 'from measured AWS data only', 'vulnhub' ) . '</span></h1>'
			. '<p class="vh-sub">' . esc_html__( 'Every suggestion shows the data it came from. Confirmed savings are arithmetic on measured usage and the AWS Price List. Items that depend on something we cannot measure are listed separately with what to check. Accept or drop each one — decisions are shared with everyone who uses VulnHub and recorded in the audit log.', 'vulnhub' ) . '</p>';
	}

	private static function export_button( string $which ): string {
		if ( ! VulnHub_AWS_Cost_Store::latest() ) {
			return '';
		}
		$url = add_query_arg(
			array( 'view' => $which, '_wpnonce' => wp_create_nonce( 'wp_rest' ) ),
			rest_url( 'vulnhub-aws/v1/cost/export' )
		);
		return '<div class="vh-page-head__actions"><a class="vh-btn" href="' . esc_url( $url ) . '" download title="' . esc_attr__( 'One HTML file with the cost dashboard and the savings list as they stand now. Opens in any browser, no sign-in needed.', 'vulnhub' ) . '">'
			. '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 3v12M7 10l5 5 5-5M5 21h14"/></svg>'
			. esc_html__( 'Export HTML', 'vulnhub' ) . '</a></div>';
	}

	public static function render_cost(): void {
		echo '<div class="vh-page-head vh-cost-head"><div>' . self::head_html( 'cost' ) . '</div>' . self::export_button( 'cost' ) . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo '<div class="vh-cost" data-vh-cost><p class="vh-sub vh-muted">' . esc_html__( 'Loading…', 'vulnhub' ) . '</p></div>';
	}

	public static function render_savings(): void {
		echo '<div class="vh-page-head vh-cost-head"><div>' . self::head_html( 'savings' ) . '</div>' . self::export_button( 'savings' ) . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo '<div class="vh-cost" data-vh-savings><p class="vh-sub vh-muted">' . esc_html__( 'Loading…', 'vulnhub' ) . '</p></div>';
	}

	/* ============================================================== REST */

	private static function can_view(): bool {
		return is_user_logged_in() && current_user_can( \VulnHub\Core\Caps::VIEW );
	}

	private static function can_decide(): bool {
		return current_user_can( \VulnHub\Core\Caps::MANAGE ) || current_user_can( \VulnHub\Core\Caps::TRIAGE );
	}

	private static function can_refresh(): bool {
		return current_user_can( \VulnHub\Core\Caps::MANAGE ) || current_user_can( \VulnHub\Core\Caps::RUN_SYNC );
	}

	public static function routes(): void {
		register_rest_route(
			'vulnhub-aws/v1',
			'/cost',
			array(
				'methods'             => 'GET',
				'permission_callback' => static fn(): bool => self::can_view(),
				'callback'            => static fn() => rest_ensure_response( self::dashboard() ),
			)
		);
		register_rest_route(
			'vulnhub-aws/v1',
			'/cost/savings',
			array(
				'methods'             => 'GET',
				'permission_callback' => static fn(): bool => self::can_view(),
				'callback'            => static fn() => rest_ensure_response( self::savings() ),
			)
		);
		register_rest_route(
			'vulnhub-aws/v1',
			'/cost/decision',
			array(
				'methods'             => 'POST',
				'permission_callback' => static fn(): bool => is_user_logged_in() && self::can_decide(),
				'callback'            => array( __CLASS__, 'decide' ),
			)
		);
		register_rest_route(
			'vulnhub-aws/v1',
			'/cost/refresh',
			array(
				'methods'             => 'POST',
				'permission_callback' => static fn(): bool => is_user_logged_in() && self::can_refresh(),
				'callback'            => static function () {
					$ok = VulnHub_AWS_Cost_Collector::queue();
					return rest_ensure_response( array( 'queued' => $ok, 'progress' => VulnHub_AWS_Cost_Store::progress() ) );
				},
			)
		);
		register_rest_route(
			'vulnhub-aws/v1',
			'/cost/settings',
			array(
				'methods'             => 'POST',
				'permission_callback' => static fn(): bool => is_user_logged_in() && self::can_refresh(),
				'callback'            => static function ( \WP_REST_Request $req ) {
					$mode = sanitize_key( (string) $req->get_param( 'auto' ) );
					if ( ! isset( VulnHub_AWS_Cost_Collector::AUTO_MODES[ $mode ] ) ) {
						return new \WP_Error( 'vh_bad_mode', __( 'Unknown auto-refresh setting.', 'vulnhub' ), array( 'status' => 400 ) );
					}
					update_option( VulnHub_AWS_Cost_Collector::OPT_AUTO, $mode, false );
					return rest_ensure_response( array( 'auto' => self::auto_meta() ) );
				},
			)
		);
		register_rest_route(
			'vulnhub-aws/v1',
			'/cost/export',
			array(
				'methods'             => 'GET',
				'permission_callback' => static fn(): bool => self::can_view(),
				'callback'            => array( __CLASS__, 'export' ),
			)
		);
		register_rest_route(
			'vulnhub-aws/v1',
			'/cost/progress',
			array(
				'methods'             => 'GET',
				'permission_callback' => static fn(): bool => self::can_view(),
				'callback'            => static fn() => rest_ensure_response( self::meta() ),
			)
		);
	}

	/** @return \WP_REST_Response|\WP_Error */
	public static function decide( \WP_REST_Request $req ) {
		$id     = sanitize_text_field( (string) $req->get_param( 'id' ) );
		$status = sanitize_key( (string) $req->get_param( 'status' ) );
		$note   = sanitize_textarea_field( (string) $req->get_param( 'note' ) );

		if ( ! in_array( $status, array( VulnHub_AWS_Cost_Store::ACCEPTED, VulnHub_AWS_Cost_Store::DISMISSED, '' ), true ) ) {
			return new \WP_Error( 'vh_bad_status', __( 'Unknown decision.', 'vulnhub' ), array( 'status' => 400 ) );
		}

		// The suggestion is looked up server-side: what gets recorded is what
		// the data says, not what the browser sent.
		$rec  = null;
		$snap = VulnHub_AWS_Cost_Store::latest();
		if ( $snap ) {
			$built = ( new VulnHub_AWS_Cost_Recs( $snap['data'] ) )->build();
			foreach ( array_merge( $built['confirmed'], $built['verify'] ) as $r ) {
				if ( $r['id'] === $id ) {
					$rec = $r;
					break;
				}
			}
		}
		$existing = VulnHub_AWS_Cost_Store::decisions()[ $id ] ?? null;
		if ( ! $rec && ! $existing ) {
			return new \WP_Error( 'vh_no_rec', __( 'That suggestion is not in the current data.', 'vulnhub' ), array( 'status' => 404 ) );
		}
		if ( ! $rec ) {
			if ( '' !== $status ) {
				return new \WP_Error( 'vh_gone', __( 'That suggestion is no longer in the current data; it can only be cleared.', 'vulnhub' ), array( 'status' => 409 ) );
			}
			$rec = (array) $existing + array( 'id' => $id );
		}

		$all = VulnHub_AWS_Cost_Store::decide( $id, $status, $note, $rec );

		return rest_ensure_response( array( 'id' => $id, 'decision' => $all[ $id ] ?? null ) );
	}

	/* ============================================================ payloads */

	/** @return array<string,mixed> */
	private static function meta(): array {
		$snap = VulnHub_AWS_Cost_Store::latest();
		$last = VulnHub_AWS_Cost_Store::last_attempt();
		$p    = VulnHub_AWS_Cost_Store::progress();
		$d    = $snap['data'] ?? array();

		$acc  = (array) ( $d['accounts'] ?? array() );
		return array(
			'has_data'      => (bool) $snap,
			'generated'     => $snap ? vh_date( $snap['finished_at'] ) : '',
			'generated_ago' => $snap ? vh_ago( $snap['finished_at'] ) : '',
			'accounts'      => count( $acc ),
			'cost_ok'       => count( array_filter( $acc, static fn( $a ) => ! empty( $a['cost_ok'] ) ) ),
			'ec2_ok'        => count( array_filter( $acc, static fn( $a ) => ! empty( $a['ec2_ok'] ) ) ),
			'errors'        => array_slice( (array) ( $d['errors'] ?? array() ), 0, 40 ),
			'ce_calls'      => (int) ( $d['ce_calls'] ?? 0 ),
			'window'        => $d['window'] ?? null,
			'periods'       => $d['periods'] ?? null,
			'timezone'      => (string) ( $d['timezone'] ?? '' ),
			'last_attempt'  => $last && 'ok' !== $last['status'] ? array( 'status' => $last['status'], 'message' => $last['message'], 'when' => vh_ago( $last['finished_at'] ) ) : null,
			'running'       => VulnHub_AWS_Cost_Collector::is_running(),
			'progress'      => $p,
			'can_refresh'   => self::can_refresh(),
			'auto'          => self::auto_meta(),
			'version'       => (int) ( $d['version'] ?? 0 ),
		);
	}

	/** @return array<string,mixed> */
	private static function auto_meta(): array {
		$opts = array();
		foreach ( VulnHub_AWS_Cost_Collector::AUTO_MODES as $k => $v ) {
			$opts[] = array( $k, $v[0] );
		}
		$last = (array) get_option( VulnHub_AWS_Cost_Collector::OPT_AUTO_LAST, array() );
		return array(
			'mode'    => VulnHub_AWS_Cost_Collector::auto_mode(),
			'options' => $opts,
			'last'    => $last ? array( 'when' => vh_ago( (string) $last['at'] ), 'result' => (string) $last['result'] ) : null,
		);
	}

	/** @return array<string,mixed> */
	public static function dashboard(): array {
		$meta = self::meta();
		$snap = VulnHub_AWS_Cost_Store::latest();
		if ( ! $snap ) {
			return array( 'meta' => $meta );
		}
		$d     = $snap['data'];
		$names = array_map( static fn( $a ) => (string) ( $a['name'] ?? '' ), (array) $d['accounts'] );

		// Accounts and services.
		$accounts = array();
		$services = array();
		$tot      = array( 'last_month' => 0.0, 'mtd' => 0.0 );
		foreach ( array( 'last_month', 'mtd' ) as $per ) {
			foreach ( (array) ( $d['services'][ $per ] ?? array() ) as $acct => $svc ) {
				$sum = array_sum( (array) $svc );
				$tot[ $per ] += $sum;
				$accounts[ $acct ][ $per ] = round( $sum, 2 );
				foreach ( (array) $svc as $s => $c ) {
					$services[ $s ][ $per ] = round( ( $services[ $s ][ $per ] ?? 0 ) + $c, 2 );
					$accounts[ $acct ]['svc'][ $per ][ $s ] = round( (float) $c, 2 );
				}
			}
		}
		$days_el = (int) ( $d['periods']['mtd']['days_elapsed'] ?? 0 );
		$dim     = (int) ( $d['periods']['mtd']['days_in_month'] ?? 30 );
		$acc_out = array();
		foreach ( $accounts as $acct => $a ) {
			$lm  = (float) ( $a['last_month'] ?? 0 );
			$mtd = (float) ( $a['mtd'] ?? 0 );
			$top = (array) ( $a['svc']['last_month'] ?? array() );
			arsort( $top );
			$acc_out[] = array(
				'id'         => (string) $acct,
				'name'       => (string) ( $names[ $acct ] ?? '' ),
				'env'        => VulnHub_AWS_Environment::label( VulnHub_AWS_Environment::classify( (string) ( $names[ $acct ] ?? '' ) ) ),
				'last_month' => round( $lm, 2 ),
				'mtd'        => round( $mtd, 2 ),
				'projected'  => $days_el > 0 ? round( $mtd / $days_el * $dim, 2 ) : null,
				'top'        => array_slice( $top, 0, 6, true ),
				'services'   => $a['svc'] ?? array(),
			);
		}
		usort( $acc_out, static fn( $x, $y ) => $y['last_month'] <=> $x['last_month'] );
		$svc_out = array();
		foreach ( $services as $s => $x ) {
			$svc_out[] = array( 'service' => (string) $s, 'last_month' => (float) ( $x['last_month'] ?? 0 ), 'mtd' => (float) ( $x['mtd'] ?? 0 ) );
		}
		usort( $svc_out, static fn( $x, $y ) => $y['last_month'] <=> $x['last_month'] );

		// Daily estate total, split by the biggest services.
		$daily   = array();
		$svc_day = array();
		foreach ( (array) ( $d['daily'] ?? array() ) as $acct => $days ) {
			foreach ( (array) $days as $day => $svc ) {
				foreach ( (array) $svc as $s => $c ) {
					$daily[ $day ]           = ( $daily[ $day ] ?? 0 ) + $c;
					$svc_day[ $s ][ $day ]   = ( $svc_day[ $s ][ $day ] ?? 0 ) + $c;
				}
			}
		}
		ksort( $daily );
		$svc_tot = array_map( 'array_sum', $svc_day );
		arsort( $svc_tot );
		$top_svc = array_slice( array_keys( $svc_tot ), 0, 6 );

		// Biggest usage lines.
		$lines = array();
		foreach ( (array) ( $d['usage']['last_month'] ?? array() ) as $acct => $rows ) {
			foreach ( (array) $rows as $r ) {
				$lines[] = array( 'account' => (string) $acct, 'account_name' => (string) ( $names[ $acct ] ?? '' ), 'service' => $r[0], 'usage_type' => $r[1], 'cost' => $r[2], 'qty' => $r[3], 'unit' => $r[4] );
			}
		}
		usort( $lines, static fn( $a, $b ) => $b['cost'] <=> $a['cost'] );

		$recs = ( new VulnHub_AWS_Cost_Recs( $d ) )->build();

		return array(
			'meta'      => $meta,
			'totals'    => array(
				'last_month' => round( $tot['last_month'], 2 ),
				'mtd'        => round( $tot['mtd'], 2 ),
				'projected'  => $days_el > 0 ? round( $tot['mtd'] / $days_el * $dim, 2 ) : null,
				'days_el'    => $days_el,
				'dim'        => $dim,
			),
			'context'   => $recs['context'],
			'savings'   => self::savings_summary( $recs ),
			'accounts'  => $acc_out,
			'services'  => $svc_out,
			'daily'     => array(
				'dates'    => array_keys( $daily ),
				'total'    => array_map( static fn( $x ) => round( $x, 2 ), array_values( $daily ) ),
				'services' => array_map(
					static function ( $s ) use ( $svc_day, $daily ) {
						return array( 'service' => $s, 'values' => array_map( static fn( $day ) => round( (float) ( $svc_day[ $s ][ $day ] ?? 0 ), 2 ), array_keys( $daily ) ) );
					},
					$top_svc
				),
			),
			'lines'     => array_slice( $lines, 0, 40 ),
			'anomalies' => self::anomalies( $d, $names ),
			'schedules' => self::schedules( $d, $recs['context'] ),
		);
	}

	/**
	 * Spikes: runs of days where an account's spend on one service was at
	 * least three times its own baseline (the median of the earliest three
	 * weeks in the series) and at least $50 that day. Every figure is a sum of
	 * Cost Explorer days.
	 *
	 * @param array<string,mixed>  $d
	 * @param array<string,string> $names
	 * @return array<int,array<string,mixed>>
	 */
	private static function anomalies( array $d, array $names ): array {
		$out = array();
		foreach ( (array) ( $d['daily'] ?? array() ) as $acct => $days ) {
			$dates = array_keys( (array) $days );
			sort( $dates );
			if ( count( $dates ) < 28 ) {
				continue;
			}
			$services = array();
			foreach ( (array) $days as $svc ) {
				$services += array_fill_keys( array_keys( (array) $svc ), true );
			}
			foreach ( array_keys( $services ) as $s ) {
				$vals = array();
				foreach ( $dates as $day ) {
					$vals[ $day ] = (float) ( $days[ $day ][ $s ] ?? 0 );
				}
				$base = array_slice( array_values( $vals ), 0, 21 );
				sort( $base );
				$median = $base[ (int) floor( count( $base ) / 2 ) ];
				$run    = null;
				foreach ( $vals as $day => $v ) {
					$spike = $v >= 50 && $v >= 3 * max( $median, 1 );
					if ( $spike ) {
						$run = $run ?? array( 'start' => $day, 'end' => $day, 'total' => 0.0, 'peak' => 0.0, 'days' => 0 );
						$run['end']    = $day;
						$run['total'] += $v;
						$run['peak']   = max( $run['peak'], $v );
						++$run['days'];
					} elseif ( $run ) {
						if ( ! self::monthly_posting( $run ) ) {
							$out[] = self::spike( (string) $acct, $names, (string) $s, $run, $median, false, $d );
						}
						$run   = null;
					}
				}
				if ( $run ) {
					if ( ! self::monthly_posting( $run ) ) {
						$out[] = self::spike( (string) $acct, $names, (string) $s, $run, $median, true, $d );
					}
				}
			}
		}
		usort( $out, static fn( $a, $b ) => $b['excess'] <=> $a['excess'] );
		return $out;
	}

	/**
	 * Monthly charges -- tax, subscriptions, support, up-front fees -- are all
	 * booked on the 1st. A one-day "spike" on the 1st is that, not an anomaly.
	 *
	 * @param array<string,mixed> $run
	 */
	private static function monthly_posting( array $run ): bool {
		return 1 === (int) $run['days'] && '01' === substr( (string) $run['start'], 8, 2 );
	}

	/**
	 * @param array<string,string> $names
	 * @param array<string,mixed>  $run
	 * @param array<string,mixed>  $d
	 * @return array<string,mixed>
	 */
	private static function spike( string $acct, array $names, string $svc, array $run, float $median, bool $ongoing, array $d ): array {
		// The usage types behind it this month, for a first clue.
		$why = array();
		foreach ( (array) ( $d['usage']['mtd'][ $acct ] ?? array() ) as $r ) {
			if ( $r[0] === $svc ) {
				$why[] = $r;
			}
		}
		usort( $why, static fn( $a, $b ) => $b[2] <=> $a[2] );
		return array(
			'account'      => $acct,
			'account_name' => (string) ( $names[ $acct ] ?? '' ),
			'service'      => $svc,
			'start'        => $run['start'],
			'end'          => $run['end'],
			'days'         => $run['days'],
			'total'        => round( $run['total'], 2 ),
			'excess'       => round( $run['total'] - $median * $run['days'], 2 ),
			'peak'         => round( $run['peak'], 2 ),
			'baseline'     => round( $median, 2 ),
			'ongoing'      => $ongoing,
			'usage'        => array_map( static fn( $r ) => array( 'usage_type' => $r[1], 'cost' => $r[2], 'qty' => $r[3], 'unit' => $r[4] ), array_slice( $why, 0, 4 ) ),
		);
	}

	/**
	 * What starts and stops instances, and what each instance actually did.
	 *
	 * @param array<string,mixed> $d
	 * @param array<string,mixed> $ctx
	 * @return array<string,mixed>
	 */
	private static function schedules( array $d, array $ctx ): array {
		$tag  = (string) $ctx['scheduler_tag'];
		$rows = array();
		$poss = (array) ( $d['window']['possible'] ?? array() );
		foreach ( (array) $d['instances'] as $i ) {
			$t        = (array) $i['tags'];
			$relevant = isset( $t['InstanceScheduler-LastAction'] ) || isset( $t['Schedule'] ) || isset( $t['CustodianOffHours'] )
				|| VulnHub_AWS_Environment::NONPROD === VulnHub_AWS_Environment::classify( (string) ( $t[ $tag ] ?? '' ), (string) $i['name'], (string) $i['account_name'] );
			if ( ! $relevant ) {
				continue;
			}
			$m      = $i['metrics'] ?? null;
			$rows[] = array(
				'id'           => $i['id'],
				'name'         => $i['name'],
				'account_name' => $i['account_name'],
				'type'         => $i['type'],
				'state'        => $i['state'],
				'tag'          => (string) ( $t[ $tag ] ?? '' ),
				'legacy'       => trim( ( isset( $t['Schedule'] ) ? 'Schedule=' . $t['Schedule'] . ' ' : '' ) . ( isset( $t['CustodianOffHours'] ) ? 'CustodianOffHours=' . $t['CustodianOffHours'] : '' ) ),
				'last_action'  => (string) ( $t['InstanceScheduler-LastAction'] ?? '' ),
				'hours'        => $m ? (int) $m['hours'] : 0,
				'weekend'      => $m ? (int) $m['buckets']['weekend']['hours'] : 0,
				'grid'         => $m['grid'] ?? null,
				'pattern'      => self::pattern( $m, $poss ),
			);
		}
		usort( $rows, static fn( $a, $b ) => [ $a['account_name'], $a['name'] ] <=> [ $b['account_name'], $b['name'] ] );

		return array(
			'tag'       => $tag,
			'fleet'     => $ctx['fleet'],
			'stacks'    => (array) ( $d['scheduler']['stacks'] ?? array() ),
			'rules'     => array_values( array_filter( (array) ( $d['scheduler']['rules'] ?? array() ), static fn( $r ) => VulnHub_AWS_Cost_Collector::is_start_stop( $r['name'] . ' ' . $r['description'] . ' ' . implode( ' ', (array) $r['targets'] ) ) ) ),
			'schedules' => array_values( array_filter( (array) ( $d['scheduler']['schedules'] ?? array() ), static fn( $r ) => VulnHub_AWS_Cost_Collector::is_start_stop( $r['name'] . ' ' . $r['target'] ) ) ),
			'instances' => $rows,
			'possible'  => $poss,
		);
	}

	/**
	 * One line for when an instance ran, from its hour grid.
	 *
	 * @param array<string,mixed>|null $m
	 * @param array<string,int>        $poss
	 */
	private static function pattern( ?array $m, array $poss ): string {
		if ( ! $m || empty( $m['hours'] ) ) {
			return __( 'Did not run in the 14-day window', 'vulnhub' );
		}
		if ( $m['hours'] >= 0.95 * ( $poss['all'] ?? 336 ) ) {
			return __( 'Around the clock, every day', 'vulnhub' );
		}
		$weeks = max( 1, (int) round( ( $poss['all'] ?? 336 ) / 168 ) );
		$wk    = array_fill( 0, 24, 0 );
		foreach ( (array) $m['grid'] as $day => $row ) {
			if ( $day < 5 ) {
				foreach ( (array) $row as $h => $n ) {
					$wk[ $h ] += (int) $n;
				}
			}
		}
		$on   = array_keys( array_filter( $wk, static fn( $n ) => $n >= 5 * $weeks * 0.5 ) );
		$line = $on ? sprintf( 'Mon–Fri %02d:00–%02d:00', min( $on ), max( $on ) + 1 ) : __( 'Occasionally', 'vulnhub' );
		$wkd  = (int) ( $m['buckets']['weekend']['hours'] ?? 0 );
		return $line . ( 0 === $wkd ? __( ', off at weekends', 'vulnhub' ) : sprintf( __( ', %d weekend hours', 'vulnhub' ), $wkd ) );
	}

	/**
	 * @param array<string,mixed> $recs
	 * @return array<string,mixed>
	 */
	private static function savings_summary( array $recs ): array {
		$dec = VulnHub_AWS_Cost_Store::decisions();
		$sum = static function ( array $list, ?string $status ) use ( $dec ): array {
			$n = 0;
			$t = 0.0;
			foreach ( $list as $r ) {
				$s = (string) ( $dec[ $r['id'] ]['status'] ?? '' );
				if ( null === $status ? '' === $s : $s === $status ) {
					++$n;
					$t += (float) ( $r['saving'] ?? 0 );
				}
			}
			return array( 'count' => $n, 'saving' => round( $t, 2 ) );
		};
		return array(
			'confirmed_open' => $sum( $recs['confirmed'], null ),
			'verify_open'    => $sum( $recs['verify'], null ),
			'accepted'       => $sum( array_merge( $recs['confirmed'], $recs['verify'] ), VulnHub_AWS_Cost_Store::ACCEPTED ),
		);
	}

	/** @return array<string,mixed> */
	public static function savings(): array {
		$meta = self::meta();
		$snap = VulnHub_AWS_Cost_Store::latest();
		if ( ! $snap ) {
			return array( 'meta' => $meta );
		}
		$recs = ( new VulnHub_AWS_Cost_Recs( $snap['data'] ) )->build();
		$dec  = VulnHub_AWS_Cost_Store::decisions();

		// Decisions whose suggestion no longer appears: usually because the
		// change was made. Kept so the plan still adds up.
		$ids  = array_column( array_merge( $recs['confirmed'], $recs['verify'] ), 'id' );
		$gone = array();
		foreach ( $dec as $id => $x ) {
			if ( ! in_array( $id, $ids, true ) ) {
				$gone[] = array( 'id' => $id ) + $x;
			}
		}

		return array(
			'meta'      => $meta,
			'confirmed' => $recs['confirmed'],
			'verify'    => $recs['verify'],
			'context'   => $recs['context'],
			'decisions' => $dec,
			'gone'      => $gone,
		);
	}

	/* ============================================================ export */

	/**
	 * One self-contained HTML file: both screens as tabs, the current data
	 * embedded, the same scripts in offline mode. Nothing is loaded from
	 * anywhere when it is opened, and nothing is written back.
	 */
	public static function export( \WP_REST_Request $req ) {
		$snap = VulnHub_AWS_Cost_Store::latest();
		if ( ! $snap ) {
			return new \WP_Error( 'vh_no_data', __( 'There is no cost data to export yet.', 'vulnhub' ), array( 'status' => 404 ) );
		}
		$view = 'savings' === sanitize_key( (string) $req->get_param( 'view' ) ) ? 'savings' : 'cost';

		$dash = self::dashboard();
		$sav  = self::savings();
		$meta = $dash['meta'];
		// Live-only controls have no meaning in a file.
		$meta['can_refresh']  = false;
		$meta['running']      = false;
		$meta['last_attempt'] = null;
		unset( $meta['auto'], $meta['progress'] );
		$dash['meta'] = $meta;
		$sav['meta']  = $meta;

		$read = static function ( string $f ): string {
			$c = @file_get_contents( VULNHUB_AWS_DIR . 'assets/' . $f ); // phpcs:ignore
			return is_string( $c ) ? $c : '';
		};
		$cfg = array(
			'offline'    => true,
			'canDecide'  => true,
			'canRefresh' => false,
			'savingsUrl' => '#savings',
			'costUrl'    => '#cost',
			'data'       => array( '' => $dash, '/progress' => $meta, '/savings' => $sav ),
		);
		// JSON_HEX_TAG keeps any "</script>" inside the data from closing the tag.
		$json = wp_json_encode( $cfg, JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES );
		$user = wp_get_current_user();
		$now  = wp_date( 'j M Y, H:i T' );
		$site = wp_parse_url( home_url(), PHP_URL_HOST );

		$html  = "<!doctype html>\n<html lang=\"en\" data-theme=\"dark\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n";
		$html .= '<meta name="robots" content="noindex">' . "\n";
		/* translators: %s: date the data was read. */
		$html .= '<title>' . esc_html( sprintf( __( 'AWS cost and savings — %s', 'vulnhub' ), $meta['generated'] ) ) . "</title>\n";
		$html .= '<style>' . $read( 'cost-export.css' ) . "\n" . $read( 'cost.css' ) . "</style>\n</head>\n<body>\n";
		$html .= '<div class="x-shell"><header class="x-head"><div><div class="x-brand">' . esc_html__( 'VulnHub · AWS cost', 'vulnhub' ) . '</div><div class="x-meta">'
			/* translators: 1: when data was read, 2: when exported, 3: user, 4: host. */
			. esc_html( sprintf( __( 'Data read from AWS %1$s · exported %2$s by %3$s from %4$s', 'vulnhub' ), $meta['generated'], $now, $user ? $user->display_name : '', (string) $site ) )
			. '</div></div><nav class="x-tabs" aria-label="' . esc_attr__( 'Sections', 'vulnhub' ) . '"><a href="#cost">' . esc_html__( 'AWS Cost', 'vulnhub' ) . '</a><a href="#savings">' . esc_html__( 'Cost Savings', 'vulnhub' ) . '</a></nav>'
			. '<button type="button" class="vh-btn" id="x-theme">' . esc_html__( 'Light theme', 'vulnhub' ) . '</button></header>';
		$html .= '<main><section id="x-cost"><div class="vh-page-head"><div>' . self::head_html( 'cost' ) . '</div></div><div class="vh-cost" data-vh-cost></div></section>';
		$html .= '<section id="x-savings" hidden><div class="vh-page-head"><div>' . self::head_html( 'savings' ) . '</div></div><div class="vh-cost" data-vh-savings></div></section></main>';
		$html .= '<footer class="x-foot">' . esc_html__( 'A snapshot, not a live view: figures are as AWS reported them when the data was read. Savings are monthly at on-demand list price (730 hours a month). Accept and Drop in this file are a what-if and are not saved anywhere. This file contains account IDs, instance names and IP addresses — share it as you would the VulnHub screens themselves.', 'vulnhub' ) . "</footer></div>\n";
		$html .= '<script>window.VH_AWS_COST = ' . $json . ";</script>\n";
		$html .= "<script>\n( function () {\n\tvar secs = { cost: document.getElementById( 'x-cost' ), savings: document.getElementById( 'x-savings' ) }, tabs = document.querySelectorAll( '.x-tabs a' ), first = true;\n"
			. "\tfunction show() { var k = location.hash.replace( '#', '' ) || '" . $view . "'; if ( ! secs[ k ] ) { k = 'cost'; } Object.keys( secs ).forEach( function ( x ) { secs[ x ].hidden = x !== k; } ); tabs.forEach( function ( a ) { if ( a.getAttribute( 'href' ) === '#' + k ) { a.setAttribute( 'aria-current', 'page' ); } else { a.removeAttribute( 'aria-current' ); } } ); if ( ! first ) { window.scrollTo( 0, 0 ); } first = false; }\n"
			. "\twindow.addEventListener( 'hashchange', show ); show();\n"
			. "\tvar t = document.getElementById( 'x-theme' ), root = document.documentElement;\n"
			. "\tfunction setT( v ) { root.setAttribute( 'data-theme', v ); t.textContent = v === 'dark' ? 'Light theme' : 'Dark theme'; }\n"
			. "\tsetT( window.matchMedia && window.matchMedia( '(prefers-color-scheme: light)' ).matches ? 'light' : 'dark' );\n"
			. "\tt.addEventListener( 'click', function () { setT( root.getAttribute( 'data-theme' ) === 'dark' ? 'light' : 'dark' ); } );\n"
			. "}() );\n</script>\n";
		$html .= '<script>' . $read( 'cost-dashboard.js' ) . "</script>\n";
		$html .= '<script>' . $read( 'cost-savings.js' ) . "</script>\n</body>\n</html>\n";

		if ( class_exists( '\\VulnHub\\Core\\Logger' ) ) {
			( new \VulnHub\Core\Logger() )->audit( 'aws_cost_export', __( 'Exported the AWS cost and savings pages as HTML', 'vulnhub' ), 'aws_cost', (string) $snap['id'], array( 'view' => $view, 'bytes' => strlen( $html ) ) );
		}

		$file = 'vulnhub-aws-cost-' . gmdate( 'Y-m-d', (int) strtotime( $snap['finished_at'] . ' UTC' ) ) . '.html';
		nocache_headers();
		header( 'Content-Type: text/html; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . $file . '"' );
		header( 'X-Content-Type-Options: nosniff' );
		header( 'Content-Length: ' . strlen( $html ) );
		echo $html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		exit;
	}
}
