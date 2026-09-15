<?php
/**
 * The VulnHub widget library for Elementor.
 *
 * @package VulnHub\Elementor
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use Elementor\Controls_Manager;
use VulnHub\Core\Coverage;
use VulnHub\Core\Repo;

/**
 * Registers the category and every widget in it.
 */
final class VulnHub_El_Widgets {

	/**
	 * The panel category slug.
	 *
	 * It lives here rather than on the widget base because
	 * `elementor/elements/categories_registered` fires before anything has
	 * required the base -- referencing the base's constant from the category
	 * callback was a fatal on a cold request.
	 */
	public const CATEGORY = 'vulnhub';

	public static function init(): void {
		add_action( 'elementor/elements/categories_registered', array( __CLASS__, 'category' ) );
		add_action( 'elementor/widgets/register', array( __CLASS__, 'widgets' ) );
		add_action( 'elementor/editor/after_enqueue_styles', array( __CLASS__, 'editor_styles' ) );
	}

	/**
	 * @param \Elementor\Elements_Manager $elements_manager Category registrar.
	 */
	public static function category( $elements_manager ): void {
		$elements_manager->add_category(
			self::CATEGORY,
			array(
				'title' => esc_html__( 'VulnHub', 'vulnhub' ),
				'icon'  => 'eicon-shield-check',
			)
		);
	}

	/**
	 * @param \Elementor\Widgets_Manager $widgets_manager Widget registrar.
	 */
	public static function widgets( $widgets_manager ): void {
		require_once VULNHUB_ELEMENTOR_DIR . 'includes/class-vh-el-widget-base.php';
		require_once VULNHUB_ELEMENTOR_DIR . 'includes/widgets.php';

		foreach (
			array(
				'VulnHub_El_Board',
				'VulnHub_El_Panel',
				'VulnHub_El_Kpi',
				'VulnHub_El_Coverage',
				'VulnHub_El_Coverage_Gaps',
				'VulnHub_El_Devices',
				'VulnHub_El_Teams',
				'VulnHub_El_Findings',
				'VulnHub_El_Nav',
				'VulnHub_El_Account',
				'VulnHub_El_Brand',
				'VulnHub_El_Freshness',
				'VulnHub_El_Theme_Toggle',
				'VulnHub_El_Mode',
			) as $class
		) {
			$widgets_manager->register( new $class() );
		}
	}

	/**
	 * The editor canvas is not the portal, so it does not carry the portal's
	 * theme variables. Without this every VulnHub widget draws with unresolved
	 * `var(--vh-*)` colours and looks broken while it is being laid out.
	 */
	public static function editor_styles(): void {
		// mtime, not the bare plugin version: the editor canvas suffers the same
		// stale-CSS problem as the portal, and app.css belongs to the dashboard
		// plugin, so its directory is the one to stat.
		$app_mtime = @filemtime( VULNHUB_DASH_DIR . 'assets/app.css' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		$app_ver   = $app_mtime ? VULNHUB_DASH_VERSION . '.' . $app_mtime : VULNHUB_DASH_VERSION;

		wp_enqueue_style( 'vulnhub-app', VULNHUB_DASH_URL . 'assets/app.css', array(), $app_ver );
	}

	/* =================================================================
	 * Shared option lists, so a control and its renderer never drift.
	 * ============================================================== */

	/** @return array<string,string> */
	public static function panel_options(): array {
		$out    = array();
		$groups = VulnHub_Dash_Widgets::groups();

		foreach ( VulnHub_Dash_Widgets::all() as $id => $def ) {
			$group        = (string) ( $groups[ $def['group'] ] ?? $def['group'] );
			$out[ $id ]   = $group . ' — ' . (string) $def['label'];
		}

		asort( $out );
		return $out;
	}

	/** @return array<string,string> */
	public static function dimension_options(): array {
		$out = array();

		foreach ( Coverage::dimensions() as $key => $def ) {
			$out[ $key ] = (string) $def['label'];
		}
		return $out;
	}

	/** @return array<string,string> */
	public static function metric_options(): array {
		return array(
			'critical'         => __( 'Critical findings open', 'vulnhub' ),
			'high'             => __( 'High findings open', 'vulnhub' ),
			'medium'           => __( 'Medium findings open', 'vulnhub' ),
			'low'              => __( 'Low findings open', 'vulnhub' ),
			'open_total'       => __( 'All open findings', 'vulnhub' ),
			'overdue'          => __( 'Past their SLA', 'vulnhub' ),
			'assets_total'     => __( 'Assets in the estate', 'vulnhub' ),
			'assets_at_risk'   => __( 'Assets carrying critical or high', 'vulnhub' ),
			'assets_unowned'   => __( 'Assets with no owner', 'vulnhub' ),
			'users_missing'    => __( 'User devices with no user', 'vulnhub' ),
			'not_in_service'   => __( 'Assets not in service', 'vulnhub' ),
			'fixed_30d'        => __( 'Fixed in the last 30 days', 'vulnhub' ),
			'excepted'         => __( 'Findings under an exception', 'vulnhub' ),
			'tickets_open'     => __( 'Open remediation tickets', 'vulnhub' ),
			'tickets_done'     => __( 'Closed remediation tickets', 'vulnhub' ),
			'awaiting_verify'  => __( 'Closures awaiting verification', 'vulnhub' ),
			'verify_failed'    => __( 'Closures that failed verification', 'vulnhub' ),
			'exceptions_open'  => __( 'Exception requests pending', 'vulnhub' ),
			'exceptions_active' => __( 'Exceptions in force', 'vulnhub' ),
			'coverage_percent' => __( 'Tenable scanning coverage %', 'vulnhub' ),
			'coverage_gaps'    => __( 'Assets with no Tenable cover', 'vulnhub' ),
		);
	}

	/**
	 * Resolve one metric to a tile-ready value. Coverage lives in its own
	 * class rather than in `Repo::summary()`, hence the two special cases.
	 *
	 * @return array{value:string|int|float,tone:string}
	 */
	public static function metric_value( string $key ): array {
		if ( 'coverage_percent' === $key ) {
			$summary = Coverage::summary();
			$pct     = (float) $summary['percent'];
			return array(
				'value' => number_format_i18n( $pct, 1 ) . '%',
				'tone'  => $pct >= 95 ? 'good' : ( $pct >= 80 ? 'warning' : 'critical' ),
			);
		}
		if ( 'coverage_gaps' === $key ) {
			$summary = Coverage::summary();
			return array(
				'value' => (int) $summary['gaps'],
				'tone'  => $summary['gaps'] > 0 ? 'warning' : 'good',
			);
		}

		$summary = Repo::summary();
		$value   = (int) ( $summary[ $key ] ?? 0 );

		$critical = array( 'critical', 'overdue', 'verify_failed' );
		$serious  = array( 'high', 'users_missing' );
		$warning  = array( 'assets_unowned', 'awaiting_verify', 'exceptions_open' );
		$good     = array( 'fixed_30d', 'tickets_done' );

		$tone = 'neutral';
		if ( in_array( $key, $critical, true ) && $value > 0 ) {
			$tone = 'critical';
		} elseif ( in_array( $key, $serious, true ) && $value > 0 ) {
			$tone = 'serious';
		} elseif ( in_array( $key, $warning, true ) && $value > 0 ) {
			$tone = 'warning';
		} elseif ( in_array( $key, $good, true ) ) {
			$tone = 'good';
		}

		return array(
			'value' => $value,
			'tone'  => $tone,
		);
	}
}

