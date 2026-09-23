<?php
/**
 * The Cloud Network map: the raw AWS dataflow graph, per account and VPC.
 *
 * Reads the captured graph (security groups, their rules, the instances that
 * belong to them) and draws it: sources on the left (internet and external
 * CIDRs), the security groups they reach, and the internal groups behind them,
 * with every edge labelled by the ports it opens.
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_AWS_Network_Page {

	public const VIEW = 'network';
	public const SLUG = 'cloud-network';

	public static function init(): void {
		add_filter( 'vulnhub_dash_views', array( __CLASS__, 'register_view' ) );
		add_action( 'vulnhub_dash_render_view_' . self::VIEW, array( __CLASS__, 'render' ) );
		add_action( 'init', array( __CLASS__, 'ensure_page' ), 20 );
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'assets' ), 20 );
	}

	/**
	 * @param array<string,array<string,mixed>> $views Existing views.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_view( array $views ): array {
		$out = array();

		foreach ( $views as $key => $def ) {
			$out[ $key ] = $def;

			if ( 'assets' === $key ) {
				$out[ self::VIEW ] = array(
					'title' => __( 'Cloud Network', 'vulnhub' ),
					'slug'  => self::SLUG,
					'menu'  => __( 'Cloud Network', 'vulnhub' ),
					'icon'  => 'M5 12h14M12 5v14M7 7l10 10M17 7L7 17',
				);
			}
		}

		return $out;
	}

	public static function ensure_page(): void {
		$map = (array) get_option( 'vulnhub_dash_pages', array() );

		if ( ! empty( $map[ self::VIEW ] ) ) {
			$e = get_post( (int) $map[ self::VIEW ] );
			if ( $e && 'trash' !== $e->post_status ) {
				return;
			}
		}

		$page = get_page_by_path( self::SLUG );

		$id = $page ? (int) $page->ID : wp_insert_post(
			array(
				'post_title'     => __( 'Cloud Network', 'vulnhub' ),
				'post_name'      => self::SLUG,
				'post_content'   => '<!-- wp:shortcode -->[vulnhub_app view="' . self::VIEW . '"]<!-- /wp:shortcode -->',
				'post_status'    => 'publish',
				'post_type'      => 'page',
				'comment_status' => 'closed',
				'ping_status'    => 'closed',
			)
		);

		if ( ! is_wp_error( $id ) && $id ) {
			$map[ self::VIEW ] = (int) $id;
			update_option( 'vulnhub_dash_pages', $map, false );
		}
	}

	public static function assets(): void {
		if ( ! is_singular() || ! class_exists( 'VulnHub_Dash_App' ) ) {
			return;
		}
		if ( self::VIEW !== VulnHub_Dash_App::view_for_post( get_post() ) ) {
			return;
		}

		$cssv  = @filemtime( VULNHUB_AWS_DIR . 'assets/network.css' ); // phpcs:ignore
		$jsv   = @filemtime( VULNHUB_AWS_DIR . 'assets/network.js' ); // phpcs:ignore
		$topov = @filemtime( VULNHUB_AWS_DIR . 'assets/topology.js' ); // phpcs:ignore

		wp_enqueue_style( 'vulnhub-aws-network', VULNHUB_AWS_URL . 'assets/network.css', array( 'vulnhub-app' ), $cssv ?: VULNHUB_AWS_VERSION );
		wp_enqueue_script( 'vulnhub-aws-network', VULNHUB_AWS_URL . 'assets/network.js', array(), $jsv ?: VULNHUB_AWS_VERSION, true );
		wp_localize_script(
			'vulnhub-aws-network',
			'VH_AWS_NETWORK',
			array(
				'rest'     => esc_url_raw( rest_url( 'vulnhub-aws/v1/network' ) ),
				'nonce'    => wp_create_nonce( 'wp_rest' ),
				'accounts' => VulnHub_AWS_Network::accounts(),
			)
		);

		wp_enqueue_script( 'vulnhub-aws-topology', VULNHUB_AWS_URL . 'assets/topology.js', array(), $topov ?: VULNHUB_AWS_VERSION, true );
		wp_localize_script(
			'vulnhub-aws-topology',
			'VH_AWS_TOPOLOGY',
			array(
				'rest'  => esc_url_raw( rest_url( 'vulnhub-aws/v1/topology' ) ),
				'nonce' => wp_create_nonce( 'wp_rest' ),
			)
		);
	}

	/** Which tab the request is on. `estate` or `account`. */
	private static function tab(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return isset( $_GET['tab'] ) && 'estate' === sanitize_key( (string) wp_unslash( $_GET['tab'] ) ) ? 'estate' : 'account';
	}

	public static function render(): void {
		$tab = self::tab();

		echo '<div class="vh-page-head"><div>';
		echo '<h1>' . esc_html__( 'Cloud Network', 'vulnhub' ) . ' <span class="vh-chip vh-chip--info">' . esc_html__( 'AWS · live from your SSO login', 'vulnhub' ) . '</span></h1>';
		echo '<p class="vh-sub">' . esc_html(
			'estate' === $tab
				? __( 'Every account at once, as a flowchart: where traffic goes along the top, what stands in its path below that, and the workloads beneath. Each lane is a default route read from the VPC\'s own route tables — an inspection appliance, the transit gateway to on-premises, an internet gateway, a NAT gateway — not from what anything is named. Production and non-production are drawn separately.', 'vulnhub' )
				: __( 'A live topology of one account: the internet and its routing at the top, then what is internet-facing, the compute behind it, and the data it reaches. Real resources with their names, IPs and states — click any one for its configuration, Defender health and Tenable / Plerion findings.', 'vulnhub' )
		) . '</p>';
		echo '</div></div>';

		$base = remove_query_arg( array( 'tab' ) );
		echo '<div class="vh-tabs" role="tablist">';
		printf(
			'<a class="vh-tabs__tab %s" href="%s">%s</a>',
			'account' === $tab ? 'is-active' : '',
			esc_url( $base ),
			esc_html__( 'One account', 'vulnhub' )
		);
		printf(
			'<a class="vh-tabs__tab %s" href="%s">%s</a>',
			'estate' === $tab ? 'is-active' : '',
			esc_url( add_query_arg( 'tab', 'estate', $base ) ),
			esc_html__( 'Whole estate', 'vulnhub' )
		);
		echo '</div>';

		if ( 'estate' === $tab ) {
			self::render_estate();
			return;
		}

		echo '<div class="vh-net-controls">';
		echo '<label>' . esc_html__( 'Account', 'vulnhub' ) . ' <select data-vh-net-account></select></label>';
		echo '<label>' . esc_html__( 'VPC', 'vulnhub' ) . ' <select data-vh-net-vpc></select></label>';
		echo '<span class="vh-meta" data-vh-net-meta></span>';
		echo '</div>';

		echo '<div class="vh-net-legend">';
		echo '<span><i class="vh-net-dot" style="background:#38bdf8"></i>' . esc_html__( 'Internet', 'vulnhub' ) . '</span>';
		echo '<span><i class="vh-net-dot" style="background:#f87171"></i>' . esc_html__( 'IGW · direct', 'vulnhub' ) . '</span>';
		echo '<span><i class="vh-net-dot" style="background:#34d399"></i>' . esc_html__( 'Check Point inspected', 'vulnhub' ) . '</span>';
		echo '<span><i class="vh-net-dot" style="background:#a78bfa"></i>' . esc_html__( 'Transit Gateway (hub)', 'vulnhub' ) . '</span>';
		echo '<span><i class="vh-net-dot" style="background:#fb923c"></i>' . esc_html__( 'EC2 / Lambda', 'vulnhub' ) . '</span>';
		echo '<span><i class="vh-net-dot" style="background:#fbbf24"></i>' . esc_html__( 'Entry / exposed', 'vulnhub' ) . '</span>';
		echo '<span><i class="vh-net-dot" style="background:#34d399"></i>' . esc_html__( 'Data (S3 / RDS)', 'vulnhub' ) . '</span>';
		echo '</div>';

		echo '<div class="vh-net-map" data-vh-net-map role="img" aria-label="' . esc_attr__( 'AWS network dataflow diagram', 'vulnhub' ) . '"></div>';
	}

	/**
	 * The estate flowchart.
	 *
	 * Four bands stacked top to bottom -- where traffic goes, what stands in
	 * the path, the workloads, and their data -- with a lane per route out.
	 * Reading upwards from a workload gives you its exit; reading down from
	 * the internet gives you everything reachable that way.
	 *
	 * Production and non-production are drawn separately because they are
	 * different conversations: one is a live risk register, the other is
	 * mostly a housekeeping list, and averaging them hides both.
	 */
	private static function render_estate(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$env = isset( $_GET['env'] ) ? sanitize_key( (string) wp_unslash( $_GET['env'] ) ) : '';
		$env = in_array( $env, array( VulnHub_AWS_Environment::PROD, VulnHub_AWS_Environment::NONPROD ), true ) ? $env : '';

		$base = remove_query_arg( array( 'env' ) );

		echo '<div class="vh-estate-bar">';
		echo '<div class="vh-segbar" role="tablist">';

		foreach ( array(
			''                              => __( 'Whole estate', 'vulnhub' ),
			VulnHub_AWS_Environment::PROD    => __( 'Production', 'vulnhub' ),
			VulnHub_AWS_Environment::NONPROD => __( 'Non-production', 'vulnhub' ),
		) as $vh_k => $vh_label ) {
			printf(
				'<a class="vh-seg%s" href="%s"%s>%s</a>',
				$env === (string) $vh_k ? ' is-active' : '',
				esc_url( '' === $vh_k ? $base : add_query_arg( 'env', $vh_k, $base ) ),
				$env === (string) $vh_k ? ' aria-current="true"' : '',
				esc_html( $vh_label )
			);
		}

		echo '</div>';
		echo '<div class="vh-estate-stats" data-vh-estate-stats></div>';
		echo '</div>';

		echo '<p class="vh-sub vh-muted vh-estate-hint">' . esc_html__( 'Click any box to trace the whole path through it — everything above and below it lights up, and everything else dims. Click it again, or press Escape, to clear.', 'vulnhub' ) . '</p>';

		echo '<div class="vh-estate" data-vh-estate data-vh-env="' . esc_attr( $env ) . '">';
		echo '<p class="vh-sub vh-muted" data-vh-estate-loading>' . esc_html__( 'Reading the estate…', 'vulnhub' ) . '</p>';
		echo '</div>';

		echo '<p class="vh-sub vh-muted">' . esc_html__(
			'Every lane is a default route read from the VPC\'s own route tables, not from what anything is called. A VPC with both a public and a private subnet has two routes out, so it counts in two lanes — the totals above are lane memberships, not distinct VPCs. Route tables decide the shape and are not drawn.',
			'vulnhub'
		) . '</p>';
	}
}
