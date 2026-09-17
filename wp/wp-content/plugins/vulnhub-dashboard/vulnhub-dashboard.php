<?php
/**
 * Plugin Name:       VulnHub Dashboard
 * Plugin URI:        https://github.com/arshdeepromy/vulnhub
 * Description:       The front-end application for VulnHub — dashboards, vulnerability triage, asset ownership, ticket tracking and the exception register, served as a theme-independent app shell at your own domain.
 * Version:           1.0.0
 * Requires at least: 6.5
 * Requires PHP:      8.1
 * Author:            Romy Sidhu
 * License:           GPL-2.0-or-later
 * Text Domain:       vulnhub
 *
 * @package VulnHub\Dashboard
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'VULNHUB_DASH_VERSION', '1.25.0' );
define( 'VULNHUB_DASH_DIR', plugin_dir_path( __FILE__ ) );
define( 'VULNHUB_DASH_URL', plugin_dir_url( __FILE__ ) );

require_once VULNHUB_DASH_DIR . 'includes/class-vh-dash-charts.php';
require_once VULNHUB_DASH_DIR . 'includes/class-vh-dash-app.php';
require_once VULNHUB_DASH_DIR . 'includes/class-vh-dash-portal.php';
require_once VULNHUB_DASH_DIR . 'includes/class-vh-dash-patching.php';
require_once VULNHUB_DASH_DIR . 'includes/class-vh-dash-action.php';
require_once VULNHUB_DASH_DIR . 'includes/class-vh-dash-eol.php';
require_once VULNHUB_DASH_DIR . 'includes/class-vh-dash-widgets.php';
require_once VULNHUB_DASH_DIR . 'includes/class-vh-product-icons.php';
require_once VULNHUB_DASH_DIR . 'includes/class-vh-dash-export.php';
require_once VULNHUB_DASH_DIR . 'includes/class-vh-dash-tickets.php';
require_once VULNHUB_DASH_DIR . 'includes/class-vh-dash-ticket-report.php';
VulnHub_Dash_Ticket_Report::hooks();
require_once VULNHUB_DASH_DIR . 'includes/class-vh-dash-sources.php';

/**
 * Core is loaded after us (plugins load alphabetically: dashboard < core), so
 * never test for it at file scope — check on `plugins_loaded` instead.
 */
add_action(
	'plugins_loaded',
	static function (): void {
		if ( ! function_exists( 'vulnhub' ) ) {
			add_action(
				'admin_notices',
				static function (): void {
					if ( current_user_can( 'activate_plugins' ) ) {
						printf(
							'<div class="notice notice-error"><p><strong>%s</strong> %s</p></div>',
							esc_html__( 'VulnHub Dashboard:', 'vulnhub' ),
							esc_html__( 'VulnHub Core must be active to serve the front-end application.', 'vulnhub' )
						);
					}
				}
			);
			return;
		}

		VulnHub_Dash_App::init();
		VulnHub_Dash_Portal::init();
		VulnHub_Dash_Export::init();
		VulnHub_Dash_Tickets::init();
		VulnHub_Dash_Sources::init();
	},
	20
);

/**
 * Anything that can move the numbers invalidates every cached widget.
 */
/**
 * A finished sync invalidates only the widgets fed by what it moved.
 *
 * The action passes the connector id, and connector_sources() maps it to the
 * data a sync of that connector can change -- so a Defender run no longer
 * throws away the Tenable widgets. An unknown connector still invalidates
 * everything, because an unmapped blast radius is an unbounded one.
 */
add_action( 'vulnhub_sync_complete', array( 'VulnHub_Dash_Widgets', 'bust_for_connector' ), 99, 1 );

/*
 * These two mean "anything may have moved". Registered with no arguments on
 * purpose: vulnhub_import_complete passes the import type first, and bust()
 * would take that as a source name, tick a key no widget reads, and bust
 * nothing.
 */
foreach ( array( 'vulnhub_import_complete', 'vulnhub_coverage_recalculated' ) as $vulnhub_dash_bust ) {
	add_action( $vulnhub_dash_bust, array( 'VulnHub_Dash_Widgets', 'bust' ), 99, 0 );
}

/*
 * ...and then rebuild the board on cron rather than in front of whoever opens
 * the dashboard next. Serve-stale already means nobody waits; this means
 * nobody looks at stale numbers for long either.
 */
foreach ( array( 'vulnhub_sync_complete', 'vulnhub_import_complete', 'vulnhub_coverage_recalculated' ) as $vulnhub_dash_warm ) {
	add_action( $vulnhub_dash_warm, array( 'VulnHub_Dash_Widgets', 'queue_warm' ), 100 );
}

/**
 * Re-render one widget in the background, queued by a stale cache read.
 *
 * Two arguments: the widget id and the host its links must be built for.
 */
add_action( VulnHub_Dash_Widgets::HOOK_REFRESH, array( 'VulnHub_Dash_Widgets', 'refresh' ), 10, 2 );

/**
 * Re-render the whole board in the background, queued after a bust.
 */
add_action( VulnHub_Dash_Widgets::HOOK_WARM, array( 'VulnHub_Dash_Widgets', 'warm' ) );

/**
 * A safety net, in case a bust is ever missed or a warm dies half way.
 *
 * Hourly, and cheap when there is nothing to do: every widget it re-renders
 * would have been re-rendered by the next reader anyway.
 */
add_action(
	'vulnhub_loaded',
	static function (): void {
		if ( ! wp_next_scheduled( 'vulnhub_widget_warm_cron' ) ) {
			wp_schedule_event( time() + wp_rand( 60, 600 ), 'hourly', 'vulnhub_widget_warm_cron' );
		}
	},
	30
);
add_action( 'vulnhub_widget_warm_cron', array( 'VulnHub_Dash_Widgets', 'warm' ) );

/**
 * Save a person's dashboard arrangement.
 *
 * Posted to admin-post.php like every other form in the product, so the
 * portal's own redirect filter carries the operator back to the dashboard
 * rather than dropping them in wp-admin.
 */
add_action(
	'admin_post_vulnhub_save_layout',
	static function (): void {
		if ( ! is_user_logged_in() || ! current_user_can( \VulnHub\Core\Caps::VIEW ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}

		check_admin_referer( 'vulnhub_save_layout' );

		$back = VulnHub_Dash_Portal::portal_url( 'dashboard' );

		if ( ! empty( $_POST['reset'] ) ) {
			VulnHub_Dash_Widgets::reset_layout();
			wp_safe_redirect( add_query_arg( 'vh_layout', 'reset', $back ) );
			exit;
		}

		$raw = isset( $_POST['layout'] ) ? sanitize_text_field( wp_unslash( $_POST['layout'] ) ) : '';
		$in  = json_decode( $raw, true );

		VulnHub_Dash_Widgets::save_layout( is_array( $in ) ? $in : array() );

		wp_safe_redirect( add_query_arg( 'vh_layout', 'saved', $back ) );
		exit;
	}
);

/**
 * Save an arrangement without reloading the page.
 *
 * The Customise form still posts to admin-post.php and still works with
 * JavaScript off. This is for the other way in: dragging a widget on the board
 * itself, where a full page round trip after every nudge would make
 * rearranging unusable. Same capability, same sanitiser, same storage -- only
 * the transport differs.
 */
add_action(
	'rest_api_init',
	static function (): void {
		register_rest_route(
			'vulnhub-dashboard/v1',
			'/layout',
			array(
				'methods'             => 'POST',
				'callback'            => static function ( WP_REST_Request $request ) {
					$raw = $request->get_param( 'layout' );

					if ( ! is_array( $raw ) ) {
						return new WP_Error(
							'vulnhub_layout_invalid',
							__( 'That is not a layout.', 'vulnhub' ),
							array( 'status' => 400 )
						);
					}

					// sanitise_layout() drops unknown ids and snaps widths to
					// the allowed set, so an edited request cannot store a
					// widget this person cannot see or a width the grid has
					// no column count for.
					VulnHub_Dash_Widgets::save_layout( $raw );

					$saved = VulnHub_Dash_Widgets::layout();

					return rest_ensure_response(
						array(
							'saved'  => true,
							'layout' => $saved,
							'count'  => count( $saved ),
						)
					);
				},
				'permission_callback' => static function (): bool {
					// A layout is stored against the person, so holding the
					// portal's view capability is exactly the right bar --
					// there is nobody else's arrangement to reach.
					return is_user_logged_in() && current_user_can( \VulnHub\Core\Caps::VIEW );
				},
				'args'                => array(
					'layout' => array(
						'required' => true,
						'type'     => 'array',
					),
				),
			)
		);

		register_rest_route(
			'vulnhub-dashboard/v1',
			'/vendor-drill',
			array(
				'methods'             => 'GET',
				'callback'            => static function ( WP_REST_Request $request ) {
					$slug   = sanitize_key( (string) $request->get_param( 'vendor' ) );
					$metric = sanitize_key( (string) $request->get_param( 'metric' ) );
					$q      = sanitize_text_field( (string) $request->get_param( 'q' ) );
					$sev    = sanitize_key( (string) $request->get_param( 'severity' ) );
					$page   = max( 1, (int) $request->get_param( 'page' ) );

					if ( '' === $slug || ! VH_Vendor::known( $slug ) ) {
						return new WP_Error( 'vulnhub_vendor_unknown', __( 'Unknown vendor.', 'vulnhub' ), array( 'status' => 404 ) );
					}
					if ( ! in_array( $metric, array( 'assets', 'uncovered', 'archived', 'products', 'findings', 'critical' ), true ) ) {
						$metric = 'assets';
					}

					$per = 25;
					$res = VH_Vendor::drill( $slug, $metric, array( 'page' => $page, 'per' => $per, 'q' => $q, 'severity' => $sev ) );

					if ( 'products' === $metric ) {
						$view = 'vendor_products';
						$args = array( 'vendor' => $slug, 'q' => $q );
					} elseif ( in_array( $metric, array( 'findings', 'critical' ), true ) ) {
						$view = 'vendor_findings';
						$args = array( 'vendor' => $slug, 'q' => $q, 'severity' => ( 'critical' === $metric && '' === $sev ) ? 'critical' : $sev );
					} else {
						$view = 'vendor_assets';
						$args = array( 'vendor' => $slug, 'metric' => $metric, 'q' => $q );
					}

					$reg = VH_Vendor::registry()[ $slug ] ?? array();

					return rest_ensure_response(
						array(
							'vendor'     => (string) ( $reg['name'] ?? $slug ),
							'metric'     => $metric,
							'title'      => (string) $res['title'],
							'columns'    => $res['columns'],
							'rows'       => $res['rows'],
							'total'      => (int) $res['total'],
							'page'       => (int) $res['page'],
							'per'        => (int) $res['per'],
							'pages'      => (int) max( 1, (int) ceil( $res['total'] / max( 1, $per ) ) ),
							'severity'   => $sev,
							'q'          => $q,
							'export_url' => VulnHub_Dash_Export::url( $view, $args ),
						)
					);
				},
				'permission_callback' => static function (): bool {
					return is_user_logged_in() && current_user_can( \VulnHub\Core\Caps::VIEW );
				},
			)
		);

		/*
		 * Infinite scroll for the findings table: a real GET request, so
		 * $_GET is populated identically to a normal page load and
		 * VulnHub_Dash_App::findings_base_args() reads the exact same
		 * filters the visible first page was rendered with -- there is no
		 * separate filter-parsing path to drift out of sync.
		 */
		register_rest_route(
			'vulnhub-dashboard/v1',
			'/findings-more',
			array(
				'methods'             => 'GET',
				'callback'            => static function ( WP_REST_Request $request ) {
					$per    = 25;
					$offset = max( 0, (int) $request->get_param( 'offset' ) );

					$scope = VulnHub_Dash_App::findings_validated_scope();
					$args  = array_merge(
						VulnHub_Dash_App::findings_base_args( $scope['orderby'], $scope['order'], $scope['lifecycle'] ),
						array( 'limit' => $per, 'offset' => $offset )
					);

					$q     = \VulnHub\Core\Repo::findings( array_filter( $args, static fn( $v ): bool => '' !== $v && 0 !== $v ) );
					$total = (int) $q['total'];

					$html = '';
					foreach ( $q['rows'] as $row ) {
						$html .= VulnHub_Dash_App::finding_row_html( $row );
					}

					return rest_ensure_response(
						array(
							'html'   => $html,
							'count'  => count( $q['rows'] ),
							'offset' => $offset + count( $q['rows'] ),
							'total'  => $total,
						)
					);
				},
				'permission_callback' => static function (): bool {
					return is_user_logged_in() && current_user_can( \VulnHub\Core\Caps::VIEW );
				},
			)
		);

		register_rest_route(
			'vulnhub-dashboard/v1',
			'/assets-more',
			array(
				'methods'             => 'GET',
				'callback'            => static function ( WP_REST_Request $request ) {
					$per    = 25;
					$offset = max( 0, (int) $request->get_param( 'offset' ) );

					$scope       = VulnHub_Dash_App::assets_validated_scope();
					$vh_can_edit = current_user_can( \VulnHub\Core\Caps::TRIAGE );

					$args = array_merge(
						VulnHub_Dash_App::assets_base_args( $scope['scope'], $scope['source'], $scope['orderby'], $scope['order'] ),
						array( 'limit' => $per, 'offset' => $offset )
					);

					$q     = \VulnHub\Core\Repo::assets( array_filter( $args, static fn( $v ): bool => '' !== $v && 0 !== $v ) );
					$total = (int) $q['total'];

					$html = '';
					foreach ( $q['rows'] as $row ) {
						$html .= VulnHub_Dash_App::asset_row_html( $row, $vh_can_edit );
					}

					return rest_ensure_response(
						array(
							'html'   => $html,
							'count'  => count( $q['rows'] ),
							'offset' => $offset + count( $q['rows'] ),
							'total'  => $total,
						)
					);
				},
				'permission_callback' => static function (): bool {
					return is_user_logged_in() && current_user_can( \VulnHub\Core\Caps::VIEW );
				},
			)
		);

		/*
		 * Affected-asset list for one vulnerability, for the expandable rows
		 * on the "Vulnerability on assets" tab. A real GET so $_GET carries
		 * the same filters the tab was rendered with, and the rendering lives
		 * in VulnHub_Dash_App so the fragment matches the rest of the portal.
		 */
		register_rest_route(
			'vulnhub-dashboard/v1',
			'/vuln-assets',
			array(
				'methods'             => 'GET',
				'callback'            => static function ( WP_REST_Request $request ) {
					$vuln = max( 0, (int) $request->get_param( 'vuln' ) );

					return rest_ensure_response(
						array(
							'html' => VulnHub_Dash_App::vuln_assets_fragment( $vuln ),
						)
					);
				},
				'permission_callback' => static function (): bool {
					return is_user_logged_in() && current_user_can( \VulnHub\Core\Caps::VIEW );
				},
			)
		);

		/*
		 * Live sync status for the connector cards' progress bar: where the
		 * running import is, how fast, a rough ETA, or the failure if it has
		 * stopped. Cheap enough to poll every few seconds; it also reaps a run
		 * that was killed mid-import and left claiming to be running.
		 */
		/*
		 * Outdated-asset list for one product, for the "By product" tab's
		 * expandable rows: what one update fixes, and where.
		 */
		register_rest_route(
			'vulnhub-dashboard/v1',
			'/product-assets',
			array(
				'methods'             => 'GET',
				'callback'            => static function ( WP_REST_Request $request ) {
					$slug = sanitize_title( (string) $request->get_param( 'product' ) );

					return rest_ensure_response(
						array(
							'html' => VulnHub_Dash_App::product_assets_fragment( $slug ),
						)
					);
				},
				'permission_callback' => static function (): bool {
					return is_user_logged_in() && current_user_can( \VulnHub\Core\Caps::VIEW );
				},
			)
		);

		register_rest_route(
			'vulnhub-dashboard/v1',
			'/sync-status',
			array(
				'methods'             => 'GET',
				'callback'            => static function ( WP_REST_Request $request ) {
					$connector = sanitize_key( (string) $request->get_param( 'connector' ) );

					if ( '' === $connector ) {
						return new WP_Error( 'vulnhub_no_connector', __( 'No connector given.', 'vulnhub' ), array( 'status' => 400 ) );
					}

					return rest_ensure_response( vulnhub()->logger->sync_status( $connector ) );
				},
				'permission_callback' => static function (): bool {
					return is_user_logged_in() && current_user_can( \VulnHub\Core\Caps::VIEW );
				},
			)
		);

		register_rest_route(
			'vulnhub-dashboard/v1',
			'/layout/reset',
			array(
				'methods'             => 'POST',
				'callback'            => static function () {
					VulnHub_Dash_Widgets::reset_layout();

					return rest_ensure_response(
						array(
							'saved'  => true,
							'layout' => VulnHub_Dash_Widgets::layout(),
						)
					);
				},
				'permission_callback' => static function (): bool {
					return is_user_logged_in() && current_user_can( \VulnHub\Core\Caps::VIEW );
				},
			)
		);
	}
);

/**
 * Move assets in or out of service from the portal.
 *
 * Decommissioning is the one destructive-feeling thing a portal user can do,
 * so it is gated on TRIAGE rather than VIEW, it is nonce-checked, and it is
 * reversible: `Lifecycle` archives findings rather than deleting them and
 * remembers what each one was, so "Return to service" puts the asset back
 * exactly as it stood.
 */
add_action(
	'admin_post_vulnhub_set_lifecycle',
	static function (): void {
		if ( ! is_user_logged_in() || ! current_user_can( \VulnHub\Core\Caps::TRIAGE ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}

		check_admin_referer( 'vulnhub_set_lifecycle' );

		// The two headline buttons post `lifecycle`; the "another status"
		// dropdown has its own field so an empty select cannot cancel them.
		$status = isset( $_POST['lifecycle'] ) ? sanitize_key( wp_unslash( $_POST['lifecycle'] ) ) : '';

		if ( '' === $status && isset( $_POST['lifecycle_other'] ) ) {
			$status = sanitize_key( wp_unslash( $_POST['lifecycle_other'] ) );
		}
		$raw    = isset( $_POST['assets'] ) ? (array) wp_unslash( $_POST['assets'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$ids    = array_values( array_filter( array_map( 'intval', $raw ) ) );

		/*
		 * Come back to the list the operator was looking at, filters and all.
		 * Decommissioning is usually done in a run down a filtered list, and
		 * losing the filter after every click makes a 100-row cleanup
		 * unbearable.
		 */
		$back = isset( $_POST['back'] ) ? esc_url_raw( wp_unslash( $_POST['back'] ) ) : '';
		$back = $back && str_starts_with( $back, home_url() ) ? $back : VulnHub_Dash_Portal::portal_url( 'assets' );

		if ( ! $ids || ! isset( vh_lifecycle_statuses()[ $status ] ) ) {
			wp_safe_redirect( add_query_arg( 'vh_life', 'none', $back ) );
			exit;
		}

		$result = \VulnHub\Core\Lifecycle::set( $ids, $status );

		VulnHub_Dash_Widgets::bust();

		wp_safe_redirect(
			add_query_arg(
				array(
					'vh_life'     => $result['status'],
					'vh_assets'   => (int) $result['assets'],
					'vh_archived' => (int) $result['archived'],
					'vh_restored' => (int) $result['restored'],
				),
				$back
			)
		);
		exit;
	}
);

/**
 * Stream one widget's underlying rows as CSV.
 *
 * The same rows the picture was drawn from, so the spreadsheet and the chart
 * can never disagree.
 */
add_action(
	'admin_post_vulnhub_widget_csv',
	static function (): void {
		if ( ! is_user_logged_in() || ! current_user_can( \VulnHub\Core\Caps::VIEW ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}

		$id = isset( $_GET['widget'] ) ? sanitize_key( wp_unslash( $_GET['widget'] ) ) : '';

		check_admin_referer( 'vulnhub_widget_csv_' . $id );

		$data = VulnHub_Dash_Widgets::export_data( $id );

		if ( ! $data ) {
			wp_die( esc_html__( 'That widget has nothing to export.', 'vulnhub' ), '', array( 'response' => 404 ) );
		}

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="vulnhub-' . $id . '-' . wp_date( 'Y-m-d' ) . '.csv"' );

		$out = fopen( 'php://output', 'w' );
		fputcsv( $out, $data['headers'] );

		foreach ( $data['rows'] as $row ) {
			fputcsv( $out, (array) $row );
		}

		fclose( $out );
		exit;
	}
);

/**
 * The front-end views, in menu order.
 *
 * @return array<string,array{title:string,slug:string,menu:string,icon:string}>
 */
function vulnhub_dash_views(): array {
	$views = array(
		'dashboard'       => array(
			'title' => __( 'Security dashboard', 'vulnhub' ),
			'slug'  => 'vulnhub',
			'menu'  => __( 'Dashboard', 'vulnhub' ),
			'icon'  => 'M4 4h6v6H4zM14 4h6v4h-6zM4 14h6v6H4zM14 12h6v8h-6z',
		),
		'vulnerabilities' => array(
			'title' => __( 'Vulnerabilities', 'vulnhub' ),
			'slug'  => 'vulnerabilities',
			'menu'  => __( 'Vulnerabilities', 'vulnhub' ),
			'icon'  => 'M12 2l9 4v6c0 5-3.8 9.3-9 10-5.2-.7-9-5-9-10V6zM12 8v5M12 16v.5',
		),
		'assets'          => array(
			'title' => __( 'Assets &amp; owners', 'vulnhub' ),
			'slug'  => 'assets',
			'menu'  => __( 'Assets', 'vulnhub' ),
			'icon'  => 'M4 5h16v5H4zM4 14h16v5H4zM7 7.5h.01M7 16.5h.01M11 7.5h4M11 16.5h4',
		),
		'tickets'         => array(
			'title' => __( 'Remediation tickets', 'vulnhub' ),
			'slug'  => 'tickets',
			'menu'  => __( 'Tickets', 'vulnhub' ),
			'icon'  => 'M4 6h16v4a2 2 0 000 4v4H4v-4a2 2 0 000-4z',
		),
		'exceptions'      => array(
			'title' => __( 'Exception register', 'vulnhub' ),
			'slug'  => 'exceptions',
			'menu'  => __( 'Exceptions', 'vulnhub' ),
			'icon'  => 'M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h12a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 3h6v4H9zM9 14l2 2 4-4',
		),
		// Reached from the "View all" control on the dashboard's
		// Exposure-by-product widget, not from the primary navigation.
		'products'        => array(
			'title'  => __( 'Exposure by product', 'vulnhub' ),
			'slug'   => 'products',
			'menu'   => __( 'Products', 'vulnhub' ),
			'icon'   => 'M3 7l9-4 9 4-9 4-9-4zM3 7v10l9 4 9-4V7M12 11v10',
			'hidden' => true,
		),
		'vendors'         => array(
			'title' => __( 'Vendors', 'vulnhub' ),
			'slug'  => 'vendors',
			'menu'  => __( 'Vendors', 'vulnhub' ),
			'icon'  => 'M3 21h18M5 21V7l7-4 7 4v14M9 21v-4h6v4M9 10h.01M15 10h.01M12 13h.01',
		),
		// Not part of the primary navigation: the admin area is reached from
		// the header, and the sign-in page from a logged-out redirect.
		'admin'           => array(
			'title'  => __( 'Administration', 'vulnhub' ),
			'slug'   => 'portal-admin',
			'menu'   => __( 'Admin', 'vulnhub' ),
			'icon'   => 'M12 15a3 3 0 100-6 3 3 0 000 6zM19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 11-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 11-4 0v-.09A1.65 1.65 0 008 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 11-2.83-2.83l.06-.06A1.65 1.65 0 004.6 15a1.65 1.65 0 00-1.51-1H3a2 2 0 110-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 112.83-2.83l.06.06A1.65 1.65 0 009 4.6a1.65 1.65 0 001-1.51V3a2 2 0 114 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 112.83 2.83l-.06.06A1.65 1.65 0 0019.4 9V9a1.65 1.65 0 001.51 1H21a2 2 0 110 4h-.09a1.65 1.65 0 00-1.51 1z',
			'hidden' => true,
		),
		'login'           => array(
			'title'  => __( 'Sign in', 'vulnhub' ),
			'slug'   => 'sign-in',
			'menu'   => __( 'Sign in', 'vulnhub' ),
			'icon'   => 'M15 3h4a2 2 0 012 2v14a2 2 0 01-2 2h-4M10 17l5-5-5-5M15 12H3',
			'hidden' => true,
		),
	);

	/**
	 * Views contributed by other VulnHub plugins.
	 *
	 * A view is a page the portal owns and renders itself, which is more than
	 * `vulnhub_portal_nav_extra` offers -- that one only adds a link. Anything
	 * added here must also answer `vulnhub_dash_render_view_<view>` and create
	 * its own page, since this list is read long after activation ran.
	 *
	 * @param array<string,array<string,mixed>> $views Keyed by view name.
	 */
	return (array) apply_filters( 'vulnhub_dash_views', $views );
}

/**
 * Create the front-end pages on activation and remember their ids.
 */
register_activation_hook(
	__FILE__,
	static function (): void {
		$map = (array) get_option( 'vulnhub_dash_pages', array() );

		foreach ( vulnhub_dash_views() as $view => $def ) {
			$existing = isset( $map[ $view ] ) ? get_post( (int) $map[ $view ] ) : null;
			if ( $existing && 'trash' !== $existing->post_status ) {
				continue;
			}

			$page = get_page_by_path( $def['slug'] );
			if ( ! $page ) {
				$id = wp_insert_post(
					array(
						'post_title'     => wp_strip_all_tags( $def['title'] ),
						'post_name'      => $def['slug'],
						'post_content'   => '<!-- wp:shortcode -->[vulnhub_app view="' . $view . '"]<!-- /wp:shortcode -->',
						'post_status'    => 'publish',
						'post_type'      => 'page',
						'comment_status' => 'closed',
						'ping_status'    => 'closed',
					)
				);
			} else {
				$id = (int) $page->ID;
			}

			if ( ! is_wp_error( $id ) ) {
				$map[ $view ] = (int) $id;
			}
		}

		update_option( 'vulnhub_dash_pages', $map, false );

		// The dashboard becomes the site's front page, so the site root lands
		// straight on the application rather than a blog index.
		if ( ! empty( $map['dashboard'] ) ) {
			update_option( 'show_on_front', 'page' );
			update_option( 'page_on_front', (int) $map['dashboard'] );
		}

		flush_rewrite_rules();
	}
);

