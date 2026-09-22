<?php
/**
 * AppStream duplicate detection and cleanup.
 *
 * An AppStream fleet spins up a fresh streaming instance on demand, each one a
 * new EC2 with a new random computer name. A Tenable agent baked into the image
 * therefore registers a brand-new asset every time — dozens of one-shot records
 * that all stand for the same fleet, only one of which is alive now.
 *
 * We spot them by their signature (a 15-hex computer name with no NetBIOS name),
 * keep the most-recently-seen one, and offer the rest for deletion straight
 * through the Tenable API. A topbar bell surfaces the count the moment a sync
 * lands. Nothing is deleted without an explicit click.
 *
 * @package VulnHub\Tenable
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Tenable_AppStream {

	public const VIEW = 'appstream';
	public const SLUG = 'appstream-cleanup';

	/** Default computer-name signature of an AppStream streaming instance. */
	private const DEFAULT_REGEX = '^[0-9a-f]{15}$';

	/** Redundant candidates unseen for this long are the safe ones to clear. */
	private const STALE_DAYS = 7;

	public static function init(): void {
		add_action( 'rest_api_init', array( __CLASS__, 'routes' ) );
		add_filter( 'vulnhub_notifications', array( __CLASS__, 'notify' ) );
		add_filter( 'vulnhub_dash_views', array( __CLASS__, 'register_view' ) );
		add_action( 'vulnhub_dash_render_view_' . self::VIEW, array( __CLASS__, 'render' ) );
		add_action( 'init', array( __CLASS__, 'ensure_page' ), 20 );
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'assets' ), 20 );
	}

	/** The signature regex, overridable by an operator. */
	public static function regex(): string {
		$re = trim( (string) get_option( 'vulnhub_tenable_appstream_regex', '' ) );
		return '' !== $re ? $re : self::DEFAULT_REGEX;
	}

	private static function assets_table(): string {
		global $wpdb;
		return $wpdb->prefix . 'vulnhub_assets';
	}

	/**
	 * Every live asset whose computer name matches the AppStream signature,
	 * newest first. Rows already cleared (dropped) are excluded.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function candidates(): array {
		global $wpdb;
		$t = self::assets_table();

		return (array) $wpdb->get_results( // phpcs:ignore WordPress.DB
			$wpdb->prepare(
				"SELECT id, hostname, tenable_uuid, aws_instance_id, cloud_account_id, cloud_region,
						primary_source, operating_system, first_seen, last_seen
				 FROM {$t}
				 WHERE hostname REGEXP %s
				   AND netbios_name = ''
				   AND ( duplicate_of IS NULL OR duplicate_of = 0 )
				   AND tenable_dropped_at IS NULL
				 ORDER BY ( last_seen IS NULL ), last_seen DESC, id DESC",
				self::regex()
			),
			ARRAY_A
		);
	}

	/**
	 * The cleanup picture: the one to keep, the redundant rest, and how many of
	 * those can actually be removed through Tenable (they carry a UUID).
	 *
	 * @return array<string,mixed>
	 */
	public static function summary(): array {
		$rows  = self::candidates();
		$keep  = null;
		$stale = 0;
		$del   = 0;
		$out   = array();

		$cutoff = gmdate( 'Y-m-d H:i:s', time() - self::STALE_DAYS * DAY_IN_SECONDS );

		foreach ( $rows as $i => $r ) {
			$node = array(
				'id'        => (int) $r['id'],
				'hostname'  => (string) $r['hostname'],
				'uuid'      => (string) $r['tenable_uuid'],
				'instance'  => (string) $r['aws_instance_id'],
				'account'   => (string) $r['cloud_account_id'],
				'region'    => (string) $r['cloud_region'],
				'source'    => (string) $r['primary_source'],
				'os'        => (string) $r['operating_system'],
				'first'     => (string) $r['first_seen'],
				'last'      => (string) $r['last_seen'],
				'deletable' => '' !== (string) $r['tenable_uuid'],
				'stale'     => '' === (string) $r['last_seen'] || $r['last_seen'] < $cutoff,
			);

			if ( 0 === $i ) {
				$node['keep'] = true;
				$keep         = $node;
				continue;
			}

			if ( $node['deletable'] ) {
				++$del;
			}
			if ( $node['stale'] ) {
				++$stale;
			}
			$out[] = $node;
		}

		return array(
			'regex'           => self::regex(),
			'total'           => count( $rows ),
			'keep'            => $keep,
			'redundant'       => $out,
			'redundant_count' => count( $out ),
			'deletable_count' => $del,
			'stale_count'     => $stale,
			'as_of'           => gmdate( 'c' ),
		);
	}

	/**
	 * Delete one redundant AppStream asset from Tenable, then mark our copy as
	 * dropped so it leaves the list. The most-recent instance is never eligible.
	 *
	 * @return array{ok:bool,message:string,deleted?:bool,status?:int}
	 */
	public static function delete_one( int $asset_id ): array {
		global $wpdb;
		$t = self::assets_table();

		$row = $wpdb->get_row( $wpdb->prepare( "SELECT id, hostname, tenable_uuid FROM {$t} WHERE id = %d", $asset_id ), ARRAY_A ); // phpcs:ignore WordPress.DB
		if ( ! $row ) {
			return array( 'ok' => false, 'message' => __( 'That asset no longer exists.', 'vulnhub' ) );
		}

		$rows = self::candidates();
		if ( isset( $rows[0] ) && (int) $rows[0]['id'] === $asset_id ) {
			return array( 'ok' => false, 'message' => __( 'That is the most recent instance — it is kept, not deleted.', 'vulnhub' ) );
		}

		$uuid = (string) $row['tenable_uuid'];
		if ( '' === $uuid ) {
			return array( 'ok' => false, 'message' => __( 'No Tenable record for this asset, so it cannot be deleted through Tenable.', 'vulnhub' ) );
		}

		$connector = vulnhub()->connectors->get( 'tenable' );
		if ( ! $connector || ! method_exists( $connector, 'client' ) ) {
			return array( 'ok' => false, 'message' => __( 'The Tenable connector is not available.', 'vulnhub' ) );
		}

		$client = $connector->client();
		if ( ! $client->has_credentials() ) {
			return array( 'ok' => false, 'message' => __( 'Tenable API credentials are not configured.', 'vulnhub' ) );
		}

		$result = $client->delete_asset( $uuid );

		if ( empty( $result['ok'] ) ) {
			$detail = trim( (string) $result['message'] );
			return array(
				'ok'      => false,
				'status'  => (int) $result['status'],
				'message' => sprintf(
					/* translators: 1: HTTP status, 2: message from Tenable. */
					__( 'Tenable refused the delete (HTTP %1$d)%2$s', 'vulnhub' ),
					(int) $result['status'],
					'' !== $detail ? ': ' . $detail : '.'
				),
			);
		}

		$wpdb->update( // phpcs:ignore WordPress.DB
			$t,
			array(
				'tenable_dropped_at' => gmdate( 'Y-m-d H:i:s' ),
				'lifecycle_status'   => 'retired',
			),
			array( 'id' => $asset_id ),
			array( '%s', '%s' ),
			array( '%d' )
		);

		if ( function_exists( 'do_action' ) ) {
			do_action( 'vulnhub_tenable_appstream_deleted', $asset_id, $uuid );
		}

		return array(
			'ok'      => true,
			'deleted' => ! empty( $result['deleted'] ),
			'message' => ! empty( $result['deleted'] )
				? __( 'Deleted from Tenable.', 'vulnhub' )
				: __( 'Tenable holds no asset with that id, so there was nothing to delete; cleared from the list here.', 'vulnhub' ),
		);
	}

	/* ============================ REST ============================ */

	public static function routes(): void {
		register_rest_route(
			'vulnhub-tenable/v1',
			'/appstream',
			array(
				'methods'             => 'GET',
				'callback'            => static function () {
					return rest_ensure_response( self::summary() );
				},
				'permission_callback' => static fn (): bool => is_user_logged_in() && current_user_can( \VulnHub\Core\Caps::VIEW ),
			)
		);

		register_rest_route(
			'vulnhub-tenable/v1',
			'/appstream/delete',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'rest_delete' ),
				'permission_callback' => static fn (): bool => current_user_can( \VulnHub\Core\Caps::MANAGE ),
			)
		);
	}

	public static function rest_delete( \WP_REST_Request $request ): \WP_REST_Response {
		$ids = $request->get_param( 'ids' );
		if ( ! is_array( $ids ) ) {
			$one = (int) $request->get_param( 'id' );
			$ids = $one ? array( $one ) : array();
		}
		$ids = array_values( array_unique( array_filter( array_map( 'intval', (array) $ids ) ) ) );

		$done    = 0;
		$gone    = 0;
		$failed  = array();
		foreach ( $ids as $id ) {
			$r = self::delete_one( $id );
			if ( ! empty( $r['ok'] ) ) {
				if ( ! empty( $r['deleted'] ) ) {
					++$done;
				} else {
					++$gone;
				}
			} else {
				$failed[] = array( 'id' => $id, 'message' => (string) ( $r['message'] ?? 'Failed.' ) );
			}
		}

		return rest_ensure_response(
			array(
				'deleted' => $done,
				'gone'    => $gone,
				'failed'  => $failed,
				'summary' => self::summary(),
			)
		);
	}

	/* ======================= Notifications ======================= */

	/**
	 * Contribute the AppStream notice to the topbar bell.
	 *
	 * @param array<int,array<string,mixed>> $items Existing notices.
	 * @return array<int,array<string,mixed>>
	 */
	public static function notify( array $items ): array {
		$s = self::summary();
		if ( $s['total'] < 2 || $s['deletable_count'] < 1 ) {
			return $items;
		}

		$keep = $s['keep'] ? (string) $s['keep']['hostname'] : '';
		$url  = '';
		$map  = (array) get_option( 'vulnhub_dash_pages', array() );
		if ( ! empty( $map[ self::VIEW ] ) ) {
			$url = (string) get_permalink( (int) $map[ self::VIEW ] );
		}

		$items[] = array(
			'id'       => 'tenable-appstream',
			'severity' => 'warn',
			'count'    => (int) $s['deletable_count'],
			'title'    => __( 'AppStream duplicates in Tenable', 'vulnhub' ),
			'body'     => sprintf(
				/* translators: 1: total, 2: newest hostname, 3: deletable count. */
				__( '%1$d assets are AppStream streaming instances. The most recent is %2$s; %3$d stale duplicates can be deleted.', 'vulnhub' ),
				(int) $s['total'],
				$keep,
				(int) $s['deletable_count']
			),
			'url'      => $url,
		);

		return $items;
	}

	/* ========================= View / page ======================= */

	/**
	 * @param array<string,array<string,mixed>> $views Existing views.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_view( array $views ): array {
		$views[ self::VIEW ] = array(
			'title'  => __( 'AppStream cleanup', 'vulnhub' ),
			'slug'   => self::SLUG,
			'menu'   => __( 'AppStream cleanup', 'vulnhub' ),
			'icon'   => 'M4 6h16M4 12h16M4 18h10',
			'hidden' => true,
		);
		return $views;
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
		$id   = $page ? (int) $page->ID : wp_insert_post(
			array(
				'post_title'     => __( 'AppStream cleanup', 'vulnhub' ),
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

		$base = plugins_url( 'assets/', VULNHUB_TENABLE_FILE );
		$cssv = @filemtime( VULNHUB_TENABLE_DIR . 'assets/appstream.css' ); // phpcs:ignore
		$jsv  = @filemtime( VULNHUB_TENABLE_DIR . 'assets/appstream.js' ); // phpcs:ignore

		wp_enqueue_style( 'vulnhub-appstream', $base . 'appstream.css', array( 'vulnhub-app' ), $cssv ?: VULNHUB_TENABLE_VERSION );
		wp_enqueue_script( 'vulnhub-appstream', $base . 'appstream.js', array( 'wp-api-fetch' ), $jsv ?: VULNHUB_TENABLE_VERSION, true );
		wp_localize_script(
			'vulnhub-appstream',
			'VH_APPSTREAM',
			array(
				'rest'  => esc_url_raw( rest_url( 'vulnhub-tenable/v1/appstream' ) ),
				'del'   => esc_url_raw( rest_url( 'vulnhub-tenable/v1/appstream/delete' ) ),
				'nonce' => wp_create_nonce( 'wp_rest' ),
				'manage' => current_user_can( \VulnHub\Core\Caps::MANAGE ),
			)
		);
	}

	public static function render(): void {
		echo '<div class="vh-page-head"><div>';
		echo '<h1>' . esc_html__( 'AppStream cleanup', 'vulnhub' ) . ' <span class="vh-chip vh-chip--info">' . esc_html__( 'Tenable', 'vulnhub' ) . '</span></h1>';
		echo '<p class="vh-sub">' . esc_html__( 'AppStream streaming instances register a fresh Tenable asset each time they start, so one fleet leaves a trail of one-shot records. The most-recently-seen instance is kept; the rest can be deleted straight through the Tenable API.', 'vulnhub' ) . '</p>';
		echo '</div></div>';
		echo '<div class="vh-appstream" data-vh-appstream><div class="vh-panel"><p>' . esc_html__( 'Loading…', 'vulnhub' ) . '</p></div></div>';
	}
}
