<?php
/**
 * Feed management: add, test, poll and disable advisory sources.
 *
 * The point of this screen is that adding a free feed is a form submission.
 * Six sources ship configured; the two generic adapters mean the seventh is
 * a URL somebody pastes in, tests, and saves.
 *
 * @package VulnHub\Alerts
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Alerts_Admin {

	public const SECTION = 'advisory-feeds';
	public const NONCE   = 'vulnhub_alerts_feeds';

	/** @var array{text:string,tone:string}|null */
	private static ?array $notice = null;

	/** @var array<string,mixed>|null Result of a "test" run, shown once. */
	private static ?array $test = null;

	public static function init(): void {
		add_filter( 'vulnhub_portal_sections', array( __CLASS__, 'register_section' ) );
		add_action( 'vulnhub_render_portal_section', array( __CLASS__, 'render_section' ) );
		add_action( 'template_redirect', array( __CLASS__, 'handle' ), 5 );
	}

	/**
	 * @param array<string,array<string,mixed>> $sections Section definitions.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_section( array $sections ): array {
		$sections[ self::SECTION ] = array(
			'label'   => __( 'Advisory feeds', 'vulnhub' ),
			'cap'     => Caps::MANAGE,
			'group'   => 'data',
			'order'   => 35,
			'summary' => __( 'Where advisory and zero-day alerts come from. Add any free feed; the generic RSS and JSON adapters take a URL and need no code.', 'vulnhub' ),
		);

		return $sections;
	}

	/** @param string $section Section slug being rendered. */
	public static function render_section( $section ): void {
		if ( self::SECTION !== (string) $section || ! current_user_can( Caps::MANAGE ) ) {
			return;
		}

		$notice = self::$notice;
		$test   = self::$test;
		$feeds  = VulnHub_Alerts_Repo::feeds();
		$counts = VulnHub_Alerts_Repo::per_source();

		include VULNHUB_ALERTS_DIR . 'admin/views/feeds.php';
	}

	public static function notice(): ?array {
		return self::$notice;
	}

	/* =================================================================
	 * Handling
	 * ============================================================== */

	public static function handle(): void {
		if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) {
			return;
		}

		if ( ! isset( $_POST['vh_feeds_nonce'] ) ) {
			return;
		}

		if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['vh_feeds_nonce'] ) ), self::NONCE ) ) {
			self::$notice = array( 'text' => __( 'That form expired. Try again.', 'vulnhub' ), 'tone' => 'bad' );

			return;
		}

		if ( ! current_user_can( Caps::MANAGE ) ) {
			self::$notice = array( 'text' => __( 'You do not have permission to manage feeds.', 'vulnhub' ), 'tone' => 'bad' );

			return;
		}

		$action = isset( $_POST['vh_action'] ) ? sanitize_key( wp_unslash( $_POST['vh_action'] ) ) : '';

		switch ( $action ) {
			case 'save':
				self::save();
				break;
			case 'test':
				self::test();
				break;
			case 'poll':
				self::poll();
				break;
			case 'toggle':
				self::toggle();
				break;
			case 'delete':
				self::delete();
				break;
			case 'poll_all':
				self::poll_all();
				break;
		}
	}

	private static function posted(): array {
		// phpcs:disable WordPress.Security.NonceVerification.Missing
		return array(
			'id'       => isset( $_POST['feed_id'] ) ? absint( wp_unslash( $_POST['feed_id'] ) ) : 0,
			'label'    => isset( $_POST['label'] ) ? sanitize_text_field( wp_unslash( $_POST['label'] ) ) : '',
			'adapter'  => isset( $_POST['adapter'] ) ? sanitize_key( wp_unslash( $_POST['adapter'] ) ) : 'rss',
			'url'      => isset( $_POST['url'] ) ? esc_url_raw( trim( (string) wp_unslash( $_POST['url'] ) ) ) : '',
			'interval' => isset( $_POST['interval_minutes'] ) ? absint( wp_unslash( $_POST['interval_minutes'] ) ) : 360,
			'auth_key' => isset( $_POST['auth_key'] ) ? sanitize_text_field( wp_unslash( $_POST['auth_key'] ) ) : '',
			'items'    => isset( $_POST['items_path'] ) ? sanitize_text_field( wp_unslash( $_POST['items_path'] ) ) : '',
			'map'      => isset( $_POST['map'] ) ? (array) wp_unslash( $_POST['map'] ) : array(),
		);
		// phpcs:enable
	}

	private static function config_from( array $p ): array {
		$config = array();

		if ( 'json' === $p['adapter'] ) {
			$config['items_path'] = $p['items'];
			$config['map']        = array_map( 'sanitize_text_field', array_filter( (array) $p['map'] ) );
		}

		return $config;
	}

	private static function save(): void {
		global $wpdb;

		$p     = self::posted();
		$table = $wpdb->prefix . 'vulnhub_alert_feeds';
		$now   = current_time( 'mysql', true );

		if ( '' === $p['label'] || '' === $p['url'] ) {
			self::$notice = array( 'text' => __( 'A feed needs both a name and a URL.', 'vulnhub' ), 'tone' => 'bad' );

			return;
		}

		if ( '' === VulnHub_Alerts_Registry::adapter_class( $p['adapter'] ) ) {
			self::$notice = array( 'text' => __( 'That is not an adapter this install knows about.', 'vulnhub' ), 'tone' => 'bad' );

			return;
		}

		$data = array(
			'label'            => $p['label'],
			'adapter'          => $p['adapter'],
			'url'              => $p['url'],
			'auth_key'         => $p['auth_key'],
			'interval_minutes' => max( 15, min( 10080, $p['interval'] ) ),
			'updated_at'       => $now,
		);

		if ( $p['id'] ) {
			$existing = VulnHub_Alerts_Repo::feed( $p['id'] );

			if ( ! $existing ) {
				self::$notice = array( 'text' => __( 'That feed no longer exists.', 'vulnhub' ), 'tone' => 'bad' );

				return;
			}

			// A built-in feed keeps its adapter and slug: those are what the
			// shipped code knows how to talk to, and letting somebody point
			// the MSRC feed at an RSS URL just breaks it silently.
			if ( (int) $existing['builtin'] ) {
				unset( $data['adapter'] );
			} else {
				$data['config_json'] = wp_json_encode( self::config_from( $p ) );
			}

			$wpdb->update( $table, $data, array( 'id' => $p['id'] ) );

			self::$notice = array( 'text' => __( 'Feed saved.', 'vulnhub' ), 'tone' => 'good' );

			return;
		}

		$data['slug']        = self::unique_slug( $p['label'] );
		$data['config_json'] = wp_json_encode( self::config_from( $p ) );
		$data['enabled']     = 1;
		$data['builtin']     = 0;
		$data['created_at']  = $now;

		$wpdb->insert( $table, $data );

		self::$notice = array(
			'text' => __( 'Feed added. Test it, then poll it — nothing is fetched until you do.', 'vulnhub' ),
			'tone' => 'good',
		);
	}

	private static function unique_slug( string $label ): string {
		global $wpdb;

		$table = $wpdb->prefix . 'vulnhub_alert_feeds';
		$base  = substr( sanitize_key( $label ) ?: 'feed', 0, 48 );
		$slug  = $base;
		$n     = 2;

		while ( $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$table} WHERE slug = %s", $slug ) ) ) {
			$slug = $base . '-' . $n;
			++$n;
		}

		return $slug;
	}

	/**
	 * Fetch and match without writing anything, so somebody can see what a
	 * new feed would actually produce before committing to it.
	 */
	private static function test(): void {
		$p = self::posted();

		if ( $p['id'] ) {
			$result = VulnHub_Alerts_Runner::run_feed( $p['id'], true );
		} else {
			// An unsaved feed has no row, so build a throwaway one.
			$class = VulnHub_Alerts_Registry::adapter_class( $p['adapter'] );

			if ( '' === $class || ! class_exists( $class ) ) {
				self::$notice = array( 'text' => __( 'Unknown adapter.', 'vulnhub' ), 'tone' => 'bad' );

				return;
			}

			$feed = array(
				'id'            => 0,
				'slug'          => 'preview',
				'url'           => $p['url'],
				'config_json'   => wp_json_encode( self::config_from( $p ) ),
				'auth_key'      => $p['auth_key'],
				'http_etag'     => '',
				'http_modified' => '',
				'last_ok_at'    => null,
			);

			try {
				$adapter = new $class( $feed );
				$rows    = $adapter->fetch();
				$samples = array();
				$matched = 0;

				foreach ( $rows as $row ) {
					$m = VulnHub_Alerts_Matcher::match( $row );

					if ( $m ) {
						++$matched;
					}

					if ( count( $samples ) < 8 ) {
						$samples[] = array(
							'title'      => (string) $row['title'],
							'severity'   => (string) $row['severity'],
							'cves'       => (array) $row['cves'],
							'products'   => array_column( (array) $row['products'], 'product' ),
							'matches'    => count( $m ),
							'confidence' => $m ? (string) $m[0]['confidence'] : '',
						);
					}
				}

				$result = array(
					'ok'      => true,
					'fetched' => count( $rows ),
					'matched' => $matched,
					'notes'   => $adapter->notes(),
					'error'   => '',
					'samples' => $samples,
				);
			} catch ( Throwable $e ) {
				$result = array(
					'ok'      => false,
					'fetched' => 0,
					'matched' => 0,
					'notes'   => array(),
					'error'   => $e->getMessage(),
					'samples' => array(),
				);
			}
		}

		self::$test = $result;

		self::$notice = $result['ok']
			? array(
				'text' => sprintf(
					/* translators: 1: fetched, 2: matched */
					__( 'Read %1$d entries; %2$d of them touch this estate. Nothing was saved.', 'vulnhub' ),
					(int) $result['fetched'],
					(int) $result['matched']
				),
				'tone' => 'good',
			)
			: array( 'text' => (string) $result['error'], 'tone' => 'bad' );
	}

	private static function poll(): void {
		$p = self::posted();

		if ( ! $p['id'] ) {
			return;
		}

		$result = VulnHub_Alerts_Runner::run_feed( $p['id'] );

		self::$notice = $result['ok']
			? array(
				'text' => sprintf(
					/* translators: 1: new, 2: updated, 3: matched */
					__( '%1$d new, %2$d updated, %3$d matched the estate.', 'vulnhub' ),
					(int) $result['new'],
					(int) $result['updated'],
					(int) $result['matched']
				),
				'tone' => 'good',
			)
			: array( 'text' => (string) $result['error'], 'tone' => 'bad' );
	}

	private static function poll_all(): void {
		$ran = VulnHub_Alerts_Runner::run_due();

		if ( ! $ran ) {
			self::$notice = array(
				'text' => __( 'Every feed has run recently enough. Poll one individually to force it.', 'vulnhub' ),
				'tone' => 'muted',
			);

			return;
		}

		$new = array_sum( array_column( $ran, 'new' ) );

		self::$notice = array(
			'text' => sprintf(
				/* translators: 1: feed count, 2: new advisories */
				__( 'Polled %1$d feeds, %2$d new advisories.', 'vulnhub' ),
				count( $ran ),
				(int) $new
			),
			'tone' => 'good',
		);
	}

	private static function toggle(): void {
		global $wpdb;

		$p = self::posted();

		if ( ! $p['id'] ) {
			return;
		}

		$feed = VulnHub_Alerts_Repo::feed( $p['id'] );

		if ( ! $feed ) {
			return;
		}

		$wpdb->update(
			$wpdb->prefix . 'vulnhub_alert_feeds',
			array( 'enabled' => (int) $feed['enabled'] ? 0 : 1, 'updated_at' => current_time( 'mysql', true ) ),
			array( 'id' => $p['id'] )
		);

		self::$notice = array(
			'text' => (int) $feed['enabled']
				? __( 'Feed switched off. Its existing alerts are kept.', 'vulnhub' )
				: __( 'Feed switched on.', 'vulnhub' ),
			'tone' => 'good',
		);
	}

	private static function delete(): void {
		global $wpdb;

		$p    = self::posted();
		$feed = $p['id'] ? VulnHub_Alerts_Repo::feed( $p['id'] ) : null;

		if ( ! $feed ) {
			return;
		}

		if ( (int) $feed['builtin'] ) {
			self::$notice = array(
				'text' => __( 'Built-in feeds can be switched off but not deleted, so an upgrade does not silently bring them back.', 'vulnhub' ),
				'tone' => 'bad',
			);

			return;
		}

		// The advisories go with it. Keeping orphans would leave rows on the
		// page that no longer refresh and that nobody can trace to a source.
		$alerts  = $wpdb->prefix . 'vulnhub_alerts';
		$matches = $wpdb->prefix . 'vulnhub_alert_matches';

		$ids = $wpdb->get_col( $wpdb->prepare( "SELECT id FROM {$alerts} WHERE feed_id = %d", $p['id'] ) );

		if ( $ids ) {
			$in = implode( ',', array_map( 'intval', $ids ) );
			$wpdb->query( "DELETE FROM {$matches} WHERE alert_id IN ({$in})" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->query( "DELETE FROM {$alerts} WHERE id IN ({$in})" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		}

		$wpdb->delete( $wpdb->prefix . 'vulnhub_alert_feeds', array( 'id' => $p['id'] ), array( '%d' ) );

		self::$notice = array(
			'text' => sprintf(
				/* translators: %d: number of advisories removed */
				__( 'Feed deleted, along with %d advisories it had contributed.', 'vulnhub' ),
				count( $ids )
			),
			'tone' => 'good',
		);
	}
}
