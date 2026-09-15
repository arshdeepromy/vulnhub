<?php
/**
 * The Alerts page: advisories from every feed, ranked by whether they can
 * actually reach us.
 *
 * @package VulnHub\Alerts
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Alerts_Page {

	public const VIEW = 'alerts';
	public const SLUG = 'alerts';

	public static function init(): void {
		add_filter( 'vulnhub_dash_views', array( __CLASS__, 'register_view' ) );
		add_action( 'vulnhub_dash_render_view_' . self::VIEW, array( __CLASS__, 'render' ) );
		add_action( 'template_redirect', array( __CLASS__, 'handle_post' ) );
		add_action( 'init', array( __CLASS__, 'ensure_page' ), 20 );
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'assets' ), 20 );
	}

	/**
	 * @param array<string,array<string,mixed>> $views Existing views.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_view( array $views ): array {
		// Placed after vulnerabilities on purpose: an operator reads "what is
		// open" before "what might be coming".
		$out = array();

		foreach ( $views as $key => $def ) {
			$out[ $key ] = $def;

			if ( 'vulnerabilities' === $key ) {
				$out[ self::VIEW ] = array(
					'title' => __( 'Advisory alerts', 'vulnhub' ),
					'slug'  => self::SLUG,
					'menu'  => self::menu_label(),
					'icon'  => 'M12 3a6 6 0 00-6 6v3.6L4 16h16l-2-3.4V9a6 6 0 00-6-6zM10 20a2 2 0 004 0',
				);
			}
		}

		return $out;
	}

	/**
	 * "Alerts" on its own, or with the count of untriaged matches beside it.
	 *
	 * The nav is the only always-visible surface in the product, so this is
	 * where somebody finds out something arrived without opening mail. The
	 * count is deliberately of matched-and-untriaged rather than of
	 * everything: a badge that reads 3,448 teaches people to ignore it.
	 */
	private static function menu_label(): string {
		if ( ! is_user_logged_in() ) {
			return __( 'Alerts', 'vulnhub' );
		}

		$count = (int) get_transient( 'vulnhub_alerts_badge' );

		if ( ! $count ) {
			global $wpdb;

			$table = $wpdb->prefix . 'vulnhub_alerts';
			$count = (int) $wpdb->get_var(
				"SELECT COUNT(*) FROM {$table} WHERE matched = 1 AND state = 'new'"
			);

			// Short cache: the nav renders on every portal page, and this
			// must not become a query per pageview.
			set_transient( 'vulnhub_alerts_badge', $count, 5 * MINUTE_IN_SECONDS );
		}

		return $count > 0
			? sprintf(
				/* translators: %d: number of untriaged matched alerts */
				__( 'Alerts (%d)', 'vulnhub' ),
				$count
			)
			: __( 'Alerts', 'vulnhub' );
	}

	/**
	 * The portal's pages are created by the dashboard's activation hook,
	 * which ran long before this plugin existed. Create ours if it is
	 * missing, and only then.
	 */
	public static function ensure_page(): void {
		$map = (array) get_option( 'vulnhub_dash_pages', array() );

		if ( ! empty( $map[ self::VIEW ] ) ) {
			$existing = get_post( (int) $map[ self::VIEW ] );

			if ( $existing && 'trash' !== $existing->post_status ) {
				return;
			}
		}

		$page = get_page_by_path( self::SLUG );

		if ( $page ) {
			$id = (int) $page->ID;
		} else {
			$id = wp_insert_post(
				array(
					'post_title'     => __( 'Advisory alerts', 'vulnhub' ),
					'post_name'      => self::SLUG,
					'post_content'   => '<!-- wp:shortcode -->[vulnhub_app view="' . self::VIEW . '"]<!-- /wp:shortcode -->',
					'post_status'    => 'publish',
					'post_type'      => 'page',
					'comment_status' => 'closed',
					'ping_status'    => 'closed',
				)
			);
		}

		if ( ! is_wp_error( $id ) && $id ) {
			$map[ self::VIEW ] = (int) $id;
			update_option( 'vulnhub_dash_pages', $map, false );
		}
	}

	public static function url( array $args = array() ): string {
		$map = (array) get_option( 'vulnhub_dash_pages', array() );
		$base = ! empty( $map[ self::VIEW ] )
			? (string) get_permalink( (int) $map[ self::VIEW ] )
			: home_url( '/' . self::SLUG . '/' );

		return $args ? add_query_arg( $args, $base ) : $base;
	}

	/**
	 * Cache-busting version for one bundled asset: the plugin version plus the
	 * file's own mtime.
	 *
	 * The plugin version alone moves only on release, so a CDN in front of the
	 * portal (which caches wp-content for hours) serves the old stylesheet to
	 * anyone who loaded the page recently -- new markup styled by old rules,
	 * which is worse than a plainly stale page. The mtime changes exactly when
	 * the bytes do. Mirrors VulnHub_Dash_App::asset_ver().
	 *
	 * @param string $rel Path relative to the plugin directory.
	 */
	private static function asset_ver( string $rel ): string {
		$mtime = @filemtime( VULNHUB_ALERTS_DIR . $rel ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		return $mtime ? VULNHUB_ALERTS_VERSION . '.' . $mtime : VULNHUB_ALERTS_VERSION;
	}

	public static function assets(): void {
		if ( ! is_singular() ) {
			return;
		}

		if ( self::VIEW !== VulnHub_Dash_App::view_for_post( get_post() ) ) {
			return;
		}

		wp_enqueue_style(
			'vulnhub-alerts',
			VULNHUB_ALERTS_URL . 'assets/alerts.css',
			array( 'vulnhub-app' ),
			self::asset_ver( 'assets/alerts.css' )
		);
	}

	/* =================================================================
	 * Actions
	 * ============================================================== */

	public static function handle_post(): void {
		if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) {
			return;
		}

		if ( ! isset( $_POST['vh_alert_nonce'] ) ) {
			return;
		}

		if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['vh_alert_nonce'] ) ), 'vulnhub_alert_action' ) ) {
			wp_die( esc_html__( 'That form expired. Go back and try again.', 'vulnhub' ) );
		}

		if ( ! current_user_can( Caps::TRIAGE ) ) {
			wp_die( esc_html__( 'You do not have permission to triage alerts.', 'vulnhub' ) );
		}

		$alert_id = isset( $_POST['alert_id'] ) ? absint( wp_unslash( $_POST['alert_id'] ) ) : 0;
		$state    = isset( $_POST['state'] ) ? sanitize_key( wp_unslash( $_POST['state'] ) ) : '';
		$note     = isset( $_POST['note'] ) ? sanitize_textarea_field( wp_unslash( $_POST['note'] ) ) : '';

		if ( $alert_id && $state ) {
			VulnHub_Alerts_Repo::set_state( $alert_id, $state, $note );
		}

		wp_safe_redirect( self::url( array( 'alert' => $alert_id, 'saved' => 1 ) ) );
		exit;
	}

	/* =================================================================
	 * Render
	 * ============================================================== */

	public static function render(): void {
		$alert_id = isset( $_GET['alert'] ) ? absint( wp_unslash( $_GET['alert'] ) ) : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		if ( $alert_id ) {
			self::render_detail( $alert_id );

			return;
		}

		self::render_list();
	}

	private static function render_list(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$args = array(
			'confidence' => isset( $_GET['confidence'] ) ? sanitize_key( wp_unslash( $_GET['confidence'] ) ) : '',
			'state'      => isset( $_GET['state'] ) ? sanitize_key( wp_unslash( $_GET['state'] ) ) : 'open',
			'severity'   => isset( $_GET['severity'] ) ? sanitize_key( wp_unslash( $_GET['severity'] ) ) : '',
			'source'     => isset( $_GET['source'] ) ? sanitize_key( wp_unslash( $_GET['source'] ) ) : '',
			'kev'        => isset( $_GET['kev'] ) && '' !== $_GET['kev'] ? absint( wp_unslash( $_GET['kev'] ) ) : '',
			'search'     => isset( $_GET['search'] ) ? sanitize_text_field( wp_unslash( $_GET['search'] ) ) : '',
			'matched'    => isset( $_GET['matched'] ) && '0' === $_GET['matched'] ? '0' : '1',
			'orderby'    => isset( $_GET['orderby'] ) ? sanitize_key( wp_unslash( $_GET['orderby'] ) ) : 'priority',
			'limit'      => 50,
			'offset'     => isset( $_GET['p'] ) ? max( 0, ( absint( wp_unslash( $_GET['p'] ) ) - 1 ) * 50 ) : 0,
		);
		// phpcs:enable

		$summary = VulnHub_Alerts_Repo::summary();
		$result  = VulnHub_Alerts_Repo::alerts( $args );

		echo '<div class="vh-page-head"><div>';
		echo '<h1>' . esc_html__( 'Advisory alerts', 'vulnhub' ) . '</h1>';
		echo '<p class="vh-sub">' . esc_html__(
			'Advisories and zero-day notices from every configured feed, matched against the software and operating systems this estate actually runs. Ranked by how sure the match is, not by how loud the advisory was.',
			'vulnhub'
		) . '</p>';
		echo '</div></div>';

		self::render_tiles( $summary );
		self::render_filters( $args );
		self::render_table( $result, $args );
	}

	private static function render_tiles( array $s ): void {
		$tiles = array(
			array(
				'label' => __( 'Needs a decision', 'vulnhub' ),
				'value' => (int) $s['untriaged'],
				'tone'  => (int) $s['untriaged'] > 0 ? 'warn' : 'good',
				'meta'  => __( 'matched and untriaged', 'vulnhub' ),
			),
			array(
				'label' => __( 'Exact matches', 'vulnhub' ),
				'value' => (int) $s['exact'],
				'tone'  => (int) $s['exact'] > 0 ? 'critical' : 'good',
				'meta'  => __( 'version confirmed affected', 'vulnhub' ),
			),
			array(
				'label' => __( 'Being exploited', 'vulnhub' ),
				'value' => (int) $s['exploited'],
				'tone'  => (int) $s['exploited'] > 0 ? 'critical' : 'good',
				'meta'  => __( 'open, and exploited in the wild', 'vulnhub' ),
			),
			array(
				'label' => __( 'Assessed, not relevant', 'vulnhub' ),
				'value' => (int) $s['not_relevant'],
				'tone'  => 'muted',
				'meta'  => __( 'checked against the estate, no match', 'vulnhub' ),
			),
		);

		echo '<div class="vh-tiles">';

		foreach ( $tiles as $tile ) {
			echo VulnHub_Dash_Charts::stat_tile( $tile ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}

		echo '</div>';
	}

	private static function render_filters( array $args ): void {
		$sources = VulnHub_Alerts_Repo::per_source();

		echo '<form method="get" class="vh-filters vh-alerts__filters">';

		printf(
			'<input type="search" name="search" value="%s" placeholder="%s" aria-label="%s">',
			esc_attr( (string) $args['search'] ),
			esc_attr__( 'CVE, product or advisory text', 'vulnhub' ),
			esc_attr__( 'Search alerts', 'vulnhub' )
		);

		echo '<select name="confidence" aria-label="' . esc_attr__( 'Match confidence', 'vulnhub' ) . '">';
		printf( '<option value="">%s</option>', esc_html__( 'Any confidence', 'vulnhub' ) );
		foreach ( VulnHub_Alerts_Matcher::confidences() as $key => $def ) {
			printf(
				'<option value="%s"%s>%s</option>',
				esc_attr( $key ),
				selected( $args['confidence'], $key, false ),
				esc_html( (string) $def['label'] )
			);
		}
		echo '</select>';

		echo '<select name="state" aria-label="' . esc_attr__( 'Triage state', 'vulnhub' ) . '">';
		printf(
			'<option value="open"%s>%s</option>',
			selected( $args['state'], 'open', false ),
			esc_html__( 'Still open', 'vulnhub' )
		);
		printf( '<option value=""%s>%s</option>', selected( $args['state'], '', false ), esc_html__( 'Any state', 'vulnhub' ) );
		foreach ( VulnHub_Alerts_Repo::states() as $key => $def ) {
			printf(
				'<option value="%s"%s>%s</option>',
				esc_attr( $key ),
				selected( $args['state'], $key, false ),
				esc_html( (string) $def['label'] )
			);
		}
		echo '</select>';

		echo '<select name="severity" aria-label="' . esc_attr__( 'Severity', 'vulnhub' ) . '">';
		printf( '<option value="">%s</option>', esc_html__( 'Any severity', 'vulnhub' ) );
		foreach ( VulnHub_Alerts_Registry::severities() as $key => $def ) {
			printf(
				'<option value="%s"%s>%s</option>',
				esc_attr( $key ),
				selected( $args['severity'], $key, false ),
				esc_html( (string) $def['label'] )
			);
		}
		echo '</select>';

		echo '<select name="source" aria-label="' . esc_attr__( 'Feed', 'vulnhub' ) . '">';
		printf( '<option value="">%s</option>', esc_html__( 'Any feed', 'vulnhub' ) );
		foreach ( $sources as $slug => $counts ) {
			printf(
				'<option value="%s"%s>%s (%d)</option>',
				esc_attr( $slug ),
				selected( $args['source'], $slug, false ),
				esc_html( $slug ),
				(int) $counts['matched']
			);
		}
		echo '</select>';

		echo '<select name="matched" aria-label="' . esc_attr__( 'Relevance', 'vulnhub' ) . '">';
		printf( '<option value="1"%s>%s</option>', selected( $args['matched'], '1', false ), esc_html__( 'Touches this estate', 'vulnhub' ) );
		printf( '<option value="0"%s>%s</option>', selected( $args['matched'], '0', false ), esc_html__( 'Assessed as not relevant', 'vulnhub' ) );
		echo '</select>';

		printf(
			'<label class="vh-alerts__kev"><input type="checkbox" name="kev" value="1"%s> %s</label>',
			checked( (string) $args['kev'], '1', false ),
			esc_html__( 'Exploited only', 'vulnhub' )
		);

		printf( '<button class="vh-btn vh-btn--sm" type="submit">%s</button>', esc_html__( 'Filter', 'vulnhub' ) );
		printf(
			'<a class="vh-btn vh-btn--ghost vh-btn--sm" href="%s">%s</a>',
			esc_url( self::url() ),
			esc_html__( 'Reset', 'vulnhub' )
		);

		echo '</form>';
	}

	private static function render_table( array $result, array $args ): void {
		$rows = $result['rows'];

		if ( ! $rows ) {
			echo '<div class="vh-panel vh-alerts__empty">';
			echo '<p>' . esc_html__( 'Nothing matches those filters.', 'vulnhub' ) . '</p>';
			echo '<p class="vh-sub">' . esc_html__(
				'If no feed has run yet, poll them from Administration → Advisory feeds. If they have run and this is still empty, that is a real answer: nothing published recently touches anything in the inventory.',
				'vulnhub'
			) . '</p>';
			echo '</div>';

			return;
		}

		printf(
			'<p class="vh-meta">%s</p>',
			esc_html(
				sprintf(
					/* translators: 1: shown, 2: total */
					__( 'Showing %1$d of %2$d advisories.', 'vulnhub' ),
					count( $rows ),
					(int) $result['total']
				)
			)
		);

		echo '<div class="vh-tablewrap"><table class="vh-table vh-alerts__table">';
		echo '<thead><tr>';
		printf( '<th scope="col">%s</th>', esc_html__( 'Confidence', 'vulnhub' ) );
		printf( '<th scope="col">%s</th>', esc_html__( 'Advisory', 'vulnhub' ) );
		printf( '<th scope="col">%s</th>', esc_html__( 'Severity', 'vulnhub' ) );
		printf( '<th scope="col" class="vh-num">%s</th>', esc_html__( 'Assets', 'vulnhub' ) );
		printf( '<th scope="col">%s</th>', esc_html__( 'Feed', 'vulnhub' ) );
		printf( '<th scope="col">%s</th>', esc_html__( 'Published', 'vulnhub' ) );
		printf( '<th scope="col">%s</th>', esc_html__( 'State', 'vulnhub' ) );
		echo '</tr></thead><tbody>';

		foreach ( $rows as $row ) {
			self::render_row( $row );
		}

		echo '</tbody></table></div>';

		self::render_paging( $result, $args );
	}

	private static function render_row( array $row ): void {
		$confidence = (string) $row['best_confidence'];
		$cves       = VulnHub_Alerts_Repo::cves( $row );

		echo '<tr>';

		printf(
			'<td><span class="vh-pill vh-pill--%s" title="%s">%s</span></td>',
			esc_attr( VulnHub_Alerts_Matcher::tone( $confidence ) ),
			esc_attr( (string) ( VulnHub_Alerts_Matcher::confidences()[ $confidence ]['help'] ?? '' ) ),
			esc_html( VulnHub_Alerts_Matcher::label( $confidence ) )
		);

		echo '<td>';
		printf(
			'<a href="%s">%s</a>',
			esc_url( self::url( array( 'alert' => (int) $row['id'] ) ) ),
			esc_html( vh_trim( (string) $row['title'], 110 ) )
		);

		if ( (int) $row['kev'] ) {
			printf(
				'<span class="vh-chip vh-chip--bad" title="%s">%s</span>',
				esc_attr__( 'Reported as exploited in the wild', 'vulnhub' ),
				esc_html__( 'Exploited', 'vulnhub' )
			);
		}

		if ( $cves ) {
			printf(
				'<div class="vh-meta vh-mono">%s</div>',
				esc_html( implode( ', ', array_slice( $cves, 0, 4 ) ) )
			);
		}
		echo '</td>';

		printf(
			'<td><span class="vh-pill vh-pill--%s">%s</span>%s</td>',
			esc_attr( (string) $row['severity'] ),
			esc_html( (string) ( VulnHub_Alerts_Registry::severities()[ $row['severity'] ]['label'] ?? $row['severity'] ) ),
			(float) $row['cvss'] > 0
				? '<span class="vh-meta vh-mono"> ' . esc_html( number_format( (float) $row['cvss'], 1 ) ) . '</span>'
				: ''
		);

		printf( '<td class="vh-num">%s</td>', esc_html( (string) (int) $row['asset_count'] ) );
		printf( '<td class="vh-mono vh-meta">%s</td>', esc_html( (string) $row['source'] ) );

		printf(
			'<td class="vh-nowrap vh-meta">%s</td>',
			esc_html( $row['published_at'] ? vh_ago( (string) $row['published_at'] ) : '—' )
		);

		printf(
			'<td><span class="vh-state vh-state--%s">%s</span></td>',
			esc_attr( VulnHub_Alerts_Repo::state_tone( (string) $row['state'] ) ),
			esc_html( VulnHub_Alerts_Repo::state_label( (string) $row['state'] ) )
		);

		echo '</tr>';
	}

	private static function render_paging( array $result, array $args ): void {
		$per   = 50;
		$total = (int) $result['total'];

		if ( $total <= $per ) {
			return;
		}

		$page  = (int) floor( ( (int) $args['offset'] ) / $per ) + 1;
		$pages = (int) ceil( $total / $per );

		echo '<nav class="vh-alerts__paging">';

		if ( $page > 1 ) {
			printf(
				'<a class="vh-btn vh-btn--ghost vh-btn--sm" href="%s">%s</a>',
				esc_url( add_query_arg( 'p', $page - 1 ) ),
				esc_html__( 'Previous', 'vulnhub' )
			);
		}

		printf(
			'<span class="vh-meta">%s</span>',
			esc_html(
				sprintf(
					/* translators: 1: current page, 2: total pages */
					__( 'Page %1$d of %2$d', 'vulnhub' ),
					$page,
					$pages
				)
			)
		);

		if ( $page < $pages ) {
			printf(
				'<a class="vh-btn vh-btn--ghost vh-btn--sm" href="%s">%s</a>',
				esc_url( add_query_arg( 'p', $page + 1 ) ),
				esc_html__( 'Next', 'vulnhub' )
			);
		}

		echo '</nav>';
	}

	/* ----------------------------------------------------------------- */

	private static function render_detail( int $alert_id ): void {
		$alert = VulnHub_Alerts_Repo::alert( $alert_id );

		if ( ! $alert ) {
			echo '<div class="vh-panel"><p>' . esc_html__( 'That alert no longer exists.', 'vulnhub' ) . '</p></div>';

			return;
		}

		$matches = VulnHub_Alerts_Repo::matches( $alert_id );
		$cves    = VulnHub_Alerts_Repo::cves( $alert );

		echo '<div class="vh-page-head"><div>';
		printf(
			'<p class="vh-meta"><a href="%s">&larr; %s</a></p>',
			esc_url( self::url() ),
			esc_html__( 'All alerts', 'vulnhub' )
		);
		echo '<h1>' . esc_html( (string) $alert['title'] ) . '</h1>';

		echo '<p class="vh-sub">';
		printf(
			'<span class="vh-pill vh-pill--%s">%s</span> ',
			esc_attr( VulnHub_Alerts_Matcher::tone( (string) $alert['best_confidence'] ) ),
			esc_html( VulnHub_Alerts_Matcher::label( (string) $alert['best_confidence'] ) )
		);
		echo esc_html(
			sprintf(
				/* translators: 1: severity, 2: source, 3: external id */
				__( '%1$s · from %2$s · %3$s', 'vulnhub' ),
				(string) $alert['severity'],
				(string) $alert['source'],
				(string) $alert['external_id']
			)
		);
		echo '</p>';
		echo '</div></div>';

		echo '<div class="vh-alerts__detail">';

		echo '<div class="vh-panel">';
		echo '<h2>' . esc_html__( 'What it says', 'vulnhub' ) . '</h2>';

		if ( '' !== trim( (string) $alert['summary'] ) ) {
			echo '<p>' . esc_html( (string) $alert['summary'] ) . '</p>';
		} else {
			echo '<p class="vh-muted">' . esc_html__( 'This feed published no description.', 'vulnhub' ) . '</p>';
		}

		echo '<dl class="vh-alerts__facts">';
		self::fact( __( 'CVE', 'vulnhub' ), $cves ? implode( ', ', $cves ) : __( 'none given', 'vulnhub' ) );
		self::fact( __( 'CVSS', 'vulnhub' ), (float) $alert['cvss'] > 0 ? number_format( (float) $alert['cvss'], 1 ) : '—' );
		self::fact(
			__( 'EPSS', 'vulnhub' ),
			(float) $alert['epss'] > 0 ? number_format( (float) $alert['epss'] * 100, 1 ) . '%' : '—'
		);
		self::fact(
			__( 'Exploited', 'vulnhub' ),
			(int) $alert['kev'] ? __( 'Yes — reported exploited in the wild', 'vulnhub' ) : __( 'Not reported', 'vulnhub' )
		);
		self::fact( __( 'Published', 'vulnhub' ), (string) ( $alert['published_at'] ?: '—' ) );
		echo '</dl>';

		if ( ! empty( $alert['url'] ) ) {
			printf(
				'<p><a class="vh-btn vh-btn--ghost vh-btn--sm" href="%s" target="_blank" rel="noopener noreferrer">%s</a></p>',
				esc_url( (string) $alert['url'] ),
				esc_html__( 'Read the advisory', 'vulnhub' )
			);
		}

		echo '</div>';

		self::render_triage( $alert );
		echo '</div>';

		self::render_matches( $alert, $matches );
		self::render_history( $alert_id );
	}

	private static function fact( string $label, string $value ): void {
		printf( '<dt>%s</dt><dd>%s</dd>', esc_html( $label ), esc_html( $value ) );
	}

	private static function render_triage( array $alert ): void {
		echo '<div class="vh-panel">';
		echo '<h2>' . esc_html__( 'Decision', 'vulnhub' ) . '</h2>';

		if ( ! current_user_can( Caps::TRIAGE ) ) {
			printf(
				'<p class="vh-muted">%s</p>',
				esc_html__( 'You can read this alert but not triage it.', 'vulnhub' )
			);
			echo '</div>';

			return;
		}

		echo '<form method="post">';
		wp_nonce_field( 'vulnhub_alert_action', 'vh_alert_nonce' );
		printf( '<input type="hidden" name="alert_id" value="%d">', (int) $alert['id'] );

		echo '<label class="vh-field"><span>' . esc_html__( 'State', 'vulnhub' ) . '</span>';
		echo '<select name="state">';
		foreach ( VulnHub_Alerts_Repo::states() as $key => $def ) {
			printf(
				'<option value="%s"%s>%s</option>',
				esc_attr( $key ),
				selected( (string) $alert['state'], $key, false ),
				esc_html( (string) $def['label'] )
			);
		}
		echo '</select></label>';

		printf(
			'<label class="vh-field"><span>%s</span><textarea name="note" rows="3" placeholder="%s">%s</textarea></label>',
			esc_html__( 'Why', 'vulnhub' ),
			esc_attr__( 'The reasoning somebody will want in six months.', 'vulnhub' ),
			esc_textarea( (string) $alert['state_note'] )
		);

		printf( '<button class="vh-btn vh-btn--primary" type="submit">%s</button>', esc_html__( 'Save decision', 'vulnhub' ) );
		echo '</form>';
		echo '</div>';
	}

	private static function render_matches( array $alert, array $matches ): void {
		echo '<div class="vh-panel">';
		printf(
			'<h2>%s</h2>',
			esc_html(
				sprintf(
					/* translators: %d: asset count */
					_n( '%d asset affected', '%d assets affected', (int) $alert['asset_count'], 'vulnhub' ),
					(int) $alert['asset_count']
				)
			)
		);

		if ( ! $matches ) {
			echo '<p class="vh-muted">' . esc_html__(
				'Nothing in the inventory matched this advisory. It is kept so there is a record that it was assessed.',
				'vulnhub'
			) . '</p></div>';

			return;
		}

		echo '<div class="vh-tablewrap"><table class="vh-table">';
		echo '<thead><tr>';
		printf( '<th scope="col">%s</th>', esc_html__( 'Asset', 'vulnhub' ) );
		printf( '<th scope="col">%s</th>', esc_html__( 'Confidence', 'vulnhub' ) );
		printf( '<th scope="col">%s</th>', esc_html__( 'Product', 'vulnhub' ) );
		printf( '<th scope="col">%s</th>', esc_html__( 'Installed', 'vulnhub' ) );
		printf( '<th scope="col">%s</th>', esc_html__( 'Why it matched', 'vulnhub' ) );
		echo '</tr></thead><tbody>';

		foreach ( $matches as $m ) {
			echo '<tr>';
			printf(
				'<td class="vh-mono">%s<div class="vh-meta">%s</div></td>',
				esc_html( (string) ( $m['hostname'] ?: __( 'unnamed', 'vulnhub' ) ) ),
				esc_html( (string) ( $m['operating_system'] ?: '' ) )
			);
			printf(
				'<td><span class="vh-pill vh-pill--%s">%s</span></td>',
				esc_attr( VulnHub_Alerts_Matcher::tone( (string) $m['confidence'] ) ),
				esc_html( VulnHub_Alerts_Matcher::label( (string) $m['confidence'] ) )
			);
			printf( '<td>%s</td>', esc_html( (string) $m['product'] ) );
			printf( '<td class="vh-mono">%s</td>', esc_html( (string) ( $m['installed_version'] ?: '—' ) ) );
			printf( '<td class="vh-meta">%s</td>', esc_html( (string) $m['evidence'] ) );
			echo '</tr>';
		}

		echo '</tbody></table></div></div>';
	}

	private static function render_history( int $alert_id ): void {
		$events = VulnHub_Alerts_Repo::events( $alert_id );

		if ( ! $events ) {
			return;
		}

		echo '<div class="vh-panel">';
		echo '<h2>' . esc_html__( 'History', 'vulnhub' ) . '</h2><ul class="vh-alerts__history">';

		foreach ( $events as $event ) {
			$user = $event['user_id'] ? get_userdata( (int) $event['user_id'] ) : null;

			printf(
				'<li><strong>%s</strong> %s <span class="vh-meta">%s · %s</span>%s</li>',
				esc_html( VulnHub_Alerts_Repo::state_label( (string) $event['to_state'] ) ),
				esc_html__( 'set by', 'vulnhub' ),
				esc_html( $user ? $user->display_name : __( 'the system', 'vulnhub' ) ),
				esc_html( (string) $event['created_at'] ),
				$event['note'] ? '<div class="vh-meta">' . esc_html( (string) $event['note'] ) . '</div>' : ''
			);
		}

		echo '</ul></div>';
	}
}
