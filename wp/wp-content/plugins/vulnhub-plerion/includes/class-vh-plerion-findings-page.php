<?php
/**
 * The Cloud Posture (CSPM) page: Plerion misconfiguration/access findings.
 *
 * Deliberately its own page, reading its own store. These findings are never
 * shown on the Vulnerabilities list and carry no raise-ticket control, because
 * they must never enter a JSM or Jira ticket. Visibility, not a work queue.
 *
 * @package VulnHub\Plerion
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Plerion_Findings_Page {

	public const VIEW = 'cspm';
	public const SLUG = 'cloud-posture';

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

			if ( 'vulnerabilities' === $key ) {
				$out[ self::VIEW ] = array(
					'title' => __( 'Cloud Posture', 'vulnhub' ),
					'slug'  => self::SLUG,
					'menu'  => __( 'Cloud Posture', 'vulnhub' ),
					'icon'  => 'M4 7h16M4 12h16M4 17h10',
				);
			}
		}

		return $out;
	}

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
					'post_title'     => __( 'Cloud Posture', 'vulnhub' ),
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
		$map  = (array) get_option( 'vulnhub_dash_pages', array() );
		$base = ! empty( $map[ self::VIEW ] )
			? (string) get_permalink( (int) $map[ self::VIEW ] )
			: home_url( '/' . self::SLUG . '/' );

		return $args ? add_query_arg( $args, $base ) : $base;
	}

	public static function assets(): void {
		if ( ! is_singular() || ! class_exists( 'VulnHub_Dash_App' ) ) {
			return;
		}

		if ( self::VIEW !== VulnHub_Dash_App::view_for_post( get_post() ) ) {
			return;
		}

		$rel   = 'assets/plerion.css';
		$mtime = @filemtime( VULNHUB_PLERION_DIR . $rel ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		wp_enqueue_style(
			'vulnhub-plerion',
			VULNHUB_PLERION_URL . $rel,
			array( 'vulnhub-app' ),
			$mtime ? VULNHUB_PLERION_VERSION . '.' . $mtime : VULNHUB_PLERION_VERSION
		);
	}

	private static function pill( string $sev ): string {
		$key = strtolower( $sev );

		return sprintf( '<span class="vh-pill vh-pill--%s">%s</span>', esc_attr( $key ), esc_html( ucfirst( $key ) ) );
	}

	public static function render(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$args = array(
			'severity'      => isset( $_GET['severity'] ) ? sanitize_text_field( wp_unslash( $_GET['severity'] ) ) : '',
			'account'       => isset( $_GET['account'] ) ? sanitize_text_field( wp_unslash( $_GET['account'] ) ) : '',
			'resource_type' => isset( $_GET['rtype'] ) ? sanitize_text_field( wp_unslash( $_GET['rtype'] ) ) : '',
			'search'        => isset( $_GET['search'] ) ? sanitize_text_field( wp_unslash( $_GET['search'] ) ) : '',
			'limit'         => 50,
			'offset'        => isset( $_GET['p'] ) ? max( 0, ( absint( wp_unslash( $_GET['p'] ) ) - 1 ) * 50 ) : 0,
		);
		// phpcs:enable

		$summary = VulnHub_Plerion_Findings::summary();
		$result  = VulnHub_Plerion_Findings::query( $args );

		echo '<div class="vh-page-head"><div>';
		echo '<h1>' . esc_html__( 'Cloud Posture', 'vulnhub' ) . ' <span class="vh-chip vh-chip--info vh-plerion-badge">' . esc_html__( 'CSPM · Plerion', 'vulnhub' ) . '</span></h1>';
		echo '<p class="vh-sub">' . esc_html__(
			'Cloud misconfiguration and access findings from Plerion. These are posture findings, not scanner vulnerabilities — they are shown here for visibility only and never enter the Vulnerabilities list or a JSM/Jira ticket.',
			'vulnhub'
		) . '</p>';
		echo '</div></div>';

		self::render_tiles( $summary );
		self::render_filters( $args );
		self::render_table( $result, $args );
	}

	private static function render_tiles( array $s ): void {
		$by = array();

		foreach ( (array) $s['by_severity'] as $r ) {
			$by[ strtoupper( (string) $r['severity'] ) ] = (int) $r['c'];
		}

		$tiles = array(
			array( 'label' => __( 'Open findings', 'vulnhub' ), 'value' => (int) $s['total'], 'tone' => (int) $s['total'] > 0 ? 'warn' : 'good', 'meta' => __( 'CSPM, not exempted', 'vulnhub' ) ),
			array( 'label' => __( 'Critical', 'vulnhub' ), 'value' => $by['CRITICAL'] ?? 0, 'tone' => ( $by['CRITICAL'] ?? 0 ) > 0 ? 'critical' : 'good', 'meta' => __( 'posture critical', 'vulnhub' ) ),
			array( 'label' => __( 'High', 'vulnhub' ), 'value' => $by['HIGH'] ?? 0, 'tone' => ( $by['HIGH'] ?? 0 ) > 0 ? 'warn' : 'good', 'meta' => __( 'posture high', 'vulnhub' ) ),
			array( 'label' => __( 'Accounts affected', 'vulnhub' ), 'value' => count( (array) $s['by_account'] ), 'tone' => 'muted', 'meta' => __( 'cloud accounts', 'vulnhub' ) ),
		);

		echo '<div class="vh-tiles">';

		foreach ( $tiles as $tile ) {
			if ( class_exists( 'VulnHub_Dash_Charts' ) ) {
				echo VulnHub_Dash_Charts::stat_tile( $tile ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			}
		}

		echo '</div>';
	}

	private static function render_filters( array $args ): void {
		echo '<form method="get" class="vh-filters">';

		printf(
			'<input type="search" name="search" value="%s" placeholder="%s" aria-label="%s">',
			esc_attr( (string) $args['search'] ),
			esc_attr__( 'detection, resource or message', 'vulnhub' ),
			esc_attr__( 'Search findings', 'vulnhub' )
		);

		echo '<select name="severity" aria-label="' . esc_attr__( 'Severity', 'vulnhub' ) . '">';
		printf( '<option value="">%s</option>', esc_html__( 'Any severity', 'vulnhub' ) );
		foreach ( array( 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW' ) as $sev ) {
			printf( '<option value="%s"%s>%s</option>', esc_attr( $sev ), selected( strtoupper( (string) $args['severity'] ), $sev, false ), esc_html( ucfirst( strtolower( $sev ) ) ) );
		}
		echo '</select>';

		echo '<select name="account" aria-label="' . esc_attr__( 'Account', 'vulnhub' ) . '">';
		printf( '<option value="">%s</option>', esc_html__( 'Any account', 'vulnhub' ) );
		foreach ( VulnHub_Plerion_Findings::accounts() as $acct ) {
			printf( '<option value="%s"%s>%s</option>', esc_attr( $acct ), selected( (string) $args['account'], $acct, false ), esc_html( $acct ) );
		}
		echo '</select>';

		echo '<select name="rtype" aria-label="' . esc_attr__( 'Resource type', 'vulnhub' ) . '">';
		printf( '<option value="">%s</option>', esc_html__( 'Any resource type', 'vulnhub' ) );
		foreach ( VulnHub_Plerion_Findings::resource_types() as $rt ) {
			printf( '<option value="%s"%s>%s</option>', esc_attr( $rt ), selected( (string) $args['resource_type'], $rt, false ), esc_html( $rt ) );
		}
		echo '</select>';

		printf( '<button class="vh-btn vh-btn--sm" type="submit">%s</button>', esc_html__( 'Filter', 'vulnhub' ) );
		printf( '<a class="vh-btn vh-btn--ghost vh-btn--sm" href="%s">%s</a>', esc_url( self::url() ), esc_html__( 'Reset', 'vulnhub' ) );

		echo '</form>';
	}

	private static function render_table( array $result, array $args ): void {
		$rows = (array) $result['rows'];

		if ( ! $rows ) {
			echo '<div class="vh-panel"><p>' . esc_html__( 'No CSPM findings match those filters.', 'vulnhub' ) . '</p>';
			echo '<p class="vh-sub">' . esc_html__( 'If the Plerion connector has not synced posture findings yet, run it from Administration → Integrations.', 'vulnhub' ) . '</p></div>';

			return;
		}

		printf(
			'<p class="vh-meta">%s</p>',
			esc_html( sprintf( /* translators: 1: shown, 2: total */ __( 'Showing %1$d of %2$d findings.', 'vulnhub' ), count( $rows ), (int) $result['total'] ) )
		);

		echo '<div class="vh-tablewrap"><table class="vh-table">';
		echo '<thead><tr>';
		foreach ( array( __( 'Severity', 'vulnhub' ), __( 'Detection', 'vulnhub' ), __( 'Resource', 'vulnhub' ), __( 'Account', 'vulnhub' ), __( 'Region', 'vulnhub' ), __( 'Finding', 'vulnhub' ), __( 'First seen', 'vulnhub' ) ) as $h ) {
			printf( '<th scope="col">%s</th>', esc_html( $h ) );
		}
		echo '</tr></thead><tbody>';

		foreach ( $rows as $r ) {
			echo '<tr>';
			echo '<td>' . self::pill( (string) $r['severity'] ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			printf( '<td class="vh-mono vh-meta">%s</td>', esc_html( (string) $r['detection_id'] ) );

			echo '<td>';
			printf( '<div>%s</div>', esc_html( (string) ( $r['resource_name'] ?: '—' ) ) );
			printf( '<div class="vh-meta vh-mono">%s</div>', esc_html( (string) $r['resource_type'] ) );
			if ( ! empty( $r['resource_url'] ) ) {
				printf( '<a class="vh-meta" href="%s" target="_blank" rel="noopener noreferrer">%s</a>', esc_url( (string) $r['resource_url'] ), esc_html__( 'Open in AWS ↗', 'vulnhub' ) );
			}
			echo '</td>';

			printf( '<td class="vh-mono">%s</td>', esc_html( (string) $r['account_id'] ) );
			printf( '<td class="vh-meta">%s</td>', esc_html( (string) $r['region'] ) );
			printf( '<td class="vh-plerion-msg">%s</td>', esc_html( vh_trim( (string) $r['message'], 160 ) ) );
			printf( '<td class="vh-nowrap vh-meta">%s</td>', esc_html( $r['first_observed'] ? substr( (string) $r['first_observed'], 0, 10 ) : '—' ) );
			echo '</tr>';
		}

		echo '</tbody></table></div>';

		self::render_paging( $result, $args );
	}

	private static function render_paging( array $result, array $args ): void {
		$per   = 50;
		$total = (int) $result['total'];

		if ( $total <= $per ) {
			return;
		}

		$page  = (int) floor( ( (int) $args['offset'] ) / $per ) + 1;
		$pages = (int) ceil( $total / $per );

		echo '<nav class="vh-paging">';

		if ( $page > 1 ) {
			printf( '<a class="vh-btn vh-btn--ghost vh-btn--sm" href="%s">%s</a>', esc_url( add_query_arg( 'p', $page - 1 ) ), esc_html__( 'Previous', 'vulnhub' ) );
		}

		printf( '<span class="vh-meta">%s</span>', esc_html( sprintf( /* translators: 1: page, 2: pages */ __( 'Page %1$d of %2$d', 'vulnhub' ), $page, $pages ) ) );

		if ( $page < $pages ) {
			printf( '<a class="vh-btn vh-btn--ghost vh-btn--sm" href="%s">%s</a>', esc_url( add_query_arg( 'p', $page + 1 ) ), esc_html__( 'Next', 'vulnhub' ) );
		}

		echo '</nav>';
	}
}
