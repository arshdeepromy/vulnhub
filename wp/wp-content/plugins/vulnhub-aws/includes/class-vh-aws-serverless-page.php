<?php
/**
 * Internet-facing functions: the serverless doors, and what is behind each.
 *
 * The rest of the estate reasons about exposure through machines -- an
 * instance, its network interface, its security groups, the route out. A
 * Lambda function has none of those, so every one of those rules answers "not
 * reachable" about a function anyone on the internet can call. This page is
 * the other half of the answer: what AWS itself says about the way in, the
 * function it lands on, and what that function's role can reach.
 *
 * Everything about the way in is read from AWS. The posture vendor's count of
 * vulnerabilities inside a function is shown as the vendor's claim, because it
 * comes from scanning code this system does not scan and carries no CVE we
 * could check against anything.
 *
 * @package VulnHub\AWS
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_AWS_Serverless_Page {

	public const VIEW   = 'serverless';
	public const SLUG   = 'internet-facing-functions';
	public const WIDGET = 'aws_serverless';

	public static function init(): void {
		add_filter( 'vulnhub_dash_views', array( __CLASS__, 'register_view' ) );
		add_action( 'vulnhub_dash_render_view_' . self::VIEW, array( __CLASS__, 'render' ) );
		add_action( 'init', array( __CLASS__, 'ensure_page' ), 20 );
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'assets' ), 20 );
		add_filter( 'vulnhub_dashboard_widgets', array( __CLASS__, 'register_widget' ) );
		add_filter( 'vulnhub_dashboard_default_layout', array( __CLASS__, 'place_widget' ) );
	}

	/* =================================================================
	 * Registration
	 * ============================================================== */

	/**
	 * @param array<string,array<string,mixed>> $views Existing views.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_view( array $views ): array {
		$out = array();

		$def = array(
			'title' => __( 'Internet-facing functions', 'vulnhub' ),
			'slug'  => self::SLUG,
			'menu'  => __( 'Serverless exposure', 'vulnhub' ),
			'icon'  => 'M13 2 3 14h7l-1 8 10-12h-7l1-8z',
		);

		foreach ( $views as $key => $existing ) {
			$out[ $key ] = $existing;

			// Directly after the network map: the same question, other half.
			if ( VulnHub_AWS_Network_Page::VIEW === $key ) {
				$out[ self::VIEW ] = $def;
			}
		}

		if ( ! isset( $out[ self::VIEW ] ) ) {
			$out[ self::VIEW ] = $def;
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

		$id = $page ? (int) $page->ID : wp_insert_post(
			array(
				'post_title'     => __( 'Internet-facing functions', 'vulnhub' ),
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

		$ver = @filemtime( VULNHUB_AWS_DIR . 'assets/serverless.css' ); // phpcs:ignore
		wp_enqueue_style( 'vulnhub-aws-serverless', VULNHUB_AWS_URL . 'assets/serverless.css', array( 'vulnhub-app' ), $ver ?: VULNHUB_AWS_VERSION );
	}

	/**
	 * The page's own URL, for the widget and for cross-links.
	 *
	 * @param array<string,string> $args Query arguments to carry.
	 */
	public static function url( array $args = array() ): string {
		$map = (array) get_option( 'vulnhub_dash_pages', array() );
		$id  = (int) ( $map[ self::VIEW ] ?? 0 );
		$url = $id ? (string) get_permalink( $id ) : home_url( '/' . self::SLUG . '/' );

		return $args ? add_query_arg( $args, $url ) : $url;
	}

	/* =================================================================
	 * The dashboard widget
	 * ============================================================== */

	/**
	 * @param array<string,array<string,mixed>> $w Widgets.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_widget( array $w ): array {
		$w[ self::WIDGET ] = array(
			'label'   => __( 'Serverless exposure: functions anyone can invoke', 'vulnhub' ),
			'summary' => __( 'Lambda functions reachable from the internet with no credential -- through an API Gateway route that asks for nothing, a function URL, or a resource policy open to the world. Counted from AWS rather than from the machine inventory, because a function is not a machine and the reachability rules that cover servers never see one.', 'vulnhub' ),
			'group'   => 'exposure',
			'width'   => 12,
			'render'  => array( __CLASS__, 'render_widget' ),
			'data'    => array( __CLASS__, 'widget_data' ),
		);

		return $w;
	}

	/**
	 * @param array<int,array<string,mixed>> $layout Default layout.
	 * @return array<int,array<string,mixed>>
	 */
	public static function place_widget( array $layout ): array {
		if ( in_array( self::WIDGET, array_column( $layout, 'id' ), true ) ) {
			return $layout;
		}

		$out    = array();
		$placed = false;

		foreach ( $layout as $entry ) {
			$out[] = $entry;

			if ( ! $placed && in_array( (string) ( $entry['id'] ?? '' ), array( 'exposure_summary', 'exposure', 'threat_flow' ), true ) ) {
				$out[]  = array(
					'id'    => self::WIDGET,
					'width' => 12,
				);
				$placed = true;
			}
		}

		if ( ! $placed ) {
			$out[] = array(
				'id'    => self::WIDGET,
				'width' => 12,
			);
		}

		return $out;
	}

	/** @return array<string,mixed> */
	public static function widget_data(): array {
		return VulnHub_AWS_Serverless::summary();
	}

	public static function render_widget(): void {
		$s   = VulnHub_AWS_Serverless::summary();
		$url = self::url();

		if ( 0 === (int) $s['scanned'] ) {
			echo '<p class="vh-sub vh-muted">' . esc_html__( 'No AWS account has been read for serverless entry points yet. Run an AWS sync -- the capture rides along with it.', 'vulnhub' ) . '</p>';
			return;
		}

		$stale = self::deprecated_count();

		echo '<div class="vh-tiles">';
		echo wp_kses_post(
			VulnHub_Dash_Charts::stat_tile(
				array(
					'label' => __( 'Functions anyone can invoke', 'vulnhub' ),
					'value' => (int) $s['targets'],
					'tone'  => $s['targets'] > 0 ? 'critical' : 'good',
					'href'  => $url,
					'meta'  => sprintf(
						/* translators: 1: open routes, 2: accounts. */
						_n( 'through %1$d open route, in %2$d account', 'through %1$d open routes, in %2$d accounts', (int) $s['public'], 'vulnhub' ),
						(int) $s['public'],
						(int) $s['accounts']
					),
				)
			)
		);
		echo wp_kses_post(
			VulnHub_Dash_Charts::stat_tile(
				array(
					'label' => __( 'On a runtime AWS no longer patches', 'vulnhub' ),
					'value' => $stale,
					'tone'  => $stale > 0 ? 'serious' : 'neutral',
					'href'  => self::url( array( 'runtime' => 'deprecated' ) ),
					'meta'  => __( 'nothing to patch to -- the runtime itself is out of support', 'vulnhub' ),
				)
			)
		);
		echo wp_kses_post(
			VulnHub_Dash_Charts::stat_tile(
				array(
					'label' => __( 'Routes behind a credential', 'vulnhub' ),
					'value' => array_sum( VulnHub_AWS_Serverless::guarded() ),
					'tone'  => 'good',
					'href'  => $url,
					'meta'  => __( 'IAM, an authorizer or an API key', 'vulnhub' ),
				)
			)
		);
		echo wp_kses_post(
			VulnHub_Dash_Charts::stat_tile(
				array(
					'label' => __( 'Accounts and regions read', 'vulnhub' ),
					'value' => (int) $s['scanned'],
					'tone'  => (int) $s['partial'] > 0 ? 'warning' : 'neutral',
					'href'  => $url,
					'meta'  => (int) $s['partial'] > 0
						? sprintf(
							/* translators: %d: partial reads. */
							_n( '%d incomplete -- the role was refused', '%d incomplete -- the role was refused', (int) $s['partial'], 'vulnhub' ),
							(int) $s['partial']
						)
						: __( 'all read in full', 'vulnhub' ),
				)
			)
		);
		echo '</div>';

		echo '<p class="vh-sub vh-muted">' . esc_html__(
			'A machine counts as reachable here when a route, a network interface and a security group line up, which is how every other exposure figure in this app is worked out. None of that applies to a function: it has no interface and no security group, so the only thing that decides is whether the door in front of it asks the caller for anything. Click the number for each function, its account, the path in, and what its role can reach.',
			'vulnhub'
		) . '</p>';
	}

	/** Publicly invokable functions sitting on a runtime AWS has stopped patching. */
	private static function deprecated_count(): int {
		$n = 0;

		foreach ( VulnHub_AWS_Serverless::targets() as $row ) {
			if ( 'deprecated' === (string) $row['runtime_state'] ) {
				++$n;
			}
		}

		return $n;
	}


	/* =================================================================
	 * The drill-down
	 * ============================================================== */

	/** @return array<string,string> */
	private static function filters(): array {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$out = array();

		foreach ( array( 'account', 'region', 'runtime' ) as $key ) {
			if ( isset( $_GET[ $key ] ) ) {
				$out[ $key ] = sanitize_text_field( (string) wp_unslash( $_GET[ $key ] ) );
			}
		}

		if ( isset( $_GET['q'] ) ) {
			$out['search'] = sanitize_text_field( (string) wp_unslash( $_GET['q'] ) );
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		return array_filter( $out, static fn( $v ) => '' !== $v );
	}

	public static function render(): void {
		$filters = self::filters();
		$summary = VulnHub_AWS_Serverless::summary();
		$rows    = VulnHub_AWS_Serverless::targets( $filters );

		echo '<div class="vh-page-head"><div>';
		echo '<h1>' . esc_html__( 'Internet-facing functions', 'vulnhub' ) . ' <span class="vh-chip vh-chip--src">' . esc_html__( 'AWS · read live from your SSO login', 'vulnhub' ) . '</span></h1>';
		echo '<p class="vh-sub">' . esc_html__(
			'Every Lambda function that something on the open internet can invoke without a credential, the door it comes in through, and what the function can reach once it runs. Read from AWS itself: the route\'s authorization setting, the API\'s endpoint type, whether a stage is deployed, the function\'s own URL and its resource policy.',
			'vulnhub'
		) . '</p>';
		echo '</div></div>';

		if ( 0 === (int) $summary['scanned'] ) {
			echo '<div class="vh-card"><p class="vh-sub vh-muted">' . esc_html__( 'No account has been read yet. Run an AWS sync — the serverless capture rides along with it.', 'vulnhub' ) . '</p></div>';
			return;
		}

		self::render_tiles( $summary );
		self::render_filters( $filters );

		if ( ! $rows ) {
			echo '<div class="vh-card"><p class="vh-sub">' . esc_html__( 'Nothing matches. Every route read either asks the caller for something, or has no function behind it.', 'vulnhub' ) . '</p></div>';
			self::render_coverage( $summary );
			return;
		}

		self::render_list_bar( count( $rows ) );

		foreach ( $rows as $row ) {
			self::render_card( $row );
		}

		self::render_open_script();
		self::render_coverage( $summary );
	}

	/** How many matched, and the two controls that open and shut them all. */
	private static function render_list_bar( int $count ): void {
		echo '<div class="vh-sl-bar">';
		printf(
			'<p class="vh-sl-count">%s</p>',
			esc_html(
				sprintf(
					/* translators: %d: matching functions. */
					_n( '%d function, collapsed — open one to see its doors and the path in', '%d functions, collapsed — open one to see its doors and the path in', $count, 'vulnhub' ),
					$count
				)
			)
		);
		echo '<div class="vh-sl-bar__acts">';
		printf(
			'<button type="button" class="vh-btn vh-btn--ghost" data-vh-sl="open">%s</button>',
			esc_html__( 'Expand all', 'vulnhub' )
		);
		printf(
			'<button type="button" class="vh-btn vh-btn--ghost" data-vh-sl="shut">%s</button>',
			esc_html__( 'Collapse all', 'vulnhub' )
		);
		echo '</div></div>';
	}

	/**
	 * Open the card a link points at, and wire the two buttons.
	 *
	 * The dashboard widget and the coverage table both link to `#fn-<key>`.
	 * A collapsed <details> is not scrolled to by the browser in every
	 * engine, so the targeted one is opened here. Everything on this page
	 * still works with the script blocked -- it is a convenience, not the
	 * mechanism.
	 */
	private static function render_open_script(): void {
		?>
<script>
( function () {
	var open = function () {
		if ( ! window.location.hash ) {
			return;
		}

		var card = document.getElementById( window.location.hash.slice( 1 ) );

		if ( card && 'DETAILS' === card.tagName ) {
			card.open = true;
			card.scrollIntoView( { block: 'start' } );
		}
	};

	document.querySelectorAll( '[data-vh-sl]' ).forEach( function ( btn ) {
		btn.addEventListener( 'click', function () {
			var want = 'open' === btn.getAttribute( 'data-vh-sl' );

			document.querySelectorAll( 'details.vh-sl-card' ).forEach( function ( card ) {
				card.open = want;
			} );
		} );
	} );

	window.addEventListener( 'hashchange', open );
	open();
}() );
</script>
		<?php
	}

	/** @param array<string,mixed> $s Summary. */
	private static function render_tiles( array $s ): void {
		echo '<div class="vh-tiles">';
		echo wp_kses_post(
			VulnHub_Dash_Charts::stat_tile(
				array(
					'label' => __( 'Functions anyone can invoke', 'vulnhub' ),
					'value' => (int) $s['targets'],
					'tone'  => $s['targets'] > 0 ? 'critical' : 'good',
				)
			)
		);
		echo wp_kses_post(
			VulnHub_Dash_Charts::stat_tile(
				array(
					'label' => __( 'Open routes into them', 'vulnhub' ),
					'value' => (int) $s['public'],
					'tone'  => 'serious',
					'meta'  => __( 'the method or policy asks for nothing', 'vulnhub' ),
				)
			)
		);
		echo wp_kses_post(
			VulnHub_Dash_Charts::stat_tile(
				array(
					'label' => __( 'Open routes with no function behind them', 'vulnhub' ),
					'value' => (int) $s['orphans'],
					'tone'  => 'warning',
					'meta'  => __( 'a mock, or a proxy to something else', 'vulnhub' ),
				)
			)
		);
		echo wp_kses_post(
			VulnHub_Dash_Charts::stat_tile(
				array(
					'label' => __( 'Accounts affected', 'vulnhub' ),
					'value' => (int) $s['accounts'],
					'tone'  => 'neutral',
					'meta'  => '' !== (string) $s['captured_at']
						/* translators: %s: local date and time. */
						? sprintf( __( 'read %s', 'vulnhub' ), vh_date( (string) $s['captured_at'] ) )
						: '',
				)
			)
		);
		echo '</div>';
	}

	/** @param array<string,string> $filters Active filters. */
	private static function render_filters( array $filters ): void {
		$accounts = array();
		$regions  = array();

		foreach ( VulnHub_AWS_Serverless::runs() as $run ) {
			$id              = (string) $run['account_id'];
			$name            = (string) $run['account_name'];
			$accounts[ $id ] = '' !== $name ? $name . ' (' . $id . ')' : $id;
			$region          = (string) $run['region'];
			$regions[ $region ] = $region;
		}

		asort( $accounts );
		asort( $regions );

		echo '<form class="vh-filters vh-sl-filters" method="get">';

		echo '<label>' . esc_html__( 'Account', 'vulnhub' ) . ' <select name="account">';
		echo '<option value="">' . esc_html__( 'Any account', 'vulnhub' ) . '</option>';
		foreach ( $accounts as $id => $label ) {
			printf(
				'<option value="%s"%s>%s</option>',
				esc_attr( (string) $id ),
				selected( (string) $id, (string) ( $filters['account'] ?? '' ), false ),
				esc_html( $label )
			);
		}
		echo '</select></label>';

		echo '<label>' . esc_html__( 'Region', 'vulnhub' ) . ' <select name="region">';
		echo '<option value="">' . esc_html__( 'Any region', 'vulnhub' ) . '</option>';
		foreach ( $regions as $region ) {
			printf(
				'<option value="%s"%s>%s</option>',
				esc_attr( (string) $region ),
				selected( (string) $region, (string) ( $filters['region'] ?? '' ), false ),
				esc_html( (string) $region )
			);
		}
		echo '</select></label>';

		echo '<label>' . esc_html__( 'Runtime', 'vulnhub' ) . ' <select name="runtime">';
		foreach ( array(
			''           => __( 'Any runtime', 'vulnhub' ),
			'deprecated' => __( 'No longer supported by AWS', 'vulnhub' ),
			'current'    => __( 'Supported', 'vulnhub' ),
			'unknown'    => __( 'Not stated', 'vulnhub' ),
		) as $key => $label ) {
			printf(
				'<option value="%s"%s>%s</option>',
				esc_attr( (string) $key ),
				selected( (string) $key, (string) ( $filters['runtime'] ?? '' ), false ),
				esc_html( $label )
			);
		}
		echo '</select></label>';

		printf(
			'<label>%s <input type="search" name="q" value="%s" placeholder="%s"></label>',
			esc_html__( 'Search', 'vulnhub' ),
			esc_attr( (string) ( $filters['search'] ?? '' ) ),
			esc_attr__( 'function or API name', 'vulnhub' )
		);

		echo '<button type="submit" class="vh-btn">' . esc_html__( 'Filter', 'vulnhub' ) . '</button>';

		if ( $filters ) {
			printf( '<a class="vh-btn vh-btn--ghost" href="%s">%s</a>', esc_url( self::url() ), esc_html__( 'Clear', 'vulnhub' ) );
		}

		echo '</form>';
	}

	/** @param array<string,mixed> $row One function, with its doors. */
	private static function render_card( array $row ): void {
		$doors   = (array) $row['doors'];
		$posture = (array) $row['posture'];
		$asset   = (array) $row['asset'];
		$reaches = (array) $row['reaches'];
		$state   = (string) $row['runtime_state'];

		// Collapsed by default: 40-odd functions, each with tables, a diagram
		// and two lists, is not a page anyone can read. <details> keeps that
		// keyboard-operable and working without JavaScript.
		printf( '<details class="vh-card vh-sl-card" id="fn-%s">', esc_attr( (string) $row['key'] ) );

		echo '<summary class="vh-sl-head">';
		echo '<span class="vh-sl-caret" aria-hidden="true"></span>';
		echo '<span class="vh-sl-headline">';
		printf( '<h2 class="vh-sl-name">%s</h2>', esc_html( (string) $row['target_name'] ) );
		printf(
			'<span class="vh-sl-where">%s</span>',
			esc_html(
				implode(
					' · ',
					array_filter(
						array(
							'' !== (string) $row['account_name'] ? (string) $row['account_name'] : (string) $row['account_id'],
							(string) $row['region'],
						)
					)
				)
			)
		);
		echo '</span>';
		echo '<div class="vh-sl-chips">';
		printf(
			'<span class="vh-chip vh-chip--bad">%s</span>',
			esc_html(
				sprintf(
					/* translators: %d: open routes. */
					_n( '%d way in, no credential needed', '%d ways in, no credential needed', count( $doors ), 'vulnhub' ),
					count( $doors )
				)
			)
		);

		if ( 'deprecated' === $state ) {
			printf(
				'<span class="vh-chip vh-chip--warn">%s</span>',
				esc_html(
					sprintf(
						/* translators: %s: runtime identifier, e.g. python3.6. */
						__( '%s — AWS no longer patches this runtime', 'vulnhub' ),
						(string) $row['runtime']
					)
				)
			);
		} elseif ( '' !== (string) $row['runtime'] ) {
			printf( '<span class="vh-chip">%s</span>', esc_html( (string) $row['runtime'] ) );
		}

		if ( $posture ) {
			printf(
				'<span class="vh-chip vh-chip--src">%s</span>',
				esc_html(
					(int) $posture['vulns'] > 0
						? sprintf(
							/* translators: 1: vendor severity, 2: the vendor's count of vulnerabilities. */
							__( 'Posture vendor: %1$s, %2$d vulnerabilities claimed', 'vulnhub' ),
							ucfirst( strtolower( (string) $posture['severity'] ) ),
							(int) $posture['vulns']
						)
						: sprintf(
							/* translators: %s: vendor severity. */
							__( 'Posture vendor: %s', 'vulnhub' ),
							ucfirst( strtolower( (string) $posture['severity'] ) )
						)
				)
			);
		}

		echo '</div></summary>';

		// The facts, each one read from somewhere nameable.
		echo '<dl class="vh-sl-facts">';
		self::fact(
			__( 'Account', 'vulnhub' ),
			'' !== (string) $row['account_name'] ? (string) $row['account_name'] : __( 'name not recorded', 'vulnhub' ),
			(string) $row['account_id']
		);
		self::fact( __( 'Region', 'vulnhub' ), (string) $row['region'], '' );
		self::fact(
			__( 'Runtime', 'vulnhub' ),
			'' !== (string) $row['runtime'] ? (string) $row['runtime'] : __( 'not stated', 'vulnhub' ),
			'deprecated' === $state
				? __( 'out of support — no security patches from AWS', 'vulnhub' )
				: ( 'current' === $state ? __( 'in support', 'vulnhub' ) : '' )
		);
		self::fact(
			__( 'Last changed', 'vulnhub' ),
			'' !== (string) $row['last_modified'] ? vh_date( (string) $row['last_modified'] ) : __( 'not stated', 'vulnhub' ),
			''
		);
		self::fact(
			__( 'Runs as', 'vulnhub' ),
			'' !== (string) $row['role_arn'] ? self::role_name( (string) $row['role_arn'] ) : __( 'not stated', 'vulnhub' ),
			(string) $row['role_arn']
		);

		if ( $asset ) {
			self::fact(
				__( 'Inventory record', 'vulnhub' ),
				(string) ( $asset['hostname'] ?? '' ),
				'' !== (string) ( $asset['patch_group'] ?? '' )
					/* translators: %s: patch group name. */
					? sprintf( __( 'patch group %s', 'vulnhub' ), (string) $asset['patch_group'] )
					: __( 'no patch group set', 'vulnhub' )
			);
		} else {
			self::fact(
				__( 'Inventory record', 'vulnhub' ),
				__( 'None — and that is correct', 'vulnhub' ),
				__( 'a function is not a machine: no patch group, no agent, nothing for Tenable to scan', 'vulnhub' )
			);
		}

		echo '</dl>';

		// The doors.
		self::render_front( $row );

		echo '<h3 class="vh-sl-h3">' . esc_html__( 'How it can be reached', 'vulnhub' ) . '</h3>';
		echo '<div class="vh-table-wrap"><table class="vh-table vh-sl-doors">';
		echo '<thead><tr>';
		echo '<th>' . esc_html__( 'Door', 'vulnhub' ) . '</th>';
		echo '<th>' . esc_html__( 'Route', 'vulnhub' ) . '</th>';
		echo '<th>' . esc_html__( 'Asks the caller for', 'vulnhub' ) . '</th>';
		echo '<th>' . esc_html__( 'Why it is open', 'vulnhub' ) . '</th>';
		echo '</tr></thead><tbody>';

		foreach ( $doors as $door ) {
			echo '<tr>';
			printf(
				'<td><span class="vh-sl-door">%s</span><span class="vh-meta">%s</span></td>',
				esc_html( self::door_kind( (string) $door['entry_type'] ) ),
				esc_html( (string) $door['entry_name'] )
			);
			printf( '<td><code>%s</code></td>', esc_html( (string) $door['route'] ) );
			printf( '<td>%s</td>', esc_html( __( 'nothing', 'vulnhub' ) ) );
			printf( '<td>%s</td>', esc_html( (string) $door['reason'] ) );
			echo '</tr>';
		}

		echo '</tbody></table></div>';

		if ( $posture ) {
			echo '<h3 class="vh-sl-h3">' . esc_html__( 'What the posture vendor reports', 'vulnhub' ) . '</h3>';

			echo '<div class="vh-table-wrap"><table class="vh-table">';
			echo '<thead><tr>';
			echo '<th>' . esc_html__( 'Severity', 'vulnhub' ) . '</th>';
			echo '<th>' . esc_html__( 'Finding', 'vulnhub' ) . '</th>';
			echo '<th>' . esc_html__( 'Detection', 'vulnhub' ) . '</th>';
			echo '<th>' . esc_html__( 'First seen', 'vulnhub' ) . '</th>';
			echo '</tr></thead><tbody>';

			foreach ( (array) $posture['findings'] as $finding ) {
				echo '<tr>';
				printf(
					'<td><span class="vh-pill vh-pill--%s">%s</span></td>',
					esc_attr( strtolower( (string) $finding['severity'] ) ),
					esc_html( ucfirst( strtolower( (string) $finding['severity'] ) ) )
				);
				printf( '<td>%s</td>', esc_html( (string) $finding['message'] ) );
				printf( '<td><code>%s</code></td>', esc_html( (string) $finding['detection'] ) );
				printf( '<td>%s</td>', esc_html( '' !== (string) $finding['observed'] ? vh_date( substr( (string) $finding['observed'], 0, 19 ) ) : '—' ) );
				echo '</tr>';
			}

			echo '</tbody></table></div>';

			echo '<p class="vh-sub vh-muted">' . esc_html(
				(int) $posture['vulns'] > 0
					? sprintf(
						/* translators: %d: the vendor's count of vulnerabilities inside the function package. */
						__( 'The vendor counts %d vulnerabilities inside this function\'s package. That is their number, not ours: it comes from scanning the deployed package, which this system does not do, and the feed carries no CVE for any of it — so there is nothing here to match against Tenable, nothing to put in a patch group, and no fixed version to quote. A function is deployed as a package, not patched in place, so the fix is a rebuild and redeploy by whoever owns the code.', 'vulnhub' ),
						(int) $posture['vulns']
					)
					: __( 'The vendor reports vulnerabilities inside this function\'s package without a count. Either way the feed carries no CVE, so there is nothing here to match against Tenable and nothing to put in a patch group — a function is deployed as a package, not patched in place, so the fix is a rebuild and redeploy by whoever owns the code.', 'vulnhub' )
			) . '</p>';

			if ( ! empty( $posture['exploits'] ) ) {
				echo '<p class="vh-sub">' . esc_html__( 'The vendor also states that at least one of those vulnerabilities has a known exploit. Combined with a door that asks the caller for nothing, that is the pairing worth treating as urgent.', 'vulnhub' ) . '</p>';
			}
		
		} else {
			echo '<p class="vh-sub vh-muted">' . esc_html__( 'No posture vendor finding is attached to this function. The exposure above stands on the AWS configuration alone.', 'vulnhub' ) . '</p>';
		}

		echo '<h3 class="vh-sl-h3">' . esc_html__( 'The path in', 'vulnhub' ) . '</h3>';
		self::topology( $row );

		echo '<div class="vh-sl-cols">';
		echo '<div><h3 class="vh-sl-h3">' . esc_html__( 'How this gets exploited', 'vulnhub' ) . '</h3><ol class="vh-sl-list">';
		foreach ( self::exploit_steps( $row ) as $step ) {
			printf( '<li>%s</li>', esc_html( $step ) );
		}
		echo '</ol></div>';

		echo '<div><h3 class="vh-sl-h3">' . esc_html__( 'How to shut it', 'vulnhub' ) . '</h3><ol class="vh-sl-list">';
		foreach ( self::mitigations( $row ) as $step ) {
			printf( '<li>%s</li>', esc_html( $step ) );
		}
		echo '</ol></div>';
		echo '</div>';

		echo '</details>';
	}

	/**
	 * What stands between the internet and each door, and who is allowed in.
	 *
	 * This is the question the diagram used to beg: the picture shows the
	 * internet reaching API Gateway with nothing drawn in between, which is
	 * usually the truth for these, but "usually" is not an answer anyone
	 * should act on. So each door states it outright -- the endpoint type,
	 * whether the AWS-issued hostname still resolves, the names that reach
	 * it, whether a web ACL is attached, and what the resource policy says
	 * about the caller.
	 *
	 * No firewall or NAT rule appears here, and that is not an omission. An
	 * API Gateway endpoint is an AWS-managed public endpoint: no VPC hop, no
	 * security group, no appliance of the estate's sits in front of one, so
	 * there is nothing of that kind to report. Where something genuinely
	 * does stand in front -- a web ACL, a CloudFront distribution, a policy
	 * that narrows the caller -- it is named.
	 *
	 * @param array<string,mixed> $row One function, with its doors.
	 */
	private static function render_front( array $row ): void {
		$doors = (array) $row['doors'];

		if ( ! $doors ) {
			return;
		}

		echo '<h3 class="vh-sl-h3">' . esc_html__( 'What stands in front', 'vulnhub' ) . '</h3>';
		echo '<div class="vh-table-wrap"><table class="vh-table vh-sl-front">';
		printf(
			'<thead><tr><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr></thead><tbody>',
			esc_html__( 'Door', 'vulnhub' ),
			esc_html__( 'Endpoint', 'vulnhub' ),
			esc_html__( 'Reachable at', 'vulnhub' ),
			esc_html__( 'In front of it', 'vulnhub' ),
			esc_html__( 'Allowed callers', 'vulnhub' )
		);

		foreach ( $doors as $door ) {
			$detail = (array) ( $door['detail'] ?? array() );
			$front  = self::front_of( $door );

			echo '<tr>';
			printf(
				'<td><span class="vh-sl-door">%s</span><span class="vh-meta">%s</span></td>',
				esc_html( self::door_kind( (string) $door['entry_type'] ) ),
				esc_html( (string) $door['route'] )
			);

			// Endpoint type, and whether the AWS-issued hostname still answers.
			$types = array_map( 'strtoupper', array_map( 'strval', (array) ( $detail['endpoint'] ?? array() ) ) );
			printf(
				'<td>%s%s</td>',
				esc_html( $types ? implode( ', ', $types ) : __( 'not stated', 'vulnhub' ) ),
				! empty( $detail['offSwitch'] )
					? '<span class="vh-meta">' . esc_html__( 'default execute-api hostname turned off', 'vulnhub' ) . '</span>'
					: ''
			);

			self::front_names_cell( $door );

			printf(
				'<td>%s</td>',
				$front
					? '<span class="vh-sl-front__yes">' . esc_html( (string) $front['label'] ) . '</span>'
						. ( '' !== (string) $front['meta'] ? '<span class="vh-meta">' . esc_html( (string) $front['meta'] ) . '</span>' : '' )
					: '<span class="vh-sl-front__no">' . esc_html__( 'nothing', 'vulnhub' ) . '</span>'
			);

			printf(
				'<td>%s</td>',
				wp_kses_post(
					// A row captured before the policy reader existed has no
					// parsed policy at all. Saying "no resource policy" for
					// one of those would be asserting something we never
					// looked at, which is the failure this page exists to
					// avoid; it says so instead, and the next sync fixes it.
					array_key_exists( 'policy', $detail )
						? self::callers_cell( (array) $detail['policy'] )
						: self::callers_unread( ! empty( $detail['apiPolicy'] ) )
				)
			);
			echo '</tr>';
		}

		echo '</tbody></table></div>';

		$cover = class_exists( 'VulnHub_AWS_Domains' ) ? VulnHub_AWS_Domains::coverage() : array();

		echo '<p class="vh-sub vh-muted">' . esc_html__(
			'"Reachable at" is the AWS-issued hostname plus any custom domain or Route 53 record that resolves to this API. Route 53 covers only the zones hosted in the accounts this login can read: a name served from elsewhere -- on-premises DNS, a registrar, a CDN -- will not appear, so treat the list as what we can see rather than as every way in.',
			'vulnhub'
		) . '</p>';

		if ( ! empty( $cover['denied'] ) || ! empty( $cover['failed'] ) ) {
			printf(
				'<p class="vh-sub vh-muted">%s</p>',
				esc_html(
					sprintf(
						/* translators: 1: accounts that refused the read, 2: accounts that failed. */
						__( 'Domain names could not be read in %1$d account(s) for want of a grant, and failed in %2$d more -- names in those accounts are missing from this table rather than absent from DNS.', 'vulnhub' ),
						(int) $cover['denied'],
						(int) $cover['failed']
					)
				)
			);
		}
	}

	/** Every name this door answers to, AWS-issued and otherwise. */
	private static function front_names_cell( array $door ): void {
		$url  = (string) $door['entry_url'];
		$rows = self::domains_for( self::api_id( $door ) );

		echo '<td>';

		if ( '' !== $url ) {
			printf( '<span class="vh-sl-host">%s</span>', esc_html( self::short_host( $url ) ) );
		}

		foreach ( array_slice( $rows, 0, 6 ) as $dom ) {
			printf(
				'<span class="vh-sl-host vh-sl-host--real">%s<span class="vh-sl-src">%s</span></span>',
				esc_html( (string) $dom['name'] ),
				esc_html( 'apigw' === (string) $dom['source'] ? __( 'custom domain', 'vulnhub' ) : __( 'Route 53', 'vulnhub' ) )
			);
		}

		if ( '' === $url && ! $rows ) {
			printf( '<span class="vh-meta">%s</span>', esc_html__( 'no hostname recorded', 'vulnhub' ) );
		}

		echo '</td>';
	}

	/**
	 * The resource policy in a sentence, or the absence of one.
	 *
	 * @param array<string,mixed> $policy Parsed policy from the capture.
	 */
	private static function callers_cell( array $policy ): string {
		if ( empty( $policy['present'] ) ) {
			return '<span class="vh-sl-front__no">' . esc_html__( 'any address on the internet', 'vulnhub' ) . '</span>'
				. '<span class="vh-meta">' . esc_html__( 'no resource policy on this API', 'vulnhub' ) . '</span>';
		}

		$parts = array();

		foreach ( array(
			'allow_ips' => __( 'only from', 'vulnhub' ),
			'deny_ips'  => __( 'all but', 'vulnhub' ),
			'vpce'      => __( 'only via VPC endpoint', 'vulnhub' ),
			'orgs'      => __( 'only the organisation', 'vulnhub' ),
			'accounts'  => __( 'only the principal', 'vulnhub' ),
		) as $key => $label ) {
			$list = array_map( 'strval', (array) ( $policy[ $key ] ?? array() ) );

			if ( ! $list ) {
				continue;
			}

			$shown   = array_slice( $list, 0, 6 );
			$more    = count( $list ) - count( $shown );
			$parts[] = '<span class="vh-sl-allow"><b>' . esc_html( $label ) . '</b> '
				. esc_html( implode( ', ', $shown ) )
				. ( $more > 0 ? ' ' . esc_html( sprintf( /* translators: %d: further entries. */ __( 'and %d more', 'vulnhub' ), $more ) ) : '' )
				. '</span>';
		}

		if ( ! $parts ) {
			return '<span class="vh-sl-front__no">' . esc_html__( 'any address on the internet', 'vulnhub' ) . '</span>'
				. '<span class="vh-meta">' . esc_html__( 'a policy is set, but nothing in it narrows the caller', 'vulnhub' ) . '</span>';
		}

		if ( ! empty( $policy['other'] ) ) {
			$parts[] = '<span class="vh-meta">' . esc_html__( 'and conditions this reader does not interpret -- read the policy itself', 'vulnhub' ) . '</span>';
		}

		return implode( '', $parts );
	}

	/** A door read before the policy reader existed. */
	private static function callers_unread( bool $has_policy ): string {
		return '<span class="vh-sl-front__no">' . esc_html__( 'not read yet', 'vulnhub' ) . '</span>'
			. '<span class="vh-meta">' . esc_html(
				$has_policy
					? __( 'this API carries a resource policy that predates the reader -- the next AWS sync will say what it allows', 'vulnhub' )
					: __( 'captured before the reader; the next AWS sync will fill this in', 'vulnhub' )
			) . '</span>';
	}

	/**
	 * The thing standing in front of one door, or [] when nothing is.
	 *
	 * @param array<string,mixed> $door One door.
	 * @return array<string,string>
	 */
	private static function front_of( array $door ): array {
		$detail = (array) ( $door['detail'] ?? array() );
		$waf    = array_filter( (array) ( $detail['waf'] ?? array() ) );
		$policy = (array) ( $detail['policy'] ?? array() );

		if ( $waf ) {
			$stage = (string) array_key_first( $waf );
			$arn   = (string) reset( $waf );
			$parts = explode( '/', $arn );

			return array(
				'icon'  => 'shield',
				'label' => __( 'WAF web ACL', 'vulnhub' ),
				'sub'   => '' !== $stage ? sprintf( /* translators: %s: stage name. */ __( 'on stage %s', 'vulnhub' ), $stage ) : '',
				'meta'  => count( $parts ) > 1 ? (string) $parts[ count( $parts ) - 2 ] : $arn,
			);
		}

		foreach ( self::domains_for( self::api_id( $door ) ) as $dom ) {
			$dist = (array) ( json_decode( (string) ( $dom['detail'] ?? '' ), true ) ?: array() );

			if ( '' !== (string) ( $dist['distribution'] ?? '' ) ) {
				return array(
					'icon'  => 'cloud',
					'label' => __( 'CloudFront', 'vulnhub' ),
					'sub'   => (string) $dom['name'],
					'meta'  => __( 'edge distribution', 'vulnhub' ),
				);
			}
		}

		if ( ! empty( $policy['restricts'] ) ) {
			return array(
				'icon'  => 'policy',
				'label' => __( 'Resource policy', 'vulnhub' ),
				'sub'   => __( 'narrows the caller', 'vulnhub' ),
				'meta'  => '',
			);
		}

		return array();
	}

	/** The REST API id behind one door. */
	private static function api_id( array $door ): string {
		$detail = (array) ( $door['detail'] ?? array() );
		$id     = (string) ( $detail['apiId'] ?? '' );

		return '' !== $id ? $id : (string) ( $door['entry_id'] ?? '' );
	}

	/**
	 * Names pointing at one API, read once per request.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	private static function domains_for( string $api_id ): array {
		if ( '' === $api_id || ! class_exists( 'VulnHub_AWS_Domains' ) ) {
			return array();
		}

		if ( ! isset( self::$domain_cache[ $api_id ] ) ) {
			self::$domain_cache[ $api_id ] = VulnHub_AWS_Domains::for_api( $api_id );
		}

		return self::$domain_cache[ $api_id ];
	}

	/** @var array<string,array<int,array<string,mixed>>> Names by API id. */
	private static array $domain_cache = array();

	private static function fact( string $label, string $value, string $meta ): void {
		echo '<div class="vh-sl-fact">';
		printf( '<dt>%s</dt>', esc_html( $label ) );
		printf( '<dd>%s', esc_html( $value ) );
		if ( '' !== $meta ) {
			printf( '<span class="vh-meta">%s</span>', esc_html( $meta ) );
		}
		echo '</dd></div>';
	}

	private static function role_name( string $arn ): string {
		$parts = explode( '/', $arn );

		return (string) end( $parts );
	}

	private static function door_kind( string $type ): string {
		switch ( $type ) {
			case 'rest':
				return __( 'API Gateway (REST)', 'vulnhub' );
			case 'http':
				return __( 'API Gateway (HTTP)', 'vulnhub' );
			case 'url':
				return __( 'Function URL', 'vulnhub' );
			case 'policy':
				return __( 'Resource policy', 'vulnhub' );
			default:
				return $type;
		}
	}


	/* =================================================================
	 * The picture
	 * ============================================================== */

	/**
	 * Internet to the affected function, hop by hop.
	 *
	 * Drawn from this row's own facts and nothing else: the doors AWS reported,
	 * the function they land on, the role it assumes, and the data stores the
	 * posture feed's path graph names. Where we have no graph the last column
	 * says so rather than drawing a guess -- an invented S3 bucket in a
	 * diagram is worse than an empty column, because somebody will act on it.
	 *
	 * @param array<string,mixed> $row One function, with its doors.
	 */
	private static function topology( array $row ): void {
		$doors   = array_slice( (array) $row['doors'], 0, 4 );
		$reaches = array_slice( (array) $row['reaches'], 0, 4 );
		$extra   = count( (array) $row['doors'] ) - count( $doors );

		$rows = max( 1, count( $doors ), count( $reaches ) );
		$rowh = 124;
		$top  = 48;
		$boxh = 96;
		$h    = $top + ( ( $rows - 1 ) * $rowh ) + $boxh + 30;

		/*
		 * The guard column is drawn only where there is a guard. An empty
		 * column headed "in front of it" on every card would read as a
		 * control that exists and is doing nothing, which is the opposite
		 * of the truth: for these endpoints there is usually nothing in the
		 * path at all, and the picture should say that by its shape.
		 */
		$fronts  = array();
		$guarded = false;

		foreach ( $doors as $i => $door ) {
			$fronts[ $i ] = self::front_of( (array) $door );
			$guarded      = $guarded || (bool) $fronts[ $i ];
		}

		if ( $guarded ) {
			$w    = 1760;
			$cols = array(
				'net'   => array( 16, 186 ),
				'front' => array( 260, 230 ),
				'door'  => array( 548, 262 ),
				'fn'    => array( 868, 262 ),
				'role'  => array( 1188, 262 ),
				'data'  => array( 1508, 236 ),
			);
		} else {
			$w    = 1560;
			$cols = array(
				'net'  => array( 16, 200 ),
				'door' => array( 274, 280 ),
				'fn'   => array( 612, 280 ),
				'role' => array( 950, 280 ),
				'data' => array( 1288, 256 ),
			);
		}

		$mid = static fn( int $count, int $index ): int => $top + (int) round( ( ( $rows - $count ) * $rowh ) / 2 ) + ( $index * $rowh );

		$uid = ++self::$svg_seq;

		printf(
			'<div class="vh-sl-topo"><svg viewBox="0 0 %d %d" role="img" aria-label="%s" preserveAspectRatio="xMidYMid meet">',
			$w,
			$h,
			esc_attr(
				sprintf(
					/* translators: %s: function name. */
					__( 'Path from the internet to %s', 'vulnhub' ),
					(string) $row['target_name']
				)
			)
		);

		// One marker per diagram: several of these cards share a page, and a
		// repeated id would have every arrow on the page point at the first.
		printf(
			'<defs><marker id="vh-sl-arrow-%d" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="context-stroke"/></marker></defs>',
			$uid
		);

		// Column captions.
		$captions = array(
			'net'   => __( 'Source', 'vulnhub' ),
			'front' => __( 'In front of it', 'vulnhub' ),
			'door'  => __( 'First hop', 'vulnhub' ),
			'fn'    => __( 'Affected hop', 'vulnhub' ),
			'role'  => __( 'Its permissions', 'vulnhub' ),
			'data'  => __( 'What it reaches', 'vulnhub' ),
		);

		$captions = array_intersect_key( $captions, $cols );

		foreach ( $captions as $key => $caption ) {
			printf(
				'<text x="%d" y="%d" class="vh-sl-cap">%s</text>',
				$cols[ $key ][0],
				24,
				esc_html( $caption )
			);
		}

		$net_y = $mid( 1, 0 );
		$fn_y  = $mid( 1, 0 );

		self::node(
			$cols['net'][0],
			$net_y,
			$cols['net'][1],
			$boxh,
			'net',
			'globe',
			__( 'The internet', 'vulnhub' ),
			__( 'anyone, anywhere', 'vulnhub' ),
			__( 'no account, no key', 'vulnhub' )
		);

		foreach ( $doors as $i => $door ) {
			$y   = $mid( count( $doors ), (int) $i );
			$url = (string) $door['entry_url'];

			self::node(
				$cols['door'][0],
				$y,
				$cols['door'][1],
				$boxh,
				'door',
				self::door_icon( (string) $door['entry_type'] ),
				self::door_kind( (string) $door['entry_type'] ),
				(string) $door['route'],
				'' !== $url ? self::short_host( $url ) : (string) $door['entry_name']
			);

			$front = (array) ( $fronts[ $i ] ?? array() );

			if ( $guarded && $front ) {
				self::node(
					$cols['front'][0],
					$y,
					$cols['front'][1],
					$boxh,
					'guard',
					(string) $front['icon'],
					(string) $front['label'],
					(string) $front['sub'],
					(string) $front['meta']
				);

				self::link( $cols['net'][0] + $cols['net'][1], $net_y + ( $boxh / 2 ), $cols['front'][0], $y + ( $boxh / 2 ), 'open', $uid );
				self::link( $cols['front'][0] + $cols['front'][1], $y + ( $boxh / 2 ), $cols['door'][0], $y + ( $boxh / 2 ), 'guard', $uid );
			} else {
				self::link( $cols['net'][0] + $cols['net'][1], $net_y + ( $boxh / 2 ), $cols['door'][0], $y + ( $boxh / 2 ), 'open', $uid );
			}

			self::link( $cols['door'][0] + $cols['door'][1], $y + ( $boxh / 2 ), $cols['fn'][0], $fn_y + ( $boxh / 2 ), 'open', $uid );
		}

		if ( $extra > 0 ) {
			printf(
				'<text x="%d" y="%d" class="vh-sl-more">%s</text>',
				$cols['door'][0],
				$top + ( ( $rows - 1 ) * $rowh ) + $boxh + 22,
				esc_html(
					sprintf(
						/* translators: %d: further open routes. */
						_n( 'and %d further open route', 'and %d further open routes', $extra, 'vulnhub' ),
						$extra
					)
				)
			);
		}

		self::node(
			$cols['fn'][0],
			$fn_y,
			$cols['fn'][1],
			$boxh,
			'fn',
			'lambda',
			(string) $row['target_name'],
			'' !== (string) $row['runtime'] ? (string) $row['runtime'] : __( 'runtime not stated', 'vulnhub' ),
			'deprecated' === (string) $row['runtime_state']
				? __( 'out of support', 'vulnhub' )
				: sprintf(
					/* translators: %s: region. */
					__( 'Lambda · %s', 'vulnhub' ),
					(string) $row['region']
				)
		);

		$role_y = $mid( 1, 0 );

		self::node(
			$cols['role'][0],
			$role_y,
			$cols['role'][1],
			$boxh,
			'role',
			'key',
			'' !== (string) $row['role_arn'] ? self::role_name( (string) $row['role_arn'] ) : __( 'Execution role', 'vulnhub' ),
			__( 'assumed on every call', 'vulnhub' ),
			__( 'IAM role', 'vulnhub' )
		);

		self::link( $cols['fn'][0] + $cols['fn'][1], $fn_y + ( $boxh / 2 ), $cols['role'][0], $role_y + ( $boxh / 2 ), 'trust', $uid );

		if ( $reaches ) {
			foreach ( $reaches as $i => $store ) {
				$y = $mid( count( $reaches ), (int) $i );

				self::node(
					$cols['data'][0],
					$y,
					$cols['data'][1],
					$boxh,
					'data',
					self::store_icon( (string) $store['kind'] ),
					(string) $store['name'],
					strtoupper( (string) $store['kind'] ),
					__( 'data', 'vulnhub' )
				);

				self::link( $cols['role'][0] + $cols['role'][1], $role_y + ( $boxh / 2 ), $cols['data'][0], $y + ( $boxh / 2 ), 'trust', $uid );
			}
		} else {
			self::node(
				$cols['data'][0],
				$role_y,
				$cols['data'][1],
				$boxh,
				'unknown',
				'unknown',
				__( 'Not established', 'vulnhub' ),
				__( 'no path graph for this', 'vulnhub' ),
				__( 'read the role policy', 'vulnhub' )
			);
			self::link( $cols['role'][0] + $cols['role'][1], $role_y + ( $boxh / 2 ), $cols['data'][0], $role_y + ( $boxh / 2 ), 'unknown', $uid );
		}

		echo '</svg></div>';

		echo '<p class="vh-sub vh-muted">' . esc_html__(
			'Every hop is read from AWS except the last column, which comes from the posture vendor\'s own path graph; where it has none, nothing is drawn. There is no network hop between the internet and the first box: API Gateway and a function URL are public AWS endpoints, so no VPC, subnet, security group or load balancer stands in the way — which is exactly why the server-shaped exposure rules never flag one of these.',
			'vulnhub'
		) . '</p>';
	}

	/**
	 * One box on the diagram: an icon, then up to two lines of name and two
	 * lines of detail, laid out so nothing leaves the box.
	 *
	 * SVG text does not wrap and does not clip itself, which is how the old
	 * version put "All S3 buckets in the acc…" through the right-hand edge of
	 * the picture. Lines are measured here, in the same units the text is
	 * drawn in, and the whole text block is clipped to the box as a backstop.
	 */
	private static function node( int $x, int $y, int $w, int $h, string $tone, string $icon, string $label, string $sub, string $meta ): void {
		$uid   = ++self::$svg_seq;
		$tx    = $x + 62;
		$avail = (float) ( $w - 62 - 14 );

		$blocks = array();

		foreach ( self::wrap_text( $label, $avail, 15.0, 0.585, 2 ) as $line ) {
			$blocks[] = array( 'vh-sl-node__label', $line, 20 );
		}

		if ( '' !== $sub ) {
			$blocks[] = array( 'vh-sl-node__sub', self::fit_text( $sub, $avail, 13.0, 0.55 ), 18 );
		}

		if ( '' !== $meta ) {
			$blocks[] = array( 'vh-sl-node__meta', self::fit_text( $meta, $avail, 12.0, 0.55 ), 16 );
		}

		$total = 0;

		foreach ( $blocks as $block ) {
			$total += (int) $block[2];
		}

		printf( '<g class="vh-sl-node vh-sl-node--%s">', esc_attr( $tone ) );

		// The untruncated value, for a hover tooltip and for screen readers.
		$full = $label;
		$full .= '' !== $sub ? ' — ' . $sub : '';
		$full .= '' !== $meta ? ' — ' . $meta : '';
		printf( '<title>%s</title>', esc_html( $full ) );

		printf( '<rect x="%d" y="%d" width="%d" height="%d" rx="12" class="vh-sl-node__box"/>', $x, $y, $w, $h );
		printf( '<rect x="%d" y="%d" width="4" height="%d" rx="2" class="vh-sl-node__edge"/>', $x, $y, $h );

		self::icon( $icon, $x + 15, $y + (int) round( ( $h - 36 ) / 2 ), 36 );

		printf(
			'<clipPath id="vh-sl-t%d"><rect x="%d" y="%d" width="%d" height="%d"/></clipPath><g clip-path="url(#vh-sl-t%d)">',
			$uid,
			$tx - 2,
			$y,
			(int) $avail + 8,
			$h,
			$uid
		);

		$cursor = $y + (int) round( ( $h - $total ) / 2 );

		foreach ( $blocks as $block ) {
			$cursor += (int) $block[2];
			printf(
				'<text x="%d" y="%d" class="%s">%s</text>',
				$tx,
				$cursor - 5,
				esc_attr( (string) $block[0] ),
				esc_html( (string) $block[1] )
			);
		}

		echo '</g></g>';
	}

	/**
	 * A line icon for one hop, drawn on a 24x24 grid into a tinted tile.
	 *
	 * Ours, not a vendor's: the strokes take the hop's own colour from CSS, so
	 * the picture follows the light and dark themes instead of carrying a
	 * second palette of fixed-colour images.
	 */
	private static function icon( string $kind, int $x, int $y, int $size ): void {
		$inner  = $size * 0.62;
		$offset = ( $size - $inner ) / 2;

		printf( '<rect x="%d" y="%d" width="%d" height="%d" rx="10" class="vh-sl-node__tile"/>', $x, $y, $size, $size );
		printf(
			'<g class="vh-sl-ico" transform="translate(%s %s) scale(%s)">%s</g>',
			esc_attr( (string) round( $x + $offset, 2 ) ),
			esc_attr( (string) round( $y + $offset, 2 ) ),
			esc_attr( (string) round( $inner / 24, 4 ) ),
			self::icon_paths( $kind )
		);
	}

	/**
	 * One glyph's shapes, for other pages that draw the same vocabulary.
	 *
	 * Shared rather than copied: the moment two pages keep their own icon
	 * set, the same thing starts being drawn two ways.
	 *
	 * @return string SVG shapes on a 24x24 grid.
	 */
	public static function glyph( string $kind ): string {
		return self::icon_paths( $kind );
	}

	/**
	 * The glyphs themselves. Fixed markup of ours, never anything from a feed.
	 *
	 * @return string SVG shapes on a 24x24 grid.
	 */
	private static function icon_paths( string $kind ): string {
		switch ( $kind ) {
			case 'globe':
				return '<circle cx="12" cy="12" r="9.2"/><path d="M2.8 12h18.4"/><ellipse cx="12" cy="12" rx="4.2" ry="9.2"/>';
			case 'gateway':
				return '<path d="M3.6 20.6V11a8.4 8.4 0 0 1 16.8 0v9.6"/><path d="M8 14.4h7.6"/><path d="M12.8 11.4l3.2 3-3.2 3"/>';
			case 'link':
				return '<path d="M10.2 13.8a4.6 4.6 0 0 0 6.5 0l2.4-2.4a4.6 4.6 0 0 0-6.5-6.5l-1.3 1.3"/><path d="M13.8 10.2a4.6 4.6 0 0 0-6.5 0l-2.4 2.4a4.6 4.6 0 0 0 6.5 6.5l1.3-1.3"/>';
			case 'policy':
				return '<path d="M6 2.8h8l4 4v14.4H6z"/><path d="M14 2.8v4h4"/><path d="M9 12.4h6"/><path d="M9 16.4h6"/>';
			case 'lambda':
				return '<path d="M5.6 20.6 12.2 3.4"/><path d="M9.8 10.6 18.4 20.6"/>';
			case 'key':
				return '<circle cx="7.8" cy="12" r="4.2"/><path d="M12 12h9.2"/><path d="M17.4 12v3.8"/><path d="M20.4 12v2.8"/>';
			case 'bucket':
				return '<ellipse cx="12" cy="6.2" rx="8.2" ry="2.8"/><path d="M3.8 6.2 5.7 19.1a2.4 2.4 0 0 0 2.4 2h7.8a2.4 2.4 0 0 0 2.4-2L20.2 6.2"/>';
			case 'queue':
				return '<rect x="3" y="5.6" width="18" height="12.8" rx="2.4"/><path d="M3.8 7 12 12.8 20.2 7"/>';
			case 'secret':
				return '<rect x="4.6" y="10.6" width="14.8" height="10.2" rx="2.4"/><path d="M8.2 10.6V7.8a3.8 3.8 0 0 1 7.6 0v2.8"/>';
			case 'shield':
				return '<path d="M12 2.9 4.6 6v6.1c0 4.6 3.1 7.7 7.4 8.9 4.3-1.2 7.4-4.3 7.4-8.9V6z"/><path d="M8.9 12.1l2.2 2.2 4-4.3"/>';
			case 'cloud':
				return '<path d="M7.4 19.1h9.2a4.3 4.3 0 0 0 .6-8.5 6 6 0 0 0-11.5-1.3 4.4 4.4 0 0 0 1.7 9.8z"/>';
			case 'unknown':
				return '<circle cx="12" cy="12" r="9.2"/><path d="M9.2 9.4a2.9 2.9 0 1 1 3.4 3.4v1.5"/><circle cx="12.6" cy="17.4" r="1" class="vh-sl-ico__dot"/>';
			case 'database':
			default:
				return '<ellipse cx="12" cy="6.2" rx="8.2" ry="3"/><path d="M3.8 6.2v11.6c0 1.7 3.7 3 8.2 3s8.2-1.3 8.2-3V6.2"/><path d="M3.8 12c0 1.7 3.7 3 8.2 3s8.2-1.3 8.2-3"/>';
		}
	}

	private static function door_icon( string $type ): string {
		switch ( $type ) {
			case 'url':
				return 'link';
			case 'policy':
				return 'policy';
			default:
				return 'gateway';
		}
	}

	private static function store_icon( string $kind ): string {
		$kind = strtolower( $kind );

		if ( false !== strpos( $kind, 's3' ) || false !== strpos( $kind, 'bucket' ) ) {
			return 'bucket';
		}

		if ( preg_match( '/sqs|sns|kinesis|event|queue|topic|stream/', $kind ) ) {
			return 'queue';
		}

		if ( preg_match( '/secret|kms|ssm|parameter|vault/', $kind ) ) {
			return 'secret';
		}

		return 'database';
	}

	/**
	 * Break a name over at most $max_lines, measured in drawing units.
	 *
	 * The width of a glyph is estimated from the font size: $ratio is the
	 * average advance of the app's sans as a fraction of its size, which is
	 * close enough for a box that already carries 14 units of slack, and it
	 * needs no font metrics on the server. Anything still over runs out with
	 * an ellipsis; the full value is on the node's title.
	 *
	 * @return string[] One or more lines, never empty.
	 */
	private static function wrap_text( string $text, float $avail, float $size, float $ratio, int $max_lines ): array {
		$text = trim( (string) preg_replace( '/\s+/u', ' ', $text ) );

		if ( '' === $text ) {
			return array( '' );
		}

		$chars = max( 4, (int) floor( $avail / max( 1.0, $size * $ratio ) ) );

		if ( mb_strlen( $text ) <= $chars ) {
			return array( $text );
		}

		// Break after a space, and also after a hyphen, underscore, dot or
		// slash: a function or role name is one long token with no spaces in
		// it, and cutting "retailer-css-bookings-fn-dev" by character count
		// gives "retailer-css-bookings-f / n-dev".
		$atoms = preg_split( '/(?<=[-_.\/])(?=[^\s])|(?<=\s)/u', $text, -1, PREG_SPLIT_NO_EMPTY );
		$atoms = false === $atoms ? array( $text ) : $atoms;

		$lines = array();
		$line  = '';

		foreach ( $atoms as $atom ) {
			if ( mb_strlen( rtrim( $line . $atom ) ) <= $chars ) {
				$line .= $atom;
				continue;
			}

			if ( '' !== trim( $line ) ) {
				$lines[] = rtrim( $line );
			}

			$line = $atom;

			// Still longer than the box on its own -- nothing left to break
			// on, so it is cut by character.
			while ( mb_strlen( rtrim( $line ) ) > $chars && count( $lines ) < $max_lines ) {
				$lines[] = mb_substr( $line, 0, $chars );
				$line    = mb_substr( $line, $chars );
			}
		}

		if ( '' !== trim( $line ) ) {
			$lines[] = rtrim( $line );
		}

		if ( count( $lines ) > $max_lines ) {
			$lines                   = array_slice( $lines, 0, $max_lines );
			$lines[ $max_lines - 1 ] = self::fit_text( $lines[ $max_lines - 1 ] . ' …', $avail, $size, $ratio );
		}

		return array() === $lines ? array( $text ) : $lines;
	}

	/**
	 * One line, cut on a word boundary rather than mid-word where it can be.
	 */
	private static function fit_text( string $text, float $avail, float $size, float $ratio ): string {
		$text  = trim( (string) preg_replace( '/\s+/u', ' ', $text ) );
		$chars = max( 4, (int) floor( $avail / max( 1.0, $size * $ratio ) ) );

		if ( mb_strlen( $text ) <= $chars ) {
			return $text;
		}

		$cut  = mb_substr( $text, 0, $chars - 1 );
		$stop = mb_strrpos( $cut, ' ' );

		if ( false !== $stop && $stop >= (int) floor( $chars * 0.55 ) ) {
			$cut = mb_substr( $cut, 0, $stop );
		}

		return rtrim( $cut, " ,.;:-·—" ) . '…';
	}

	private static function link( float $x1, float $y1, float $x2, float $y2, string $tone, int $uid ): void {
		$dx = ( $x2 - $x1 ) / 2;

		printf(
			'<path d="M%1$s,%2$s C%3$s,%2$s %4$s,%5$s %6$s,%5$s" class="vh-sl-link vh-sl-link--%7$s" marker-end="url(#vh-sl-arrow-%8$d)"/>',
			esc_attr( (string) round( $x1, 1 ) ),
			esc_attr( (string) round( $y1, 1 ) ),
			esc_attr( (string) round( $x1 + $dx, 1 ) ),
			esc_attr( (string) round( $x2 - $dx, 1 ) ),
			esc_attr( (string) round( $y2, 1 ) ),
			esc_attr( (string) round( $x2, 1 ) ),
			esc_attr( $tone ),
			$uid
		);
	}

	/**
	 * Counter behind the clip-path and arrow-marker ids.
	 *
	 * Several cards render on one page, so the ids have to be unique across
	 * the whole document, not just within one diagram.
	 *
	 * @var int
	 */
	private static int $svg_seq = 0;

	private static function clip( string $text, int $max ): string {
		return mb_strlen( $text ) > $max ? mb_substr( $text, 0, $max - 1 ) . '…' : $text;
	}

	private static function short_host( string $url ): string {
		$host = (string) wp_parse_url( $url, PHP_URL_HOST );

		return '' !== $host ? $host : $url;
	}

	/* =================================================================
	 * What it means, said from the facts on the row
	 * ============================================================== */

	/**
	 * @param array<string,mixed> $row One function, with its doors.
	 * @return string[]
	 */
	private static function exploit_steps( array $row ): array {
		$doors   = (array) $row['doors'];
		$first   = (array) ( $doors[0] ?? array() );
		$posture = (array) $row['posture'];
		$reaches = (array) $row['reaches'];
		$out     = array();

		$where = '' !== (string) ( $first['entry_url'] ?? '' )
			? self::short_host( (string) $first['entry_url'] )
			: (string) ( $first['entry_name'] ?? '' );

		$out[] = sprintf(
			/* translators: 1: route, 2: host or API name. */
			__( 'Find the endpoint. Nothing needs to be guessed: %1$s on %2$s answers requests from any address, and the endpoint is discoverable from certificate transparency logs, from anything that has ever called it, and from internet-wide scanning.', 'vulnhub' ),
			(string) ( $first['route'] ?? '' ),
			$where
		);

		$out[] = __( 'Call it. There is no sign-in step to get past and no key to steal — the method is configured to ask the caller for nothing, so a single HTTP request runs the function\'s code.', 'vulnhub' );

		if ( 'policy' === (string) ( $first['entry_type'] ?? '' ) ) {
			$out[] = __( 'In this case the door is the function\'s own resource policy, not a gateway: any AWS principal at all can invoke it directly, with no condition narrowing who.', 'vulnhub' );
		}

		$out[] = 'deprecated' === (string) $row['runtime_state']
			? sprintf(
				/* translators: %s: runtime identifier. */
				__( 'Attack the code it runs. The function is on %s, which AWS no longer patches, so any vulnerability in that runtime or in the libraries pinned to it stays open however long it sits there. Input handling is the usual way in: an injected payload, a deserialisation bug, a path that reaches the filesystem.', 'vulnhub' ),
				(string) $row['runtime']
			)
			: __( 'Attack the code it runs. Whatever the request body reaches — a parser, a database query it builds, a command it shells out to — is now reachable by an unauthenticated stranger, and the function has no WAF, rate limit or authorizer in front of it to slow that down.', 'vulnhub' );

		$out[] = sprintf(
			/* translators: %s: role name. */
			__( 'Use its permissions. Code running in the function assumes %s automatically; there is no second credential to obtain. Everything that role is allowed to do is now reachable from the internet, including any secret it can read.', 'vulnhub' ),
			'' !== (string) $row['role_arn'] ? self::role_name( (string) $row['role_arn'] ) : __( 'its execution role', 'vulnhub' )
		);

		if ( $reaches ) {
			$names = array();
			foreach ( $reaches as $store ) {
				$names[] = (string) $store['name'];
			}

			$out[] = sprintf(
				/* translators: %s: comma-separated data store names. */
				__( 'Reach the data. The posture vendor\'s path graph puts %s within that role\'s reach — which is where an invocation stops being a nuisance and becomes a data incident.', 'vulnhub' ),
				implode( ', ', array_slice( $names, 0, 4 ) )
			);
		} else {
			$out[] = __( 'Reach the data. We have no path graph for this one, so what the role can touch has to be read from its policy before you can say how far an invocation goes. Treat that as the next step, not as a clean result.', 'vulnhub' );
		}

		if ( $posture ) {
			$out[] = sprintf(
				/* translators: %s: vendor severity. */
				__( 'The posture vendor rates it %s and says it verified the invocation itself, rather than inferring it from configuration.', 'vulnhub' ),
				strtolower( (string) $posture['severity'] )
			);
		}

		return $out;
	}

	/**
	 * @param array<string,mixed> $row One function, with its doors.
	 * @return string[]
	 */
	private static function mitigations( array $row ): array {
		$doors = (array) $row['doors'];
		$types = array();

		foreach ( $doors as $door ) {
			$types[ (string) $door['entry_type'] ] = true;
		}

		$out = array();

		$out[] = __( 'Decide first whether it is meant to be public. A webhook receiver from a named third party, a health check, a public data feed — those are legitimate and the answer is to constrain them, not to close them. Anything else is a mistake and should be shut today.', 'vulnhub' );

		if ( isset( $types['rest'] ) || isset( $types['http'] ) ) {
			$out[] = __( 'Put something in front of the route. Set the method\'s authorization to IAM, a Cognito user pool or a Lambda authorizer; an API key on its own is a usage counter, not authentication, so it does not count here.', 'vulnhub' );
			$out[] = __( 'If it only ever needs to be reached from inside, change the API\'s endpoint type to PRIVATE and reach it over a VPC endpoint, or turn off the default execute-api endpoint so the AWS-issued hostname stops resolving.', 'vulnhub' );
			$out[] = __( 'If it must stay public, attach a resource policy that narrows it to the caller\'s source addresses, put WAF in front with rate limiting, and enable execution logging so a burst of unauthenticated calls is visible rather than merely billed.', 'vulnhub' );
		}

		if ( isset( $types['url'] ) ) {
			$out[] = __( 'Set the function URL\'s auth type to AWS_IAM, or delete the URL entirely if a gateway already fronts the function — two doors into one function means two things to get right forever.', 'vulnhub' );
		}

		if ( isset( $types['policy'] ) ) {
			$out[] = __( 'Rewrite the resource policy: name the principal that is supposed to invoke it, and add a condition on the source account or ARN. A statement with a wildcard principal and no condition lets any AWS account in the world call it.', 'vulnhub' );
		}

		if ( 'deprecated' === (string) $row['runtime_state'] ) {
			$out[] = sprintf(
				/* translators: %s: runtime identifier. */
				__( 'Move it off %s. An unsupported runtime is the part that cannot be compensated for: no patch is coming, so the only fix is the newer runtime, and doing it while the function is publicly callable is the wrong order — close the door first.', 'vulnhub' ),
				(string) $row['runtime']
			);
		}

		$out[] = sprintf(
			/* translators: %s: role name. */
			__( 'Cut the role down to exactly what the function uses. %s is what an attacker inherits, so every permission it does not need is free blast radius — read its CloudTrail history, then write the policy from that rather than from what was convenient at build time.', 'vulnhub' ),
			'' !== (string) $row['role_arn'] ? self::role_name( (string) $row['role_arn'] ) : __( 'The execution role', 'vulnhub' )
		);

		$out[] = __( 'Then keep it shut: this page is rebuilt from AWS on every sync, so a route that reverts to asking for nothing reappears here on its own.', 'vulnhub' );

		return $out;
	}

	/** @param array<string,mixed> $s Summary. */
	private static function render_coverage( array $s ): void {
		$runs    = VulnHub_AWS_Serverless::runs();
		$guarded = VulnHub_AWS_Serverless::guarded();

		echo '<section class="vh-card">';
		echo '<h2 class="vh-sl-h3">' . esc_html__( 'What was looked at', 'vulnhub' ) . '</h2>';

		if ( $guarded ) {
			$bits = array();

			foreach ( $guarded as $auth => $count ) {
				$bits[] = sprintf(
					/* translators: 1: number of routes, 2: what the route asks for. */
					_n( '%1$d asks for %2$s', '%1$d ask for %2$s', (int) $count, 'vulnhub' ),
					(int) $count,
					self::auth_words( (string) $auth )
				);
			}

			printf(
				'<p class="vh-sub">%s</p>',
				esc_html(
					sprintf(
						/* translators: %s: sentence listing what guarded routes ask for. */
						__( 'Routes that are not open: %s. Those are working as intended and are not listed above.', 'vulnhub' ),
						implode( '; ', $bits )
					)
				)
			);
		}

		$failed = array();

		foreach ( $runs as $run ) {
			if ( 'ok' !== (string) $run['status'] ) {
				$failed[] = $run;
			}
		}

		printf(
			'<p class="vh-sub">%s</p>',
			esc_html(
				sprintf(
					/* translators: 1: account/region pairs read, 2: pairs read only partly. */
					__( '%1$d account and region pairs were read; %2$d were refused part of what they asked for, so those are incomplete rather than clean.', 'vulnhub' ),
					(int) $s['scanned'],
					count( $failed )
				)
			)
		);

		if ( $failed ) {
			echo '<div class="vh-table-wrap"><table class="vh-table">';
			echo '<thead><tr>';
			echo '<th>' . esc_html__( 'Account', 'vulnhub' ) . '</th>';
			echo '<th>' . esc_html__( 'Region', 'vulnhub' ) . '</th>';
			echo '<th>' . esc_html__( 'What was refused', 'vulnhub' ) . '</th>';
			echo '</tr></thead><tbody>';

			foreach ( array_slice( $failed, 0, 40 ) as $run ) {
				echo '<tr>';
				printf(
					'<td>%s<span class="vh-meta">%s</span></td>',
					esc_html( '' !== (string) $run['account_name'] ? (string) $run['account_name'] : (string) $run['account_id'] ),
					esc_html( (string) $run['account_id'] )
				);
				printf( '<td>%s</td>', esc_html( (string) $run['region'] ) );
				printf( '<td class="vh-sl-note">%s</td>', esc_html( self::clip( (string) $run['note'], 220 ) ) );
				echo '</tr>';
			}

			echo '</tbody></table></div>';
		}

		echo '</section>';
	}

	private static function auth_words( string $auth ): string {
		switch ( $auth ) {
			case 'iam':
				return __( 'a signed AWS request', 'vulnhub' );
			case 'authorizer':
				return __( 'a token an authorizer checks', 'vulnhub' );
			case 'apikey':
				return __( 'an API key', 'vulnhub' );
			case 'cognito':
				return __( 'a Cognito sign-in', 'vulnhub' );
			default:
				return $auth;
		}
	}
}

