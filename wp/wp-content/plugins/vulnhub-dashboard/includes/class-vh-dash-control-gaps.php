<?php
/**
 * Control gaps: findings that repeat because a control is missing.
 *
 * The other screens answer "what is wrong, where". This one answers "what
 * keeps producing it". A finding that recurs across many accounts, many
 * environment tiers or many machines is rarely many separate mistakes; it
 * is one template, one pipeline or one missing guardrail stamping the same
 * mistake out again. Fixing the rows one by one clears the screen until the
 * next deploy. Fixing the cause stops the rows arriving.
 *
 * Three cuts, one per tab, all read from data the platform already keeps:
 *
 *   - Cloud causes: Plerion findings grouped by the cross-account key
 *     (VulnHub_Plerion_Cause) -- same detection, same kind of resource, same
 *     name with the environment and account taken out.
 *   - Cloud detections: the same findings by detection, with how many
 *     distinct causes sit behind them ("340 findings, 171 fixes").
 *   - Hosts: Tenable product rows (the Exposure-by-product grouping, read
 *     from the materialised summary) that reach enough machines to be a
 *     process problem rather than a machine problem.
 *
 * Each row names the strongest layer of control that would stop it
 * recurring -- org-wide prevention, pipeline prevention, auto-remediation,
 * or detect-and-ticket -- and a mechanism. That suggestion is a starting
 * point for a person, not an instruction, and every rule behind it is
 * filterable.
 *
 * Every count links to exactly the rows behind it: cloud rows to Cloud
 * Posture filtered by `cause` or `detection`, host rows to the
 * Vulnerabilities list with the same arguments the product widget uses.
 *
 * @package VulnHub\Dashboard
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_Dash_Control_Gaps {

	public const VIEW = 'control-gaps';
	public const SLUG = 'control-gaps';

	private const PER_PAGE = 50;

	public static function init(): void {
		add_filter( 'vulnhub_dash_views', array( __CLASS__, 'register_view' ), 20 );
		add_action( 'vulnhub_dash_render_view_' . self::VIEW, array( __CLASS__, 'render' ) );
		add_action( 'init', array( __CLASS__, 'ensure_page' ), 21 );
	}

	/**
	 * Placed after Cloud Posture when that page exists, else after
	 * Vulnerabilities.
	 *
	 * @param array<string,array<string,mixed>> $views Existing views.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_view( array $views ): array {
		$after = isset( $views['cspm'] ) ? 'cspm' : 'vulnerabilities';
		$def   = array(
			'title' => __( 'Control gaps', 'vulnhub' ),
			'slug'  => self::SLUG,
			'menu'  => __( 'Control gaps', 'vulnhub' ),
			'icon'  => 'M12 2l8 4v6c0 5-3.4 9-8 10-4.6-1-8-5-8-10V6zM9 12h6M12 9v6',
		);
		$out   = array();

		foreach ( $views as $key => $view ) {
			$out[ $key ] = $view;

			if ( $after === $key ) {
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

		if ( $page ) {
			$id = (int) $page->ID;
		} else {
			$id = wp_insert_post(
				array(
					'post_title'     => __( 'Control gaps', 'vulnhub' ),
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

	/* =================================================================
	 * Rules
	 * ============================================================== */

	/**
	 * When a repeated cause counts as a control gap.
	 *
	 * @return array{accounts:int,resources:int,tiers:int,assets:int}
	 */
	public static function thresholds(): array {
		$t = (array) apply_filters(
			'vulnhub_control_gap_thresholds',
			array(
				'accounts'  => 3,
				'resources' => 5,
				'tiers'     => 3,
				'assets'    => 5,
			)
		);

		return array(
			'accounts'  => max( 1, (int) ( $t['accounts'] ?? 3 ) ),
			'resources' => max( 1, (int) ( $t['resources'] ?? 5 ) ),
			'tiers'     => max( 1, (int) ( $t['tiers'] ?? 3 ) ),
			'assets'    => max( 1, (int) ( $t['assets'] ?? 5 ) ),
		);
	}

	/**
	 * The control layers, strongest first.
	 *
	 * @return array<string,string> key => label.
	 */
	public static function layers(): array {
		return array(
			'org'       => __( 'Org prevention', 'vulnhub' ),
			'pipeline'  => __( 'Pipeline prevention', 'vulnhub' ),
			'auto'      => __( 'Auto-remediation', 'vulnhub' ),
			'exception' => __( 'Exception', 'vulnhub' ),
			'detect'    => __( 'Detect and ticket', 'vulnhub' ),
		);
	}

	/**
	 * The suggested control for a cloud posture cause.
	 *
	 * Plerion detection ids are its public catalogue numbers. Where a
	 * detection is not listed, the finding's source family decides.
	 *
	 * @return array{layer:string,mechanism:string}
	 */
	public static function cloud_control( string $detection, string $source, string $type ): array {
		$no_auth   = array( 'org', __( 'SCP denying API routes and function URLs that have no authentication; exceptions by tag', 'vulnhub' ) );
		$outside   = array( 'org', __( 'RCP denying access from outside the organisation', 'vulnhub' ) );
		$by_id     = array(
			'PLERION-AWS-1178' => array( 'org', __( 'SCP denying leaving the organisation and closing the account', 'vulnhub' ) ),
			'PLERION-AWS-1179' => array( 'org', __( 'Organisation trail with network-activity events, set once for every account', 'vulnhub' ) ),
			'PLERION-AWS-93'   => $outside,
			'PLERION-AWS-89'   => $outside,
			'PLERION-AWS-551'  => $outside,
			'PLERION-AWS-530'  => $no_auth,
			'PLERION-AWS-98'   => $no_auth,
			'PLERION-AWS-755'  => $no_auth,
			'PLERION-AWS-194'  => $no_auth,
			'PLERION-AWS-558'  => $no_auth,
			'PLERION-AWS-887'  => array( 'auto', __( 'Firewall Manager security-group audit policy with automatic remediation', 'vulnhub' ) ),
		);
		$by_source = array(
			'ACCESS'      => array( 'org', __( 'RCP on STS allowing only your organisation and approved vendor accounts; keep a register of approved vendors', 'vulnhub' ) ),
			'IAM_ACCESS'  => array( 'org', __( 'SCP requiring a permission boundary on new roles; trim unused access with Access Analyzer', 'vulnhub' ) ),
			'GRAPH'       => $no_auth,
			'ATTACK_PATH' => $no_auth,
			'CWPP'        => array( 'pipeline', __( 'Dependency update bot on the repository, a pipeline gate on critical or known-exploited, scheduled base-image rebuilds', 'vulnhub' ) ),
			'CSPM'        => array( 'auto', __( 'AWS Config rule with automatic remediation', 'vulnhub' ) ),
		);

		$pick = $by_id[ $detection ] ?? $by_source[ strtoupper( $source ) ] ?? array( 'detect', __( 'Ticket the owner and fix', 'vulnhub' ) );

		// A running instance is patched, not rebuilt from a repository.
		if ( 'CWPP' === strtoupper( $source ) && 'AWS::EC2::Instance' === $type ) {
			$pick = array( 'auto', __( 'Patch policy (SSM Patch Manager) or a rebuilt image from an AMI pipeline', 'vulnhub' ) );
		}

		$out = array( 'layer' => (string) $pick[0], 'mechanism' => (string) $pick[1] );

		return (array) apply_filters( 'vulnhub_control_gap_cloud_control', $out, $detection, $source, $type );
	}

	/**
	 * The suggested control for a Tenable product row.
	 *
	 * @param array<string,mixed> $row A product row.
	 * @return array{layer:string,mechanism:string}
	 */
	public static function host_control( array $row ): array {
		$kind     = (string) ( $row['product_kind'] ?? '' );
		$findings = (int) ( $row['findings'] ?? 0 );
		$bundled  = (int) ( $row['bundled_findings'] ?? 0 );

		switch ( $kind ) {
			case 'os_package':
				$out = array( 'auto', __( 'Patch policy on a fixed schedule; CVEs with no vendor fix go to the exception register', 'vulnhub' ) );
				break;
			case 'os_update':
				$out = array( 'auto', __( 'Update rings with install deadlines', 'vulnhub' ) );
				break;
			case 'application':
				$out = $bundled * 2 > $findings
					? array( 'exception', __( 'Mostly files shipped inside the app: fixed when its vendor ships a build. Record an exception with a review date and keep the app current', 'vulnhub' ) )
					: array( 'auto', __( 'Managed app updates (third-party catalogue or the app\'s own auto-update); remove per-user installs', 'vulnhub' ) );
				break;
			case 'library':
				$out = array( 'pipeline', __( 'Find the software that ships this library; if you build it, a dependency bot and pipeline gate', 'vulnhub' ) );
				break;
			default:
				$out = array( 'detect', __( 'Ticket the owner and fix', 'vulnhub' ) );
		}

		$res = array( 'layer' => (string) $out[0], 'mechanism' => (string) $out[1] );

		return (array) apply_filters( 'vulnhub_control_gap_host_control', $res, $row );
	}

	/* =================================================================
	 * Rows -- one shape for the screen and the CSV
	 * ============================================================== */

	/** @return array<string,string> tab key => label. */
	public static function tabs(): array {
		$tabs = array();

		if ( self::cloud_ready() ) {
			$tabs['cloud']      = __( 'Cloud causes', 'vulnhub' );
			$tabs['detections'] = __( 'Cloud detections', 'vulnhub' );
		}

		$tabs['hosts'] = __( 'Hosts by product', 'vulnhub' );

		return $tabs;
	}

	private static function cloud_ready(): bool {
		return class_exists( 'VulnHub_Plerion_Cause' ) && class_exists( 'VulnHub_Plerion_Findings_Page' );
	}

	private static function sev_label( int $rank ): string {
		$names = array( 1 => 'critical', 2 => 'high', 3 => 'medium', 4 => 'low' );

		return $names[ $rank ] ?? 'info';
	}

	/**
	 * Rows for one tab, normalised so the table and the export share them.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function rows( string $tab ): array {
		$min = self::thresholds();
		$out = array();

		if ( 'cloud' === $tab && self::cloud_ready() ) {
			foreach ( VulnHub_Plerion_Cause::groups( $min ) as $g ) {
				$ctl   = self::cloud_control( (string) $g['detection_id'], (string) $g['source'], (string) $g['resource_type'] );
				$out[] = array(
					'tab'           => 'cloud',
					'name'          => '' !== (string) $g['stem'] ? (string) $g['stem'] : __( '(account setting)', 'vulnhub' ),
					'detail'        => (string) $g['detection_id'],
					'source'        => (string) $g['source'],
					'resource_type' => (string) $g['resource_type'],
					'sample'        => (string) $g['sample'],
					'severity'      => self::sev_label( (int) $g['sev_rank'] ),
					'findings'      => (int) $g['findings'],
					'resources'     => (int) $g['resources'],
					'accounts'      => (int) $g['accounts'],
					'tiers'         => (string) ( $g['tier_list'] ?? '' ),
					'tier_count'    => (int) $g['tiers'],
					'causes'        => 1,
					'layer'         => $ctl['layer'],
					'mechanism'     => $ctl['mechanism'],
					'url'           => VulnHub_Plerion_Findings_Page::url( array( 'cause' => (string) $g['cause_key'] ) ),
				);
			}
		} elseif ( 'detections' === $tab && self::cloud_ready() ) {
			foreach ( VulnHub_Plerion_Cause::families() as $g ) {
				$types = (string) $g['resource_types'];
				$ctl   = self::cloud_control( (string) $g['detection_id'], (string) $g['source'], false === strpos( $types, ',' ) ? $types : '' );
				$out[] = array(
					'tab'           => 'detections',
					'name'          => (string) $g['detection_id'],
					'detail'        => (string) $g['source'],
					'source'        => (string) $g['source'],
					'resource_type' => $types,
					'sample'        => (string) $g['sample'],
					'severity'      => self::sev_label( (int) $g['sev_rank'] ),
					'findings'      => (int) $g['findings'],
					'resources'     => (int) $g['resources'],
					'accounts'      => (int) $g['accounts'],
					'tiers'         => '',
					'tier_count'    => 0,
					'causes'        => (int) $g['causes'],
					'layer'         => $ctl['layer'],
					'mechanism'     => $ctl['mechanism'],
					'url'           => VulnHub_Plerion_Findings_Page::url( array( 'detection' => (string) $g['detection_id'] ) ),
				);
			}
		} elseif ( 'hosts' === $tab && class_exists( 'VulnHub_Dash_Widgets' ) ) {
			foreach ( VulnHub_Dash_Widgets::product_rows( 0, '' ) as $r ) {
				if ( (int) $r['assets'] < $min['assets'] ) {
					continue;
				}

				$ctl   = self::host_control( $r );
				$out[] = array(
					'tab'            => 'hosts',
					'name'           => (string) $r['product'],
					'detail'         => (string) $r['product_kind'],
					'source'         => 'TENABLE',
					'resource_type'  => (string) $r['component_class'],
					'sample'         => (string) ( $r['bundles'] ?? '' ),
					'severity'       => '',
					'findings'       => (int) $r['findings'],
					'resources'      => (int) $r['assets'],
					'accounts'       => 0,
					'tiers'          => '',
					'tier_count'     => 0,
					'causes'         => 1,
					'bundled'        => (int) ( $r['bundled_findings'] ?? 0 ),
					'bundled_assets' => (int) ( $r['bundled_assets'] ?? 0 ),
					'app_assets'     => (int) ( $r['app_assets'] ?? 0 ),
					'product_slug'   => (string) $r['product_slug'],
					'class'          => (string) $r['component_class'],
					'layer'          => $ctl['layer'],
					'mechanism'      => $ctl['mechanism'],
					'url'            => VulnHub_Dash_Widgets::product_findings_url( $r ),
				);
			}
		}

		return $out;
	}

	/**
	 * The headline numbers.
	 *
	 * @return array<string,int>
	 */
	public static function summary(): array {
		$s = array(
			'cloud_groups'   => 0,
			'cloud_in_gaps'  => 0,
			'cloud_total'    => 0,
			'cloud_causes'   => 0,
			'host_rows'      => 0,
			'host_in_gaps'   => 0,
			'host_total'     => 0,
		);

		if ( self::cloud_ready() ) {
			$groups              = self::rows( 'cloud' );
			$s['cloud_groups']   = count( $groups );
			$s['cloud_in_gaps']  = (int) array_sum( array_column( $groups, 'findings' ) );
			$s['cloud_total']    = VulnHub_Plerion_Cause::total();
			$s['cloud_causes']   = VulnHub_Plerion_Cause::distinct_causes();
		}

		if ( class_exists( 'VulnHub_Dash_Widgets' ) ) {
			$min = self::thresholds();

			foreach ( VulnHub_Dash_Widgets::product_rows( 0, '' ) as $r ) {
				$s['host_total'] += (int) $r['findings'];

				if ( (int) $r['assets'] >= $min['assets'] ) {
					++$s['host_rows'];
					$s['host_in_gaps'] += (int) $r['findings'];
				}
			}
		}

		return $s;
	}

	/* =================================================================
	 * Screen
	 * ============================================================== */

	private static function layer_chip( string $layer ): string {
		$labels = self::layers();

		return '<span class="vh-cg-layer vh-cg-layer--' . esc_attr( $layer ) . '">' . esc_html( $labels[ $layer ] ?? $layer ) . '</span>';
	}

	private static function pill( string $sev ): string {
		if ( '' === $sev ) {
			return '';
		}

		return sprintf( '<span class="vh-pill vh-pill--%s">%s</span>', esc_attr( $sev ), esc_html( ucfirst( $sev ) ) );
	}

	private static function n( int $v ): string {
		return esc_html( number_format_i18n( $v ) );
	}

	public static function render(): void {
		$tabs = self::tabs();

		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$tab  = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : '';
		$page = isset( $_GET['p'] ) ? max( 1, absint( wp_unslash( $_GET['p'] ) ) ) : 1;
		// phpcs:enable

		if ( ! isset( $tabs[ $tab ] ) ) {
			$tab = (string) array_key_first( $tabs );
		}

		$min = self::thresholds();
		$sum = self::summary();

		echo '<div class="vh-page-head"><div>';
		echo '<h1>' . esc_html__( 'Control gaps', 'vulnhub' ) . '</h1>';
		echo '<p class="vh-sub">' . esc_html__(
			'Findings that keep coming back because the same mistake is copied into many accounts, environments or machines. Each row is one cause, with the strongest control that would stop it recurring.',
			'vulnhub'
		) . '</p>';
		echo '</div></div>';

		self::render_tiles( $sum );

		echo '<p class="vh-meta vh-cg-rule">' . esc_html(
			sprintf(
				/* translators: 1: accounts, 2: resources, 3: tiers, 4: assets. */
				__( 'A cloud cause is listed when it repeats in %1$d+ accounts, on %2$d+ resources or in %3$d+ environment tiers. A host product is listed when it is on %4$d+ assets.', 'vulnhub' ),
				$min['accounts'],
				$min['resources'],
				$min['tiers'],
				$min['assets']
			)
		) . '</p>';

		echo '<nav class="vh-tabs vh-cg-tabs" aria-label="' . esc_attr__( 'Control gap views', 'vulnhub' ) . '">';
		foreach ( $tabs as $key => $label ) {
			printf(
				'<a class="vh-tabs__tab%s" href="%s"%s>%s</a>',
				$key === $tab ? ' is-active' : '',
				esc_url( self::url( array( 'tab' => $key ) ) ),
				$key === $tab ? ' aria-current="page"' : '',
				esc_html( $label )
			);
		}
		echo '</nav>';

		$rows  = self::rows( $tab );
		$total = count( $rows );

		echo '<div class="vh-cg-bar">';
		printf(
			'<p class="vh-meta">%s</p>',
			esc_html( sprintf( /* translators: %s: row count */ _n( '%s row', '%s rows', $total, 'vulnhub' ), number_format_i18n( $total ) ) )
		);
		if ( class_exists( 'VulnHub_Dash_Export' ) ) {
			VulnHub_Dash_Export::link_button( 'control_gaps', array( 'tab' => $tab ), '', $total, __( 'rows', 'vulnhub' ) );
		}
		echo '</div>';

		if ( ! $rows ) {
			echo '<div class="vh-panel"><p>' . esc_html__( 'Nothing repeats past the thresholds in this view.', 'vulnhub' ) . '</p></div>';
			return;
		}

		$slice = array_slice( $rows, ( $page - 1 ) * self::PER_PAGE, self::PER_PAGE );

		if ( 'hosts' === $tab ) {
			self::render_hosts( $slice );
		} elseif ( 'detections' === $tab ) {
			self::render_detections( $slice );
		} else {
			self::render_cloud( $slice );
		}

		self::render_paging( $total, $page, $tab );
	}

	/** @param array<string,int> $s */
	private static function render_tiles( array $s ): void {
		if ( ! class_exists( 'VulnHub_Dash_Charts' ) ) {
			return;
		}

		$tiles = array();

		if ( self::cloud_ready() ) {
			$tiles[] = array(
				'label' => __( 'Repeated cloud causes', 'vulnhub' ),
				'value' => $s['cloud_groups'],
				'tone'  => $s['cloud_groups'] > 0 ? 'warn' : 'good',
				'meta'  => sprintf(
					/* translators: 1: findings in groups, 2: all findings. */
					__( '%1$s of %2$s posture findings', 'vulnhub' ),
					number_format_i18n( $s['cloud_in_gaps'] ),
					number_format_i18n( $s['cloud_total'] )
				),
				'href'  => self::url( array( 'tab' => 'cloud' ) ),
			);
		}

		$tiles[] = array(
			'label' => __( 'Host products on many assets', 'vulnhub' ),
			'value' => $s['host_rows'],
			'tone'  => $s['host_rows'] > 0 ? 'warn' : 'good',
			'meta'  => sprintf(
				/* translators: 1: findings in rows, 2: all findings. */
				__( '%1$s of %2$s host findings', 'vulnhub' ),
				number_format_i18n( $s['host_in_gaps'] ),
				number_format_i18n( $s['host_total'] )
			),
			'href'  => self::url( array( 'tab' => 'hosts' ) ),
		);

		/*
		 * Not a combined "share in control gaps": on the host side nearly
		 * every finding sits on a product that is on five or more machines
		 * (distro CVEs with no vendor fix dominate), so a blended percentage
		 * reads close to 100% and says nothing. Findings per fix does: it is
		 * how much one change to a template or pipeline clears.
		 */
		if ( self::cloud_ready() && $s['cloud_causes'] > 0 ) {
			$tiles[] = array(
				'label' => __( 'Cloud findings per fix', 'vulnhub' ),
				'value' => number_format_i18n( $s['cloud_total'] / $s['cloud_causes'], 1 ) . '×', // a suffix, so stat_tile does not round it to a whole number
				'tone'  => 'muted',
				'meta'  => sprintf(
					/* translators: 1: findings, 2: distinct causes. */
					__( '%1$s findings from %2$s distinct causes', 'vulnhub' ),
					number_format_i18n( $s['cloud_total'] ),
					number_format_i18n( $s['cloud_causes'] )
				),
				'href'  => self::url( array( 'tab' => 'detections' ) ),
			);
		}

		echo '<div class="vh-tiles">';
		foreach ( $tiles as $tile ) {
			echo VulnHub_Dash_Charts::stat_tile( $tile ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}
		echo '</div>';
	}

	/** @param array<int,string> $heads */
	private static function thead( array $heads ): void {
		echo '<div class="vh-tablewrap"><table class="vh-table vh-cg-table"><thead><tr>';
		foreach ( $heads as $h ) {
			printf( '<th scope="col">%s</th>', esc_html( $h ) );
		}
		echo '</tr></thead><tbody>';
	}

	private static function control_cell( array $r ): string {
		return '<td class="vh-cg-control">' . self::layer_chip( (string) $r['layer'] )
			. '<div class="vh-meta">' . esc_html( (string) $r['mechanism'] ) . '</div></td>';
	}

	/** @param array<int,array<string,mixed>> $rows */
	private static function render_cloud( array $rows ): void {
		self::thead( array( __( 'Severity', 'vulnhub' ), __( 'Cause', 'vulnhub' ), __( 'Findings', 'vulnhub' ), __( 'Resources', 'vulnhub' ), __( 'Accounts', 'vulnhub' ), __( 'Tiers', 'vulnhub' ), __( 'Control', 'vulnhub' ) ) );

		foreach ( $rows as $r ) {
			echo '<tr>';
			echo '<td>' . self::pill( (string) $r['severity'] ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo '<td class="vh-cg-cause">';
			printf( '<div class="vh-cg-stem">%s</div>', esc_html( (string) $r['name'] ) );
			printf( '<div class="vh-meta"><span class="vh-mono">%s</span> · %s</div>', esc_html( (string) $r['detail'] ), esc_html( (string) $r['resource_type'] ) );
			printf( '<div class="vh-meta vh-cg-sample">%s</div>', esc_html( vh_trim( (string) $r['sample'], 140 ) ) );
			echo '</td>';
			printf( '<td class="vh-num"><a href="%s">%s</a></td>', esc_url( (string) $r['url'] ), self::n( (int) $r['findings'] ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			printf( '<td class="vh-num">%s</td>', self::n( (int) $r['resources'] ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			printf( '<td class="vh-num">%s</td>', self::n( (int) $r['accounts'] ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			printf( '<td class="vh-meta">%s</td>', esc_html( '' !== (string) $r['tiers'] ? (string) $r['tiers'] : '—' ) );
			echo self::control_cell( $r ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo '</tr>';
		}

		echo '</tbody></table></div>';
	}

	/** @param array<int,array<string,mixed>> $rows */
	private static function render_detections( array $rows ): void {
		self::thead( array( __( 'Severity', 'vulnhub' ), __( 'Detection', 'vulnhub' ), __( 'Findings', 'vulnhub' ), __( 'Distinct causes', 'vulnhub' ), __( 'Resources', 'vulnhub' ), __( 'Accounts', 'vulnhub' ), __( 'Control', 'vulnhub' ) ) );

		foreach ( $rows as $r ) {
			$findings = (int) $r['findings'];
			$causes   = max( 1, (int) $r['causes'] );

			echo '<tr>';
			echo '<td>' . self::pill( (string) $r['severity'] ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo '<td class="vh-cg-cause">';
			printf( '<div class="vh-cg-stem vh-mono">%s</div>', esc_html( (string) $r['name'] ) );
			printf( '<div class="vh-meta">%s · %s</div>', esc_html( (string) $r['source'] ), esc_html( (string) $r['resource_type'] ) );
			printf( '<div class="vh-meta vh-cg-sample">%s</div>', esc_html( vh_trim( (string) $r['sample'], 140 ) ) );
			echo '</td>';
			printf( '<td class="vh-num"><a href="%s">%s</a></td>', esc_url( (string) $r['url'] ), self::n( $findings ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo '<td class="vh-num">' . self::n( $causes ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			if ( $findings > $causes ) {
				printf(
					'<div class="vh-meta">%s</div>',
					esc_html( sprintf( /* translators: %s: findings per fix */ __( '%s findings per fix', 'vulnhub' ), number_format_i18n( $findings / $causes, 1 ) ) )
				);
			}
			echo '</td>';
			printf( '<td class="vh-num">%s</td>', self::n( (int) $r['resources'] ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			printf( '<td class="vh-num">%s</td>', self::n( (int) $r['accounts'] ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo self::control_cell( $r ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo '</tr>';
		}

		echo '</tbody></table></div>';
	}

	/** @param array<int,array<string,mixed>> $rows */
	private static function render_hosts( array $rows ): void {
		self::thead( array( __( 'Product', 'vulnhub' ), __( 'Assets', 'vulnhub' ), __( 'Findings', 'vulnhub' ), __( 'App update / bundled', 'vulnhub' ), __( 'Control', 'vulnhub' ) ) );

		foreach ( $rows as $r ) {
			$findings = (int) $r['findings'];
			$bundled  = (int) $r['bundled'];
			$app      = max( 0, $findings - $bundled );
			$url      = (string) $r['url'];

			echo '<tr>';
			echo '<td class="vh-cg-cause">';
			printf(
				'<div class="vh-cg-stem"><a href="%s">%s</a> %s</div>',
				esc_url( $url ),
				esc_html( (string) $r['name'] ),
				VulnHub_Dash_Widgets::product_kind_badge( (string) $r['detail'] ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			);
			if ( '' !== (string) $r['sample'] ) {
				printf( '<div class="vh-meta vh-cg-sample">%s</div>', esc_html( sprintf( /* translators: %s: library list */ __( 'Carries: %s', 'vulnhub' ), vh_trim( (string) $r['sample'], 120 ) ) ) );
			}
			echo '</td>';
			printf( '<td class="vh-num"><a href="%s">%s</a></td>', esc_url( $url ), self::n( (int) $r['resources'] ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			printf( '<td class="vh-num">%s</td>', self::n( $findings ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

			echo '<td class="vh-meta">';
			if ( $bundled > 0 && $app > 0 ) {
				printf(
					'<a href="%s">%s</a><br><a href="%s">%s</a>',
					esc_url( add_query_arg( 'comp', 'app', $url ) ),
					esc_html( sprintf( /* translators: %s: findings */ __( 'App update: %s', 'vulnhub' ), number_format_i18n( $app ) ) ),
					esc_url( add_query_arg( 'comp', 'bundled', $url ) ),
					esc_html( sprintf( /* translators: %s: findings */ __( 'Bundled: %s', 'vulnhub' ), number_format_i18n( $bundled ) ) )
				);
			} else {
				echo esc_html( $bundled > 0 ? __( 'All bundled', 'vulnhub' ) : __( 'All app update', 'vulnhub' ) );
			}
			echo '</td>';

			echo self::control_cell( $r ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo '</tr>';
		}

		echo '</tbody></table></div>';
	}

	private static function render_paging( int $total, int $page, string $tab ): void {
		$pages = (int) ceil( $total / self::PER_PAGE );

		if ( $pages <= 1 ) {
			return;
		}

		$page = min( $page, $pages );

		echo '<nav class="vh-paging">';
		if ( $page > 1 ) {
			printf( '<a class="vh-btn vh-btn--ghost vh-btn--sm" href="%s">%s</a>', esc_url( self::url( array( 'tab' => $tab, 'p' => $page - 1 ) ) ), esc_html__( 'Previous', 'vulnhub' ) );
		}
		printf( '<span class="vh-meta">%s</span>', esc_html( sprintf( /* translators: 1: page, 2: pages */ __( 'Page %1$d of %2$d', 'vulnhub' ), $page, $pages ) ) );
		if ( $page < $pages ) {
			printf( '<a class="vh-btn vh-btn--ghost vh-btn--sm" href="%s">%s</a>', esc_url( self::url( array( 'tab' => $tab, 'p' => $page + 1 ) ) ), esc_html__( 'Next', 'vulnhub' ) );
		}
		echo '</nav>';
	}
}

