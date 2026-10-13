<?php
/**
 * The Firewall policy page: what the Check Point import concluded.
 *
 * Four tabs:
 *   - Internet exposure: machine, port, who can reach it, how (its own
 *     public address or NAT), the rule that opens it, and the critical and
 *     high findings on that port.
 *   - Broad rules: rules that let the internet reach `Any` destination.
 *     Not mapped onto machines (that would call the whole estate exposed),
 *     so listed here as findings of their own.
 *   - NAT: static translations, automatic and manual.
 *   - Gateways: what is managed, version, installed policy.
 *   - Interfaces: each firewall's interfaces, what each faces, and the
 *     networks its topology lists behind it; the one AWS comes in on is
 *     marked.
 *   - AWS ↔ on-premises: the accept rules in that firewall's policy with
 *     AWS on one side and the rest of the network on the other.
 *
 * Read-only, like the connector behind it.
 *
 * @package VulnHub\CheckPoint
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class VulnHub_CheckPoint_Page {

	public const VIEW = 'firewall';
	public const SLUG = 'firewall-policy';

	private const PER_PAGE = 100;

	public static function init(): void {
		add_filter( 'vulnhub_dash_views', array( __CLASS__, 'register_view' ), 25 );
		add_action( 'vulnhub_dash_render_view_' . self::VIEW, array( __CLASS__, 'render' ) );
		add_action( 'init', array( __CLASS__, 'ensure_page' ), 22 );
	}

	/**
	 * After Cloud Network when present, else after Vulnerabilities.
	 *
	 * @param array<string,array<string,mixed>> $views
	 * @return array<string,array<string,mixed>>
	 */
	public static function register_view( array $views ): array {
		$after = isset( $views['network'] ) ? 'network' : 'vulnerabilities';
		$def   = array(
			'title' => __( 'Firewall policy', 'vulnhub' ),
			'slug'  => self::SLUG,
			'menu'  => __( 'Firewall policy', 'vulnhub' ),
			'icon'  => 'M3 5h18v14H3zM3 10h18M3 15h18M9 5v5M15 10v5M9 15v4',
		);
		$out   = array();

		foreach ( $views as $k => $v ) {
			$out[ $k ] = $v;

			if ( $after === $k ) {
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
			$p = get_post( (int) $map[ self::VIEW ] );

			if ( $p && 'trash' !== $p->post_status ) {
				return;
			}
		}

		$page = get_page_by_path( self::SLUG );
		$id   = $page ? (int) $page->ID : wp_insert_post(
			array(
				'post_title'     => __( 'Firewall policy', 'vulnhub' ),
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

	public static function url( array $args = array() ): string {
		$map  = (array) get_option( 'vulnhub_dash_pages', array() );
		$base = ! empty( $map[ self::VIEW ] ) ? (string) get_permalink( (int) $map[ self::VIEW ] ) : home_url( '/' . self::SLUG . '/' );

		return $args ? add_query_arg( $args, $base ) : $base;
	}

	private static function ports( int $from, int $to ): string {
		if ( 1 === $from && 65535 === $to ) {
			return __( 'any', 'vulnhub' );
		}

		return $from === $to ? (string) $from : $from . '–' . $to;
	}

	public static function render(): void {
		global $wpdb;

		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$tab  = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'exposure';
		$page = isset( $_GET['p'] ) ? max( 1, absint( wp_unslash( $_GET['p'] ) ) ) : 1;
		// phpcs:enable

		$tabs = array(
			'exposure' => __( 'Internet exposure', 'vulnhub' ),
			'broad'    => __( 'Broad rules', 'vulnhub' ),
			'nat'      => __( 'NAT and port forwards', 'vulnhub' ),
			'gateways' => __( 'Gateways', 'vulnhub' ),
			'ifaces'   => __( 'Interfaces', 'vulnhub' ),
			'hybrid'   => __( 'AWS ↔ on-premises', 'vulnhub' ),
		);
		$tab  = isset( $tabs[ $tab ] ) ? $tab : 'exposure';

		$c     = VulnHub_CheckPoint_Store::counts();
		$stamp = (string) get_option( VulnHub_CheckPoint_Store::STAMP_OPTION, '' );
		$broad = (array) get_option( VulnHub_CheckPoint_Store::BROAD_OPTION, array() );

		echo '<div class="vh-page-head"><div>';
		echo '<h1>' . esc_html__( 'Firewall policy', 'vulnhub' ) . ' <span class="vh-chip vh-chip--info">' . esc_html__( 'Check Point · read-only', 'vulnhub' ) . '</span></h1>';
		echo '<p class="vh-sub">' . esc_html__( 'Which machines the internet can reach through the firewall policy, on which ports, and the rule that opens each one. Read from Check Point management with a read-only session; nothing is ever changed there.', 'vulnhub' ) . '</p>';
		if ( '' !== $stamp ) {
			/* translators: %s: time ago. */
			echo '<p class="vh-meta">' . esc_html( sprintf( __( 'Policy read %s.', 'vulnhub' ), vh_ago( $stamp ) ) ) . '</p>';
		}
		echo '</div></div>';

		if ( 0 === $c['rules'] ) {
			echo '<div class="vh-panel"><p>' . esc_html(
				$c['gateways'] > 0
					? __( 'Gateways have been read, but not the rule base yet: the management server has not accepted a login. See the Check Point connector\'s last run under Administration → Integrations.', 'vulnhub' )
					: __( 'No policy has been read yet. Set up the Check Point connector under Administration → Integrations and run it.', 'vulnhub' )
			) . '</p></div>';

			if ( $c['gateways'] > 0 ) {
				self::render_gateways();
			}
			return;
		}

		if ( class_exists( 'VulnHub_Dash_Charts' ) ) {
			echo '<div class="vh-tiles">';
			foreach (
				array(
					array( 'label' => __( 'Reachable machines', 'vulnhub' ), 'value' => $c['assets'], 'tone' => $c['assets'] ? 'warn' : 'good', 'meta' => sprintf( /* translators: %s: count */ __( '%s ways in', 'vulnhub' ), number_format_i18n( $c['paths'] ) ), 'href' => self::url() ),
					array( 'label' => __( 'Allowed, not routed', 'vulnhub' ), 'value' => $c['latent'], 'tone' => 'muted', 'meta' => __( 'policy allows; no public address or NAT', 'vulnhub' ) ),
					array( 'label' => __( 'Broad rules', 'vulnhub' ), 'value' => count( (array) ( $broad['rules'] ?? array() ) ), 'tone' => ! empty( $broad['rules'] ) ? 'critical' : 'good', 'meta' => __( 'internet to any destination', 'vulnhub' ), 'href' => self::url( array( 'tab' => 'broad' ) ) ),
					array( 'label' => __( 'Rules read', 'vulnhub' ), 'value' => $c['rules'], 'tone' => 'muted', 'meta' => sprintf( /* translators: 1: gateways, 2: NAT rules */ __( '%1$s gateways · %2$s NAT rules', 'vulnhub' ), number_format_i18n( $c['gateways'] ), number_format_i18n( $c['nat'] ) ) ),
				) as $tile
			) {
				echo VulnHub_Dash_Charts::stat_tile( $tile ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			}
			echo '</div>';
		}

		echo '<nav class="vh-tabs" aria-label="' . esc_attr__( 'Firewall policy views', 'vulnhub' ) . '">';
		foreach ( $tabs as $k => $label ) {
			printf( '<a class="vh-tabs__tab%s" href="%s"%s>%s</a>', $k === $tab ? ' is-active' : '', esc_url( self::url( array( 'tab' => $k ) ) ), $k === $tab ? ' aria-current="page"' : '', esc_html( $label ) );
		}
		echo '</nav>';

		switch ( $tab ) {
			case 'broad':
				self::render_broad( (array) ( $broad['rules'] ?? array() ) );
				break;
			case 'nat':
				self::render_nat();
				break;
			case 'gateways':
				self::render_gateways();
				break;
			case 'ifaces':
				self::render_interfaces();
				break;
			case 'hybrid':
				self::render_hybrid();
				break;
			default:
				self::render_exposure( $page );
		}

		echo '<p class="vh-meta vh-cp-limits">' . esc_html__( 'How this is worked out: first match in rule order, inline layers included, static NAT applied. Only the first ordered layer of each package is read, so a port shown open may still be blocked by a later layer; a port shown closed is closed. Rules to Any destination are listed under Broad rules rather than mapped onto every machine.', 'vulnhub' ) . '</p>';
	}

	private static function render_exposure( int $page ): void {
		global $wpdb;

		$e = VulnHub_CheckPoint_Store::table( 'exposure' );
		$f = vh_table( 'findings' );
		$a = vh_table( 'assets' );

		$total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$e} WHERE latent = 0" ); // phpcs:ignore

		if ( ! $total ) {
			echo '<div class="vh-panel"><p>' . esc_html__( 'The policy opens no port from the internet to a known machine.', 'vulnhub' ) . '</p></div>';
			return;
		}

		$rows = (array) $wpdb->get_results( // phpcs:ignore
			$wpdb->prepare(
				"SELECT e.*, a.hostname,
					(SELECT COUNT(*) FROM {$f} f
					  WHERE f.asset_id = e.asset_id AND f.port BETWEEN e.port_from AND e.port_to
					    AND f.protocol = e.protocol AND f.state IN ('open','reopened')
					    AND f.severity IN ('critical','high') AND f.archived_at IS NULL) AS hot
				   FROM {$e} e LEFT JOIN {$a} a ON a.id = e.asset_id
				  WHERE e.latent = 0
				  ORDER BY hot DESC, e.reach = 'anyone' DESC, a.hostname, e.port_from
				  LIMIT %d OFFSET %d",
				self::PER_PAGE,
				( $page - 1 ) * self::PER_PAGE
			),
			ARRAY_A
		);

		echo '<div class="vh-tablewrap"><table class="vh-table"><thead><tr>';
		foreach ( array( __( 'Machine', 'vulnhub' ), __( 'Port', 'vulnhub' ), __( 'From', 'vulnhub' ), __( 'Reached on', 'vulnhub' ), __( 'Opened by', 'vulnhub' ), __( 'Critical / high findings on this port', 'vulnhub' ) ) as $h ) {
			printf( '<th scope="col">%s</th>', esc_html( $h ) );
		}
		echo '</tr></thead><tbody>';

		foreach ( $rows as $r ) {
			$host = '' !== (string) $r['hostname'] ? (string) $r['hostname'] : '#' . (int) $r['asset_id'];
			$link = class_exists( 'VulnHub_Dash_Portal' ) ? VulnHub_Dash_Portal::portal_url( 'assets', array( 'asset' => (int) $r['asset_id'] ) ) : '';

			echo '<tr>';
			printf( '<td><a href="%s">%s</a><div class="vh-meta vh-mono">%s</div></td>', esc_url( $link ), esc_html( $host ), esc_html( (string) $r['ip'] ) );
			printf( '<td class="vh-mono">%s/%s</td>', esc_html( (string) $r['protocol'] ), esc_html( self::ports( (int) $r['port_from'], (int) $r['port_to'] ) ) );
			printf(
				'<td>%s</td>',
				esc_html(
					'anyone' === $r['reach']
						? __( 'Anyone', 'vulnhub' )
						/* translators: %s: count of address objects */
						: sprintf( _n( '%s listed source', '%s listed sources', max( 1, (int) $r['sources'] ), 'vulnhub' ), number_format_i18n( max( 1, (int) $r['sources'] ) ) )
				)
			);
			printf(
				'<td class="vh-mono">%s<div class="vh-meta">%s</div></td>',
				esc_html( (string) $r['front'] ),
				esc_html( 'nat' === $r['via'] ? __( 'static NAT', 'vulnhub' ) : __( 'its own public address', 'vulnhub' ) )
			);
			printf( '<td>%s</td>', esc_html( (string) $r['rule_label'] ) );
			printf( '<td class="vh-num">%s</td>', (int) $r['hot'] > 0 ? '<strong>' . esc_html( number_format_i18n( (int) $r['hot'] ) ) . '</strong>' : '0' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo '</tr>';
		}

		echo '</tbody></table></div>';

		$pages = (int) ceil( $total / self::PER_PAGE );
		if ( $pages > 1 ) {
			echo '<nav class="vh-paging">';
			if ( $page > 1 ) {
				printf( '<a class="vh-btn vh-btn--ghost vh-btn--sm" href="%s">%s</a>', esc_url( self::url( array( 'p' => $page - 1 ) ) ), esc_html__( 'Previous', 'vulnhub' ) );
			}
			/* translators: 1: page, 2: pages */
			printf( '<span class="vh-meta">%s</span>', esc_html( sprintf( __( 'Page %1$d of %2$d', 'vulnhub' ), $page, $pages ) ) );
			if ( $page < $pages ) {
				printf( '<a class="vh-btn vh-btn--ghost vh-btn--sm" href="%s">%s</a>', esc_url( self::url( array( 'p' => $page + 1 ) ) ), esc_html__( 'Next', 'vulnhub' ) );
			}
			echo '</nav>';
		}

		if ( class_exists( 'VulnHub_Dash_Portal' ) ) {
			printf(
				'<p class="vh-meta">%s <a href="%s">%s</a></p>',
				esc_html__( 'These ways in also feed the threat context, which ranks the findings behind them by whether an exploit exists.', 'vulnhub' ),
				esc_url( VulnHub_Dash_Portal::portal_url( 'vulnerabilities', array( 'expo' => 'all' ) ) ),
				esc_html__( 'Open the reachable findings', 'vulnhub' )
			);
		}
	}

	/** @param array<int,array<string,mixed>> $rules */
	private static function render_broad( array $rules ): void {
		if ( ! $rules ) {
			echo '<div class="vh-panel"><p>' . esc_html__( 'No rule lets the internet reach any destination.', 'vulnhub' ) . '</p></div>';
			return;
		}

		echo '<p class="vh-meta">' . esc_html__( 'Each rule below lets traffic from outside reach any destination behind the gateway on these ports. They are not mapped onto machines here; narrow the destination and the machines behind it will show under Internet exposure.', 'vulnhub' ) . '</p>';
		echo '<div class="vh-tablewrap"><table class="vh-table"><thead><tr>';
		foreach ( array( __( 'Rule', 'vulnhub' ), __( 'From', 'vulnhub' ), __( 'Ports', 'vulnhub' ) ) as $h ) {
			printf( '<th scope="col">%s</th>', esc_html( $h ) );
		}
		echo '</tr></thead><tbody>';
		foreach ( $rules as $r ) {
			printf(
				'<tr><td>%s</td><td>%s</td><td class="vh-mono">%s</td></tr>',
				esc_html( (string) $r['rule'] ),
				esc_html( 'anyone' === $r['reach'] ? __( 'Anyone', 'vulnhub' ) : __( 'Listed sources', 'vulnhub' ) ),
				esc_html( (string) $r['ports'] )
			);
		}
		echo '</tbody></table></div>';
	}

	/**
	 * NAT: port forwards first (a manual rule that translates one address on
	 * one service -- "WAN port to LAN port"), then whole-address
	 * translations (automatic static NAT and manual rules on any service).
	 * Each row names the NAT rule it comes from so it can be found in
	 * SmartConsole. The first version listed only whole-address mappings and
	 * hid every port forward.
	 */
	private static function render_nat(): void {
		global $wpdb;

		$pol  = new VulnHub_CheckPoint_Policy( VulnHub_CheckPoint_Store::objects() );
		$rows = (array) $wpdb->get_results( 'SELECT package, rule_number, enabled, data FROM ' . VulnHub_CheckPoint_Store::table( 'nat' ) . ' ORDER BY package, position', ARRAY_A ); // phpcs:ignore

		$names = static function ( mixed $col ) use ( $pol ): string {
			$out = array();
			foreach ( (array) $col as $u ) {
				$u     = is_array( $u ) ? (string) ( $u['uid'] ?? '' ) : (string) $u;
				$out[] = $pol->name( $u );
			}
			return implode( ', ', array_slice( $out, 0, 3 ) ) . ( count( $out ) > 3 ? ' +' . ( count( $out ) - 3 ) : '' );
		};
		$is_any = static function ( mixed $col ) use ( $pol ): bool {
			$col = (array) $col;
			if ( ! $col ) {
				return true;
			}
			foreach ( $col as $u ) {
				$o = $pol->object( is_array( $u ) ? (string) ( $u['uid'] ?? '' ) : (string) $u );
				if ( 'cpmianyobject' === strtolower( (string) ( $o['type'] ?? '' ) ) || 'any' === strtolower( (string) ( $o['name'] ?? '' ) ) ) {
					return true;
				}
			}
			return false;
		};

		$fwd   = array();
		$whole = array();

		foreach ( $rows as $row ) {
			$r  = (array) json_decode( (string) $row['data'], true );
			$od = $pol->column( $r['original-destination'] ?? array() );
			$td = $pol->column( $r['translated-destination'] ?? array() );

			if ( 1 !== count( $od['ranges'] ) || 1 !== count( $td['ranges'] ) ) {
				continue;
			}
			[ $a, $b ] = $od['ranges'][0];
			[ $c, $d ] = $td['ranges'][0];
			if ( $a !== $b || $c !== $d || $a === $c ) {
				continue;
			}

			$svc  = $r['original-service'] ?? array();
			$tsvc = $r['translated-service'] ?? array();
			$item = array(
				'rule'    => (string) $row['package'] . ' #' . (string) $row['rule_number'],
				'on'      => (int) $row['enabled'] === 1,
				'pub'     => VulnHub_CheckPoint_Policy::int2ip( $a ),
				'public'  => ! VulnHub_CheckPoint_Policy::is_private( $a ),
				'priv'    => VulnHub_CheckPoint_Policy::int2ip( $c ),
				'to'      => $names( $r['translated-destination'] ?? array() ),
				'from'    => $is_any( $r['original-source'] ?? array() ) ? __( 'Anyone', 'vulnhub' ) : $names( $r['original-source'] ?? array() ),
				'port'    => $is_any( $svc ) ? '' : ( VulnHub_CheckPoint_Policy::describe_ports( $pol->rule_services( array( 'service' => $svc ) ) ) ?: $names( $svc ) ),
				'tport'   => $is_any( $tsvc ) || 'original' === strtolower( $names( $tsvc ) ) ? __( 'same', 'vulnhub' ) : ( VulnHub_CheckPoint_Policy::describe_ports( $pol->rule_services( array( 'service' => $tsvc ) ) ) ?: $names( $tsvc ) ),
			);

			if ( '' !== $item['port'] ) {
				$fwd[] = $item;
			} else {
				$whole[] = $item;
			}
		}

		// Automatic static NAT lives on the host object, not in a rule.
		foreach ( VulnHub_CheckPoint_Store::objects() as $o ) {
			$ns = (array) ( $o['nat-settings'] ?? array() );
			if ( empty( $ns['auto-rule'] ) || 'static' !== strtolower( (string) ( $ns['method'] ?? '' ) ) ) {
				continue;
			}
			$priv = VulnHub_CheckPoint_Policy::ip2int( (string) ( $o['ipv4-address'] ?? '' ) );
			$pub  = VulnHub_CheckPoint_Policy::ip2int( (string) ( $ns['ipv4-address'] ?? '' ) );
			if ( null === $priv || null === $pub || $priv === $pub ) {
				continue;
			}
			$whole[] = array(
				'rule'   => __( 'automatic (on the object)', 'vulnhub' ),
				'on'     => true,
				'pub'    => VulnHub_CheckPoint_Policy::int2ip( $pub ),
				'public' => ! VulnHub_CheckPoint_Policy::is_private( $pub ),
				'priv'   => VulnHub_CheckPoint_Policy::int2ip( $priv ),
				'to'     => (string) ( $o['name'] ?? '' ),
				'from'   => __( 'Anyone', 'vulnhub' ),
				'port'   => '',
				'tport'  => '',
			);
		}

		$sort = static fn( array $x, array $y ): int => array( ! $x['public'], VulnHub_CheckPoint_Policy::ip2int( $x['pub'] ), $x['port'] ) <=> array( ! $y['public'], VulnHub_CheckPoint_Policy::ip2int( $y['pub'] ), $y['port'] );
		usort( $fwd, $sort );
		usort( $whole, $sort );

		$pf = count( array_filter( $fwd, static fn( array $x ): bool => $x['public'] && $x['on'] ) );
		$pa = count( array_filter( $fwd, static fn( array $x ): bool => $x['public'] && $x['on'] && __( 'Anyone', 'vulnhub' ) === $x['from'] ) );

		printf(
			'<p class="vh-meta">%s</p>',
			esc_html(
				sprintf(
					/* translators: 1: forwards, 2: from anyone, 3: whole-address. */
					__( '%1$d port forwards on public addresses (%2$d of them for anyone) and %3$d whole-address translations, read from the NAT rule base and from host objects\' automatic NAT. A port forward opens nothing by itself: the access rules decide whether the traffic is allowed, which Internet exposure works out.', 'vulnhub' ),
					$pf,
					$pa,
					count( $whole )
				)
			)
		);

		$table = static function ( string $title, array $list, bool $ports ): void {
			printf( '<h3 class="vh-h3">%s <span class="vh-meta">%s</span></h3>', esc_html( $title ), esc_html( number_format_i18n( count( $list ) ) ) );
			if ( ! $list ) {
				echo '<div class="vh-panel"><p>' . esc_html__( 'None.', 'vulnhub' ) . '</p></div>';
				return;
			}
			$head = $ports
				? array( __( 'Public address', 'vulnhub' ), __( 'Public port', 'vulnhub' ), __( 'Allowed from', 'vulnhub' ), __( 'Translates to', 'vulnhub' ), __( 'Internal port', 'vulnhub' ), __( 'NAT rule', 'vulnhub' ) )
				: array( __( 'Original address', 'vulnhub' ), __( 'Translates to', 'vulnhub' ), __( 'Applies to', 'vulnhub' ), __( 'NAT rule', 'vulnhub' ) );
			echo '<div class="vh-tablewrap"><table class="vh-table"><thead><tr>';
			foreach ( $head as $h ) {
				printf( '<th scope="col">%s</th>', esc_html( $h ) );
			}
			echo '</tr></thead><tbody>';
			foreach ( $list as $x ) {
				$flag = ( $x['public'] ? '' : ' <span class="vh-chip">' . esc_html__( 'internal address', 'vulnhub' ) . '</span>' ) . ( $x['on'] ? '' : ' <span class="vh-chip vh-chip--muted">' . esc_html__( 'disabled', 'vulnhub' ) . '</span>' );
				echo '<tr>';
				printf( '<td class="vh-mono">%s%s</td>', esc_html( $x['pub'] ), $flag ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				if ( $ports ) {
					printf( '<td class="vh-mono">%s</td>', esc_html( $x['port'] ) );
					printf( '<td>%s</td>', __( 'Anyone', 'vulnhub' ) === $x['from'] ? '<span class="vh-chip vh-chip--warn">' . esc_html( $x['from'] ) . '</span>' : esc_html( $x['from'] ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				}
				printf( '<td><span class="vh-mono">%s</span><div class="vh-meta">%s</div></td>', esc_html( $x['priv'] ), esc_html( $x['to'] ) );
				if ( $ports ) {
					printf( '<td class="vh-mono">%s</td>', esc_html( $x['tport'] ) );
				} else {
					printf( '<td>%s</td>', esc_html( $x['from'] ) );
				}
				printf( '<td>%s</td>', esc_html( $x['rule'] ) );
				echo '</tr>';
			}
			echo '</tbody></table></div>';
		};

		$table( __( 'Port forwards (public port → internal server and port)', 'vulnhub' ), $fwd, true );
		$table( __( 'Whole-address translations (every port)', 'vulnhub' ), $whole, false );
	}

	/** Each firewall's interfaces, with what its topology lists behind them. */
	private static function render_interfaces(): void {
		$m = VulnHub_CheckPoint_Interfaces::model();

		if ( ! $m['gateways'] ) {
			echo '<div class="vh-panel"><p>' . esc_html__( 'No gateway interfaces were in the policy read.', 'vulnhub' ) . '</p></div>';
			return;
		}

		$kind = array(
			'internal' => __( 'Internal', 'vulnhub' ),
			'dmz'      => __( 'DMZ', 'vulnhub' ),
			'internet' => __( 'Internet', 'vulnhub' ),
		);
		$e    = $m['entry'];

		echo '<p class="vh-meta">' . esc_html__( 'Read from each gateway\'s own interface settings. "Behind it" is the interface\'s topology: the networks the firewall accepts traffic from on that interface (its anti-spoofing list). An internal interface with no list covers the subnet it is plugged into.', 'vulnhub' ) . '</p>';

		foreach ( $m['gateways'] as $g ) {
			printf(
				'<h3 class="vh-h3">%s <span class="vh-meta">%s</span></h3>',
				esc_html( (string) $g['name'] ),
				esc_html( trim( ( '' !== (string) $g['site'] ? $g['site'] : __( 'site not known', 'vulnhub' ) ) . ' · ' . ( 'cluster' === $g['kind'] ? __( 'cluster', 'vulnhub' ) : __( 'gateway', 'vulnhub' ) ) . ( '' !== (string) $g['policy'] ? ' · ' . $g['policy'] : '' ) ) )
			);

			echo '<div class="vh-tablewrap"><table class="vh-table vh-cp-ifaces"><thead><tr>';
			foreach ( array( __( 'Interface', 'vulnhub' ), __( 'Address', 'vulnhub' ), __( 'Faces', 'vulnhub' ), __( 'Behind it', 'vulnhub' ), __( 'AWS networks', 'vulnhub' ) ) as $h ) {
				printf( '<th scope="col">%s</th>', esc_html( $h ) );
			}
			echo '</tr></thead><tbody>';

			foreach ( $g['ifaces'] as $i ) {
				$is_entry = $e && $e['gateway'] === $g['name'] && $e['iface'] === $i['name'];
				$listed   = array_slice( (array) $i['behind'], 1 );

				echo '<tr>';
				printf( '<td class="vh-mono">%s%s</td>', esc_html( (string) $i['name'] ), $is_entry ? ' <span class="vh-chip vh-chip--good">' . esc_html__( 'AWS comes in here', 'vulnhub' ) . '</span>' : '' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				printf( '<td class="vh-mono">%s<div class="vh-meta">%s</div></td>', esc_html( (string) $i['ip'] ), esc_html( (string) $i['cidr'] ) );
				printf( '<td>%s</td>', esc_html( $kind[ (string) $i['kind'] ] ?? (string) $i['kind'] ) );

				echo '<td>';
				if ( 'internet' === $i['kind'] ) {
					echo '—';
				} elseif ( ! $listed ) {
					echo esc_html__( 'its own subnet', 'vulnhub' );
				} else {
					/* translators: 1: count, 2: topology group. */
					echo '<details><summary>' . esc_html( sprintf( _n( '%1$d network · %2$s', '%1$d networks · %2$s', count( $listed ), 'vulnhub' ), count( $listed ), (string) $i['spec'] ) ) . '</summary><ul class="vh-cp-behind" style="margin:6px 0 0;padding-left:16px;max-height:280px;overflow:auto">';
					foreach ( array_slice( $listed, 0, 120 ) as $b ) {
						printf( '<li><span class="vh-mono">%s</span> %s</li>', esc_html( VulnHub_CheckPoint_Interfaces::span( (int) $b[0], (int) $b[1] ) ), esc_html( (string) $b[2] ) );
					}
					if ( count( $listed ) > 120 ) {
						/* translators: %d: more networks. */
						echo '<li class="vh-meta">' . esc_html( sprintf( __( '+%d more', 'vulnhub' ), count( $listed ) - 120 ) ) . '</li>';
					}
					echo '</ul></details>';
				}
				echo '</td>';

				printf( '<td class="vh-num">%s</td>', (int) $i['aws'] > 0 ? esc_html( number_format_i18n( (int) $i['aws'] ) ) : '' );
				echo '</tr>';
			}

			echo '</tbody></table></div>';
		}
	}

	/** Accept rules between AWS and the rest of the network. */
	private static function render_hybrid(): void {
		$m = VulnHub_CheckPoint_Interfaces::model();
		$e = $m['entry'];

		if ( ! $e ) {
			echo '<div class="vh-panel"><p>' . esc_html__( 'No firewall interface lists AWS VPC ranges behind it, so the firewall AWS comes in through is not known. This needs the AWS network capture and the firewall policy.', 'vulnhub' ) . '</p></div>';
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$want  = isset( $_GET['dir'] ) ? sanitize_key( wp_unslash( $_GET['dir'] ) ) : '';
		$rules = $m['rules'];
		$dirs  = array(
			''           => __( 'All', 'vulnhub' ),
			'aws-onprem' => __( 'AWS → on-premises', 'vulnhub' ),
			'onprem-aws' => __( 'On-premises → AWS', 'vulnhub' ),
			'both'       => __( 'Both ways', 'vulnhub' ),
			'wide'       => __( 'Every port or Any', 'vulnhub' ),
		);
		$want  = isset( $dirs[ $want ] ) ? $want : '';

		printf(
			'<p class="vh-meta">%s</p>',
			esc_html(
				sprintf(
					/* translators: 1: firewall, 2: site, 3: interface, 4: subnet, 5: AWS ranges, 6: policy. */
					__( 'AWS comes in through %1$s (%2$s) on interface %3$s, %4$s, whose topology lists %5$d AWS VPC ranges. These are the accept rules in %6$s with an AWS range on one side and the rest of the network (or Any) on the other. A side counts as AWS only when it names a range inside a VPC; an RFC 1918 summary that happens to cover AWS does not.', 'vulnhub' ),
					$e['gateway'],
					'' !== (string) $e['site'] ? $e['site'] : '?',
					$e['iface'],
					$e['cidr'],
					(int) $e['aws'],
					$e['policy']
				)
			)
		);

		echo '<nav class="vh-cp-filter" style="display:flex;flex-wrap:wrap;gap:6px;margin:8px 0 14px" aria-label="' . esc_attr__( 'Direction', 'vulnhub' ) . '">';
		foreach ( $dirs as $k => $label ) {
			$n = '' === $k ? count( $rules ) : count( array_filter( $rules, static fn( array $r ): bool => 'wide' === $k ? ( ! empty( $r['anyport'] ) || ! empty( $r['broad'] ) ) : $k === $r['dir'] ) );
			printf( '<a class="vh-chip%s" href="%s">%s · %s</a> ', $k === $want ? ' vh-chip--filter' : '', esc_url( self::url( array_filter( array( 'tab' => 'hybrid', 'dir' => $k ) ) ) ), esc_html( $label ), esc_html( number_format_i18n( $n ) ) );
		}
		echo '</nav>';

		if ( '' !== $want ) {
			$rules = array_values( array_filter( $rules, static fn( array $r ): bool => 'wide' === $want ? ( ! empty( $r['anyport'] ) || ! empty( $r['broad'] ) ) : $want === $r['dir'] ) );
		}

		if ( ! $rules ) {
			echo '<div class="vh-panel"><p>' . esc_html__( 'No rule matches.', 'vulnhub' ) . '</p></div>';
			return;
		}

		$arrow = array(
			'aws-onprem' => __( 'AWS → on-prem', 'vulnhub' ),
			'onprem-aws' => __( 'on-prem → AWS', 'vulnhub' ),
			'both'       => __( 'both ways', 'vulnhub' ),
		);

		echo '<div class="vh-tablewrap"><table class="vh-table"><thead><tr>';
		foreach ( array( __( 'Rule', 'vulnhub' ), __( 'Direction', 'vulnhub' ), __( 'From', 'vulnhub' ), __( 'To', 'vulnhub' ), __( 'Ports', 'vulnhub' ) ) as $h ) {
			printf( '<th scope="col">%s</th>', esc_html( $h ) );
		}
		echo '</tr></thead><tbody>';

		foreach ( $rules as $r ) {
			$flags = array();
			if ( ! empty( $r['anyport'] ) ) {
				$flags[] = '<span class="vh-chip vh-chip--bad">' . esc_html__( 'every port', 'vulnhub' ) . '</span>';
			}
			if ( ! empty( $r['broad'] ) ) {
				$flags[] = '<span class="vh-chip vh-chip--warn">' . esc_html__( 'Any on one side', 'vulnhub' ) . '</span>';
			}

			echo '<tr>';
			printf( '<td>#%s %s%s</td>', esc_html( (string) $r['number'] ), esc_html( (string) $r['name'] ), '' !== (string) $r['layer'] ? '<div class="vh-meta">' . esc_html( sprintf( /* translators: %s: layer */ __( 'inside %s', 'vulnhub' ), (string) $r['layer'] ) ) . '</div>' : '' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			printf( '<td>%s</td>', esc_html( $arrow[ (string) $r['dir'] ] ?? '' ) );
			printf( '<td>%s</td>', esc_html( (string) $r['src'] ) );
			printf( '<td>%s</td>', esc_html( (string) $r['dst'] ) );
			printf( '<td class="vh-mono">%s %s</td>', esc_html( (string) $r['ports'] ), implode( ' ', $flags ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo '</tr>';
		}

		echo '</tbody></table></div>';
	}

	private static function render_gateways(): void {
		global $wpdb;

		$rows = VulnHub_CheckPoint_Store::gateway_rows();
		usort( $rows, static fn( array $a, array $b ): int => array( '' === (string) $a['site'], (string) $a['site'], (string) $a['platform'], (string) $a['name'] ) <=> array( '' === (string) $b['site'], (string) $b['site'], (string) $b['platform'], (string) $b['name'] ) );
		$plat = array(
			'aws'     => __( 'AWS', 'vulnhub' ),
			'cluster' => __( 'Cluster member', 'vulnhub' ),
			'gateway' => __( 'Gateway', 'vulnhub' ),
			'unknown' => __( 'Unknown', 'vulnhub' ),
		);

		echo '<p class="vh-meta">' . esc_html__( 'Where each firewall is, worked out from its name, its address and its neighbours, the location register, and the AWS capture. Expand a row for the evidence. A wrong answer can be corrected with wp vulnhub checkpoint-sites --set=<name> --site=<site>.', 'vulnhub' ) . '</p>';
		echo '<div class="vh-tablewrap"><table class="vh-table"><thead><tr>';
		foreach ( array( __( 'Site', 'vulnhub' ), __( 'Firewall', 'vulnhub' ), __( 'Platform', 'vulnhub' ), __( 'Address', 'vulnhub' ), __( 'Version', 'vulnhub' ), __( 'Status / policy', 'vulnhub' ), __( 'How sure', 'vulnhub' ) ) as $h ) {
			printf( '<th scope="col">%s</th>', esc_html( $h ) );
		}
		echo '</tr></thead><tbody>';
		foreach ( $rows as $r ) {
			$ev = (array) json_decode( (string) $r['evidence'], true );

			echo '<tr>';
			printf( '<td><strong>%s</strong></td>', esc_html( '' !== (string) $r['site'] ? (string) $r['site'] : __( 'Not placed', 'vulnhub' ) ) );
			echo '<td>' . esc_html( '' !== (string) $r['name'] ? (string) $r['name'] : __( '(unnamed registration)', 'vulnhub' ) );
			if ( $ev ) {
				echo '<details class="vh-meta"><summary>' . esc_html__( 'Evidence', 'vulnhub' ) . '</summary><ul>';
				foreach ( $ev as $e ) {
					echo '<li>' . esc_html( (string) $e ) . '</li>';
				}
				echo '</ul></details>';
			}
			echo '</td>';
			printf( '<td>%s%s</td>', esc_html( $plat[ (string) $r['platform'] ] ?? (string) $r['type'] ), '' !== (string) $r['cluster'] ? '<div class="vh-meta">' . esc_html( (string) $r['cluster'] ) . '</div>' : '' );
			printf( '<td class="vh-mono">%s</td>', esc_html( (string) $r['ipv4'] ) );
			printf( '<td>%s</td>', esc_html( (string) $r['version'] ) );
			printf( '<td>%s</td>', esc_html( '' !== (string) $r['policy'] ? (string) $r['policy'] : '—' ) );
			printf( '<td>%s</td>', esc_html( (string) $r['confidence'] ) );
			echo '</tr>';
		}
		echo '</tbody></table></div>';
	}
}

