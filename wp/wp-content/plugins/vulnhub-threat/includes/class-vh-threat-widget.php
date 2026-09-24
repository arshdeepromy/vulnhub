<?php
/**
 * The attack-path widget.
 *
 * One picture that answers the question a board asks and a vulnerability table
 * cannot: of everything open right now, how much of it can somebody actually
 * get to today, and by which door.
 *
 * Three lanes, in the order an intrusion runs:
 *
 *   edge   — a stranger opens a socket to something we publish. No account, no
 *            user, no phone call. This is the lane where the number ought to
 *            be zero.
 *   user   — a stranger sends something a person opens: an attachment, a link,
 *            a download. Split three ways because the countermeasures are
 *            three different teams.
 *   inside — everything that only works once one of the first two has already
 *            worked. This is not a third door; it is what is waiting on the
 *            other side of the first two, which is why it is drawn underneath
 *            them rather than beside them.
 *
 * The picture is an SVG so that "Download PNG" on the widget menu works, and
 * every number in it is a link into the findings list filtered to exactly the
 * rows it counted.
 *
 * @package VulnHub\Threat
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Registers and draws the attack-path widget.
 */
final class VulnHub_Threat_Widget {

	public const ID = 'attack_paths';

	/*
	 * Flow geometry. Declared once because each path is used twice: as the
	 * drawn stroke, and as the `offset-path` the animated dots travel along.
	 * Two copies that could disagree would show dots floating beside the line.
	 */
	private const PATH_EDGE = 'M152,176 C300,150 430,112 686,112';
	private const PATH_MAIL = 'M150,224 C286,246 396,258 566,256';
	private const PATH_WEB  = 'M152,236 C286,266 398,282 566,268';
	private const PATH_FILE = 'M148,248 C286,288 404,302 566,280';
	private const PATH_USER = 'M612,266 C642,256 660,244 686,240';
	/*
	 * Both landing boxes drop into the band underneath, and both do it down
	 * the right-hand margin. Routing the edge lane's arrow straight down
	 * instead would take it behind the user lane's box, which reads as one
	 * lane feeding the other rather than as both feeding the floor below.
	 */
	private const PATH_DOWN_EDGE = 'M1104,170 C1146,220 1146,292 1096,318';
	private const PATH_DOWN_USER = 'M1078,298 C1094,306 1090,314 1064,318';

	public static function init(): void {
		add_filter( 'vulnhub_dashboard_widgets', array( __CLASS__, 'register' ) );
		add_filter( 'vulnhub_dashboard_default_layout', array( __CLASS__, 'place' ) );
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'assets' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
	}

	/**
	 * @param array<string,array<string,mixed>> $w Widget registry.
	 * @return array<string,array<string,mixed>>
	 */
	public static function register( array $w ): array {
		$w[ self::ID ] = array(
			'label'   => __( 'How an attacker gets in', 'vulnhub' ),
			'summary' => __( 'Open findings with a working exploit, sorted by the route somebody would have to take to use one.', 'vulnhub' ),
			'group'   => 'exposure',
			'width'   => 12,
			'render'  => array( __CLASS__, 'render' ),
			'data'    => array( __CLASS__, 'data' ),
		);

		return $w;
	}

	/**
	 * Put it directly under the headline figures on a board nobody has
	 * arranged: it is the second question after "how bad is it".
	 *
	 * @param array<int,array{id:string,width:int}> $layout Default layout.
	 * @return array<int,array{id:string,width:int}>
	 */
	public static function place( array $layout ): array {
		foreach ( $layout as $entry ) {
			if ( self::ID === ( $entry['id'] ?? '' ) ) {
				return $layout;
			}
		}

		$out = array();

		foreach ( $layout as $entry ) {
			$out[] = $entry;

			if ( 'headline' === ( $entry['id'] ?? '' ) ) {
				$out[] = array( 'id' => self::ID, 'width' => 12 );
			}
		}

		return $out;
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
		$mtime = @filemtime( VULNHUB_THREAT_DIR . $rel ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		return $mtime ? VULNHUB_THREAT_VERSION . '.' . $mtime : VULNHUB_THREAT_VERSION;
	}

	public static function assets(): void {
		wp_enqueue_style(
			'vulnhub-threat',
			VULNHUB_THREAT_URL . 'assets/threat.css',
			array(),
			self::asset_ver( 'assets/threat.css' )
		);
	}

	/* =================================================================
	 * Drawing
	 * ============================================================== */

	public static function render(): void {
		if ( ! VulnHub_Threat_Repo::has_data() ) {
			echo self::empty_state(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

			return;
		}

		$d = VulnHub_Threat_Repo::lanes();

		// The busiest lane sets the dot density for all of them, so the
		// picture reads as volume before anybody has read a number.
		$peak = max(
			1,
			(int) $d['edge']['findings'],
			(int) $d['user']['findings'],
			(int) $d['inside']['findings']
		);

		echo '<div class="vh-flow">';

		self::render_open_doors();
		self::render_svg( $d, $peak );
		self::render_exposure( $d );
		self::render_cards( $d );

		printf(
			'<p class="vh-sub vh-flow__foot">%s</p>',
			esc_html(
				sprintf(
					/* translators: 1: total open findings, 2: internet-facing asset count, 3: EPSS threshold as a percentage, 4: findings with no CVSS vector. */
					__( 'Counted from %1$s open findings. %2$s assets are treated as reachable from the internet, on observed evidence — a listening web or mail service, or a public address — and everything else is placed where it can actually be used, once somebody is already inside. In AWS, reachability is read from the security groups, routes and load balancers themselves (the list at the top); elsewhere it is observed, not proven. "Exploitable today" means the CVE is on CISA\'s exploited list, has a published exploit referenced by NVD, or FIRST puts it at %3$s or more likely to be exploited in the next 30 days. %4$s open findings carry no CVSS v3 vector and are not placed on any lane.', 'vulnhub' ),
					number_format_i18n( (int) $d['totals']['open'] ),
					number_format_i18n( (int) $d['totals']['facing'] ),
					number_format_i18n( (float) $d['threshold'] * 100 ) . '%',
					number_format_i18n( (int) $d['totals']['unknown'] )
				)
			)
		);

		echo '</div>';
	}

	/**
	 * Open to the internet, and vulnerable on that port -- the list to work
	 * first, above the lanes. See VulnHub_Threat_Exposure.
	 *
	 * Every row reads left to right as the attack does: from where, through
	 * which door, to which machine, using what. An empty list is said out
	 * loud, with what was checked, because "nothing" and "nothing looked"
	 * must never look alike.
	 */
	private static function render_open_doors(): void {
		if ( ! class_exists( 'VulnHub_Threat_Exposure' ) ) {
			return;
		}

		$x = VulnHub_Threat_Exposure::data();
		$c = $x['counts'];

		if ( ! $x['has_map'] && ! $x['items'] ) {
			return;
		}

		$tiers = array(
			'now'    => __( 'Mitigate now', 'vulnhub' ),
			'next'   => __( 'Next', 'vulnhub' ),
			'review' => __( 'Review', 'vulnhub' ),
		);
		$csv   = wp_nonce_url( admin_url( 'admin-post.php?action=vulnhub_threat_exposure_csv' ), 'vulnhub_threat_exposure_csv' );
		$shown = array_slice( $x['items'], 0, 8 );

		echo '<section class="vh-doors" aria-labelledby="vh-doors-h">';
		echo '<header class="vh-doors__head"><div>';
		printf( '<h4 class="vh-doors__h" id="vh-doors-h">%s</h4>', esc_html__( 'Open to the internet — and vulnerable on that port', 'vulnhub' ) );
		printf( '<p class="vh-doors__sub">%s</p>', esc_html__( 'A way in from outside, the vulnerable service answering on it, and whether anyone has an exploit. Everything else on these machines needs a foothold first. Work this list first.', 'vulnhub' ) );
		echo '</div><div class="vh-doors__tally">';

		foreach ( $tiers as $tier => $label ) {
			$n = (int) $c[ $tier ];
			printf(
				'<a class="vh-doors__chip vh-doors__chip--%1$s%2$s" href="%3$s"><b>%4$s</b> %5$s</a>',
				esc_attr( $tier ),
				0 === $n ? ' is-zero' : '',
				esc_url( VulnHub_Threat_Repo::expo_url( $tier ) ),
				esc_html( number_format_i18n( $n ) ),
				esc_html( $label )
			);
		}

		printf( '<a class="vh-doors__csv" href="%s">%s</a>', esc_url( $csv ), esc_html__( 'CSV', 'vulnhub' ) );
		echo '</div></header>';

		if ( ! $shown ) {
			printf(
				'<p class="vh-doors__none"><b>%1$s</b> %2$s</p>',
				esc_html__( 'Nothing scanned and open to the internet is vulnerable on the port it is open on.', 'vulnhub' ),
				esc_html(
					sprintf(
						/* translators: 1: scanned servers with a way in, 2: never-scanned ones. */
						__( 'Checked %1$s scanned servers with a way in from outside; %2$s more have never been scanned (below).', 'vulnhub' ),
						number_format_i18n( (int) $c['quiet'] ),
						number_format_i18n( (int) $c['blind'] )
					)
				)
			);
		} else {
			echo '<ol class="vh-doors__list">';

			foreach ( $shown as $i ) {
				self::render_door( $i, $tiers[ $i['tier'] ] );
			}

			echo '</ol>';

			if ( count( $x['items'] ) > count( $shown ) ) {
				printf(
					'<p class="vh-doors__more"><a href="%1$s">%2$s</a></p>',
					esc_url( VulnHub_Threat_Repo::expo_url( 'all' ) ),
					esc_html(
						sprintf(
							/* translators: %s: number of further services. */
							_n( '%s more exposed service — every finding behind this list', '%s more exposed services — every finding behind this list', count( $x['items'] ) - count( $shown ), 'vulnhub' ),
							number_format_i18n( count( $x['items'] ) - count( $shown ) )
						)
					)
				);
			}
		}

		self::render_blind( (array) $x['blind'] );
		self::render_door_notes( $x );

		echo '</section>';
	}

	/**
	 * One exposed service, as the path an attacker would take.
	 *
	 * @param array<string,mixed> $i    Item.
	 * @param string              $tier Tier label.
	 */
	private static function render_door( array $i, string $tier ): void {
		$from = 'anyone' === $i['reach']
			? __( 'Anyone', 'vulnhub' )
			: ( 'listed' === $i['reach']
				/* translators: %s: number of outside address ranges. */
				? sprintf( _n( '%s listed address', '%s listed addresses', max( 1, (int) $i['sources'] ), 'vulnhub' ), number_format_i18n( max( 1, (int) $i['sources'] ) ) )
				: __( 'Public address', 'vulnhub' ) );
		$via  = match ( $i['via'] ) {
			'lb'       => sprintf( /* translators: %s: load balancer and listener. */ __( 'via load balancer %s', 'vulnhub' ), $i['front'] ),
			'observed' => sprintf( /* translators: %s: address. */ __( 'answers on %s; firewall not read', 'vulnhub' ), $i['front'] ),
			default    => sprintf( /* translators: %s: address. */ __( 'on %s', 'vulnhub' ), $i['front'] ),
		};
		$top  = (array) ( $i['vulns'][0] ?? array() );
		$host = '' !== $i['host'] ? $i['host'] : '#' . $i['asset_id'];

		printf( '<li class="vh-door vh-door--%1$s vh-door--%2$s">', esc_attr( $i['tier'] ), esc_attr( $i['reach'] ) );
		printf( '<span class="vh-door__tier">%s</span>', esc_html( $tier ) );

		// The path: outside -> port -> machine.
		echo '<span class="vh-door__path">';
		printf( '<span class="vh-door__from" title="%1$s">%2$s</span>', esc_attr( $via ), esc_html( $from ) );
		echo '<span class="vh-door__wire" aria-hidden="true"></span>';
		printf( '<span class="vh-door__port" title="%1$s">%2$s</span>', esc_attr( $i['service'] ), esc_html( $i['port'] ) );
		echo '<span class="vh-door__wire" aria-hidden="true"></span>';
		printf(
			'<a class="vh-door__host" href="%1$s">%2$s</a>',
			esc_url( class_exists( 'VulnHub_Dash_Portal' ) ? VulnHub_Dash_Portal::portal_url( 'assets', array( 'asset' => (int) $i['asset_id'] ) ) : '' ),
			esc_html( $host )
		);
		echo '</span>';

		echo '<span class="vh-door__what">';
		printf( '<span class="vh-door__svc">%1$s <span class="vh-door__via">%2$s</span></span>', esc_html( $i['service'] ), esc_html( $via ) );
		printf( '<span class="vh-door__vuln">%s</span>', esc_html( vh_trim( (string) ( $top['title'] ?? '' ), 90 ) ) );
		echo '<span class="vh-door__tags">';
		if ( $i['kev'] > 0 ) {
			printf( '<span class="vh-door__tag vh-door__tag--kev">%s</span>', esc_html__( 'exploited in the wild', 'vulnhub' ) );
		} elseif ( $i['poc'] > 0 ) {
			printf( '<span class="vh-door__tag vh-door__tag--poc">%s</span>', esc_html__( 'public exploit', 'vulnhub' ) );
		}
		printf( '<span class="vh-door__tag vh-door__tag--sev vh-door__tag--%1$s">%1$s</span>', esc_html( $i['severity'] ) );
		if ( $i['epss'] >= 0.01 ) {
			/* translators: %s: EPSS percentage. */
			printf( '<span class="vh-door__tag">%s</span>', esc_html( sprintf( __( 'EPSS %s', 'vulnhub' ), number_format_i18n( 100 * $i['epss'], 1 ) . '%' ) ) );
		}
		echo self::firewall_tag( (string) $i['firewall'] ); // phpcs:ignore WordPress.Security.EscapeOutput -- built escaped.
		if ( 'yes' === ( $i['listening'] ?? '' ) ) {
			printf( '<span class="vh-door__tag vh-door__tag--listen" title="%1$s">%2$s</span>', esc_attr__( 'The scanner read the host\'s listening table and this port is in it.', 'vulnhub' ), esc_html__( 'seen listening', 'vulnhub' ) );
		} elseif ( 'no' === ( $i['listening'] ?? '' ) ) {
			printf( '<span class="vh-door__tag vh-door__tag--soft" title="%1$s">%2$s</span>', esc_attr__( 'The scanner read the host\'s listening table and this port is not in it: the package is vulnerable, but nothing answers on the open port today.', 'vulnhub' ), esc_html__( 'not listening', 'vulnhub' ) );
		} else {
			printf( '<span class="vh-door__tag vh-door__tag--soft" title="%1$s">%2$s</span>', esc_attr__( 'No listening table for this host: the service is inferred from the installed package. Confirm it answers on this port.', 'vulnhub' ), esc_html__( 'listening: inferred', 'vulnhub' ) );
		}
		if ( 'vpc' === $i['route'] ) {
			printf( '<span class="vh-door__tag vh-door__tag--soft" title="%1$s">%2$s</span>', esc_attr__( 'The route was read for the VPC, not this subnet. The next network capture reads the subnet\'s own table.', 'vulnhub' ), esc_html__( 'route: VPC-level', 'vulnhub' ) );
		}
		echo '</span></span>';

		echo '<span class="vh-door__do">';
		echo self::ticket_line( $i ); // phpcs:ignore WordPress.Security.EscapeOutput -- built escaped.
		printf( '<span>%s</span>', esc_html( $i['do'] ) );
		printf(
			'<a href="%1$s">%2$s</a>',
			esc_url( VulnHub_Threat_Repo::expo_url( 'all', (int) $i['asset_id'] ) ),
			esc_html(
				sprintf(
					/* translators: %s: number of findings. */
					_n( '%s finding →', '%s findings →', count( $i['findings'] ), 'vulnhub' ),
					number_format_i18n( count( $i['findings'] ) )
				)
			)
		);
		echo '</span></li>';
	}

	/**
	 * Is this already raised? The tickets the row's findings are on, each a
	 * link to its ticket page with its status; "2 of 7 raised" when only some
	 * are; "Not raised" when none are.
	 *
	 * @param array<string,mixed> $i Item.
	 */
	private static function ticket_line( array $i ): string {
		$tickets = (array) ( $i['tickets'] ?? array() );
		$total   = count( (array) $i['findings'] );
		$on      = (int) ( $i['ticketed'] ?? 0 );

		if ( ! $tickets ) {
			return '<span class="vh-door__ticket vh-door__ticket--none">' . esc_html__( 'Not raised', 'vulnhub' ) . '</span>';
		}

		$links = array_map(
			static fn( array $t ): string => sprintf(
				'<a class="vh-door__ticket%1$s" href="%2$s">%3$s%4$s</a>',
				$t['done'] ? ' vh-door__ticket--done' : '',
				esc_url( class_exists( 'VulnHub_Dash_Portal' ) ? VulnHub_Dash_Portal::portal_url( 'tickets', array( 'ticket' => $t['id'] ) ) : '' ),
				esc_html( '' !== $t['key'] ? $t['key'] : '#' . $t['id'] ),
				'' !== $t['status'] ? ' · ' . esc_html( $t['status'] ) : ''
			),
			$tickets
		);

		$partial = $on < $total
			? ' <span class="vh-door__ticket-part">' . esc_html( sprintf( /* translators: 1: findings on a ticket, 2: all findings. */ __( '%1$s of %2$s raised', 'vulnhub' ), number_format_i18n( $on ), number_format_i18n( $total ) ) ) . '</span>'
			: '';

		return '<span class="vh-door__tickets">' . implode( ' ', $links ) . $partial . '</span>';
	}

	/**
	 * Whether an inline firewall stands in front of a door.
	 */
	private static function firewall_tag( string $fw ): string {
		[ $label, $tip ] = match ( $fw ) {
			'none'      => array( __( 'no firewall in front', 'vulnhub' ), __( 'Nothing in this VPC sends inbound traffic through the inline firewall: the security group is the only control.', 'vulnhub' ) ),
			'inspected' => array( __( 'through the inline firewall', 'vulnhub' ), __( 'The internet gateway sends arriving traffic to the inline firewall before it reaches the machine.', 'vulnhub' ) ),
			default     => array( __( 'firewall: not known yet', 'vulnhub' ), __( 'The VPC uses the inline firewall for something, but the capture has not read whether it inspects inbound traffic. The next network capture reads it.', 'vulnhub' ) ),
		};

		return sprintf( '<span class="vh-door__tag vh-door__tag--fw-%1$s" title="%2$s">%3$s</span>', esc_attr( $fw ), esc_attr( $tip ), esc_html( $label ) );
	}

	/**
	 * Servers with a door open from outside that no scanner has ever looked
	 * at. "No findings" on those is not an all-clear, and it must not read
	 * like one -- so they get a block of their own, above the quieter notes.
	 *
	 * @param array<int,array<string,mixed>> $blind Rows.
	 */
	private static function render_blind( array $blind ): void {
		if ( ! $blind ) {
			return;
		}

		$anyone = count( array_filter( $blind, static fn( array $b ): bool => 'anyone' === $b['reach'] ) );

		echo '<div class="vh-doors__blind">';
		printf(
			'<p class="vh-doors__blind-h"><b>%1$s</b> %2$s</p>',
			esc_html(
				sprintf(
					/* translators: 1: servers, 2: of which open to anyone. */
					_n( '%1$s server is open from outside and has never been scanned (%2$s open to anyone).', '%1$s servers are open from outside and have never been scanned (%2$s open to anyone).', count( $blind ), 'vulnhub' ),
					number_format_i18n( count( $blind ) ),
					number_format_i18n( $anyone )
				)
			),
			esc_html__( 'Nothing is known about what answers behind these doors, so "no findings" here means nobody has looked. Put a scanner on them, or close the doors.', 'vulnhub' )
		);
		echo '<ul class="vh-doors__blind-list">';

		foreach ( $blind as $b ) {
			printf(
				'<li class="vh-door--%1$s"><a href="%2$s">%3$s</a> <span class="vh-door__from">%4$s</span> %5$s %6$s</li>',
				esc_attr( $b['reach'] ),
				esc_url( class_exists( 'VulnHub_Dash_Portal' ) ? VulnHub_Dash_Portal::portal_url( 'assets', array( 'asset' => (int) $b['asset_id'] ) ) : '' ),
				esc_html( '' !== $b['host'] ? $b['host'] : '#' . $b['asset_id'] ),
				esc_html( 'anyone' === $b['reach'] ? __( 'anyone', 'vulnhub' ) : __( 'listed addresses', 'vulnhub' ) ),
				implode( ' ', array_map( static fn( string $p ): string => '<span class="vh-door__port">' . esc_html( $p ) . '</span>', array_slice( (array) $b['ports'], 0, 5 ) ) ), // phpcs:ignore
				self::firewall_tag( (string) $b['firewall'] ) // phpcs:ignore
			);
		}

		echo '</ul></div>';
	}

	/**
	 * What sits beside the list: doors open with nothing known behind them,
	 * doors one change from open, and doors not traced yet.
	 *
	 * @param array<string,mixed> $x Exposure data.
	 */
	private static function render_door_notes( array $x ): void {
		$notes = array();
		$late  = $x['latent'];

		if ( $late ) {
			$worst = array_filter( $late, static fn( array $i ): bool => $i['kev'] > 0 || $i['poc'] > 0 );
			$list  = implode( ', ', array_map( static fn( array $i ): string => ( '' !== $i['host'] ? $i['host'] : '#' . $i['asset_id'] ) . ' ' . $i['port'], array_slice( $late, 0, 6 ) ) );

			$notes[] = array(
				'latent',
				sprintf(
					/* translators: 1: number of services, 2: of which exploitable, 3: examples. */
					_n( '%1$s vulnerable service is one change from exposed: a rule opens it to anyone, but nothing routes in from outside today (%2$s exploitable). Narrow the rule before a route or address change makes it real: %3$s.', '%1$s vulnerable services are one change from exposed: a rule opens them to anyone, but nothing routes in from outside today (%2$s exploitable). Narrow the rules before a route or address change makes them real: %3$s.', count( $late ), 'vulnhub' ),
					number_format_i18n( count( $late ) ),
					number_format_i18n( count( $worst ) ),
					$list
				),
				VulnHub_Threat_Repo::expo_url( 'latent' ),
			);
		}

		if ( $x['quiet'] ) {
			$anyone = array_filter( $x['quiet'], static fn( array $q ): bool => 'anyone' === $q['reach'] );
			$list   = implode( '; ', array_map( static fn( array $q ): string => ( '' !== $q['host'] ? $q['host'] : '#' . $q['asset_id'] ) . ' ' . implode( ', ', array_slice( $q['ports'], 0, 4 ) ), array_slice( $anyone ?: $x['quiet'], 0, 5 ) ) );

			$notes[] = array(
				'quiet',
				sprintf(
					/* translators: 1: servers, 2: open to anyone, 3: examples. */
					_n( '%1$s more server has a way in, was scanned, and shows nothing vulnerable behind its open ports (%2$s open to anyone). Less surface is still less surface: %3$s.', '%1$s more servers have a way in, were scanned, and show nothing vulnerable behind their open ports (%2$s open to anyone). Less surface is still less surface: %3$s.', count( $x['quiet'] ), 'vulnhub' ),
					number_format_i18n( count( $x['quiet'] ) ),
					number_format_i18n( count( $anyone ) ),
					$list
				),
				'',
			);
		}

		// Published through a balancer to something nobody scans.
		$unscanned = array_values( array_filter( (array) $x['doors'], static fn( array $d ): bool => ! empty( $d['targets'] ) && empty( $d['managed'] ) ) );
		$managed   = array_values( array_filter( (array) $x['doors'], static fn( array $d ): bool => ! empty( $d['managed'] ) ) );

		if ( $unscanned ) {
			$notes[] = array(
				'unscanned',
				sprintf(
					/* translators: 1: listeners, 2: examples. */
					_n( '%1$s internet-facing load balancer listener publishes something no scanner covers — an instance with no asset record, or a container: %2$s. Nothing here can say what is vulnerable behind it.', '%1$s internet-facing load balancer listeners publish something no scanner covers — instances with no asset record, or containers: %2$s. Nothing here can say what is vulnerable behind them.', count( $unscanned ), 'vulnhub' ),
					number_format_i18n( count( $unscanned ) ),
					implode( '; ', array_map( static fn( array $d ): string => $d['name'] . ' ' . $d['listener'] . ' → ' . implode( ', ', array_slice( (array) $d['targets'], 0, 3 ) ), array_slice( $unscanned, 0, 5 ) ) )
				),
				'',
			);
		}

		if ( $managed ) {
			$notes[] = array(
				'managed',
				sprintf(
					/* translators: %s: listeners. */
					_n( '%s listener publishes an AWS-managed service (Transfer Family SFTP): AWS patches it, and the only control on our side is who its rules admit.', '%s listeners publish an AWS-managed service (Transfer Family SFTP): AWS patches it, and the only control on our side is who its rules admit.', count( $managed ), 'vulnhub' ),
					number_format_i18n( count( $managed ) )
				),
				'',
			);
		}

		$untraced = array_values( array_filter( (array) $x['doors'], static fn( array $d ): bool => ! isset( $d['targets'] ) ) );

		if ( $untraced ) {
			$x['doors'] = $untraced;
			$ports      = array_count_values( array_map( static fn( array $d ): string => (string) $d['listener'], $x['doors'] ) );
			arsort( $ports );

			$notes[] = array(
				'doors',
				sprintf(
					/* translators: 1: listeners, 2: ports. */
					_n( '%1$s internet-facing load balancer listener admits outside traffic (%2$s), and the servers behind it are not traced yet. Sign in to AWS and capture the network again to name them.', '%1$s internet-facing load balancer listeners admit outside traffic (%2$s), and the servers behind them are not traced yet. Sign in to AWS and capture the network again to name them.', count( $x['doors'] ), 'vulnhub' ),
					number_format_i18n( count( $x['doors'] ) ),
					implode( ', ', array_map( static fn( string $p, int $n ): string => $n > 1 ? $p . ' ×' . $n : $p, array_keys( $ports ), $ports ) )
				),
				'',
			);
		}

		if ( $notes ) {
			echo '<ul class="vh-doors__notes">';

			foreach ( $notes as [ $kind, $text, $url ] ) {
				printf(
					'<li class="vh-doors__note vh-doors__note--%1$s">%2$s%3$s</li>',
					esc_attr( $kind ),
					esc_html( $text ),
					'' !== $url ? ' <a href="' . esc_url( $url ) . '">' . esc_html__( 'See the findings →', 'vulnhub' ) . '</a>' : ''
				);
			}

			echo '</ul>';
		}

		if ( '' !== $x['captured_at'] ) {
			printf(
				'<p class="vh-doors__when">%s</p>',
				esc_html(
					sprintf(
						/* translators: %s: time ago. */
						__( 'Network map read %s. Firewall rules in front of AWS and on-premises are not read; a door here can only be closed by them, never opened.', 'vulnhub' ),
						vh_ago( $x['captured_at'] )
					)
				)
			);
		}
	}

	/**
	 * @param array<string,mixed> $d    Lane data.
	 * @param int                 $peak Busiest lane, for dot density.
	 */
	private static function render_svg( array $d, int $peak ): void {
		$edge  = (int) $d['edge']['findings'];
		$user  = (int) $d['user']['findings'];
		$in    = (int) $d['inside']['findings'];
		$deliv = (array) $d['user']['delivery'];

		$title = __( 'Attack paths into the estate', 'vulnhub' );
		$desc  = sprintf(
			/* translators: 1: edge count, 2: user count, 3: inside count. */
			__( 'A flow diagram. From the internet, %1$s open findings can be reached directly on an internet-facing asset, and %2$s can be delivered to a person by email, website or download. Once inside, a further %3$s become usable.', 'vulnhub' ),
			number_format_i18n( $edge ),
			number_format_i18n( $user ),
			number_format_i18n( $in )
		);

		?>
		<div class="vh-flow__stage">
		<svg class="vh-flow__svg" viewBox="0 0 1160 452" role="img"
			aria-labelledby="vh-flow-t vh-flow-d" preserveAspectRatio="xMidYMid meet">
			<title id="vh-flow-t"><?php echo esc_html( $title ); ?></title>
			<desc id="vh-flow-d"><?php echo esc_html( $desc ); ?></desc>

			<?php self::defs(); ?>

			<!-- The perimeter. Dashed, because it is an assumption. -->
			<line x1="632" y1="34" x2="632" y2="310" class="vh-flow__perimeter"/>
			<text x="632" y="24" class="vh-flow__perimeter-label" text-anchor="middle"><?php esc_html_e( 'your perimeter', 'vulnhub' ); ?></text>

			<!-- The internet. -->
			<g class="vh-flow__net">
				<circle cx="100" cy="212" r="52" class="vh-flow__globe"/>
				<circle cx="100" cy="212" r="52" class="vh-flow__pulse"/>
				<path d="M48,212 h104 M100,160 v104 M100,160 C70,186 70,238 100,264 M100,160 C130,186 130,238 100,264"
					class="vh-flow__globe-lines"/>
				<text x="100" y="292" text-anchor="middle" class="vh-flow__net-label"><?php esc_html_e( 'The internet', 'vulnhub' ); ?></text>
				<text x="100" y="308" text-anchor="middle" class="vh-flow__net-sub"><?php esc_html_e( 'anybody, from anywhere', 'vulnhub' ); ?></text>
			</g>

			<?php
			self::strand( self::PATH_EDGE, 'edge', $edge, $peak, 3.0 );
			self::strand( self::PATH_MAIL, 'user', (int) ( $deliv['mail'] ?? 0 ), $peak, 1.6 );
			self::strand( self::PATH_WEB, 'user', (int) ( $deliv['web'] ?? 0 ), $peak, 1.6 );
			self::strand( self::PATH_FILE, 'user', (int) ( $deliv['file'] ?? 0 ), $peak, 1.6 );
			self::strand( self::PATH_USER, 'user', $user, $peak, 3.0 );
			self::strand( self::PATH_DOWN_EDGE, 'inside', $edge, $peak, 2.2 );
			self::strand( self::PATH_DOWN_USER, 'inside', $user, $peak, 2.2 );
			?>

			<!-- The three doors a person is handed something through. Each one is
			     a link into the findings that arrive that way, exactly as the
			     landing boxes are: a number on this diagram that you cannot open
			     is a number nobody can act on. -->
			<?php
			$doors = array(
				array( 244, 228, 'mail', __( 'email', 'vulnhub' ), (int) ( $deliv['mail'] ?? 0 ) ),
				array( 328, 260, 'web', __( 'website', 'vulnhub' ), (int) ( $deliv['web'] ?? 0 ) ),
				array( 412, 280, 'file', __( 'download', 'vulnhub' ), (int) ( $deliv['file'] ?? 0 ) ),
			);

			foreach ( $doors as $door ) :
				[ $x, $y, $channel, $label, $n ] = $door;

				$url = VulnHub_Threat_Repo::delivery_url( $channel );
				$aria = sprintf(
					/* translators: 1: channel, e.g. "email"; 2: number of findings. */
					__( '%1$s: %2$s exploitable findings delivered this way — see them', 'vulnhub' ),
					$label,
					number_format_i18n( $n )
				);

				// An anchor when the portal is reachable, a plain group when it
				// is not, so the picture never renders a dead link.
				if ( '' !== $url ) {
					printf( '<a href="%s" class="vh-flow__door vh-flow__door--%s" aria-label="%s">', esc_url( $url ), esc_attr( $channel ), esc_attr( $aria ) );
				} else {
					printf( '<g class="vh-flow__door vh-flow__door--%s">', esc_attr( $channel ) );
				}
				?>
					<rect x="<?php echo (int) $x; ?>" y="<?php echo (int) $y; ?>" width="100" height="26" rx="13"/>
					<text x="<?php echo (int) $x + 50; ?>" y="<?php echo (int) $y + 17; ?>" text-anchor="middle">
						<?php echo esc_html( $label . ' · ' . number_format_i18n( $n ) ); ?>
					</text>
				<?php echo '' !== $url ? '</a>' : '</g>'; ?>
			<?php endforeach; ?>

			<!-- The person who opens it. -->
			<g class="vh-flow__person">
				<circle cx="588" cy="266" r="24"/>
				<path d="M588,256 m-7,0 a7,7 0 1,0 14,0 a7,7 0 1,0 -14,0 M574,280 a14,12 0 0,1 28,0"/>
			</g>

			<?php
			self::lane_box(
				'edge',
				686,
				62,
				$edge,
				(int) $d['edge']['assets'],
				__( 'Reached straight from the internet', 'vulnhub' ),
				__( 'the internet can open the port, and the bug is in what answers', 'vulnhub' ),
				414
			);

			self::lane_box(
				'user',
				686,
				190,
				$user,
				(int) $d['user']['assets'],
				__( 'Delivered to one of your people', 'vulnhub' ),
				__( 'they open the attachment, the link or the download', 'vulnhub' ),
				414
			);

			self::lane_box(
				'inside',
				350,
				322,
				$in,
				(int) $d['inside']['assets'],
				__( 'Then usable once they are inside', 'vulnhub' ),
				__( 'privilege escalation and lateral movement, after either door', 'vulnhub' ),
				750
			);
			?>
		</svg>
		</div>
		<?php
	}

	/** Gradients and the arrowhead, defined once per widget. */
	private static function defs(): void {
		?>
		<defs>
			<marker id="vh-flow-arrow" viewBox="0 0 10 10" refX="9" refY="5"
				markerWidth="6" markerHeight="6" orient="auto-start-reverse">
				<path d="M0,0 L10,5 L0,10 z" fill="context-stroke"/>
			</marker>
		</defs>
		<?php
	}

	/**
	 * One flow line plus the dots travelling along it.
	 *
	 * Dot count is proportional to the lane's share of the busiest lane, so
	 * the picture reads as volume before anybody has read a number. It is
	 * capped at nine: past that the dots merge into a line and stop meaning
	 * anything.
	 *
	 * The dots are moved with CSS `offset-path` rather than SMIL, for one
	 * reason — CSS honours `prefers-reduced-motion` and SMIL cannot be
	 * stopped by a stylesheet. Somebody who has asked their operating system
	 * for stillness gets a static diagram, not a hidden one.
	 */
	private static function strand( string $path, string $lane, int $n, int $peak, float $width ): void {
		printf(
			'<path d="%1$s" class="vh-flow__line vh-flow__line--%2$s" style="stroke-width:%3$s" marker-end="url(#vh-flow-arrow)"/>',
			esc_attr( $path ),
			esc_attr( $lane ),
			esc_attr( (string) $width )
		);

		if ( $n <= 0 ) {
			return;
		}

		$dots = max( 1, min( 9, (int) round( ( $n / max( 1, $peak ) ) * 9 ) ) );

		for ( $i = 0; $i < $dots; $i++ ) {
			printf(
				'<circle r="%1$s" class="vh-flow__dot vh-flow__dot--%2$s" style="offset-path:path(\'%3$s\');animation-delay:%4$ss"/>',
				esc_attr( (string) round( $width * 1.35, 1 ) ),
				esc_attr( $lane ),
				esc_attr( $path ),
				esc_attr( (string) round( $i * ( 3.6 / $dots ), 2 ) )
			);
		}
	}

	/**
	 * A landing box: the number, what it means, and a link to the rows.
	 */
	/**
	 * One lane: how many findings, on how many machines, and what that means.
	 *
	 * Laid out in bands down the box rather than left number / right label.
	 * The old arrangement right-aligned the description against a left-aligned
	 * unit line at almost the same baseline, so "no account, no user, no click
	 * -- a listening service" ran straight through "findings, across 113
	 * machines" and both became unreadable. SVG will not reflow to save you:
	 * if two <text> runs can grow into the same space, eventually they do.
	 *
	 * Assets are their own figure here, not a suffix. "285 findings" and "18
	 * machines" answer different questions -- how much work, and how many
	 * places to go -- and the second was previously buried in a sentence.
	 */
	private static function lane_box( string $lane, int $x, int $y, int $n, int $assets, string $label, string $sub, int $w = 444 ): void {
		$url = VulnHub_Threat_Repo::lane_url( $lane );
		$h   = 124;

		printf( '<a href="%s" class="vh-flow__box vh-flow__box--%s">', esc_url( $url ), esc_attr( $lane ) );

		printf( '<rect x="%d" y="%d" width="%d" height="%d" rx="12"/>', $x, $y, $w, $h );
		printf( '<rect x="%d" y="%d" width="5" height="%d" rx="2.5" class="vh-flow__box-edge"/>', $x, $y, $h );

		// Band 1: what this lane is.
		printf(
			'<text x="%d" y="%d" class="vh-flow__box-label">%s</text>',
			$x + 26,
			$y + 28,
			esc_html( $label )
		);

		// Band 2: the two figures, side by side, each with its own unit.
		printf(
			'<text x="%d" y="%d" class="vh-flow__n">%s</text>',
			$x + 26,
			$y + 66,
			esc_html( number_format_i18n( $n ) )
		);
		printf(
			'<text x="%d" y="%d" class="vh-flow__n-unit">%s</text>',
			$x + 26,
			$y + 90,
			esc_html( _n( 'finding', 'findings', $n, 'vulnhub' ) )
		);

		$split = $x + 26 + max( 92, 22 * strlen( number_format_i18n( $n ) ) );

		printf( '<line x1="%d" y1="%d" x2="%d" y2="%d" class="vh-flow__box-rule"/>', $split - 18, $y + 44, $split - 18, $y + 94 );

		printf(
			'<text x="%d" y="%d" class="vh-flow__n vh-flow__n--assets">%s</text>',
			$split,
			$y + 66,
			esc_html( number_format_i18n( $assets ) )
		);
		printf(
			'<text x="%d" y="%d" class="vh-flow__n-unit">%s</text>',
			$split,
			$y + 90,
			esc_html( _n( 'machine', 'machines', $assets, 'vulnhub' ) )
		);

		// Band 3: the sentence, and the way in.
		printf(
			'<text x="%d" y="%d" class="vh-flow__box-sub">%s</text>',
			$x + 26,
			$y + 111,
			esc_html( $sub )
		);
		printf(
			'<text x="%d" y="%d" class="vh-flow__box-cta" text-anchor="end">%s</text>',
			$x + $w - 22,
			$y + 28,
			esc_html__( 'see the findings →', 'vulnhub' )
		);

		echo '</a>';
	}

	/**
	 * What we actually know about who can be reached from the internet.
	 *
	 * The edge lane is only as good as the exposure verdict behind it, and
	 * that verdict has three states, not two. Every asset is either confirmed
	 * reachable by something observed, ruled out because we looked and nothing
	 * publishable was listening, or unknown because no port scan has ever run
	 * against it.
	 *
	 * Printing the third state is the whole reason this strip exists. Before
	 * the listening-port inventory was read, exposure was decided by asset
	 * type: 388 machines were called internet-facing for being typed `server`,
	 * and the widget reported 5,125 findings as reachable with no account and
	 * no click. The evidence supports 23. But 330 servers have never been port
	 * scanned, and a dashboard that showed only the smaller number would have
	 * traded an overstatement for a false all-clear.
	 *
	 * @param array<string,mixed> $d Lane data.
	 */
	private static function render_exposure( array $d ): void {
		$x = (array) ( $d['exposure'] ?? array() );

		if ( ! $x ) {
			return;
		}

		$confirmed = (int) ( $x['confirmed'] ?? 0 );
		$ruled     = (int) ( $x['ruled_out'] ?? 0 );
		$unknown   = (int) ( $x['unknown'] ?? 0 );
		$servers   = (int) ( $x['unknown_servers'] ?? 0 );
		$asserted  = (int) ( $x['asserted'] ?? 0 );

		// A legacy rule is in force: the verdicts are labels, not observations.
		if ( $asserted > 0 && 0 === $confirmed && 0 === $ruled ) {
			printf(
				'<p class="vh-flow__evidence">%s</p>',
				esc_html(
					sprintf(
						/* translators: %s: number of assets. */
						__( 'Exposure is currently set by asset type, not by anything observed: %s assets are treated as internet-facing because of what they are labelled. Switch the exposure rule to "observed" to decide it on listening services and addresses instead.', 'vulnhub' ),
						number_format_i18n( $asserted )
					)
				)
			);

			return;
		}

		// Proven: a cloud rule and route, or a public address, show a way in.
		// The rest of the confirmed are a listening service and no more.
		$proven = class_exists( 'VulnHub_Threat_Exposure' ) ? count( (array) VulnHub_Threat_Exposure::data()['door_assets'] ) : 0;

		$states = array(
			array(
				'key'   => 'confirmed',
				'n'     => $proven,
				'label' => __( 'Open from outside', 'vulnhub' ),
				'note'  => __( 'a cloud firewall rule and route let the internet open a port on it, or it answers on a public address', 'vulnhub' ),
			),
			array(
				'key'   => 'published',
				'n'     => max( 0, $confirmed - $proven ),
				'label' => __( 'Looks published', 'vulnhub' ),
				'note'  => __( 'a web or mail service is listening; the firewall in front is not readable, so whether the internet reaches it is unproven', 'vulnhub' ),
			),
			array(
				'key'   => 'unknown',
				'n'     => $unknown,
				'label' => __( 'Never looked', 'vulnhub' ),
				'note'  => __( 'no listening-port scan has run — neither reachable nor safe', 'vulnhub' ),
			),
			array(
				'key'   => 'ruled_out',
				'n'     => $ruled,
				'label' => __( 'Ruled out', 'vulnhub' ),
				'note'  => __( 'scanned, and nothing a stranger could connect to was listening', 'vulnhub' ),
			),
		);

		echo '<div class="vh-flow__exposure">';
		printf( '<h4 class="vh-flow__exposure-h">%s</h4>', esc_html__( 'What we know about reachability', 'vulnhub' ) );
		echo '<ul class="vh-flow__states">';

		foreach ( $states as $st ) {
			printf(
				'<li class="vh-flow__state vh-flow__state--%1$s">'
				. '<span class="vh-flow__state-n">%2$s</span>'
				. '<span class="vh-flow__state-label">%3$s</span>'
				. '<span class="vh-flow__state-note">%4$s</span></li>',
				esc_attr( $st['key'] ),
				esc_html( number_format_i18n( (int) $st['n'] ) ),
				esc_html( (string) $st['label'] ),
				esc_html( (string) $st['note'] )
			);
		}

		echo '</ul>';

		if ( $servers > 0 ) {
			printf(
				'<p class="vh-flow__gap">%s</p>',
				esc_html(
					sprintf(
						/* translators: %s: number of servers with no port scan. */
						_n(
							'%s server has never been port scanned. Until it is, nothing here can say whether it is reachable — the edge lane is a floor, not a total.',
							'%s servers have never been port scanned. Until they are, nothing here can say whether they are reachable — the edge lane is a floor, not a total.',
							$servers,
							'vulnhub'
						),
						number_format_i18n( $servers )
					)
				)
			);
		}

		echo '</div>';
	}

	/**
	 * The same three numbers as text, for narrow screens and screen readers.
	 *
	 * Not a fallback nobody sees: on a phone the SVG is hidden and this is the
	 * widget. Severity and lane are never carried by colour alone anywhere in
	 * this product, and a diagram is the easiest place to break that rule.
	 *
	 * @param array<string,mixed> $d Lane data.
	 */
	private static function render_cards( array $d ): void {
		$ev    = (array) $d['evidence'];
		$deliv = (array) $d['user']['delivery'];

		$lanes = array(
			array(
				'lane'   => 'edge',
				'n'      => (int) $d['edge']['findings'],
				'assets' => (int) $d['edge']['assets'],
				'label'  => __( 'Straight from the internet', 'vulnhub' ),
				'note'   => sprintf(
					/* translators: 1: assets carrying these findings. */
					_n( 'On %1$s machine, the internet can open the port the bug is on. Nobody has to click.', 'On %1$s machines, the internet can open the port the bug is on. Nobody has to click.', (int) $d['edge']['assets'], 'vulnhub' ),
					number_format_i18n( (int) $d['edge']['assets'] )
				),
			),
			array(
				'lane'   => 'user',
				'n'      => (int) $d['user']['findings'],
				'assets' => (int) $d['user']['assets'],
				'label'  => __( 'Handed to a person', 'vulnhub' ),
				'note'   => sprintf(
					/* translators: 1: email count, 2: website count, 3: download count. */
					__( 'Email %1$s · website %2$s · download %3$s. The exploit needs somebody to open something.', 'vulnhub' ),
					number_format_i18n( (int) ( $deliv['mail'] ?? 0 ) ),
					number_format_i18n( (int) ( $deliv['web'] ?? 0 ) ),
					number_format_i18n( (int) ( $deliv['file'] ?? 0 ) )
				),
			),
			array(
				'lane'   => 'inside',
				'n'      => (int) $d['inside']['findings'],
				'assets' => (int) $d['inside']['assets'],
				'label'  => __( 'Waiting once they are in', 'vulnhub' ),
				'note'   => sprintf(
					/* translators: %s: findings that are network-exploitable but on unreachable assets. */
					__( 'Includes %s that a stranger could use over the network, on machines where nothing shows the internet can open the port they are on — so they wait for somebody to get inside first.', 'vulnhub' ),
					number_format_i18n( (int) $d['inside']['borrowed'] )
				),
			),
		);

		echo '<ul class="vh-flow__cards">';

		foreach ( $lanes as $l ) {
			printf(
				'<li class="vh-flow__card vh-flow__card--%1$s"><a href="%2$s">'
				. '<span class="vh-flow__card-n">%3$s</span>'
				. '<span class="vh-flow__card-unit">%4$s</span>'
				. '<span class="vh-flow__card-label">%5$s</span>'
				. '<span class="vh-flow__card-note">%6$s</span></a></li>',
				esc_attr( $l['lane'] ),
				esc_url( VulnHub_Threat_Repo::lane_url( $l['lane'] ) ),
				esc_html( number_format_i18n( $l['n'] ) ),
				esc_html(
					sprintf(
						/* translators: 1: "finding"/"findings", 2: "3 machines". */
						__( '%1$s · %2$s', 'vulnhub' ),
						_n( 'finding', 'findings', (int) $l['n'], 'vulnhub' ),
						sprintf(
							/* translators: %s: number of machines. */
							_n( '%s machine', '%s machines', (int) $l['assets'], 'vulnhub' ),
							number_format_i18n( (int) $l['assets'] )
						)
					)
				),
				esc_html( $l['label'] ),
				esc_html( $l['note'] )
			);
		}

		echo '</ul>';

		// The machines that only look published: their own question.
		$maybe = (array) ( $d['edge']['maybe'] ?? array() );

		if ( (int) ( $maybe['findings'] ?? 0 ) > 0 ) {
			printf(
				'<p class="vh-flow__maybe">%1$s <a href="%2$s">%3$s</a></p>',
				esc_html(
					sprintf(
						/* translators: 1: findings, 2: machines. */
						_n( 'Not counted above: %1$s finding a stranger could use over the network, on %2$s machine that looks published — a web or mail service is listening, but nothing here can read the firewall in front of it to say whether the internet reaches it.', 'Not counted above: %1$s findings a stranger could use over the network, on %2$s machines that look published — a web or mail service is listening, but nothing here can read the firewall in front of them to say whether the internet reaches them.', (int) $maybe['findings'], 'vulnhub' ),
						number_format_i18n( (int) $maybe['findings'] ),
						number_format_i18n( (int) $maybe['assets'] )
					)
				),
				esc_url( VulnHub_Threat_Repo::lane_url( 'maybe' ) ),
				esc_html__( 'Check them against the firewall →', 'vulnhub' )
			);
		}

		printf(
			'<p class="vh-flow__evidence">%s</p>',
			esc_html(
				sprintf(
					/* translators: 1: KEV count, 2: CVEs with a published exploit, 3: CVEs over the EPSS threshold, 4: last refresh. */
					__( 'Evidence behind "exploitable": %1$s CVEs on CISA\'s known-exploited list, %2$s with an exploit NVD links to, %3$s over the EPSS threshold. Feeds last refreshed %4$s.', 'vulnhub' ),
					number_format_i18n( (int) $ev['kev'] ),
					number_format_i18n( (int) $ev['exploit_ref'] ),
					number_format_i18n( (int) $ev['epss'] ),
					'' !== $d['as_of'] ? (string) $d['as_of'] . ' UTC' : __( 'never', 'vulnhub' )
				)
			)
		);
	}

	/** Shown before the first refresh has run. */
	private static function empty_state(): string {
		$msg = __( 'No CVE intelligence yet. The nightly refresh downloads NVD, CISA KEV and FIRST EPSS and places every vulnerability on a route; until it has run there is nothing to draw.', 'vulnhub' );

		$html = class_exists( 'VulnHub_Dash_Charts' )
			? VulnHub_Dash_Charts::empty_state( $msg )
			: '<p class="vh-chart-empty">' . esc_html( $msg ) . '</p>';

		if ( current_user_can( Caps::MANAGE ) && class_exists( 'VulnHub_Dash_Portal' ) ) {
			$html .= sprintf(
				'<p class="vh-sub"><a href="%s">%s</a></p>',
				esc_url( VulnHub_Dash_Portal::portal_url( VulnHub_Dash_Portal::ADMIN_VIEW, array( 'section' => VulnHub_Threat_Admin::SECTION ) ) ),
				esc_html__( 'Run it now →', 'vulnhub' )
			);
		}

		return $html;
	}

	/* =================================================================
	 * CSV
	 * ============================================================== */

	/**
	 * @return array{headers:string[],rows:array<int,array<int,scalar>>}
	 */
	public static function data(): array {
		$d     = VulnHub_Threat_Repo::lanes();
		$deliv = (array) $d['user']['delivery'];

		return array(
			'headers' => array(
				__( 'Route', 'vulnhub' ),
				__( 'Open findings', 'vulnhub' ),
				__( 'Machines', 'vulnhub' ),
				__( 'Vulnerability definitions', 'vulnhub' ),
				__( 'What it means', 'vulnhub' ),
			),
			'rows'    => array(
				array(
					__( 'Straight from the internet', 'vulnhub' ),
					(int) $d['edge']['findings'],
					(int) $d['edge']['assets'],
					(int) $d['edge']['vulns'],
					__( 'Network reachable, no privileges, no user interaction, on an internet-facing asset', 'vulnhub' ),
				),
				array(
					__( 'Delivered by email', 'vulnhub' ),
					(int) ( $deliv['mail'] ?? 0 ),
					0,
					0,
					__( 'User interaction required; the CVE describes a mail client or message', 'vulnhub' ),
				),
				array(
					__( 'Delivered by website', 'vulnhub' ),
					(int) ( $deliv['web'] ?? 0 ),
					0,
					0,
					__( 'User interaction required; the CVE describes browsing or web content', 'vulnhub' ),
				),
				array(
					__( 'Delivered by download', 'vulnhub' ),
					(int) ( $deliv['file'] ?? 0 ),
					0,
					0,
					__( 'User interaction required; the CVE describes opening a file', 'vulnhub' ),
				),
				array(
					__( 'Handed to a person (all three)', 'vulnhub' ),
					(int) $d['user']['findings'],
					(int) $d['user']['assets'],
					(int) $d['user']['vulns'],
					__( 'User interaction required', 'vulnhub' ),
				),
				array(
					__( 'Waiting once they are inside', 'vulnhub' ),
					(int) $d['inside']['findings'],
					(int) $d['inside']['assets'],
					(int) $d['inside']['vulns'],
					__( 'Local, adjacent or authenticated — plus network-reachable findings on assets the internet cannot reach', 'vulnhub' ),
				),
				array(
					__( 'Not placed', 'vulnhub' ),
					(int) $d['totals']['unknown'],
					0,
					0,
					__( 'No CVSS v3 vector published, so no route can be inferred', 'vulnhub' ),
				),

				/*
				 * Reachability travels with the lanes. Exporting the findings
				 * without the basis they were split on would hand somebody a
				 * spreadsheet that looks like a conclusion, and the whole
				 * point of the three states is that one of them is "we have
				 * not checked".
				 */
				array(
					__( 'Reachability — confirmed', 'vulnhub' ),
					0,
					(int) ( $d['exposure']['confirmed'] ?? 0 ),
					0,
					__( 'A published service is listening, or the asset answers on a public address', 'vulnhub' ),
				),
				array(
					__( 'Reachability — never looked', 'vulnhub' ),
					0,
					(int) ( $d['exposure']['unknown'] ?? 0 ),
					0,
					__( 'No listening-port scan has run against it; neither reachable nor safe', 'vulnhub' ),
				),
				array(
					__( 'Reachability — ruled out', 'vulnhub' ),
					0,
					(int) ( $d['exposure']['ruled_out'] ?? 0 ),
					0,
					__( 'Scanned, and nothing a stranger could connect to was listening', 'vulnhub' ),
				),
				array(
					__( 'Reachability — unscanned servers', 'vulnhub' ),
					0,
					(int) ( $d['exposure']['unknown_servers'] ?? 0 ),
					0,
					__( 'Servers inside "never looked" — the coverage gap that bounds the edge lane', 'vulnhub' ),
				),
			),
		);
	}
}
