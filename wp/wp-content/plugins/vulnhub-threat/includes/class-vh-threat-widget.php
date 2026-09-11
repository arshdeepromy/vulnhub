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

	public static function assets(): void {
		wp_enqueue_style(
			'vulnhub-threat',
			VULNHUB_THREAT_URL . 'assets/threat.css',
			array(),
			VULNHUB_THREAT_VERSION
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

		self::render_svg( $d, $peak );
		self::render_cards( $d );

		printf(
			'<p class="vh-sub vh-flow__foot">%s</p>',
			esc_html(
				sprintf(
					/* translators: 1: total open findings, 2: internet-facing asset count, 3: EPSS threshold as a percentage, 4: findings with no CVSS vector. */
					__( 'Counted from %1$s open findings. %2$s assets are treated as reachable from the internet — everything else can only be reached once somebody is already inside. "Exploitable today" means the CVE is on CISA\'s exploited list, has a published exploit referenced by NVD, or FIRST puts it at %3$s or more likely to be exploited in the next 30 days. %4$s open findings carry no CVSS v3 vector and are not placed on any lane.', 'vulnhub' ),
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
		<svg class="vh-flow__svg" viewBox="0 0 1160 432" role="img"
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

			<!-- The three doors a person is handed something through. -->
			<?php
			$doors = array(
				array( 244, 228, __( 'email', 'vulnhub' ), (int) ( $deliv['mail'] ?? 0 ) ),
				array( 328, 260, __( 'website', 'vulnhub' ), (int) ( $deliv['web'] ?? 0 ) ),
				array( 412, 280, __( 'download', 'vulnhub' ), (int) ( $deliv['file'] ?? 0 ) ),
			);

			foreach ( $doors as $door ) :
				[ $x, $y, $label, $n ] = $door;
				?>
				<g class="vh-flow__door">
					<rect x="<?php echo (int) $x; ?>" y="<?php echo (int) $y; ?>" width="100" height="26" rx="13"/>
					<text x="<?php echo (int) $x + 50; ?>" y="<?php echo (int) $y + 17; ?>" text-anchor="middle">
						<?php echo esc_html( $label . ' · ' . number_format_i18n( $n ) ); ?>
					</text>
				</g>
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
				__( 'no account, no user, no click — a listening service', 'vulnhub' ),
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
	private static function lane_box( string $lane, int $x, int $y, int $n, int $assets, string $label, string $sub, int $w = 444 ): void {
		$url = VulnHub_Threat_Repo::lane_url( $lane );
		$h   = 106;

		printf( '<a href="%s" class="vh-flow__box vh-flow__box--%s">', esc_url( $url ), esc_attr( $lane ) );

		printf(
			'<rect x="%d" y="%d" width="%d" height="%d" rx="12"/>',
			$x,
			$y,
			$w,
			$h
		);
		printf( '<rect x="%d" y="%d" width="5" height="%d" rx="2.5" class="vh-flow__box-edge"/>', $x, $y, $h );

		printf(
			'<text x="%d" y="%d" class="vh-flow__n">%s</text>',
			$x + 26,
			$y + 50,
			esc_html( number_format_i18n( $n ) )
		);
		printf(
			'<text x="%d" y="%d" class="vh-flow__n-unit">%s</text>',
			$x + 26,
			$y + 72,
			esc_html(
				sprintf(
					/* translators: %s: number of assets. */
					_n( 'finding, on %s machine', 'findings, across %s machines', $assets, 'vulnhub' ),
					number_format_i18n( $assets )
				)
			)
		);
		printf(
			'<text x="%d" y="%d" class="vh-flow__box-label" text-anchor="end">%s</text>',
			$x + $w - 22,
			$y + 42,
			esc_html( $label )
		);
		printf(
			'<text x="%d" y="%d" class="vh-flow__box-sub" text-anchor="end">%s</text>',
			$x + $w - 22,
			$y + 62,
			esc_html( $sub )
		);
		printf(
			'<text x="%d" y="%d" class="vh-flow__box-cta" text-anchor="end">%s</text>',
			$x + $w - 22,
			$y + 88,
			esc_html__( 'see the findings →', 'vulnhub' )
		);

		echo '</a>';
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
				'lane'  => 'edge',
				'n'     => (int) $d['edge']['findings'],
				'label' => __( 'Straight from the internet', 'vulnhub' ),
				'note'  => sprintf(
					/* translators: %s: number of internet-facing assets. */
					__( 'On the %s assets anything outside can open a connection to. Nobody has to click.', 'vulnhub' ),
					number_format_i18n( (int) $d['totals']['facing'] )
				),
			),
			array(
				'lane'  => 'user',
				'n'     => (int) $d['user']['findings'],
				'label' => __( 'Handed to a person', 'vulnhub' ),
				'note'  => sprintf(
					/* translators: 1: email count, 2: website count, 3: download count. */
					__( 'Email %1$s · website %2$s · download %3$s. The exploit needs somebody to open something.', 'vulnhub' ),
					number_format_i18n( (int) ( $deliv['mail'] ?? 0 ) ),
					number_format_i18n( (int) ( $deliv['web'] ?? 0 ) ),
					number_format_i18n( (int) ( $deliv['file'] ?? 0 ) )
				),
			),
			array(
				'lane'  => 'inside',
				'n'     => (int) $d['inside']['findings'],
				'label' => __( 'Waiting once they are in', 'vulnhub' ),
				'note'  => sprintf(
					/* translators: %s: findings that are network-exploitable but on unreachable assets. */
					__( 'Includes %s that would be reachable from the internet if the machine were published, and is not.', 'vulnhub' ),
					number_format_i18n( (int) $d['inside']['borrowed'] )
				),
			),
		);

		echo '<ul class="vh-flow__cards">';

		foreach ( $lanes as $l ) {
			printf(
				'<li class="vh-flow__card vh-flow__card--%1$s"><a href="%2$s">'
				. '<span class="vh-flow__card-n">%3$s</span>'
				. '<span class="vh-flow__card-label">%4$s</span>'
				. '<span class="vh-flow__card-note">%5$s</span></a></li>',
				esc_attr( $l['lane'] ),
				esc_url( VulnHub_Threat_Repo::lane_url( $l['lane'] ) ),
				esc_html( number_format_i18n( $l['n'] ) ),
				esc_html( $l['label'] ),
				esc_html( $l['note'] )
			);
		}

		echo '</ul>';

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
			),
		);
	}
}
