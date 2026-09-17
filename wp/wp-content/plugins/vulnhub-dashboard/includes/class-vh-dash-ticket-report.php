<?php
/**
 * The Tickets page's report: what has been raised, and how tickets are doing.
 *
 * Two panels:
 *
 * - **Raised vs not raised.** Open findings per severity, split into those on
 *   a ticket and those not, for the severities ticked and for patchable, not
 *   patchable or both. Every number is a link to the Vulnerabilities list
 *   holding exactly those rows (same state, lifecycle scope, exception scope,
 *   patch test and ticket test), where they can be selected and raised.
 * - **Ticket report.** SLA outcome by severity, time to resolve, how long each
 *   critical ticket has taken against its SLA, and tickets raised vs resolved
 *   per week. Each with a CSV of the rows behind it.
 *
 * A ticket's SLA is its due date: the date it was raised with (see
 * docs/TICKETS.md, "Due dates"). Met means closed by the end of that day in
 * site time; breached means closed after it; overdue means still open after
 * it; on track means open and not yet due.
 *
 * @package VulnHub\Dashboard
 */

declare( strict_types = 1 );

use VulnHub\Core\Caps;
use VulnHub\Core\Repo;
use VulnHub\Core\Tickets;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Ticket coverage and ticket reporting.
 */
final class VulnHub_Dash_Ticket_Report {

	public const SEVERITIES = array( 'critical', 'high', 'medium', 'low' );

	/** Checkbox names on the wire, one per severity (arrays do not survive q()). */
	private const SEV_PARAM = array(
		'critical' => 'cov_c',
		'high'     => 'cov_h',
		'medium'   => 'cov_m',
		'low'      => 'cov_l',
	);

	public const SLA_STATES = array( 'met', 'on_track', 'breached', 'overdue' );

	public static function hooks(): void {
		add_action( 'admin_post_vulnhub_ticket_report_csv', array( self::class, 'handle_csv' ) );
	}

	/* =================================================================
	 * Raised vs not raised
	 * ============================================================== */

	/**
	 * Open, non-excepted findings on reporting-scope assets, by severity,
	 * patch availability and whether they are on a ticket.
	 *
	 * Cached against the widget epoch (moves on every sync and import) and
	 * the ticket-link table (moves on every raise).
	 *
	 * @return array<string,array<int,array<int,array{findings:int,assets:int}>>> severity => patchable(1|0) => raised(1|0) => counts.
	 */
	public static function coverage(): array {
		global $wpdb;

		$sig = implode(
			'|',
			array(
				class_exists( 'VulnHub_Dash_Widgets' ) ? VulnHub_Dash_Widgets::epoch() : '',
				(string) $wpdb->get_var( 'SELECT CONCAT(COUNT(*), ":", COALESCE(MAX(id),0)) FROM ' . vh_table( 'ticket_findings' ) ), // phpcs:ignore WordPress.DB.PreparedSQL
			)
		);
		$key    = 'vh_ticket_cov_' . md5( $sig );
		$cached = get_transient( $key );

		if ( is_array( $cached ) ) {
			return $cached;
		}

		$patch = Repo::patch_sql( 'v' );
		$rows  = (array) $wpdb->get_results(
			'SELECT f.severity AS severity,
				CASE WHEN ' . $patch . ' THEN 1 ELSE 0 END AS patchable,
				CASE WHEN f.ticket_id > 0 THEN 1 ELSE 0 END AS raised,
				COUNT(*) AS findings,
				COUNT(DISTINCT f.asset_id) AS assets
			 FROM ' . vh_table( 'findings' ) . ' f
			 INNER JOIN ' . vh_table( 'vulns' ) . ' v ON v.id = f.vuln_id
			 INNER JOIN ' . vh_table( 'assets' ) . " a ON a.id = f.asset_id
			 WHERE f.state IN ('open','reopened') AND f.exception_id = 0
			   AND a.lifecycle_status IN (" . vh_reportable_sql() . ')
			 GROUP BY f.severity, patchable, raised', // phpcs:ignore WordPress.DB.PreparedSQL
			ARRAY_A
		);

		$out = array();

		foreach ( self::SEVERITIES as $sev ) {
			foreach ( array( 1, 0 ) as $p ) {
				foreach ( array( 1, 0 ) as $r ) {
					$out[ $sev ][ $p ][ $r ] = array( 'findings' => 0, 'assets' => 0 );
				}
			}
		}

		foreach ( $rows as $row ) {
			$sev = (string) $row['severity'];

			if ( isset( $out[ $sev ] ) ) {
				$out[ $sev ][ (int) $row['patchable'] ][ (int) $row['raised'] ] = array(
					'findings' => (int) $row['findings'],
					'assets'   => (int) $row['assets'],
				);
			}
		}

		// Delete other signatures' copies lazily: they expire within the hour.
		set_transient( $key, $out, HOUR_IN_SECONDS );

		return $out;
	}

	/**
	 * Severities ticked, defaulting to critical and high.
	 *
	 * @return string[]
	 */
	public static function chosen_severities(): array {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET['cov'] ) ) {
			return array( 'critical', 'high' );
		}

		return array_values( array_filter( self::SEVERITIES, static fn( string $s ): bool => ! empty( $_GET[ self::SEV_PARAM[ $s ] ] ) ) );
		// phpcs:enable
	}

	public static function chosen_patch(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$p = isset( $_GET['cov_patch'] ) ? sanitize_key( wp_unslash( (string) $_GET['cov_patch'] ) ) : 'both';

		return in_array( $p, array( 'both', 'yes', 'no' ), true ) ? $p : 'both';
	}

	/**
	 * Counts for one severity under a patch choice.
	 *
	 * @return array{raised:array{findings:int,assets:int},not:array{findings:int,assets:int}}
	 */
	private static function cell( array $cov, string $sev, string $patch ): array {
		$pick = 'both' === $patch ? array( 1, 0 ) : array( 'yes' === $patch ? 1 : 0 );
		$out  = array( 'raised' => array( 'findings' => 0, 'assets' => 0 ), 'not' => array( 'findings' => 0, 'assets' => 0 ) );

		foreach ( $pick as $p ) {
			foreach ( array( 1 => 'raised', 0 => 'not' ) as $r => $side ) {
				$out[ $side ]['findings'] += $cov[ $sev ][ $p ][ $r ]['findings'];
				// Assets can sit in both halves; summed, this is an upper bound
				// and the tooltip says "up to" when both are counted.
				$out[ $side ]['assets'] += $cov[ $sev ][ $p ][ $r ]['assets'];
			}
		}

		return $out;
	}

	/**
	 * The Vulnerabilities list holding exactly one number's rows.
	 *
	 * @param bool|null $raised True: on a ticket; false: not; null: either.
	 */
	public static function list_url( string $severity, string $patch, ?bool $raised ): string {
		$args = array(
			'severity' => $severity,
			'state'    => 'open_any',
			'excepted' => 'exclude',
		);

		if ( 'both' !== $patch ) {
			$args['patch_available'] = 'yes' === $patch ? '1' : '0';
		}
		if ( null !== $raised ) {
			$args['ticketed'] = $raised ? 'yes' : 'no';
		}

		return VulnHub_Dash_Portal::portal_url( 'vulnerabilities', $args );
	}

	public static function render_coverage(): void {
		$cov    = self::coverage();
		$chosen = self::chosen_severities();
		$patch  = self::chosen_patch();
		$can    = current_user_can( Caps::RAISE_TICKET );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$keep   = array_diff_key( is_array( $_GET ) ? wp_unslash( $_GET ) : array(), array_flip( array_merge( array_values( self::SEV_PARAM ), array( 'cov', 'cov_patch', 'tp' ) ) ) );
		?>
		<section class="vh-panel vh-trep" aria-labelledby="vh-trep-cov">
			<div class="vh-trep__head">
				<div>
					<h2 id="vh-trep-cov"><?php esc_html_e( 'Raised vs not raised', 'vulnhub' ); ?></h2>
					<p class="vh-sub"><?php esc_html_e( 'Open findings on the assets the dashboard reports on, excluding accepted risk. Click a number to open exactly those findings.', 'vulnhub' ); ?></p>
				</div>
				<a class="vh-btn vh-btn--ghost vh-btn--sm" href="<?php echo esc_url( self::csv_url( 'coverage' ) ); ?>"><?php esc_html_e( 'Export CSV', 'vulnhub' ); ?></a>
			</div>

			<form class="vh-trep__controls" method="get" data-vh-autosubmit>
				<?php foreach ( $keep as $k => $v ) : ?>
					<?php if ( ! is_array( $v ) && '' !== sanitize_key( (string) $k ) ) : ?>
						<input type="hidden" name="<?php echo esc_attr( sanitize_key( (string) $k ) ); ?>" value="<?php echo esc_attr( sanitize_text_field( (string) $v ) ); ?>">
					<?php endif; ?>
				<?php endforeach; ?>
				<input type="hidden" name="cov" value="1">
				<fieldset class="vh-trep__chips">
					<legend><?php esc_html_e( 'Severity', 'vulnhub' ); ?></legend>
					<?php foreach ( self::SEVERITIES as $sev ) : ?>
						<label class="vh-chipcheck vh-chipcheck--<?php echo esc_attr( $sev ); ?>">
							<input type="checkbox" name="<?php echo esc_attr( self::SEV_PARAM[ $sev ] ); ?>" value="1" <?php checked( in_array( $sev, $chosen, true ) ); ?>>
							<span><?php echo esc_html( vh_severity_label( $sev ) ); ?></span>
						</label>
					<?php endforeach; ?>
				</fieldset>
				<fieldset class="vh-trep__chips">
					<legend><?php esc_html_e( 'Patch', 'vulnhub' ); ?></legend>
					<?php foreach ( array( 'yes' => __( 'Patchable', 'vulnhub' ), 'no' => __( 'Not patchable', 'vulnhub' ), 'both' => __( 'Both', 'vulnhub' ) ) as $val => $label ) : ?>
						<label class="vh-chipcheck">
							<input type="radio" name="cov_patch" value="<?php echo esc_attr( $val ); ?>" <?php checked( $patch, $val ); ?>>
							<span><?php echo esc_html( $label ); ?></span>
						</label>
					<?php endforeach; ?>
				</fieldset>
				<noscript><button class="vh-btn vh-btn--sm"><?php esc_html_e( 'Show', 'vulnhub' ); ?></button></noscript>
			</form>

			<?php if ( ! $chosen ) : ?>
				<p class="vh-chart-empty"><?php esc_html_e( 'Tick at least one severity.', 'vulnhub' ); ?></p>
			<?php else : ?>
				<div class="vh-trep__bars">
					<?php foreach ( $chosen as $sev ) : ?>
						<?php
						$c     = self::cell( $cov, $sev, $patch );
						$r     = $c['raised']['findings'];
						$n     = $c['not']['findings'];
						$total = $r + $n;
						$pct   = $total ? round( 100 * $r / $total ) : 0;
						?>
						<div class="vh-trep__row">
							<div class="vh-trep__label">
								<span class="vh-sevdot vh-sevdot--<?php echo esc_attr( $sev ); ?>"></span>
								<a href="<?php echo esc_url( self::list_url( $sev, $patch, null ) ); ?>"><?php echo esc_html( vh_severity_label( $sev ) ); ?></a>
								<span class="vh-meta">
									<?php
									/* translators: 1: total findings, 2: percent raised. */
									echo esc_html( sprintf( __( '%1$s findings · %2$s%% raised', 'vulnhub' ), number_format_i18n( $total ), $pct ) );
									?>
								</span>
							</div>
							<div class="vh-trep__track" role="img" aria-label="<?php echo esc_attr( sprintf( '%s: %s raised, %s not raised', vh_severity_label( $sev ), number_format_i18n( $r ), number_format_i18n( $n ) ) ); ?>">
								<?php if ( $total ) : ?>
									<a class="vh-trep__seg vh-trep__seg--raised" style="flex:<?php echo (int) $r; ?>" href="<?php echo esc_url( self::list_url( $sev, $patch, true ) ); ?>" data-vh-tip="<?php echo esc_attr( sprintf( __( '%s raised', 'vulnhub' ), number_format_i18n( $r ) ) ); ?>"></a>
									<a class="vh-trep__seg vh-trep__seg--not vh-trep__seg--<?php echo esc_attr( $sev ); ?>" style="flex:<?php echo (int) $n; ?>" href="<?php echo esc_url( self::list_url( $sev, $patch, false ) ); ?>" data-vh-tip="<?php echo esc_attr( sprintf( __( '%s not raised', 'vulnhub' ), number_format_i18n( $n ) ) ); ?>"></a>
								<?php endif; ?>
							</div>
							<div class="vh-trep__nums">
								<a class="vh-trep__num vh-trep__num--not" href="<?php echo esc_url( self::list_url( $sev, $patch, false ) ); ?>">
									<strong><?php echo esc_html( number_format_i18n( $n ) ); ?></strong>
									<span>
										<?php
										/* translators: %s: assets. */
										echo esc_html( sprintf( __( 'not raised · %s assets', 'vulnhub' ), ( 'both' === $patch ? '≤' : '' ) . number_format_i18n( $c['not']['assets'] ) ) );
										?>
									</span>
								</a>
								<a class="vh-trep__num vh-trep__num--raised" href="<?php echo esc_url( self::list_url( $sev, $patch, true ) ); ?>">
									<strong><?php echo esc_html( number_format_i18n( $r ) ); ?></strong>
									<span><?php esc_html_e( 'raised', 'vulnhub' ); ?></span>
								</a>
							</div>
						</div>
					<?php endforeach; ?>
				</div>
				<p class="vh-meta vh-trep__foot">
					<span class="vh-trep__key vh-trep__key--raised"></span><?php esc_html_e( 'On a ticket', 'vulnhub' ); ?>
					<span class="vh-trep__key vh-trep__key--not"></span><?php esc_html_e( 'Not raised', 'vulnhub' ); ?>
					<?php if ( $can ) : ?>
						&nbsp;·&nbsp;<?php esc_html_e( 'To raise: open a "not raised" number, choose "Select all matching" (up to 500) or tick rows, then "Raise ticket for selected".', 'vulnhub' ); ?>
					<?php endif; ?>
				</p>
			<?php endif; ?>
		</section>
		<?php
	}

	/* =================================================================
	 * Ticket facts
	 * ============================================================== */

	/**
	 * One row per ticket with everything the report measures.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public static function facts(): array {
		global $wpdb;

		static $memo = null;

		if ( null !== $memo ) {
			return $memo;
		}

		$rows = (array) $wpdb->get_results(
			'SELECT t.id, t.external_key, t.url, t.kind, t.summary, t.status, t.status_category, t.assignee,
				t.verification_state, t.finding_count, t.asset_count, t.payload_json, t.created_at, t.remote_closed_at, t.updated_at,
				( SELECT MAX( CASE f.severity WHEN \'critical\' THEN 4 WHEN \'high\' THEN 3 WHEN \'medium\' THEN 2 WHEN \'low\' THEN 1 ELSE 0 END )
				  FROM ' . vh_table( 'ticket_findings' ) . ' tf JOIN ' . vh_table( 'findings' ) . ' f ON f.id = tf.finding_id WHERE tf.ticket_id = t.id ) AS sev_rank
			 FROM ' . vh_table( 'tickets' ) . " t
			 WHERE t.external_key <> ''
			 ORDER BY t.created_at DESC", // phpcs:ignore WordPress.DB.PreparedSQL
			ARRAY_A
		);

		$now  = time();
		$tz   = wp_timezone();
		$rank = array( 4 => 'critical', 3 => 'high', 2 => 'medium', 1 => 'low' );
		$out  = array();

		foreach ( $rows as $row ) {
			$payload  = json_decode( (string) $row['payload_json'], true );
			$payload  = is_array( $payload ) ? $payload : array();
			$is_asset = (int) $row['asset_count'] > 0;
			$severity = $is_asset ? '' : (string) ( $payload['severity'] ?? '' );

			if ( ! in_array( $severity, self::SEVERITIES, true ) ) {
				$severity = $is_asset ? '' : ( $rank[ (int) $row['sev_rank'] ] ?? '' );
			}

			$created = (int) strtotime( (string) $row['created_at'] . ' UTC' );
			$done    = 'done' === (string) $row['status_category'];
			$closed  = 0;

			if ( $done ) {
				$when   = '' !== (string) $row['remote_closed_at'] ? (string) $row['remote_closed_at'] : (string) $row['updated_at'];
				$closed = (int) strtotime( $when . ' UTC' );
			}

			$due     = Tickets::due_date( $row );
			$due_end = 0;

			if ( '' !== $due ) {
				$d       = DateTimeImmutable::createFromFormat( 'Y-m-d H:i:s', $due . ' 23:59:59', $tz );
				$due_end = $d ? $d->getTimestamp() : 0;
			}

			if ( ! $due_end ) {
				$state = 'no_due';
			} elseif ( $done ) {
				$state = $closed <= $due_end ? 'met' : 'breached';
			} else {
				$state = $now > $due_end ? 'overdue' : 'on_track';
			}

			$days     = max( 0, ( ( $done ? $closed : $now ) - $created ) / DAY_IN_SECONDS );
			$sla_days = $due_end ? max( 0, ( $due_end - $created ) / DAY_IN_SECONDS ) : 0;

			$out[] = array(
				'id'           => (int) $row['id'],
				'key'          => (string) $row['external_key'],
				'url'          => (string) $row['url'],
				'type'         => Tickets::kind_label( (string) $row['kind'] ),
				'summary'      => (string) $row['summary'],
				'severity'     => $severity,
				'status'       => (string) $row['status'],
				'done'         => $done,
				'assignee'     => (string) $row['assignee'],
				'created'      => $created,
				'due'          => $due,
				'closed'       => $closed,
				'days'         => $days,
				'sla_days'     => $sla_days,
				'sla'          => $state,
				'late_days'    => $due_end ? max( 0, ( ( $done ? $closed : $now ) - $due_end ) / DAY_IN_SECONDS ) : 0,
				'verification' => (string) ( Tickets::verification_labels()[ (string) $row['verification_state'] ] ?? '' ),
				'findings'     => (int) $row['finding_count'],
				'assets'       => (int) $row['asset_count'],
			);
		}

		$memo = $out;

		return $memo;
	}

	/**
	 * Ticket ids for the Tickets list's `sla` and `severity` filters, or null
	 * when neither is set.
	 *
	 * @return int[]|null
	 */
	public static function ids_for( string $sla, string $severity ): ?array {
		if ( '' === $sla && '' === $severity ) {
			return null;
		}

		$ids = array();

		foreach ( self::facts() as $f ) {
			if ( '' !== $sla && $f['sla'] !== $sla ) {
				continue;
			}
			if ( '' !== $severity && ( 'asset' === $severity ? $f['assets'] <= 0 : $f['severity'] !== $severity ) ) {
				continue;
			}
			$ids[] = (int) $f['id'];
		}

		return $ids;
	}

	public static function sla_label( string $state ): string {
		return array(
			'met'      => __( 'Met SLA', 'vulnhub' ),
			'on_track' => __( 'On track', 'vulnhub' ),
			'breached' => __( 'Closed late', 'vulnhub' ),
			'overdue'  => __( 'Overdue', 'vulnhub' ),
			'no_due'   => __( 'No due date', 'vulnhub' ),
		)[ $state ] ?? $state;
	}

	private static function tickets_url( array $args ): string {
		return VulnHub_Dash_Portal::portal_url( 'tickets', $args );
	}

	/* =================================================================
	 * Ticket report
	 * ============================================================== */

	public static function render_report(): void {
		$facts = self::facts();
		?>
		<section class="vh-panel vh-trep" aria-labelledby="vh-trep-rep">
			<div class="vh-trep__head">
				<div>
					<h2 id="vh-trep-rep"><?php esc_html_e( 'Ticket report', 'vulnhub' ); ?></h2>
					<p class="vh-sub"><?php esc_html_e( 'SLA is the due date each ticket was raised with. Resolution time runs from raising the ticket to its closure in Jira.', 'vulnhub' ); ?></p>
				</div>
				<a class="vh-btn vh-btn--ghost vh-btn--sm" href="<?php echo esc_url( self::csv_url( 'tickets' ) ); ?>"><?php esc_html_e( 'Export CSV', 'vulnhub' ); ?></a>
			</div>
			<?php
			if ( ! $facts ) {
				echo VulnHub_Dash_Charts::empty_state( esc_html__( 'No tickets raised yet. The report fills in as tickets are raised and closed.', 'vulnhub' ) ); // phpcs:ignore WordPress.Security.EscapeOutput
				echo '</section>';
				return;
			}

			$sla_rows = array();
			$counts   = array_fill_keys( array( 'met', 'on_track', 'breached', 'overdue' ), 0 );
			$groups   = array_merge( self::SEVERITIES, array( 'asset' ) );
			$tones    = array(
				'met'      => 'var(--vh-good)',
				'on_track' => 'var(--vh-series-1)',
				'breached' => 'var(--vh-warn)',
				'overdue'  => 'var(--vh-bad)',
			);

			foreach ( $groups as $g ) {
				$in = array_filter( $facts, static fn( array $f ): bool => 'asset' === $g ? $f['assets'] > 0 : $f['severity'] === $g );

				if ( ! $in ) {
					continue;
				}

				$segments = array();

				foreach ( array_keys( $tones ) as $state ) {
					$n                = count( array_filter( $in, static fn( array $f ): bool => $f['sla'] === $state ) );
					$counts[ $state ] += $n;
					$segments[]       = array(
						'label'  => self::sla_label( $state ),
						'value'  => $n,
						'colour' => $tones[ $state ],
						'href'   => self::tickets_url( array( 'sla' => $state, 'tsev' => $g ) ),
					);
				}

				$sla_rows[] = array(
					'label'      => 'asset' === $g ? __( 'Asset requests', 'vulnhub' ) : vh_severity_label( $g ),
					'segments'   => $segments,
					'total_href' => self::tickets_url( array( 'tsev' => $g ) ),
				);
			}

			$closed      = array_values( array_filter( $facts, static fn( array $f ): bool => $f['done'] ) );
			$failed      = $counts['breached'] + $counts['overdue'];
			$measured    = array_sum( $counts );
			$crit_closed = array_values( array_filter( $closed, static fn( array $f ): bool => 'critical' === $f['severity'] ) );
			?>
			<div class="vh-tiles vh-trep__tiles">
				<?php
				echo VulnHub_Dash_Charts::stat_tile( // phpcs:ignore WordPress.Security.EscapeOutput
					array(
						'label' => __( 'Failed SLA', 'vulnhub' ),
						'value' => $failed,
						'tone'  => $failed ? 'critical' : 'good',
						/* translators: 1: overdue, 2: closed late, 3: percent. */
						'meta'  => sprintf( __( '%1$d overdue, %2$d closed late (%3$s%% of tickets with a due date)', 'vulnhub' ), $counts['overdue'], $counts['breached'], $measured ? number_format_i18n( round( 100 * $failed / $measured ) ) : '0' ),
						'href'  => self::tickets_url( array( 'sla' => 'overdue' ) ),
					)
				);
				echo VulnHub_Dash_Charts::stat_tile( // phpcs:ignore WordPress.Security.EscapeOutput
					array(
						'label' => __( 'Median time to resolve', 'vulnhub' ),
						'value' => $closed ? self::days_text( self::median( array_column( $closed, 'days' ) ) ) : '—',
						'tone'  => 'neutral',
						/* translators: %d: closed tickets. */
						'meta'  => sprintf( _n( 'across %d closed ticket', 'across %d closed tickets', count( $closed ), 'vulnhub' ), count( $closed ) ),
					)
				);
				echo VulnHub_Dash_Charts::stat_tile( // phpcs:ignore WordPress.Security.EscapeOutput
					array(
						'label' => __( 'Critical: median to resolve', 'vulnhub' ),
						'value' => $crit_closed ? self::days_text( self::median( array_column( $crit_closed, 'days' ) ) ) : '—',
						'tone'  => 'neutral',
						/* translators: %d: SLA days. */
						'meta'  => sprintf( __( 'SLA %d days', 'vulnhub' ), vh_sla_days( 'critical' ) ),
					)
				);
				?>
			</div>

			<div class="vh-trep__grid">
				<div class="vh-trep__card">
					<h3><?php esc_html_e( 'SLA outcome by severity', 'vulnhub' ); ?></h3>
					<?php
					echo VulnHub_Dash_Charts::segment_bars( // phpcs:ignore WordPress.Security.EscapeOutput
						$sla_rows,
						array(
							'unit'   => __( 'tickets', 'vulnhub' ),
							'legend' => array_map( static fn( string $s ): array => array( 'label' => self::sla_label( $s ), 'colour' => $tones[ $s ] ), array_keys( $tones ) ),
							'empty'  => __( 'No tickets with a due date yet.', 'vulnhub' ),
						)
					);
					?>
				</div>

				<div class="vh-trep__card">
					<h3><?php esc_html_e( 'Time to resolve', 'vulnhub' ); ?></h3>
					<?php
					$bands     = array(
						'le7'  => array( __( '≤ 7 days', 'vulnhub' ), 0, 7, 'var(--vh-good)' ),
						'le30' => array( __( '8–30 days', 'vulnhub' ), 7, 30, 'var(--vh-series-1)' ),
						'le90' => array( __( '31–90 days', 'vulnhub' ), 30, 90, 'var(--vh-warn)' ),
						'gt90' => array( __( '> 90 days', 'vulnhub' ), 90, PHP_INT_MAX, 'var(--vh-bad)' ),
					);
					$ttr_rows  = array();
					foreach ( $groups as $g ) {
						$in = array_filter( $closed, static fn( array $f ): bool => 'asset' === $g ? $f['assets'] > 0 : $f['severity'] === $g );
						if ( ! $in ) {
							continue;
						}
						$ttr_rows[] = array(
							'label'    => 'asset' === $g ? __( 'Asset requests', 'vulnhub' ) : vh_severity_label( $g ),
							/* translators: 1: median, 2: average. */
							'sub'      => sprintf( __( 'median %1$s · average %2$s', 'vulnhub' ), self::days_text( self::median( array_column( $in, 'days' ) ) ), self::days_text( array_sum( array_column( $in, 'days' ) ) / count( $in ) ) ),
							'segments' => array_values(
								array_map(
									static fn( array $b ): array => array(
										'label'  => $b[0],
										// Bands are (lo, hi]; the first one starts at zero inclusive.
										'value'  => count( array_filter( $in, static fn( array $f ): bool => ( 0 === $b[1] || $f['days'] > $b[1] ) && $f['days'] <= $b[2] ) ),
										'colour' => $b[3],
									),
									$bands
								)
							),
						);
					}
					echo VulnHub_Dash_Charts::segment_bars( // phpcs:ignore WordPress.Security.EscapeOutput
						$ttr_rows,
						array(
							'unit'   => __( 'closed tickets', 'vulnhub' ),
							'legend' => array_values( array_map( static fn( array $b ): array => array( 'label' => $b[0], 'colour' => $b[3] ), $bands ) ),
							'empty'  => __( 'No closed tickets yet, so nothing to time.', 'vulnhub' ),
						)
					);
					?>
				</div>

				<div class="vh-trep__card vh-trep__card--wide">
					<h3><?php esc_html_e( 'Critical tickets: days taken against SLA', 'vulnhub' ); ?></h3>
					<?php self::render_critical( $facts ); ?>
				</div>

				<div class="vh-trep__card vh-trep__card--wide">
					<h3><?php esc_html_e( 'Raised vs resolved, last 12 weeks', 'vulnhub' ); ?></h3>
					<?php
					$weeks = self::weekly( $facts );
					echo VulnHub_Dash_Charts::line_chart( // phpcs:ignore WordPress.Security.EscapeOutput
						array(
							__( 'Raised', 'vulnhub' )   => $weeks['raised'],
							__( 'Resolved', 'vulnhub' ) => $weeks['resolved'],
						),
						array(
							__( 'Raised', 'vulnhub' )   => 'var(--vh-series-1)',
							__( 'Resolved', 'vulnhub' ) => 'var(--vh-good)',
						),
						array( 'height' => 180, 'unit' => __( 'tickets', 'vulnhub' ) )
					);
					?>
				</div>
			</div>
		</section>
		<?php
	}

	/**
	 * One bar per critical ticket: days taken, the SLA marked on the track.
	 *
	 * @param array<int,array<string,mixed>> $facts Facts.
	 */
	private static function render_critical( array $facts ): void {
		$crit = array_values( array_filter( $facts, static fn( array $f ): bool => 'critical' === $f['severity'] && ( ! $f['done'] || $f['closed'] > time() - 90 * DAY_IN_SECONDS ) ) );

		if ( ! $crit ) {
			echo VulnHub_Dash_Charts::empty_state( esc_html__( 'No critical tickets open or closed in the last 90 days.', 'vulnhub' ) ); // phpcs:ignore WordPress.Security.EscapeOutput
			return;
		}

		usort( $crit, static fn( array $a, array $b ): int => $b['days'] <=> $a['days'] );
		$shown = array_slice( $crit, 0, 25 );
		$max   = max( 1.0, max( array_map( static fn( array $f ): float => max( (float) $f['days'], (float) $f['sla_days'] ), $shown ) ) );

		echo '<div class="vh-trep__crit">';

		foreach ( $shown as $f ) {
			$tone = array( 'met' => 'good', 'on_track' => 'info', 'breached' => 'warn', 'overdue' => 'bad' )[ $f['sla'] ] ?? 'info';
			$href = VulnHub_Dash_Portal::portal_url( 'tickets', array( 'ticket' => $f['id'] ) );
			/* translators: 1: key, 2: days, 3: SLA days, 4: state. */
			$tip  = sprintf( __( '%1$s: %2$s taken, SLA %3$s, %4$s', 'vulnhub' ), $f['key'], self::days_text( $f['days'] ), self::days_text( $f['sla_days'] ), strtolower( self::sla_label( $f['sla'] ) ) );

			printf(
				'<a class="vh-trep__critrow" href="%1$s" data-vh-tip="%2$s"><span class="vh-mono vh-trep__critkey">%3$s</span><span class="vh-trep__crittrack"><span class="vh-trep__critbar vh-trep__critbar--%4$s" style="width:%5$s%%"></span>%6$s</span><span class="vh-trep__critdays">%7$s <em>%8$s</em></span></a>',
				esc_url( $href ),
				esc_attr( $tip ),
				esc_html( $f['key'] ),
				esc_attr( $tone ),
				esc_attr( (string) round( 100 * $f['days'] / $max, 2 ) ),
				$f['sla_days'] > 0 ? '<span class="vh-trep__critsla" style="left:' . esc_attr( (string) round( 100 * $f['sla_days'] / $max, 2 ) ) . '%" title="' . esc_attr__( 'SLA', 'vulnhub' ) . '"></span>' : '',
				esc_html( self::days_text( $f['days'] ) ),
				esc_html( $f['done'] ? __( 'closed', 'vulnhub' ) : __( 'open', 'vulnhub' ) )
			);
		}

		echo '</div>';

		if ( count( $crit ) > count( $shown ) ) {
			/* translators: %d: hidden tickets. */
			echo '<p class="vh-meta">' . esc_html( sprintf( __( 'The 25 longest are shown; %d more are in the CSV.', 'vulnhub' ), count( $crit ) - count( $shown ) ) ) . '</p>';
		}

		echo '<p class="vh-meta"><span class="vh-trep__key vh-trep__key--sla"></span>' . esc_html__( 'Marker: the SLA (due date). Open tickets keep growing until they close.', 'vulnhub' ) . '</p>';
	}

	/**
	 * Tickets raised and resolved per week (weeks start Monday, site time).
	 *
	 * @param array<int,array<string,mixed>> $facts Facts.
	 * @return array{raised:array<string,float>,resolved:array<string,float>}
	 */
	private static function weekly( array $facts ): array {
		$tz     = wp_timezone();
		$monday = ( new DateTimeImmutable( 'now', $tz ) )->modify( 'monday this week' )->setTime( 0, 0 );
		$out    = array( 'raised' => array(), 'resolved' => array() );
		$starts = array();

		for ( $i = 11; $i >= 0; $i-- ) {
			$start               = $monday->modify( '-' . $i . ' weeks' );
			$label               = $start->format( 'Y-m-d' );
			$starts[ $label ]    = $start->getTimestamp();
			$out['raised'][ $label ]   = 0;
			$out['resolved'][ $label ] = 0;
		}

		$bucket = static function ( int $ts ) use ( $starts ): string {
			$hit = '';
			foreach ( $starts as $label => $start ) {
				if ( $ts >= $start && $ts < $start + WEEK_IN_SECONDS ) {
					$hit = $label;
				}
			}
			return $hit;
		};

		foreach ( $facts as $f ) {
			$b = $bucket( (int) $f['created'] );
			if ( '' !== $b ) {
				++$out['raised'][ $b ];
			}
			if ( $f['done'] ) {
				$b = $bucket( (int) $f['closed'] );
				if ( '' !== $b ) {
					++$out['resolved'][ $b ];
				}
			}
		}

		return $out;
	}

	/**
	 * @param float[] $values Values.
	 */
	private static function median( array $values ): float {
		if ( ! $values ) {
			return 0.0;
		}

		sort( $values );
		$n = count( $values );

		return $n % 2 ? (float) $values[ intdiv( $n, 2 ) ] : ( $values[ $n / 2 - 1 ] + $values[ $n / 2 ] ) / 2;
	}

	private static function days_text( float $days ): string {
		if ( $days < 1 ) {
			/* translators: %s: hours. */
			return sprintf( __( '%sh', 'vulnhub' ), number_format_i18n( max( 0, round( $days * 24 ) ) ) );
		}

		/* translators: %s: days. */
		return sprintf( __( '%sd', 'vulnhub' ), number_format_i18n( $days, $days < 10 ? 1 : 0 ) );
	}

	/* =================================================================
	 * CSV
	 * ============================================================== */

	public static function csv_url( string $set ): string {
		return str_replace(
			'&amp;',
			'&',
			wp_nonce_url(
				add_query_arg( array( 'action' => 'vulnhub_ticket_report_csv', 'set' => $set ), admin_url( 'admin-post.php' ) ),
				'vulnhub_ticket_report_csv_' . $set
			)
		);
	}

	/**
	 * @return array{headers:string[],rows:array<int,array<int,string>>}
	 */
	public static function csv_data( string $set ): array {
		if ( 'coverage' === $set ) {
			$cov  = self::coverage();
			$rows = array();

			foreach ( self::SEVERITIES as $sev ) {
				foreach ( array( 1 => 'yes', 0 => 'no' ) as $p => $pl ) {
					foreach ( array( 1 => 'yes', 0 => 'no' ) as $r => $rl ) {
						$rows[] = array(
							vh_severity_label( $sev ),
							$pl,
							$rl,
							(string) $cov[ $sev ][ $p ][ $r ]['findings'],
							(string) $cov[ $sev ][ $p ][ $r ]['assets'],
							self::list_url( $sev, $pl, 'yes' === $rl ),
						);
					}
				}
			}

			return array(
				'headers' => array( 'Severity', 'Patch available', 'Raised', 'Open findings', 'Assets', 'List' ),
				'rows'    => $rows,
			);
		}

		$fmt = static fn( int $ts ): string => $ts ? wp_date( 'Y-m-d H:i', $ts ) : '';

		return array(
			'headers' => array( 'Key', 'Type', 'Severity', 'Summary', 'Status', 'Assignee', 'Raised', 'Due date', 'SLA days', 'Closed', 'Days open / to resolve', 'SLA', 'Days past due', 'Verification', 'Findings', 'Assets', 'Link' ),
			'rows'    => array_map(
				static fn( array $f ): array => array(
					$f['key'],
					$f['type'],
					'' !== $f['severity'] ? vh_severity_label( $f['severity'] ) : '',
					$f['summary'],
					$f['status'],
					$f['assignee'],
					$fmt( (int) $f['created'] ),
					$f['due'],
					$f['sla_days'] ? (string) round( $f['sla_days'], 1 ) : '',
					$fmt( (int) $f['closed'] ),
					(string) round( $f['days'], 1 ),
					self::sla_label( $f['sla'] ),
					(string) round( $f['late_days'], 1 ),
					$f['verification'],
					(string) $f['findings'],
					(string) $f['assets'],
					$f['url'],
				),
				self::facts()
			),
		);
	}

	public static function handle_csv(): void {
		if ( ! is_user_logged_in() || ! current_user_can( Caps::VIEW ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$set = isset( $_GET['set'] ) && 'coverage' === sanitize_key( wp_unslash( (string) $_GET['set'] ) ) ? 'coverage' : 'tickets';

		check_admin_referer( 'vulnhub_ticket_report_csv_' . $set );

		$data = self::csv_data( $set );

		vulnhub()->logger->audit( 'export.ticket_report', sprintf( 'Exported the ticket report (%s, %d rows)', $set, count( $data['rows'] ) ), 'export', $set );

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . ( 'coverage' === $set ? 'tickets-raised-vs-not' : 'ticket-report' ) . '-' . wp_date( 'Y-m-d' ) . '.csv"' );

		$out = fopen( 'php://output', 'w' );
		fwrite( $out, "\xEF\xBB\xBF" );
		fputcsv( $out, $data['headers'] );

		foreach ( $data['rows'] as $row ) {
			// Formula injection: a cell starting with = + - @ is text.
			fputcsv( $out, array_map( static fn( string $c ): string => '' !== $c && in_array( $c[0], array( '=', '+', '-', '@' ), true ) && ! is_numeric( $c ) ? "'" . $c : $c, $row ) );
		}

		fclose( $out );
		exit;
	}
}
