<?php
/**
 * Closure-verification responder.
 *
 * When a ticket is closed in the ITSM tool, "done" is a claim, not evidence.
 * Core parks the ticket in the `pending` verification state and fires
 * `vulnhub_verify_closures` hourly; this class answers that hook for the
 * Tenable connector.
 *
 * For each pending ticket it:
 *
 *   1. waits until the platform's configured settling period has elapsed
 *      (`auto_verify_hours` after the ticket was closed remotely), so the
 *      re-check happens after a rescan has plausibly run;
 *   2. re-checks every finding the ticket covers against *current* Tenable
 *      data — live, via a vulnerability export narrowed to the plugin ids in
 *      question; in mock mode, by re-evaluating the deterministic fixture;
 *   3. records a verdict with a human-readable note explaining, per finding,
 *      why it landed where it did.
 *
 * Verdicts:
 *   VERIFY_CONFIRMED   every covered finding is FIXED (or no longer reported
 *                      by a scan that has since run against the asset).
 *   VERIFY_STILL_OPEN  at least one finding is still detected. Those findings
 *                      are flipped back to `reopened` — the ticket said it was
 *                      done and it demonstrably is not.
 *   VERIFY_UNKNOWN     Tenable has no scan data for the asset since the ticket
 *                      closed, so nothing can honestly be concluded.
 *
 * @package VulnHub\Tenable
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Answers `vulnhub_verify_closures` for the Tenable connector.
 */
final class VulnHub_Tenable_Verifier {

	/**
	 * Maximum tickets examined per pass, so an hourly cron stays bounded.
	 */
	private const BATCH = 25;

	/**
	 * How many verdicts to keep for the admin screen.
	 */
	private const HISTORY = 30;

	/**
	 * Register hooks.
	 */
	public function hooks(): void {
		// Zero accepted args: `do_action()` with no payload still hands the
		// callback an empty string, which is a TypeError against `int $limit`.
		add_action( 'vulnhub_verify_closures', array( $this, 'run' ), 10, 0 );
		add_action( 'admin_post_vulnhub_tenable_verify', array( $this, 'handle_manual_run' ) );
	}

	/**
	 * Re-check every ticket awaiting verification.
	 *
	 * @param int $limit Maximum tickets to examine.
	 * @return array{checked:int,confirmed:int,still_open:int,unknown:int,waiting:int}
	 */
	public function run( int $limit = self::BATCH ): array {
		$totals = array(
			'checked'    => 0,
			'confirmed'  => 0,
			'still_open' => 0,
			'unknown'    => 0,
			'waiting'    => 0,
		);

		$connector = vulnhub()->connectors->get( 'tenable' );

		if ( ! $connector instanceof VulnHub_Tenable_Connector ) {
			return $totals;
		}
		if ( ! $connector->is_enabled() ) {
			return $totals;
		}

		$delay_hours = vh_verification_delay_hours();
		$tickets     = \VulnHub\Core\Tickets::awaiting_verification( max( 1, min( 200, $limit ) ) );

		foreach ( $tickets as $ticket ) {
			$outcome = $this->verify_ticket( $connector, $ticket, $delay_hours );

			if ( 'waiting' === $outcome ) {
				++$totals['waiting'];
				continue;
			}

			++$totals['checked'];

			match ( $outcome ) {
				\VulnHub\Core\Tickets::VERIFY_CONFIRMED  => $totals['confirmed']  = $totals['confirmed'] + 1,
				\VulnHub\Core\Tickets::VERIFY_STILL_OPEN => $totals['still_open'] = $totals['still_open'] + 1,
				default                                  => $totals['unknown']    = $totals['unknown'] + 1,
			};
		}

		return $totals;
	}

	/**
	 * Verify one ticket.
	 *
	 * @param VulnHub_Tenable_Connector $connector   The Tenable connector.
	 * @param array<string,mixed>       $ticket      Ticket row.
	 * @param int                       $delay_hours Settling period in hours.
	 * @return string A Tickets::VERIFY_* constant, or 'waiting'.
	 */
	private function verify_ticket( VulnHub_Tenable_Connector $connector, array $ticket, int $delay_hours ): string {
		$ticket_id = (int) $ticket['id'];
		$key       = (string) ( $ticket['external_key'] ?: $ticket_id );
		$closed    = (string) ( $ticket['remote_closed_at'] ?: $ticket['updated_at'] ?? '' );
		$closed_ts = $closed ? strtotime( $closed . ' UTC' ) : false;

		// 1. Has the settling period elapsed?
		if ( false === $closed_ts ) {
			return 'waiting';
		}

		$ready_at = $closed_ts + $delay_hours * HOUR_IN_SECONDS;

		if ( time() < $ready_at ) {
			return 'waiting';
		}

		$findings = \VulnHub\Core\Tickets::findings_for( $ticket_id );

		if ( ! $findings ) {
			\VulnHub\Core\Tickets::record_verification(
				$ticket_id,
				\VulnHub\Core\Tickets::VERIFY_UNKNOWN,
				sprintf(
					/* translators: %s: ticket key. */
					__( '%s covers no findings, so there is nothing to re-check against Tenable.', 'vulnhub' ),
					$key
				),
				array( 'reason' => 'no_findings' )
			);

			$this->remember( $ticket, \VulnHub\Core\Tickets::VERIFY_UNKNOWN, 0, 0, 0, __( 'Ticket covers no findings.', 'vulnhub' ) );

			return \VulnHub\Core\Tickets::VERIFY_UNKNOWN;
		}

		// 2. Resolve the Tenable identity and scan freshness of every asset.
		$assets      = $this->assets_for( $findings );
		$asset_uuids = array();
		$plugin_ids  = array();

		foreach ( $findings as $finding ) {
			$asset = $assets[ (int) $finding['asset_id'] ] ?? null;

			if ( $asset && '' !== $asset['tenable_uuid'] ) {
				$asset_uuids[] = $asset['tenable_uuid'];
			}
			if ( '' !== (string) $finding['plugin_id'] ) {
				$plugin_ids[] = (string) $finding['plugin_id'];
			}
		}

		$states = $connector->current_finding_states(
			$asset_uuids,
			$plugin_ids,
			(int) ( $closed_ts - 30 * DAY_IN_SECONDS )
		);

		// 3. Judge each finding.
		$notes      = array();
		$detail     = array();
		$confirmed  = 0;
		$still_open = 0;
		$unknown    = 0;

		foreach ( $findings as $finding ) {
			$verdict = $this->judge_finding( $finding, $assets, $states, $closed_ts );

			$notes[]  = $verdict['note'];
			$detail[] = array(
				'finding_id' => (int) $finding['id'],
				'hostname'   => (string) $finding['hostname'],
				'plugin_id'  => (string) $finding['plugin_id'],
				'verdict'    => $verdict['verdict'],
				'note'       => $verdict['note'],
			);

			switch ( $verdict['verdict'] ) {
				case 'fixed':
					++$confirmed;
					$this->stamp_finding( (int) $finding['id'], \VulnHub\Core\Tickets::VERIFY_CONFIRMED, false );
					break;

				case 'open':
					++$still_open;
					// The ticket claimed this was done. It is not. Reopen it.
					$this->stamp_finding( (int) $finding['id'], \VulnHub\Core\Tickets::VERIFY_STILL_OPEN, true );
					break;

				default:
					++$unknown;
					$this->stamp_finding( (int) $finding['id'], \VulnHub\Core\Tickets::VERIFY_UNKNOWN, false );
			}
		}

		// 4. Aggregate. Any single still-detected finding invalidates the close.
		if ( $still_open > 0 ) {
			$state   = \VulnHub\Core\Tickets::VERIFY_STILL_OPEN;
			$headline = sprintf(
				/* translators: 1: ticket key, 2: still-detected count, 3: total findings. */
				__( '%1$s was closed but Tenable still detects %2$d of %3$d findings. Those findings have been reopened.', 'vulnhub' ),
				$key,
				$still_open,
				count( $findings )
			);
		} elseif ( $unknown > 0 ) {
			$state   = \VulnHub\Core\Tickets::VERIFY_UNKNOWN;
			$headline = sprintf(
				/* translators: 1: ticket key, 2: unverifiable count, 3: total findings. */
				__( '%1$s cannot be verified: Tenable has no scan data since it closed for %2$d of %3$d findings.', 'vulnhub' ),
				$key,
				$unknown,
				count( $findings )
			);
		} else {
			$state   = \VulnHub\Core\Tickets::VERIFY_CONFIRMED;
			$headline = sprintf(
				/* translators: 1: ticket key, 2: confirmed count. */
				__( '%1$s verified: all %2$d findings are confirmed remediated in Tenable.', 'vulnhub' ),
				$key,
				$confirmed
			);
		}

		$note = $headline . ' ' . implode( ' ', $notes );

		\VulnHub\Core\Tickets::record_verification(
			$ticket_id,
			$state,
			$note,
			array(
				'source'      => 'tenable',
				'mode'        => $connector->is_mock() ? 'mock' : 'live',
				'closed_at'   => gmdate( 'Y-m-d H:i:s', $closed_ts ),
				'delay_hours' => $delay_hours,
				'confirmed'   => $confirmed,
				'still_open'  => $still_open,
				'unknown'     => $unknown,
				'findings'    => $detail,
			)
		);

		$this->remember( $ticket, $state, $confirmed, $still_open, $unknown, $headline );

		return $state;
	}

	/**
	 * Decide the fate of one finding.
	 *
	 * @param array<string,mixed>                     $finding   Finding row joined to asset + vuln.
	 * @param array<int,array{tenable_uuid:string,hostname:string,last_seen:string}> $assets Asset lookup.
	 * @param array<string,array<string,string>>      $states    Current Tenable states.
	 * @param int                                     $closed_ts When the ticket closed.
	 * @return array{verdict:string,note:string}
	 */
	private function judge_finding( array $finding, array $assets, array $states, int $closed_ts ): array {
		$asset     = $assets[ (int) $finding['asset_id'] ] ?? null;
		$hostname  = (string) ( $finding['hostname'] ?? '' );
		$plugin_id = (string) ( $finding['plugin_id'] ?? '' );
		$title     = vh_trim( (string) ( $finding['vuln_title'] ?? '' ), 70 );

		if ( ! $asset || '' === $asset['tenable_uuid'] ) {
			return array(
				'verdict' => 'unknown',
				'note'    => sprintf(
					/* translators: 1: vulnerability title, 2: hostname. */
					__( '"%1$s" on %2$s: the asset has no Tenable identity, so it cannot be re-scanned.', 'vulnhub' ),
					$title,
					$hostname
				),
			);
		}

		/*
		 * If Tenable has not seen the asset since the ticket closed, no rescan
		 * has happened and "still open" would be an unfair reading of stale
		 * data. Say so plainly instead of guessing.
		 */
		$last_seen = $asset['last_seen'] ? strtotime( $asset['last_seen'] . ' UTC' ) : false;

		if ( false === $last_seen || $last_seen < $closed_ts ) {
			return array(
				'verdict' => 'unknown',
				'note'    => sprintf(
					/* translators: 1: vulnerability title, 2: hostname, 3: relative time. */
					__( '"%1$s" on %2$s: no Tenable scan since the ticket closed (last seen %3$s), so remediation is unproven.', 'vulnhub' ),
					$title,
					$hostname,
					$asset['last_seen'] ? vh_ago( $asset['last_seen'] ) : __( 'never', 'vulnhub' )
				),
			);
		}

		$state = $states[ $asset['tenable_uuid'] . '|' . $plugin_id ] ?? null;

		if ( null === $state ) {
			// The asset has been rescanned and the plugin no longer fires.
			return array(
				'verdict' => 'fixed',
				'note'    => sprintf(
					/* translators: 1: vulnerability title, 2: hostname, 3: relative time. */
					__( '"%1$s" on %2$s: no longer reported by Tenable after the rescan of %3$s.', 'vulnhub' ),
					$title,
					$hostname,
					vh_ago( $asset['last_seen'] )
				),
			);
		}

		if ( 'FIXED' === $state['state'] ) {
			return array(
				'verdict' => 'fixed',
				'note'    => sprintf(
					/* translators: 1: vulnerability title, 2: hostname, 3: date. */
					__( '"%1$s" on %2$s: Tenable marked it FIXED on %3$s.', 'vulnhub' ),
					$title,
					$hostname,
					vh_date( vh_to_mysql( $state['last_fixed'] ?: $state['last_found'] ) ?? '', 'j M Y' )
				),
			);
		}

		return array(
			'verdict' => 'open',
			'note'    => sprintf(
				/* translators: 1: vulnerability title, 2: hostname, 3: Tenable state, 4: date. */
				__( '"%1$s" on %2$s: still %3$s in Tenable, last detected %4$s — reopened.', 'vulnhub' ),
				$title,
				$hostname,
				strtolower( $state['state'] ),
				vh_date( vh_to_mysql( $state['last_found'] ) ?? '', 'j M Y' )
			),
		);
	}

	/**
	 * Load the Tenable identity and scan freshness for the assets behind a set
	 * of findings.
	 *
	 * @param array<int,array<string,mixed>> $findings Findings.
	 * @return array<int,array{tenable_uuid:string,hostname:string,last_seen:string}>
	 */
	private function assets_for( array $findings ): array {
		global $wpdb;

		$ids = array_values( array_unique( array_map( static fn( array $f ): int => (int) $f['asset_id'], $findings ) ) );
		$ids = array_values( array_filter( $ids ) );

		if ( ! $ids ) {
			return array();
		}

		$placeholders = implode( ', ', array_fill( 0, count( $ids ), '%d' ) );

		$rows = (array) $wpdb->get_results(
			$wpdb->prepare(
				'SELECT id, tenable_uuid, hostname, last_seen FROM ' . vh_table( 'assets' ) . " WHERE id IN ({$placeholders})", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				...$ids
			),
			ARRAY_A
		);

		$out = array();

		foreach ( $rows as $row ) {
			$out[ (int) $row['id'] ] = array(
				'tenable_uuid' => (string) $row['tenable_uuid'],
				'hostname'     => (string) $row['hostname'],
				'last_seen'    => (string) ( $row['last_seen'] ?? '' ),
			);
		}

		return $out;
	}

	/**
	 * Write the verification outcome onto the finding, reopening it when the
	 * vulnerability is demonstrably still present.
	 *
	 * @param int    $finding_id Finding id.
	 * @param string $state      Verification state constant.
	 * @param bool   $reopen     Flip the finding back to `reopened`.
	 */
	private function stamp_finding( int $finding_id, string $state, bool $reopen ): void {
		global $wpdb;

		if ( ! $finding_id ) {
			return;
		}

		$row = array(
			'verification_state' => $state,
			'verified_at'        => vh_now(),
			'updated_at'         => vh_now(),
		);

		if ( $reopen ) {
			$current = $wpdb->get_var(
				$wpdb->prepare( 'SELECT state FROM ' . vh_table( 'findings' ) . ' WHERE id = %d', $finding_id )
			);

			if ( 'reopened' !== (string) $current ) {
				$row['state'] = 'reopened';
			}
		}

		$wpdb->update( vh_table( 'findings' ), $row, array( 'id' => $finding_id ) );
	}

	/**
	 * Keep a short history of verdicts for the Tenable admin screen.
	 *
	 * @param array<string,mixed> $ticket     Ticket row.
	 * @param string              $state      Verification state.
	 * @param int                 $confirmed  Findings confirmed fixed.
	 * @param int                 $still_open Findings still detected.
	 * @param int                 $unknown    Findings that could not be judged.
	 * @param string              $headline   Human summary.
	 */
	private function remember( array $ticket, string $state, int $confirmed, int $still_open, int $unknown, string $headline ): void {
		$settings = vulnhub()->settings;
		$log      = $settings->get( 'tenable', 'verify_log', array() );
		$log      = is_array( $log ) ? $log : array();

		array_unshift(
			$log,
			array(
				'ticket_id'  => (int) $ticket['id'],
				'key'        => (string) ( $ticket['external_key'] ?? '' ),
				'url'        => (string) ( $ticket['url'] ?? '' ),
				'summary'    => vh_trim( (string) ( $ticket['summary'] ?? '' ), 120 ),
				'state'      => $state,
				'confirmed'  => $confirmed,
				'still_open' => $still_open,
				'unknown'    => $unknown,
				'note'       => vh_trim( $headline, 240 ),
				'checked_at' => vh_now(),
			)
		);

		$settings->set( 'tenable', 'verify_log', array_slice( $log, 0, self::HISTORY ) );
	}

	/* -----------------------------------------------------------------
	 * Manual trigger from the admin screen
	 * --------------------------------------------------------------- */

	/**
	 * Handle the "Run verification now" button.
	 */
	public function handle_manual_run(): void {
		if ( ! current_user_can( \VulnHub\Core\Caps::RUN_SYNC ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}

		check_admin_referer( 'vulnhub_tenable_verify' );

		$totals = $this->run();

		$message = sprintf(
			/* translators: 1: tickets checked, 2: confirmed, 3: still open, 4: unknown, 5: waiting. */
			__( 'Checked %1$d ticket(s): %2$d verified fixed, %3$d still detected, %4$d unverifiable, %5$d still inside the settling period.', 'vulnhub' ),
			$totals['checked'],
			$totals['confirmed'],
			$totals['still_open'],
			$totals['unknown'],
			$totals['waiting']
		);

		wp_safe_redirect(
			vh_admin_url(
				'vulnhub-tenable',
				array(
					'vh_msg'  => $message,
					'vh_type' => $totals['still_open'] > 0 ? 'warning' : 'success',
				)
			)
		);
		exit;
	}
}

