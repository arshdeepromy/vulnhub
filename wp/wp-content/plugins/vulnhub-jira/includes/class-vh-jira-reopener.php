<?php
/**
 * Writes closure-verification verdicts back to Jira.
 *
 * The Tenable plugin owns the verdict. Its verifier answers core's hourly
 * `vulnhub_verify_closures` hook and, for each ticket, calls
 * `Tickets::record_verification()` with one of the `VERIFY_*` constants —
 * stamping `verification_state`, `verification_note` and `verified_at` on the
 * ticket row and writing an audit entry. Findings it judged still-present are
 * flipped back to `reopened` at the same time.
 *
 * Core exposes no dedicated "a verdict was recorded" action, so rather than
 * patching core this class watches the same rows the verifier writes:
 *
 *   - it runs on `vulnhub_verify_closures` at priority 20, i.e. immediately
 *     after Tenable's verifier (priority 10) has finished its pass;
 *   - it also runs after any Tenable sync and on the automation tick, so a
 *     verdict recorded by a manual run is never left unanswered;
 *   - it keeps a per-ticket watermark of the `verified_at` it last acted on,
 *     so each verdict is answered exactly once even though the hook is
 *     re-entered many times a day.
 *
 * For a VERIFY_STILL_OPEN verdict it comments on the Jira issue explaining
 * that the scanner still detects the vulnerability, then transitions the issue
 * back to an open status if the workflow offers a valid transition. For a
 * VERIFY_CONFIRMED verdict it comments with the confirmation, so the person
 * who closed the ticket sees the evidence without leaving Jira.
 *
 * @package VulnHub\Jira
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Reopens and annotates Jira issues from verification verdicts.
 */
final class VulnHub_Jira_Reopener {

	/** Verdicts examined per pass. */
	private const BATCH = 40;

	/** Verdict history kept for the admin screen. */
	private const HISTORY = 30;

	/**
	 * Register hooks.
	 */
	public function hooks(): void {
		// Priority 20: after the Tenable verifier has recorded its verdicts.
		add_action( 'vulnhub_verify_closures', array( $this, 'run' ), 20 );
		add_action( 'vulnhub_run_automations', array( $this, 'run' ), 5 );
		add_action( 'vulnhub_sync_complete', array( $this, 'on_sync_complete' ), 10, 3 );
		add_action( 'admin_post_vulnhub_jira_verdicts', array( $this, 'handle_manual_run' ) );
	}

	/**
	 * Answer a completed sync from the vulnerability source.
	 *
	 * @param string            $connector Connector id.
	 * @param string            $status    success|failed.
	 * @param array<string,int> $stats     Counters.
	 */
	public function on_sync_complete( string $connector, string $status, array $stats = array() ): void {
		unset( $stats );

		if ( 'success' === $status && in_array( $connector, array( 'tenable', 'jira' ), true ) ) {
			$this->run();
		}
	}

	/* =================================================================
	 * The pass
	 * ============================================================== */

	/**
	 * Act on every verification verdict we have not answered yet.
	 *
	 * @return array{reopened:int,confirmed:int,skipped:int,failed:int}
	 */
	public function run(): array {
		$totals = array(
			'reopened'  => 0,
			'confirmed' => 0,
			'skipped'   => 0,
			'failed'    => 0,
		);

		$connector = vulnhub_jira_connector();

		if ( ! $connector || ! $connector->is_enabled() ) {
			return $totals;
		}

		$settings = vulnhub()->settings;
		$seen     = (array) $settings->get( 'jira', 'verdicts_seen', array() );
		$seen     = is_array( $seen ) ? $seen : array();
		$dirty    = false;

		foreach ( $this->fresh_verdicts() as $ticket ) {
			$ticket_id = (int) $ticket['id'];
			$verified  = (string) ( $ticket['verified_at'] ?? '' );
			$state     = (string) ( $ticket['verification_state'] ?? '' );

			if ( '' === $verified ) {
				continue;
			}
			if ( ( $seen[ $ticket_id ] ?? '' ) === $verified ) {
				continue;
			}

			$outcome = match ( $state ) {
				\VulnHub\Core\Tickets::VERIFY_STILL_OPEN => $this->handle_still_open( $connector, $ticket ),
				\VulnHub\Core\Tickets::VERIFY_CONFIRMED  => $this->handle_confirmed( $connector, $ticket ),
				default                                  => 'skipped',
			};

			if ( 'failed' !== $outcome ) {
				$seen[ $ticket_id ] = $verified;
				$dirty              = true;
			}

			++$totals[ $outcome ];
		}

		if ( $dirty ) {
			// Keep the watermark bounded; oldest entries fall off.
			if ( count( $seen ) > 500 ) {
				$seen = array_slice( $seen, -500, null, true );
			}

			$settings->set( 'jira', 'verdicts_seen', $seen );
		}

		return $totals;
	}

	/**
	 * Tickets carrying a verdict that might need writing back.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	private function fresh_verdicts(): array {
		global $wpdb;

		return (array) $wpdb->get_results(
			$wpdb->prepare(
				'SELECT * FROM ' . vh_table( 'tickets' ) . '
				 WHERE provider = %s
				   AND external_key <> %s
				   AND verification_state IN ( %s, %s )
				   AND verified_at IS NOT NULL
				 ORDER BY verified_at DESC
				 LIMIT %d',
				'jira',
				'',
				\VulnHub\Core\Tickets::VERIFY_STILL_OPEN,
				\VulnHub\Core\Tickets::VERIFY_CONFIRMED,
				self::BATCH
			),
			ARRAY_A
		);
	}

	/* =================================================================
	 * VERIFY_STILL_OPEN — the vulnerability came back (or never left)
	 * ============================================================== */

	/**
	 * Comment on, and reopen, an issue whose vulnerability is still detected.
	 *
	 * @param VulnHub_Jira_Connector $connector Connector.
	 * @param array<string,mixed>    $ticket    Ticket row.
	 * @return string reopened|skipped|failed
	 */
	private function handle_still_open( VulnHub_Jira_Connector $connector, array $ticket ): string {
		if ( ! $connector->reopens() ) {
			return 'skipped';
		}

		$key      = (string) $ticket['external_key'];
		$findings = \VulnHub\Core\Tickets::findings_for( (int) $ticket['id'] );

		$still = array_values(
			array_filter(
				$findings,
				static fn( array $f ): bool => \VulnHub\Core\Tickets::VERIFY_STILL_OPEN === (string) ( $f['verification_state'] ?? '' )
			)
		);

		$doc = VulnHub_Jira_Adf::doc();

		$doc->paragraph(
			array(
				VulnHub_Jira_Adf::strong( __( 'Reopened by VulnHub: the scanner still detects this vulnerability.', 'vulnhub' ) ),
			)
		);

		$doc->paragraph(
			sprintf(
				/* translators: 1: issue key, 2: relative time since closure, 3: still-detected count, 4: total findings. */
				__( '%1$s was closed %2$s. VulnHub then re-checked every finding it covered against current scan data, and %3$d of %4$d are still being reported. A closure is only accepted when the vulnerability source agrees, so this issue has been reopened.', 'vulnhub' ),
				$key,
				vh_ago( (string) ( $ticket['remote_closed_at'] ?: $ticket['updated_at'] ) ),
				count( $still ) ?: 1,
				count( $findings )
			)
		);

		if ( $still ) {
			$doc->paragraph( __( 'Still detected:', 'vulnhub' ) );
			$doc->bullets(
				array_map(
					static fn( array $f ): string => sprintf(
						/* translators: 1: vulnerability title, 2: hostname, 3: plugin id. */
						__( '%1$s on %2$s (plugin %3$s)', 'vulnhub' ),
						vh_trim( (string) $f['vuln_title'], 120 ),
						(string) $f['hostname'],
						(string) $f['plugin_id']
					),
					array_slice( $still, 0, 20 )
				)
			);
		}

		$note = trim( (string) ( $ticket['verification_note'] ?? '' ) );

		if ( '' !== $note ) {
			$doc->paragraph( __( 'Verification detail:', 'vulnhub' ) );
			$doc->code_block( vh_trim( $note, 3000 ), 'text' );
		}

		$asset_id = (int) ( $ticket['asset_id'] ?? 0 );

		if ( $asset_id ) {
			$doc->paragraph(
				array(
					VulnHub_Jira_Adf::text( __( 'Evidence in VulnHub: ', 'vulnhub' ) ),
					VulnHub_Jira_Adf::link(
						__( 'open the asset', 'vulnhub' ),
						vh_admin_url( 'vulnhub-assets', array( 'asset' => $asset_id ) )
					),
				)
			);
		}

		$comment = $connector->client()->comment( $key, $doc->to_array() );

		if ( ! $comment->ok() ) {
			$connector->log(
				sprintf(
					'Could not comment the reopen explanation on %s (HTTP %d): %s',
					$key,
					$comment->status,
					vh_trim( $comment->error_message(), 160 )
				)
			);

			return 'failed';
		}

		$moved = $this->transition_to_open( $connector, $key );

		vulnhub()->logger->audit(
			'ticket.reopened',
			$moved['ok']
				? sprintf(
					/* translators: 1: issue key, 2: target status. */
					__( 'Reopened Jira issue %1$s to "%2$s" — the scanner still detects the vulnerability.', 'vulnhub' ),
					$key,
					$moved['status']
				)
				: sprintf(
					/* translators: %s: issue key. */
					__( 'Commented on Jira issue %s: the scanner still detects the vulnerability, but no transition back to an open status was available.', 'vulnhub' ),
					$key
				),
			'ticket',
			(int) $ticket['id'],
			array(
				'transitioned' => $moved['ok'],
				'status'       => $moved['status'],
				'reason'       => $moved['reason'],
				'still_open'   => count( $still ),
				'findings'     => count( $findings ),
			),
			'warning'
		);

		$this->remember( $ticket, \VulnHub\Core\Tickets::VERIFY_STILL_OPEN, $moved );

		return 'reopened';
	}

	/**
	 * Move an issue back to an open status.
	 *
	 * Transition ids are workflow specific, so the available transitions are
	 * read first and the best target chosen by status *category*: an
	 * `indeterminate` (in progress) target is preferred over `new`, because
	 * the work has demonstrably already been attempted once.
	 *
	 * @param VulnHub_Jira_Connector $connector Connector.
	 * @param string                 $key       Issue key.
	 * @return array{ok:bool,status:string,reason:string}
	 */
	private function transition_to_open( VulnHub_Jira_Connector $connector, string $key ): array {
		$response = $connector->client()->transitions( $key );

		if ( ! $response->ok() ) {
			return array(
				'ok'     => false,
				'status' => '',
				'reason' => sprintf( 'HTTP %d reading transitions', $response->status ),
			);
		}

		$best     = null;
		$best_key = '';

		foreach ( (array) ( $response->data()['transitions'] ?? array() ) as $transition ) {
			if ( ! is_array( $transition ) || empty( $transition['id'] ) ) {
				continue;
			}
			if ( isset( $transition['isAvailable'] ) && ! $transition['isAvailable'] ) {
				continue;
			}

			$category = VulnHub_Jira_Connector::status_category(
				(string) ( $transition['to']['statusCategory']['key'] ?? '' )
			);

			if ( 'done' === $category ) {
				continue;
			}

			// Prefer "in progress" over "to do".
			if ( 'indeterminate' === $category ) {
				$best     = $transition;
				$best_key = $category;
				break;
			}
			if ( null === $best ) {
				$best     = $transition;
				$best_key = $category;
			}
		}

		if ( null === $best ) {
			$connector->log( sprintf( '%s has no available transition back to an open status; the explanatory comment stands alone.', $key ) );

			return array(
				'ok'     => false,
				'status' => '',
				'reason' => 'no_open_transition',
			);
		}

		$moved = $connector->client()->transition( $key, (string) $best['id'] );

		if ( ! $moved->ok() ) {
			$connector->log(
				sprintf(
					'Transition of %s to "%s" failed (HTTP %d): %s',
					$key,
					(string) ( $best['to']['name'] ?? $best['name'] ?? '' ),
					$moved->status,
					vh_trim( $moved->error_message(), 160 )
				)
			);

			return array(
				'ok'     => false,
				'status' => (string) ( $best['to']['name'] ?? '' ),
				'reason' => sprintf( 'HTTP %d applying transition', $moved->status ),
			);
		}

		$status = (string) ( $best['to']['name'] ?? $best['name'] ?? '' );

		$connector->log( sprintf( 'Reopened %s — transitioned to "%s" (%s).', $key, $status, $best_key ) );

		// Pull the issue back so the ticket row stops looking closed and the
		// scheduled sync starts polling it again.
		$refreshed = $connector->client()->get_issue( $key );

		if ( $refreshed->ok() ) {
			\VulnHub\Core\Tickets::upsert( $connector->normalise_issue( $refreshed->data() ) );
		}

		return array(
			'ok'     => true,
			'status' => $status,
			'reason' => '',
		);
	}

	/* =================================================================
	 * VERIFY_CONFIRMED — the closure held up
	 * ============================================================== */

	/**
	 * Comment on an issue whose closure the scanner confirmed.
	 *
	 * @param VulnHub_Jira_Connector $connector Connector.
	 * @param array<string,mixed>    $ticket    Ticket row.
	 * @return string confirmed|skipped|failed
	 */
	private function handle_confirmed( VulnHub_Jira_Connector $connector, array $ticket ): string {
		if ( ! $connector->comments_on_verify() ) {
			return 'skipped';
		}

		$key      = (string) $ticket['external_key'];
		$findings = \VulnHub\Core\Tickets::findings_for( (int) $ticket['id'] );

		$doc = VulnHub_Jira_Adf::doc();

		$doc->paragraph(
			array(
				VulnHub_Jira_Adf::strong( __( 'Closure verified by VulnHub.', 'vulnhub' ) ),
				VulnHub_Jira_Adf::text( ' ' ),
				VulnHub_Jira_Adf::text(
					sprintf(
						/* translators: 1: number of findings, 2: relative time. */
						_n(
							'The vulnerability source has re-scanned since this issue closed %2$s and confirms the %1$d finding it covered is remediated.',
							'The vulnerability source has re-scanned since this issue closed %2$s and confirms all %1$d findings it covered are remediated.',
							count( $findings ),
							'vulnhub'
						),
						count( $findings ),
						vh_ago( (string) ( $ticket['remote_closed_at'] ?: $ticket['updated_at'] ) )
					)
				),
			)
		);

		$note = trim( (string) ( $ticket['verification_note'] ?? '' ) );

		if ( '' !== $note ) {
			$doc->code_block( vh_trim( $note, 3000 ), 'text' );
		}

		$response = $connector->client()->comment( $key, $doc->to_array() );

		if ( ! $response->ok() ) {
			$connector->log(
				sprintf(
					'Could not comment the verification result on %s (HTTP %d): %s',
					$key,
					$response->status,
					vh_trim( $response->error_message(), 160 )
				)
			);

			return 'failed';
		}

		$connector->log( sprintf( 'Commented the confirmed-fixed verdict on %s.', $key ) );

		$this->remember(
			$ticket,
			\VulnHub\Core\Tickets::VERIFY_CONFIRMED,
			array(
				'ok'     => true,
				'status' => (string) $ticket['status'],
				'reason' => '',
			)
		);

		return 'confirmed';
	}

	/* =================================================================
	 * History + manual trigger
	 * ============================================================== */

	/**
	 * Keep a short history for the Jira admin screen.
	 *
	 * @param array<string,mixed>                       $ticket Ticket row.
	 * @param string                                    $state  Verification state acted on.
	 * @param array{ok:bool,status:string,reason:string} $moved  Transition outcome.
	 */
	private function remember( array $ticket, string $state, array $moved ): void {
		$settings = vulnhub()->settings;
		$log      = $settings->get( 'jira', 'writeback_log', array() );
		$log      = is_array( $log ) ? $log : array();

		array_unshift(
			$log,
			array(
				'ticket_id'    => (int) $ticket['id'],
				'key'          => (string) $ticket['external_key'],
				'url'          => (string) $ticket['url'],
				'summary'      => vh_trim( (string) $ticket['summary'], 120 ),
				'state'        => $state,
				'transitioned' => (bool) $moved['ok'],
				'status'       => (string) $moved['status'],
				'reason'       => (string) $moved['reason'],
				'at'           => vh_now(),
			)
		);

		$settings->set( 'jira', 'writeback_log', array_slice( $log, 0, self::HISTORY ) );
	}

	/**
	 * Handle the "Write verdicts back to Jira now" button.
	 */
	public function handle_manual_run(): void {
		if ( ! current_user_can( \VulnHub\Core\Caps::RAISE_TICKET ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}

		check_admin_referer( 'vulnhub_jira_verdicts' );

		$totals = $this->run();

		wp_safe_redirect(
			vh_admin_url(
				'vulnhub-jira',
				array(
					'vh_msg'  => sprintf(
						/* translators: 1: reopened, 2: confirmed, 3: skipped, 4: failed. */
						__( 'Wrote verdicts back to Jira: %1$d reopened, %2$d confirmations commented, %3$d skipped by settings, %4$d failed.', 'vulnhub' ),
						$totals['reopened'],
						$totals['confirmed'],
						$totals['skipped'],
						$totals['failed']
					),
					'vh_type' => $totals['failed'] > 0 ? 'warning' : 'success',
				)
			)
		);
		exit;
	}
}

