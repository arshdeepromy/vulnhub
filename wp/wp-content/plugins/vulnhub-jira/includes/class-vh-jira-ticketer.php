<?php
/**
 * Ticket creation: grouping, ADF body, Jira issue, persistence, remote link.
 *
 * This class answers the `vulnhub_create_ticket` filter, which is how core's
 * REST route, the Findings screen and the automation engine all ask for a
 * ticket. It is deliberately the only place that talks to Jira about *making*
 * issues, so grouping and the description template stay consistent no matter
 * who asked.
 *
 * Grouping decides how many issues a set of findings becomes:
 *
 *   per_finding             one issue per finding — precise, noisy
 *   per_asset               one issue per machine — "fix this box"
 *   per_vulnerability       one issue per CVE across the fleet — "patch this"
 *   per_asset_and_severity  one issue per machine per severity — the default,
 *                           because it matches how remediation teams queue work
 *
 * An open ticket already carrying the same grouping key is reused rather than
 * duplicated: the new findings are attached to it and a comment explains what
 * arrived. That is what stops a nightly scan from opening the same issue again
 * every night.
 *
 * @package VulnHub\Jira
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Turns findings into Jira issues.
 */
final class VulnHub_Jira_Ticketer {

	/**
	 * Hard ceiling on findings covered by a single request, so a runaway
	 * "select all" cannot try to describe a whole estate inside one issue.
	 *
	 * The description does not grow with the selection: every section of it is
	 * capped, and the full list travels as the CSV attachment. So this bounds
	 * the query, the file and the rows linked to the ticket -- not how much
	 * text Jira is asked to hold. 500 was below what people actually select:
	 * one product across the estate is routinely more than that, and "raise
	 * one ticket for this product" is a single piece of work whether it lands
	 * on 400 machines or 900. Sites with a different idea of one ticket's
	 * worth of work move it with 'vulnhub_ticket_max_findings'.
	 */
	private const MAX_FINDINGS = 5000;

	/** Copies of a bundled component described in words before the rest are summarised. */
	private const APP_FIX_SENTENCES = 6;

	/** Longest edited description accepted, in characters (Jira's field holds 32,767). */
	private const DESCRIPTION_EDIT_MAX = 30000;

	/** Assets named in a description when the full list is attached. */
	private const DESCRIPTION_ASSETS = 30;

	/**
	 * Where a section stops adding to the description, in bytes of ADF.
	 *
	 * Every section was already capped by count -- 15 definitions, 10
	 * applications, 8 solutions, 12 evidence bullets -- and each cap is
	 * reasonable on its own. They multiply: a definition carrying long vendor
	 * prose runs to two kilobytes, so a selection that fills every cap builds
	 * a description over the 32,767 Jira accepts, and Jira refuses the create
	 * call outright. A refused ticket is worse than a short one, and the
	 * attachment carries every finding either way -- so the sections that grow
	 * with the selection spend against this budget and say what they left out.
	 *
	 * This is a *stop adding* mark, not the limit, and the difference is the
	 * point: the check happens before a block is appended, so the block in
	 * flight still lands after it. It sits a whole block below the limit for
	 * that reason -- 26,000 to stop, up to ~4,500 for the largest single block
	 * (one application's per-copy evidence), 1,500 for the SLA and closing
	 * sections that always follow, which is 32,000 in the worst case.
	 *
	 * Measured before any of this existed: 3,641 findings on one product built
	 * 36 KB, which Jira rejects outright, and an ordinary 572-finding ticket
	 * built 31 KB -- inside the limit by 1,600 bytes, entirely by luck.
	 */
	private const DESCRIPTION_BYTES = 26000;

	/** Where vulnerability detail stops, so remediation still gets room. */
	private const DESCRIPTION_DETAIL_BYTES = 16000;

	/** Vulnerability definitions described in full. */
	private const DESCRIPTION_VULNS = 15;

	/** Applications whose bundled components are described. */
	private const DESCRIPTION_APPS = 10;

	/** Distinct vendor solution texts quoted. */
	private const DESCRIPTION_SOLUTIONS = 8;

	/**
	 * The most findings one ticket may cover.
	 *
	 * Read the limit through this everywhere, so the screens that tell an
	 * operator what it is and the code that enforces it cannot drift apart.
	 */
	public static function max_findings(): int {
		return max( 1, (int) apply_filters( 'vulnhub_ticket_max_findings', self::MAX_FINDINGS ) );
	}

	/**
	 * The largest attachment Jira will take, in bytes.
	 *
	 * Jira Cloud's default is 10 MB and a site administrator can change it, so
	 * a deployment that raised it says so with
	 * 'vulnhub_ticket_attachment_limit' rather than losing the warning.
	 */
	public static function attachment_limit(): int {
		return max( 1, (int) apply_filters( 'vulnhub_ticket_attachment_limit', 10 * MB_IN_BYTES ) );
	}

	/**
	 * Resolved account ids, keyed by the configured assignee string.
	 *
	 * @var array<string,string>
	 */
	private array $assignee_cache = array();

	/**
	 * Routing directory, built once per request. The routing screen resolves
	 * every team in one page load, so re-reading the cached snapshot a dozen
	 * times would be pure waste.
	 */
	private ?VulnHub_Jira_Directory $directory = null;

	/**
	 * Register the filters core calls.
	 */
	public function hooks(): void {
		add_filter( 'vulnhub_create_ticket', array( $this, 'create_ticket' ), 10, 3 );
		add_filter( 'vulnhub_draft_ticket', array( $this, 'draft_ticket' ), 10, 2 );
		add_action( 'admin_post_' . self::DRAFT_CSV_ACTION, array( $this, 'download_draft_csv' ) );
		add_filter( 'vulnhub_refresh_ticket', array( $this, 'refresh_ticket' ), 10, 2 );
		add_filter( 'vulnhub_ticket_comments', array( $this, 'ticket_comments' ), 10, 2 );
		add_filter( 'vulnhub_post_ticket_comment', array( $this, 'post_ticket_comment' ), 10, 4 );
		add_filter( 'vulnhub_ticket_transitions', array( $this, 'ticket_transitions' ), 10, 2 );
		add_filter( 'vulnhub_apply_ticket_transition', array( $this, 'apply_ticket_transition' ), 10, 5 );
		add_filter( 'vulnhub_refresh_ticket_attachment', array( $this, 'refresh_attachment' ), 10, 3 );
	}

	/**
	 * Answer `vulnhub_create_ticket`.
	 *
	 * @param array<string,mixed>|null $result      Result from an earlier ITSM plugin.
	 * @param array<int,int>           $finding_ids Findings to cover.
	 * @param mixed                    $request     The originating REST request, if any.
	 * @return array{ok:bool,message:string,ticket?:array<string,mixed>}|null
	 */
	public function create_ticket( ?array $result, array $finding_ids, mixed $request = null ): ?array {
		if ( null !== $result ) {
			return $result;
		}

		$connector = vulnhub_jira_connector();

		if ( ! $connector || ! $connector->is_enabled() ) {
			// Another ITSM plugin may be able to handle this.
			return null;
		}

		/*
		 * A person asking for a ticket gets exactly one ticket, and only one
		 * they have reviewed: the request must name a draft built by
		 * draft(), and that draft -- fields, description and attachment as
		 * shown -- is what is sent. Grouping into several tickets is for
		 * automation, which calls raise() directly.
		 */
		$token = $request instanceof WP_REST_Request ? (string) $request->get_param( 'draft' ) : '';

		if ( '' === $token ) {
			return array(
				'ok'      => false,
				'message' => __( 'Review the ticket before it is sent: open it from Raise ticket, check what will go to Jira, then press Send.', 'vulnhub' ),
			);
		}

		unset( $finding_ids );

		return $this->send_draft( $token );
	}

	/**
	 * Answer `vulnhub_refresh_ticket` by delegating to the connector.
	 *
	 * @param array<string,mixed>|null $result Result so far.
	 * @param array<string,mixed>      $ticket Ticket row.
	 * @return array<string,mixed>|null
	 */
	public function refresh_ticket( ?array $result, array $ticket ): ?array {
		$connector = vulnhub_jira_connector();

		return $connector ? $connector->refresh_ticket( $result, $ticket ) : $result;
	}

	/**
	 * Answer `vulnhub_ticket_comments`.
	 *
	 * A ticket recorded by hand (`provider = jsm`) has no issue to read, and
	 * says so rather than looking like a ticket nobody has commented on.
	 *
	 * @param array<string,mixed>|null $result Result from an earlier ITSM plugin.
	 * @param array<string,mixed>      $ticket Ticket row.
	 * @return array<string,mixed>|null
	 */
	public function ticket_comments( ?array $result, array $ticket ): ?array {
		if ( null !== $result ) {
			return $result;
		}

		$connector = vulnhub_jira_connector();

		if ( ! $connector ) {
			return null;
		}

		if ( 'jira' !== (string) ( $ticket['provider'] ?? '' ) ) {
			return array(
				'ok'       => false,
				'message'  => __( 'This ticket was recorded by hand, so VulnHub has no issue to read comments from. Open it in Jira.', 'vulnhub' ),
				'comments' => array(),
			);
		}

		$read = $connector->comments( (string) ( $ticket['external_key'] ?? '' ) );

		// Reading the comments is also the freshest look anyone has had at the
		// ticket, so keep the newest one rather than throwing the trip away.
		if ( ! empty( $read['ok'] ) ) {
			\VulnHub\Core\Tickets::set_last_comment( (int) $ticket['id'], $read['comments'][0] ?? null );
		}

		return $read;
	}

	/**
	 * Re-attach a vulnerability ticket's still-open findings, current.
	 *
	 * The analogue of the asset path for findings tickets. The findings the
	 * ticket was raised about are rebuilt from `ticket_findings`, and only
	 * the ones still open -- open or reopened, risk-accepted excluded -- go
	 * in the file. Fixed findings drop off, so the list shrinks as work
	 * lands and the comment says how many are done, which is the progress
	 * report a scope ticket gets from its outcomes.
	 *
	 * @param object              $connector Jira connector.
	 * @param array<string,mixed> $ticket    Ticket row.
	 * @param string              $key       Jira issue key.
	 * @return array<string,mixed>
	 */
	private function refresh_findings_attachment( $connector, array $ticket, string $key, bool $preview = false, string $note_override = '' ): array {
		if ( ! class_exists( 'VulnHub_Dash_Export' ) ) {
			return array( 'ok' => false, 'message' => __( 'The export component is not available.', 'vulnhub' ) );
		}

		$ticket_id = (int) $ticket['id'];
		$findings  = \VulnHub\Core\Tickets::findings_for( $ticket_id );
		$total     = count( $findings );

		if ( $total < 1 ) {
			return array( 'ok' => false, 'message' => __( 'This ticket covers no findings, so there is no list to send.', 'vulnhub' ) );
		}

		// Still open is open or reopened, and never a finding whose risk has
		// been accepted -- that is not outstanding remediation work.
		$open_ids = array();
		$fixed    = 0;

		foreach ( $findings as $f ) {
			$state = (string) ( $f['state'] ?? '' );

			if ( in_array( $state, array( 'open', 'reopened' ), true ) && 0 === (int) ( $f['exception_id'] ?? 0 ) ) {
				$open_ids[] = (int) $f['id'];
			} elseif ( 'fixed' === $state ) {
				++$fixed;
			}
		}

		if ( ! $open_ids ) {
			return array( 'ok' => false, 'message' => __( 'Every finding on this ticket is fixed or risk-accepted, so there is nothing still open to send.', 'vulnhub' ) );
		}

		// The columns it was raised with, so the file matches the first one.
		$scope = json_decode( (string) ( $ticket['scope_json'] ?? '' ), true );
		$cols  = is_array( $scope ) ? array_map( 'strval', (array) ( $scope['cols'] ?? array() ) ) : array();

		$csv = \VulnHub_Dash_Export::findings_csv( $open_ids, $cols );

		if ( empty( $csv['bytes'] ) ) {
			return array( 'ok' => false, 'message' => __( 'The list could not be rebuilt.', 'vulnhub' ) );
		}

		$limit = self::attachment_limit();

		if ( strlen( (string) $csv['bytes'] ) > $limit ) {
			return array(
				'ok'      => false,
				/* translators: %s: size limit. */
				'message' => sprintf( __( 'The rebuilt list is larger than the %s Jira accepts as an attachment.', 'vulnhub' ), size_format( $limit ) ),
			);
		}

		$name  = sprintf( 'open-findings-%s-%s.csv', strtolower( $key ), gmdate( 'Y-m-d' ) );
		$still = count( $open_ids );

		$default_note = sprintf(
			/* translators: 1: file name, 2: fixed, 3: total, 4: still open. */
			__( 'Refreshed list attached: %1$s. %2$d of %3$d now fixed; the file lists the %4$d vulnerabilities still open (open or reopened) on this ticket, with where each one stands today. Earlier attachments are out of date.', 'vulnhub' ),
			$name,
			$fixed,
			$total,
			$still
		);

		// Preview: everything above is in memory only. Return what will be sent
		// -- counts, file, a sample and the default note -- and attach nothing.
		if ( $preview ) {
			$sample = array();

			foreach ( $findings as $f ) {
				if ( ! in_array( (string) ( $f['state'] ?? '' ), array( 'open', 'reopened' ), true ) || 0 !== (int) ( $f['exception_id'] ?? 0 ) ) {
					continue;
				}

				$sample[] = array(
					'Asset'         => (string) ( $f['hostname'] ?? '' ),
					'Vulnerability' => vh_trim( (string) ( $f['vuln_title'] ?? '' ), 70 ),
					'Severity'      => ucfirst( (string) ( $f['severity'] ?? '' ) ),
					'State'         => ucfirst( (string) ( $f['state'] ?? '' ) ),
				);

				if ( count( $sample ) >= 15 ) {
					break;
				}
			}

			return array(
				'ok'           => true,
				'preview'      => true,
				'kind'         => 'vulnerability',
				'filename'     => $name,
				/* translators: 1: still open, 2: total, 3: fixed. */
				'scope'        => sprintf( __( '%1$d still open of %2$d — %3$d fixed', 'vulnhub' ), $still, $total, $fixed ),
				'rows'         => (int) $csv['rows'],
				'columns'      => array( 'Asset', 'Vulnerability', 'Severity', 'State' ),
				'sample'       => $sample,
				'more'         => max( 0, $still - count( $sample ) ),
				'default_note' => $default_note,
			);
		}

		$note   = '' !== $note_override ? $note_override : $default_note;
		$upload = $connector->client()->attach( $key, $name, (string) $csv['bytes'], 'text/csv' );

		if ( ! $upload->ok() ) {
			return array(
				'ok'      => false,
				/* translators: 1: file name, 2: HTTP status, 3: error. */
				'message' => sprintf( __( 'Attaching %1$s failed (HTTP %2$d): %3$s', 'vulnhub' ), $name, $upload->status, vh_trim( $upload->error_message(), 160 ) ),
			);
		}

		// Internal first, like every comment this product posts; an ordinary
		// comment is the fallback for an issue with no service-desk request.
		$said = $connector->post_comment( $key, $note, false );

		if ( empty( $said['ok'] ) ) {
			$said = $connector->post_comment( $key, $note, true );
		}

		$connector->forget_comments( $key );

		vulnhub()->logger->audit(
			'ticket.attachment_refreshed',
			sprintf( '%s: %s (%d rows, %d still open, %d of %d fixed)', $key, $name, (int) $csv['rows'], $still, $fixed, $total ),
			'ticket',
			$ticket_id,
			array( 'file' => $name, 'rows' => (int) $csv['rows'], 'still_open' => $still, 'fixed' => $fixed, 'total' => $total )
		);

		return array(
			'ok'      => true,
			/* translators: 1: file name, 2: still open, 3: fixed, 4: total, 5: what happened to the note. */
			'message' => sprintf(
				__( 'Attached %1$s (%2$d still-open finding(s)). %3$d of %4$d now fixed. %5$s', 'vulnhub' ),
				$name,
				$still,
				$fixed,
				$total,
				! empty( $said['ok'] )
					? __( 'A comment on the ticket says so.', 'vulnhub' )
					: __( 'The explanatory comment could not be posted, so say which file is current yourself.', 'vulnhub' )
			),
		);
	}

	/**
	 * Answer `vulnhub_refresh_ticket_attachment`: send the list again, current.
	 *
	 * A scope ticket travels as a CSV, and that CSV is a photograph of the day
	 * it was raised. Weeks later two of the twenty-five machines have an agent
	 * and nobody working the ticket can tell which -- the file still lists all
	 * twenty-five as outstanding.
	 *
	 * **Rebuilt from the ticket's own assets, never from its filter.** The
	 * saved filter is "workstations not in Tenable", so re-running it today
	 * returns the machines still missing an agent and *drops the ones that
	 * have been done*. The team would get a shorter list with no explanation
	 * of what left it -- the opposite of a progress report. `assets_for()`
	 * returns the assets the ticket was raised about, whatever the filter says
	 * now, each carrying today's outcome.
	 *
	 * The file is dated because Jira keeps every attachment: there is no
	 * replace, so two files called `assets.csv` on one ticket is somebody
	 * working from the wrong one. The comment says which is current.
	 *
	 * @param array<string,mixed>|null $result Result from an earlier ITSM plugin.
	 * @param array<string,mixed>      $ticket Ticket row.
	 * @return array<string,mixed>|null
	 */
	public function refresh_attachment( ?array $result, array $ticket, array $options = array() ): ?array {
		if ( null !== $result ) {
			return $result;
		}

		$connector = vulnhub_jira_connector();

		if ( ! $connector ) {
			return null;
		}

		$key = (string) ( $ticket['external_key'] ?? '' );

		if ( 'jira' !== (string) ( $ticket['provider'] ?? '' ) || '' === $key ) {
			return array(
				'ok'      => false,
				'message' => __( 'This ticket was recorded by hand, so there is no Jira issue to attach a file to.', 'vulnhub' ),
			);
		}

		$preview       = ! empty( $options['preview'] );
		$note_override = trim( (string) ( $options['note'] ?? '' ) );

		// A vulnerability ticket travels as a findings list, not an asset
		// list. Its progress report is the findings still open, so it takes a
		// different path; scope tickets fall through to the asset path below.
		if ( \VulnHub\Core\Tickets::KIND_VULNERABILITY === (string) ( $ticket['kind'] ?? '' ) ) {
			return $this->refresh_findings_attachment( $connector, $ticket, $key, $preview, $note_override );
		}

		if ( ! class_exists( 'VulnHub_Dash_Export' ) ) {
			return array( 'ok' => false, 'message' => __( 'The export component is not available.', 'vulnhub' ) );
		}

		$counts = \VulnHub\Core\Tickets::asset_outcomes( $ticket );
		$total  = (int) ( $counts['total'] ?? 0 );

		if ( $total < 1 ) {
			return array( 'ok' => false, 'message' => __( 'This ticket covers no assets, so there is no list to send.', 'vulnhub' ) );
		}

		$list = \VulnHub\Core\Tickets::assets_for( $ticket, array( 'limit' => 5000 ) );
		$ids  = array_map( static fn( array $r ): int => (int) $r['asset_id'], (array) $list['rows'] );
		$ids  = array_values( array_filter( $ids ) );

		if ( ! $ids ) {
			return array( 'ok' => false, 'message' => __( 'None of this ticket’s assets are still in the inventory.', 'vulnhub' ) );
		}

		// The columns it was raised with, so the file matches the first one.
		$scope = json_decode( (string) ( $ticket['scope_json'] ?? '' ), true );
		$cols  = is_array( $scope ) ? array_map( 'strval', (array) ( $scope['cols'] ?? array() ) ) : array();

		$csv = \VulnHub_Dash_Export::assets_csv( $ids, $cols );

		if ( empty( $csv['bytes'] ) ) {
			return array( 'ok' => false, 'message' => __( 'The list could not be rebuilt.', 'vulnhub' ) );
		}

		$limit = self::attachment_limit();

		if ( strlen( (string) $csv['bytes'] ) > $limit ) {
			return array(
				'ok'      => false,
				/* translators: %s: size limit. */
				'message' => sprintf( __( 'The rebuilt list is larger than the %s Jira accepts as an attachment.', 'vulnhub' ), size_format( $limit ) ),
			);
		}

		$name = sprintf( 'assets-%s-%s.csv', strtolower( $key ), gmdate( 'Y-m-d' ) );
		$done = (int) ( $counts['resolved'] ?? 0 );

		$default_note = sprintf(
			/* translators: 1: file name, 2: done, 3: total. */
			__( 'Refreshed list attached: %1$s. %2$d of %3$d now done; the file lists every asset this ticket was raised about, with where each one stands today. Earlier attachments are out of date.', 'vulnhub' ),
			$name,
			$done,
			$total
		);

		// Preview: return what will be sent and attach nothing.
		if ( $preview ) {
			$sample = array();

			foreach ( (array) $list['rows'] as $row ) {
				$sample[] = array(
					'Asset'   => (string) ( $row['hostname'] ?? '' ),
					'Type'    => (string) ( $row['asset_type'] ?? '' ),
					'Outcome' => ucfirst( (string) ( $row['outcome'] ?? '' ) ),
				);

				if ( count( $sample ) >= 15 ) {
					break;
				}
			}

			return array(
				'ok'           => true,
				'preview'      => true,
				'kind'         => 'scope',
				'filename'     => $name,
				/* translators: 1: done, 2: total. */
				'scope'        => sprintf( __( '%1$d of %2$d done', 'vulnhub' ), $done, $total ),
				'rows'         => (int) $csv['rows'],
				'columns'      => array( 'Asset', 'Type', 'Outcome' ),
				'sample'       => $sample,
				'more'         => max( 0, $total - count( $sample ) ),
				'default_note' => $default_note,
			);
		}

		$note   = '' !== $note_override ? $note_override : $default_note;
		$upload = $connector->client()->attach( $key, $name, (string) $csv['bytes'], 'text/csv' );

		if ( ! $upload->ok() ) {
			return array(
				'ok'      => false,
				'message' => sprintf(
					/* translators: 1: file name, 2: HTTP status, 3: error. */
					__( 'Attaching %1$s failed (HTTP %2$d): %3$s', 'vulnhub' ),
					$name,
					$upload->status,
					vh_trim( $upload->error_message(), 160 )
				),
			);
		}

		/*
		 * Internal first, like every other comment this product posts: a reply
		 * notifies whoever raised the request and cannot be taken back.
		 *
		 * But a ticket VulnHub created through the issue API is an ordinary
		 * issue, not a service desk *request*, and the desk API 404s on it --
		 * so there is no such thing as an internal note there and the attempt
		 * is refused. The file went up through the same issue API and is
		 * already visible to anyone who can see the issue, so a comment beside
		 * it reveals nothing further: fall back to an ordinary comment rather
		 * than leave the attachment sitting there unexplained.
		 *
		 * The result is checked either way. The first version of this ignored
		 * it and reported "left a note" while no note had been posted.
		 */
		$said = $connector->post_comment( $key, $note, false );

		if ( empty( $said['ok'] ) ) {
			$said = $connector->post_comment( $key, $note, true );
		}

		$connector->forget_comments( $key );

		vulnhub()->logger->audit(
			'ticket.attachment_refreshed',
			sprintf( '%s: %s (%d rows, %d of %d done)', $key, $name, (int) $csv['rows'], $done, $total ),
			'ticket',
			(int) $ticket['id'],
			array( 'file' => $name, 'rows' => (int) $csv['rows'], 'done' => $done, 'total' => $total )
		);

		return array(
			'ok'      => true,
			'message' => sprintf(
				/* translators: 1: file name, 2: rows, 3: done, 4: total, 5: what happened to the note. */
				__( 'Attached %1$s (%2$d rows). %3$d of %4$d assets are done. %5$s', 'vulnhub' ),
				$name,
				(int) $csv['rows'],
				$done,
				$total,
				! empty( $said['ok'] )
					? __( 'A comment on the ticket says so.', 'vulnhub' )
					: sprintf(
						/* translators: %s: why the comment failed. */
						__( 'The explanatory comment could not be posted (%s), so say which file is current yourself.', 'vulnhub' ),
						vh_trim( (string) ( $said['message'] ?? '' ), 120 )
					)
			),
			'noted'   => ! empty( $said['ok'] ),
			'file'    => $name,
			'rows'    => (int) $csv['rows'],
			'done'    => $done,
			'total'   => $total,
		);
	}

	/**
	 * Answer `vulnhub_ticket_transitions`.
	 *
	 * @param array<string,mixed>|null $result Result from an earlier ITSM plugin.
	 * @param array<string,mixed>      $ticket Ticket row.
	 * @return array<string,mixed>|null
	 */
	public function ticket_transitions( ?array $result, array $ticket ): ?array {
		if ( null !== $result ) {
			return $result;
		}

		$connector = vulnhub_jira_connector();

		if ( ! $connector ) {
			return null;
		}

		if ( 'jira' !== (string) ( $ticket['provider'] ?? '' ) ) {
			return array(
				'ok'          => false,
				'message'     => __( 'This ticket was recorded by hand, so there is no Jira workflow to move it through. Set its status on this page instead.', 'vulnhub' ),
				'transitions' => array(),
			);
		}

		return $connector->transitions_for( (string) ( $ticket['external_key'] ?? '' ) );
	}

	/**
	 * Answer `vulnhub_apply_ticket_transition`.
	 *
	 * @param array<string,mixed>|null $result Result from an earlier ITSM plugin.
	 * @param array<string,mixed>      $ticket Ticket row.
	 * @param string                   $id     Transition id.
	 * @param array<string,string>     $values Required field values.
	 * @param string                   $note   Optional comment posted with the move.
	 * @return array<string,mixed>|null
	 */
	public function apply_ticket_transition( ?array $result, array $ticket, string $id, array $values, string $note ): ?array {
		if ( null !== $result ) {
			return $result;
		}

		$connector = vulnhub_jira_connector();

		if ( ! $connector ) {
			return null;
		}

		if ( 'jira' !== (string) ( $ticket['provider'] ?? '' ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'This ticket was recorded by hand, so there is no Jira workflow to move it through.', 'vulnhub' ),
			);
		}

		$moved = $connector->apply_transition( (string) ( $ticket['external_key'] ?? '' ), $id, $values, $note );

		/*
		 * Read the issue straight back. The status, its category, the
		 * resolution and -- when the move closed the ticket -- the start of
		 * the verification clock all come from that refresh, so the screen
		 * never shows a status VulnHub has not actually recorded.
		 */
		if ( ! empty( $moved['ok'] ) ) {
			$connector->refresh_ticket( null, $ticket );
		}

		return $moved;
	}

	/**
	 * Answer `vulnhub_post_ticket_comment`.
	 *
	 * @param array<string,mixed>|null $result Result from an earlier ITSM plugin.
	 * @param array<string,mixed>      $ticket Ticket row.
	 * @param string                   $body   Comment text.
	 * @param bool                     $public True for a customer-visible reply.
	 * @return array<string,mixed>|null
	 */
	public function post_ticket_comment( ?array $result, array $ticket, string $body, bool $public ): ?array {
		if ( null !== $result ) {
			return $result;
		}

		$connector = vulnhub_jira_connector();

		if ( ! $connector ) {
			return null;
		}

		if ( 'jira' !== (string) ( $ticket['provider'] ?? '' ) ) {
			return array(
				'ok'      => false,
				'message' => __( 'This ticket was recorded by hand, so there is no issue here to comment on. Open it in Jira.', 'vulnhub' ),
			);
		}

		$posted = $connector->post_comment( (string) ( $ticket['external_key'] ?? '' ), $body, $public );

		if ( ! empty( $posted['ok'] ) && isset( $posted['comment'] ) ) {
			\VulnHub\Core\Tickets::set_last_comment( (int) $ticket['id'], (array) $posted['comment'] );
		}

		return $posted;
	}

	/* =================================================================
	 * The main entry point
	 * ============================================================== */

	/**
	 * Raise (or extend) Jira issues covering a set of findings.
	 *
	 * @param array<int,int>      $finding_ids Finding ids.
	 * @param array<string,mixed> $options     grouping, created_via, automation_id,
	 *                                         created_by, note, max_tickets.
	 * @return array{ok:bool,message:string,ticket?:array<string,mixed>,tickets:array<int,array<string,mixed>>,created:int,updated:int,failed:int}
	 */
	public function raise( array $finding_ids, array $options = array() ): array {
		$connector = vulnhub_jira_connector();

		$empty = array(
			'tickets' => array(),
			'created' => 0,
			'updated' => 0,
			'failed'  => 0,
		);

		if ( ! $connector ) {
			return array_merge(
				$empty,
				array(
					'ok'      => false,
					'message' => __( 'The Jira connector is not registered.', 'vulnhub' ),
				)
			);
		}

		$finding_ids = array_values( array_unique( array_filter( array_map( 'intval', $finding_ids ) ) ) );

		if ( ! $finding_ids ) {
			return array_merge(
				$empty,
				array(
					'ok'      => false,
					'message' => __( 'Select at least one finding.', 'vulnhub' ),
				)
			);
		}

		$max = self::max_findings();

		if ( count( $finding_ids ) > $max ) {
			$finding_ids = array_slice( $finding_ids, 0, $max );
		}

		$rows = $this->load_findings( $finding_ids );

		if ( ! $rows ) {
			return array_merge(
				$empty,
				array(
					'ok'      => false,
					'message' => __( 'None of those findings exist any more.', 'vulnhub' ),
				)
			);
		}

		$grouping = (string) ( $options['grouping'] ?? '' );
		$grouping = isset( VulnHub_Jira_Connector::grouping_options()[ $grouping ] ) ? $grouping : $connector->grouping();

		$groups      = $this->group( $rows, $grouping );
		$max_tickets = (int) ( $options['max_tickets'] ?? 0 );

		if ( $max_tickets > 0 && count( $groups ) > $max_tickets ) {
			$groups = array_slice( $groups, 0, $max_tickets, true );
		}

		$tickets = array();
		$created = 0;
		$updated = 0;
		$failed  = 0;
		$errors  = array();

		foreach ( $groups as $group_key => $group_rows ) {
			$outcome = $this->handle_group( $connector, (string) $group_key, $group_rows, $grouping, $options );

			if ( empty( $outcome['ok'] ) ) {
				++$failed;
				$errors[] = (string) ( $outcome['message'] ?? '' );
				continue;
			}

			$tickets[] = $outcome['ticket'];

			if ( ! empty( $outcome['created'] ) ) {
				++$created;
			} else {
				++$updated;
			}
		}

		if ( ! $tickets ) {
			return array_merge(
				$empty,
				array(
					'ok'      => false,
					'failed'  => $failed,
					'message' => $errors
						? vh_trim( implode( ' ', $errors ), 400 )
						: __( 'No Jira issues could be raised.', 'vulnhub' ),
				)
			);
		}

		$message = sprintf(
			/* translators: 1: issues created, 2: issues updated, 3: findings covered, 4: grouping label. */
			_n(
				'Raised %1$d Jira issue (%2$d existing updated) covering %3$d finding(s), grouped %4$s.',
				'Raised %1$d Jira issues (%2$d existing updated) covering %3$d finding(s), grouped %4$s.',
				$created,
				'vulnhub'
			),
			$created,
			$updated,
			count( $rows ),
			strtolower( (string) VulnHub_Jira_Connector::grouping_options()[ $grouping ] )
		);

		if ( $failed ) {
			$message .= ' ' . sprintf(
				/* translators: %d: number of groups that failed. */
				_n( '%d group failed.', '%d groups failed.', $failed, 'vulnhub' ),
				$failed
			);
		}

		return array(
			'ok'      => true,
			'message' => $message,
			'ticket'  => $tickets[0],
			'tickets' => $tickets,
			'created' => $created,
			'updated' => $updated,
			'failed'  => $failed,
		);
	}

	/* =================================================================
	 * One ticket per click
	 * ============================================================== */

	/** Lock name shared by every manual raise: one at a time, site-wide. */
	private const MANUAL_LOCK = 'manual-raise';

	/** How long a reviewed draft can wait before it must be reviewed again. */
	private const DRAFT_TTL = 30 * MINUTE_IN_SECONDS;

	public const DRAFT_CSV_ACTION = 'vulnhub_ticket_draft_csv';

	/**
	 * Answer `vulnhub_draft_ticket`.
	 *
	 * @param array<string,mixed>|null $result Result from an earlier ITSM plugin.
	 * @param array<string,mixed>      $params finding_ids, or all + filters; cols.
	 * @return array<string,mixed>|null
	 */
	public function draft_ticket( ?array $result, array $params ): ?array {
		return null !== $result ? $result : $this->draft( $params );
	}

	/**
	 * Build a ticket for review: everything that would travel to Jira, and
	 * nothing sent.
	 *
	 * The issue fields, the rendered description and the CSV are built here
	 * once and kept, keyed by a token, for DRAFT_TTL. Sending uses that stored
	 * draft verbatim, so the review is of the actual payload, not of a
	 * description of it.
	 *
	 * @param array<string,mixed> $params `finding_ids` (int[]) or `all` with
	 *                                    `filters` (the findings screen's own
	 *                                    filter values); `cols` (string[]).
	 * @return array<string,mixed>
	 */
	public function draft( array $params ): array {
		$connector = vulnhub_jira_connector();
		$fail      = static fn( string $message, array $extra = array() ): array => array_merge( array( 'ok' => false, 'message' => $message ), $extra );

		if ( ! $connector || ! $connector->is_enabled() ) {
			return $fail( __( 'Jira is not enabled.', 'vulnhub' ) );
		}

		// "All N matching findings" is resolved on the server, through the
		// same query Export selected uses, so it means the same N.
		$selected = array_values( array_filter( array_map( 'intval', (array) ( $params['finding_ids'] ?? array() ) ) ) );

		if ( ! empty( $params['all'] ) ) {
			if ( ! class_exists( 'VulnHub_Dash_Export' ) ) {
				return $fail( __( 'Selecting every matching finding needs the dashboard plugin.', 'vulnhub' ) );
			}

			$filters = array();

			foreach ( (array) ( $params['filters'] ?? array() ) as $k => $v ) {
				if ( is_scalar( $v ) && ! in_array( (string) $k, array( 'action', 'view', '_wpnonce', '_wp_http_referer', 'cols' ), true ) ) {
					$filters[ sanitize_key( (string) $k ) ] = sanitize_text_field( (string) $v );
				}
			}

			$max   = self::max_findings();
			$scope = VulnHub_Dash_Export::findings_scope( $filters, $max );

			if ( $scope['total'] > $max ) {
				return $fail(
					sprintf(
						/* translators: 1: matching findings, 2: the limit. */
						__( '%1$d findings match these filters; one ticket can cover at most %2$d. Narrow the filters.', 'vulnhub' ),
						$scope['total'],
						$max
					)
				);
			}

			if ( ! $scope['ids'] ) {
				return $fail( __( 'No findings match these filters, or the list changed while it was being read. Refresh and try again.', 'vulnhub' ) );
			}

			$selected = $scope['ids'];
		}

		$plan = $this->plan( $selected );

		$scope_out = array(
			'selected'   => count( array_unique( $selected ) ),
			'eligible'   => count( $plan['rows'] ),
			'skipped'    => $plan['skipped'],
			'on_tickets' => $plan['on_tickets'],
			'assets'     => count( $this->distinct( $plan['rows'], 'asset_id' ) ),
		);

		if ( '' !== $plan['error'] ) {
			return $fail( $plan['error'], array( 'scope' => $scope_out ) );
		}

		$ids = array_map( static fn( array $r ): int => (int) $r['id'], $plan['rows'] );
		sort( $ids );

		$warnings = array();

		/* ---- the attachment ---- */
		$csv = null;

		if ( class_exists( 'VulnHub_Dash_Export' ) ) {
			$name = sprintf( 'findings-%s.csv', wp_date( 'Y-m-d-Hi' ) );
			$csv  = VulnHub_Dash_Export::findings_csv( $ids, array_map( 'sanitize_key', (array) ( $params['cols'] ?? array() ) ) );

			$csv['name'] = $name;

			if ( $csv['rows'] !== count( $ids ) ) {
				$warnings[] = sprintf(
					/* translators: 1: rows in the file, 2: findings on the ticket. */
					__( 'The attachment has %1$d rows but the ticket covers %2$d findings. Some findings may have changed state since the list was loaded; review again before sending.', 'vulnhub' ),
					$csv['rows'],
					count( $ids )
				);
			}
		} else {
			$warnings[] = __( 'No attachment: the dashboard plugin that builds the CSV is not active.', 'vulnhub' );
		}

		/* ---- the issue ---- */
		$due_date = vh_valid_due_date( (string) ( $params['due_date'] ?? '' ) );

		if ( '' !== (string) ( $params['due_date'] ?? '' ) && '' === $due_date ) {
			return $fail( __( 'The due date must be a real date, today or later.', 'vulnhub' ), array( 'scope' => $scope_out ) );
		}

		$built = $this->build_issue(
			$connector,
			'selection:' . md5( implode( ',', $ids ) ),
			$plan['rows'],
			'per_selection',
			array(
				'created_via' => 'manual',
				'attachment'  => $csv ? $csv['name'] : '',
				'due_date'    => $due_date,
			) + ( self::priority_choice( $params )['set'] ? array( 'priority' => self::priority_choice( $params )['value'] ) : array() )
		);

		if ( empty( $built['ok'] ) ) {
			return $fail( (string) $built['message'], array( 'scope' => $scope_out ) );
		}

		$built = $this->apply_review_selects( $connector, $built, $params );
		$built = $this->apply_description_edit( $built, $params );

		return $this->present_draft(
			$connector,
			$built,
			$csv,
			$scope_out,
			$warnings,
			array(
				'type' => 'findings',
				'ids'  => $ids,
			),
			'findings'
		);
	}

	/**
	 * Keep a built draft under a token and describe it for the review screen.
	 *
	 * Shared by finding tickets and asset tickets, so both reviews show the
	 * same things the same way.
	 *
	 * @param array<string,mixed>      $built     From build_issue() or build_scope_issue().
	 * @param array<string,mixed>|null $csv       bytes, rows, columns, name.
	 * @param array<string,mixed>      $scope_out Counts for the review.
	 * @param string[]                 $warnings  Shown above the review.
	 * @param array<string,mixed>      $extra     Stored with the draft for sending.
	 * @param string                   $view      Export view whose columns the picker offers.
	 * @return array<string,mixed>
	 */
	public function present_draft( VulnHub_Jira_Connector $connector, array $built, ?array $csv, array $scope_out, array $warnings, array $extra, string $view ): array {
		$allowed = $connector->allowed_projects();

		if ( $allowed && ! in_array( strtoupper( (string) $built['project'] ), $allowed, true ) ) {
			$warnings[] = sprintf(
				/* translators: 1: project, 2: allowed projects. */
				__( 'This would go to project %1$s, which is outside the allowed projects (%2$s). Sending will be refused.', 'vulnhub' ),
				(string) $built['project'],
				implode( ', ', $allowed )
			);
		}

		$allowed_prio = $this->allowed_priorities( $connector, (string) $built['project'], (array) ( $built['fields']['issuetype'] ?? array() ) );
		$sent_prio    = (string) ( $built['fields']['priority']['name'] ?? '' );

		if ( '' !== $sent_prio && $allowed_prio['names'] && ! in_array( $sent_prio, $allowed_prio['names'], true ) ) {
			$warnings[] = sprintf(
				/* translators: 1: priority name, 2: project, 3: allowed names. */
				__( 'Priority "%1$s" does not exist in %2$s, which allows %3$s. Jira will refuse the ticket: pick one of those or leave it unset.', 'vulnhub' ),
				$sent_prio,
				(string) $built['project'],
				implode( ', ', $allowed_prio['names'] )
			);
		}

		$description_bytes = strlen( (string) wp_json_encode( $built['fields']['description'] ) );

		if ( ! empty( $built['description_trimmed'] ) ) {
			/* translators: %s: characters. */
			$warnings[] = sprintf( __( 'Your edited description was cut to %s characters.', 'vulnhub' ), number_format_i18n( self::DESCRIPTION_EDIT_MAX ) );
		}

		if ( $csv && strlen( (string) $csv['bytes'] ) > self::attachment_limit() ) {
			$warnings[] = sprintf(
				/* translators: 1: file size, 2: the limit Jira accepts. */
				__( 'The attachment is %1$s, over the %2$s this Jira accepts. The file is uploaded after the issue is created, so the ticket would be raised with the attachment missing. Narrow the selection, or attach the file by hand afterwards.', 'vulnhub' ),
				size_format( strlen( (string) $csv['bytes'] ) ),
				size_format( self::attachment_limit() )
			);
		}

		if ( $description_bytes > 32000 ) {
			$warnings[] = sprintf(
				/* translators: %s: size. */
				__( 'The description is %s, close to the size Jira accepts. Jira may reject it; narrow the selection if it does.', 'vulnhub' ),
				size_format( $description_bytes )
			);
		}

		/* ---- keep it ---- */
		$token = wp_generate_password( 32, false, false );

		set_transient(
			self::draft_key( $token ),
			array_merge(
				$extra,
				array(
					'user'    => get_current_user_id(),
					'created' => time(),
					'built'   => $built,
					'csv'     => $csv ? array( 'name' => $csv['name'], 'bytes' => base64_encode( $csv['bytes'] ), 'rows' => $csv['rows'] ) : null,
				)
			),
			self::DRAFT_TTL
		);

		/* ---- show it ---- */
		$fields = (array) $built['fields'];
		$shown  = array(
			array( __( 'Project', 'vulnhub' ), (string) $built['project'] ),
			array( __( 'Issue type', 'vulnhub' ), (string) $built['type'] . ( isset( $fields['issuetype']['id'] ) ? ' (id ' . $fields['issuetype']['id'] . ')' : '' ) ),
			array( __( 'Summary', 'vulnhub' ), (string) $fields['summary'] ),
			array( __( 'Priority', 'vulnhub' ), (string) ( $fields['priority']['name'] ?? __( 'not set', 'vulnhub' ) ) ),
			array( __( 'Due date', 'vulnhub' ), (string) ( $fields['duedate'] ?? __( 'not set', 'vulnhub' ) ) ),
			array( __( 'Labels', 'vulnhub' ), implode( ', ', (array) ( $fields['labels'] ?? array() ) ) ),
			array( __( 'Assignee', 'vulnhub' ), isset( $fields['assignee']['id'] ) ? (string) $fields['assignee']['id'] : __( 'not set (Jira decides)', 'vulnhub' ) ),
		);

		foreach ( (array) ( $built['selects'] ?? array() ) as $select ) {
			$shown[] = array( (string) $select['label'], '' !== $select['text'] ? (string) $select['text'] : __( 'not set', 'vulnhub' ) );
		}

		if ( '' !== (string) $built['routing']['team_field'] && isset( $fields[ (string) $built['routing']['team_field'] ] ) ) {
			$shown[] = array( __( 'Team', 'vulnhub' ) . ' (' . (string) $built['routing']['team_field'] . ')', (string) $built['routing']['team_value'] );
		}

		$preview = array();
		$header  = array();

		if ( $csv ) {
			$lines = preg_split( "/\r\n|\n/", ltrim( $csv['bytes'], "\xEF\xBB\xBF" ) );

			foreach ( array_slice( array_filter( (array) $lines, static fn( $l ): bool => '' !== $l ), 0, 9 ) as $i => $line ) {
				$cells = str_getcsv( (string) $line, ',', '"', '' );

				if ( 0 === $i ) {
					$header = $cells;
				} else {
					$preview[] = $cells;
				}
			}
		}

		$picker = array();

		if ( class_exists( 'VulnHub_Dash_Export' ) ) {
			$chosen = $csv ? array_keys( $csv['columns'] ) : array();

			foreach ( VulnHub_Dash_Export::columns( $view ) as $key => $col ) {
				$picker[] = array(
					'key'     => (string) $key,
					'label'   => (string) $col['label'],
					'group'   => (string) $col['group'],
					'checked' => in_array( (string) $key, $chosen, true ),
				);
			}
		}

		return array(
			'ok'          => true,
			'token'       => $token,
			'expires_in'  => self::DRAFT_TTL,
			'scope'       => $scope_out,
			'fields'      => $shown,
			'due'         => array(
				'value' => (string) ( $fields['duedate'] ?? '' ),
				'min'   => wp_date( 'Y-m-d' ),
			),
			'selects'     => array_values( (array) ( $built['selects'] ?? array() ) ),
			'priority'    => array(
				'value'   => (string) ( $fields['priority']['name'] ?? '' ),
				'options' => $allowed_prio['names'],
				'default' => $allowed_prio['default'],
			),
			'description' => array(
				'html'    => VulnHub_Jira_Adf::to_html( (array) $fields['description'] ),
				'text'    => VulnHub_Jira_Adf::to_editable( (array) $fields['description'] ),
				'edited'  => ! empty( $built['description_edited'] ),
				'bytes'   => $description_bytes,
			),
			'attachment'  => $csv ? array(
				'name'     => $csv['name'],
				'size'     => size_format( strlen( $csv['bytes'] ) ),
				'rows'     => $csv['rows'],
				'columns'  => array_values( $csv['columns'] ),
				'header'   => $header,
				'preview'  => $preview,
				// wp_nonce_url() escapes & for HTML; this travels as JSON and is
				// set as a property by script, where &amp; breaks the query.
				'download' => str_replace( '&amp;', '&', wp_nonce_url( add_query_arg( array( 'action' => self::DRAFT_CSV_ACTION, 'draft' => $token ), admin_url( 'admin-post.php' ) ), self::DRAFT_CSV_ACTION ) ),
			) : null,
			'columns'     => $picker,
			'also'        => $connector->links_back()
				? array( __( 'A remote link on the issue back to the first asset in VulnHub.', 'vulnhub' ) )
				: array(),
			'payload'     => $fields,
			'warnings'    => $warnings,
		);
	}

	/**
	 * Build the issue for an asset-list ticket (Tenable coverage, CMDB gap,
	 * clean-up…): same routing, issue type and allowlist as a finding ticket,
	 * with a description that says what is being asked and of which assets.
	 *
	 * @param array<string,mixed> $spec kind, kind_label, kind_help, summary,
	 *                                  notes, filters (words), total, assets
	 *                                  (rows), attachment (file name).
	 * @return array<string,mixed> ok=false with message, or the built issue.
	 */
	public function build_scope_issue( array $spec ): array {
		$connector = vulnhub_jira_connector();

		if ( ! $connector ) {
			return array( 'ok' => false, 'message' => __( 'The Jira connector is not registered.', 'vulnhub' ) );
		}

		$team    = array();
		$routing = $this->routing( $connector, $team );
		$project = (string) $routing['project'];

		if ( '' === $project ) {
			return array( 'ok' => false, 'message' => __( 'No Jira project key is configured.', 'vulnhub' ) );
		}

		$assets = (array) $spec['assets'];
		$total  = (int) $spec['total'];
		$due    = '' !== (string) ( $spec['due_date'] ?? '' ) ? (string) $spec['due_date'] : vh_due_in_days( vh_asset_request_due_days() );
		$doc    = VulnHub_Jira_Adf::doc();

		$doc->paragraph(
			array(
				VulnHub_Jira_Adf::text( (string) $spec['kind_help'] ),
			)
		);

		if ( '' !== trim( (string) $spec['notes'] ) ) {
			$doc->paragraph( (string) $spec['notes'] );
		}

		$doc->heading( __( 'Which assets', 'vulnhub' ) );
		$doc->paragraph(
			sprintf(
				/* translators: %d: number of assets. */
				_n( '%d asset matching:', '%d assets matching:', $total, 'vulnhub' ),
				$total
			)
		);
		$doc->bullets( array_map( static fn( string $f ): string => $f, (array) $spec['filters'] ) );

		if ( '' !== (string) $spec['attachment'] ) {
			// The assets are in the attached file; the description says so
			// instead of repeating them.
			/* translators: %s: file name. */
			$doc->paragraph( sprintf( __( 'Every asset is listed in the attached %s.', 'vulnhub' ), (string) $spec['attachment'] ) );
		} else {
			$doc->heading( __( 'Assets', 'vulnhub' ) );

			$lines = array();

			foreach ( array_slice( $assets, 0, self::DESCRIPTION_ASSETS ) as $a ) {
				$detail = array_filter(
					array(
						(string) ( $a['ipv4'] ?? '' ),
						vh_asset_type_label( (string) ( $a['asset_type'] ?? '' ) ),
						(string) ( $a['operating_system'] ?? '' ),
						(string) ( $a['site'] ?? '' ),
						'' !== (string) ( $a['owner'] ?? '' ) ? sprintf( /* translators: %s: owner name. */ __( 'owner %s', 'vulnhub' ), (string) $a['owner'] ) : '',
						'' !== (string) ( $a['team'] ?? '' ) ? sprintf( /* translators: %s: team name. */ __( 'team %s', 'vulnhub' ), (string) $a['team'] ) : '',
					)
				);

				$lines[] = array(
					VulnHub_Jira_Adf::strong( (string) $a['hostname'] ),
					VulnHub_Jira_Adf::text( $detail ? ' — ' . implode( ' · ', $detail ) : '' ),
				);
			}

			$doc->bullets( $lines );

			if ( $total > count( $lines ) ) {
				$doc->paragraph(
					sprintf(
						/* translators: %d: number of assets not listed. */
						_n( '… and %d more asset.', '… and %d more assets.', $total - count( $lines ), 'vulnhub' ),
						$total - count( $lines )
					)
				);
			}
		}

		/* translators: %s: due date. */
		$doc->paragraph( sprintf( __( 'Please complete this by %s.', 'vulnhub' ), $due ) );

		$doc->rule();
		$doc->heading( __( 'How this is tracked', 'vulnhub' ) );
		$doc->paragraph( __( 'Each of these assets is re-checked against the latest inventory and scan data, and recorded as done, still outstanding, or no longer relevant because it was retired. Please only close this ticket once the work is done.', 'vulnhub' ) );

		$fields = array(
			'duedate'     => $due,
			'project'     => array( 'key' => $project ),
			'summary'     => vh_trim( (string) $spec['summary'], 250 ),
			'issuetype'   => $routing['issue_type_ref'],
			'description' => $doc->to_array(),
			'labels'      => array( str_replace( '_', '-', sanitize_key( (string) $spec['kind'] ) ) ),
		);

		if ( '' !== $routing['team_field'] && '' !== $routing['team_value'] ) {
			$fields[ $routing['team_field'] ] = $routing['team_write'];
		}

		// Asset requests have no severity, so no mapped priority: only one the
		// reviewer picked.
		if ( '' !== (string) ( $spec['priority'] ?? '' ) ) {
			$fields['priority'] = array( 'name' => (string) $spec['priority'] );
		}

		return array(
			'ok'         => true,
			'fields'     => $fields,
			'routing'    => $routing,
			'project'    => $project,
			'type'       => (string) $routing['issue_type'],
			'priority'   => (string) ( $spec['priority'] ?? '' ),
			'summary'    => (string) $fields['summary'],
			'due'        => $due,
			'team'       => $team,
			'severity'   => '',
			'account_id' => '',
			'group_key'  => 'assets:' . md5( implode( ',', array_map( static fn( array $a ): int => (int) $a['id'], $assets ) ) ),
			'grouping'   => 'scope',
		);
	}

	/**
	 * Create a reviewed asset-list ticket, record it with its asset snapshot.
	 *
	 * @param array<string,mixed> $draft Stored draft.
	 * @return array<string,mixed>
	 */
	private function submit_scope_issue( VulnHub_Jira_Connector $connector, array $draft ): array {
		$built  = (array) $draft['built'];
		$fields = (array) $built['fields'];

		$response = $connector->client()->create_issue( $fields );

		if ( ! $response->ok() ) {
			$message = sprintf(
				/* translators: 1: project key, 2: HTTP status, 3: error message. */
				__( 'Jira refused to create the issue in %1$s (HTTP %2$d): %3$s', 'vulnhub' ),
				(string) $built['project'],
				$response->status,
				vh_trim( $response->error_message(), 220 )
			);

			$connector->log( $message );
			vulnhub()->logger->audit( 'ticket.create_failed', $message, 'ticket', 0, array( 'kind' => (string) $draft['kind'], 'status' => $response->status ), 'error' );

			return array( 'ok' => false, 'message' => $message );
		}

		$key = (string) ( $response->data()['key'] ?? '' );

		if ( '' === $key ) {
			return array( 'ok' => false, 'message' => __( 'Jira accepted the issue but returned no issue key.', 'vulnhub' ) );
		}

		$saved = \VulnHub\Core\Tickets::upsert(
			array(
				'provider'        => 'jira',
				'external_id'     => (string) ( $response->data()['id'] ?? '' ),
				'external_key'    => $key,
				'url'             => $connector->client()->browse_url( $key ),
				'project_key'     => (string) $built['project'],
				'issue_type'      => (string) $built['type'],
				'summary'         => (string) $fields['summary'],
				'status'          => __( 'To Do', 'vulnhub' ),
				'status_category' => 'new',
				'team_id'         => (int) ( $draft['team_id'] ?? 0 ),
				'grouping_key'    => (string) $built['group_key'],
				'created_via'     => 'manual',
				'created_by'      => get_current_user_id(),
				'kind'            => (string) $draft['kind'],
				'source_view'     => 'assets',
				'notes'           => (string) ( $draft['notes'] ?? '' ),
				'scope'           => (array) ( $draft['scope'] ?? array() ),
				'payload'         => array(
					'duedate' => (string) ( $fields['duedate'] ?? '' ),
					'labels'  => (array) ( $fields['labels'] ?? array() ),
				),
			)
		);

		\VulnHub\Core\Tickets::attach_assets( (int) $saved['id'], (array) $draft['assets'] );

		vulnhub()->logger->audit(
			'ticket.scope_created',
			sprintf( 'Raised Jira issue %1$s (%2$s) covering %3$d assets', $key, (string) $draft['kind'], count( (array) $draft['assets'] ) ),
			'ticket',
			(int) $saved['id'],
			array( 'kind' => (string) $draft['kind'], 'assets' => count( (array) $draft['assets'] ), 'project_key' => (string) $built['project'] )
		);

		return array(
			'ok'      => true,
			'message' => sprintf(
				/* translators: 1: issue key, 2: number of assets. */
				_n( 'Created %1$s covering %2$d asset.', 'Created %1$s covering %2$d assets.', count( (array) $draft['assets'] ), 'vulnhub' ),
				$key,
				count( (array) $draft['assets'] )
			),
			'ticket'  => (array) \VulnHub\Core\Tickets::get( (int) $saved['id'] ),
		);
	}

	/**
	 * The priorities Jira allows on this project and issue type, and its
	 * default, read from create metadata and cached for an hour.
	 *
	 * Names are site specific (Highest…Lowest on one site, P1…P4 on a service
	 * desk), so the review offers exactly these and sending checks against
	 * them. An empty list means "could not tell" -- mock mode, or a project
	 * the account cannot read -- and nothing is refused on that basis.
	 *
	 * @param array<string,string> $type_ref `{id}` or `{name}` as sent.
	 * @return array{names:string[],default:string}
	 */
	public function allowed_priorities( VulnHub_Jira_Connector $connector, string $project, array $type_ref ): array {
		$none = array( 'names' => array(), 'default' => '' );

		if ( '' === $project || $connector->is_mock() ) {
			return $none;
		}

		return $this->create_meta_summary( $connector, $project, $type_ref )['priority'];
	}

	/**
	 * The selectable fields the review offers, besides priority, by the name
	 * Jira gives them. Matched by name rather than id, because custom field
	 * ids differ on every site.
	 */
	public const REVIEW_SELECTS = array(
		'urgency' => 'Urgency',
		'impact'  => 'Impact',
	);

	/**
	 * What the project's create screen allows for the ticket's issue type:
	 * priorities, and the REVIEW_SELECTS fields with their options. Read from
	 * create metadata and cached for an hour.
	 *
	 * @param array<string,string> $type_ref `{id}` or `{name}` as sent.
	 * @return array{priority:array{names:string[],default:string},selects:array<string,array{field:string,label:string,options:array<int,array{id:string,value:string}>}>}
	 */
	public function create_meta_summary( VulnHub_Jira_Connector $connector, string $project, array $type_ref ): array {
		$none = array( 'priority' => array( 'names' => array(), 'default' => '' ), 'selects' => array() );

		if ( '' === $project || $connector->is_mock() ) {
			return $none;
		}

		$key    = 'vh_jira_meta_' . md5( $project . '|' . wp_json_encode( $type_ref ) );
		$cached = get_transient( $key );

		if ( is_array( $cached ) ) {
			return $cached;
		}

		$client  = $connector->client();
		$type_id = (string) ( $type_ref['id'] ?? '' );

		if ( '' === $type_id && '' !== (string) ( $type_ref['name'] ?? '' ) ) {
			$types = $client->create_issue_types( $project );

			foreach ( (array) ( $types->data()['issueTypes'] ?? $types->data()['values'] ?? array() ) as $t ) {
				if ( strcasecmp( (string) ( $t['name'] ?? '' ), (string) $type_ref['name'] ) === 0 ) {
					$type_id = (string) $t['id'];
					break;
				}
			}
		}

		if ( '' === $type_id ) {
			return $none;
		}

		$meta = $client->create_field_meta( $project, $type_id );

		if ( ! $meta->ok() ) {
			return $none;
		}

		$out = $none;

		foreach ( (array) ( $meta->data()['fields'] ?? $meta->data()['values'] ?? array() ) as $field ) {
			$field_id = (string) ( $field['fieldId'] ?? '' );

			if ( 'priority' === $field_id ) {
				$out['priority']['names']   = array_values( array_filter( array_map( static fn( $v ): string => (string) ( $v['name'] ?? '' ), (array) ( $field['allowedValues'] ?? array() ) ) ) );
				$out['priority']['default'] = (string) ( $field['defaultValue']['name'] ?? '' );
				continue;
			}

			$slug = array_search( strtolower( trim( (string) ( $field['name'] ?? '' ) ) ), array_map( 'strtolower', self::REVIEW_SELECTS ), true );

			if ( false === $slug || empty( $field['allowedValues'] ) || isset( $out['selects'][ $slug ] ) ) {
				continue;
			}

			$out['selects'][ $slug ] = array(
				'field'   => $field_id,
				'label'   => (string) $field['name'],
				'options' => array_values(
					array_map(
						static fn( $v ): array => array(
							'id'    => (string) ( $v['id'] ?? '' ),
							'value' => (string) ( $v['value'] ?? $v['name'] ?? '' ),
						),
						(array) $field['allowedValues']
					)
				),
			);
		}

		set_transient( $key, $out, HOUR_IN_SECONDS );

		return $out;
	}

	/**
	 * Put the reviewer's Urgency / Impact choices on a built issue, and
	 * describe the fields for the review.
	 *
	 * Nothing is set unless chosen: a choice is `{id}` of an option Jira
	 * listed for this project and issue type; anything else is ignored.
	 *
	 * @param array<string,mixed> $built  From build_issue() / build_scope_issue().
	 * @param array<string,mixed> $params Draft params (`selects` => slug => option id).
	 * @return array<string,mixed> The built issue with fields set and `selects` for the review.
	 */
	/**
	 * Replace the generated description with the reviewer's edited text.
	 *
	 * The review offers the description as editable text (see
	 * VulnHub_Jira_Adf::to_editable()); an edit rebuilds the draft with
	 * `description`, which is read back into ADF here, so the preview, the
	 * stored draft and what Send transmits are one document. Empty means "use
	 * the generated description".
	 *
	 * @param array<string,mixed> $built  Built issue.
	 * @param array<string,mixed> $params Draft request.
	 * @return array<string,mixed>
	 */
	public function apply_description_edit( array $built, array $params ): array {
		$text = trim( str_replace( "\r\n", "\n", (string) ( $params['description'] ?? '' ) ) );

		if ( '' === $text || empty( $built['fields'] ) ) {
			return $built;
		}

		$doc = VulnHub_Jira_Adf::from_editable( mb_substr( $text, 0, self::DESCRIPTION_EDIT_MAX ) );

		$built['fields']['description'] = $doc;
		$built['description_edited']    = true;

		if ( mb_strlen( $text ) > self::DESCRIPTION_EDIT_MAX ) {
			$built['description_trimmed'] = true;
		}

		return $built;
	}

	public function apply_review_selects( VulnHub_Jira_Connector $connector, array $built, array $params ): array {
		$meta    = $this->create_meta_summary( $connector, (string) $built['project'], (array) ( $built['fields']['issuetype'] ?? array() ) );
		$chosen  = (array) ( $params['selects'] ?? array() );
		$review  = array();

		foreach ( $meta['selects'] as $slug => $def ) {
			$pick  = sanitize_text_field( (string) ( $chosen[ $slug ] ?? '' ) );
			$valid = array_column( $def['options'], 'value', 'id' );
			$value = '';

			if ( '' !== $pick && 'none' !== $pick && isset( $valid[ $pick ] ) ) {
				$built['fields'][ $def['field'] ] = array( 'id' => $pick );
				$value                            = $pick;
			}

			$review[] = array(
				'key'     => $slug,
				'label'   => $def['label'],
				'value'   => $value,
				'text'    => '' !== $value ? (string) $valid[ $value ] : '',
				'options' => $def['options'],
			);
		}

		$built['selects'] = $review;

		return $built;
	}

	/**
	 * Read a reviewer's priority choice from draft params.
	 *
	 * @param array<string,mixed> $params Draft params.
	 * @return array{set:bool,value:string} set=false when no choice was made.
	 */
	public static function priority_choice( array $params ): array {
		if ( ! array_key_exists( 'priority', $params ) || '' === (string) $params['priority'] ) {
			return array( 'set' => false, 'value' => '' );
		}

		$value = sanitize_text_field( (string) $params['priority'] );

		return array( 'set' => true, 'value' => 'none' === $value ? '' : $value );
	}

	private static function draft_key( string $token ): string {
		return 'vh_jira_draft_' . hash_hmac( 'sha256', $token, wp_salt( 'auth' ) );
	}

	/**
	 * The exact CSV a draft will attach, for the reviewer to open.
	 */
	public function download_draft_csv(): void {
		if ( ! is_user_logged_in() || ! current_user_can( \VulnHub\Core\Caps::RAISE_TICKET ) ) {
			wp_die( esc_html__( 'You do not have permission to do that.', 'vulnhub' ), '', array( 'response' => 403 ) );
		}

		check_admin_referer( self::DRAFT_CSV_ACTION );

		$token = isset( $_GET['draft'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['draft'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$draft = '' !== $token ? get_transient( self::draft_key( $token ) ) : false;

		if ( ! is_array( $draft ) || (int) $draft['user'] !== get_current_user_id() || empty( $draft['csv'] ) ) {
			wp_die( esc_html__( 'That draft has expired. Open the review again.', 'vulnhub' ), '', array( 'response' => 410 ) );
		}

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . sanitize_file_name( (string) $draft['csv']['name'] ) . '"' );

		while ( ob_get_level() > 0 ) {
			ob_end_clean();
		}

		echo base64_decode( (string) $draft['csv']['bytes'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- a CSV file, sent as a download.
		exit;
	}

	/**
	 * Send a reviewed draft: exactly its fields, then exactly its attachment.
	 *
	 * @return array<string,mixed>
	 */
	public function send_draft( string $token ): array {
		$connector = vulnhub_jira_connector();
		$fail      = static fn( string $message ): array => array( 'ok' => false, 'message' => $message, 'tickets' => array(), 'created' => 0, 'updated' => 0, 'failed' => 1 );

		if ( ! $connector || ! $connector->is_enabled() ) {
			return $fail( __( 'Jira is not enabled.', 'vulnhub' ) );
		}

		if ( ! $this->lock_group( self::MANUAL_LOCK ) ) {
			return $fail( __( 'Another ticket is being raised right now. Try again in a moment.', 'vulnhub' ) );
		}

		try {
			$key   = self::draft_key( $token );
			$draft = get_transient( $key );

			if ( ! is_array( $draft ) || (int) $draft['user'] !== get_current_user_id() ) {
				return $fail( __( 'That review has expired or was already sent. Open Raise ticket again to review it.', 'vulnhub' ) );
			}

			// Spent now, before anything goes out: a second press of Send, or
			// a retried request, finds nothing to send.
			delete_transient( $key );

			if ( 'assets' === ( $draft['type'] ?? 'findings' ) ) {
				$result = $this->submit_scope_issue( $connector, $draft );
			} else {
				$result = $this->send_findings_draft( $connector, $draft );
			}

			if ( empty( $result['ok'] ) ) {
				return $fail( (string) $result['message'] );
			}

			return $this->attach_draft_file( $connector, $draft, $result );
		} finally {
			$this->unlock_group( self::MANUAL_LOCK );
		}
	}

	/**
	 * Re-check a finding draft's selection and create its issue exactly.
	 *
	 * @param array<string,mixed> $draft Stored draft.
	 * @return array<string,mixed>
	 */
	private function send_findings_draft( VulnHub_Jira_Connector $connector, array $draft ): array {
		$fail = static fn( string $message ): array => array( 'ok' => false, 'message' => $message );
		$ids  = array_map( 'intval', (array) $draft['ids'] );
		$plan = $this->plan( $ids );
		$now  = array_map( static fn( array $r ): int => (int) $r['id'], $plan['rows'] );
		sort( $now );

		if ( $now !== $ids ) {
			return $fail(
				sprintf(
					/* translators: %d: findings no longer eligible. */
					__( 'The selection changed after you reviewed it (%d finding(s) are now on another ticket or gone). Nothing was sent; open Raise ticket again to review the current version.', 'vulnhub' ),
					count( array_diff( $ids, $now ) )
				)
			);
		}

		$result = $this->submit_issue(
			$connector,
			(array) $draft['built'],
			$plan['rows'],
			array(
				'exact'       => true,
				'created_via' => 'manual',
				'created_by'  => get_current_user_id(),
			)
		);

		return $result;
	}

	/**
	 * Attach a sent draft's file to the ticket that was just created.
	 *
	 * @param array<string,mixed> $draft  Stored draft.
	 * @param array<string,mixed> $result Successful create result.
	 * @return array<string,mixed>
	 */
	private function attach_draft_file( VulnHub_Jira_Connector $connector, array $draft, array $result ): array {
		$ticket  = (array) $result['ticket'];
		$message = (string) $result['message'];

		if ( ! empty( $draft['csv'] ) ) {
			$upload = $connector->client()->attach(
				(string) $ticket['external_key'],
				(string) $draft['csv']['name'],
				(string) base64_decode( (string) $draft['csv']['bytes'] ),
				'text/csv'
			);

			if ( $upload->ok() ) {
				$message .= ' ' . sprintf(
					/* translators: 1: file name, 2: rows. */
					__( 'Attached %1$s (%2$d rows).', 'vulnhub' ),
					(string) $draft['csv']['name'],
					(int) $draft['csv']['rows']
				);
			} else {
				$message .= ' ' . sprintf(
					/* translators: 1: file name, 2: HTTP status, 3: error. */
					__( 'The ticket was created, but attaching %1$s failed (HTTP %2$d: %3$s). It was not retried; export the list and attach it by hand.', 'vulnhub' ),
					(string) $draft['csv']['name'],
					$upload->status,
					vh_trim( $upload->error_message(), 140 )
				);
			}

			vulnhub()->logger->audit(
				$upload->ok() ? 'ticket.attached' : 'ticket.attach_failed',
				sprintf( '%s: %s %s', (string) $ticket['external_key'], (string) $draft['csv']['name'], $upload->ok() ? 'attached' : 'not attached' ),
				'ticket',
				(int) $ticket['id'],
				array( 'rows' => (int) $draft['csv']['rows'], 'status' => $upload->status ),
				$upload->ok() ? 'info' : 'warning'
			);
		}

		return array(
			'ok'       => true,
			'message'  => $message,
			'ticket'   => $ticket,
			'tickets'  => array( $ticket ),
			'created'  => 1,
			'updated'  => 0,
			'failed'   => 0,
			'redirect' => (string) apply_filters( 'vulnhub_ticket_page_url', '', (int) $ticket['id'] ),
		);
	}

	/**
	 * The findings a manual raise will cover, and the ones it leaves out.
	 *
	 * Left out: findings already on a ticket that is still open, so a finding
	 * is never on two open tickets. A finding whose ticket is closed can be
	 * raised again -- that is how a recurrence gets a fresh ticket.
	 *
	 * @param int[] $finding_ids Selected findings.
	 * @return array{rows:array<int,array<string,mixed>>,skipped:int,on_tickets:string[],error:string}
	 */
	private function plan( array $finding_ids ): array {
		global $wpdb;

		$out         = array( 'rows' => array(), 'skipped' => 0, 'on_tickets' => array(), 'error' => '' );
		$finding_ids = array_values( array_unique( array_filter( array_map( 'intval', $finding_ids ) ) ) );

		if ( ! $finding_ids ) {
			$out['error'] = __( 'Select at least one finding.', 'vulnhub' );
			return $out;
		}

		// Refused, not trimmed: quietly ticketing the first 500 of 800 would
		// leave 300 findings looking handled when nobody was asked about them.
		if ( count( $finding_ids ) > self::max_findings() ) {
			$out['error'] = sprintf(
				/* translators: 1: selected count, 2: the limit. */
				__( '%1$d findings are selected; one ticket can cover at most %2$d. Narrow the selection.', 'vulnhub' ),
				count( $finding_ids ),
				self::max_findings()
			);
			return $out;
		}

		$rows = $this->load_findings( $finding_ids );

		if ( ! $rows ) {
			$out['error'] = __( 'None of those findings exist any more.', 'vulnhub' );
			return $out;
		}

		$ticket_ids = array_values( array_unique( array_filter( array_map( static fn( array $r ): int => (int) $r['ticket_id'], $rows ) ) ) );
		$open       = array();

		if ( $ticket_ids ) {
			$found = (array) $wpdb->get_results(
				'SELECT id, external_key FROM ' . vh_table( 'tickets' ) . " WHERE status_category <> 'done' AND id IN (" . implode( ',', $ticket_ids ) . ')', // phpcs:ignore WordPress.DB.PreparedSQL
				ARRAY_A
			);

			foreach ( $found as $t ) {
				$open[ (int) $t['id'] ] = (string) $t['external_key'];
			}
		}

		foreach ( $rows as $row ) {
			$tid = (int) $row['ticket_id'];

			if ( $tid && isset( $open[ $tid ] ) ) {
				++$out['skipped'];
				$out['on_tickets'][ $open[ $tid ] ] = $open[ $tid ];
				continue;
			}

			$out['rows'][] = $row;
		}

		$out['on_tickets'] = array_values( $out['on_tickets'] );

		if ( ! $out['rows'] ) {
			$out['error'] = sprintf(
				/* translators: %s: ticket keys. */
				__( 'Nothing to raise: every selected finding is already on an open ticket (%s).', 'vulnhub' ),
				implode( ', ', $out['on_tickets'] )
			);
		}

		return $out;
	}

	/* =================================================================
	 * Grouping
	 * ============================================================== */

	/**
	 * Split findings into the groups that will each become one Jira issue.
	 *
	 * @param array<int,array<string,mixed>> $rows     Finding rows.
	 * @param string                         $grouping Grouping strategy.
	 * @return array<string,array<int,array<string,mixed>>> Grouping key => rows.
	 */
	public function group( array $rows, string $grouping ): array {
		$groups = array();

		foreach ( $rows as $row ) {
			$key = $this->grouping_key( $row, $grouping );

			$groups[ $key ][] = $row;
		}

		return $groups;
	}

	/**
	 * The stable identity of the ticket a finding belongs in.
	 *
	 * @param array<string,mixed> $row      Finding row.
	 * @param string              $grouping Grouping strategy.
	 */
	public function grouping_key( array $row, string $grouping ): string {
		return match ( $grouping ) {
			'per_asset'              => 'asset:' . (int) $row['asset_id'],
			'per_vulnerability'      => 'vuln:' . (int) $row['vuln_id'],
			'per_asset_and_severity' => 'asset:' . (int) $row['asset_id'] . ':' . (string) $row['severity'],
			default                  => 'finding:' . (int) $row['id'],
		};
	}

	/* =================================================================
	 * One group -> one Jira issue
	 * ============================================================== */

	/**
	 * Create or extend the issue for one group.
	 *
	 * @param VulnHub_Jira_Connector         $connector  Connector.
	 * @param string                         $group_key  Grouping key.
	 * @param array<int,array<string,mixed>> $rows       Finding rows in the group.
	 * @param string                         $grouping   Grouping strategy.
	 * @param array<string,mixed>            $options    Caller options.
	 * @return array{ok:bool,message:string,created?:bool,ticket?:array<string,mixed>}
	 */
	private function handle_group(
		VulnHub_Jira_Connector $connector,
		string $group_key,
		array $rows,
		string $grouping,
		array $options
	): array {
		/*
		 * One raise per group at a time.
		 *
		 * The open-ticket check and the create are separate steps, so two
		 * raises for the same asset and severity arriving together would both
		 * find nothing open and both create an issue. The first to arrive holds
		 * a lock for the group; a second one arriving meanwhile is refused and
		 * told to try again, rather than waiting -- by then the first has saved
		 * its ticket and the retry joins it.
		 */
		if ( ! $this->lock_group( $group_key ) ) {
			$connector->log( sprintf( 'Refused a second raise for %s while another was still creating its ticket.', $group_key ) );

			return array(
				'ok'      => false,
				'message' => __( 'A ticket for this asset and severity is being raised right now. Try again in a moment.', 'vulnhub' ),
			);
		}

		try {
			$existing = $this->open_ticket_for( $group_key );

			if ( $existing ) {
				return $this->extend_ticket( $connector, $existing, $rows, $grouping );
			}

			return $this->create_group_ticket( $connector, $group_key, $rows, $grouping, $options );
		} finally {
			$this->unlock_group( $group_key );
		}
	}

	/**
	 * A lock older than this belongs to a raise that died mid-way. Long enough
	 * to cover the create call's own 45-second timeout plus the remote link.
	 */
	private const GROUP_LOCK_TTL = 120;

	private function group_lock_name( string $group_key ): string {
		return 'vulnhub_jira_raise_' . md5( $group_key );
	}

	/**
	 * Take the group's lock. add_option() is an INSERT on a unique key, so
	 * exactly one concurrent caller succeeds.
	 */
	private function lock_group( string $group_key ): bool {
		$name = $this->group_lock_name( $group_key );

		if ( add_option( $name, (string) time(), '', false ) ) {
			return true;
		}

		wp_cache_delete( $name, 'options' );

		if ( (int) get_option( $name, 0 ) < time() - self::GROUP_LOCK_TTL ) {
			delete_option( $name );

			return add_option( $name, (string) time(), '', false );
		}

		return false;
	}

	private function unlock_group( string $group_key ): void {
		delete_option( $this->group_lock_name( $group_key ) );
	}

	/**
	 * Recompute a grouped ticket's summary from every finding it now covers and
	 * push the change to Jira.
	 *
	 * Called only when a ticket actually gained findings, so a ticket whose
	 * contents did not change is never edited remotely.
	 *
	 * @param array<string,mixed> $ticket   Ticket row.
	 * @param string              $grouping Grouping strategy.
	 */
	private function restate_summary( VulnHub_Jira_Connector $connector, array $ticket, string $grouping ): void {
		$ticket_id = (int) $ticket['id'];
		$covered   = \VulnHub\Core\Tickets::findings_for( $ticket_id );

		if ( count( $covered ) < 2 ) {
			return;
		}

		$fresh = $this->summary( $covered, $grouping, $this->top_severity( $covered ) );
		$old   = (string) $ticket['summary'];

		if ( '' === $fresh || $fresh === $old ) {
			return;
		}

		$response = $connector->client()->update_issue( (string) $ticket['external_key'], array( 'summary' => $fresh ) );

		if ( ! $response->ok() ) {
			$connector->log(
				sprintf(
					'Could not restate the summary of %s (HTTP %d): %s',
					(string) $ticket['external_key'],
					$response->status,
					vh_trim( $response->error_message(), 160 )
				)
			);
			return;
		}

		\VulnHub\Core\Tickets::upsert(
			array(
				'provider'     => (string) $ticket['provider'],
				'external_key' => (string) $ticket['external_key'],
				'summary'      => $fresh,
			)
		);

		$connector->log( sprintf( 'Restated %s summary to "%s"', (string) $ticket['external_key'], vh_trim( $fresh, 90 ) ) );
	}

	/**
	 * An open Jira ticket already covering this grouping key, if any.
	 *
	 * @return array<string,mixed>|null
	 */
	private function open_ticket_for( string $group_key ): ?array {
		global $wpdb;

		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT * FROM ' . vh_table( 'tickets' ) . " WHERE provider = %s AND grouping_key = %s AND status_category <> 'done' ORDER BY id DESC LIMIT 1",
				'jira',
				$group_key
			),
			ARRAY_A
		);

		return $row ?: null;
	}

	/**
	 * Attach newly-seen findings to an open ticket and say so in Jira.
	 *
	 * @param VulnHub_Jira_Connector         $connector Connector.
	 * @param array<string,mixed>            $ticket    Existing ticket row.
	 * @param array<int,array<string,mixed>> $rows      Finding rows.
	 * @param string                         $grouping  Grouping strategy, so the
	 *                                                  summary can be restated.
	 * @return array{ok:bool,message:string,created:bool,ticket:array<string,mixed>}
	 */
	private function extend_ticket( VulnHub_Jira_Connector $connector, array $ticket, array $rows, string $grouping = '' ): array {
		$ticket_id = (int) $ticket['id'];
		$known     = array();

		foreach ( \VulnHub\Core\Tickets::findings_for( $ticket_id ) as $existing ) {
			$known[ (int) $existing['id'] ] = true;
		}

		$new = array_values(
			array_filter(
				$rows,
				static fn( array $row ): bool => ! isset( $known[ (int) $row['id'] ] )
			)
		);

		\VulnHub\Core\Tickets::attach_findings( $ticket_id, array_map( static fn( array $r ): int => (int) $r['id'], $rows ) );

		if ( $new ) {
			$adf = VulnHub_Jira_Adf::doc()
				->paragraph(
					array(
						VulnHub_Jira_Adf::strong( __( 'Further findings added to this ticket.', 'vulnhub' ) ),
						VulnHub_Jira_Adf::text( ' ' ),
						VulnHub_Jira_Adf::text(
							sprintf(
								/* translators: %d: number of findings. */
								_n(
									'%d further finding matched the same grouping while this ticket was still open, so it has been folded in here rather than raised separately.',
									'%d further findings matched the same grouping while this ticket was still open, so they have been folded in here rather than raised separately.',
									count( $new ),
									'vulnhub'
								),
								count( $new )
							)
						),
					)
				)
				->bullets( array_map( array( $this, 'finding_line' ), $new ) )
				->to_array();

			$response = $connector->client()->comment( (string) $ticket['external_key'], $adf );

			if ( ! $response->ok() ) {
				$connector->log(
					sprintf(
						'Could not comment on %s (HTTP %d): %s',
						(string) $ticket['external_key'],
						$response->status,
						vh_trim( $response->error_message(), 160 )
					)
				);
			}
		}

		// A grouped ticket that grows must not keep advertising only the first
		// vulnerability that created it — that misrepresents its own contents.
		if ( $new && '' !== $grouping ) {
			$this->restate_summary( $connector, $ticket, $grouping );
		}

		vulnhub()->logger->audit(
			'ticket.extended',
			sprintf(
				/* translators: 1: ticket key, 2: number of findings added. */
				__( 'Attached %2$d finding(s) to the open Jira issue %1$s.', 'vulnhub' ),
				(string) $ticket['external_key'],
				count( $new )
			),
			'ticket',
			$ticket_id,
			array(
				'grouping_key' => (string) $ticket['grouping_key'],
				'added'        => count( $new ),
				'total'        => count( $rows ),
			)
		);

		return array(
			'ok'      => true,
			'created' => false,
			'message' => sprintf(
				/* translators: 1: ticket key, 2: findings added. */
				__( '%1$s already covers this group; %2$d new finding(s) attached.', 'vulnhub' ),
				(string) $ticket['external_key'],
				count( $new )
			),
			'ticket'  => (array) \VulnHub\Core\Tickets::get( $ticket_id ),
		);
	}

	/**
	 * Create a brand new Jira issue for a group.
	 *
	 * @param VulnHub_Jira_Connector         $connector Connector.
	 * @param string                         $group_key Grouping key.
	 * @param array<int,array<string,mixed>> $rows      Finding rows.
	 * @param string                         $grouping  Grouping strategy.
	 * @param array<string,mixed>            $options   Caller options.
	 * @return array{ok:bool,message:string,created?:bool,ticket?:array<string,mixed>}
	 */
	private function create_group_ticket(
		VulnHub_Jira_Connector $connector,
		string $group_key,
		array $rows,
		string $grouping,
		array $options
	): array {
		$built = $this->build_issue( $connector, $group_key, $rows, $grouping, $options );

		if ( empty( $built['ok'] ) ) {
			return $built;
		}

		return $this->submit_issue( $connector, $built, $rows, $options );
	}

	/**
	 * Everything a new issue will carry, without sending it.
	 *
	 * The review screen shows exactly this, and submit_issue() sends exactly
	 * this: one build, so what was approved is what travels.
	 *
	 * @param array<int,array<string,mixed>> $rows Finding rows.
	 * @param array<string,mixed>            $options Caller options.
	 * @return array<string,mixed> ok=false with message, or the built issue.
	 */
	private function build_issue( VulnHub_Jira_Connector $connector, string $group_key, array $rows, string $grouping, array $options ): array {
		$team     = $this->dominant_team( $rows );
		$severity = $this->top_severity( $rows );
		$routing  = $this->routing( $connector, $team );
		$project  = $routing['project'];
		$type     = $routing['issue_type'];
		// A reviewer's choice wins ('' = send none); otherwise the severity
		// mapping, when the connector sends a priority at all.
		$priority = array_key_exists( 'priority', $options )
			? (string) $options['priority']
			: ( $connector->sends_priority() ? $connector->priority_for( $severity ) : '' );
		$summary  = $this->summary( $rows, $grouping, $severity );
		// Due from the day the ticket is raised, by the organisation SLA for its
		// severity -- or the date the reviewer set.
		$due      = '' !== (string) ( $options['due_date'] ?? '' ) ? (string) $options['due_date'] : vh_due_in_days( vh_sla_days( $severity ) );

		if ( '' === $project ) {
			return array(
				'ok'      => false,
				'message' => __( 'No Jira project key is configured, and the owning team has none either.', 'vulnhub' ),
			);
		}

		$fields = array(
			'project'     => array( 'key' => $project ),
			'summary'     => $summary,
			'issuetype'   => $routing['issue_type_ref'],
			'description' => $this->description( $rows, $grouping, $severity, $team, $options ),
			'labels'      => $this->labels( $rows, $severity ),
		);

		// The whole point of the routing settings: the team goes on the issue,
		// so a service desk stops dropping every VulnHub ticket on whichever
		// team the desk itself defaults to.
		if ( '' !== $routing['team_field'] && '' !== $routing['team_value'] ) {
			$fields[ $routing['team_field'] ] = $routing['team_write'];
		}

		if ( '' !== $priority ) {
			$fields['priority'] = array( 'name' => $priority );
		}
		if ( '' !== $due ) {
			$fields['duedate'] = $due;
		}

		$account_id = $this->resolve_assignee( $connector, (string) ( $team['jira_default_assignee'] ?? '' ) );

		if ( '' !== $account_id ) {
			$fields['assignee'] = array( 'id' => $account_id );
		}

		return array(
			'ok'         => true,
			'fields'     => $fields,
			'routing'    => $routing,
			'project'    => $project,
			'type'       => $type,
			'priority'   => $priority,
			'summary'    => $summary,
			'due'        => $due,
			'team'       => $team,
			'severity'   => $severity,
			'account_id' => $account_id,
			'group_key'  => $group_key,
			'grouping'   => $grouping,
		);
	}

	/**
	 * Send a built issue, record it, and link it back.
	 *
	 * With `exact` set (the reviewed path) nothing is changed and re-sent: if
	 * Jira rejects a field, the person who approved the ticket is told, rather
	 * than a different ticket going out in their name. Automation keeps the
	 * one self-healing retry below.
	 *
	 * @param array<string,mixed>            $built   From build_issue().
	 * @param array<int,array<string,mixed>> $rows    Finding rows.
	 * @param array<string,mixed>            $options Caller options.
	 * @return array{ok:bool,message:string,created?:bool,ticket?:array<string,mixed>,key?:string}
	 */
	private function submit_issue( VulnHub_Jira_Connector $connector, array $built, array $rows, array $options ): array {
		$fields     = (array) $built['fields'];
		$routing    = (array) $built['routing'];
		$project    = (string) $built['project'];
		$type       = (string) $built['type'];
		$priority   = (string) $built['priority'];
		$summary    = (string) $built['summary'];
		$due        = (string) $built['due'];
		$team       = (array) $built['team'];
		$severity   = (string) $built['severity'];
		$account_id = (string) $built['account_id'];
		$group_key  = (string) $built['group_key'];
		$grouping   = (string) $built['grouping'];

		$response = $connector->client()->create_issue( $fields );

		// A site can have the Team field out of the create screen's field
		// configuration, in which case Jira rejects the whole issue with an
		// error naming that field. Losing the team is much better than losing
		// the ticket, so drop it and try once more, loudly.
		if ( empty( $options['exact'] ) && ! $response->ok() && isset( $fields[ $routing['team_field'] ] ) && $this->rejected_field( $response, (string) $routing['team_field'] ) ) {
			$connector->log(
				sprintf(
					'Jira rejected the Team field %s on %s ("%s"); retrying without it. Add the field to that project\'s create screen to route by team.',
					(string) $routing['team_field'],
					$project,
					vh_trim( $response->error_message(), 140 )
				)
			);

			unset( $fields[ $routing['team_field'] ] );

			$routing['team_value'] = '';
			$response              = $connector->client()->create_issue( $fields );
		}

		if ( ! $response->ok() ) {
			$message = sprintf(
				/* translators: 1: project key, 2: HTTP status, 3: error message. */
				__( 'Jira refused to create the issue in %1$s (HTTP %2$d): %3$s', 'vulnhub' ),
				$project,
				$response->status,
				vh_trim( $response->error_message(), 220 )
			);

			$connector->log( $message );

			vulnhub()->logger->audit(
				'ticket.create_failed',
				$message,
				'finding',
				(int) $rows[0]['id'],
				array(
					'project_key'  => $project,
					'issue_type'   => $type,
					'grouping_key' => $group_key,
					'status'       => $response->status,
				),
				'error'
			);

			return array(
				'ok'      => false,
				'message' => $message,
			);
		}

		$data = $response->data();
		$key  = (string) ( $data['key'] ?? '' );

		if ( '' === $key ) {
			return array(
				'ok'      => false,
				'message' => __( 'Jira accepted the issue but returned no issue key.', 'vulnhub' ),
			);
		}

		$url = $connector->client()->browse_url( $key );

		$upsert = \VulnHub\Core\Tickets::upsert(
			array(
				'provider'        => 'jira',
				'external_id'     => (string) ( $data['id'] ?? '' ),
				'external_key'    => $key,
				'url'             => $url,
				'project_key'     => $project,
				'issue_type'      => $type,
				'summary'         => $summary,
				'status'          => __( 'To Do', 'vulnhub' ),
				'status_category' => 'new',
				'priority'        => $priority,
				'assignee'        => '',
				'assignee_id'     => $account_id,
				'team_id'         => (int) ( $team['id'] ?? 0 ),
				'asset_id'        => $this->single_asset_id( $rows ),
				'grouping_key'    => $group_key,
				'created_via'     => (string) ( $options['created_via'] ?? 'manual' ),
				'created_by'      => (int) ( $options['created_by'] ?? get_current_user_id() ),
				'automation_id'   => (int) ( $options['automation_id'] ?? 0 ),
				'verification_state' => \VulnHub\Core\Tickets::VERIFY_NOT_REQUIRED,
				'payload'         => array(
					'grouping'  => $grouping,
					'severity'  => $severity,
					'routing'   => $routing['audit'],
					'duedate'   => $due,
					'labels'    => $fields['labels'],
					'findings'  => array_map( static fn( array $r ): int => (int) $r['id'], $rows ),
					'mock'      => $connector->is_mock(),
				),
			)
		);

		$ticket_id = (int) $upsert['id'];

		\VulnHub\Core\Tickets::attach_findings( $ticket_id, array_map( static fn( array $r ): int => (int) $r['id'], $rows ) );

		if ( $connector->links_back() ) {
			$this->add_remote_link( $connector, $key, $rows, $ticket_id, $summary );
		}

		$connector->log(
			sprintf(
				'Created %s in %s (%s, priority %s) covering %d finding(s), routed by %s%s%s — %s',
				$key,
				$project,
				$type,
				$priority,
				count( $rows ),
				$routing['source'],
				'' !== $routing['request_type_name'] ? ', request type "' . $routing['request_type_name'] . '"' : '',
				'' !== $routing['team_value'] ? ', team "' . $routing['team_value'] . '"' : '',
				$url
			)
		);

		vulnhub()->logger->audit(
			'ticket.created',
			sprintf(
				/* translators: 1: issue key, 2: number of findings, 3: severity label, 4: project key. */
				__( 'Raised Jira issue %1$s in %4$s covering %2$d %3$s finding(s).', 'vulnhub' ),
				$key,
				count( $rows ),
				strtolower( vh_severity_label( $severity ) ),
				$project
			),
			'ticket',
			$ticket_id,
			array(
				'url'          => $url,
				'project_key'  => $project,
				'issue_type'   => $type,
				'priority'     => $priority,
				'severity'     => $severity,
				'grouping'     => $grouping,
				'grouping_key' => $group_key,
				'team'         => (string) ( $team['name'] ?? '' ),
				'routing'      => $routing['audit'],
				'assignee_id'  => $account_id,
				'due_date'     => $due,
				'findings'     => array_map( static fn( array $r ): int => (int) $r['id'], $rows ),
				'assets'       => array_values( array_unique( array_map( static fn( array $r ): string => (string) $r['hostname'], $rows ) ) ),
				'created_via'  => (string) ( $options['created_via'] ?? 'manual' ),
				'mode'         => $connector->is_mock() ? 'mock' : 'live',
			)
		);

		return array(
			'ok'      => true,
			'created' => true,
			'message' => sprintf(
				/* translators: 1: issue key, 2: number of findings. */
				__( 'Created %1$s covering %2$d finding(s).', 'vulnhub' ),
				$key,
				count( $rows )
			),
			'ticket'  => (array) \VulnHub\Core\Tickets::get( $ticket_id ),
		);
	}

	/**
	 * Link the Jira issue back to VulnHub so the loop is closed from both ends.
	 *
	 * `globalId` makes this idempotent — re-running never duplicates the link.
	 *
	 * @param VulnHub_Jira_Connector         $connector Connector.
	 * @param string                         $key       Issue key.
	 * @param array<int,array<string,mixed>> $rows      Finding rows.
	 * @param int                            $ticket_id VulnHub ticket id.
	 * @param string                         $summary   Issue summary.
	 */
	private function add_remote_link( VulnHub_Jira_Connector $connector, string $key, array $rows, int $ticket_id, string $summary ): void {
		$asset_id = (int) $rows[0]['asset_id'];
		$url      = $asset_id
			? vh_admin_url( 'vulnhub-assets', array( 'asset' => $asset_id ) )
			: vh_admin_url( 'vulnhub-tickets', array( 'ticket' => $ticket_id ) );

		$response = $connector->client()->remote_link(
			$key,
			$url,
			sprintf(
				/* translators: %s: hostname. */
				__( 'Remediation record — %s', 'vulnhub' ),
				(string) $rows[0]['hostname']
			),
			$summary,
			'remediation:ticket:' . $ticket_id
		);

		if ( ! $response->ok() ) {
			$connector->log(
				sprintf(
					'Remote issue link on %s failed (HTTP %d): %s',
					$key,
					$response->status,
					vh_trim( $response->error_message(), 160 )
				)
			);
		}
	}

	/* =================================================================
	 * Summary, labels and the ADF description
	 * ============================================================== */

	/**
	 * The issue summary line.
	 *
	 * @param array<int,array<string,mixed>> $rows     Finding rows.
	 * @param string                         $grouping Grouping strategy.
	 * @param string                         $severity Highest severity in the group.
	 */
	private function summary( array $rows, string $grouping, string $severity ): string {
		$first    = $rows[0];
		$hostname = (string) $first['hostname'];
		$label    = strtoupper( vh_severity_label( $severity ) );
		$count    = count( $rows );
		$assets   = count( $this->distinct( $rows, 'asset_id' ) );
		$where    = $this->summary_platform( $rows );

		/*
		 * A queue is read by its summaries, so a ticket covering more than one
		 * finding says what, of which kind, and where: "Microsoft Office —
		 * application vulnerability — Windows workstations — 32 vulnerabilities
		 * on 4 assets". A single finding keeps its title, which already names
		 * the product, plus the machine and its platform.
		 */
		if ( 'per_vulnerability' === $grouping ) {
			$text = sprintf(
				/* translators: 1: vulnerability title, 2: number of assets. */
				_n( '%1$s — %2$d affected asset', '%1$s — %2$d affected assets', $assets, 'vulnhub' ),
				vh_trim( (string) $first['vuln_title'], 150 ),
				$assets
			);

			return vh_trim( sprintf( '[%s] %s', $label, '' !== $where ? $text . ' — ' . $where : $text ), 250 );
		}

		if ( $count > 1 ) {
			$text = implode(
				' — ',
				array_filter(
					array(
						$this->summary_products( $rows ),
						$this->summary_kind( $rows ),
						$where,
						1 === $assets
							? sprintf(
								/* translators: 1: number of vulnerabilities, 2: hostname. */
								_n( '%1$d vulnerability on %2$s', '%1$d vulnerabilities on %2$s', $count, 'vulnhub' ),
								$count,
								$hostname
							)
							: sprintf(
								/* translators: 1: number of vulnerabilities, 2: number of assets. */
								__( '%1$d vulnerabilities on %2$d assets', 'vulnhub' ),
								$count,
								$assets
							),
					)
				)
			);

			return vh_trim( sprintf( '[%s] %s', $label, $text ), 250 );
		}

		/* translators: 1: vulnerability title, 2: hostname, 3: platform and asset type. */
		$text = '' !== $where
			? sprintf( __( '%1$s on %2$s (%3$s)', 'vulnhub' ), vh_trim( (string) $first['vuln_title'], 150 ), $hostname, $where )
			: sprintf( __( '%1$s on %2$s', 'vulnhub' ), vh_trim( (string) $first['vuln_title'], 150 ), $hostname );

		return vh_trim( sprintf( '[%s] %s', $label, $text ), 250 );
	}

	/**
	 * Remediation for one application's bundled components, instruction first.
	 *
	 * For the service desk the order matters more than the detail: say whether
	 * updating the application fixes it (and on which machine that is already
	 * true), say which copy will survive the update, then list the paths.
	 *
	 * @param array<string,array<int,array<string,mixed>>> $copies Rows by product|path key.
	 */
	private function describe_app_fix( VulnHub_Jira_Adf $doc, string $app, array $copies ): void {
		// Merge copies by where they sit inside the application (the last three
		// path segments), so a Store install and a Program Files install of the
		// same driver read as one line.
		$groups = array();

		foreach ( $copies as $rows ) {
			$ref  = \VulnHub\Core\App_Fix::references( $rows[0], 1 );
			$path = str_replace( '/', '\\', (string) preg_replace( '#\\\\{2,}#', '\\', $ref['path'] ) );
			$tail = implode( '\\', array_slice( explode( '\\', $path ), -3 ) );
			$key  = (string) ( $rows[0]['product'] ?? '' ) . '|' . strtolower( $tail );

			$g = $groups[ $key ] ?? array(
				'product'   => (string) ( $rows[0]['product'] ?? '' ),
				'tail'      => '' !== $tail ? $tail : __( 'an unreported path', 'vulnhub' ),
				'paths'     => array(),
				'findings'  => 0,
				'installed' => $ref['installed'],
				'fixed'     => $ref['fixed'],
				'max'       => '',
				'observed'  => 0,
				'newer'     => null,
				'newer_n'   => 0,
				'resolved'  => null,
				'resolved_n' => 0,
				'fixed_from' => '',
				'newest_vulnerable' => '',
				'newest'     => '',
			);

			$g['paths'][ $path ] = true;

			foreach ( array( 'fixed_from', 'newest_vulnerable', 'newest' ) as $k ) {
				if ( '' !== $ref[ $k ] && ( '' === $g[ $k ] || ( 'fixed_from' === $k ? version_compare( $ref[ $k ], $g[ $k ], '<' ) : version_compare( $ref[ $k ], $g[ $k ], '>' ) ) ) ) {
					$g[ $k ] = $ref[ $k ];
				}
			}
			$g['findings']      += count( $rows );
			$g['observed']       = max( $g['observed'], $ref['observed'] );
			if ( '' !== $ref['max'] && ( '' === $g['max'] || version_compare( $ref['max'], $g['max'], '>' ) ) ) {
				$g['max'] = $ref['max'];
			}
			if ( $ref['newer'] && $ref['newer_total'] > $g['newer_n'] ) {
				$g['newer']   = $ref['newer'][0];
				$g['newer_n'] = $ref['newer_total'];
			}
			if ( $ref['resolved'] && $ref['resolved_total'] > $g['resolved_n'] ) {
				$g['resolved']   = $ref['resolved'][0];
				$g['resolved_n'] = $ref['resolved_total'];
			}

			$groups[ $key ] = $g;
		}

		$fixable = array_filter( $groups, static fn( array $g ): bool => null !== $g['newer'] || null !== $g['resolved'] );
		$waiting = array_filter( $groups, static fn( array $g ): bool => ! ( null !== $g['newer'] || null !== $g['resolved'] ) && '' !== $g['max'] && '' !== $g['fixed'] );
		$unknown = array_diff_key( $groups, $fixable, $waiting );
		$count   = static fn( array $gs ): int => (int) array_sum( array_column( $gs, 'findings' ) );

		$doc->paragraph(
			array(
				VulnHub_Jira_Adf::strong(
					$fixable
						/* translators: %s: application. */
						? sprintf( __( 'Update %s: an update that fixes this is available', 'vulnhub' ), $app )
						/* translators: %s: application. */
						: ( $waiting ? sprintf( __( '%s: no update fixes this yet', 'vulnhub' ), $app ) : sprintf( __( 'Update %s', 'vulnhub' ), $app ) )
				),
			)
		);

		$sentences = array();

		if ( $fixable ) {
			$best = reset( $fixable );
			$m    = $best['newer'] ?? $best['resolved'];

			$sentences[] = null !== $best['newer']
				? sprintf(
					/* translators: 1: hostname, 2: component, 3: version, 4: application (with its version when known), 5: vulnerable version, 6: application, 7: target version, 8: findings. */
					_n( '%1$s already has %2$s %3$s inside %4$s (the vulnerable copy is %5$s), so updating %6$s to %7$s fixes %8$d finding on this ticket.', '%1$s already has %2$s %3$s inside %4$s (the vulnerable copies are %5$s), so updating %6$s to %7$s fixes %8$d findings on this ticket.', $count( $fixable ), 'vulnhub' ),
					$m['hostname'],
					$best['product'],
					$m['version'],
					'' !== (string) ( $m['app_version'] ?? '' ) ? $app . ' ' . $m['app_version'] : $app,
					$best['installed'],
					$app,
					// The lowest application version seen with the fixed copy, when
					// install folders name versions; otherwise the reference's.
					'' !== $best['fixed_from']
						/* translators: %s: application version. */
						? sprintf( __( '%s or later', 'vulnhub' ), $best['fixed_from'] )
						: __( 'the version on that machine', 'vulnhub' ),
					$count( $fixable )
				)
				: sprintf(
					/* translators: 1: hostname, 2: application, 3: date, 4: findings. */
					_n( 'On %1$s this was fixed on %3$s while %2$s stayed installed, so updating %2$s fixes %4$d finding on this ticket.', 'On %1$s this was fixed on %3$s while %2$s stayed installed, so updating %2$s fixes %4$d findings on this ticket.', $count( $fixable ), 'vulnhub' ),
					$m['hostname'],
					$app,
					$m['when'],
					$count( $fixable )
				);
		}

		/*
		 * One sentence per copy, not one per finding. A selection covering a
		 * product across the estate carries hundreds of copies of a bundled
		 * component, and naming them all is both unreadable and enough text on
		 * its own to reach the size Jira refuses. The copies are in the
		 * attachment; the paragraph says how many there are.
		 */
		$waiting_shown = array_slice( $waiting, 0, self::APP_FIX_SENTENCES, true );

		foreach ( $waiting_shown as $g ) {
			$sentences[] = sprintf(
				/* translators: 1: "Except:" or "", 2: component, 3: location inside the app, 4: version, 5: machines, 6: findings. */
				_n( '%1$s%2$s in %3$s is still %4$s on every machine it was seen on (%5$d)%7$s, so updating will not fix %6$d finding yet: remove that component if it is not used, or record an exception.', '%1$s%2$s in %3$s is still %4$s on every machine it was seen on (%5$d)%7$s, so updating will not fix %6$d findings yet: remove that component if it is not used, or record an exception.', $g['findings'], 'vulnhub' ),
				$fixable ? __( 'Except: ', 'vulnhub' ) : '',
				$g['product'],
				$g['tail'],
				$g['max'],
				max( 1, $g['observed'] ),
				$g['findings'],
				'' !== $g['newest_vulnerable'] && $g['newest_vulnerable'] === $g['newest']
					/* translators: 1: application, 2: application version. */
					? sprintf( __( ', including %1$s %2$s, the newest version seen', 'vulnhub' ), $app, $g['newest'] )
					: ''
			);
		}

		$waiting_rest = array_slice( $waiting, count( $waiting_shown ), null, true );

		if ( $waiting_rest ) {
			$sentences[] = sprintf(
				/* translators: 1: number of further copies, 2: findings on them. */
				_n( 'A further copy has no fixed build either, covering %2$d more finding on this ticket.', 'A further %1$d copies have no fixed build either, covering %2$d more findings on this ticket.', count( $waiting_rest ), 'vulnhub' ),
				count( $waiting_rest ),
				$count( $waiting_rest )
			);
		}

		if ( $unknown ) {
			/* translators: 1: findings, 2: application. */
			$sentences[] = sprintf( _n( 'For %1$d finding there is not enough evidence to tell whether updating %2$s fixes it; update, then re-check.', 'For %1$d findings there is not enough evidence to tell whether updating %2$s fixes them; update, then re-check.', $count( $unknown ), 'vulnhub' ), $count( $unknown ), $app );
		}

		$doc->paragraph( implode( ' ', $sentences ) );

		// Details: the reference machine, then where each copy sits.
		$details = array();

		foreach ( $fixable as $g ) {
			$m = $g['newer'] ?? $g['resolved'];
			/* translators: 1: hostname, 2: details, 3: component, 4: version or "fixed", 5: path, 6: date. */
			$details[] = sprintf(
				__( 'Reference machine: %1$s (%2$s) — %3$s %4$s at %5$s, %6$s', 'vulnhub' ),
				$m['hostname'],
				self::ref_details( $m ) . ( '' !== (string) ( $m['app_version'] ?? '' ) ? ' · ' . $app . ' ' . $m['app_version'] : '' ),
				$g['product'],
				null !== $g['newer'] ? $m['version'] : __( 'fixed', 'vulnhub' ),
				$m['path'],
				null !== $g['newer']
					/* translators: %s: date. */
					? sprintf( __( 'last scanned %s', 'vulnhub' ), $m['when'] )
					/* translators: %s: date. */
					: sprintf( __( 'resolved %s', 'vulnhub' ), $m['when'] )
			);
		}

		foreach ( $groups as $key => $g ) {
			$state = isset( $fixable[ $key ] ) ? __( 'fixed by updating', 'vulnhub' ) : ( isset( $waiting[ $key ] ) ? __( 'no fixed build yet', 'vulnhub' ) : __( 'not enough evidence', 'vulnhub' ) );

			foreach ( array_keys( $g['paths'] ) as $path ) {
				/* translators: 1: path, 2: component, 3: installed version, 4: fixed version, 5: state. */
				$details[] = sprintf( __( '%1$s — %2$s %3$s (fixed in %4$s) — %5$s', 'vulnhub' ), $path, $g['product'], '' !== $g['installed'] ? $g['installed'] : '?', '' !== $g['fixed'] ? $g['fixed'] : '?', $state );
			}
		}

		$doc->bullets( array_slice( $details, 0, 12 ) );
	}

	/**
	 * A reference machine in words: FQDN or IP, OS, type, site.
	 *
	 * @param array<string,string> $m App_Fix::references() entry.
	 */
	private static function ref_details( array $m ): string {
		return implode(
			' · ',
			array_filter(
				array(
					strtolower( $m['fqdn'] ) !== strtolower( $m['hostname'] ) ? $m['fqdn'] : '',
					$m['ipv4'],
					$m['os'],
					$m['type'],
					$m['location'],
				)
			)
		);
	}

	/**
	 * The product(s) a set of findings is about, by what someone would update:
	 * the application that ships a bundled component, otherwise the product.
	 *
	 * @param array<int,array<string,mixed>> $rows Finding rows.
	 */
	private function summary_products( array $rows ): string {
		$counts = array();

		foreach ( $rows as $row ) {
			// A bundled component is named by the application that ships it; an
			// OS package by its source package ("kernel", "openssl"), which is
			// what gets updated, rather than the scanner's generic family.
			$name = \VulnHub\Core\Repo::is_component( $row )
				|| ( 'os_package' === (string) ( $row['product_kind'] ?? '' ) && '' !== (string) ( $row['bundle_app'] ?? '' ) )
				? (string) ( $row['bundle_app'] ?? '' )
				: (string) ( $row['product'] ?? '' );
			$name = trim( $name );

			if ( '' !== $name ) {
				$counts[ $name ] = ( $counts[ $name ] ?? 0 ) + 1;
			}
		}

		if ( ! $counts ) {
			return '';
		}

		arsort( $counts );
		$names = array_keys( $counts );

		return match ( count( $names ) ) {
			1       => $names[0],
			/* translators: 1: product, 2: product. */
			2       => sprintf( __( '%1$s and %2$s', 'vulnhub' ), $names[0], $names[1] ),
			/* translators: 1: product, 2: number of other products. */
			default => sprintf( __( '%1$s and %2$d other products', 'vulnhub' ), $names[0], count( $names ) - 1 ),
		};
	}

	/**
	 * What kind of vulnerability most of the findings are.
	 *
	 * @param array<int,array<string,mixed>> $rows Finding rows.
	 */
	private function summary_kind( array $rows ): string {
		$seol   = class_exists( '\VulnHub\Core\Eol' ) ? array_flip( \VulnHub\Core\Eol::seol_vuln_ids() ) : array();
		$counts = array();

		foreach ( $rows as $row ) {
			$kind = (string) ( $row['product_kind'] ?? '' );
			$key  = match ( true ) {
				isset( $seol[ (int) ( $row['vuln_id'] ?? 0 ) ] ) => 'unsupported',
				'os_update' === $kind                            => 'os_update',
				'os_package' === $kind                           => 'os_package',
				'library' === $kind                              => \VulnHub\Core\Repo::is_component( $row ) ? 'bundled_library' : 'library',
				'application' === $kind                          => 'application',
				default                                          => 'other',
			};

			$counts[ $key ] = ( $counts[ $key ] ?? 0 ) + 1;
		}

		arsort( $counts );

		return array(
			'unsupported'     => __( 'unsupported software', 'vulnhub' ),
			'os_update'       => __( 'OS security update', 'vulnhub' ),
			'os_package'      => __( 'OS package update', 'vulnhub' ),
			'bundled_library' => __( 'bundled library vulnerability', 'vulnhub' ),
			'library'         => __( 'library vulnerability', 'vulnhub' ),
			'application'     => __( 'application vulnerability', 'vulnhub' ),
			'other'           => __( 'vulnerability', 'vulnhub' ),
		)[ (string) array_key_first( $counts ) ] ?? '';
	}

	/**
	 * Platform and asset type: "Windows workstations", "Linux servers",
	 * "Windows servers and workstations", "Windows and Linux servers".
	 *
	 * @param array<int,array<string,mixed>> $rows Finding rows.
	 */
	private function summary_platform( array $rows ): string {
		$platforms = array();
		$types     = array();
		$assets    = array();

		foreach ( $rows as $row ) {
			$aid = (int) ( $row['asset_id'] ?? 0 );

			if ( isset( $assets[ $aid ] ) ) {
				continue;
			}
			$assets[ $aid ] = true;

			$platform = \VulnHub\Core\Os::platform( (string) ( $row['operating_system'] ?? '' ) );
			if ( 'other' !== $platform ) {
				$platforms[ $platform ] = true;
			}

			$type = (string) ( $row['asset_type'] ?? '' );
			if ( '' !== $type && 'unknown' !== $type ) {
				$types[ $type ] = true;
			}
		}

		$many  = count( $assets ) > 1;
		$plat  = array_map( array( '\VulnHub\Core\Os', 'platform_label' ), array_keys( $platforms ) );
		$nouns = array(
			'workstation' => array( __( 'workstation', 'vulnhub' ), __( 'workstations', 'vulnhub' ) ),
			'server'      => array( __( 'server', 'vulnhub' ), __( 'servers', 'vulnhub' ) ),
		);
		$kinds = array();

		foreach ( array_keys( $types ) as $type ) {
			$kinds[] = isset( $nouns[ $type ] )
				? $nouns[ $type ][ $many ? 1 : 0 ]
				: strtolower( (string) ( vh_asset_types()[ $type ] ?? $type ) ) . ( $many ? 's' : '' );
		}
		sort( $kinds );

		$plat_text = match ( count( $plat ) ) {
			0       => '',
			1       => $plat[0],
			2       => sprintf( /* translators: 1: platform, 2: platform. */ __( '%1$s and %2$s', 'vulnhub' ), $plat[0], $plat[1] ),
			default => __( 'mixed-platform', 'vulnhub' ),
		};
		$kind_text = match ( count( $kinds ) ) {
			0       => $many ? __( 'machines', 'vulnhub' ) : __( 'machine', 'vulnhub' ),
			1       => $kinds[0],
			2       => sprintf( /* translators: 1: asset type, 2: asset type. */ __( '%1$s and %2$s', 'vulnhub' ), $kinds[0], $kinds[1] ),
			default => __( 'mixed machine types', 'vulnhub' ),
		};

		if ( '' === $plat_text && ! $kinds ) {
			return '';
		}

		// "Windows servers and workstations": the platform reads once.
		return trim( $plat_text . ' ' . $kind_text );
	}

	/**
	 * Jira labels for the issue. Labels may not contain spaces.
	 *
	 * @param array<int,array<string,mixed>> $rows     Finding rows.
	 * @param string                         $severity Highest severity.
	 * @return string[]
	 */
	private function labels( array $rows, string $severity ): array {
		/*
		 * Neutral labels: useful for filtering a queue, and nothing in them
		 * names the tool that raised the ticket.
		 */
		$labels = array( $severity );

		$type = sanitize_key( (string) $rows[0]['asset_type'] );

		if ( '' !== $type ) {
			$labels[] = $type;
		}

		foreach ( $rows as $row ) {
			if ( ! empty( $row['exploit_available'] ) ) {
				$labels[] = 'exploit-available';
				break;
			}
		}

		return array_values( array_unique( $labels ) );
	}

	/**
	 * Build the Atlassian Document Format description.
	 *
	 * Jira Cloud v3 rejects a plain string here — the field is ADF, so the
	 * document is assembled node by node.
	 *
	 * @param array<int,array<string,mixed>> $rows     Finding rows.
	 * @param string                         $grouping Grouping strategy.
	 * @param string                         $severity Highest severity.
	 * @param array<string,mixed>            $team     Owning team row.
	 * @param array<string,mixed>            $options  Caller options.
	 * @return array<string,mixed> ADF document.
	 */
	private function description( array $rows, string $grouping, string $severity, array $team, array $options ): array {
		$doc      = VulnHub_Jira_Adf::doc();
		$assets   = $this->distinct( $rows, 'asset_id' );
		$vulns    = $this->distinct( $rows, 'vuln_id' );
		$custom   = '' !== (string) ( $options['due_date'] ?? '' );
		$due      = $custom ? (string) $options['due_date'] : vh_due_in_days( vh_sla_days( $severity ) );

		/* --- 1. What this is and why -------------------------------- */

		$doc->paragraph(
			array(
				VulnHub_Jira_Adf::text(
					sprintf(
						/* translators: 1: findings, 2: severity, 3: assets, 4: vulnerabilities, 5: grouping label. */
						__( 'This ticket covers %1$d finding(s) at %2$s severity across %3$d asset(s) and %4$d distinct vulnerability definition(s). Findings were grouped %5$s.', 'vulnhub' ),
						count( $rows ),
						strtolower( vh_severity_label( $severity ) ),
						count( $assets ),
						count( $vulns ),
						'per_selection' === $grouping
							? __( 'as one ticket for the selection', 'vulnhub' )
							: strtolower( (string) ( VulnHub_Jira_Connector::grouping_options()[ $grouping ] ?? $grouping ) )
					)
				),
			)
		);

		if ( ! empty( $options['note'] ) ) {
			$doc->paragraph( (string) $options['note'] );
		}

		/* --- 2. Affected assets ------------------------------------- */

		/*
		 * With a CSV attached, the assets are in the file, so the description
		 * says where they are rather than repeating them: the list made the
		 * description long, and every host in it was already one click away.
		 * Without an attachment the list is the only place they appear.
		 */
		if ( ! empty( $options['attachment'] ) ) {
			$doc->paragraph(
				sprintf(
					/* translators: 1: number of assets, 2: attachment file name. */
					_n( 'The affected asset and every finding are listed in the attached %2$s.', 'All %1$d affected assets and every finding are listed in the attached %2$s.', count( $assets ), 'vulnhub' ),
					count( $assets ),
					(string) $options['attachment']
				)
			);
		} else {
			$doc->heading( __( 'Affected assets', 'vulnhub' ) );

			$seen  = array();
			$items = array();

			foreach ( $rows as $row ) {
				$asset_id = (int) $row['asset_id'];

				if ( isset( $seen[ $asset_id ] ) ) {
					continue;
				}
				$seen[ $asset_id ] = true;

				$items[] = $this->asset_line( $row );
			}

			$doc->bullets( $items );
		}

		/* --- 3. Vulnerability detail -------------------------------- */

		$doc->heading( __( 'Vulnerability detail', 'vulnhub' ) );

		$seen_vulns = array();

		foreach ( $rows as $row ) {
			$vuln_id = (int) $row['vuln_id'];

			if ( isset( $seen_vulns[ $vuln_id ] ) ) {
				continue;
			}
			$seen_vulns[ $vuln_id ] = true;

			$doc->paragraph(
				array(
					VulnHub_Jira_Adf::strong( vh_trim( (string) $row['vuln_title'], 200 ) ),
				)
			);

			$doc->bullets( $this->vuln_lines( $row, $rows, ! empty( $options['attachment'] ) ) );

			$description = vh_trim( (string) ( $row['vuln_description'] ?? '' ), 900 );

			if ( '' !== $description ) {
				$doc->paragraph( $description );
			}

			if ( count( $seen_vulns ) >= self::DESCRIPTION_VULNS || $doc->bytes() >= self::DESCRIPTION_DETAIL_BYTES ) {
				$doc->paragraph(
					sprintf(
						/* translators: %d: number of vulnerabilities not listed. */
						__( '… and %d further vulnerability definition(s); every finding is listed in the attachment, when one is attached.', 'vulnhub' ),
						max( 0, count( $vulns ) - count( $seen_vulns ) )
					)
				);
				break;
			}
		}

		/* --- 4. Vendor remediation ---------------------------------- */

		$doc->heading( __( 'Vendor remediation', 'vulnhub' ) );

		/*
		 * Components shipped inside other applications: the solution text
		 * below is the component's own release ("Upgrade libcurl to 8.4.0"),
		 * which nobody can install into someone else's application. Say which
		 * applications carry them and, per copy, whether a fixed build has been
		 * seen -- with one machine as evidence the service desk can look at.
		 */
		$bundled = array(); // app => [ product|path key => rows ]

		foreach ( $rows as $row ) {
			if ( 'app' !== \VulnHub\Core\Repo::fix_route( $row ) ) {
				continue;
			}

			$copy = \VulnHub\Core\App_Fix::copies( (string) ( $row['output'] ?? '' ) )[0] ?? null;
			$key  = (string) $row['product_slug'] . '|' . ( $copy ? $copy['key'] : '' );

			$bundled[ (string) $row['bundle_app'] ][ $key ][] = $row;
		}

		if ( $bundled ) {
			$described = 0;

			foreach ( array_slice( $bundled, 0, self::DESCRIPTION_APPS, true ) as $app => $copies ) {
				if ( $doc->bytes() >= self::DESCRIPTION_BYTES ) {
					break;
				}

				$this->describe_app_fix( $doc, (string) $app, $copies );
				++$described;
			}

			if ( count( $bundled ) > $described ) {
				$doc->paragraph(
					sprintf(
						/* translators: %d: applications not described here. */
						_n(
							'One further application ships an affected component; its findings are in the attachment.',
							'%d further applications ship affected components; their findings are in the attachment.',
							count( $bundled ) - $described,
							'vulnhub'
						),
						count( $bundled ) - $described
					)
				);
			}
		}

		$solutions = array();

		foreach ( $rows as $row ) {
			// A component's own release ("Upgrade libcurl to 8.4.0") cannot be
			// applied inside another application; the instruction above is the
			// remediation for those, so its text would only contradict it.
			if ( 'app' === \VulnHub\Core\Repo::fix_route( $row ) ) {
				continue;
			}

			$solution = trim( (string) ( $row['solution'] ?? '' ) );

			if ( '' === $solution ) {
				continue;
			}

			$solutions[ md5( $solution ) ] = $solution;
		}

		if ( $solutions ) {
			foreach ( array_slice( array_values( $solutions ), 0, self::DESCRIPTION_SOLUTIONS ) as $solution ) {
				if ( $doc->bytes() >= self::DESCRIPTION_BYTES ) {
					break;
				}

				// A scanner's remediation text is occasionally an essay. The
				// instruction is at the top of it, so a bounded quote says the
				// same thing as the whole of it.
				$doc->paragraph( vh_trim( $solution, 2000 ) );
			}
		} elseif ( ! $bundled ) {
			$doc->paragraph( __( 'The vulnerability source published no remediation text for these findings. Apply the vendor patch or mitigation referenced by the CVEs above.', 'vulnhub' ) );
		}

		$references = $this->references( $rows );

		if ( $references ) {
			$doc->paragraph( __( 'References:', 'vulnhub' ) );
			$doc->bullets(
				array_map(
					static fn( string $url ): array => array( VulnHub_Jira_Adf::link( $url, $url ) ),
					$references
				)
			);
		}

		/* --- 5. SLA -------------------------------------------------- */

		$doc->heading( __( 'Remediation SLA', 'vulnhub' ) );
		$doc->paragraph(
			$custom
				/* translators: %s: due date. */
				? sprintf( __( 'Remediation is due by %s.', 'vulnhub' ), $due )
				: sprintf(
					/* translators: 1: due date, 2: number of days, 3: severity. */
					__( 'Remediation is due by %1$s: %2$d days for %3$s severity.', 'vulnhub' ),
					$due,
					vh_sla_days( $severity ),
					strtolower( vh_severity_label( $severity ) )
				)
		);

		/* --- 6. After closing ---------------------------------------- */

		$doc->rule();

		// A link into VulnHub only where the operator wants one: the address
		// it is built from is whatever host the raise came in on, which for a
		// portal opened on localhost is a link nobody else can follow.
		if ( vulnhub_jira_connector() && vulnhub_jira_connector()->links_back() ) {
			$doc->heading( __( 'Asset record', 'vulnhub' ) );

			$asset_id  = (int) $rows[0]['asset_id'];
			$asset_url = vh_admin_url( 'vulnhub-assets', array( 'asset' => $asset_id ) );

			$doc->paragraph(
				array(
					VulnHub_Jira_Adf::text( __( 'Open the asset record: ', 'vulnhub' ) ),
					VulnHub_Jira_Adf::link( (string) $rows[0]['hostname'], $asset_url ),
				)
			);
		} else {
			$doc->heading( __( 'After this ticket is closed', 'vulnhub' ) );
		}

		/*
		 * Say what will really happen after closure. Promising an automatic
		 * reopen on a site where reopening is switched off would teach the
		 * service desk to expect something that never comes.
		 */
		$connector = vulnhub_jira_connector();
		$reopens   = $connector && $connector->reopens();
		$comments  = $connector && $connector->comments_on_verify();

		$doc->paragraph(
			array(
				VulnHub_Jira_Adf::text(
					$reopens
						? __( 'These findings are re-checked against the vulnerability scanner after this ticket is closed. If a vulnerability is still detected the ticket is reopened automatically, so please only close it once the remediation is actually deployed.', 'vulnhub' )
						: ( $comments
							? __( 'These findings are re-checked against the vulnerability scanner after this ticket is closed, and the result is added as a comment. Please only close it once the remediation is actually deployed.', 'vulnhub' )
							: __( 'These findings are re-checked against the vulnerability scanner after this ticket is closed. Please only close it once the remediation is actually deployed.', 'vulnhub' ) )
				),
			)
		);

		return $doc->to_array();
	}

	/**
	 * One bullet describing an asset.
	 *
	 * @param array<string,mixed> $row Finding row.
	 * @return array<int,array<string,mixed>> Inline nodes.
	 */
	private function asset_line( array $row ): array {
		$bits = array();

		$bits[] = VulnHub_Jira_Adf::strong( (string) $row['hostname'] );

		$detail = array();

		if ( ! empty( $row['fqdn'] ) && strtolower( (string) $row['fqdn'] ) !== strtolower( (string) $row['hostname'] ) ) {
			$detail[] = (string) $row['fqdn'];
		}
		if ( ! empty( $row['ipv4'] ) ) {
			$detail[] = (string) $row['ipv4'];
		}

		$os = trim( (string) $row['operating_system'] . ' ' . (string) $row['os_version'] );

		if ( '' !== $os ) {
			$detail[] = $os;
		}

		$detail[] = sprintf(
			/* translators: 1: asset type label, 2: criticality. */
			__( '%1$s, %2$s criticality', 'vulnhub' ),
			(string) ( vh_asset_types()[ (string) $row['asset_type'] ] ?? $row['asset_type'] ),
			(string) $row['criticality']
		);

		if ( ! empty( $row['environment'] ) ) {
			$detail[] = (string) $row['environment'];
		}
		if ( ! empty( $row['location_name'] ) ) {
			$detail[] = (string) $row['location_name'];
		}

		$owner = trim( (string) ( $row['owner_name'] ?? '' ) );
		$team  = trim( (string) ( $row['team_name'] ?? '' ) );

		/*
		 * The owner's name, not their address. Everyone who can open the
		 * ticket in Jira sees the description; a name is enough for an agent
		 * to find the person in the directory, and keeps a list of hundreds
		 * of staff email addresses out of the service desk.
		 */
		if ( '' !== $owner ) {
			$detail[] = sprintf(
				/* translators: %s: owner name. */
				__( 'owner %s', 'vulnhub' ),
				$owner
			);
		}
		if ( '' !== $team ) {
			$detail[] = sprintf(
				/* translators: %s: team name. */
				__( 'team %s', 'vulnhub' ),
				$team
			);
		}
		if ( '' === $owner && '' === $team ) {
			$detail[] = __( 'no owner resolved yet', 'vulnhub' );
		}

		$bits[] = VulnHub_Jira_Adf::text( ' — ' . implode( ' · ', array_filter( $detail ) ) );

		return array_values( array_filter( $bits ) );
	}

	/**
	 * Bullets describing one vulnerability definition.
	 *
	 * @param array<string,mixed>            $row  The representative finding row.
	 * @param array<int,array<string,mixed>> $rows All rows in the group.
	 * @return array<int,string>
	 */
	private function vuln_lines( array $row, array $rows, bool $attached = false ): array {
		$lines = array();

		$lines[] = sprintf(
			/* translators: 1: source, 2: plugin id, 3: family. */
			__( 'Plugin: %1$s %2$s%3$s', 'vulnhub' ),
			ucfirst( (string) ( $row['vuln_source'] ?? 'tenable' ) ),
			(string) $row['plugin_id'],
			! empty( $row['family'] ) ? ' — ' . (string) $row['family'] : ''
		);

		$cves = array_values( array_filter( array_map( 'strval', vh_json( (string) ( $row['cve_json'] ?? '' ) ) ) ) );

		$lines[] = $cves
			? sprintf(
				/* translators: %s: comma separated CVE list. */
				__( 'CVE: %s', 'vulnhub' ),
				implode( ', ', array_slice( $cves, 0, 12 ) )
			)
			: __( 'CVE: none assigned', 'vulnhub' );

		$scores = array();

		if ( (float) $row['cvss3_base'] > 0 ) {
			$scores[] = sprintf( 'CVSSv3 %.1f', (float) $row['cvss3_base'] );
		}
		if ( (float) ( $row['cvss2_base'] ?? 0 ) > 0 ) {
			$scores[] = sprintf( 'CVSSv2 %.1f', (float) $row['cvss2_base'] );
		}
		if ( (float) $row['vpr_score'] > 0 ) {
			$scores[] = sprintf( 'VPR %.1f', (float) $row['vpr_score'] );
		}

		$lines[] = $scores
			? sprintf(
				/* translators: %s: score list. */
				__( 'Scoring: %s', 'vulnhub' ),
				implode( ' · ', $scores )
			)
			: __( 'Scoring: not published', 'vulnhub' );

		$lines[] = ! empty( $row['exploit_available'] )
			? __( 'Exploit availability: a public exploit exists — treat this as actively exploitable.', 'vulnhub' )
			: __( 'Exploit availability: no public exploit recorded.', 'vulnhub' );

		if ( ! empty( $row['patch_publication_date'] ) ) {
			$lines[] = sprintf(
				/* translators: %s: date. */
				__( 'Patch published: %s', 'vulnhub' ),
				(string) $row['patch_publication_date']
			);
		}

		// Where this definition actually fires inside the group.
		$where = array();

		foreach ( $rows as $candidate ) {
			if ( (int) $candidate['vuln_id'] !== (int) $row['vuln_id'] ) {
				continue;
			}

			$port = (int) $candidate['port'];

			$where[] = $port > 0
				? sprintf( '%s:%d/%s', (string) $candidate['hostname'], $port, (string) $candidate['protocol'] )
				: (string) $candidate['hostname'];
		}

		$where = array_values( array_unique( $where ) );

		// With the file attached, a count: the hosts are in the file.
		$lines[] = $attached
			? sprintf(
				/* translators: %d: number of hosts. */
				_n( 'Detected on %d asset (see the attachment).', 'Detected on %d assets (see the attachment).', count( array_unique( array_map( static fn( string $w ): string => explode( ':', $w )[0], $where ) ) ), 'vulnhub' ),
				count( array_unique( array_map( static fn( string $w ): string => explode( ':', $w )[0], $where ) ) )
			)
			: sprintf(
				/* translators: %s: host:port list. */
				__( 'Detected on: %s', 'vulnhub' ),
				implode( ', ', array_slice( $where, 0, 20 ) )
			);

		$lines[] = sprintf(
			/* translators: 1: first seen date, 2: last seen date. */
			__( 'First found %1$s, last confirmed %2$s.', 'vulnhub' ),
			vh_date( (string) $row['first_found'], 'j M Y' ),
			vh_date( (string) $row['last_found'], 'j M Y' )
		);

		return $lines;
	}

	/**
	 * A one-line description of a finding, for comments.
	 *
	 * @param array<string,mixed> $row Finding row.
	 */
	public function finding_line( array $row ): string {
		return sprintf(
			/* translators: 1: severity, 2: vulnerability title, 3: hostname, 4: plugin id. */
			__( '%1$s — %2$s on %3$s (plugin %4$s)', 'vulnhub' ),
			vh_severity_label( (string) $row['severity'] ),
			vh_trim( (string) $row['vuln_title'], 120 ),
			(string) $row['hostname'],
			(string) $row['plugin_id']
		);
	}

	/**
	 * External references across the group, de-duplicated and capped.
	 *
	 * @param array<int,array<string,mixed>> $rows Finding rows.
	 * @return string[]
	 */
	private function references( array $rows ): array {
		$urls = array();

		foreach ( $rows as $row ) {
			foreach ( preg_split( '/\R+/', (string) ( $row['see_also'] ?? '' ) ) ?: array() as $line ) {
				$line = trim( (string) $line );

				if ( '' !== $line && preg_match( '#^https?://#i', $line ) ) {
					$urls[ $line ] = true;
				}
			}
		}

		return array_slice( array_keys( $urls ), 0, 8 );
	}

	/* =================================================================
	 * Routing — which desk, which request type, which team
	 * ============================================================== */

	/**
	 * Decide where one group of findings is raised, and as what.
	 *
	 * Precedence, most specific first. The team row wins wherever it has an
	 * opinion; the connector defaults are a fallback, never an override:
	 *
	 *   project      teams.jira_project_key
	 *                → the default service desk's peer project
	 *                → the connector's default project key
	 *   issue type   teams.jira_issue_type
	 *                → the resolved request type's issueTypeId
	 *                → the connector's default issue type
	 *   request type this team's saved request type
	 *                → the default request type, but only when the target
	 *                  project really is that default desk
	 *   team value   this team's saved Team value
	 *                → the connector's default team
	 *
	 * The directory is consulted from cache; a cold cache costs one discovery
	 * pass and is then good for an hour.
	 *
	 * @param VulnHub_Jira_Connector $connector Connector.
	 * @param array<string,mixed>    $team      Owning team row (may be empty).
	 * @return array{project:string,issue_type:string,issue_type_ref:array<string,string>,service_desk:string,request_type:string,request_type_name:string,team_field:string,team_value:string,team_write:mixed,source:string,audit:array<string,mixed>}
	 */
	public function routing( VulnHub_Jira_Connector $connector, array $team ): array {
		$team_id   = (int) ( $team['id'] ?? 0 );
		$override  = $team_id ? $connector->team_routing_for( $team_id ) : array(
			'service_desk' => '',
			'request_type' => '',
			'team_value'   => '',
		);
		$directory = $this->directory ??= new VulnHub_Jira_Directory( $connector );

		$team_project = strtoupper( trim( (string) ( $team['jira_project_key'] ?? '' ) ) );
		$team_type    = trim( (string) ( $team['jira_issue_type'] ?? '' ) );

		$default_desk_id = $connector->default_service_desk();
		$default_desk    = '' !== $default_desk_id ? $directory->service_desk( $default_desk_id ) : null;

		$source  = 'team';
		$project = $team_project;

		if ( '' === $project ) {
			$source  = $default_desk ? 'default-desk' : 'default-project';
			$project = $default_desk
				? strtoupper( (string) $default_desk['project_key'] )
				: $connector->default_project();
		}

		if ( '' === $project ) {
			$project = $connector->default_project();
		}

		// Which desk, if any, does the chosen project actually belong to?
		$desk = $directory->desk_for_project( $project );

		if ( ! $desk && '' !== trim( (string) $override['service_desk'] ) ) {
			$desk = $directory->service_desk( (string) $override['service_desk'] );
		}

		$desk_id      = $desk ? (string) $desk['id'] : '';
		$request_type = null;

		if ( '' !== trim( (string) $override['request_type'] ) ) {
			$request_type = $directory->request_type( (string) $override['request_type'], $desk_id );
		}

		// The default request type only applies inside the default desk —
		// a request type id means nothing in a desk it does not belong to.
		if ( ! $request_type && '' !== $desk_id && $desk_id === $default_desk_id ) {
			$request_type = $directory->request_type( $connector->default_request_type(), $desk_id );
		}

		$issue_type     = $team_type;
		$issue_type_ref = '' !== $team_type ? array( 'name' => $team_type ) : array();

		if ( ! $issue_type_ref && $request_type && '' !== (string) $request_type['issue_type_id'] ) {
			$issue_type     = (string) $request_type['name'];
			$issue_type_ref = array( 'id' => (string) $request_type['issue_type_id'] );
		}

		if ( ! $issue_type_ref ) {
			$issue_type     = $connector->default_issue_type();
			$issue_type_ref = array( 'name' => $issue_type );
		}

		$field      = $directory->team_field();
		$team_value = trim( (string) $override['team_value'] );

		if ( '' === $team_value ) {
			$team_value = $connector->default_team();
		}

		return array(
			'project'           => $project,
			'issue_type'        => $issue_type,
			'issue_type_ref'    => $issue_type_ref,
			'service_desk'      => $desk_id,
			'request_type'      => $request_type ? (string) $request_type['id'] : '',
			'request_type_name' => $request_type ? (string) $request_type['name'] : '',
			'team_field'        => (string) ( $field['id'] ?? '' ),
			'team_value'        => $team_value,
			'team_write'        => $this->team_field_value( $field, $team_value ),
			'source'            => $source,
			'audit'             => array(
				'source'       => $source,
				'project'      => $project,
				'issue_type'   => $issue_type,
				'service_desk' => $desk_id,
				'request_type' => $request_type ? (string) $request_type['id'] : '',
				'team_field'   => (string) ( $field['id'] ?? '' ),
				'team_value'   => $team_value,
				'team_id'      => $team_id,
			),
		);
	}

	/**
	 * The value shape the Team custom field expects.
	 *
	 * The Atlassian Teams field takes a bare team id string
	 * (`"customfield_10001": "36885b3c-…"`). An option-backed select called
	 * Team takes an object — `{"id": …}` when we know the option id, otherwise
	 * `{"value": …}`.
	 *
	 * @param array<string,mixed> $field Discovered Team field.
	 * @param string              $value Configured team value.
	 * @return mixed
	 */
	private function team_field_value( array $field, string $value ) {
		if ( '' === $value ) {
			return '';
		}

		if ( 'value' !== (string) ( $field['write'] ?? '' ) ) {
			return $value;
		}

		foreach ( (array) ( $field['options'] ?? array() ) as $option ) {
			if ( is_array( $option ) && (string) ( $option['value'] ?? '' ) === $value && '' !== (string) ( $option['id'] ?? '' ) ) {
				return array( 'id' => (string) $option['id'] );
			}
		}

		return array( 'value' => $value );
	}

	/**
	 * Did Jira reject this specific field by name?
	 *
	 * Jira's error envelope puts field-level problems in `errors` keyed by
	 * field id, which is precise enough to retry on.
	 *
	 * @param \VulnHub\Core\Http_Response $response Failed response.
	 * @param string                       $field    Field id.
	 */
	private function rejected_field( \VulnHub\Core\Http_Response $response, string $field ): bool {
		if ( '' === $field || 400 !== $response->status ) {
			return false;
		}

		$errors = (array) ( $response->data()['errors'] ?? array() );

		return array_key_exists( $field, $errors );
	}

	/* =================================================================
	 * Small helpers
	 * ============================================================== */

	/**
	 * Load findings joined to their asset, vulnerability, owner, team and site.
	 *
	 * @param array<int,int> $ids Finding ids.
	 * @return array<int,array<string,mixed>>
	 */
	public function load_findings( array $ids ): array {
		global $wpdb;

		$ids = array_values( array_unique( array_filter( array_map( 'intval', $ids ) ) ) );

		if ( ! $ids ) {
			return array();
		}

		$placeholders = implode( ', ', array_fill( 0, count( $ids ), '%d' ) );

		$sql = 'SELECT
				f.id, f.severity, f.state, f.port, f.protocol, f.service, f.risk_score,
				f.first_found, f.last_found, f.due_at, f.ticket_id, f.exception_id,
				f.bundle_app, f.bundle_app_slug, f.app_fix, f.output,
				a.id AS asset_id, a.hostname, a.fqdn, a.ipv4, a.asset_type,
				a.operating_system, a.os_version, a.criticality, a.environment,
				a.business_service, a.team_id, a.owner_person_id, a.location_id, a.tags_json,
				v.id AS vuln_id, v.source AS vuln_source, v.plugin_id, v.title AS vuln_title,
				v.family, v.cve_json, v.cvss2_base, v.cvss3_base, v.vpr_score,
				v.exploit_available, v.description AS vuln_description, v.solution,
				v.see_also, v.patch_publication_date, v.product, v.product_slug, v.product_kind, v.component_class,
				p.display_name AS owner_name, p.upn AS owner_upn, p.email AS owner_email,
				p.job_title AS owner_title, p.department AS owner_department, p.manager_upn,
				t.id AS team_row_id, t.name AS team_name, t.manager_email,
				t.jira_project_key, t.jira_issue_type, t.jira_default_assignee,
				t.sla_critical_days, t.sla_high_days, t.sla_medium_days, t.sla_low_days,
				l.name AS location_name
			FROM ' . vh_table( 'findings' ) . ' f
			INNER JOIN ' . vh_table( 'assets' ) . ' a ON a.id = f.asset_id
			INNER JOIN ' . vh_table( 'vulns' ) . ' v ON v.id = f.vuln_id
			LEFT JOIN ' . vh_table( 'people' ) . ' p ON p.id = a.owner_person_id
			LEFT JOIN ' . vh_table( 'teams' ) . ' t ON t.id = a.team_id
			LEFT JOIN ' . vh_table( 'locations' ) . " l ON l.id = a.location_id
			WHERE f.id IN ({$placeholders})
			ORDER BY f.risk_score DESC, f.id ASC"; // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		return (array) $wpdb->get_results(
			$wpdb->prepare( $sql, ...$ids ), // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			ARRAY_A
		);
	}

	/**
	 * Distinct values of a column across rows.
	 *
	 * @param array<int,array<string,mixed>> $rows   Rows.
	 * @param string                         $column Column.
	 * @return array<int,string>
	 */
	private function distinct( array $rows, string $column ): array {
		return array_values( array_unique( array_map( static fn( array $r ): string => (string) ( $r[ $column ] ?? '' ), $rows ) ) );
	}

	/**
	 * The highest severity present in a group.
	 *
	 * @param array<int,array<string,mixed>> $rows Rows.
	 */
	private function top_severity( array $rows ): string {
		$ladder = vh_severities();
		$best   = 'info';
		$rank   = -1;

		foreach ( $rows as $row ) {
			$severity = (string) $row['severity'];
			$weight   = (int) ( $ladder[ $severity ]['id'] ?? 0 );

			if ( $weight > $rank ) {
				$rank = $weight;
				$best = isset( $ladder[ $severity ] ) ? $severity : 'info';
			}
		}

		return $best;
	}

	/**
	 * The team that owns most of the assets in a group.
	 *
	 * @param array<int,array<string,mixed>> $rows Rows.
	 * @return array<string,mixed>
	 */
	private function dominant_team( array $rows ): array {
		$tally = array();

		foreach ( $rows as $row ) {
			$team_id = (int) $row['team_id'];

			if ( $team_id ) {
				$tally[ $team_id ] = ( $tally[ $team_id ] ?? 0 ) + 1;
			}
		}

		if ( ! $tally ) {
			return array();
		}

		arsort( $tally );

		$team_id = (int) array_key_first( $tally );

		return (array) ( \VulnHub\Core\Repo::team( $team_id ) ?? array() );
	}

	/**
	 * The asset id, but only when the whole group is one asset.
	 *
	 * @param array<int,array<string,mixed>> $rows Rows.
	 */
	private function single_asset_id( array $rows ): int {
		$ids = $this->distinct( $rows, 'asset_id' );

		return 1 === count( $ids ) ? (int) $ids[0] : 0;
	}

	/**
	 * Turn a configured assignee (account id or email) into an account id.
	 *
	 * Jira has not accepted usernames since the GDPR API changes, so an email
	 * has to be resolved through GET /rest/api/3/user/search first.
	 *
	 * @param VulnHub_Jira_Connector $connector Connector.
	 * @param string                 $assignee  Configured value.
	 */
	private function resolve_assignee( VulnHub_Jira_Connector $connector, string $assignee ): string {
		$assignee = trim( $assignee );

		if ( '' === $assignee ) {
			return '';
		}
		if ( isset( $this->assignee_cache[ $assignee ] ) ) {
			return $this->assignee_cache[ $assignee ];
		}

		// Not an email? Treat it as an account id and use it as given.
		if ( ! str_contains( $assignee, '@' ) ) {
			$this->assignee_cache[ $assignee ] = $assignee;

			return $assignee;
		}

		$response = $connector->client()->user_search( $assignee );
		$account  = '';

		if ( $response->ok() ) {
			foreach ( $response->data() as $user ) {
				if ( is_array( $user ) && ! empty( $user['accountId'] ) ) {
					$account = (string) $user['accountId'];
					break;
				}
			}
		}

		if ( '' === $account ) {
			$connector->log( sprintf( 'Could not resolve "%s" to a Jira account id; the issue will be left unassigned.', $assignee ) );
		}

		$this->assignee_cache[ $assignee ] = $account;

		return $account;
	}
}

