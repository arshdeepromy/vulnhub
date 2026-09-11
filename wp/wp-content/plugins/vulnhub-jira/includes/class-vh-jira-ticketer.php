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
	 * "select all" cannot try to describe ten thousand rows inside one issue.
	 */
	private const MAX_FINDINGS = 500;

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
		add_filter( 'vulnhub_refresh_ticket', array( $this, 'refresh_ticket' ), 10, 2 );
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

		$options = array( 'created_via' => 'manual' );

		if ( $request instanceof WP_REST_Request ) {
			$grouping = (string) $request->get_param( 'grouping' );

			if ( '' !== $grouping ) {
				$options['grouping'] = $grouping;
			}

			$options['created_via'] = 'api';
		}

		return $this->raise( array_map( 'intval', $finding_ids ), $options );
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

		if ( count( $finding_ids ) > self::MAX_FINDINGS ) {
			$finding_ids = array_slice( $finding_ids, 0, self::MAX_FINDINGS );
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
		$existing = $this->open_ticket_for( $group_key );

		if ( $existing ) {
			return $this->extend_ticket( $connector, $existing, $rows, $grouping );
		}

		return $this->create_group_ticket( $connector, $group_key, $rows, $grouping, $options );
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
						VulnHub_Jira_Adf::strong( __( 'VulnHub added findings to this ticket.', 'vulnhub' ) ),
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
		$team     = $this->dominant_team( $rows );
		$severity = $this->top_severity( $rows );
		$routing  = $this->routing( $connector, $team );
		$project  = $routing['project'];
		$type     = $routing['issue_type'];
		$priority = $connector->priority_for( $severity );
		$summary  = $this->summary( $rows, $grouping, $severity );
		$due      = $this->due_date( $rows );

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

		$response = $connector->client()->create_issue( $fields );

		// A site can have the Team field out of the create screen's field
		// configuration, in which case Jira rejects the whole issue with an
		// error naming that field. Losing the team is much better than losing
		// the ticket, so drop it and try once more, loudly.
		if ( ! $response->ok() && isset( $fields[ $routing['team_field'] ] ) && $this->rejected_field( $response, (string) $routing['team_field'] ) ) {
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

		$this->add_remote_link( $connector, $key, $rows, $ticket_id, $summary );

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
				__( 'VulnHub — %s', 'vulnhub' ),
				(string) $rows[0]['hostname']
			),
			$summary,
			'vulnhub:ticket:' . $ticket_id
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

		$text = match ( $grouping ) {
			'per_asset'         => sprintf(
				/* translators: 1: number of vulnerabilities, 2: hostname. */
				_n( '%1$d vulnerability to remediate on %2$s', '%1$d vulnerabilities to remediate on %2$s', $count, 'vulnhub' ),
				$count,
				$hostname
			),
			'per_vulnerability' => sprintf(
				/* translators: 1: vulnerability title, 2: number of assets. */
				_n( '%1$s — %2$d affected asset', '%1$s — %2$d affected assets', count( $this->distinct( $rows, 'asset_id' ) ), 'vulnhub' ),
				vh_trim( (string) $first['vuln_title'], 150 ),
				count( $this->distinct( $rows, 'asset_id' ) )
			),
			'per_asset_and_severity' => 1 === $count
				? sprintf(
					/* translators: 1: vulnerability title, 2: hostname. */
					__( '%1$s on %2$s', 'vulnhub' ),
					vh_trim( (string) $first['vuln_title'], 150 ),
					$hostname
				)
				: sprintf(
					/* translators: 1: count, 2: severity label, 3: hostname. */
					__( '%1$d %2$s vulnerabilities on %3$s', 'vulnhub' ),
					$count,
					strtolower( vh_severity_label( $severity ) ),
					$hostname
				),
			default             => sprintf(
				/* translators: 1: vulnerability title, 2: hostname. */
				__( '%1$s on %2$s', 'vulnhub' ),
				vh_trim( (string) $first['vuln_title'], 150 ),
				$hostname
			),
		};

		return vh_trim( sprintf( '[%s] %s', $label, $text ), 250 );
	}

	/**
	 * Jira labels for the issue. Labels may not contain spaces.
	 *
	 * @param array<int,array<string,mixed>> $rows     Finding rows.
	 * @param string                         $severity Highest severity.
	 * @return string[]
	 */
	private function labels( array $rows, string $severity ): array {
		$labels = array(
			'vulnhub',
			'vulnhub-' . $severity,
		);

		$type = sanitize_key( (string) $rows[0]['asset_type'] );

		if ( '' !== $type ) {
			$labels[] = 'vulnhub-' . $type;
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
		$due      = $this->due_date( $rows );
		$overdue  = '' !== $due && strtotime( $due . ' 23:59:59 UTC' ) < time();

		/* --- 1. What this is and why -------------------------------- */

		$doc->paragraph(
			array(
				VulnHub_Jira_Adf::strong( __( 'Raised automatically by VulnHub.', 'vulnhub' ) ),
				VulnHub_Jira_Adf::text( ' ' ),
				VulnHub_Jira_Adf::text(
					sprintf(
						/* translators: 1: findings, 2: severity, 3: assets, 4: vulnerabilities, 5: grouping label. */
						__( 'This ticket covers %1$d finding(s) at %2$s severity across %3$d asset(s) and %4$d distinct vulnerability definition(s). Findings were grouped %5$s.', 'vulnhub' ),
						count( $rows ),
						strtolower( vh_severity_label( $severity ) ),
						count( $assets ),
						count( $vulns ),
						strtolower( (string) ( VulnHub_Jira_Connector::grouping_options()[ $grouping ] ?? $grouping ) )
					)
				),
			)
		);

		if ( ! empty( $options['note'] ) ) {
			$doc->paragraph( (string) $options['note'] );
		}

		/* --- 2. Affected assets ------------------------------------- */

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

		if ( ! empty( $team['name'] ) ) {
			$doc->paragraph(
				sprintf(
					/* translators: 1: team name, 2: SLA days for this severity. */
					__( 'Remediation owner: %1$s (SLA for %2$s severity: %3$d days).', 'vulnhub' ),
					(string) $team['name'],
					strtolower( vh_severity_label( $severity ) ),
					$this->team_sla_days( $team, $severity )
				)
			);
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

			$doc->bullets( $this->vuln_lines( $row, $rows ) );

			$description = vh_trim( (string) ( $row['vuln_description'] ?? '' ), 900 );

			if ( '' !== $description ) {
				$doc->paragraph( $description );
			}

			if ( count( $seen_vulns ) >= 15 ) {
				$doc->paragraph(
					sprintf(
						/* translators: %d: number of vulnerabilities not listed. */
						__( '… and %d further vulnerability definition(s); see the full list in VulnHub.', 'vulnhub' ),
						max( 0, count( $vulns ) - 15 )
					)
				);
				break;
			}
		}

		/* --- 4. Vendor remediation ---------------------------------- */

		$doc->heading( __( 'Vendor remediation', 'vulnhub' ) );

		$solutions = array();

		foreach ( $rows as $row ) {
			$solution = trim( (string) ( $row['solution'] ?? '' ) );

			if ( '' === $solution ) {
				continue;
			}

			$solutions[ md5( $solution ) ] = $solution;
		}

		if ( $solutions ) {
			foreach ( array_slice( array_values( $solutions ), 0, 8 ) as $solution ) {
				$doc->paragraph( $solution );
			}
		} else {
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

		if ( '' === $due ) {
			$doc->paragraph( __( 'No SLA due date has been calculated for these findings yet — that happens on the next vulnerability sync once ownership is resolved.', 'vulnhub' ) );
		} elseif ( $overdue ) {
			$doc->paragraph(
				array(
					VulnHub_Jira_Adf::strong( __( 'Past SLA.', 'vulnhub' ) ),
					VulnHub_Jira_Adf::text( ' ' ),
					VulnHub_Jira_Adf::text(
						sprintf(
							/* translators: 1: due date, 2: relative time. */
							__( 'Remediation was due %1$s (%2$s).', 'vulnhub' ),
							$due,
							vh_ago( $due . ' 00:00:00' )
						)
					),
				)
			);
		} else {
			$doc->paragraph(
				sprintf(
					/* translators: 1: due date, 2: relative time. */
					__( 'Remediation is due by %1$s (%2$s).', 'vulnhub' ),
					$due,
					vh_ago( $due . ' 00:00:00' )
				)
			);
		}

		/* --- 6. Back to VulnHub ------------------------------------- */

		$doc->rule();
		$doc->heading( __( 'In VulnHub', 'vulnhub' ) );

		$asset_id  = (int) $rows[0]['asset_id'];
		$asset_url = vh_admin_url( 'vulnhub-assets', array( 'asset' => $asset_id ) );

		$doc->paragraph(
			array(
				VulnHub_Jira_Adf::text( __( 'Open the asset in VulnHub: ', 'vulnhub' ) ),
				VulnHub_Jira_Adf::link( (string) $rows[0]['hostname'], $asset_url ),
			)
		);

		$doc->paragraph(
			array(
				VulnHub_Jira_Adf::text( __( 'VulnHub tracks this ticket and re-checks it against the scanner after it is closed. If the vulnerability is still detected the ticket is reopened automatically, so please only close it once the remediation is actually deployed.', 'vulnhub' ) ),
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

		if ( '' !== $owner ) {
			$detail[] = sprintf(
				/* translators: 1: owner name, 2: owner UPN. */
				__( 'owner %1$s (%2$s)', 'vulnhub' ),
				$owner,
				(string) ( $row['owner_upn'] ?? '' )
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
	private function vuln_lines( array $row, array $rows ): array {
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

		$lines[] = sprintf(
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
				a.id AS asset_id, a.hostname, a.fqdn, a.ipv4, a.asset_type,
				a.operating_system, a.os_version, a.criticality, a.environment,
				a.business_service, a.team_id, a.owner_person_id, a.location_id, a.tags_json,
				v.id AS vuln_id, v.source AS vuln_source, v.plugin_id, v.title AS vuln_title,
				v.family, v.cve_json, v.cvss2_base, v.cvss3_base, v.vpr_score,
				v.exploit_available, v.description AS vuln_description, v.solution,
				v.see_also, v.patch_publication_date,
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
	 * Earliest SLA due date in the group, as Y-m-d (Jira's `duedate` format).
	 *
	 * @param array<int,array<string,mixed>> $rows Rows.
	 */
	private function due_date( array $rows ): string {
		$earliest = null;

		foreach ( $rows as $row ) {
			$due = (string) ( $row['due_at'] ?? '' );

			if ( '' === $due || '0000-00-00 00:00:00' === $due ) {
				continue;
			}

			$ts = strtotime( $due . ' UTC' );

			if ( false === $ts ) {
				continue;
			}
			if ( null === $earliest || $ts < $earliest ) {
				$earliest = $ts;
			}
		}

		return null === $earliest ? '' : gmdate( 'Y-m-d', $earliest );
	}

	/**
	 * The team's SLA in days for a severity.
	 *
	 * @param array<string,mixed> $team     Team row.
	 * @param string              $severity Severity slug.
	 */
	private function team_sla_days( array $team, string $severity ): int {
		$defaults = array(
			'critical' => 7,
			'high'     => 30,
			'medium'   => 90,
			'low'      => 180,
			'info'     => 180,
		);

		$key = 'sla_' . ( 'info' === $severity ? 'low' : $severity ) . '_days';

		return (int) ( $team[ $key ] ?? $defaults[ $severity ] ?? 30 );
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

