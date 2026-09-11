<?php
/**
 * Jira integration screen.
 *
 * Rendered by core via the `vulnhub_render_admin_page` action, inside the
 * standard `.vulnhub-wrap` shell, so it reuses core's CSS classes throughout.
 *
 * @package VulnHub\Jira
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! current_user_can( 'vulnhub_view' ) ) {
	wp_die( esc_html__( 'You do not have permission to view this screen.', 'vulnhub' ) );
}

global $wpdb;

$vh_ji_settings  = vulnhub()->settings;
$vh_ji_connector = vulnhub_jira_connector();
$vh_ji_health    = $vh_ji_connector ? $vh_ji_connector->health() : array(
	'state'  => 'off',
	'label'  => __( 'Not registered', 'vulnhub' ),
	'detail' => '',
);

$vh_ji_poll      = (array) $vh_ji_settings->get( 'jira', 'last_poll', array() );
$vh_ji_poll_at   = (string) $vh_ji_settings->get( 'jira', 'last_poll_at', '' );
$vh_ji_poll_mode = (string) $vh_ji_settings->get( 'jira', 'last_poll_mode', '' );
$vh_ji_writeback = (array) $vh_ji_settings->get( 'jira', 'writeback_log', array() );
$vh_ji_labels    = \VulnHub\Core\Tickets::verification_labels();

$vh_ji_by_category = (array) $wpdb->get_results(
	$wpdb->prepare(
		'SELECT status_category, COUNT(*) AS n FROM ' . vh_table( 'tickets' ) . ' WHERE provider = %s GROUP BY status_category',
		'jira'
	),
	ARRAY_A
);
$vh_ji_by_status = (array) $wpdb->get_results(
	$wpdb->prepare(
		'SELECT status, status_category, COUNT(*) AS n FROM ' . vh_table( 'tickets' ) . ' WHERE provider = %s GROUP BY status, status_category ORDER BY n DESC',
		'jira'
	),
	ARRAY_A
);
$vh_ji_by_project = (array) $wpdb->get_results(
	$wpdb->prepare(
		'SELECT project_key, COUNT(*) AS n, SUM(finding_count) AS findings FROM ' . vh_table( 'tickets' ) . ' WHERE provider = %s GROUP BY project_key ORDER BY n DESC',
		'jira'
	),
	ARRAY_A
);
$vh_ji_by_origin = (array) $wpdb->get_results(
	$wpdb->prepare(
		'SELECT created_via, COUNT(*) AS n FROM ' . vh_table( 'tickets' ) . ' WHERE provider = %s GROUP BY created_via ORDER BY n DESC',
		'jira'
	),
	ARRAY_A
);

$vh_ji_total    = 0;
$vh_ji_open     = 0;
$vh_ji_done     = 0;
$vh_ji_counts   = array(
	'new'           => 0,
	'indeterminate' => 0,
	'done'          => 0,
);

foreach ( $vh_ji_by_category as $vh_ji_row ) {
	$vh_ji_n      = (int) $vh_ji_row['n'];
	$vh_ji_total += $vh_ji_n;
	$vh_ji_key    = (string) $vh_ji_row['status_category'];

	if ( isset( $vh_ji_counts[ $vh_ji_key ] ) ) {
		$vh_ji_counts[ $vh_ji_key ] += $vh_ji_n;
	}

	if ( 'done' === $vh_ji_key ) {
		$vh_ji_done += $vh_ji_n;
	} else {
		$vh_ji_open += $vh_ji_n;
	}
}

$vh_ji_links = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . vh_table( 'ticket_findings' ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
$vh_ji_await = (int) $wpdb->get_var(
	$wpdb->prepare(
		'SELECT COUNT(*) FROM ' . vh_table( 'tickets' ) . ' WHERE provider = %s AND verification_state = %s',
		'jira',
		\VulnHub\Core\Tickets::VERIFY_PENDING
	)
);
$vh_ji_failed = (int) $wpdb->get_var(
	$wpdb->prepare(
		'SELECT COUNT(*) FROM ' . vh_table( 'tickets' ) . ' WHERE provider = %s AND verification_state = %s',
		'jira',
		\VulnHub\Core\Tickets::VERIFY_STILL_OPEN
	)
);
?>

<div class="vh-grid vh-grid--4">
	<div class="vh-card">
		<h2><?php esc_html_e( 'Jira issues tracked', 'vulnhub' ); ?></h2>
		<p class="vh-card__value"><?php echo esc_html( number_format_i18n( $vh_ji_total ) ); ?></p>
		<p class="vh-card__meta">
			<?php
			printf(
				/* translators: 1: open tickets, 2: closed tickets. */
				esc_html__( '%1$s open, %2$s closed in Jira', 'vulnhub' ),
				'<strong>' . esc_html( number_format_i18n( $vh_ji_open ) ) . '</strong>',
				'<strong>' . esc_html( number_format_i18n( $vh_ji_done ) ) . '</strong>'
			);
			?>
		</p>
	</div>

	<div class="vh-card">
		<h2><?php esc_html_e( 'Findings covered', 'vulnhub' ); ?></h2>
		<p class="vh-card__value"><?php echo esc_html( number_format_i18n( $vh_ji_links ) ); ?></p>
		<p class="vh-card__meta"><?php esc_html_e( 'finding-to-ticket links across every provider', 'vulnhub' ); ?></p>
	</div>

	<div class="vh-card <?php echo esc_attr( $vh_ji_failed > 0 ? 'vh-card--warn' : '' ); ?>">
		<h2><?php esc_html_e( 'Closure verification', 'vulnhub' ); ?></h2>
		<p class="vh-card__value"><?php echo esc_html( number_format_i18n( $vh_ji_await ) ); ?></p>
		<p class="vh-card__meta">
			<?php
			printf(
				/* translators: %s: tickets whose closure failed verification. */
				esc_html__( 'awaiting a re-check; %s still detected', 'vulnhub' ),
				'<strong>' . esc_html( number_format_i18n( $vh_ji_failed ) ) . '</strong>'
			);
			?>
		</p>
	</div>

	<div class="vh-card <?php echo esc_attr( in_array( (string) $vh_ji_health['state'], array( 'ok', 'mock' ), true ) ? 'vh-card--ok' : 'vh-card--warn' ); ?>">
		<h2><?php esc_html_e( 'Connector health', 'vulnhub' ); ?></h2>
		<p class="vh-card__value" style="font-size:20px"><?php echo esc_html( (string) $vh_ji_health['label'] ); ?></p>
		<p class="vh-card__meta"><?php echo esc_html( vh_trim( (string) $vh_ji_health['detail'], 120 ) ); ?></p>
	</div>
</div>

<div class="vh-grid vh-grid--2">

	<div class="vh-card">
		<h2><?php esc_html_e( 'Where the work sits', 'vulnhub' ); ?></h2>
		<p class="vh-muted">
			<?php esc_html_e( 'Jira status names differ from site to site, so VulnHub keys its logic off the status category — new, indeterminate or done — which the platform defines and every workflow maps onto.', 'vulnhub' ); ?>
		</p>

		<?php if ( 0 === $vh_ji_total ) : ?>
			<div class="vh-empty">
				<p><?php esc_html_e( 'No Jira issues have been raised yet. Enable the connector, then raise a ticket from the Vulnerabilities screen or let an automation rule do it.', 'vulnhub' ); ?></p>
				<a class="button button-primary" href="<?php echo esc_url( vh_admin_url( 'vulnhub-integrations', array( 'connector' => 'jira' ) ) ); ?>">
					<?php esc_html_e( 'Configure Jira', 'vulnhub' ); ?>
				</a>
			</div>
		<?php else : ?>
			<div class="vh-bar">
				<?php
				$vh_ji_colours = array(
					'new'           => '#64748b',
					'indeterminate' => '#d97706',
					'done'          => '#15803d',
				);
				foreach ( $vh_ji_counts as $vh_ji_cat => $vh_ji_n ) :
					?>
					<span style="width:<?php echo esc_attr( (string) round( ( $vh_ji_n / max( 1, $vh_ji_total ) ) * 100, 2 ) ); ?>%;background:<?php echo esc_attr( $vh_ji_colours[ $vh_ji_cat ] ); ?>"
						title="<?php echo esc_attr( $vh_ji_cat . ': ' . $vh_ji_n ); ?>"></span>
				<?php endforeach; ?>
			</div>

			<div class="vh-table-wrap" style="margin-top:12px">
				<table class="wp-list-table widefat striped">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Status', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'Category', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'Tickets', 'vulnhub' ); ?></th>
							<th></th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $vh_ji_by_status as $vh_ji_row ) : ?>
						<tr>
							<td><strong><?php echo esc_html( (string) ( $vh_ji_row['status'] ?: __( 'Unknown', 'vulnhub' ) ) ); ?></strong></td>
							<td>
								<span class="vh-state <?php echo esc_attr( 'done' === (string) $vh_ji_row['status_category'] ? 'vh-state--done' : 'vh-state--open' ); ?>">
									<?php echo esc_html( (string) $vh_ji_row['status_category'] ); ?>
								</span>
							</td>
							<td><?php echo esc_html( number_format_i18n( (int) $vh_ji_row['n'] ) ); ?></td>
							<td class="vh-nowrap">
								<a href="<?php echo esc_url( vh_admin_url( 'vulnhub-tickets', array( 'status_category' => (string) $vh_ji_row['status_category'] ) ) ); ?>">
									<?php esc_html_e( 'View', 'vulnhub' ); ?> &rarr;
								</a>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			</div>

			<h2 style="margin-top:18px"><?php esc_html_e( 'By project and origin', 'vulnhub' ); ?></h2>
			<div class="vh-table-wrap">
				<table class="wp-list-table widefat striped">
					<tbody>
					<?php foreach ( $vh_ji_by_project as $vh_ji_row ) : ?>
						<tr>
							<td class="vh-mono"><?php echo esc_html( (string) ( $vh_ji_row['project_key'] ?: '—' ) ); ?></td>
							<td>
								<?php
								printf(
									/* translators: 1: tickets, 2: findings. */
									esc_html__( '%1$s ticket(s), %2$s finding(s)', 'vulnhub' ),
									esc_html( number_format_i18n( (int) $vh_ji_row['n'] ) ),
									esc_html( number_format_i18n( (int) $vh_ji_row['findings'] ) )
								);
								?>
							</td>
						</tr>
					<?php endforeach; ?>
					<?php foreach ( $vh_ji_by_origin as $vh_ji_row ) : ?>
						<tr>
							<td><?php echo esc_html( ucfirst( (string) $vh_ji_row['created_via'] ) ); ?></td>
							<td>
								<?php
								printf(
									/* translators: %s: ticket count. */
									esc_html__( 'raised %s ticket(s)', 'vulnhub' ),
									esc_html( number_format_i18n( (int) $vh_ji_row['n'] ) )
								);
								?>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		<?php endif; ?>
	</div>

	<div class="vh-card">
		<h2><?php esc_html_e( 'Last status poll', 'vulnhub' ); ?></h2>

		<?php if ( ! $vh_ji_poll ) : ?>
			<div class="vh-empty"><p><?php esc_html_e( 'No Jira sync has completed yet.', 'vulnhub' ); ?></p></div>
		<?php else : ?>
			<p class="vh-muted">
				<?php
				printf(
					/* translators: 1: relative time, 2: mock or live. */
					esc_html__( 'Completed %1$s against %2$s.', 'vulnhub' ),
					esc_html( vh_ago( $vh_ji_poll_at ) ),
					esc_html( 'mock' === $vh_ji_poll_mode ? __( 'the simulated Jira site', 'vulnhub' ) : __( 'live Jira Cloud', 'vulnhub' ) )
				);
				?>
			</p>
			<p class="vh-muted">
				<?php esc_html_e( 'Tickets are polled in batched JQL searches — "key in (…)" against POST /rest/api/3/search/jql, paged with its nextPageToken cursor — rather than one request per issue.', 'vulnhub' ); ?>
			</p>

			<div class="vh-table-wrap">
				<table class="wp-list-table widefat striped">
					<tbody>
					<?php
					$vh_ji_metrics = array(
						'checked'  => __( 'Tickets checked', 'vulnhub' ),
						'changed'  => __( 'Tickets whose status changed', 'vulnhub' ),
						'closed'   => __( 'Tickets newly closed in Jira', 'vulnhub' ),
						'missing'  => __( 'Tickets Jira did not return', 'vulnhub' ),
						'batches'  => __( 'JQL batches issued', 'vulnhub' ),
						'requests' => __( 'Search requests (including paging)', 'vulnhub' ),
					);
					foreach ( $vh_ji_metrics as $vh_ji_key => $vh_ji_label ) :
						?>
						<tr>
							<td><?php echo esc_html( $vh_ji_label ); ?></td>
							<td style="width:90px;text-align:right">
								<strong><?php echo esc_html( number_format_i18n( (int) ( $vh_ji_poll[ $vh_ji_key ] ?? 0 ) ) ); ?></strong>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		<?php endif; ?>

		<h2 style="margin-top:18px"><?php esc_html_e( 'Ticket settings in force', 'vulnhub' ); ?></h2>
		<div class="vh-table-wrap">
			<table class="wp-list-table widefat striped">
				<tbody>
					<tr>
						<td><?php esc_html_e( 'Default project', 'vulnhub' ); ?></td>
						<td class="vh-mono"><?php echo esc_html( $vh_ji_connector ? $vh_ji_connector->default_project() : '—' ); ?></td>
					</tr>
					<tr>
						<td><?php esc_html_e( 'Default issue type', 'vulnhub' ); ?></td>
						<td><?php echo esc_html( $vh_ji_connector ? $vh_ji_connector->default_issue_type() : '—' ); ?></td>
					</tr>
					<tr>
						<td><?php esc_html_e( 'Grouping', 'vulnhub' ); ?></td>
						<td>
							<?php
							echo esc_html(
								$vh_ji_connector
									? (string) ( VulnHub_Jira_Connector::grouping_options()[ $vh_ji_connector->grouping() ] ?? '' )
									: '—'
							);
							?>
						</td>
					</tr>
					<tr>
						<td><?php esc_html_e( 'Priority mapping', 'vulnhub' ); ?></td>
						<td>
							<?php
							if ( $vh_ji_connector ) {
								$vh_ji_map = array();
								foreach ( array( 'critical', 'high', 'medium', 'low' ) as $vh_ji_sev ) {
									$vh_ji_map[] = vh_severity_label( $vh_ji_sev ) . ' → ' . $vh_ji_connector->priority_for( $vh_ji_sev );
								}
								echo esc_html( implode( ', ', $vh_ji_map ) );
							} else {
								echo '—';
							}
							?>
						</td>
					</tr>
					<tr>
						<td><?php esc_html_e( 'Reopen when the vulnerability returns', 'vulnhub' ); ?></td>
						<td><?php echo esc_html( $vh_ji_connector && $vh_ji_connector->reopens() ? __( 'Yes', 'vulnhub' ) : __( 'No', 'vulnhub' ) ); ?></td>
					</tr>
					<tr>
						<td><?php esc_html_e( 'Comment on verified closures', 'vulnhub' ); ?></td>
						<td><?php echo esc_html( $vh_ji_connector && $vh_ji_connector->comments_on_verify() ? __( 'Yes', 'vulnhub' ) : __( 'No', 'vulnhub' ) ); ?></td>
					</tr>
				</tbody>
			</table>
		</div>
	</div>
</div>

<div class="vh-card">
	<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap">
		<div>
			<h2><?php esc_html_e( 'Verdicts written back to Jira', 'vulnhub' ); ?></h2>
			<p class="vh-muted" style="max-width:75ch">
				<?php esc_html_e( 'When closure verification finds the scanner still detects a vulnerability, VulnHub comments on the Jira issue with the evidence and transitions it back to an open status if the workflow allows one. When verification confirms the fix, it says so on the issue instead.', 'vulnhub' ); ?>
			</p>
		</div>

		<?php if ( current_user_can( 'vulnhub_raise_ticket' ) ) : ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-form">
				<?php wp_nonce_field( 'vulnhub_jira_verdicts' ); ?>
				<input type="hidden" name="action" value="vulnhub_jira_verdicts" />
				<button type="submit" class="button button-secondary">
					<?php esc_html_e( 'Write verdicts back now', 'vulnhub' ); ?>
				</button>
			</form>
		<?php endif; ?>
	</div>

	<?php if ( ! $vh_ji_writeback ) : ?>
		<div class="vh-empty">
			<p><?php esc_html_e( 'Nothing has been written back yet. Entries appear here once tickets are closed and the settling period has elapsed.', 'vulnhub' ); ?></p>
		</div>
	<?php else : ?>
		<div class="vh-table-wrap">
			<table class="wp-list-table widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Ticket', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Verdict', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Transitioned', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Now', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'When', 'vulnhub' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $vh_ji_writeback as $vh_ji_entry ) : ?>
					<?php $vh_ji_state = (string) ( $vh_ji_entry['state'] ?? '' ); ?>
					<tr>
						<td class="vh-nowrap">
							<?php if ( ! empty( $vh_ji_entry['url'] ) ) : ?>
								<a href="<?php echo esc_url( (string) $vh_ji_entry['url'] ); ?>" target="_blank" rel="noopener noreferrer">
									<?php echo esc_html( (string) $vh_ji_entry['key'] ); ?>
								</a>
							<?php else : ?>
								<?php echo esc_html( (string) $vh_ji_entry['key'] ); ?>
							<?php endif; ?>
							<br />
							<span class="vh-muted"><?php echo esc_html( vh_trim( (string) ( $vh_ji_entry['summary'] ?? '' ), 70 ) ); ?></span>
						</td>
						<td>
							<span class="vh-state <?php echo esc_attr( \VulnHub\Core\Tickets::VERIFY_STILL_OPEN === $vh_ji_state ? 'vh-state--open' : 'vh-state--fixed' ); ?>">
								<?php echo esc_html( $vh_ji_labels[ $vh_ji_state ] ?? $vh_ji_state ); ?>
							</span>
						</td>
						<td>
							<?php
							echo esc_html(
								! empty( $vh_ji_entry['transitioned'] )
									? __( 'Yes', 'vulnhub' )
									: ( (string) ( $vh_ji_entry['reason'] ?? '' ) ?: __( 'No', 'vulnhub' ) )
							);
							?>
						</td>
						<td><?php echo esc_html( (string) ( $vh_ji_entry['status'] ?? '—' ) ); ?></td>
						<td class="vh-nowrap"><?php echo esc_html( vh_ago( (string) ( $vh_ji_entry['at'] ?? '' ) ) ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	<?php endif; ?>
</div>

<div class="vh-card">
	<h2><?php esc_html_e( 'Live API surface', 'vulnhub' ); ?></h2>
	<p class="vh-muted" style="max-width:85ch">
		<?php esc_html_e( 'This connector speaks Jira Cloud REST API v3 with HTTP Basic authentication (account email plus API token, base64 encoded with no trailing newline). Rich text is Atlassian Document Format, never plain text.', 'vulnhub' ); ?>
	</p>
	<div class="vh-table-wrap">
		<table class="wp-list-table widefat striped">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Endpoint', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Used for', 'vulnhub' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php
			$vh_ji_endpoints = array(
				'GET /rest/api/3/myself'                                        => __( 'Connection test — confirms the credential and reports the display name and account id.', 'vulnhub' ),
				'GET /rest/api/3/project/{key}'                                 => __( 'Connection test — confirms the default project key actually exists.', 'vulnhub' ),
				'POST /rest/api/3/issue'                                        => __( 'Ticket creation, with an ADF description.', 'vulnhub' ),
				'POST /rest/api/3/search/jql'                                   => __( 'Batched status sync. Replaces /rest/api/3/search, which Atlassian is removing; pages with nextPageToken.', 'vulnhub' ),
				'GET /rest/api/3/issue/{key}'                                   => __( 'Single-ticket refresh.', 'vulnhub' ),
				'GET|POST /rest/api/3/issue/{key}/transitions'                  => __( 'Reopening an issue, and the automation transition action.', 'vulnhub' ),
				'POST /rest/api/3/issue/{key}/comment'                          => __( 'Verification verdicts and automation comments.', 'vulnhub' ),
				'POST /rest/api/3/issue/{key}/remotelink'                       => __( 'Linking the Jira issue back to the VulnHub asset.', 'vulnhub' ),
				'GET /rest/api/3/issue/createmeta/{key}/issuetypes/{typeId}'    => __( 'Field discovery. The parent /createmeta endpoint is deprecated; this one is not.', 'vulnhub' ),
				'GET /rest/api/3/priority/search'                               => __( 'Priority names. Plain /rest/api/3/priority is deprecated.', 'vulnhub' ),
				'GET /rest/api/3/user/search'                                   => __( 'Resolving a team default assignee email to an account id.', 'vulnhub' ),
			);
			foreach ( $vh_ji_endpoints as $vh_ji_endpoint => $vh_ji_why ) :
				?>
				<tr>
					<td class="vh-mono vh-nowrap"><?php echo esc_html( $vh_ji_endpoint ); ?></td>
					<td class="vh-muted"><?php echo esc_html( $vh_ji_why ); ?></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>

