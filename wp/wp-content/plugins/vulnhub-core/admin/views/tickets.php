<?php
/**
 * Ticket tracking screen, including closure verification against Tenable.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

use VulnHub\Core\Repo;
use VulnHub\Core\Tickets;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.Security.NonceVerification.Recommended
$vh_ticket_id = isset( $_GET['ticket'] ) ? (int) $_GET['ticket'] : 0;
$vh_page      = max( 1, isset( $_GET['paged'] ) ? (int) $_GET['paged'] : 1 );
$vh_args      = array(
	'status_category'    => isset( $_GET['status_category'] ) ? sanitize_key( wp_unslash( $_GET['status_category'] ) ) : '',
	'verification_state' => isset( $_GET['verification_state'] ) ? sanitize_key( wp_unslash( $_GET['verification_state'] ) ) : '',
	'team_id'            => isset( $_GET['team_id'] ) ? (int) $_GET['team_id'] : 0,
	'search'             => isset( $_GET['search'] ) ? sanitize_text_field( wp_unslash( $_GET['search'] ) ) : '',
);
// phpcs:enable

if ( $vh_ticket_id ) {
	$vh_ticket = Tickets::get( $vh_ticket_id );
	if ( ! $vh_ticket ) {
		echo '<div class="vh-card vh-empty"><h2>' . esc_html__( 'Ticket not found', 'vulnhub' ) . '</h2></div>';
		return;
	}
	$vh_covered = Tickets::findings_for( $vh_ticket_id );
	?>
	<p style="margin:0 0 14px">
		<a href="<?php echo esc_url( vh_admin_url( 'vulnhub-tickets' ) ); ?>">&larr; <?php esc_html_e( 'All tickets', 'vulnhub' ); ?></a>
	</p>

	<div class="vh-grid vh-grid--2">
		<div class="vh-card">
			<h2><?php esc_html_e( 'Ticket', 'vulnhub' ); ?></h2>
			<h3 style="margin:0 0 12px;text-transform:none;letter-spacing:0;color:#1d2327;font-size:17px">
				<a href="<?php echo esc_url( (string) $vh_ticket['url'] ); ?>" target="_blank" rel="noopener noreferrer" class="vh-mono">
					<?php echo esc_html( (string) $vh_ticket['external_key'] ); ?>
				</a>
			</h3>
			<p style="margin:0 0 14px"><?php echo esc_html( (string) $vh_ticket['summary'] ); ?></p>
			<div class="vh-detail">
				<dl>
					<dt><?php esc_html_e( 'Status', 'vulnhub' ); ?></dt>
					<dd>
						<span class="vh-state vh-state--<?php echo esc_attr( 'done' === $vh_ticket['status_category'] ? 'done' : 'open' ); ?>">
							<?php echo esc_html( (string) $vh_ticket['status'] ); ?>
						</span>
					</dd>
					<dt><?php esc_html_e( 'Resolution', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( (string) ( $vh_ticket['resolution'] ?: '—' ) ); ?></dd>
					<dt><?php esc_html_e( 'Project', 'vulnhub' ); ?></dt>
					<dd class="vh-mono"><?php echo esc_html( (string) $vh_ticket['project_key'] ); ?></dd>
					<dt><?php esc_html_e( 'Issue type', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( (string) $vh_ticket['issue_type'] ); ?></dd>
					<dt><?php esc_html_e( 'Assignee', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( (string) ( $vh_ticket['assignee'] ?: __( 'Unassigned', 'vulnhub' ) ) ); ?></dd>
					<dt><?php esc_html_e( 'Created', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( vh_date( (string) $vh_ticket['created_at'] ) ); ?></dd>
					<dt><?php esc_html_e( 'Raised via', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( (string) $vh_ticket['created_via'] ); ?></dd>
					<dt><?php esc_html_e( 'Last synced', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( vh_ago( (string) $vh_ticket['last_synced_at'] ) ); ?></dd>
				</dl>
			</div>
			<p style="margin-top:14px">
				<button type="button" class="button" data-vh-action="refresh-ticket" data-vh-ticket="<?php echo esc_attr( (string) $vh_ticket['id'] ); ?>">
					<?php esc_html_e( 'Refresh from Jira', 'vulnhub' ); ?>
				</button>
			</p>
		</div>

		<div class="vh-card">
			<h2><?php esc_html_e( 'Closure verification', 'vulnhub' ); ?></h2>
			<?php
			$vh_state  = (string) $vh_ticket['verification_state'];
			$vh_labels = Tickets::verification_labels();
			$vh_class  = match ( $vh_state ) {
				Tickets::VERIFY_CONFIRMED  => 'approved',
				Tickets::VERIFY_STILL_OPEN => 'rejected',
				Tickets::VERIFY_PENDING    => 'pending',
				default                    => 'draft',
			};
			?>
			<p><span class="vh-state vh-state--<?php echo esc_attr( $vh_class ); ?>"><?php echo esc_html( $vh_labels[ $vh_state ] ?? $vh_state ); ?></span></p>
			<p style="line-height:1.6;max-width:620px" class="vh-muted">
				<?php esc_html_e( 'When a ticket is closed in Jira, VulnHub does not take that as proof. It re-checks each covered finding against the latest Tenable data and only records the vulnerability as remediated once the scanner agrees.', 'vulnhub' ); ?>
			</p>
			<?php if ( ! empty( $vh_ticket['verification_note'] ) ) : ?>
				<div class="vh-log" style="max-height:200px"><?php echo esc_html( (string) $vh_ticket['verification_note'] ); ?></div>
			<?php endif; ?>
			<div class="vh-detail" style="margin-top:14px">
				<dl>
					<dt><?php esc_html_e( 'Closed in Jira', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( $vh_ticket['remote_closed_at'] ? vh_date( (string) $vh_ticket['remote_closed_at'] ) : '—' ); ?></dd>
					<dt><?php esc_html_e( 'Verified at', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( $vh_ticket['verified_at'] ? vh_date( (string) $vh_ticket['verified_at'] ) : '—' ); ?></dd>
					<dt><?php esc_html_e( 'Findings covered', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( number_format_i18n( (int) $vh_ticket['finding_count'] ) ); ?></dd>
				</dl>
			</div>
		</div>
	</div>

	<h2 style="margin:24px 0 12px;font-size:15px"><?php esc_html_e( 'Findings covered by this ticket', 'vulnhub' ); ?></h2>
	<div class="vh-table-wrap">
		<table class="wp-list-table widefat fixed striped">
			<thead>
				<tr>
					<th style="width:88px"><?php esc_html_e( 'Severity', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Vulnerability', 'vulnhub' ); ?></th>
					<th style="width:160px"><?php esc_html_e( 'Asset', 'vulnhub' ); ?></th>
					<th style="width:110px"><?php esc_html_e( 'State', 'vulnhub' ); ?></th>
					<th style="width:150px"><?php esc_html_e( 'Verification', 'vulnhub' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php if ( ! $vh_covered ) : ?>
				<tr><td colspan="5" class="vh-muted"><?php esc_html_e( 'No findings linked.', 'vulnhub' ); ?></td></tr>
			<?php endif; ?>
			<?php foreach ( $vh_covered as $vh_f ) : ?>
				<tr>
					<td><?php echo wp_kses_post( vh_severity_pill( (string) $vh_f['severity'] ) ); ?></td>
					<td><?php echo esc_html( vh_trim( (string) $vh_f['vuln_title'], 90 ) ); ?></td>
					<td>
						<a class="vh-mono" href="<?php echo esc_url( vh_admin_url( 'vulnhub-assets', array( 'asset' => (int) $vh_f['asset_id'] ) ) ); ?>">
							<?php echo esc_html( (string) $vh_f['hostname'] ); ?>
						</a>
					</td>
					<td><span class="vh-state vh-state--<?php echo esc_attr( (string) $vh_f['state'] ); ?>"><?php echo esc_html( vh_finding_states()[ (string) $vh_f['state'] ] ?? (string) $vh_f['state'] ); ?></span></td>
					<td class="vh-muted"><?php echo esc_html( Tickets::verification_labels()[ (string) $vh_f['verification_state'] ] ?? '—' ); ?></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	</div>
	<?php
	return;
}

$vh_per   = 40;
$vh_query = Tickets::query(
	array_merge(
		array_filter( $vh_args, static fn( $v ): bool => '' !== $v && 0 !== $v ),
		array(
			'limit'  => $vh_per,
			'offset' => ( $vh_page - 1 ) * $vh_per,
		)
	)
);
$vh_pages = max( 1, (int) ceil( (int) $vh_query['total'] / $vh_per ) );
$vh_teams = Repo::teams();
$vh_sum   = Repo::summary();
?>

<div class="vh-grid vh-grid--4">
	<div class="vh-card">
		<h2><?php esc_html_e( 'Open', 'vulnhub' ); ?></h2>
		<p class="vh-card__value"><?php echo esc_html( number_format_i18n( (int) $vh_sum['tickets_open'] ) ); ?></p>
	</div>
	<div class="vh-card vh-card--ok">
		<h2><?php esc_html_e( 'Closed', 'vulnhub' ); ?></h2>
		<p class="vh-card__value"><?php echo esc_html( number_format_i18n( (int) $vh_sum['tickets_done'] ) ); ?></p>
	</div>
	<div class="vh-card vh-card--warn">
		<h2><?php esc_html_e( 'Awaiting verification', 'vulnhub' ); ?></h2>
		<p class="vh-card__value"><?php echo esc_html( number_format_i18n( (int) $vh_sum['awaiting_verify'] ) ); ?></p>
	</div>
	<div class="vh-card <?php echo (int) $vh_sum['verify_failed'] > 0 ? 'vh-card--crit' : 'vh-card--ok'; ?>">
		<h2><?php esc_html_e( 'Closed but still detected', 'vulnhub' ); ?></h2>
		<p class="vh-card__value"><?php echo esc_html( number_format_i18n( (int) $vh_sum['verify_failed'] ) ); ?></p>
	</div>
</div>

<form method="get" class="vh-filters">
	<input type="hidden" name="page" value="vulnhub-tickets">
	<label>
		<?php esc_html_e( 'Status', 'vulnhub' ); ?>
		<select name="status_category" data-vh-autosubmit>
			<option value=""><?php esc_html_e( 'All', 'vulnhub' ); ?></option>
			<option value="new" <?php selected( $vh_args['status_category'], 'new' ); ?>><?php esc_html_e( 'To do', 'vulnhub' ); ?></option>
			<option value="indeterminate" <?php selected( $vh_args['status_category'], 'indeterminate' ); ?>><?php esc_html_e( 'In progress', 'vulnhub' ); ?></option>
			<option value="done" <?php selected( $vh_args['status_category'], 'done' ); ?>><?php esc_html_e( 'Done', 'vulnhub' ); ?></option>
		</select>
	</label>
	<label>
		<?php esc_html_e( 'Verification', 'vulnhub' ); ?>
		<select name="verification_state" data-vh-autosubmit>
			<option value=""><?php esc_html_e( 'All', 'vulnhub' ); ?></option>
			<?php foreach ( Tickets::verification_labels() as $vh_k => $vh_l ) : ?>
				<option value="<?php echo esc_attr( $vh_k ); ?>" <?php selected( $vh_args['verification_state'], $vh_k ); ?>><?php echo esc_html( $vh_l ); ?></option>
			<?php endforeach; ?>
		</select>
	</label>
	<label>
		<?php esc_html_e( 'Team', 'vulnhub' ); ?>
		<select name="team_id" data-vh-autosubmit>
			<option value="0"><?php esc_html_e( 'All teams', 'vulnhub' ); ?></option>
			<?php foreach ( $vh_teams as $vh_t ) : ?>
				<option value="<?php echo esc_attr( (string) $vh_t['id'] ); ?>" <?php selected( $vh_args['team_id'], (int) $vh_t['id'] ); ?>><?php echo esc_html( (string) $vh_t['name'] ); ?></option>
			<?php endforeach; ?>
		</select>
	</label>
	<label>
		<?php esc_html_e( 'Search', 'vulnhub' ); ?>
		<input type="search" name="search" value="<?php echo esc_attr( (string) $vh_args['search'] ); ?>" placeholder="<?php esc_attr_e( 'key or summary…', 'vulnhub' ); ?>">
	</label>
	<button class="button button-primary"><?php esc_html_e( 'Filter', 'vulnhub' ); ?></button>
	<a class="button" href="<?php echo esc_url( vh_admin_url( 'vulnhub-tickets' ) ); ?>"><?php esc_html_e( 'Reset', 'vulnhub' ); ?></a>
</form>

<?php if ( ! $vh_query['rows'] ) : ?>
	<div class="vh-card vh-empty">
		<span class="dashicons dashicons-tickets-alt"></span>
		<h2><?php esc_html_e( 'No tickets yet', 'vulnhub' ); ?></h2>
		<p><?php esc_html_e( 'Raise one from the Vulnerabilities screen, or let an automation rule do it for you.', 'vulnhub' ); ?></p>
		<a class="button button-primary" href="<?php echo esc_url( vh_admin_url( 'vulnhub-findings' ) ); ?>"><?php esc_html_e( 'Go to vulnerabilities', 'vulnhub' ); ?></a>
	</div>
<?php else : ?>
<div class="vh-table-wrap">
	<table class="wp-list-table widefat fixed striped">
		<thead>
			<tr>
				<th style="width:110px"><?php esc_html_e( 'Key', 'vulnhub' ); ?></th>
				<th><?php esc_html_e( 'Summary', 'vulnhub' ); ?></th>
				<th style="width:130px"><?php esc_html_e( 'Status', 'vulnhub' ); ?></th>
				<th style="width:160px"><?php esc_html_e( 'Assignee', 'vulnhub' ); ?></th>
				<th style="width:80px"><?php esc_html_e( 'Findings', 'vulnhub' ); ?></th>
				<th style="width:160px"><?php esc_html_e( 'Verification', 'vulnhub' ); ?></th>
				<th style="width:100px"><?php esc_html_e( 'Updated', 'vulnhub' ); ?></th>
			</tr>
		</thead>
		<tbody>
		<?php foreach ( $vh_query['rows'] as $vh_t ) : ?>
			<?php
			$vh_vclass = match ( (string) $vh_t['verification_state'] ) {
				Tickets::VERIFY_CONFIRMED  => 'approved',
				Tickets::VERIFY_STILL_OPEN => 'rejected',
				Tickets::VERIFY_PENDING    => 'pending',
				default                    => 'draft',
			};
			?>
			<tr>
				<td>
					<a class="vh-mono" href="<?php echo esc_url( vh_admin_url( 'vulnhub-tickets', array( 'ticket' => (int) $vh_t['id'] ) ) ); ?>">
						<strong><?php echo esc_html( (string) $vh_t['external_key'] ); ?></strong>
					</a>
				</td>
				<td><span class="vh-truncate"><?php echo esc_html( (string) $vh_t['summary'] ); ?></span></td>
				<td>
					<span class="vh-state vh-state--<?php echo esc_attr( 'done' === $vh_t['status_category'] ? 'done' : 'open' ); ?>">
						<?php echo esc_html( (string) $vh_t['status'] ); ?>
					</span>
				</td>
				<td><?php echo esc_html( (string) ( $vh_t['assignee'] ?: '—' ) ); ?></td>
				<td><?php echo esc_html( number_format_i18n( (int) $vh_t['finding_count'] ) ); ?></td>
				<td>
					<span class="vh-state vh-state--<?php echo esc_attr( $vh_vclass ); ?>">
						<?php echo esc_html( Tickets::verification_labels()[ (string) $vh_t['verification_state'] ] ?? '—' ); ?>
					</span>
				</td>
				<td class="vh-muted vh-nowrap"><?php echo esc_html( vh_ago( (string) $vh_t['updated_at'] ) ); ?></td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
</div>

<?php if ( $vh_pages > 1 ) : ?>
	<div class="tablenav bottom"><div class="tablenav-pages">
	<?php
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended
	$vh_base = add_query_arg( array_map( 'sanitize_text_field', wp_unslash( $_GET ) ), admin_url( 'admin.php' ) );
	echo wp_kses_post( paginate_links( array( 'base' => add_query_arg( 'paged', '%#%', $vh_base ), 'format' => '', 'total' => $vh_pages, 'current' => $vh_page ) ) ?? '' );
	?>
	</div></div>
<?php endif; ?>
<?php endif; ?>

