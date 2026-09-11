<?php
/**
 * Vulnerability findings screen.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

use VulnHub\Core\Repo;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.Security.NonceVerification.Recommended
$vh_page   = max( 1, isset( $_GET['paged'] ) ? (int) $_GET['paged'] : 1 );
$vh_per    = 40;
$vh_filter = array(
	'state'       => isset( $_GET['state'] ) ? sanitize_key( wp_unslash( $_GET['state'] ) ) : 'open_any',
	'severity'    => isset( $_GET['severity'] ) ? sanitize_key( wp_unslash( $_GET['severity'] ) ) : '',
	'asset_type'  => isset( $_GET['asset_type'] ) ? sanitize_key( wp_unslash( $_GET['asset_type'] ) ) : '',
	'team_id'     => isset( $_GET['team_id'] ) ? (int) $_GET['team_id'] : 0,
	'has_ticket'  => isset( $_GET['has_ticket'] ) && '' !== $_GET['has_ticket'] ? sanitize_key( wp_unslash( $_GET['has_ticket'] ) ) : '',
	'overdue'     => isset( $_GET['overdue'] ) ? 1 : 0,
	'search'      => isset( $_GET['search'] ) ? sanitize_text_field( wp_unslash( $_GET['search'] ) ) : '',
	'orderby'     => isset( $_GET['orderby'] ) ? sanitize_key( wp_unslash( $_GET['orderby'] ) ) : 'risk_score',
	'order'       => isset( $_GET['order'] ) ? sanitize_key( wp_unslash( $_GET['order'] ) ) : 'desc',
);
// phpcs:enable

$vh_query = Repo::findings(
	array_merge(
		array_filter(
			$vh_filter,
			static fn( $v ): bool => '' !== $v && 0 !== $v
		),
		array(
			'limit'  => $vh_per,
			'offset' => ( $vh_page - 1 ) * $vh_per,
		)
	)
);

$vh_rows  = $vh_query['rows'];
$vh_total = $vh_query['total'];
$vh_pages = max( 1, (int) ceil( $vh_total / $vh_per ) );
$vh_teams = Repo::teams();
?>

<form method="get" class="vh-filters">
	<input type="hidden" name="page" value="vulnhub-findings">

	<label>
		<?php esc_html_e( 'State', 'vulnhub' ); ?>
		<select name="state" data-vh-autosubmit>
			<option value="open_any" <?php selected( $vh_filter['state'], 'open_any' ); ?>><?php esc_html_e( 'Open &amp; reopened', 'vulnhub' ); ?></option>
			<option value="open" <?php selected( $vh_filter['state'], 'open' ); ?>><?php esc_html_e( 'Open only', 'vulnhub' ); ?></option>
			<option value="reopened" <?php selected( $vh_filter['state'], 'reopened' ); ?>><?php esc_html_e( 'Reopened', 'vulnhub' ); ?></option>
			<option value="fixed" <?php selected( $vh_filter['state'], 'fixed' ); ?>><?php esc_html_e( 'Fixed', 'vulnhub' ); ?></option>
		</select>
	</label>

	<label>
		<?php esc_html_e( 'Severity', 'vulnhub' ); ?>
		<select name="severity" data-vh-autosubmit>
			<option value=""><?php esc_html_e( 'All', 'vulnhub' ); ?></option>
			<?php foreach ( vh_severities() as $vh_slug => $vh_meta ) : ?>
				<option value="<?php echo esc_attr( $vh_slug ); ?>" <?php selected( $vh_filter['severity'], $vh_slug ); ?>>
					<?php echo esc_html( (string) $vh_meta['label'] ); ?>
				</option>
			<?php endforeach; ?>
		</select>
	</label>

	<label>
		<?php esc_html_e( 'Asset type', 'vulnhub' ); ?>
		<select name="asset_type" data-vh-autosubmit>
			<option value=""><?php esc_html_e( 'All', 'vulnhub' ); ?></option>
			<?php foreach ( vh_asset_types() as $vh_slug => $vh_label ) : ?>
				<option value="<?php echo esc_attr( $vh_slug ); ?>" <?php selected( $vh_filter['asset_type'], $vh_slug ); ?>>
					<?php echo esc_html( $vh_label ); ?>
				</option>
			<?php endforeach; ?>
		</select>
	</label>

	<label>
		<?php esc_html_e( 'Team', 'vulnhub' ); ?>
		<select name="team_id" data-vh-autosubmit>
			<option value="0"><?php esc_html_e( 'All teams', 'vulnhub' ); ?></option>
			<?php foreach ( $vh_teams as $vh_t ) : ?>
				<option value="<?php echo esc_attr( (string) $vh_t['id'] ); ?>" <?php selected( $vh_filter['team_id'], (int) $vh_t['id'] ); ?>>
					<?php echo esc_html( (string) $vh_t['name'] ); ?>
				</option>
			<?php endforeach; ?>
		</select>
	</label>

	<label>
		<?php esc_html_e( 'Ticket', 'vulnhub' ); ?>
		<select name="has_ticket" data-vh-autosubmit>
			<option value=""><?php esc_html_e( 'Any', 'vulnhub' ); ?></option>
			<option value="1" <?php selected( $vh_filter['has_ticket'], '1' ); ?>><?php esc_html_e( 'Has a ticket', 'vulnhub' ); ?></option>
			<option value="0" <?php selected( $vh_filter['has_ticket'], '0' ); ?>><?php esc_html_e( 'No ticket yet', 'vulnhub' ); ?></option>
		</select>
	</label>

	<label>
		<?php esc_html_e( 'Search', 'vulnhub' ); ?>
		<input type="search" name="search" value="<?php echo esc_attr( (string) $vh_filter['search'] ); ?>"
			placeholder="<?php esc_attr_e( 'CVE, host, plugin id…', 'vulnhub' ); ?>">
	</label>

	<label style="flex-direction:row;align-items:center;gap:6px;text-transform:none;font-weight:400">
		<input type="checkbox" name="overdue" value="1" <?php checked( (int) $vh_filter['overdue'], 1 ); ?> data-vh-autosubmit>
		<?php esc_html_e( 'Past SLA only', 'vulnhub' ); ?>
	</label>

	<button class="button button-primary"><?php esc_html_e( 'Filter', 'vulnhub' ); ?></button>
	<a class="button" href="<?php echo esc_url( vh_admin_url( 'vulnhub-findings' ) ); ?>"><?php esc_html_e( 'Reset', 'vulnhub' ); ?></a>
</form>

<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;flex-wrap:wrap;gap:10px">
	<p class="vh-muted" style="margin:0">
		<?php
		printf(
			/* translators: %s: number of findings. */
			esc_html( _n( '%s finding', '%s findings', $vh_total, 'vulnhub' ) ),
			'<strong>' . esc_html( number_format_i18n( $vh_total ) ) . '</strong>'
		);
		?>
	</p>
	<?php if ( current_user_can( 'vulnhub_raise_ticket' ) ) : ?>
		<button type="button" class="button button-primary" data-vh-action="raise-ticket">
			<span class="dashicons dashicons-tickets-alt" style="margin:4px 4px 0 -2px"></span>
			<?php esc_html_e( 'Raise Jira ticket for selected', 'vulnhub' ); ?>
		</button>
	<?php endif; ?>
</div>

<?php if ( ! $vh_rows ) : ?>
	<div class="vh-card vh-empty">
		<span class="dashicons dashicons-search"></span>
		<h2><?php esc_html_e( 'No findings match these filters', 'vulnhub' ); ?></h2>
		<p><?php esc_html_e( 'Try widening the severity or state filter, or run a Tenable sync to bring in current scan data.', 'vulnhub' ); ?></p>
	</div>
<?php else : ?>

<div class="vh-table-wrap">
	<table class="wp-list-table widefat fixed striped">
		<thead>
			<tr>
				<td class="check-column" style="width:32px"><input type="checkbox" class="vh-select-all"></td>
				<th style="width:88px"><?php esc_html_e( 'Severity', 'vulnhub' ); ?></th>
				<th><?php esc_html_e( 'Vulnerability', 'vulnhub' ); ?></th>
				<th style="width:150px"><?php esc_html_e( 'Asset', 'vulnhub' ); ?></th>
				<th style="width:170px"><?php esc_html_e( 'Owner', 'vulnhub' ); ?></th>
				<th style="width:120px"><?php esc_html_e( 'Team', 'vulnhub' ); ?></th>
				<th style="width:96px"><?php esc_html_e( 'State', 'vulnhub' ); ?></th>
				<th style="width:110px"><?php esc_html_e( 'Due', 'vulnhub' ); ?></th>
				<th style="width:130px"><?php esc_html_e( 'Ticket', 'vulnhub' ); ?></th>
				<th style="width:90px"><?php esc_html_e( 'Actions', 'vulnhub' ); ?></th>
			</tr>
		</thead>
		<tbody>
		<?php foreach ( $vh_rows as $vh_f ) : ?>
			<?php
			$vh_cves     = vh_json( (string) $vh_f['cve_json'] );
			$vh_overdue  = ! empty( $vh_f['due_at'] ) && strtotime( (string) $vh_f['due_at'] . ' UTC' ) < time() && in_array( (string) $vh_f['state'], array( 'open', 'reopened' ), true );
			$vh_excepted = (int) $vh_f['exception_id'] > 0;
			?>
			<tr<?php echo $vh_excepted ? ' style="opacity:.6"' : ''; ?>>
				<td class="check-column">
					<input type="checkbox" class="vh-select-finding" value="<?php echo esc_attr( (string) $vh_f['id'] ); ?>">
				</td>
				<td><?php echo wp_kses_post( vh_severity_pill( (string) $vh_f['severity'] ) ); ?></td>
				<td>
					<strong><?php echo esc_html( vh_trim( (string) $vh_f['vuln_title'], 80 ) ); ?></strong>
					<div class="vh-muted vh-mono" style="font-size:11px;margin-top:2px">
						<?php echo esc_html( 'plugin ' . $vh_f['plugin_id'] ); ?>
						<?php if ( $vh_cves ) : ?>
							&middot; <?php echo esc_html( implode( ', ', array_slice( $vh_cves, 0, 3 ) ) ); ?>
						<?php endif; ?>
						<?php if ( (float) $vh_f['cvss3_base'] > 0 ) : ?>
							&middot; CVSS <?php echo esc_html( (string) $vh_f['cvss3_base'] ); ?>
						<?php endif; ?>
						<?php if ( ! empty( $vh_f['exploit_available'] ) ) : ?>
							&middot; <span style="color:var(--vh-crit);font-weight:600"><?php esc_html_e( 'exploit available', 'vulnhub' ); ?></span>
						<?php endif; ?>
					</div>
					<?php if ( $vh_excepted ) : ?>
						<span class="vh-state vh-state--approved"><?php esc_html_e( 'Exception approved', 'vulnhub' ); ?></span>
					<?php endif; ?>
				</td>
				<td>
					<a class="vh-mono" href="<?php echo esc_url( vh_admin_url( 'vulnhub-assets', array( 'asset' => (int) $vh_f['asset_id'] ) ) ); ?>">
						<?php echo esc_html( (string) $vh_f['hostname'] ); ?>
					</a>
					<div class="vh-muted" style="font-size:11px"><?php echo esc_html( (string) $vh_f['ipv4'] ); ?></div>
				</td>
				<td>
					<?php if ( ! empty( $vh_f['owner_name'] ) ) : ?>
						<?php echo esc_html( (string) $vh_f['owner_name'] ); ?>
						<div class="vh-muted" style="font-size:11px"><?php echo esc_html( vh_trim( (string) $vh_f['owner_upn'], 30 ) ); ?></div>
					<?php elseif ( in_array( (string) $vh_f['asset_type'], vh_user_bound_asset_types(), true ) ) : ?>
						<span class="vh-state vh-state--open"><?php esc_html_e( 'No user assigned', 'vulnhub' ); ?></span>
					<?php else : ?>
						<span class="vh-muted">—</span>
					<?php endif; ?>
				</td>
				<td><?php echo esc_html( (string) ( $vh_f['team_name'] ?: '—' ) ); ?></td>
				<td><span class="vh-state vh-state--<?php echo esc_attr( (string) $vh_f['state'] ); ?>"><?php echo esc_html( vh_finding_states()[ (string) $vh_f['state'] ] ?? (string) $vh_f['state'] ); ?></span></td>
				<td class="vh-nowrap<?php echo $vh_overdue ? ' ' : ''; ?>"<?php echo $vh_overdue ? ' style="color:var(--vh-crit);font-weight:600"' : ''; ?>>
					<?php echo esc_html( $vh_f['due_at'] ? vh_ago( (string) $vh_f['due_at'] ) : '—' ); ?>
				</td>
				<td>
					<?php if ( ! empty( $vh_f['ticket_key'] ) ) : ?>
						<a href="<?php echo esc_url( (string) $vh_f['ticket_url'] ); ?>" target="_blank" rel="noopener noreferrer" class="vh-mono">
							<?php echo esc_html( (string) $vh_f['ticket_key'] ); ?>
						</a>
						<div class="vh-muted" style="font-size:11px"><?php echo esc_html( (string) $vh_f['ticket_status'] ); ?></div>
					<?php else : ?>
						<span class="vh-muted">—</span>
					<?php endif; ?>
				</td>
				<td>
					<div class="vh-actions">
						<?php if ( current_user_can( 'vulnhub_raise_ticket' ) && empty( $vh_f['ticket_key'] ) ) : ?>
							<button type="button" class="button button-small" data-vh-action="raise-ticket"
								data-vh-finding="<?php echo esc_attr( (string) $vh_f['id'] ); ?>"
								title="<?php esc_attr_e( 'Raise a Jira ticket for this finding', 'vulnhub' ); ?>">
								<?php esc_html_e( 'Ticket', 'vulnhub' ); ?>
							</button>
						<?php endif; ?>
						<?php if ( current_user_can( 'vulnhub_request_exception' ) && ! $vh_excepted ) : ?>
							<a class="button button-small"
								href="<?php echo esc_url( vh_admin_url( 'vulnhub-exceptions', array( 'new' => 1, 'finding' => (int) $vh_f['id'] ) ) ); ?>"
								title="<?php esc_attr_e( 'Request an exception for this finding', 'vulnhub' ); ?>">
								<?php esc_html_e( 'Except', 'vulnhub' ); ?>
							</a>
						<?php endif; ?>
					</div>
				</td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
</div>

<?php if ( $vh_pages > 1 ) : ?>
	<div class="tablenav bottom">
		<div class="tablenav-pages">
			<?php
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$vh_base = add_query_arg( array_map( 'sanitize_text_field', wp_unslash( $_GET ) ), admin_url( 'admin.php' ) );
			echo wp_kses_post(
				paginate_links(
					array(
						'base'      => add_query_arg( 'paged', '%#%', $vh_base ),
						'format'    => '',
						'total'     => $vh_pages,
						'current'   => $vh_page,
						'prev_text' => '&lsaquo;',
						'next_text' => '&rsaquo;',
					)
				) ?? ''
			);
			?>
		</div>
	</div>
<?php endif; ?>

<?php endif; ?>

