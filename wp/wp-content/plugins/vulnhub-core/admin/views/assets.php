<?php
/**
 * Asset inventory screen, with a single-asset detail panel.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

use VulnHub\Core\Repo;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.Security.NonceVerification.Recommended
$vh_asset_id = isset( $_GET['asset'] ) ? (int) $_GET['asset'] : 0;
// phpcs:enable

if ( $vh_asset_id ) {
	$vh_asset = Repo::asset( $vh_asset_id );

	if ( ! $vh_asset ) {
		echo '<div class="vh-card vh-empty"><h2>' . esc_html__( 'Asset not found', 'vulnhub' ) . '</h2></div>';
		return;
	}

	$vh_owner    = Repo::person( (int) $vh_asset['owner_person_id'] );
	$vh_team     = Repo::team( (int) $vh_asset['team_id'] );
	$vh_location = Repo::location( (int) $vh_asset['location_id'] );
	$vh_tags     = vh_json( (string) $vh_asset['tags_json'] );
	$vh_findings = Repo::findings(
		array(
			'asset_id' => $vh_asset_id,
			'state'    => 'open_any',
			'limit'    => 200,
		)
	);
	$vh_needs_user = in_array( (string) $vh_asset['asset_type'], vh_user_bound_asset_types(), true );
	?>

	<p style="margin:0 0 14px">
		<a href="<?php echo esc_url( vh_admin_url( 'vulnhub-assets' ) ); ?>">&larr; <?php esc_html_e( 'All assets', 'vulnhub' ); ?></a>
	</p>

	<div class="vh-grid vh-grid--2">
		<div class="vh-card">
			<h2><?php esc_html_e( 'Asset', 'vulnhub' ); ?></h2>
			<h3 class="vh-mono" style="font-size:18px;color:#1d2327;text-transform:none;letter-spacing:0;margin:0 0 12px">
				<?php echo esc_html( (string) $vh_asset['hostname'] ); ?>
			</h3>
			<div class="vh-detail">
				<dl>
					<dt><?php esc_html_e( 'FQDN', 'vulnhub' ); ?></dt>
					<dd class="vh-mono"><?php echo esc_html( (string) ( $vh_asset['fqdn'] ?: '—' ) ); ?></dd>
					<dt><?php esc_html_e( 'IPv4', 'vulnhub' ); ?></dt>
					<dd class="vh-mono"><?php echo esc_html( (string) ( $vh_asset['ipv4'] ?: '—' ) ); ?></dd>
					<dt><?php esc_html_e( 'Type', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( vh_asset_types()[ (string) $vh_asset['asset_type'] ] ?? (string) $vh_asset['asset_type'] ); ?></dd>
					<dt><?php esc_html_e( 'Operating system', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( trim( $vh_asset['operating_system'] . ' ' . $vh_asset['os_version'] ) ?: '—' ); ?></dd>
					<dt><?php esc_html_e( 'Hardware', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( trim( $vh_asset['manufacturer'] . ' ' . $vh_asset['model'] ) ?: '—' ); ?></dd>
					<dt><?php esc_html_e( 'Serial', 'vulnhub' ); ?></dt>
					<dd class="vh-mono"><?php echo esc_html( (string) ( $vh_asset['serial_number'] ?: '—' ) ); ?></dd>
					<dt><?php esc_html_e( 'Criticality', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( ucfirst( (string) $vh_asset['criticality'] ) ); ?></dd>
					<dt><?php esc_html_e( 'Compliance', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( (string) ( $vh_asset['compliance_state'] ?: '—' ) ); ?></dd>
					<dt><?php esc_html_e( 'Last seen', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( vh_date( (string) $vh_asset['last_seen'] ) ); ?></dd>
					<dt><?php esc_html_e( 'Tenable UUID', 'vulnhub' ); ?></dt>
					<dd class="vh-mono" style="font-size:11px"><?php echo esc_html( (string) ( $vh_asset['tenable_uuid'] ?: '—' ) ); ?></dd>
					<dt><?php esc_html_e( 'Intune id', 'vulnhub' ); ?></dt>
					<dd class="vh-mono" style="font-size:11px"><?php echo esc_html( (string) ( $vh_asset['intune_id'] ?: '—' ) ); ?></dd>
				</dl>
			</div>

			<?php if ( $vh_tags ) : ?>
				<h2 style="margin-top:18px"><?php esc_html_e( 'Tenable tags', 'vulnhub' ); ?></h2>
				<p>
					<?php foreach ( $vh_tags as $vh_tag ) : ?>
						<span class="vh-state" style="margin:0 4px 4px 0;display:inline-block">
							<?php echo esc_html( is_array( $vh_tag ) ? ( ( $vh_tag['key'] ?? '' ) . ': ' . ( $vh_tag['value'] ?? '' ) ) : (string) $vh_tag ); ?>
						</span>
					<?php endforeach; ?>
				</p>
			<?php endif; ?>
		</div>

		<div class="vh-card">
			<h2><?php esc_html_e( 'Ownership', 'vulnhub' ); ?></h2>

			<?php if ( $vh_needs_user && ! $vh_owner ) : ?>
				<div class="notice notice-warning inline" style="margin:0 0 14px">
					<p>
						<?php esc_html_e( 'This is a user-bound asset with no owner resolved. Intune did not report a primary user, or that user has not been synced yet.', 'vulnhub' ); ?>
					</p>
				</div>
			<?php endif; ?>

			<div class="vh-detail">
				<dl>
					<dt><?php esc_html_e( 'Owner', 'vulnhub' ); ?></dt>
					<dd>
						<?php if ( $vh_owner ) : ?>
							<strong><?php echo esc_html( (string) $vh_owner['display_name'] ); ?></strong><br>
							<span class="vh-muted"><?php echo esc_html( (string) $vh_owner['upn'] ); ?></span>
						<?php else : ?>
							<span class="vh-muted"><?php esc_html_e( 'Unassigned', 'vulnhub' ); ?></span>
						<?php endif; ?>
					</dd>
					<dt><?php esc_html_e( 'Job title', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( (string) ( $vh_owner['job_title'] ?? '—' ) ); ?></dd>
					<dt><?php esc_html_e( 'Department', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( (string) ( $vh_owner['department'] ?? '—' ) ); ?></dd>
					<dt><?php esc_html_e( 'Manager', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( (string) ( $vh_owner['manager_upn'] ?? '—' ) ); ?></dd>
					<dt><?php esc_html_e( 'Team', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( (string) ( $vh_team['name'] ?? '—' ) ); ?></dd>
					<dt><?php esc_html_e( 'Location', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( (string) ( $vh_location['name'] ?? ( $vh_owner['office_location'] ?? '—' ) ) ); ?></dd>
					<dt><?php esc_html_e( 'Resolved by', 'vulnhub' ); ?></dt>
					<dd class="vh-muted" style="font-size:12px"><?php echo esc_html( (string) ( $vh_asset['owner_rule'] ?: '—' ) ); ?></dd>
					<dt><?php esc_html_e( 'Source', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( (string) ( $vh_asset['owner_source'] ?: '—' ) ); ?></dd>
				</dl>
			</div>

			<h2 style="margin-top:20px"><?php esc_html_e( 'Open exposure', 'vulnhub' ); ?></h2>
			<div class="vh-grid vh-grid--4" style="gap:8px;margin:0">
				<?php foreach ( array( 'critical' => 'open_critical', 'high' => 'open_high', 'medium' => 'open_medium', 'low' => 'open_low' ) as $vh_sev => $vh_col ) : ?>
					<div style="text-align:center;padding:8px;border:1px solid var(--vh-line);border-radius:6px">
						<div style="font-size:22px;font-weight:600;color:<?php echo esc_attr( vh_severity_color( $vh_sev ) ); ?>">
							<?php echo esc_html( number_format_i18n( (int) $vh_asset[ $vh_col ] ) ); ?>
						</div>
						<div style="font-size:11px;text-transform:uppercase;color:var(--vh-muted)">
							<?php echo esc_html( vh_severity_label( $vh_sev ) ); ?>
						</div>
					</div>
				<?php endforeach; ?>
			</div>
		</div>
	</div>

	<h2 style="margin:24px 0 12px;font-size:15px"><?php esc_html_e( 'Open findings on this asset', 'vulnhub' ); ?></h2>
	<?php if ( ! $vh_findings['rows'] ) : ?>
		<div class="vh-card"><p class="vh-muted" style="margin:0"><?php esc_html_e( 'No open findings. Nice.', 'vulnhub' ); ?></p></div>
	<?php else : ?>
		<div class="vh-table-wrap">
			<table class="wp-list-table widefat fixed striped">
				<thead>
					<tr>
						<th style="width:88px"><?php esc_html_e( 'Severity', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Vulnerability', 'vulnhub' ); ?></th>
						<th style="width:110px"><?php esc_html_e( 'First found', 'vulnhub' ); ?></th>
						<th style="width:110px"><?php esc_html_e( 'Due', 'vulnhub' ); ?></th>
						<th style="width:130px"><?php esc_html_e( 'Ticket', 'vulnhub' ); ?></th>
						<th style="width:90px"><?php esc_html_e( 'Actions', 'vulnhub' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $vh_findings['rows'] as $vh_f ) : ?>
					<tr>
						<td><?php echo wp_kses_post( vh_severity_pill( (string) $vh_f['severity'] ) ); ?></td>
						<td>
							<strong><?php echo esc_html( vh_trim( (string) $vh_f['vuln_title'], 90 ) ); ?></strong>
							<?php if ( ! empty( $vh_f['solution'] ) ) : ?>
								<div class="vh-muted" style="font-size:11px;margin-top:3px">
									<?php echo esc_html( vh_trim( (string) $vh_f['solution'], 130 ) ); ?>
								</div>
							<?php endif; ?>
						</td>
						<td class="vh-muted vh-nowrap"><?php echo esc_html( vh_ago( (string) $vh_f['first_found'] ) ); ?></td>
						<td class="vh-nowrap"><?php echo esc_html( $vh_f['due_at'] ? vh_ago( (string) $vh_f['due_at'] ) : '—' ); ?></td>
						<td>
							<?php if ( ! empty( $vh_f['ticket_key'] ) ) : ?>
								<a class="vh-mono" href="<?php echo esc_url( (string) $vh_f['ticket_url'] ); ?>" target="_blank" rel="noopener noreferrer">
									<?php echo esc_html( (string) $vh_f['ticket_key'] ); ?>
								</a>
							<?php else : ?>
								<span class="vh-muted">—</span>
							<?php endif; ?>
						</td>
						<td>
							<?php if ( current_user_can( 'vulnhub_raise_ticket' ) && empty( $vh_f['ticket_key'] ) ) : ?>
								<button type="button" class="button button-small" data-vh-action="raise-ticket"
									data-vh-finding="<?php echo esc_attr( (string) $vh_f['id'] ); ?>">
									<?php esc_html_e( 'Ticket', 'vulnhub' ); ?>
								</button>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	<?php endif; ?>

	<?php
	return;
}

// ---------------------------------------------------------------- list view.
// phpcs:disable WordPress.Security.NonceVerification.Recommended
$vh_page = max( 1, isset( $_GET['paged'] ) ? (int) $_GET['paged'] : 1 );
$vh_per  = 40;
$vh_args = array(
	'search'     => isset( $_GET['search'] ) ? sanitize_text_field( wp_unslash( $_GET['search'] ) ) : '',
	'asset_type' => isset( $_GET['asset_type'] ) ? sanitize_key( wp_unslash( $_GET['asset_type'] ) ) : '',
	'team_id'    => isset( $_GET['team_id'] ) ? (int) $_GET['team_id'] : 0,
	'needs_user' => isset( $_GET['needs_user'] ) ? 1 : 0,
	'unowned'    => isset( $_GET['unowned'] ) ? 1 : 0,
);
// phpcs:enable

$vh_query = Repo::assets(
	array_merge(
		array_filter( $vh_args, static fn( $v ): bool => '' !== $v && 0 !== $v ),
		array(
			'limit'  => $vh_per,
			'offset' => ( $vh_page - 1 ) * $vh_per,
		)
	)
);
$vh_pages = max( 1, (int) ceil( $vh_query['total'] / $vh_per ) );
$vh_teams = Repo::teams();
?>

<form method="get" class="vh-filters">
	<input type="hidden" name="page" value="vulnhub-assets">
	<label>
		<?php esc_html_e( 'Search', 'vulnhub' ); ?>
		<input type="search" name="search" value="<?php echo esc_attr( (string) $vh_args['search'] ); ?>"
			placeholder="<?php esc_attr_e( 'hostname, IP, serial…', 'vulnhub' ); ?>">
	</label>
	<label>
		<?php esc_html_e( 'Type', 'vulnhub' ); ?>
		<select name="asset_type" data-vh-autosubmit>
			<option value=""><?php esc_html_e( 'All types', 'vulnhub' ); ?></option>
			<?php foreach ( vh_asset_types() as $vh_slug => $vh_label ) : ?>
				<option value="<?php echo esc_attr( $vh_slug ); ?>" <?php selected( $vh_args['asset_type'], $vh_slug ); ?>>
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
				<option value="<?php echo esc_attr( (string) $vh_t['id'] ); ?>" <?php selected( $vh_args['team_id'], (int) $vh_t['id'] ); ?>>
					<?php echo esc_html( (string) $vh_t['name'] ); ?>
				</option>
			<?php endforeach; ?>
		</select>
	</label>
	<label style="flex-direction:row;align-items:center;gap:6px;text-transform:none;font-weight:400">
		<input type="checkbox" name="needs_user" value="1" <?php checked( (int) $vh_args['needs_user'], 1 ); ?> data-vh-autosubmit>
		<?php esc_html_e( 'Missing a user', 'vulnhub' ); ?>
	</label>
	<label style="flex-direction:row;align-items:center;gap:6px;text-transform:none;font-weight:400">
		<input type="checkbox" name="unowned" value="1" <?php checked( (int) $vh_args['unowned'], 1 ); ?> data-vh-autosubmit>
		<?php esc_html_e( 'No owner at all', 'vulnhub' ); ?>
	</label>
	<button class="button button-primary"><?php esc_html_e( 'Filter', 'vulnhub' ); ?></button>
	<a class="button" href="<?php echo esc_url( vh_admin_url( 'vulnhub-assets' ) ); ?>"><?php esc_html_e( 'Reset', 'vulnhub' ); ?></a>
</form>

<p class="vh-muted">
	<?php
	printf(
		/* translators: %s: number of assets. */
		esc_html( _n( '%s asset', '%s assets', (int) $vh_query['total'], 'vulnhub' ) ),
		'<strong>' . esc_html( number_format_i18n( (int) $vh_query['total'] ) ) . '</strong>'
	);
	?>
</p>

<?php if ( ! $vh_query['rows'] ) : ?>
	<div class="vh-card vh-empty">
		<span class="dashicons dashicons-desktop"></span>
		<h2><?php esc_html_e( 'No assets yet', 'vulnhub' ); ?></h2>
		<p><?php esc_html_e( 'Run a Tenable or Intune sync to populate the inventory.', 'vulnhub' ); ?></p>
		<a class="button button-primary" href="<?php echo esc_url( vh_admin_url( 'vulnhub-integrations' ) ); ?>">
			<?php esc_html_e( 'Go to integrations', 'vulnhub' ); ?>
		</a>
	</div>
<?php else : ?>
<div class="vh-table-wrap">
	<table class="wp-list-table widefat fixed striped">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Host', 'vulnhub' ); ?></th>
				<th style="width:110px"><?php esc_html_e( 'Type', 'vulnhub' ); ?></th>
				<th style="width:190px"><?php esc_html_e( 'Operating system', 'vulnhub' ); ?></th>
				<th style="width:180px"><?php esc_html_e( 'Owner', 'vulnhub' ); ?></th>
				<th style="width:140px"><?php esc_html_e( 'Team', 'vulnhub' ); ?></th>
				<th style="width:150px"><?php esc_html_e( 'Open C/H/M/L', 'vulnhub' ); ?></th>
				<th style="width:110px"><?php esc_html_e( 'Last seen', 'vulnhub' ); ?></th>
			</tr>
		</thead>
		<tbody>
		<?php foreach ( $vh_query['rows'] as $vh_a ) : ?>
			<?php
			$vh_owner  = Repo::person( (int) $vh_a['owner_person_id'] );
			$vh_team   = Repo::team( (int) $vh_a['team_id'] );
			$vh_needs  = in_array( (string) $vh_a['asset_type'], vh_user_bound_asset_types(), true );
			?>
			<tr>
				<td>
					<a class="vh-mono" href="<?php echo esc_url( vh_admin_url( 'vulnhub-assets', array( 'asset' => (int) $vh_a['id'] ) ) ); ?>">
						<strong><?php echo esc_html( (string) $vh_a['hostname'] ); ?></strong>
					</a>
					<div class="vh-muted" style="font-size:11px"><?php echo esc_html( (string) $vh_a['ipv4'] ); ?></div>
				</td>
				<td><?php echo esc_html( vh_asset_types()[ (string) $vh_a['asset_type'] ] ?? (string) $vh_a['asset_type'] ); ?></td>
				<td><?php echo esc_html( vh_trim( trim( $vh_a['operating_system'] . ' ' . $vh_a['os_version'] ), 34 ) ); ?></td>
				<td>
					<?php if ( $vh_owner ) : ?>
						<?php echo esc_html( (string) $vh_owner['display_name'] ); ?>
					<?php elseif ( $vh_needs ) : ?>
						<span class="vh-state vh-state--open"><?php esc_html_e( 'Missing', 'vulnhub' ); ?></span>
					<?php else : ?>
						<span class="vh-muted">—</span>
					<?php endif; ?>
				</td>
				<td><?php echo esc_html( (string) ( $vh_team['name'] ?? '—' ) ); ?></td>
				<td class="vh-mono">
					<span style="color:var(--vh-crit);font-weight:600"><?php echo esc_html( (string) $vh_a['open_critical'] ); ?></span> /
					<span style="color:var(--vh-high);font-weight:600"><?php echo esc_html( (string) $vh_a['open_high'] ); ?></span> /
					<?php echo esc_html( $vh_a['open_medium'] . ' / ' . $vh_a['open_low'] ); ?>
				</td>
				<td class="vh-muted vh-nowrap"><?php echo esc_html( vh_ago( (string) $vh_a['last_seen'] ) ); ?></td>
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
						'base'    => add_query_arg( 'paged', '%#%', $vh_base ),
						'format'  => '',
						'total'   => $vh_pages,
						'current' => $vh_page,
					)
				) ?? ''
			);
			?>
		</div>
	</div>
<?php endif; ?>
<?php endif; ?>

