<?php
/**
 * Intune & Entra ID admin screen.
 *
 * Rendered by core through the `vulnhub_render_admin_page` action, inside
 * core's own <div class="wrap vulnhub-wrap"> and page header, so this file
 * only emits the body of the screen and reuses core's CSS classes.
 *
 * @package VulnHub\Intune
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

global $wpdb;

$vh_assets  = vh_table( 'assets' );
$vh_people  = vh_table( 'people' );
$vh_source  = VulnHub_Intune_Connector::SOURCE;
$vh_conn    = function_exists( 'vulnhub' ) ? vulnhub()->connectors->get( $vh_source ) : null;
$vh_health  = $vh_conn ? $vh_conn->health() : array(
	'state'  => 'off',
	'label'  => __( 'Not registered', 'vulnhub' ),
	'detail' => '',
);
$vh_summary = (array) get_option( 'vulnhub_intune_last_summary', array() );
$vh_last    = function_exists( 'vulnhub' ) ? vulnhub()->logger->last_run( $vh_source ) : null;

// phpcs:disable WordPress.Security.NonceVerification.Recommended
$vh_notice = isset( $_GET['vh_intune'] ) ? sanitize_key( wp_unslash( $_GET['vh_intune'] ) ) : '';
// phpcs:enable

$vh_people_count = (int) $wpdb->get_var(
	$wpdb->prepare( "SELECT COUNT(*) FROM {$vh_people} WHERE source = %s", $vh_source ) // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
);
$vh_device_count = (int) $wpdb->get_var(
	$wpdb->prepare( "SELECT COUNT(*) FROM {$vh_assets} WHERE intune_id <> %s", '' ) // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
);
$vh_owned_count  = (int) $wpdb->get_var(
	$wpdb->prepare( "SELECT COUNT(*) FROM {$vh_assets} WHERE intune_id <> %s AND owner_person_id > 0", '' ) // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
);

/** @var array<int,array<string,mixed>> $vh_compliance */
$vh_compliance = (array) $wpdb->get_results(
	$wpdb->prepare(
		"SELECT compliance_state AS k, COUNT(*) AS n FROM {$vh_assets} WHERE intune_id <> %s GROUP BY compliance_state ORDER BY n DESC", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		''
	),
	ARRAY_A
);

/** @var array<int,array<string,mixed>> $vh_enrollment */
$vh_enrollment = (array) $wpdb->get_results(
	$wpdb->prepare(
		"SELECT enrollment_type AS k, COUNT(*) AS n FROM {$vh_assets} WHERE intune_id <> %s GROUP BY enrollment_type ORDER BY n DESC", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		''
	),
	ARRAY_A
);

/** @var array<int,array<string,mixed>> $vh_orphans */
$vh_orphans = (array) $wpdb->get_results(
	$wpdb->prepare(
		"SELECT id, hostname, asset_type, operating_system, model, compliance_state, raw_json, last_intune_sync
		 FROM {$vh_assets}
		 WHERE intune_id <> %s AND owner_person_id = 0
		 ORDER BY asset_type ASC, hostname ASC
		 LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		'',
		100
	),
	ARRAY_A
);

$vh_checklist = '';
foreach ( VulnHub_Intune_Connector::required_permissions() as $vh_perm ) {
	$vh_checklist .= '[ ] ' . $vh_perm['name'] . ' (application permission, admin consent required)' . "\n";
}
?>

<?php if ( 'synced' === $vh_notice ) : ?>
	<div class="notice notice-success"><p><?php esc_html_e( 'Intune sync finished.', 'vulnhub' ); ?></p></div>
<?php elseif ( 'failed' === $vh_notice ) : ?>
	<div class="notice notice-error"><p><?php esc_html_e( 'The Intune sync failed. Check the sync activity log for detail.', 'vulnhub' ); ?></p></div>
<?php elseif ( 'missing' === $vh_notice ) : ?>
	<div class="notice notice-error"><p><?php esc_html_e( 'The Intune connector is not registered.', 'vulnhub' ); ?></p></div>
<?php endif; ?>

<div class="vh-grid vh-grid--4" style="margin-bottom:16px">
	<div class="vh-card">
		<h2><?php esc_html_e( 'People synced', 'vulnhub' ); ?></h2>
		<p style="font-size:28px;margin:6px 0 0"><?php echo esc_html( number_format_i18n( $vh_people_count ) ); ?></p>
		<p class="vh-muted" style="margin:4px 0 0"><?php esc_html_e( 'From Entra ID', 'vulnhub' ); ?></p>
	</div>
	<div class="vh-card">
		<h2><?php esc_html_e( 'Devices synced', 'vulnhub' ); ?></h2>
		<p style="font-size:28px;margin:6px 0 0"><?php echo esc_html( number_format_i18n( $vh_device_count ) ); ?></p>
		<p class="vh-muted" style="margin:4px 0 0"><?php esc_html_e( 'Intune-managed', 'vulnhub' ); ?></p>
	</div>
	<div class="vh-card">
		<h2><?php esc_html_e( 'Ownership resolved', 'vulnhub' ); ?></h2>
		<p style="font-size:28px;margin:6px 0 0">
			<?php
			echo esc_html(
				$vh_device_count > 0
					? number_format_i18n( (int) round( $vh_owned_count / $vh_device_count * 100 ) ) . '%'
					: '—'
			);
			?>
		</p>
		<p class="vh-muted" style="margin:4px 0 0">
			<?php
			printf(
				/* translators: 1: owned devices, 2: total devices. */
				esc_html__( '%1$s of %2$s have an owner', 'vulnhub' ),
				esc_html( number_format_i18n( $vh_owned_count ) ),
				esc_html( number_format_i18n( $vh_device_count ) )
			);
			?>
		</p>
	</div>
	<div class="vh-card">
		<h2><?php esc_html_e( 'No primary user', 'vulnhub' ); ?></h2>
		<p style="font-size:28px;margin:6px 0 0"><?php echo esc_html( number_format_i18n( count( $vh_orphans ) ) ); ?></p>
		<p class="vh-muted" style="margin:4px 0 0"><?php esc_html_e( 'Shown below (max 100)', 'vulnhub' ); ?></p>
	</div>
</div>

<div class="vh-card" style="margin-bottom:16px">
	<h2><?php esc_html_e( 'Connection', 'vulnhub' ); ?></h2>
	<div class="vh-detail">
		<dl>
			<dt><?php esc_html_e( 'Status', 'vulnhub' ); ?></dt>
			<dd>
				<span class="vh-state vh-state--<?php echo 'ok' === $vh_health['state'] ? 'fixed' : 'open'; ?>">
					<?php echo esc_html( (string) $vh_health['label'] ); ?>
				</span>
				<span class="vh-muted"><?php echo esc_html( (string) $vh_health['detail'] ); ?></span>
			</dd>
			<dt><?php esc_html_e( 'Tenant ID', 'vulnhub' ); ?></dt>
			<dd class="vh-mono">
				<?php
				$vh_tenant = $vh_conn ? (string) $vh_conn->get( 'tenant_id', '' ) : '';
				echo esc_html( '' !== $vh_tenant ? $vh_tenant : __( 'not set', 'vulnhub' ) );
				?>
			</dd>
			<dt><?php esc_html_e( 'Application (client) ID', 'vulnhub' ); ?></dt>
			<dd class="vh-mono">
				<?php
				$vh_client = $vh_conn ? (string) $vh_conn->get( 'client_id', '' ) : '';
				echo esc_html( '' !== $vh_client ? $vh_client : __( 'not set', 'vulnhub' ) );
				?>
			</dd>
			<dt><?php esc_html_e( 'Graph endpoint', 'vulnhub' ); ?></dt>
			<dd class="vh-mono"><?php echo esc_html( $vh_conn ? (string) $vh_conn->get( 'base_url', 'https://graph.microsoft.com/v1.0' ) : '' ); ?></dd>
			<dt><?php esc_html_e( 'Data source', 'vulnhub' ); ?></dt>
			<dd>
				<?php
				echo esc_html(
					$vh_conn && $vh_conn->is_mock()
						? __( 'Generated mock tenant (no credentials used)', 'vulnhub' )
						: __( 'Live Microsoft Graph', 'vulnhub' )
				);
				?>
			</dd>
			<dt><?php esc_html_e( 'Team source', 'vulnhub' ); ?></dt>
			<dd><?php echo esc_html( $vh_conn ? (string) $vh_conn->get( 'team_source', 'department' ) : '' ); ?></dd>
			<dt><?php esc_html_e( 'Group memberships', 'vulnhub' ); ?></dt>
			<dd>
				<?php
				echo esc_html(
					$vh_conn && vulnhub()->settings->get_bool( $vh_source, 'sync_groups' )
						? __( 'Synced', 'vulnhub' )
						: __( 'Not synced', 'vulnhub' )
				);
				?>
			</dd>
			<dt><?php esc_html_e( 'Last run', 'vulnhub' ); ?></dt>
			<dd>
				<?php if ( $vh_last ) : ?>
					<?php echo esc_html( vh_ago( (string) $vh_last['finished_at'] ) ); ?>
					&mdash; <?php echo esc_html( vh_trim( (string) $vh_last['message'], 200 ) ); ?>
				<?php else : ?>
					<span class="vh-muted"><?php esc_html_e( 'Never', 'vulnhub' ); ?></span>
				<?php endif; ?>
			</dd>
			<?php if ( ! empty( $vh_summary['requests'] ) ) : ?>
				<dt><?php esc_html_e( 'Graph requests last run', 'vulnhub' ); ?></dt>
				<dd><?php echo esc_html( number_format_i18n( (int) $vh_summary['requests'] ) ); ?></dd>
			<?php endif; ?>
		</dl>
	</div>

	<?php if ( current_user_can( 'vulnhub_run_sync' ) ) : ?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-form" style="margin-top:12px">
			<?php wp_nonce_field( 'vulnhub_intune_sync' ); ?>
			<input type="hidden" name="action" value="vulnhub_intune_sync" />
			<button type="submit" class="button button-primary"><?php esc_html_e( 'Sync Intune now', 'vulnhub' ); ?></button>
			<a class="button" href="<?php echo esc_url( vh_admin_url( 'vulnhub-integrations' ) ); ?>"><?php esc_html_e( 'Settings', 'vulnhub' ); ?></a>
			<a class="button" href="<?php echo esc_url( vh_admin_url( 'vulnhub-sync', array( 'connector' => $vh_source ) ) ); ?>"><?php esc_html_e( 'Run log', 'vulnhub' ); ?></a>
		</form>
	<?php endif; ?>
</div>

<div class="vh-grid vh-grid--2" style="margin-bottom:16px">
	<div class="vh-card">
		<h2><?php esc_html_e( 'Devices by compliance state', 'vulnhub' ); ?></h2>
		<?php if ( ! $vh_compliance ) : ?>
			<p class="vh-muted" style="margin:0"><?php esc_html_e( 'No Intune devices yet.', 'vulnhub' ); ?></p>
		<?php else : ?>
			<div class="vh-table-wrap">
				<table class="widefat striped">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Compliance state', 'vulnhub' ); ?></th>
							<th style="width:90px"><?php esc_html_e( 'Devices', 'vulnhub' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $vh_compliance as $vh_row ) : ?>
							<tr>
								<td><?php echo esc_html( '' !== (string) $vh_row['k'] ? (string) $vh_row['k'] : __( '(not reported)', 'vulnhub' ) ); ?></td>
								<td><?php echo esc_html( number_format_i18n( (int) $vh_row['n'] ) ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		<?php endif; ?>
	</div>

	<div class="vh-card">
		<h2><?php esc_html_e( 'Devices by enrolment type', 'vulnhub' ); ?></h2>
		<?php if ( ! $vh_enrollment ) : ?>
			<p class="vh-muted" style="margin:0"><?php esc_html_e( 'No Intune devices yet.', 'vulnhub' ); ?></p>
		<?php else : ?>
			<div class="vh-table-wrap">
				<table class="widefat striped">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Enrolment type', 'vulnhub' ); ?></th>
							<th style="width:90px"><?php esc_html_e( 'Devices', 'vulnhub' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $vh_enrollment as $vh_row ) : ?>
							<tr>
								<td class="vh-mono"><?php echo esc_html( '' !== (string) $vh_row['k'] ? (string) $vh_row['k'] : __( '(not reported)', 'vulnhub' ) ); ?></td>
								<td><?php echo esc_html( number_format_i18n( (int) $vh_row['n'] ) ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		<?php endif; ?>
	</div>
</div>

<div class="vh-card" style="margin-bottom:16px">
	<h2><?php esc_html_e( 'Devices with no primary user', 'vulnhub' ); ?></h2>
	<p class="vh-muted" style="margin-top:0">
		<?php esc_html_e( 'Shared, kiosk and device-enrolled machines legitimately have no primary user in Intune. Everything else in this list is a workstation nobody is accountable for.', 'vulnhub' ); ?>
	</p>
	<?php if ( ! $vh_orphans ) : ?>
		<div class="vh-empty"><p><?php esc_html_e( 'Every Intune device has an owner. Nothing to chase.', 'vulnhub' ); ?></p></div>
	<?php else : ?>
		<div class="vh-table-wrap">
			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Hostname', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Type', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Operating system', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Model', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Reported user', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Last Intune sync', 'vulnhub' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php
					foreach ( $vh_orphans as $vh_row ) :
						$vh_raw     = vh_json( isset( $vh_row['raw_json'] ) ? (string) $vh_row['raw_json'] : null );
						$vh_reported = (string) ( $vh_raw['intune']['userPrincipalName'] ?? '' );
						?>
						<tr>
							<td>
								<a href="<?php echo esc_url( vh_admin_url( 'vulnhub-assets', array( 'asset' => (int) $vh_row['id'] ) ) ); ?>">
									<?php echo esc_html( (string) $vh_row['hostname'] ); ?>
								</a>
							</td>
							<td><?php echo esc_html( vh_asset_types()[ (string) $vh_row['asset_type'] ] ?? (string) $vh_row['asset_type'] ); ?></td>
							<td><?php echo esc_html( trim( (string) $vh_row['operating_system'] ) ); ?></td>
							<td><?php echo esc_html( (string) $vh_row['model'] ); ?></td>
							<td class="vh-mono">
								<?php
								echo '' !== $vh_reported
									? esc_html( $vh_reported )
									: '<span class="vh-muted">' . esc_html__( 'none — userless device', 'vulnhub' ) . '</span>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
								?>
							</td>
							<td><?php echo esc_html( vh_date( (string) $vh_row['last_intune_sync'] ) ); ?></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	<?php endif; ?>
</div>

<div class="vh-card">
	<h2><?php esc_html_e( 'Entra ID app registration', 'vulnhub' ); ?></h2>
	<p class="vh-muted" style="margin-top:0">
		<?php esc_html_e( 'Add these as APPLICATION permissions (not delegated) on the app registration, then click "Grant admin consent for {tenant}". Every one of them requires a tenant administrator; without consent Graph answers 403 and the sync imports nothing.', 'vulnhub' ); ?>
	</p>
	<div class="vh-table-wrap">
		<table class="widefat striped">
			<thead>
				<tr>
					<th style="width:320px"><?php esc_html_e( 'Permission', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'What it is for', 'vulnhub' ); ?></th>
					<th style="width:180px"><?php esc_html_e( 'Consent', 'vulnhub' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( VulnHub_Intune_Connector::required_permissions() as $vh_perm ) : ?>
					<tr>
						<td class="vh-mono"><?php echo esc_html( $vh_perm['name'] ); ?></td>
						<td><?php echo esc_html( $vh_perm['why'] ); ?></td>
						<td><span class="vh-pill vh-sev-medium"><?php echo esc_html( $vh_perm['consent'] ); ?></span></td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
	</div>
	<p style="margin-bottom:4px"><strong><?php esc_html_e( 'Copyable checklist', 'vulnhub' ); ?></strong></p>
	<textarea readonly rows="<?php echo esc_attr( (string) ( count( VulnHub_Intune_Connector::required_permissions() ) + 1 ) ); ?>" style="width:100%;font-family:monospace" onclick="this.select();"><?php echo esc_textarea( $vh_checklist ); ?></textarea>
</div>

