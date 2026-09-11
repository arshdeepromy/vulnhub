<?php
/**
 * Tenable integration screen.
 *
 * Rendered by core via the `vulnhub_render_admin_page` action, inside the
 * standard `.vulnhub-wrap` shell, so it reuses core's CSS classes throughout.
 *
 * @package VulnHub\Tenable
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! current_user_can( 'vulnhub_view' ) ) {
	wp_die( esc_html__( 'You do not have permission to view this screen.', 'vulnhub' ) );
}

global $wpdb;

$vh_tn_settings  = vulnhub()->settings;
$vh_tn_connector = vulnhub()->connectors->get( 'tenable' );
$vh_tn_health    = $vh_tn_connector ? $vh_tn_connector->health() : array(
	'state'  => 'off',
	'label'  => __( 'Not registered', 'vulnhub' ),
	'detail' => '',
);

$vh_tn_last    = (array) $vh_tn_settings->get( 'tenable', 'last_import', array() );
$vh_tn_when    = (string) $vh_tn_settings->get( 'tenable', 'last_import_at', '' );
$vh_tn_mode    = (string) $vh_tn_settings->get( 'tenable', 'last_import_mode', '' );
$vh_tn_jobs    = (array) $vh_tn_settings->get( 'tenable', 'export_jobs', array() );
$vh_tn_verify  = (array) $vh_tn_settings->get( 'tenable', 'verify_log', array() );
$vh_tn_labels  = \VulnHub\Core\Tickets::verification_labels();

/* --- Live counts for everything this connector owns --------------------- */

/*
 * Counted from `sources_json`, not `primary_source`. The latter records only
 * which feed first created the row, so a host the CMDB registered before
 * Tenable ever scanned it would not be counted here -- even though Tenable
 * knows it perfectly well and this page exists to say so.
 */
$vh_tn_like = '%' . $wpdb->esc_like( '"tenable"' ) . '%';

$vh_tn_assets = (int) $wpdb->get_var(
	$wpdb->prepare( 'SELECT COUNT(*) FROM ' . vh_table( 'assets' ) . ' WHERE sources_json LIKE %s', $vh_tn_like )
);
$vh_tn_defs = (int) $wpdb->get_var(
	$wpdb->prepare( 'SELECT COUNT(*) FROM ' . vh_table( 'vulns' ) . ' WHERE source = %s', 'tenable' )
);
$vh_tn_rows = (array) $wpdb->get_results(
	$wpdb->prepare(
		'SELECT severity, state, COUNT(*) AS n FROM ' . vh_table( 'findings' ) . ' WHERE source = %s GROUP BY severity, state',
		'tenable'
	),
	ARRAY_A
);
$vh_tn_types = (array) $wpdb->get_results(
	$wpdb->prepare(
		'SELECT asset_type, COUNT(*) AS n FROM ' . vh_table( 'assets' ) . ' WHERE sources_json LIKE %s GROUP BY asset_type ORDER BY n DESC',
		$vh_tn_like
	),
	ARRAY_A
);

$vh_tn_dist = array();
foreach ( array_keys( vh_severities() ) as $vh_tn_sev ) {
	$vh_tn_dist[ $vh_tn_sev ] = array(
		'open'  => 0,
		'fixed' => 0,
		'total' => 0,
	);
}

$vh_tn_findings = 0;
$vh_tn_fixed    = 0;

foreach ( $vh_tn_rows as $vh_tn_row ) {
	$vh_tn_sev = (string) $vh_tn_row['severity'];
	if ( ! isset( $vh_tn_dist[ $vh_tn_sev ] ) ) {
		continue;
	}

	$vh_tn_n         = (int) $vh_tn_row['n'];
	$vh_tn_findings += $vh_tn_n;

	$vh_tn_dist[ $vh_tn_sev ]['total'] += $vh_tn_n;

	if ( 'fixed' === (string) $vh_tn_row['state'] ) {
		$vh_tn_dist[ $vh_tn_sev ]['fixed'] += $vh_tn_n;
		$vh_tn_fixed                       += $vh_tn_n;
	} else {
		$vh_tn_dist[ $vh_tn_sev ]['open'] += $vh_tn_n;
	}
}

$vh_tn_scale = max( 1, $vh_tn_findings );
?>

<div class="vh-grid vh-grid--4">
	<div class="vh-card">
		<h2><?php esc_html_e( 'Assets imported', 'vulnhub' ); ?></h2>
		<p class="vh-card__value"><?php echo esc_html( number_format_i18n( $vh_tn_assets ) ); ?></p>
		<p class="vh-card__meta">
			<?php
			printf(
				/* translators: %s: number of assets created on the last run. */
				esc_html__( '%s new on the last run', 'vulnhub' ),
				'<strong>' . esc_html( number_format_i18n( (int) ( $vh_tn_last['assets_created'] ?? 0 ) ) ) . '</strong>'
			);
			?>
		</p>
	</div>

	<div class="vh-card">
		<h2><?php esc_html_e( 'Plugin definitions', 'vulnhub' ); ?></h2>
		<p class="vh-card__value"><?php echo esc_html( number_format_i18n( $vh_tn_defs ) ); ?></p>
		<p class="vh-card__meta"><?php esc_html_e( 'distinct Tenable plugins in the catalogue', 'vulnhub' ); ?></p>
	</div>

	<div class="vh-card">
		<h2><?php esc_html_e( 'Findings', 'vulnhub' ); ?></h2>
		<p class="vh-card__value"><?php echo esc_html( number_format_i18n( $vh_tn_findings ) ); ?></p>
		<p class="vh-card__meta">
			<?php
			printf(
				/* translators: %s: number of remediated findings. */
				esc_html__( 'including %s already remediated', 'vulnhub' ),
				'<strong>' . esc_html( number_format_i18n( $vh_tn_fixed ) ) . '</strong>'
			);
			?>
		</p>
	</div>

	<div class="vh-card <?php echo esc_attr( 'ok' === $vh_tn_health['state'] || 'mock' === $vh_tn_health['state'] ? 'vh-card--ok' : 'vh-card--warn' ); ?>">
		<h2><?php esc_html_e( 'Connector health', 'vulnhub' ); ?></h2>
		<p class="vh-card__value" style="font-size:20px"><?php echo esc_html( (string) $vh_tn_health['label'] ); ?></p>
		<p class="vh-card__meta"><?php echo esc_html( vh_trim( (string) $vh_tn_health['detail'], 120 ) ); ?></p>
	</div>
</div>

<div class="vh-grid vh-grid--2">

	<div class="vh-card">
		<h2><?php esc_html_e( 'Severity distribution imported', 'vulnhub' ); ?></h2>

		<?php if ( 0 === $vh_tn_findings ) : ?>
			<div class="vh-empty">
				<p><?php esc_html_e( 'Nothing imported yet. Enable the connector on the Integrations screen and run a sync — mock mode needs no credentials.', 'vulnhub' ); ?></p>
				<a class="button button-primary" href="<?php echo esc_url( vh_admin_url( 'vulnhub-integrations', array( 'connector' => 'tenable' ) ) ); ?>">
					<?php esc_html_e( 'Configure Tenable', 'vulnhub' ); ?>
				</a>
			</div>
		<?php else : ?>
			<div class="vh-bar">
				<?php foreach ( $vh_tn_dist as $vh_tn_sev => $vh_tn_counts ) : ?>
					<span style="width:<?php echo esc_attr( (string) round( ( $vh_tn_counts['total'] / $vh_tn_scale ) * 100, 2 ) ); ?>%;background:<?php echo esc_attr( vh_severity_color( $vh_tn_sev ) ); ?>"
						title="<?php echo esc_attr( vh_severity_label( $vh_tn_sev ) . ': ' . $vh_tn_counts['total'] ); ?>"></span>
				<?php endforeach; ?>
			</div>

			<div class="vh-table-wrap" style="margin-top:12px">
				<table class="wp-list-table widefat striped">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Severity', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'Open', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'Fixed', 'vulnhub' ); ?></th>
							<th><?php esc_html_e( 'Total', 'vulnhub' ); ?></th>
							<th></th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $vh_tn_dist as $vh_tn_sev => $vh_tn_counts ) : ?>
						<tr>
							<td><?php echo wp_kses_post( vh_severity_pill( $vh_tn_sev ) ); ?></td>
							<td><strong><?php echo esc_html( number_format_i18n( $vh_tn_counts['open'] ) ); ?></strong></td>
							<td class="vh-muted"><?php echo esc_html( number_format_i18n( $vh_tn_counts['fixed'] ) ); ?></td>
							<td><?php echo esc_html( number_format_i18n( $vh_tn_counts['total'] ) ); ?></td>
							<td class="vh-nowrap">
								<a href="<?php echo esc_url( vh_admin_url( 'vulnhub-findings', array( 'severity' => $vh_tn_sev, 'state' => 'open_any' ) ) ); ?>">
									<?php esc_html_e( 'View', 'vulnhub' ); ?> &rarr;
								</a>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		<?php endif; ?>
	</div>

	<div class="vh-card">
		<h2><?php esc_html_e( 'Last import', 'vulnhub' ); ?></h2>

		<?php if ( ! $vh_tn_last ) : ?>
			<div class="vh-empty"><p><?php esc_html_e( 'No Tenable sync has completed yet.', 'vulnhub' ); ?></p></div>
		<?php else : ?>
			<p class="vh-muted">
				<?php
				printf(
					/* translators: 1: relative time, 2: mock or live. */
					esc_html__( 'Completed %1$s against %2$s data.', 'vulnhub' ),
					esc_html( vh_ago( $vh_tn_when ) ),
					esc_html( 'mock' === $vh_tn_mode ? __( 'generated sample', 'vulnhub' ) : __( 'live Tenable', 'vulnhub' ) )
				);
				?>
			</p>

			<div class="vh-table-wrap">
				<table class="wp-list-table widefat striped">
					<tbody>
					<?php
					$vh_tn_metrics = array(
						'assets'            => __( 'Assets processed', 'vulnhub' ),
						'assets_created'    => __( 'Assets created', 'vulnhub' ),
						'assets_updated'    => __( 'Assets updated', 'vulnhub' ),
						'assets_skipped'    => __( 'Assets skipped', 'vulnhub' ),
						'vulns'             => __( 'Vulnerability definitions upserted', 'vulnhub' ),
						'findings'          => __( 'Findings imported', 'vulnhub' ),
						'findings_created'  => __( 'Findings first seen', 'vulnhub' ),
						'findings_fixed'    => __( 'Findings already remediated', 'vulnhub' ),
						'findings_reopened' => __( 'Findings reopened', 'vulnhub' ),
						'findings_skipped'  => __( 'Findings skipped', 'vulnhub' ),
					);
					foreach ( $vh_tn_metrics as $vh_tn_key => $vh_tn_label ) :
						?>
						<tr>
							<td><?php echo esc_html( $vh_tn_label ); ?></td>
							<td style="width:90px;text-align:right">
								<strong><?php echo esc_html( number_format_i18n( (int) ( $vh_tn_last[ $vh_tn_key ] ?? 0 ) ) ); ?></strong>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		<?php endif; ?>

		<?php if ( $vh_tn_types ) : ?>
			<h2 style="margin-top:18px"><?php esc_html_e( 'Asset types classified', 'vulnhub' ); ?></h2>
			<p class="vh-muted">
				<?php esc_html_e( 'Workstations and mobiles must resolve to an individual owner; everything else falls back to a team.', 'vulnhub' ); ?>
			</p>
			<div class="vh-table-wrap">
				<table class="wp-list-table widefat striped">
					<tbody>
					<?php foreach ( $vh_tn_types as $vh_tn_type ) : ?>
						<tr>
							<td>
								<?php echo esc_html( vh_asset_types()[ (string) $vh_tn_type['asset_type'] ] ?? (string) $vh_tn_type['asset_type'] ); ?>
								<?php if ( in_array( (string) $vh_tn_type['asset_type'], vh_user_bound_asset_types(), true ) ) : ?>
									<span class="vh-pill"><?php esc_html_e( 'needs a user', 'vulnhub' ); ?></span>
								<?php endif; ?>
							</td>
							<td style="width:90px;text-align:right">
								<strong><?php echo esc_html( number_format_i18n( (int) $vh_tn_type['n'] ) ); ?></strong>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		<?php endif; ?>
	</div>
</div>

<div class="vh-card">
	<h2><?php esc_html_e( 'Recent export jobs', 'vulnhub' ); ?></h2>
	<p class="vh-muted">
		<?php esc_html_e( 'Tenable exports are asynchronous: VulnHub queues a job, polls its status, and downloads each chunk as it becomes available. Chunks stay downloadable for 24 hours.', 'vulnhub' ); ?>
	</p>

	<?php if ( ! $vh_tn_jobs ) : ?>
		<div class="vh-empty"><p><?php esc_html_e( 'No export jobs recorded yet.', 'vulnhub' ); ?></p></div>
	<?php else : ?>
		<div class="vh-table-wrap">
			<table class="wp-list-table widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Export', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Job id', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Status', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Chunks', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Records', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Duration', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Finished', 'vulnhub' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $vh_tn_jobs as $vh_tn_job ) : ?>
					<tr>
						<td>
							<?php echo esc_html( ucfirst( (string) ( $vh_tn_job['kind'] ?? '' ) ) ); ?>
							<?php if ( ! empty( $vh_tn_job['mock'] ) ) : ?>
								<span class="vh-badge vh-badge--mock"><?php esc_html_e( 'mock', 'vulnhub' ); ?></span>
							<?php endif; ?>
						</td>
						<td class="vh-mono"><?php echo esc_html( (string) ( $vh_tn_job['uuid'] ?? '' ) ); ?></td>
						<td>
							<span class="vh-state <?php echo esc_attr( 'FINISHED' === (string) ( $vh_tn_job['status'] ?? '' ) ? 'vh-state--done' : 'vh-state--open' ); ?>">
								<?php echo esc_html( (string) ( $vh_tn_job['status'] ?? '' ) ); ?>
							</span>
						</td>
						<td><?php echo esc_html( number_format_i18n( (int) ( $vh_tn_job['chunks'] ?? 0 ) ) ); ?></td>
						<td><?php echo esc_html( number_format_i18n( (int) ( $vh_tn_job['records'] ?? 0 ) ) ); ?></td>
						<td class="vh-nowrap"><?php echo esc_html( sprintf( '%.2fs', (float) ( $vh_tn_job['seconds'] ?? 0 ) ) ); ?></td>
						<td class="vh-nowrap"><?php echo esc_html( vh_date( (string) ( $vh_tn_job['finished'] ?? '' ) ) ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	<?php endif; ?>
</div>

<div class="vh-card">
	<div class="vh-actions" style="display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap">
		<div>
			<h2><?php esc_html_e( 'Closure verification', 'vulnhub' ); ?></h2>
			<p class="vh-muted" style="max-width:70ch">
				<?php
				printf(
					/* translators: %d: configured settling period in hours. */
					esc_html__( 'When a ticket is closed, VulnHub waits %d hours and then re-checks every finding it covered against current Tenable data. "Done" only counts when the scanner agrees.', 'vulnhub' ),
					vh_verification_delay_hours()
				);
				?>
			</p>
		</div>

		<?php if ( current_user_can( 'vulnhub_run_sync' ) ) : ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-form">
				<?php wp_nonce_field( 'vulnhub_tenable_verify' ); ?>
				<input type="hidden" name="action" value="vulnhub_tenable_verify" />
				<button type="submit" class="button button-secondary">
					<?php esc_html_e( 'Run verification now', 'vulnhub' ); ?>
				</button>
			</form>
		<?php endif; ?>
	</div>

	<?php if ( ! $vh_tn_verify ) : ?>
		<div class="vh-empty">
			<p><?php esc_html_e( 'No closures have been verified yet. Verdicts appear here once tickets are closed and the settling period has elapsed.', 'vulnhub' ); ?></p>
		</div>
	<?php else : ?>
		<div class="vh-table-wrap">
			<table class="wp-list-table widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Ticket', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Verdict', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Fixed', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Still open', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Unverifiable', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Explanation', 'vulnhub' ); ?></th>
						<th><?php esc_html_e( 'Checked', 'vulnhub' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $vh_tn_verify as $vh_tn_v ) : ?>
					<?php
					$vh_tn_state = (string) ( $vh_tn_v['state'] ?? '' );
					$vh_tn_class = match ( $vh_tn_state ) {
						\VulnHub\Core\Tickets::VERIFY_CONFIRMED  => 'vh-state--fixed',
						\VulnHub\Core\Tickets::VERIFY_STILL_OPEN => 'vh-state--open',
						default                                  => 'vh-state--pending',
					};
					?>
					<tr>
						<td class="vh-nowrap">
							<?php if ( ! empty( $vh_tn_v['url'] ) ) : ?>
								<a href="<?php echo esc_url( (string) $vh_tn_v['url'] ); ?>" target="_blank" rel="noopener noreferrer">
									<?php echo esc_html( (string) ( $vh_tn_v['key'] ?: $vh_tn_v['ticket_id'] ?? '' ) ); ?>
								</a>
							<?php else : ?>
								<?php echo esc_html( (string) ( $vh_tn_v['key'] ?: $vh_tn_v['ticket_id'] ?? '' ) ); ?>
							<?php endif; ?>
							<br />
							<span class="vh-muted"><?php echo esc_html( vh_trim( (string) ( $vh_tn_v['summary'] ?? '' ), 60 ) ); ?></span>
						</td>
						<td>
							<span class="vh-state <?php echo esc_attr( $vh_tn_class ); ?>">
								<?php echo esc_html( $vh_tn_labels[ $vh_tn_state ] ?? $vh_tn_state ); ?>
							</span>
						</td>
						<td><?php echo esc_html( number_format_i18n( (int) ( $vh_tn_v['confirmed'] ?? 0 ) ) ); ?></td>
						<td><?php echo esc_html( number_format_i18n( (int) ( $vh_tn_v['still_open'] ?? 0 ) ) ); ?></td>
						<td><?php echo esc_html( number_format_i18n( (int) ( $vh_tn_v['unknown'] ?? 0 ) ) ); ?></td>
						<td><?php echo esc_html( (string) ( $vh_tn_v['note'] ?? '' ) ); ?></td>
						<td class="vh-nowrap"><?php echo esc_html( vh_ago( (string) ( $vh_tn_v['checked_at'] ?? '' ) ) ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	<?php endif; ?>
</div>

