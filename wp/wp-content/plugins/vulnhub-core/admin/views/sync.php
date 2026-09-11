<?php
/**
 * Sync activity screen.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

use VulnHub\Core\Scheduler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.Security.NonceVerification.Recommended
$vh_run_id    = isset( $_GET['run'] ) ? (int) $_GET['run'] : 0;
$vh_connector = isset( $_GET['connector'] ) ? sanitize_key( wp_unslash( $_GET['connector'] ) ) : '';
// phpcs:enable

global $wpdb;

if ( $vh_run_id ) {
	$vh_run = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . vh_table( 'sync_runs' ) . ' WHERE id = %d', $vh_run_id ), ARRAY_A );
	if ( ! $vh_run ) {
		echo '<div class="vh-card vh-empty"><h2>' . esc_html__( 'Run not found', 'vulnhub' ) . '</h2></div>';
		return;
	}
	?>
	<p style="margin:0 0 14px">
		<a href="<?php echo esc_url( vh_admin_url( 'vulnhub-sync' ) ); ?>">&larr; <?php esc_html_e( 'All sync runs', 'vulnhub' ); ?></a>
	</p>

	<div class="vh-card" style="margin-bottom:16px">
		<h2><?php echo esc_html( ucfirst( (string) $vh_run['connector'] ) . ' — run #' . $vh_run['id'] ); ?></h2>
		<div class="vh-detail">
			<dl>
				<dt><?php esc_html_e( 'Status', 'vulnhub' ); ?></dt>
				<dd>
					<span class="vh-state vh-state--<?php echo 'success' === $vh_run['status'] ? 'fixed' : 'open'; ?>">
						<?php echo esc_html( (string) $vh_run['status'] ); ?>
					</span>
				</dd>
				<dt><?php esc_html_e( 'Mode', 'vulnhub' ); ?></dt>
				<dd><?php echo esc_html( (string) $vh_run['mode'] ); ?></dd>
				<dt><?php esc_html_e( 'Started', 'vulnhub' ); ?></dt>
				<dd><?php echo esc_html( vh_date( (string) $vh_run['started_at'], 'j M Y, H:i:s' ) ); ?></dd>
				<dt><?php esc_html_e( 'Finished', 'vulnhub' ); ?></dt>
				<dd><?php echo esc_html( $vh_run['finished_at'] ? vh_date( (string) $vh_run['finished_at'], 'j M Y, H:i:s' ) : '—' ); ?></dd>
				<dt><?php esc_html_e( 'Duration', 'vulnhub' ); ?></dt>
				<dd><?php echo esc_html( number_format_i18n( (int) $vh_run['duration_ms'] / 1000, 1 ) . 's' ); ?></dd>
				<dt><?php esc_html_e( 'Counts', 'vulnhub' ); ?></dt>
				<dd>
					<?php
					printf(
						/* translators: 1: processed, 2: created, 3: updated, 4: skipped, 5: failed. */
						esc_html__( '%1$d processed · %2$d created · %3$d updated · %4$d skipped · %5$d failed', 'vulnhub' ),
						(int) $vh_run['processed'],
						(int) $vh_run['created'],
						(int) $vh_run['updated'],
						(int) $vh_run['skipped'],
						(int) $vh_run['failed']
					);
					?>
				</dd>
				<?php if ( ! empty( $vh_run['message'] ) ) : ?>
					<dt><?php esc_html_e( 'Message', 'vulnhub' ); ?></dt>
					<dd><?php echo esc_html( (string) $vh_run['message'] ); ?></dd>
				<?php endif; ?>
			</dl>
		</div>
	</div>

	<h2 style="font-size:15px;margin:0 0 10px"><?php esc_html_e( 'Run log', 'vulnhub' ); ?></h2>
	<div class="vh-log" style="max-height:640px"><?php echo esc_html( (string) ( $vh_run['log_text'] ?: __( '(no log output)', 'vulnhub' ) ) ); ?></div>
	<?php
	return;
}

$vh_runs = vulnhub()->logger->recent_runs( 60, $vh_connector );
?>

<div class="vh-card" style="margin-bottom:16px">
	<h2><?php esc_html_e( 'Scheduled runs', 'vulnhub' ); ?></h2>
	<?php if ( ! vulnhub()->connectors->all() ) : ?>
		<p class="vh-muted" style="margin:0"><?php esc_html_e( 'No connectors registered.', 'vulnhub' ); ?></p>
	<?php else : ?>
		<table class="widefat striped">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Connector', 'vulnhub' ); ?></th>
					<th style="width:140px"><?php esc_html_e( 'Schedule', 'vulnhub' ); ?></th>
					<th style="width:170px"><?php esc_html_e( 'Next run', 'vulnhub' ); ?></th>
					<th style="width:170px"><?php esc_html_e( 'Last run', 'vulnhub' ); ?></th>
					<th style="width:130px"></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( vulnhub()->connectors->all() as $vh_id => $vh_c ) : ?>
				<?php
				$vh_next     = Scheduler::next_run( (string) $vh_id );
				$vh_last     = vulnhub()->logger->last_run( (string) $vh_id );
				$vh_interval = (string) vulnhub()->settings->get( (string) $vh_id, 'interval', $vh_c->default_interval() );
				?>
				<tr>
					<td><strong><?php echo esc_html( $vh_c->label() ); ?></strong></td>
					<td class="vh-muted"><?php echo esc_html( Scheduler::interval_choices()[ $vh_interval ] ?? $vh_interval ); ?></td>
					<td class="vh-muted">
						<?php echo $vh_next ? esc_html( vh_date( gmdate( 'Y-m-d H:i:s', $vh_next ) ) ) : esc_html__( 'not scheduled', 'vulnhub' ); ?>
					</td>
					<td class="vh-muted">
						<?php echo $vh_last ? esc_html( vh_ago( (string) $vh_last['started_at'] ) ) : esc_html__( 'never', 'vulnhub' ); ?>
					</td>
					<td>
						<?php if ( $vh_c->supports_sync() && current_user_can( 'vulnhub_run_sync' ) ) : ?>
							<button type="button" class="button button-small" data-vh-action="sync" data-vh-connector="<?php echo esc_attr( (string) $vh_id ); ?>">
								<?php esc_html_e( 'Run now', 'vulnhub' ); ?>
							</button>
						<?php endif; ?>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>
</div>

<h2 style="font-size:15px;margin:22px 0 10px"><?php esc_html_e( 'Recent runs', 'vulnhub' ); ?></h2>

<?php if ( ! $vh_runs ) : ?>
	<div class="vh-card vh-empty">
		<span class="dashicons dashicons-update"></span>
		<h2><?php esc_html_e( 'Nothing has run yet', 'vulnhub' ); ?></h2>
		<p><?php esc_html_e( 'Enable a connector and trigger its first sync.', 'vulnhub' ); ?></p>
	</div>
<?php else : ?>
	<div class="vh-table-wrap">
		<table class="wp-list-table widefat fixed striped">
			<thead>
				<tr>
					<th style="width:60px"><?php esc_html_e( 'Run', 'vulnhub' ); ?></th>
					<th style="width:150px"><?php esc_html_e( 'Connector', 'vulnhub' ); ?></th>
					<th style="width:100px"><?php esc_html_e( 'Status', 'vulnhub' ); ?></th>
					<th style="width:90px"><?php esc_html_e( 'Mode', 'vulnhub' ); ?></th>
					<th><?php esc_html_e( 'Result', 'vulnhub' ); ?></th>
					<th style="width:90px"><?php esc_html_e( 'Duration', 'vulnhub' ); ?></th>
					<th style="width:130px"><?php esc_html_e( 'Started', 'vulnhub' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $vh_runs as $vh_r ) : ?>
				<tr>
					<td>
						<a class="vh-mono" href="<?php echo esc_url( vh_admin_url( 'vulnhub-sync', array( 'run' => (int) $vh_r['id'] ) ) ); ?>">
							#<?php echo esc_html( (string) $vh_r['id'] ); ?>
						</a>
					</td>
					<td><?php echo esc_html( ucfirst( (string) $vh_r['connector'] ) ); ?></td>
					<td>
						<span class="vh-state vh-state--<?php echo 'success' === $vh_r['status'] ? 'fixed' : ( 'running' === $vh_r['status'] ? 'pending' : 'open' ); ?>">
							<?php echo esc_html( (string) $vh_r['status'] ); ?>
						</span>
					</td>
					<td class="vh-muted"><?php echo esc_html( (string) $vh_r['mode'] ); ?></td>
					<td class="vh-muted">
						<?php
						printf(
							/* translators: 1: processed, 2: created, 3: updated. */
							esc_html__( '%1$d processed, %2$d new, %3$d updated', 'vulnhub' ),
							(int) $vh_r['processed'],
							(int) $vh_r['created'],
							(int) $vh_r['updated']
						);
						if ( ! empty( $vh_r['message'] ) ) {
							echo ' — ' . esc_html( vh_trim( (string) $vh_r['message'], 70 ) );
						}
						?>
					</td>
					<td class="vh-mono"><?php echo esc_html( number_format_i18n( (int) $vh_r['duration_ms'] / 1000, 1 ) . 's' ); ?></td>
					<td class="vh-muted vh-nowrap"><?php echo esc_html( vh_ago( (string) $vh_r['started_at'] ) ); ?></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	</div>
<?php endif; ?>

