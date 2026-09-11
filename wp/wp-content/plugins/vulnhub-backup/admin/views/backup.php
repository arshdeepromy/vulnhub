<?php
/**
 * Backup & Restore admin screen.
 *
 * Included by vulnhub_render_admin_page (core's Admin::render_screen()
 * fallthrough) — never requested directly.
 *
 * @package VulnHub\Backup
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! current_user_can( \VulnHub\Core\Caps::MANAGE ) ) {
	return;
}

$settings   = vulnhub()->settings;
$local_sets = VulnHub_Backup_Storage::list_local();
$recent     = VulnHub_Backup_Jobs::recent( 10 );
$last_run   = vulnhub()->logger->last_run( 'backup_s3' );

$enabled   = $settings->get_bool( 'backup_s3', 'enabled', false );
$bucket    = (string) $settings->get( 'backup_s3', 'bucket', '' );
$region    = (string) $settings->get( 'backup_s3', 'region', 'us-east-1' );
$prefix    = (string) $settings->get( 'backup_s3', 'prefix', 'vulnhub-backups' );
$interval  = (string) $settings->get( 'backup_s3', 'interval', 'manual' );
$retention = (int) $settings->get( 'backup_s3', 'retention_count', 10 );

$access_hint = $settings->secret_hint( 'backup_s3', 'access_key_id' );
$secret_hint = $settings->secret_hint( 'backup_s3', 'secret_access_key' );
?>
<div class="vh-card">
	<h2><?php esc_html_e( 'Backup & Restore', 'vulnhub' ); ?></h2>
	<p class="description">
		<?php esc_html_e( 'A backup captures the database and every plugin, theme and upload file — everything needed to stand this exact install up again on a fresh stack. It does not include the wp-config secrets (DB password, encryption key); note those down separately if this backup will be restored onto a different environment.', 'vulnhub' ); ?>
	</p>

	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin: 16px 0;">
		<?php wp_nonce_field( 'vulnhub_backup_now' ); ?>
		<input type="hidden" name="action" value="vulnhub_backup_now" />
		<?php submit_button( __( 'Backup Now', 'vulnhub' ), 'primary', 'submit', false ); ?>
	</form>

	<h3><?php esc_html_e( 'Recent jobs', 'vulnhub' ); ?></h3>
	<table class="widefat striped">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Started', 'vulnhub' ); ?></th>
				<th><?php esc_html_e( 'Mode', 'vulnhub' ); ?></th>
				<th><?php esc_html_e( 'Phase', 'vulnhub' ); ?></th>
				<th><?php esc_html_e( 'Status', 'vulnhub' ); ?></th>
				<th><?php esc_html_e( 'Rows / Files', 'vulnhub' ); ?></th>
			</tr>
		</thead>
		<tbody id="vh-backup-jobs">
			<?php if ( ! $recent ) : ?>
				<tr><td colspan="5"><?php esc_html_e( 'No backups yet.', 'vulnhub' ); ?></td></tr>
			<?php endif; ?>
			<?php foreach ( $recent as $job ) : ?>
				<?php $counters = (array) $job['counters_arr']; ?>
				<tr data-job-id="<?php echo esc_attr( (string) $job['id'] ); ?>">
					<td><?php echo esc_html( (string) $job['started_at'] ); ?></td>
					<td><?php echo esc_html( (string) $job['mode'] ); ?></td>
					<td><?php echo esc_html( (string) $job['phase'] ); ?></td>
					<td><?php echo esc_html( (string) ( VulnHub_Backup_Jobs::statuses()[ (string) $job['status'] ] ?? $job['status'] ) ); ?></td>
					<td><?php echo esc_html( sprintf( '%d rows, %d files', (int) ( $counters['rows_exported'] ?? 0 ), (int) ( $counters['files_archived'] ?? 0 ) ) ); ?></td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>

	<h3><?php esc_html_e( 'Local backups', 'vulnhub' ); ?></h3>
	<table class="widefat striped">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Created', 'vulnhub' ); ?></th>
				<th><?php esc_html_e( 'Size', 'vulnhub' ); ?></th>
				<th><?php esc_html_e( 'Download', 'vulnhub' ); ?></th>
				<th></th>
			</tr>
		</thead>
		<tbody>
			<?php if ( ! $local_sets ) : ?>
				<tr><td colspan="4"><?php esc_html_e( 'None on disk yet.', 'vulnhub' ); ?></td></tr>
			<?php endif; ?>
			<?php foreach ( $local_sets as $set ) : ?>
				<tr>
					<td><?php echo esc_html( (string) $set['createdAt'] ); ?></td>
					<td><?php echo esc_html( (string) $set['sizeLabel'] ); ?></td>
					<td>
						<?php foreach ( array( 'manifest.json', 'db.sql.gz', 'wp-content.zip' ) as $file ) : ?>
							<a href="<?php echo esc_url( rest_url( VulnHub_Backup_Rest::NS . '/download/' . rawurlencode( (string) $set['folder'] ) . '/' . $file ) ); ?>"><?php echo esc_html( $file ); ?></a>&nbsp;
						<?php endforeach; ?>
					</td>
					<td>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" onsubmit="return confirm('<?php echo esc_js( __( 'Delete this local backup permanently?', 'vulnhub' ) ); ?>');">
							<?php wp_nonce_field( 'vulnhub_backup_delete' ); ?>
							<input type="hidden" name="action" value="vulnhub_backup_delete" />
							<input type="hidden" name="folder" value="<?php echo esc_attr( (string) $set['folder'] ); ?>" />
							<button type="submit" class="button-link-delete"><?php esc_html_e( 'Delete', 'vulnhub' ); ?></button>
						</form>
					</td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>
</div>

<div class="vh-card">
	<h2><?php esc_html_e( 'Upload & Restore', 'vulnhub' ); ?></h2>
	<p class="description">
		<strong><?php esc_html_e( 'This permanently replaces every table and every plugin/theme/upload file on this site with the uploaded backup.', 'vulnhub' ); ?></strong>
		<?php esc_html_e( 'Use it to stand a backup up on a fresh stack, not to merge into a live one.', 'vulnhub' ); ?>
	</p>

	<input type="file" id="vh-restore-file" accept=".zip" />
	<div id="vh-restore-progress" hidden>
		<progress id="vh-restore-bar" max="100" value="0"></progress>
		<span id="vh-restore-status"></span>
	</div>
	<p>
		<label>
			<?php esc_html_e( 'Type this site\'s domain to confirm:', 'vulnhub' ); ?>
			<input type="text" id="vh-restore-confirm" placeholder="<?php echo esc_attr( (string) wp_parse_url( home_url(), PHP_URL_HOST ) ); ?>" />
		</label>
	</p>
	<button type="button" class="button button-secondary" id="vh-restore-start" disabled><?php esc_html_e( 'Restore', 'vulnhub' ); ?></button>
</div>

<div class="vh-card">
	<h2><?php esc_html_e( 'S3 auto-backup settings', 'vulnhub' ); ?></h2>

	<?php if ( $last_run ) : ?>
		<div class="vh-last-run vh-last-run--<?php echo esc_attr( (string) $last_run['status'] ); ?>">
			<strong><?php esc_html_e( 'Last run:', 'vulnhub' ); ?></strong>
			<?php echo esc_html( (string) $last_run['status'] ); ?>
			&mdash; <?php echo esc_html( (string) $last_run['started_at'] ); ?>
			(<?php echo esc_html( sprintf( '%d ms', (int) $last_run['duration_ms'] ) ); ?>)
			<?php if ( ! empty( $last_run['message'] ) ) : ?>
				<div class="vh-last-run__message"><?php echo esc_html( (string) $last_run['message'] ); ?></div>
			<?php endif; ?>
		</div>
	<?php endif; ?>

	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
		<?php wp_nonce_field( 'vulnhub_backup_save_settings' ); ?>
		<input type="hidden" name="action" value="vulnhub_backup_save_settings" />

		<table class="form-table">
			<tr>
				<th><label for="vh-enabled"><?php esc_html_e( 'Enable S3 push', 'vulnhub' ); ?></label></th>
				<td><input type="checkbox" id="vh-enabled" name="enabled" value="1" <?php checked( $enabled ); ?> /></td>
			</tr>
			<tr>
				<th><label for="vh-access-key"><?php esc_html_e( 'Access key ID', 'vulnhub' ); ?></label></th>
				<td>
					<input type="password" id="vh-access-key" name="vh_access_key_id" class="regular-text" placeholder="<?php echo esc_attr( $access_hint ); ?>" autocomplete="off" />
					<?php if ( '' !== $access_hint ) : ?>
						<label><input type="checkbox" name="clear_access_key_id" value="1" /> <?php esc_html_e( 'Clear', 'vulnhub' ); ?></label>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th><label for="vh-secret-key"><?php esc_html_e( 'Secret access key', 'vulnhub' ); ?></label></th>
				<td>
					<input type="password" id="vh-secret-key" name="vh_secret_access_key" class="regular-text" placeholder="<?php echo esc_attr( $secret_hint ); ?>" autocomplete="off" />
					<?php if ( '' !== $secret_hint ) : ?>
						<label><input type="checkbox" name="clear_secret_access_key" value="1" /> <?php esc_html_e( 'Clear', 'vulnhub' ); ?></label>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th><label for="vh-bucket"><?php esc_html_e( 'Bucket', 'vulnhub' ); ?></label></th>
				<td><input type="text" id="vh-bucket" name="bucket" class="regular-text" value="<?php echo esc_attr( $bucket ); ?>" /></td>
			</tr>
			<tr>
				<th><label for="vh-region"><?php esc_html_e( 'Region', 'vulnhub' ); ?></label></th>
				<td><input type="text" id="vh-region" name="region" class="regular-text" value="<?php echo esc_attr( $region ); ?>" placeholder="us-east-1" /></td>
			</tr>
			<tr>
				<th><label for="vh-prefix"><?php esc_html_e( 'Key prefix', 'vulnhub' ); ?></label></th>
				<td><input type="text" id="vh-prefix" name="prefix" class="regular-text" value="<?php echo esc_attr( $prefix ); ?>" /></td>
			</tr>
			<tr>
				<th><label for="vh-interval"><?php esc_html_e( 'Frequency', 'vulnhub' ); ?></label></th>
				<td>
					<select id="vh-interval" name="interval">
						<?php foreach ( \VulnHub\Core\Scheduler::interval_choices() as $key => $label ) : ?>
							<option value="<?php echo esc_attr( $key ); ?>" <?php selected( $interval, $key ); ?>><?php echo esc_html( $label ); ?></option>
						<?php endforeach; ?>
					</select>
				</td>
			</tr>
			<tr>
				<th><label for="vh-retention"><?php esc_html_e( 'Retention (backups to keep)', 'vulnhub' ); ?></label></th>
				<td><input type="number" id="vh-retention" name="retention_count" min="1" max="365" value="<?php echo esc_attr( (string) $retention ); ?>" />
					<p class="description"><?php esc_html_e( 'The newest N backups are kept, locally and in S3; older ones are deleted automatically after each run.', 'vulnhub' ); ?></p>
				</td>
			</tr>
		</table>

		<?php submit_button( __( 'Save settings', 'vulnhub' ) ); ?>
	</form>
</div>

