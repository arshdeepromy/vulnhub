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

if ( ! function_exists( 'vulnhub_backup_portal_field' ) ) {
	/**
	 * Mark a form as submitted from the portal.
	 *
	 * `keep_redirects_in_portal()` falls back to the referer, which is usually
	 * enough — but a referer is the one request header a browser, proxy or
	 * privacy setting is free to strip, and losing it here means the operator
	 * silently lands in wp-admin. The flag costs nothing and does not rely on
	 * anyone's goodwill.
	 *
	 * Guarded on the dashboard classes because this same view renders in
	 * wp-admin, where the portal is not loaded at all.
	 */
	function vulnhub_backup_portal_field(): void {
		if ( ! class_exists( 'VulnHub_Dash_App' ) || ! class_exists( 'VulnHub_Dash_Portal' ) ) {
			return;
		}

		if ( VulnHub_Dash_App::current_view() !== VulnHub_Dash_Portal::ADMIN_VIEW ) {
			return;
		}

		echo '<input type="hidden" name="vh_from_portal" value="1" />';
	}
}

$settings   = vulnhub()->settings;
$local_sets = VulnHub_Backup_Storage::list_local();
$recent     = VulnHub_Backup_Jobs::recent( 10 );
$last_run   = vulnhub()->logger->last_run( 'backup_s3' );

/*
 * The job the progress panel follows: whichever is still running, else the one
 * the redirect just told us about, else the most recent. A backup that is
 * still going has to be visible the moment the page loads, not after the first
 * poll — otherwise pressing the button looks like it did nothing.
 */
$vh_running = null;
$vh_latest  = $recent[0] ?? null;

foreach ( $recent as $vh_job ) {
	if ( VulnHub_Backup_Jobs::RUNNING === (string) $vh_job['status'] ) {
		$vh_running = $vh_job;
		break;
	}
}

// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only.
$vh_flagged = isset( $_GET['vh_job'] ) ? (int) $_GET['vh_job'] : 0;

/*
 * $vh_running means running, and nothing else — it is what disables the
 * button. The job named in the redirect is only a hint about which one to
 * show, and by the time the page renders it may already have finished.
 */
$vh_panel = $vh_running;

if ( ! $vh_panel && $vh_flagged > 0 ) {
	$vh_panel = VulnHub_Backup_Jobs::get( $vh_flagged );
}

if ( ! $vh_panel ) {
	$vh_panel = $vh_latest;
}

/*
 * How long the last finished backup took, so the warning below can say what
 * "a while" actually means on this install rather than making the operator
 * guess.
 */
$vh_last_took = '';

foreach ( $recent as $vh_job ) {
	if ( VulnHub_Backup_Jobs::DONE === (string) $vh_job['status'] && '' !== (string) $vh_job['finished_at'] ) {
		$vh_from = strtotime( (string) $vh_job['started_at'] . ' UTC' );
		$vh_to   = strtotime( (string) $vh_job['finished_at'] . ' UTC' );

		if ( $vh_from && $vh_to && $vh_to > $vh_from ) {
			$vh_last_took = human_time_diff( $vh_from, $vh_to );
		}
		break;
	}
}

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

	<p class="vh-backup__cost">
		<?php
		if ( '' !== $vh_last_took ) {
			printf(
				/* translators: %s: how long the last backup took, e.g. "2 minutes". */
				esc_html__( 'A backup reads every table and every file, so the app is slower while it runs — the last one took %s. You can leave this page; it carries on in the background, and comes back here to show you where it got to.', 'vulnhub' ),
				esc_html( $vh_last_took )
			);
		} else {
			esc_html_e( 'A backup reads every table and every file, so the app is slower while it runs. You can leave this page; it carries on in the background.', 'vulnhub' );
		}
		?>
	</p>

	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin: 16px 0;" data-vh-backup-form>
		<?php wp_nonce_field( 'vulnhub_backup_now' ); ?>
		<input type="hidden" name="action" value="vulnhub_backup_now" />
		<?php vulnhub_backup_portal_field(); ?>
		<button type="submit" class="button button-primary vh-btn vh-btn--primary" <?php disabled( (bool) $vh_running ); ?>>
			<?php echo $vh_running ? esc_html__( 'Backup running…', 'vulnhub' ) : esc_html__( 'Backup Now', 'vulnhub' ); ?>
		</button>
	</form>

	<?php if ( $vh_panel ) : ?>
		<?php
		$vh_summary = VulnHub_Backup_Rest::summarise( $vh_panel );
		$vh_is_run  = VulnHub_Backup_Jobs::RUNNING === (string) $vh_panel['status'];
		?>
		<div class="vh-backup-progress<?php echo $vh_is_run ? ' is-running' : ''; ?>"
			data-vh-backup-progress="<?php echo esc_attr( (string) $vh_panel['id'] ); ?>"
			data-vh-backup-active="<?php echo $vh_is_run ? '1' : '0'; ?>">

			<div class="vh-backup-progress__head">
				<strong data-vh-backup-phase>
					<?php echo esc_html( (string) ( VulnHub_Backup_Jobs::phases()[ (string) $vh_panel['phase'] ] ?? $vh_panel['phase'] ) ); ?>
				</strong>
				<span class="vh-backup-progress__status" data-vh-backup-status>
					<?php echo esc_html( (string) ( VulnHub_Backup_Jobs::statuses()[ (string) $vh_panel['status'] ] ?? $vh_panel['status'] ) ); ?>
				</span>
			</div>

			<div class="vh-backup-progress__track" role="progressbar" aria-valuemin="0" aria-valuemax="100"
				aria-valuenow="<?php echo esc_attr( (string) VulnHub_Backup_Jobs::progress( $vh_panel ) ); ?>"
				aria-label="<?php esc_attr_e( 'Backup progress', 'vulnhub' ); ?>" data-vh-backup-track>
				<span class="vh-backup-progress__fill" data-vh-backup-fill
					style="width: <?php echo esc_attr( (string) VulnHub_Backup_Jobs::progress( $vh_panel ) ); ?>%"></span>
			</div>

			<p class="vh-backup-progress__meta">
				<span data-vh-backup-counters>
					<?php
					// The same line the poller paints, so the first paint and
					// every later one agree — including for a restore job.
					echo esc_html( $vh_summary['summary'] );
					?>
				</span>
				<span class="vh-backup-progress__started">
					<?php
					printf(
						/* translators: %s: relative time, e.g. "2 minutes ago". */
						esc_html__( 'started %s', 'vulnhub' ),
						esc_html( vh_ago( (string) $vh_panel['started_at'] ) )
					);
					?>
				</span>
			</p>

			<?php if ( '' !== (string) $vh_panel['error'] ) : ?>
				<p class="vh-backup-progress__error" data-vh-backup-error><?php echo esc_html( (string) $vh_panel['error'] ); ?></p>
			<?php else : ?>
				<p class="vh-backup-progress__error" data-vh-backup-error hidden></p>
			<?php endif; ?>

			<p class="vh-backup-progress__notice" data-vh-backup-notice<?php echo '' === $vh_summary['notice'] ? ' hidden' : ''; ?>><?php echo esc_html( $vh_summary['notice'] ); ?></p>
		</div>
	<?php endif; ?>

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
					<td title="<?php echo esc_attr( vh_date( (string) $job['started_at'] ) ); ?>"><?php echo esc_html( vh_ago( (string) $job['started_at'] ) ); ?></td>
					<td><?php echo esc_html( (string) $job['mode'] ); ?></td>
					<td><?php echo esc_html( (string) ( VulnHub_Backup_Jobs::phases()[ (string) $job['phase'] ] ?? $job['phase'] ) ); ?></td>
					<td><?php echo esc_html( (string) ( VulnHub_Backup_Jobs::statuses()[ (string) $job['status'] ] ?? $job['status'] ) ); ?></td>
					<td>
						<?php
						// A restore keeps its counts on its cursor, not in the
						// backup counters, which read "0 rows, 0 files" for it.
						echo esc_html(
							'restore' === (string) $job['mode']
								? VulnHub_Backup_Rest::summarise( $job )['summary']
								: sprintf( '%d rows, %d files', (int) ( $counters['rows_exported'] ?? 0 ), (int) ( $counters['files_archived'] ?? 0 ) )
						);
						?>
					</td>
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
					<td title="<?php echo esc_attr( vh_date( (string) $set['createdAt'] ) ); ?>"><?php echo esc_html( vh_ago( (string) $set['createdAt'] ) ); ?></td>
					<td><?php echo esc_html( (string) $set['sizeLabel'] ); ?></td>
					<td>
						<?php
						/*
						 * Whatever the set actually contains, not a hardcoded
						 * list: the archive format is the runner's business,
						 * and this screen should not need editing when it
						 * changes.
						 */
						$vh_files = isset( $set['files'] ) && is_array( $set['files'] )
							? $set['files']
							: array( 'manifest.json', 'db.sql.gz', 'wp-content.zip' );
						?>
						<?php
						/*
						 * The link needs the core wp_rest nonce. Without it the
						 * REST API ignores the login cookie, treats the request
						 * as anonymous, and the download answers 401.
						 */
						$vh_rest_nonce = wp_create_nonce( 'wp_rest' );
						?>
						<?php foreach ( $vh_files as $file ) : ?>
							<a href="<?php echo esc_url( add_query_arg( '_wpnonce', $vh_rest_nonce, rest_url( VulnHub_Backup_Rest::NS . '/download/' . rawurlencode( (string) $set['folder'] ) . '/' . $file ) ) ); ?>"><?php echo esc_html( $file ); ?></a>&nbsp;
						<?php endforeach; ?>
					</td>
					<td>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" onsubmit="return confirm('<?php echo esc_js( __( 'Delete this local backup permanently?', 'vulnhub' ) ); ?>');">
							<?php wp_nonce_field( 'vulnhub_backup_delete' ); ?>
							<?php vulnhub_backup_portal_field(); ?>
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

	<input type="file" id="vh-restore-file" accept=".zip,.gz,.tgz,.tar.gz" />
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

	<?php
	/*
	 * Live progress for a restore started from this tab. It is followed with
	 * a one-job token rather than the login, because the restore replaces the
	 * users table — and with it this session — part way through.
	 */
	?>
	<div class="vh-backup-progress" id="vh-restore-job" hidden aria-live="polite">
		<div class="vh-backup-progress__head">
			<strong data-vh-restore="phase"></strong>
			<span class="vh-backup-progress__status" data-vh-restore="status"></span>
		</div>
		<div class="vh-backup-progress__track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"
			aria-label="<?php esc_attr_e( 'Restore progress', 'vulnhub' ); ?>" data-vh-restore="track">
			<span class="vh-backup-progress__fill" data-vh-restore="fill"></span>
		</div>
		<p class="vh-backup-progress__meta">
			<span data-vh-restore="summary"></span>
			<span data-vh-restore="elapsed"></span>
		</p>
		<p class="vh-backup-progress__hint" data-vh-restore="hint">
			<?php esc_html_e( 'Keep this tab open to follow the restore. Part way through, the restored database replaces this site\'s users and you are signed out — that is expected, and the progress here carries on. If you close the tab, the restore still finishes on the server.', 'vulnhub' ); ?>
		</p>
		<p class="vh-backup-progress__error" data-vh-restore="error" hidden></p>
		<p class="vh-backup-progress__notice" data-vh-restore="notice" hidden></p>
		<p class="vh-backup-progress__actions" data-vh-restore="actions" hidden>
			<a class="button button-primary" href="<?php echo esc_url( wp_login_url( admin_url( 'admin.php?page=vulnhub-backup' ) ) ); ?>"><?php esc_html_e( 'Sign in', 'vulnhub' ); ?></a>
		</p>
	</div>
</div>

<div class="vh-card">
	<h2><?php esc_html_e( 'S3 auto-backup settings', 'vulnhub' ); ?></h2>

	<?php if ( $last_run ) : ?>
		<div class="vh-last-run vh-last-run--<?php echo esc_attr( (string) $last_run['status'] ); ?>">
			<strong><?php esc_html_e( 'Last run:', 'vulnhub' ); ?></strong>
			<?php echo esc_html( (string) $last_run['status'] ); ?>
			&mdash; <?php echo esc_html( vh_date( (string) $last_run['started_at'] ) ); ?>
			(<?php echo esc_html( vh_duration_human( (int) $last_run['duration_ms'] ) ); ?>)
			<?php if ( ! empty( $last_run['message'] ) ) : ?>
				<div class="vh-last-run__message"><?php echo esc_html( (string) $last_run['message'] ); ?></div>
			<?php endif; ?>
		</div>
	<?php endif; ?>

	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
		<?php wp_nonce_field( 'vulnhub_backup_save_settings' ); ?>
		<?php vulnhub_backup_portal_field(); ?>
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

