<?php
/**
 * Instance sync — share this instance with a copy, or watch this copy sync.
 *
 * @package VulnHub\Replica
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only view state.
$vh_notice = isset( $_GET['vh_notice'] ) ? sanitize_key( wp_unslash( $_GET['vh_notice'] ) ) : '';
// phpcs:enable

$vh_fresh   = VulnHub_Replica_Admin::fresh_key();
$vh_keys    = VulnHub_Replica_Tokens::all();
$vh_jobs    = VulnHub_Replica_Job::all();
$vh_is_copy = VulnHub_Replica_Guard::active();
$vh_last    = (array) get_option( VulnHub_Replica_Connector::OPT_LAST, array() );
$vh_run     = (array) get_option( VulnHub_Replica_Connector::OPT_RUN, array() );
$vh_guard   = (array) get_option( VulnHub_Replica_Guard::OPT_COUNTS, array() );
$vh_tables  = VulnHub_Replica_Schema::tables();
$vh_rows    = array_sum( array_map( static fn( $t ) => (int) $t['rows'], $vh_tables ) );
?>

<?php if ( 'revoked' === $vh_notice ) : ?>
	<p class="vh-flash vh-flash--good"><?php esc_html_e( 'Key revoked. A copy using it stops at its next request, and any package it was collecting is deleted.', 'vulnhub' ); ?></p>
<?php elseif ( 'queued' === $vh_notice ) : ?>
	<p class="vh-flash vh-flash--good"><?php esc_html_e( 'Sync started in the background. Progress shows on the connector card under Integrations.', 'vulnhub' ); ?></p>
<?php elseif ( 'full' === $vh_notice ) : ?>
	<p class="vh-flash vh-flash--good"><?php esc_html_e( 'The next sync rebuilds every table from the source.', 'vulnhub' ); ?></p>
<?php endif; ?>

<?php if ( $vh_fresh ) : ?>
	<div class="vh-form" style="border-left:3px solid var(--vh-good);margin-bottom:18px">
		<h2 style="margin-top:14px"><?php esc_html_e( 'Your sync key', 'vulnhub' ); ?></h2>
		<p class="vh-warn-note"><?php esc_html_e( 'This is the only time it is shown: only a hash of it is kept. Copy it now. If it is lost, revoke it and make another.', 'vulnhub' ); ?></p>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'Source instance address', 'vulnhub' ); ?></th>
				<td><input type="text" class="large-text vh-mono" readonly onclick="this.select()" value="<?php echo esc_attr( home_url() ); ?>"></td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Sync key', 'vulnhub' ); ?></th>
				<td><input type="text" class="large-text vh-mono" readonly onclick="this.select()" value="<?php echo esc_attr( (string) $vh_fresh['token'] ); ?>"></td>
			</tr>
		</table>
		<p class="vh-field-help"><?php esc_html_e( 'On the other instance: Integrations → Instance copy (one-way sync). Paste both, switch it on, pick a frequency and save. The address must be one the other instance can reach — use the network address rather than localhost if the two run on different machines.', 'vulnhub' ); ?></p>
	</div>
<?php endif; ?>

<!-- ------------------------------------------------------------- this instance -->
<div class="vh-grid vh-grid--2">
	<div class="vh-form">
		<h2 style="margin-top:14px"><?php esc_html_e( 'This instance', 'vulnhub' ); ?></h2>
		<?php if ( $vh_is_copy ) : ?>
			<p><span class="vh-chip vh-chip--warn"><?php esc_html_e( 'Copy', 'vulnhub' ); ?></span>
				<?php esc_html_e( 'Receives data from another instance. Nothing here reaches a real system.', 'vulnhub' ); ?></p>
		<?php else : ?>
			<p><span class="vh-chip vh-chip--good"><?php esc_html_e( 'Primary', 'vulnhub' ); ?></span>
				<?php esc_html_e( 'Collects its own data. It can also be the source for a copy.', 'vulnhub' ); ?></p>
		<?php endif; ?>
		<p class="vh-field-help">
			<?php
			printf(
				/* translators: 1: table count, 2: row count. */
				esc_html__( '%1$d tables, about %2$s rows, would be offered to a copy. Credentials, connector secrets, sign-in settings and this instance\'s own logs never are.', 'vulnhub' ),
				count( $vh_tables ),
				esc_html( number_format_i18n( $vh_rows ) )
			);
			?>
		</p>
		<p class="vh-muted" style="font-size:11.5px"><?php echo esc_html( sprintf( __( 'Instance id %s', 'vulnhub' ), substr( VulnHub_Replica_Schema::instance_id(), 0, 8 ) ) ); ?></p>
	</div>

	<form method="post" action="<?php echo esc_url( VulnHub_Replica_Admin::section_url() ); ?>" class="vh-form">
		<?php wp_nonce_field( VulnHub_Replica_Admin::NONCE_ACTION, VulnHub_Replica_Admin::NONCE_FIELD ); ?>
		<input type="hidden" name="vh_replica_do" value="create">
		<h2 style="margin-top:14px"><?php esc_html_e( 'Let another instance copy this one', 'vulnhub' ); ?></h2>
		<p class="vh-field-help"><?php esc_html_e( 'A sync key can only read the estate data through the sync endpoints. It cannot sign in, change anything here, or see any credential.', 'vulnhub' ); ?></p>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><label for="vh-rep-label"><?php esc_html_e( 'Which copy is it for', 'vulnhub' ); ?></label></th>
				<td><input type="text" id="vh-rep-label" name="label" class="regular-text" placeholder="<?php esc_attr_e( 'Test copy on the lab box', 'vulnhub' ); ?>"></td>
			</tr>
			<tr>
				<th scope="row"><label for="vh-rep-days"><?php esc_html_e( 'Expires after', 'vulnhub' ); ?></label></th>
				<td>
					<select id="vh-rep-days" name="days">
						<option value="0"><?php esc_html_e( 'Never', 'vulnhub' ); ?></option>
						<option value="365"><?php esc_html_e( 'A year', 'vulnhub' ); ?></option>
						<option value="90"><?php esc_html_e( '90 days', 'vulnhub' ); ?></option>
						<option value="30"><?php esc_html_e( '30 days', 'vulnhub' ); ?></option>
					</select>
				</td>
			</tr>
		</table>
		<p><button type="submit" class="button button-primary"><?php esc_html_e( 'Create a sync key', 'vulnhub' ); ?></button></p>
	</form>
</div>

<?php if ( $vh_is_copy || $vh_last || $vh_run ) : ?>
<!-- --------------------------------------------------------------- the copy -->
<div class="vh-panel" style="margin-top:20px">
	<div class="vh-panel__head">
		<h2><?php esc_html_e( 'Syncing from the source', 'vulnhub' ); ?></h2>
		<p class="vh-sub"><?php esc_html_e( 'Each run fingerprints the tables here, the source zips only what differs and cuts it into chunks, and each chunk is checked before the package is unpacked and applied.', 'vulnhub' ); ?></p>
	</div>

	<?php if ( $vh_run && ! empty( $vh_run['job'] ) ) : ?>
		<p class="vh-warn-note">
			<?php
			$vh_m = (array) ( $vh_run['manifest'] ?? array() );
			printf(
				/* translators: 1: phase, 2: chunks done, 3: chunk count. */
				esc_html__( 'A sync is part-way through (%1$s phase, %2$d of %3$d chunks downloaded). It carries on from there on its next run.', 'vulnhub' ),
				esc_html( (string) $vh_run['phase'] ),
				count( (array) ( $vh_run['done'] ?? array() ) ),
				(int) ( $vh_m['chunk_count'] ?? 0 )
			);
			if ( ! empty( $vh_run['error'] ) ) {
				echo ' ' . esc_html( sprintf( __( 'Last error: %s', 'vulnhub' ), (string) $vh_run['error'] ) );
			}
			?>
		</p>
	<?php endif; ?>

	<?php if ( $vh_last ) : ?>
		<table class="wp-list-table widefat striped" style="margin-top:10px">
			<tbody>
				<tr><th style="width:220px"><?php esc_html_e( 'Last finished', 'vulnhub' ); ?></th><td><?php echo esc_html( vh_ago( (string) $vh_last['at'] ) . ( ! empty( $vh_last['full'] ) ? ' · ' . __( 'full copy', 'vulnhub' ) : '' ) ); ?></td></tr>
				<tr><th><?php esc_html_e( 'Package', 'vulnhub' ); ?></th><td><?php echo esc_html( sprintf( '%s in %d chunk(s), %s row(s), %ds', size_format( (int) $vh_last['bytes'], 1 ), (int) $vh_last['chunks'], number_format_i18n( (int) $vh_last['rows'] ), (int) $vh_last['seconds'] ) ); ?></td></tr>
				<tr><th><?php esc_html_e( 'Tables changed', 'vulnhub' ); ?></th>
					<td>
						<?php if ( empty( $vh_last['tables'] ) ) : ?>
							<?php esc_html_e( 'None — already up to date.', 'vulnhub' ); ?>
						<?php else : ?>
							<?php foreach ( (array) $vh_last['tables'] as $vh_t => $vh_info ) : ?>
								<span class="vh-chip" title="<?php echo esc_attr( 'ranges' === $vh_info['mode'] ? __( 'Changed key ranges rewritten', 'vulnhub' ) : __( 'Rebuilt and swapped in', 'vulnhub' ) ); ?>"><?php echo esc_html( $vh_t . ' · ' . number_format_i18n( (int) $vh_info['rows'] ) ); ?></span>
							<?php endforeach; ?>
						<?php endif; ?>
					</td>
				</tr>
				<?php foreach ( array_merge( (array) ( $vh_last['warnings'] ?? array() ), (array) ( $vh_last['skipped'] ?? array() ) ) as $vh_w ) : ?>
					<tr><th><span class="vh-chip vh-chip--warn"><?php echo esc_html( (string) ( $vh_w['table'] ?? '' ) ); ?></span></th><td><?php echo esc_html( (string) ( $vh_w['why'] ?? '' ) ); ?></td></tr>
				<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>

	<?php if ( $vh_is_copy ) : ?>
		<p class="vh-field-help" style="margin-top:12px">
			<?php
			printf(
				/* translators: 1: blocked syncs, 2: blocked jobs, 3: blocked calls, 4: held emails. */
				esc_html__( 'Held back so far on this copy: %1$d connector sync(s), %2$d background job(s), %3$d outbound call(s), %4$d email(s).', 'vulnhub' ),
				(int) ( $vh_guard['sync'] ?? 0 ),
				(int) ( $vh_guard['jobs'] ?? 0 ),
				(int) ( $vh_guard['http'] ?? 0 ),
				(int) ( $vh_guard['mail'] ?? 0 )
			);
			?>
		</p>
		<div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:10px">
			<form method="post" action="<?php echo esc_url( VulnHub_Replica_Admin::section_url() ); ?>">
				<?php wp_nonce_field( VulnHub_Replica_Admin::NONCE_ACTION, VulnHub_Replica_Admin::NONCE_FIELD ); ?>
				<input type="hidden" name="vh_replica_do" value="sync">
				<button type="submit" class="button button-primary"><?php esc_html_e( 'Sync now', 'vulnhub' ); ?></button>
			</form>
			<form method="post" action="<?php echo esc_url( VulnHub_Replica_Admin::section_url() ); ?>">
				<?php wp_nonce_field( VulnHub_Replica_Admin::NONCE_ACTION, VulnHub_Replica_Admin::NONCE_FIELD ); ?>
				<input type="hidden" name="vh_replica_do" value="full">
				<button type="submit" class="button"><?php esc_html_e( 'Rebuild everything on the next sync', 'vulnhub' ); ?></button>
			</form>
			<a class="button" href="<?php echo esc_url( VulnHub_Replica_Admin::connector_url() ); ?>"><?php esc_html_e( 'Source, key and frequency', 'vulnhub' ); ?></a>
		</div>
	<?php endif; ?>
</div>
<?php elseif ( ! $vh_is_copy ) : ?>
<p class="vh-field-help" style="margin-top:16px">
	<?php esc_html_e( 'To make this instance a copy of another, create a sync key on the other one and enter it under', 'vulnhub' ); ?>
	<a href="<?php echo esc_url( VulnHub_Replica_Admin::connector_url() ); ?>"><?php esc_html_e( 'Integrations → Instance copy', 'vulnhub' ); ?></a>.
</p>
<?php endif; ?>

<!-- ------------------------------------------------------------------- keys -->
<div class="vh-panel" style="margin-top:20px">
	<div class="vh-panel__head">
		<h2><?php esc_html_e( 'Sync keys issued by this instance', 'vulnhub' ); ?></h2>
		<p class="vh-sub"><?php esc_html_e( 'Revoking takes effect on the copy\'s next request.', 'vulnhub' ); ?></p>
	</div>

	<?php if ( ! $vh_keys ) : ?>
		<div class="vh-empty"><p><?php esc_html_e( 'No copy has been given access to this instance.', 'vulnhub' ); ?></p></div>
	<?php else : ?>
		<div style="overflow-x:auto">
			<table class="wp-list-table widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'For', 'vulnhub' ); ?></th>
						<th style="width:150px"><?php esc_html_e( 'Key', 'vulnhub' ); ?></th>
						<th style="width:100px"><?php esc_html_e( 'Status', 'vulnhub' ); ?></th>
						<th style="width:190px"><?php esc_html_e( 'Last used', 'vulnhub' ); ?></th>
						<th style="width:80px"><?php esc_html_e( 'Calls', 'vulnhub' ); ?></th>
						<th style="width:100px"></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $vh_keys as $vh_k ) : ?>
					<?php $vh_expired = ! empty( $vh_k['expires_at'] ) && strtotime( $vh_k['expires_at'] . ' UTC' ) < time(); ?>
					<tr>
						<td><strong><?php echo esc_html( (string) $vh_k['label'] ); ?></strong>
							<div class="vh-muted" style="font-size:11.5px"><?php echo esc_html( vh_ago( (string) $vh_k['created_at'] ) . ( ! empty( $vh_k['expires_at'] ) ? ' · ' . sprintf( __( 'expires %s', 'vulnhub' ), vh_date_only( (string) $vh_k['expires_at'] ) ) : '' ) ); ?></div></td>
						<td class="vh-mono"><?php echo esc_html( (string) $vh_k['hint'] ); ?></td>
						<td>
							<?php if ( ! empty( $vh_k['revoked_at'] ) ) : ?>
								<span class="vh-chip vh-chip--bad"><?php esc_html_e( 'Revoked', 'vulnhub' ); ?></span>
							<?php elseif ( $vh_expired ) : ?>
								<span class="vh-chip vh-chip--warn"><?php esc_html_e( 'Expired', 'vulnhub' ); ?></span>
							<?php else : ?>
								<span class="vh-chip vh-chip--good"><?php esc_html_e( 'Active', 'vulnhub' ); ?></span>
							<?php endif; ?>
						</td>
						<td class="vh-muted" style="font-size:12px"><?php echo esc_html( ! empty( $vh_k['last_used_at'] ) ? vh_ago( (string) $vh_k['last_used_at'] ) . ' · ' . $vh_k['last_used_ip'] : __( 'never', 'vulnhub' ) ); ?></td>
						<td class="vh-muted"><?php echo esc_html( number_format_i18n( (int) $vh_k['calls'] ) ); ?></td>
						<td>
							<?php if ( empty( $vh_k['revoked_at'] ) ) : ?>
								<form method="post" action="<?php echo esc_url( VulnHub_Replica_Admin::section_url() ); ?>" onsubmit="return confirm('<?php echo esc_js( __( 'Revoke this key? The copy using it stops syncing.', 'vulnhub' ) ); ?>');">
									<?php wp_nonce_field( VulnHub_Replica_Admin::NONCE_ACTION, VulnHub_Replica_Admin::NONCE_FIELD ); ?>
									<input type="hidden" name="vh_replica_do" value="revoke">
									<input type="hidden" name="id" value="<?php echo esc_attr( (string) $vh_k['id'] ); ?>">
									<button type="submit" class="button button-small"><?php esc_html_e( 'Revoke', 'vulnhub' ); ?></button>
								</form>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	<?php endif; ?>

	<?php if ( $vh_jobs ) : ?>
		<h3 style="margin:18px 0 6px"><?php esc_html_e( 'Packages being collected', 'vulnhub' ); ?></h3>
		<table class="wp-list-table widefat striped">
			<tbody>
			<?php foreach ( $vh_jobs as $vh_j ) : ?>
				<?php $vh_jm = (array) ( $vh_j['manifest'] ?? array() ); ?>
				<tr>
					<td class="vh-mono" style="width:120px"><?php echo esc_html( substr( (string) $vh_j['id'], 0, 8 ) ); ?></td>
					<td><?php echo esc_html( sprintf( __( 'Key #%d', 'vulnhub' ), (int) $vh_j['token_id'] ) ); ?></td>
					<td><?php echo esc_html( 'ready' === $vh_j['status'] ? sprintf( '%s · %d chunk(s) · %s row(s)', size_format( (int) $vh_jm['bytes_total'], 1 ), (int) $vh_jm['chunk_count'], number_format_i18n( (int) $vh_jm['records'] ) ) : (string) $vh_j['status'] . ' · ' . (string) $vh_j['step'] ); ?></td>
					<td class="vh-muted"><?php echo esc_html( human_time_diff( (int) $vh_j['created'] ) . ' ' . __( 'ago', 'vulnhub' ) ); ?></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>
</div>

