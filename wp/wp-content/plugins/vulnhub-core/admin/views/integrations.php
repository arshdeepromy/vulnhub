<?php
/**
 * Integrations screen — the admin portal where connectors are configured.
 *
 * @package VulnHub\Core
 */

declare( strict_types = 1 );

use VulnHub\Core\Connectors;
use VulnHub\Core\Scheduler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$vh_all      = vulnhub()->connectors->all();
$vh_selected = isset( $_GET['connector'] ) ? sanitize_key( wp_unslash( $_GET['connector'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification
$vh_active   = $vh_selected ? vulnhub()->connectors->get( $vh_selected ) : null;
?>

<?php if ( ! $vh_all ) : ?>
	<div class="vh-card vh-empty">
		<span class="dashicons dashicons-admin-plugins"></span>
		<h2><?php esc_html_e( 'No integration plugins are active', 'vulnhub' ); ?></h2>
		<p><?php esc_html_e( 'VulnHub Core provides the data model and portal. Each integration ships as its own plugin so it can be updated or disabled independently. Activate the ones you need from the Plugins screen.', 'vulnhub' ); ?></p>
		<a class="button button-primary" href="<?php echo esc_url( admin_url( 'plugins.php' ) ); ?>">
			<?php esc_html_e( 'Go to Plugins', 'vulnhub' ); ?>
		</a>
	</div>
	<?php return; ?>
<?php endif; ?>

<?php if ( $vh_active ) : ?>

	<p style="margin:0 0 14px">
		<a href="<?php echo esc_url( vh_admin_url( 'vulnhub-integrations' ) ); ?>">&larr; <?php esc_html_e( 'All integrations', 'vulnhub' ); ?></a>
	</p>

	<?php
	$vh_health   = $vh_active->health();
	$vh_last_run = vulnhub()->logger->last_run( $vh_active->id() );
	?>

	<div class="vh-grid vh-grid--2">
		<div>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="vh-form">
				<?php wp_nonce_field( 'vulnhub_save_connector' ); ?>
				<input type="hidden" name="action" value="vulnhub_save_connector">
				<input type="hidden" name="connector" value="<?php echo esc_attr( $vh_active->id() ); ?>">

				<h2 style="margin-top:16px"><?php echo esc_html( $vh_active->label() ); ?></h2>
				<p class="vh-muted" style="max-width:640px"><?php echo esc_html( $vh_active->description() ); ?></p>

				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e( 'Status', 'vulnhub' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="enabled" value="1" <?php checked( $vh_active->is_enabled() ); ?>>
								<?php esc_html_e( 'Enable this integration', 'vulnhub' ); ?>
							</label>
							<span class="vh-field-help"><?php esc_html_e( 'A disabled connector never runs, scheduled or manual.', 'vulnhub' ); ?></span>
						</td>
					</tr>
					<?php if ( $vh_active->supports_mock() ) : ?>
					<tr>
						<th scope="row"><?php esc_html_e( 'Data source', 'vulnhub' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="mock" value="1" <?php checked( $vh_active->is_mock() ); ?>>
								<?php esc_html_e( 'Use mock data instead of the live API', 'vulnhub' ); ?>
							</label>
							<span class="vh-field-help">
								<?php esc_html_e( 'Mock mode generates a realistic sample fleet that flows through exactly the same normalisation code as live data. Turn it off once your credentials below are in place and tested.', 'vulnhub' ); ?>
							</span>
						</td>
					</tr>
					<?php endif; ?>

					<?php if ( $vh_active->supports_sync() ) : ?>
					<tr>
						<th scope="row"><label for="vh-interval"><?php esc_html_e( 'Sync schedule', 'vulnhub' ); ?></label></th>
						<td>
							<select name="interval" id="vh-interval">
								<?php
								$vh_current = (string) vulnhub()->settings->get( $vh_active->id(), 'interval', $vh_active->default_interval() );
								foreach ( Scheduler::interval_choices() as $vh_key => $vh_label ) :
									?>
									<option value="<?php echo esc_attr( $vh_key ); ?>" <?php selected( $vh_current, $vh_key ); ?>>
										<?php echo esc_html( $vh_label ); ?>
									</option>
								<?php endforeach; ?>
							</select>
							<?php $vh_next = Scheduler::next_run( $vh_active->id() ); ?>
							<span class="vh-field-help">
								<?php
								echo $vh_next
									? esc_html( sprintf( /* translators: %s: relative time. */ __( 'Next scheduled run in %s.', 'vulnhub' ), human_time_diff( time(), $vh_next ) ) )
									: esc_html__( 'Not currently scheduled.', 'vulnhub' );
								?>
							</span>
						</td>
					</tr>
					<?php endif; ?>

					<?php foreach ( $vh_active->fields() as $vh_field ) : ?>
						<?php
						$vh_key    = (string) $vh_field['key'];
						$vh_type   = (string) ( $vh_field['type'] ?? 'text' );

						/*
						 * A `note` is guidance, not a setting: setup steps, a
						 * warning, a link to somewhere else. It spans both
						 * columns and stores nothing.
						 *
						 * Without it the only place to put a paragraph of
						 * instructions is a field's help text, which leaves a
						 * one-line label stranded beside a tall block and
						 * reads as though the prose belongs to that input.
						 */
						if ( 'note' === $vh_type ) {
							printf(
								'<tr class="vh-field-note"><td colspan="2">%s</td></tr>',
								wp_kses_post( (string) ( $vh_field['help'] ?? '' ) )
							);
							continue;
						}

						$vh_name   = 'vh_' . $vh_key;
						$vh_id     = 'vh-field-' . $vh_key;
						$vh_secret = ! empty( $vh_field['secret'] );
						$vh_value  = $vh_secret ? '' : (string) vulnhub()->settings->get( $vh_active->id(), $vh_key, (string) ( $vh_field['default'] ?? '' ) );
						$vh_hint   = $vh_secret ? vulnhub()->settings->secret_hint( $vh_active->id(), $vh_key ) : '';
						?>
						<tr>
							<th scope="row">
								<label for="<?php echo esc_attr( $vh_id ); ?>">
									<?php echo esc_html( (string) $vh_field['label'] ); ?>
									<?php if ( ! empty( $vh_field['required'] ) ) : ?>
										<span style="color:var(--vh-crit)" title="<?php esc_attr_e( 'Required', 'vulnhub' ); ?>">*</span>
									<?php endif; ?>
								</label>
							</th>
							<td>
								<?php if ( 'select' === $vh_type ) : ?>
									<select name="<?php echo esc_attr( $vh_name ); ?>" id="<?php echo esc_attr( $vh_id ); ?>">
										<?php foreach ( (array) ( $vh_field['options'] ?? array() ) as $vh_ok => $vh_ol ) : ?>
											<option value="<?php echo esc_attr( (string) $vh_ok ); ?>" <?php selected( $vh_value, (string) $vh_ok ); ?>>
												<?php echo esc_html( (string) $vh_ol ); ?>
											</option>
										<?php endforeach; ?>
									</select>

								<?php elseif ( 'textarea' === $vh_type ) : ?>
									<textarea name="<?php echo esc_attr( $vh_name ); ?>" id="<?php echo esc_attr( $vh_id ); ?>"
										rows="4" class="large-text code"
										placeholder="<?php echo esc_attr( (string) ( $vh_field['placeholder'] ?? '' ) ); ?>"><?php echo esc_textarea( $vh_value ); ?></textarea>

								<?php elseif ( 'checkbox' === $vh_type ) : ?>
									<label>
										<input type="checkbox" name="<?php echo esc_attr( $vh_name ); ?>" id="<?php echo esc_attr( $vh_id ); ?>"
											value="1" <?php checked( vulnhub()->settings->get_bool( $vh_active->id(), $vh_key, (bool) ( $vh_field['default'] ?? false ) ) ); ?>>
										<?php echo esc_html( (string) ( $vh_field['checkbox_label'] ?? __( 'Enabled', 'vulnhub' ) ) ); ?>
									</label>

								<?php elseif ( $vh_secret ) : ?>
									<input type="password" name="<?php echo esc_attr( $vh_name ); ?>" id="<?php echo esc_attr( $vh_id ); ?>"
										class="regular-text" autocomplete="new-password"
										placeholder="<?php echo $vh_hint ? esc_attr( $vh_hint ) : esc_attr( (string) ( $vh_field['placeholder'] ?? '' ) ); ?>">
									<?php if ( $vh_hint ) : ?>
										<span class="vh-secret-set">
											<span class="dashicons dashicons-yes-alt" style="font-size:16px;width:16px;height:16px"></span>
											<?php esc_html_e( 'stored', 'vulnhub' ); ?>
										</span>
										<label style="margin-left:10px">
											<input type="checkbox" name="clear_<?php echo esc_attr( $vh_key ); ?>" value="1">
											<?php esc_html_e( 'clear', 'vulnhub' ); ?>
										</label>
									<?php endif; ?>

								<?php else : ?>
									<input type="<?php echo esc_attr( in_array( $vh_type, array( 'url', 'email', 'number' ), true ) ? $vh_type : 'text' ); ?>"
										name="<?php echo esc_attr( $vh_name ); ?>" id="<?php echo esc_attr( $vh_id ); ?>"
										value="<?php echo esc_attr( $vh_value ); ?>" class="regular-text"
										placeholder="<?php echo esc_attr( (string) ( $vh_field['placeholder'] ?? '' ) ); ?>">
								<?php endif; ?>

								<?php if ( ! empty( $vh_field['help'] ) ) : ?>
									<span class="vh-field-help"><?php echo wp_kses_post( (string) $vh_field['help'] ); ?></span>
								<?php endif; ?>
							</td>
						</tr>
					<?php endforeach; ?>
				</table>

				<?php submit_button( __( 'Save integration settings', 'vulnhub' ) ); ?>
			</form>
		</div>

		<div>
			<div class="vh-card">
				<h2><?php esc_html_e( 'Connection', 'vulnhub' ); ?></h2>
				<p>
					<span class="vh-health vh-health--<?php echo esc_attr( (string) $vh_health['state'] ); ?>">
						<?php echo esc_html( (string) $vh_health['label'] ); ?>
					</span>
				</p>
				<p class="vh-card__meta"><?php echo esc_html( (string) $vh_health['detail'] ); ?></p>

				<p style="margin-top:14px" class="vh-actions">
					<button type="button" class="button" data-vh-action="test" data-vh-connector="<?php echo esc_attr( $vh_active->id() ); ?>">
						<?php esc_html_e( 'Test connection', 'vulnhub' ); ?>
					</button>
					<?php if ( $vh_active->supports_sync() && current_user_can( 'vulnhub_run_sync' ) ) : ?>
						<button type="button" class="button button-primary" data-vh-action="sync" data-vh-connector="<?php echo esc_attr( $vh_active->id() ); ?>">
							<?php esc_html_e( 'Sync now', 'vulnhub' ); ?>
						</button>
						<?php if ( $vh_active->supports_full_sync() ) : ?>
							<button type="button" class="button" data-vh-action="sync" data-vh-full="1" data-vh-connector="<?php echo esc_attr( $vh_active->id() ); ?>"
								data-vh-sync-confirm="<?php esc_attr_e( 'Run a full resync? It downloads everything the source holds rather than only what changed, so it takes much longer than a normal sync. It runs in the background.', 'vulnhub' ); ?>">
								<?php esc_html_e( 'Full resync', 'vulnhub' ); ?>
							</button>
						<?php endif; ?>
					<?php endif; ?>
				</p>
				<?php if ( '' !== $vh_active->full_sync_note() ) : ?>
					<p class="vh-card__meta"><?php echo esc_html( $vh_active->full_sync_note() ); ?></p>
				<?php endif; ?>
				<?php if ( $vh_active->supports_sync() ) : ?>
					<div class="vh-sync-progress" data-vh-sync-progress="<?php echo esc_attr( $vh_active->id() ); ?>" hidden></div>
				<?php endif; ?>
			</div>

			<?php if ( $vh_last_run ) : ?>
				<div class="vh-card" style="margin-top:16px">
					<h2><?php esc_html_e( 'Last run', 'vulnhub' ); ?></h2>
					<div class="vh-detail">
						<dl>
							<dt><?php esc_html_e( 'Status', 'vulnhub' ); ?></dt>
							<dd><?php echo esc_html( (string) $vh_last_run['status'] ); ?></dd>
							<dt><?php esc_html_e( 'Started', 'vulnhub' ); ?></dt>
							<dd><?php echo esc_html( vh_date( (string) $vh_last_run['started_at'] ) ); ?></dd>
							<dt><?php esc_html_e( 'Duration', 'vulnhub' ); ?></dt>
							<dd><?php echo esc_html( number_format_i18n( (int) $vh_last_run['duration_ms'] / 1000, 1 ) . 's' ); ?></dd>
							<dt><?php esc_html_e( 'Processed', 'vulnhub' ); ?></dt>
							<dd><?php echo esc_html( number_format_i18n( (int) $vh_last_run['processed'] ) ); ?></dd>
							<dt><?php esc_html_e( 'Created', 'vulnhub' ); ?></dt>
							<dd><?php echo esc_html( number_format_i18n( (int) $vh_last_run['created'] ) ); ?></dd>
							<dt><?php esc_html_e( 'Updated', 'vulnhub' ); ?></dt>
							<dd><?php echo esc_html( number_format_i18n( (int) $vh_last_run['updated'] ) ); ?></dd>
						</dl>
					</div>
					<?php if ( ! empty( $vh_last_run['log_text'] ) ) : ?>
						<p style="margin:12px 0 6px">
							<a href="#" data-vh-toggle="vh-last-log"><?php esc_html_e( 'Show run log', 'vulnhub' ); ?></a>
						</p>
						<div class="vh-log" id="vh-last-log" hidden><?php echo esc_html( (string) $vh_last_run['log_text'] ); ?></div>
					<?php endif; ?>
				</div>
			<?php endif; ?>
		</div>
	</div>

<?php else : ?>

	<?php foreach ( Connectors::categories() as $vh_cat => $vh_cat_label ) : ?>
		<?php
		$vh_in_cat = vulnhub()->connectors->by_category( $vh_cat );
		if ( ! $vh_in_cat ) {
			continue;
		}
		?>
		<h2 style="margin:24px 0 12px;font-size:15px"><?php echo esc_html( $vh_cat_label ); ?></h2>
		<div class="vh-grid vh-grid--3">
			<?php foreach ( $vh_in_cat as $vh_id => $vh_c ) : ?>
				<?php $vh_h = $vh_c->health(); ?>
				<div class="vh-connector">
					<div class="vh-connector__head">
						<span class="dashicons <?php echo esc_attr( $vh_c->icon() ); ?>"></span>
						<div>
							<h3><?php echo esc_html( $vh_c->label() ); ?></h3>
							<span class="vh-health vh-health--<?php echo esc_attr( (string) $vh_h['state'] ); ?>">
								<?php echo esc_html( (string) $vh_h['label'] ); ?>
							</span>
						</div>
					</div>
					<p class="vh-connector__desc"><?php echo esc_html( $vh_c->description() ); ?></p>
					<p class="vh-connector__desc"><em><?php echo esc_html( (string) $vh_h['detail'] ); ?></em></p>
					<?php if ( ! empty( $vh_h['last'] ) ) : ?>
						<dl class="vh-connector__sync">
							<dt><?php esc_html_e( 'Last sync finished', 'vulnhub' ); ?></dt>
							<dd><?php echo esc_html( vh_date( (string) $vh_h['last']['finished_at'], 'j M Y, H:i:s' ) ); ?></dd>
							<dt><?php esc_html_e( 'Duration', 'vulnhub' ); ?></dt>
							<dd><?php echo esc_html( vh_duration_human( (int) $vh_h['last']['duration_ms'] ) ); ?></dd>
						</dl>
					<?php endif; ?>
					<div class="vh-connector__foot">
						<a class="button button-primary" href="<?php echo esc_url( vh_admin_url( 'vulnhub-integrations', array( 'connector' => (string) $vh_id ) ) ); ?>">
							<?php esc_html_e( 'Configure', 'vulnhub' ); ?>
						</a>
						<button type="button" class="button" data-vh-action="test" data-vh-connector="<?php echo esc_attr( (string) $vh_id ); ?>">
							<?php esc_html_e( 'Test', 'vulnhub' ); ?>
						</button>
						<?php if ( $vh_c->supports_sync() && $vh_c->is_enabled() && current_user_can( 'vulnhub_run_sync' ) ) : ?>
							<button type="button" class="button" data-vh-action="sync" data-vh-connector="<?php echo esc_attr( (string) $vh_id ); ?>">
								<?php esc_html_e( 'Sync now', 'vulnhub' ); ?>
							</button>
						<?php endif; ?>
					</div>
					<?php if ( $vh_c->supports_sync() ) : ?>
						<div class="vh-sync-progress" data-vh-sync-progress="<?php echo esc_attr( (string) $vh_id ); ?>" hidden></div>
					<?php endif; ?>
				</div>
			<?php endforeach; ?>
		</div>
	<?php endforeach; ?>

<?php endif; ?>

